// auth.rs — PAM authentication with credential caching
//
// Security fixes applied:
//   C3:  update_cache sets mode 0600 explicitly + fchown/fchmod on open fd
//        (correct permissions regardless of the process umask)
//   C3:  cache directory enforced to 0700 via open-fd fchmod (not chmod by path)
//   M1:  ensure_pam_service uses create_new (O_CREAT|O_EXCL) + O_NOFOLLOW
//   A1:  password zeroed via SensitiveString — unsafe confined to one Drop impl
//   A2:  audit logging at every relevant outcome
//   A3:  PAM file verification uses lstat (does not follow symlinks)
//
// FreeBSD note: the 'pam' crate (0.7) links against libpam on Linux and
// OpenPAM on FreeBSD. The Rust API is identical; only the PAM config file
// content differs (handled in pam_content()).

use crate::security;
use anyhow::{Context, Result};
use nix::sys::stat::{Mode, SFlag, fchmod, lstat};
use nix::unistd::{Gid, Uid, fchown, getsid};
use pam::Authenticator;
use std::fs::{File, OpenOptions, create_dir, read_dir, remove_file};
use std::io::{Read, Write as IoWrite, stdout};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{Ordering, compiler_fence};
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use toml::Value;

const PAM_SERVICE: &str = "odus";
const PAM_CREATE_MODE: u32 = 0o600;
const PAM_FINAL_MODE: Mode = Mode::from_bits_truncate(0o644);
const SECURE_RUNTIME_DIR_MODE: Mode = Mode::from_bits_truncate(0o700);
const STATE_FILE_MODE: Mode = Mode::from_bits_truncate(0o600);
const RUNTIME_DIR: &str = "/var/run/odus";
const CACHE_DIR_NAME: &str = "ts";
const RATE_LIMIT_DIR_NAME: &str = "fails";
const AUTH_FAILURE_COOLDOWN: Duration = Duration::from_secs(2);
const FAILURE_STATE_RETENTION: Duration = Duration::from_secs(15 * 60);
const SESSION_CACHE_MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);

// ─── Password memory safety ─────────────────────────────────────────────────

/// A String wrapper that overwrites its heap buffer with zeroes when dropped.
///
/// This prevents the plaintext password from remaining in process memory after
/// authentication completes (fix A1). The unsafe is confined to the Drop impl
/// and is unavoidable: `write_volatile` is required to prevent the compiler
/// from eliminating the zeroing as dead code after the String is no longer read.
struct SensitiveString(String);

impl Drop for SensitiveString {
    fn drop(&mut self) {
        // SAFETY: `as_bytes_mut` gives a &mut [u8] into our own String's heap
        // buffer. We zero each byte with write_volatile, which the compiler is
        // not allowed to optimise away (unlike a regular assignment). The fence
        // prevents reordering around the zeroing loop.
        let bytes = unsafe { self.0.as_bytes_mut() };
        for b in bytes.iter_mut() {
            // SAFETY: `b` is a valid &mut u8 within our own allocation.
            unsafe { std::ptr::write_volatile(b, 0u8) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

// ─── PAM service file ────────────────────────────────────────────────────────

/// Ensures /etc/pam.d/odus exists and is owned by root.
///
/// Security:
///   - create_new (O_CREAT|O_EXCL) + O_NOFOLLOW — atomic, no TOCTOU
///   - initial mode 0600 — safe regardless of caller umask
///   - final mode 0644 applied only after the full content is written
pub fn ensure_pam_service() -> Result<()> {
    let pam_path = std::path::PathBuf::from(format!("/etc/pam.d/{PAM_SERVICE}"));

    match OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL — atomic
        .mode(PAM_CREATE_MODE)
        .custom_flags(libc::O_NOFOLLOW) // reject symlinks on the final component
        .open(&pam_path)
    {
        Ok(mut file) => {
            file.write_all(pam_content().as_bytes())
                .context("Failed to write PAM service file")?;
            file.sync_all()
                .context("Failed to flush PAM service file to disk")?;

            // fchmod/fchown via AsFd — no as_raw_fd(), no path re-open.
            fchown(
                file.as_raw_fd(),
                Some(Uid::from_raw(0)),
                Some(Gid::from_raw(0)),
            )
            .context("Failed to set root ownership on PAM file")?;
            fchmod(file.as_raw_fd(), PAM_FINAL_MODE)
                .context("Failed to set 0644 permissions on PAM file")?;

            eprintln!("odus: PAM service file created at {}", pam_path.display());
            Ok(())
        }

        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => verify_pam_integrity(&pam_path),

        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            crate::audit::log_security(&format!(
                "symlink detected at PAM path: {}",
                pam_path.display()
            ));
            Err(anyhow::anyhow!("Security: symlink at PAM service path"))
        }

        Err(e) => Err(e).context("Failed to create PAM service file"),
    }
}

// ─── Authentication ──────────────────────────────────────────────────────────

/// Authenticates the current user via cache or PAM.
///
/// `command` is used only for audit logging — execution happens in exec.rs.
///
/// Fix A1: password memory zeroed via SensitiveString regardless of outcome.
/// Fix A2: every outcome produces an audit log entry.
pub fn authenticate(cfg: &Value, rule: &Value, command: &[String]) -> Result<()> {
    let nopasswd = rule
        .as_table()
        .and_then(|m| m.get("nopasswd").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    // cache_timeout semantics:
    //   -1 : authenticate once per TTY session (cache never expires by time)
    //    0 : always prompt (no caching)
    //  1-60: cache valid for N minutes (clamped to this range)
    let cache_timeout_raw = cfg
        .get("cache_timeout")
        .and_then(|v| v.as_integer())
        .unwrap_or(15);

    let cache_mode = CacheMode::from_config(cache_timeout_raw);

    // Configurable retry limit (mirrors sudo passwd_tries). Clamped to 1..=10
    // so a misconfigured value cannot produce zero attempts or an open-ended loop.
    let max_tries = cfg
        .get("max_tries")
        .and_then(|v| v.as_integer())
        .unwrap_or(3)
        .clamp(1, 10) as u32;

    let current_user = users::get_current_username().unwrap_or_default();
    let username = current_user.to_string_lossy();

    let (cache_dir, rate_limit_dir) = ensure_runtime_dirs()?;
    cleanup_state_files(&cache_dir, &rate_limit_dir, &cache_mode)?;

    // Cache file includes the Session ID so each login session gets its own file.
    // When a session ends its SID is never reused, so the old cache is naturally
    // invalidated in practice. A hard TTL is still enforced to bound replay risk
    // if an SID is ever reused after process-id wrap-around.
    let sid = getsid(None).unwrap_or(nix::unistd::Pid::from_raw(0));
    let cache_name = format!("{username}_{sid}");
    let cache_file = cache_dir.join(&cache_name);
    let rate_limit_file = rate_limit_dir.join(username.as_ref());

    if nopasswd {
        crate::audit::log_exec(&username, command);
        return Ok(());
    }

    match needs_auth(&cache_file, &cache_mode)? {
        false => {
            crate::audit::log_cache_hit(&username);
            crate::audit::log_exec(&username, command);
            Ok(())
        }
        true => {
            let mut attempts_left = max_tries;

            loop {
                enforce_failure_cooldown(&rate_limit_file)?;
                eprint!("[odus] password for {username}: ");
                stdout().flush().ok();

                let raw = rpassword::read_password().context("Failed to read password")?;
                // Wrap immediately — zeroed on drop regardless of what happens next.
                let password = SensitiveString(raw);

                match do_pam_auth(&username, &password.0) {
                    Ok(()) => {
                        clear_state_file(&rate_limit_file)
                            .context("Failed to clear authentication cooldown state")?;
                        crate::audit::log_auth_ok(&username);
                        crate::audit::log_exec(&username, command);
                        drop(password);
                        return update_cache(&cache_file);
                    }
                    Err(e) => {
                        // Log the real PAM error to syslog for the admin.
                        // Do NOT surface PAM internals (error codes) to the user —
                        // they provide no value to a legitimate user but may aid an attacker.
                        crate::audit::log_auth_fail(&username, &e.to_string());
                        record_auth_failure(&rate_limit_file)?;
                        drop(password);
                        attempts_left -= 1;

                        if attempts_left > 0 {
                            eprintln!("Sorry, try again.");
                        } else {
                            // All attempts exhausted — mirrors sudo output format
                            eprintln!(
                                "\x1b[31modus: {max_tries} incorrect password attempt{}\x1b[0m",
                                if max_tries == 1 { "" } else { "s" }
                            );
                            // Return a generic error — PAM details stay in syslog only
                            return Err(anyhow::anyhow!("\x1b[31mAuthentication failed\x1b[0m"));
                        }
                    }
                }
            }
        }
    }
}

/// How the authentication cache behaves, derived from the cache_timeout config value.
pub enum CacheMode {
    /// Always prompt — no caching (cache_timeout = 0).
    AlwaysPrompt,
    /// Cache valid for N minutes (cache_timeout = 1..=60).
    Timed(u64),
    /// Cache valid for the entire TTY session (cache_timeout = -1).
    Session,
}

impl CacheMode {
    pub fn from_config(raw: i64) -> Self {
        match raw {
            -1 => CacheMode::Session,
            0 => CacheMode::AlwaysPrompt,
            n => CacheMode::Timed(n.clamp(1, 60) as u64),
        }
    }
}

/// Returns `true` if PAM authentication is required, `false` if the cache is valid.
pub fn needs_auth(cache_file: &Path, mode: &CacheMode) -> Result<bool> {
    // AlwaysPrompt: skip cache entirely — always require authentication.
    if matches!(mode, CacheMode::AlwaysPrompt) {
        return Ok(true);
    }

    match security::open_and_verify_cache(cache_file)? {
        None => Ok(true),
        Some(mut file) => {
            let mut buf = String::new();
            file.read_to_string(&mut buf)
                .context("Failed to read authentication cache")?;

            let Ok(ts) = buf.trim().parse::<u64>() else {
                return Ok(true); // corrupted cache → re-authenticate
            };

            let cached = SystemTime::UNIX_EPOCH + Duration::from_secs(ts);
            let elapsed = SystemTime::now()
                .duration_since(cached)
                .unwrap_or(Duration::MAX);

            match mode {
                // Session mode: any valid (root-owned) cache file for this SID
                // means the user already authenticated in this session, but a
                // hard upper bound still applies so stale files cannot replay
                // indefinitely if the SID is reused after wrap-around.
                CacheMode::Session => Ok(elapsed >= SESSION_CACHE_MAX_AGE),

                // Timed mode: check whether the cached timestamp is still fresh.
                CacheMode::Timed(minutes) => {
                    let timeout = Duration::from_secs(minutes * 60);
                    Ok(elapsed >= timeout)
                }

                CacheMode::AlwaysPrompt => unreachable!(),
            }
        }
    }
}

/// Writes the current timestamp to the cache file.
///
/// Fix C3:
///   - mode(0o600) on OpenOptions — correct permissions regardless of umask
///   - O_NOFOLLOW — rejects symlinks
///   - fchown + fchmod on open fd — verifies owner/perms without path re-open
pub fn update_cache(cache_file: &Path) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    write_state_file(cache_file, &now.to_string()).context("Failed to update authentication cache")
}

// ─── Private ────────────────────────────────────────────────────────────────

fn do_pam_auth(username: &str, password: &str) -> Result<()> {
    let mut pam = Authenticator::with_password(PAM_SERVICE).context("Failed to initialise PAM")?;
    pam.get_handler().set_credentials(username, password);
    pam.authenticate()
        .context("PAM authentication failed — incorrect password")
}

/// Creates and secures the odus runtime directories under `/var/run/odus`.
///
/// Both the parent directory and the child state directories are verified as
/// root-owned directories and forced to mode 0700 to prevent path substitution
/// or disclosure through an insecure intermediate directory.
fn ensure_runtime_dirs() -> Result<(PathBuf, PathBuf)> {
    let runtime_dir = PathBuf::from(RUNTIME_DIR);
    let cache_dir = runtime_dir.join(CACHE_DIR_NAME);
    let rate_limit_dir = runtime_dir.join(RATE_LIMIT_DIR_NAME);

    ensure_secure_dir(&runtime_dir, "runtime directory")?;
    ensure_secure_dir(&cache_dir, "cache directory")?;
    ensure_secure_dir(&rate_limit_dir, "rate-limit directory")?;

    Ok((cache_dir, rate_limit_dir))
}

/// Ensures a state directory exists, is a real directory, and is only
/// accessible to root.
fn ensure_secure_dir(path: &Path, label: &str) -> Result<()> {
    match create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("Failed to create {label}")),
    }

    let stat = lstat(path).with_context(|| format!("Failed to stat {label}"))?;

    let file_type = SFlag::from_bits_truncate(stat.st_mode);
    if !file_type.contains(SFlag::S_IFDIR) {
        crate::audit::log_security(&format!(
            "{} {} is not a directory (mode={:#o})",
            label,
            path.display(),
            stat.st_mode
        ));
        return Err(anyhow::anyhow!(
            "Security: {} is not a directory",
            path.display()
        ));
    }

    if stat.st_uid != 0 || stat.st_gid != 0 {
        crate::audit::log_security(&format!(
            "{} {} has invalid owner uid={} gid={}",
            label,
            path.display(),
            stat.st_uid,
            stat.st_gid
        ));
        return Err(anyhow::anyhow!(
            "Security: {} is not owned by root",
            path.display()
        ));
    }

    let dir_fd =
        File::open(path).with_context(|| format!("Failed to open {label} for hardening"))?;
    fchmod(dir_fd.as_raw_fd(), SECURE_RUNTIME_DIR_MODE)
        .with_context(|| format!("Failed to set 0700 on {label}"))?;

    Ok(())
}

/// Applies rate limiting between invocations by pausing until the stored
/// cooldown expires.
fn enforce_failure_cooldown(rate_limit_file: &Path) -> Result<()> {
    let Some(next_allowed_at) = read_state_timestamp(rate_limit_file)? else {
        return Ok(());
    };

    let now = unix_now_secs();
    if next_allowed_at > now {
        sleep(Duration::from_secs(next_allowed_at - now));
    }

    Ok(())
}

/// Records the next time a new password prompt may be shown after a failure.
fn record_auth_failure(rate_limit_file: &Path) -> Result<()> {
    let next_allowed_at = unix_now_secs() + AUTH_FAILURE_COOLDOWN.as_secs();
    write_state_file(rate_limit_file, &next_allowed_at.to_string())
        .context("Failed to persist authentication cooldown state")
}

/// Removes a root-owned state file if it exists.
fn clear_state_file(path: &Path) -> Result<()> {
    match remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to remove state file {}", path.display())),
    }
}

/// Writes a root-owned state file with mode 0600 using an fd-based ownership
/// and permission hardening step.
fn write_state_file(path: &Path, content: &str) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(STATE_FILE_MODE.bits())
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("Failed to open state file {}", path.display()))?;

    fchown(
        file.as_raw_fd(),
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )
    .with_context(|| format!("Failed to set root ownership on {}", path.display()))?;
    fchmod(file.as_raw_fd(), STATE_FILE_MODE)
        .with_context(|| format!("Failed to set 0600 permissions on {}", path.display()))?;

    (&file)
        .write_all(content.as_bytes())
        .with_context(|| format!("Failed to write state file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to flush state file {}", path.display()))
}

/// Reads a validated root-owned state file and parses its UNIX timestamp.
fn read_state_timestamp(path: &Path) -> Result<Option<u64>> {
    let Some(mut file) = security::open_and_verify_cache(path)? else {
        return Ok(None);
    };

    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .with_context(|| format!("Failed to read state file {}", path.display()))?;

    Ok(buf.trim().parse::<u64>().ok())
}

/// Removes expired cache and rate-limit files so short-lived runtime state does
/// not accumulate indefinitely under `/var/run/odus`.
fn cleanup_state_files(cache_dir: &Path, rate_limit_dir: &Path, mode: &CacheMode) -> Result<()> {
    cleanup_cache_files(cache_dir, cache_retention(mode))?;
    cleanup_rate_limit_files(rate_limit_dir)
}

/// Returns how long cache files may live before odus removes them automatically.
fn cache_retention(mode: &CacheMode) -> Duration {
    match mode {
        CacheMode::AlwaysPrompt => Duration::ZERO,
        CacheMode::Timed(minutes) => Duration::from_secs(minutes * 60),
        CacheMode::Session => SESSION_CACHE_MAX_AGE,
    }
}

/// Deletes expired or invalid cache files from the secure cache directory.
fn cleanup_cache_files(cache_dir: &Path, retention: Duration) -> Result<()> {
    for entry in
        read_dir(cache_dir).with_context(|| format!("Failed to read {}", cache_dir.display()))?
    {
        let entry = entry.context("Failed to iterate cache directory entry")?;
        let path = entry.path();

        let should_remove = if retention.is_zero() {
            true
        } else {
            match read_state_timestamp(&path)? {
                Some(ts) => unix_now_secs().saturating_sub(ts) >= retention.as_secs(),
                None => true,
            }
        };

        if should_remove {
            clear_state_file(&path)?;
        }
    }

    Ok(())
}

/// Deletes stale rate-limit files once they are well past their cooldown window.
fn cleanup_rate_limit_files(rate_limit_dir: &Path) -> Result<()> {
    for entry in read_dir(rate_limit_dir)
        .with_context(|| format!("Failed to read {}", rate_limit_dir.display()))?
    {
        let entry = entry.context("Failed to iterate rate-limit directory entry")?;
        let path = entry.path();

        let should_remove = match read_state_timestamp(&path)? {
            Some(ts) => unix_now_secs().saturating_sub(ts) >= FAILURE_STATE_RETENTION.as_secs(),
            None => true,
        };

        if should_remove {
            clear_state_file(&path)?;
        }
    }

    Ok(())
}

/// Returns the current UNIX time in seconds and clamps pre-epoch anomalies to 0.
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Verifies the integrity of an existing PAM service file.
///
/// Fix A3: uses lstat (does not follow symlinks) and checks file type.
fn verify_pam_integrity(pam_path: &Path) -> Result<()> {
    let stat = lstat(pam_path).context("Failed to stat PAM service file")?;

    let file_type = SFlag::from_bits_truncate(stat.st_mode);
    if !file_type.contains(SFlag::S_IFREG) {
        crate::audit::log_security(&format!(
            "PAM file {} is not a regular file (mode={:#o})",
            pam_path.display(),
            stat.st_mode
        ));
        return Err(anyhow::anyhow!(
            "Security: {} is not a regular file",
            pam_path.display()
        ));
    }

    if stat.st_uid != 0 || stat.st_gid != 0 {
        crate::audit::log_security(&format!(
            "PAM file {} has invalid owner uid={} gid={}",
            pam_path.display(),
            stat.st_uid,
            stat.st_gid
        ));
        eprintln!(
            "odus: security error — {} must be owned by root:root",
            pam_path.display()
        );
        return Err(anyhow::anyhow!("PAM service file is not owned by root"));
    }

    if !pam_permissions_are_safe(stat.st_mode) {
        crate::audit::log_security(&format!(
            "PAM file {} has unsafe permissions mode={:#o}",
            pam_path.display(),
            stat.st_mode
        ));
        eprintln!(
            "odus: security error — {} must not be writable by group or others",
            pam_path.display()
        );
        return Err(anyhow::anyhow!("PAM service file has unsafe permissions"));
    }

    Ok(())
}

/// Returns `true` when an existing PAM service file has non-writable,
/// non-executable permissions suitable for a root-owned policy file.
fn pam_permissions_are_safe(st_mode: libc::mode_t) -> bool {
    let perms = st_mode & 0o7777;

    perms & 0o022 == 0 && perms & 0o111 == 0 && perms & 0o7000 == 0
}

/// Returns the PAM configuration content for the current OS.
///
/// Linux (Linux-PAM):
///   Uses common-auth/account/session-noninteractive includes — integrates with
///   LDAP, Active Directory, pam_faillock, etc., whatever the host has configured.
///
/// FreeBSD (OpenPAM):
///   OpenPAM uses a different module set. pam_env.so and pam_limits.so do not
///   exist on FreeBSD. The 'system' include delegates to /etc/pam.d/system,
///   which covers local passwd, RADIUS, Kerberos, etc. as configured by the admin.
///   pam_permit.so satisfies the session requirement without pam_lastlog issues.
fn pam_content() -> &'static str {
    #[cfg(target_os = "linux")]
    return r#"#%PAM-1.0
# odus PAM configuration (Linux / Linux-PAM)
# Auto-generated — do not edit manually.

session    required   pam_limits.so
session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0

@include common-auth
@include common-account
@include common-session-noninteractive
"#;

    #[cfg(target_os = "freebsd")]
    return r#"# odus PAM configuration (FreeBSD / OpenPAM)
# Auto-generated — do not edit manually.

auth       include      system
account    include      system
session    required     pam_permit.so
password   include      system
"#;

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    compile_error!("Unsupported OS. Add a PAM configuration block for this target.");
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_FAILURE_COOLDOWN, CacheMode, FAILURE_STATE_RETENTION, SESSION_CACHE_MAX_AGE,
        cache_retention, pam_permissions_are_safe, unix_now_secs,
    };
    use std::time::Duration;

    #[test]
    fn pam_permissions_allow_safe_readable_modes() {
        assert!(pam_permissions_are_safe(0o600));
        assert!(pam_permissions_are_safe(0o640));
        assert!(pam_permissions_are_safe(0o644));
    }

    #[test]
    fn pam_permissions_reject_group_or_world_write_bits() {
        assert!(!pam_permissions_are_safe(0o664));
        assert!(!pam_permissions_are_safe(0o666));
    }

    #[test]
    fn pam_permissions_reject_exec_and_special_bits() {
        assert!(!pam_permissions_are_safe(0o755));
        assert!(!pam_permissions_are_safe(0o4644));
    }

    #[test]
    fn session_cache_retention_is_bounded() {
        assert_eq!(cache_retention(&CacheMode::Session), SESSION_CACHE_MAX_AGE);
    }

    #[test]
    fn always_prompt_retention_removes_all_cache_files() {
        assert_eq!(cache_retention(&CacheMode::AlwaysPrompt), Duration::ZERO);
    }

    #[test]
    fn timed_cache_retention_tracks_configured_minutes() {
        assert_eq!(
            cache_retention(&CacheMode::Timed(15)),
            Duration::from_secs(15 * 60)
        );
    }

    #[test]
    fn cooldown_constants_are_non_zero_and_ordered() {
        assert!(AUTH_FAILURE_COOLDOWN > Duration::ZERO);
        assert!(FAILURE_STATE_RETENTION > AUTH_FAILURE_COOLDOWN);
        assert!(unix_now_secs() > 0);
    }
}
