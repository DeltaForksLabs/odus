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
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Read, Write as IoWrite, stdout};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{Ordering, compiler_fence};
use std::time::{Duration, SystemTime};
use toml::Value;

const PAM_SERVICE: &str = "odus";

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
/// Fix M1: uses create_new (O_CREAT|O_EXCL) + O_NOFOLLOW — atomic, no TOCTOU.
pub fn ensure_pam_service() -> Result<()> {
    let pam_path = std::path::PathBuf::from(format!("/etc/pam.d/{PAM_SERVICE}"));

    match OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL — atomic
        .custom_flags(libc::O_NOFOLLOW) // reject symlinks on the final component
        .open(&pam_path)
    {
        Ok(mut file) => {
            file.write_all(pam_content().as_bytes())
                .context("Failed to write PAM service file")?;

            // fchmod/fchown via AsFd — no as_raw_fd(), no path re-open.
            fchown(
                file.as_raw_fd(),
                Some(Uid::from_raw(0)),
                Some(Gid::from_raw(0)),
            )
            .context("Failed to set root ownership on PAM file")?;
            fchmod(file.as_raw_fd(), Mode::from_bits_truncate(0o644))
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

    let cache_dir = Path::new("/var/run/odus/ts");
    ensure_cache_dir(cache_dir)?;

    // Cache file includes the Session ID so each login session gets its own file.
    // When a session ends its SID is never reused, so the old cache is naturally
    // invalidated — this is the mechanism behind cache_timeout = -1.
    let sid = getsid(None).unwrap_or(nix::unistd::Pid::from_raw(0));
    let cache_name = format!("{username}_{sid}");
    let cache_file = cache_dir.join(&cache_name);

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
                eprint!("[odus] password for {username}: ");
                stdout().flush().ok();

                let raw = rpassword::read_password().context("Failed to read password")?;
                // Wrap immediately — zeroed on drop regardless of what happens next.
                let password = SensitiveString(raw);

                match do_pam_auth(&username, &password.0) {
                    Ok(()) => {
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

            match mode {
                // Session mode: any valid (root-owned) cache file for this SID
                // means the user already authenticated in this session.
                CacheMode::Session => Ok(false),

                // Timed mode: check whether the cached timestamp is still fresh.
                CacheMode::Timed(minutes) => {
                    let cached = SystemTime::UNIX_EPOCH + Duration::from_secs(ts);
                    let timeout = Duration::from_secs(minutes * 60);
                    let elapsed = SystemTime::now()
                        .duration_since(cached)
                        .unwrap_or(Duration::MAX);
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

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600) // explicit — do not rely on umask
        .custom_flags(libc::O_NOFOLLOW) // reject symlinks
        .open(cache_file)
        .context("Failed to open cache file for writing")?;

    // Defence in depth: confirm owner and permissions on the open fd.
    fchown(
        file.as_raw_fd(),
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )
    .context("Failed to set root ownership on cache file")?;
    fchmod(file.as_raw_fd(), Mode::from_bits_truncate(0o600))
        .context("Failed to set 0600 permissions on cache file")?;

    (&file)
        .write_all(now.to_string().as_bytes())
        .context("Failed to write timestamp to cache file")
}

// ─── Private ────────────────────────────────────────────────────────────────

fn do_pam_auth(username: &str, password: &str) -> Result<()> {
    let mut pam = Authenticator::with_password(PAM_SERVICE).context("Failed to initialise PAM")?;
    pam.get_handler().set_credentials(username, password);
    pam.authenticate()
        .context("PAM authentication failed — incorrect password")
}

/// Creates and secures the authentication cache directory.
///
/// Fix C3: directory must be root-owned and mode 0700 (no access for others).
/// Uses open-fd fchmod instead of the non-existent nix::sys::stat::chmod.
fn ensure_cache_dir(cache_dir: &Path) -> Result<()> {
    create_dir_all(cache_dir).context("Failed to create cache directory")?;

    // lstat does not follow symlinks.
    let stat = lstat(cache_dir).context("Failed to stat cache directory")?;

    if stat.st_uid != 0 {
        crate::audit::log_security(&format!(
            "cache directory {} has invalid owner uid={}",
            cache_dir.display(),
            stat.st_uid
        ));
        return Err(anyhow::anyhow!(
            "Security: cache directory is not owned by root"
        ));
    }

    // Fix insecure permissions if needed (e.g. created by an old version or manually).
    // Open the directory as a file descriptor, then call fchmod on it.
    // nix does not expose chmod-by-path; the correct API is fchmod on an open fd.
    if stat.st_mode & 0o077 != 0 {
        let dir_fd = File::open(cache_dir).context("Failed to open cache directory for fchmod")?;
        fchmod(dir_fd.as_raw_fd(), Mode::from_bits_truncate(0o700))
            .context("Failed to fix cache directory permissions")?;
    }

    Ok(())
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

    Ok(())
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
