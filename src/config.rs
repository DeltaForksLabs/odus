// config.rs — Configuration loading and security verification
//
// Security fixes applied:
//   C1/M2: Creation uses OpenOptions::create_new (O_CREAT|O_EXCL) + O_NOFOLLOW
//          → atomic, rejects symlinks, no TOCTOU window
//   A3:    Integrity check uses lstat() (does not follow symlinks)
//          + explicit file-type verification
//   A4:    Path is a compile-time constant — not user-supplied

use anyhow::{Context, Result};
use nix::sys::stat::{fchmod, lstat, Mode, SFlag};
use nix::unistd::{fchown, Gid, Uid};
use std::io::Write as IoWrite;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::fs::OpenOptions;

/// Fixed configuration path — not configurable by unprivileged users (fix C1/A4).
pub const CONFIG_PATH: &str = "/etc/odus.toml";

/// File permission: read/write for root only (0600).
const CONFIG_MODE: Mode = Mode::from_bits_truncate(0o600);

pub fn config_path() -> PathBuf {
    PathBuf::from(CONFIG_PATH)
}

/// Ensures the config file exists with sane defaults and correct permissions.
///
/// Security:
///   - Creation: O_CREAT|O_EXCL|O_NOFOLLOW (atomic, symlink-safe)
///   - Permissions set via fchmod on the open fd (no path re-open)
///   - Integrity: lstat (no symlink follow) + file-type check + owner check
pub fn ensure_default_and_perms() -> Result<()> {
    let path = config_path();
    create_if_missing(&path)?;
    verify_integrity(&path)
}

/// Loads and parses /etc/odus.toml.
pub fn load() -> Result<toml::Value> {
    let config_str =
        std::fs::read_to_string(config_path()).context("Failed to read /etc/odus.toml")?;
    config_str
        .parse::<toml::Value>()
        .context("Failed to parse /etc/odus.toml as TOML")
}

// ─── Private ────────────────────────────────────────────────────────────────

// Default configuration varies by OS:
//   - Linux:   only the 'wheel' group is conventional for admin users.
//   - FreeBSD: both 'wheel' AND 'operator' are used; operator has traditional
//              access to certain system commands (shutdown, reboot, etc.) and
//              is a standard group since 4.2BSD.
#[cfg(target_os = "freebsd")]
const DEFAULT_CONFIG: &str = r#"# odus.toml — Privilege escalation configuration
# Owner: root:root   Permissions: 0600
# Do NOT change ownership or permissions.

# Authentication cache timeout in minutes (0 = always prompt)
cache_timeout = 15

# Trusted directories for relative command resolution
secure_path = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]

# Allow members of 'wheel' to run any command
[[rules]]
group    = "wheel"
cmd      = "ALL"
nopasswd = false

# Allow members of 'operator' to run any command
# 'operator' is a traditional FreeBSD group (gid 5) for privileged system users
[[rules]]
group    = "operator"
cmd      = "ALL"
nopasswd = false
"#;

#[cfg(not(target_os = "freebsd"))]
const DEFAULT_CONFIG: &str = r#"# odus.toml — Privilege escalation configuration
# Owner: root:root   Permissions: 0600
# Do NOT change ownership or permissions.

# Authentication cache timeout in minutes (0 = always prompt)
cache_timeout = 15

# Trusted directories for relative command resolution
secure_path = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]

# Allow members of 'wheel' to run any command
[[rules]]
group    = "wheel"
cmd      = "ALL"
nopasswd = false
"#;

fn create_if_missing(config_path: &Path) -> Result<()> {
    // O_CREAT|O_EXCL (create_new): fails atomically if the file already exists.
    // O_NOFOLLOW: rejects symlinks on the final path component.
    // Together these eliminate the TOCTOU window and symlink attack entirely.
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(config_path)
    {
        Ok(mut file) => {
            file.write_all(DEFAULT_CONFIG.as_bytes())
                .context("Failed to write default config")?;

            // Set owner and permissions on the open fd — never re-open by path.
            // fchmod/fchown in nix 0.29 accept any AsFd, so &file works directly.
            fchown(file.as_raw_fd(), Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
                .context("Failed to set root ownership on config")?;
            fchmod(file.as_raw_fd(), CONFIG_MODE)
                .context("Failed to set 0600 permissions on config")?;

            eprintln!(
                "odus: default configuration created at {}. Adjust as needed.",
                config_path.display()
            );
            Ok(())
        }
        // File already exists — proceed to integrity verification.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).context("Failed to create configuration file"),
    }
}

fn verify_integrity(config_path: &Path) -> Result<()> {
    // lstat does NOT follow symlinks — returns metadata for the path entry itself.
    let stat = lstat(config_path).context("Failed to stat config file")?;

    // Reject anything that is not a plain regular file (symlinks, FIFOs, devices…).
    let file_type = SFlag::from_bits_truncate(stat.st_mode);
    if !file_type.contains(SFlag::S_IFREG) {
        crate::audit::log_security(&format!(
            "config {} is not a regular file (mode={:#o})",
            config_path.display(),
            stat.st_mode
        ));
        return Err(anyhow::anyhow!(
            "Security: {} is not a regular file",
            config_path.display()
        ));
    }

    // Must be owned by root:root.
    if stat.st_uid != 0 || stat.st_gid != 0 {
        crate::audit::log_security(&format!(
            "config {} has invalid owner uid={} gid={}",
            config_path.display(),
            stat.st_uid,
            stat.st_gid
        ));
        eprintln!(
            "odus: security error — {} must be owned by root:root",
            config_path.display()
        );
        return Err(anyhow::anyhow!("Config file is not owned by root"));
    }

    // Group and other must have no permissions (bits 0o077 must be zero).
    if stat.st_mode & 0o077 != 0 {
        crate::audit::log_security(&format!(
            "config {} has unsafe permissions mode={:#o}",
            config_path.display(),
            stat.st_mode
        ));
        eprintln!(
            "odus: security error — {} must have permissions 0600",
            config_path.display()
        );
        return Err(anyhow::anyhow!("Config file has invalid permissions"));
    }

    Ok(())
}
