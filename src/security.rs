// security.rs — Secure file-opening primitives for sensitive paths
//
// Fix C2 (TOCTOU on authentication cache):
//   Old pattern: exists() → stat(path) → open(path)  ← three separate operations,
//                three opportunities for inode substitution between steps.
//
//   New pattern:
//     1. open(path, O_NOFOLLOW) — atomic: rejects symlinks, returns fd or error
//     2. file.metadata()        — fstat on the open fd, same inode guaranteed
//     3. ownership check on fd  → zero TOCTOU window

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Opens the authentication cache file with security checks.
///
/// Returns:
///   `Ok(Some(file))` — file exists, is owned by root, ready to read
///   `Ok(None)`       — file does not exist (authentication required)
///   `Err(_)`         — security violation or I/O error (treat as auth required + log)
pub fn open_and_verify_cache(cache_file: &Path) -> Result<Option<File>> {
    let result = OpenOptions::new()
        .read(true)
        // O_NOFOLLOW: if the final path component is a symlink, the open fails
        // with ELOOP (errno 40). This prevents the symlink-swap race between
        // the ownership check and the file read.
        .custom_flags(libc::O_NOFOLLOW)
        .open(cache_file);

    match result {
        // Normal first-run case: cache does not exist yet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),

        // ELOOP = O_NOFOLLOW triggered: a symlink was detected.
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            crate::audit::log_security(&format!(
                "symlink detected at cache path: {}",
                cache_file.display()
            ));
            Err(anyhow::anyhow!(
                "Security: symlink detected at cache path ({})",
                cache_file.display()
            ))
        }

        Err(e) => Err(e).context("Failed to open authentication cache"),

        Ok(file) => {
            // file.metadata() calls fstat(2) on the open file descriptor.
            // Unlike stat(path), this is immune to inode substitution after open.
            let meta = file.metadata().context("Failed to stat authentication cache")?;

            if meta.uid() != 0 {
                crate::audit::log_security(&format!(
                    "cache {} has invalid owner uid={}",
                    cache_file.display(),
                    meta.uid()
                ));
                return Err(anyhow::anyhow!(
                    "Security: cache file is not owned by root — possible tampering"
                ));
            }

            // Reject non-regular files (FIFOs, devices, etc.).
            if meta.mode() & libc::S_IFMT != libc::S_IFREG {
                crate::audit::log_security(&format!(
                    "cache {} is not a regular file (mode={:#o})",
                    cache_file.display(),
                    meta.mode()
                ));
                return Err(anyhow::anyhow!(
                    "Security: cache is not a regular file"
                ));
            }

            Ok(Some(file))
        }
    }
}
