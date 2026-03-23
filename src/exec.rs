// exec.rs — Root command execution via execvp
//
// Security fixes applied:
//   M4: CString::new propagated via ? instead of unwrap()
//       — prevents panic on NUL bytes in arguments
//   I3: PATH is replaced with secure_path before execvp
//       — prevents child processes that call system()/popen() from using
//         the caller's untrusted PATH

use anyhow::{Context, Result};
use nix::unistd::{Gid, Uid, execvp, setgid, setuid};
use std::ffi::CString;
use std::path::Path;
use toml::Value;

/// Elevates to root (setgid + setuid) and replaces the process image with
/// `command` via execvp. Never returns on success.
pub fn run_as_root(command: &[String], cfg: &Value) -> Result<()> {
    let secure_paths = load_secure_paths(cfg);

    // Replace the inherited (user-controlled) PATH with the trusted secure_path.
    // Fix I3: any binary legitimately executed as root that internally calls
    // system(3) or popen(3) will resolve commands from trusted directories only.
    //
    // SAFETY: odus is strictly single-threaded. std::env::set_var is marked
    // unsafe in Rust 2024 because it is not thread-safe (concurrent reads from
    // other threads could observe a partially written env). There are no other
    // threads in this process at this point, so the operation is safe.
    unsafe {
        std::env::set_var("PATH", secure_paths.join(":"));
    }

    // setgid must precede setuid: after setuid(0) the process becomes root and
    // can always call setgid again, but the reverse ordering is safer practice.
    setgid(Gid::from_raw(0)).context("setgid to root failed")?;
    setuid(Uid::from_raw(0)).context("setuid to root failed")?;

    let cmd0 = &command[0];
    let abs_cmd = resolve_command(cmd0, &secure_paths)?;

    // Build the argv CString vector.
    // Fix M4: use ? instead of unwrap() — NUL bytes in arguments are invalid
    // in C strings and must be caught here rather than causing a panic.
    let cstr_args: Vec<CString> = std::iter::once(abs_cmd.clone())
        .chain(command.iter().skip(1).cloned())
        .map(|s| {
            CString::new(s).context("Command argument contains a NUL byte (\\0), which is invalid")
        })
        .collect::<Result<Vec<_>>>()?;

    match execvp(&cstr_args[0], &cstr_args) {
        Ok(_) => unreachable!("execvp does not return on success"),
        Err(e) => Err(anyhow::anyhow!(e).context(format!("execvp failed for '{abs_cmd}'"))),
    }
}

// ─── Private ────────────────────────────────────────────────────────────────

/// Loads the secure_path from config, accepting both TOML array and colon-separated string.
fn load_secure_paths(cfg: &Value) -> Vec<String> {
    match cfg.get("secure_path") {
        Some(v) if v.is_array() => v
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(v) if v.is_str() => v.as_str().unwrap().split(':').map(str::to_string).collect(),
        _ => vec![
            "/usr/bin".into(),
            "/bin".into(),
            "/usr/sbin".into(),
            "/sbin".into(),
            "/usr/local/bin".into(),
            "/usr/local/sbin".into(),
        ],
    }
}

/// Resolves `cmd` to an absolute path.
///
/// - Absolute paths are used as-is (existence verified by execvp).
/// - Relative names are searched in secure_path in order.
fn resolve_command(cmd: &str, secure_paths: &[String]) -> Result<String> {
    if Path::new(cmd).is_absolute() {
        return Ok(cmd.to_string());
    }

    for dir in secure_paths {
        let candidate = Path::new(dir).join(cmd);
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }

    Err(anyhow::anyhow!(
        "Command '{}' not found in secure_path {:?}",
        cmd,
        secure_paths
    ))
}
