// exec.rs — Root command execution via execvp
//
// Security fixes applied:
//   M4: CString::new propagated via ? instead of unwrap()
//       — prevents panic on NUL bytes in arguments
//   I3: PATH is replaced with secure_path before execvp
//       — prevents child processes that call system()/popen() from using
//         the caller's untrusted PATH

use anyhow::{Context, Result};
use nix::unistd::{Gid, Uid, execve, setgid, setgroups, setuid};
use std::path::{Component, Path, PathBuf};
use std::{ffi::CString, fs};
use toml::Value;

/// Resolves and validates the executable path before policy evaluation.
///
/// Security:
///   - absolute paths must already be normalised (no '.' or '..' segments)
///   - relative commands must be bare executable names, never subpaths
///   - secure_path entries must be absolute directories
pub fn prepare_command(command: &[String], cfg: &Value) -> Result<Vec<String>> {
    let secure_paths = load_secure_paths(cfg)?;
    let abs_cmd = resolve_command(&command[0], &secure_paths)?;

    let mut prepared = command.to_vec();
    prepared[0] = abs_cmd;
    Ok(prepared)
}

/// Elevates to root (setgid + setuid) and replaces the process image with
/// `command` via execvp. Never returns on success.
pub fn run_as_root(command: &[String], cfg: &Value) -> Result<()> {
    let secure_paths = load_secure_paths(cfg)?;

    // Replace the inherited (user-controlled) PATH with the trusted secure_path.
    // Fix I3: any binary legitimately executed as root that internally calls
    // system(3) or popen(3) will resolve commands from trusted directories only.
    //
    // SAFETY: odus is strictly single-threaded. std::env::set_var is marked
    // unsafe in Rust 2024 because it is not thread-safe (concurrent reads from
    // other threads could observe a partially written env). There are no other
    // threads in this process at this point, so the operation is safe.

    // Keep the original TERM if it exists and does not contain NUL; otherwise, omit it
    let term_entry = std::env::var("TERM")
        .ok()
        .and_then(|t| CString::new(format!("TERM={t}")).ok());

    let path_form = format!("PATH={}", secure_paths.join(":"));
    // Create a clean and safe environment
    let mut clean_environment: Vec<CString> = vec![
        CString::new(path_form).context("[!] secure_path contains a NULL byte!")?,
        CString::new("USER=root").unwrap(),
        CString::new("HOME=/root").unwrap(),
        CString::new("LOGNAME=root").unwrap(),
        CString::new("SHELL=/bin/sh").unwrap(),
    ]
    .into_iter()
    .collect();

    if let Some(term) = term_entry {
        clean_environment.push(term);
    }

    // setgid must precede setuid: after setuid(0) the process becomes root and
    // can always call setgid again, but the reverse ordering is safer practice.
    setgroups(&[Gid::from_raw(0)]).context("setgroups to root failed")?;
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

    match execve(&cstr_args[0], &cstr_args, &clean_environment) {
        Ok(_) => unreachable!("execve does not return on success"),
        Err(e) => Err(anyhow::anyhow!(e).context(format!("execve failed for '{abs_cmd}'"))),
    }
}

// ─── Private ────────────────────────────────────────────────────────────────

/// Loads the secure_path from config, accepting both TOML array and colon-separated string.
fn load_secure_paths(cfg: &Value) -> Result<Vec<String>> {
    let raw_paths = match cfg.get("secure_path") {
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
    };

    let secure_paths = raw_paths
        .into_iter()
        .map(|path| {
            normalize_absolute_path(Path::new(&path))
                .with_context(|| format!("Invalid secure_path entry '{path}'"))
        })
        .collect::<Result<Vec<_>>>()?;

    if secure_paths.is_empty() {
        return Err(anyhow::anyhow!(
            "secure_path must contain at least one absolute directory"
        ));
    }

    Ok(secure_paths)
}

/// Resolves `cmd` to an absolute path.
///
/// - Absolute paths are used as-is (existence verified by execvp).
/// - Relative names are searched in secure_path in order.
fn resolve_command(cmd: &str, secure_paths: &[String]) -> Result<String> {
    let cmd_path = Path::new(cmd);

    if cmd_path.is_absolute() {
        return normalize_absolute_path(cmd_path);
    }

    let bare_name = validate_relative_command(cmd_path)?;

    for dir in secure_paths {
        let candidate = Path::new(dir).join(&bare_name);
        // symlink_metadata (lstat) does NOT follow symlinks, unlike
        // is_file() which resolves them — prevents symlink-based
        // privilege escalation through secure_path entries.
        if let Ok(meta) = fs::symlink_metadata(&candidate) {
            if meta.is_file() && !meta.file_type().is_symlink() {
                return Ok(candidate.to_string_lossy().into_owned());
            }
        }
    }

    Err(anyhow::anyhow!(
        "Command '{}' not found in secure_path {:?}",
        cmd,
        secure_paths
    ))
}

fn normalize_absolute_path(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "Expected an absolute path, got '{}'",
            path.display()
        ));
    }

    let mut normalized = PathBuf::from("/");

    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::CurDir | Component::ParentDir => {
                return Err(anyhow::anyhow!(
                    "Command paths must not contain '.' or '..' segments: {}",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(anyhow::anyhow!(
                    "Unsupported path prefix in command path: {}",
                    path.display()
                ));
            }
        }
    }

    Ok(normalized.to_string_lossy().into_owned())
}

fn validate_relative_command(path: &Path) -> Result<String> {
    let mut components = path.components();

    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Ok(name.to_string_lossy().into_owned()),
        _ => Err(anyhow::anyhow!(
            "Relative commands must be bare executable names, not paths: {}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn config_with_secure_path(path: &Path) -> Value {
        toml::from_str(&format!(r#"secure_path = ["{}"]"#, path.display())).unwrap()
    }

    fn unique_temp_dir() -> PathBuf {
        let mut dir = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("odus-tests-{}-{stamp}", std::process::id()));
        dir
    }

    #[test]
    fn prepare_command_rejects_absolute_parent_segments() {
        let cfg: Value = toml::from_str(r#"secure_path = ["/usr/bin"]"#).unwrap();
        let command = vec!["/usr/bin/../../bin/sh".to_string()];

        assert!(prepare_command(&command, &cfg).is_err());
    }

    #[test]
    fn prepare_command_rejects_relative_subpaths() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();

        let cfg = config_with_secure_path(&dir);
        let command = vec!["bin/sh".to_string()];

        assert!(prepare_command(&command, &cfg).is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prepare_command_resolves_bare_names_from_secure_path() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();

        let binary = dir.join("tool");
        File::create(&binary).unwrap();

        let cfg = config_with_secure_path(&dir);
        let command = vec!["tool".to_string(), "--version".to_string()];
        let prepared = prepare_command(&command, &cfg).unwrap();

        assert_eq!(prepared[0], binary.to_string_lossy());
        assert_eq!(prepared[1], "--version");

        let _ = fs::remove_dir_all(dir);
    }
}
