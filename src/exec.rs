use anyhow::{Context, Result};
use nix::unistd::{execvp, setgid, setuid};
use nix::unistd::{Gid, Uid};
use std::ffi::CString;
use std::path::Path;
use toml::Value;

pub fn run_as_root(command: &Vec<String>, cfg: &Value) -> Result<()> {
    let secure_paths: Vec<String> = match cfg.get("secure_path") {
        Some(v) if v.is_array() => v.as_array().unwrap().iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
        Some(v) if v.is_str() => v.as_str().unwrap().split(':').map(|s| s.to_string()).collect(),
        _ => vec!["/usr/bin".into(), "/bin".into(), "/usr/sbin".into(), "/sbin".into(), "/usr/local/bin/".into(), "/usr/local/sbin".into()],
    };

    setgid(Gid::from_raw(0)).context("Failed to setgid")?;
    setuid(Uid::from_raw(0)).context("Failed to setuid")?;
    println!("[*] Executing command as root");

    let cmd0 = &command[0];
    let abs_cmd = if Path::new(cmd0).is_absolute() {
        cmd0.clone()
    } else {
        let mut found = None;
        for dir in &secure_paths {
            let candidate = Path::new(dir).join(cmd0);
            if candidate.exists() && candidate.is_file() {
                found = Some(candidate.to_string_lossy().to_string());
                break;
            }
        }
        found.ok_or_else(|| anyhow::anyhow!("Command '{}' not found in secure_path", cmd0))?
    };
    let cstr_cmd: Vec<CString> = std::iter::once(abs_cmd).chain(command.iter().skip(1).cloned()).map(|s| CString::new(s).unwrap()).collect();
    let res = execvp(&cstr_cmd[0], &cstr_cmd);
    match res {
        Ok(_) => unreachable!("execvp should not return on success"),
        Err(e) => Err(anyhow::anyhow!(e).context("Failed to exec")),
    }
}