use anyhow::{Context, Result};
use std::fs::{write, File};
use std::path::Path;
use nix::unistd::{chown, Uid, Gid};
use nix::sys::stat::{fchmod, Mode};
use std::os::unix::io::AsRawFd;
use toml::Value;

const CONFIG_MODE: Mode = Mode::from_bits_truncate(0o600);

pub fn ensure_default_and_perms(config_path: &Path) -> Result<()> {
    if !config_path.exists() {
        let default_config = r#"
cache_timeout = 15
secure_path = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin/", "/usr/local/sbin"]

[[rules]]
group = "wheel"
cmd = "ALL"
nopasswd = false
"#;
        write(config_path, default_config).context("Falha ao criar config default")?;
        chown(config_path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).context("Falha ao setar owner root na config")?;
        let cfg_file = File::open(config_path).context("Abrir config para chmod")?;
        fchmod(cfg_file.as_raw_fd(), CONFIG_MODE).context("Falha ao setar permissões na config")?;
        println!("Configuração default criada em {}. Ajuste conforme necessário.", config_path.display());
    }

    let config_stat = nix::sys::stat::stat(config_path).context("Falha ao stat config")?;
    if Uid::from_raw(config_stat.st_uid) != Uid::from_raw(0) || Gid::from_raw(config_stat.st_gid) != Gid::from_raw(0) {
        eprintln!("Erro de segurança: Config {} deve ser root-owned.", config_path.display());
        return Err(anyhow::anyhow!("Config not root-owned"));
    }
    if config_stat.st_mode & 0o077 != 0 {
        eprintln!("Erro de segurança: Config {} deve ter permissões 0600.", config_path.display());
        return Err(anyhow::anyhow!("Invalid config permissions"));
    }
    Ok(())
}

pub fn load(config_path: &Path) -> Result<Value> {
    let config_str = std::fs::read_to_string(config_path).context("Falha ao ler config")?;
    config_str.parse::<Value>().context("Falha ao parse TOML")
}