use anyhow::{Context, Result};
use std::path::Path;
use nix::sys::stat::stat;
use nix::unistd::{Uid};

pub fn verify_cache_security(cache_file: &Path) -> Result<()> {
    if cache_file.exists() {
        let cache_stat = stat(cache_file).context("Falha ao verificar cache")?;
        if Uid::from_raw(cache_stat.st_uid) != Uid::from_raw(0) {
            eprintln!("Cache ownership inválida; forçando nova autenticação.");
            return Err(anyhow::anyhow!("Invalid cache ownership"));
        }
    }
    Ok(())
}