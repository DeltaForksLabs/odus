use anyhow::{Result};
use pico_args::Arguments;
use std::path::PathBuf;

pub struct Args {
    pub config_path: PathBuf,
    pub command: Vec<String>,
}

pub fn parse() -> Result<Args> {
    let mut pars = Arguments::from_env();
    if pars.contains("--help") || pars.contains("-h") {
        println!("odus: Simple privilege escalation tool\nUsage: odus [--config <path>] <command> [args]\nDefault config: /etc/odus.toml");
        std::process::exit(0);
    }
    let config_path_str: String = pars.opt_value_from_str("--config")?.unwrap_or("/etc/odus.toml".to_string());
    let remaining = pars.finish();
    if remaining.is_empty() {
        eprintln!("Erro: Nenhum comando fornecido. Use --help para mais informações.");
        return Err(anyhow::anyhow!("No command provided"));
    }
    let command: Vec<String> = remaining.into_iter().map(|s| s.into_string().unwrap()).collect();
    Ok(Args {
        config_path: PathBuf::from(config_path_str),
        command,
    })
}