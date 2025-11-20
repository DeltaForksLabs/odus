mod cli;
mod config;
mod rules;
mod auth;
mod security;
mod exec;

use anyhow::Result;

fn main() -> Result<()> {
    let args = cli::parse()?;
    // Garantias básicas de segurança e criação de defaults
    config::ensure_default_and_perms(&args.config_path)?;
    // Tenta garantir serviço PAM 'odus' com fallback inteligente
    auth::ensure_pam_service()?;
    // Carrega config e regras
    let cfg = config::load(&args.config_path)?;
    let rule = rules::match_rule(&cfg, &args.command)?;
    // Autenticação (cache, PAM)
    auth::authenticate(&cfg, &rule)?;
    // Execução como root
    exec::run_as_root(&args.command, &cfg)?;
    Ok(())
}