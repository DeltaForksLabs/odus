mod audit;
mod cli;
mod config;
mod rules;
mod auth;
mod security;
mod exec;

use anyhow::Result;

fn main() -> Result<()> {
    // Initialise audit log (syslog LOG_AUTHPRIV/LOG_AUTH) before any operation.
    // LOG_NDELAY ensures the socket is opened now, before setuid() is called.
    audit::init();

    let args = cli::parse()?;

    // Security checks and default config creation (/etc/odus.toml, always).
    config::ensure_default_and_perms()?;

    // Ensure /etc/pam.d/odus exists and is owned by root.
    auth::ensure_pam_service()?;

    // Load and parse /etc/odus.toml.
    let cfg = config::load()?;

    // Find the rule that authorises the current user to run the command.
    let rule = rules::match_rule(&cfg, &args.command)?;

    // Authenticate via cache or PAM (audit logging included).
    auth::authenticate(&cfg, &rule, &args.command)?;

    // Replace the process image with the target command running as root.
    // This call never returns on success.
    exec::run_as_root(&args.command, &cfg)?;

    Ok(())
}
