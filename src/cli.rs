// cli.rs — Command-line argument parsing
//
// The --config flag was intentionally removed (security fix C1/A4).
// Setuid-root binaries must not accept arbitrary file paths from unprivileged
// callers — this is the primary vector for symlink attacks.
// The configuration file is always /etc/odus.toml.

use anyhow::Result;
use pico_args::Arguments;

pub struct Args {
    /// Command to execute as root: argv[0] followed by its arguments.
    pub command: Vec<String>,
}

pub fn parse() -> Result<Args> {
    let mut pars = Arguments::from_env();

    if pars.contains("--help") || pars.contains("-h") {
        eprintln!(
            "odus {}\n\
             Minimal privilege escalation tool\n\
             \n\
             USAGE: odus <command> [args...]\n\
             \n\
             CONFIG:    /etc/odus.toml  (root-owned, mode 0600)\n\
             AUDIT LOG: /var/log/auth.log (Linux) | /var/log/authlog (FreeBSD)",
            env!("CARGO_PKG_VERSION")
        );
        std::process::exit(0);
    }

    let remaining = pars.finish();

    if remaining.is_empty() {
        eprintln!("odus: no command provided. Use --help for usage.");
        return Err(anyhow::anyhow!("No command provided"));
    }

    let command: Vec<String> = remaining
        .into_iter()
        .map(|s| s.into_string().unwrap_or_default())
        .collect();

    Ok(Args { command })
}
