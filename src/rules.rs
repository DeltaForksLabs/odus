// rules.rs — Authorisation rule matching
//
// Note (M3): the '*' wildcard in 'cmd' performs prefix matching
// (e.g. "/usr/bin/python*" matches any binary whose path starts with that
// prefix). Administrators should use exact paths whenever possible.
//
// FreeBSD note: the default config includes an 'operator' rule in addition
// to 'wheel'. The matching logic here is OS-agnostic; group membership is
// resolved by the 'users' crate against the system's group database.

use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::path::Path;
use toml::Value;

/// Finds the first rule in the configuration that authorises the current user
/// to run the requested command.
///
/// `command[0]` is the original user input and `resolved_command` is the
/// validated absolute executable path. Absolute rule entries are matched against
/// `resolved_command`; bare-name rules keep matching the original invocation.
pub fn match_rule(cfg: &Value, command: &[String], resolved_command: &str) -> Result<Value> {
    let rules = cfg.get("rules").and_then(|v| v.as_array()).ok_or_else(|| {
        eprintln!("odus: 'rules' key is missing or invalid in /etc/odus.toml");
        anyhow::anyhow!("Missing 'rules' in config")
    })?;

    let current_user = users::get_current_username().unwrap_or_default();
    let user_obj = users::get_user_by_name(current_user.to_string_lossy().as_ref())
        .context("Failed to look up current user in the system database")?;
    let user_groups = user_obj.groups().unwrap_or_default();

    let idx = rules
        .iter()
        .position(|rule_val| {
            let empty = toml::map::Map::new();
            let rule = rule_val.as_table().unwrap_or(&empty);

            let user_match = rule
                .get("user")
                .and_then(|u| u.as_str())
                .is_some_and(|u| u == current_user.to_string_lossy());

            let group_match = rule
                .get("group")
                .and_then(|g| g.as_str())
                .is_some_and(|g| user_groups.iter().any(|grp| grp.name() == OsStr::new(g)));

            let cmd_match = rule
                .get("cmd")
                .and_then(|c| c.as_str())
                .is_none_or(|c| matches_rule_command(c, &command[0], resolved_command));

            (user_match || group_match) && cmd_match
        })
        .ok_or_else(|| {
            crate::audit::log_denied(&current_user.to_string_lossy(), command);
            eprintln!(
                "odus: permission denied for {}.",
                current_user.to_string_lossy()
            );
            anyhow::anyhow!("Permission denied")
        })?;

    Ok(rules[idx].clone())
}

fn matches_rule_command(rule_cmd: &str, original_command: &str, resolved_command: &str) -> bool {
    if rule_cmd == "ALL" {
        return true;
    }

    let target = if Path::new(rule_cmd).is_absolute() {
        resolved_command
    } else {
        original_command
    };

    if let Some(prefix) = rule_cmd.strip_suffix('*') {
        target.starts_with(prefix)
    } else {
        target == rule_cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_for_current_user(cmd: &str) -> Value {
        let user = users::get_current_username()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        toml::from_str(&format!(
            r#"
                [[rules]]
                user = "{user}"
                cmd = "{cmd}"
            "#
        ))
        .unwrap()
    }

    #[test]
    fn absolute_rules_match_against_resolved_path() {
        let cfg = config_for_current_user("/bin/sh");
        let command = vec!["sh".to_string()];

        assert!(match_rule(&cfg, &command, "/bin/sh").is_ok());
    }

    #[test]
    fn absolute_wildcards_do_not_match_traversal_input_after_resolution() {
        let cfg = config_for_current_user("/usr/bin/*");
        let command = vec!["/usr/bin/../../bin/sh".to_string()];

        assert!(match_rule(&cfg, &command, "/bin/sh").is_err());
    }

    #[test]
    fn bare_name_rules_still_match_bare_invocations() {
        let cfg = config_for_current_user("ls");
        let command = vec!["ls".to_string()];

        assert!(match_rule(&cfg, &command, "/bin/ls").is_ok());
    }
}
