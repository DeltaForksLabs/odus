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
use toml::Value;

/// Finds the first rule in the configuration that authorises the current user
/// to run `command[0]`. Returns the matched rule or a permission-denied error.
pub fn match_rule(cfg: &Value, command: &[String]) -> Result<Value> {
    let rules = cfg
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
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
                .map_or(false, |u| u == current_user.to_string_lossy());

            let group_match = rule
                .get("group")
                .and_then(|g| g.as_str())
                .map_or(false, |g| {
                    user_groups.iter().any(|grp| grp.name() == OsStr::new(g))
                });

            let cmd_match = rule
                .get("cmd")
                .and_then(|c| c.as_str())
                .map_or(true, |c| {
                    if c == "ALL" {
                        true
                    } else if c.ends_with('*') {
                        // Prefix match — see note M3 in the module comment above
                        let prefix = &c[..c.len() - 1];
                        command[0].starts_with(prefix)
                    } else {
                        command[0] == c
                    }
                });

            (user_match || group_match) && cmd_match
        })
        .ok_or_else(|| {
            crate::audit::log_denied(&current_user.to_string_lossy(), command);
            eprintln!("odus: permission denied for {}.", current_user.to_string_lossy());
            anyhow::anyhow!("Permission denied")
        })?;

    Ok(rules[idx].clone())
}
