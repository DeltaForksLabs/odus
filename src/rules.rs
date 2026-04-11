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

struct RuleSpec<'a> {
    user: Option<&'a str>,
    group: Option<&'a str>,
    cmd: &'a str,
}

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

    let current_user = uzers::get_current_username().unwrap_or_default();
    let user_obj = uzers::get_user_by_name(current_user.to_string_lossy().as_ref())
        .context("Failed to look up current user in the system database")?;
    let user_groups = user_obj.groups().unwrap_or_default();

    for (idx, rule_val) in rules.iter().enumerate() {
        let rule = parse_rule(rule_val, idx)?;

        let user_match = rule
            .user
            .is_some_and(|u| u == current_user.to_string_lossy());

        let group_match = rule
            .group
            .is_some_and(|g| user_groups.iter().any(|grp| grp.name() == OsStr::new(g)));

        let cmd_match = matches_rule_command(rule.cmd, &command[0], resolved_command);

        if (user_match || group_match) && cmd_match {
            return Ok(rule_val.clone());
        }
    }

    crate::audit::log_denied(&current_user.to_string_lossy(), command);
    eprintln!(
        "odus: permission denied for {}.",
        current_user.to_string_lossy()
    );
    Err(anyhow::anyhow!("Permission denied"))
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

/// Parses a raw TOML rule entry into validated string fields.
fn parse_rule<'a>(rule_val: &'a Value, index: usize) -> Result<RuleSpec<'a>> {
    let rule = rule_val
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Rule {} is invalid: expected a TOML table", index + 1))?;

    let user = optional_string_field(rule, "user", index)?;
    let group = optional_string_field(rule, "group", index)?;
    let cmd = required_string_field(rule, "cmd", index)?;

    validate_rule_command(cmd, index)?;

    Ok(RuleSpec { user, group, cmd })
}

/// Reads an optional string field from a rule and fails closed on type mismatches.
fn optional_string_field<'a>(
    rule: &'a toml::map::Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<Option<&'a str>> {
    match rule.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("Rule {} has invalid '{}' field", index + 1, field)),
    }
}

/// Reads a required string field from a rule and reports a precise configuration error.
fn required_string_field<'a>(
    rule: &'a toml::map::Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<&'a str> {
    optional_string_field(rule, field, index)?
        .ok_or_else(|| anyhow::anyhow!("Rule {} is missing required '{}' field", index + 1, field))
}

/// Validates rule command syntax before the match logic is evaluated.
///
/// This keeps malformed or ambiguous rules from silently authorising access.
fn validate_rule_command(cmd: &str, index: usize) -> Result<()> {
    if cmd.is_empty() {
        return Err(anyhow::anyhow!(
            "Rule {} has an empty 'cmd' field",
            index + 1
        ));
    }

    if cmd == "*" {
        return Err(anyhow::anyhow!(
            "Rule {} must use 'ALL' for full command access, not '*'",
            index + 1
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_for_current_user(cmd: &str) -> Value {
        let user = uzers::get_current_username()
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

    #[test]
    fn missing_cmd_field_is_rejected() {
        let user = uzers::get_current_username()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let cfg: Value = toml::from_str(&format!(
            r#"
                [[rules]]
                user = "{user}"
            "#
        ))
        .unwrap();
        let command = vec!["ls".to_string()];

        assert!(match_rule(&cfg, &command, "/bin/ls").is_err());
    }

    #[test]
    fn non_string_cmd_field_is_rejected() {
        let user = uzers::get_current_username()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let cfg: Value = toml::from_str(&format!(
            r#"
                [[rules]]
                user = "{user}"
                cmd = 42
            "#
        ))
        .unwrap();
        let command = vec!["ls".to_string()];

        assert!(match_rule(&cfg, &command, "/bin/ls").is_err());
    }

    #[test]
    fn bare_star_cmd_is_rejected() {
        let user = uzers::get_current_username()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let cfg: Value = toml::from_str(&format!(
            r#"
                [[rules]]
                user = "{user}"
                cmd = "*"
            "#
        ))
        .unwrap();
        let command = vec!["ls".to_string()];

        assert!(match_rule(&cfg, &command, "/bin/ls").is_err());
    }
}
