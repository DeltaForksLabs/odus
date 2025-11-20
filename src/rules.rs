use anyhow::{Context, Result};
use std::ffi::OsStr;
use toml::Value;

pub fn match_rule(cfg: &Value, command: &Vec<String>) -> Result<Value> {
    let rules_value = cfg.get("rules").and_then(|v| v.as_array()).ok_or_else(|| {
        eprintln!("Erro na configuração: 'rules' ausente ou inválida.");
        anyhow::anyhow!("Missing 'rules'")
    })?;

    let current_user = users::get_current_username().unwrap_or_default();
    let current_user_obj = users::get_user_by_name(current_user.to_string_lossy().as_ref()).context("Falha ao obter usuário")?;
    let user_groups = current_user_obj.groups().unwrap_or_default();

    let matching_index = rules_value.iter().position(|rule_val| {
        let binding = toml::map::Map::new();
        let rule_map = rule_val.as_table().unwrap_or(&binding);
        let user_match = rule_map.get("user").and_then(|u| u.as_str()).map_or(false, |u| u == current_user.to_string_lossy());
        let group_match = rule_map.get("group").and_then(|g| g.as_str()).map_or(false, |g| {
            user_groups.iter().any(|group| group.name() == OsStr::new(g))
        });
        let cmd_match = rule_map.get("cmd").and_then(|c| c.as_str()).map_or(true, |c| {
            if c == "ALL" {
                true
            } else if c.ends_with("*") {
                let prefix = &c[..c.len() - 1];
                command[0].starts_with(prefix)
            } else {
                command[0] == c
            }
        });
        (user_match || group_match) && cmd_match
    }).ok_or_else(|| {
        eprintln!("Permissão negada para {}. Verifique autorização.", current_user.to_string_lossy());
        anyhow::anyhow!("Permission denied")
    })?;

    Ok(rules_value[matching_index].clone())
}