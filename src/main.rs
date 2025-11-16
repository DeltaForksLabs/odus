use anyhow::{Context, Result};
use nix::unistd::{execvp, setuid, ROOT};
use pam::Authenticator;  // Para autenticação PAM
use pico_args::Arguments;
use rpassword;  // Para leitura de senha sem echo
use std::io::{self, Write};  // Adicionado para eprint!
use std::path::Path;
use users::{get_current_username, get_user_by_name};
use std::time::{Duration, SystemTime};  // Para gerenciamento de timestamp
use std::fs::{create_dir_all, OpenOptions};  // Para criação e escrita em arquivos de cache
use std::io::Read;  // Para leitura de timestamp
use nix::sys::stat::stat;  // Para verificação de permissões de arquivos
use nix::unistd::{Gid, Uid};  // Para checagem de owner
use toml::Value;  // Para parsing manual

fn main() -> Result<()> {
    let mut pars = Arguments::from_env();
    if pars.contains("--help") || pars.contains("-h") {
        println!("odus: Simple privilege escalation tool\nUsage: odus [--config <path>] <command> [args]\nDefault config: /etc/odus.toml");
        return Ok(());
    }
    let config_path_str: String = pars.opt_value_from_str("--config")?.unwrap_or("/etc/odus.toml".to_string());
    let remaining = pars.finish();
    if remaining.is_empty() {
        eprintln!("Erro: Nenhum comando fornecido. Use --help para mais informações.");
        return Err(anyhow::anyhow!("No command provided"));
    }
    let command: Vec<String> = remaining.into_iter().map(|s| s.into_string().unwrap()).collect();
    let config_path = Path::new(&config_path_str);

   // Cria config se não existir, com conteúdo default seguro (como root via setuid)
    if !config_path.exists() {
       let default_config = r#"
cache_timeout = 15

[[rules]]
group = "wheel"
cmd = "ALL"
nopasswd = false
       "#;
       std::fs::write(config_path, default_config).context("Falha ao criar config default")?;
       nix::unistd::chown(config_path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).context("Falha ao setar owner root na config")?;
       nix::sys::stat::fchmodat(None, config_path, nix::sys::stat::Mode::from_bits(0o600).unwrap(), nix::sys::stat::FchmodatFlags::FollowSymlink).context("Falha ao setar permissões 0600 na config")?;
       println!("Configuração default criada em {}. Ajuste conforme necessário.", config_path.display());
    }

    // Verificação de segurança: Config deve ser root-owned e 0600
    let config_stat = stat(config_path).context("Falha ao verificar permissões da config")?;

    if Uid::from_raw(config_stat.st_uid) != Uid::from_raw(0) || Gid::from_raw(config_stat.st_gid) != Gid::from_raw(0) {
        eprintln!("Erro de segurança: Arquivo de configuração {} deve ser de propriedade do root.", config_path.display());
        return Err(anyhow::anyhow!("Config not root-owned"));
    }
    if config_stat.st_mode & 0o077 != 0 {
        eprintln!("Erro de segurança: Arquivo de configuração {} deve ter permissões 0600 (somente leitura/escrita para root).", config_path.display());
        return Err(anyhow::anyhow!("Invalid config permissions"));
    }

    // Carrega config TOML manualmente com toml::Value
    let config_str = std::fs::read_to_string(config_path).context("Failed to read config")?;
    let config_value: Value = config_str.parse::<Value>().context("Failed to parse TOML")?;
    let rules_value = config_value.get("rules").and_then(|v| v.as_array()).ok_or_else(|| {
        eprintln!("Erro na configuração: Seção 'rules' ausente ou inválida em {}.", config_path.display());
        anyhow::anyhow!("Missing 'rules' array")
    })?;
    let cache_timeout_min = config_value.get("cache_timeout").and_then(|v| v.as_integer()).unwrap_or(15) as u64;

    // Verifica permissões
    let current_user = get_current_username().unwrap_or_default();
    let current_user_obj = get_user_by_name(current_user.to_string_lossy().as_ref()).context("Failed to get user")?;
    let user_groups = current_user_obj.groups().unwrap_or_default();  // Fallback para Vec vazia se None
    let matching_rule_index = rules_value.iter().position(|rule_val| {
        let binding_rule_map = &toml::map::Map::new();
        let rule_map = rule_val.as_table().unwrap_or(&binding_rule_map);
        let user_match = rule_map.get("user").and_then(|u| u.as_str()).map_or(false, |u| u == current_user.to_string_lossy());
        let group_match = rule_map.get("group").and_then(|g| g.as_str()).map_or(false, |g| {
            user_groups.iter().any(|group| group.name() == std::ffi::OsStr::new(g))
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
    });

    let rule_val = matching_rule_index.map(|i| &rules_value[i]).ok_or_else(|| {
        eprintln!("Permissão negada para usuário {}. Verifique se você está autorizado na configuração.", current_user.to_string_lossy());
        anyhow::anyhow!("Permission denied")
    })?;
    let rule_map = rule_val.as_table().ok_or(anyhow::anyhow!("Invalid rule format"))?;
    let nopasswd = rule_map.get("nopasswd").and_then(|v| v.as_bool()).unwrap_or(false);

    // Autenticação via senha se não for NOPASSWD
    let cache_dir = Path::new("/var/run/odus/ts");
    create_dir_all(cache_dir).context("Falha ao criar diretório de cache. Verifique permissões do sistema.")?;
    let cache_file = cache_dir.join(current_user.to_string_lossy().as_ref());
    let cache_timeout = Duration::from_secs(cache_timeout_min * 60);
    let mut auth_needed = true;

    if let Ok(mut file) = OpenOptions::new().read(true).open(&cache_file) {
        let mut timestamp_str = String::new();
        file.read_to_string(&mut timestamp_str).context("Falha ao ler cache de autenticação.")?;
        if let Ok(timestamp) = timestamp_str.trim().parse::<u64>() {
            let cached_time = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
            if SystemTime::now().duration_since(cached_time).unwrap_or(Duration::MAX) < cache_timeout {
                println!("Using cached credentials");
                auth_needed = false;
            }
        }
    }

    if !nopasswd {
       if auth_needed {
           eprint!("[odus] senha para {}: ", current_user.to_string_lossy());
           io::stdout().flush().ok();  // Garante que o prompt apareça imediatamente
           let password = rpassword::read_password().context("Failed to read password")?;
           // Verifica com PAM (serviço 'sudo' para segurança otimizada)
           let mut pam_handle = Authenticator::with_password("sudo").context("PAM init failed")?;
           pam_handle.get_handler().set_credentials(current_user.to_string_lossy(), password);
           pam_handle.authenticate().context("Falha na autenticação. Senha incorreta ou problema no PAM.")?;

           // Atualiza cache de timestamp
           let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();
           let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&cache_file).context("Falha ao atualizar cache de autenticação.")?;
           write!(file, "{}", now).context("Failed to update cache")?;
       }
    }

    println!("Executing command as root");
    setuid(ROOT).context("Failed to setuid")?;
    // Sanitize command path: Resolve to absolute if relative (security against path injection)
    let abs_cmd = if Path::new(&command[0]).is_relative() {
        std::env::current_dir().context("Falha ao obter diretório atual.")?.join(&command[0]).to_string_lossy().to_string()
    } else {
        command[0].clone()
    };
    let cstr_cmd: Vec<_> = std::iter::once(abs_cmd).chain(command.iter().skip(1).cloned()).map(|s| std::ffi::CString::new(s).unwrap()).collect();
    execvp(&cstr_cmd[0], &cstr_cmd).context("Failed to exec")?;

    Ok(())
}