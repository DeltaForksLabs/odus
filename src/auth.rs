use crate::security::verify_cache_security;
use anyhow::{Context, Result};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{Gid, Uid, fchown};
use pam::Authenticator;
use rpassword;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Read, Write as IoWrite, stdout};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};
use toml::Value;

const PAM_SERVICE_DEFAULT: &str = "odus";

pub fn ensure_pam_service() -> Result<()> {
    let tmp_pam_path_odus = &format!("/etc/pam.d/{}", PAM_SERVICE_DEFAULT);
    let pam_path_odus = Path::new(tmp_pam_path_odus);
    if !pam_path_odus.exists() {
        println!("[*] Criando arquivo PAM odus!");
        #[cfg(target_os = "linux")]
        const PAM_ODUS_CONTENT: &str = r#"#%PAM-1.0
# Configuração PAM para ODUS (Linux)

# Define limites do usuário (arquivos abertos, memória, etc)
session    required   pam_limits.so

# Configura variáveis de ambiente (LANG, etc) - Exclusivo Linux
session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0

# Inclui a pilha padrão do sistema (Melhor prática no Linux)
# Isso garante integração com LDAP, Active Directory, Systemd, etc.
@include common-auth
@include common-account
@include common-session-noninteractive
"#;
        #[cfg(target_os = "freebsd")]
        const PAM_ODUS_CONTENT: &str = r#"# PAM configuration for ODUS (FreeBSD)        
# Autenticação: Delega para a configuração do sistema
# Isso garante que métodos como OPIE ou TACACS+ funcionem se configurados no host
auth       include      system

# Gerenciamento de conta (expiração, bloqueio)
account    include      system

# Sessão
# pam_lastlog é problemático em serviços tipo sudo no FreeBSD,
# então usamos pam_permit.so para satisfazer a exigência de sessão.
session    required     pam_permit.so

# Senha (caso seja necessário trocar, usa o sistema)
password   include      system
"#;
        
        let mut odus_file = File::create(pam_path_odus).with_context(|| {
            format!("Falha ao criar o arquivo em {}", pam_path_odus.display())
        })?;

        odus_file
            .write_all(PAM_ODUS_CONTENT.as_bytes())
            .with_context(|| {
                format!("Falha ao escrever conteúdo em {}", pam_path_odus.display())
            })?;

        configure_pam_file_permissions(pam_path_odus)?;
    } else {
        let md = std::fs::metadata(pam_path_odus).context("Stat PAM")?;
        if md.uid() != 0 || md.gid() != 0 {
            eprintln!("Erro: {} deve ser root:root.", pam_path_odus.display());
            return Err(anyhow::anyhow!("PAM not root-owned"));
        }
    }
    Ok(())
}

pub fn authenticate(cfg: &Value, rule: &Value) -> Result<()> {
    let nopasswd = rule
        .as_table()
        .and_then(|m| m.get("nopasswd").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let cache_timeout_min = cfg
        .get("cache_timeout")
        .and_then(|v| v.as_integer())
        .unwrap_or(15) as u64;
    let current_user = users::get_current_username().unwrap_or_default();
    let cache_dir = Path::new("/var/run/odus/ts");
    create_dir_all(cache_dir).context("Falha ao criar cache dir")?;
    let cache_file = cache_dir.join(current_user.to_string_lossy().as_ref());

    let auth_needed = needs_auth(&cache_file, cache_timeout_min)?;

    if !nopasswd {
        if auth_needed {
            eprint!("[odus] senha para {}: ", current_user.to_string_lossy());
            stdout().flush().ok();
            let password = rpassword::read_password().context("Falha ao ler senha")?;
            let mut pam_handle =
                Authenticator::with_password(PAM_SERVICE_DEFAULT).context("PAM init failed")?;
            pam_handle
                .get_handler()
                .set_credentials(current_user.to_string_lossy(), password);
            pam_handle.authenticate().context("Falha na autentificação, senha incorreta!")?;

            update_cache(&cache_file)?;
        }
    }
    Ok(())
}

pub fn needs_auth(cache_file: &Path, cache_timeout_min: u64) -> Result<bool> {
    verify_cache_security(cache_file)?;
    let mut auth_needed = true;
    if let Ok(mut file) = OpenOptions::new().read(true).open(&cache_file) {
        let mut timestamp_str = String::new();
        file.read_to_string(&mut timestamp_str)
            .context("Falha ao ler cache de autenticação.")?;
        if let Ok(timestamp) = timestamp_str.trim().parse::<u64>() {
            let cached_time = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
            let cache_timeout = Duration::from_secs(cache_timeout_min * 60);
            if SystemTime::now()
                .duration_since(cached_time)
                .unwrap_or(Duration::MAX)
                < cache_timeout
            {
                println!("[*] Using cached credentials");
                auth_needed = false;
            }
        }
    }
    Ok(auth_needed)
}

pub fn update_cache(cache_file: &Path) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&cache_file)
        .context("Falha ao atualizar cache de autenticação.")?;
    file.write_all(now.to_string().as_bytes())
        .context("Failed to update cache")
}

pub fn configure_pam_file_permissions(file_src: &Path) -> Result<()> {
    if file_src.exists() {
        let root_uid = Some(Uid::from_raw(0));
        let root_gid = Some(Gid::from_raw(0));
        let file = File::open(file_src).context("Abrir PAM para chmod")?;
        let fd = file.as_raw_fd();
        fchown(fd, root_uid, root_gid).context("Falha ao chown PAM")?;
        fchmod(fd, Mode::from_bits_truncate(0o644)).context("Falha ao chmod PAM")?;
    } else {
        eprintln!("Arquivo não encontrado ou não existe!");
    }
    Ok(())
}
