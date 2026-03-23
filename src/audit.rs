// audit.rs — Security event logging via syslog(3) (facility LOG_AUTHPRIV / LOG_AUTH)
//
// All public functions are fully safe. The two unsafe blocks are confined to
// private helpers and are the minimum necessary for C FFI (openlog/syslog).
// There is no safe Rust equivalent for direct syslog calls.

use std::ffi::CString;

// Linux uses LOG_AUTHPRIV (private auth messages → /var/log/auth.log).
// FreeBSD's syslog does not expose LOG_AUTHPRIV; LOG_AUTH is the correct
// facility there (→ /var/log/authlog).
#[cfg(target_os = "linux")]
const FACILITY: libc::c_int = libc::LOG_AUTHPRIV;
#[cfg(not(target_os = "linux"))]
const FACILITY: libc::c_int = libc::LOG_AUTH;

/// Initialises syslog with identity "odus".
/// Must be called once at program start, before any log_* call.
pub fn init() {
    // SAFETY: openlog(3) requires a pointer to a NUL-terminated string that
    // remains valid for the lifetime of the program. We intentionally leak the
    // CString via std::mem::forget, which is the standard pattern for
    // single-process system utilities (see sudo, doas source).
    // LOG_NDELAY opens the socket immediately, before setuid() may restrict
    // the ability to (re-)connect to the syslog socket.
    let ident = CString::new("odus").expect("static string, never fails");
    unsafe {
        libc::openlog(
            ident.as_ptr(),
            libc::LOG_PID | libc::LOG_NDELAY,
            FACILITY,
        );
    }
    std::mem::forget(ident);
}

/// Logs a successful command execution as root.
pub fn log_exec(user: &str, command: &[String]) {
    let cmd = command.join(" ");
    syslog(libc::LOG_INFO, &format!("EXEC user={user} cmd=\"{cmd}\""));
}

/// Logs a successful PAM authentication.
pub fn log_auth_ok(user: &str) {
    syslog(libc::LOG_INFO, &format!("AUTH OK user={user}"));
}

/// Logs a valid cached credential reuse (no password prompt issued).
pub fn log_cache_hit(user: &str) {
    syslog(libc::LOG_INFO, &format!("CACHE HIT user={user}"));
}

/// Logs a failed authentication attempt (wrong password, PAM rejection, etc.).
pub fn log_auth_fail(user: &str, reason: &str) {
    syslog(libc::LOG_WARNING, &format!("AUTH FAIL user={user} reason={reason}"));
}

/// Logs an authorisation denial (no matching rule found for this user/command).
pub fn log_denied(user: &str, command: &[String]) {
    let cmd = command.join(" ");
    syslog(libc::LOG_WARNING, &format!("DENIED user={user} cmd=\"{cmd}\""));
}

/// Logs a security-relevant anomaly (tampered file, unexpected symlink, etc.).
pub fn log_security(detail: &str) {
    syslog(libc::LOG_WARNING, &format!("SECURITY {detail}"));
}

// ─── Private ────────────────────────────────────────────────────────────────

fn syslog(level: libc::c_int, msg: &str) {
    // Replace NUL bytes so the message is never silently truncated at the C layer.
    let sanitized = msg.replace('\0', "?");

    let (Ok(msg_c), Ok(fmt_c)) = (CString::new(sanitized), CString::new("%s")) else {
        return; // unreachable after NUL replacement, but handle gracefully
    };

    // SAFETY: syslog(3) is a C variadic function. We pass the literal "%s" as
    // the format string to prevent format-string injection even if `msg`
    // contains '%' characters. Both CStrings are valid for the duration of
    // this call and are not modified by syslog.
    unsafe {
        libc::syslog(FACILITY | level, fmt_c.as_ptr(), msg_c.as_ptr());
    }
}
