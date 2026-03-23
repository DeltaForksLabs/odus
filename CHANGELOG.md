# Changelog

All notable changes to odus are documented in this file.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---
## [0.2.1] - 2026-03-23

### Changed
- Cargo.toml - Updated to new versions of the dependencies!

### Added
- `CHANGELOG.md` — this file.

## [0.2.0] — 2026-03-22

### Security — Critical fixes

- **[C1] Symlink attack via `--config` (CWE-61, CWE-73)**  
  The `--config` flag was removed entirely. The configuration path is now a
  compile-time constant (`/etc/odus.toml`). Previously, an unprivileged user
  could pass an arbitrary path pointing to a symlink, causing the setuid-root
  process to overwrite any system file with the default config content.

- **[C2] TOCTOU on authentication cache (CWE-367)**  
  `verify_cache_security` + separate `open()` replaced by `open_and_verify_cache()`
  in `security.rs`. The new function opens the file with `O_NOFOLLOW`, then calls
  `fstat` on the open file descriptor. The verified inode and the read inode are
  now guaranteed to be the same — the TOCTOU window is eliminated entirely.

- **[C3] Cache file created without explicit permissions (CWE-732)**  
  `update_cache` now sets `mode(0o600)` on `OpenOptions` and confirms permissions
  via `fchown` + `fchmod` on the open fd. Previously, permissions depended on the
  process umask; a permissive umask (e.g. `0000`) produced a world-writable
  root-owned cache file, allowing any user to forge a valid timestamp and bypass
  authentication completely.

### Security — High fixes

- **[A1] Plaintext password retained in heap memory (CWE-316)**  
  Introduced `SensitiveString` — a `String` wrapper whose `Drop` implementation
  zeroes the heap buffer with `ptr::write_volatile` + `compiler_fence`. The unsafe
  is confined to that single `Drop` impl. No new dependency required.

- **[A2] No audit logging**  
  Added `audit.rs` module. Every security-relevant event is now written to syslog
  facility `LOG_AUTHPRIV` (Linux) / `LOG_AUTH` (FreeBSD) via `openlog`/`syslog`.
  Events logged: `EXEC`, `AUTH OK`, `CACHE HIT`, `AUTH FAIL`, `DENIED`, `SECURITY`.

- **[A3] `stat()` follows symlinks in security checks (CWE-61)**  
  All ownership and permission checks now use `lstat()` (does not follow symlinks)
  instead of `stat()`. Applies to config file, PAM service file, and cache directory.

- **[A4] `--config` flag accessible to unprivileged users (CWE-426)**  
  Resolved as part of C1 — flag removed entirely.

### Security — Medium fixes

- **[M1] TOCTOU on PAM service file creation (CWE-367)**  
  `ensure_pam_service` now uses `OpenOptions::create_new` (`O_CREAT|O_EXCL`) with
  `O_NOFOLLOW`. The check-then-create race window is fully eliminated.

- **[M2] TOCTOU on default config creation (CWE-367)**  
  `create_if_missing` now uses `OpenOptions::create_new` + `O_NOFOLLOW`.
  Same fix as M1, applied to config creation.

- **[M4] `unwrap()` on `CString::new` causes panic on NUL bytes (CWE-476)**  
  In `exec.rs`, `CString::new(s).unwrap()` replaced with `CString::new(s)?`.
  Arguments containing `\0` now return a proper error instead of aborting the
  process with a panic.

### Security — Low / Info fixes

- **[B4] `debug = "full"` conflicting with `strip = true` in release profile**  
  `debug = "full"` removed from `[profile.release]`. The combination could produce
  a production binary with full DWARF symbols, exposing function names and source
  paths.

- **[I3] Inherited `PATH` passed to root process**  
  `exec.rs` now calls `std::env::set_var("PATH", secure_paths.join(":"))` before
  `execvp`. Binaries legitimately executed as root that internally call `system(3)`
  or `popen(3)` will only resolve commands from trusted directories.

- **[I5] `incremental = true` in release profile**  
  Changed to `incremental = false` for reproducible release builds.

### Added

- `src/audit.rs` — new module; syslog-based security event logging.
- `Makefile` — automates `build`, `install` (with `chown` + `chmod u+s`),
  `uninstall`, `clean`, and `check` (audit + clippy) targets.
- `CHANGELOG.md` — this file.

### Changed

- `src/security.rs` — `verify_cache_security(path)` replaced by
  `open_and_verify_cache(path) -> Result<Option<File>>`. Returns the open `File`
  to the caller, eliminating any need to re-open by path.
- `src/config.rs` — `ensure_default_and_perms(config_path)` signature simplified
  to `ensure_default_and_perms()` (path is now internal constant).  
  `load(config_path)` simplified to `load()` for the same reason.  
  Added `operator` group rule to FreeBSD default config.
- `src/auth.rs` — `authenticate` signature gains `command: &[String]` parameter
  for audit logging. All `fchmod`/`fchown` calls migrated to `AsFd` API
  (nix 0.29) — `as_raw_fd()` no longer used.
- `src/exec.rs` — `command` parameter type narrowed from `&Vec<String>` to
  `&[String]`. PATH sanitisation added before `execvp`.
- `src/rules.rs` — `command` parameter type narrowed from `&Vec<String>` to
  `&[String]`.
- `src/main.rs` — `audit::init()` call added at startup. All call sites updated
  for the simplified `config` API.
- `Cargo.toml` — `libc` added as an explicit dependency (was transitive via nix).
  Version bumped to `0.2.0`. `incremental` set to `false` in release profile.
- All user-facing messages (errors, warnings, help text) translated to English.

### Removed

- `--config` CLI flag — see C1/A4 above.
- `split-debuginfo = "packed"` from release profile (redundant with `strip = true`).

---

## [0.1.0] — initial release

Initial implementation of odus: a minimal privilege escalation tool for Linux
and FreeBSD, providing sudo/doas-like functionality with PAM authentication,
credential caching, and a TOML-based rule configuration.
