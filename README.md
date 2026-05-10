# odus

Minimal privilege escalation tool for FreeBSD and Linux — a lightweight alternative to `sudo` and `doas`. A setuid-root binary that runs commands as root according to rules defined in `/etc/odus.toml`.

---

## Features

- **PAM authentication** — native Linux-PAM and OpenPAM integration
- **Credential caching** — per TTY session or time-based (1–60 min)
- **Flexible rules** — by user, group, exact command, or wildcard prefix (`/usr/bin/python*`)
- **Passwordless mode** — skip authentication for specific commands (`nopasswd = true`)
- **Syslog audit** — all security events logged to `LOG_AUTHPRIV` (Linux) / `LOG_AUTH` (FreeBSD)
- **PATH sanitization** — replaces user `PATH` with `secure_path` before `execve`
- **Anti-TOCTOU** — all file operations use `O_NOFOLLOW` + fstat on fd
- **In-memory wipe** — password buffer zeroed immediately after PAM use
- **Rate limiting** — 2-second cooldown between authentication attempts

---

## Installation

### Requirements

- FreeBSD (OpenPAM) or Linux (glibc)
- PAM libraries with development headers
- Rust stable toolchain ([rustup](https://rustup.rs))

### Build & install

```bash
make              # build target/release/odus
sudo make install # install to /usr/local/bin/odus, setuid-root
```

`make install` automatically creates `/etc/odus.toml` and `/etc/pam.d/odus` with sensible defaults.

### Uninstall

```bash
sudo make uninstall
```

---

## Configuration (`/etc/odus.toml`)

Created automatically on first run. Must be `root:root`, `0600`, regular file (symlinks rejected).

### Example

```toml
cache_timeout = 15
max_tries     = 3
secure_path   = [
    "/usr/bin", "/bin", "/usr/sbin",
    "/sbin", "/usr/local/bin", "/usr/local/sbin"
]

# Members of the 'wheel' group can run anything
[[rules]]
group = "wheel"
cmd   = "ALL"

# User 'deploy' can restart services without a password
[[rules]]
user     = "deploy"
cmd      = "systemctl"
nopasswd = true
```

### Rule fields

| Field      | Required | Description                                                      |
|------------|----------|------------------------------------------------------------------|
| `cmd`      | **Yes**  | Command. `"ALL"`, exact name, absolute path, or `*` wildcard.    |
| `user`     | No       | Username (exact). Omit to match any user.                        |
| `group`    | No       | Group name (exact). Omit to match any group.                     |
| `nopasswd` | No       | `true` to skip password prompt. Default: `false`.                |

Rules are evaluated top-down — first match wins.

### Global settings

| Key             | Type          | Default | Description                                                       |
|-----------------|---------------|---------|-------------------------------------------------------------------|
| `cache_timeout` | int           | `15`    | `-1` = session, `0` = always prompt, `1-60` = minutes (clamped).  |
| `max_tries`     | int           | `3`     | Password attempts before exit (clamped 1–10).                     |
| `secure_path`   | array/string  | 6 dirs  | Trusted directories for resolving bare command names.             |

---

## Usage

```bash
odus <command> [args...]
```

```bash
odus apt update
odus apt install nginx
```
OR
```bash
odus pkg update
odus systemctl restart nginx
odus --help
```

- `..` and `.` path segments are rejected.
- Bare names (`sh`, `ls`) are resolved through `secure_path` directories.

---

## Contributing / Feedback

Feedback, issue reports, experiments, and focused pull requests are welcome.

Good contributions should:

- Keep changes scoped and explain the technical impact.
- Preserve existing demos and tests.
- Add or update tests when behavior changes.
- Avoid unrelated formatting or refactors.
- Mention platform-specific rendering behavior when relevant.

The project is still moving quickly, so larger API changes should be discussed before implementation.

## License

Odus is licensed under either of:

- MIT License, see `LICENSE_MIT`.
- Apache License 2.0, see `LICENSE_APACHE_2.0`.

You may choose either license when using, modifying, or distributing the project.

## Credits

Built by Paulo Daniel <paulodanielpro@proton.me> and <https://github.com/DeltaForksLabs>.
