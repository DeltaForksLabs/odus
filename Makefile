# Makefile — odus build, install and uninstall
#
# Targets:
#   make              → build release binary
#   make install      → build + install with correct ownership and setuid bit
#   make uninstall    → remove installed binary
#   make clean        → remove build artifacts
#   make check        → cargo audit + clippy
#
# Override cargo path if needed:
#   CARGO=/path/to/cargo make

# ─── Cargo / rustup detection ────────────────────────────────────────────────
# Three problems solved here:
#
# 1. make runs /bin/sh with a minimal PATH — ~/.cargo/bin is not included.
# 2. Under 'sudo', HOME becomes /root, hiding the real user's ~/.cargo.
# 3. cargo may exist as a rustup shim with no default toolchain configured,
#    causing "rustup could not choose a version of cargo to run".
#
# CARGO can be overridden on the command line: CARGO=/path/to/cargo make

ifeq ($(origin CARGO),undefined)

# Identify the invoking user regardless of whether sudo was used
_WHOAMI     := $(or $(SUDO_USER),$(LOGNAME),$(USER))
# Read home from passwd — reliable even under sudo (HOME may be /root)
_REAL_HOME  := $(shell getent passwd "$(_WHOAMI)" 2>/dev/null | cut -d: -f6)
_RUSTUP_BIN := $(_REAL_HOME)/.cargo/bin

CARGO := $(shell \
	{ [ -x "$(_RUSTUP_BIN)/cargo" ] && echo "$(_RUSTUP_BIN)/cargo"; } \
	|| command -v cargo 2>/dev/null \
	|| { [ -x "/usr/local/bin/cargo" ] && echo "/usr/local/bin/cargo"; } \
	|| { [ -x "/usr/bin/cargo" ] && echo "/usr/bin/cargo"; })

ifeq ($(CARGO),)
$(error cargo not found for user '$(_WHOAMI)' (home: $(_REAL_HOME)). \
Install Rust via https://rustup.rs or run: CARGO=/path/to/cargo make)
endif

endif # CARGO override

# Diretório real onde estão cargo/rustc/rustup
CARGO_BIN_DIR := $(patsubst %/,%,$(dir $(CARGO)))

# Garante que o cargo consiga encontrar rustc/rustdoc/rustup,
# mesmo quando o make ou o sudo usam um PATH mínimo.
export PATH := $(CARGO_BIN_DIR):$(PATH)

# Mantém rustup/cargo apontando para a instalação do usuário real,
# inclusive quando o make for executado com sudo.
ifneq ($(_REAL_HOME),)
export CARGO_HOME := $(_REAL_HOME)/.cargo
export RUSTUP_HOME := $(_REAL_HOME)/.rustup
endif

# Localiza o rustup ao lado do cargo
_RUSTUP := $(CARGO_BIN_DIR)/rustup

# ─── Toolchain check ─────────────────────────────────────────────────────────
# If rustup is present but no default toolchain is set, install stable now.
# This runs once at Makefile parse time and is a no-op if stable is already set.
_TOOLCHAIN_OK := $(shell \
	if [ -x "$(_RUSTUP)" ]; then \
		"$(_RUSTUP)" show active-toolchain >/dev/null 2>&1 && echo "ok"; \
	else \
		echo "ok"; \
	fi)

ifneq ($(_TOOLCHAIN_OK),ok)
$(info [*] No default rustup toolchain found. Installing stable...)
$(shell "$(_RUSTUP)" default stable >/dev/tty 2>&1)
endif

# ─── Configuration ───────────────────────────────────────────────────────────

BINARY      := odus
INSTALL_DIR := $(DESTDIR)/usr/local/bin
TARGET      := target/release/$(BINARY)
CONF_DIR    := /etc/odus.toml
COMPL_BASE  := $(DESTDIR)/usr/local/share
BASH_COMPL   := $(COMPL_BASE)/bash-completion/completions/$(BINARY)
ZSH_COMPL    := $(COMPL_BASE)/zsh/site-functions/_$(BINARY)
FISH_COMPL   := $(COMPL_BASE)/fish/vendor_completions.d/$(BINARY).fish

# ─── Phony targets ───────────────────────────────────────────────────────────

.PHONY: all build install uninstall clean check install-completions uninstall-completions

all: build

# ─── Build ───────────────────────────────────────────────────────────────────

build:
	@echo "[*] Using cargo: $(CARGO)"
	@echo "[*] Building $(BINARY) (release)..."
	"$(CARGO)" build --release
	@echo "[✓] Binary ready at $(TARGET)"

# ─── Install ─────────────────────────────────────────────────────────────────

install: build
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "[!] Installation requires root. Run: sudo make install"; \
		exit 1; \
	fi
	@echo "[*] Installing $(BINARY) to $(INSTALL_DIR)..."
	install -d "$(INSTALL_DIR)"
	install -m 4755 -o root -g root "$(TARGET)" "$(INSTALL_DIR)/$(BINARY)"
	@echo "[✓] Installed: $(INSTALL_DIR)/$(BINARY)"
	@ls -lha "$(INSTALL_DIR)/$(BINARY)"
	@if [ ! -f /etc/odus.toml ]; then \
		echo "[i] /etc/odus.toml not found — odus will create a default on first run."; \
	fi
	@echo "[*] Installing shell completions..."
	@install -d "$(dir $(BASH_COMPL))" 2>/dev/null && \
		install -m 0644 completions/odus.bash "$(BASH_COMPL)" && \
		echo " ✓  bash → $(BASH_COMPL)"
	@install -d "$(dir $(ZSH_COMPL))" 2>/dev/null && \
		install -m 0644 completions/_odus "$(ZSH_COMPL)" && \
		echo " ✓  zsh  → $(ZSH_COMPL)"
	@install -d "$(dir $(FISH_COMPL))" 2>/dev/null && \
		install -m 0644 completions/odus.fish "$(FISH_COMPL)" && \
		echo " ✓  fish → $(FISH_COMPL)"
	@echo "[✓] Installation complete."

# ─── Uninstall ───────────────────────────────────────────────────────────────

uninstall:
	@if [ "$$(id -u)" -ne 0 ]; then \
	    echo "[!] Uninstall requires root privileges. Run: sudo make uninstall"; \
		exit 1; \
	fi
	@echo "[*] Uninstalling $(BINARY)..."
	@if [ -e "$(INSTALL_DIR)/$(BINARY)" ]; then \
		rm -f "$(INSTALL_DIR)/$(BINARY)"; \
		echo " ✓  Removed $(INSTALL_DIR)/$(BINARY)"; \
	else \
		echo "[i] $(INSTALL_DIR)/$(BINARY) not found. Skipping."; \
	fi
	@echo "[*] Removing configuration..."
	@if [ -e "$(CONF_DIR)" ]; then \
		rm -rf "$(CONF_DIR)"; \
		echo " ✓  Removed $(CONF_DIR)"; \
	else \
		echo "[i] $(CONF_DIR) not found. Skipping."; \
	fi
	@echo "[*] Removing shell completions..."
	@rm -f "$(BASH_COMPL)" 2>/dev/null && echo " ✓  Removed $(BASH_COMPL)" || true
	@rm -f "$(ZSH_COMPL)"  2>/dev/null && echo " ✓  Removed $(ZSH_COMPL)" || true
	@rm -f "$(FISH_COMPL)" 2>/dev/null && echo " ✓  Removed $(FISH_COMPL)" || true
	@echo "[✓] Uninstallation complete."

# ─── Clean ───────────────────────────────────────────────────────────────────

clean:
	@echo "[*] Cleaning build artifacts..."
	"$(CARGO)" clean
	@echo "[✓] Done."

# ─── Check ───────────────────────────────────────────────────────────────────

check:
	@echo "[*] Running security and code quality checks..."
	@if ! $(CARGO) audit --help >/dev/null 2>&1; then \
		echo "[!] cargo-audit is not installed."; \
		echo "    Install it with: cargo install cargo-audit"; \
		exit 1; \
	fi
	@echo "[*] Scanning dependencies for vulnerabilities..."
	@$(CARGO) audit
	@echo "[*] Running clippy lints..."
	@if ! $(CARGO) clippy --help >/dev/null 2>&1; then \
		echo "[!] cargo-clippy is not installed."; \
		echo "    Install it with: rustup component add clippy"; \
		exit 1; \
	fi
	@$(CARGO) clippy -- -D warnings
	@echo "[✓] All checks completed successfully."

# ─── Shell completions ────────────────────────────────────────────────────────

install-completions:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "[!] Installing completions requires root. Run: sudo make install-completions"; \
		exit 1; \
	fi
	@echo "[*] Installing shell completions..."
	@install -d "$(dir $(BASH_COMPL))"; \
		install -m 0644 completions/odus.bash "$(BASH_COMPL)"; \
		echo " ✓  bash → $(BASH_COMPL)"
	@install -d "$(dir $(ZSH_COMPL))"; \
		install -m 0644 completions/_odus "$(ZSH_COMPL)"; \
		echo " ✓  zsh  → $(ZSH_COMPL)"
	@install -d "$(dir $(FISH_COMPL))"; \
		install -m 0644 completions/odus.fish "$(FISH_COMPL)"; \
		echo " ✓  fish → $(FISH_COMPL)"
	@echo "[✓] Shell completions installed."

uninstall-completions:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "[!] Removing completions requires root. Run: sudo make uninstall-completions"; \
		exit 1; \
	fi
	@echo "[*] Removing shell completions..."
	@rm -f "$(BASH_COMPL)" 2>/dev/null && echo " ✓  Removed $(BASH_COMPL)" || true
	@rm -f "$(ZSH_COMPL)"  2>/dev/null && echo " ✓  Removed $(ZSH_COMPL)" || true
	@rm -f "$(FISH_COMPL)" 2>/dev/null && echo " ✓  Removed $(FISH_COMPL)" || true
	@echo "[✓] Shell completions removed."
