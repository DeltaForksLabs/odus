# Makefile — odus build, install and uninstall
#
# Targets:
#   make              → build release binary
#   make install      → build + install to $(DESTDIR)/usr/local/bin with correct ownership
#   make uninstall    → remove installed binary
#   make clean        → remove build artifacts

# ─── Configuration ───────────────────────────────────────────────────────────

BINARY      := odus
INSTALL_DIR := $(DESTDIR)/usr/local/bin
TARGET      := target/release/$(BINARY)

# Detect OS for platform-specific messages
UNAME := $(shell uname -s)

# ─── Phony targets ───────────────────────────────────────────────────────────

.PHONY: all build install uninstall clean check

# ─── Default ─────────────────────────────────────────────────────────────────

all: build

# ─── Build ───────────────────────────────────────────────────────────────────

build:
	@echo "[*] Building $(BINARY) (release)..."
	cargo build --release
	@echo "[✓] Binary ready at $(TARGET)"

# ─── Install ─────────────────────────────────────────────────────────────────

install: build
	@# Require root for chown and setuid
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "[!] Installation requires root. Run: sudo make install"; \
		exit 1; \
	fi

	@echo "[*] Installing $(BINARY) to $(INSTALL_DIR)..."
	install -d $(INSTALL_DIR)

	@# Copy binary (strips setuid temporarily during copy)
	install -m 0755 $(TARGET) $(INSTALL_DIR)/$(BINARY)

	@# Set root ownership
	chown root:root $(INSTALL_DIR)/$(BINARY)

	@# Activate setuid bit — required for privilege escalation
	chmod u+s $(INSTALL_DIR)/$(BINARY)

	@echo "[✓] Installed: $(INSTALL_DIR)/$(BINARY)"
	@ls -la $(INSTALL_DIR)/$(BINARY)

	@# Warn if /etc/odus.toml is missing (odus will create it on first run)
	@if [ ! -f /etc/odus.toml ]; then \
		echo "[i] /etc/odus.toml not found — odus will create a default on first run."; \
	fi

# ─── Uninstall ───────────────────────────────────────────────────────────────

uninstall:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "[!] Uninstall requires root. Run: sudo make uninstall"; \
		exit 1; \
	fi

	@if [ -f $(INSTALL_DIR)/$(BINARY) ]; then \
		rm -f $(INSTALL_DIR)/$(BINARY); \
		echo "[✓] Removed $(INSTALL_DIR)/$(BINARY)"; \
	else \
		echo "[i] $(INSTALL_DIR)/$(BINARY) not found, nothing to remove."; \
	fi

# ─── Clean ───────────────────────────────────────────────────────────────────

clean:
	@echo "[*] Cleaning build artifacts..."
	cargo clean
	@echo "[✓] Done."

# ─── Check ───────────────────────────────────────────────────────────────────

check:
	@echo "[*] Running cargo audit..."
	cargo audit
	@echo "[*] Running clippy..."
	cargo clippy -- -D warnings
