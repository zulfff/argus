#!/usr/bin/env bash
# ============================================================
# ARGUS Router Installer — One-Command Setup
# Usage: curl -sSL https://raw.githubusercontent.com/zulfff/argus/main/scripts/install-router.sh | sudo bash
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
BOLD='\033[1m'

INSTALL_DIR="/opt/argus"
CONFIG_DIR="/etc/argus"
LOG_DIR="/var/log/argus"
DATA_DIR="/opt/argus/data"
REPO="zulfff/argus"
VERSION="${ARGUS_VERSION:-latest}"

log()  { echo -e "${CYAN}[ARGUS]${NC} $1"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $1"; }
warn() { echo -e "${YELLOW}[ WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Pre-flight checks ──────────────────────────────────────
echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════╗"
echo -e "║     ARGUS Firewall — Router Installer         ║"
echo -e "╚══════════════════════════════════════════════╝${NC}\n"

[ "$(id -u)" -eq 0 ] || err "Must run as root. Use: curl ... | sudo bash"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  BIN_ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64) BIN_ARCH="aarch64-unknown-linux-gnu"  ;;
    *)       err "Unsupported architecture: $ARCH. Only x86_64 and aarch64 are supported." ;;
esac

OS=""
[ -f /etc/os-release ] && . /etc/os-release && OS="$ID"
case "$OS" in
    debian|ubuntu|vyos) ok "Detected: $OS $VERSION_ID" ;;
    *) err "Unsupported OS: $OS. Requires Debian, Ubuntu, or VyOS." ;;
esac

KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 4 ]; }; then
    warn "Kernel $(uname -r) is older than 5.4. eBPF features limited."
else
    ok "Kernel $(uname -r) — eBPF ready"
fi

# ── Install system dependencies (minimal) ─────────────────
log "Installing system dependencies..."
apt-get update -qq
DEPS="curl ca-certificates"
if [ "$OS" = "vyos" ]; then
    DEPS="$DEPS"
else
    DEPS="$DEPS build-essential pkg-config libssl-dev"
fi
apt-get install -y -qq $DEPS 2>/dev/null || true
# sqlx needs libpq for postgres feature at build time
apt-get install -y -qq libpq-dev 2>/dev/null || true
ok "System dependencies installed"

# ── Install Rust (only if building from source) ───────────
NEED_RUST=false
if [ "$VERSION" = "latest" ] || [ "$VERSION" = "main" ]; then
    NEED_RUST=true
fi

if $NEED_RUST; then
    if ! command -v cargo &>/dev/null; then
        log "Installing Rust toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>/dev/null
        . "$HOME/.cargo/env"
        ok "Rust $(rustc --version | awk '{print $2}') installed"
    else
        ok "Rust already installed: $(rustc --version | awk '{print $2}')"
    fi
fi

# ── Create directories ────────────────────────────────────
log "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
ok "Directories created"

# ── Download or build binaries ────────────────────────────
log "Setting up ARGUS binaries..."

if [ "$VERSION" = "latest" ] || [ "$VERSION" = "main" ]; then
    # Build from source
    if [ ! -d "$INSTALL_DIR/.git" ]; then
        log "Cloning repository..."
        git clone --depth 1 https://github.com/$REPO.git "$INSTALL_DIR" 2>/dev/null
    else
        log "Updating repository..."
        cd "$INSTALL_DIR" && git pull --ff-only origin main 2>/dev/null
    fi

    log "Building release binaries (this may take 5-10 minutes)..."
    cd "$INSTALL_DIR"
    cargo build --release --workspace --exclude argus-ebpf -q 2>&1 | tail -3
    cp target/release/argus-api /usr/local/bin/
    cp target/release/argus-cli /usr/local/bin/
    ok "Binaries built from source"

elif [ "$VERSION" = "system" ]; then
    # Use system Rust/cargo (already installed)
    if ! command -v argus-api &>/dev/null; then
        err "argus-api not found. Install with VERSION=latest first."
    fi
    ok "Using existing system installation"

else
    # Download pre-built release
    API_URL="https://github.com/$REPO/releases/download/$VERSION/argus-api-$BIN_ARCH"
    CLI_URL="https://github.com/$REPO/releases/download/$VERSION/argus-cli-$BIN_ARCH"

    log "Downloading argus-api $VERSION..."
    curl -sSL "$API_URL" -o /usr/local/bin/argus-api 2>/dev/null || err "Failed to download argus-api. Does release $VERSION exist?"
    chmod +x /usr/local/bin/argus-api

    log "Downloading argus-cli $VERSION..."
    curl -sSL "$CLI_URL" -o /usr/local/bin/argus-cli 2>/dev/null || err "Failed to download argus-cli. Does release $VERSION exist?"
    chmod +x /usr/local/bin/argus-cli

    ok "Binaries downloaded: argus-api, argus-cli ($VERSION)"
fi

# ── Generate secrets ──────────────────────────────────────
log "Generating secrets..."

if [ ! -f "$CONFIG_DIR/env" ]; then
    JWT_SECRET=$(openssl rand -base64 48 2>/dev/null || head -c32 /dev/urandom | base64)
    ADMIN_PASS=$(openssl rand -base64 16 2>/dev/null || head -c12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')

    cat > "$CONFIG_DIR/env" << EOF
# ARGUS Configuration — generated $(date)
ARGUS_JWT_SECRET=$JWT_SECRET
ARGUS_ADMIN_PASS=$ADMIN_PASS
ARGUS_ADMIN_USER=admin
RUST_LOG=argus=info
EOF

    chmod 600 "$CONFIG_DIR/env"
    ok "Secrets generated: $CONFIG_DIR/env"
    warn "ADMIN PASSWORD: $ADMIN_PASS  (save this!)"
else
    ok "Config already exists: $CONFIG_DIR/env"
    . "$CONFIG_DIR/env"
    if [ -n "${ARGUS_ADMIN_PASS:-}" ]; then
        warn "Existing admin password found"
    fi
fi

# ── Create system user ────────────────────────────────────
if ! id -u argus &>/dev/null; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" argus 2>/dev/null || true
    ok "User 'argus' created"
else
    ok "User 'argus' already exists"
fi

chown -R argus:argus "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR" 2>/dev/null || true

# ── Install systemd service ───────────────────────────────
log "Installing systemd service..."

SERVICE_FILE="/etc/systemd/system/argus-api.service"
if [ ! -f "$SERVICE_FILE" ]; then
    cat > "$SERVICE_FILE" << 'UNITEOF'
[Unit]
Description=ARGUS Firewall API Server
Documentation=https://github.com/zulfff/argus
After=network.target
Wants=network.target

[Service]
Type=simple
User=argus
Group=argus
WorkingDirectory=/opt/argus
ExecStart=/usr/local/bin/argus-api
Restart=always
RestartSec=5
EnvironmentFile=/etc/argus/env
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/argus/data /var/log/argus
PrivateTmp=yes
MemoryMax=256M
CPUQuota=150%
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNITEOF

    systemctl daemon-reload
    ok "Systemd service installed"
else
    ok "Systemd service already exists"
fi

# ── Health check timer ─────────────────────────────────────
TIMER_FILE="/etc/systemd/system/argus-health.timer"
if [ ! -f "$TIMER_FILE" ]; then
    cat > /etc/systemd/system/argus-health.service << 'EOF'
[Unit]
Description=ARGUS Self Health Check
After=argus-api.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/argus-cli --api-url http://127.0.0.1:8443 stats
User=argus
StandardOutput=journal
EOF

    cat > "$TIMER_FILE" << 'EOF'
[Unit]
Description=ARGUS Health Check Timer

[Timer]
OnBootSec=60s
OnUnitActiveSec=30s

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now argus-health.timer 2>/dev/null || true
    ok "Health check timer installed"
fi

# ── Start service ─────────────────────────────────────────
log "Starting ARGUS API..."
systemctl enable --now argus-api 2>/dev/null || true

sleep 2
if systemctl is-active --quiet argus-api; then
    ok "ARGUS API is running"
else
    warn "ARGUS API failed to start. Check: journalctl -u argus-api -n 20"
fi

# ── Verify ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗"
echo -e "║     ARGUS Installation Complete!              ║"
echo -e "╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  API URL:      ${CYAN}http://127.0.0.1:8443${NC}"
echo -e "  Metrics:      ${CYAN}http://127.0.0.1:8443/metrics${NC}"
echo -e "  Health:       ${CYAN}http://127.0.0.1:8443/health${NC}"
echo -e "  Login:        ${CYAN}http://127.0.0.1:8443/api/v1/auth/login${NC}"
echo ""

. "$CONFIG_DIR/env" 2>/dev/null || true
if [ -n "${ARGUS_ADMIN_PASS:-}" ]; then
    echo -e "  ${BOLD}Username:${NC} admin"
    echo -e "  ${BOLD}Password:${NC} ${YELLOW}$ARGUS_ADMIN_PASS${NC}"
    echo -e "  ${RED}Save this password! It won't be shown again.${NC}"
fi

echo ""
echo -e "  ${BOLD}Quick test:${NC}"
echo -e "    argus-cli stats"
echo -e "    curl http://127.0.0.1:8443/health"
echo ""
echo -e "  ${BOLD}View logs:${NC}"
echo -e "    journalctl -u argus-api -f"
echo ""
echo -e "  ${BOLD}Restart:${NC}"
echo -e "    systemctl restart argus-api"
echo ""
echo -e "  ${BOLD}Uninstall:${NC}"
echo -e "    curl -sSL https://raw.githubusercontent.com/zulfff/argus/main/scripts/uninstall.sh | sudo bash"
echo ""

# ── Optional: Open firewall rule ──────────────────────────
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    log "Opening port 8443 in ufw..."
    ufw allow 8443/tcp comment "ARGUS API" 2>/dev/null || true
    ok "Port 8443 opened"
fi

exit 0
