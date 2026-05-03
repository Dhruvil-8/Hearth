#!/usr/bin/env bash
#
# Hearth — Local Network Intelligence Daemon
# Install script for Debian/Ubuntu/Raspberry Pi OS
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/hearth/main/install.sh | sudo bash
#
# Or clone and run locally:
#   chmod +x install.sh && sudo ./install.sh
#

set -euo pipefail

HEARTH_VERSION="0.1.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/hearth"
DATA_DIR="/var/lib/hearth"

echo "============================================"
echo "  Hearth v${HEARTH_VERSION} Installer"
echo "  Local Network Intelligence Daemon"
echo "============================================"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

# Check OS
if [[ ! -f /etc/debian_version ]] && [[ ! -f /etc/arch-release ]]; then
    echo "WARNING: This installer is designed for Debian/Ubuntu/Raspberry Pi OS."
    echo "Continuing anyway — some steps may fail."
fi

echo "-> Step 1/6: Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq libpcap-dev cmake build-essential curl >/dev/null 2>&1
echo "   Done."

echo "-> Step 2/6: Installing Rust (if not present)..."
if command -v rustup &>/dev/null; then
    echo "   Rust already installed ($(rustc --version))"
else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    source "$HOME/.cargo/env"
    echo "   Rust installed ($(rustc --version))"
fi

echo "-> Step 3/6: Building Hearth from source..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/Cargo.toml" ]]; then
    cd "$SCRIPT_DIR"
else
    TMPDIR=$(mktemp -d)
    echo "   Cloning repository..."
    git clone --depth 1 https://github.com/YOUR_USERNAME/hearth.git "$TMPDIR/hearth"
    cd "$TMPDIR/hearth"
fi

cargo build --release --workspace 2>&1 | tail -5
echo "   Build complete."

echo "-> Step 4/6: Installing binaries..."
install -m 755 target/release/hearth "$INSTALL_DIR/hearth"
install -m 755 target/release/hearth-cli "$INSTALL_DIR/hearth-cli"
install -m 755 target/release/hearth-vad "$INSTALL_DIR/hearth-vad"
echo "   Binaries installed to $INSTALL_DIR"

echo "-> Step 5/6: Setting up configuration..."
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
if [[ ! -f "$CONFIG_DIR/hearth.toml" ]]; then
    # Auto-detect default interface
    DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)
    DEFAULT_IFACE=${DEFAULT_IFACE:-eth0}

    cat > "$CONFIG_DIR/hearth.toml" <<EOF
interface = "${DEFAULT_IFACE}"
dashboard_port = 7777
db_path = "${DATA_DIR}/hearth.db"
oui_db_path = "${DATA_DIR}/oui.csv"
geoip_db_path = "${DATA_DIR}/GeoLite2-Country.mmdb"

# Add device labels and rules:
# [[devices]]
# mac = "AA:BB:CC:DD:EE:FF"
# label = "Samsung TV"
# max_upload_per_hour_mb = 500.0
EOF
    echo "   Config written to $CONFIG_DIR/hearth.toml"
    echo "   Detected interface: $DEFAULT_IFACE"
else
    echo "   Config already exists (preserving)."
fi

echo "-> Step 6/6: Installing systemd service..."
cat > /etc/systemd/system/hearth.service <<EOF
[Unit]
Description=Hearth Network Intelligence Daemon
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/hearth --config ${CONFIG_DIR}/hearth.toml
Restart=on-failure
RestartSec=5s
User=root
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
WorkingDirectory=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hearth
echo "   systemd service installed and enabled."

echo ""
echo "============================================"
echo "  Hearth installed successfully."
echo "============================================"
echo ""
echo "  Start:   sudo systemctl start hearth"
echo "  Status:  sudo systemctl status hearth"
echo "  Logs:    sudo journalctl -u hearth -f"
echo "  CLI:     hearth-cli status"
echo "  Web:     http://$(hostname -I | awk '{print $1}'):7777"
echo ""
echo "  Config:  ${CONFIG_DIR}/hearth.toml"
echo "  Data:    ${DATA_DIR}/"
echo ""
