#!/usr/bin/env bash
#
# dnsttui install script
# Usage:
#   bash <(curl -Ls https://raw.githubusercontent.com/sartoopjj/dnsttui/main/install.sh) [install|update|uninstall]
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO="sartoopjj/dnsttui"
BINARY_NAME="dnsttui"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/opt/dnsttui"
SERVICE_NAME="dnsttui"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)   echo "arm64" ;;
        *)               error "Unsupported architecture: $arch" ;;
    esac
}

detect_os() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os" in
        linux)  echo "linux" ;;
        *)      error "Unsupported OS: $os (only Linux is supported)" ;;
    esac
}

get_latest_version() {
    curl -sL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed -E 's/.*"([^"]+)".*/\1/'
}

download_binary() {
    local os arch version url tmp
    os=$(detect_os)
    arch=$(detect_arch)
    version=$(get_latest_version)

    if [[ -z "$version" ]]; then
        error "Could not determine latest version. Check your internet connection."
    fi

    url="https://github.com/${REPO}/releases/download/${version}/${BINARY_NAME}-${os}-${arch}"
    info "Downloading ${BINARY_NAME} ${version} for ${os}/${arch}..."

    tmp=$(mktemp)
    if ! curl -fSL -o "$tmp" "$url"; then
        rm -f "$tmp"
        error "Download failed. URL: $url"
    fi

    chmod +x "$tmp"
    mv "$tmp" "${INSTALL_DIR}/${BINARY_NAME}"
    info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

create_service() {
    mkdir -p "$DATA_DIR"

    # Ask for configuration
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━ Configuration ━━━━━━━━━━━${NC}"

    local admin_user admin_pass panel_port panel_domain tunnel_domain

    read -rp "$(echo -e "${GREEN}Admin username${NC}: ")" admin_user
    while [[ -z "$admin_user" ]]; do
        echo -e "${RED}Username cannot be empty${NC}"
        read -rp "$(echo -e "${GREEN}Admin username${NC}: ")" admin_user
    done

    read -srp "$(echo -e "${GREEN}Admin password${NC}: ")" admin_pass
    echo ""
    while [[ ${#admin_pass} -lt 6 ]]; do
        echo -e "${RED}Password must be at least 6 characters${NC}"
        read -srp "$(echo -e "${GREEN}Admin password${NC}: ")" admin_pass
        echo ""
    done

    read -rp "$(echo -e "${GREEN}Panel port${NC} [8080]: ")" panel_port
    panel_port="${panel_port:-8080}"

    read -rp "$(echo -e "${GREEN}Panel domain${NC} (for HTTPS, leave blank for HTTP): ")" panel_domain
    read -rp "$(echo -e "${GREEN}Tunnel domain${NC} (e.g. t.example.com, leave blank to set later): ")" tunnel_domain

    echo ""

    # Initialize config in the database before starting the service
    local init_cmd="${INSTALL_DIR}/${BINARY_NAME} config init --db ${DATA_DIR}/dnsttui.db"
    init_cmd="${init_cmd} --admin-user ${admin_user} --admin-pass ${admin_pass} --panel-port ${panel_port}"
    info "Initializing configuration..."
    eval "$init_cmd"

    # Set tunnel domain and panel domain if provided
    if [[ -n "$panel_domain" ]] || [[ -n "$tunnel_domain" ]]; then
        local set_cmd="${INSTALL_DIR}/${BINARY_NAME} config set --db ${DATA_DIR}/dnsttui.db"
        if [[ -n "$panel_domain" ]]; then
            set_cmd="${set_cmd} --panel-domain ${panel_domain}"
        fi
        if [[ -n "$tunnel_domain" ]]; then
            set_cmd="${set_cmd} --dnstt-domain ${tunnel_domain}"
        fi
        eval "$set_cmd"
    fi

    # Build ExecStart command
    local exec_cmd="${INSTALL_DIR}/${BINARY_NAME} serve --db ${DATA_DIR}/dnsttui.db --panel-addr :${panel_port}"
    if [[ -n "$panel_domain" ]]; then
        exec_cmd="${exec_cmd} --domain ${panel_domain}"
    fi

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=dnsttui - DNS Tunnel + Shadowsocks Panel
After=network.target

[Service]
Type=simple
ExecStart=${exec_cmd}
WorkingDirectory=${DATA_DIR}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    info "Systemd service created and enabled"

    # Export for use in do_install
    ADMIN_USER="$admin_user"
    PANEL_PORT="$panel_port"
    PANEL_DOMAIN="$panel_domain"
}

start_service() {
    systemctl restart "$SERVICE_NAME"
    info "Service started"
}

stop_service() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        info "Service stopped"
    fi
}

do_install() {
    check_root
    info "Installing ${BINARY_NAME}..."

    # Check dependencies
    command -v curl >/dev/null 2>&1 || error "curl is required but not installed"

    download_binary
    create_service
    start_service

    local ip
    ip=$(curl -s4 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

    # Read base path from DB
    local panel_path
    panel_path=$("${INSTALL_DIR}/${BINARY_NAME}" config show --db "${DATA_DIR}/dnsttui.db" 2>/dev/null | grep "Panel Base Path" | awk -F': +' '{print $2}' || echo "")

    local proto="http"
    local port_part=":${PANEL_PORT:-8080}"
    if [[ -n "${PANEL_DOMAIN:-}" ]]; then
        proto="https"
        ip="$PANEL_DOMAIN"
        if [[ "$PANEL_PORT" == "443" ]]; then
            port_part=""
        fi
    else
        if [[ "$PANEL_PORT" == "80" ]]; then
            port_part=""
        fi
    fi

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN} dnsttui installed successfully!${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e " Panel:    ${CYAN}${proto}://${ip}${port_part}${panel_path}/${NC}"
    echo -e " Username: ${CYAN}${ADMIN_USER:-admin}${NC}"
    echo -e " Data dir: ${CYAN}${DATA_DIR}${NC}"
    echo -e ""
    echo -e " ${YELLOW}Manage config: dnsttui config --help${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

do_update() {
    check_root
    info "Updating ${BINARY_NAME}..."
    stop_service
    download_binary
    start_service
    info "Update complete"
}

do_uninstall() {
    check_root
    info "Uninstalling ${BINARY_NAME}..."

    stop_service

    if [[ -f "$SERVICE_FILE" ]]; then
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        info "Systemd service removed"
    fi

    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    info "Binary removed"

    echo ""
    echo -e "${YELLOW}Data directory ${DATA_DIR} was NOT removed.${NC}"
    echo -e "${YELLOW}To remove all data: rm -rf ${DATA_DIR}${NC}"
}

show_usage() {
    echo "dnsttui installer"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install     Install dnsttui (default)"
    echo "  update      Update to latest version"
    echo "  uninstall   Remove dnsttui"
    echo ""
}

# Main
case "${1:-install}" in
    install)    do_install ;;
    update)     do_update ;;
    uninstall)  do_uninstall ;;
    -h|--help)  show_usage ;;
    *)          error "Unknown command: $1. Use install, update, or uninstall." ;;
esac
