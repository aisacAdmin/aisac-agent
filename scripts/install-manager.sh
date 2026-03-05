#!/bin/bash
#
# AISAC - Wazuh Manager + AISAC Collector Installer
#
# Installs and configures:
#   1. Wazuh Manager (indexer + server + dashboard)
#   2. Tenant agent group on the Manager
#   3. AISAC Agent in collector mode (forwards Wazuh alerts to AISAC Platform)
#
# Usage:
#   sudo bash install-manager.sh -k <API_KEY>
#   sudo bash install-manager.sh -k <API_KEY> -u <REGISTER_URL>
#
# One-liner:
#   curl -sSL https://raw.githubusercontent.com/aisacAdmin/aisac-agent/main/scripts/install-manager.sh -o install-manager.sh
#   sudo bash install-manager.sh -k <API_KEY>
#

set -euo pipefail

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Defaults ───
DEFAULT_REGISTER_URL="https://api.aisac.cisec.es/functions/v1/install-config"
WAZUH_VERSION="4.14"
WAZUH_SERVER_NAME="wazuh-1"

INSTALL_DIR="/opt/aisac"
CONFIG_DIR="/etc/aisac"
DATA_DIR="/var/lib/aisac"
LOG_DIR="/var/log/aisac"
SERVICE_NAME="aisac-agent"
BINARY_NAME="aisac-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║           AISAC Manager Installer v1.0                        ║"
    echo "║                                                               ║"
    echo "║   Installs: Wazuh Manager + AISAC Collector                   ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 -k <API_KEY> -t <AUTH_TOKEN> [-u <REGISTER_URL>] [-i] [--no-indexer]"
    echo ""
    echo "Options:"
    echo "  -k <API_KEY>       AISAC Platform API Key for the collector asset"
    echo "  -t <AUTH_TOKEN>    Supabase anon key (JWT) for gateway auth"
    echo "  -u <REGISTER_URL>  Install-config endpoint (default: production)"
    echo "  -i                 Ignore hardware requirements check (for small VMs)"
    echo "  --no-indexer       Install only Wazuh Manager (no Indexer/Dashboard, ~500MB RAM)"
    echo "  -h                 Show this help"
    echo ""
    echo "Example:"
    echo "  sudo bash $0 -k aisac_xxxxxxxxxxxx -t eyJhbG..."
    echo "  sudo bash $0 -k aisac_xxxxxxxxxxxx -t eyJhbG... --no-indexer -i"
}

# ─── JSON helper ───
json_extract() {
    local json="$1" key="$2"
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r "$key // empty"
    elif command -v python3 &>/dev/null; then
        echo "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
keys = '$key'.lstrip('.').split('.')
val = data
for k in keys:
    val = val.get(k, '') if isinstance(val, dict) else ''
print(val if val else '')
"
    else
        # Fallback: grep
        local simple_key
        simple_key=$(echo "$key" | sed 's/.*\.//')
        echo "$json" | grep -o "\"${simple_key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
            | head -1 | sed 's/.*":\s*"\(.*\)"/\1/'
    fi
}

#==============================================================================
# Step 1: Detect private IP
#==============================================================================

detect_private_ip() {
    log_info "Detecting private IP..."
    local ip=""

    # Try ip command first
    if command -v ip &>/dev/null; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    fi

    # Fallback to hostname
    if [ -z "$ip" ] && command -v hostname &>/dev/null; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    if [ -z "$ip" ]; then
        log_error "Could not detect private IP"
        exit 1
    fi

    PRIVATE_IP="$ip"
    log_success "Private IP: ${PRIVATE_IP}"
}

#==============================================================================
# Step 2: Install Wazuh Manager
#==============================================================================

install_wazuh_manager() {
    # Skip if already installed
    if [ -f /var/ossec/bin/wazuh-control ]; then
        log_success "Wazuh Manager already installed, skipping"
        return 0
    fi

    log_info "Downloading Wazuh ${WAZUH_VERSION} installer..."
    cd /tmp
    curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
    curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/config.yml"

    # Generate config.yml and certificates tar (needed by all modes)
    log_info "Configuring Wazuh with IP: ${PRIVATE_IP}"
    cat > /tmp/config.yml << EOCFG
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "${PRIVATE_IP}"

  server:
    - name: ${WAZUH_SERVER_NAME}
      ip: "${PRIVATE_IP}"

  dashboard:
    - name: wazuh-dashboard
      ip: "${PRIVATE_IP}"
EOCFG

    if [ -f /tmp/wazuh-install-files.tar ]; then
        log_info "Wazuh config files already exist, reusing them"
    else
        log_info "Generating Wazuh config files..."
        bash /tmp/wazuh-install.sh -g 2>&1 | tail -5
    fi

    if [ "$NO_INDEXER" = true ]; then
        # Lightweight mode: only Wazuh Manager (no Indexer/Dashboard)
        log_info "Installing Wazuh Manager only (no Indexer/Dashboard)..."
        bash /tmp/wazuh-install.sh --wazuh-server "${WAZUH_SERVER_NAME}" ${IGNORE_REQUIREMENTS} -o 2>&1 | tail -10

        # Disable indexer-connector warnings (no indexer to connect to)
        if [ -f /var/ossec/etc/ossec.conf ]; then
            sed -i 's|<enabled>yes</enabled>\(.*indexer\)|<enabled>no</enabled>\1|' /var/ossec/etc/ossec.conf 2>/dev/null || true
        fi
    else
        # Full mode: Indexer + Server + Dashboard
        log_info "Installing Wazuh Indexer..."
        bash /tmp/wazuh-install.sh --wazuh-indexer wazuh-indexer ${IGNORE_REQUIREMENTS} 2>&1 | tail -5

        log_info "Starting Wazuh cluster..."
        bash /tmp/wazuh-install.sh --start-cluster ${IGNORE_REQUIREMENTS} 2>&1 | tail -5

        log_info "Installing Wazuh Server..."
        bash /tmp/wazuh-install.sh --wazuh-server "${WAZUH_SERVER_NAME}" ${IGNORE_REQUIREMENTS} 2>&1 | tail -5

        log_info "Installing Wazuh Dashboard..."
        bash /tmp/wazuh-install.sh --wazuh-dashboard wazuh-dashboard ${IGNORE_REQUIREMENTS} 2>&1 | tail -5
    fi

    # Verify
    if [ ! -f /var/ossec/logs/alerts/alerts.json ]; then
        # alerts.json may not exist until first alert, create parent dir check
        if [ ! -d /var/ossec/logs/alerts ]; then
            log_error "Wazuh Manager installation failed - alerts directory not found"
            exit 1
        fi
    fi

    log_success "Wazuh Manager installed"
}

#==============================================================================
# Step 3: Call install-config to get AISAC config
#==============================================================================

fetch_aisac_config() {
    log_info "Fetching AISAC config from: ${REGISTER_URL}"

    local response http_code body auth_header=""
    if [ -n "$AUTH_TOKEN" ]; then
        auth_header="Authorization: Bearer ${AUTH_TOKEN}"
    fi

    response=$(curl -s -w "\n%{http_code}" -X GET "${REGISTER_URL}" \
        -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        ${auth_header:+-H "$auth_header"} 2>/dev/null)

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        log_error "install-config returned HTTP ${http_code}"
        log_error "Response: ${body}"
        exit 1
    fi

    # Extract config values
    TENANT_ID=$(json_extract "$body" ".tenant_id")
    ASSET_ID=$(json_extract "$body" ".asset_id")
    ASSET_NAME=$(json_extract "$body" ".asset_name")
    HEARTBEAT_URL=$(json_extract "$body" ".aisac.heartbeat_url")
    INGEST_URL=$(json_extract "$body" ".aisac.ingest_url")
    AUTH_TOKEN=$(json_extract "$body" ".aisac.auth_token")

    if [ -z "$ASSET_ID" ] || [ -z "$TENANT_ID" ]; then
        log_error "Missing asset_id or tenant_id in response"
        exit 1
    fi

    log_success "Config received"
    log_info "  Asset ID:   ${ASSET_ID}"
    log_info "  Asset Name: ${ASSET_NAME}"
    log_info "  Tenant ID:  ${TENANT_ID}"
}

#==============================================================================
# Step 4: Create tenant group on Wazuh Manager
#==============================================================================

create_tenant_group() {
    local group_name="${TENANT_ID}"

    # Check if group already exists
    if /var/ossec/bin/agent_groups -l 2>/dev/null | grep -q "${group_name}"; then
        log_success "Agent group '${group_name}' already exists"
        return 0
    fi

    log_info "Creating agent group: ${group_name}"
    /var/ossec/bin/agent_groups -a -g "${group_name}" -q 2>/dev/null || true
    log_success "Agent group '${group_name}' created"
}

#==============================================================================
# Step 5: Install AISAC Agent binary
#==============================================================================

install_aisac_binary() {
    log_info "Installing AISAC Agent binary..."

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 755 "$DATA_DIR"
    chmod 755 "$LOG_DIR"

    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
    fi

    # Option 1: Local binary in same directory
    local local_bin="${SCRIPT_DIR}/${BINARY_NAME}"
    if [ ! -f "$local_bin" ]; then
        local_bin="${SCRIPT_DIR}/${BINARY_NAME}-linux-amd64"
    fi

    if [ -f "$local_bin" ]; then
        cp "$local_bin" "$INSTALL_DIR/$BINARY_NAME"
        log_success "Binary copied from ${local_bin}"

    # Option 2: Compile from source
    elif [ -f "${SCRIPT_DIR}/../go.mod" ] && command -v go &>/dev/null; then
        log_info "Compiling from source..."
        (cd "${SCRIPT_DIR}/.." && go build -o "$INSTALL_DIR/$BINARY_NAME" ./cmd/agent/)
        log_success "Binary compiled"

    # Option 3: Download from GitHub
    else
        local arch
        arch=$(uname -m)
        case "$arch" in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            *) log_error "Unsupported arch: $arch"; exit 1 ;;
        esac

        local url="https://github.com/aisacAdmin/aisac-agent/releases/latest/download/aisac-agent-linux-${arch}"
        log_info "Downloading from: ${url}"
        curl -fsSL "$url" -o "$INSTALL_DIR/$BINARY_NAME" || {
            log_error "Failed to download binary"
            exit 1
        }
        log_success "Binary downloaded"
    fi

    chmod 755 "$INSTALL_DIR/$BINARY_NAME"
    ln -sf "$INSTALL_DIR/$BINARY_NAME" /usr/local/bin/$BINARY_NAME
    log_success "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

#==============================================================================
# Step 6: Generate collector config
#==============================================================================

generate_collector_config() {
    log_info "Generating collector configuration..."

    local agent_id
    agent_id="collector-$(hostname | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')"

    # Detect additional sources
    local suricata_source=""
    if [ -f /var/log/suricata/eve.json ]; then
        log_success "Detected: Suricata EVE logs"
        suricata_source="    - name: suricata
      type: file
      path: /var/log/suricata/eve.json
      parser: suricata_eve
      tags:
        - security
        - ids"
    fi

    local heartbeat_domain
    heartbeat_domain=$(echo "$HEARTBEAT_URL" | sed -E 's|^https?://([^:/]+).*|\1|')

    cat > "$CONFIG_DIR/agent.yaml" << EOF
# AISAC Agent Configuration - Collector Mode
# Generated by install-manager.sh on $(date)
# This agent collects Wazuh Manager alerts and forwards them to AISAC Platform.

agent:
  id: "${agent_id}"
  labels:
    - collector
    - wazuh-manager
  heartbeat_interval: 30s
  reconnect_delay: 5s
  max_reconnect_delay: 5m

server:
  enabled: false

tls:
  enabled: false

actions:
  enabled: []
  default_timeout: 5m

heartbeat:
  enabled: true
  url: "${HEARTBEAT_URL}"
  api_key: "${API_KEY}"
  auth_token: "${AUTH_TOKEN}"
  asset_id: "${ASSET_ID}"
  interval: 120s
  timeout: 10s
  skip_tls_verify: false

collector:
  enabled: true

  sources:
    - name: wazuh_alerts
      type: file
      path: /var/ossec/logs/alerts/alerts.json
      parser: wazuh_alerts
      tags:
        - security
        - hids
${suricata_source}

  output:
    type: http
    url: "${INGEST_URL}"
    api_key: "${API_KEY}"
    auth_token: "${AUTH_TOKEN}"
    asset_id: "${ASSET_ID}"
    timeout: 30s
    retry_attempts: 3
    retry_delay: 5s
    skip_tls_verify: false

  batch:
    size: 100
    interval: 5s

  file:
    start_position: end
    sincedb_path: ${DATA_DIR}/sincedb.json

control_plane:
  domains:
    - "${heartbeat_domain}"
  always_allowed: true

safety:
  state_file: "${DATA_DIR}/safety_state.json"
  auto_revert_enabled: false

logging:
  level: "info"
  format: "json"
  output: "stdout"
EOF

    chmod 600 "$CONFIG_DIR/agent.yaml"
    log_success "Collector config saved to ${CONFIG_DIR}/agent.yaml"
}

#==============================================================================
# Step 7: Install and start systemd service
#==============================================================================

install_service() {
    log_info "Installing systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=AISAC Security Agent (Collector)
After=network-online.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -c ${CONFIG_DIR}/agent.yaml
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.log
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "AISAC Collector is running"
    else
        log_warning "AISAC Collector may not be running yet (alerts.json may not exist until first agent connects)"
        log_info "Check: journalctl -u ${SERVICE_NAME} -n 20"
    fi
}

#==============================================================================
# Main
#==============================================================================

main() {
    local API_KEY="" AUTH_TOKEN="" REGISTER_URL="$DEFAULT_REGISTER_URL"
    IGNORE_REQUIREMENTS=""
    NO_INDEXER=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -k) API_KEY="$2"; shift 2 ;;
            -t) AUTH_TOKEN="$2"; shift 2 ;;
            -u) REGISTER_URL="$2"; shift 2 ;;
            -i) IGNORE_REQUIREMENTS="-i"; shift ;;
            --no-indexer) NO_INDEXER=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) log_error "Unknown argument: $1"; usage; exit 1 ;;
        esac
    done

    if [ -z "$API_KEY" ]; then
        log_error "API Key is required (-k)"
        usage
        exit 1
    fi

    if [ -z "$AUTH_TOKEN" ]; then
        log_error "Auth token is required (-t)"
        usage
        exit 1
    fi

    if [ "$EUID" -ne 0 ]; then
        log_error "Must be run as root"
        exit 1
    fi

    print_banner

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 1/5: Detecting server configuration                    ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    detect_private_ip

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 2/5: Installing Wazuh Manager                          ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    install_wazuh_manager

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 3/5: Fetching AISAC Platform config                    ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    fetch_aisac_config

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 4/5: Creating tenant group on Wazuh Manager            ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    create_tenant_group

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 5/5: Installing AISAC Collector                        ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    install_aisac_binary
    generate_collector_config
    install_service

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Manager installation complete!                     ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Wazuh Manager:${NC}  systemctl status wazuh-manager"
    echo -e "  ${CYAN}AISAC Collector:${NC} systemctl status aisac-agent"
    echo -e "  ${CYAN}Collector Logs:${NC} tail -f ${LOG_DIR}/agent.log"
    echo -e "  ${CYAN}Collector Config:${NC} ${CONFIG_DIR}/agent.yaml"
    echo -e "  ${CYAN}Wazuh Alerts:${NC}   /var/ossec/logs/alerts/alerts.json"
    echo -e "  ${CYAN}Wazuh Dashboard:${NC} https://${PRIVATE_IP} (admin/admin)"
    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo -e "    1. Open ports 1514/1515 (TCP) in firewall/security group"
    echo -e "    2. Install agents on assets with:"
    echo -e "       ${BLUE}curl -sSL .../install.sh -o install.sh && sudo bash install.sh -k <ASSET_API_KEY>${NC}"
    echo ""
}

main "$@"
