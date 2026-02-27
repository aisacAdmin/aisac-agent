#!/bin/bash
#
# AISAC - AISAC Agent Installer for Linux
#
# Reads tenant config from /tmp/aisac-register.json (written by install-wazuh-agent.sh)
# and installs the AISAC Agent with the correct configuration.
#
# Usage:
#   ./install-aisac-agent.sh
#
# Requires:
#   /tmp/aisac-register.json  - Written by install-wazuh-agent.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/aisac"
CONFIG_DIR="/etc/aisac"
DATA_DIR="/var/lib/aisac"
LOG_DIR="/var/log/aisac"
SERVICE_NAME="aisac-agent"
BINARY_NAME="aisac-agent"
REGISTER_OUTPUT="/tmp/aisac-register.json"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

#------------------------------------------------------------------------------
# Parse JSON
#------------------------------------------------------------------------------

json_get_file() {
    local file="$1"
    local key="$2"

    if command -v jq &>/dev/null; then
        jq -r "$key // empty" "$file"
    elif command -v python3 &>/dev/null; then
        python3 -c "
import json
with open('$file') as f:
    data = json.load(f)
keys = '$key'.lstrip('.').split('.')
val = data
for k in keys:
    val = val.get(k, '') if isinstance(val, dict) else ''
print(val if val else '')
"
    else
        local simple_key
        simple_key=$(echo "$key" | sed 's/.*\.//')
        grep -o "\"${simple_key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" \
            | head -1 | sed 's/.*":\s*"\(.*\)"/\1/'
    fi
}

#------------------------------------------------------------------------------
# Read config from agent-register response
#------------------------------------------------------------------------------

load_register_config() {
    if [ ! -f "$REGISTER_OUTPUT" ]; then
        log_error "Register output not found: ${REGISTER_OUTPUT}"
        log_error "Run install-wazuh-agent.sh first"
        exit 1
    fi

    API_KEY=$(json_get_file "$REGISTER_OUTPUT" ".aisac.api_key")
    AUTH_TOKEN=$(json_get_file "$REGISTER_OUTPUT" ".aisac.auth_token")
    ASSET_ID=$(json_get_file "$REGISTER_OUTPUT" ".asset_id")
    HEARTBEAT_URL=$(json_get_file "$REGISTER_OUTPUT" ".aisac.heartbeat_url")
    INGEST_URL=$(json_get_file "$REGISTER_OUTPUT" ".aisac.ingest_url")
    TENANT_ID=$(json_get_file "$REGISTER_OUTPUT" ".tenant_id")

    if [ -z "$API_KEY" ] || [ -z "$ASSET_ID" ]; then
        log_error "Missing api_key or asset_id in ${REGISTER_OUTPUT}"
        exit 1
    fi

    log_success "Config loaded from ${REGISTER_OUTPUT}"
    log_info "  Asset ID:      ${ASSET_ID}"
    log_info "  Tenant ID:     ${TENANT_ID}"
    log_info "  Heartbeat URL: ${HEARTBEAT_URL}"
    log_info "  Ingest URL:    ${INGEST_URL}"
}

#------------------------------------------------------------------------------
# Create directories
#------------------------------------------------------------------------------

create_directories() {
    log_info "Creating directories..."
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR/certs" "$DATA_DIR" "$LOG_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR/certs"
    chmod 755 "$DATA_DIR"
    chmod 755 "$LOG_DIR"
    log_success "Directories created"
}

#------------------------------------------------------------------------------
# Install binary
#------------------------------------------------------------------------------

install_binary() {
    log_info "Installing AISAC Agent binary..."

    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
    fi

    # Option 1: Compile from source
    if [ -f "./go.mod" ] && [ -d "./cmd/agent" ] && command -v go &>/dev/null; then
        log_info "Compiling from source..."
        go build -o "$INSTALL_DIR/$BINARY_NAME" ./cmd/agent/
        log_success "Binary compiled"

    # Option 2: Local prebuilt binary (exact name or with os-arch suffix)
    elif [ -f "./bin/${BINARY_NAME}" ]; then
        cp "./bin/${BINARY_NAME}" "$INSTALL_DIR/$BINARY_NAME"
        log_success "Binary copied from ./bin/${BINARY_NAME}"
    elif ls ./bin/${BINARY_NAME}-*-* &>/dev/null; then
        local local_bin
        local_bin=$(ls ./bin/${BINARY_NAME}-*-* | head -1)
        cp "$local_bin" "$INSTALL_DIR/$BINARY_NAME"
        log_success "Binary copied from $local_bin"

    # Option 3: Download from GitHub Releases
    else
        local arch os
        arch=$(uname -m)
        os=$(uname -s | tr '[:upper:]' '[:lower:]')
        case "$arch" in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            *) log_error "Unsupported arch: $arch"; exit 1 ;;
        esac

        local url="https://github.com/aisacAdmin/aisac-agent/releases/latest/download/aisac-agent-${os}-${arch}"
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

#------------------------------------------------------------------------------
# Generate config
#------------------------------------------------------------------------------

generate_config() {
    log_info "Generating configuration..."

    local agent_id
    agent_id="agent-$(hostname | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')-$(head -c 4 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 4)"

    # Detect local log sources (Suricata only - Wazuh alerts are on the centralized Manager)
    local enable_suricata=false
    [ -f /var/log/suricata/eve.json ] && enable_suricata=true

    [ "$enable_suricata" = "true" ] && log_success "Detected: Suricata"

    cat > "$CONFIG_DIR/agent.yaml" << EOF
# AISAC Agent Configuration
# Generated by installer on $(date)

agent:
  id: "${agent_id}"
  labels:
    - production
  heartbeat_interval: 30s
  reconnect_delay: 5s
  max_reconnect_delay: 5m

server:
  enabled: false
  url: "wss://localhost:8443/ws"

tls:
  enabled: false

actions:
  enabled:
    - block_ip
    - unblock_ip
    - isolate_host
    - unisolate_host
    - disable_user
    - enable_user
    - kill_process
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
  enabled: ${enable_suricata}

  sources:
EOF

    if [ "$enable_suricata" = "true" ]; then
        cat >> "$CONFIG_DIR/agent.yaml" << EOF
    - name: suricata
      type: file
      path: /var/log/suricata/eve.json
      parser: suricata_eve
      tags:
        - security
        - ids
EOF
    fi

    cat >> "$CONFIG_DIR/agent.yaml" << EOF

  output:
    type: http
    url: "${INGEST_URL}"
    api_key: "${API_KEY}"
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
    - "$(echo "$HEARTBEAT_URL" | sed -E 's|^https?://([^:/]+).*|\1|')"
  always_allowed: true

safety:
  state_file: "${DATA_DIR}/safety_state.json"
  auto_revert_enabled: true
  default_ttl: 1h
  action_ttls:
    isolate_host: 30m
    block_ip: 4h
    disable_user: 2h
  heartbeat_failure_threshold: 5
  recovery_actions:
    - unisolate_host
    - unblock_all_ips

logging:
  level: "info"
  format: "json"
  output: "stdout"
EOF

    chmod 600 "$CONFIG_DIR/agent.yaml"
    log_success "Configuration saved to ${CONFIG_DIR}/agent.yaml"
}

#------------------------------------------------------------------------------
# Install systemd service
#------------------------------------------------------------------------------

install_service() {
    log_info "Installing systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=AISAC Security Agent
After=network-online.target
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
    log_success "Service installed and enabled"
}

#------------------------------------------------------------------------------
# Start service
#------------------------------------------------------------------------------

start_service() {
    log_info "Starting AISAC Agent..."
    systemctl start "$SERVICE_NAME"
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "AISAC Agent is running"
    else
        log_error "Failed to start AISAC Agent"
        echo "Check: journalctl -u ${SERVICE_NAME} -n 50"
        exit 1
    fi
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

main() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Must be run as root"
        exit 1
    fi

    load_register_config
    create_directories
    install_binary
    generate_config
    install_service
    start_service

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}              AISAC Agent installed successfully!               ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Config:  ${CONFIG_DIR}/agent.yaml"
    echo -e "  Logs:    ${LOG_DIR}/agent.log"
    echo -e "  Status:  systemctl status ${SERVICE_NAME}"
    echo ""

    # Cleanup temp file
    rm -f "$REGISTER_OUTPUT"
}

main "$@"
