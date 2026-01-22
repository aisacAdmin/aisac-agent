#!/bin/bash
#
# AISAC Agent Installer
# Interactive installation script for Linux servers
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/aisac"
CONFIG_DIR="/etc/aisac"
DATA_DIR="/var/lib/aisac"
LOG_DIR="/var/log/aisac"
SERVICE_NAME="aisac-agent"
BINARY_NAME="aisac-agent"

# Default values
DEFAULT_SERVER_URL="wss://localhost:8443/ws"
DEFAULT_INGEST_URL="https://api.aisac.cisec.es/functions/v1/syslog-ingest"
DEFAULT_HEARTBEAT_URL="https://api.aisac.cisec.es/v1/heartbeat"
SERVICE_WAS_RUNNING=false

#------------------------------------------------------------------------------
# Helper functions
#------------------------------------------------------------------------------

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║              AISAC Agent Installer v1.0                       ║"
    echo "║                                                               ║"
    echo "║   Security Information and Event Management (SIEM) Agent      ║"
    echo "║   with Security Orchestration and Response (SOAR) Actions     ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

prompt() {
    local message="$1"
    local default="$2"
    local result

    if [ -n "$default" ]; then
        echo -en "${CYAN}$message${NC} [${default}]: "
        read result
        echo "${result:-$default}"
    else
        echo -en "${CYAN}$message${NC}: "
        read result
        echo "$result"
    fi
}

prompt_password() {
    local message="$1"
    local result

    echo -en "${CYAN}$message${NC}: "
    read -s result
    echo
    echo "$result"
}

prompt_yes_no() {
    local message="$1"
    local default="$2"
    local result

    if [ "$default" = "y" ]; then
        echo -en "${CYAN}$message${NC} [Y/n]: "
    else
        echo -en "${CYAN}$message${NC} [y/N]: "
    fi

    read result
    result=$(echo "$result" | tr '[:upper:]' '[:lower:]')

    if [ -z "$result" ]; then
        result="$default"
    fi

    [ "$result" = "y" ] || [ "$result" = "yes" ]
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi
}

check_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS. /etc/os-release not found"
        exit 1
    fi

    . /etc/os-release

    case "$ID" in
        ubuntu|debian|centos|rhel|fedora|rocky|almalinux)
            log_success "Detected OS: $PRETTY_NAME"
            ;;
        *)
            log_warning "OS '$ID' not officially supported, but installation may work"
            ;;
    esac
}

check_systemd() {
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is required but not found"
        exit 1
    fi
    log_success "systemd detected"
}

#------------------------------------------------------------------------------
# Installation functions
#------------------------------------------------------------------------------

create_directories() {
    log_info "Creating directories..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR/certs"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"

    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR/certs"
    chmod 755 "$DATA_DIR"
    chmod 755 "$LOG_DIR"

    log_success "Directories created"
}

install_binary() {
    log_info "Installing AISAC Agent binary..."

    # Stop service if running (binary might be in use)
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping running service to update binary..."
        systemctl stop "$SERVICE_NAME"
        SERVICE_WAS_RUNNING=true
    fi

    # Check if binary exists locally first
    local binary_path=""

    if [ -f "./bin/${BINARY_NAME}" ]; then
        binary_path="./bin/${BINARY_NAME}"
    elif [ -f "./${BINARY_NAME}" ]; then
        binary_path="./${BINARY_NAME}"
    elif [ -f "../bin/${BINARY_NAME}" ]; then
        binary_path="../bin/${BINARY_NAME}"
    fi

    if [ -n "$binary_path" ]; then
        log_info "Using local binary: $binary_path"
        cp "$binary_path" "$INSTALL_DIR/$BINARY_NAME"
    else
        # Download from GitHub Releases
        log_info "Downloading binary from GitHub Releases..."

        local arch=$(uname -m)
        local os=$(uname -s | tr '[:upper:]' '[:lower:]')

        case "$arch" in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            armv7l)  arch="arm" ;;
            *)
                log_error "Unsupported architecture: $arch"
                exit 1
                ;;
        esac

        local download_url="https://github.com/aisacAdmin/aisac-agent/releases/latest/download/aisac-agent-${os}-${arch}"

        log_info "Downloading from: $download_url"

        if command -v curl &> /dev/null; then
            if ! curl -fsSL "$download_url" -o "$INSTALL_DIR/$BINARY_NAME"; then
                log_error "Failed to download binary from GitHub Releases"
                echo ""
                echo "Options:"
                echo "  1. Check if releases exist at: https://github.com/aisacAdmin/aisac-agent/releases"
                echo "  2. Build locally with: make build"
                echo "  3. Or compile for Linux with:"
                echo "     GOOS=linux GOARCH=amd64 go build -o aisac-agent ./cmd/agent"
                exit 1
            fi
        elif command -v wget &> /dev/null; then
            if ! wget -q "$download_url" -O "$INSTALL_DIR/$BINARY_NAME"; then
                log_error "Failed to download binary from GitHub Releases"
                exit 1
            fi
        else
            log_error "curl or wget is required to download the binary"
            exit 1
        fi

        log_success "Binary downloaded successfully"
    fi

    chmod 755 "$INSTALL_DIR/$BINARY_NAME"

    # Create symlink
    ln -sf "$INSTALL_DIR/$BINARY_NAME" /usr/local/bin/$BINARY_NAME

    log_success "Binary installed to $INSTALL_DIR/$BINARY_NAME"
}

configure_agent() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    Agent Configuration                         ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Agent ID
    local hostname=$(hostname)
    AGENT_ID=$(prompt "Agent ID (unique identifier)" "$hostname")

    # SOAR Configuration
    echo ""
    echo -e "${YELLOW}--- SOAR Configuration (Command Server) ---${NC}"

    if prompt_yes_no "Enable SOAR functionality (receive commands from server)?" "n"; then
        SOAR_ENABLED=true
        SERVER_URL=$(prompt "Command Server WebSocket URL" "$DEFAULT_SERVER_URL")

        echo ""
        log_info "For mTLS, you'll need certificate files in $CONFIG_DIR/certs/"
        TLS_ENABLED=true
    else
        SOAR_ENABLED=false
        SERVER_URL="$DEFAULT_SERVER_URL"
        TLS_ENABLED=false
    fi

    # Collector Configuration
    echo ""
    echo -e "${YELLOW}--- Log Collector Configuration (SIEM) ---${NC}"

    if prompt_yes_no "Enable Log Collector (send logs to AISAC platform)?" "y"; then
        COLLECTOR_ENABLED=true

        echo ""
        echo -e "${BLUE}You need an API Key from the AISAC Platform.${NC}"
        echo -e "${BLUE}Get it from: Platform > Assets > [Your Asset] > API Key${NC}"
        echo ""

        API_KEY=$(prompt_password "API Key (format: aisac_xxxx...)")

        if [ -z "$API_KEY" ]; then
            log_warning "No API Key provided. You'll need to add it later in the config file."
            API_KEY="aisac_your_api_key_here"
        fi

        INGEST_URL=$(prompt "Log Ingest URL" "$DEFAULT_INGEST_URL")

        # Log sources
        echo ""
        echo -e "${YELLOW}--- Log Sources ---${NC}"

        ENABLE_SURICATA=false
        ENABLE_SYSLOG=false

        if [ -f /var/log/suricata/eve.json ]; then
            if prompt_yes_no "Suricata EVE logs detected. Enable collection?" "y"; then
                ENABLE_SURICATA=true
            fi
        else
            if prompt_yes_no "Enable Suricata EVE log collection?" "n"; then
                ENABLE_SURICATA=true
                SURICATA_PATH=$(prompt "Suricata EVE log path" "/var/log/suricata/eve.json")
            fi
        fi

        if [ -f /var/log/syslog ]; then
            if prompt_yes_no "Syslog detected. Enable collection?" "y"; then
                ENABLE_SYSLOG=true
            fi
        elif [ -f /var/log/messages ]; then
            if prompt_yes_no "System messages detected. Enable collection?" "y"; then
                ENABLE_SYSLOG=true
                SYSLOG_PATH="/var/log/messages"
            fi
        fi
    else
        COLLECTOR_ENABLED=false
    fi

    # Heartbeat Configuration
    echo ""
    echo -e "${YELLOW}--- Heartbeat Configuration (Status Reporting) ---${NC}"

    if prompt_yes_no "Enable Heartbeat (report agent status to AISAC platform)?" "y"; then
        HEARTBEAT_ENABLED=true

        echo ""
        echo -e "${BLUE}Heartbeat reports agent status and system metrics to the platform.${NC}"
        echo ""

        # If API Key was already provided for collector, reuse it
        if [ -z "$API_KEY" ] || [ "$API_KEY" = "aisac_your_api_key_here" ]; then
            echo -e "${BLUE}You need an API Key from the AISAC Platform.${NC}"
            echo -e "${BLUE}Get it from: Platform > Assets > [Your Asset] > API Key${NC}"
            echo ""
            API_KEY=$(prompt_password "API Key (format: aisac_xxxx...)")

            if [ -z "$API_KEY" ]; then
                log_warning "No API Key provided. You'll need to add it later in the config file."
                API_KEY="aisac_your_api_key_here"
            fi
        fi

        echo ""
        echo -e "${BLUE}You need the Asset ID (UUID) from the AISAC Platform.${NC}"
        echo -e "${BLUE}Get it from: Platform > Assets > [Your Asset] > Asset ID${NC}"
        echo ""

        ASSET_ID=$(prompt "Asset ID (UUID)")

        if [ -z "$ASSET_ID" ]; then
            log_warning "No Asset ID provided. You'll need to add it later in the config file."
            ASSET_ID="your-asset-uuid-here"
        fi

        HEARTBEAT_URL=$(prompt "Heartbeat URL" "$DEFAULT_HEARTBEAT_URL")
    else
        HEARTBEAT_ENABLED=false
    fi
}

generate_config() {
    log_info "Generating configuration file..."

    local config_file="$CONFIG_DIR/agent.yaml"

    cat > "$config_file" << EOF
# AISAC Agent Configuration
# Generated by installer on $(date)

agent:
  id: "${AGENT_ID}"
  labels:
    - production
  heartbeat_interval: 30s
  reconnect_delay: 5s
  max_reconnect_delay: 5m

server:
  enabled: ${SOAR_ENABLED}
  url: "${SERVER_URL}"
  connect_timeout: 30s
  write_timeout: 10s
  read_timeout: 60s

tls:
  enabled: ${TLS_ENABLED}
  cert_file: "${CONFIG_DIR}/certs/agent.crt"
  key_file: "${CONFIG_DIR}/certs/agent.key"
  ca_file: "${CONFIG_DIR}/certs/ca.crt"
  skip_verify: false

actions:
  enabled:
    - block_ip
    - unblock_ip
    - isolate_host
    - unisolate_host
    - disable_user
    - enable_user
    - kill_process
  rate_limits:
    block_ip:
      max_per_minute: 10
      max_per_hour: 100
    isolate_host:
      max_per_minute: 1
      max_per_hour: 5
  default_timeout: 5m

callback:
  enabled: false
  url: ""
  auth_token: ""
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s

heartbeat:
  enabled: ${HEARTBEAT_ENABLED:-false}
  url: "${HEARTBEAT_URL:-$DEFAULT_HEARTBEAT_URL}"
  api_key: "${API_KEY:-aisac_your_api_key_here}"
  asset_id: "${ASSET_ID:-your-asset-uuid-here}"
  interval: 120s
  timeout: 10s
  skip_tls_verify: false

collector:
  enabled: ${COLLECTOR_ENABLED}
EOF

    if [ "$COLLECTOR_ENABLED" = "true" ]; then
        cat >> "$config_file" << EOF

  sources:
EOF

        if [ "$ENABLE_SURICATA" = "true" ]; then
            cat >> "$config_file" << EOF
    - name: suricata
      type: file
      path: ${SURICATA_PATH:-/var/log/suricata/eve.json}
      parser: suricata_eve
      tags:
        - security
        - ids
EOF
        fi

        if [ "$ENABLE_SYSLOG" = "true" ]; then
            cat >> "$config_file" << EOF
    - name: syslog
      type: file
      path: ${SYSLOG_PATH:-/var/log/syslog}
      parser: syslog
      tags:
        - system
EOF
        fi

        cat >> "$config_file" << EOF

  output:
    type: http
    url: "${INGEST_URL}"
    api_key: "${API_KEY}"
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
EOF
    fi

    cat >> "$config_file" << EOF

logging:
  level: "info"
  format: "json"
  output: "file"
  file: "${LOG_DIR}/agent.log"
EOF

    chmod 600 "$config_file"
    log_success "Configuration saved to $config_file"
}

install_systemd_service() {
    log_info "Installing systemd service..."

    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=AISAC Security Agent
Documentation=https://github.com/aisacAdmin/aisac-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -c ${CONFIG_DIR}/agent.yaml
Restart=always
RestartSec=5
StandardOutput=null
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
PrivateTmp=true

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}

    log_success "Systemd service installed and enabled"
}

start_service() {
    echo ""
    if prompt_yes_no "Start AISAC Agent now?" "y"; then
        log_info "Starting AISAC Agent..."
        systemctl start ${SERVICE_NAME}
        sleep 2

        if systemctl is-active --quiet ${SERVICE_NAME}; then
            log_success "AISAC Agent is running"
        else
            log_error "Failed to start AISAC Agent"
            echo "Check logs with: journalctl -u ${SERVICE_NAME} -f"
        fi
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                 Installation Complete!                         ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Installation Directory:${NC} $INSTALL_DIR"
    echo -e "  ${CYAN}Configuration:${NC}          $CONFIG_DIR/agent.yaml"
    echo -e "  ${CYAN}Data Directory:${NC}         $DATA_DIR"
    echo -e "  ${CYAN}Log File:${NC}               $LOG_DIR/agent.log"
    echo ""
    echo -e "  ${YELLOW}Useful Commands:${NC}"
    echo -e "    Start:   ${CYAN}systemctl start ${SERVICE_NAME}${NC}"
    echo -e "    Stop:    ${CYAN}systemctl stop ${SERVICE_NAME}${NC}"
    echo -e "    Status:  ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
    echo -e "    Logs:    ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
    echo -e "    Config:  ${CYAN}nano ${CONFIG_DIR}/agent.yaml${NC}"
    echo ""

    if [ "$API_KEY" = "aisac_your_api_key_here" ]; then
        echo -e "  ${YELLOW}IMPORTANT:${NC} Don't forget to add your API Key to the config file!"
        echo ""
    fi

    if [ "$HEARTBEAT_ENABLED" = "true" ] && [ "$ASSET_ID" = "your-asset-uuid-here" ]; then
        echo -e "  ${YELLOW}IMPORTANT:${NC} Don't forget to add your Asset ID to the config file!"
        echo ""
    fi

    if [ "$TLS_ENABLED" = "true" ]; then
        echo -e "  ${YELLOW}IMPORTANT:${NC} For SOAR functionality, add certificates to:"
        echo -e "    - ${CONFIG_DIR}/certs/agent.crt"
        echo -e "    - ${CONFIG_DIR}/certs/agent.key"
        echo -e "    - ${CONFIG_DIR}/certs/ca.crt"
        echo ""
    fi
}

#------------------------------------------------------------------------------
# Uninstall function
#------------------------------------------------------------------------------

uninstall() {
    echo ""
    log_warning "This will remove AISAC Agent from your system"

    if ! prompt_yes_no "Are you sure you want to uninstall?" "n"; then
        echo "Uninstall cancelled"
        exit 0
    fi

    log_info "Stopping service..."
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true

    log_info "Removing files..."
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    rm -f /usr/local/bin/${BINARY_NAME}
    rm -rf "$INSTALL_DIR"

    systemctl daemon-reload

    if prompt_yes_no "Remove configuration and data?" "n"; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$DATA_DIR"
        rm -rf "$LOG_DIR"
        log_success "Configuration and data removed"
    else
        log_info "Configuration preserved in $CONFIG_DIR"
    fi

    log_success "AISAC Agent uninstalled"
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

main() {
    print_banner

    # Parse arguments
    case "${1:-}" in
        --uninstall|-u)
            check_root
            uninstall
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --uninstall, -u    Uninstall AISAC Agent"
            echo "  --help, -h         Show this help message"
            echo ""
            exit 0
            ;;
    esac

    # Pre-flight checks
    log_info "Running pre-flight checks..."
    check_root
    check_os
    check_systemd
    echo ""

    # Installation
    create_directories
    install_binary
    configure_agent
    generate_config
    install_systemd_service
    start_service
    print_summary
}

main "$@"
