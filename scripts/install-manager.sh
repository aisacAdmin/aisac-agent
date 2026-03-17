#!/bin/bash
#
# AISAC - Wazuh Manager + AISAC Agent Installer
#
# Installs and configures:
#   1. Wazuh Manager (indexer + server + dashboard)
#   2. Tenant agent group on the Manager
#   3. AISAC Agent in collector mode (forwards Wazuh alerts to AISAC Platform)
#
# With --agent flag, also enables full asset capabilities:
#   - Response actions (block_ip, isolate_host, etc.)
#   - Safety auto-revert with TTLs
#   - Syslog collection
#   - Agent registration with platform
#
# With --soar flag, additionally enables:
#   - mTLS certificates
#   - Command server for SOAR orchestration
#
# With --mcp flag, additionally installs:
#   - Wazuh MCP Server (AI-powered security operations via MCP protocol)
#   - Generates auth token for MCP access and registers it with the platform
#
# Usage:
#   sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN>
#   sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN> --agent
#   sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN> --soar
#   sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN> --soar --mcp
#
# One-liner:
#   curl -sSL https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/install-manager.sh -o install-manager.sh
#   sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN>
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
DEFAULT_SERVER_URL="wss://localhost:8443/ws"

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
    local mode="Collector"
    if [ "$AGENT_MODE" = true ]; then
        mode="Agent"
        if [ "$SOAR_ENABLED" = true ]; then
            mode="Agent + SOAR"
        fi
    fi
    if [ "${MCP_ENABLED:-false}" = true ]; then
        mode="${mode} + MCP"
    fi

    echo -e "${CYAN}"
    echo "╔═════════════════════════════════════════════════════════════╗"
    echo "║                                                             ║"
    echo "║           AISAC Manager Installer v2.0                      ║"
    echo "║                                                             ║"
    echo "║   Installs: Wazuh Manager + AISAC ${mode}$(printf '%*s' $((25 - ${#mode})) '') ║"
    echo "║                                                             ║"
    echo "╚═════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 -k <API_KEY> -t <AUTH_TOKEN> [-u <REGISTER_URL>] [-i] [--no-indexer] [--agent] [--soar]"
    echo ""
    echo "Options:"
    echo "  -k <API_KEY>       AISAC Platform API Key"
    echo "  -t <AUTH_TOKEN>    Supabase anon key (JWT) for gateway auth"
    echo "  -u <REGISTER_URL>  Install-config endpoint (default: production)"
    echo "  -i                 Ignore hardware requirements check (for small VMs)"
    echo "  --no-indexer       Install only Wazuh Manager (no Indexer/Dashboard, ~500MB RAM)"
    echo "  --no-dashboard     Install Indexer but skip Dashboard (saves ~200MB RAM)"
    echo "  --agent            Enable full asset capabilities (actions, safety, syslog)"
    echo "  --soar             Enable SOAR mode (mTLS + command server). Implies --agent"
    echo "  --mcp              Install Wazuh MCP Server for AI-powered security operations"
    echo "  -o|--overwrite     Overwrite existing Wazuh installation"
    echo "  --uninstall        Uninstall everything (Wazuh Manager, AISAC Agent, data)"
    echo "  -h                 Show this help"
    echo ""
    echo "Examples:"
    echo "  # Collector only (default)"
    echo "  sudo bash $0 -k aisac_xxxx -t eyJhbG..."
    echo ""
    echo "  # Full asset with response actions"
    echo "  sudo bash $0 -k aisac_xxxx -t eyJhbG... --agent"
    echo ""
    echo "  # Full asset with SOAR orchestration"
    echo "  sudo bash $0 -k aisac_xxxx -t eyJhbG... --soar"
    echo ""
    echo "  # Uninstall everything"
    echo "  sudo bash $0 --uninstall"
}

#==============================================================================
# Uninstall
#==============================================================================

prompt_yes_no() {
    local message="$1"
    local default="${2:-n}"
    local result

    if [ "$default" = "y" ]; then
        echo -en "${CYAN}$message${NC} [Y/n]: " >/dev/tty
    else
        echo -en "${CYAN}$message${NC} [y/N]: " >/dev/tty
    fi
    read result </dev/tty

    result="${result:-$default}"
    case "$result" in
        [Yy]*) return 0 ;;
        *) return 1 ;;
    esac
}

uninstall() {
    echo ""
    log_warning "This will remove Wazuh Manager, AISAC Agent, Command Server, and all related data"

    if ! prompt_yes_no "Are you sure you want to uninstall?" "n"; then
        echo "Uninstall cancelled"
        exit 0
    fi

    # ── Stop and remove AISAC services ──
    log_info "Stopping AISAC services..."
    for svc in aisac-agent aisac-server; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null || true
        fi
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done

    # Stop and remove Cloudflare Tunnel
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        log_info "Removing Cloudflare Tunnel..."
        cloudflared service uninstall 2>/dev/null || true
    fi

    # Kill lingering processes
    pkill -x "aisac-agent" 2>/dev/null || true
    pkill -x "aisac-server" 2>/dev/null || true
    sleep 1

    # Remove AISAC binaries
    log_info "Removing AISAC binaries..."
    rm -f /usr/local/bin/aisac-agent
    rm -f /usr/local/bin/aisac-server
    rm -rf "$INSTALL_DIR"
    log_success "AISAC binaries removed"

    # ── Stop and remove Wazuh Manager ──
    log_info "Stopping Wazuh Manager..."
    systemctl stop wazuh-manager 2>/dev/null || true
    systemctl stop filebeat 2>/dev/null || true
    systemctl stop wazuh-indexer 2>/dev/null || true
    systemctl stop wazuh-dashboard 2>/dev/null || true

    # Remove Wazuh packages
    if command -v dpkg &>/dev/null; then
        log_info "Removing Wazuh packages (deb)..."
        for pkg in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
            dpkg --purge "$pkg" 2>/dev/null || true
        done
    elif command -v rpm &>/dev/null; then
        log_info "Removing Wazuh packages (rpm)..."
        for pkg in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
            rpm -e "$pkg" 2>/dev/null || true
        done
    fi
    log_success "Wazuh packages removed"

    # ── Remove data ──
    if prompt_yes_no "Remove ALL data (config, certs, logs, Wazuh data)?" "n"; then
        log_info "Removing AISAC data..."
        rm -rf "$CONFIG_DIR"
        rm -rf "$DATA_DIR"
        rm -rf "$LOG_DIR"

        log_info "Removing Wazuh data..."
        rm -rf /var/ossec
        rm -rf /etc/filebeat
        rm -rf /etc/wazuh-indexer
        rm -rf /etc/wazuh-dashboard
        rm -rf /tmp/wazuh-install-files.tar
        rm -f /tmp/wazuh-install.sh /tmp/config.yml

        log_success "All data removed"
    else
        log_info "Data preserved in $CONFIG_DIR, /var/ossec, etc."
    fi

    systemctl daemon-reload

    echo ""
    log_success "Uninstall complete. All AISAC and Wazuh components removed."
    echo ""
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
# Step: Detect private IP
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
# Step: Install Wazuh Manager
#==============================================================================

install_wazuh_manager() {
    # Skip if already installed
    if [ -f /var/ossec/bin/wazuh-control ]; then
        log_success "Wazuh Manager already installed, skipping"
        return 0
    fi

    # Build overwrite flag for Wazuh installer
    local OVERWRITE_FLAG=""
    if [ "$OVERWRITE" = true ]; then
        OVERWRITE_FLAG="-o"
        log_info "Overwrite mode enabled — will reinstall existing Wazuh components"
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
        bash /tmp/wazuh-install.sh --wazuh-server "${WAZUH_SERVER_NAME}" ${IGNORE_REQUIREMENTS} ${OVERWRITE_FLAG} 2>&1 | tail -10

        # Disable indexer-connector warnings (no indexer to connect to)
        if [ -f /var/ossec/etc/ossec.conf ]; then
            sed -i 's|<enabled>yes</enabled>\(.*indexer\)|<enabled>no</enabled>\1|' /var/ossec/etc/ossec.conf 2>/dev/null || true
        fi
    else
        # Indexer + Server (Dashboard is optional)
        log_info "Installing Wazuh Indexer..."
        bash /tmp/wazuh-install.sh --wazuh-indexer wazuh-indexer ${IGNORE_REQUIREMENTS} ${OVERWRITE_FLAG} 2>&1 | tail -5

        log_info "Starting Wazuh cluster..."
        bash /tmp/wazuh-install.sh --start-cluster ${IGNORE_REQUIREMENTS} 2>&1 | tail -5

        log_info "Installing Wazuh Server..."
        bash /tmp/wazuh-install.sh --wazuh-server "${WAZUH_SERVER_NAME}" ${IGNORE_REQUIREMENTS} ${OVERWRITE_FLAG} 2>&1 | tail -5

        if [ "$NO_DASHBOARD" = false ]; then
            log_info "Installing Wazuh Dashboard..."
            bash /tmp/wazuh-install.sh --wazuh-dashboard wazuh-dashboard ${IGNORE_REQUIREMENTS} ${OVERWRITE_FLAG} 2>&1 | tail -5
        else
            log_info "Skipping Wazuh Dashboard (--no-dashboard)"
        fi
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
# Extract OpenSearch (Wazuh Indexer) admin password
#==============================================================================

extract_opensearch_password() {
    OPENSEARCH_PASSWORD=""

    # Only needed when Indexer is installed
    if [ "$NO_INDEXER" = true ]; then
        log_info "No Indexer installed — skipping OpenSearch password extraction"
        return
    fi

    # Method 1: Extract from wazuh-install-files.tar using wazuh-install.sh -p
    if [ -f /tmp/wazuh-install.sh ] && [ -f /tmp/wazuh-install-files.tar ]; then
        log_info "Extracting OpenSearch admin password from install files..."
        local passwords_output
        passwords_output=$(bash /tmp/wazuh-install.sh -p 2>/dev/null) || true
        if [ -n "$passwords_output" ]; then
            OPENSEARCH_PASSWORD=$(echo "$passwords_output" | grep -A1 "indexer" | grep -oP "password:\s*'\K[^']+|password:\s*\K\S+" | head -1) || true
        fi
    fi

    # Method 2: Extract from wazuh-passwords.txt if it exists
    if [ -z "$OPENSEARCH_PASSWORD" ] && [ -f /tmp/wazuh-install-files/wazuh-passwords.txt ]; then
        OPENSEARCH_PASSWORD=$(grep -A1 "indexer" /tmp/wazuh-install-files/wazuh-passwords.txt | grep -oP "password:\s*'\K[^']+|password:\s*\K\S+" | head -1) || true
    fi

    # Method 3: Try extracting passwords file from tar
    if [ -z "$OPENSEARCH_PASSWORD" ] && [ -f /tmp/wazuh-install-files.tar ]; then
        local tmp_extract="/tmp/wazuh-pw-extract"
        mkdir -p "$tmp_extract"
        tar -xf /tmp/wazuh-install-files.tar -C "$tmp_extract" 2>/dev/null || true
        if [ -f "$tmp_extract/wazuh-install-files/wazuh-passwords.txt" ]; then
            OPENSEARCH_PASSWORD=$(grep -A1 "indexer" "$tmp_extract/wazuh-install-files/wazuh-passwords.txt" | grep -oP "password:\s*'\K[^']+|password:\s*\K\S+" | head -1) || true
        fi
        rm -rf "$tmp_extract"
    fi

    # Method 4: Prompt the user
    if [ -z "$OPENSEARCH_PASSWORD" ]; then
        log_warning "Could not auto-detect OpenSearch admin password"
        echo -e "${YELLOW}The OpenSearch password is needed for alert collection from Wazuh Indexer.${NC}"
        echo -e "${YELLOW}You can find it by running: sudo bash /tmp/wazuh-install.sh -p${NC}"
        echo ""
        read -r -s -p "Enter OpenSearch admin password (or press Enter to skip): " OPENSEARCH_PASSWORD
        echo ""
    fi

    if [ -n "$OPENSEARCH_PASSWORD" ]; then
        log_success "OpenSearch admin password obtained"
    else
        log_warning "OpenSearch password not set - you must set AISAC_WAZUH_INDEXER_PASSWORD in the systemd service manually"
    fi
}

#==============================================================================
# Step: Call install-config to get AISAC config
#==============================================================================

fetch_aisac_config() {
    log_info "Fetching AISAC config from: ${REGISTER_URL}"

    local response http_code body auth_header=""
    if [ -n "$AUTH_TOKEN" ]; then
        auth_header="Authorization: Bearer ${AUTH_TOKEN}"
    fi

    local config_url="${REGISTER_URL}"
    if [ "${MCP_ENABLED:-false}" = true ]; then
        config_url="${REGISTER_URL}?mcp=true"
    fi

    response=$(curl -s -w "\n%{http_code}" -X GET "${config_url}" \
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

    # ── Validate and fix URLs ──
    # The install-config edge function sometimes returns agent-heartbeat for
    # ingest_url.  Detect and correct this so the collector always points at
    # syslog-ingest and the heartbeat always points at agent-heartbeat.

    # Ensure HEARTBEAT_URL points to agent-heartbeat
    if [ -n "$HEARTBEAT_URL" ] && ! echo "$HEARTBEAT_URL" | grep -q "agent-heartbeat"; then
        local base_url
        base_url=$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*|/functions/v1|')
        HEARTBEAT_URL="${base_url}/agent-heartbeat"
        log_warning "Corrected heartbeat URL to: ${HEARTBEAT_URL}"
    fi

    # Ensure INGEST_URL points to syslog-ingest
    if [ -n "$INGEST_URL" ] && ! echo "$INGEST_URL" | grep -q "syslog-ingest"; then
        local base_url
        base_url=$(echo "$INGEST_URL" | sed -E 's|/functions/v1/.*|/functions/v1|')
        INGEST_URL="${base_url}/syslog-ingest"
        log_warning "Corrected ingest URL to: ${INGEST_URL}"
    fi

    # If INGEST_URL is empty, derive it from HEARTBEAT_URL
    if [ -z "$INGEST_URL" ]; then
        local base_url
        base_url=$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*|/functions/v1|')
        INGEST_URL="${base_url}/syslog-ingest"
        log_warning "Ingest URL was empty, derived: ${INGEST_URL}"
    fi

    # Extract Cloudflare Tunnel config (if provisioned)
    CF_TUNNEL_TOKEN=$(json_extract "$body" ".tunnel.token" 2>/dev/null || echo "")
    CF_TUNNEL_HOSTNAME=$(json_extract "$body" ".tunnel.hostname" 2>/dev/null || echo "")

    log_success "Config received"
    log_info "  Asset ID:      ${ASSET_ID}"
    log_info "  Asset Name:    ${ASSET_NAME}"
    log_info "  Tenant ID:     ${TENANT_ID}"
    log_info "  Heartbeat URL: ${HEARTBEAT_URL}"
    log_info "  Ingest URL:    ${INGEST_URL}"
    if [ -n "${CF_TUNNEL_HOSTNAME}" ]; then
        log_info "  Tunnel:        ${CF_TUNNEL_HOSTNAME}"
    fi
}

#==============================================================================
# Step: Create tenant group on Wazuh Manager
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
# Agent ID management (persistent)
#==============================================================================

generate_agent_id() {
    local hostname_part
    hostname_part=$(hostname | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | head -c 20)
    local random_part
    random_part=$(head -c 6 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 6)
    echo "agent-${hostname_part}-${random_part}"
}

get_or_create_agent_id() {
    local id_file="$DATA_DIR/agent-id"

    # Allow explicit override via env var
    if [ -n "${AISAC_AGENT_ID:-}" ]; then
        log_info "Using Agent ID from AISAC_AGENT_ID env var" >&2
        mkdir -p "$DATA_DIR"
        echo "${AISAC_AGENT_ID}" > "$id_file"
        chmod 644 "$id_file"
        echo "${AISAC_AGENT_ID}"
        return
    fi

    # Reuse persisted ID if it exists
    if [ -f "$id_file" ]; then
        local existing_id
        existing_id=$(cat "$id_file" 2>/dev/null | tr -d '[:space:]')
        if [ -n "$existing_id" ]; then
            log_info "Reusing existing Agent ID from ${id_file}" >&2
            echo "$existing_id"
            return
        fi
    fi

    # Generate new ID and persist it
    local new_id
    new_id=$(generate_agent_id)
    mkdir -p "$DATA_DIR"
    echo "$new_id" > "$id_file"
    chmod 644 "$id_file"
    log_info "Generated new Agent ID: ${new_id}" >&2
    echo "$new_id"
}

#==============================================================================
# Step: Install AISAC Agent binary
#==============================================================================

install_aisac_binary() {
    log_info "Installing AISAC Agent binary..."

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 755 "$DATA_DIR"
    chmod 755 "$LOG_DIR"

    if [ "$AGENT_MODE" = true ]; then
        mkdir -p "$CONFIG_DIR/certs"
        chmod 700 "$CONFIG_DIR/certs"
    fi

    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
    fi

    # Option 1: Local binary in same directory
    local local_bin="${SCRIPT_DIR}/${BINARY_NAME}"
    if [ ! -f "$local_bin" ]; then
        local_bin="${SCRIPT_DIR}/${BINARY_NAME}-linux-amd64"
    fi
    if [ ! -f "$local_bin" ]; then
        # Try with os-arch suffix pattern
        local found_bin
        found_bin=$(ls "${SCRIPT_DIR}/${BINARY_NAME}"-*-* 2>/dev/null | head -1 || true)
        if [ -n "$found_bin" ]; then
            local_bin="$found_bin"
        fi
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

        local url="https://github.com/CISECSL/aisac-agent/releases/latest/download/aisac-agent-linux-${arch}"
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
# SOAR: Certificate Generation (mTLS)
#==============================================================================

generate_certificates() {
    local cert_dir="$1"
    local server_hostname="$2"

    log_info "Generating mTLS certificates for SOAR mode..."

    if ! command -v openssl &>/dev/null; then
        log_error "OpenSSL is required to generate certificates but not found"
        return 1
    fi

    local days=365
    local ca_subject="/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=AISAC CA"
    local agent_subject="/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=${AGENT_ID:-aisac-agent}"

    mkdir -p "$cert_dir"

    # Remove old certificates for clean state
    if [ -f "$cert_dir/ca.crt" ] || [ -f "$cert_dir/agent.crt" ] || [ -f "$cert_dir/server.crt" ]; then
        log_info "Removing old certificates for clean regeneration..."
        rm -f "$cert_dir/ca.crt" "$cert_dir/ca.key" "$cert_dir/ca.srl"
        rm -f "$cert_dir/agent.crt" "$cert_dir/agent.key"
        rm -f "$cert_dir/server.crt" "$cert_dir/server.key"
    fi

    # Generate CA
    log_info "Generating CA private key..."
    openssl genrsa -out "$cert_dir/ca.key" 4096 2>/dev/null

    log_info "Generating CA certificate..."
    openssl req -new -x509 -days $days -key "$cert_dir/ca.key" \
        -out "$cert_dir/ca.crt" -subj "$ca_subject" 2>/dev/null

    # Generate agent certificate
    log_info "Generating agent private key..."
    openssl genrsa -out "$cert_dir/agent.key" 2048 2>/dev/null

    openssl req -new -key "$cert_dir/agent.key" \
        -out "$cert_dir/agent.csr" -subj "$agent_subject" 2>/dev/null

    cat > "$cert_dir/agent.ext" << EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EXTEOF

    log_info "Generating agent certificate..."
    openssl x509 -req -in "$cert_dir/agent.csr" \
        -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
        -out "$cert_dir/agent.crt" -days $days \
        -extfile "$cert_dir/agent.ext" 2>/dev/null

    # Generate server certificates
    if [ -n "$server_hostname" ]; then
        local server_subject="/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=${server_hostname}"

        log_info "Generating server private key..."
        openssl genrsa -out "$cert_dir/server.key" 2048 2>/dev/null

        openssl req -new -key "$cert_dir/server.key" \
            -out "$cert_dir/server.csr" -subj "$server_subject" 2>/dev/null

        cat > "$cert_dir/server.ext" << EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = ${server_hostname}
IP.1 = 127.0.0.1
IP.2 = ::1
EXTEOF

        openssl x509 -req -in "$cert_dir/server.csr" \
            -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
            -out "$cert_dir/server.crt" -days $days \
            -extfile "$cert_dir/server.ext" 2>/dev/null

        rm -f "$cert_dir/server.csr" "$cert_dir/server.ext"
    fi

    # Clean up
    rm -f "$cert_dir/agent.csr" "$cert_dir/agent.ext" "$cert_dir"/*.srl

    # Set permissions
    chmod 600 "$cert_dir"/*.key
    chmod 644 "$cert_dir"/*.crt

    log_success "Certificates generated in $cert_dir"
    return 0
}

verify_certificates() {
    local cert_dir="$1"

    if [ ! -f "$cert_dir/ca.crt" ] || [ ! -f "$cert_dir/agent.crt" ] || [ ! -f "$cert_dir/agent.key" ]; then
        log_error "Missing certificate files in $cert_dir"
        return 1
    fi

    if ! openssl verify -CAfile "$cert_dir/ca.crt" "$cert_dir/agent.crt" &>/dev/null; then
        log_error "Agent certificate verification failed - not signed by CA"
        return 1
    fi

    if [ -f "$cert_dir/server.crt" ]; then
        if ! openssl verify -CAfile "$cert_dir/ca.crt" "$cert_dir/server.crt" &>/dev/null; then
            log_error "Server certificate verification failed - not signed by CA"
            return 1
        fi
        log_success "Server certificate verified against CA"
    fi

    log_success "Agent certificate verified against CA"
    return 0
}

#==============================================================================
# SOAR: Command Server Installation
#==============================================================================

generate_api_token() {
    local password="$1"
    if [ -n "$password" ]; then
        echo -n "$password" | sha256sum | cut -d' ' -f1
    else
        head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 44
    fi
}

install_command_server() {
    local api_token="$1"

    log_info "Installing AISAC Command Server..."

    # Strategy 1: Compile from source if available
    if [ -f "${SCRIPT_DIR}/../go.mod" ] && [ -d "${SCRIPT_DIR}/../cmd/server" ] && command -v go &>/dev/null; then
        log_info "Compiling command server from source..."
        if (cd "${SCRIPT_DIR}/.." && go build -o "$INSTALL_DIR/aisac-server" ./cmd/server/); then
            log_success "Command server compiled successfully"
        else
            log_error "Failed to compile command server from source"
            return 1
        fi
    # Strategy 2: Use local pre-built binary
    elif [ -f "$INSTALL_DIR/aisac-server" ]; then
        log_info "Using existing command server binary at $INSTALL_DIR/aisac-server"
    # Strategy 3: Download from GitHub Releases
    elif command -v curl &>/dev/null; then
        log_info "Downloading command server binary from GitHub Releases..."
        local arch
        arch=$(uname -m)
        case $arch in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            armv7l)  arch="arm" ;;
        esac
        local os
        os=$(uname -s | tr '[:upper:]' '[:lower:]')
        local repo="CISECSL/aisac-agent"
        local latest=""
        latest=$(curl -fs "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        local version="${latest:-v1.0.5}"
        local download_url="https://github.com/${repo}/releases/download/${version}/aisac-server-${os}-${arch}"

        log_info "Downloading from: ${download_url}"
        local tmpfile
        tmpfile=$(mktemp /tmp/aisac-server-XXXXXX)
        if curl -fsSL -o "$tmpfile" "$download_url"; then
            systemctl stop aisac-server 2>/dev/null || true
            rm -f "$INSTALL_DIR/aisac-server" 2>/dev/null || true
            mv "$tmpfile" "$INSTALL_DIR/aisac-server"
            log_success "Command server binary downloaded (${version})"
        else
            rm -f "$tmpfile"
            log_error "Failed to download command server binary"
            return 1
        fi
    else
        log_error "Cannot install command server: no source code, no local binary, and curl not available"
        return 1
    fi

    chmod 755 "$INSTALL_DIR/aisac-server"

    # Create systemd service for command server
    log_info "Creating command server systemd service..."

    cat > /etc/systemd/system/aisac-server.service << EOF
[Unit]
Description=AISAC Command Server (SOAR)
Documentation=https://github.com/CISECSL/aisac-agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/aisac-server --listen :8443 --cert $CONFIG_DIR/certs/server.crt --key $CONFIG_DIR/certs/server.key --ca $CONFIG_DIR/certs/ca.crt --api-token ${api_token} --api-mtls=false --log-level info
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aisac-server

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable aisac-server

    # Save API token to a secure file
    echo "$api_token" > "$CONFIG_DIR/server-api-token"
    chmod 600 "$CONFIG_DIR/server-api-token"
    log_info "API token saved to $CONFIG_DIR/server-api-token"

    log_success "Command server service installed"
    return 0
}

start_command_server() {
    log_info "Starting command server..."
    systemctl start aisac-server
    sleep 2

    if systemctl is-active --quiet aisac-server; then
        log_success "Command server is running"
        return 0
    else
        log_error "Failed to start command server"
        echo "Check logs with: journalctl -u aisac-server -n 50"
        return 1
    fi
}

#==============================================================================
# MCP Server Installation (Docker)
#==============================================================================

MCP_INSTALL_DIR="/opt/wazuh-mcp-server"
MCP_REPO="https://github.com/gensecaihq/Wazuh-MCP-Server.git"

install_mcp_server() {
    log_info "Installing Wazuh MCP Server..."

    # ── Ensure Docker is available ──
    if ! command -v docker &>/dev/null; then
        log_info "Docker not found. Installing Docker..."
        if command -v apt-get &>/dev/null; then
            curl -fsSL https://get.docker.com | bash 2>&1 | tail -5
            systemctl enable docker
            systemctl start docker
        elif command -v yum &>/dev/null; then
            curl -fsSL https://get.docker.com | bash 2>&1 | tail -5
            systemctl enable docker
            systemctl start docker
        else
            log_error "Cannot install Docker: unsupported package manager"
            return 1
        fi
        log_success "Docker installed"
    else
        log_success "Docker $(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) available"
    fi

    # Verify Docker Compose v2
    if ! docker compose version &>/dev/null; then
        log_error "Docker Compose v2 not available. Please install docker-compose-plugin."
        return 1
    fi

    # ── Ensure git is available ──
    if ! command -v git &>/dev/null; then
        log_info "Installing git..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y git 2>&1 | tail -2
        elif command -v yum &>/dev/null; then
            yum install -y git 2>&1 | tail -2
        fi
    fi

    # ── Clone or update repository ──
    if [ -d "$MCP_INSTALL_DIR" ]; then
        log_info "Updating existing MCP Server repository..."
        (cd "$MCP_INSTALL_DIR" && git pull --ff-only 2>&1 | tail -3) || true
    else
        log_info "Cloning Wazuh MCP Server..."
        git clone "$MCP_REPO" "$MCP_INSTALL_DIR" 2>&1 | tail -3
    fi

    # ── Generate X25519 DH keypair for DRA token rotation ──
    log_info "Generating X25519 DH keypair for MCP DRA..."
    local dh_privkey_raw dh_pubkey_raw
    dh_privkey_raw=$(openssl genpkey -algorithm X25519 2>/dev/null)
    MCP_DH_PRIVATE_KEY=$(echo "$dh_privkey_raw" | openssl pkey -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=')
    MCP_DH_PUBLIC_KEY=$(echo "$dh_privkey_raw" | openssl pkey -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=')

    # Generate a backup seed for self-healing
    MCP_SEED=$(openssl rand -hex 32)
    MCP_ROTATION_EPOCH=$(date +%s)

    # Save DH keys and seed to config dir
    cat > "$CONFIG_DIR/mcp-dra-state.json" << DRAEOF
{
    "dh_public_key": "${MCP_DH_PUBLIC_KEY}",
    "dh_priv_key": "${MCP_DH_PRIVATE_KEY}",
    "seed": "${MCP_SEED}",
    "rotation_epoch": ${MCP_ROTATION_EPOCH},
    "root_key": "",
    "chain_key": "",
    "peer_dh_pub": ""
}
DRAEOF
    chmod 600 "$CONFIG_DIR/mcp-dra-state.json"
    log_success "DRA keypair generated and saved to $CONFIG_DIR/mcp-dra-state.json"

    # Generate a temporary MCP auth token (will be replaced by DRA-derived token after registration)
    MCP_AUTH_TOKEN=$(python3 -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))" 2>/dev/null)
    echo "$MCP_AUTH_TOKEN" > "$CONFIG_DIR/mcp-auth-token"
    chmod 600 "$CONFIG_DIR/mcp-auth-token"
    log_success "Initial MCP auth token generated"

    # ── Detect Wazuh API password (wazuh-wui) ──
    local wazuh_api_password=""
    if [ -f /tmp/wazuh-install.sh ] && [ -f /tmp/wazuh-install-files.tar ]; then
        local passwords_output
        passwords_output=$(bash /tmp/wazuh-install.sh -p 2>/dev/null) || true
        if [ -n "$passwords_output" ]; then
            wazuh_api_password=$(echo "$passwords_output" | grep -A1 "wazuh-wui" | grep -oP "password:\s*'\K[^']+|password:\s*\K\S+" | head -1) || true
        fi
    fi
    if [ -z "$wazuh_api_password" ]; then
        log_warning "Could not auto-detect Wazuh API password"
        read -r -s -p "Enter Wazuh API password for user wazuh-wui (or press Enter to skip): " wazuh_api_password
        echo ""
    fi

    # ── Detect Wazuh Indexer host ──
    local indexer_host="localhost"
    if [ -f /etc/wazuh-indexer/opensearch.yml ]; then
        local configured_host
        configured_host=$(grep -oP '^network\.host:\s*\K\S+' /etc/wazuh-indexer/opensearch.yml 2>/dev/null || true)
        if [ -n "$configured_host" ]; then
            indexer_host="$configured_host"
        fi
    fi

    # ── Create .env for Docker container ──
    cat > "$MCP_INSTALL_DIR/.env" << MCPEOF
# Wazuh MCP Server Configuration
# Generated by install-manager.sh on $(date)

# === Wazuh Manager API ===
WAZUH_HOST=https://${PRIVATE_IP}
WAZUH_USER=wazuh-wui
WAZUH_PASS=${wazuh_api_password:-CHANGE_ME}
WAZUH_PORT=55000

# === MCP Server ===
MCP_HOST=$([ -n "${CF_TUNNEL_HOSTNAME:-}" ] && echo "127.0.0.1" || echo "0.0.0.0")
MCP_PORT=3000

# === Authentication ===
AUTH_MODE=bearer
AUTH_SECRET_KEY=${MCP_AUTH_TOKEN}
MCP_API_KEY=${MCP_AUTH_TOKEN}
TOKEN_LIFETIME_HOURS=8760

# === Wazuh Indexer (OpenSearch) ===
WAZUH_INDEXER_HOST=${indexer_host}
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=${OPENSEARCH_PASSWORD:-CHANGE_ME}

# === SSL ===
WAZUH_VERIFY_SSL=false

# === CORS ===
ALLOWED_ORIGINS=https://claude.ai,https://*.anthropic.com,http://localhost:*

# === Logging ===
LOG_LEVEL=INFO
MCPEOF

    chmod 600 "$MCP_INSTALL_DIR/.env"
    log_success "MCP Server .env configured"

    # ── Build and start with Docker Compose ──
    log_info "Building MCP Server Docker image..."
    (cd "$MCP_INSTALL_DIR" && docker compose build --pull 2>&1 | tail -5)
    log_success "MCP Server Docker image built"

    log_info "Starting MCP Server container..."
    (cd "$MCP_INSTALL_DIR" && docker compose up -d 2>&1 | tail -3)

    # Wait for healthy
    log_info "Waiting for MCP Server to be healthy..."
    local attempt=1
    local max_attempts=20
    while [ $attempt -le $max_attempts ]; do
        if curl -sf --max-time 3 http://localhost:3000/health 2>/dev/null | grep -q "healthy"; then
            break
        fi
        sleep 3
        attempt=$((attempt + 1))
    done

    if [ $attempt -gt $max_attempts ]; then
        log_warning "MCP Server health check timed out. Check: docker compose -f $MCP_INSTALL_DIR/compose.yml logs"
    else
        log_success "MCP Server is running and healthy on port 3000"
    fi

    # Detect MCP URL — use Cloudflare Tunnel if available, otherwise public IP
    MCP_SERVER_URL=""
    if [ -n "${CF_TUNNEL_HOSTNAME:-}" ]; then
        MCP_SERVER_URL="https://${CF_TUNNEL_HOSTNAME}/mcp"
        log_info "MCP Server URL (Cloudflare Tunnel): ${MCP_SERVER_URL}"
    else
        local public_ip
        public_ip=$(curl -sf --max-time 5 https://ifconfig.me 2>/dev/null || curl -sf --max-time 5 https://api.ipify.org 2>/dev/null || echo "")
        if [ -n "$public_ip" ]; then
            MCP_SERVER_URL="http://${public_ip}:3000/mcp"
        else
            MCP_SERVER_URL="http://${PRIVATE_IP}:3000/mcp"
        fi
        log_warning "MCP Server URL (no tunnel, HTTP): ${MCP_SERVER_URL}"
    fi
}

#==============================================================================
# Install Cloudflare Tunnel (cloudflared)
#==============================================================================

install_cloudflared() {
    log_info "Installing Cloudflare Tunnel..."

    # 1. Download cloudflared binary
    if command -v cloudflared &>/dev/null; then
        log_success "cloudflared already installed: $(cloudflared --version 2>/dev/null | head -1)"
    else
        log_info "Downloading cloudflared..."
        local arch
        arch=$(uname -m)
        case "$arch" in
            x86_64|amd64) arch="amd64" ;;
            aarch64|arm64) arch="arm64" ;;
            *) log_error "Unsupported architecture: $arch"; return 1 ;;
        esac
        curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}" \
            -o /usr/local/bin/cloudflared
        chmod +x /usr/local/bin/cloudflared
        log_success "cloudflared installed: $(cloudflared --version 2>/dev/null | head -1)"
    fi

    # 2. Stop existing cloudflared service if running (reinstall case)
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        log_info "Stopping existing cloudflared service..."
        cloudflared service uninstall 2>/dev/null || true
    fi

    # 3. Install as systemd service with tunnel token
    log_info "Configuring cloudflared service..."
    cloudflared service install "${CF_TUNNEL_TOKEN}"
    systemctl enable cloudflared 2>/dev/null
    systemctl start cloudflared

    # 4. Verify tunnel is connected
    log_info "Waiting for Cloudflare Tunnel to connect..."
    local attempt=1
    local max_attempts=20
    while [ $attempt -le $max_attempts ]; do
        if curl -sf --max-time 5 "https://${CF_TUNNEL_HOSTNAME}/health" 2>/dev/null | grep -qi "healthy\|ok\|running"; then
            log_success "Cloudflare Tunnel is active: https://${CF_TUNNEL_HOSTNAME}"
            return 0
        fi
        sleep 3
        attempt=$((attempt + 1))
    done

    # Tunnel might still be initializing — check cloudflared status instead
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        log_warning "Tunnel health check timed out, but cloudflared service is running"
        log_info "DNS propagation may take a few minutes. URL: https://${CF_TUNNEL_HOSTNAME}"
    else
        log_error "cloudflared service is not running. Check: journalctl -u cloudflared"
        return 1
    fi
}

#==============================================================================
# Agent registration with platform
#==============================================================================

register_agent() {
    log_info "Registering agent with AISAC platform..."

    # Collect system information
    local hostname_val os_info os_version arch kernel ip_address
    hostname_val=$(hostname)
    arch=$(uname -m)
    kernel=$(uname -r)
    os_info=""
    os_version=""

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os_info="$ID"
        os_version="$VERSION_ID"
    fi

    ip_address=""
    if command -v ip &>/dev/null; then
        ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "")
    fi

    # Determine capabilities
    local capabilities='["collector", "heartbeat"]'
    if [ "$SOAR_ENABLED" = true ] && [ -n "${SERVER_API_TOKEN:-}" ]; then
        capabilities='["collector", "soar", "heartbeat"]'
    fi

    # Build command_server fields if SOAR
    local cs_fields=""
    if [ "$SOAR_ENABLED" = true ] && [ -n "${SERVER_API_TOKEN:-}" ]; then
        cs_fields=$(cat <<CSEOF
,
    "command_server": {
        "api_token": "${SERVER_API_TOKEN}",
        "url": "${PUBLIC_SERVER_URL:-}"
    }
CSEOF
)
    fi

    # Build MCP fields if MCP enabled (DRA mode with DH public key)
    local mcp_fields=""
    if [ "$MCP_ENABLED" = true ] && [ -n "${MCP_DH_PUBLIC_KEY:-}" ]; then
        mcp_fields=$(cat <<MCPFEOF
,
    "mcp_server": {
        "auth_token": "${MCP_AUTH_TOKEN:-}",
        "dh_public_key": "${MCP_DH_PUBLIC_KEY}",
        "seed": "${MCP_SEED:-}",
        "rotation_epoch": ${MCP_ROTATION_EPOCH:-0},
        "url": "${MCP_SERVER_URL:-}"
    }
MCPFEOF
)
    fi

    local register_url
    register_url="$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*||')/functions/v1/agent-register"

    local payload=$(cat <<EOF
{
    "agent_id": "${AGENT_ID}",
    "asset_id": "${ASSET_ID}",
    "hostname": "${hostname_val}",
    "os": "${os_info}",
    "os_version": "${os_version}",
    "arch": "${arch}",
    "kernel": "${kernel}",
    "ip_address": "${ip_address}",
    "version": "1.0.5",
    "capabilities": ${capabilities}${cs_fields}${mcp_fields}
}
EOF
)

    log_info "Registration URL: ${register_url}"

    local response="" http_code=""

    if [ -n "$AUTH_TOKEN" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST "${register_url}" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: ${API_KEY}" \
            -H "Authorization: Bearer ${AUTH_TOKEN}" \
            -d "${payload}" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" -X POST "${register_url}" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: ${API_KEY}" \
            -d "${payload}" 2>/dev/null)
    fi
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | sed '$d')

    log_info "Registration response (HTTP ${http_code}): ${response}"

    case "$http_code" in
        200|201)
            log_success "Agent registered successfully"

            # Process DRA DH key exchange if platform returned its DH public key
            local platform_dh_pub
            platform_dh_pub=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mcp_dh_public_key',''))" 2>/dev/null || true)

            if [ -n "$platform_dh_pub" ] && [ -n "${MCP_DH_PRIVATE_KEY:-}" ]; then
                log_info "Computing DRA shared secret..."

                # Compute shared secret and initialize DRA using Python
                local dra_result
                dra_result=$(PLATFORM_DH_PUB="$platform_dh_pub" MCP_DH_PRIVATE_KEY="$MCP_DH_PRIVATE_KEY" python3 << 'PYEOF'
import sys, json, hashlib, hmac, base64, struct

def b64url_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (4 - len(s) % 4) if len(s) % 4 else ''
    return base64.b64decode(s)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def hkdf_derive(ikm, salt, info, length=32):
    """HKDF-SHA256 matching Web Crypto API."""
    # Extract
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt if isinstance(salt, bytes) else salt.encode(), ikm, hashlib.sha256).digest()
    # Expand
    t = b''
    okm = b''
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + (info if isinstance(info, bytes) else info.encode()) + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def x25519_scalar_mult(k, u):
    """X25519 scalar multiplication (RFC 7748)."""
    # Clamp scalar
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64

    # Convert u to integer (little-endian)
    u_int = int.from_bytes(u, 'little')
    u_int &= (1 << 255) - 1  # mask MSB

    p = 2**255 - 19
    a24 = 121665

    # Montgomery ladder
    x_1 = u_int
    x_2 = 1
    z_2 = 0
    x_3 = u_int
    z_3 = 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (int.from_bytes(bytes(k), 'little') >> t) & 1
        swap ^= k_t
        x_2, x_3 = (x_3, x_2) if swap else (x_2, x_3)
        z_2, z_3 = (z_3, z_2) if swap else (z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % p
        AA = (A * A) % p
        B = (x_2 - z_2) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x_3 = pow(DA + CB, 2, p)
        z_3 = (x_1 * pow(DA - CB, 2, p)) % p
        x_2 = (AA * BB) % p
        z_2 = (E * (AA + a24 * E)) % p

    x_2, x_3 = (x_3, x_2) if swap else (x_2, x_3)
    z_2, z_3 = (z_3, z_2) if swap else (z_2, z_3)

    result = (x_2 * pow(z_2, p - 2, p)) % p
    return result.to_bytes(32, 'little')

import os
priv_b64 = os.environ.get('MCP_DH_PRIVATE_KEY', '')
peer_pub_b64 = os.environ.get('PLATFORM_DH_PUB', '')

priv = b64url_decode(priv_b64)
peer_pub = b64url_decode(peer_pub_b64)

# X25519 shared secret
shared = x25519_scalar_mult(priv, peer_pub)

# Initialize DRA (must match TypeScript exactly)
root_key = hkdf_derive(shared, 'aisac-mcp-root', 'aisac-mcp-root-init', 32)
chain_key = hkdf_derive(root_key, 'aisac-mcp-chain-salt', 'aisac-mcp-chain', 32)
token_bytes = hkdf_derive(chain_key, 'aisac-mcp-salt', 'aisac-mcp-token', 32)
mcp_token = 'wazuh_' + b64url_encode(token_bytes)

print(json.dumps({
    'root_key': b64url_encode(root_key),
    'chain_key': b64url_encode(chain_key),
    'mcp_token': mcp_token,
}))
PYEOF
)
                if [ -n "$dra_result" ]; then
                    local dra_root_key dra_chain_key dra_mcp_token
                    dra_root_key=$(echo "$dra_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_key'])")
                    dra_chain_key=$(echo "$dra_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['chain_key'])")
                    dra_mcp_token=$(echo "$dra_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['mcp_token'])")

                    # Update DRA state file
                    cat > "$CONFIG_DIR/mcp-dra-state.json" << DRAEOF2
{
    "root_key": "${dra_root_key}",
    "chain_key": "${dra_chain_key}",
    "dh_public_key": "${MCP_DH_PUBLIC_KEY}",
    "dh_priv_key": "${MCP_DH_PRIVATE_KEY}",
    "peer_dh_pub": "${platform_dh_pub}"
}
DRAEOF2
                    chmod 600 "$CONFIG_DIR/mcp-dra-state.json"

                    # Update MCP_API_KEY in .env with DRA-derived token
                    if [ -d "$MCP_INSTALL_DIR" ] && [ -f "$MCP_INSTALL_DIR/.env" ]; then
                        sed -i "s|^MCP_API_KEY=.*|MCP_API_KEY=${dra_mcp_token}|" "$MCP_INSTALL_DIR/.env"
                        # Restart container to pick up new key
                        (cd "$MCP_INSTALL_DIR" && sudo docker compose restart 2>/dev/null) || true
                    fi

                    # Update local token file
                    echo "$dra_mcp_token" > "$CONFIG_DIR/mcp-auth-token"
                    chmod 600 "$CONFIG_DIR/mcp-auth-token"

                    log_success "DRA initialized: MCP token derived from DH key exchange"
                else
                    log_warning "DRA computation failed, using initial token"
                fi
            fi
            ;;
        *)
            log_warning "Registration returned HTTP ${http_code}. Continuing without registration."
            ;;
    esac
}

#==============================================================================
# Generate configuration
#==============================================================================

generate_config() {
    log_info "Generating configuration..."

    AGENT_ID=$(get_or_create_agent_id)
    log_info "Agent ID: ${AGENT_ID}"

    # Detect additional log sources
    local suricata_source="" syslog_source=""

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

    if [ "$AGENT_MODE" = true ]; then
        if [ -f /var/log/syslog ]; then
            log_success "Detected: Syslog"
            syslog_source="    - name: syslog
      type: file
      path: /var/log/syslog
      parser: syslog
      tags:
        - system"
        elif [ -f /var/log/messages ]; then
            log_success "Detected: System messages"
            syslog_source="    - name: syslog
      type: file
      path: /var/log/messages
      parser: syslog
      tags:
        - system"
        fi
    fi

    # SOAR-specific variables
    local server_enabled="false"
    local server_url="$DEFAULT_SERVER_URL"
    local tls_enabled="false"

    if [ "$SOAR_ENABLED" = true ]; then
        server_enabled="true"
        tls_enabled="true"
    fi

    local heartbeat_domain
    heartbeat_domain=$(echo "$HEARTBEAT_URL" | sed -E 's|^https?://([^:/]+).*|\1|')

    # ── Agent labels ──
    local labels="    - wazuh-manager"
    if [ "$AGENT_MODE" = true ]; then
        labels="    - production
    - wazuh-manager"
    else
        labels="    - collector
    - wazuh-manager"
    fi

    # ── Base config ──
    cat > "$CONFIG_DIR/agent.yaml" << EOF
# AISAC Agent Configuration
# Generated by install-manager.sh on $(date)
# Mode: $([ "$SOAR_ENABLED" = true ] && echo "Agent + SOAR" || ([ "$AGENT_MODE" = true ] && echo "Agent" || echo "Collector"))

agent:
  id: "${AGENT_ID}"
  labels:
${labels}
  heartbeat_interval: 30s
  reconnect_delay: 5s
  max_reconnect_delay: 5m

server:
  enabled: ${server_enabled}
  url: "${server_url}"
  connect_timeout: 30s
  write_timeout: 10s
  read_timeout: 60s

tls:
  enabled: ${tls_enabled}
  cert_file: "${CONFIG_DIR}/certs/agent.crt"
  key_file: "${CONFIG_DIR}/certs/agent.key"
  ca_file: "${CONFIG_DIR}/certs/ca.crt"
  skip_verify: false

EOF

    # ── Actions ──
    if [ "$AGENT_MODE" = true ]; then
        cat >> "$CONFIG_DIR/agent.yaml" << EOF
actions:
  enabled:
    - block_ip
    - unblock_ip
    - isolate_host
    - unisolate_host
    - disable_user
    - enable_user
    - kill_process
EOF
        if [ "$SOAR_ENABLED" = true ]; then
            cat >> "$CONFIG_DIR/agent.yaml" << EOF
  rate_limits:
    block_ip:
      max_per_minute: 10
      max_per_hour: 100
    isolate_host:
      max_per_minute: 1
      max_per_hour: 5
EOF
        fi
        cat >> "$CONFIG_DIR/agent.yaml" << EOF
  default_timeout: 5m
EOF
    else
        cat >> "$CONFIG_DIR/agent.yaml" << EOF
actions:
  enabled: []
  default_timeout: 5m
EOF
    fi

    # ── Callback ──
    cat >> "$CONFIG_DIR/agent.yaml" << EOF

callback:
  enabled: false
  url: ""
  auth_token: ""
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s

EOF

    # ── Heartbeat ──
    cat >> "$CONFIG_DIR/agent.yaml" << EOF
heartbeat:
  enabled: true
  url: "${HEARTBEAT_URL}"
  api_key: "${API_KEY}"
  auth_token: "${AUTH_TOKEN}"
  asset_id: "${ASSET_ID}"
  interval: 120s
  timeout: 10s
  skip_tls_verify: false

EOF

    # ── Registration ──
    if [ "$AGENT_MODE" = true ]; then
        cat >> "$CONFIG_DIR/agent.yaml" << EOF
registration:
  enabled: true
  url: "$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*||')/functions/v1/agent-webhook"
  api_key: "${API_KEY}"
  auth_token: "${AUTH_TOKEN}"
  asset_id: "${ASSET_ID}"
  command_server_url: "${PUBLIC_SERVER_URL:-}"
  command_server_token: "${SERVER_API_TOKEN:-}"

EOF
    fi

    # ── Collector ──
    # Wazuh alerts source: file-based if --no-indexer, OpenSearch API if indexer installed
    local wazuh_source
    if [ "$NO_INDEXER" = true ]; then
        wazuh_source="    - name: wazuh_alerts
      type: file
      path: /var/ossec/logs/alerts/alerts.json
      parser: wazuh_alerts
      tags:
        - security
        - hids"
    else
        wazuh_source="    - name: wazuh_alerts
      type: api
      parser: wazuh_alerts
      tags:
        - security
        - hids
      api:
        # Credentials set via environment variables in systemd service:
        #   AISAC_WAZUH_INDEXER_URL, AISAC_WAZUH_INDEXER_USER, AISAC_WAZUH_INDEXER_PASSWORD
        poll_interval: 30s
        page_size: 500
        skip_tls_verify: true
        min_rule_level: 3"
    fi

    cat >> "$CONFIG_DIR/agent.yaml" << EOF
collector:
  enabled: true

  sources:
${wazuh_source}
${suricata_source}
${syslog_source}

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

EOF

    # ── Control plane ──
    local control_plane_ips=""
    if [ "$SOAR_ENABLED" = true ] && [ -n "${PUBLIC_SERVER_URL:-}" ]; then
        local server_host
        server_host=$(echo "$PUBLIC_SERVER_URL" | sed -E 's|^https?://([^:/]+).*|\1|')
        if echo "$server_host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            control_plane_ips="    - \"${server_host}\"      # SOAR Command Server"
        fi
    fi

    cat >> "$CONFIG_DIR/agent.yaml" << EOF
control_plane:
  ips:
${control_plane_ips:-    # No control plane IPs configured}
  domains:
    - "${heartbeat_domain}"
  always_allowed: true

EOF

    # ── Safety ──
    if [ "$AGENT_MODE" = true ]; then
        cat >> "$CONFIG_DIR/agent.yaml" << EOF
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

EOF
    else
        cat >> "$CONFIG_DIR/agent.yaml" << EOF
safety:
  state_file: "${DATA_DIR}/safety_state.json"
  auto_revert_enabled: false

EOF
    fi

    # ── Logging ──
    cat >> "$CONFIG_DIR/agent.yaml" << EOF
logging:
  level: "info"
  format: "json"
  output: "stdout"
EOF

    chmod 600 "$CONFIG_DIR/agent.yaml"
    log_success "Configuration saved to ${CONFIG_DIR}/agent.yaml"
}

#==============================================================================
# Install and start systemd service
#==============================================================================

install_service() {
    log_info "Installing systemd service..."

    # OpenSearch env vars only when Indexer is installed
    local wazuh_env_lines=""
    if [ "$NO_INDEXER" = false ]; then
        # Detect Indexer bind address from opensearch.yml (falls back to localhost)
        local indexer_host="localhost"
        if [ -f /etc/wazuh-indexer/opensearch.yml ]; then
            local configured_host
            configured_host=$(grep -oP '^network\.host:\s*\K\S+' /etc/wazuh-indexer/opensearch.yml 2>/dev/null || true)
            if [ -n "$configured_host" ]; then
                indexer_host="$configured_host"
            fi
        fi
        wazuh_env_lines="# OpenSearch (Wazuh Indexer) credentials for alert collection
Environment=AISAC_WAZUH_INDEXER_URL=https://${indexer_host}:9200
Environment=AISAC_WAZUH_INDEXER_USER=admin
Environment=AISAC_WAZUH_INDEXER_PASSWORD=${OPENSEARCH_PASSWORD:-CHANGE_ME}"
    fi

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=AISAC Security Agent
Documentation=https://github.com/CISECSL/aisac-agent
After=network-online.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -c ${CONFIG_DIR}/agent.yaml
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.log

${wazuh_env_lines}

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
PrivateTmp=true

LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "AISAC Agent is running"
    else
        log_warning "AISAC Agent may not be running yet (check Wazuh API connectivity)"
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
    NO_DASHBOARD=false
    OVERWRITE=false
    AGENT_MODE=false
    SOAR_ENABLED=false
    MCP_ENABLED=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -k) API_KEY="$2"; shift 2 ;;
            -t) AUTH_TOKEN="$2"; shift 2 ;;
            -u) REGISTER_URL="$2"; shift 2 ;;
            -i) IGNORE_REQUIREMENTS="-i"; shift ;;
            --no-indexer) NO_INDEXER=true; NO_DASHBOARD=true; shift ;;
            --no-dashboard) NO_DASHBOARD=true; shift ;;
            -o|--overwrite) OVERWRITE=true; shift ;;
            --agent) AGENT_MODE=true; shift ;;
            --soar) SOAR_ENABLED=true; AGENT_MODE=true; shift ;;
            --mcp) MCP_ENABLED=true; shift ;;
            --uninstall)
                if [ "$EUID" -ne 0 ]; then
                    log_error "Must be run as root"
                    exit 1
                fi
                uninstall
                exit 0
                ;;
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

    # Calculate total steps
    local total_steps=5
    if [ "$AGENT_MODE" = true ]; then
        total_steps=6  # +registration
    fi
    if [ "$SOAR_ENABLED" = true ]; then
        total_steps=7  # +SOAR setup
    fi
    if [ "$MCP_ENABLED" = true ]; then
        total_steps=$((total_steps + 1))  # +MCP setup
    fi
    local step=0

    # ── Step: Detect server configuration ──
    step=$((step + 1))
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step ${step}/${total_steps}: Detecting server configuration                    ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    detect_private_ip

    # ── Step: Install Wazuh Manager ──
    step=$((step + 1))
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step ${step}/${total_steps}: Installing Wazuh Manager                          ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    install_wazuh_manager
    extract_opensearch_password

    # ── Step: Fetch AISAC config ──
    step=$((step + 1))
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step ${step}/${total_steps}: Fetching AISAC Platform config                    ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    fetch_aisac_config

    # ── Step: Create tenant group ──
    step=$((step + 1))
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step ${step}/${total_steps}: Creating tenant group on Wazuh Manager            ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    create_tenant_group

    # ── Step: SOAR setup (if enabled) ──
    SERVER_API_TOKEN=""
    PUBLIC_SERVER_URL=""

    if [ "$SOAR_ENABLED" = true ]; then
        step=$((step + 1))
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}  Step ${step}/${total_steps}: Setting up SOAR (certificates + command server) ${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""

        # Get or reuse API token
        if [ -f "$CONFIG_DIR/server-api-token" ]; then
            SERVER_API_TOKEN=$(cat "$CONFIG_DIR/server-api-token" 2>/dev/null | tr -d '[:space:]')
            log_info "Reusing existing Command Server API token"
        fi
        if [ -z "$SERVER_API_TOKEN" ]; then
            SERVER_API_TOKEN=$(generate_api_token "")
            log_info "Generated new Command Server API token"
        fi

        # Auto-detect public URL
        if [ -n "$PRIVATE_IP" ]; then
            PUBLIC_SERVER_URL="https://${PRIVATE_IP}:8443"
            log_info "Public CS URL: ${PUBLIC_SERVER_URL}"
        fi
    fi

    # ── Step: Install AISAC Agent ──
    step=$((step + 1))
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step ${step}/${total_steps}: Installing AISAC Agent                            ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    install_aisac_binary
    generate_config

    if [ "$SOAR_ENABLED" = true ]; then
        # Generate certificates if not present
        if [ ! -f "$CONFIG_DIR/certs/agent.crt" ] || [ ! -f "$CONFIG_DIR/certs/ca.crt" ]; then
            generate_certificates "$CONFIG_DIR/certs" "localhost"
        else
            log_info "Existing certificates found in $CONFIG_DIR/certs/"
        fi

        # Verify certificates
        if ! verify_certificates "$CONFIG_DIR/certs"; then
            log_error "Certificate verification failed"
            exit 1
        fi

        # Install and start command server
        install_command_server "$SERVER_API_TOKEN"
        start_command_server

        log_info "Waiting for command server to be ready..."
        sleep 3
    fi

    install_service

    # ── Step: Install MCP Server (if --mcp) ──
    MCP_AUTH_TOKEN=""
    MCP_SERVER_URL=""

    if [ "$MCP_ENABLED" = true ]; then
        step=$((step + 1))
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}  Step ${step}/${total_steps}: Installing Wazuh MCP Server (Docker)              ${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        install_mcp_server

        # Install Cloudflare Tunnel if provisioned
        if [ -n "${CF_TUNNEL_TOKEN:-}" ] && [ -n "${CF_TUNNEL_HOSTNAME:-}" ]; then
            log_info "Setting up Cloudflare Tunnel for MCP Server..."
            install_cloudflared
        fi
    fi

    # ── Step: Register agent (if --agent) ──
    if [ "$AGENT_MODE" = true ]; then
        step=$((step + 1))
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}  Step ${step}/${total_steps}: Registering agent with platform                 ${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        register_agent
    fi

    # ── Summary ──
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Manager installation complete!                     ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Wazuh Manager:${NC}   systemctl status wazuh-manager"
    echo -e "  ${CYAN}AISAC Agent:${NC}     systemctl status aisac-agent"
    echo -e "  ${CYAN}Agent Logs:${NC}      tail -f ${LOG_DIR}/agent.log"
    echo -e "  ${CYAN}Agent Config:${NC}    ${CONFIG_DIR}/agent.yaml"
    if [ "$NO_INDEXER" = false ]; then
        echo -e "  ${CYAN}Wazuh Indexer:${NC}   https://localhost:9200 (admin)"
        if [ "$NO_DASHBOARD" = false ]; then
            echo -e "  ${CYAN}Wazuh Dashboard:${NC} https://${PRIVATE_IP} (admin)"
        fi
        echo -e "  ${CYAN}Alert source:${NC}    OpenSearch API (wazuh-alerts-* index)"
    else
        echo -e "  ${CYAN}Alert source:${NC}    File (/var/ossec/logs/alerts/alerts.json)"
    fi

    if [ "$SOAR_ENABLED" = true ]; then
        echo ""
        echo -e "  ${CYAN}SOAR:${NC}"
        echo -e "    Command Server:  systemctl status aisac-server"
        echo -e "    API Token:       ${CONFIG_DIR}/server-api-token"
        echo -e "    Certificates:    ${CONFIG_DIR}/certs/"
    fi

    if [ "$AGENT_MODE" = true ]; then
        echo ""
        echo -e "  ${CYAN}Agent Mode:${NC}      Enabled (actions, safety, registration)"
    fi

    if [ "$MCP_ENABLED" = true ]; then
        echo ""
        echo -e "  ${CYAN}MCP Server:${NC}"
        echo -e "    Status:          docker compose -f ${MCP_INSTALL_DIR}/compose.yml ps"
        echo -e "    Logs:            docker compose -f ${MCP_INSTALL_DIR}/compose.yml logs -f"
        echo -e "    Health:          curl http://localhost:3000/health"
        echo -e "    URL:             ${MCP_SERVER_URL:-http://localhost:3000/mcp}"
        echo -e "    Auth Token:      ${CONFIG_DIR}/mcp-auth-token"
        if [ -n "${CF_TUNNEL_HOSTNAME:-}" ]; then
            echo -e "    Tunnel:          systemctl status cloudflared"
            echo -e "    Tunnel URL:      https://${CF_TUNNEL_HOSTNAME}"
        fi
        echo ""
        echo -e "  ${YELLOW}Claude Code config (~/.claude.json):${NC}"
        echo -e "    \"mcpServers\": {"
        echo -e "      \"wazuh\": {"
        echo -e "        \"type\": \"http\","
        echo -e "        \"url\": \"${MCP_SERVER_URL:-http://localhost:3000/mcp}\","
        echo -e "        \"headers\": { \"Authorization\": \"Bearer ${MCP_AUTH_TOKEN:-<token>}\" }"
        echo -e "      }"
        echo -e "    }"
    fi

    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo -e "    1. Open ports 1514/1515 (TCP) in firewall/security group"
    echo -e "    2. Install agents on assets with:"
    echo -e "       ${BLUE}curl -sSL .../install.sh -o install.sh && sudo bash install.sh -k <ASSET_API_KEY>${NC}"
    echo ""
}

main "$@"
