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
# Usage:
#   sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN>
#   sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN> --agent
#   sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN> --agent --soar
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

    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║           AISAC Manager Installer v2.0                        ║"
    echo "║                                                               ║"
    echo "║   Installs: Wazuh Manager + AISAC ${mode}$(printf '%*s' $((25 - ${#mode})) '')   ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
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
    echo "  --agent            Enable full asset capabilities (actions, safety, syslog)"
    echo "  --soar             Enable SOAR mode (mTLS + command server). Implies --agent"
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
# Extract Wazuh API password for wazuh-wui user
#==============================================================================

extract_wazuh_api_password() {
    WAZUH_API_PASSWORD=""

    # Method 1: Extract from wazuh-install-files.tar using wazuh-install.sh -p
    if [ -f /tmp/wazuh-install.sh ] && [ -f /tmp/wazuh-install-files.tar ]; then
        log_info "Extracting Wazuh API password from install files..."
        local passwords_output
        passwords_output=$(bash /tmp/wazuh-install.sh -p 2>/dev/null) || true
        if [ -n "$passwords_output" ]; then
            WAZUH_API_PASSWORD=$(echo "$passwords_output" | grep -A1 "wazuh-wui" | grep -oP "password:\s*'\K[^']+|password:\s*\K\S+" | head -1) || true
        fi
    fi

    # Method 2: Extract from wazuh-passwords.txt if it exists
    if [ -z "$WAZUH_API_PASSWORD" ] && [ -f /tmp/wazuh-install-files/wazuh-passwords.txt ]; then
        WAZUH_API_PASSWORD=$(grep -A1 "wazuh-wui" /tmp/wazuh-install-files/wazuh-passwords.txt | grep -oP "password:\s*'\K[^']+|password:\s*\K\S+" | head -1) || true
    fi

    # Method 3: Try extracting passwords file from tar
    if [ -z "$WAZUH_API_PASSWORD" ] && [ -f /tmp/wazuh-install-files.tar ]; then
        local tmp_extract="/tmp/wazuh-pw-extract"
        mkdir -p "$tmp_extract"
        tar -xf /tmp/wazuh-install-files.tar -C "$tmp_extract" 2>/dev/null || true
        if [ -f "$tmp_extract/wazuh-install-files/wazuh-passwords.txt" ]; then
            WAZUH_API_PASSWORD=$(grep -A1 "wazuh-wui" "$tmp_extract/wazuh-install-files/wazuh-passwords.txt" | grep -oP "password:\s*'\K[^']+|password:\s*\K\S+" | head -1) || true
        fi
        rm -rf "$tmp_extract"
    fi

    # Method 4: Prompt the user
    if [ -z "$WAZUH_API_PASSWORD" ]; then
        log_warning "Could not auto-detect Wazuh API password for user 'wazuh-wui'"
        echo -e "${YELLOW}The Wazuh API password is needed for alert collection via API.${NC}"
        echo -e "${YELLOW}You can find it by running: sudo bash /tmp/wazuh-install.sh -p${NC}"
        echo ""
        read -r -s -p "Enter Wazuh API password for user 'wazuh-wui' (or press Enter to skip): " WAZUH_API_PASSWORD
        echo ""
    fi

    if [ -n "$WAZUH_API_PASSWORD" ]; then
        log_success "Wazuh API password obtained"
    else
        log_warning "Wazuh API password not set - you must set AISAC_WAZUH_API_PASSWORD in the systemd service manually"
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

    log_success "Config received"
    log_info "  Asset ID:      ${ASSET_ID}"
    log_info "  Asset Name:    ${ASSET_NAME}"
    log_info "  Tenant ID:     ${TENANT_ID}"
    log_info "  Heartbeat URL: ${HEARTBEAT_URL}"
    log_info "  Ingest URL:    ${INGEST_URL}"
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
    "command_server_token": "${SERVER_API_TOKEN}",
    "command_server_url": "${PUBLIC_SERVER_URL:-}"
CSEOF
)
    fi

    # Build integration_config (Manager monitors itself as agent 000)
    local integration_config=""
    local manager_name
    manager_name=$(hostname | tr '[:upper:]' '[:lower:]')
    integration_config=$(cat <<ICEOF
,
    "integration_config": {
        "wazuh_agent_name": "${manager_name}",
        "wazuh_agent_id": "000"
    }
ICEOF
)

    local register_url
    register_url="$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*||')/functions/v1/agent-webhook"

    local payload=$(cat <<EOF
{
    "event": "agent_registered",
    "asset_id": "${ASSET_ID}",
    "agent_info": {
        "agent_id": "${AGENT_ID}",
        "hostname": "${hostname_val}",
        "os": "${os_info}",
        "os_version": "${os_version}",
        "arch": "${arch}",
        "kernel": "${kernel}",
        "ip_address": "${ip_address}",
        "version": "1.0.5",
        "capabilities": ${capabilities}
    }${cs_fields}${integration_config}
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
    cat >> "$CONFIG_DIR/agent.yaml" << EOF
collector:
  enabled: true

  sources:
    - name: wazuh_alerts
      type: api
      parser: wazuh_alerts
      tags:
        - security
        - hids
      api:
        # Credentials set via environment variables in systemd service:
        #   AISAC_WAZUH_API_URL, AISAC_WAZUH_API_USER, AISAC_WAZUH_API_PASSWORD
        poll_interval: 30s
        page_size: 500
        skip_tls_verify: true
        min_rule_level: 3
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

# Wazuh API credentials for alert collection
Environment=AISAC_WAZUH_API_URL=https://localhost:55000
Environment=AISAC_WAZUH_API_USER=wazuh-wui
Environment=AISAC_WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD:-CHANGE_ME}

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
    AGENT_MODE=false
    SOAR_ENABLED=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -k) API_KEY="$2"; shift 2 ;;
            -t) AUTH_TOKEN="$2"; shift 2 ;;
            -u) REGISTER_URL="$2"; shift 2 ;;
            -i) IGNORE_REQUIREMENTS="-i"; shift ;;
            --no-indexer) NO_INDEXER=true; shift ;;
            --agent) AGENT_MODE=true; shift ;;
            --soar) SOAR_ENABLED=true; AGENT_MODE=true; shift ;;
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
    extract_wazuh_api_password

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
    echo -e "  ${CYAN}Wazuh API:${NC}       https://localhost:55000 (wazuh-wui)"

    if [ "$NO_INDEXER" = false ]; then
        echo -e "  ${CYAN}Wazuh Dashboard:${NC} https://${PRIVATE_IP} (admin/admin)"
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

    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo -e "    1. Open ports 1514/1515 (TCP) in firewall/security group"
    echo -e "    2. Install agents on assets with:"
    echo -e "       ${BLUE}curl -sSL .../install.sh -o install.sh && sudo bash install.sh -k <ASSET_API_KEY>${NC}"
    echo ""
}

main "$@"
