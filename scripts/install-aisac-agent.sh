#!/bin/bash
#
# AISAC - AISAC Agent Installer for Linux
#
# Reads tenant config from /tmp/aisac-register.json (written by install-wazuh-agent.sh)
# and installs the AISAC Agent with the correct configuration.
#
# Usage:
#   ./install-aisac-agent.sh [--soar]
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/aisac"
CONFIG_DIR="/etc/aisac"
DATA_DIR="/var/lib/aisac"
LOG_DIR="/var/log/aisac"
SERVICE_NAME="aisac-agent"
BINARY_NAME="aisac-agent"
REGISTER_OUTPUT="/tmp/aisac-register.json"

# SOAR defaults
DEFAULT_SERVER_URL="wss://localhost:8443/ws"
SOAR_ENABLED=false

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
    WAZUH_AGENT_NAME=$(json_get_file "$REGISTER_OUTPUT" ".wazuh.agent_name")
    WAZUH_AGENT_ID=$(json_get_file "$REGISTER_OUTPUT" ".wazuh.agent_id")

    if [ -z "$API_KEY" ] || [ -z "$ASSET_ID" ]; then
        log_error "Missing api_key or asset_id in ${REGISTER_OUTPUT}"
        exit 1
    fi

    # ── Validate and fix URLs ──
    # The install-config edge function sometimes returns incorrect endpoints.
    # Ensure heartbeat → agent-heartbeat and ingest → syslog-ingest.

    if [ -n "$HEARTBEAT_URL" ] && ! echo "$HEARTBEAT_URL" | grep -q "agent-heartbeat"; then
        local base_url
        base_url=$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*|/functions/v1|')
        HEARTBEAT_URL="${base_url}/agent-heartbeat"
        log_warning "Corrected heartbeat URL to: ${HEARTBEAT_URL}"
    fi

    if [ -n "$INGEST_URL" ] && ! echo "$INGEST_URL" | grep -q "syslog-ingest"; then
        local base_url
        base_url=$(echo "$INGEST_URL" | sed -E 's|/functions/v1/.*|/functions/v1|')
        INGEST_URL="${base_url}/syslog-ingest"
        log_warning "Corrected ingest URL to: ${INGEST_URL}"
    fi

    if [ -z "$INGEST_URL" ]; then
        local base_url
        base_url=$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*|/functions/v1|')
        INGEST_URL="${base_url}/syslog-ingest"
        log_warning "Ingest URL was empty, derived: ${INGEST_URL}"
    fi

    log_success "Config loaded from ${REGISTER_OUTPUT}"
    log_info "  Asset ID:      ${ASSET_ID}"
    log_info "  Tenant ID:     ${TENANT_ID}"
    log_info "  Heartbeat URL: ${HEARTBEAT_URL}"
    log_info "  Ingest URL:    ${INGEST_URL}"
}

#------------------------------------------------------------------------------
# Agent ID management
#------------------------------------------------------------------------------

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

    # Option 1: Binary in same directory as script (exact name or with os-arch suffix)
    if [ -f "${SCRIPT_DIR}/${BINARY_NAME}" ]; then
        cp "${SCRIPT_DIR}/${BINARY_NAME}" "$INSTALL_DIR/$BINARY_NAME"
        log_success "Binary copied from ${SCRIPT_DIR}/${BINARY_NAME}"
    elif ls "${SCRIPT_DIR}/${BINARY_NAME}"-*-* &>/dev/null 2>&1; then
        local local_bin
        local_bin=$(ls "${SCRIPT_DIR}/${BINARY_NAME}"-*-* | head -1)
        cp "$local_bin" "$INSTALL_DIR/$BINARY_NAME"
        log_success "Binary copied from $local_bin"

    # Option 2: Download from GitHub Releases
    else
        local arch os
        arch=$(uname -m)
        os=$(uname -s | tr '[:upper:]' '[:lower:]')
        case "$arch" in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            *) log_error "Unsupported arch: $arch"; exit 1 ;;
        esac

        local url="https://github.com/CISECSL/aisac-agent/releases/latest/download/aisac-agent-${os}-${arch}"
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
# SOAR: Certificate Generation (mTLS)
#------------------------------------------------------------------------------

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

    # Generate server certificates if hostname provided
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

    if [ ! -f "$cert_dir/ca.crt" ]; then
        log_error "CA certificate not found: $cert_dir/ca.crt"
        return 1
    fi

    if [ ! -f "$cert_dir/agent.crt" ]; then
        log_error "Agent certificate not found: $cert_dir/agent.crt"
        return 1
    fi

    if [ ! -f "$cert_dir/agent.key" ]; then
        log_error "Agent key not found: $cert_dir/agent.key"
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

#------------------------------------------------------------------------------
# SOAR: Command Server Installation
#------------------------------------------------------------------------------

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
    # Strategy 3: Download pre-built binary from GitHub Releases
    elif command -v curl &>/dev/null; then
        log_info "Downloading command server binary from GitHub Releases..."
        local arch os
        arch=$(uname -m)
        case $arch in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            armv7l)  arch="arm" ;;
        esac
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

    log_success "Command server service installed"

    # Save API token to a secure file
    echo "$api_token" > "$CONFIG_DIR/server-api-token"
    chmod 600 "$CONFIG_DIR/server-api-token"
    log_info "API token saved to $CONFIG_DIR/server-api-token"

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

#------------------------------------------------------------------------------
# SOAR: Agent registration with platform
#------------------------------------------------------------------------------

register_agent() {
    local agent_id="$1"
    local api_key="$2"
    local asset_id="$3"
    local register_url="$4"
    local cs_api_token="${5:-}"
    local cs_url="${6:-}"
    local auth_token="${7:-}"

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
    if [ -n "$cs_api_token" ]; then
        capabilities='["collector", "soar", "heartbeat"]'
    fi

    # Build command_server fields if CS data provided
    local cs_fields=""
    if [ -n "$cs_api_token" ]; then
        cs_fields=$(cat <<CSEOF
,
    "command_server_token": "${cs_api_token}",
    "command_server_url": "${cs_url}"
CSEOF
)
    fi

    # Build integration_config with Wazuh agent mapping
    local integration_config=""
    if [ -n "$WAZUH_AGENT_NAME" ]; then
        integration_config=$(cat <<ICEOF
,
    "integration_config": {
        "wazuh_agent_name": "${WAZUH_AGENT_NAME}",
        "wazuh_agent_id": "${WAZUH_AGENT_ID:-}"
    }
ICEOF
)
    fi

    local payload=$(cat <<EOF
{
    "event": "agent_registered",
    "asset_id": "${asset_id}",
    "agent_info": {
        "agent_id": "${agent_id}",
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

    # Build auth headers: X-API-Key for the function + Authorization for Supabase gateway
    local auth_header=""
    if [ -n "$auth_token" ]; then
        auth_header="-H \"Authorization: Bearer ${auth_token}\""
    fi

    if command -v curl &>/dev/null; then
        if [ -n "$auth_token" ]; then
            response=$(curl -s -w "\n%{http_code}" -X POST "${register_url}" \
                -H "Content-Type: application/json" \
                -H "X-API-Key: ${api_key}" \
                -H "Authorization: Bearer ${auth_token}" \
                -d "${payload}" 2>/dev/null)
        else
            response=$(curl -s -w "\n%{http_code}" -X POST "${register_url}" \
                -H "Content-Type: application/json" \
                -H "X-API-Key: ${api_key}" \
                -d "${payload}" 2>/dev/null)
        fi
        http_code=$(echo "$response" | tail -n1)
        response=$(echo "$response" | sed '$d')
    elif command -v wget &>/dev/null; then
        if [ -n "$auth_token" ]; then
            response=$(wget -q -O - --header="Content-Type: application/json" \
                --header="X-API-Key: ${api_key}" \
                --header="Authorization: Bearer ${auth_token}" \
                --post-data="${payload}" "${register_url}" 2>/dev/null)
        else
            response=$(wget -q -O - --header="Content-Type: application/json" \
                --header="X-API-Key: ${api_key}" \
                --post-data="${payload}" "${register_url}" 2>/dev/null)
        fi
        if [ $? -eq 0 ]; then
            http_code="200"
        else
            http_code="500"
        fi
    else
        log_warning "Neither curl nor wget found. Skipping registration."
        return 1
    fi

    log_info "Registration response (HTTP ${http_code}): ${response}"

    case "$http_code" in
        200|201)
            log_success "Agent registered successfully"
            REGISTRATION_SUCCESS=true
            return 0
            ;;
        *)
            log_warning "Registration returned HTTP ${http_code}. Continuing without registration."
            return 0
            ;;
    esac
}

#------------------------------------------------------------------------------
# Generate config (supports both standard and SOAR modes)
#------------------------------------------------------------------------------

generate_config() {
    log_info "Generating configuration..."

    AGENT_ID=$(get_or_create_agent_id)
    log_info "Agent ID: ${AGENT_ID}"

    # Detect log sources
    local enable_suricata=false enable_wazuh=false enable_syslog=false
    local suricata_path="" wazuh_path="" syslog_path=""
    local collector_enabled=false

    if [ -f /var/log/suricata/eve.json ]; then
        enable_suricata=true
        suricata_path="/var/log/suricata/eve.json"
        collector_enabled=true
        log_success "Detected: Suricata EVE logs"
    fi

    if [ -f /var/ossec/logs/alerts/alerts.json ]; then
        enable_wazuh=true
        wazuh_path="/var/ossec/logs/alerts/alerts.json"
        collector_enabled=true
        log_success "Detected: Wazuh alerts"
    fi

    if [ -f /var/log/syslog ]; then
        enable_syslog=true
        syslog_path="/var/log/syslog"
        collector_enabled=true
        log_success "Detected: Syslog"
    elif [ -f /var/log/messages ]; then
        enable_syslog=true
        syslog_path="/var/log/messages"
        collector_enabled=true
        log_success "Detected: System messages"
    fi

    # SOAR-specific variables
    local server_enabled="false"
    local server_url="$DEFAULT_SERVER_URL"
    local tls_enabled="false"

    if [ "$SOAR_ENABLED" = "true" ]; then
        server_enabled="true"
        tls_enabled="true"
    fi

    # ── Base config ──
    cat > "$CONFIG_DIR/agent.yaml" << EOF
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

    # Add rate_limits only in SOAR mode
    if [ "$SOAR_ENABLED" = "true" ]; then
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

callback:
  enabled: false
  url: ""
  auth_token: ""
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s

heartbeat:
  enabled: true
  url: "${HEARTBEAT_URL}"
  api_key: "${API_KEY}"
  auth_token: "${AUTH_TOKEN}"
  asset_id: "${ASSET_ID}"
  interval: 120s
  timeout: 10s
  skip_tls_verify: false

registration:
  enabled: true
  url: "$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*||')/functions/v1/agent-webhook"
  api_key: "${API_KEY}"
  auth_token: "${AUTH_TOKEN}"
  asset_id: "${ASSET_ID}"
  command_server_url: "${PUBLIC_SERVER_URL:-}"
  command_server_token: "${SERVER_API_TOKEN:-}"

collector:
  enabled: ${collector_enabled}
EOF

    # ── Collector sources ──
    if [ "$collector_enabled" = "true" ]; then
        cat >> "$CONFIG_DIR/agent.yaml" << 'EOF'

  sources:
EOF

        if [ "$enable_suricata" = "true" ]; then
            cat >> "$CONFIG_DIR/agent.yaml" << EOF
    - name: suricata
      type: file
      path: ${suricata_path}
      parser: suricata_eve
      tags:
        - security
        - ids
EOF
        fi

        if [ "$enable_wazuh" = "true" ]; then
            cat >> "$CONFIG_DIR/agent.yaml" << EOF
    - name: wazuh
      type: file
      path: ${wazuh_path}
      parser: wazuh_alerts
      tags:
        - security
        - hids
        - wazuh
EOF
        fi

        if [ "$enable_syslog" = "true" ]; then
            cat >> "$CONFIG_DIR/agent.yaml" << EOF
    - name: syslog
      type: file
      path: ${syslog_path}
      parser: syslog
      tags:
        - system
EOF
        fi

        cat >> "$CONFIG_DIR/agent.yaml" << EOF

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
    fi

    # ── Control plane protection ──
    local control_plane_ips=""
    local control_plane_domains=""

    # Extract domain from heartbeat URL
    local hb_host
    hb_host=$(echo "$HEARTBEAT_URL" | sed -E 's|^https?://([^:/]+).*|\1|')
    if [ -n "$hb_host" ]; then
        control_plane_domains="    - \"$hb_host\""
    fi

    # Add SOAR server IP to control plane
    if [ "$SOAR_ENABLED" = "true" ] && [ -n "$server_url" ]; then
        local server_host
        server_host=$(echo "$server_url" | sed -E 's|^wss?://([^:/]+).*|\1|')
        if [ -n "$server_host" ] && echo "$server_host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            control_plane_ips="    - \"$server_host\"      # SOAR Command Server"
        fi
    fi

    if [ -z "$control_plane_ips" ]; then
        control_plane_ips="    # Add your control plane IPs here
    # - \"10.0.0.1\""
    fi
    if [ -z "$control_plane_domains" ]; then
        control_plane_domains="    - \"api.aisac.cisec.es\""
    fi

    cat >> "$CONFIG_DIR/agent.yaml" << EOF

control_plane:
  ips:
$control_plane_ips
  domains:
$control_plane_domains
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
  output: "file"
  file: "${LOG_DIR}/agent.log"
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
Documentation=https://github.com/CISECSL/aisac-agent
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
    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --soar) SOAR_ENABLED=true; shift ;;
            *) shift ;;
        esac
    done

    if [ "$EUID" -ne 0 ]; then
        log_error "Must be run as root"
        exit 1
    fi

    # Load config from install-wazuh-agent.sh output
    load_register_config
    create_directories
    install_binary

    # SOAR setup (before generate_config so variables are available)
    SERVER_API_TOKEN=""
    PUBLIC_SERVER_URL=""
    REGISTRATION_SUCCESS=false

    if [ "$SOAR_ENABLED" = "true" ]; then
        log_info "SOAR mode enabled"

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
        local detected_ip
        detected_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}')
        if [ -n "$detected_ip" ]; then
            PUBLIC_SERVER_URL="https://${detected_ip}:8443"
            log_info "Public CS URL: ${PUBLIC_SERVER_URL}"
        fi
    fi

    # Generate YAML config
    generate_config

    if [ "$SOAR_ENABLED" = "true" ]; then
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

        # Wait for server to be ready
        log_info "Waiting for command server to be ready..."
        sleep 3
    fi

    install_service
    start_service

    # Register agent with platform (after services are running)
    local register_url
    register_url="$(echo "$HEARTBEAT_URL" | sed -E 's|/functions/v1/.*||')/functions/v1/agent-webhook"
    if [ -n "$SERVER_API_TOKEN" ] && [ -n "$PUBLIC_SERVER_URL" ]; then
        register_agent "$AGENT_ID" "$API_KEY" "$ASSET_ID" "$register_url" "$SERVER_API_TOKEN" "$PUBLIC_SERVER_URL" "$AUTH_TOKEN"
    else
        register_agent "$AGENT_ID" "$API_KEY" "$ASSET_ID" "$register_url" "" "" "$AUTH_TOKEN"
    fi

    # Summary
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}              AISAC Agent installed successfully!               ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Config:${NC}  ${CONFIG_DIR}/agent.yaml"
    echo -e "  ${CYAN}Logs:${NC}    ${LOG_DIR}/agent.log"
    echo -e "  ${CYAN}Status:${NC}  systemctl status ${SERVICE_NAME}"

    if [ "$SOAR_ENABLED" = "true" ]; then
        echo ""
        echo -e "  ${CYAN}SOAR:${NC}"
        echo -e "    Command Server:  systemctl status aisac-server"
        echo -e "    API Token:       ${CONFIG_DIR}/server-api-token"
        echo -e "    Certificates:    ${CONFIG_DIR}/certs/"
    fi

    echo ""

    # Cleanup temp file
    rm -f "$REGISTER_OUTPUT"
}

main "$@"
