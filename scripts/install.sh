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
DEFAULT_INGEST_URL="https://api.aisac.cisec.es/v1/logs"
DEFAULT_HEARTBEAT_URL="https://api.aisac.cisec.es/v1/heartbeat"
DEFAULT_REGISTER_URL="https://api.aisac.cisec.es/v1/agent-webhook"
SERVICE_WAS_RUNNING=false
REGISTRATION_SUCCESS=false

#------------------------------------------------------------------------------
# Helper functions
#------------------------------------------------------------------------------

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║              AISAC Agent Installer v1.2                       ║"
    echo "║                                                               ║"
    echo "║   Security Information and Event Management (SIEM) Agent      ║"
    echo "║   with Security Orchestration and Response (SOAR) Actions     ║"
    echo "║                                                               ║"
    echo "║   • Auto-registration with AISAC Platform                     ║"
    echo "║   • Suricata, Wazuh, and Syslog collection                    ║"
    echo "║   • Automated incident response capabilities                  ║"
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
        echo -en "${CYAN}$message${NC} [$default]: " >/dev/tty
        read result </dev/tty
        if [ -z "$result" ]; then
            echo "$default"
        else
            echo "$result"
        fi
    else
        echo -en "${CYAN}$message${NC}: " >/dev/tty
        read result </dev/tty
        echo "$result"
    fi
}

prompt_password() {
    local message="$1"
    local result

    echo -en "${CYAN}$message${NC}: " >/dev/tty
    read -s result </dev/tty
    echo >/dev/tty
    echo "$result"
}

prompt_yes_no() {
    local message="$1"
    local default="$2"
    local result

    if [ "$default" = "y" ]; then
        echo -en "${CYAN}$message${NC} [Y/n]: " >/dev/tty
    else
        echo -en "${CYAN}$message${NC} [y/N]: " >/dev/tty
    fi

    read result </dev/tty
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
# Agent ID Generation and Registration
#------------------------------------------------------------------------------

generate_agent_id() {
    local hostname=$(hostname | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')
    local random_suffix=$(head -c 6 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 6)
    echo "agent-${hostname}-${random_suffix}"
}

register_agent() {
    local agent_id="$1"
    local api_key="$2"
    local asset_id="$3"
    local register_url="${4:-$DEFAULT_REGISTER_URL}"
    # Optional: Command Server data
    local cs_api_token="${5:-}"
    local cs_url="${6:-}"

    log_info "Registering agent with AISAC platform..."
    if [ -n "$cs_api_token" ]; then
        log_info "Including Command Server data (token: ${cs_api_token:0:16}..., url: ${cs_url})"
    else
        log_info "Registering without Command Server data (SOAR not configured)"
    fi

    # Collect system information
    local hostname=$(hostname)
    local os_info=""
    local os_version=""
    local arch=$(uname -m)
    local kernel=$(uname -r)

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os_info="$ID"
        os_version="$VERSION_ID"
    fi

    # Get primary IP address
    local ip_address=""
    if command -v ip &> /dev/null; then
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

    # Build JSON payload (agent-webhook format)
    local payload=$(cat <<EOF
{
    "event": "agent_registered",
    "asset_id": "${asset_id}",
    "agent_info": {
        "agent_id": "${agent_id}",
        "hostname": "${hostname}",
        "os": "${os_info}",
        "os_version": "${os_version}",
        "arch": "${arch}",
        "kernel": "${kernel}",
        "ip_address": "${ip_address}",
        "version": "1.0.1",
        "capabilities": ${capabilities}
    }${cs_fields}
}
EOF
)

    # Debug: show payload being sent (redact token)
    local debug_payload="$payload"
    if [ -n "$cs_api_token" ]; then
        debug_payload=$(echo "$payload" | sed "s/${cs_api_token}/${cs_api_token:0:8}...REDACTED/g")
    fi
    log_info "Registration URL: ${register_url}"
    log_info "Registration payload:"
    echo "$debug_payload"

    # Make registration request
    local response=""
    local http_code=""

    if command -v curl &> /dev/null; then
        response=$(curl -s -w "\n%{http_code}" -X POST "${register_url}" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: ${api_key}" \
            -d "${payload}" 2>/dev/null)
        http_code=$(echo "$response" | tail -n1)
        response=$(echo "$response" | sed '$d')
    elif command -v wget &> /dev/null; then
        # wget doesn't easily return status codes, so we'll try a simpler approach
        response=$(wget -q -O - --header="Content-Type: application/json" \
            --header="X-API-Key: ${api_key}" \
            --post-data="${payload}" "${register_url}" 2>/dev/null)
        if [ $? -eq 0 ]; then
            http_code="200"
        else
            http_code="500"
        fi
    else
        log_warning "Neither curl nor wget found. Skipping registration."
        return 1
    fi

    # Debug: show response
    log_info "Registration response (HTTP ${http_code}): ${response}"

    # Check response
    case "$http_code" in
        200|201)
            log_success "Agent registered successfully with ID: ${agent_id}"
            REGISTRATION_SUCCESS=true
            return 0
            ;;
        401|403)
            log_warning "Registration endpoint not available (HTTP ${http_code}). Continuing without registration."
            log_info "Agent will work normally with heartbeat and collector."
            return 0
            ;;
        404)
            log_warning "Registration endpoint not found. Agent will work in offline mode."
            log_info "Agent ID '${agent_id}' saved locally."
            return 0
            ;;
        409)
            log_warning "Agent ID already registered. Using existing registration."
            REGISTRATION_SUCCESS=true
            return 0
            ;;
        *)
            log_warning "Registration returned code ${http_code}. Continuing with local configuration."
            log_info "Response: ${response}"
            return 0
            ;;
    esac
}

#------------------------------------------------------------------------------
# Certificate Generation for mTLS (SOAR mode)
#------------------------------------------------------------------------------

generate_certificates() {
    local cert_dir="$1"
    local server_hostname="$2"

    log_info "Generating mTLS certificates for SOAR mode..."

    # Check if openssl is available
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL is required to generate certificates but not found"
        return 1
    fi

    local days=365
    local ca_subject="/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=AISAC CA"
    local agent_subject="/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=${AGENT_ID:-aisac-agent}"

    mkdir -p "$cert_dir"

    # Remove old certificates to ensure clean state
    # (This is important for reinstall scenarios where CA might have changed)
    if [ -f "$cert_dir/ca.crt" ] || [ -f "$cert_dir/agent.crt" ] || [ -f "$cert_dir/server.crt" ]; then
        log_info "Removing old certificates for clean regeneration..."
        rm -f "$cert_dir/ca.crt" "$cert_dir/ca.key" "$cert_dir/ca.srl"
        rm -f "$cert_dir/agent.crt" "$cert_dir/agent.key"
        rm -f "$cert_dir/server.crt" "$cert_dir/server.key"
    fi

    # Generate CA private key
    log_info "Generating CA private key..."
    openssl genrsa -out "$cert_dir/ca.key" 4096 2>/dev/null

    # Generate CA certificate
    log_info "Generating CA certificate..."
    openssl req -new -x509 -days $days -key "$cert_dir/ca.key" \
        -out "$cert_dir/ca.crt" -subj "$ca_subject" 2>/dev/null

    # Generate agent private key
    log_info "Generating agent private key..."
    openssl genrsa -out "$cert_dir/agent.key" 2048 2>/dev/null

    # Generate agent CSR
    openssl req -new -key "$cert_dir/agent.key" \
        -out "$cert_dir/agent.csr" -subj "$agent_subject" 2>/dev/null

    # Create agent certificate extensions
    cat > "$cert_dir/agent.ext" << EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EXTEOF

    # Generate agent certificate
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

        # Server extensions with SANs
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

    # Clean up temporary files
    rm -f "$cert_dir/agent.csr" "$cert_dir/agent.ext" "$cert_dir"/*.srl

    # Set permissions
    chmod 600 "$cert_dir"/*.key
    chmod 644 "$cert_dir"/*.crt

    log_success "Certificates generated in $cert_dir"
    echo ""
    echo -e "  ${CYAN}Generated files:${NC}"
    echo -e "    - ca.crt      (CA certificate - share with server)"
    echo -e "    - ca.key      (CA private key - keep secure!)"
    echo -e "    - agent.crt   (Agent certificate)"
    echo -e "    - agent.key   (Agent private key)"
    if [ -f "$cert_dir/server.crt" ]; then
        echo -e "    - server.crt  (Server certificate)"
        echo -e "    - server.key  (Server private key)"
    fi
    echo ""

    return 0
}

#------------------------------------------------------------------------------
# Command Server Installation (SOAR)
#------------------------------------------------------------------------------

generate_api_token() {
    local password="$1"

    if [ -n "$password" ]; then
        # Generate token from password using SHA256
        echo -n "$password" | sha256sum | cut -d' ' -f1
    else
        # Generate random 32-byte token
        head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 44
    fi
}

install_command_server() {
    local api_token="$1"

    log_info "Installing AISAC Command Server..."

    # Compile server binary if source available
    if [ -f "./go.mod" ] && [ -d "./cmd/server" ]; then
        if command -v go &> /dev/null; then
            log_info "Compiling command server from source..."
            if go build -o "$INSTALL_DIR/aisac-server" ./cmd/server/; then
                log_success "Command server compiled successfully"
            else
                log_error "Failed to compile command server"
                return 1
            fi
        else
            log_error "Go is required to compile the command server"
            return 1
        fi
    else
        log_error "Source code not found. Cannot compile command server."
        return 1
    fi

    chmod 755 "$INSTALL_DIR/aisac-server"

    # Create systemd service for command server
    log_info "Creating command server systemd service..."

    # Build ExecStart command
    local exec_cmd="$INSTALL_DIR/aisac-server \\\\\n"
    exec_cmd+="    --listen :8443 \\\\\n"
    exec_cmd+="    --cert $CONFIG_DIR/certs/server.crt \\\\\n"
    exec_cmd+="    --key $CONFIG_DIR/certs/server.key \\\\\n"
    exec_cmd+="    --ca $CONFIG_DIR/certs/ca.crt \\\\\n"
    exec_cmd+="    --api-token \"${api_token}\" \\\\\n"
    exec_cmd+="    --api-mtls=false \\\\\n"
    exec_cmd+="    --log-level info"

    cat > /etc/systemd/system/aisac-server.service << EOF
[Unit]
Description=AISAC Command Server (SOAR)
Documentation=https://github.com/aisacAdmin/aisac-agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=$(echo -e "$exec_cmd")
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aisac-server

# Security hardening
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

    # Save API token to a secure file for reference
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

    # Option 1: Compile from source if we're in the project directory with Go
    if [ -f "./go.mod" ] && [ -d "./cmd/agent" ]; then
        if command -v go &> /dev/null; then
            log_info "Source code detected, compiling from source..."
            if go build -o "$INSTALL_DIR/$BINARY_NAME" ./cmd/agent/; then
                log_success "Binary compiled successfully"
                chmod 755 "$INSTALL_DIR/$BINARY_NAME"
                ln -sf "$INSTALL_DIR/$BINARY_NAME" /usr/local/bin/$BINARY_NAME
                log_success "Binary installed to $INSTALL_DIR/$BINARY_NAME"
                return 0
            else
                log_warning "Compilation failed, trying other methods..."
            fi
        else
            log_warning "Go not installed, cannot compile from source"
        fi
    fi

    # Option 2: Check if prebuilt binary exists locally
    local binary_path=""

    if [ -f "./bin/${BINARY_NAME}" ]; then
        binary_path="./bin/${BINARY_NAME}"
    elif [ -f "./${BINARY_NAME}" ]; then
        binary_path="./${BINARY_NAME}"
    elif [ -f "../bin/${BINARY_NAME}" ]; then
        binary_path="../bin/${BINARY_NAME}"
    fi

    if [ -n "$binary_path" ]; then
        log_info "Using prebuilt binary: $binary_path"
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

        local download_url="https://github.com/aisacAdmin/aisac-agent/releases/download/v1.0.1/aisac-agent-${os}-${arch}"

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

    #--------------------------------------------------------------------------
    # Step 1: Platform Credentials (required for registration)
    #--------------------------------------------------------------------------
    echo -e "${YELLOW}--- Step 1: AISAC Platform Credentials ---${NC}"
    echo ""
    echo -e "${BLUE}To connect this agent to AISAC, you need:${NC}"
    echo -e "${BLUE}  1. API Key - from Platform > Assets > [Your Asset] > API Key${NC}"
    echo -e "${BLUE}  2. Asset ID - from Platform > Assets > [Your Asset] > ID${NC}"
    echo ""

    API_KEY=$(prompt "API Key (format: aisac_xxxx...)")

    if [ -z "$API_KEY" ]; then
        log_warning "No API Key provided. Agent will work in offline mode."
        API_KEY="aisac_your_api_key_here"
    fi

    ASSET_ID=$(prompt "Asset ID (UUID from platform)")

    if [ -z "$ASSET_ID" ]; then
        log_warning "No Asset ID provided. You'll need to add it later in the config file."
        ASSET_ID="your-asset-uuid-here"
    fi

    #--------------------------------------------------------------------------
    # Step 2: Auto-generate Agent ID
    #--------------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}--- Step 2: Agent ID ---${NC}"
    echo ""

    AGENT_ID=$(generate_agent_id)
    log_info "Generated Agent ID: ${AGENT_ID}"

    #--------------------------------------------------------------------------
    # Step 3: SOAR Configuration (optional)
    #--------------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}--- Step 3: SOAR Configuration (Command Server) ---${NC}"
    echo -e "${BLUE}SOAR allows receiving automated response commands from the platform.${NC}"
    echo -e "${BLUE}This enables n8n to send security actions to this agent.${NC}"
    echo ""

    INSTALL_COMMAND_SERVER=false
    SERVER_API_TOKEN=""
    PUBLIC_SERVER_URL=""

    if prompt_yes_no "Enable SOAR functionality (receive commands from server)?" "n"; then
        SOAR_ENABLED=true

        echo ""
        echo -e "${BLUE}The Command Server receives commands from n8n and forwards them to agents.${NC}"
        echo -e "${BLUE}It can run on this machine or on a separate server.${NC}"
        echo ""

        if prompt_yes_no "Install Command Server on this machine?" "y"; then
            INSTALL_COMMAND_SERVER=true
            SERVER_URL="wss://localhost:8443/ws"

            echo ""
            echo -e "${BLUE}API Token protects the Command Server REST API (used by n8n).${NC}"
            echo -e "${BLUE}You can enter a password to derive the token, or leave empty for random.${NC}"
            echo ""

            local token_password=$(prompt "Password for API token (leave empty for random)")
            SERVER_API_TOKEN=$(generate_api_token "$token_password")

            log_info "Generated API Token: ${SERVER_API_TOKEN:0:16}..."
            echo ""
            echo -e "${YELLOW}IMPORTANT: Save this token for n8n configuration:${NC}"
            echo -e "${CYAN}${SERVER_API_TOKEN}${NC}"
            echo ""

            # Public Server URL (needed for platform to send commands back)
            echo -e "${BLUE}Public Server URL: Used by the platform to send commands back to agents.${NC}"
            echo -e "${BLUE}This must be the publicly accessible URL (IP or domain) where this server listens.${NC}"
            echo -e "${YELLOW}Example: https://148.230.125.219:8443${NC}"
            echo ""
            PUBLIC_SERVER_URL=$(prompt "Public Server URL" "https://$(hostname -I | awk '{print $1}'):8443")
            echo ""
        else
            SERVER_URL=$(prompt "Command Server WebSocket URL" "$DEFAULT_SERVER_URL")

            echo ""
            echo -e "${BLUE}To enable SOAR commands from the platform, the CS API token and public URL are needed.${NC}"
            echo -e "${BLUE}These are used during registration so the platform can reach the Command Server.${NC}"
            echo ""

            SERVER_API_TOKEN=$(prompt "Command Server API Token (Bearer token used by n8n)")
            if [ -n "$SERVER_API_TOKEN" ]; then
                PUBLIC_SERVER_URL=$(prompt "Public Command Server URL" "https://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'IP'):8443")
            fi
        fi

        echo ""
        echo -e "${BLUE}mTLS certificates are required for secure communication.${NC}"

        if [ -f "$CONFIG_DIR/certs/agent.crt" ] && [ -f "$CONFIG_DIR/certs/ca.crt" ]; then
            log_success "Existing certificates found in $CONFIG_DIR/certs/"
            if prompt_yes_no "Use existing certificates?" "y"; then
                TLS_ENABLED=true
                GENERATE_CERTS=false
            else
                GENERATE_CERTS=true
            fi
        else
            if prompt_yes_no "Generate mTLS certificates automatically?" "y"; then
                GENERATE_CERTS=true
            else
                log_warning "You'll need to manually copy certificates to $CONFIG_DIR/certs/"
                log_info "Required files: ca.crt, agent.crt, agent.key"
                GENERATE_CERTS=false
            fi
        fi

        # Extract server hostname from URL for certificate generation
        SERVER_HOSTNAME=""
        if [ "$GENERATE_CERTS" = "true" ]; then
            # Extract hostname from wss://hostname:port/path
            SERVER_HOSTNAME=$(echo "$SERVER_URL" | sed -E 's#wss?://([^:/]+).*#\1#')
            if prompt_yes_no "Also generate server certificates for '$SERVER_HOSTNAME'?" "y"; then
                GENERATE_SERVER_CERTS=true
            else
                GENERATE_SERVER_CERTS=false
                SERVER_HOSTNAME=""
            fi
        fi

        TLS_ENABLED=true
    else
        SOAR_ENABLED=false
        SERVER_URL="$DEFAULT_SERVER_URL"
        TLS_ENABLED=false
        GENERATE_CERTS=false
    fi

    #--------------------------------------------------------------------------
    # Register agent with platform (includes CS data if SOAR enabled)
    #--------------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}--- Agent Registration ---${NC}"
    echo ""

    # Registration URL (allow override for staging)
    local register_url="${AISAC_REGISTER_URL:-$DEFAULT_REGISTER_URL}"

    if [ "$API_KEY" != "aisac_your_api_key_here" ] && [ "$ASSET_ID" != "your-asset-uuid-here" ]; then
        log_info "DEBUG registration decision: SERVER_API_TOKEN='${SERVER_API_TOKEN:0:8}...' PUBLIC_SERVER_URL='${PUBLIC_SERVER_URL}'"
        if [ -n "$SERVER_API_TOKEN" ] && [ -n "$PUBLIC_SERVER_URL" ]; then
            log_info "Registering WITH command_server data"
            register_agent "$AGENT_ID" "$API_KEY" "$ASSET_ID" "$register_url" \
                "$SERVER_API_TOKEN" "$PUBLIC_SERVER_URL"
        else
            log_info "Registering WITHOUT command_server data (SERVER_API_TOKEN empty='$([ -z "$SERVER_API_TOKEN" ] && echo yes || echo no)', PUBLIC_SERVER_URL empty='$([ -z "$PUBLIC_SERVER_URL" ] && echo yes || echo no)')"
            register_agent "$AGENT_ID" "$API_KEY" "$ASSET_ID" "$register_url"
        fi
    else
        log_warning "Skipping registration (missing credentials). Configure manually later."
    fi

    #--------------------------------------------------------------------------
    # Step 4: Log Collector Configuration
    #--------------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}--- Step 4: Log Collector Configuration (SIEM) ---${NC}"
    echo -e "${BLUE}Collector sends security logs to the AISAC platform for analysis.${NC}"
    echo ""

    if prompt_yes_no "Enable Log Collector?" "y"; then
        COLLECTOR_ENABLED=true

        INGEST_URL=$(prompt "Log Ingest URL" "$DEFAULT_INGEST_URL")

        # Auto-detect and configure log sources
        echo ""
        echo -e "${YELLOW}--- Detected Log Sources ---${NC}"

        ENABLE_SURICATA=false
        ENABLE_SYSLOG=false
        ENABLE_WAZUH=false

        # Suricata detection
        if [ -f /var/log/suricata/eve.json ]; then
            log_success "Suricata EVE logs detected at /var/log/suricata/eve.json"
            if prompt_yes_no "Enable Suricata collection?" "y"; then
                ENABLE_SURICATA=true
                SURICATA_PATH="/var/log/suricata/eve.json"
            fi
        else
            if prompt_yes_no "Enable Suricata EVE log collection (not detected)?" "n"; then
                ENABLE_SURICATA=true
                SURICATA_PATH=$(prompt "Suricata EVE log path" "/var/log/suricata/eve.json")
            fi
        fi

        # Wazuh detection
        if [ -f /var/ossec/logs/alerts/alerts.json ]; then
            log_success "Wazuh alerts detected at /var/ossec/logs/alerts/alerts.json"
            if prompt_yes_no "Enable Wazuh alerts collection?" "y"; then
                ENABLE_WAZUH=true
                WAZUH_PATH="/var/ossec/logs/alerts/alerts.json"
            fi
        else
            if prompt_yes_no "Enable Wazuh alerts collection (not detected)?" "n"; then
                ENABLE_WAZUH=true
                WAZUH_PATH=$(prompt "Wazuh alerts.json path" "/var/ossec/logs/alerts/alerts.json")
            fi
        fi

        # Syslog detection
        if [ -f /var/log/syslog ]; then
            log_success "Syslog detected at /var/log/syslog"
            if prompt_yes_no "Enable Syslog collection?" "y"; then
                ENABLE_SYSLOG=true
                SYSLOG_PATH="/var/log/syslog"
            fi
        elif [ -f /var/log/messages ]; then
            log_success "System messages detected at /var/log/messages"
            if prompt_yes_no "Enable system messages collection?" "y"; then
                ENABLE_SYSLOG=true
                SYSLOG_PATH="/var/log/messages"
            fi
        fi
    else
        COLLECTOR_ENABLED=false
    fi

    #--------------------------------------------------------------------------
    # Step 5: Heartbeat Configuration
    #--------------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}--- Step 5: Heartbeat Configuration ---${NC}"
    echo -e "${BLUE}Heartbeat reports agent status and health to the platform.${NC}"
    echo ""

    if prompt_yes_no "Enable Heartbeat (recommended)?" "y"; then
        HEARTBEAT_ENABLED=true
        HEARTBEAT_URL=$(prompt "Heartbeat URL" "$DEFAULT_HEARTBEAT_URL")
    else
        HEARTBEAT_ENABLED=false
    fi

    #--------------------------------------------------------------------------
    # Step 6: Safety Configuration (only if SOAR is enabled)
    #--------------------------------------------------------------------------
    ADDITIONAL_CONTROL_PLANE_IPS=""

    if [ "$SOAR_ENABLED" = "true" ]; then
        echo ""
        echo -e "${YELLOW}--- Step 6: Safety Configuration ---${NC}"
        echo -e "${BLUE}Safety features protect against accidental lockout:${NC}"
        echo -e "${BLUE}  • Control Plane Whitelist: IPs that can never be blocked${NC}"
        echo -e "${BLUE}  • Auto-Revert: Actions automatically undo after TTL expires${NC}"
        echo -e "${BLUE}  • Heartbeat Recovery: Auto-recovery if agent loses connectivity${NC}"
        echo ""
        echo -e "${GREEN}Detected control plane endpoints (auto-protected):${NC}"
        [ -n "$SERVER_URL" ] && echo -e "  • Command Server: $SERVER_URL"
        [ -n "$HEARTBEAT_URL" ] && echo -e "  • Heartbeat: ${HEARTBEAT_URL:-$DEFAULT_HEARTBEAT_URL}"
        [ "$COLLECTOR_ENABLED" = "true" ] && echo -e "  • Log Ingest: $INGEST_URL"
        echo ""

        if prompt_yes_no "Add additional control plane IPs? (SSH bastion, VPN, etc.)" "n"; then
            echo ""
            echo -e "${BLUE}Enter additional IPs to whitelist (comma-separated):${NC}"
            echo -e "${BLUE}Example: 10.0.0.1, 192.168.1.100${NC}"
            local extra_ips=$(prompt "Additional IPs" "")
            if [ -n "$extra_ips" ]; then
                # Convert comma-separated to YAML format
                ADDITIONAL_CONTROL_PLANE_IPS=$(echo "$extra_ips" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | while read ip; do
                    [ -n "$ip" ] && echo "    - \"$ip\""
                done)
            fi
        fi

        log_success "Safety features configured"
    fi

    #--------------------------------------------------------------------------
    # Summary
    #--------------------------------------------------------------------------
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    Configuration Summary                       ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Agent ID:${NC}       ${AGENT_ID}"
    echo -e "  ${CYAN}Asset ID:${NC}       ${ASSET_ID}"
    echo -e "  ${CYAN}SOAR Enabled:${NC}   ${SOAR_ENABLED}"
    echo -e "  ${CYAN}Collector:${NC}      ${COLLECTOR_ENABLED}"
    if [ "$COLLECTOR_ENABLED" = "true" ]; then
        [ "$ENABLE_SURICATA" = "true" ] && echo -e "    - Suricata:   ${SURICATA_PATH:-/var/log/suricata/eve.json}"
        [ "$ENABLE_WAZUH" = "true" ] && echo -e "    - Wazuh:      ${WAZUH_PATH:-/var/ossec/logs/alerts/alerts.json}"
        [ "$ENABLE_SYSLOG" = "true" ] && echo -e "    - Syslog:     ${SYSLOG_PATH:-/var/log/syslog}"
    fi
    echo -e "  ${CYAN}Heartbeat:${NC}      ${HEARTBEAT_ENABLED}"
    if [ "$SOAR_ENABLED" = "true" ]; then
        echo -e "  ${CYAN}Safety:${NC}         Enabled (Whitelist + Auto-Revert + Recovery)"
    fi
    if [ "$REGISTRATION_SUCCESS" = "true" ]; then
        echo -e "  ${GREEN}Registration:${NC}   ✓ Registered with platform"
    else
        echo -e "  ${YELLOW}Registration:${NC}   Offline mode"
    fi
    echo ""

    if ! prompt_yes_no "Proceed with this configuration?" "y"; then
        log_error "Installation cancelled by user"
        exit 1
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

        if [ "$ENABLE_WAZUH" = "true" ]; then
            cat >> "$config_file" << EOF
    - name: wazuh
      type: file
      path: ${WAZUH_PATH:-/var/ossec/logs/alerts/alerts.json}
      parser: wazuh_alerts
      tags:
        - security
        - hids
        - wazuh
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

    # Extract control plane domains/IPs from configured URLs
    local control_plane_ips=""
    local control_plane_domains=""

    # Extract domain from SERVER_URL (wss://host:port/path -> host)
    if [ -n "$SERVER_URL" ] && [ "$SOAR_ENABLED" = "true" ]; then
        local server_host=$(echo "$SERVER_URL" | sed -E 's|^wss?://([^:/]+).*|\1|')
        if [ -n "$server_host" ]; then
            # Check if it's an IP or domain
            if echo "$server_host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                control_plane_ips="    - \"$server_host\"      # SOAR Command Server"
            else
                control_plane_domains="    - \"$server_host\""
            fi
        fi
    fi

    # Extract domain from HEARTBEAT_URL
    if [ -n "$HEARTBEAT_URL" ] || [ -n "$DEFAULT_HEARTBEAT_URL" ]; then
        local hb_url="${HEARTBEAT_URL:-$DEFAULT_HEARTBEAT_URL}"
        local hb_host=$(echo "$hb_url" | sed -E 's|^https?://([^:/]+).*|\1|')
        if [ -n "$hb_host" ]; then
            if [ -n "$control_plane_domains" ]; then
                control_plane_domains="$control_plane_domains
    - \"$hb_host\""
            else
                control_plane_domains="    - \"$hb_host\""
            fi
        fi
    fi

    # Extract domain from INGEST_URL (collector)
    if [ -n "$INGEST_URL" ] && [ "$COLLECTOR_ENABLED" = "true" ]; then
        local ingest_host=$(echo "$INGEST_URL" | sed -E 's|^https?://([^:/]+).*|\1|')
        if [ -n "$ingest_host" ]; then
            # Avoid duplicates
            if ! echo "$control_plane_domains" | grep -q "$ingest_host"; then
                if [ -n "$control_plane_domains" ]; then
                    control_plane_domains="$control_plane_domains
    - \"$ingest_host\""
                else
                    control_plane_domains="    - \"$ingest_host\""
                fi
            fi
        fi
    fi

    # Add user-provided additional IPs
    if [ -n "$ADDITIONAL_CONTROL_PLANE_IPS" ]; then
        if [ -n "$control_plane_ips" ]; then
            control_plane_ips="$control_plane_ips
$ADDITIONAL_CONTROL_PLANE_IPS"
        else
            control_plane_ips="$ADDITIONAL_CONTROL_PLANE_IPS"
        fi
    fi

    # Default control plane entries if none extracted
    if [ -z "$control_plane_ips" ]; then
        control_plane_ips="    # Add your control plane IPs here (SOAR server, management, etc.)
    # - \"10.0.0.1\""
    fi
    if [ -z "$control_plane_domains" ]; then
        control_plane_domains="    - \"api.aisac.cisec.es\""
    fi

    cat >> "$config_file" << EOF

# Control plane protection (IPs/domains that should NEVER be blocked)
# These are auto-detected from your configured URLs
control_plane:
  ips:
$control_plane_ips
  domains:
$control_plane_domains
  always_allowed: true

# Safety mechanisms for destructive SOAR actions
safety:
  # Persist active actions to survive agent restarts
  state_file: "${DATA_DIR}/safety_state.json"

  # Auto-revert: automatically undo destructive actions after TTL expires
  auto_revert_enabled: true

  # Default TTL for reversible actions
  default_ttl: 1h

  # Per-action TTL overrides
  action_ttls:
    isolate_host: 30m   # Critical: short TTL - most disruptive action
    block_ip: 4h        # IP blocks revert after 4 hours
    disable_user: 2h    # User disables revert after 2 hours

  # Heartbeat Auto-Recovery: if agent loses connectivity, trigger recovery
  # Prevents lockout if an action accidentally blocks the agent
  heartbeat_failure_threshold: 5   # 5 failures x 2min = ~10 min before recovery
  recovery_actions:
    - unisolate_host    # Restore network connectivity
    - unblock_all_ips   # Remove all IP blocks

logging:
  level: "info"
  format: "json"
  output: "file"
  file: "${LOG_DIR}/agent.log"
EOF

    chmod 600 "$config_file"
    log_success "Configuration saved to $config_file"
    log_info "Safety features enabled: Control Plane Whitelist, TTL Auto-Revert, Heartbeat Recovery"
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
    echo -e "  ${CYAN}Agent ID:${NC}               ${AGENT_ID}"
    echo -e "  ${CYAN}Installation Directory:${NC} $INSTALL_DIR"
    echo -e "  ${CYAN}Configuration:${NC}          $CONFIG_DIR/agent.yaml"
    echo -e "  ${CYAN}Data Directory:${NC}         $DATA_DIR"
    echo -e "  ${CYAN}Log File:${NC}               $LOG_DIR/agent.log"
    echo ""

    # Registration status
    if [ "$REGISTRATION_SUCCESS" = "true" ]; then
        echo -e "  ${GREEN}✓ Agent registered with AISAC platform${NC}"
    else
        echo -e "  ${YELLOW}○ Agent running in offline mode${NC}"
    fi

    # Safety features status (only for SOAR mode)
    if [ "$SOAR_ENABLED" = "true" ]; then
        echo ""
        echo -e "  ${CYAN}Safety Features:${NC}"
        echo -e "    ${GREEN}✓${NC} Control Plane Whitelist (protected IPs/domains)"
        echo -e "    ${GREEN}✓${NC} Auto-Revert (isolate_host: 30m, block_ip: 4h)"
        echo -e "    ${GREEN}✓${NC} Heartbeat Recovery (after 5 consecutive failures)"
    fi

    # Command server status
    if [ "${INSTALL_COMMAND_SERVER:-false}" = "true" ]; then
        echo ""
        echo -e "  ${GREEN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "  ${GREEN}                 Command Server (SOAR)                       ${NC}"
        echo -e "  ${GREEN}═══════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  ${CYAN}Service:${NC}     aisac-server"
        echo -e "  ${CYAN}Listen:${NC}      :8443 (WebSocket + REST API)"
        echo -e "  ${CYAN}API Token:${NC}   ${CONFIG_DIR}/server-api-token"
        echo ""
        echo -e "  ${YELLOW}n8n Configuration:${NC}"
        echo -e "    REST API URL:  ${CYAN}https://localhost:8443/api/v1${NC}"
        echo -e "    API Token:     ${CYAN}${SERVER_API_TOKEN}${NC}"
        echo ""
        echo -e "  ${YELLOW}Server Commands:${NC}"
        echo -e "    Start:   ${CYAN}systemctl start aisac-server${NC}"
        echo -e "    Stop:    ${CYAN}systemctl stop aisac-server${NC}"
        echo -e "    Status:  ${CYAN}systemctl status aisac-server${NC}"
        echo -e "    Logs:    ${CYAN}journalctl -u aisac-server -f${NC}"
    fi
    echo ""

    echo -e "  ${YELLOW}Agent Commands:${NC}"
    echo -e "    Start:   ${CYAN}systemctl start ${SERVICE_NAME}${NC}"
    echo -e "    Stop:    ${CYAN}systemctl stop ${SERVICE_NAME}${NC}"
    echo -e "    Status:  ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
    echo -e "    Logs:    ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
    echo -e "    Config:  ${CYAN}nano ${CONFIG_DIR}/agent.yaml${NC}"
    echo ""

    # Pending configuration warnings
    local has_warnings=false

    if [ "$API_KEY" = "aisac_your_api_key_here" ]; then
        has_warnings=true
        echo -e "  ${YELLOW}⚠ PENDING:${NC} Add your API Key to the config file"
    fi

    if [ "$ASSET_ID" = "your-asset-uuid-here" ]; then
        has_warnings=true
        echo -e "  ${YELLOW}⚠ PENDING:${NC} Add your Asset ID to the config file"
    fi

    if [ "$TLS_ENABLED" = "true" ] && [ "${GENERATE_CERTS:-false}" = "false" ]; then
        has_warnings=true
        echo -e "  ${YELLOW}⚠ PENDING:${NC} For SOAR, add certificates to ${CONFIG_DIR}/certs/"
        echo -e "              (agent.crt, agent.key, ca.crt)"
    fi

    if [ "$has_warnings" = "true" ]; then
        echo ""
    fi

    # Quick start guide
    echo -e "  ${CYAN}Quick Start:${NC}"
    echo -e "    1. Verify config:  ${CYAN}cat ${CONFIG_DIR}/agent.yaml${NC}"
    echo -e "    2. Check status:   ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
    echo -e "    3. Watch logs:     ${CYAN}tail -f ${LOG_DIR}/agent.log${NC}"
    echo ""
    echo -e "  ${BLUE}Documentation: https://github.com/aisacAdmin/aisac-agent${NC}"
    echo ""
}

#------------------------------------------------------------------------------
# Certificate verification
#------------------------------------------------------------------------------

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

    # Verify agent certificate against CA
    if ! openssl verify -CAfile "$cert_dir/ca.crt" "$cert_dir/agent.crt" &>/dev/null; then
        log_error "Agent certificate verification failed - not signed by CA"
        return 1
    fi

    # If server certificates exist, verify them too
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
# Cleanup function (stops all AISAC services)
#------------------------------------------------------------------------------

cleanup_services() {
    log_info "Cleaning up existing AISAC services..."

    # Stop and disable aisac-agent
    if systemctl is-active --quiet aisac-agent 2>/dev/null; then
        log_info "Stopping aisac-agent..."
        systemctl stop aisac-agent 2>/dev/null || true
    fi
    systemctl disable aisac-agent 2>/dev/null || true

    # Stop and disable aisac-server
    if systemctl is-active --quiet aisac-server 2>/dev/null; then
        log_info "Stopping aisac-server..."
        systemctl stop aisac-server 2>/dev/null || true
    fi
    systemctl disable aisac-server 2>/dev/null || true

    # Kill any lingering processes (exact match only to avoid killing installer)
    pkill -x "aisac-agent" 2>/dev/null || true
    pkill -x "aisac-server" 2>/dev/null || true

    # Wait for processes to terminate
    sleep 2

    # Remove old service files
    rm -f /etc/systemd/system/aisac-agent.service
    rm -f /etc/systemd/system/aisac-server.service
    systemctl daemon-reload

    log_success "Services cleaned up"
}

#------------------------------------------------------------------------------
# Uninstall function
#------------------------------------------------------------------------------

uninstall() {
    echo ""
    log_warning "This will remove AISAC Agent and Command Server from your system"

    if ! prompt_yes_no "Are you sure you want to uninstall?" "n"; then
        echo "Uninstall cancelled"
        exit 0
    fi

    # Clean up all services
    cleanup_services

    log_info "Removing binaries..."
    rm -f /usr/local/bin/${BINARY_NAME}
    rm -f /usr/local/bin/aisac-server
    rm -rf "$INSTALL_DIR"

    if prompt_yes_no "Remove configuration, data, and certificates?" "n"; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$DATA_DIR"
        rm -rf "$LOG_DIR"
        log_success "Configuration, data, and certificates removed"
    else
        log_info "Configuration preserved in $CONFIG_DIR"
    fi

    log_success "AISAC Agent and Command Server uninstalled"
}

#------------------------------------------------------------------------------
# Non-interactive mode support
#------------------------------------------------------------------------------

# Environment variables for non-interactive mode:
# AISAC_API_KEY     - API Key from AISAC Platform
# AISAC_ASSET_ID    - Asset ID (UUID) from AISAC Platform
# AISAC_SOAR        - Enable SOAR (true/false, default: false)
# AISAC_COLLECTOR   - Enable Collector (true/false, default: true)
# AISAC_HEARTBEAT   - Enable Heartbeat (true/false, default: true)
# AISAC_CS_TOKEN    - Command Server API token (optional, for SOAR)
# AISAC_CS_URL      - Command Server public URL (optional, for SOAR)
# AISAC_REGISTER_URL - Override registration endpoint (optional, for staging)
# AISAC_NONINTERACTIVE - Run in non-interactive mode (true/false)

configure_noninteractive() {
    log_info "Running in non-interactive mode..."

    # Required: API Key and Asset ID
    API_KEY="${AISAC_API_KEY:-aisac_your_api_key_here}"
    ASSET_ID="${AISAC_ASSET_ID:-your-asset-uuid-here}"

    # Generate Agent ID
    AGENT_ID=$(generate_agent_id)
    log_info "Generated Agent ID: ${AGENT_ID}"

    # Features (with defaults)
    SOAR_ENABLED="${AISAC_SOAR:-false}"
    COLLECTOR_ENABLED="${AISAC_COLLECTOR:-true}"
    HEARTBEAT_ENABLED="${AISAC_HEARTBEAT:-true}"

    SERVER_URL="$DEFAULT_SERVER_URL"
    TLS_ENABLED=false
    SERVER_API_TOKEN=""
    PUBLIC_SERVER_URL=""
    if [ "$SOAR_ENABLED" = "true" ]; then
        TLS_ENABLED=true
        SERVER_API_TOKEN="${AISAC_CS_TOKEN:-}"
        PUBLIC_SERVER_URL="${AISAC_CS_URL:-}"
    fi

    # Registration URL (allow override for staging)
    local register_url="${AISAC_REGISTER_URL:-$DEFAULT_REGISTER_URL}"

    # Attempt registration (with CS data if SOAR enabled)
    if [ "$API_KEY" != "aisac_your_api_key_here" ] && [ "$ASSET_ID" != "your-asset-uuid-here" ]; then
        if [ -n "$SERVER_API_TOKEN" ] && [ -n "$PUBLIC_SERVER_URL" ]; then
            register_agent "$AGENT_ID" "$API_KEY" "$ASSET_ID" "$register_url" \
                "$SERVER_API_TOKEN" "$PUBLIC_SERVER_URL"
        else
            register_agent "$AGENT_ID" "$API_KEY" "$ASSET_ID" "$register_url"
        fi
    else
        log_warning "Missing credentials. Set AISAC_API_KEY and AISAC_ASSET_ID environment variables."
    fi

    INGEST_URL="$DEFAULT_INGEST_URL"
    HEARTBEAT_URL="$DEFAULT_HEARTBEAT_URL"

    # Auto-detect log sources
    ENABLE_SURICATA=false
    ENABLE_WAZUH=false
    ENABLE_SYSLOG=false

    if [ -f /var/log/suricata/eve.json ]; then
        ENABLE_SURICATA=true
        SURICATA_PATH="/var/log/suricata/eve.json"
        log_success "Auto-detected: Suricata EVE logs"
    fi

    if [ -f /var/ossec/logs/alerts/alerts.json ]; then
        ENABLE_WAZUH=true
        WAZUH_PATH="/var/ossec/logs/alerts/alerts.json"
        log_success "Auto-detected: Wazuh alerts"
    fi

    if [ -f /var/log/syslog ]; then
        ENABLE_SYSLOG=true
        SYSLOG_PATH="/var/log/syslog"
        log_success "Auto-detected: Syslog"
    elif [ -f /var/log/messages ]; then
        ENABLE_SYSLOG=true
        SYSLOG_PATH="/var/log/messages"
        log_success "Auto-detected: System messages"
    fi

    # Summary
    echo ""
    echo -e "${CYAN}Configuration Summary:${NC}"
    echo -e "  Agent ID:    ${AGENT_ID}"
    echo -e "  SOAR:        ${SOAR_ENABLED}"
    echo -e "  Collector:   ${COLLECTOR_ENABLED}"
    echo -e "  Heartbeat:   ${HEARTBEAT_ENABLED}"
    echo -e "  Suricata:    ${ENABLE_SURICATA}"
    echo -e "  Wazuh:       ${ENABLE_WAZUH}"
    echo -e "  Syslog:      ${ENABLE_SYSLOG}"
    echo ""
}

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
            echo "Non-interactive mode (for automation):"
            echo "  Set AISAC_NONINTERACTIVE=true and configure with environment variables:"
            echo ""
            echo "  Required:"
            echo "    AISAC_API_KEY      API Key from AISAC Platform"
            echo "    AISAC_ASSET_ID     Asset ID (UUID) from AISAC Platform"
            echo ""
            echo "  Optional:"
            echo "    AISAC_SOAR         Enable SOAR (true/false, default: false)"
            echo "    AISAC_COLLECTOR    Enable Collector (true/false, default: true)"
            echo "    AISAC_HEARTBEAT    Enable Heartbeat (true/false, default: true)"
            echo ""
            echo "Example:"
            echo "  AISAC_API_KEY=aisac_xxx AISAC_ASSET_ID=uuid-here AISAC_NONINTERACTIVE=true ./install.sh"
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

    # Clean up any existing installation (ensures fresh state on reinstall)
    cleanup_services
    echo ""

    # Installation
    create_directories
    install_binary

    # Configuration - interactive or non-interactive
    if [ "${AISAC_NONINTERACTIVE:-false}" = "true" ]; then
        configure_noninteractive
    else
        configure_agent
    fi

    # Generate certificates if SOAR mode is enabled and requested
    if [ "${GENERATE_CERTS:-false}" = "true" ]; then
        echo ""
        log_info "Generating mTLS certificates..."
        if [ "${GENERATE_SERVER_CERTS:-false}" = "true" ]; then
            generate_certificates "$CONFIG_DIR/certs" "$SERVER_HOSTNAME"
        else
            generate_certificates "$CONFIG_DIR/certs" ""
        fi
    fi

    # Install Command Server if requested
    if [ "${INSTALL_COMMAND_SERVER:-false}" = "true" ]; then
        echo ""
        install_command_server "$SERVER_API_TOKEN"
    fi

    generate_config
    install_systemd_service

    # Verify certificates before starting services (if SOAR mode enabled)
    if [ "$TLS_ENABLED" = "true" ]; then
        echo ""
        log_info "Verifying certificates..."
        if ! verify_certificates "$CONFIG_DIR/certs"; then
            log_error "Certificate verification failed. Services will not start correctly."
            log_info "Please regenerate certificates or fix the issue before starting services."
            exit 1
        fi
    fi

    # Start services with proper sequence
    if [ "${AISAC_NONINTERACTIVE:-false}" = "true" ]; then
        # Start command server first if installed (must be ready before agent)
        if [ "${INSTALL_COMMAND_SERVER:-false}" = "true" ]; then
            start_command_server
            # Wait for server to be fully ready
            log_info "Waiting for command server to be fully ready..."
            sleep 3
        fi

        log_info "Starting AISAC Agent..."
        systemctl start ${SERVICE_NAME}
        sleep 2
        if systemctl is-active --quiet ${SERVICE_NAME}; then
            log_success "AISAC Agent is running"
        else
            log_error "Failed to start AISAC Agent"
            echo "Check logs with: journalctl -u ${SERVICE_NAME} -n 50"
        fi
    else
        # Start command server first if installed (must be ready before agent)
        if [ "${INSTALL_COMMAND_SERVER:-false}" = "true" ]; then
            if prompt_yes_no "Start Command Server now?" "y"; then
                start_command_server
                # Wait for server to be fully ready
                log_info "Waiting for command server to be fully ready..."
                sleep 3
            fi
        fi
        start_service
    fi

    print_summary
}

main "$@"
