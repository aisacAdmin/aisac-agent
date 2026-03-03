#!/bin/bash
#
# AISAC - Wazuh Agent Installer for Linux
#
# Calls the agent-register Edge Function to get tenant config,
# then installs the Wazuh Agent pointing to the centralized Wazuh Manager.
#
# Usage:
#   ./install-wazuh-agent.sh <api_key> <register_url>
#
# Outputs:
#   /tmp/aisac-register.json  - Full response from agent-register (used by install-aisac-agent.sh)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WAZUH_VERSION="4.14.3"
REGISTER_OUTPUT="/tmp/aisac-register.json"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
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
# Call agent-register Edge Function
#------------------------------------------------------------------------------

call_register() {
    local api_key="$1"
    local register_url="$2"

    log_info "Calling agent-register: ${register_url}"

    local response http_code
    response=$(curl -s -w "\n%{http_code}" -X GET "${register_url}" \
        -H "X-API-Key: ${api_key}" 2>/dev/null)
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        log_error "agent-register returned HTTP ${http_code}: ${response}"
        exit 1
    fi

    echo "$response" > "$REGISTER_OUTPUT"
    log_success "Registration data received"
}

#------------------------------------------------------------------------------
# Detect distro
#------------------------------------------------------------------------------

detect_distro() {
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS"
        exit 1
    fi

    . /etc/os-release

    case "$ID" in
        ubuntu|debian)
            DISTRO_TYPE="deb"
            ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
            ;;
        centos|rhel|fedora|rocky|almalinux)
            DISTRO_TYPE="rpm"
            ARCH=$(uname -m)
            case "$ARCH" in
                x86_64)  ARCH="x86_64" ;;
                aarch64) ARCH="aarch64" ;;
            esac
            ;;
        *)
            log_error "Unsupported distro: $ID"
            exit 1
            ;;
    esac

    log_success "Detected: ${PRETTY_NAME} (${DISTRO_TYPE}, ${ARCH})"
}

#------------------------------------------------------------------------------
# Install Wazuh Agent
#------------------------------------------------------------------------------

install_wazuh_agent() {
    local manager_ip="$1"
    local manager_port="$2"
    local agent_group="$3"
    local agent_name="$4"

    log_info "Installing Wazuh Agent ${WAZUH_VERSION}..."
    log_info "  Manager:     ${manager_ip}:${manager_port}"
    log_info "  Group:       ${agent_group}"
    log_info "  Agent name:  ${agent_name}"

    if [ "$DISTRO_TYPE" = "deb" ]; then
        local pkg="wazuh-agent_${WAZUH_VERSION}-1_${ARCH}.deb"
        local url="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/${pkg}"

        log_info "Downloading ${pkg}..."
        curl -fsSL "$url" -o "/tmp/${pkg}"

        WAZUH_MANAGER="$manager_ip" \
        WAZUH_MANAGER_PORT="$manager_port" \
        WAZUH_AGENT_NAME="$agent_name" \
        WAZUH_AGENT_GROUP="$agent_group" \
        dpkg -i "/tmp/${pkg}"

        rm -f "/tmp/${pkg}"

    elif [ "$DISTRO_TYPE" = "rpm" ]; then
        local pkg="wazuh-agent-${WAZUH_VERSION}-1.${ARCH}.rpm"
        local url="https://packages.wazuh.com/4.x/yum/${pkg}"

        log_info "Downloading ${pkg}..."
        curl -fsSL "$url" -o "/tmp/${pkg}"

        WAZUH_MANAGER="$manager_ip" \
        WAZUH_MANAGER_PORT="$manager_port" \
        WAZUH_AGENT_NAME="$agent_name" \
        WAZUH_AGENT_GROUP="$agent_group" \
        rpm -ihv "/tmp/${pkg}"

        rm -f "/tmp/${pkg}"
    fi

    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    sleep 2

    if systemctl is-active --quiet wazuh-agent; then
        log_success "Wazuh Agent is running"
    else
        log_error "Wazuh Agent failed to start"
        echo "Check: journalctl -u wazuh-agent -n 50"
        exit 1
    fi
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

main() {
    local api_key="${1:-}"
    local register_url="${2:-}"

    if [ -z "$api_key" ] || [ -z "$register_url" ]; then
        log_error "Usage: $0 <api_key> <register_url>"
        exit 1
    fi

    if [ "$EUID" -ne 0 ]; then
        log_error "Must be run as root"
        exit 1
    fi

    # 1. Call agent-register (saves response to REGISTER_OUTPUT)
    call_register "$api_key" "$register_url"

    # 2. Parse Wazuh config from saved response (read file directly to avoid bash variable issues)
    local manager_ip manager_port agent_group asset_name
    manager_ip=$(json_get_file "$REGISTER_OUTPUT" ".wazuh.manager_ip")
    manager_port=$(json_get_file "$REGISTER_OUTPUT" ".wazuh.manager_port")
    agent_group=$(json_get_file "$REGISTER_OUTPUT" ".wazuh.agent_group")
    asset_name=$(json_get_file "$REGISTER_OUTPUT" ".asset_name")

    if [ -z "$manager_ip" ] || [ -z "$agent_group" ]; then
        log_error "Missing wazuh config in agent-register response"
        exit 1
    fi

    [ -z "$asset_name" ] && asset_name=$(hostname)

    # 3. Detect distro
    detect_distro

    # 4. Install Wazuh Agent
    install_wazuh_agent "$manager_ip" "${manager_port:-1514}" "$agent_group" "$asset_name"

    log_success "Wazuh Agent installed → Manager: ${manager_ip} | Group: ${agent_group}"
}

main "$@"
