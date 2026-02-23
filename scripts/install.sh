#!/bin/bash
#
# AISAC Agent - Main Installer (Linux)
#
# Orchestrates the installation of:
#   1. Wazuh Manager (via install-wazuh-agent.sh)
#   2. AISAC Agent   (via install-aisac-agent.sh)
#
# Usage:
#   sudo ./install.sh
#   sudo ./install.sh --register-url https://custom-url/functions/v1/agent-register
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
DEFAULT_REGISTER_URL="https://api.aisac.cisec.es/functions/v1/agent-register"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║              AISAC Agent Installer v2.0                       ║"
    echo "║                                                               ║"
    echo "║   Installs: Wazuh Manager + AISAC Agent                      ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    if ! command -v curl &>/dev/null; then
        log_error "curl is required but not installed"
        echo "Install it with: apt install curl  or  yum install curl"
        exit 1
    fi

    if ! command -v systemctl &>/dev/null; then
        log_error "systemd is required but not found"
        exit 1
    fi

    log_success "Dependencies OK"
}

check_scripts() {
    for script in install-wazuh-agent.sh install-aisac-agent.sh; do
        if [ ! -f "${SCRIPT_DIR}/${script}" ]; then
            log_error "Missing script: ${SCRIPT_DIR}/${script}"
            exit 1
        fi
        chmod +x "${SCRIPT_DIR}/${script}"
    done
    log_success "Scripts found"
}

prompt_api_key() {
    echo ""
    echo -e "${YELLOW}--- AISAC Platform Credentials ---${NC}"
    echo ""
    echo -e "${BLUE}You need the API Key from the AISAC Platform:${NC}"
    echo -e "${BLUE}  Platform > Assets > [Your Asset] > API Key${NC}"
    echo ""
    echo -en "${CYAN}API Key${NC}: " >/dev/tty
    read -r API_KEY </dev/tty

    if [ -z "$API_KEY" ]; then
        log_error "API Key is required"
        exit 1
    fi

    log_success "API Key received"
}

main() {
    # Parse arguments
    REGISTER_URL="$DEFAULT_REGISTER_URL"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --register-url)
                REGISTER_URL="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [--register-url <url>]"
                echo ""
                echo "Options:"
                echo "  --register-url   URL of the agent-register Edge Function"
                echo "                   Default: ${DEFAULT_REGISTER_URL}"
                echo ""
                echo "Non-interactive mode:"
                echo "  AISAC_API_KEY=aisac_xxx sudo ./install.sh"
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                exit 1
                ;;
        esac
    done

    print_banner
    check_root
    check_dependencies
    check_scripts

    # Get API key (from env or prompt)
    if [ -n "${AISAC_API_KEY:-}" ]; then
        API_KEY="$AISAC_API_KEY"
        log_info "Using API Key from environment"
    else
        prompt_api_key
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 1/2: Installing Wazuh Manager                           ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    bash "${SCRIPT_DIR}/install-wazuh-agent.sh" "$API_KEY" "$REGISTER_URL"

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 2/2: Installing AISAC Agent                             ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    bash "${SCRIPT_DIR}/install-aisac-agent.sh"

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}               Installation complete!                          ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Wazuh Manager:${NC}  systemctl status wazuh-manager"
    echo -e "  ${CYAN}AISAC Agent:${NC}    systemctl status aisac-agent"
    echo -e "  ${CYAN}AISAC Logs:${NC}     tail -f /var/log/aisac/agent.log"
    echo ""
}

main "$@"
