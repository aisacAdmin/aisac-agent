#!/bin/bash
#
# AISAC Installer — Orchestrator
#
# Installs Wazuh Agent + AISAC Agent by delegating to sub-scripts.
#
# Usage:
#   sudo ./install.sh -k <API_KEY> -t <AUTH_TOKEN> -m <MANAGER_IP> [-u <CONFIG_URL>] [--soar]
#   sudo ./install.sh --uninstall
#
# Examples:
#   sudo ./install.sh -k aisac_xxxx -t eyJhbG... -m 13.49.226.17
#   sudo ./install.sh -k aisac_xxxx -t eyJhbG... -m 13.49.226.17 -u https://xyz.supabase.co/functions/v1/install-config
#   sudo ./install.sh -k aisac_xxxx -t eyJhbG... -m 13.49.226.17 --soar
#   sudo ./install.sh --uninstall
#

set -e

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Defaults ───
DEFAULT_CONFIG_URL="https://api.aisac.cisec.es/functions/v1/install-config"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Service/directory constants (for uninstall)
INSTALL_DIR="/opt/aisac"
CONFIG_DIR="/etc/aisac"
DATA_DIR="/var/lib/aisac"
LOG_DIR="/var/log/aisac"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

prompt_yes_no() {
    local message="$1"
    local default="${2:-y}"
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

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║              AISAC Installer v2.0                             ║"
    echo "║                                                               ║"
    echo "║   Installs: Wazuh Agent + AISAC Agent                         ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 -k <API_KEY> -t <AUTH_TOKEN> -m <MANAGER_IP> [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  -k <api_key>       API Key from AISAC Platform (format: aisac_xxxx)"
    echo "  -t <auth_token>    Supabase JWT anon key (for API gateway auth)"
    echo "  -m <manager_ip>    Wazuh Manager IP address"
    echo ""
    echo "Optional:"
    echo "  -u <url>           install-config edge function URL"
    echo "                     (default: ${DEFAULT_CONFIG_URL})"
    echo "  --soar             Enable SOAR mode (Command Server + mTLS certs)"
    echo "  --uninstall        Uninstall AISAC Agent, Command Server, and Wazuh Agent"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0 -k aisac_xxxx -t eyJhbG... -m 13.49.226.17"
    echo "  sudo $0 -k aisac_xxxx -t eyJhbG... -m 13.49.226.17 --soar"
    echo "  sudo $0 --uninstall"
    echo ""
}

#------------------------------------------------------------------------------
# Cleanup / Uninstall
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

    # Kill any lingering processes
    pkill -x "aisac-agent" 2>/dev/null || true
    pkill -x "aisac-server" 2>/dev/null || true
    sleep 2

    # Remove old service files
    rm -f /etc/systemd/system/aisac-agent.service
    rm -f /etc/systemd/system/aisac-server.service
    systemctl daemon-reload

    log_success "AISAC services cleaned up"
}

uninstall() {
    echo ""
    log_warning "This will remove AISAC Agent, Command Server, and Wazuh Agent from your system"

    if ! prompt_yes_no "Are you sure you want to uninstall?" "n"; then
        echo "Uninstall cancelled"
        exit 0
    fi

    # Clean up AISAC services
    cleanup_services

    # Remove AISAC binaries
    log_info "Removing AISAC binaries..."
    rm -f /usr/local/bin/aisac-agent
    rm -f /usr/local/bin/aisac-server
    rm -rf "$INSTALL_DIR"

    # Remove Wazuh Agent
    if dpkg -l wazuh-agent &>/dev/null 2>&1; then
        log_info "Removing Wazuh Agent (deb)..."
        systemctl stop wazuh-agent 2>/dev/null || true
        systemctl disable wazuh-agent 2>/dev/null || true
        dpkg --purge wazuh-agent 2>/dev/null || true
    elif rpm -q wazuh-agent &>/dev/null 2>&1; then
        log_info "Removing Wazuh Agent (rpm)..."
        systemctl stop wazuh-agent 2>/dev/null || true
        systemctl disable wazuh-agent 2>/dev/null || true
        rpm -e wazuh-agent 2>/dev/null || true
    fi

    if prompt_yes_no "Remove configuration, data, and certificates?" "n"; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$DATA_DIR"
        rm -rf "$LOG_DIR"
        log_success "Configuration, data, and certificates removed"
    else
        log_info "Configuration preserved in $CONFIG_DIR"
    fi

    log_success "AISAC Agent, Command Server, and Wazuh Agent uninstalled"
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

main() {
    local API_KEY="" AUTH_TOKEN="" MANAGER_IP="" CONFIG_URL="$DEFAULT_CONFIG_URL" SOAR=false

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -k) API_KEY="$2"; shift 2 ;;
            -t) AUTH_TOKEN="$2"; shift 2 ;;
            -m) MANAGER_IP="$2"; shift 2 ;;
            -u) CONFIG_URL="$2"; shift 2 ;;
            --soar) SOAR=true; shift ;;
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

    print_banner

    # Validate required flags
    local missing=false
    if [ -z "$API_KEY" ]; then
        log_error "API Key is required (-k)"
        missing=true
    fi
    if [ -z "$AUTH_TOKEN" ]; then
        log_error "Auth token is required (-t)"
        missing=true
    fi
    if [ -z "$MANAGER_IP" ]; then
        log_error "Manager IP is required (-m)"
        missing=true
    fi
    if [ "$missing" = "true" ]; then
        echo ""
        usage
        exit 1
    fi

    # Check root
    if [ "$EUID" -ne 0 ]; then
        log_error "Must be run as root"
        exit 1
    fi

    # ── Step 1: Install Wazuh Agent ──
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 1/2: Installing Wazuh Agent                            ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    if ! "${SCRIPT_DIR}/install-wazuh-agent.sh" "$API_KEY" "$CONFIG_URL" "$AUTH_TOKEN" "$MANAGER_IP"; then
        log_error "Wazuh Agent installation failed"
        exit 1
    fi

    # ── Step 2: Install AISAC Agent ──
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Step 2/2: Installing AISAC Agent                            ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    local aisac_args=()
    if [ "$SOAR" = "true" ]; then
        aisac_args+=(--soar)
    fi

    if ! "${SCRIPT_DIR}/install-aisac-agent.sh" "${aisac_args[@]}"; then
        log_error "AISAC Agent installation failed"
        exit 1
    fi

    # ── Done ──
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}              Installation Complete!                           ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}AISAC Agent:${NC}  systemctl status aisac-agent"
    echo -e "  ${CYAN}Wazuh Agent:${NC}  systemctl status wazuh-agent"
    if [ "$SOAR" = "true" ]; then
        echo -e "  ${CYAN}SOAR Server:${NC}  systemctl status aisac-server"
    fi
    echo -e "  ${CYAN}Agent Config:${NC} ${CONFIG_DIR}/agent.yaml"
    echo -e "  ${CYAN}Agent Logs:${NC}   ${LOG_DIR}/agent.log"
    echo ""
}

main "$@"
