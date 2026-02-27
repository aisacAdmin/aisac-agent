#!/bin/bash
#
# AISAC Agent Quick Installer v1.1
#
# Interactive mode:
#   curl -sSL https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/quick-install.sh | sudo bash
#
# Non-interactive mode (for automation):
#   curl -sSL https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/quick-install.sh | \
#     sudo AISAC_API_KEY=aisac_xxx AISAC_ASSET_ID=uuid-here AISAC_NONINTERACTIVE=true bash
#

set -e

REPO="CISECSL/aisac-agent"
INSTALL_DIR="/opt/aisac"
CONFIG_DIR="/etc/aisac"
BINARY_NAME="aisac-agent"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║          AISAC Agent Quick Installer v1.1                     ║"
echo "║                                                               ║"
echo "║   • Auto-registration with AISAC Platform                     ║"
echo "║   • Suricata, Wazuh, and Syslog collection                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root${NC}"
    echo "Usage: curl -sSL <url> | sudo bash"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="arm" ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

echo -e "${GREEN}[1/5]${NC} Detecting system: ${OS}/${ARCH}"

# Get latest release
echo -e "${GREEN}[2/5]${NC} Fetching latest release..."
LATEST=$(curl -fs "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo -e "${YELLOW}Could not fetch latest release. Using fallback version...${NC}"
    LATEST="v1.0.4"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY_NAME}-${OS}-${ARCH}"
else
    echo "Latest version: $LATEST"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY_NAME}-${OS}-${ARCH}"
fi

# Create directories
echo -e "${GREEN}[3/5]${NC} Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p /var/lib/aisac
mkdir -p /var/log/aisac

# Stop running agent (binary cannot be overwritten while running)
if systemctl is-active --quiet aisac-agent 2>/dev/null; then
    echo -e "${YELLOW}Stopping running agent...${NC}"
    systemctl stop aisac-agent 2>/dev/null || true
fi

# Download binary to temp file first, then move into place
echo -e "${GREEN}[4/5]${NC} Downloading AISAC Agent..."
TMPFILE=$(mktemp /tmp/aisac-agent-XXXXXX)
if ! curl -fsSL -o "$TMPFILE" "$DOWNLOAD_URL"; then
    rm -f "$TMPFILE"
    echo -e "${RED}Download failed. Please check your internet connection.${NC}"
    echo "  URL: $DOWNLOAD_URL"
    exit 1
fi
rm -f "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
mv "$TMPFILE" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"
ln -sf "$INSTALL_DIR/$BINARY_NAME" /usr/local/bin/$BINARY_NAME

# Download full installer
echo -e "${GREEN}[5/5]${NC} Downloading configuration wizard..."
curl -fsSL -o /tmp/aisac-install.sh "https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh"
chmod +x /tmp/aisac-install.sh

echo ""
echo -e "${GREEN}Download complete!${NC}"
echo ""

# Check for non-interactive mode
if [ "${AISAC_NONINTERACTIVE:-false}" = "true" ]; then
    echo -e "${YELLOW}Running in non-interactive mode...${NC}"
    echo ""
    # Pass environment variables to the installer
    export AISAC_NONINTERACTIVE
    export AISAC_API_KEY
    export AISAC_ASSET_ID
    export AISAC_SOAR
    export AISAC_COLLECTOR
    export AISAC_HEARTBEAT
    /tmp/aisac-install.sh
else
    echo "Run the configuration wizard:"
    echo -e "  ${CYAN}sudo /tmp/aisac-install.sh${NC}"
    echo ""
    echo "Or for automated deployment:"
    echo -e "  ${CYAN}sudo AISAC_API_KEY=xxx AISAC_ASSET_ID=uuid AISAC_NONINTERACTIVE=true /tmp/aisac-install.sh${NC}"
    echo ""
    echo "Or configure manually:"
    echo -e "  ${CYAN}nano ${CONFIG_DIR}/agent.yaml${NC}"
    echo ""
fi
