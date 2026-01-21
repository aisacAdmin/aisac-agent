#!/bin/bash
#
# AISAC Agent Quick Installer
# Usage: curl -sSL https://raw.githubusercontent.com/aisacAdmin/aisac-agent/main/scripts/quick-install.sh | sudo bash
#

set -e

REPO="aisacAdmin/aisac-agent"
INSTALL_DIR="/opt/aisac"
CONFIG_DIR="/etc/aisac"
BINARY_NAME="aisac-agent"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║            AISAC Agent Quick Installer                        ║"
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
LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo -e "${RED}Failed to get latest release. Using main branch...${NC}"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v1.0.0/${BINARY_NAME}-${OS}-${ARCH}"
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

# Download binary
echo -e "${GREEN}[4/5]${NC} Downloading AISAC Agent..."
if ! curl -sSL -o "$INSTALL_DIR/$BINARY_NAME" "$DOWNLOAD_URL"; then
    echo -e "${RED}Download failed. Please check your internet connection.${NC}"
    exit 1
fi
chmod +x "$INSTALL_DIR/$BINARY_NAME"
ln -sf "$INSTALL_DIR/$BINARY_NAME" /usr/local/bin/$BINARY_NAME

# Download full installer
echo -e "${GREEN}[5/5]${NC} Downloading configuration wizard..."
curl -sSL -o /tmp/aisac-install.sh "https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh"
chmod +x /tmp/aisac-install.sh

echo ""
echo -e "${GREEN}Download complete!${NC}"
echo ""
echo "Run the configuration wizard:"
echo -e "  ${CYAN}sudo /tmp/aisac-install.sh${NC}"
echo ""
echo "Or configure manually:"
echo -e "  ${CYAN}nano ${CONFIG_DIR}/agent.yaml${NC}"
echo ""
