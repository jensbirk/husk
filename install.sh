#!/bin/bash
set -e

# --- Configuration ---
# REPLACE THIS WITH YOUR DETAILS:
REPO="jensbirk/husk"
BINARY="husk"
INSTALL_DIR="$HOME/.local/bin"
# ---------------------

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}📦 Husk Installer${NC}"
echo "---------------------"

# 1. Prepare Directory
mkdir -p "$INSTALL_DIR"

# 2. Determine Download URL (Latest Release)
ASSET_URL="https://github.com/$REPO/releases/latest/download/$BINARY"

echo -e "⬇️  Downloading latest version from GitHub..."

# 3. Download (Support curl or wget)
if command -v curl >/dev/null 2>&1; then
    curl -L -o "$INSTALL_DIR/$BINARY" "$ASSET_URL"
elif command -v wget >/dev/null 2>&1; then
    wget -O "$INSTALL_DIR/$BINARY" "$ASSET_URL"
else
    echo -e "${RED}❌ Error: You need 'curl' or 'wget' installed to download.${NC}"
    exit 1
fi

# 4. Make Executable
chmod +x "$INSTALL_DIR/$BINARY"

# 5. Verify Installation
if [ -f "$INSTALL_DIR/$BINARY" ]; then
    echo -e "${GREEN}✅ Installed to $INSTALL_DIR/$BINARY${NC}"
else
    echo -e "${RED}❌ Installation failed.${NC}"
    exit 1
fi

# 6. Check PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo -e "${RED}⚠️  Warning: $INSTALL_DIR is not in your PATH.${NC}"
    echo "   Add the following line to your ~/.bashrc or ~/.zshrc:"
    echo -e "   ${BLUE}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
fi

echo ""
echo -e "🚀 Run it with: ${GREEN}husk install${NC}"