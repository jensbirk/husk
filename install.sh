#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}📦 Husk Installer${NC}"
echo "---------------------"

if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Error: Go is not installed.${NC}"
    exit 1
fi

# Go Mod setup
if [ ! -f "go.mod" ]; then
    echo -e "${BLUE}⚙️  Initializing Go module...${NC}"
    go mod init husk
    go get gopkg.in/yaml.v3
    go get github.com/jensbirk/husk
fi

# Build
echo -e "${BLUE}🔨 Building Husk...${NC}"
go build -ldflags="-s -w" -o husk main.go

# Install
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
echo -e "${BLUE}📂 Installing to $INSTALL_DIR...${NC}"
mv husk "$INSTALL_DIR/"

# Migrate Config if needed
if [ -f "nixey.yaml" ] && [ ! -f "husk.yaml" ]; then
    echo -e "${BLUE}🔄 Detected nixey.yaml. Renaming to husk.yaml...${NC}"
    mv nixey.yaml husk.yaml
fi

# Check Path
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${RED}⚠️  Warning: $INSTALL_DIR is not in your PATH.${NC}"
else
    echo -e "${GREEN}✅ Installed successfully!${NC}"
fi

echo ""
echo -e "🚀 Usage: ${GREEN}husk install${NC}"