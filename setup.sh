#!/bin/bash
# All-in-one setup script for Dorothy
# This script builds, publishes, and sets up the dorothy command
# Usage: ./setup.sh [linux-x64|linux-arm64]

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default to Raspberry Pi (ARM64) - can override with linux-x64
RUNTIME=${1:-linux-arm64}

# Validate runtime
if [[ "$RUNTIME" != "linux-x64" && "$RUNTIME" != "linux-arm64" ]]; then
    echo -e "${RED}ERROR: Invalid runtime identifier: $RUNTIME${NC}"
    echo "Valid runtimes: linux-x64, linux-arm64"
    exit 1
fi

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Dorothy Setup Script${NC}"
echo -e "${CYAN}  Runtime: $RUNTIME${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Step 1: Clean previous builds
echo -e "${YELLOW}[1/5] Cleaning previous builds...${NC}"
dotnet clean -c Release 2>/dev/null || true
rm -rf bin obj 2>/dev/null || true
echo -e "${GREEN}✓ Cleaned${NC}"
echo ""

# Step 2: Restore packages
echo -e "${YELLOW}[2/5] Restoring NuGet packages...${NC}"
dotnet restore
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Packages restored${NC}"
else
    echo -e "${RED}✗ Package restore failed${NC}"
    exit 1
fi
echo ""

# Step 3: Build
echo -e "${YELLOW}[3/5] Building project...${NC}"
dotnet build -c Release
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo ""

# Step 4: Publish
echo -e "${YELLOW}[4/5] Publishing for $RUNTIME...${NC}"
dotnet publish -c Release -r $RUNTIME --self-contained
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Publish successful${NC}"
else
    echo -e "${RED}✗ Publish failed${NC}"
    exit 1
fi
echo ""

# Step 5: Setup dorothy command
echo -e "${YELLOW}[5/5] Setting up 'dorothy' command...${NC}"

PUBLISH_PATH="$SCRIPT_DIR/bin/Release/net8.0/$RUNTIME/publish/Dorothy"

if [ ! -f "$PUBLISH_PATH" ]; then
    echo -e "${RED}✗ Published executable not found at $PUBLISH_PATH${NC}"
    exit 1
fi

# Make executable
chmod +x "$PUBLISH_PATH"
echo -e "${GREEN}✓ Made executable${NC}"

# Create symlink in /usr/local/bin
if [ -w /usr/local/bin ]; then
    # User has write access
    ln -sf "$PUBLISH_PATH" /usr/local/bin/dorothy
    echo -e "${GREEN}✓ Created symlink in /usr/local/bin/dorothy${NC}"
else
    # Need sudo
    echo "Creating symlink requires sudo privileges..."
    sudo ln -sf "$PUBLISH_PATH" /usr/local/bin/dorothy
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Created symlink in /usr/local/bin/dorothy${NC}"
    else
        echo -e "${YELLOW}⚠ Could not create symlink. Adding to PATH instead...${NC}"
        # Add to PATH in .bashrc
        EXPORT_LINE="export PATH=\"\$PATH:$SCRIPT_DIR/bin/Release/net8.0/$RUNTIME/publish\""
        if ! grep -q "$EXPORT_LINE" ~/.bashrc 2>/dev/null; then
            echo "" >> ~/.bashrc
            echo "# Dorothy path" >> ~/.bashrc
            echo "$EXPORT_LINE" >> ~/.bashrc
            echo -e "${GREEN}✓ Added to ~/.bashrc${NC}"
        else
            echo -e "${YELLOW}⚠ Already in ~/.bashrc${NC}"
        fi
    fi
fi

# Source .bashrc to apply changes
if [ -f ~/.bashrc ]; then
    source ~/.bashrc 2>/dev/null || true
    echo -e "${GREEN}✓ Sourced ~/.bashrc${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${CYAN}You can now use 'dorothy' command from anywhere.${NC}"
echo -e "${CYAN}Published files: $PUBLISH_PATH${NC}"
echo ""
echo -e "${YELLOW}Note: If 'dorothy' command doesn't work, restart your terminal or run:${NC}"
echo -e "${YELLOW}  source ~/.bashrc${NC}"
echo ""

