#!/bin/bash
# Setup script to create 'dorothy' command (Linux)
# Usage: ./setup-dorothy-command.sh [linux-x64|linux-arm64]

RUNTIME=${1:-linux-x64}

echo "Setting up 'dorothy' command..."

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLISH_PATH="$SCRIPT_DIR/bin/Release/net8.0/$RUNTIME/publish/Dorothy"

# Check if published executable exists
if [ ! -f "$PUBLISH_PATH" ]; then
    echo "Published executable not found. Publishing first..."
    "$SCRIPT_DIR/publish.sh" "$RUNTIME"
    
    if [ ! -f "$PUBLISH_PATH" ]; then
        echo "ERROR: Could not find executable at $PUBLISH_PATH"
        echo "Please run: ./publish.sh $RUNTIME"
        exit 1
    fi
fi

# Make executable
chmod +x "$PUBLISH_PATH"

# Create symlink in /usr/local/bin (requires sudo)
echo "Creating symlink in /usr/local/bin..."
sudo ln -sf "$PUBLISH_PATH" /usr/local/bin/dorothy

if [ $? -eq 0 ]; then
    echo "Symlink created successfully!"
    echo ""
    echo "You can now use 'dorothy' command from anywhere."
    echo "If the command doesn't work, try: source ~/.bashrc"
else
    echo "ERROR: Failed to create symlink. You may need to run with sudo."
    echo ""
    echo "Alternative: Add to your PATH manually:"
    echo "  export PATH=\"\$PATH:$SCRIPT_DIR/bin/Release/net8.0/$RUNTIME/publish\""
    echo "  echo 'export PATH=\"\$PATH:$SCRIPT_DIR/bin/Release/net8.0/$RUNTIME/publish\"' >> ~/.bashrc"
    exit 1
fi

