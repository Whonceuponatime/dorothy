#!/bin/bash
# Build script for Dorothy (Linux)
# Usage: ./build.sh [Release|Debug]

CONFIGURATION=${1:-Release}

echo "Building Dorothy..."
echo "Configuration: $CONFIGURATION"

# Build the project
dotnet build -c $CONFIGURATION

if [ $? -eq 0 ]; then
    echo ""
    echo "Build completed successfully!"
    OUTPUT_PATH="bin/x64/$CONFIGURATION/net8.0/linux-x64/Dorothy"
    if [ -f "$OUTPUT_PATH" ]; then
        echo "Output: $OUTPUT_PATH"
        chmod +x "$OUTPUT_PATH"
    fi
else
    echo ""
    echo "Build failed!"
    exit 1
fi

