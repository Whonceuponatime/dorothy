#!/bin/bash
# Publish script for Dorothy (Linux)
# Usage: ./publish.sh [linux-x64|linux-arm64]

RUNTIME=${1:-linux-x64}

echo "Publishing Dorothy for $RUNTIME..."

# Validate runtime identifier
VALID_RUNTIMES=("linux-x64" "linux-arm64")
VALID=false
for valid_runtime in "${VALID_RUNTIMES[@]}"; do
    if [ "$RUNTIME" == "$valid_runtime" ]; then
        VALID=true
        break
    fi
done

if [ "$VALID" != "true" ]; then
    echo "ERROR: Invalid runtime identifier: $RUNTIME"
    echo "Valid runtimes: ${VALID_RUNTIMES[*]}"
    exit 1
fi

# Publish the project
dotnet publish -c Release -r $RUNTIME --self-contained

if [ $? -eq 0 ]; then
    echo ""
    echo "Publish completed successfully!"
    PUBLISH_PATH="bin/Release/net8.0/$RUNTIME/publish"
    if [ -d "$PUBLISH_PATH" ]; then
        echo "Published files location: $PUBLISH_PATH"
        
        EXE_NAME="Dorothy"
        EXE_PATH="$PUBLISH_PATH/$EXE_NAME"
        if [ -f "$EXE_PATH" ]; then
            echo "Executable: $EXE_PATH"
            chmod +x "$EXE_PATH"
        fi
    fi
else
    echo ""
    echo "Publish failed!"
    exit 1
fi

