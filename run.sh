#!/bin/bash
# Run script for Dorothy (Linux)
# Usage: ./run.sh [Release|Debug]

CONFIGURATION=${1:-Release}

EXE_PATH="bin/x64/$CONFIGURATION/net8.0/linux-x64/Dorothy"

if [ ! -f "$EXE_PATH" ]; then
    echo "Executable not found. Building first..."
    ./build.sh $CONFIGURATION
fi

if [ -f "$EXE_PATH" ]; then
    echo "Running Dorothy..."
    chmod +x "$EXE_PATH"
    "$EXE_PATH"
else
    echo "ERROR: Could not find executable at $EXE_PATH"
    exit 1
fi

