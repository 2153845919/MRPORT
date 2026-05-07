#!/bin/bash
# build.sh - Build MRPORT from source
set -e

echo "[MRPORT Build] Starting..."

# Download WinDivert if not present
if [ ! -f "WinDivert/WinDivert.dll" ]; then
    echo "[MRPORT Build] Downloading WinDivert..."
    bash download-windivert.sh
fi

# Restore NuGet packages
echo "[MRPORT Build] Restoring packages..."
dotnet restore MRPORT.csproj

# Build
echo "[MRPORT Build] Building..."
dotnet publish MRPORT.csproj -c Release -o out \
    --runtime win-x64 \
    --self-contained false \
    -p:DebugType=embedded

echo "[MRPORT Build] Done! Output in out/"
ls -la out/
