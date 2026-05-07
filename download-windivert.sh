#!/bin/bash
# download-windivert.sh - Download WinDivert DLLs for build
set -e

WINDIVERT_VERSION="2.2.0"
BASE_URL="https://github.com/basil00/WinDivert/releases/download/v${WINDIVERT_VERSION}"

echo "Downloading WinDivert v${WINDIVERT_VERSION}..."
curl -sL "${BASE_URL}/WinDivert-${WINDIVERT_VERSION}-x64.zip" -o /tmp/windivert.zip
unzip -o -q /tmp/windivert.zip -d /tmp/windivert-extract

mkdir -p WinDivert
cp /tmp/windivert-extract/x64/WinDivert64.sys WinDivert/
cp /tmp/windivert-extract/x64/WinDivert.dll WinDivert/

echo "WinDivert files extracted to WinDivert/"
ls -la WinDivert/
