#!/bin/bash
# download-windivert.sh - Download WinDivert DLLs for build
set -e

WINDIVERT_VERSION="2.2.2"
ARCH="A"  # A=x64, B=ARM64, C=x86
BASE_URL="https://github.com/basil00/WinDivert/releases/download/v${WINDIVERT_VERSION}"

ZIP_NAME="WinDivert-${WINDIVERT_VERSION}-${ARCH}.zip"
echo "Downloading WinDivert v${WINDIVERT_VERSION}..."
curl -sL "${BASE_URL}/${ZIP_NAME}" -o /tmp/windivert.zip
unzip -o -q /tmp/windivert.zip -d /tmp/windivert-extract

mkdir -p WinDivert
cp /tmp/windivert-extract/WinDivert-${WINDIVERT_VERSION}-${ARCH}/x64/WinDivert64.sys WinDivert/
cp /tmp/windivert-extract/WinDivert-${WINDIVERT_VERSION}-${ARCH}/x64/WinDivert.dll WinDivert/

echo "WinDivert files extracted to WinDivert/"
ls -la WinDivert/
