#!/bin/sh
# sipxtract installer
# Usage: curl -fsSL https://raw.githubusercontent.com/maurice2k/sipxtract/main/install.sh | sh

set -e

REPO="maurice2k/sipxtract"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="sipxtract"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  arm64|aarch64)
    ARCH="arm64"
    ;;
  *)
    echo "Error: Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

case "$OS" in
  darwin)
    if [ "$ARCH" != "arm64" ]; then
      echo "Error: macOS builds are only available for arm64 (Apple Silicon)"
      exit 1
    fi
    PLATFORM="darwin-arm64"
    ;;
  linux)
    if [ "$ARCH" != "amd64" ]; then
      echo "Error: Linux builds are only available for amd64"
      exit 1
    fi
    PLATFORM="linux-amd64"
    ;;
  *)
    echo "Error: Unsupported OS: $OS"
    exit 1
    ;;
esac

echo "Fetching latest release..."
LATEST_RELEASE=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ]; then
  echo "Error: Could not determine latest release"
  exit 1
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/${BINARY_NAME}-${PLATFORM}"

echo "Installing ${BINARY_NAME} ${LATEST_RELEASE} for ${PLATFORM}..."

TMP_FILE=$(mktemp)
trap "rm -f $TMP_FILE" EXIT

echo "Downloading from ${DOWNLOAD_URL}..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_FILE"; then
  echo "Error: Download failed"
  exit 1
fi

chmod +x "$TMP_FILE"

if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo ""
echo "${BINARY_NAME} ${LATEST_RELEASE} installed to ${INSTALL_DIR}/${BINARY_NAME}"
echo ""

if command -v sipxtract >/dev/null 2>&1; then
  echo "Verify: $(sipxtract --version)"
else
  echo "Note: ${INSTALL_DIR} may not be in your PATH"
fi
