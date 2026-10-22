#!/bin/sh
# Install br from the latest GitHub release.
# Usage: curl -fsSL https://raw.githubusercontent.com/jondot/blastradius/main/install.sh | sh
#    or: ... | sh -s -- --version v0.1.0
# Set BR_INSTALL_DIR to choose the install directory (default ~/.local/bin).
set -eu

REPO="jondot/blastradius"
BINARY="br"
VERSION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version|-v)
      [ $# -ge 2 ] || { echo "Error: $1 needs a value" >&2; exit 2; }
      VERSION="$2"; shift 2 ;;
    *) echo "Error: unknown option: $1" >&2; exit 2 ;;
  esac
done

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Darwin) os_part="apple-darwin" ;;
  Linux)  os_part="unknown-linux-musl" ;;
  *) echo "Error: unsupported OS: $os (on Windows, download the .zip from the releases page)" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) arch_part="x86_64" ;;
  arm64|aarch64) arch_part="aarch64" ;;
  *) echo "Error: unsupported architecture: $arch" >&2; exit 1 ;;
esac

TARGET="${arch_part}-${os_part}"

if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
  [ -n "$VERSION" ] || { echo "Error: could not determine the latest version" >&2; exit 1; }
fi

NUM="${VERSION#v}"
ARCHIVE="${BINARY}-${NUM}-${TARGET}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/v${NUM}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Installing ${BINARY} v${NUM} for ${TARGET}..."
curl -fsSL "${BASE}/${ARCHIVE}" -o "${TMP}/${ARCHIVE}"
curl -fsSL "${BASE}/${ARCHIVE}.sha256" -o "${TMP}/${ARCHIVE}.sha256"

expected=$(awk '{print $1}' "${TMP}/${ARCHIVE}.sha256")
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "${TMP}/${ARCHIVE}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "${TMP}/${ARCHIVE}" | awk '{print $1}')
else
  echo "Error: neither sha256sum nor shasum is available to verify the download" >&2
  exit 1
fi

if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "Error: checksum mismatch for ${ARCHIVE}" >&2
  echo "  expected: ${expected}" >&2
  echo "  actual:   ${actual}" >&2
  exit 1
fi

tar xzf "${TMP}/${ARCHIVE}" -C "$TMP"

INSTALL_DIR="${BR_INSTALL_DIR:-${HOME}/.local/bin}"
mkdir -p "$INSTALL_DIR"
mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
chmod +x "${INSTALL_DIR}/${BINARY}"

echo "Installed ${BINARY} v${NUM} to ${INSTALL_DIR}/${BINARY} (checksum verified)"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) echo "Note: ${INSTALL_DIR} is not in PATH. Add: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
