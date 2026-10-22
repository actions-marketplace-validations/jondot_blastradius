#!/bin/sh
# Fill packaging/homebrew/br.rb from a release's checksum files.
# Usage: packaging/homebrew/fill.sh VERSION [DIR]
#   VERSION   the release version without the v, e.g. 0.1.0
#   DIR       a directory holding the release's br-VERSION-TARGET.tar.gz.sha256 files.
#             Without it, the files are downloaded from the GitHub release (needs the network).
# Writes packaging/homebrew/br.filled.rb. Stops if any of the four checksums is missing.
set -eu

[ $# -ge 1 ] || { echo "usage: $0 VERSION [DIR]" >&2; exit 2; }
VERSION="$1"
DIR="${2:-}"
HERE=$(cd "$(dirname "$0")" && pwd)
REPO="jondot/blastradius"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

sum_for() {
  target="$1"
  name="br-${VERSION}-${target}.tar.gz.sha256"
  if [ -n "$DIR" ]; then
    f="$DIR/$name"
  else
    f="$TMP/$name"
    curl -fsSL "https://github.com/${REPO}/releases/download/v${VERSION}/${name}" -o "$f"
  fi
  [ -f "$f" ] || { echo "Error: missing $f" >&2; exit 1; }
  s=$(awk '{print $1}' "$f")
  case "$s" in
    *[!0-9a-f]*|"") echo "Error: $f does not hold a sha256" >&2; exit 1 ;;
  esac
  [ "${#s}" -eq 64 ] || { echo "Error: $f does not hold a sha256" >&2; exit 1; }
  printf '%s' "$s"
}

a_mac=$(sum_for aarch64-apple-darwin)
x_mac=$(sum_for x86_64-apple-darwin)
a_lin=$(sum_for aarch64-unknown-linux-musl)
x_lin=$(sum_for x86_64-unknown-linux-musl)

sed -e "s/@VERSION@/${VERSION}/" \
    -e "s/@SHA256_AARCH64_APPLE_DARWIN@/${a_mac}/" \
    -e "s/@SHA256_X86_64_APPLE_DARWIN@/${x_mac}/" \
    -e "s/@SHA256_AARCH64_UNKNOWN_LINUX_MUSL@/${a_lin}/" \
    -e "s/@SHA256_X86_64_UNKNOWN_LINUX_MUSL@/${x_lin}/" \
    "$HERE/br.rb" > "$HERE/br.filled.rb"

if grep -q '@[A-Z0-9_]*@' "$HERE/br.filled.rb"; then
  echo "Error: placeholders are left in br.filled.rb" >&2
  exit 1
fi
echo "wrote $HERE/br.filled.rb"
