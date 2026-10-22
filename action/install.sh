#!/usr/bin/env bash
# Install a pinned br release for the GitHub Action, checking the archive against its SHA-256.
#
# Inputs (environment):
#   BR_VERSION       release to install, with or without the leading v (default: the pin in action/VERSION)
#   BR_SHA256        optional: the archive's SHA-256, pinned by you. When set it is the only checksum trusted; when empty the
#                    release's own .sha256 file is used (that catches a damaged download, not a replaced release)
#   BR_BIN_PATH      use this br binary and download nothing (a build from source, a mirror you vet yourself)
#   BR_RELEASE_BASE  where releases are (default https://github.com/jondot/blastradius/releases/download), for a mirror
#   BR_INSTALL_DIR   where to put br (default $RUNNER_TEMP/br-bin)
# Writes the directory holding br to $GITHUB_PATH. Needs no token.
set -eu

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dir="${BR_INSTALL_DIR:-${RUNNER_TEMP:-/tmp}/br-bin}"

say() { printf 'br install: %s\n' "$*"; }
die() { printf '::error title=br install::%s\n' "$*" >&2; printf 'br install: %s\n' "$*" >&2; exit 1; }

add_path() {
  if [ -n "${GITHUB_PATH:-}" ]; then printf '%s\n' "$1" >> "$GITHUB_PATH"; fi
  PATH="$1:$PATH"
}

if [ -n "${BR_BIN_PATH:-}" ]; then
  [ -x "$BR_BIN_PATH" ] || die "br-path $BR_BIN_PATH is not an executable file"
  mkdir -p "$dir"
  cp "$BR_BIN_PATH" "$dir/br"
  chmod +x "$dir/br"
  add_path "$dir"
  say "using $BR_BIN_PATH (no download)"
  exit 0
fi

version="${BR_VERSION:-}"
if [ -z "$version" ]; then
  version="$(tr -d ' \t\r\n' < "$here/VERSION")"
fi
num="${version#v}"
case "$num" in
  ''|*[!0-9A-Za-z.+-]*) die "version \"$version\" is not a release number (example: 0.1.0)" ;;
  latest*) die "version must name a release (example: 0.1.0): a pinned version is what makes the run reproducible" ;;
esac

os="${RUNNER_OS:-$(uname -s)}"
arch="${RUNNER_ARCH:-$(uname -m)}"
case "$os" in
  Linux) os_part="unknown-linux-musl" ;;
  macOS|Darwin) os_part="apple-darwin" ;;
  *) die "unsupported runner OS $os: the Action installs on Linux and macOS runners (on Windows, put br.exe on PATH and pass br-path)" ;;
esac
case "$arch" in
  X64|x86_64|amd64) arch_part="x86_64" ;;
  ARM64|arm64|aarch64) arch_part="aarch64" ;;
  *) die "unsupported runner architecture $arch" ;;
esac
target="${arch_part}-${os_part}"
archive="br-${num}-${target}.tar.gz"
base="${BR_RELEASE_BASE:-https://github.com/jondot/blastradius/releases/download}/v${num}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "downloading $archive"
curl -fsSL --retry 3 "$base/$archive" -o "$tmp/$archive" || die "could not download $base/$archive"

if [ -n "${BR_SHA256:-}" ]; then
  expected="$(printf '%s' "$BR_SHA256" | tr 'A-F' 'a-f' | tr -d ' \t\r\n')"
  source_of="the checksum you pinned"
else
  curl -fsSL --retry 3 "$base/$archive.sha256" -o "$tmp/$archive.sha256" || die "could not download $base/$archive.sha256"
  expected="$(awk '{print tolower($1)}' "$tmp/$archive.sha256" | head -n 1)"
  source_of="the release's $archive.sha256"
fi
case "$expected" in
  *[!0-9a-f]*|'') die "the expected checksum is not a SHA-256 hex digest" ;;
esac
[ "${#expected}" -eq 64 ] || die "the expected checksum is not a SHA-256 hex digest"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
else
  die "neither sha256sum nor shasum is on this runner, so the download cannot be checked"
fi
if [ "$actual" != "$expected" ]; then
  die "checksum mismatch for $archive: expected $expected (from $source_of), got $actual. Nothing was installed."
fi
say "checksum ok ($source_of)"

mkdir -p "$dir"
tar xzf "$tmp/$archive" -C "$dir" br || die "could not unpack $archive"
chmod +x "$dir/br"
add_path "$dir"
say "installed br ${num} in $dir"
