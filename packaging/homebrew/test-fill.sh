#!/bin/sh
# Checks fill.sh with made-up checksum files: every placeholder is replaced, and a missing file stops it.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d)
trap 'rm -rf "$D" "$HERE/br.filled.rb"' EXIT
for t in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
  h=$(printf '%s' "$t" | sha256sum 2>/dev/null | cut -d' ' -f1 || printf '%s' "$t" | shasum -a 256 | cut -d' ' -f1)
  echo "$h  br-9.9.9-$t.tar.gz" > "$D/br-9.9.9-$t.tar.gz.sha256"
done
sh "$HERE/fill.sh" 9.9.9 "$D" >/dev/null
grep -q 'version "9.9.9"' "$HERE/br.filled.rb"
[ "$(grep -c 'sha256 "[0-9a-f]\{64\}"' "$HERE/br.filled.rb")" -eq 4 ]
! grep -q '@[A-Z0-9_]*@' "$HERE/br.filled.rb"
rm "$D/br-9.9.9-x86_64-apple-darwin.tar.gz.sha256"
if sh "$HERE/fill.sh" 9.9.9 "$D" >/dev/null 2>&1; then echo "fill.sh accepted a missing checksum" >&2; exit 1; fi
echo "fill.sh ok"
