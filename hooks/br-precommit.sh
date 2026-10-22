#!/usr/bin/env bash
# pre-commit hook: hunt the lockfiles in this commit for the indicators listed in .br-indicators.
#
#   .br-indicators   one indicator per line (eco:name@version, sha256:HASH, action:owner/repo@ref); blank lines and
#                    lines starting with # are ignored; a # after a space starts a comment
#
# pre-commit passes the changed lockfiles as arguments. They are copied, with their paths, into a scratch directory and
# br hunts that directory (br hunt --path): it reads those files only, makes no network call and needs no token.
# Exit 0: nothing listed is in them. Exit 1: one is (br's report is printed). Any other br failure is passed on.
# Install br first: https://github.com/jondot/blastradius#install
set -u

list="${BR_INDICATORS_FILE:-.br-indicators}"
BR="${BR_BIN:-br}"

if [ "$#" -eq 0 ]; then exit 0; fi

if [ ! -f "$list" ]; then
  printf 'blastradius: no %s in this repo, so there is nothing to check the lockfiles against.\n' "$list"
  printf '  Add one indicator per line, for example: npm:left-pad@1.3.0\n'
  exit 0
fi

if ! command -v "$BR" >/dev/null 2>&1; then
  printf 'blastradius: br is not installed, so the lockfiles in this commit were NOT checked.\n' >&2
  printf '  Install it (https://github.com/jondot/blastradius#install) or remove this hook.\n' >&2
  exit 1
fi

INDS=()
while IFS= read -r tok; do
  [ -n "$tok" ] || continue
  case "$tok" in -*) printf 'blastradius: %s: "%s" starts with a dash; write it as eco:name@version\n' "$list" "$tok" >&2; exit 1 ;; esac
  INDS+=("$tok")
done < <(sed -e 's/^[[:space:]]*#.*//' -e 's/[[:space:]]#.*//' "$list" | tr ',[:space:]' '\n\n' | sed -e '/^$/d')

if [ "${#INDS[@]}" -eq 0 ]; then
  printf 'blastradius: %s lists no indicators, so there is nothing to check.\n' "$list"
  exit 0
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
copied=0
for f in "$@"; do
  [ -f "$f" ] || continue   # a deleted lockfile has nothing to check
  rel="${f#./}"
  mkdir -p "$scratch/$(dirname "$rel")"
  cp "$f" "$scratch/$rel"
  copied=$((copied + 1))
done
if [ "$copied" -eq 0 ]; then exit 0; fi

"$BR" hunt "${INDS[@]}" --path "$scratch" --fail-if found
rc=$?
case "$rc" in
  0) exit 0 ;;
  10) printf '\nblastradius: a listed package is in this commit. Fix the lockfile, or remove the line from %s if it no longer applies.\n' "$list" >&2; exit 1 ;;
  *) exit "$rc" ;;
esac
