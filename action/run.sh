#!/usr/bin/env bash
# Run br hunt for the GitHub Action and write its outputs. It never fails the job over a finding itself: the job
# fails in action/enforce.sh, after the SARIF upload step has had its chance. A usage error exits 2 at once.
#
# Inputs (environment, set by action.yml from the `with:` block; never interpolated into this script):
#   BR_MODE         checkout | advisory
#   BR_INDICATORS   indicators (eco:name@version, sha256:..., action:...), split on spaces, commas and newlines; # comments
#   BR_ADVISORY     an advisory id (GHSA-..., MAL-..., CVE-...); advisory mode only
#   BR_FAIL_ON      found (default: fail when found) | gaps (also fail when some source was not checked)
#   BR_SARIF        true | false: also write a SARIF file
#   BR_HOME_DIR     advisory mode: a br home (an index) to hunt too
#   BR_SCAN_PATH    the checkout directory (default .)
#   BR_BIN          the br command (default br)
#   BR_OUT_DIR      where to write files (default $RUNNER_TEMP/br-action)
# Outputs ($GITHUB_OUTPUT): result (clear|gaps|found|error), exit-code, sarif-file, summary-file.
set -u

BR="${BR_BIN:-br}"
MODE="${BR_MODE:-checkout}"
FAIL_ON="${BR_FAIL_ON:-gaps}"
SARIF="${BR_SARIF:-false}"
SCAN_PATH="${BR_SCAN_PATH:-.}"
OUT_DIR="${BR_OUT_DIR:-${RUNNER_TEMP:-/tmp}/br-action}"
MD_LIMIT=900000

usage() { printf '::error title=blastradius::%s\n' "$*"; printf 'blastradius: %s\n' "$*" >&2; exit 2; }
out() { if [ -n "${GITHUB_OUTPUT:-}" ]; then printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"; fi; }

case "$MODE" in checkout|advisory) ;; *) usage "mode must be checkout or advisory (got \"$MODE\")" ;; esac
case "$FAIL_ON" in found|gaps) ;; *) usage "fail-on must be found or gaps (got \"$FAIL_ON\")" ;; esac
case "$SARIF" in true|false) ;; *) usage "sarif must be true or false (got \"$SARIF\")" ;; esac

# indicators: one token each; comments start at a # that begins a line or follows a space (action:x#sha keeps its #)
INDS=()
if [ -n "${BR_INDICATORS:-}" ]; then
  while IFS= read -r tok; do
    [ -n "$tok" ] && INDS+=("$tok")
  done < <(printf '%s\n' "$BR_INDICATORS" | sed -e 's/^[[:space:]]*#.*//' -e 's/[[:space:]]#.*//' | tr ',[:space:]' '\n\n' | sed -e '/^$/d')
fi
for t in ${INDS[@]+"${INDS[@]}"}; do
  case "$t" in -*) usage "indicator \"$t\" starts with a dash; say it as eco:name@version" ;; esac
done

ADVISORY="${BR_ADVISORY:-}"
case "$ADVISORY" in -*) usage "advisory \"$ADVISORY\" starts with a dash" ;; esac
if [ "$MODE" = checkout ]; then
  [ "${#INDS[@]}" -gt 0 ] || usage "mode checkout needs indicators: (for example npm:name@1.2.3), or use mode advisory with advisory:"
  if [ -n "$ADVISORY" ]; then
    printf '::warning title=blastradius::advisory is ignored in checkout mode; use mode: advisory to hunt an advisory\n'
    ADVISORY=""
  fi
  if [ -n "${BR_HOME_DIR:-}" ]; then
    printf '::warning title=blastradius::br-home is ignored in checkout mode; use mode: advisory to hunt an index\n'
  fi
else
  [ -n "$ADVISORY" ] || usage "mode advisory needs advisory: (an id such as GHSA-xxxx-xxxx-xxxx)"
fi
[ -d "$SCAN_PATH" ] || usage "path \"$SCAN_PATH\" is not a directory"
command -v "$BR" >/dev/null 2>&1 || usage "br is not installed (the install step failed, or br-path is wrong)"

mkdir -p "$OUT_DIR" || usage "cannot write to $OUT_DIR"
MD="$OUT_DIR/hunt.md"
SARIF_FILE="$OUT_DIR/br.sarif"
SUMMARY="$OUT_DIR/summary.md"
rm -f "$MD" "$SARIF_FILE" "$SUMMARY" "$OUT_DIR/index.md"

STRICT=()
[ "$FAIL_ON" = gaps ] && STRICT=(--strict)

# the checkout hunt: INDICATORS (and the advisory) against the files in the directory; nothing else is read, no token is used
CHECK=(hunt)
if [ -n "$ADVISORY" ]; then CHECK+=(--advisory "$ADVISORY"); fi
CHECK+=(${INDS[@]+"${INDS[@]}"} --path "$SCAN_PATH" --fail-if found ${STRICT[@]+"${STRICT[@]}"})

"$BR" "${CHECK[@]}" --format md > "$MD" 2> "$OUT_DIR/hunt.err"
RC=$?
cat "$MD"
cat "$OUT_DIR/hunt.err" >&2

SARIF_OUT=""
if [ "$SARIF" = true ] && { [ "$RC" -eq 0 ] || [ "$RC" -eq 3 ] || [ "$RC" -eq 10 ]; }; then
  "$BR" "${CHECK[@]}" --format sarif > "$SARIF_FILE" 2>> "$OUT_DIR/hunt.err"
  SRC=$?
  if [ "$SRC" -ne "$RC" ] || [ ! -s "$SARIF_FILE" ]; then
    printf '::error title=blastradius::the SARIF run ended differently from the report run (exit %s, then %s)\n' "$RC" "$SRC"
    RC=1
  else
    SARIF_OUT="$SARIF_FILE"
  fi
fi

# the index hunt (advisory mode with br-home): where the advisory landed in what you have indexed
RC_INDEX=0
if [ "$MODE" = advisory ] && [ -n "${BR_HOME_DIR:-}" ]; then
  IDX=(hunt --advisory "$ADVISORY" ${INDS[@]+"${INDS[@]}"} --fail-if found ${STRICT[@]+"${STRICT[@]}"} --format md)
  BR_HOME="$BR_HOME_DIR" "$BR" "${IDX[@]}" > "$OUT_DIR/index.md" 2> "$OUT_DIR/index.err"
  RC_INDEX=$?
  cat "$OUT_DIR/index.md"
  cat "$OUT_DIR/index.err" >&2
fi

# one exit code: an error beats a finding beats a gap
FINAL=0
for c in "$RC" "$RC_INDEX"; do
  case "$c" in
    0) ;;
    10) [ "$FINAL" -eq 0 ] || [ "$FINAL" -eq 3 ] && FINAL=10 ;;
    3) [ "$FINAL" -eq 0 ] && FINAL=3 ;;
    *) FINAL="$c"; break ;;
  esac
done
case "$FINAL" in
  0) RESULT=clear ;;
  3) RESULT=gaps ;;
  10) RESULT=found ;;
  *) RESULT=error ;;
esac

# the job summary: the report as markdown, under a heading that says the answer
{
  case "$RESULT" in
    found) echo "## blastradius: FOUND" ;;
    gaps) echo "## blastradius: CLEAR WITH GAPS" ;;
    clear) echo "## blastradius: CLEAR" ;;
    *) echo "## blastradius: ERROR (exit $FINAL)" ;;
  esac
  echo
  if [ -s "$MD" ]; then head -c "$MD_LIMIT" "$MD"; echo; else echo "br printed no report; see the job log."; fi
  if [ -s "$OUT_DIR/index.md" ]; then
    echo
    echo "### Your index"
    echo
    head -c "$MD_LIMIT" "$OUT_DIR/index.md"
    echo
  fi
  if [ -s "$OUT_DIR/hunt.err" ] && [ "$RESULT" = error ]; then
    echo
    echo '```'
    head -c 20000 "$OUT_DIR/hunt.err"
    echo '```'
  fi
} > "$SUMMARY"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  # GitHub refuses a step summary over 1 MiB
  head -c "$MD_LIMIT" "$SUMMARY" >> "$GITHUB_STEP_SUMMARY"
fi

out result "$RESULT"
out exit-code "$FINAL"
out sarif-file "$SARIF_OUT"
out summary-file "$SUMMARY"
exit 0
