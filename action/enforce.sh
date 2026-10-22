#!/usr/bin/env bash
# The last step of the Action: turn the answer run.sh recorded into the job's result, after the SARIF upload has run.
# Usage: enforce.sh EXIT_CODE RESULT   (RESULT is clear, gaps, found or error)
set -u
code="${1:-}"
result="${2:-}"
case "$code" in ''|*[!0-9]*) printf '::error title=blastradius::the run step did not record an answer; see its log\n'; exit 1 ;; esac
case "$result" in
  clear) printf 'blastradius: clear.\n'; exit 0 ;;
  found) printf '::error title=blastradius::FOUND: a listed package is in this checkout (exit %s). The job summary lists where.\n' "$code" ;;
  gaps) printf '::error title=blastradius::CLEAR WITH GAPS: something could not be checked, and fail-on is gaps (exit %s). Set fail-on: found to fail only when found.\n' "$code" ;;
  *) printf '::error title=blastradius::br stopped with exit %s; the job summary has its message.\n' "$code" ;;
esac
[ "$code" -ne 0 ] && exit "$code"
exit 1
