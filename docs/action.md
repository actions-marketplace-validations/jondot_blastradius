# br in your pipeline: the GitHub Action, SARIF and the pre-commit hook

Three ways to put br where work already happens. All of them only read, and none needs a token for the checkout gate.

## The GitHub Action

### Gate a checkout

Fail the build when a lockfile in the checkout holds a package from an advisory you are tracking:

```yaml
jobs:
  br:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: jondot/blastradius@v1
        with:
          indicators: |
            npm:@tanstack/react-router@1.120.3
            pypi:litellm@1.82.7
```

`mode: checkout` (the default) runs `br hunt INDICATORS --path . --fail-if found --strict` (the `--strict` goes with `fail-on: gaps`, the default; `fail-on: found` leaves it off). It reads the lockfiles and manifests under the directory, and the installed packages there, in a throwaway index. It does not touch any index of yours and makes no network call besides downloading br.

### Hunt an advisory

```yaml
      - uses: jondot/blastradius@v1
        with:
          mode: advisory
          advisory: GHSA-q7vr-4xhc-m2jw
          br-home: ${{ github.workspace }}/.br     # optional: an index you restored from a cache or an artifact
```

`mode: advisory` hunts the advisory in the checkout. With `br-home` it also hunts that index (`BR_HOME`), and the job summary shows both. Looking the advisory up asks OSV; that is the one network call besides the download. The index hunt does not ask the SARIF upload to carry it: an index finding is not a file in this repo.

### Inputs

| input | default | meaning |
|---|---|---|
| `mode` | `checkout` | `checkout` or `advisory` |
| `indicators` | | `eco:name@version`, `sha256:HASH`, `action:owner/repo@ref`; split on spaces, commas and newlines; `#` after a space starts a comment. Required for `checkout` |
| `advisory` | | advisory id (GHSA, MAL, CVE). Required for `advisory`; ignored, with a warning, in `checkout` |
| `version` | the pin in `action/VERSION` | the br release to install, for example `0.1.0` |
| `checksum` | the release's `.sha256` file | the archive's SHA-256, pinned by you |
| `br-path` | | use this binary and download nothing |
| `br-home` | | advisory mode: an index to hunt too |
| `path` | `.` | the directory to read |
| `sarif` | `false` | `true` uploads to code scanning |
| `sarif-category` | `blastradius` | set it if the workflow runs the Action more than once |
| `fail-on` | `gaps` | `found` fails only when something is found; `gaps` also fails when something could not be checked |

Outputs: `result` (`clear`, `gaps`, `found`, `error`), `exit-code` (0, 3, 10, or br's error code), `sarif-file`.

### What the job does

1. **Install.** It downloads `br-VERSION-TARGET.tar.gz` from the release and checks its SHA-256 before unpacking. With `checksum:` the value you pinned is the only one trusted. Without it the release's own `.sha256` file is used: that catches a damaged download, not a replaced release, so pin `checksum:` if your threat model includes the release page. A mismatch installs nothing and fails the job. Supported runners: Linux and macOS (x86_64 and arm64). On Windows, put `br.exe` on `PATH` and pass `br-path`.
2. **Hunt.** The report is printed in the log and written to the job summary (`$GITHUB_STEP_SUMMARY`) as markdown, under the heading FOUND, CLEAR WITH GAPS, CLEAR or ERROR.
3. **Upload SARIF** (`sarif: true`) with `github/codeql-action/upload-sarif`. The job needs `security-events: write`. Pull requests from forks get a read-only token, so the upload fails there: set `sarif` only on events that have the permission.
4. **Enforce.** The job fails last, so the upload and the summary happen even when something was found. Exit 10 means found; 3 means gaps under `fail-on: gaps`.

The Action's own text is `action.yml`; the scripts it runs are in `action/`. Inputs reach the scripts as environment variables, never spliced into shell text.

### Use a mirror or your own build

`br-path` skips the download. `BR_RELEASE_BASE` in the job environment points the installer at a mirror laid out like GitHub's `releases/download`.

## `br hunt --format sarif`

```sh
br hunt npm:evil-dep@1.2.3 --path . --format sarif > br.sarif
```

SARIF 2.1.0, one run, one tool (`blastradius`):

- **One result per finding.** Level `error` for something present now, `warning` for a CI run that installed it and is gone, `note` for a possible match br could not confirm. A finding that is present now but first seen after the exposure window ended is `error` too.
- **Locations.** A lockfile or workflow hit has a physical location: the file path, and the lockfile line when the parser recorded one (a line is never invented). Everything else has logical locations only: `repo:ORG/NAME`, `image:REF@DIGEST`, `host:NAME:PATH`, `repo:ORG/NAME/cache:KEY`, with a `kind` on each. With `--path`, file paths are relative to that directory and carry `uriBaseId: %SRCROOT%`.
- **Rules.** One per place a package can sit (`br.repo`, `br.ci-run`, `br.cache`, `br.artifact`, `br.image`, `br.host`, `br.release-asset`, `br.workflow-ref`) and `br.possible`.
- **Gaps are notifications.** Every source br could not check is a `toolExecutionNotifications` entry (level `warning`, "Not checked: ...") in the run, with the command that closes it. The run's `properties.verdict` is `found`, `clear` or `clear_with_gaps`. A SARIF file with no results and some notifications is not a clean bill.
- **Stable fingerprints.** `partialFingerprints["blastradius/v1"]` is a hash of the rule, indicator and place, so the same finding keeps its alert across runs.

GitHub code scanning shows results that have a physical location. An index hunt (repos, images, hosts) produces logical locations only, which SARIF allows and other consumers show, but which GitHub's Security tab may not list. For the Security tab use the checkout gate.

Files listed under SIMILAR, NOT IDENTICAL are lookalikes br never counts as findings, so they are not results. `--format sarif` does not combine with `--quiet`, `--progress`, `--wide` or `--yara`.

## `br claimcheck --format sarif`

```sh
br claimcheck --path . --org YOURORG --format sarif --fail-if exposed > claims.sarif
```

The dependency-confusion check as SARIF 2.1.0, from the same writer (`src/out/sarif.rs`) as the hunt:

- **One result per name that is FREE, SQUATTED or SCOPE UNCLAIMED, and one per file where it was seen**, so each manifest, lockfile or registry setting that names it carries its own annotation. Level `error`. Names shown to be yours (OURS) are not results. The rules are `br.claim.free`, `br.claim.squatted` and `br.claim.scope-unclaimed`; the flags (`higher_version`, `bin_match`, `scope_held`) are in the message and in `properties.flags`.
- **Locations.** The file where the name was seen, relative to the checkout with `uriBaseId: %SRCROOT%` when one `--path` is given (several `--path` directories are prefixed with their folder name; a name read from the index's repos or a CI artifact carries the repo as a logical location). br records no line for a claim, so there is no region.
- **Gaps are notifications.** An unreachable or rate-limited registry, a name beyond `--max-names`, a repo it could not read: each is a `toolExecutionNotifications` warning, and `properties.verdict` is `exposed`, `clear` or `clear_with_gaps`.

### claimcheck is not an Action mode

The Action is built around `br hunt`: it requires `indicators` or an `advisory`, maps the hunt's exit codes to `result`, and promises that checkout mode "makes no network call besides downloading br". `br claimcheck` takes no indicators and asks the public registries about your names, which breaks that promise, and its exit code means exposed, not found. Adding a mode would mean a second result vocabulary and a second set of promises in one `action.yml`, so it is left out. To run it in a workflow, reuse the installer from the Action's own checkout and call br yourself:

```yaml
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with: {repository: jondot/blastradius, ref: v0.1.0, path: .br-action}
      - run: bash .br-action/action/install.sh
      - run: br claimcheck --path . --org YOURORG --format sarif --fail-if exposed > claims.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: {sarif_file: claims.sarif, category: blastradius-claimcheck}
```

Add `--strict` to also fail when a registry could not answer. This recipe has not been run on GitHub; the installer and the SARIF are tested locally (end-to-end tests and the unit test in `sarif.rs`).

## The pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/jondot/blastradius
    rev: v0.1.0
    hooks:
      - id: blastradius
```

List what you are tracking, one per line, in `.br-indicators` at the repo root:

```text
# the worm from this morning
npm:@tanstack/react-router@1.120.3
npm:@tanstack/router-core@1.120.3
pypi:litellm@1.82.7
```

On each commit pre-commit passes the lockfiles the commit changes (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, poetry.lock, uv.lock, pdm.lock, Pipfile.lock, Cargo.lock, go.mod, go.sum, go.work, requirements files) to `hooks/br-precommit.sh`. It copies them into a scratch directory and runs `br hunt INDICATORS --path SCRATCH --fail-if found`. The commit is blocked when one is found (exit 1, with br's report). Needs `br` on `PATH`; the hook says so, and fails, when it is missing: a hook that cannot check must not look like a pass. No `.br-indicators` file, or one with no indicators, means nothing to check: the hook says that and passes.

Set `BR_INDICATORS_FILE` to use another file name.

## Checking it works

- End-to-end tests run `br claimcheck --format sarif`, `br hunt --format sarif`, the Action's scripts (with a stub GitHub environment) and the hook.
- `.github/workflows/action-selftest.yml` runs the real Action against `tests/action/bad` (must fail) and `tests/action/clean` (must pass).
