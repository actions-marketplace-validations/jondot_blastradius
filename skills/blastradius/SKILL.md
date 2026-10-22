---
name: blastradius
description: Answer "are we exposed?" during a supply-chain or security incident with the read-only br CLI. Use when someone names a malicious or vulnerable package, a GHSA/CVE/MAL advisory, a file hash, a GitHub Action ref, a language runtime that needs a fixed version (PHP, Node), a distrusted CA certificate, or a leaked secret, and wants to know where it lives across repos, CI runs, caches, container images and laptops, who owns each place, and how to clean up.
---

# blastradius (br)

br answers "where did this bad thing land in our org, and who owns each place?" It only reads. It never changes repos, CI, registries or machines.

## Install

Prefer the one that needs nothing set up:

```sh
npx -y blastradius --version        # runs br through npm, nothing else to install
npm i -g blastradius                # puts `br` on PATH
curl -fsSL https://raw.githubusercontent.com/jondot/blastradius/main/install.sh | sh   # no Node: binary to ~/.local/bin
```

In the commands below, `br` can be replaced by `npx -y blastradius`.

## Pick the mode

1. **One checkout, no token, no network.** Use this first when the question is about the repo you are in:
   `br hunt npm:name@1.2.3 --path . --fail-if found --strict`
2. **The whole org.** Needs an index, built once with a read-only GitHub token:
   `GITHUB_TOKEN=... br init --org ORG`, then `br hunt ...` without `--path`. Building the index reads many repos and can take a while; ask the user before running `br init` on a large org.
3. **Just exploring.** `br demo` is a sample org inside the binary, with no token and no network. `br demo hunt --advisory GHSA-q7vr-4xhc-m2jw` shows a real answer.

## Indicators

| What you were told | Indicator |
|---|---|
| a package version | `npm:@scope/name@1.2.3`, `pypi:name@1.2.3`, `cargo:`, `go:` |
| an advisory | `--advisory GHSA-xxxx-xxxx-xxxx` (or CVE-, MAL-) |
| a pasted advisory or blog post | `--text FILE` (or `--text -` for stdin) |
| a file hash | `sha256:HASH` |
| a GitHub Action | `action:owner/repo@ref` |
| a runtime that must be upgraded | `runtime:php@fixed:8.3.27,8.4.14` (any version below a fix line is reported) |
| a CA certificate to distrust | `cert:SHA256HEX` or `cert:subject:TEXT` |
| a leaked secret, by name | `secret:NPM_TOKEN` (globs, quoted: `'secret:AWS_*'`), with `--since DATE` for "used since the leak" |

Names match whole: `lodash` never matches `lodash.merge`. Several indicators can go in one hunt.

## Read the answer correctly

- Use `--format json` when you will parse the result; the default table is for people.
- **CLEAR WITH GAPS is not clear.** It means some sources could not be checked (a 403, an expired CI log, an unreadable lockfile). Tell the user it is clear *with gaps* and list the gaps; never shorten it to "clear".
- Every answer states how old the index is. If it is old, say so, or refresh with `br scan`.
- Exit codes: `0` clear, `10` found, `3` clear with gaps (only with `--strict`), `5` no index or stale index, `2` bad flag or indicator, `4` auth, `1` failure. A hunt that finds something is a normal answer, not an error.

## After a finding

- `br fix --advisory ID`: how each repo reaches a fixed version.
- `br notify --advisory ID`: one draft message per owning team (it drafts; it does not send).
- `br purge --advisory ID`: the caches, artifacts and images to delete (it lists them; it never deletes).
- `br evidence --advisory ID --out evidence.json`: a sealed record for an auditor or customer.

## As an MCP server

```sh
claude mcp add blastradius -- npx -y blastradius mcp
```

Tools: `hunt`, `status`, `advisory_show`, `hosts`, `evidence_summary`, `claimcheck`. They read an index built with `br init`; the server never builds one.

More: https://github.com/jondot/blastradius
