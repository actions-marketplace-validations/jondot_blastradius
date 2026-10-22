# Why br, what it reads, and what it never does

`br` answers one question after a package goes bad: where did it land, what could it reach, and is it really gone? It reads your GitHub org, your container registries and the machines you point it at, builds a local index, and answers from that index.

Try it first: `br demo`. No token, no network, nothing of yours is read.

## What br reads

- **GitHub org.** Repos, lockfiles and manifests with their commit history (npm, yarn, pnpm, PyPI, Cargo, Go), CODEOWNERS, workflow files, Actions runs, caches, artifacts, releases and their assets, teams and members, registered runners, and the org's container images on GHCR.
- **Container registries.** Images, layers and the files in them, by hash, including files a later layer deleted. It uses your existing `docker login` credentials.
- **Machines.** A directory tree on this machine, ssh-reachable hosts and runners, and `.brx` files exported by laptops.
- **Advisories.** OSV, for `GHSA-` and `MAL-` ids, and the advisory ids in pasted text.
- **For `br claimcheck` only:** the files that name your own packages (manifests, registry settings, lockfiles, shipped source maps), from your repos or a checkout.

## What it sends, and where

The index lives on your disk (`BR_HOME`, default `~/.blastradius`). A hunt reads only the index. It touches the network or a machine only when you pass `--now`, `--live` or `--path`.

| To | When | What |
|---|---|---|
| GitHub API (or your GHE host) | `init`, `scan`, `--now` | read requests (GET and HEAD) with your token |
| container registries you are logged into | `init`, `scan` | read requests; the standard token handshake for the credentials in your docker config |
| OSV (`api.osv.dev`) | an advisory id the index does not hold | the advisory id |
| the npm registry | `br fix` | package names, to check whether a bump moves a dependency |
| ssh hosts you registered | `scan --host`, `--live` | a read-only scan over ssh |
| the public registries (npmjs.org, pypi.org, crates.io, proxy.golang.org) | `br claimcheck`, and the `claimcheck` tool of `br mcp`; never a hunt | your own package names, one read-only GET each |

`br` has no telemetry, no account and no server of its own. Set `BR_GITHUB_API`, `BR_OSV_API`, `BR_NPM_REGISTRY`, `BR_PYPI_API`, `BR_CRATES_API` and `BR_GOPROXY` to point it at mirrors or to nothing. `br claimcheck` is the one command that sends names of your internal packages to public registries; if the names themselves are sensitive, run it against a mirror or not at all.

## What it never does

- It does not write to anything it reads. Every GitHub call is a GET or a HEAD. The only POSTs are the registry token exchanges above.
- It does not delete, rotate, rebuild, unarchive or merge anything. `br fix`, `br purge` and `br notify` print commands and drafts, and a person runs them.
- It does not send a message. `br notify` writes the drafts.
- It does not upload your index, your file hashes or your lockfiles.
- It does not say "clear" when it could not check. A clean answer with gaps is `CLEAR WITH GAPS`, and `--strict` makes that exit 3.

## Where br fits

These tools do different jobs. The descriptions are short and from their public documentation; read theirs for detail.

| Tool | What it is built to answer | What br adds |
|---|---|---|
| **Dependabot** | Is a dependency in this repo vulnerable now, and here is a PR to update it. | Where a bad version was in the past (commit history and CI runs), and in caches, images and machines. |
| **osv-scanner** | Which of these lockfiles, directories or images have packages with known OSV vulnerabilities, now. | An index across the org, the exposure window, CI runs with the secrets they could read, deleted image layers, and owners. br reads OSV too. |
| **trivy** | Vulnerabilities, misconfigurations and secrets in an image, filesystem or repo, and SBOMs. | The same question asked across the whole org after the fact, and what the CI jobs could reach. |
| **Socket** | Does this package behave badly, before you install it. | What to do once a package is known to be bad: every place it landed and who owns it. br does not judge packages. |
| **Dependabot, Socket and the rest on dependency confusion** | They watch the packages you install. They do not ask which of your own internal names a stranger could register. | `br claimcheck`: your internal names against the public registries, with where each is used. It does not stop an install; it tells you what to pin or claim. |
| **GitHub secret scanning** | Has a secret been committed. | The secret names a CI run could read when it installed a bad package. br names secrets; it does not read their values. |

Use them together. A scanner tells you a package is bad before or after the fact. `br` tells you what that cost you, place by place.

## Where br does not fit

- It is not a scanner that finds new vulnerabilities. It looks for the indicators you give it, or that an advisory lists.
- It is not a monitor. `br claimcheck` is a check you run, not a watcher that notices a name being registered tomorrow. The index is as fresh as its last scan.
- It does not cover what it cannot reach: laptops nobody exported, SaaS tools, cloud accounts, personal repos.
- It matches packages by ecosystem, whole name and exact version. A renamed or repacked package is found only by hash or by `--similar`.

## FAQ

**Does it need a server or an account?** No. It is one binary and a local index.

**What token does it need?** A read-only GitHub token (`GITHUB_TOKEN`, `GH_TOKEN`, or a `gh` login). Registries use your `docker login`. Checkout mode (`br hunt INDICATOR --path .`) needs neither.

**How long does the first index take?** In testing, a 6-repo org took about 8 seconds. Time grows with the number of repos, and GitHub's rate limits apply. Later scans use conditional requests, so an unchanged repo costs about 3 API calls.

**How do I know the answer is current?** Every answer starts with the index age and the stale sources. `--max-age DUR` refuses to answer (exit 5) if a source is older.

**What if a source is unreachable?** It is listed under NOT CHECKED with the command to close it. A 403, an expired log or an unreadable lockfile is a gap, never a clear.

**Can I use it in CI?** Yes. `br hunt npm:name@1.2.3 --path . --fail-if found --strict` reads the lockfiles under the directory, with no index and no network. Exit 10 is found; exit 3 is "clear with gaps". A GitHub Action for the same gate is described in [docs/action.md](action.md), with `--format sarif` for GitHub code scanning (also for `br claimcheck`) and a pre-commit hook.

**Can an AI agent use it?** Yes, read-only. `br mcp` serves `hunt`, `status`, `advisory_show`, `hosts`, `evidence_summary` and `claimcheck` over MCP on stdio. It never scans, writes, notifies or purges, and `claimcheck` is the one tool that makes (read-only) network calls: [docs/mcp.md](mcp.md).

**Does `br claimcheck` publish or claim names for me?** No. It prints what to pin, claim or publish, as text. A person does it. It writes nothing either, unless you pass `--record`, which stores a snapshot under `BR_HOME/claimcheck/` for `br diff --claimcheck`.

**Why can `br claimcheck` say "owner not shown"?** A public registry shows a name and its metadata, not who really owns it. br calls a name OURS only on a proof it prints (a repository URL on your GitHub org, a registry owner that is your team, a verified member as publisher). Otherwise it is SQUATTED, and it does not guess.

**Can I hand the result to an auditor?** `br evidence` writes a JSON file, a Markdown report and a sha256 seal. `--sign KEY` adds an `ssh-keygen -Y sign` signature. `br verify` checks both. The seal shows the files were not changed; only the signature shows who made them.

**Does it find laptops?** Only laptops that were scanned. A laptop runs `br scan --local --export NAME.brx --seal`, and you `br import` the file. `br hosts` lists the people with no scan.

**Does it tell me whether the malware ran?** No. It tells you where the package was installed and which secret names a CI job could read. A cache entry on a laptop is shown as "the install likely ran". That is an inference, and it is labelled as one.

**Is the sample org real?** No. It is a made-up org, built from the test world used to develop br, with a pinned clock of 2026-05-12T07:10:00Z.

**What does it cost?** It is open source under the MIT license.

**What are the known rough edges?** The default hunt tables are wide. The index does not see what it was not given. `br fix` can only check dependency moves when it can reach the npm registry.
