# SOC analyst

## The incident

You work for the MDR provider watching a customer. The EDR gave you a sha256 and a name, `netprobe`. You work from hashes and EDR alerts, not package names. You want every place that exact file lives: laptops, runner tool caches, release assets and images, deleted layers included. For each place you want first and last seen, which package version carried it, and files that look like it but are not identical.

The sample org in `br demo` holds no malware hash, so the hash commands below are shown without output. The package commands are real output from the sample.

## Commands

**1. Search by hash.** The index holds the sha256 of files in caches, build artifacts, release assets, image layers and scanned hosts. No path is needed.

```sh
br hunt sha256:HASH                      # the 64 hex characters from the EDR alert
br hunt sha256:HASH --similar-related     # also files that look like the others shipped in the same package install
```

Each location comes back with first seen, last seen, the owner and the package version that carried it. If the hash is listed in an advisory, the output says which.

**2. Tell a final image from a deleted layer.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --only images
...
  note: FIRST SEEN is the build time; LAST SEEN is when the registry was last read
  note: 'layer N (deleted in layer M)' means the file is in an earlier image layer, deleted later but still downloadable by digest
...
[exit 10]
```

A file in a deleted layer is still in the registry. Anyone who pulls the image by digest can read it. The other kind of row says `final image`.

**3. Ask for files that look alike.** A repacked dropper has a new hash. Give br a sample and it lists files that are close to it:

```sh
br hunt --similar suspect.js
```

Similarity is a score, not a match. `/etc/os-release` can score high against a small script. Treat a similarity hit as a lead and do not put it in a "hosts to clean" count.

**4. See what was not looked at.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --only hosts --near-misses
FOUND  3 indicators (GHSA-q7vr-4xhc-m2jw)
2 hosts to clean.
...
POSSIBLE (evidence of exposure on a host the index cannot confirm; not counted as found):
...
[exit 10]
```

`--near-misses` lists the packages br left out and why: a different name, or a prerelease. A package matches on ecosystem, whole name and exact version.

**5. Query the index yourself.** `br sql` runs read-only SQL over the index. `br demo sql --schema` lists the tables.

```
$ br demo sql "SELECT repository, tags, built FROM images ORDER BY built"
REPOSITORY                 TAGS                        BUILT
ghcr.io/acme/embed-widget  ["1.8.1"]                   2026-05-05 10:30:00 UTC
ghcr.io/acme/web           []                          2026-05-08 10:20:00 UTC
ghcr.io/acme/web           ["latest", "main-5e1f0a2"]  2026-05-11 15:20:00 UTC
ghcr.io/acme/embed-widget  ["1.8.2"]                   2026-05-11 16:46:00 UTC
[exit 0]
```

## Beyond this advisory

- **From an agent or a script.** `br mcp` ([docs/mcp.md](../mcp.md)) serves `hunt` over stdio, and `br hunt --format sarif` writes SARIF 2.1.0 for any SARIF consumer ([docs/action.md](../action.md)). Neither changes the index. For a name-squatting report rather than a bad package, see [claimcheck.md](claimcheck.md).

## Reading the output

- A hash match is exact. A package match is on name and version.
- **possible** on a host means a CI run used it, or a person works in an affected repo, but the host's scan is older than that. It is a lead.
- One index per client: `br --home ~/clients/NAME ...`. Each keeps its own notes and custody log.

## What br does not tell you

- A host scan hashes only the files that match its filter. An extensionless binary in `/tmp` can be missed. `br status --config` shows the filter.
- It does not read container layer caches on a host.
- It has no network path to a laptop. A laptop appears in the answer only after someone ran `br scan --local --export` on it and you imported the file.
- Similarity is by content. A file that changed enough to look different will not score.
