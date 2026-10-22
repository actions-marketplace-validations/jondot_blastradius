# Packaging

What is here, what each file is for, and what publishing needs. Nothing in this directory has been published. Publishing is the maintainer's decision.

| File | What it is | Status |
|---|---|---|
| `homebrew/br.rb` | A Homebrew formula template for the four Unix release archives (macOS and Linux, arm64 and x86_64). Checksums and the version are placeholders. | Syntax checked with `ruby -c`. Not run through `brew audit` or `brew test`. |
| `homebrew/fill.sh` | Fills `br.rb` from a release's `.sha256` files and writes `br.filled.rb`. It stops if any checksum is missing or malformed. | Tested by `homebrew/test-fill.sh` with made-up checksums. |
| `../Dockerfile` | A multi-stage build: `rust:1-alpine` builds a static musl binary, and the final image is `scratch` with only `br`, an empty `/tmp` and a writable `/data` for `BR_HOME`. Runs as a non-root user. | Not built here (no network). |
| `../Cargo.toml` | Crate metadata for `cargo publish`: description, license, repository, readme, keywords, categories, an `include` list. `publish = false` is still set. | `cargo package --list` checked. |

## Publishing, step by step

Each step needs the maintainer's go-ahead.

### Release archives (the base for everything else)
1. Tag `vX.Y.Z`. `.github/workflows/release.yml` builds five targets and attaches `br-X.Y.Z-TARGET.tar.gz` (a `.zip` for Windows) and a `.sha256` file for each.
2. Checksums are per archive, not signed. Signing (for example `cosign` or `minisign`) is not set up. Adding it means a key, a step in the release workflow and a line in `install.sh` to verify it. This directory does not do that.

### Homebrew
1. Create a tap repository, for example `jondot/homebrew-tap`.
2. After the release is up: `packaging/homebrew/fill.sh X.Y.Z`. It downloads the four `.sha256` files and writes `packaging/homebrew/br.filled.rb`.
3. Copy it to the tap as `Formula/br.rb`, then run `brew audit --strict --new br` and `brew test br` on a Mac and on Linux.
4. Users run `brew install jondot/tap/br`.

The formula installs a binary built by the release workflow. It does not build from source.

### Container image
1. `docker build -t ghcr.io/jondot/blastradius:X.Y.Z .` from the repository root.
2. Try it: `docker run --rm ghcr.io/jondot/blastradius:X.Y.Z demo`.
3. Push after logging in to GHCR. Pin the builder image by digest first, so the build is repeatable.

The image has no shell, no `git`, no `ssh` and no `gh`. A hunt over a mounted checkout (`--path`) and `br demo` work. Scanning ssh hosts, or relying on a `gh` login for the token, does not. Pass `GITHUB_TOKEN` instead.

### crates.io
1. Remove `publish = false` from `Cargo.toml`.
2. `cargo publish --dry-run`, then `cargo publish`. The crate name `blastradius` has not been checked for availability.
3. Users then run `cargo install blastradius`. Until then, `cargo install --path .` is the way.

The `include` list ships the sources, the embedded demo org and the docs that the unit tests read. `docs/demo.gif` is not included, so the README image will not show on crates.io.

## Rebuilding the demo org

`br demo` carries a sample org inside the binary: `assets/demo/home.tar.gz`, a tarball of a seeded index. It is rebuilt by the maintainers when the index schema changes; the build is repeatable, so the same sample and the same `br` give the same bytes.
