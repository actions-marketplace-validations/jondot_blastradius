# blastradius

Find everywhere a bad package, runtime, CA certificate or secret lives in your org: repos, CI runs, caches, container images and laptops. Read-only.

```sh
npx -y @jondot/blastradius demo                       # a sample org built into the binary, no token, no network
npx -y @jondot/blastradius hunt npm:name@1.2.3 --path . --fail-if found --strict
npm i -g @jondot/blastradius && br --help             # installs the `br` and `blastradius` commands
claude mcp add blastradius -- npx -y @jondot/blastradius mcp
```

This package runs the native `br` binary for your platform (macOS and Linux, x86_64 and arm64; for Windows, take the zip from the [releases page](https://github.com/jondot/blastradius/releases)), installed as an optional dependency. Exit codes are br's own: 0 clear, 10 found, 3 clear with gaps under `--strict`.

Docs, the GitHub Action and the agent skill: https://github.com/jondot/blastradius
