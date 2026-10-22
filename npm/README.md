# blastradius

Find everywhere a bad package, runtime, CA certificate or secret lives in your org: repos, CI runs, caches, container images and laptops. Read-only.

```sh
npx -y blastradius demo                       # a sample org built into the binary, no token, no network
npx -y blastradius hunt npm:name@1.2.3 --path . --fail-if found --strict
npm i -g blastradius && br --help             # installs the `br` and `blastradius` commands
claude mcp add blastradius -- npx -y blastradius mcp
```

This package runs the native `br` binary for your platform (macOS and Linux on x86_64 and arm64, Windows on x86_64), installed as an optional dependency. Exit codes are br's own: 0 clear, 10 found, 3 clear with gaps under `--strict`.

Docs, the GitHub Action and the agent skill: https://github.com/jondot/blastradius
