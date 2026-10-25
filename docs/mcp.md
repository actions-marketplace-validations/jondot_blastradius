# br mcp: let an AI agent ask br

`br mcp` is a read-only [Model Context Protocol](https://modelcontextprotocol.io) server over stdio. During an incident you can ask your agent "are we hit by X?", and it calls br instead of guessing.

It targets MCP revision **2025-06-18**. It also answers a client that asks for 2025-03-26 or 2024-11-05. Messages are JSON-RPC 2.0, one per line, on stdin and stdout. Nothing else is written to stdout.

## Register it

Claude Code:

```sh
claude mcp add blastradius -- br mcp
```

Without installing br first, through npm:

```sh
claude mcp add blastradius -- npx -y @jondot/blastradius mcp
```

Use one client's index by setting `BR_HOME` in the server's environment:

```sh
claude mcp add blastradius -e BR_HOME=$HOME/clients/acme -- br mcp
```

Any client with a JSON config (Claude Desktop, Cursor, Zed and others):

```json
{ "mcpServers": { "blastradius": { "command": "br", "args": ["mcp"], "env": { "BR_HOME": "/home/me/.blastradius" } } } }
```

Build the index first with `br init`; the server reads it and never builds one.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `hunt` | `indicators` (array) or `advisory`; `path`, `repo`, `owner`, `host`, `now`, `only`, `window` | A one-line summary (verdict, findings, places, gaps) and the JSON `br hunt --format json` prints |
| `status` | `all`, `owner` | A summary line and `br status` output: how fresh each source is |
| `advisory_show` | `id` | `br advisory show` output for an advisory the index or your notes hold |
| `hosts` | none | `br hosts list` output |
| `evidence_summary` | `file` | The claim, verdict, counts and gaps of an evidence file already written, and the result of checking its seal |
| `claimcheck` | `path`, `repo`, `org`, `max_names` (0 or more, the CLI default is 400), `as_of` | Which of your package names are FREE, SQUATTED or SCOPE UNCLAIMED on the public registries, with the flags and where each name was seen. Makes read-only GETs to public registries; writes nothing |

Every result has a summary block first, then the output. A hunt with no findings says `CLEAR WITH GAPS` and the number of sources not checked: an agent must pass that on, not say "clear".

A hunt that finds something is a normal answer (`isError` is false). `isError` is true when br itself fails, such as no index (exit 5) or a bad indicator, and the text carries br's message and hint. Bad arguments (an unknown field, a value that starts with `-`) are also tool errors. An unknown tool name is JSON-RPC error -32602 and an unknown method -32601.

## What it never does

- It does not scan, init, import, write a note, notify, fix, purge or write evidence. Those stay in the CLI, and none is a tool.
- `claimcheck` is the one tool that uses the network: it makes read-only GETs to the public registries (npmjs.org, pypi.org, crates.io, proxy.golang.org) and, without `path`, reads the index's repos through the GitHub API (needs a token). It writes nothing: no index, no cache, no BR_HOME, and it cannot pass `--record`, so it never stores a snapshot. Its `max_names` is the CLI's (0 or more, default 400). It never publishes or claims a name. An unreachable registry is a gap, not a clear answer.
- Apart from `claimcheck`, it does not ask OSV or any network: an advisory id must already be in the index or your notes (`br advisory note`), or be a local file. A miss comes back as a tool error. This is because a lookup caches the record in the index, and this server writes nothing.
- It cannot be given a flag: arguments are fixed fields, and any value starting with `-` is refused. `--live` and `--yara` are not reachable.
- Each tool starts `br` again with fixed arguments (the same binary), so a tool answers exactly as the CLI does.

## Try it by hand

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"me","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hunt","arguments":{"indicators":["npm:left-pad@1.3.0"]}}}' | br mcp
```


