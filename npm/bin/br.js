#!/usr/bin/env node
// Runs the br binary from the platform package npm installed next to this one.
"use strict";
const { spawnSync } = require("node:child_process");
const platforms = require("../platforms.json");

const key = `${process.platform}-${process.arch}`;
const install = "curl -fsSL https://raw.githubusercontent.com/jondot/blastradius/main/install.sh | sh";

if (!(key in platforms)) {
  console.error(`blastradius: no build for ${key}. Builds: ${Object.keys(platforms).join(", ")}.`);
  process.exit(1);
}

let bin;
try {
  bin = require.resolve(`blastradius-${key}/bin/${process.platform === "win32" ? "br.exe" : "br"}`);
} catch {
  console.error(`blastradius: the package blastradius-${key} is missing (installed with --no-optional or --omit=optional?).`);
  console.error(`Reinstall without that flag, or install the binary directly: ${install}`);
  process.exit(1);
}

const run = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (run.error) {
  console.error(`blastradius: could not run ${bin}: ${run.error.message}`);
  process.exit(1);
}
if (run.signal) {
  process.kill(process.pid, run.signal);
}
// br's exit codes carry the answer (10 found, 3 clear with gaps), so pass them through unchanged
process.exit(run.status ?? 1);
