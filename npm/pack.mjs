// Lay out the npm packages for one release: one per platform holding the binary, and `blastradius`, which runs it.
// usage: node npm/pack.mjs VERSION DIST_DIR OUT_DIR
//   DIST_DIR holds the release archives (br-VERSION-TARGET.tar.gz, .zip for Windows)
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const [rawVersion, dist, out] = process.argv.slice(2);
if (!rawVersion || !dist || !out) {
  console.error("usage: node npm/pack.mjs VERSION DIST_DIR OUT_DIR");
  process.exit(2);
}
const version = rawVersion.replace(/^v/, "");
const platforms = JSON.parse(readFileSync(join(here, "platforms.json"), "utf8"));
const common = {
  version,
  license: "MIT",
  homepage: "https://github.com/jondot/blastradius",
  repository: { type: "git", url: "git+https://github.com/jondot/blastradius.git" },
};

rmSync(out, { recursive: true, force: true });
for (const [key, target] of Object.entries(platforms)) {
  const [os, cpu] = key.split("-");
  const name = `blastradius-${key}`;
  const dir = join(out, name);
  mkdirSync(join(dir, "bin"), { recursive: true });
  const windows = os === "win32";
  const archive = resolve(dist, `br-${version}-${target}.${windows ? "zip" : "tar.gz"}`);
  if (!existsSync(archive)) {
    console.error(`missing ${archive}`);
    process.exit(1);
  }
  if (windows) {
    execFileSync("unzip", ["-q", "-o", archive, "-d", join(dir, "bin")]);
  } else {
    execFileSync("tar", ["xzf", archive, "-C", join(dir, "bin")]);
  }
  const exe = join(dir, "bin", windows ? "br.exe" : "br");
  if (!existsSync(exe)) {
    console.error(`${archive} has no ${windows ? "br.exe" : "br"}`);
    process.exit(1);
  }
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name, ...common, description: `The br binary of blastradius for ${key}`, os: [os], cpu: [cpu], files: ["bin"], preferUnplugged: true }, null, 2) + "\n",
  );
  writeFileSync(join(dir, "README.md"), `The \`br\` binary of [blastradius](https://github.com/jondot/blastradius) for ${key}. Install \`blastradius\` instead; it picks this package for you.\n`);
}

const main = join(out, "blastradius");
mkdirSync(join(main, "bin"), { recursive: true });
cpSync(join(here, "bin", "br.js"), join(main, "bin", "br.js"));
cpSync(join(here, "platforms.json"), join(main, "platforms.json"));
cpSync(join(here, "README.md"), join(main, "README.md"));
writeFileSync(
  join(main, "package.json"),
  JSON.stringify(
    {
      name: "blastradius",
      ...common,
      description: "Find everywhere a bad package, runtime, certificate or secret lives in your org: repos, CI, images, laptops. Read-only.",
      keywords: ["security", "supply-chain", "incident-response", "sbom", "secrets", "mcp", "cli"],
      bin: { br: "bin/br.js", blastradius: "bin/br.js" },
      files: ["bin", "platforms.json"],
      engines: { node: ">=18" },
      optionalDependencies: Object.fromEntries(Object.keys(platforms).map((k) => [`blastradius-${k}`, version])),
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${Object.keys(platforms).length + 1} packages for ${version} to ${out}`);
