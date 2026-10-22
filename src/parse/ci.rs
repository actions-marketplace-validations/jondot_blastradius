//! GitHub Actions workflows, composite actions and job logs.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use super::idx::pep503;
use crate::view::{CompositeAction, Workflow};

fn walk_uses(v: &serde_yaml::Value, out: &mut Vec<String>) {
    match v {
        serde_yaml::Value::Mapping(m) => {
            for (k, x) in m {
                if k.as_str() == Some("uses") {
                    if let Some(s) = x.as_str() {
                        if !s.starts_with("./") && !s.starts_with("docker://") && !out.contains(&s.to_string()) {
                            out.push(s.to_string());
                        }
                    }
                } else {
                    walk_uses(x, out);
                }
            }
        }
        serde_yaml::Value::Sequence(s) => s.iter().for_each(|x| walk_uses(x, out)),
        _ => {}
    }
}

static SECRET_DOT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bsecrets\.([A-Za-z_][A-Za-z0-9_-]*)").unwrap());
static SECRET_BRACKET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\bsecrets\[\s*['"]([^'"]+)['"]\s*\]"#).unwrap());
static SECRET_ALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)tojson\(\s*secrets\s*\)|^\s*secrets:\s*inherit\b").unwrap());

/// Every secret a workflow text references, in first-seen order: `secrets.NAME`, `secrets['NAME']`. `toJSON(secrets)` and
/// `secrets: inherit` expose every secret, which is reported as `*`. `GITHUB_TOKEN` is left out in any case.
pub fn secret_refs(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut hits: Vec<(usize, String)> = vec![];
    for c in SECRET_DOT.captures_iter(text).chain(SECRET_BRACKET.captures_iter(text)) {
        hits.push((c.get(0).map(|m| m.start()).unwrap_or(0), c[1].to_string()));
    }
    for l in text.lines() {
        if SECRET_ALL.is_match(l) {
            let at = l.as_ptr() as usize - text.as_ptr() as usize;
            hits.push((at, "*".to_string()));
        }
    }
    hits.sort_by_key(|h| h.0);
    let mut out = vec![];
    for (_, n) in hits {
        if n.eq_ignore_ascii_case("GITHUB_TOKEN") {
            continue;
        }
        if seen.insert(n.to_lowercase()) {
            out.push(n);
        }
    }
    out
}

/// The lines (1-based) of the workflow text that read each secret `secret_refs` names, keyed by that name.
pub fn secret_ref_lines(text: &str) -> BTreeMap<String, Vec<u32>> {
    let names: BTreeMap<String, String> = secret_refs(text).into_iter().map(|n| (n.to_lowercase(), n)).collect();
    let mut out: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for (i, l) in text.lines().enumerate() {
        let n = (i + 1) as u32;
        let mut hit = |k: &str| {
            if let Some(name) = names.get(&k.to_lowercase()) {
                let v = out.entry(name.clone()).or_default();
                if !v.contains(&n) {
                    v.push(n);
                }
            }
        };
        for c in SECRET_DOT.captures_iter(l).chain(SECRET_BRACKET.captures_iter(l)) {
            hit(&c[1]);
        }
        if SECRET_ALL.is_match(l) {
            hit("*");
        }
    }
    out
}

/// A command that installs dependencies. `yarn` counts alone or as `yarn install`, never `yarn build`.
static INSTALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[\s;&|(])(?:npm\s+(?:ci|install|i|install-test|it)\b|yarn(?:\s+install\b[^\n]*)?\s*$|yarn\s+(?:--[\w-]+(?:=\S+)?\s*)+$|pnpm\s+(?:install|i)\b|bun\s+(?:install|i)\b|pipenv\s+(?:install|sync)\b|pip3?\s+install\b|python3?\s+-m\s+pip\s+install\b|poetry\s+install\b|uv\s+(?:sync|pip\s+install)\b|cargo\s+(?:build|fetch|test)\b|go\s+(?:mod\s+download|build|test)\b)").unwrap()
});

/// One row per package manager: which install commands take their versions from the lockfile. `cmds` are word sequences
/// that identify the command; the install is frozen when a command matches and either `by_default` holds (and no `off`
/// flag is present) or one of the `flags` is. pnpm installs frozen by default when `CI` is set, which GitHub Actions
/// always sets; poetry installs what poetry.lock pins; go reads go.sum for every module in the build list.
struct FrozenRow {
    manager: &'static str,
    cmds: &'static [&'static [&'static str]],
    flags: &'static [&'static str],
    off: &'static [&'static str],
    by_default: bool,
}

const FROZEN_INSTALLS: &[FrozenRow] = &[
    FrozenRow { manager: "npm", cmds: &[&["npm", "ci"], &["npm", "clean-install"], &["npm", "cit"]], flags: &[], off: &[], by_default: true },
    FrozenRow {
        manager: "yarn",
        cmds: &[&["yarn"]],
        flags: &["--frozen-lockfile", "--immutable"],
        off: &["--no-immutable", "--immutable=false", "--frozen-lockfile=false", "--no-frozen-lockfile"],
        by_default: false,
    },
    FrozenRow {
        manager: "pnpm",
        cmds: &[&["pnpm", "install"], &["pnpm", "i"], &["pnpm", "ci"]],
        flags: &["--frozen-lockfile"],
        off: &["--no-frozen-lockfile", "--frozen-lockfile=false"],
        by_default: true,
    },
    FrozenRow { manager: "bun", cmds: &[&["bun", "install"], &["bun", "i"]], flags: &["--frozen-lockfile"], off: &[], by_default: false },
    FrozenRow { manager: "poetry", cmds: &[&["poetry", "install"], &["poetry", "sync"]], flags: &[], off: &[], by_default: true },
    FrozenRow { manager: "uv", cmds: &[&["uv", "sync"]], flags: &["--locked", "--frozen"], off: &["--upgrade"], by_default: false },
    FrozenRow { manager: "pipenv", cmds: &[&["pipenv", "sync"]], flags: &[], off: &[], by_default: true },
    FrozenRow { manager: "pipenv", cmds: &[&["pipenv", "install"]], flags: &["--deploy", "--ignore-pipfile"], off: &[], by_default: false },
    FrozenRow { manager: "cargo", cmds: &[&["cargo"]], flags: &["--locked", "--frozen"], off: &[], by_default: false },
    FrozenRow { manager: "go", cmds: &[&["go", "build"], &["go", "mod", "download"]], flags: &[], off: &[], by_default: true },
];

/// The package manager whose frozen install this command is, if any.
pub fn frozen_manager(install: &str) -> Option<&'static str> {
    let toks: Vec<&str> = install.split(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '|' || c == '(' || c == ')').filter(|t| !t.is_empty()).collect();
    let has_seq = |seq: &[&str]| toks.windows(seq.len()).any(|w| w == seq);
    FROZEN_INSTALLS.iter().find_map(|r| {
        if !r.cmds.iter().any(|c| has_seq(c)) {
            return None;
        }
        let flag = r.flags.iter().any(|f| toks.contains(f));
        let off = r.off.iter().any(|f| toks.contains(f));
        ((r.by_default && !off) || (flag && !off)).then_some(r.manager)
    })
}

/// Does this install command resolve exactly what the lockfile pins? One table, `FROZEN_INSTALLS`.
pub fn frozen_install(install: &str) -> bool {
    frozen_manager(install).is_some()
}

/// What a run installed and where that comes from. A frozen install of a lockfile br parsed (`lock` holds its packages) is
/// decided by the lockfile: the log is only a cross-check, and poetry or uv print a line per package even when frozen.
/// Any other install is whatever the log says it installed; with neither, nothing is known.
pub fn run_installed(install: Option<&str>, lock: Option<Vec<String>>, log: &str) -> Option<(Vec<String>, &'static str)> {
    if let (Some(mut l), true) = (lock, install.is_some_and(frozen_install)) {
        l.sort();
        l.dedup();
        return Some((l, "lockfile"));
    }
    (!log.is_empty()).then(|| (installed(log), "runner-log"))
}

static HOSTED_LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(ubuntu|macos|windows)-[0-9a-z.]+(-arm(64)?|-xlarge|-large|-intel)*$").unwrap());

fn label_class(l: &str) -> String {
    let l = l.trim();
    if l == "self-hosted" {
        "self-hosted".into()
    } else if HOSTED_LABEL.is_match(l) {
        "github-hosted".into()
    } else {
        l.to_string()
    }
}

/// The runner labels of one job, with `${{ matrix.x }}` expanded from the job's matrix when it names a list.
fn job_labels(job: &serde_yaml::Value) -> Vec<String> {
    let Some(r) = job.get("runs-on") else { return vec![] };
    let matrix_values = |expr: &str| -> Vec<String> {
        let key = expr.trim().trim_start_matches("${{").trim_end_matches("}}").trim().strip_prefix("matrix.").map(str::to_string);
        let Some(k) = key else { return vec![expr.to_string()] };
        let vals: Vec<String> = job
            .get("strategy")
            .and_then(|s| s.get("matrix"))
            .and_then(|m| m.get(k.as_str()))
            .and_then(|s| s.as_sequence())
            .map(|s| s.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if vals.is_empty() {
            vec![expr.to_string()]
        } else {
            vals
        }
    };
    match r {
        serde_yaml::Value::String(s) if s.contains("${{") => matrix_values(s),
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Sequence(q) => {
            // a list is one runner that must carry every label
            let all: Vec<String> = q.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
            if all.iter().any(|l| l == "self-hosted") {
                vec!["self-hosted".to_string()]
            } else {
                all.first().cloned().into_iter().flat_map(|f| if f.contains("${{") { matrix_values(&f) } else { vec![f] }).collect()
            }
        }
        serde_yaml::Value::Mapping(m) => {
            let g = m.get("group").and_then(|g| g.as_str()).unwrap_or("?");
            vec![format!("runner-group:{g}")]
        }
        _ => vec![],
    }
}

/// Parse a workflow. A file that is not valid YAML is an Err with the parser's message, so the caller can record a gap.
pub fn workflow_checked(file: &str, text: &str) -> Result<Workflow, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    Ok(workflow_of(file, text, &doc))
}

pub fn workflow(file: &str, text: &str) -> Workflow {
    let doc: serde_yaml::Value = serde_yaml::from_str(text).unwrap_or(serde_yaml::Value::Null);
    workflow_of(file, text, &doc)
}

fn workflow_of(file: &str, text: &str, doc: &serde_yaml::Value) -> Workflow {
    let mut uses = vec![];
    walk_uses(doc, &mut uses);
    let mut classes: BTreeSet<String> = BTreeSet::new();
    let mut install = None;
    if let Some(jobs) = doc.get("jobs").and_then(|j| j.as_mapping()) {
        for (_, job) in jobs {
            for l in job_labels(job) {
                classes.insert(label_class(&l));
            }
            if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                for st in steps {
                    if let Some(run) = st.get("run").and_then(|r| r.as_str()) {
                        if install.is_none() {
                            if let Some(l) = run.lines().find(|l| INSTALL.is_match(l.trim())) {
                                install = Some(l.trim().to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    // every job counts: one self-hosted job among hosted ones is "mixed", not hosted
    let runs_on = match classes.len() {
        0 => None,
        1 => classes.into_iter().next(),
        _ => Some(format!("mixed: {}", classes.into_iter().collect::<Vec<_>>().join(", "))),
    };
    // paths-ignore under on.push / on.pull_request
    let mut paths_ignore = vec![];
    if let Some(m) = doc.get("on").and_then(|on| on.as_mapping()) {
        for (_, trig) in m {
            if let Some(p) = trig.get("paths-ignore").and_then(|p| p.as_sequence()) {
                for x in p.iter().filter_map(|x| x.as_str()) {
                    if !paths_ignore.contains(&x.to_string()) {
                        paths_ignore.push(x.to_string());
                    }
                }
            }
        }
    }
    // `on:` is a string, a list or a mapping; any of them can name workflow_dispatch
    let dispatch = match doc.get("on") {
        Some(serde_yaml::Value::String(s)) => s == "workflow_dispatch",
        Some(serde_yaml::Value::Sequence(q)) => q.iter().any(|x| x.as_str() == Some("workflow_dispatch")),
        Some(serde_yaml::Value::Mapping(m)) => m.keys().any(|k| k.as_str() == Some("workflow_dispatch")),
        _ => false,
    };
    Workflow { file: file.to_string(), uses, runs_on, install, secrets: secret_refs(text), paths_ignore, secret_lines: secret_ref_lines(text), dispatch }
}

pub fn composite(path: &str, text: &str) -> Option<CompositeAction> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text).ok()?;
    if doc.get("runs")?.get("using")?.as_str()? != "composite" {
        return None;
    }
    let mut uses = vec![];
    walk_uses(&doc, &mut uses);
    Some(CompositeAction { path: path.to_string(), uses })
}

static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new("\u{1b}\\[[0-9;]*[A-Za-z]").unwrap());

/// One log line without its GitHub timestamp prefix (`2025-03-14T10:22:01.1234567Z `) and ANSI colour codes.
fn clean(raw: &str) -> String {
    let s = ANSI.replace_all(raw, "");
    let s = s.trim_start_matches('\u{feff}');
    match s.split_once(' ') {
        Some((t, rest)) if t.len() > 18 && t.ends_with('Z') && t.as_bytes().get(4) == Some(&b'-') => rest.trim_end().to_string(),
        _ => s.trim_end().to_string(),
    }
}

/// A setup action or actions/cache key from `Cache saved with key: K` / `Cache saved with the key: K` /
/// `Cache restored from key: K`, in first-seen order.
pub fn cache_keys(log: &str) -> Vec<String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Cache (?:saved with|restored from) (?:the )?key: (\S+)").unwrap());
    let mut out: Vec<String> = vec![];
    for l in log.lines() {
        if let Some(c) = RE.captures(&clean(l)) {
            if !out.contains(&c[1].to_string()) {
                out.push(c[1].to_string());
            }
        }
    }
    out
}

/// An action pulled from the registry as an immutable package (GitHub-hosted runners since 2025).
#[derive(Debug, Clone, PartialEq)]
pub struct ImmutableAction {
    pub action: String,
    pub version: Option<String>,
    pub digest: Option<String>,
    pub source_sha: Option<String>,
}

/// `Download immutable action package 'actions/checkout@v4'` blocks, with the `Version:`, `Digest: sha256:...` and
/// `Source Commit SHA:` lines that follow.
pub fn immutable_downloads(log: &str) -> Vec<ImmutableAction> {
    static HEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Download immutable action package '([^']+)'").unwrap());
    let mut out: Vec<ImmutableAction> = vec![];
    for raw in log.lines() {
        let l = clean(raw);
        let t = l.trim();
        if let Some(c) = HEAD.captures(t) {
            out.push(ImmutableAction { action: c[1].to_string(), version: None, digest: None, source_sha: None });
            continue;
        }
        let Some(cur) = out.last_mut() else { continue };
        let lower = t.to_lowercase();
        if let Some(v) = t.get(..8).filter(|_| lower.starts_with("version:")).and(t.get(8..)) {
            cur.version.get_or_insert(v.trim().to_string());
        } else if lower.starts_with("digest:") {
            cur.digest.get_or_insert(t[7..].trim().to_string());
        } else if lower.starts_with("source commit sha:") {
            cur.source_sha.get_or_insert(t[18..].trim().to_string());
        }
    }
    out
}

/// Actions a job log names as downloaded: `Download action repository 'owner/repo@ref' (SHA:abc)` and the immutable form
/// (whose pin is the source commit SHA). Each is the `uses` text and the commit it resolved to.
pub fn action_downloads(log: &str) -> Vec<(String, Option<String>)> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Download action repository '([^']+)'(?: \(SHA:([0-9a-f]+)\))?").unwrap());
    let mut out: Vec<(String, Option<String>)> = vec![];
    for raw in log.lines() {
        if let Some(c) = RE.captures(&clean(raw)) {
            out.push((c[1].to_string(), c.get(2).map(|m| m.as_str().to_string())));
        }
    }
    for im in immutable_downloads(log) {
        out.push((im.action, im.source_sha));
    }
    out
}

/// Installed packages from a runner log: npm `+ name@ver`, pnpm `+ name 1.2.3`, pip `Collecting name==ver` /
/// `Successfully installed name-ver ...`, go `go: downloading mod vX`, cargo ` Downloaded name vX`. Lines carry a GitHub
/// timestamp prefix and may carry ANSI colour. npm >=7 and yarn print no per-package lines: for those the list is empty,
/// which means "not in the log", not "nothing installed" (resolve from the lockfile at the run's commit instead).
pub fn installed(log: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let mut add = |p: String| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    for raw in log.lines() {
        let line = clean(raw);
        if let Some(r) = line.strip_prefix("+ ") {
            let r = r.trim();
            if let Some((n, v)) = r.rsplit_once('@') {
                if !n.is_empty() && v.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    add(format!("npm:{n}@{v}"));
                    continue;
                }
            }
            // pnpm: `+ lodash 4.17.21`, also `+ @types/node 20.1.0 (20.2.0 is available)`
            let mut p = r.split_whitespace();
            if let (Some(n), Some(v), true) = (p.next(), p.next(), !r.contains('@') || r.starts_with('@')) {
                if v.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) && !n.is_empty() {
                    add(format!("npm:{n}@{v}"));
                }
            }
        } else if let Some(r) = line.strip_prefix("Collecting ") {
            if let Some((n, v)) = r.trim().split_once("==") {
                add(format!("pypi:{}@{}", pep503(n), v.split_whitespace().next().unwrap_or(v)));
            }
        } else if let Some(r) = line.strip_prefix("Successfully installed ") {
            for t in r.split_whitespace() {
                if let Some(ix) = t.char_indices().filter(|(_, c)| *c == '-').map(|(i, _)| i).rfind(|i| t[i + 1..].starts_with(|c: char| c.is_ascii_digit())) {
                    add(format!("pypi:{}@{}", pep503(&t[..ix]), &t[ix + 1..]));
                }
            }
        } else if let Some(r) = line.trim_start().strip_prefix("- Installing ").or_else(|| line.trim_start().strip_prefix("- Updating ")) {
            // poetry: `  - Installing requests (2.31.0)` and `  - Updating idna (3.6 -> 3.7)` (the new version is installed)
            if let Some((n, rest)) = r.split_once(" (") {
                let v = rest.trim_end_matches(')').rsplit("-> ").next().unwrap_or("").split_whitespace().next().unwrap_or("");
                if !n.contains(' ') && v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    add(format!("pypi:{}@{}", pep503(n), v));
                }
            }
        } else if let Some(r) = line.trim_start().strip_prefix("+ ").filter(|r| r.contains("==")) {
            // uv: ` + requests==2.31.0`
            if let Some((n, v)) = r.trim().split_once("==") {
                if !n.contains(' ') && !n.contains('@') {
                    add(format!("pypi:{}@{}", pep503(n), v.split_whitespace().next().unwrap_or(v)));
                }
            }
        } else if let Some(r) = line.strip_prefix("go: downloading ") {
            if let Some((m, v)) = r.trim().rsplit_once(' ') {
                add(format!("go:{m}@{v}"));
            }
        } else if let Some(r) = line.trim_start().strip_prefix("Downloaded ") {
            if let Some((n, v)) = r.trim().split_once(' ') {
                if let Some(v) = v.strip_prefix('v') {
                    add(format!("cargo:{n}@{v}"));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wf() {
        let t = "on:\n  push:\n    paths-ignore: ['docs/**']\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: yarn install --frozen-lockfile\n        env:\n          K: ${{ secrets.STRIPE_TEST_KEY }}\n";
        let w = workflow(".github/workflows/ci.yml", t);
        assert_eq!(w.uses, vec!["actions/checkout@v4"]);
        assert_eq!(w.runs_on.as_deref(), Some("github-hosted"));
        assert_eq!(w.install.as_deref(), Some("yarn install --frozen-lockfile"));
        assert_eq!(w.secrets, vec!["STRIPE_TEST_KEY"]);
        assert_eq!(w.paths_ignore, vec!["docs/**"]);
    }

    #[test]
    fn logs() {
        let l = "2026-05-11T15:14:09.0000000Z + @tanstack/react-router@1.119.2\n2026-05-11T15:14:09.0000001Z added 2 packages in 3s\n2026-05-11T15:14:10.0000000Z Successfully installed Foo_Bar-1.2.3 baz-0.1\n2026-05-11T15:14:11.0000000Z go: downloading example.com/m v1.0.0\n2026-05-11T15:14:12.0000000Z  Downloaded serde v1.0.1\n";
        assert_eq!(installed(l), vec!["npm:@tanstack/react-router@1.119.2", "pypi:foo-bar@1.2.3", "pypi:baz@0.1", "go:example.com/m@v1.0.0", "cargo:serde@1.0.1"]);
    }

    // item 9: one table of the installs that take their versions from the lockfile, one row per manager
    #[test]
    fn frozen_installs_come_from_one_table() {
        for (c, m) in [
            ("npm ci", "npm"),
            ("npm ci --ignore-scripts", "npm"),
            ("yarn install --frozen-lockfile", "yarn"),
            ("yarn install --immutable", "yarn"),
            ("pnpm install --frozen-lockfile", "pnpm"),
            ("pnpm install", "pnpm"),
            ("poetry install --no-root", "poetry"),
            ("uv sync --locked", "uv"),
            ("uv sync --frozen", "uv"),
            ("pipenv sync", "pipenv"),
            ("pipenv install --deploy", "pipenv"),
            ("cargo build --locked --release", "cargo"),
            ("go mod download", "go"),
            ("cd app && npm ci", "npm"),
        ] {
            assert_eq!(frozen_manager(c), Some(m), "{c}");
        }
        for c in [
            "npm install",
            "yarn install",
            "yarn install --no-immutable",
            "pnpm install --no-frozen-lockfile",
            "uv sync",
            "uv sync --upgrade",
            "pipenv install",
            "cargo build",
            "cargo update",
            "pip install -r requirements.txt",
            "pip install foo",
            "poetry add requests",
            "poetry update",
        ] {
            assert_eq!(frozen_manager(c), None, "{c}");
        }
    }

    // item 9: a frozen install is lockfile-resolved even when its log lists packages; any other install keeps the log
    #[test]
    fn a_frozen_install_is_decided_by_the_lockfile_and_the_log_only_cross_checks() {
        let log = "2026-05-11T15:14:08.0000001Z   - Installing certifi (2024.2.2)\n2026-05-11T15:14:08.0000002Z   - Installing idna (3.7)\n";
        let lock = || Some(vec!["pypi:idna@3.7".to_string(), "pypi:certifi@2024.2.2".to_string(), "pypi:extra@1.0".to_string()]);
        let (p, from) = run_installed(Some("poetry install --no-root"), lock(), log).unwrap();
        assert_eq!((from, p), ("lockfile", vec!["pypi:certifi@2024.2.2".to_string(), "pypi:extra@1.0".to_string(), "pypi:idna@3.7".to_string()]));
        // uv sync --frozen
        assert_eq!(run_installed(Some("uv sync --frozen"), lock(), " + idna==3.7").unwrap().1, "lockfile");
        // not frozen: the log is what ran
        let (p, from) = run_installed(Some("poetry add requests"), lock(), log).unwrap();
        assert_eq!((from, p), ("runner-log", vec!["pypi:certifi@2024.2.2".to_string(), "pypi:idna@3.7".to_string()]));
        assert_eq!(run_installed(Some("pip install -r requirements.txt"), lock(), log).unwrap().1, "runner-log");
        // frozen but the lockfile could not be read: the log
        assert_eq!(run_installed(Some("poetry install"), None, log).unwrap().1, "runner-log");
        // nothing at all
        assert!(run_installed(Some("poetry install"), None, "").is_none());
    }

    // item 9: real poetry and uv log lines (poetry 1.8 and 2.x print `  - Installing name (version)`; uv prints ` + name==version`)
    #[test]
    fn poetry_and_uv_logs_name_what_was_installed() {
        let poetry = "2026-05-11T15:14:07.0000000Z Installing dependencies from lock file\n2026-05-11T15:14:07.0000001Z \n2026-05-11T15:14:07.0000002Z Package operations: 3 installs, 1 update, 0 removals\n2026-05-11T15:14:08.0000003Z \n2026-05-11T15:14:08.0000004Z   - Installing certifi (2024.2.2)\n2026-05-11T15:14:08.0000005Z   - Installing charset-normalizer (3.3.2)\n2026-05-11T15:14:09.0000006Z   - Updating idna (3.6 -> 3.7)\n2026-05-11T15:14:09.0000007Z   - Installing \u{1b}[39;1mRequests_Toolbelt\u{1b}[39;22m (\u{1b}[39;1m1.0.0\u{1b}[39;22m)\n";
        assert_eq!(installed(poetry), vec!["pypi:certifi@2024.2.2", "pypi:charset-normalizer@3.3.2", "pypi:idna@3.7", "pypi:requests-toolbelt@1.0.0"]);
        let uv = "2026-05-11T15:14:07.0000000Z Resolved 3 packages in 2ms\n2026-05-11T15:14:07.0000001Z Installed 3 packages in 11ms\n2026-05-11T15:14:07.0000002Z  + certifi==2024.2.2\n2026-05-11T15:14:07.0000003Z  + requests==2.31.0\n2026-05-11T15:14:07.0000004Z  - urllib3==1.26.0\n2026-05-11T15:14:07.0000005Z  + urllib3==2.2.1\n";
        assert_eq!(installed(uv), vec!["pypi:certifi@2024.2.2", "pypi:requests@2.31.0", "pypi:urllib3@2.2.1"]);
    }

    #[test]
    fn frozen_defaults_in_ci() {
        assert!(frozen_install("pnpm install"));
        assert!(frozen_install("pnpm i"));
        assert!(!frozen_install("pnpm install --no-frozen-lockfile"));
        assert!(frozen_install("yarn install --immutable"));
        assert!(!frozen_install("yarn install --no-immutable"));
        assert!(frozen_install("npm ci"));
        assert!(!frozen_install("npm install"));
        assert!(frozen_install("pipenv sync"));
        assert!(frozen_install("cargo build --locked"));
    }

    #[test]
    fn install_detection_ignores_yarn_scripts() {
        let w = |run: &str| workflow("a.yml", &format!("jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {run}\n")).install;
        assert_eq!(w("yarn build"), None);
        assert_eq!(w("yarn test --watch"), None);
        assert_eq!(w("yarn"), Some("yarn".into()));
        assert_eq!(w("yarn install --frozen-lockfile"), Some("yarn install --frozen-lockfile".into()));
        assert_eq!(w("bun install"), Some("bun install".into()));
        assert_eq!(w("pipenv install --deploy"), Some("pipenv install --deploy".into()));
        assert_eq!(w("uv sync --frozen"), Some("uv sync --frozen".into()));
        assert_eq!(w("cargo fetch"), Some("cargo fetch".into()));
    }

    #[test]
    fn runner_is_judged_over_every_job() {
        let t = "jobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps: []\n  build:\n    runs-on: [self-hosted, linux, ubuntu-22.04]\n    steps: []\n";
        assert_eq!(workflow("a.yml", t).runs_on.as_deref(), Some("mixed: github-hosted, self-hosted"));
        let g = "jobs:\n  b:\n    runs-on:\n      group: large-runners\n      labels: ubuntu-latest-8-cores\n    steps: []\n";
        assert_eq!(workflow("a.yml", g).runs_on.as_deref(), Some("runner-group:large-runners"));
        let m = "jobs:\n  b:\n    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-14, windows-2022]\n    steps: []\n";
        assert_eq!(workflow("a.yml", m).runs_on.as_deref(), Some("github-hosted"));
        let u = "jobs:\n  b:\n    runs-on: ${{ inputs.runner }}\n    steps: []\n";
        assert_eq!(workflow("a.yml", u).runs_on.as_deref(), Some("${{ inputs.runner }}"), "an unresolvable expression is kept, never assumed hosted");
    }

    #[test]
    fn secrets_bracket_form_all_and_case() {
        assert_eq!(secret_refs("a: ${{ secrets['NPM_TOKEN'] }}\nb: ${{ secrets.github_token }}\nc: ${{ secrets.NPM_token }}"), vec!["NPM_TOKEN"]);
        assert_eq!(secret_refs("env:\n  ALL: ${{ toJSON(secrets) }}\n"), vec!["*"]);
        assert_eq!(secret_refs("jobs:\n  call:\n    uses: o/r/.github/workflows/x.yml@v1\n    secrets: inherit\n"), vec!["*"]);
    }

    #[test]
    fn workflow_yaml_error_is_reported_not_nulled() {
        assert!(workflow_checked("a.yml", "jobs:\n  b: [unclosed\n").is_err());
        let anchors = "jobs:\n  a: &j\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n  b: *j\n";
        let w = workflow_checked("a.yml", anchors).unwrap();
        assert_eq!(w.uses, vec!["actions/checkout@v4"]);
    }

    #[test]
    fn setup_action_cache_lines() {
        let l = "2025-03-14T10:22:01.1234567Z Cache saved with the key: node-cache-Linux-x64-npm-0a1b2c\n2025-03-14T10:22:02.0000000Z Cache restored from key: pip-Linux-3.12-abc\n2025-03-14T10:22:03.0000000Z Cache saved with key: cargo-deadbeef\n";
        assert_eq!(cache_keys(l), vec!["node-cache-Linux-x64-npm-0a1b2c", "pip-Linux-3.12-abc", "cargo-deadbeef"]);
    }

    #[test]
    fn immutable_action_download_lines() {
        let l = "2025-06-02T08:00:00.1000000Z Download action repository 'actions/setup-node@v4' (SHA:49933ea5288caeca8642d1e84afbd3f7d6820020)\n2025-06-02T08:00:00.2000000Z Download immutable action package 'actions/checkout@v4'\n2025-06-02T08:00:00.2100000Z Version: 4.2.2\n2025-06-02T08:00:00.2200000Z Digest: sha256:fa7b0c6a1b1f6f9e5e1b4a0b1b9d7c3a2e1f0d9c8b7a6958473625140f0e1d2c\n2025-06-02T08:00:00.2300000Z Source Commit SHA: 11bd71901bbe5b1630ceea73d27597364c9af683\n";
        let im = immutable_downloads(l);
        assert_eq!(im.len(), 1);
        assert_eq!(im[0].action, "actions/checkout@v4");
        assert_eq!(im[0].version.as_deref(), Some("4.2.2"));
        assert!(im[0].digest.as_deref().unwrap().starts_with("sha256:fa7b"));
        assert_eq!(im[0].source_sha.as_deref(), Some("11bd71901bbe5b1630ceea73d27597364c9af683"));
        let all = action_downloads(l);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, "actions/setup-node@v4");
        assert_eq!(all[1], ("actions/checkout@v4".to_string(), Some("11bd71901bbe5b1630ceea73d27597364c9af683".to_string())));
    }

    #[test]
    fn installed_pnpm_ansi_and_pip() {
        let l = "2025-03-14T10:22:01.1234567Z \u{1b}[32m+\u{1b}[39m lodash 4.17.21\n2025-03-14T10:22:01.1234568Z + @types/node 20.1.0\n2025-03-14T10:22:02.0000000Z Collecting requests\n2025-03-14T10:22:05.0000000Z Successfully installed requests-2.32.3 urllib3-2.2.1 charset-normalizer-3.3.2\n";
        let got = installed(l);
        assert!(got.contains(&"npm:@types/node@20.1.0".to_string()), "{got:?}");
        assert!(got.contains(&"pypi:requests@2.32.3".to_string()));
        assert!(got.contains(&"pypi:charset-normalizer@3.3.2".to_string()));
        assert!(got.contains(&"npm:lodash@4.17.21".to_string()), "{got:?}");
    }
}
