//! Claims: the names an org uses that only its own registries are meant to answer for, and how a public registry
//! answers for each. Dependency confusion needs two things: a name the org resolves privately, and a public package
//! with that name (usually at a higher version, often with an install script). This module reads the files that hold
//! those names (`collect_tree`) and classifies each name against what the public registry showed (`classify`).
//! Nothing here touches the network: the lookups are passed in.
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::collect::public::{github_org_of, Eco, Lookup, Public, ScopeLookup};
use crate::query::version;

// ---- where a name was seen ---------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seen {
    pub repo: String,
    pub file: String,
}

impl Seen {
    pub fn show(&self) -> String {
        format!("{}: {}", self.repo, self.file)
    }
}

/// Why a name is on the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// a package the org builds (its manifest names it)
    Own,
    /// a lockfile or manifest resolves it from a private registry
    Private,
    /// a command a package installs (`bin`)
    Bin,
    /// named inside a shipped source map
    SourceMap,
    /// a requirement listed beside a private extra index
    ExtraIndex,
    /// a dependency a manifest declares, in a checkout that sets a private registry and has no lockfile to say where it resolves
    Declared,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::Own => "own package",
            Kind::Private => "resolved from a private registry",
            Kind::Bin => "command name (bin)",
            Kind::SourceMap => "named in a shipped source map",
            Kind::ExtraIndex => "requirement beside a private extra index",
            Kind::Declared => "dependency in a checkout with a private registry setting and no lockfile",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// the only index (`--index-url`, a primary source): the public registry is not asked
    Only,
    /// searched together with the public one (`--extra-index-url`, a supplemental source): the highest version wins
    Extra,
    /// used only for the packages that name it
    Explicit,
}

#[derive(Debug, Clone, Default)]
pub struct Claim {
    pub kinds: BTreeSet<Kind>,
    /// versions the org itself uses or publishes
    pub versions: BTreeSet<String>,
    pub seen: BTreeSet<Seen>,
    /// repos where the name appears, with how that repo pins it ("" = not pinned)
    pub repos: BTreeSet<String>,
    pub pin: BTreeMap<String, String>,
    /// private / unpublished by its own manifest, and nothing in the org depends on it
    pub unpublished: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ScopeUse {
    pub seen: BTreeSet<Seen>,
    /// private registries a repo maps this scope to
    pub mapped: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct IndexRef {
    pub what: &'static str,
    pub url: String,
    pub seen: Seen,
}

#[derive(Debug, Default)]
pub struct Collected {
    pub claims: BTreeMap<(Eco, String), Claim>,
    pub scopes: BTreeMap<String, ScopeUse>,
    /// command name -> where a package installs it
    pub bin_cmds: BTreeMap<String, BTreeSet<Seen>>,
    pub indexes: Vec<IndexRef>,
    pub dep_names: BTreeSet<(Eco, String)>,
    /// where a manifest declares each dependency
    pub dep_seen: BTreeMap<(Eco, String), BTreeSet<Seen>>,
    /// (repo, ecosystem, directory) of every lockfile read: the manifests under it resolve exactly
    locked: BTreeSet<(String, Eco, String)>,
    /// (scope or "" for the default registry) per repo -> private registry URL
    npm_pins: BTreeMap<(String, String), String>,
    py_modes: BTreeMap<String, Vec<(Mode, String)>>,
    go_requires: Vec<(String, String, Seen)>,
    /// every require line of every go.mod, for GOPRIVATE (which is resolved once all files are read)
    go_requires_all: Vec<(String, String, Seen)>,
    /// (repo, file) of requirements files whose lines carry hashes: the hash binds each name to one artifact, so they resolve exactly
    hashed_reqs: BTreeSet<(String, String)>,
    /// dependencies that are not looked up in a registry at all (a path or git dependency): (repo, ecosystem, name)
    local_deps: BTreeSet<(String, Eco, String)>,
    /// repo -> the private registry that replaces crates.io (`[source.crates-io] replace-with`)
    cargo_mirror: BTreeMap<String, String>,
    /// repo -> the GOPRIVATE patterns a file of the tree sets
    go_private: BTreeMap<String, Vec<String>>,
    /// (repo, directory) of every go.sum: it records the hash of each module version
    go_sums: BTreeSet<(String, String)>,
    /// what could not be read: (scope, reason)
    pub gaps: Vec<(String, String)>,
    pub trees: usize,
    /// how many of `trees` are CI artifacts (a tree labelled "org/repo (artifact NAME)")
    pub artifact_trees: usize,
    /// manifest dependencies no private registry setting covers: treated as public and not asked about
    pub treated_public: usize,
    pub files_read: usize,
    pub maps_read: usize,
    pub go_public_skipped: usize,
    pub unreferenced_private: usize,
}

impl Collected {
    fn claim(&mut self, eco: Eco, name: &str, kind: Kind, seen: &Seen) -> &mut Claim {
        let c = self.claims.entry((eco, name.to_string())).or_default();
        c.kinds.insert(kind);
        c.seen.insert(seen.clone());
        c.repos.insert(seen.repo.clone());
        c
    }
    fn scope_seen(&mut self, scope: &str, seen: &Seen) -> &mut ScopeUse {
        let s = self.scopes.entry(scope.to_string()).or_default();
        s.seen.insert(seen.clone());
        s
    }
}

pub trait Tree {
    fn label(&self) -> String;
    fn paths(&self) -> Vec<String>;
    /// Ok(None): not there. Err: could not be read (a gap).
    fn read(&self, path: &str) -> Result<Option<String>, String>;
}

// ---- which files matter ------------------------------------------------------------------------------------------
fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn skipped(p: &str) -> bool {
    p.split('/').any(|d| matches!(d, "node_modules" | ".git" | "target" | "site-packages" | "__pycache__" | ".venv" | "venv"))
}

/// Files this module reads, most telling first (configs, manifests, lockfiles, then source maps).
pub fn priority(p: &str) -> Option<u8> {
    if skipped(p) {
        return None;
    }
    let b = base(p);
    Some(match b {
        ".npmrc" | ".yarnrc" | ".yarnrc.yml" | "pip.conf" | "pip.ini" => 0,
        "config.toml" | "config" if p.contains(".cargo/") => 0,
        "package.json" | "pyproject.toml" | "setup.py" | "setup.cfg" | "Cargo.toml" | "go.mod" => 1,
        "package-lock.json" | "npm-shrinkwrap.json" | "yarn.lock" | "pnpm-lock.yaml" | "poetry.lock" | "uv.lock" | "Cargo.lock" => 2,
        "go.sum" => 2,
        _ if crate::parse::lock::is_requirements(p) => 1,
        _ if is_go_env_file(p) => 0,
        _ if b.ends_with(".map") && !b.ends_with(".d.ts.map") => 3,
        _ => return None,
    })
}

const MAX_FILES_PER_TREE: usize = 400;
const MAX_MAPS_PER_TREE: usize = 60;
const MAX_FILE_BYTES: usize = 40 * 1024 * 1024;

pub fn collect_tree(c: &mut Collected, t: &dyn Tree) {
    let repo = t.label();
    c.trees += 1;
    if repo.contains(" (artifact") {
        c.artifact_trees += 1;
    }
    let mut want: Vec<(u8, String)> = t.paths().into_iter().filter_map(|p| priority(&p).map(|k| (k, p))).collect();
    want.sort();
    let (mut n, mut maps, mut cut) = (0usize, 0usize, false);
    for (k, p) in want {
        if k == 3 {
            if maps >= MAX_MAPS_PER_TREE {
                cut = true;
                continue;
            }
            maps += 1;
        } else if n >= MAX_FILES_PER_TREE {
            cut = true;
            continue;
        }
        n += 1;
        let text = match t.read(&p) {
            Ok(Some(x)) => x,
            Ok(None) => continue,
            Err(e) => {
                c.gaps.push((format!("{repo}: {p}"), e));
                continue;
            }
        };
        if text.len() > MAX_FILE_BYTES {
            c.gaps.push((format!("{repo}: {p}"), "larger than 40 MB, not read".into()));
            continue;
        }
        c.files_read += 1;
        let seen = Seen { repo: repo.clone(), file: p.clone() };
        on_file(c, &seen, &text);
        // go.mod is a manifest: a module with no requirements is an ordinary module, not a lockfile that read empty
        if crate::parse::lock::is_lockfile(&p) && base(&p) != "go.mod" {
            lock_fault(c, t, &repo, &p, &text);
        }
    }
    // a lockfile format br has no parser for is found and not read: said, as every reader says it
    for p in t.paths().into_iter().filter(|p| !skipped(p) && crate::parse::lock::is_unsupported_lock(p)) {
        let (_, why) = crate::parse::lock::no_packages_gap(&p, &crate::parse::lock::NoPackages::Unsupported);
        c.gaps.push((format!("{repo}: {p}"), why));
    }
    if cut {
        c.gaps.push((repo.clone(), format!("more than {MAX_FILES_PER_TREE} manifests and lockfiles or {MAX_MAPS_PER_TREE} source maps: the rest were not read")));
    }
}

/// The one lockfile-read class (`parse::lock::no_packages_gap`): a lockfile that parses to no package, or does not parse, is a gap.
fn lock_fault(c: &mut Collected, t: &dyn Tree, repo: &str, p: &str, text: &str) {
    use crate::parse::lock::{no_packages_gap, packages, parse_with, NoPackages};
    let dir = p.rsplit_once('/').map(|x| x.0).unwrap_or("");
    let scope = format!("{repo}: {p}");
    let why = match parse_with(p, text, &mut |rel: &str| {
        let mut parts: Vec<&str> = if rel.starts_with('/') { vec![] } else { dir.split('/').filter(|x| !x.is_empty()).collect() };
        for seg in rel.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                x => parts.push(x),
            }
        }
        t.read(&parts.join("/")).ok().flatten()
    }) {
        None => NoPackages::Unparsed,
        Some(l) if packages(&l, None).is_empty() => NoPackages::Empty,
        Some(_) => return,
    };
    // a parse failure the file's own reader already named is not said twice
    if !c.gaps.iter().any(|g| g.0 == scope) {
        c.gaps.push((scope, no_packages_gap(p, &why).1));
    }
}

pub fn on_file(c: &mut Collected, seen: &Seen, text: &str) {
    let p = seen.file.as_str();
    let b = base(p);
    let locks = match b {
        "package-lock.json" | "npm-shrinkwrap.json" | "yarn.lock" | "pnpm-lock.yaml" => Some(Eco::Npm),
        "poetry.lock" | "uv.lock" => Some(Eco::Pypi),
        "Cargo.lock" => Some(Eco::Cargo),
        _ => None,
    };
    if let Some(e) = locks {
        c.locked.insert((seen.repo.clone(), e, dir_of(p).to_string()));
    }
    if b == "go.sum" {
        c.go_sums.insert((seen.repo.clone(), dir_of(p).to_string()));
    }
    match b {
        "package.json" => on_package_json(c, seen, text),
        ".npmrc" => on_npmrc(c, seen, text),
        ".yarnrc.yml" => on_yarnrc_yml(c, seen, text),
        ".yarnrc" => on_yarnrc(c, seen, text),
        "pip.conf" | "pip.ini" => on_pip_conf(c, seen, text),
        "pyproject.toml" => on_pyproject(c, seen, text),
        "setup.py" => on_setup_py(c, seen, text),
        "setup.cfg" => on_setup_cfg(c, seen, text),
        "Cargo.toml" => on_cargo_toml(c, seen, text),
        "config.toml" | "config" if p.contains(".cargo/") => on_cargo_config(c, seen, text),
        "go.mod" => on_go_mod(c, seen, text),
        "package-lock.json" | "npm-shrinkwrap.json" => on_package_lock(c, seen, text),
        "yarn.lock" => on_yarn_lock(c, seen, text),
        "pnpm-lock.yaml" => on_pnpm_lock(c, seen, text),
        "poetry.lock" => on_poetry_lock(c, seen, text),
        "uv.lock" => on_uv_lock(c, seen, text),
        "Cargo.lock" => on_cargo_lock(c, seen, text),
        _ if crate::parse::lock::is_requirements(p) => on_requirements(c, seen, text),
        _ if is_go_env_file(p) => on_go_env(c, seen, text),
        _ if b.ends_with(".map") => on_source_map(c, seen, text),
        _ => {}
    }
}

// ---- helpers -----------------------------------------------------------------------------------------------------
pub fn host_of(url: &str) -> String {
    let u = url.trim().trim_matches(|c| c == '"' || c == '\'');
    let u = u.split_once("://").map(|x| x.1).unwrap_or(u);
    let u = u.trim_start_matches("//");
    let u = u.rsplit_once('@').map(|x| x.1).unwrap_or(u);
    u.split(['/', ':', '?', '#']).next().unwrap_or("").to_lowercase()
}

const NPM_PUBLIC: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com", "github.com", "codeload.github.com", "npm.pkg.github.com"];
const PY_PUBLIC: &[&str] = &["pypi.org", "files.pythonhosted.org", "test.pypi.org", "pypi.python.org"];
const CARGO_PUBLIC: &[&str] = &["crates.io", "index.crates.io", "static.crates.io", "github.com"];
const GO_PUBLIC: &[&str] = &["github.com", "gitlab.com", "bitbucket.org", "gopkg.in", "golang.org", "sr.ht", "git.sr.ht", "codeberg.org", "go.googlesource.com", "google.golang.org"];

fn private(url: &str, public: &[&str]) -> bool {
    let h = host_of(url);
    !h.is_empty() && !public.contains(&h.as_str())
}

fn is_http(url: &str) -> bool {
    let u = url.trim();
    u.starts_with("http://") || u.starts_with("https://") || u.starts_with("//")
}

fn pep503(n: &str) -> String {
    let mut o = String::new();
    let mut dash = false;
    for ch in n.to_lowercase().chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !dash {
                o.push('-');
            }
            dash = true;
        } else {
            o.push(ch);
            dash = false;
        }
    }
    o
}

fn scope_of_name(n: &str) -> Option<&str> {
    n.strip_prefix('@').and_then(|r| r.split('/').next()).filter(|s| !s.is_empty() && n.contains('/'))
}

/// An npm package name taken from the tail of a `node_modules/` path: `@scope/name` or `name`.
fn name_after_node_modules(p: &str) -> Option<String> {
    let i = p.rfind("node_modules/")?;
    let rest = &p[i + "node_modules/".len()..];
    let mut it = rest.split('/');
    let first = it.next()?;
    if first.is_empty() || first.starts_with('.') {
        return None;
    }
    let n = if first.starts_with('@') {
        let second = it.next()?;
        if second.is_empty() {
            return None;
        }
        format!("{first}/{second}")
    } else {
        first.to_string()
    };
    valid_npm_name(&n).then_some(n)
}

fn valid_npm_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 214
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '/' | '~'))
        && n.matches('/').count() <= 1
        && (n.starts_with('@') == n.contains('/'))
}

fn add_dep(c: &mut Collected, seen: &Seen, eco: Eco, name: &str) {
    let key = (eco, if eco == Eco::Pypi { pep503(name) } else { name.to_string() });
    c.dep_names.insert(key.clone());
    c.dep_seen.entry(key).or_default().insert(seen.clone());
}

fn dir_of(p: &str) -> &str {
    p.rsplit_once('/').map(|x| x.0).unwrap_or("")
}

fn norm(eco: Eco, name: &str) -> String {
    if eco == Eco::Pypi {
        pep503(name)
    } else {
        name.to_string()
    }
}

// ---- npm ---------------------------------------------------------------------------------------------------------
fn on_package_json(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(j) = serde_json::from_str::<Value>(text) else {
        c.gaps.push((seen.show(), "not valid JSON, so its package name and commands are unknown".into()));
        return;
    };
    for k in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
        for n in j[k].as_object().into_iter().flatten().map(|x| x.0) {
            add_dep(c, seen, Eco::Npm, n);
        }
    }
    if let Some(r) = j["publishConfig"]["registry"].as_str().filter(|r| private(r, NPM_PUBLIC)) {
        c.indexes.push(IndexRef { what: "npm publishConfig registry", url: r.to_string(), seen: seen.clone() });
    }
    let Some(name) = j["name"].as_str().filter(|n| valid_npm_name(n)) else { return };
    let unpublished = j["private"].as_bool() == Some(true);
    let ver = j["version"].as_str().map(str::to_string);
    let cl = c.claim(Eco::Npm, name, Kind::Own, seen);
    cl.unpublished |= unpublished;
    if let Some(v) = ver {
        cl.versions.insert(v);
    }
    if let Some(s) = scope_of_name(name) {
        let s = s.to_string();
        c.scope_seen(&s, seen);
    }
    let cmds: Vec<String> = match &j["bin"] {
        Value::String(_) => vec![name.rsplit('/').next().unwrap_or(name).to_string()],
        Value::Object(m) => m.keys().cloned().collect(),
        _ => vec![],
    };
    for cmd in cmds {
        c.bin_cmds.entry(cmd.clone()).or_default().insert(seen.clone());
        if cmd != name && valid_npm_name(&cmd) {
            let cl = c.claim(Eco::Npm, &cmd, Kind::Bin, seen);
            cl.unpublished = false;
        } else if cmd == name {
            c.claim(Eco::Npm, name, Kind::Bin, seen);
        }
    }
}

fn pin_scope(c: &mut Collected, seen: &Seen, scope: &str, url: &str, what: &'static str) {
    if !private(url, NPM_PUBLIC) {
        return;
    }
    c.npm_pins.insert((seen.repo.clone(), scope.to_string()), url.trim().to_string());
    c.indexes.push(IndexRef { what, url: url.trim().to_string(), seen: seen.clone() });
    if !scope.is_empty() {
        c.scope_seen(scope, seen).mapped.insert(url.trim().to_string());
    }
}

fn on_npmrc(c: &mut Collected, seen: &Seen, text: &str) {
    for l in text.lines() {
        let l = l.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim().trim_matches('"'));
        if let Some(s) = k.strip_prefix('@').and_then(|x| x.strip_suffix(":registry")) {
            pin_scope(c, seen, s, v, "npm scope registry");
        } else if k == "registry" {
            pin_scope(c, seen, "", v, "npm default registry");
        }
    }
}

fn on_yarnrc_yml(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(y) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        c.gaps.push((seen.show(), "not valid YAML, so its scope registries are unknown".into()));
        return;
    };
    if let Some(s) = y["npmRegistryServer"].as_str() {
        pin_scope(c, seen, "", s, "yarn default registry");
    }
    if let Some(m) = y["npmScopes"].as_mapping() {
        for (k, v) in m {
            if let (Some(k), Some(u)) = (k.as_str(), v["npmRegistryServer"].as_str()) {
                pin_scope(c, seen, k.trim_start_matches('@'), u, "yarn scope registry");
            }
        }
    }
}

fn on_yarnrc(c: &mut Collected, seen: &Seen, text: &str) {
    for l in text.lines() {
        let l = l.trim();
        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.len() == 2 {
            let k = parts[0].trim_matches('"');
            let v = parts[1].trim_matches('"');
            if let Some(s) = k.strip_prefix('@').and_then(|x| x.strip_suffix(":registry")) {
                pin_scope(c, seen, s, v, "yarn scope registry");
            } else if k == "registry" {
                pin_scope(c, seen, "", v, "yarn default registry");
            }
        }
    }
}

fn private_npm_pkg(c: &mut Collected, seen: &Seen, name: &str, version: Option<&str>, url: &str) {
    if !valid_npm_name(name) || !is_http(url) || !private(url, NPM_PUBLIC) {
        return;
    }
    let cl = c.claim(Eco::Npm, name, Kind::Private, seen);
    if let Some(v) = version {
        cl.versions.insert(v.to_string());
    }
    if let Some(s) = scope_of_name(name) {
        let s = s.to_string();
        c.scope_seen(&s, seen);
    }
}

fn on_package_lock(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(j) = serde_json::from_str::<Value>(text) else {
        c.gaps.push((seen.show(), "not valid JSON, so the registries it resolved from are unknown".into()));
        return;
    };
    if let Some(m) = j["packages"].as_object() {
        for (k, d) in m {
            if let (Some(n), Some(u)) = (name_after_node_modules(k).or_else(|| d["name"].as_str().map(str::to_string)), d["resolved"].as_str()) {
                private_npm_pkg(c, seen, &n, d["version"].as_str(), u);
            }
        }
    }
    fn walk(c: &mut Collected, seen: &Seen, m: &serde_json::Map<String, Value>) {
        for (n, d) in m {
            if let Some(u) = d["resolved"].as_str() {
                private_npm_pkg(c, seen, n, d["version"].as_str(), u);
            }
            if let Some(sub) = d["dependencies"].as_object() {
                walk(c, seen, sub);
            }
        }
    }
    if j["packages"].is_null() {
        if let Some(m) = j["dependencies"].as_object() {
            walk(c, seen, m);
        }
    }
}

fn on_yarn_lock(c: &mut Collected, seen: &Seen, text: &str) {
    let mut cur: Option<(String, Option<String>)> = None;
    let flush = |c: &mut Collected, cur: &mut Option<(String, Option<String>)>, ver: &Option<String>, res: &Option<String>| {
        if let (Some((n, _)), Some(r)) = (cur.take(), res) {
            private_npm_pkg(c, seen, &n, ver.as_deref(), r.split('#').next().unwrap_or(r));
        }
    };
    let (mut ver, mut res): (Option<String>, Option<String>) = (None, None);
    for l in text.lines() {
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if !l.starts_with(' ') && l.ends_with(':') {
            flush(c, &mut cur, &ver, &res);
            ver = None;
            res = None;
            let first = l.trim_end_matches(':').split(',').next().unwrap_or("").trim().trim_matches('"');
            let name = first.rfind('@').filter(|i| *i > 0).map(|i| &first[..i]).unwrap_or(first);
            cur = Some((name.to_string(), None));
        } else if let Some(v) = l.trim().strip_prefix("version ") {
            ver = Some(v.trim().trim_matches('"').to_string());
        } else if let Some(r) = l.trim().strip_prefix("resolved ") {
            res = Some(r.trim().trim_matches('"').to_string());
        }
    }
    flush(c, &mut cur, &ver, &res);
}

fn on_pnpm_lock(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(y) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        c.gaps.push((seen.show(), "not valid YAML, so the registries it resolved from are unknown".into()));
        return;
    };
    if let Some(m) = y["packages"].as_mapping() {
        for (k, d) in m {
            let (Some(k), Some(t)) = (k.as_str(), d["resolution"]["tarball"].as_str()) else { continue };
            let k = k.trim_start_matches('/');
            let at = k[1..].find('@').map(|i| i + 1);
            let (n, v) = match at {
                Some(i) => (&k[..i], Some(k[i + 1..].split('(').next().unwrap_or(""))),
                None => (k, None),
            };
            private_npm_pkg(c, seen, n, v, t);
        }
    }
}

// ---- python ------------------------------------------------------------------------------------------------------
fn py_index(c: &mut Collected, seen: &Seen, what: &'static str, url: &str, mode: Mode) {
    if !is_http(url) || !private(url, PY_PUBLIC) {
        return;
    }
    c.indexes.push(IndexRef { what, url: url.trim().to_string(), seen: seen.clone() });
    c.py_modes.entry(seen.repo.clone()).or_default().push((mode, url.trim().to_string()));
}

fn on_pip_conf(c: &mut Collected, seen: &Seen, text: &str) {
    let mut key = String::new();
    for l in text.lines() {
        if l.trim().is_empty() || l.trim().starts_with(['#', ';']) {
            continue;
        }
        let cont = l.starts_with(' ') || l.starts_with('\t');
        let val = if cont {
            l.trim().to_string()
        } else if let Some((k, v)) = l.split_once(['=', ':']) {
            key = k.trim().replace('_', "-");
            v.trim().to_string()
        } else {
            continue;
        };
        match key.as_str() {
            "index-url" => py_index(c, seen, "pip index", &val, Mode::Only),
            "extra-index-url" => py_index(c, seen, "pip extra index", &val, Mode::Extra),
            _ => {}
        }
    }
}

fn req_name(l: &str) -> Option<String> {
    let l = l.trim();
    if l.is_empty() || l.starts_with(['#', '-', '.', '/']) || l.contains("://") && !l.contains(" @ ") {
        return None;
    }
    let end = l.find(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))).unwrap_or(l.len());
    let n = &l[..end];
    (!n.is_empty() && n.starts_with(|ch: char| ch.is_ascii_alphanumeric())).then(|| n.to_string())
}

fn on_requirements(c: &mut Collected, seen: &Seen, text: &str) {
    let mut names = vec![];
    let mut extra = false;
    for raw in text.lines() {
        let l = raw.split(" #").next().unwrap_or(raw).trim();
        let flag = |l: &str, f: &[&str]| -> Option<String> {
            for x in f {
                if let Some(r) = l.strip_prefix(x) {
                    if r.starts_with('=') || r.starts_with(char::is_whitespace) {
                        return Some(r.trim_start_matches('=').trim().to_string());
                    }
                }
            }
            None
        };
        if let Some(u) = flag(l, &["--index-url", "-i"]) {
            py_index(c, seen, "pip index", &u, Mode::Only);
        } else if let Some(u) = flag(l, &["--extra-index-url"]) {
            if is_http(&u) && private(&u, PY_PUBLIC) {
                extra = true;
            }
            py_index(c, seen, "pip extra index", &u, Mode::Extra);
        } else if let Some(n) = req_name(l) {
            names.push(n);
        }
    }
    if text.contains("--hash=") || text.contains("--hash ") {
        c.hashed_reqs.insert((seen.repo.clone(), seen.file.clone()));
    }
    for n in &names {
        add_dep(c, seen, Eco::Pypi, n);
    }
    if extra {
        for n in names {
            let n = norm(Eco::Pypi, &n);
            c.claim(Eco::Pypi, &n, Kind::ExtraIndex, seen);
        }
    }
}

fn on_pyproject(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(t) = toml::from_str::<toml::Value>(text) else {
        c.gaps.push((seen.show(), "not valid TOML, so its package name and indexes are unknown".into()));
        return;
    };
    let ver = t.get("project").and_then(|p| p.get("version")).or_else(|| t.get("tool").and_then(|x| x.get("poetry")).and_then(|p| p.get("version"))).and_then(|v| v.as_str()).map(str::to_string);
    let name = t.get("project").and_then(|p| p.get("name")).or_else(|| t.get("tool").and_then(|x| x.get("poetry")).and_then(|p| p.get("name"))).and_then(|v| v.as_str());
    if let Some(n) = name {
        let n = norm(Eco::Pypi, n);
        let cl = c.claim(Eco::Pypi, &n, Kind::Own, seen);
        if let Some(v) = ver {
            cl.versions.insert(v);
        }
    }
    if let Some(deps) = t.get("project").and_then(|p| p.get("dependencies")).and_then(|d| d.as_array()) {
        for d in deps.iter().filter_map(|d| d.as_str()).filter_map(req_name) {
            add_dep(c, seen, Eco::Pypi, &d);
        }
    }
    if let Some(d) = t.get("tool").and_then(|x| x.get("poetry")).and_then(|p| p.get("dependencies")).and_then(|d| d.as_table()) {
        for (k, v) in d {
            add_dep(c, seen, Eco::Pypi, k);
            if v.get("path").is_some() || v.get("git").is_some() || v.get("url").is_some() {
                c.local_deps.insert((seen.repo.clone(), Eco::Pypi, pep503(k)));
            }
            // a dependency that names its source resolves from there (the poetry form of a scoped npm pin)
            if let Some(src) = v.get("source").and_then(|x| x.as_str()) {
                let cl = c.claim(Eco::Pypi, &pep503(k), Kind::Private, seen);
                cl.pin.insert(seen.repo.clone(), format!("source \"{src}\" in {}", seen.file));
            }
        }
    }
    // poetry sources: priority explicit / supplemental / primary (default)
    if let Some(src) = t.get("tool").and_then(|x| x.get("poetry")).and_then(|p| p.get("source")).and_then(|s| s.as_array()) {
        for s in src {
            let Some(u) = s.get("url").and_then(|u| u.as_str()) else { continue };
            let mode = match s.get("priority").and_then(|p| p.as_str()).unwrap_or("primary") {
                "explicit" => Mode::Explicit,
                "supplemental" | "secondary" => Mode::Extra,
                _ => Mode::Only,
            };
            py_index(c, seen, "poetry source", u, mode);
        }
    }
    // uv: [[tool.uv.index]] (explicit / default) and the older index-url / extra-index-url
    let uv = t.get("tool").and_then(|x| x.get("uv"));
    if let Some(ix) = uv.and_then(|u| u.get("index")).and_then(|i| i.as_array()) {
        for s in ix {
            let Some(u) = s.get("url").and_then(|u| u.as_str()) else { continue };
            let mode = if s.get("explicit").and_then(|b| b.as_bool()) == Some(true) {
                Mode::Explicit
            } else if s.get("default").and_then(|b| b.as_bool()) == Some(true) {
                Mode::Only
            } else {
                Mode::Extra
            };
            py_index(c, seen, "uv index", u, mode);
        }
    }
    for (k, v) in uv.and_then(|u| u.get("sources")).and_then(|x| x.as_table()).into_iter().flatten() {
        if v.get("path").is_some() || v.get("git").is_some() || v.get("url").is_some() || v.get("workspace").is_some() {
            c.local_deps.insert((seen.repo.clone(), Eco::Pypi, pep503(k)));
        } else if let Some(ix) = v.get("index").and_then(|x| x.as_str()) {
            let cl = c.claim(Eco::Pypi, &pep503(k), Kind::Private, seen);
            cl.pin.insert(seen.repo.clone(), format!("uv index \"{ix}\" in {}", seen.file));
        }
    }
    if let Some(u) = uv.and_then(|u| u.get("index-url")).and_then(|u| u.as_str()) {
        py_index(c, seen, "uv index", u, Mode::Only);
    }
    for u in uv.and_then(|u| u.get("extra-index-url")).and_then(|u| u.as_array()).into_iter().flatten().filter_map(|u| u.as_str()) {
        py_index(c, seen, "uv extra index", u, Mode::Extra);
    }
}

fn on_setup_py(c: &mut Collected, seen: &Seen, text: &str) {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#"(?s)\bsetup\s*\(.*?\bname\s*=\s*['"]([A-Za-z0-9._-]+)['"]"#).unwrap());
    if let Some(m) = RE.captures(text) {
        let n = norm(Eco::Pypi, &m[1]);
        c.claim(Eco::Pypi, &n, Kind::Own, seen);
    }
}

fn on_setup_cfg(c: &mut Collected, seen: &Seen, text: &str) {
    let mut in_meta = false;
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            in_meta = t == "[metadata]";
        } else if in_meta {
            if let Some((k, v)) = t.split_once('=') {
                if k.trim() == "name" && !v.trim().is_empty() {
                    let n = norm(Eco::Pypi, v.trim());
                    c.claim(Eco::Pypi, &n, Kind::Own, seen);
                }
            }
        }
    }
}

fn on_poetry_lock(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(t) = toml::from_str::<toml::Value>(text) else {
        c.gaps.push((seen.show(), "not valid TOML, so the indexes it resolved from are unknown".into()));
        return;
    };
    for p in t.get("package").and_then(|p| p.as_array()).into_iter().flatten() {
        let (Some(n), Some(s)) = (p.get("name").and_then(|n| n.as_str()), p.get("source")) else { continue };
        if s.get("type").and_then(|t| t.as_str()) == Some("legacy") {
            if let Some(u) = s.get("url").and_then(|u| u.as_str()).filter(|u| is_http(u) && private(u, PY_PUBLIC)) {
                let _ = u;
                let n = norm(Eco::Pypi, n);
                let cl = c.claim(Eco::Pypi, &n, Kind::Private, seen);
                if let Some(v) = p.get("version").and_then(|v| v.as_str()) {
                    cl.versions.insert(v.to_string());
                }
            }
        }
    }
}

fn on_uv_lock(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(t) = toml::from_str::<toml::Value>(text) else {
        c.gaps.push((seen.show(), "not valid TOML, so the indexes it resolved from are unknown".into()));
        return;
    };
    for p in t.get("package").and_then(|p| p.as_array()).into_iter().flatten() {
        let (Some(n), Some(u)) = (p.get("name").and_then(|n| n.as_str()), p.get("source").and_then(|s| s.get("registry")).and_then(|r| r.as_str())) else { continue };
        if is_http(u) && private(u, PY_PUBLIC) {
            let n = norm(Eco::Pypi, n);
            let cl = c.claim(Eco::Pypi, &n, Kind::Private, seen);
            if let Some(v) = p.get("version").and_then(|v| v.as_str()) {
                cl.versions.insert(v.to_string());
            }
        }
    }
}

// ---- cargo -------------------------------------------------------------------------------------------------------
fn on_cargo_toml(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(t) = toml::from_str::<toml::Value>(text) else {
        c.gaps.push((seen.show(), "not valid TOML, so its crate name is unknown".into()));
        return;
    };
    if let Some(p) = t.get("package") {
        if let Some(n) = p.get("name").and_then(|n| n.as_str()) {
            let unpub = match p.get("publish") {
                Some(toml::Value::Boolean(false)) => true,
                Some(toml::Value::Array(a)) => a.is_empty(),
                _ => false,
            };
            let cl = c.claim(Eco::Cargo, n, Kind::Own, seen);
            cl.unpublished |= unpub;
            if let Some(v) = p.get("version").and_then(|v| v.as_str()) {
                cl.versions.insert(v.to_string());
            }
        }
    }
    let mut tables: Vec<&toml::Value> = vec![];
    for k in ["dependencies", "dev-dependencies", "build-dependencies"] {
        tables.extend(t.get(k));
        for tg in t.get("target").and_then(|x| x.as_table()).into_iter().flat_map(|x| x.values()) {
            tables.extend(tg.get(k));
        }
    }
    tables.extend(t.get("workspace").and_then(|w| w.get("dependencies")));
    for d in tables.iter().filter_map(|t| t.as_table()) {
        for (k, v) in d {
            let real = v.get("package").and_then(|p| p.as_str()).unwrap_or(k);
            add_dep(c, seen, Eco::Cargo, real);
            if v.get("path").is_some() || v.get("git").is_some() || v.get("workspace").is_some() {
                c.local_deps.insert((seen.repo.clone(), Eco::Cargo, real.to_string()));
            }
            if let Some(r) = v.get("registry").and_then(|r| r.as_str()) {
                let cl = c.claim(Eco::Cargo, real, Kind::Private, seen);
                cl.pin.insert(seen.repo.clone(), format!("registry = \"{r}\" in {}", seen.file));
            }
        }
    }
}

fn on_cargo_config(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(t) = toml::from_str::<toml::Value>(text) else {
        c.gaps.push((seen.show(), "not valid TOML, so its registries are unknown".into()));
        return;
    };
    for (_, r) in t.get("registries").and_then(|r| r.as_table()).into_iter().flatten() {
        if let Some(u) = r.get("index").and_then(|i| i.as_str()).filter(|u| private(u, CARGO_PUBLIC)) {
            c.indexes.push(IndexRef { what: "cargo registry", url: u.to_string(), seen: seen.clone() });
        }
    }
    // `[source.crates-io] replace-with = "x"` with x a private registry: every dependency without `registry =` resolves through it
    let src = t.get("source").and_then(|s| s.as_table());
    if let Some(to) = src.and_then(|s| s.get("crates-io")).and_then(|x| x.get("replace-with")).and_then(|x| x.as_str()) {
        if let Some(u) = src.and_then(|s| s.get(to)).and_then(|x| x.get("registry")).and_then(|x| x.as_str()).filter(|u| private(u, CARGO_PUBLIC)) {
            c.indexes.push(IndexRef { what: "cargo source replacement", url: u.to_string(), seen: seen.clone() });
            c.cargo_mirror.insert(seen.repo.clone(), u.to_string());
        }
    }
}

fn on_cargo_lock(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(t) = toml::from_str::<toml::Value>(text) else {
        c.gaps.push((seen.show(), "not valid TOML, so the registries it resolved from are unknown".into()));
        return;
    };
    for p in t.get("package").and_then(|p| p.as_array()).into_iter().flatten() {
        let (Some(n), Some(s)) = (p.get("name").and_then(|n| n.as_str()), p.get("source").and_then(|s| s.as_str())) else { continue };
        let Some(u) = s.strip_prefix("registry+").or_else(|| s.strip_prefix("sparse+")) else { continue };
        if private(u, CARGO_PUBLIC) || (u.contains("github.com") && !u.contains("rust-lang/crates.io-index")) {
            let cl = c.claim(Eco::Cargo, n, Kind::Private, seen);
            if let Some(v) = p.get("version").and_then(|v| v.as_str()) {
                cl.versions.insert(v.to_string());
            }
            cl.pin.entry(seen.repo.clone()).or_insert_with(|| format!("locked to {u}"));
        }
    }
}

// ---- go ----------------------------------------------------------------------------------------------------------
fn on_go_mod(c: &mut Collected, seen: &Seen, text: &str) {
    let m = crate::parse::golang::parse_go_mod(text);
    if m.module.is_empty() {
        return;
    }
    if GO_PUBLIC.contains(&host_of(&m.module).as_str()) {
        c.go_public_skipped += 1;
    } else {
        c.claim(Eco::Go, &m.module, Kind::Own, seen);
    }
    for r in &m.requires {
        c.go_requires.push((r.path.clone(), r.version.clone(), seen.clone()));
        c.go_requires_all.push((r.path.clone(), r.version.clone(), seen.clone()));
    }
}

/// Files that set Go's environment for a build: GOPRIVATE is read from them, nowhere else.
fn is_go_env_file(p: &str) -> bool {
    let b = base(p);
    matches!(b, "go.env" | ".envrc" | ".env" | "Makefile" | "makefile" | "GNUmakefile" | ".gitlab-ci.yml" | "config.yml") && (b != "config.yml" || p.contains(".circleci/"))
        || b.starts_with("Dockerfile")
        || b.ends_with(".dockerfile")
        || (p.contains(".github/workflows/") && (b.ends_with(".yml") || b.ends_with(".yaml")))
}

fn on_go_env(c: &mut Collected, seen: &Seen, text: &str) {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#"\bGOPRIVATE\b[ \t]*[=:][ \t]*["']?([^\s"']+)"#).unwrap());
    for m in RE.captures_iter(text) {
        let pats = c.go_private.entry(seen.repo.clone()).or_default();
        for pat in m[1].split(',').map(str::trim).filter(|x| !x.is_empty()) {
            if !pats.iter().any(|x| x == pat) {
                pats.push(pat.to_string());
            }
        }
    }
}

/// Go's rule for GOPRIVATE and GONOPROXY: a pattern is a path.Match glob applied to as many leading path elements of the module.
fn go_private_match(pattern: &str, module: &str) -> bool {
    fn glob(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => glob(&p[1..], s) || (!s.is_empty() && glob(p, &s[1..])),
            (Some(b'?'), Some(_)) => glob(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => glob(&p[1..], &s[1..]),
            _ => false,
        }
    }
    let n = pattern.split('/').count();
    let prefix: Vec<&str> = module.split('/').take(n).collect();
    prefix.len() == n && pattern.split('/').zip(prefix).all(|(pp, mm)| glob(pp.as_bytes(), mm.as_bytes()))
}

// ---- source maps -------------------------------------------------------------------------------------------------
fn on_source_map(c: &mut Collected, seen: &Seen, text: &str) {
    let Ok(j) = serde_json::from_str::<Value>(text) else { return };
    let mut sources: Vec<&Value> = j["sources"].as_array().into_iter().flatten().collect();
    // an index map holds sections, each with its own map
    for s in j["sections"].as_array().into_iter().flatten() {
        sources.extend(s["map"]["sources"].as_array().into_iter().flatten());
    }
    c.maps_read += 1;
    let mut names = BTreeSet::new();
    for s in sources.iter().filter_map(|s| s.as_str()) {
        if let Some(n) = name_after_node_modules(s) {
            names.insert(n);
        }
    }
    for n in names {
        c.claim(Eco::Npm, &n, Kind::SourceMap, seen).unpublished = false;
        if let Some(s) = scope_of_name(&n) {
            let s = s.to_string();
            c.scope_seen(&s, seen);
        }
    }
}

// ---- finishing the collection --------------------------------------------------------------------------------------
impl Collected {
    /// Resolve what needs every tree first: pins, internal Go requirements, packages nothing depends on.
    pub fn finish(&mut self) {
        // Go: a requirement on a host an own module lives on is an internal module
        let own_hosts: BTreeSet<String> = self.claims.iter().filter(|((e, _), cl)| *e == Eco::Go && cl.kinds.contains(&Kind::Own)).map(|((_, n), _)| host_of(n)).collect();
        for (path, ver, seen) in std::mem::take(&mut self.go_requires) {
            if own_hosts.contains(&host_of(&path)) {
                let cl = self.claim(Eco::Go, &path, Kind::Private, &seen);
                cl.versions.insert(ver);
            }
        }
        // dependencies declared where a private index is set and nothing records where they resolve: asked about, not skipped
        let declared: Vec<((Eco, String), Seen)> = self.dep_seen.iter().flat_map(|(k, v)| v.iter().map(move |s| (k.clone(), s.clone()))).collect();
        for ((eco, name), seen) in declared {
            let dir = dir_of(&seen.file).to_string();
            let covered = self.locked.iter().any(|(r, e, d)| *r == seen.repo && *e == eco && (d.is_empty() || *d == dir || dir.starts_with(&format!("{d}/"))));
            if covered || self.local_deps.contains(&(seen.repo.clone(), eco, name.clone())) {
                continue;
            }
            match eco {
                Eco::Npm => {
                    let scoped = scope_of_name(&name).and_then(|s| self.npm_pins.get(&(seen.repo.clone(), s.to_string())).cloned());
                    let default = self.npm_pins.get(&(seen.repo.clone(), String::new())).cloned();
                    if scoped.is_some() {
                        self.claim(eco, &name, Kind::Private, &seen);
                    } else if default.is_some() {
                        self.claim(eco, &name, Kind::Declared, &seen);
                    }
                }
                Eco::Pypi => {
                    // an index that is searched (the only one, or beside the public one); an explicit-only index serves only the names that pick it
                    let searched = self.py_modes.get(&seen.repo).is_some_and(|m| m.iter().any(|(k, _)| matches!(k, Mode::Only | Mode::Extra)));
                    let hashed = self.hashed_reqs.contains(&(seen.repo.clone(), seen.file.clone()));
                    let known = self.claims.get(&(eco, name.clone())).is_some_and(|cl| cl.kinds.iter().any(|k| matches!(k, Kind::Private | Kind::ExtraIndex)));
                    if searched && !hashed && !known && name != "python" {
                        self.claim(eco, &name, Kind::Declared, &seen);
                    }
                }
                Eco::Cargo => {
                    let known = self.claims.get(&(eco, name.clone())).is_some_and(|cl| cl.kinds.contains(&Kind::Private));
                    if self.cargo_mirror.contains_key(&seen.repo) && !known {
                        self.claim(eco, &name, Kind::Declared, &seen);
                    }
                }
                _ => {}
            }
        }
        // Go: a requirement GOPRIVATE names is fetched directly, not through the public proxy; with no go.sum to record its hash it is asked about
        for (path, ver, seen) in std::mem::take(&mut self.go_requires_all) {
            let patterns = self.go_private.get(&seen.repo).cloned().unwrap_or_default();
            let dir = dir_of(&seen.file).to_string();
            let known = self.claims.get(&(Eco::Go, path.clone())).is_some_and(|cl| cl.kinds.contains(&Kind::Private));
            if !known && patterns.iter().any(|pt| go_private_match(pt, &path)) && !self.go_sums.contains(&(seen.repo.clone(), dir)) {
                let cl = self.claim(Eco::Go, &path, Kind::Declared, &seen);
                cl.versions.insert(ver);
            }
        }
        // pins
        let keys: Vec<(Eco, String)> = self.claims.keys().cloned().collect();
        for (eco, name) in keys {
            let repos: Vec<String> = self.claims[&(eco, name.clone())].repos.iter().cloned().collect();
            for repo in repos {
                let pin = match eco {
                    Eco::Npm => {
                        let sc = scope_of_name(&name).map(str::to_string);
                        sc.and_then(|s| self.npm_pins.get(&(repo.clone(), s.clone())).map(|u| format!("@{s}:registry = {u}")))
                            .or_else(|| self.npm_pins.get(&(repo.clone(), String::new())).map(|u| format!("registry = {u} (the registry may still proxy the public one)")))
                    }
                    Eco::Pypi => {
                        let modes = self.py_modes.get(&repo);
                        match modes {
                            Some(m) if m.iter().any(|(k, _)| *k == Mode::Extra) => None,
                            Some(m) => m.iter().find(|(k, _)| matches!(k, Mode::Only | Mode::Explicit)).map(|(k, u)| format!("{} {u}", if *k == Mode::Only { "only index" } else { "explicit index" })),
                            None => None,
                        }
                    }
                    _ => None,
                };
                if let Some(p) = pin {
                    self.claims.get_mut(&(eco, name.clone())).unwrap().pin.insert(repo, p);
                }
            }
        }
        // a private, unpublished package nothing in the org depends on cannot be confused
        let drop: Vec<(Eco, String)> =
            self.claims.iter().filter(|((e, n), cl)| cl.unpublished && cl.kinds == BTreeSet::from([Kind::Own]) && !self.dep_names.contains(&(*e, n.clone()))).map(|(k, _)| k.clone()).collect();
        self.unreferenced_private = drop.len();
        for k in drop {
            self.claims.remove(&k);
        }
        // a manifest dependency that nothing above turned into a name to ask about is treated as an ordinary public dependency
        self.treated_public = self
            .dep_seen
            .iter()
            .filter(|((e, n), seen)| *e != Eco::Go && !self.claims.contains_key(&(*e, n.clone())) && seen.iter().any(|s| !self.local_deps.contains(&(s.repo.clone(), *e, n.clone()))))
            .count();
    }
}

// ---- classification ----------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Squatted,
    ScopeUnclaimed,
    Free,
    NotChecked,
    Ours,
}

impl Status {
    pub fn word(self) -> &'static str {
        match self {
            Status::Squatted => "SQUATTED",
            Status::ScopeUnclaimed => "SCOPE UNCLAIMED",
            Status::Free => "FREE",
            Status::NotChecked => "NOT CHECKED",
            Status::Ours => "OURS",
        }
    }
    pub fn exposed(self) -> bool {
        matches!(self, Status::Squatted | Status::ScopeUnclaimed | Status::Free)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Flag {
    /// the public registry has a version above the highest one the org uses
    HigherVersion { public: String, yours: String },
    /// the public package is named like, or installs, a command the org's packages install
    BinMatch { command: String },
    /// an npm scope the org uses is held by someone else
    ScopeHeld { by: Vec<String> },
}

impl Flag {
    pub fn key(&self) -> &'static str {
        match self {
            Flag::HigherVersion { .. } => "higher_version",
            Flag::BinMatch { .. } => "bin_match",
            Flag::ScopeHeld { .. } => "scope_held",
        }
    }
    pub fn text(&self) -> String {
        match self {
            Flag::HigherVersion { public, yours } => format!("public version {public} is above the highest you use ({yours})"),
            Flag::BinMatch { command } => format!("public package matches your command name \"{command}\" (bin harvesting)"),
            Flag::ScopeHeld { by } if by.is_empty() => "public packages sit under this scope and none is shown to be yours; the registry does not show who holds it".to_string(),
            Flag::ScopeHeld { by } => format!("scope held by someone else ({})", by.join(", ")),
        }
    }
}

/// How strong the proof behind an OURS is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// the registry itself says so (a verified owner account or team)
    Verified,
    /// the publisher typed it (a repository URL in the package's own metadata)
    Declared,
}

impl Strength {
    pub fn key(self) -> &'static str {
        match self {
            Strength::Verified => "verified_by_registry",
            Strength::Declared => "declared_by_publisher",
        }
    }
    pub fn words(self) -> &'static str {
        match self {
            Strength::Verified => "verified by the registry",
            Strength::Declared => "declared by the publisher",
        }
    }
}

/// What br knows about the npm scope a name lives under.
#[derive(Debug, Clone, PartialEq)]
pub enum ScopeFact {
    /// public packages sit under it and none is shown to be yours: its holders (empty: owner not shown)
    Held(Vec<String>),
    /// no public package is under it
    Unheld,
    /// shown to be yours
    Ours,
    /// the registry could not say
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Row {
    pub eco: Eco,
    pub name: String,
    pub is_scope: bool,
    pub kinds: Vec<Kind>,
    pub status: Status,
    /// which proof made it OURS; or "owner not shown"
    pub proof: Option<String>,
    pub public_max: Option<String>,
    pub published: Option<String>,
    /// when the name was first claimed on the public registry: the earliest publish time of any version
    pub first_published: Option<String>,
    pub install_script: Option<bool>,
    pub publishers: Vec<String>,
    pub yours: Option<String>,
    pub flags: Vec<Flag>,
    pub seen: Vec<Seen>,
    pub pinned: Vec<String>,
    pub unpinned: Vec<String>,
    pub mapped: Vec<String>,
    /// why it was not checked, or a note on the answer
    pub note: Option<String>,
    /// OURS only: how strong the proof is
    pub strength: Option<Strength>,
    /// the teams (or people) that own the repos the name was seen in, from the one owner resolver; empty: unresolved
    pub owners: Vec<String>,
    /// a scope row: the public packages under it
    pub scope_pkgs: Vec<String>,
    /// a scoped name: its scope and what is known of it
    pub under_scope: Option<(String, ScopeFact)>,
    /// `--as-of`: what the date did to this name
    pub as_of_notes: Vec<String>,
}

impl Row {
    pub fn held_by(&self) -> Option<Vec<String>> {
        if let Some(Flag::ScopeHeld { by }) = self.flags.iter().find(|f| matches!(f, Flag::ScopeHeld { .. })) {
            return Some(by.clone());
        }
        match &self.under_scope {
            Some((_, ScopeFact::Held(by))) => Some(by.clone()),
            _ => None,
        }
    }
    pub fn higher_version(&self) -> bool {
        self.flags.iter().any(|f| matches!(f, Flag::HigherVersion { .. }))
    }
    pub fn bin_command(&self) -> Option<&str> {
        self.flags.iter().find_map(|f| if let Flag::BinMatch { command } = f { Some(command.as_str()) } else { None })
    }
}

/// The one rule that orders exposed names by what happens if nothing is done. Lower is more urgent:
/// 0 an install script by a stranger, 1 a stranger's higher version, 2 a scope held by someone else,
/// 3 a command name of yours, 4 any other name a stranger already has, 5 a name nobody has (free).
pub fn urgency(r: &Row) -> u8 {
    match r.status {
        Status::Squatted if r.install_script == Some(true) => 0,
        Status::Squatted if r.higher_version() => 1,
        Status::ScopeUnclaimed if r.flags.iter().any(|f| matches!(f, Flag::ScopeHeld { .. })) => 2,
        Status::Squatted if r.bin_command().is_some() => 3,
        Status::Squatted => 4,
        Status::ScopeUnclaimed | Status::Free => 5,
        Status::NotChecked => 8,
        Status::Ours => 9,
    }
}

/// The words for who published or holds something: the accounts the registry shows, or the plain fact that it shows none.
/// A claim that "a stranger" or "someone else" did it needs a publisher on the page that is not the org's; with none
/// shown, the text says the owner is not shown and goes no further.
const NOT_SHOWN: &str = "an owner the registry does not show";

/// What the exposure is, in plain words, for a person who does not read registry metadata.
pub fn plain(r: &Row) -> String {
    match r.status {
        Status::Squatted => {
            let v = r.public_max.clone().unwrap_or_else(|| "a version".into());
            let shown = !r.publishers.is_empty();
            // "a stranger published X" only when the publisher is shown (and is not the org: a publisher that is would make it OURS)
            let published = if shown { format!("a stranger published {v}") } else { format!("{v} was published by {NOT_SHOWN}") };
            if r.install_script == Some(true) {
                format!("{published}, and it runs code when installed")
            } else if r.higher_version() {
                format!("{published}, a higher version than the {} you use, so an install that takes the highest version picks theirs", r.yours.clone().unwrap_or_default())
            } else if let Some(c) = r.bin_command() {
                if shown {
                    format!("a stranger published a package that installs a command named \"{c}\", the same as one of yours")
                } else {
                    format!("a package published by {NOT_SHOWN} installs a command named \"{c}\", the same as one of yours")
                }
            } else if shown {
                format!("a stranger already owns this name on the public registry (version {v})")
            } else {
                format!("this name is already taken on the public registry (version {v}) by {NOT_SHOWN}")
            }
        }
        Status::ScopeUnclaimed => match r.held_by() {
            Some(by) if !by.is_empty() => format!("the scope {} is held by someone else ({}), so they can publish any name under it", r.name, by.join(", ")),
            Some(_) => format!("public packages sit under the scope {} and none is shown to be yours; the registry does not show who holds it, so its holder can publish any name under it", r.name),
            None => format!("no public package is under the scope {}, so anyone could claim it", r.name),
        },
        Status::Free => match &r.under_scope {
            Some((s, ScopeFact::Held(by))) if !by.is_empty() => format!("only the scope's holder ({}) could publish it, because @{s} is held by someone else", by.join(", ")),
            Some((s, ScopeFact::Held(_))) => {
                format!("only the scope's holder could publish it, because public packages sit under @{s} that are not shown to be yours (the registry does not show who holds it)")
            }
            Some((s, ScopeFact::Ours)) => format!("only the holder of @{s}, which is shown to be yours, could publish it"),
            Some((s, ScopeFact::Unheld)) => format!("no public package has this name and nobody is shown to hold @{s}, so anyone could claim the scope and publish it"),
            _ => "no public package has this name, so anyone could publish it".to_string(),
        },
        Status::NotChecked => r.note.clone().unwrap_or_else(|| "not checked".into()),
        Status::Ours => r.proof.clone().unwrap_or_default(),
    }
}

// ---- what to do, by status ----------------------------------------------------------------------------------------
/// The class an exposed row's steps are chosen by. One function (`remediation`) turns these into text, for claimcheck,
/// notify and evidence alike, so the three never disagree. SQUATTED names are in the first arm: a name a stranger already
/// holds cannot be claimed or covered with a placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fix {
    /// a public package already has the name
    Squatted(Eco),
    /// an npm scope with public packages under it that are not shown to be yours
    ScopeHeld,
    /// an npm name that is free, under a scope someone else holds: only the holder can publish it
    FreeUnderHeldScope,
    /// no public package has the name (npm: unscoped)
    Free(Eco),
    /// an npm scoped name that is free, under a scope nobody is shown to hold
    FreeScoped,
    /// an npm scope no public package is under
    ScopeUnheld,
}

pub fn fix_for(r: &Row) -> Option<Fix> {
    match r.status {
        Status::Squatted => Some(Fix::Squatted(r.eco)),
        Status::ScopeUnclaimed if r.is_scope => Some(if r.held_by().is_some() { Fix::ScopeHeld } else { Fix::ScopeUnheld }),
        Status::Free => Some(match (&r.under_scope, r.eco) {
            (Some((_, ScopeFact::Held(_))), _) => Fix::FreeUnderHeldScope,
            (_, Eco::Npm) if r.name.starts_with('@') => Fix::FreeScoped,
            _ => Fix::Free(r.eco),
        }),
        _ => None,
    }
}

fn pin_words(eco: Eco) -> &'static str {
    match eco {
        Eco::Npm => "pin the registry (or the scope) to yours in .npmrc, so npm never asks the public one",
        Eco::Pypi => "use your index as the only index (--index-url, not --extra-index-url; uv `explicit = true`; poetry `priority = \"explicit\"`)",
        Eco::Cargo => "set `registry = \"NAME\"` on every dependency that comes from your registry",
        Eco::Go => "set GOPRIVATE (and GONOSUMDB) for these module paths so the Go tool never asks the public proxy, and point GOPROXY at your own",
    }
}

fn cap(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

fn names_list(v: &[&Row]) -> String {
    let mut s = v.iter().take(6).map(|r| r.name.clone()).collect::<Vec<_>>().join(", ");
    if v.len() > 6 {
        s += &format!(" and {} more", v.len() - 6);
    }
    s
}

/// The hunt that answers "did anything install their version?": `br hunt npm:NAME@THEIRVERSION`.
pub fn hunt_command(r: &Row) -> String {
    match &r.public_max {
        Some(v) => format!("br hunt {}:{}@{}", r.eco.word(), r.name, v),
        None => format!("br hunt {}:{}", r.eco.word(), r.name),
    }
}

/// The steps for a set of exposed rows, one line per class and ecosystem, chosen by status (the one remediation function).
pub fn remediation(rows: &[&Row]) -> Vec<String> {
    let mut by: BTreeMap<Fix, Vec<&Row>> = BTreeMap::new();
    for r in rows {
        if let Some(f) = fix_for(r) {
            by.entry(f).or_default().push(r);
        }
    }
    let mut out = vec![];
    for (f, v) in &by {
        let list = names_list(v);
        out.push(match f {
            Fix::Squatted(eco) => {
                let rename = match eco {
                    Eco::Npm => "rename it (move it under a scope you own)",
                    Eco::Go => "rename the module",
                    _ => "rename the package",
                };
                let hunts = v.iter().take(4).map(|r| hunt_command(r)).collect::<Vec<_>>().join("; ");
                format!(
                    "{list}: already public, so you cannot claim it. {}; or {rename}. Report the package to {}. To see whether anything installed their version, run {hunts}{}",
                    cap(pin_words(*eco)),
                    eco.registry(),
                    if v.len() > 4 { format!(" (and the same for the other {})", v.len() - 4) } else { String::new() }
                )
            }
            Fix::ScopeHeld => {
                let who = if v.iter().any(|r| r.held_by().is_some_and(|b| !b.is_empty())) { "someone else holds the scope on npmjs.org, so you cannot claim it".to_string() } else { "public packages sit under the scope on npmjs.org and none is shown to be yours, so you cannot claim it".to_string() };
                format!("{list}: {who}. Pin the scope to your registry (`@SCOPE:registry=URL` in .npmrc, or npmScopes in .yarnrc.yml), or rename the scope: move your packages to a scope you own, or ask the holder to hand it over")
            }
            Fix::FreeUnderHeldScope => format!("{list}: only the holder of the scope could publish these names on npmjs.org, so you cannot claim them. Pin the scope to your registry in .npmrc so npm never asks the public one, and move them to a scope you own"),
            Fix::Free(eco) => {
                match eco {
                    Eco::Npm => format!("{list}: claim the name: publish a placeholder package with it on npmjs.org, or {}", pin_words(*eco)),
                    Eco::Pypi => format!("{list}: claim the name: publish a placeholder on pypi.org, or {}", pin_words(*eco)),
                    Eco::Cargo => format!("{list}: claim the name: publish a placeholder on crates.io, or {}", pin_words(*eco)),
                    Eco::Go => format!("{list}: {}", pin_words(*eco)),
                }
            }
            Fix::FreeScoped => format!("{list}: claim the scope on npmjs.org (or publish a placeholder under it), and pin the scope to your registry in .npmrc so npm never asks the public one"),
            Fix::ScopeUnheld => format!("{list}: claim the scope on npmjs.org with an org that you own, and pin it to your registry (`@SCOPE:registry=URL` in .npmrc, or npmScopes in .yarnrc.yml)"),
        });
    }
    out
}

pub struct Facts<'a> {
    /// GitHub logins the org is known by (lower case)
    pub orgs: Vec<String>,
    /// logins of verified org members (the index's people)
    pub members: BTreeSet<String>,
    pub bin_cmds: &'a BTreeSet<String>,
}

/// OURS proof from what the registry shows: a repository URL on the org's GitHub, or a publisher that is a verified member.
pub fn proof(p: &Public, f: &Facts) -> Option<String> {
    proof_strength(p, f).map(|x| x.0)
}

/// The proof, and how strong it is. The registry's own owner list beats a URL the publisher typed, so it is tried first.
pub fn proof_strength(p: &Public, f: &Facts) -> Option<(String, Strength)> {
    if p.publishers_are_github {
        for pubr in &p.publishers {
            if let Some(rest) = pubr.strip_prefix("github:") {
                let o = rest.split(':').next().unwrap_or("");
                if f.orgs.iter().any(|x| x.eq_ignore_ascii_case(o)) {
                    return Some((format!("the registry lists the org's GitHub team {pubr} as an owner"), Strength::Verified));
                }
            } else if f.members.contains(&pubr.to_lowercase()) {
                return Some((format!("the publisher {pubr} is a verified org member (GitHub login)"), Strength::Verified));
            }
        }
    }
    for u in &p.repo_urls {
        if let Some(o) = github_org_of(u) {
            if f.orgs.iter().any(|x| x.eq_ignore_ascii_case(&o)) {
                return Some((format!("the package's repository URL points at github.com/{o} (declared by the publisher, not verified by the registry)"), Strength::Declared));
            }
        }
    }
    None
}

fn max_of(eco: Eco, vs: &BTreeSet<String>) -> Option<String> {
    let e = eco.word();
    let mut best: Option<&String> = None;
    for v in vs {
        best = match best {
            None => Some(v),
            Some(b) => match version::cmp(e, v, b) {
                Some(Ordering::Greater) => Some(v),
                _ => Some(b),
            },
        };
    }
    best.cloned()
}

pub fn classify(eco: Eco, name: &str, cl: &Claim, look: &Lookup, f: &Facts) -> Row {
    let mut row = Row {
        eco,
        name: name.to_string(),
        is_scope: false,
        kinds: cl.kinds.iter().copied().collect(),
        status: Status::NotChecked,
        proof: None,
        public_max: None,
        published: None,
        first_published: None,
        install_script: None,
        publishers: vec![],
        yours: max_of(eco, &cl.versions),
        flags: vec![],
        seen: cl.seen.iter().cloned().collect(),
        pinned: cl.pin.iter().map(|(r, h)| format!("{r}: {h}")).collect(),
        unpinned: cl.repos.iter().filter(|r| !cl.pin.contains_key(*r)).cloned().collect(),
        mapped: vec![],
        note: None,
        strength: None,
        owners: vec![],
        scope_pkgs: vec![],
        under_scope: None,
        as_of_notes: vec![],
    };
    match look {
        Lookup::Unknown(why) => {
            row.note = Some(why.clone());
        }
        Lookup::Free => row.status = Status::Free,
        Lookup::Found(p) => {
            let mx = p.max(eco);
            row.public_max = mx.map(|m| m.v.clone());
            row.published = mx.and_then(|m| m.time.clone());
            row.first_published = p.first_published();
            row.install_script = mx.and_then(|m| m.install_script);
            row.publishers = p.publishers.clone();
            if let Some((t, st)) = proof_strength(p, f) {
                row.proof = Some(t);
                row.strength = Some(st);
            }
            row.status = if row.proof.is_some() { Status::Ours } else { Status::Squatted };
            if row.status == Status::Squatted && p.publishers.is_empty() {
                row.note = Some("owner not shown".into());
            }
            if let (Some(pm), Some(y)) = (&row.public_max, &row.yours) {
                if version::cmp(eco.word(), pm, y) == Some(Ordering::Greater) {
                    row.flags.push(Flag::HigherVersion { public: pm.clone(), yours: y.clone() });
                }
            }
            // bin harvesting: the public package is named like a command of ours, or installs one
            let mut cmds: BTreeSet<String> = BTreeSet::new();
            if eco == Eco::Npm {
                if f.bin_cmds.contains(name) && cl.kinds.contains(&Kind::Bin) {
                    cmds.insert(name.to_string());
                }
                for b in &p.bins {
                    if f.bin_cmds.contains(b) {
                        cmds.insert(b.clone());
                    }
                }
            }
            for command in cmds {
                row.flags.push(Flag::BinMatch { command });
            }
        }
    }
    row
}

pub fn classify_scope(scope: &str, su: &ScopeUse, look: &ScopeLookup, f: &Facts) -> Row {
    let mut row = Row {
        eco: Eco::Npm,
        name: format!("@{scope}"),
        is_scope: true,
        kinds: vec![],
        status: Status::NotChecked,
        proof: None,
        public_max: None,
        published: None,
        first_published: None,
        install_script: None,
        publishers: vec![],
        yours: None,
        flags: vec![],
        seen: su.seen.iter().cloned().collect(),
        pinned: vec![],
        unpinned: vec![],
        mapped: su.mapped.iter().cloned().collect(),
        note: None,
        strength: None,
        owners: vec![],
        scope_pkgs: vec![],
        under_scope: None,
        as_of_notes: vec![],
    };
    match look {
        ScopeLookup::Unknown(why) => row.note = Some(why.clone()),
        ScopeLookup::Empty => {
            row.status = Status::ScopeUnclaimed;
            row.note = Some("no public package is under this scope; npm does not show whether the scope itself is registered".into());
        }
        ScopeLookup::Packages(ps) => {
            let theirs = ps.iter().find(|p| p.repo_urls.iter().any(|u| github_org_of(u).map(|o| f.orgs.iter().any(|x| x.eq_ignore_ascii_case(&o))).unwrap_or(false)));
            if let Some(p) = theirs {
                row.status = Status::Ours;
                row.strength = Some(Strength::Declared);
                row.proof = Some(format!("public package {} declares a repository under the org's GitHub (declared by the publisher, not verified by the registry)", p.name));
            } else {
                row.status = Status::ScopeUnclaimed;
                let mut by: Vec<String> = ps.iter().filter_map(|p| p.publisher.clone()).collect();
                by.sort();
                by.dedup();
                row.publishers = by.clone();
                row.scope_pkgs = ps.iter().map(|p| p.name.clone()).collect();
                row.note = Some(format!(
                    "{} under it, none shown to be yours{}",
                    if ps.len() == 1 { "1 public package".to_string() } else { format!("{} public packages", ps.len()) },
                    if by.is_empty() { "; owner not shown" } else { "" }
                ));
                row.flags.push(Flag::ScopeHeld { by });
            }
        }
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::public::PubVersion;

    struct T(&'static str, Vec<(&'static str, &'static str)>);
    impl Tree for T {
        fn label(&self) -> String {
            self.0.to_string()
        }
        fn paths(&self) -> Vec<String> {
            self.1.iter().map(|x| x.0.to_string()).collect()
        }
        fn read(&self, p: &str) -> Result<Option<String>, String> {
            Ok(self.1.iter().find(|x| x.0 == p).map(|x| x.1.to_string()))
        }
    }

    fn collect(files: Vec<(&'static str, &'static str)>) -> Collected {
        let mut c = Collected::default();
        collect_tree(&mut c, &T("org/r", files));
        c.finish();
        c
    }

    fn names(c: &Collected, eco: Eco) -> Vec<String> {
        c.claims.keys().filter(|(e, _)| *e == eco).map(|(_, n)| n.clone()).collect()
    }

    #[test]
    fn npm_names_bins_scopes_and_private_unreferenced_are_told_apart() {
        let c = collect(vec![
            ("package.json", r#"{"name":"@corp/core","version":"2.3.0","bin":{"corp-cli":"bin/c.js"},"dependencies":{"internal-lib":"^1"}}"#),
            ("packages/a/package.json", r#"{"name":"internal-lib","version":"1.4.2"}"#),
            ("packages/app/package.json", r#"{"name":"the-app","private":true,"version":"0.0.1"}"#),
            ("node_modules/x/package.json", r#"{"name":"vendored"}"#),
        ]);
        assert_eq!(names(&c, Eco::Npm), vec!["@corp/core", "corp-cli", "internal-lib"]);
        assert_eq!(c.unreferenced_private, 1);
        assert!(c.scopes.contains_key("corp"));
        assert!(c.bin_cmds.contains_key("corp-cli"));
        assert!(c.claims[&(Eco::Npm, "corp-cli".into())].kinds.contains(&Kind::Bin));
        assert!(c.claims[&(Eco::Npm, "internal-lib".into())].versions.contains("1.4.2"));
    }

    #[test]
    fn npmrc_scope_pin_and_yarnrc_yml_map_scopes_to_private_registries() {
        let c = collect(vec![
            (".npmrc", "@corp:registry=https://npm.corp.example/\nregistry=https://registry.npmjs.org/\n//npm.corp.example/:_authToken=${T}\n"),
            (".yarnrc.yml", "npmScopes:\n  team:\n    npmRegistryServer: \"https://yarn.corp.example\"\n"),
            ("package.json", r#"{"name":"@corp/core","version":"1.0.0"}"#),
            ("w/package.json", r#"{"name":"@loose/x","version":"1.0.0"}"#),
        ]);
        assert!(c.scopes["corp"].mapped.contains("https://npm.corp.example/"));
        assert!(c.scopes["team"].mapped.contains("https://yarn.corp.example"));
        assert!(c.claims[&(Eco::Npm, "@corp/core".into())].pin.values().any(|p| p.contains("@corp:registry")));
        assert!(c.claims[&(Eco::Npm, "@loose/x".into())].pin.is_empty());
        // the public default registry is not a private one
        assert!(!c.indexes.iter().any(|i| i.url.contains("registry.npmjs.org")));
    }

    #[test]
    fn lockfiles_name_what_resolves_from_a_private_registry() {
        let lock = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},
            "node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
            "node_modules/@corp/ui":{"version":"3.1.0","resolved":"https://npm.corp.example/@corp/ui/-/ui-3.1.0.tgz"},
            "node_modules/a/node_modules/inner-lib":{"version":"1.0.0","resolved":"https://npm.corp.example/inner-lib/-/inner-lib-1.0.0.tgz"}}}"#;
        let yarn = "# yarn lockfile v1\n\n\"@corp/theme@^2.0.0\", \"@corp/theme@^2.1.0\":\n  version \"2.1.0\"\n  resolved \"https://npm.corp.example/@corp/theme/-/theme-2.1.0.tgz#abc\"\n\nreact@^18:\n  version \"18.3.1\"\n  resolved \"https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#d\"\n";
        let pnpm = "lockfileVersion: '9.0'\npackages:\n  '@corp/pn@1.2.3':\n    resolution: {tarball: https://npm.corp.example/pn.tgz}\n  react@18.3.1:\n    resolution: {integrity: sha512-x}\n";
        let c = collect(vec![("package-lock.json", lock), ("yarn.lock", yarn), ("pnpm-lock.yaml", pnpm)]);
        assert_eq!(names(&c, Eco::Npm), vec!["@corp/pn", "@corp/theme", "@corp/ui", "inner-lib"]);
        assert!(c.claims[&(Eco::Npm, "@corp/ui".into())].versions.contains("3.1.0"));
        assert!(c.claims[&(Eco::Npm, "@corp/theme".into())].versions.contains("2.1.0"));
        assert!(c.scopes.contains_key("corp"));
    }

    #[test]
    fn python_indexes_modes_names_and_extra_index_requirements() {
        let c = collect(vec![
            ("requirements.txt", "--index-url https://pypi.org/simple\n--extra-index-url https://py.corp.example/simple\nrequests==2.31\ncorp-utils>=1.0  # internal\n"),
            ("pyproject.toml", "[project]\nname = \"Corp_Tool\"\nversion = \"2.0.0\"\n[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://py.corp.example/simple\"\nexplicit = true\n"),
            (
                "svc/pyproject.toml",
                "[tool.poetry]\nname = \"corp.svc\"\nversion = \"0.3.0\"\n[[tool.poetry.source]]\nname = \"corp\"\nurl = \"https://py.corp.example/simple\"\npriority = \"primary\"\n",
            ),
            ("old/setup.py", "from setuptools import setup\nsetup(\n    name='corp-old',\n    version='1.0')\n"),
            ("pip.conf", "[global]\nindex-url = https://py.corp.example/simple\nextra-index-url =\n    https://mirror.corp.example/simple\n"),
        ]);
        assert_eq!(names(&c, Eco::Pypi), vec!["corp-old", "corp-svc", "corp-tool", "corp-utils", "requests"]);
        assert!(c.claims[&(Eco::Pypi, "corp-utils".into())].kinds.contains(&Kind::ExtraIndex));
        // the repo has an extra index, so its own names are not pinned
        assert!(c.claims[&(Eco::Pypi, "corp-tool".into())].pin.is_empty());
        let urls: Vec<&str> = c.indexes.iter().map(|i| i.what).collect();
        assert!(urls.contains(&"pip extra index") && urls.contains(&"uv index") && urls.contains(&"poetry source") && urls.contains(&"pip index"));
    }

    #[test]
    fn a_private_only_index_pins_the_names() {
        let c = collect(vec![("pyproject.toml", "[project]\nname = \"corp-lib\"\n[tool.uv]\nindex-url = \"https://py.corp.example/simple\"\n")]);
        assert!(c.claims[&(Eco::Pypi, "corp-lib".into())].pin.values().any(|p| p.contains("only index")));
    }

    #[test]
    fn cargo_names_registries_and_private_sources() {
        let c = collect(vec![
            ("Cargo.toml", "[package]\nname = \"corp-core\"\nversion = \"0.5.0\"\n[dependencies]\ncorp-proto = { version = \"1\", registry = \"corp\" }\nserde = \"1\"\n"),
            ("crates/x/Cargo.toml", "[package]\nname = \"corp-x\"\nversion = \"0.1.0\"\npublish = false\n"),
            (".cargo/config.toml", "[registries.corp]\nindex = \"sparse+https://cargo.corp.example/index/\"\n"),
            ("Cargo.lock", "[[package]]\nname = \"corp-proto\"\nversion = \"1.2.0\"\nsource = \"registry+https://cargo.corp.example/index\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"),
        ]);
        assert_eq!(names(&c, Eco::Cargo), vec!["corp-core", "corp-proto"]);
        assert!(c.claims[&(Eco::Cargo, "corp-proto".into())].versions.contains("1.2.0"));
        assert!(c.claims[&(Eco::Cargo, "corp-proto".into())].pin.values().any(|p| p.contains("registry")));
        assert_eq!(c.unreferenced_private, 1);
        assert!(c.indexes.iter().any(|i| i.what == "cargo registry"));
    }

    #[test]
    fn go_modules_on_private_hosts_and_their_internal_requirements() {
        let c = collect(vec![
            ("go.mod", "module git.corp.example/platform/core\n\ngo 1.22\n\nrequire (\n\tgit.corp.example/platform/lib v1.4.0\n\tgithub.com/spf13/cobra v1.8.0\n)\n"),
            ("pub/go.mod", "module github.com/acme/pub\n"),
        ]);
        assert_eq!(names(&c, Eco::Go), vec!["git.corp.example/platform/core", "git.corp.example/platform/lib"]);
        assert_eq!(c.go_public_skipped, 1);
        assert!(c.claims[&(Eco::Go, "git.corp.example/platform/lib".into())].versions.contains("v1.4.0"));
    }

    #[test]
    fn source_maps_name_the_packages_inside_the_bundle() {
        let map = r#"{"version":3,"sources":["webpack:///./node_modules/@corp/ui/dist/a.js","webpack:///./node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/x.js","../src/app.ts","webpack:///node_modules/internal-sdk/index.js"]}"#;
        let c = collect(vec![("dist/app.js.map", map), ("dist/app.d.ts.map", "{}")]);
        assert_eq!(names(&c, Eco::Npm), vec!["@corp/ui", "internal-sdk", "lodash"]);
        assert_eq!(c.maps_read, 1);
        assert!(c.claims[&(Eco::Npm, "lodash".into())].kinds.contains(&Kind::SourceMap));
    }

    #[test]
    fn unreadable_files_are_gaps() {
        let c = collect(vec![("package.json", "{nope"), ("pyproject.toml", "= =")]);
        assert_eq!(c.gaps.len(), 2, "{:?}", c.gaps);
    }

    fn facts<'a>(bins: &'a BTreeSet<String>) -> Facts<'a> {
        Facts { orgs: vec!["acme".into()], members: BTreeSet::from(["jo".to_string()]), bin_cmds: bins }
    }

    fn found(vs: &[(&str, &str, Option<bool>)], repo: Option<&str>) -> Lookup {
        Lookup::Found(Public {
            versions: vs.iter().map(|(v, t, s)| PubVersion { v: v.to_string(), time: Some(t.to_string()), install_script: *s }).collect(),
            repo_urls: repo.map(|r| vec![r.to_string()]).unwrap_or_default(),
            ..Default::default()
        })
    }

    fn cl(versions: &[&str]) -> Claim {
        let mut c = Claim::default();
        c.kinds.insert(Kind::Own);
        c.versions = versions.iter().map(|s| s.to_string()).collect();
        c
    }

    #[test]
    fn classes_free_squatted_ours_and_not_checked() {
        let bins = BTreeSet::new();
        let f = facts(&bins);
        assert_eq!(classify(Eco::Npm, "a", &cl(&["1.0.0"]), &Lookup::Free, &f).status, Status::Free);
        let r = classify(Eco::Npm, "a", &cl(&["1.4.2"]), &found(&[("9999.0.0", "2026-05-01T00:00:00Z", Some(true)), ("1.0.0", "2025-01-01T00:00:00Z", Some(false))], None), &f);
        assert_eq!(r.status, Status::Squatted);
        assert_eq!(r.public_max.as_deref(), Some("9999.0.0"));
        assert_eq!(r.install_script, Some(true));
        assert_eq!(r.note.as_deref(), Some("owner not shown"));
        assert_eq!(r.flags, vec![Flag::HigherVersion { public: "9999.0.0".into(), yours: "1.4.2".into() }]);
        let o = classify(Eco::Npm, "a", &cl(&["1.4.2"]), &found(&[("1.4.2", "2025-01-01T00:00:00Z", Some(false))], Some("git+https://github.com/Acme/a.git")), &f);
        assert_eq!(o.status, Status::Ours);
        assert!(o.proof.unwrap().contains("repository URL"));
        assert!(o.flags.is_empty());
        let n = classify(Eco::Npm, "a", &cl(&[]), &Lookup::Unknown("rate limited (HTTP 429)".into()), &f);
        assert_eq!(n.status, Status::NotChecked);
        assert!(!n.status.exposed());
        // a repository URL on someone else's GitHub is not proof
        let s = classify(Eco::Npm, "a", &cl(&["1.0.0"]), &found(&[("1.0.0", "2025-01-01T00:00:00Z", None)], Some("https://github.com/other/a")), &f);
        assert_eq!(s.status, Status::Squatted);
        // no known version of ours: the "higher" flag is not guessed
        let g = classify(Eco::Npm, "a", &cl(&[]), &found(&[("9999.0.0", "2026-05-01T00:00:00Z", None)], None), &f);
        assert!(g.flags.is_empty());
    }

    #[test]
    fn crates_owner_proofs_and_bin_matches() {
        let bins = BTreeSet::from(["corp-cli".to_string()]);
        let f = facts(&bins);
        let mut p = Public {
            versions: vec![PubVersion { v: "0.1.0".into(), time: None, install_script: None }],
            publishers: vec!["github:acme:core".into()],
            publishers_are_github: true,
            ..Default::default()
        };
        assert!(proof(&p, &f).unwrap().contains("GitHub team"));
        p.publishers = vec!["Jo".into()];
        assert!(proof(&p, &f).unwrap().contains("verified org member"));
        p.publishers = vec!["mallory".into()];
        assert!(proof(&p, &f).is_none());
        // npm maintainer names are not verified GitHub identities
        p.publishers = vec!["jo".into()];
        p.publishers_are_github = false;
        assert!(proof(&p, &f).is_none());
        // bin harvesting: a public package that installs a command of ours
        let mut claim = cl(&["1.0.0"]);
        claim.kinds.insert(Kind::Bin);
        let q = Lookup::Found(Public { versions: vec![PubVersion { v: "1.0.0".into(), time: None, install_script: Some(false) }], bins: vec!["corp-cli".into()], ..Default::default() });
        let r = classify(Eco::Npm, "other-name", &claim, &q, &f);
        assert!(r.flags.contains(&Flag::BinMatch { command: "corp-cli".into() }));
    }

    #[test]
    fn scopes_ours_held_by_someone_else_and_empty() {
        let bins = BTreeSet::new();
        let f = facts(&bins);
        let su = ScopeUse::default();
        let mine = ScopeLookup::Packages(vec![crate::collect::public::ScopePkg { name: "@s/a".into(), repo_urls: vec!["https://github.com/acme/a".into()], publisher: Some("x".into()) }]);
        assert_eq!(classify_scope("s", &su, &mine, &f).status, Status::Ours);
        let theirs = ScopeLookup::Packages(vec![crate::collect::public::ScopePkg { name: "@s/a".into(), repo_urls: vec![], publisher: Some("mallory".into()) }]);
        let r = classify_scope("s", &su, &theirs, &f);
        assert_eq!(r.status, Status::ScopeUnclaimed);
        assert_eq!(r.flags, vec![Flag::ScopeHeld { by: vec!["mallory".into()] }]);
        let e = classify_scope("s", &su, &ScopeLookup::Empty, &f);
        assert_eq!(e.status, Status::ScopeUnclaimed);
        assert!(e.flags.is_empty());
        assert_eq!(classify_scope("s", &su, &ScopeLookup::Unknown("HTTP 503".into()), &f).status, Status::NotChecked);
    }

    #[test]
    fn host_parsing() {
        assert_eq!(host_of("https://user:pw@Npm.Corp.Example:8443/x"), "npm.corp.example");
        assert_eq!(host_of("sparse+https://x/y"), "x");
        assert_eq!(host_of("//npm.corp.example/"), "npm.corp.example");
    }
}
