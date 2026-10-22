//! Lockfile parsers: package-lock.json / npm-shrinkwrap.json (v1, v2, v3), yarn.lock (v1 and berry), pnpm-lock.yaml (5.x to 9),
//! bun.lock, poetry.lock (1.x and 2.x), uv.lock, pdm.lock, Pipfile.lock, requirements files, Cargo.lock (v1 to v4), go.mod,
//! go.work, vendor/modules.txt and go.sum. Each gives the complete package list with the line of its entry, its dependency
//! edges, and a `via` chain from a direct dependency.
//!
//! Things a parser could not decide are never dropped quietly: they are in `Lock::gaps` (text for a Gap on the source),
//! `Lock::unpinned` (requirements with no exact version) and `Lock::members` (workspace packages that are not registry packages).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde_json::Value;

use super::idx::{join_path, json_paths, pep503};
use crate::view::LockPackage;

#[derive(Debug, Clone, Default)]
pub struct Entry {
    /// `eco:name@version`
    pub id: String,
    pub line: u32,
    /// ids of the packages this one depends on
    pub deps: Vec<String>,
    pub dev: bool,
    /// How the lockfile spells the package when that differs from the id: a requirements.txt spelling, a yarn/bun alias.
    pub as_written: Option<String>,
}

/// A requirement whose version the file does not fix (`flask>=2`, `pkg @ git+https://...`).
#[derive(Debug, Clone, PartialEq)]
pub struct Unpinned {
    pub name: String,
    pub spec: String,
    pub line: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Lock {
    pub entries: Vec<Entry>,
    /// Names the lockfile itself says are direct (package-lock root and workspaces, pnpm importers).
    pub direct_names: Option<BTreeSet<String>>,
    /// Direct dependency names marked dev by the lockfile.
    pub direct_dev: BTreeSet<String>,
    /// Exact ids the lockfile says are direct (Cargo, uv, yarn berry, bun, go.mod). When set it is authoritative, so two
    /// versions of one name (`syn 1` and `syn 2`) are told apart.
    pub direct_ids: Option<BTreeSet<String>>,
    pub direct_dev_ids: BTreeSet<String>,
    /// Every entry of this file is a direct pin (requirements.txt).
    pub all_direct: bool,
    /// Workspace packages, links and local-path replacements found in the file. They are not registry packages.
    pub members: Vec<String>,
    /// Things this file could not tell, as text for a Gap on its source.
    pub gaps: Vec<String>,
    pub unpinned: Vec<Unpinned>,
}

/// Lockfiles this parser understands, by base name. Order is precedence at one directory level: `npm-shrinkwrap.json` is read
/// instead of `package-lock.json`; `go.mod` before `go.sum`, which is only a fallback (see [`super::golang::build_list`]).
pub const LOCKFILES: &[&str] = &[
    "npm-shrinkwrap.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.mod",
    "go.work",
    "go.sum",
    "requirements.txt",
];

/// Lockfiles of ecosystems this tool does not read: (base name, what it is). Finding one is a gap, not "nothing here".
pub const UNSUPPORTED: &[(&str, &str)] = &[
    ("bun.lockb", "Bun binary lockfile (run `bun install --save-text-lockfile` to get bun.lock)"),
    ("Gemfile.lock", "Bundler (Ruby)"),
    ("composer.lock", "Composer (PHP)"),
    ("packages.lock.json", "NuGet (.NET)"),
    ("gradle.lockfile", "Gradle (JVM)"),
    ("Podfile.lock", "CocoaPods"),
    ("Package.resolved", "Swift Package Manager"),
    ("mix.lock", "Mix (Elixir)"),
    ("pubspec.lock", "pub (Dart)"),
    ("deno.lock", "Deno"),
    ("conan.lock", "Conan (C/C++)"),
    ("pnpm-workspace.yaml.lock", "pnpm"),
];

/// A lockfile this tool cannot read, named by its path; the returned text says which tool wrote it.
pub fn unsupported(path: &str) -> Option<&'static str> {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    UNSUPPORTED.iter().find(|(n, _)| *n == base).map(|(_, d)| *d)
}

/// The manifest that goes with a lockfile (its direct dependencies, with lines).
pub fn manifest_for(lockfile: &str) -> Option<&'static str> {
    let base = lockfile.rsplit(['/', '\\']).next().unwrap_or(lockfile);
    Some(match base {
        "package-lock.json" | "npm-shrinkwrap.json" | "yarn.lock" | "pnpm-lock.yaml" | "bun.lock" => "package.json",
        "poetry.lock" | "uv.lock" | "pdm.lock" => "pyproject.toml",
        "Pipfile.lock" => "Pipfile",
        "Cargo.lock" => "Cargo.toml",
        "go.sum" | "go.mod" | "modules.txt" => "go.mod",
        _ => return None,
    })
}

/// A pip requirements file by path: `requirements*.txt`, `*-requirements.txt`, `constraints*.txt`, or any `.txt` under a
/// `requirements/` directory (Django layouts: `requirements/base.txt`, `requirements/prod.txt`).
pub fn is_requirements(path: &str) -> bool {
    let mut parts: Vec<&str> = path.split(['/', '\\']).collect();
    let base = parts.pop().unwrap_or("").to_lowercase();
    let Some(stem) = base.strip_suffix(".txt") else { return false };
    if parts.iter().any(|d| matches!(*d, "node_modules" | "site-packages" | "dist-info") || d.ends_with(".dist-info") || d.ends_with(".egg-info")) {
        return false;
    }
    stem.starts_with("requirements")
        || stem.ends_with("requirements")
        || stem.starts_with("constraints")
        || stem.ends_with("constraints")
        || parts.iter().any(|d| d.eq_ignore_ascii_case("requirements"))
}

/// pip-tools input (`requirements.in`): a manifest, not a lockfile.
pub fn is_requirements_in(path: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path).to_lowercase();
    base.ends_with(".in") && (base.starts_with("requirements") || base.ends_with("requirements.in"))
}

/// Lockfile formats br names but cannot read (second list of the class: found, never read).
const UNSUPPORTED_LOCKS: &[&str] =
    &["bun.lockb", "bun.lock", "pdm.lock", "Gemfile.lock", "composer.lock", "packages.lock.json", "gradle.lockfile", "Podfile.lock", "mix.lock", "pubspec.lock", "Package.resolved", "conan.lock"];

/// A lockfile br finds by name and has no parser for.
pub fn is_unsupported_lock(path: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    UNSUPPORTED_LOCKS.contains(&base) && !LOCKFILES.contains(&base)
}

/// A gap that starts with this says br found a lockfile and read no packages from it (status counts these repos).
pub const NO_PACKAGES: &str = "no packages read";

/// Why a lockfile or manifest br found gave no packages. Every reader (repo, `--path` checkout, host scan, CI artifact) names
/// the reason through [`no_packages_gap`], so the same fault reads the same everywhere.
pub enum NoPackages<'a> {
    /// parsed, and lists no packages
    Empty,
    /// the format has no parser
    Unsupported,
    /// the file's bytes could not be read (the OS or host error)
    Unreadable(&'a str),
    /// the parser refused it (checkout, host, artifact: the file itself)
    Unparsed,
    /// the host's history for the path could not be read or parsed
    HistoryUnread,
    /// the host gives no history for the path and HEAD could not be read or parsed
    NoHistoryUnread,
    /// an export lists the file but carries no package from it
    NotInExport,
    /// the host gives no history for the path; read at HEAD, it lists no packages
    NoHistoryEmpty,
}

/// The gap (scope, reason) for a lockfile at `path` that gave no packages. The reason always starts with [`NO_PACKAGES`].
pub fn no_packages_gap(path: &str, why: &NoPackages) -> (String, String) {
    let t = match why {
        NoPackages::Empty => "the lockfile lists no packages".to_string(),
        NoPackages::Unsupported => "this lockfile format is not supported, so packages from it are not checked".to_string(),
        NoPackages::Unreadable(e) => format!("the file could not be read: {e}"),
        NoPackages::Unparsed => "the file could not be parsed, so the packages it declares were not read".to_string(),
        NoPackages::NotInExport => "the export lists this file but holds no packages from it".to_string(),
        NoPackages::HistoryUnread => "its history could not be read or parsed".to_string(),
        NoPackages::NoHistoryUnread => "the host gives no commit history for this path and the file at HEAD could not be read or parsed".to_string(),
        NoPackages::NoHistoryEmpty => "the host gives no commit history for this path, so it was read at HEAD, and it lists no packages".to_string(),
    };
    (format!("lockfile {path}"), format!("{NO_PACKAGES}: {t}"))
}

/// Whether `path` names a file [`parse`] reads: a known lockfile, a requirements file or `vendor/modules.txt`.
pub fn is_lockfile(path: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if base == "modules.txt" {
        return path.ends_with("vendor/modules.txt");
    }
    LOCKFILES.contains(&base) && base != "requirements.txt" || is_requirements(path)
}

pub fn parse(path: &str, text: &str) -> Option<Lock> {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match base {
        "package-lock.json" | "npm-shrinkwrap.json" => package_lock(text),
        "yarn.lock" => yarn_lock(text),
        "pnpm-lock.yaml" => pnpm_lock(text),
        "bun.lock" => super::bun::parse(text),
        "poetry.lock" | "uv.lock" | "pdm.lock" => py_toml_lock(text),
        "Pipfile.lock" => pipfile_lock(text),
        "Cargo.lock" => cargo_lock(text),
        "go.mod" => Some(super::golang::build_from_go_mod(&super::golang::parse_go_mod(text), &[])),
        "go.sum" => Some(super::golang::parse_go_sum(text)),
        "go.work" => Some(Lock { members: super::golang::parse_go_work(text).uses, ..Default::default() }),
        "modules.txt" if path.ends_with("vendor/modules.txt") => Some(super::golang::parse_vendor_modules(text)),
        _ if is_requirements(path) => Some(super::pyreq::parse(text)),
        _ => None,
    }
}

/// Like [`parse`], but a requirements file's `-r` includes are fetched (repo-relative path -> text) and followed.
pub fn parse_with(path: &str, text: &str, fetch: &mut dyn FnMut(&str) -> Option<String>) -> Option<Lock> {
    if is_requirements(path) {
        return Some(super::pyreq::parse_following(path, text, fetch));
    }
    parse(path, text)
}

// ---- finalize -----------------------------------------------------------------------------------------
fn name_of(id: &str) -> String {
    // npm names may start with '@' and no ecosystem's name holds another, so the first '@' after the first char splits name and version
    let rest = id.split_once(':').map(|x| x.1).unwrap_or(id);
    match rest.char_indices().skip(1).find(|(_, c)| *c == '@') {
        Some((i, _)) => rest[..i].to_string(),
        None => rest.to_string(),
    }
}

/// Mark as dev every entry that cannot be reached from `prod_roots`.
pub(crate) fn mark_dev(entries: &mut [Entry], prod_roots: &BTreeSet<String>) {
    let by_id: HashMap<&str, &Entry> = entries.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut reach: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut q: VecDeque<&str> = VecDeque::new();
    for r in prod_roots {
        if reach.insert(r.clone()) {
            q.push_back(r);
        }
    }
    while let Some(c) = q.pop_front() {
        if let Some(e) = by_id.get(c) {
            for d in &e.deps {
                if reach.insert(d.clone()) {
                    q.push_back(d);
                }
            }
        }
    }
    for e in entries.iter_mut() {
        if !reach.contains(&e.id) {
            e.dev = true;
        }
    }
}

/// For locks that know their direct ids and which of them are dev: dev-only transitive packages become dev.
pub(crate) fn mark_dev_by_reach(lock: &mut Lock) {
    if lock.direct_dev_ids.is_empty() {
        return;
    }
    let Some(d) = &lock.direct_ids else { return };
    let prod: BTreeSet<String> = d.difference(&lock.direct_dev_ids).cloned().collect();
    mark_dev(&mut lock.entries, &prod);
}

/// Turn a parsed lock plus the manifest's direct names into the View's package list. `manifest_direct` maps a direct
/// dependency name to whether it is a dev dependency.
pub fn packages(lock: &Lock, manifest_direct: Option<&BTreeMap<String, bool>>) -> Vec<LockPackage> {
    let eco_of = |id: &str| id.split(':').next().unwrap_or("").to_string();
    // one pass over the manifest: raw name -> dev, normalised name -> dev
    let man_raw: HashMap<&str, bool> = manifest_direct.map(|m| m.iter().map(|(k, v)| (k.as_str(), *v)).collect()).unwrap_or_default();
    let man_norm: HashMap<String, bool> = manifest_direct.map(|m| m.iter().map(|(k, v)| (pep503(k), *v)).collect()).unwrap_or_default();
    // without a manifest or a root entry in the lockfile, the packages nothing else depends on are the direct ones
    let depended: std::collections::HashSet<&str> = lock.entries.iter().flat_map(|e| e.deps.iter().map(|d| d.as_str())).collect();
    let direct_of = |id: &str| -> Option<bool> {
        // Some(dev) when direct
        if lock.all_direct {
            return Some(false);
        }
        let n = name_of(id);
        let man_dev = if eco_of(id) == "pypi" { man_norm.get(&pep503(&n)).copied() } else { man_raw.get(n.as_str()).copied() };
        if let Some(ids) = &lock.direct_ids {
            return ids.contains(id).then(|| man_dev.unwrap_or(lock.direct_dev_ids.contains(id)));
        }
        if let Some(d) = man_dev {
            return Some(d);
        }
        if manifest_direct.is_some() && lock.direct_names.is_none() {
            return None;
        }
        if manifest_direct.is_none() && lock.direct_names.is_none() {
            return if depended.contains(id) { None } else { Some(false) };
        }
        if let Some(d) = &lock.direct_names {
            if d.contains(&n) {
                return Some(lock.direct_dev.contains(&n));
            }
        }
        None
    };
    let mut by_id: HashMap<&str, usize> = HashMap::new();
    for (i, e) in lock.entries.iter().enumerate() {
        by_id.entry(&e.id).or_insert(i);
    }
    // BFS from the direct set: shortest chain, ties by lock order
    let mut chain: HashMap<&str, Vec<String>> = HashMap::new();
    let mut q: VecDeque<&str> = VecDeque::new();
    let directs: Vec<Option<bool>> = lock.entries.iter().map(|e| direct_of(&e.id)).collect();
    for (e, d) in lock.entries.iter().zip(&directs) {
        if d.is_some() {
            chain.insert(&e.id, vec![]);
            q.push_back(&e.id);
        }
    }
    while let Some(cur) = q.pop_front() {
        let c = chain[cur].clone();
        let Some(&i) = by_id.get(cur) else { continue };
        for d in &lock.entries[i].deps {
            if !chain.contains_key(d.as_str()) && by_id.contains_key(d.as_str()) {
                let mut nc = c.clone();
                nc.push(cur.to_string());
                let key: &str = &lock.entries[by_id[d.as_str()]].id;
                chain.insert(key, nc);
                q.push_back(key);
            }
        }
    }
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    for (e, d) in lock.entries.iter().zip(directs) {
        if !seen.insert(e.id.clone()) {
            continue;
        }
        out.push(LockPackage {
            p: e.id.clone(),
            direct: d.is_some(),
            dev: e.dev || d == Some(true),
            via: if d.is_some() { vec![] } else { chain.get(e.id.as_str()).cloned().unwrap_or_default() },
            lock_line: Some(e.line),
            as_written: e.as_written.clone(),
        });
    }
    out
}

// ---- package-lock.json ---------------------------------------------------------------------------------
fn package_lock(text: &str) -> Option<Lock> {
    let v: Value = serde_json::from_str(text).ok()?;
    let mut lock = Lock::default();
    let paths = json_paths(text);
    let line_at = |p: &[&str]| paths.get(&join_path(p)).copied().unwrap_or(0);
    if let Some(pk) = v["packages"].as_object() {
        // v2/v3: keys are paths
        let mut ver: HashMap<String, String> = HashMap::new();
        for (k, e) in pk {
            if let (false, Some(vs)) = (k.is_empty(), e["version"].as_str()) {
                ver.insert(k.clone(), vs.to_string());
            }
        }
        let name_of = |k: &str| -> String {
            // use the last node_modules segment (aliases keep the alias path; "name" field wins)
            k.rsplit("node_modules/").next().unwrap_or(k).to_string()
        };
        let is_link = |e: &Value| e["link"].as_bool().unwrap_or(false);
        // a workspace package lives at a path outside node_modules (`packages/foo`, `apps/web`); the root is `""`
        let is_member = |k: &str, e: &Value| k.is_empty() || (!k.contains("node_modules/") && !is_link(e));
        // direct = the dependencies of the root and of every workspace package
        let (mut names, mut prod, mut dev) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for (k, e) in pk {
            if !is_member(k, e) {
                continue;
            }
            if !k.is_empty() {
                lock.members.push(e["name"].as_str().map(str::to_string).unwrap_or_else(|| k.clone()));
            }
            for sec in ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"] {
                if let Some(o) = e[sec].as_object() {
                    for d in o.keys() {
                        names.insert(d.clone());
                        if sec == "devDependencies" {
                            dev.insert(d.clone());
                        } else {
                            prod.insert(d.clone());
                        }
                    }
                }
            }
        }
        if pk.contains_key("") || !names.is_empty() {
            lock.direct_dev = dev.difference(&prod).cloned().collect();
            lock.direct_names = Some(names);
        }
        for (k, e) in pk {
            if is_member(k, e) {
                continue;
            }
            if is_link(e) {
                lock.members.push(format!("{} -> {}", k.trim_start_matches("node_modules/"), e["resolved"].as_str().unwrap_or("?")));
                continue;
            }
            let Some(version) = e["version"].as_str() else { continue };
            let name = e["name"].as_str().map(str::to_string).unwrap_or_else(|| name_of(k));
            let mut deps = vec![];
            for sec in ["dependencies", "optionalDependencies"] {
                if let Some(o) = e[sec].as_object() {
                    for d in o.keys() {
                        // resolve like node: nested first, then up the tree
                        let mut base = k.clone();
                        loop {
                            let cand = if base.is_empty() { format!("node_modules/{d}") } else { format!("{base}/node_modules/{d}") };
                            if let Some(vs) = ver.get(&cand) {
                                deps.push(format!("npm:{d}@{vs}"));
                                break;
                            }
                            match base.rfind("/node_modules/") {
                                Some(i) => base.truncate(i),
                                None => {
                                    if base.is_empty() {
                                        break;
                                    }
                                    base.clear();
                                }
                            }
                        }
                    }
                }
            }
            lock.entries.push(Entry {
                id: format!("npm:{name}@{version}"),
                line: line_at(&["packages", k]),
                deps,
                // devOptional: dev or optional, never needed by a plain production install
                dev: e["dev"].as_bool().unwrap_or(false) || e["devOptional"].as_bool().unwrap_or(false),
                as_written: None,
            });
        }
        // document order
        lock.entries.sort_by_key(|e| e.line);
        return Some(lock);
    }
    if let Some(deps) = v["dependencies"].as_object() {
        // v1: nested "dependencies"; direct = top level
        type Walk<'a> = (&'a HashMap<String, u32>, &'a mut Lock);
        fn walk(w: &mut Walk, o: &serde_json::Map<String, Value>, scope: &[&serde_json::Map<String, Value>], top: bool, path: &mut Vec<String>) {
            for (name, e) in o {
                let Some(version) = e["version"].as_str() else { continue };
                path.push("dependencies".into());
                path.push(name.clone());
                let refs: Vec<&str> = path.iter().map(String::as_str).collect();
                let line = w.0.get(&join_path(&refs)).copied().unwrap_or(0);
                let mut deps = vec![];
                if let Some(req) = e["requires"].as_object() {
                    for d in req.keys() {
                        let mut found = None;
                        if let Some(n) = e["dependencies"].as_object().and_then(|m| m.get(d)) {
                            found = n["version"].as_str().map(str::to_string);
                        }
                        if found.is_none() {
                            for s in scope.iter().rev() {
                                if let Some(n) = s.get(d) {
                                    found = n["version"].as_str().map(str::to_string);
                                    break;
                                }
                            }
                        }
                        if let Some(vs) = found {
                            deps.push(format!("npm:{d}@{vs}"));
                        }
                    }
                }
                w.1.entries.push(Entry { id: format!("npm:{name}@{version}"), line, deps, dev: e["dev"].as_bool().unwrap_or(false), as_written: None });
                if top {
                    w.1.direct_names.get_or_insert_with(Default::default).insert(name.clone());
                }
                if let Some(n) = e["dependencies"].as_object() {
                    let mut sc = scope.to_vec();
                    sc.push(o);
                    walk(w, n, &sc, false, path);
                }
                path.pop();
                path.pop();
            }
        }
        let mut w: Walk = (&paths, &mut lock);
        walk(&mut w, deps, &[], true, &mut vec![]);
        lock.entries.sort_by_key(|e| e.line);
        return Some(lock);
    }
    Some(lock)
}

// ---- yarn.lock ---------------------------------------------------------------------------------------------
fn unquote(s: &str) -> &str {
    s.trim().trim_matches('"')
}

/// Name and alias of a yarn descriptor or resolution: `lodash@^4` is `lodash`; `string-width-cjs@npm:string-width@^4.2.0` is
/// the package `string-width` under the alias `string-width-cjs`; `typescript@patch:typescript@npm%3A5.0.4#...` is `typescript`.
/// Cuts only at ASCII `@`, so a multibyte first character cannot panic.
fn yarn_key_name(k: &str) -> (String, Option<String>) {
    let at = |s: &str| s.char_indices().skip(1).find(|(_, c)| *c == '@').map(|(i, _)| i);
    let Some(i) = at(k) else { return (k.to_string(), None) };
    let (name, rest) = (&k[..i], &k[i + 1..]);
    for prefix in ["npm:", "patch:"] {
        if let Some(r) = rest.strip_prefix(prefix) {
            if let Some(j) = at(r) {
                let real = &r[..j];
                return (real.to_string(), (real != name).then(|| name.to_string()));
            }
        }
    }
    (name.to_string(), None)
}

fn yarn_lock(text: &str) -> Option<Lock> {
    let berry = text.lines().any(|l| l.starts_with("__metadata:"));
    struct Block {
        keys: Vec<String>,
        line: u32,
        version: String,
        deps: Vec<(String, String)>,
        resolution: String,
    }
    let mut blocks: Vec<Block> = vec![];
    let mut cur: Option<Block> = None;
    let mut in_deps = false;
    for (i, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
            in_deps = false;
            let head = raw.trim_end().trim_end_matches(':');
            if head == "__metadata" {
                continue;
            }
            let keys = head.split(',').map(|k| unquote(k).to_string()).collect();
            cur = Some(Block { keys, line: i as u32 + 1, version: String::new(), deps: vec![], resolution: String::new() });
            continue;
        }
        let Some(b) = cur.as_mut() else { continue };
        let t = raw.trim();
        if indent == 2 {
            in_deps = false;
            let (k, v) = match t.split_once(':') {
                Some((k, v)) if berry => (k, v),
                _ => match t.split_once(' ') {
                    Some((k, v)) => (k, v),
                    None => (t.trim_end_matches(':'), ""),
                },
            };
            let k = k.trim_end_matches(':');
            match k {
                "version" => b.version = unquote(v).to_string(),
                "resolution" => b.resolution = unquote(v).to_string(),
                "dependencies" | "optionalDependencies" => in_deps = true,
                _ => {}
            }
        } else if indent >= 4 && in_deps {
            let (k, v) = if berry {
                // a key may be quoted and hold a ':'-free scope, but never a ': '
                match t.rfind(": ") {
                    Some(i) => (&t[..i], &t[i + 2..]),
                    None => (t.trim_end_matches(':'), ""),
                }
            } else {
                // `"@babel/code-frame" "^7.0.0"` / `left-pad "^1.0.0"`
                match t.strip_prefix('"').and_then(|r| r.split_once('"')) {
                    Some((k, v)) => (k, v),
                    None => t.split_once(' ').unwrap_or((t, "")),
                }
            };
            b.deps.push((unquote(k).to_string(), unquote(v).to_string()));
        }
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }
    let mut by_key: HashMap<String, String> = HashMap::new(); // "name@range" -> id
    let mut ids = vec![];
    for b in &blocks {
        let Some(k0) = b.keys.first() else {
            ids.push((String::new(), None));
            continue;
        };
        let (name, alias) = if berry && !b.resolution.is_empty() { yarn_key_name(&b.resolution) } else { yarn_key_name(k0) };
        let id = format!("npm:{name}@{}", b.version);
        for k in &b.keys {
            by_key.insert(k.clone(), id.clone());
        }
        ids.push((id, alias));
    }
    let mut lock = Lock::default();
    let mut direct = BTreeSet::new();
    let resolve = |d: &str, r: &str| -> Option<&String> {
        let k = if berry { format!("{d}@{}", if r.contains(':') { r.to_string() } else { format!("npm:{r}") }) } else { format!("{d}@{r}") };
        by_key.get(&k).or_else(|| by_key.get(&format!("{d}@{r}")))
    };
    for (b, (id, alias)) in blocks.iter().zip(ids) {
        if b.version.is_empty() {
            continue;
        }
        // berry's own workspace entries are not packages; their dependencies are the direct ones. link:/portal: point at local code.
        if berry && b.resolution.contains("@workspace:") {
            for (d, r) in &b.deps {
                if let Some(i) = resolve(d, r) {
                    direct.insert(i.clone());
                }
            }
            continue;
        }
        if berry && (b.resolution.contains("@link:") || b.resolution.contains("@portal:")) {
            lock.members.push(b.resolution.clone());
            continue;
        }
        let mut deps = vec![];
        for (d, r) in &b.deps {
            if let Some(i) = resolve(d, r) {
                deps.push(i.clone());
            }
        }
        lock.entries.push(Entry { id, line: b.line, deps, dev: false, as_written: alias });
    }
    if berry && !direct.is_empty() {
        lock.direct_ids = Some(direct);
    }
    Some(lock)
}

// ---- pnpm-lock.yaml ---------------------------------------------------------------------------------------------
fn pnpm_split(key: &str) -> Option<(String, String)> {
    let k = key.trim_start_matches('/');
    // strip peer suffixes: 1.2.3(react@18) (v6, v9)
    let k = k.split('(').next().unwrap_or(k);
    // v5: /name/1.2.3 or /name/1.2.3_peer@4 (the peer suffix may hold an '@')
    if let Some((n, v)) = k.rsplit_once('/') {
        let ver = v.split('_').next().unwrap_or(v);
        let semver_like = ver.split('.').count() >= 2 && ver.split('.').next().map(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false);
        if semver_like && !n.is_empty() && !n.ends_with('@') && !n.contains('@') || (semver_like && n.starts_with('@') && n.matches('@').count() == 1 && n.contains('/')) {
            return Some((n.to_string(), ver.to_string()));
        }
    }
    // v9 / v6: name@ver. A git or tarball spec (`name@git+ssh://git@github.com/o/r.git#sha`) holds more '@': the one that
    // splits name from version is the last one before the first ':'.
    let head = &k[..k.find(':').unwrap_or(k.len())];
    if let Some(i) = head.rfind('@') {
        if i > 0 {
            let (n, v) = (&k[..i], &k[i + 1..]);
            return Some((n.to_string(), v.split('_').next().unwrap_or(v).to_string()));
        }
    }
    let i = k.rfind('/')?;
    Some((k[..i].to_string(), k[i + 1..].split('_').next().unwrap_or("").to_string()))
}

/// Split a pnpm file into its YAML documents (pnpm 10 may put an env-lock document first), with the 0-based line each starts on.
fn yaml_docs(text: &str) -> Vec<(usize, String)> {
    let mut docs = vec![];
    let (mut start, mut cur) = (0usize, String::new());
    for (i, l) in text.lines().enumerate() {
        if l.trim_end() == "---" {
            if !cur.trim().is_empty() {
                docs.push((start, std::mem::take(&mut cur)));
            }
            cur.clear();
            start = i + 1;
            continue;
        }
        cur.push_str(l);
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        docs.push((start, cur));
    }
    docs
}

fn pnpm_lock(text: &str) -> Option<Lock> {
    // the project's lock is the last document carrying `lockfileVersion`; configDependencies / packageManagerDependencies live in an earlier one
    let docs = yaml_docs(text);
    let (last_start, last_text) = docs.last()?.clone();
    let doc: serde_yaml::Value = serde_yaml::from_str(&last_text).ok()?;
    let (start, doc) = if doc.get("lockfileVersion").is_some() {
        (last_start, doc)
    } else {
        let mut found = None;
        for (s, t) in docs.iter().rev() {
            if let Ok(d) = serde_yaml::from_str::<serde_yaml::Value>(t) {
                if d.get("lockfileVersion").is_some() {
                    found = Some((*s, d));
                    break;
                }
            }
        }
        found?
    };
    let mut lock = Lock::default();
    let pk = doc.get("packages").and_then(|p| p.as_mapping()).cloned().unwrap_or_default();
    let snaps = doc.get("snapshots").and_then(|s| s.as_mapping());
    let pnpm_ver = |v: &serde_yaml::Value| -> Option<String> {
        let s = v.as_str().map(str::to_string).or_else(|| v.get("version").and_then(|x| x.as_str()).map(str::to_string))?;
        Some(s.split('(').next()?.split('_').next()?.to_string())
    };
    let (mut names, mut dev_names, mut prod_names) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let (mut prod_roots, mut dev_roots) = (BTreeSet::new(), BTreeSet::new());
    let mut imports: Vec<&serde_yaml::Value> = vec![];
    if let Some(imp) = doc.get("importers").and_then(|i| i.as_mapping()) {
        imports.extend(imp.values());
    } else {
        imports.push(&doc);
    }
    for imp in imports {
        for sec in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(m) = imp.get(sec).and_then(|m| m.as_mapping()) {
                for (k, val) in m {
                    if let Some(k) = k.as_str() {
                        names.insert(k.to_string());
                        // an alias (`wrap-cjs` -> `wrap-ansi@7.0.0`, v6 `/wrap-ansi@7.0.0`) is direct under its real name too
                        let ver = val.get("version").and_then(|x| x.as_str()).or_else(|| val.as_str()).unwrap_or("");
                        let ver = ver.trim_start_matches('/').split('(').next().unwrap_or("");
                        let mut root = None;
                        if let Some(i) = ver.char_indices().skip(1).find(|(_, c)| *c == '@').map(|x| x.0) {
                            names.insert(ver[..i].to_string());
                            root = Some(format!("npm:{}@{}", &ver[..i], &ver[i + 1..]));
                        } else if !ver.is_empty() && !ver.starts_with("link:") && !ver.starts_with("file:") && !ver.starts_with("workspace:") {
                            root = Some(format!("npm:{k}@{ver}"));
                        }
                        let dev = sec == "devDependencies";
                        if dev {
                            dev_names.insert(k.to_string());
                        } else {
                            prod_names.insert(k.to_string());
                        }
                        if let Some(r) = root {
                            if dev {
                                dev_roots.insert(r)
                            } else {
                                prod_roots.insert(r)
                            };
                        }
                    }
                }
            }
        }
    }
    lock.direct_dev = dev_names.difference(&prod_names).cloned().collect();
    lock.direct_names = Some(names);
    // lines of the keys of `packages:`, in one pass
    let mut pk_lines: HashMap<String, u32> = HashMap::new();
    let mut in_pk = false;
    for (i, l) in text.lines().enumerate().skip(start) {
        if l.starts_with("packages:") {
            in_pk = true;
            continue;
        }
        if in_pk && !l.starts_with(' ') && !l.is_empty() {
            in_pk = false;
        }
        if in_pk && l.starts_with("  ") && !l.starts_with("   ") {
            let t = l.trim().trim_end_matches(':').trim_matches('\'').trim_matches('"');
            pk_lines.entry(t.to_string()).or_insert(i as u32 + 1);
        }
    }
    // an entry names itself in its body for git and tarball packages; otherwise the key says it
    let ident = |k: &str, v: &serde_yaml::Value| -> Option<(String, String)> {
        match (v.get("name").and_then(|x| x.as_str()), v.get("version").and_then(|x| x.as_str())) {
            (Some(n), Some(ver)) => Some((n.to_string(), ver.to_string())),
            _ => pnpm_split(k),
        }
    };
    // snapshot key -> id, for edges
    let mut snap_id: HashMap<String, String> = HashMap::new();
    for (k, v) in &pk {
        if let Some(k) = k.as_str() {
            if let Some((n, ver)) = ident(k, v) {
                snap_id.insert(k.to_string(), format!("npm:{n}@{ver}"));
            }
        }
    }
    if let Some(sn) = snaps {
        for k in sn.keys().filter_map(|k| k.as_str()) {
            if let Some((n, v)) = pnpm_split(k) {
                snap_id.entry(k.to_string()).or_insert(format!("npm:{n}@{v}"));
            }
        }
    }
    // v9 snapshot keys carry the peer suffix: group them by the package key they belong to
    let mut snaps_of: HashMap<&str, Vec<&serde_yaml::Value>> = HashMap::new();
    if let Some(sn) = snaps {
        for (sk, sv) in sn {
            if let Some(sk) = sk.as_str() {
                let base = sk.split('(').next().unwrap_or(sk);
                snaps_of.entry(base).or_default().push(sv);
            }
        }
    }
    let mut any_dev_flag = false;
    for (k, v) in &pk {
        let Some(k) = k.as_str() else { continue };
        let Some((n, ver)) = ident(k, v) else { continue };
        let mut deps = vec![];
        // v9 keeps edges in `snapshots`; v6 and earlier keep them in the entry
        let mut srcs: Vec<&serde_yaml::Value> = snaps_of.get(k).cloned().unwrap_or_default();
        if srcs.is_empty() {
            srcs.push(v);
        }
        for src in srcs {
            for sec in ["dependencies", "optionalDependencies"] {
                if let Some(m) = src.get(sec).and_then(|m| m.as_mapping()) {
                    for (dn, dv) in m {
                        if let (Some(dn), Some(dv)) = (dn.as_str(), pnpm_ver(dv)) {
                            // an alias is written `real-name@1.2.3`
                            let id = match dv.char_indices().skip(1).find(|(_, c)| *c == '@').map(|x| x.0) {
                                Some(i) => format!("npm:{}@{}", &dv[..i], &dv[i + 1..]),
                                None => format!("npm:{dn}@{dv}"),
                            };
                            if !deps.contains(&id) {
                                deps.push(id);
                            }
                        }
                    }
                }
            }
        }
        any_dev_flag |= v.get("dev").is_some();
        let dev = v.get("dev").and_then(|d| d.as_bool()).unwrap_or(false);
        lock.entries.push(Entry { id: format!("npm:{n}@{ver}"), line: pk_lines.get(k.trim_matches('\'')).copied().unwrap_or(0), deps, dev, as_written: None });
    }
    // lockfile v9 dropped the per-package `dev` flag: derive it from reachability from the production roots
    if !any_dev_flag && !dev_roots.is_empty() {
        let only_dev: BTreeSet<String> = prod_roots.clone();
        mark_dev(&mut lock.entries, &only_dev);
    }
    lock.entries.sort_by_key(|e| e.line);
    Some(lock)
}

// ---- poetry.lock, uv.lock and pdm.lock -------------------------------------------------------------------------------
fn py_toml_lock(text: &str) -> Option<Lock> {
    let v: toml::Value = toml::from_str(text).ok()?;
    let pkgs = v.get("package")?.as_array()?;
    // lines of `[[package]]` headers, in order
    let header_lines: Vec<u32> = text.lines().enumerate().filter(|(_, l)| l.trim() == "[[package]]").map(|(i, _)| i as u32 + 1).collect();
    // every version of a name: uv forks resolution per marker, so `numpy 1.26.4` and `numpy 2.1.0` can both be locked
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    for p in pkgs {
        if let (Some(n), Some(vs)) = (p.get("name").and_then(|x| x.as_str()), p.get("version").and_then(|x| x.as_str())) {
            versions.entry(pep503(n)).or_default().push(vs.to_string());
        }
    }
    // dependency references of all three shapes: poetry's table, uv's `{ name, version? }` array, pdm's requirement strings
    let refs = |d: &toml::Value| -> Vec<(String, Option<String>)> {
        let mut out = vec![];
        if let Some(t) = d.as_table() {
            out.extend(t.keys().map(|k| (k.clone(), None)));
        } else if let Some(a) = d.as_array() {
            for x in a {
                if let Some(s) = x.as_str() {
                    if let Some((n, _)) = super::idx::pep508(s) {
                        out.push((n, None));
                    }
                } else if let Some(n) = x.get("name").and_then(|n| n.as_str()) {
                    out.push((n.to_string(), x.get("version").and_then(|v| v.as_str()).map(str::to_string)));
                }
            }
        }
        out
    };
    let ids_of = |n: &str, ver: &Option<String>| -> Vec<String> {
        let key = pep503(n);
        match versions.get(&key) {
            Some(vs) => vs.iter().filter(|v| ver.as_ref().map(|w| w == *v).unwrap_or(true)).map(|v| format!("pypi:{key}@{v}")).collect(),
            None => vec![],
        }
    };
    let mut lock = Lock::default();
    let (mut direct, mut direct_dev, mut direct_prod) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (i, p) in pkgs.iter().enumerate() {
        let (Some(n), Some(vs)) = (p.get("name").and_then(|x| x.as_str()), p.get("version").and_then(|x| x.as_str())) else { continue };
        let mut deps: Vec<String> = vec![];
        if let Some(d) = p.get("dependencies") {
            for (dn, dv) in refs(d) {
                deps.extend(ids_of(&dn, &dv));
            }
        }
        // uv: the project itself (and each workspace member) is virtual/editable/a directory: its dependencies are the direct ones
        let src = p.get("source");
        let is_local = src.map(|s| s.get("virtual").is_some() || s.get("editable").is_some() || s.get("directory").is_some()).unwrap_or(false);
        if is_local {
            lock.members.push(n.to_string());
            for d in &deps {
                direct.insert(d.clone());
                direct_prod.insert(d.clone());
            }
            // PEP 735 groups, `tool.uv.dev-dependencies`: all dev. Extras: direct, not dev.
            if let Some(g) = p.get("dev-dependencies").and_then(|g| g.as_table()) {
                for arr in g.values() {
                    for (dn, dv) in refs(arr) {
                        for id in ids_of(&dn, &dv) {
                            direct.insert(id.clone());
                            direct_dev.insert(id);
                        }
                    }
                }
            }
            if let Some(g) = p.get("optional-dependencies").and_then(|g| g.as_table()) {
                for arr in g.values() {
                    for (dn, dv) in refs(arr) {
                        for id in ids_of(&dn, &dv) {
                            direct.insert(id.clone());
                            direct_prod.insert(id);
                        }
                    }
                }
            }
            continue;
        }
        // poetry <1.5: `category = "dev"`. poetry >=1.5 / 2.x: `groups = ["main", "dev"]`. pdm: `groups = ["default", "dev"]`.
        // `optional = true` means an extra, not dev.
        let groups: Option<Vec<&str>> = p.get("groups").and_then(|g| g.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect());
        let dev = p.get("category").and_then(|c| c.as_str()) == Some("dev") || groups.as_ref().map(|g| !g.is_empty() && !g.iter().any(|x| *x == "main" || *x == "default")).unwrap_or(false);
        // a pdm/poetry package that is a local path or editable install is not a registry package
        if p.get("editable").and_then(|e| e.as_bool()).unwrap_or(false) {
            lock.members.push(n.to_string());
            continue;
        }
        lock.entries.push(Entry { id: format!("pypi:{}@{vs}", pep503(n)), line: header_lines.get(i).copied().unwrap_or(0), deps, dev, as_written: None });
    }
    if !direct.is_empty() {
        let dev_only: BTreeSet<String> = direct_dev.difference(&direct_prod).cloned().collect();
        lock.direct_ids = Some(direct);
        lock.direct_dev_ids = dev_only;
        mark_dev_by_reach(&mut lock);
    }
    Some(lock)
}

fn pipfile_lock(text: &str) -> Option<Lock> {
    let v: Value = serde_json::from_str(text).ok()?;
    let paths = json_paths(text);
    let mut lock = Lock::default();
    let mut no_version = vec![];
    for (sec, dev) in [("default", false), ("develop", true)] {
        if let Some(o) = v[sec].as_object() {
            for (name, e) in o {
                // a package present in both sections points at the line inside its own
                let line = paths.get(&join_path(&[sec, name])).copied().unwrap_or(0);
                let Some(ver) = e["version"].as_str() else {
                    // git, path and url requirements carry a `ref` or `path` instead of a version
                    no_version.push(name.clone());
                    lock.unpinned.push(Unpinned { name: name.clone(), spec: e["git"].as_str().or(e["path"].as_str()).or(e["file"].as_str()).map(|s| format!("@{s}")).unwrap_or_default(), line });
                    continue;
                };
                let ver = ver.trim_start_matches("==");
                lock.entries.push(Entry { id: format!("pypi:{}@{ver}", pep503(name)), line, deps: vec![], dev, as_written: None });
            }
        }
    }
    if !no_version.is_empty() {
        lock.gaps.push(format!("Pipfile.lock has {} entr{} without a version (git, path or url): {}", no_version.len(), if no_version.len() == 1 { "y" } else { "ies" }, no_version.join(", ")));
    }
    lock.entries.sort_by_key(|e| e.line);
    Some(lock)
}

// ---- Cargo.lock --------------------------------------------------------------------------------------------------
const CRATES_IO: &[&str] = &["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/", "sparse+https://index.crates.io"];

/// The ecosystem prefix of a crate by its `source`: `cargo` for crates.io, `cargo+host` for another registry, `cargo+git` for git.
/// Only crates.io crates may be matched against crates.io advisories.
fn cargo_eco(source: &str) -> String {
    if CRATES_IO.contains(&source) {
        return "cargo".to_string();
    }
    if source.starts_with("git+") {
        return "cargo+git".to_string();
    }
    let url = source.split_once('+').map(|x| x.1).unwrap_or(source);
    let host = url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or("").split('@').next_back().unwrap_or("");
    let host = host.split(':').next().unwrap_or(host);
    format!("cargo+{}", if host.is_empty() { "registry" } else { host })
}

fn cargo_lock(text: &str) -> Option<Lock> {
    let v: toml::Value = toml::from_str(text).ok()?;
    // Cargo.lock v1 writes the root package as its own `[root]` table
    let mut pkgs: Vec<&toml::Value> = v.get("package").and_then(|p| p.as_array()).map(|a| a.iter().collect()).unwrap_or_default();
    let mut lines: Vec<u32> = text.lines().enumerate().filter(|(_, l)| l.trim() == "[[package]]").map(|(i, _)| i as u32 + 1).collect();
    if let Some(r) = v.get("root") {
        pkgs.push(r);
        lines.push(text.lines().position(|l| l.trim() == "[root]").map(|i| i as u32 + 1).unwrap_or(0));
    }
    if pkgs.is_empty() && v.get("package").is_none() {
        return None;
    }
    let field = |p: &toml::Value, k: &str| p.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, p) in pkgs.iter().enumerate() {
        if let (Some(n), Some(_)) = (field(p, "name"), field(p, "version")) {
            by_name.entry(n).or_default().push(i);
        }
    }
    let id_of = |i: usize| -> Option<String> {
        let p = pkgs[i];
        let src = field(p, "source")?;
        Some(format!("{}:{}@{}", cargo_eco(&src), field(p, "name")?, field(p, "version")?))
    };
    // a dependency string is `name`, `name version` or `name version (source)`; a version appears when the name is ambiguous
    let resolve = |d: &str| -> Vec<usize> {
        let mut parts = d.split_whitespace();
        let Some(name) = parts.next() else { return vec![] };
        let ver = parts.next();
        let src = parts.next().map(|s| s.trim_matches(|c| c == '(' || c == ')'));
        let Some(c) = by_name.get(name) else { return vec![] };
        let mut hit: Vec<usize> = c.iter().copied().filter(|&i| ver.map(|v| field(pkgs[i], "version").as_deref() == Some(v)).unwrap_or(true)).collect();
        if let Some(s) = src {
            let narrowed: Vec<usize> = hit.iter().copied().filter(|&i| field(pkgs[i], "source").as_deref() == Some(s)).collect();
            if !narrowed.is_empty() {
                hit = narrowed;
            }
        }
        hit
    };
    let mut lock = Lock::default();
    let mut direct = BTreeSet::new();
    let mut foreign = 0usize;
    for (i, p) in pkgs.iter().enumerate() {
        let (Some(_), Some(_)) = (field(p, "name"), field(p, "version")) else { continue };
        let deps: Vec<String> = p.get("dependencies").and_then(|d| d.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).flat_map(&resolve).filter_map(id_of).collect()).unwrap_or_default();
        let Some(id) = id_of(i) else {
            // no source: a workspace member or path dependency; its dependencies are the direct ones
            lock.members.push(field(p, "name").unwrap_or_default());
            direct.extend(deps);
            continue;
        };
        if !id.starts_with("cargo:") {
            foreign += 1;
        }
        lock.entries.push(Entry { id, line: lines.get(i).copied().unwrap_or(0), deps, dev: false, as_written: None });
    }
    if foreign > 0 {
        lock.gaps.push(format!("{foreign} crate{} come from git or a registry other than crates.io; they are not matched against crates.io advisories", if foreign == 1 { "" } else { "s" }));
    }
    // A lock with no workspace member or root package (a trimmed or generated one) cannot say what is direct; an empty
    // set would call every crate transitive, so leave the question to the manifest that declares them
    lock.direct_ids = if direct.is_empty() { None } else { Some(direct) };
    Some(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_lock_v3() {
        let t = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^2"}},
    "node_modules/a": {"version": "1.2.0", "dependencies": {"b": "^1"}},
    "node_modules/b": {"version": "1.1.0", "dependencies": {"c": "^1"}},
    "node_modules/c": {"version": "1.0.5"},
    "node_modules/d": {"version": "2.0.0", "dev": true}
  }
}"#;
        let l = parse("package-lock.json", t).unwrap();
        let p = packages(&l, None);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0].p, "npm:a@1.2.0");
        assert!(p[0].direct && p[0].lock_line == Some(6));
        assert_eq!(p[2].via, vec!["npm:a@1.2.0", "npm:b@1.1.0"]);
        assert!(p[3].dev && p[3].direct);
    }

    #[test]
    fn yarn_v1() {
        let t = "# yarn lockfile v1\n\n\n\"@acme/nav@^2.0.0\":\n  version \"2.0.4\"\n  resolved \"x\"\n  dependencies:\n    left-pad \"^1.0.0\"\n\nleft-pad@^1.0.0, left-pad@^1.3.0:\n  version \"1.3.0\"\n";
        let l = parse("yarn.lock", t).unwrap();
        assert_eq!(l.entries.len(), 2);
        assert_eq!(l.entries[0].id, "npm:@acme/nav@2.0.4");
        assert_eq!(l.entries[0].line, 4);
        assert_eq!(l.entries[0].deps, vec!["npm:left-pad@1.3.0"]);
    }

    #[test]
    fn yarn_berry() {
        let t = "__metadata:\n  version: 6\n\n\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: x\n";
        let l = parse("yarn.lock", t).unwrap();
        assert_eq!(l.entries[0].id, "npm:left-pad@1.3.0");
    }

    #[test]
    fn requirements_pins() {
        let t = "# c\nflask>=2\nNetprobe_Py==0.4.2\nrequests==2.31.0  # x\n";
        let l = parse("requirements.txt", t).unwrap();
        let p = packages(&l, None);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].p, "pypi:netprobe-py@0.4.2");
        assert_eq!(p[0].lock_line, Some(3));
        assert_eq!(p[0].as_written.as_deref(), Some("Netprobe_Py==0.4.2"));
        assert!(p[1].as_written.is_none());
    }

    #[test]
    fn cargo_and_go() {
        let t = "[[package]]\nname = \"me\"\nversion = \"0.1.0\"\ndependencies = [\"a\"]\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\"b 2.0.0\"]\n\n[[package]]\nname = \"b\"\nversion = \"2.0.0\"\nsource = \"registry+x\"\n";
        let l = parse("Cargo.lock", t).unwrap();
        let p = packages(&l, None);
        assert_eq!(p.len(), 2);
        assert!(p[0].direct);
        assert_eq!(p[1].via, vec!["cargo:a@1.0.0"]);
        assert_eq!(p[0].lock_line, Some(6));
        let g = parse("go.sum", "github.com/x/y v1.0.0 h1:abc=\ngithub.com/x/y v1.0.0/go.mod h1:def=\n").unwrap();
        assert_eq!(g.entries.len(), 1);
        assert_eq!(g.entries[0].id, "go:github.com/x/y@v1.0.0");
    }

    #[test]
    fn poetry() {
        let t = "[[package]]\nname = \"Netprobe_Py\"\nversion = \"0.4.2\"\n\n[package.dependencies]\nrequests = \"*\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let l = parse("poetry.lock", t).unwrap();
        assert_eq!(l.entries[0].id, "pypi:netprobe-py@0.4.2");
        assert_eq!(l.entries[0].deps, vec!["pypi:requests@2.31.0"]);
        assert_eq!(l.entries[1].line, 8);
    }

    #[test]
    fn pnpm_v6_and_v9_real_shapes() {
        // pnpm 8 (lockfileVersion 6.0): '/' keys, peer suffix in parentheses, edges inside the entry, root deps without importers
        let v6 = "lockfileVersion: '6.0'\n\nsettings:\n  autoInstallPeers: true\n\ndependencies:\n  react-dom:\n    specifier: ^18.2.0\n    version: 18.2.0(react@18.2.0)\n  react:\n    specifier: ^18.2.0\n    version: 18.2.0\n\npackages:\n\n  /@babel/runtime@7.23.2:\n    resolution: {integrity: sha512-a}\n    engines: {node: '>=6.9.0'}\n    dev: false\n\n  /js-tokens@4.0.0:\n    resolution: {integrity: sha512-b}\n    dev: false\n\n  /loose-envify@1.4.0:\n    resolution: {integrity: sha512-c}\n    dependencies:\n      js-tokens: 4.0.0\n    dev: false\n\n  /react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-d}\n    peerDependencies:\n      react: ^18.2.0\n    dependencies:\n      loose-envify: 1.4.0\n      react: 18.2.0\n    dev: false\n\n  /react@18.2.0:\n    resolution: {integrity: sha512-e}\n    dependencies:\n      loose-envify: 1.4.0\n    dev: false\n";
        let l = parse("pnpm-lock.yaml", v6).unwrap();
        let p = packages(&l, None);
        let ids: Vec<_> = p.iter().map(|x| x.p.clone()).collect();
        assert_eq!(ids, vec!["npm:@babel/runtime@7.23.2", "npm:js-tokens@4.0.0", "npm:loose-envify@1.4.0", "npm:react-dom@18.2.0", "npm:react@18.2.0"]);
        let jt = p.iter().find(|x| x.p == "npm:js-tokens@4.0.0").unwrap();
        assert!(!jt.direct);
        assert_eq!(jt.via, vec!["npm:react-dom@18.2.0", "npm:loose-envify@1.4.0"]);
        // pnpm 9 (lockfileVersion 9.0): edges live in `snapshots`, whose keys carry the peer suffix; aliases are name@version
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react-dom:\n        specifier: ^18.2.0\n        version: 18.2.0(react@18.2.0)\n      react:\n        specifier: ^18.2.0\n        version: 18.2.0\n      wrap-cjs:\n        specifier: npm:wrap-ansi@^7.0.0\n        version: wrap-ansi@7.0.0\n\npackages:\n\n  js-tokens@4.0.0:\n    resolution: {integrity: sha512-b}\n\n  loose-envify@1.4.0:\n    resolution: {integrity: sha512-c}\n    hasBin: true\n\n  react-dom@18.2.0:\n    resolution: {integrity: sha512-d}\n    peerDependencies:\n      react: ^18.2.0\n\n  react@18.2.0:\n    resolution: {integrity: sha512-e}\n\n  wrap-ansi@7.0.0:\n    resolution: {integrity: sha512-f}\n\nsnapshots:\n\n  js-tokens@4.0.0: {}\n\n  loose-envify@1.4.0:\n    dependencies:\n      js-tokens: 4.0.0\n\n  react-dom@18.2.0(react@18.2.0):\n    dependencies:\n      loose-envify: 1.4.0\n      react: 18.2.0\n\n  react@18.2.0:\n    dependencies:\n      loose-envify: 1.4.0\n\n  wrap-ansi@7.0.0: {}\n";
        let l = parse("pnpm-lock.yaml", v9).unwrap();
        let p = packages(&l, None);
        assert_eq!(p.len(), 5);
        let jt = p.iter().find(|x| x.p == "npm:js-tokens@4.0.0").unwrap();
        assert_eq!(jt.via, vec!["npm:react-dom@18.2.0", "npm:loose-envify@1.4.0"], "edges must survive the peer suffix on the snapshot key");
        assert!(p.iter().find(|x| x.p == "npm:wrap-ansi@7.0.0").unwrap().direct);
        // pnpm 5 keys
        assert_eq!(pnpm_split("/@babel/core/7.0.0_@babel+x@1.0.0"), Some(("@babel/core".into(), "7.0.0".into())));
        assert_eq!(pnpm_split("/foo/1.2.3_bar@2.0.0"), Some(("foo".into(), "1.2.3".into())));
        assert_eq!(pnpm_split("/@a/3d@1.0.0"), Some(("@a/3d".into(), "1.0.0".into())));
        assert_eq!(pnpm_split("/2fa@1.0.0"), Some(("2fa".into(), "1.0.0".into())));
    }

    #[test]
    fn yarn_real_shapes() {
        // yarn 1: comment header, unquoted and quoted keys, several ranges per entry, git/tarball resolutions
        let c = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.10.4\":\n  version \"7.12.13\"\n  resolved \"https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc826beef65e75c50e21d3837d870d89109eb5\"\n  integrity sha512-HV1Cm0Q3ZrpCR93tkWOYiuYIgLxZXZFVG2VgK+MBWjUqZTundupbfx2aXarXuw5Ko5aMcjtJgbSs4vUGBS5v6g==\n  dependencies:\n    \"@babel/highlight\" \"^7.12.13\"\n\n\"@babel/highlight@^7.12.13\":\n  version \"7.13.10\"\n  resolved \"https://registry.yarnpkg.com/@babel/highlight/-/highlight-7.13.10.tgz#a8b2a66148f5b27d666b15d81774347a731d52d1\"\n  dependencies:\n    chalk \"^2.0.0\"\n\nchalk@^2.0.0, chalk@^2.4.2:\n  version \"2.4.2\"\n  resolved \"https://registry.yarnpkg.com/chalk/-/chalk-2.4.2.tgz#cd42541677a54333cf541a49108c1432b44c9424\"\n  dependencies:\n    ansi-styles \"^3.2.1\"\n\nansi-styles@^3.2.1:\n  version \"3.2.1\"\n\nleft-pad@dyladan/left-pad:\n  version \"1.3.0\"\n  resolved \"https://codeload.github.com/dyladan/left-pad/tar.gz/abc\"\n";
        let l = parse("yarn.lock", c).unwrap();
        let p = packages(&l, None);
        let ids: Vec<_> = p.iter().map(|x| x.p.as_str()).collect();
        assert_eq!(ids, vec!["npm:@babel/code-frame@7.12.13", "npm:@babel/highlight@7.13.10", "npm:chalk@2.4.2", "npm:ansi-styles@3.2.1", "npm:left-pad@1.3.0"]);
        assert_eq!(p[3].via.last().map(String::as_str), Some("npm:chalk@2.4.2"));
        // yarn berry: __metadata, `resolution:`, workspace entry, an aliased npm: range, a patch: duplicate of a package
        let b = "# This file is generated by running \"yarn install\" inside your project.\n\n__metadata:\n  version: 6\n  cacheKey: 8\n\n\"@babel/code-frame@npm:^7.0.0, @babel/code-frame@npm:^7.10.4\":\n  version: 7.12.13\n  resolution: \"@babel/code-frame@npm:7.12.13\"\n  dependencies:\n    \"@babel/highlight\": ^7.12.13\n  checksum: 10c0/abc\n  languageName: node\n  linkType: hard\n\n\"@babel/highlight@npm:^7.12.13\":\n  version: 7.13.10\n  resolution: \"@babel/highlight@npm:7.13.10\"\n  languageName: node\n  linkType: hard\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n  dependencies:\n    \"@babel/code-frame\": ^7.0.0\n    typescript: ^5.0.0\n  languageName: unknown\n  linkType: soft\n\n\"typescript@npm:^5.0.0\":\n  version: 5.0.4\n  resolution: \"typescript@npm:5.0.4\"\n  bin:\n    tsc: bin/tsc\n  languageName: node\n  linkType: hard\n\n\"typescript@patch:typescript@^5.0.0#optional!builtin<compat/typescript>\":\n  version: 5.0.4\n  resolution: \"typescript@patch:typescript@npm%3A5.0.4#optional!builtin<compat/typescript>::version=5.0.4&hash=5da071\"\n  bin:\n    tsc: bin/tsc\n  languageName: node\n  linkType: hard\n";
        let l = parse("yarn.lock", b).unwrap();
        let p = packages(&l, None);
        let ids: Vec<_> = p.iter().map(|x| x.p.as_str()).collect();
        assert_eq!(ids, vec!["npm:@babel/code-frame@7.12.13", "npm:@babel/highlight@7.13.10", "npm:typescript@5.0.4"], "{ids:?}");
        assert_eq!(p[1].via.last().map(String::as_str), Some("npm:@babel/code-frame@7.12.13"));
    }

    #[test]
    fn package_lock_v1_v2_real_shapes() {
        // lockfileVersion 1 (npm 5/6): nested `dependencies` only; bundled and git entries
        let v1 = r#"{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{
  "a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-x","requires":{"b":"^2.0.0"},"dependencies":{"b":{"version":"2.1.0","resolved":"https://registry.npmjs.org/b/-/b-2.1.0.tgz","integrity":"sha512-y","dev":true}}},
  "b":{"version":"2.0.0","resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz","integrity":"sha512-z"},
  "@s/c":{"version":"3.0.0","resolved":"https://registry.npmjs.org/@s/c/-/c-3.0.0.tgz","integrity":"sha512-w"}}}"#;
        let l = parse("package-lock.json", v1).unwrap();
        let mut ids: Vec<_> = packages(&l, None).iter().map(|x| x.p.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["npm:@s/c@3.0.0", "npm:a@1.0.0", "npm:b@2.0.0", "npm:b@2.1.0"]);
        // lockfileVersion 2 (npm 7/8): both `packages` and the legacy `dependencies`; each package counted once
        let v2 = r#"{"name":"app","version":"1.0.0","lockfileVersion":2,"requires":true,"packages":{
  "":{"name":"app","version":"1.0.0","dependencies":{"a":"^1.0.0"}},
  "node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","dependencies":{"b":"^2.0.0"}},
  "node_modules/a/node_modules/b":{"version":"2.1.0","dev":true},
  "node_modules/b":{"version":"2.0.0"},
  "node_modules/alias":{"name":"b","version":"2.0.0"},
  "packages/local":{"name":"local","version":"0.0.1"},
  "node_modules/local":{"resolved":"packages/local","link":true}},
 "dependencies":{"a":{"version":"1.0.0","requires":{"b":"^2.0.0"},"dependencies":{"b":{"version":"2.1.0"}}},"b":{"version":"2.0.0"}}}"#;
        let l = parse("package-lock.json", v2).unwrap();
        let mut ids: Vec<_> = packages(&l, None).iter().map(|x| x.p.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["npm:a@1.0.0", "npm:b@2.0.0", "npm:b@2.1.0"], "{ids:?}");
        // the workspace package and its link are members, not registry packages (dependency confusion if reported as npm)
        assert_eq!(l.members.len(), 2, "{:?}", l.members);
    }

    #[test]
    fn cargo_v3_v4_go_poetry_real_shapes() {
        // Cargo.lock v3 has `checksum`, v4 adds source suffix #hash in git sources and drops `metadata`; dependency strings carry a
        // version only when the name is ambiguous
        let v4 = "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde 1.0.200\",\n \"syn 1.0.109\",\n \"syn 2.0.60\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc\"\ndependencies = [\n \"syn 2.0.60\",\n]\n\n[[package]]\nname = \"syn\"\nversion = \"1.0.109\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"def\"\n\n[[package]]\nname = \"syn\"\nversion = \"2.0.60\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ghi\"\n\n[[package]]\nname = \"gitdep\"\nversion = \"0.2.0\"\nsource = \"git+https://github.com/x/gitdep?rev=abc#abcdef0123456789\"\n";
        let l = parse("Cargo.lock", v4).unwrap();
        let ids: Vec<_> = packages(&l, None).iter().map(|x| x.p.clone()).collect();
        assert_eq!(ids, vec!["cargo:serde@1.0.200", "cargo:syn@1.0.109", "cargo:syn@2.0.60", "cargo+git:gitdep@0.2.0"]);
        assert!(l.gaps.iter().any(|g| g.contains("other than crates.io")), "{:?}", l.gaps);
        // go.sum: h1 lines for the module and its go.mod; pseudo-versions and +incompatible
        let g = "github.com/BurntSushi/toml v1.3.2 h1:abc=\ngithub.com/BurntSushi/toml v1.3.2/go.mod h1:def=\ngolang.org/x/sys v0.0.0-20220715151400-c0bba94af5f7 h1:ghi=\ngolang.org/x/sys v0.0.0-20220715151400-c0bba94af5f7/go.mod h1:jkl=\ngithub.com/x/y v2.0.0+incompatible h1:mno=\ngithub.com/x/y v2.0.0+incompatible/go.mod h1:pqr=\n";
        let l = parse("go.sum", g).unwrap();
        let ids: Vec<_> = packages(&l, None).iter().map(|x| x.p.clone()).collect();
        assert_eq!(ids, vec!["go:github.com/BurntSushi/toml@v1.3.2", "go:golang.org/x/sys@v0.0.0-20220715151400-c0bba94af5f7", "go:github.com/x/y@v2.0.0+incompatible"]);
        // poetry.lock (name normalised per PEP 503) and uv.lock (the project itself is virtual/editable and not a dependency)
        let po = "# This file is automatically @generated by Poetry 1.8.2 and should not be changed by hand.\n\n[[package]]\nname = \"Typing_Extensions\"\nversion = \"4.9.0\"\ndescription = \"x\"\noptional = false\npython-versions = \">=3.8\"\nfiles = [\n    {file = \"a.whl\", hash = \"sha256:1\"},\n]\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.10\"\ncontent-hash = \"abc\"\n";
        let l = parse("poetry.lock", po).unwrap();
        let ids: Vec<_> = packages(&l, None).iter().map(|x| x.p.clone()).collect();
        assert_eq!(ids, vec!["pypi:typing-extensions@4.9.0"]);
        let uv = "version = 1\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n    { name = \"idna\" },\n]\n\n[[package]]\nname = \"idna\"\nversion = \"3.6\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"myproj\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\ndependencies = [\n    { name = \"requests\" },\n]\n";
        let l = parse("uv.lock", uv).unwrap();
        let p = packages(&l, None);
        let mut ids: Vec<_> = p.iter().map(|x| x.p.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["pypi:idna@3.6", "pypi:requests@2.31.0"], "{ids:?}");
    }

    #[test]
    fn pnpm() {
        let t = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        version: 1.0.0\npackages:\n  a@1.0.0:\n    resolution: {integrity: x}\n  b@2.0.0:\n    resolution: {integrity: y}\nsnapshots:\n  a@1.0.0:\n    dependencies:\n      b: 2.0.0\n  b@2.0.0: {}\n";
        let l = parse("pnpm-lock.yaml", t).unwrap();
        let p = packages(&l, None);
        assert_eq!(p.len(), 2);
        assert!(p[0].direct);
        assert_eq!(p[1].via, vec!["npm:a@1.0.0"]);
        assert_eq!(p[0].lock_line, Some(9));
    }

    /// Dev aid: `BR_LOCK_FILES=a:b cargo test --release dump_locks -- --ignored --nocapture` prints one parsed id per line.
    #[test]
    #[ignore]
    fn dump_locks() {
        for f in std::env::var("BR_LOCK_FILES").unwrap_or_default().split(':').filter(|f| !f.is_empty()) {
            let t = std::fs::read_to_string(f).unwrap();
            match parse(f, &t) {
                Some(l) => {
                    println!("#FILE {f} {}", l.entries.len());
                    for e in l.entries {
                        println!("{}", e.id);
                    }
                }
                None => println!("#FILE {f} PARSE-FAILED"),
            }
        }
    }
}

#[cfg(test)]
mod f2_tests {
    use super::*;

    fn ids(l: &Lock) -> Vec<String> {
        l.entries.iter().map(|e| e.id.clone()).collect()
    }

    #[test]
    fn npm_workspaces_union_direct_and_skip_links() {
        // npm 9 workspaces: root + packages/web, one internal link, one devOptional package
        let t = r#"{
  "name": "mono",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "mono", "workspaces": ["packages/*"], "devDependencies": { "typescript": "^5" } },
    "node_modules/@acme/web": { "resolved": "packages/web", "link": true },
    "node_modules/express": { "version": "4.19.2" },
    "node_modules/fsevents": { "version": "2.3.3", "devOptional": true },
    "node_modules/typescript": { "version": "5.4.5", "dev": true },
    "packages/web": { "name": "@acme/web", "version": "1.0.0", "dependencies": { "express": "^4.19.0" } }
  }
}"#;
        let l = parse("package-lock.json", t).unwrap();
        assert_eq!(ids(&l), vec!["npm:express@4.19.2", "npm:fsevents@2.3.3", "npm:typescript@5.4.5"]);
        assert_eq!(l.members.len(), 2, "{:?}", l.members);
        let p = packages(&l, None);
        assert!(p[0].direct, "express is a dependency of the workspace, not of the root");
        assert!(p[1].dev, "devOptional is never needed by a production install");
        assert_eq!(p[0].lock_line, Some(7));
        assert!(!p.iter().any(|x| x.p.contains("@acme/web")));
    }

    #[test]
    fn pnpm_10_env_lock_document_git_key_and_v9_dev_derivation() {
        let t = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies: {}\n\npackages: {}\nsnapshots: {}\n\n---\nlockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: ^1.3.0\n        version: 1.3.0\n    devDependencies:\n      vitest:\n        specifier: ^1.0.0\n        version: 1.6.0\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n\n  vitest@1.6.0:\n    resolution: {integrity: sha512-y}\n\n  tiny-spy@2.0.0:\n    resolution: {integrity: sha512-z}\n\n  mylib@https://codeload.github.com/o/mylib/tar.gz/abc123:\n    resolution: {tarball: https://codeload.github.com/o/mylib/tar.gz/abc123}\n    version: 1.2.3\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n\n  vitest@1.6.0:\n    dependencies:\n      tiny-spy: 2.0.0\n\n  tiny-spy@2.0.0: {}\n";
        let l = parse("pnpm-lock.yaml", t).expect("a leading env-lock document must not drop the file");
        let got = ids(&l);
        assert!(got.contains(&"npm:left-pad@1.3.0".to_string()), "{got:?}");
        assert!(got.contains(&"npm:tiny-spy@2.0.0".to_string()), "{got:?}");
        let p = packages(&l, None);
        let by = |id: &str| p.iter().find(|x| x.p == id).unwrap();
        assert!(!by("npm:left-pad@1.3.0").dev);
        assert!(by("npm:vitest@1.6.0").dev && by("npm:vitest@1.6.0").direct);
        assert!(by("npm:tiny-spy@2.0.0").dev, "v9 has no per-package dev flag; reachable only from a dev root");
        assert_eq!(by("npm:left-pad@1.3.0").lock_line, Some(32));
    }

    #[test]
    fn poetry_2_groups_and_optional_is_an_extra() {
        // poetry 2.x: `groups`, no `category`; `optional = true` marks an extra and must not make the package dev
        let t = "# This file is automatically @generated by Poetry 2.0.1 and should not be changed by hand.\n\n[[package]]\nname = \"Requests\"\nversion = \"2.32.3\"\ndescription = \"x\"\noptional = false\npython-versions = \">=3.8\"\ngroups = [\"main\"]\n\n[package.dependencies]\nidna = \">=2.5,<4\"\n\n[[package]]\nname = \"idna\"\nversion = \"3.7\"\noptional = false\ngroups = [\"main\"]\n\n[[package]]\nname = \"pytest\"\nversion = \"8.2.0\"\noptional = false\ngroups = [\"dev\"]\n\n[[package]]\nname = \"boto3\"\nversion = \"1.34.0\"\noptional = true\ngroups = [\"main\"]\n\n[metadata]\nlock-version = \"2.1\"\n";
        let l = parse("poetry.lock", t).unwrap();
        let p = packages(&l, None);
        let by = |id: &str| p.iter().find(|x| x.p == id).unwrap();
        assert!(by("pypi:pytest@8.2.0").dev);
        assert!(!by("pypi:boto3@1.34.0").dev, "optional means extra, not dev");
        assert!(!by("pypi:requests@2.32.3").dev);
        assert_eq!(by("pypi:requests@2.32.3").lock_line, Some(3));
        assert_eq!(by("pypi:idna@3.7").lock_line, Some(14));
    }

    #[test]
    fn uv_lock_forks_groups_and_local_project() {
        let t = "version = 1\nrequires-python = \">=3.9\"\nresolution-markers = [\"python_full_version < '3.10'\", \"python_full_version >= '3.10'\"]\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\ndependencies = [\n    { name = \"numpy\", version = \"1.26.4\", source = { registry = \"https://pypi.org/simple\" }, marker = \"python_full_version < '3.10'\" },\n    { name = \"numpy\", version = \"2.1.0\", source = { registry = \"https://pypi.org/simple\" }, marker = \"python_full_version >= '3.10'\" },\n]\n\n[package.dev-dependencies]\ndev = [\n    { name = \"pytest\" },\n]\n\n[[package]]\nname = \"numpy\"\nversion = \"1.26.4\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"numpy\"\nversion = \"2.1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"pytest\"\nversion = \"8.2.0\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n    { name = \"iniconfig\" },\n]\n\n[[package]]\nname = \"iniconfig\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
        let l = parse("uv.lock", t).unwrap();
        assert_eq!(ids(&l), vec!["pypi:numpy@1.26.4", "pypi:numpy@2.1.0", "pypi:pytest@8.2.0", "pypi:iniconfig@2.0.0"], "both forks are kept; the project itself is not a package");
        assert_eq!(l.members, vec!["app"]);
        let p = packages(&l, None);
        let by = |id: &str| p.iter().find(|x| x.p == id).unwrap();
        assert!(by("pypi:numpy@1.26.4").direct && by("pypi:numpy@2.1.0").direct);
        assert!(!by("pypi:numpy@2.1.0").dev);
        assert!(by("pypi:pytest@8.2.0").direct && by("pypi:pytest@8.2.0").dev);
        assert!(by("pypi:iniconfig@2.0.0").dev && !by("pypi:iniconfig@2.0.0").direct);
        assert_eq!(by("pypi:numpy@2.1.0").lock_line, Some(24));
    }

    #[test]
    fn pdm_lock_groups() {
        let t = "# This file is @generated by PDM.\n[metadata]\ngroups = [\"default\", \"dev\"]\nlock_version = \"4.5.0\"\n\n[[package]]\nname = \"click\"\nversion = \"8.1.7\"\ngroups = [\"default\"]\n\n[[package]]\nname = \"pytest\"\nversion = \"8.2.0\"\ngroups = [\"dev\"]\n";
        let l = parse("pdm.lock", t).unwrap();
        let p = packages(&l, None);
        assert!(!p[0].dev);
        assert!(p[1].dev);
        assert_eq!(p[1].lock_line, Some(11));
    }

    #[test]
    fn pipfile_lock_package_in_both_sections_points_at_its_own_line() {
        let t = "{\n    \"_meta\": {\"sources\": []},\n    \"default\": {\n        \"six\": {\n            \"hashes\": [\"sha256:aa\"],\n            \"version\": \"==1.16.0\"\n        }\n    },\n    \"develop\": {\n        \"pytest\": {\n            \"version\": \"==8.2.0\"\n        },\n        \"six\": {\n            \"hashes\": [\"sha256:aa\"],\n            \"version\": \"==1.16.0\"\n        },\n        \"mylib\": {\n            \"git\": \"https://github.com/o/mylib.git\",\n            \"ref\": \"abc\"\n        }\n    }\n}\n";
        let l = parse("Pipfile.lock", t).unwrap();
        let six: Vec<_> = l.entries.iter().filter(|e| e.id == "pypi:six@1.16.0").collect();
        assert_eq!(six.len(), 2, "kept once per section");
        assert_eq!(six[0].line, 4);
        assert_eq!(six[1].line, 13);
        assert!(six[1].dev);
        assert_eq!(l.unpinned.len(), 1);
        assert_eq!(l.unpinned[0].name, "mylib");
        assert!(l.gaps.iter().any(|g| g.contains("mylib")));
    }

    #[test]
    fn cargo_lock_v1_root_and_private_registry() {
        let t = "[root]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)\",\n \"corp 0.3.0 (registry+https://cargo.corp.example/index)\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"corp\"\nversion = \"0.3.0\"\nsource = \"registry+https://cargo.corp.example/index\"\n\n[metadata]\n\"checksum serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)\" = \"abc\"\n";
        let l = parse("Cargo.lock", t).unwrap();
        assert_eq!(ids(&l), vec!["cargo:serde@1.0.0", "cargo+cargo.corp.example:corp@0.3.0"]);
        assert_eq!(l.members, vec!["app"]);
        let p = packages(&l, None);
        assert!(p.iter().all(|x| x.direct));
        assert!(l.gaps.iter().any(|g| g.contains("other than crates.io")));
    }

    #[test]
    fn cargo_workspace_members_dev_build_and_target_tables_are_direct() {
        // a virtual workspace: two members, one depends on the other; dev-, build- and target-specific dependencies of a member are its own direct ones
        let t = "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"lib\",\n \"serde\",\n \"tempfile\",\n \"cc\",\n \"winapi\",\n]\n\n[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\ndependencies = [\n \"itoa\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"itoa\",\n \"deep\",\n]\n\n[[package]]\nname = \"tempfile\"\nversion = \"3.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"cc\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"winapi\"\nversion = \"0.3.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"deep\"\nversion = \"0.2.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let l = parse("Cargo.lock", t).unwrap();
        let m = crate::parse::manifest::parse("Cargo.toml", "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n[dev-dependencies]\ntempfile = \"3\"\n[build-dependencies]\ncc = \"1\"\n[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n");
        let md = m.deps.iter().map(|(k, d)| (k.clone(), d.section.as_deref().map(|s| s.contains("dev")).unwrap_or(false))).collect();
        let p = packages(&l, Some(&md));
        let by = |id: &str| p.iter().find(|x| x.p == id).unwrap();
        for id in ["cargo:serde@1.0.0", "cargo:tempfile@3.0.0", "cargo:cc@1.0.0", "cargo:winapi@0.3.0", "cargo:itoa@1.0.0"] {
            assert!(by(id).direct, "{id} is declared by a workspace member");
        }
        assert!(by("cargo:tempfile@3.0.0").dev && !by("cargo:cc@1.0.0").dev && !by("cargo:winapi@0.3.0").dev && !by("cargo:serde@1.0.0").dev);
        assert!(!by("cargo:deep@0.2.0").direct);
        assert_eq!(by("cargo:deep@0.2.0").via, vec!["cargo:serde@1.0.0"]);
    }

    #[test]
    fn cargo_lock_without_a_root_package_defers_to_the_manifest() {
        // No workspace member in the lock means the lock cannot say what is direct; the manifest that declares it does
        let t = "version = 3\n\n[[package]]\nname = \"netprobe\"\nversion = \"0.4.2\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"inner\",\n]\n\n[[package]]\nname = \"inner\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let l = parse("Cargo.lock", t).unwrap();
        assert!(l.direct_ids.is_none());
        let md: BTreeMap<String, bool> = [("netprobe".to_string(), false)].into();
        let p = packages(&l, Some(&md));
        assert!(p.iter().find(|x| x.p == "cargo:netprobe@0.4.2").unwrap().direct);
        assert!(!p.iter().find(|x| x.p == "cargo:inner@1.0.0").unwrap().direct);
    }

    #[test]
    fn cargo_lock_same_name_two_versions_direct_by_id() {
        let t = "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"syn 2.0.60\",\n \"dep\",\n]\n\n[[package]]\nname = \"dep\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"syn 1.0.109\",\n]\n\n[[package]]\nname = \"syn\"\nversion = \"1.0.109\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"syn\"\nversion = \"2.0.60\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let l = parse("Cargo.lock", t).unwrap();
        let p = packages(&l, None);
        let by = |id: &str| p.iter().find(|x| x.p == id).unwrap();
        assert!(by("cargo:syn@2.0.60").direct);
        assert!(!by("cargo:syn@1.0.109").direct, "the older syn is only reached through dep");
        assert_eq!(by("cargo:syn@1.0.109").via, vec!["cargo:dep@1.0.0"]);
    }

    #[test]
    fn go_mod_vendor_work_and_sum_dispatch() {
        let m = "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/a/b v1.2.0\n\tgithub.com/c/d v0.1.0 // indirect\n)\n\nreplace github.com/a/b => github.com/a/b v1.3.0\n";
        let l = parse("go.mod", m).unwrap();
        assert!(ids(&l).contains(&"go:github.com/a/b@v1.3.0".to_string()), "replace changes the build list: {:?}", ids(&l));
        let v = "# github.com/a/b v1.2.0\n## explicit; go 1.20\ngithub.com/a/b\n";
        let l = parse("vendor/modules.txt", v).unwrap();
        assert_eq!(ids(&l), vec!["go:github.com/a/b@v1.2.0"]);
        assert!(is_lockfile("svc/vendor/modules.txt"));
        assert!(!is_lockfile("docs/modules.txt"));
        let w = parse("go.work", "go 1.22\n\nuse (\n\t./svc\n\t./lib\n)\n").unwrap();
        assert_eq!(w.members, vec!["./svc", "./lib"]);
    }

    #[test]
    fn requirements_paths_and_include_following() {
        for p in ["requirements.txt", "requirements/base.txt", "requirements/prod.txt", "dev-requirements.txt", "constraints.txt", "requirements-dev.txt", "a/b/requirements_test.txt"] {
            assert!(is_requirements(p), "{p}");
        }
        for p in ["notes.txt", "CMakeLists.txt", "node_modules/x/requirements.txt", "robots.txt"] {
            assert!(!is_requirements(p), "{p}");
        }
        assert!(is_requirements_in("requirements.in"));
        let mut files: HashMap<String, String> = HashMap::new();
        files.insert("requirements/base.txt".into(), "idna==3.7\n".into());
        let mut fetch = |p: &str| files.get(p).cloned();
        let l = parse_with("requirements/prod.txt", "-r base.txt\nflask>=2\nrequests==2.32.3\n", &mut fetch).unwrap();
        assert!(ids(&l).contains(&"pypi:idna@3.7".to_string()), "{:?}", ids(&l));
        assert!(ids(&l).contains(&"pypi:requests@2.32.3".to_string()));
        assert_eq!(l.unpinned.len(), 1);
        assert_eq!(l.unpinned[0].name, "flask");
    }

    #[test]
    fn unsupported_lockfiles_are_named_not_ignored() {
        assert!(unsupported("app/Gemfile.lock").is_some());
        assert!(unsupported("bun.lockb").unwrap().contains("bun.lock"));
        assert!(unsupported("package-lock.json").is_none());
        assert_eq!(manifest_for("sub/bun.lock"), Some("package.json"));
        assert_eq!(manifest_for("uv.lock"), Some("pyproject.toml"));
    }

    #[test]
    fn yarn_alias_non_ascii_key_does_not_panic() {
        let t = "# yarn lockfile v1\n\n\n\"é-pkg@^1.0.0\":\n  version \"1.0.0\"\n";
        let l = parse("yarn.lock", t).unwrap();
        assert_eq!(l.entries.len(), 1);
    }

    #[test]
    fn pnpm_8_v6_root_deps_scoped_keys_and_peer_suffix() {
        // lockfileVersion '6.0' (pnpm 8): direct deps at the top level with specifier/version, `/name@ver` keys, `dev` flags
        let t = "lockfileVersion: '6.0'\n\nsettings:\n  autoInstallPeers: true\n\ndependencies:\n  '@tanstack/react-router':\n    specifier: ^1.120.3\n    version: 1.120.3\n  a:\n    specifier: ^1.0.0\n    version: 1.0.0\n\ndevDependencies:\n  vitest:\n    specifier: ^1.0.0\n    version: 1.6.0\n\npackages:\n\n  /@tanstack/react-router@1.120.3:\n    resolution: {integrity: sha512-aa}\n    dev: false\n\n  /a@1.0.0:\n    resolution: {integrity: sha512-bb}\n    dependencies:\n      b: 2.0.0\n    dev: false\n\n  /b@2.0.0(react@18.2.0):\n    resolution: {integrity: sha512-cc}\n    dev: false\n\n  /vitest@1.6.0:\n    resolution: {integrity: sha512-dd}\n    dev: true\n";
        let l = parse("pnpm-lock.yaml", t).unwrap();
        let p = packages(&l, None);
        let by = |id: &str| p.iter().find(|x| x.p == id).unwrap_or_else(|| panic!("{id} missing: {p:?}"));
        assert!(by("npm:@tanstack/react-router@1.120.3").direct);
        assert!(by("npm:vitest@1.6.0").direct && by("npm:vitest@1.6.0").dev);
        assert_eq!(by("npm:b@2.0.0").via, vec!["npm:a@1.0.0"]);
    }
}
