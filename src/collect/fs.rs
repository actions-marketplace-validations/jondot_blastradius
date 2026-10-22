//! Reading a file tree: stage 1 (metadata walk), stage 2 (sha256 and simhash of what the hash filter selects), and
//! package detection from what sits on disk. The same analyzer takes files from a local walk, a tar stream from an
//! ssh host, an artifact zip or an image layer, so every source is detected the same way.

use std::collections::BTreeMap;
use std::io::Read;

use sha2::{Digest, Sha256};

use crate::collect::util::{epoch, iso, under, Globs};
use crate::view::{HostFile, HostItem};

pub const MAX_SIMHASH_BYTES: u64 = 1024 * 1024;

// ---- hashes -------------------------------------------------------------------------------------------
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// The simhash: features are the lowercased tokens (runs of `[a-z0-9_]`), weight is the
/// count, feature hash is FNV-1a 64, one vote per bit (bit i is the i-th least significant), ties go to 0.
/// None when the bytes are not UTF-8 text or hold no token.
pub fn simhash64(data: &[u8]) -> Option<String> {
    if data.len() > 1_000_000 || data.contains(&0) {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    let lower = text.to_ascii_lowercase();
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    let mut start = None;
    let bytes = lower.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        let w = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_';
        match (w, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                *counts.entry(&lower[s..i]).or_insert(0) += 1;
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        *counts.entry(&lower[s..]).or_insert(0) += 1;
    }
    if counts.is_empty() {
        return None;
    }
    Some(simhash_from_counts(counts.iter().map(|(t, c)| (t.as_bytes(), *c))))
}

pub fn simhash_from_counts<'a>(feats: impl Iterator<Item = (&'a [u8], i64)>) -> String {
    let mut v = [0i64; 64];
    for (tok, w) in feats {
        let h = fnv1a64(tok);
        for (i, slot) in v.iter_mut().enumerate() {
            if (h >> i) & 1 == 1 {
                *slot += w;
            } else {
                *slot -= w;
            }
        }
    }
    let mut out: u64 = 0;
    for (i, x) in v.iter().enumerate() {
        if *x > 0 {
            out |= 1 << i;
        }
    }
    format!("{out:016x}")
}

pub fn simhash_similarity(a: &str, b: &str) -> Option<f64> {
    let x = u64::from_str_radix(a, 16).ok()?;
    let y = u64::from_str_radix(b, 16).ok()?;
    Some(1.0 - ((x ^ y).count_ones() as f64) / 64.0)
}

// ---- the analyzer ---------------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct FileMeta {
    pub path: String,
    pub size: u64,
    /// Epoch seconds.
    pub mtime: i64,
}

#[derive(Debug, Clone, Default)]
pub struct FileRec {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub sha256: Option<String>,
    pub simhash: Option<String>,
    /// YARA rules that matched this file's content (set by the scan, which reads the file for the rules).
    pub yara_hits: Vec<String>,
}

/// Directories that hold other people's code or build output: a lockfile inside one is not the project's own.
pub const LOCK_SKIP_DIRS: &[&str] = &["node_modules", ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "site-packages", "dist-packages", "target", ".tox", ".cargo", ".npm", ".cache"];

/// A lockfile or requirements file in a project directory (the same files `init --path` and `hunt --path` read).
pub fn is_project_lock(path: &str) -> bool {
    crate::parse::lock::is_lockfile(path) && !path.split('/').rev().skip(1).any(|c| LOCK_SKIP_DIRS.contains(&c))
}

/// Largest file read for package detection: lockfiles can be large (a monorepo's package-lock.json), everything else is small.
pub const LOCK_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// A scan that read nothing: it hashed no file and found no package, declared or installed. Only such a scan proves nothing; a
/// checkout with a lockfile and no file the filter selects has still been read.
pub fn read_nothing(hashed: usize, items: &[crate::view::HostItem]) -> bool {
    hashed == 0 && items.iter().all(|i| i.pkgs.is_empty())
}

/// How many bytes of this file package detection reads, when it needs the file at all.
pub fn capture_limit(path: &str) -> Option<u64> {
    if is_project_lock(path) {
        Some(LOCK_MAX_BYTES)
    } else if crate::query::runtime::is_distro_db(path) {
        Some(16 * 1024 * 1024)
    } else if wants_capture(path) {
        Some(4 * MAX_SIMHASH_BYTES)
    } else {
        None
    }
}

/// Files whose content package detection needs even when the hash filter does not select them.
pub fn wants_capture(path: &str) -> bool {
    (path.ends_with("/package.json") && path.contains("/node_modules/"))
        || (path.ends_with(".dist-info/METADATA") && (path.contains("site-packages/") || path.contains("dist-packages/")))
        || (path.ends_with(".egg-info/PKG-INFO") && (path.contains("site-packages/") || path.contains("dist-packages/")))
        || (path.contains("/conda-meta/") && path.ends_with(".json"))
        || path.contains("_cacache/index-v5/")
        || is_pnpm_index(path)
}

/// A pnpm content-addressable store index file. pnpm 8 and 9 (store v3): `<store>/v3/files/xx/<hash>-index.json`; pnpm 10 (store
/// v10): `<store>/v10/index/xx/<hash>-<name>@<version>.json`. Both hold `{"name","version","files":{...}}`. pnpm 11 keeps its
/// index in `index.db` and a `links/` tree whose `node_modules` package.json files are read like any other.
fn is_pnpm_index(path: &str) -> bool {
    pnpm_index_root(path).is_some()
}

/// (store dir, name@version from the file name when it has one)
fn pnpm_index_root(path: &str) -> Option<(&str, Option<String>)> {
    if path.ends_with("-index.json") {
        return path.find("/v3/files/").map(|i| (&path[..i], None));
    }
    if !path.ends_with(".json") {
        return None;
    }
    let comps: Vec<&str> = path.split('/').collect();
    let n = comps.len();
    if n < 4 || comps[n - 3] != "index" || !comps[n - 4].strip_prefix('v').map(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false) || comps[n - 2].len() != 2 {
        return None;
    }
    let root_len: usize = comps[..n - 4].iter().map(|c| c.len() + 1).sum::<usize>().saturating_sub(1);
    // `<hash>-<name>@<version>.json`, scoped names written with `+` for `/`
    let stem = comps[n - 1].trim_end_matches(".json");
    let named = stem.split_once('-').map(|(_, nv)| nv.replace('+', "/"));
    Some((&path[..root_len], named))
}

pub struct Analyzer {
    globs: Globs,
    pub stage1: u64,
    pub files: Vec<FileRec>,
    docs: BTreeMap<String, Vec<u8>>,
    /// every stage-1 path under a package directory layout we recognise, without content (go, cargo, tool cache)
    paths: Vec<(String, i64)>,
    pub now_epoch: Option<i64>,
    /// Files that should have been read but could not be (path, why): a hash that is not there is never a clean file.
    pub skipped: Vec<(String, String)>,
    /// Files dated after the clock (count, first path, the clock): left out, and said so.
    pub future_files: (u64, String, String),
    /// Lockfiles parsed once, on first use: (path, mtime, packages) and what could not be parsed.
    locks: std::cell::OnceCell<(Vec<(String, i64, Vec<crate::view::LockPackage>)>, Vec<(String, String)>)>,
    /// Directories that hold a requirements file: a `-r other.txt` include sits beside it, so those `.txt` files are read too.
    req_dirs: std::collections::HashSet<String>,
    /// Read certificate files anywhere (images and checkouts), not only the system trust dirs and certifi (hosts).
    pub wide_trust: bool,
    trust: Vec<crate::view::TrustFile>,
    trust_notes: Vec<String>,
}

/// `dir/../x` and `./x` made plain, for a requirements file's `-r` includes.
fn join_norm(dir: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = if rel.starts_with('/') { vec![] } else { dir.split('/').filter(|c| !c.is_empty()).collect() };
    for c in rel.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

impl Analyzer {
    pub fn new<S: AsRef<str>>(globs: &[S], now: Option<&str>) -> Analyzer {
        Analyzer {
            globs: Globs::new(globs),
            stage1: 0,
            files: vec![],
            docs: BTreeMap::new(),
            paths: vec![],
            now_epoch: now.and_then(epoch),
            skipped: vec![],
            future_files: (0, String::new(), now.unwrap_or_default().to_string()),
            locks: std::cell::OnceCell::new(),
            req_dirs: Default::default(),
            wide_trust: false,
            trust: vec![],
            trust_notes: vec![],
        }
    }

    /// The trust stores read so far (path as walked, sorted) and the notes about what was left out.
    pub fn trust_stores(&self) -> (Vec<crate::view::TrustFile>, Vec<String>) {
        let mut t = self.trust.clone();
        t.sort_by(|a, b| a.path.cmp(&b.path));
        (t, self.trust_notes.clone())
    }

    fn add_trust(&mut self, path: &str, bytes: Option<&[u8]>, size: u64, known: bool) {
        if self.trust.len() >= crate::parse::x509::MAX_FILES {
            let n = format!("more than {} certificate files: the rest were not read", crate::parse::x509::MAX_FILES);
            if !self.trust_notes.contains(&n) {
                self.trust_notes.push(n);
            }
            return;
        }
        match bytes {
            Some(b) => {
                let r = crate::parse::x509::read_store(b, known);
                if r.store {
                    self.trust.push(crate::view::TrustFile { path: path.to_string(), certs: r.certs, gaps: r.gaps });
                }
            }
            None => self.trust.push(crate::view::TrustFile {
                path: path.to_string(),
                certs: vec![],
                gaps: vec![format!("{size} bytes is over the {} MiB br reads of a trust store file", crate::parse::x509::MAX_BYTES / (1024 * 1024))],
            }),
        }
    }

    /// Tell the analyzer what a directory holds before its files come in (the walk lists a directory first; ssh has the whole
    /// listing): a requirements file makes its `.txt` neighbours readable as includes.
    pub fn note_dir<'a>(&mut self, dir: &str, names: impl IntoIterator<Item = &'a str>) {
        if names.into_iter().any(|n| is_project_lock(&format!("{}/{n}", dir.trim_end_matches('/'))) && crate::parse::lock::is_requirements(n)) {
            self.req_dirs.insert(dir.trim_end_matches('/').to_string());
        }
    }

    /// How many bytes of this file package detection reads, when it needs the file at all (see [`capture_limit`]).
    pub fn limit_for(&self, path: &str) -> Option<u64> {
        capture_limit(path).or_else(|| crate::parse::x509::store_path(path, self.wide_trust).map(|_| crate::parse::x509::MAX_BYTES)).or_else(|| {
            let (dir, base) = path.rsplit_once('/')?;
            let include = (base.ends_with(".txt") || base.ends_with(".in")) && self.req_dirs.contains(dir) && !path.split('/').rev().skip(1).any(|c| LOCK_SKIP_DIRS.contains(&c));
            include.then_some(1024 * 1024)
        })
    }

    /// The lockfiles and requirements files under the scanned roots, read with the parsers `init --path` and `hunt --path`
    /// use (`checkout::checkout_repo`), and the ones that could not be read as gaps. A checkout on a laptop is then packages
    /// declared in that checkout's files.
    fn lock_report(&self) -> &(Vec<(String, i64, Vec<crate::view::LockPackage>)>, Vec<(String, String)>) {
        self.locks.get_or_init(|| {
            let mut found = vec![];
            let mut gaps = vec![];
            for (path, content) in self.docs.iter().filter(|(p, _)| is_project_lock(p)) {
                let text = String::from_utf8_lossy(content).to_string();
                let dir = path.rsplit_once('/').map(|x| x.0).unwrap_or("");
                let parsed = crate::parse::lock::parse_with(path, &text, &mut |rel: &str| {
                    let k = join_norm(dir, rel);
                    self.docs.get(&k).map(|c| String::from_utf8_lossy(c).to_string())
                });
                match parsed {
                    Some(l) => {
                        let pk = crate::parse::lock::packages(&l, None);
                        if pk.is_empty() {
                            gaps.push(crate::parse::lock::no_packages_gap(path, &crate::parse::lock::NoPackages::Empty));
                        }
                        let mtime = self.paths.iter().find(|(p, _)| p == path).map(|x| x.1).unwrap_or(0);
                        found.push((path.clone(), mtime, pk));
                    }
                    None => gaps.push(crate::parse::lock::no_packages_gap(path, &crate::parse::lock::NoPackages::Unparsed)),
                }
            }
            // seen on disk, never read: a format with no parser, or a lockfile whose bytes were not captured
            for (path, _) in &self.paths {
                let in_skip = path.split('/').rev().skip(1).any(|c| LOCK_SKIP_DIRS.contains(&c));
                if in_skip {
                    continue;
                }
                if crate::parse::lock::is_unsupported_lock(path) {
                    gaps.push(crate::parse::lock::no_packages_gap(path, &crate::parse::lock::NoPackages::Unsupported));
                } else if is_project_lock(path) && !self.docs.contains_key(path) && !self.skipped.iter().any(|s| &s.0 == path) {
                    gaps.push(crate::parse::lock::no_packages_gap(
                        path,
                        &crate::parse::lock::NoPackages::Unreadable("it was seen but its content was not captured (unreadable or over the size br reads)"),
                    ));
                }
            }
            (found, gaps)
        })
    }

    /// What each lockfile declares, for the View's `Host.declared`.
    pub fn declared(&self) -> Vec<crate::view::DeclaredLock> {
        self.lock_report().0.iter().map(|(p, _, pk)| crate::view::DeclaredLock { loc: p.clone(), packages: pk.clone() }).collect()
    }

    /// Lockfiles that were found and could not be read: never a quiet "no packages".
    pub fn lock_gaps(&self) -> Vec<(String, String)> {
        self.lock_report().1.clone()
    }

    /// Every path the walk saw (stage 1) with its mtime, whether or not it was hashed.
    pub fn seen_paths(&self) -> &[(String, i64)] {
        &self.paths
    }

    /// Is this file dated after the clock? Such files are ignored.
    pub fn future(&self, mtime: i64) -> bool {
        self.now_epoch.map(|n| mtime > n).unwrap_or(false)
    }

    fn note_future(&mut self, path: &str) {
        if self.future_files.0 == 0 {
            self.future_files.1 = path.to_string();
        }
        self.future_files.0 += 1;
    }

    /// The gap for files left out because they are dated after the clock, if any.
    pub fn future_gap(&self) -> Option<(String, String)> {
        let (n, first, now) = &self.future_files;
        (*n > 0).then(|| ("files dated after the scan clock".into(), format!("{n} file(s) modified after {now} were left out, e.g. {first}; the clock is the system time unless BR_NOW sets it")))
    }

    pub fn selected(&self, path: &str) -> bool {
        self.globs.matches(path)
    }

    /// Whether the content of this file is needed: to hash it, or for package detection.
    pub fn needs_content(&self, m: &FileMeta) -> bool {
        self.selected(&m.path) || self.limit_for(&m.path).is_some_and(|l| m.size <= l)
    }

    /// Stage 1 for every file; stage 2 when `reader` is given. A file is skipped (not counted) when dated after the clock.
    pub fn add(&mut self, m: FileMeta, reader: Option<&mut dyn Read>) {
        if self.future(m.mtime) {
            self.note_future(&m.path);
            return;
        }
        self.stage1 += 1;
        self.paths.push((m.path.clone(), m.mtime));
        let mut rec = FileRec { path: m.path.clone(), size: m.size, mtime: m.mtime, ..Default::default() };
        let hashed = self.selected(&m.path);
        let limit = self.limit_for(&m.path);
        let capture = limit.is_some_and(|l| m.size <= l);
        let tp = if is_project_lock(&m.path) { None } else { crate::parse::x509::store_path(&m.path, self.wide_trust) };
        if let (Some(known), false) = (tp, capture) {
            self.add_trust(&m.path, None, m.size, known);
        } else if limit.is_some() && !capture {
            self.skipped.push((m.path.clone(), format!("{} bytes is too large to read for package detection", m.size)));
        }
        if let Some(r) = reader {
            if hashed || capture {
                let mut h = Sha256::new();
                let mut head: Vec<u8> = vec![];
                let mut buf = vec![0u8; 1 << 16];
                let mut ok = true;
                loop {
                    match r.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            h.update(&buf[..n]);
                            if (head.len() as u64) <= MAX_SIMHASH_BYTES.max(if capture { limit.unwrap_or(0) } else { 0 }) {
                                head.extend_from_slice(&buf[..n]);
                            }
                        }
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    self.skipped.push((m.path.clone(), "unreadable while hashing".into()));
                }
                if ok {
                    if hashed {
                        rec.sha256 = Some(hex::encode(h.finalize()));
                        if m.size <= MAX_SIMHASH_BYTES {
                            rec.simhash = simhash64(&head);
                        }
                    }
                    if capture {
                        match tp {
                            Some(known) => self.add_trust(&m.path, Some(&head), m.size, known),
                            None => {
                                self.docs.insert(m.path.clone(), head);
                            }
                        }
                    }
                }
            }
        }
        if rec.sha256.is_some() {
            self.files.push(rec);
        }
    }

    pub fn hashed(&self) -> usize {
        self.files.len()
    }

    pub fn simhashed(&self) -> usize {
        self.files.iter().filter(|f| f.simhash.is_some()).count()
    }

    /// (package, file path that revealed it) for every package found.
    pub fn package_paths(&self) -> Vec<(String, String)> {
        let mut out = vec![];
        for (path, _) in &self.paths {
            if let Some((pkg, _, _)) = path_package(path) {
                out.push((pkg, path.clone()));
            }
        }
        for (path, content) in &self.docs {
            for (pkg, _, _) in doc_packages(path, content) {
                out.push((pkg, path.clone()));
            }
            // Distro packages of the runtimes (possible only), from the package database
            if crate::query::runtime::is_distro_db(path) {
                for (n, v) in crate::query::runtime::distro_packages(&String::from_utf8_lossy(content)) {
                    out.push((crate::query::runtime::pseudo_distro(&n, &v), path.clone()));
                }
            }
        }
        // A runtime's install directory (the directory is the path a deletion has to take away)
        let mut roots = std::collections::BTreeSet::new();
        for (path, _) in &self.paths {
            if let Some((n, v, root)) = crate::query::runtime::install_root(path) {
                roots.insert((crate::query::runtime::pseudo(n, &v), root));
            }
        }
        out.extend(roots);
        out
    }

    /// Group into the items a host scan reports: one per place a package manager or a tool put files.
    pub fn items(&self) -> Vec<HostItem> {
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        let mut cache: BTreeMap<(String, i64), std::collections::BTreeSet<String>> = BTreeMap::new();
        for f in &self.files {
            let (kind, loc) = classify(&f.path);
            if kind == "loose-file" && (f.path.contains("_cacache/") || is_pnpm_index(&f.path)) {
                continue;
            }
            let g = groups.entry((kind, loc)).or_default();
            g.files.push(f.clone());
        }
        // packages
        for (path, mtime) in &self.paths {
            if let Some((eco_pkg, kind, loc)) = path_package(path) {
                let g = groups.entry((kind, loc)).or_default();
                g.pkgs.insert(eco_pkg);
                g.at = g.at.max(*mtime);
            }
        }
        for (path, content) in &self.docs {
            for (pkg, kind, loc) in doc_packages(path, content) {
                if kind == "npm-cache" {
                    continue;
                }
                let g = groups.entry((kind, loc)).or_default();
                g.pkgs.insert(pkg);
            }
            // npm cache entries written together share a `time` and form one item
            if let Some(ix) = path.find("_cacache/index-v5/") {
                let loc = path[..ix + 8].to_string();
                for line in String::from_utf8_lossy(content).lines() {
                    let Some((_, js)) = line.split_once('\t') else { continue };
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(js) else { continue };
                    let (Some(key), Some(ms)) = (v["key"].as_str(), v["time"].as_i64()) else { continue };
                    if let Some(p) = npm_cache_key_package(key) {
                        cache.entry((loc.clone(), ms / 1000)).or_default().insert(p);
                    }
                }
            }
        }
        // Runtime install directories (tool cache, Homebrew, nvm, asdf, mise, volta, fnm) and distro package databases
        for (path, mtime) in &self.paths {
            if let Some((n, v, root)) = crate::query::runtime::install_root(path) {
                let g = groups.entry(("runtime-install".to_string(), root)).or_default();
                g.pkgs.insert(crate::query::runtime::pseudo(n, &v));
                g.at = g.at.max(*mtime);
            }
        }
        for (path, content) in &self.docs {
            if crate::query::runtime::is_distro_db(path) {
                let mtime = self.paths.iter().find(|(p, _)| p == path).map(|(_, t)| *t).unwrap_or(0);
                let g = groups.entry(("distro-packages".to_string(), path.clone())).or_default();
                for (n, v) in crate::query::runtime::distro_packages(&String::from_utf8_lossy(content)) {
                    g.pkgs.insert(crate::query::runtime::pseudo_distro(&n, &v));
                }
                g.at = g.at.max(mtime);
            }
        }
        let mut out = vec![];
        for ((kind, loc), g) in groups {
            let mut at = g.at;
            for f in &g.files {
                at = at.max(f.mtime);
            }
            if g.files.is_empty() && g.pkgs.is_empty() {
                continue;
            }
            if at == 0 {
                // no mtime to date a package-only item (npm cache): newest of the index files under it
                at = self.paths.iter().filter(|(p, _)| under(p, &loc)).map(|(_, t)| *t).max().unwrap_or(0);
            }
            let relative = kind == "action-checkout";
            let files = g
                .files
                .iter()
                .map(|f| HostFile {
                    path: if relative { f.path.strip_prefix(&format!("{}/", loc)).unwrap_or(&f.path).to_string() } else { f.path.clone() },
                    sha256: f.sha256.clone().unwrap_or_default(),
                    size: Some(f.size),
                    mtime: Some(iso(f.mtime)),
                    simhash: f.simhash.clone(),
                    yara_hits: f.yara_hits.clone(),
                })
                .collect();
            out.push(HostItem { at: iso(at), kind, loc, pkgs: g.pkgs.into_iter().collect(), files, hidden: false });
        }
        for (path, mtime, pk) in &self.lock_report().0 {
            let set: std::collections::BTreeSet<String> = pk.iter().map(|p| p.p.clone()).collect();
            if !set.is_empty() {
                out.push(HostItem { at: iso(*mtime), kind: "lockfile".into(), loc: path.clone(), pkgs: set.into_iter().collect(), files: vec![], hidden: false });
            }
        }
        for ((loc, t), pkgs) in cache {
            out.push(HostItem { at: iso(t), kind: "npm-cache".into(), loc, pkgs: pkgs.into_iter().collect(), files: vec![], hidden: false });
        }
        out.sort_by(|a, b| (a.at.as_str(), a.loc.as_str()).cmp(&(b.at.as_str(), b.loc.as_str())));
        out
    }
}

#[derive(Default)]
struct Group {
    files: Vec<FileRec>,
    pkgs: std::collections::BTreeSet<String>,
    at: i64,
}

/// (kind, loc) of the item a file belongs to.
pub fn classify(path: &str) -> (String, String) {
    let comps: Vec<&str> = path.split('/').collect();
    let join = |n: usize| comps[..n].join("/");
    // go module cache: .../go/pkg/mod/<module path>@vX/...
    if let Some(i) = find_seq(&comps, &["pkg", "mod"]) {
        if let Some(j) = comps.iter().enumerate().skip(i + 2).find(|(_, c)| c.contains('@')).map(|(j, _)| j) {
            if comps.get(i + 2) != Some(&"cache") {
                return ("go-mod-cache".into(), join(j + 1));
            }
        }
    }
    if let Some(i) = comps.iter().position(|c| *c == "_actions") {
        if comps.len() > i + 4 {
            return ("action-checkout".into(), join(i + 4));
        }
    }
    if let Some(i) = comps.iter().position(|c| *c == "hostedtoolcache") {
        if comps.len() > i + 4 {
            return ("tool-cache".into(), join(i + 4));
        }
    }
    // self-hosted runners keep the tool cache at <runner>/_work/_tool/<tool>/<version>/<arch>
    if let Some(i) = find_seq(&comps, &["_work", "_tool"]) {
        if comps.len() > i + 5 {
            return ("tool-cache".into(), join(i + 5));
        }
    }
    if let Some(i) = comps.iter().position(|c| *c == "node_modules") {
        return ("node_modules".into(), join(i + 1));
    }
    if let Some(i) = comps.iter().position(|c| *c == "site-packages" || *c == "dist-packages") {
        return ("site-packages".into(), join(i + 1));
    }
    if let Some(i) = cargo_registry_at(&comps) {
        if comps.len() > i + 4 {
            return ("cargo-registry".into(), join(i + 4));
        }
    }
    let dir = comps[..comps.len().saturating_sub(1)].join("/");
    ("loose-file".into(), if dir.is_empty() { "/".into() } else { dir })
}

/// Index of the `cargo` (or `.cargo`) component whose next component is `registry`: any cargo home, not only `~/.cargo`
/// (CARGO_HOME=/usr/local/cargo in the official rust images).
fn cargo_registry_at(comps: &[&str]) -> Option<usize> {
    (0..comps.len().saturating_sub(1)).find(|&i| (comps[i] == ".cargo" || comps[i] == "cargo" || comps[i].ends_with("cargo")) && comps[i + 1] == "registry")
}

fn find_seq(comps: &[&str], seq: &[&str]) -> Option<usize> {
    (0..comps.len().saturating_sub(seq.len() - 1)).find(|&i| comps[i..i + seq.len()] == *seq)
}

/// Packages that a path alone names: go modules, cargo crates.
fn path_package(path: &str) -> Option<(String, String, String)> {
    let comps: Vec<&str> = path.split('/').collect();
    if let Some(i) = find_seq(&comps, &["pkg", "mod"]) {
        if comps.get(i + 2) != Some(&"cache") {
            if let Some(j) = comps.iter().enumerate().skip(i + 2).find(|(_, c)| c.contains('@')).map(|(j, _)| j) {
                let module = comps[i + 2..=j].join("/");
                let (m, v) = module.rsplit_once('@')?;
                let (m, v) = (unescape_go(m), unescape_go(v));
                return Some((format!("go:{m}@{v}"), "go-mod-cache".into(), comps[..=j].join("/")));
            }
        }
    }
    // yarn berry (PnP) keeps zips at .yarn/cache/<name>-npm-<version>-<hash>.zip, scoped as @scope-name-npm-...
    if let Some(i) = find_seq(&comps, &[".yarn", "cache"]) {
        if comps.len() == i + 3 {
            if let Some(pkg) = berry_zip_package(comps[i + 2]) {
                return Some((pkg, "yarn-cache".into(), comps[..=i + 1].join("/")));
            }
        }
    }
    // bun: ~/.bun/install/cache/<name>@<version>[@@@1]
    if let Some(i) = find_seq(&comps, &[".bun", "install", "cache"]) {
        if comps.len() > i + 3 {
            let d = comps[i + 3];
            let d = d.split("@@@").next().unwrap_or(d);
            if let Some((n, v)) = d.rsplit_once('@') {
                if !n.is_empty() && v.starts_with(|c: char| c.is_ascii_digit()) {
                    return Some((format!("npm:{n}@{v}"), "bun-cache".into(), comps[..=i + 2].join("/")));
                }
            }
        }
    }
    if let Some(i) = cargo_registry_at(&comps) {
        if comps.get(i + 2) == Some(&"src") && comps.len() > i + 5 {
            let crate_dir = comps[i + 4];
            // name-1.2.3: split at the last '-' followed by a digit
            let idx = crate_dir.rmatch_indices('-').map(|(k, _)| k).find(|&k| crate_dir[k + 1..].starts_with(|c: char| c.is_ascii_digit()))?;
            return Some((format!("cargo:{}@{}", &crate_dir[..idx], &crate_dir[idx + 1..]), "cargo-registry".into(), comps[..=i + 4].join("/")));
        }
    }
    None
}

/// `lodash-npm-4.17.21-6382451519-eb835a2e51.zip` -> `npm:lodash@4.17.21`; `@babel-core-npm-7.1.0-...zip` -> `npm:@babel/core@7.1.0`.
fn berry_zip_package(file: &str) -> Option<String> {
    let stem = file.strip_suffix(".zip")?;
    let (head, rest) = stem.split_once("-npm-")?;
    let ver = rest.split('-').next()?;
    if !ver.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let name = match head.strip_prefix('@') {
        Some(sc) => {
            let (scope, n) = sc.split_once('-')?;
            format!("@{scope}/{n}")
        }
        None => head.to_string(),
    };
    Some(format!("npm:{name}@{ver}"))
}

fn unescape_go(s: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in s.chars() {
        if c == '!' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

pub fn pep503(name: &str) -> String {
    let re = regex::Regex::new(r"[-_.]+").unwrap();
    re.replace_all(&name.to_lowercase(), "-").to_string()
}

/// Packages named by the content of a captured file: package.json, dist-info METADATA, npm cache index entries.
fn doc_packages(path: &str, content: &[u8]) -> Vec<(String, String, String)> {
    let mut out = vec![];
    let text = String::from_utf8_lossy(content);
    if is_pnpm_index(path) {
        if let Some((root, named)) = pnpm_index_root(path) {
            let v = serde_json::from_str::<serde_json::Value>(&text).unwrap_or_default();
            let from_file = named.as_deref().and_then(|nv| nv.rsplit_once('@')).map(|(n, v)| (n.to_string(), v.to_string()));
            let nv = match (v["name"].as_str(), v["version"].as_str()) {
                (Some(n), Some(ver)) => Some((n.to_string(), ver.to_string())),
                _ => from_file,
            };
            if let Some((name, ver)) = nv {
                out.push((format!("npm:{name}@{ver}"), "pnpm-store".to_string(), root.to_string()));
            }
        }
    } else if path.ends_with("/package.json") {
        if let Some(i) = path.rfind("/node_modules/") {
            let rest = &path[i + 14..];
            // node_modules/<name or @scope/name>/package.json only (not a nested file in a package)
            let n = rest.trim_end_matches("/package.json");
            let depth_ok = if n.starts_with('@') { n.matches('/').count() == 1 } else { !n.contains('/') };
            if depth_ok {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let (Some(name), Some(ver)) = (v["name"].as_str(), v["version"].as_str()) {
                        let first = path.find("/node_modules/").unwrap();
                        out.push((format!("npm:{name}@{ver}"), "node_modules".to_string(), path[..first + 13].to_string()));
                    }
                }
            }
        }
    } else if path.ends_with(".dist-info/METADATA") || path.ends_with(".egg-info/PKG-INFO") {
        let (mut name, mut ver) = (None, None);
        for line in text.lines() {
            if line.is_empty() {
                break;
            }
            if let Some(v) = line.strip_prefix("Name:") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version:") {
                ver = Some(v.trim().to_string());
            }
        }
        if let (Some(n), Some(v)) = (name, ver) {
            let at = path.find("site-packages/").map(|i| i + 13).or_else(|| path.find("dist-packages/").map(|i| i + 13));
            if let Some(i) = at {
                out.push((format!("pypi:{}@{v}", pep503(&n)), "site-packages".to_string(), path[..i].to_string()));
            }
        }
    } else if path.contains("/conda-meta/") && path.ends_with(".json") {
        // conda-meta/<name>-<version>-<build>.json
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let (Some(n), Some(ver)) = (v["name"].as_str(), v["version"].as_str()) {
                let i = path.find("/conda-meta/").unwrap();
                out.push((format!("pypi:{}@{ver}", pep503(n)), "conda".to_string(), path[..i].to_string()));
            }
        }
    } else if let Some(i) = path.find("_cacache/index-v5/") {
        let loc = path[..i + 8].to_string();
        for line in text.lines() {
            if let Some((_, js)) = line.split_once('\t') {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(js) {
                    if let Some(key) = v["key"].as_str() {
                        if let Some(p) = npm_cache_key_package(key) {
                            out.push((p, "npm-cache".to_string(), loc.clone()));
                        }
                    }
                }
            }
        }
    }
    out
}

/// `make-fetch-happen:request-cache:https://registry.npmjs.org/@scope/name/-/name-1.2.3.tgz` -> `npm:@scope/name@1.2.3`
pub fn npm_cache_key_package(key: &str) -> Option<String> {
    let url = key.rsplit_once("request-cache:").map(|(_, u)| u).unwrap_or(key);
    let rest = url.split("://").nth(1)?;
    let path = rest.split_once('/')?.1;
    // only the segment(s) right before `/-/` name the package; proxies (Artifactory, Nexus, GitLab) prefix the path
    let (before, file) = path.split_once("/-/")?;
    let before = before.replace("%2f", "/").replace("%2F", "/");
    let segs: Vec<&str> = before.split('/').collect();
    let name = match segs.as_slice() {
        [.., sc, n] if sc.starts_with('@') => format!("{sc}/{n}"),
        [.., n] => n.to_string(),
        [] => return None,
    };
    let file = file.strip_suffix(".tgz")?;
    let base = name.rsplit('/').next()?;
    let ver = file.strip_prefix(&format!("{base}-"))?;
    Some(format!("npm:{name}@{ver}"))
}

/// Walk a real directory. Never follows symlinks; unreadable files are skipped.
/// BR_REMOTE_ROOT as a canonical directory: the prefix applied to every absolute path read, never shown in output.
pub fn remote_root() -> Option<std::path::PathBuf> {
    let r = std::env::var("BR_REMOTE_ROOT").ok().filter(|s| !s.is_empty())?;
    std::fs::canonicalize(r).ok()
}

/// Paths are `/`-separated everywhere downstream. On Windows the walk's `\\` becomes `/` here, once; elsewhere a backslash is
/// a legal file-name character and stays.
pub fn norm_path(p: &str) -> String {
    norm_path_for(p, cfg!(windows))
}

pub fn norm_path_for(p: &str, windows: bool) -> String {
    if windows {
        p.replace('\\', "/").trim_start_matches("//?/").to_string()
    } else {
        p.to_string()
    }
}

pub fn walk_local(root: &std::path::Path, an: &mut Analyzer) -> Vec<(String, String)> {
    let strip = remote_root();
    let mut gaps: Vec<(String, String)> = vec![];
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut ents: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd.flatten().collect(),
            Err(e) => {
                gaps.push((dir.to_string_lossy().to_string(), format!("directory not readable: {e}")));
                continue;
            }
        };
        ents.sort_by_key(|e| e.file_name());
        {
            let names: Vec<String> = ents.iter().map(|e| e.file_name().to_string_lossy().to_string()).collect();
            let shown_dir = norm_path(&match &strip {
                Some(r) => format!("/{}", dir.strip_prefix(r).unwrap_or(&dir).to_string_lossy().trim_start_matches('/')),
                None => dir.to_string_lossy().to_string(),
            });
            an.note_dir(&shown_dir, names.iter().map(|s| s.as_str()));
        }
        for e in ents {
            let p = e.path();
            let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
            if md.file_type().is_symlink() {
                continue;
            }
            if md.is_dir() {
                stack.push(p);
                continue;
            }
            if !md.is_file() {
                continue;
            }
            let mtime = md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
            let shown = norm_path(&match &strip {
                Some(r) => format!("/{}", p.strip_prefix(r).unwrap_or(&p).to_string_lossy().trim_start_matches('/')),
                None => p.to_string_lossy().to_string(),
            });
            let meta = FileMeta { path: shown.clone(), size: md.len(), mtime };
            crate::collect::progress::tick(|el| format!("scanning {}: {} files walked, {} hashed, {el} elapsed", dir.display(), an.stage1, an.files.len()));
            if an.future(mtime) {
                an.note_future(&shown);
                continue;
            }
            if an.needs_content(&meta) {
                match std::fs::File::open(&p) {
                    Ok(mut f) => an.add(meta, Some(&mut f)),
                    Err(er) => {
                        an.skipped.push((shown, format!("cannot open: {er}")));
                        an.add(meta, None)
                    }
                }
            } else {
                an.add(meta, None);
            }
        }
    }
    gaps
}

/// What this machine shows about its own role: Some("runner") for an actions-runner or gitlab-runner install, a
/// `/home/runner/_work` tree, or RUNNER_* in the environment of a runner job. Never guessed from a name.
pub fn detect_runner() -> Option<String> {
    let root = remote_root();
    let at = |p: &str| -> std::path::PathBuf {
        match &root {
            Some(r) => r.join(p.trim_start_matches('/')),
            None => std::path::PathBuf::from(p),
        }
    };
    let mut hit = at("/home/runner/_work").exists() || at("/etc/gitlab-runner/config.toml").exists() || at("/opt/actions-runner/.runner").exists() || at("/actions-runner/.runner").exists();
    if !hit {
        for base in ["/home", "/Users"] {
            if let Ok(rd) = std::fs::read_dir(at(base)) {
                for e in rd.flatten() {
                    if e.path().join("actions-runner/.runner").exists() || e.path().join("_work/_PipelineMapping").exists() {
                        hit = true;
                        break;
                    }
                }
            }
        }
    }
    if !hit && root.is_none() {
        hit = std::env::var("GITHUB_ACTIONS").map(|v| v == "true").unwrap_or(false) && std::env::var("RUNNER_OS").is_ok();
    }
    hit.then(|| "runner".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_paths_are_normalised_once_and_then_classify() {
        let p = norm_path_for(r"C:\Users\dev\proj\node_modules\lodash\package.json", true);
        assert_eq!(p, "C:/Users/dev/proj/node_modules/lodash/package.json");
        assert!(wants_capture(&p));
        assert_eq!(norm_path_for(r"\\?\C:\x\y", true), "C:/x/y");
        assert_eq!(norm_path_for(r"/home/a\b", false), r"/home/a\b");
        assert!(crate::parse::lock::is_lockfile(r"C:\proj\package-lock.json"));
    }

    #[test]
    fn simhash_is_stable() {
        // empty and non-text
        assert_eq!(simhash64(b"   "), None);
        assert_eq!(simhash64(&[0xff, 0xfe]), None);
        // identical text, identical hash; one changed word moves few bits
        let a: String = (0..60).map(|i| format!("word{i} ")).collect();
        let b = a.replace("word7 ", "other7 ");
        let (ha, hb) = (simhash64(a.as_bytes()).unwrap(), simhash64(b.as_bytes()).unwrap());
        assert_eq!(ha, simhash64(a.as_bytes()).unwrap());
        assert!(simhash_similarity(&ha, &hb).unwrap() > 0.8);
    }

    #[test]
    fn contract_vectors() {
        assert_eq!(fnv1a64(b"foobar"), 0x85944171f73967e8);
        let a: String = (0..60).map(|i| format!("word{i} ")).collect::<String>().trim_end().to_string() + "\n";
        let b = a.replace("word7 ", "other7 ");
        assert_eq!(simhash64(a.as_bytes()).as_deref(), Some("26b40a7da4a3175c"));
        assert_eq!(simhash64(b.as_bytes()).as_deref(), Some("26b40b7da4a3170c"));
        assert_eq!(simhash64(b"x").as_deref(), Some("af63f54c86021707"));
        assert_eq!(simhash64(b""), None);
        assert_eq!(simhash64(b"--- ,,, "), None);
        assert_eq!(simhash64(b"ab\0c"), None);
        assert_eq!(simhash64(&[0xff, 0xfe, 0x61, 0x62, 0x63]), None);
        assert_eq!(simhash_similarity("26b40a7da4a3175c", "6db23adefb20a89b"), Some(0.484375));
    }

    #[test]
    fn fnv_vector() {
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a64(b"a"), 0xaf63dc4c8601ec8c);
    }

    #[test]
    fn classify_paths() {
        assert_eq!(classify("/Users/k/go/pkg/mod/github.com/x/y@v1.0.0/a/b.so").0, "go-mod-cache");
        assert_eq!(classify("/home/r/_work/_actions/o/r/abc/dist/index.js"), ("action-checkout".into(), "/home/r/_work/_actions/o/r/abc".into()));
        assert_eq!(classify("/opt/hostedtoolcache/netprobe/0.4.2/x64/netprobe").1, "/opt/hostedtoolcache/netprobe/0.4.2/x64");
        assert_eq!(classify("/w/portal/node_modules/a/b.js").1, "/w/portal/node_modules");
        assert_eq!(classify("/tmp/.cache/upd.js").0, "loose-file");
    }

    #[test]
    fn npm_keys() {
        assert_eq!(
            npm_cache_key_package("make-fetch-happen:request-cache:https://registry.npmjs.org/@tanstack/react-router/-/react-router-1.120.3.tgz"),
            Some("npm:@tanstack/react-router@1.120.3".into())
        );
        assert_eq!(npm_cache_key_package("make-fetch-happen:request-cache:https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"), Some("npm:left-pad@1.3.0".into()));
    }

    #[test]
    fn go_and_cargo() {
        let (p, _, _) = path_package("/h/go/pkg/mod/github.com/!azure/x@v1.2.3/f.go").unwrap();
        assert_eq!(p, "go:github.com/Azure/x@v1.2.3");
        let (p, _, _) = path_package("/h/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde_json-1.0.100/src/lib.rs").unwrap();
        assert_eq!(p, "cargo:serde_json@1.0.100");
    }

    #[test]
    fn other_package_homes() {
        assert_eq!(path_package("/usr/local/cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.200/src/lib.rs").unwrap().0, "cargo:serde@1.0.200");
        assert_eq!(classify("/home/r/actions-runner/_work/_tool/node/20.11.0/x64/bin/node").0, "tool-cache");
        assert_eq!(path_package("/p/.yarn/cache/lodash-npm-4.17.21-6382451519-eb835a2e51.zip").unwrap().0, "npm:lodash@4.17.21");
        assert_eq!(path_package("/p/.yarn/cache/@babel-core-npm-7.1.0-abc-def.zip").unwrap().0, "npm:@babel/core@7.1.0");
        assert_eq!(path_package("/h/.bun/install/cache/left-pad@1.3.0").unwrap().0, "npm:left-pad@1.3.0");
        assert_eq!(classify("/usr/lib/python3/dist-packages/requests/api.py").0, "site-packages");
        let d = doc_packages("/usr/lib/python3/dist-packages/Foo_Bar-1.2.egg-info/PKG-INFO", b"Metadata-Version: 1.1\nName: Foo_Bar\nVersion: 1.2\n\nbody");
        assert_eq!(d[0].0, "pypi:foo-bar@1.2");
        let c = doc_packages("/opt/conda/conda-meta/numpy-1.26.0-py311.json", br#"{"name":"numpy","version":"1.26.0"}"#);
        assert_eq!(c[0].0, "pypi:numpy@1.26.0");
    }

    #[test]
    fn npm_cache_key_behind_a_proxy() {
        assert_eq!(npm_cache_key_package("make-fetch-happen:request-cache:https://artifactory.acme.com/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz").unwrap(), "npm:lodash@4.17.21");
        assert_eq!(npm_cache_key_package("make-fetch-happen:request-cache:https://nexus.acme.com/repository/npm/@scope/name/-/name-1.0.0.tgz").unwrap(), "npm:@scope/name@1.0.0");
    }

    #[test]
    fn pnpm_store_index_shapes() {
        // pnpm 9 (store v3): the shape pnpm writes, with per-file integrity and mode
        let v3 = br#"{"name":"left-pad","version":"1.3.0","requiresBuild":false,"files":{"package.json":{"checkedAt":1727000000000,"integrity":"sha512-AAAA","mode":420,"size":1013},"index.js":{"checkedAt":1727000000000,"integrity":"sha512-BBBB","mode":420,"size":790}}}"#;
        let p3 = "/home/u/.local/share/pnpm/store/v3/files/ab/cdef0123-index.json";
        assert!(is_pnpm_index(p3));
        assert_eq!(doc_packages(p3, v3), vec![("npm:left-pad@1.3.0".to_string(), "pnpm-store".to_string(), "/home/u/.local/share/pnpm/store".to_string())]);
        // pnpm 10 (store v10): `index/xx/<hash>-<name>@<version>.json`, scoped names with `+`
        let p10 = "/Users/u/Library/pnpm/store/v10/index/ab/cdef0123-@types+node@22.1.0.json";
        assert!(is_pnpm_index(p10));
        assert_eq!(doc_packages(p10, br#"{"name":"@types/node","version":"22.1.0","files":{}}"#)[0].0, "npm:@types/node@22.1.0");
        // a real pnpm 10.x file from this machine's store (checkedAt in ms, 3-field entries)
        let real = "/Users/jondot/Library/pnpm/store/v10/index/00/007d862a2642ce435d6711075aeab31194b2d6d1ae814e3cf540a26364ff75-is-decimal@2.0.1.json";
        let body = br#"{"name":"is-decimal","version":"2.0.1","requiresBuild":false,"files":{"license":{"checkedAt":1790489826446,"integrity":"sha512-cQvy4TvDNGTww5W7wo7SHRjv/0G8g3u/v8V2BhwwrAM+M5M2Z7W8hy+cQrU+e4exnULY2LrZ0EQqBk6Fj/Sdrw==","mode":420,"size":1099}}}"#;
        assert_eq!(doc_packages(real, body)[0], ("npm:is-decimal@2.0.1".to_string(), "pnpm-store".to_string(), "/Users/jondot/Library/pnpm/store".to_string()));
        // no name in the body: the file name still says it
        let got = doc_packages(p10, br#"{"files":{}}"#);
        assert_eq!(got[0], ("npm:@types/node@22.1.0".to_string(), "pnpm-store".to_string(), "/Users/u/Library/pnpm/store".to_string()));
        // other json files under an index dir are not store indexes
        assert!(!is_pnpm_index("/x/node_modules/index/ab/foo.json"));
        assert!(!is_pnpm_index("/x/v10/index/abc/foo.json"));
    }
}

#[cfg(test)]
mod future_tests {
    use super::*;

    #[test]
    fn files_dated_after_the_clock_are_counted_and_named() {
        let d = std::env::temp_dir().join(format!("br-future-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("index.js"), "x").unwrap();
        let mut an = Analyzer::new(&["**/*.js"], Some("2001-01-01T00:00:00Z"));
        let _ = walk_local(&d, &mut an);
        assert_eq!(an.stage1, 0);
        let (scope, why) = an.future_gap().expect("a gap, never a silent 0");
        assert_eq!(scope, "files dated after the scan clock");
        assert!(why.starts_with("1 file(s) modified after 2001-01-01T00:00:00Z") && why.contains("index.js"), "{why}");
        let mut an = Analyzer::new(&["**/*.js"], None);
        let _ = walk_local(&d, &mut an);
        assert!(an.future_gap().is_none());
        std::fs::remove_dir_all(&d).ok();
    }
}
