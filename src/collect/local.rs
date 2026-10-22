//! Scan this machine's own disk.

use std::path::Path;

use crate::collect::fs::{simhash_similarity, walk_local, Analyzer};
use crate::collect::util::{num, plural, secs};
use crate::collect::{brx, config};
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::query::iocs::{parse_ioc, IocKind};
use crate::store::Store;
use crate::view::HostItem;

pub struct Match {
    pub path: String,
    pub sha256: String,
    pub indicator: String,
    pub advisory: String,
    pub sim: Option<f64>,
}

/// A package found on disk that an advisory in the index names.
pub struct PkgMatch {
    /// `eco:name@version` as the scan read it
    pub pkg: String,
    /// where it sits (the item's location)
    pub loc: String,
    pub advisory: String,
}

/// What the YARA pass did: rules compiled, the hits, and the files that carry them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct YaraSummary {
    pub rules: usize,
    pub hits: usize,
    pub files: usize,
    pub evaluated: usize,
}

/// One YARA hit, with the file's hash so the hit is a finding of its own (the rules' hash travels with the scan).
#[derive(Debug, Clone, PartialEq)]
pub struct YaraHit {
    pub rule: String,
    pub path: String,
    pub sha256: String,
}

impl LocalInfo {
    /// The scan hashed no file and found no package (see [`crate::collect::fs::read_nothing`]).
    pub fn read_nothing(&self) -> bool {
        crate::collect::fs::read_nothing(self.hashed, &self.items)
    }
}

pub struct LocalInfo {
    pub host: String,
    pub known: bool,
    pub roots: Vec<String>,
    pub items: Vec<HostItem>,
    pub matches: Vec<Match>,
    /// packages on disk that an indexed advisory names, apart from the file matches above
    pub pkg_matches: Vec<PkgMatch>,
    /// false when there is no index here, or it holds no advisory, so nothing was compared
    pub compared: bool,
    pub yara: Option<YaraSummary>,
    /// every rule that matched a file, with the file's path and sha256
    pub yara_hits: Vec<YaraHit>,
    /// the hash filter was turned off (`--hash-all`)
    pub hash_all: bool,
    /// declared packages of the lockfiles found under the roots
    pub declared: Vec<crate::view::DeclaredLock>,
    /// The trust stores read under the roots (system trust dirs, certifi bundles) and what was left out
    pub trust: crate::view::TrustSet,
    pub hashed: usize,
    pub simhashed: usize,
    pub stage1: u64,
    pub secs: u64,
    pub kind: Option<String>,
    pub gaps: Vec<(String, String)>,
    pub rules_sha256: Option<String>,
    /// Files left out because they are dated after the clock (shown, not a gap: a scan at that clock could not have seen them).
    pub future: Option<String>,
}

const YARA_MAX_FILE: u64 = 64 * 1024 * 1024;
const SKIP_TOP: &[&str] = &["/proc", "/sys", "/dev", "/run", "/snap", "/System/Volumes", "/Volumes", "/private/var/vm", "/mnt", "/media"];

fn index_indicators(ctx: &Ctx) -> Vec<(String, crate::query::iocs::Ioc)> {
    let Ok(st) = Store::open(ctx, false) else { return vec![] };
    let mut out = vec![];
    for a in config::advisories(ctx, &st) {
        for t in &a.affected {
            if t.starts_with("sha256:") || t.starts_with("simhash:") {
                if let Ok(i) = parse_ioc(t, None) {
                    out.push((a.id.clone(), i));
                }
            }
        }
    }
    out
}

/// The package indicators of every advisory in the index: each package's own versions and ranges decide a match.
fn package_indicators(ctx: &Ctx) -> Vec<(String, crate::query::iocs::Ioc)> {
    let Ok(st) = Store::open(ctx, false) else { return vec![] };
    let mut out = vec![];
    for a in config::advisories(ctx, &st) {
        for p in &a.packages {
            if let Some(i) = crate::query::iocs::Ioc::from_package(p) {
                out.push((a.id.clone(), i));
            }
        }
        if a.packages.is_empty() {
            for t in a.affected.iter().filter(|t| !t.starts_with("sha256:") && !t.starts_with("simhash:") && !t.starts_with("action:")) {
                if let Ok(i) = parse_ioc(t, None) {
                    if i.kind == IocKind::Pkg {
                        out.push((a.id.clone(), i));
                    }
                }
            }
        }
    }
    out
}

/// The packages a scan found that the index's advisories name. `eco:name@version` is how a scan writes a package.
pub fn package_matches(items: &[HostItem], inds: &[(String, crate::query::iocs::Ioc)]) -> Vec<PkgMatch> {
    let mut out: Vec<PkgMatch> = vec![];
    for it in items {
        for p in &it.pkgs {
            let Some((eco_name, ver)) = p.rsplit_once('@').filter(|(a, _)| a.contains(':')) else { continue };
            let Some((eco, name)) = eco_name.split_once(':') else { continue };
            for (adv, ioc) in inds {
                if crate::query::iocs::match_pkg(ioc, eco, name, ver) && !out.iter().any(|m| m.pkg == *p && m.loc == it.loc && m.advisory == *adv) {
                    out.push(PkgMatch { pkg: p.clone(), loc: it.loc.clone(), advisory: adv.clone() });
                }
            }
        }
    }
    out
}

/// The verdict line of a local scan: packages and files are counted apart, so a package match is never "no match".
pub fn verdict_line(pkgs: usize, files: usize) -> String {
    format!(
        "{} {} indicators in the index; {} {} by hash",
        plural_word(pkgs, "package", "packages"),
        if pkgs == 1 { "matches" } else { "match" },
        files,
        if files == 1 { "file matches" } else { "files match" }
    )
}

fn plural_word(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Print what the scan found against the index: the verdict line, then each package and file that matched.
pub fn print_verdict(info: &LocalInfo) {
    if !info.compared {
        println!(
            "nothing to compare with: the index holds no advisory (br hunt --advisory ID or br advisory note ID --ioc ... adds one); {} hashed, {} read",
            plural(info.hashed, "file"),
            plural(info.items.iter().map(|i| i.pkgs.len()).sum::<usize>(), "package")
        );
    } else {
        println!("{}", verdict_line(info.pkg_matches.len(), info.matches.len()));
    }
    if !info.pkg_matches.is_empty() {
        println!("PACKAGES that match indicators in the index ({})", info.pkg_matches.len());
        for m in &info.pkg_matches {
            println!("  {}  in {}  {}", m.pkg, m.loc, m.advisory);
        }
    }
    if !info.matches.is_empty() {
        println!("MATCHES with indicators in the index ({})", info.matches.len());
        for m in &info.matches {
            let how = match m.sim {
                None => "exact".to_string(),
                Some(s) => format!("similar {s:.2}"),
            };
            let ind: String = m.indicator.chars().take(40).collect();
            println!("  {}  sha256 {}  {}  {}  {}", m.path, &m.sha256[..12], ind, m.advisory, how);
        }
    }
    if let Some(y) = &info.yara {
        println!("YARA: {}, {} in {}", plural_word(y.rules, "rule", "rules"), plural_word(y.hits, "hit", "hits"), plural_word(y.files, "file", "files"));
        // The files that hit, with the rule and the file's hash, so the line can be acted on
        for h in &info.yara_hits {
            println!("  {}  {}  sha256 {}", h.rule, h.path, &h.sha256[..h.sha256.len().min(12)]);
        }
    }
}

pub fn local_scan(ctx: &Ctx, path: &[String], hash: &[String], announce: bool) -> BrResult<LocalInfo> {
    local_scan_with(ctx, path, hash, announce, None, false)
}

/// With `yara` (a rules file), every hashed file is also matched against the rules and the hits travel with the file.
pub fn local_scan_with(ctx: &Ctx, path: &[String], hash: &[String], announce: bool, yara: Option<&str>, hash_all: bool) -> BrResult<LocalInfo> {
    let rules = match yara {
        Some(p) => Some(crate::out::yara::compile(p)?),
        None => None,
    };
    let host = brx::local_host(ctx)?;
    let known = Store::open(ctx, false).map(|s| s.source(&host).is_some()).unwrap_or(false);
    let defaulted = path.is_empty();
    let roots: Vec<String> = if defaulted { default_roots()? } else { path.to_vec() };
    let mut real: Vec<(String, String)> = vec![];
    for r in &roots {
        let ex = shellexpand(r);
        let full = match crate::collect::fs::remote_root() {
            Some(rr) if ex.starts_with('/') => rr.join(ex.trim_start_matches('/')).to_string_lossy().to_string(),
            _ => ex,
        };
        let p = std::fs::canonicalize(full).ok().filter(|p| p.is_dir());
        match p {
            Some(p) => real.push((r.clone(), p.to_string_lossy().to_string())),
            None => {
                return Err(BrError::new(format!("{} does not exist on {host}", r.trim_end_matches('/').to_string().if_empty("/")), Some("check --path; nothing was scanned and nothing was written")));
            }
        }
    }
    // One filter for every root, --path included. --hash-all turns it off, and the stage line says so. The rules read
    // files the filter does not select, but only a file that hits is hashed on top of the filter (it needs a hash to be a finding).
    // The roots are recorded as absolute paths on the scanned machine (a relative `--path .` says nothing about coverage)
    let rr0 = crate::collect::fs::remote_root();
    let roots: Vec<String> = real
        .iter()
        .map(|(given, abs)| {
            let shown = match &rr0 {
                Some(r) => std::path::Path::new(abs).strip_prefix(r).map(|p| format!("/{}", p.to_string_lossy())).unwrap_or_else(|_| given.clone()),
                None => abs.clone(),
            };
            if shown.is_empty() {
                "/".to_string()
            } else {
                shown
            }
        })
        .collect();
    let mut globs = config::hash_filter(ctx);
    globs.extend(hash.iter().cloned());
    if hash_all {
        globs = vec!["**".to_string()];
    }
    let started = std::time::Instant::now();
    let mut an = Analyzer::new(&globs, Some(&ctx.now));
    let mut gaps: Vec<(String, String)> = vec![];
    for (_, abs) in &real {
        let rr = crate::collect::fs::remote_root();
        let is_root = abs == "/" || rr.as_ref().map(|r| std::path::Path::new(abs) == r.as_path()).unwrap_or(false);
        if is_root {
            if let Err(e) = std::fs::read_dir(abs) {
                gaps.push((abs.clone(), format!("directory not readable: {e}")));
            }
            if let Ok(rd) = std::fs::read_dir(abs) {
                let mut ents: Vec<_> = rd.flatten().collect();
                ents.sort_by_key(|e| e.file_name());
                for e in ents {
                    let p = e.path();
                    let ps = p.to_string_lossy().to_string();
                    if SKIP_TOP.contains(&ps.as_str()) {
                        continue;
                    }
                    if p.is_dir() && !e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
                        gaps.extend(walk_local(&p, &mut an));
                    }
                }
            }
        } else {
            gaps.extend(walk_local(Path::new(abs), &mut an));
        }
    }
    // The rules read every file the walk saw (up to 64 MB each), not only the ones the hash filter selected. A file that
    // hits is hashed even when the filter did not select it, so the hit has a sha256 and a path to stand on.
    let mut yara_sum: Option<YaraSummary> = None;
    let mut yara_hits: Vec<YaraHit> = vec![];
    let mut yara_gaps: Vec<(String, String)> = vec![];
    if let Some(r) = &rules {
        let rr = crate::collect::fs::remote_root();
        let disk = |p: &str| -> std::path::PathBuf {
            match &rr {
                Some(r) => r.join(p.trim_start_matches('/')),
                None => std::path::PathBuf::from(p),
            }
        };
        let mut errs = 0usize;
        let mut first_err = String::new();
        let mut sum = YaraSummary { rules: r.names.len(), ..Default::default() };
        let mut big = 0usize;
        let hashed_paths: std::collections::HashSet<String> = an.files.iter().map(|f| f.path.clone()).collect();
        let seen: Vec<(String, i64)> = an.seen_paths().to_vec();
        let mut extra: Vec<crate::collect::fs::FileRec> = vec![];
        let mut hit_files = std::collections::BTreeSet::new();
        let mut scan_one = |path: &str, hashed: Option<usize>, an_files: &mut Vec<crate::collect::fs::FileRec>, extra: &mut Vec<crate::collect::fs::FileRec>, mtime: i64| {
            let dp = disk(path);
            let size = std::fs::symlink_metadata(&dp).map(|m| m.len()).unwrap_or(0);
            if size > YARA_MAX_FILE {
                big += 1;
                return;
            }
            let data = match std::fs::read(&dp) {
                Ok(d) => d,
                Err(e) => {
                    errs += 1;
                    if first_err.is_empty() {
                        first_err = format!("{path}: {e}");
                    }
                    return;
                }
            };
            sum.evaluated += 1;
            match r.scan(&data) {
                Ok(h) if !h.is_empty() => {
                    sum.hits += h.len();
                    hit_files.insert(path.to_string());
                    let sha = crate::collect::fs::sha256_hex(&data);
                    for rule in &h {
                        yara_hits.push(YaraHit { rule: rule.clone(), path: path.to_string(), sha256: sha.clone() });
                    }
                    match hashed {
                        Some(i) => an_files[i].yara_hits = h,
                        None => extra.push(crate::collect::fs::FileRec {
                            path: path.to_string(),
                            size,
                            mtime,
                            sha256: Some(sha),
                            simhash: if size <= crate::collect::fs::MAX_SIMHASH_BYTES { crate::collect::fs::simhash64(&data) } else { None },
                            yara_hits: h,
                        }),
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    errs += 1;
                    if first_err.is_empty() {
                        first_err = format!("{path}: {e}");
                    }
                }
            }
        };
        let by_path: std::collections::HashMap<String, usize> = an.files.iter().enumerate().map(|(i, f)| (f.path.clone(), i)).collect();
        let mut files = std::mem::take(&mut an.files);
        for (path, mtime) in &seen {
            let hashed = by_path.get(path).copied();
            if hashed.is_none() && hashed_paths.contains(path) {
                continue;
            }
            scan_one(path, hashed, &mut files, &mut extra, *mtime);
        }
        files.extend(extra);
        sum.files = hit_files.len();
        an.files = files;
        if errs > 0 {
            yara_gaps.push(("yara".into(), format!("{errs} file(s) could not be matched against the rules, e.g. {first_err}")));
        }
        if big > 0 {
            yara_gaps.push(("yara".into(), format!("{big} file(s) over 64 MB were not matched against the rules")));
        }
        yara_sum = Some(sum);
    }
    let items = an.items();
    let declared = an.declared();
    let trust = {
        let (files, notes) = an.trust_stores();
        crate::view::TrustSet { files, notes, api_calls: 0, read: true }
    };
    if !an.skipped.is_empty() {
        gaps.push(("files not read in full".into(), format!("{} file(s), e.g. {} ({})", an.skipped.len(), an.skipped[0].0, an.skipped[0].1)));
    }
    gaps.extend(an.lock_gaps());
    gaps.extend(yara_gaps);
    if gaps.len() > 1 {
        let n = gaps.len();
        let first = gaps[0].clone();
        let unreadable = gaps.iter().filter(|g| g.1.starts_with("directory not readable")).count();
        if unreadable > 1 {
            gaps.retain(|g| !g.1.starts_with("directory not readable"));
            gaps.push(("unreadable directories".into(), format!("{unreadable} directories could not be read, e.g. {} ({}); run as a user that can read them", first.0, first.1)));
        }
        let _ = n;
    }
    let hashed = an.hashed();
    let simhashed = an.simhashed();
    let stage1 = an.stage1;
    let t1 = started.elapsed().as_secs();
    if announce {
        println!("scanning {host} locally; nothing leaves this machine");
        if !known {
            println!("  {host} is not in the index yet: importing the result registers it as a new import-only host");
        }
        println!("  roots: {}", roots.join(", "));
        if defaulted {
            println!("  (your home directory and the package and tool caches br knows about; br scan --local --path / scans the whole machine)");
        }
        println!("stage 1: {} files in {} (path, size, mtime, mode; hashing runs in the same pass)", num(stage1), secs(t1));
        if let Some((_, why)) = an.future_gap() {
            println!("  note: {why}");
        }
        let extra = if hash.is_empty() { String::new() } else { format!(" (+{} from --hash)", hash.len()) };
        // The line names the filter that was applied: the globs, or none when --hash-all turned it off
        let filter = if hash_all { "filter off: hashing every file".to_string() } else { format!("filter {} globs{}", globs.len(), extra) };
        let read = match &yara_sum {
            Some(y) => format!("; yara read {} (hashed only where the filter selects or a rule hits)", plural(y.evaluated, "file")),
            None => String::new(),
        };
        println!("stage 2: hashed {}, simhashed {}, skipped {}; {}{}", plural(hashed, "file"), simhashed, num(stage1.saturating_sub(hashed as u64)), filter, read);
    }
    let inds = index_indicators(ctx);
    let mut matches = vec![];
    for f in &an.files {
        let Some(sha) = &f.sha256 else { continue };
        for (adv, ioc) in &inds {
            let (ok, sim) = match ioc.kind {
                IocKind::Sha256 => (&ioc.sha == sha, None),
                _ => match f.simhash.as_ref().and_then(|s| simhash_similarity(&ioc.sha, s)) {
                    Some(s) => (s >= ioc.thr - 1e-9, Some(s)),
                    None => (false, None),
                },
            };
            if ok {
                matches.push(Match { path: f.path.clone(), sha256: sha.clone(), indicator: ioc.text.clone(), advisory: adv.clone(), sim });
            }
        }
    }
    let pinds = package_indicators(ctx);
    let pkg_matches = package_matches(&items, &pinds);
    let compared = !(inds.is_empty() && pinds.is_empty());
    if announce {
        println!("  read {} under {} on this machine", plural(stage1 as usize, "file"), real.iter().map(|(_, a)| a.as_str()).collect::<Vec<_>>().join(", "));
    }
    Ok(LocalInfo {
        host,
        known,
        roots,
        items,
        matches,
        pkg_matches,
        compared,
        yara: yara_sum,
        yara_hits,
        hash_all,
        declared,
        trust,
        hashed,
        simhashed,
        stage1,
        secs: started.elapsed().as_secs(),
        kind: crate::collect::fs::detect_runner(),
        gaps,
        rules_sha256: rules.as_ref().map(|r| r.sha256.clone()),
        future: an.future_gap().map(|g| g.1),
    })
}

/// Package and tool caches that live outside a home directory, one row per package manager or tool. They are the same places
/// package detection reads (`fs::classify`); a default scan covers them with the home directory, never the whole disk.
pub const CACHE_ROOTS: &[(&str, &[&str])] = &[
    ("npm", &["/usr/local/lib/node_modules", "/usr/lib/node_modules", "/opt/homebrew/lib/node_modules"]),
    ("pip", &["/usr/lib/python3/dist-packages", "/usr/local/lib/python3"]),
    ("cargo", &["/usr/local/cargo/registry"]),
    ("go", &["/usr/local/go/pkg/mod", "/go/pkg/mod"]),
    // Where the system keeps the certificates it trusts (certifi bundles are found in the language roots above)
    ("system trust stores", &["/etc/ssl/certs", "/etc/pki", "/usr/local/share/ca-certificates", "/usr/share/ca-certificates", "/etc/ca-certificates"]),
    ("github actions tool cache", &["/opt/hostedtoolcache", "/actions-runner/_work/_tool", "/opt/actions-runner/_work/_tool"]),
    ("homebrew", &["/opt/homebrew/Cellar", "/usr/local/Cellar", "/home/linuxbrew/.linuxbrew/Cellar"]),
    ("os packages", &["/var/lib/dpkg", "/lib/apk/db"]),
];

/// The scanning user's home directory, recorded with the scan: the one fact that tells a narrow root from the home.
pub fn scanning_home() -> Option<String> {
    dirs::home_dir().map(|h| h.to_string_lossy().to_string())
}

/// What `scan --local` reads with no `--path`: the user's home directory and the caches above that exist on this machine.
/// `--path /` is the whole machine, and has to be asked for.
pub fn default_roots() -> BrResult<Vec<String>> {
    let home = dirs::home_dir().ok_or_else(|| BrError::new("cannot tell which directory is your home", Some("pass --path DIR (or --path / for the whole machine)")))?;
    let mut roots = vec![home.to_string_lossy().to_string()];
    let rr = crate::collect::fs::remote_root();
    for (_, dirs_) in CACHE_ROOTS {
        for d in *dirs_ {
            let on_disk = match &rr {
                Some(r) => r.join(d.trim_start_matches('/')),
                None => std::path::PathBuf::from(d),
            };
            if on_disk.is_dir() && !roots.iter().any(|r| d.starts_with(&format!("{}/", r.trim_end_matches('/')))) {
                roots.push(d.to_string());
            }
        }
    }
    Ok(roots)
}

fn shellexpand(r: &str) -> String {
    if let Some(rest) = r.strip_prefix("~/").or_else(|| r.strip_prefix("~\\")) {
        if let Some(h) = dirs::home_dir() {
            return h.join(rest).to_string_lossy().to_string();
        }
    }
    r.to_string()
}

trait IfEmpty {
    fn if_empty(self, d: &str) -> String;
}
impl IfEmpty for String {
    fn if_empty(self, d: &str) -> String {
        if self.is_empty() {
            d.to_string()
        } else {
            self
        }
    }
}

#[cfg(test)]
mod r58_tests {
    use super::*;

    // A package on disk that an advisory names is a match of its own, never "no file matches"
    #[test]
    fn packages_and_files_are_counted_apart() {
        let adv = crate::view::AffectedPackage { ecosystem: "npm".into(), name: "evil-pkg".into(), versions: vec!["1.0.0".into()], ranges: vec![] };
        let inds = vec![("GHSA-x".to_string(), crate::query::iocs::Ioc::from_package(&adv).unwrap())];
        let items = vec![
            HostItem {
                kind: "node_modules".into(),
                loc: "/home/u/app/node_modules".into(),
                pkgs: vec!["npm:evil-pkg@1.0.0".into(), "npm:evil-pkg@1.0.1".into(), "npm:other@1.0.0".into()],
                ..Default::default()
            },
            HostItem { kind: "npm-cache".into(), loc: "/home/u/.npm/_cacache".into(), pkgs: vec!["npm:evil-pkg@1.0.0".into()], ..Default::default() },
        ];
        let m = package_matches(&items, &inds);
        assert_eq!(m.len(), 2, "one per place: {:?}", m.iter().map(|x| (&x.pkg, &x.loc)).collect::<Vec<_>>());
        assert!(m.iter().all(|x| x.pkg == "npm:evil-pkg@1.0.0" && x.advisory == "GHSA-x"));
        assert_eq!(verdict_line(2, 0), "2 packages match indicators in the index; 0 files match by hash");
        assert_eq!(verdict_line(1, 1), "1 package matches indicators in the index; 1 file matches by hash");
        assert_eq!(verdict_line(0, 0), "0 packages match indicators in the index; 0 files match by hash");
    }
}
