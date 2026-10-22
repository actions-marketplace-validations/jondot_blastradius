//! `br hunt --yara FILE`: evaluate YARA rules against file content, from `--path DIR` or `--live`.

use std::path::Path;

use crate::cmd::hunt::HuntArgs;
use crate::collect::{brx, fs as cfs, ssh};
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::out::yara::Rules;
use crate::query::index::Index;
use crate::query::util::{fmtz, table};
use crate::store::Store;

const MAX_FILE: u64 = 64 * 1024 * 1024;

/// What one pass looked at and what it could not: a skipped file is a gap, never a quiet "no match".
#[derive(Default)]
struct Pass {
    hits: Vec<(String, String, String)>,
    evaluated: usize,
    /// (host, what, why)
    gaps: Vec<(String, String, String)>,
}

/// All regular files below `dir` (never following symlinks), as (path shown, path on disk). BR_REMOTE_ROOT is a prefix that is not shown.
/// Unreadable directories and files over 64 MB are recorded in `gaps`.
fn walk(dir: &Path, strip: &Option<std::path::PathBuf>, out: &mut Vec<(String, std::path::PathBuf)>, gaps: &mut Vec<(String, String)>) {
    let mut ents: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.flatten().collect(),
        Err(e) => {
            gaps.push((dir.to_string_lossy().to_string(), format!("cannot read directory: {e}")));
            return;
        }
    };
    ents.sort_by_key(|e| e.file_name());
    for e in ents {
        let p = e.path();
        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir() {
            walk(&p, strip, out, gaps);
        } else if md.is_file() {
            let shown = match strip {
                Some(r) => format!("/{}", p.strip_prefix(r).unwrap_or(&p).to_string_lossy().trim_start_matches('/')),
                None => p.to_string_lossy().to_string(),
            };
            if md.len() > MAX_FILE {
                gaps.push((shown, format!("not scanned: {} MB is over the 64 MB limit", md.len() / 1_048_576)));
            } else {
                out.push((shown, p));
            }
        }
    }
}

fn eval_path(rules: &Rules, host: &str, dir: &str) -> BrResult<Pass> {
    let strip = cfs::remote_root();
    let real = match &strip {
        Some(r) => r.join(dir.trim_start_matches('/')),
        None => std::path::PathBuf::from(dir),
    };
    if !real.exists() {
        return Err(BrError::new(format!("--path {dir} does not exist"), Some("check the path; a typo here would otherwise read as CLEAR")));
    }
    let mut pass = Pass::default();
    let mut files = vec![];
    let mut dgaps = vec![];
    if real.is_file() {
        files.push((dir.to_string(), real.clone()));
    } else {
        walk(&real, &strip, &mut files, &mut dgaps);
    }
    for (what, why) in dgaps {
        pass.gaps.push((host.to_string(), what, why));
    }
    for (shown, disk) in files {
        match std::fs::read(&disk) {
            Ok(data) => {
                pass.evaluated += 1;
                match rules.scan(&data) {
                    Ok(m) => pass.hits.extend(m.into_iter().map(|r| (host.to_string(), shown.clone(), r))),
                    Err(e) => pass.gaps.push((host.to_string(), shown.clone(), format!("YARA error: {e}"))),
                }
            }
            Err(e) => pass.gaps.push((host.to_string(), shown, format!("cannot read: {e}"))),
        }
    }
    Ok(pass)
}

/// Fetch `paths` (files, or directories that tar descends into, so files the scan never hashed are included) and scan them.
/// An unreachable host is one gap, not an abort; a requested file that did not come back is listed.
fn eval_live(rules: &Rules, host: &str, paths: &[String]) -> Pass {
    let mut pass = Pass::default();
    let files = match ssh::fetch_files(host, paths) {
        Ok(f) => f,
        Err(e) => {
            pass.gaps.push((host.to_string(), "the whole host".into(), format!("not evaluated: {}", e.msg)));
            return pass;
        }
    };
    let got: std::collections::HashSet<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    for p in paths {
        let looks_like_file = !p.ends_with('/');
        let under = files.iter().any(|(g, _)| g.starts_with(&format!("{}/", p.trim_end_matches('/'))));
        if looks_like_file && !got.contains(p.as_str()) && !under {
            pass.gaps.push((host.to_string(), p.clone(), "not returned by the host (deleted since the scan, or unreadable)".into()));
        }
    }
    for (p, data) in &files {
        pass.evaluated += 1;
        if data.len() as u64 >= MAX_FILE {
            pass.gaps.push((host.to_string(), p.clone(), "truncated at 64 MB before scanning".into()));
        }
        match rules.scan(data) {
            Ok(m) => pass.hits.extend(m.into_iter().map(|r| (host.to_string(), p.clone(), r))),
            Err(e) => pass.gaps.push((host.to_string(), p.clone(), format!("YARA error: {e}"))),
        }
    }
    pass
}

pub fn run(a: &HuntArgs, ctx: &Ctx) -> BrResult<i32> {
    let file = a.yara.clone().unwrap_or_default();
    let rules = crate::out::yara::compile(&file)?;
    if !a.live && a.path.is_none() {
        return Err(BrError::new("the index holds no file content, so rules cannot be evaluated against it", Some("re-run with --live or --path DIR (--live: reachable hosts; --path: this machine)")));
    }
    let view = ctx.view().unwrap_or_default();
    let ix = Index::new(&view, &ctx.now);
    let (mut hits, mut skipped, mut done): (Vec<(String, String, String)>, Vec<String>, Vec<String>) = (vec![], vec![], vec![]);
    let (mut gaps, mut evaluated): (Vec<(String, String, String)>, usize) = (vec![], 0);
    if let Some(p) = &a.path {
        let host = brx::local_host(ctx)?;
        done.push(host.clone());
        let pass = eval_path(&rules, &host, p)?;
        evaluated += pass.evaluated;
        hits.extend(pass.hits);
        gaps.extend(pass.gaps);
    }
    if a.live {
        for (n, s) in &view.sources {
            if s.kind != "host" {
                continue;
            }
            if s.reach == "ssh" {
                // the item directories themselves, not only the files the index hashed: the hash filter skips
                // .mjs/.cjs/.ts/.pth/.rb/.ps1 and extensionless binaries, which a rule must still see
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                let mut paths: Vec<String> = vec![];
                for it in ix.host_items(n) {
                    let mut add = |p: String| {
                        if seen.insert(p.clone()) {
                            paths.push(p);
                        }
                    };
                    if !it.loc.is_empty() {
                        add(it.loc.trim_end_matches('/').to_string());
                    }
                    for f in &it.files {
                        add(if f.path.starts_with('/') { f.path.clone() } else { format!("{}/{}", it.loc.trim_end_matches('/'), f.path) });
                    }
                }
                let pass = eval_live(&rules, n, &paths);
                if pass.evaluated > 0 || pass.gaps.is_empty() {
                    done.push(n.clone());
                }
                evaluated += pass.evaluated;
                hits.extend(pass.hits);
                gaps.extend(pass.gaps);
            } else {
                skipped.push(n.clone());
            }
        }
    }
    hits.sort();
    hits.dedup();
    if let Ok(st) = Store::open(ctx, true) {
        let seen: Vec<(String, String, String)> = st
            .list("yara_hits")
            .iter()
            .map(|y| {
                let g = |k: &str| y.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                (g("source_id"), g("path"), g("rule"))
            })
            .collect();
        for (h, p, r) in &hits {
            if !seen.contains(&(h.clone(), p.clone(), r.clone())) {
                let _ = st.push("yara_hits", &serde_json::json!({"source_id": h, "path": p, "rule": r, "rules_sha256": rules.sha256, "first_seen": ctx.now}));
            }
        }
    }
    let verdict = if !hits.is_empty() {
        "FOUND"
    } else if !skipped.is_empty() || !gaps.is_empty() {
        "CLEAR WITH GAPS"
    } else {
        "CLEAR"
    };
    println!("{verdict}  {} matches  {file} (sha256 {})", hits.len(), &rules.sha256[..12]);
    println!(
        "evaluated {} file(s) on {} host(s) ({}) at {}; {} rules; matches are stored with this time",
        evaluated,
        done.len(),
        if done.is_empty() { "none".to_string() } else { done.join(", ") },
        fmtz(&ctx.now),
        rules.names.len()
    );
    if !hits.is_empty() {
        println!();
        println!("YARA MATCHES");
        let rows: Vec<Vec<String>> = hits.iter().map(|(h, p, r)| vec![h.clone(), p.clone(), r.clone()]).collect();
        println!("{}", table(&["HOST", "PATH", "RULE"], &rows, 2).join("\n"));
    }
    if !gaps.is_empty() {
        println!();
        println!("NOT CHECKED ({} gap{}: the verdict covers only what was scanned)", gaps.len(), if gaps.len() == 1 { "" } else { "s" });
        for (h, what, why) in gaps.iter().take(20) {
            println!("  {h}: {what}: {why}");
        }
        if gaps.len() > 20 {
            println!("  ... and {} more", gaps.len() - 20);
        }
    }
    if !skipped.is_empty() {
        println!();
        println!("NOT EVALUATED (import-only; run the pass on the machine itself)");
        for n in &skipped {
            let mut roots: Vec<String> = ix.host_items(n).iter().map(|it| it.loc.clone()).filter(|l| !l.is_empty()).collect();
            roots.sort();
            roots.dedup();
            let flags: Vec<String> = roots.iter().map(|r| format!("--path {}", crate::out::shell::shpath(r))).collect();
            println!("  {n}: BR_HOST={} br hunt --yara {} {}", crate::out::shell::shquote(n), crate::out::shell::shpath(&file), flags.join(" "));
        }
    }
    if a.fail_if == "none" {
        return Ok(if hits.is_empty() { 11 } else { 0 });
    }
    if hits.is_empty() && a.strict && (!gaps.is_empty() || !skipped.is_empty()) {
        return Ok(3);
    }
    Ok(if hits.is_empty() { 0 } else { 10 })
}
