//! The commands that write the index: init, scan, import, hosts, teams, advisory note, debug view.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::cli::*;
use crate::collect::progress;
use crate::collect::util::{age_str, fmt, is_stale, norm_iso, num, plural, plural2, secs, table};
use crate::collect::words::{nearest, never_scanned, TOKEN_WORDS};
use crate::collect::{brx, config, github, local, osv, registry, ssh};
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::parse::lock;
use crate::query::hunt as H;
use crate::query::index::Index;
use crate::query::iocs as I;
use crate::store::{view_kind, Row, Store, ORG};
use crate::view::*;

const REPO_KINDS: &[&str] = &["repo", "commit", "run", "cache", "artifact", "release", "trust"];
const HOST_KINDS: &[&str] = &["host", "item", "trust"];

fn fmtz(s: &str) -> String {
    match crate::collect::util::epoch(s) {
        None => "-".into(),
        Some(t) => {
            let i = crate::collect::util::iso(t);
            format!("{} {}Z", &i[..10], &i[11..16])
        }
    }
}

fn host_os() -> String {
    // a scan of a mounted disk image (BR_REMOTE_ROOT) is of the machine the image came from, not of the one br runs on
    if let Ok(root) = std::env::var("BR_REMOTE_ROOT") {
        let root = std::path::Path::new(&root);
        if root.join("System/Library/CoreServices/SystemVersion.plist").exists() {
            return "macos".into();
        }
        if root.join("etc/os-release").exists() {
            return "linux".into();
        }
    }
    match std::env::consts::OS {
        "macos" => "macos".into(),
        o => o.to_string(),
    }
}

fn source(kind: &str, reach: &str, at: &str) -> Source {
    Source { kind: kind.into(), reach: reach.into(), indexed_at: at.into(), empty: false, gaps: vec![] }
}

/// Write one host (its row and its items) and register the source.
/// The kind comes from `br hosts add --kind`, else from what the machine itself shows (an actions-runner or
/// gitlab-runner install), else it is just a "host". A name or how it was reached never decides it.
fn put_host(st: &mut Store, ctx: &Ctx, name: &str, os: Option<String>, items: &[HostItem], src: &Source, detected: Option<&str>) -> BrResult<()> {
    put_host_with(st, ctx, name, os, items, &[], &TrustSet::default(), src, detected)
}

/// The rows for the trust stores read at one place (repo HEAD or host): one per file, one per note, one for the call count.
pub fn trust_rows(t: &TrustSet) -> Vec<Row> {
    let mut rows: Vec<Row> = t.files.iter().map(|f| Row::new("trust", f.path.clone(), f)).collect();
    for (i, n) in t.notes.iter().enumerate() {
        rows.push(Row::new("trust", format!("\u{1}note{i}"), &json!({"note": n})));
    }
    if t.read || t.api_calls > 0 {
        rows.push(Row::new("trust", "\u{1}read".to_string(), &json!({"read": true, "api_calls": t.api_calls})));
    }
    rows
}

/// `declared`: what each `lockfile` item's file declares; it travels in the item's row, so the View's `Host.declared` is
/// rebuilt from the same rows.
fn put_host_with(st: &mut Store, ctx: &Ctx, name: &str, os: Option<String>, items: &[HostItem], declared: &[DeclaredLock], trust: &TrustSet, src: &Source, detected: Option<&str>) -> BrResult<()> {
    let cfg = config::hosts(ctx);
    let kind = cfg.get(name).and_then(|c| c.kind.clone()).map(|k| view_kind(&k).to_string()).or_else(|| detected.map(|d| view_kind(d).to_string())).unwrap_or_else(|| "host".to_string());
    let host = Host { kind: Some(kind), os, ..Default::default() };
    let mut rows = vec![Row::new("host", name, &host)];
    for it in items {
        let mut j = serde_json::to_value(it).unwrap_or(Value::Null);
        if it.kind == "lockfile" {
            if let Some(d) = declared.iter().find(|d| d.loc == it.loc) {
                j["declared"] = serde_json::to_value(&d.packages).unwrap_or(Value::Null);
            }
        }
        rows.push(Row::new("item", format!("{}|{}|{}", it.at, it.kind, it.loc), &j));
    }
    rows.extend(trust_rows(trust));
    st.set_source(name, src, &ctx.now)?;
    st.replace(name, HOST_KINDS, rows, &ctx.now)
}

/// The rules' matches of a scan, recorded in the index: rule, path, sha256 and the rules' sha256, once per (host, file,
/// rule, rules, content). A hit seen again moves its `last_seen`; the history is never rewritten, and a reader that wants only
/// the hits of the scan of record compares `last_seen` with the host's `indexed_at`.
fn record_yara(st: &Store, host: &str, hits: &[local::YaraHit], rules_sha: Option<&str>, at: &str) -> BrResult<()> {
    let rules = rules_sha.unwrap_or("");
    let mut have: Vec<(i64, Value)> = vec![];
    if let Ok(mut q) = st.conn.prepare("SELECT id,data FROM yara_hits ORDER BY id") {
        if let Ok(rows) = q.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))) {
            for (id, d) in rows.flatten() {
                if let Ok(v) = serde_json::from_str::<Value>(&d) {
                    have.push((id, v));
                }
            }
        }
    }
    for h in hits {
        let same = |v: &Value| {
            v["source_id"] == host
                && v["path"] == h.path.as_str()
                && v["rule"] == h.rule.as_str()
                && v["rules_sha256"].as_str().unwrap_or("") == rules
                && v["sha256"].as_str().unwrap_or("") == h.sha256
        };
        match have.iter().find(|(_, v)| same(v)) {
            Some((id, v)) => {
                let mut v = v.clone();
                if v["last_seen"].as_str().unwrap_or("") < at {
                    v["last_seen"] = json!(at);
                    let _ = st.conn.execute("UPDATE yara_hits SET data=? WHERE id=?", rusqlite::params![serde_json::to_string(&v).unwrap_or_default(), id]);
                }
            }
            None => {
                st.push("yara_hits", &json!({"source_id": host, "path": h.path, "rule": h.rule, "sha256": h.sha256, "rules_sha256": rules, "first_seen": at, "last_seen": at}))?;
            }
        }
    }
    Ok(())
}

/// The directories a host's scans read, and whether the host is the machine br runs on. Decided when the scan is
/// taken or imported; every later reader (hunt, purge, notify, evidence) reads this, never the name again.
/// `home` is the scanning user's home (local scan: `$HOME` at scan time; import: the .brx manifest; ssh: the remote `$HOME`).
/// A scan that did not record one keeps the one already known.
fn record_roots(st: &Store, host: &str, roots: &[String], this_machine: bool, home: Option<&str>) -> BrResult<()> {
    let imports = st.imports();
    let prior = imports.get(host).and_then(|v| v["this_machine"].as_bool()).unwrap_or(false);
    let home = home.filter(|h| !h.is_empty()).map(str::to_string).or_else(|| imports.get(host).and_then(|v| v["home"].as_str().map(str::to_string)));
    st.set_import(host, &json!({"roots": roots, "this_machine": this_machine || prior, "home": home}))
}

/// A machine registered with `br hosts add` is a source from that moment: never scanned, so every hunt lists it as
/// not checked, `br hosts` and `br status` show it, and `br scan --host NAME` reads it. Returns false when it already was one.
fn register_host(st: &mut Store, ctx: &Ctx, name: &str) -> BrResult<bool> {
    if st.source(name).is_some() {
        return Ok(false);
    }
    let cfg = config::hosts(ctx).get(name).cloned().unwrap_or_default();
    let mut src = source("host", cfg.reach.as_deref().unwrap_or("import-only"), &ctx.now);
    src.empty = true;
    put_host(st, ctx, name, None, &[], &src, None)?;
    st.set_gaps(name, &[Gap { scope: "registered".into(), reason: "registered with br hosts add and never scanned".into(), at: ctx.now.clone() }])?;
    Ok(true)
}

/// Register every machine in hosts.yaml that the index does not hold yet (after `br init`, which starts a new index).
fn register_configured_hosts(st: &mut Store, ctx: &Ctx) -> BrResult<()> {
    for name in config::hosts(ctx).keys() {
        register_host(st, ctx, name)?;
    }
    Ok(())
}

// ---- registries ----------------------------------------------------------------------------------------------
fn run_lookup(st: &Store) -> impl Fn(&str, &str) -> Option<u64> + '_ {
    move |repo: &str, imgref: &str| {
        for (_, v) in st.present(repo, "run") {
            if let Ok(r) = serde_json::from_value::<Run>(v) {
                if r.produced_images.iter().any(|p| p == imgref) {
                    return Some(r.id);
                }
            }
        }
        None
    }
}

fn put_registry(st: &mut Store, ctx: &Ctx, name: &str, reach: &str, reg: &registry::Reg) -> BrResult<usize> {
    let found = {
        let look = run_lookup(st);
        // images read on an earlier scan keep their layers: a blob never changes under its digest
        let prior: std::collections::HashMap<String, ImageBuild> = st.present(name, "image").into_iter().filter_map(|(k, v)| serde_json::from_value::<ImageBuild>(v).ok().map(|b| (k, b))).collect();
        let known = |repo: &str, digest: &str| -> Option<ImageBuild> { prior.get(&format!("{repo}@{digest}")).cloned() };
        registry::images(reg, ctx, &look, &known)?
    };
    let n = found.images.len();
    let rows: Vec<Row> = found.images.iter().map(|b| Row::new("image", format!("{}@{}", b.repository, b.digest), b)).collect();
    st.set_source(name, &source("registry", reach, &ctx.now), &ctx.now)?;
    // a listing that failed outright must not wipe what an earlier scan found
    if n == 0 && found.gaps.iter().any(|g| g.scope == "registry listing") && st.source(name).is_some() && !st.present(name, "image").is_empty() {
        // keep the old rows
    } else {
        st.replace(name, &["image"], rows, &ctx.now)?;
    }
    st.set_gaps(name, &found.gaps)?;
    Ok(n)
}

fn read_registry(st: &mut Store, ctx: &Ctx, host: &str) -> BrResult<(String, usize)> {
    let name = host.trim_end_matches('/').to_string();
    let reg = registry::Reg::open(&name, None);
    // a public registry can be read without a login, but a missing login is said so when the registry refuses
    if !reg.has_creds() {
        return Err(registry::no_creds_why(host, reg.cred_err.as_deref()));
    }
    let n = put_registry(st, ctx, &name, "docker-creds", &reg)?;
    let g = st.source(&name).map(|s| s.gaps.len()).unwrap_or(0);
    let tail = if g > 0 { format!(", {} not checked (br status shows them)", plural(g, "gap")) } else { String::new() };
    println!("reading container images in {name} with the credentials docker login stored for it; no GitHub token needed: {}{tail}", plural(n, "image"));
    Ok((name, n))
}

// ---- repos ---------------------------------------------------------------------------------------------------
/// Which stored kind a gap scope stands for: those rows are kept (not marked removed) when the scope could not be read.
fn kind_of_scope(scope: &str) -> Option<&'static str> {
    match scope {
        "actions runs" | "run logs" => Some("run"),
        "actions caches" => Some("cache"),
        "actions artifacts" => Some("artifact"),
        "releases" => Some("release"),
        "git tree" => None,
        _ => None,
    }
}

/// B9: the three cheap conditional probes (github::probe_urls) all answering "not modified" mean the stored rows are still right.
fn collect_repo_into(st: &mut Store, ctx: &Ctx, gh: &github::Gh, info: &github::RepoInfo) -> BrResult<()> {
    let etag_key = format!("etag:{}", info.name);
    let stored: BTreeMap<String, String> = st.kv_get(&etag_key).unwrap_or_default();
    gh.load_etags(stored.clone());
    let had = st.source(&info.name).map(|s| s.kind == "repo").unwrap_or(false);
    let mut changed = true;
    let trust_key = format!("trustread:{}", info.name);
    // an index made before certificate files were read has no trust rows: one full read, then the shortcut applies again
    let trust_done = st.kv_get::<bool>(&trust_key).unwrap_or(false);
    if had && !stored.is_empty() && trust_done && st.present(&info.name, "repo").values().next().and_then(|v| v["archived"].as_bool()) == Some(info.archived) {
        changed = false;
        for u in github::probe_urls(info, &ctx.now) {
            if !matches!(gh.json_cond(&u)?, github::Cond::NotModified) {
                changed = true;
                break;
            }
        }
    }
    gh.take_gaps(&ctx.now);
    if !changed {
        // nothing moved: keep the rows and the gaps, record that the repo was checked now
        let mut src = source("repo", "github", &ctx.now);
        src.empty = st.source(&info.name).map(|s| s.empty).unwrap_or(false);
        st.set_source(&info.name, &src, &ctx.now)?;
        return Ok(());
    }
    // the validators are taken before any row is read: a push during the scan changes them, so the next scan sees it
    let snapshot = github::snapshot_etags(gh, info, &ctx.now);
    let known = github::Known { commits: st.present(&info.name, "commit"), artifacts: st.present(&info.name, "artifact"), releases: st.present(&info.name, "release") };
    let rows = github::collect_repo(gh, ctx, info, &known)?;
    let gaps = gh.take_gaps(&ctx.now);
    let keep: Vec<&str> = gaps.iter().filter_map(|g| kind_of_scope(&g.scope)).collect();
    // the certificate files cannot be listed without the tree: what was read before stays
    let tree_gap = gaps.iter().any(|g| g.scope == "git tree");
    let kinds: Vec<&str> = REPO_KINDS.iter().copied().filter(|k| !keep.contains(k) && !(tree_gap && *k == "trust")).collect();
    // A repo whose lockfiles gave no package at all is an empty read, never "fresh, nothing found"
    let read_none = gaps.iter().any(|g| g.scope.starts_with("lockfile ") && g.reason.starts_with(github::NO_PACKAGES))
        && !rows.iter().filter(|r| r.kind == "commit").any(|r| {
            let n = |k: &str| r.data[k].as_array().map_or(0, |a| a.len()) + r.data[k].as_object().map_or(0, |o| o.values().map(|v| v.as_array().map_or(0, |a| a.len())).sum());
            n("packages") + n("lock_packages") > 0
        });
    let mut src = source("repo", "github", &ctx.now);
    src.empty = read_none;
    st.set_source(&info.name, &src, &ctx.now)?;
    st.replace(&info.name, &kinds, rows, &ctx.now)?;
    st.set_gaps(&info.name, &gaps)?;
    st.kv_set(&etag_key, &snapshot)?;
    st.kv_set(&trust_key, &true)?;
    Ok(())
}

/// A source br could not read: it is listed with one gap saying why, so no answer calls it clear.
fn gap_source(st: &mut Store, ctx: &Ctx, name: &str, kind: &str, reach: &str, why: &str) {
    let mut src = source(kind, reach, &ctx.now);
    if st.source(name).is_some() {
        // keep the old rows and their time; only the gap is new
        src.indexed_at = st.source(name).map(|s| s.indexed_at).unwrap_or_else(|| ctx.now.clone());
    } else {
        src.empty = true;
    }
    let _ = st.set_source(name, &src, &src.indexed_at.clone());
    let _ = st.set_gaps(name, &[Gap { scope: "scan".into(), reason: why.to_string(), at: ctx.now.clone() }]);
}

fn put_org(st: &mut Store, ctx: &Ctx, o: &github::OrgData) -> BrResult<()> {
    let mut rows = vec![];
    for p in &o.people {
        rows.push(Row::new("person", p.login.clone(), p));
    }
    for t in &o.teams {
        rows.push(Row::new("team", t.id.clone(), t));
    }
    st.replace(ORG, &["person", "team"], rows, &ctx.now)?;
    st.kv_set("org", &o.org)?;
    st.kv_set("org_admins", &o.admins)?;
    st.kv_set("org_secret_scopes", &o.secret_scopes)?;
    st.kv_set("org_secrets_unreadable", &!o.secrets_readable)?;
    st.kv_set("org_secrets", &o.secrets)
}

fn refresh_advisories(ctx: &Ctx) {
    if std::env::var_os("BR_OSV_API").is_none() {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(ctx.home.join("advisories")) {
        for e in rd.flatten() {
            if let Some(id) = e.path().file_stem().and_then(|s| s.to_str()).map(str::to_string) {
                let _ = osv::resolve(ctx, &id);
            }
        }
    }
}

// ---- hosts over ssh --------------------------------------------------------------------------------------------
fn read_ssh_host(st: &mut Store, ctx: &Ctx, name: &str) -> BrResult<usize> {
    let cfg = config::hosts(ctx);
    let c = cfg.get(name).cloned().unwrap_or_default();
    let target = c.target.clone().unwrap_or_else(|| name.to_string());
    let globs = config::hash_filter(ctx);
    let hs = ssh::scan(&target, &c.roots, &globs, &ctx.now)?;
    let mut src = source("host", "ssh", &ctx.now);
    src.empty = crate::collect::fs::read_nothing(hs.hashed, &hs.items);
    put_host_with(st, ctx, name, hs.os.clone(), &hs.items, &hs.declared, &hs.trust, &src, hs.kind.as_deref())?;
    let g: Vec<Gap> = hs.gaps.iter().map(|(s, r)| Gap { scope: s.clone(), reason: r.clone(), at: ctx.now.clone() }).collect();
    st.set_gaps(name, &g)?;
    // An ssh host's roots are the ones it was registered with, `/` when none
    let roots = if c.roots.is_empty() { vec!["/".to_string()] } else { c.roots.clone() };
    record_roots(st, name, &roots, false, hs.home.as_deref())?;
    Ok(hs.hashed)
}

/// The runners the org lists that br was not told about, and how to tell it: with an owner, so a hunt can name whose they are.
pub fn unregistered_tail(org: &str, names: &[&str]) -> String {
    if names.is_empty() {
        return String::new();
    }
    format!(
        "; not registered with br yet: {} (br hosts add NAME --kind runner --reach ssh --owner @{org}/TEAM, then br scan --host NAME; a machine ssh cannot reach scans itself with br scan --local --export, and br import FILE.brx --kind runner --owner @{org}/TEAM brings it in)",
        names.join(", ")
    )
}

/// What the token can see of the org's self-hosted runners, and what to do about the ones br cannot read yet.
fn runner_line(gh: &github::Gh, ctx: &Ctx, org: &str, cfg: &BTreeMap<String, config::HostCfg>) -> String {
    let _ = gh.take_gaps(&ctx.now);
    let listed = gh.list_max(&format!("/orgs/{org}/actions/runners?per_page=100"), Some("runners"), 2000);
    let why = gh.take_gaps(&ctx.now).into_iter().next().map(|g| g.reason);
    match listed {
        Ok((Some(rs), _)) => {
            let names: Vec<String> = rs.iter().filter_map(|r| r["name"].as_str().map(str::to_string)).collect();
            if names.is_empty() {
                return "runners: none visible to this token (the org lists no self-hosted runners)".to_string();
            }
            let unregistered: Vec<&String> = names.iter().filter(|n| !cfg.contains_key(*n)).collect();
            let tail = unregistered_tail(org, &unregistered.iter().map(|n| n.as_str()).collect::<Vec<_>>());
            format!("runners: {} visible to this token ({}){tail}", plural(names.len(), "self-hosted runner"), names.join(", "))
        }
        Ok((None, _)) => format!("runners: none visible to this token ({})", why.unwrap_or_else(|| "the org's runner list is missing, or the token cannot read it".into())),
        Err(e) => format!("runners: the list could not be read ({})", e.msg),
    }
}

// ---- init ------------------------------------------------------------------------------------------------------------
/// Ends progress reporting when the command returns, whichever way it returns.
struct StopProgress;
impl Drop for StopProgress {
    fn drop(&mut self) {
        progress::stop();
    }
}

pub fn init(ctx: &Ctx, a: &InitArgs) -> BrResult<i32> {
    let started = std::time::Instant::now();
    if Store::open(ctx, false).is_ok() {
        let n = Store::open(ctx, false).map(|s| s.sources().len()).unwrap_or(1);
        if n > 0 && !a.force {
            return Err(BrError::new(
                format!("an index with {} already exists at {}", plural(n, "source"), crate::store::index_path(ctx).display()),
                Some("br scan --stale refreshes it; br init ... --force replaces it with a new one"),
            ));
        }
        if n > 0 {
            println!("replacing the existing index ({}) because of --force", plural(n, "source"));
        }
    }
    if a.org.is_none() && a.path.is_empty() && a.registry.is_none() && !a.no_github {
        return Err(BrError::new("nothing to index", Some(&format!("pass --org ORG (needs {TOKEN_WORDS}) or --path DIR, or --registry HOST; --no-github alone makes an empty index"))));
    }
    let use_gh = a.org.is_some() && !a.no_github;
    if use_gh && ctx.token().is_none() {
        return Err(BrError::with_code("no GitHub token found", Some(&format!("set {TOKEN_WORDS} (read-only is enough)")), 4));
    }
    // read everything that can fail before touching the old index
    let gh = github::Gh::new(ctx);
    let mut org_data = None;
    let mut repos = vec![];
    if use_gh {
        let org = a.org.as_deref().unwrap();
        let o = github::org(&gh, org)?;
        repos = github::repos(&gh, org)?;
        org_data = Some(o);
    }
    let mut st = Store::reset(ctx)?;
    // an init that indexes nothing stays empty, as it says; any other init also holds the machines registered before it
    if a.org.is_some() || !a.path.is_empty() || a.registry.is_some() {
        register_configured_hosts(&mut st, ctx)?;
    }
    progress::start(a.quiet);
    let _stop = StopProgress;
    let (mut n_repos, mut n_hosts, mut n_regs) = (0usize, 0usize, 0usize);
    let mut extra: Vec<String> = vec![];
    let mut reached: Vec<String> = vec![];
    if let Some(o) = &org_data {
        println!("listing repositories in {}: {} found", a.org.as_deref().unwrap(), repos.len());
        println!("reading lockfiles, manifests and commit history");
        println!("reading CODEOWNERS and workflow files");
        println!("reading CI runs, Actions caches and artifacts");
        put_org(&mut st, ctx, o)?;
        // one repo failing is a gap, not the end of the run; a refused token or a spent quota stops it
        let mut gaps: Vec<(String, String)> = vec![];
        for (i, r) in repos.iter().enumerate() {
            progress::tick_now(|el| format!("reading repositories: {i} of {} done, now {}, {el} elapsed", repos.len(), r.name));
            match collect_repo_into(&mut st, ctx, &gh, r) {
                Ok(()) => n_repos += 1,
                Err(e) if e.code == 4 && !e.msg.contains("SSO") => return Err(e),
                Err(e) if e.msg.starts_with(github::RATE_STOP) => {
                    for rest in &repos[i..] {
                        gap_source(&mut st, ctx, &rest.name, "repo", "github", &e.msg);
                        gaps.push((rest.name.clone(), e.msg.clone()));
                    }
                    break;
                }
                Err(e) => {
                    gap_source(&mut st, ctx, &r.name, "repo", "github", &e.msg);
                    gaps.push((r.name.clone(), e.msg.clone()))
                }
            }
        }
        for (n, why) in &gaps {
            eprintln!("not indexed: {n}: {why}");
        }
    }
    if !a.path.is_empty() {
        println!("indexing this machine; no account needed, nothing leaves it");
        let info = local::local_scan_with(ctx, &a.path, &[], !a.quiet, None, a.hash_all)?;
        local::print_verdict(&info);
        let mut src = source("host", "local", &ctx.now);
        src.empty = info.read_nothing();
        put_host_with(&mut st, ctx, &info.host, Some(host_os()), &info.items, &info.declared, &info.trust, &src, info.kind.as_deref())?;
        // what the scan could not read is the host's gaps; a machine registered before the scan is no longer "never scanned"
        let g: Vec<Gap> = info.gaps.iter().map(|(s, r)| Gap { scope: s.clone(), reason: r.clone(), at: ctx.now.clone() }).collect();
        st.set_gaps(&info.host, &g)?;
        record_roots(&st, &info.host, &info.roots, true, local::scanning_home().as_deref())?;
        record_yara(&st, &info.host, &info.yara_hits, info.rules_sha256.as_deref(), &ctx.now)?;
        n_hosts += 1;
        if info.read_nothing() {
            eprintln!("warning: the scan of {0} hashed 0 files, so {0} stays NOT CHECKED; check that --path covers where files live", info.host);
        }
    }
    if let Some(r) = &a.registry {
        match read_registry(&mut st, ctx, r) {
            Ok(_) => n_regs += 1,
            Err(e) => {
                gap_source(&mut st, ctx, r, "registry", "registry", &e.msg);
                extra.push(format!("not reached: registry {r}: {}", e.msg));
            }
        }
    }
    if use_gh {
        // what the same token can also read: the org's GHCR images, and the registered runners
        let org = a.org.as_deref().unwrap();
        let name = format!("ghcr.io/{}", org.to_lowercase());
        if st.source(&name).is_none() {
            if let Some(t) = ctx.token() {
                let reg = registry::Reg::open(&name, Some((org.to_string(), t)));
                match put_registry(&mut st, ctx, &name, "registry", &reg) {
                    Ok(n) if n > 0 => {
                        extra.push(format!("reading container images in {name}: {}", plural(n, "image")));
                        reached.push("1 registry".to_string());
                    }
                    Ok(_) => {
                        // an org with no packages is normal; one whose packages could not be listed is a gap
                        if st.source(&name).map(|s| s.gaps.is_empty()).unwrap_or(true) {
                            let _ = st.remove_source(&name, &ctx.now);
                        } else {
                            extra.push(format!("{name}: no images read, and some could not be checked (br status shows why)"));
                        }
                    }
                    Err(e) => gap_source(&mut st, ctx, &name, "registry", "registry", &e.msg),
                }
            }
        }
        let cfg = config::hosts(ctx);
        let runners: Vec<(&String, &config::HostCfg)> = cfg.iter().filter(|(_, c)| c.kind.as_deref() == Some("runner")).collect();
        let mut got = vec![];
        let mut why: std::collections::BTreeMap<String, String> = Default::default();
        for (h, c) in &runners {
            if c.reach.as_deref() == Some("ssh") {
                match read_ssh_host(&mut st, ctx, h) {
                    Ok(_) => got.push(h.to_string()),
                    Err(e) => {
                        why.insert(h.to_string(), e.msg);
                    }
                }
            }
        }
        if !got.is_empty() {
            extra.push(format!("reading registered runners: {} ({})", plural(got.len(), "runner"), got.join(", ")));
            reached.push(plural(got.len(), "runner"));
        }
        extra.push(runner_line(&gh, ctx, org, &cfg));
        for (h, _) in &runners {
            if !got.contains(h) {
                let w = why.get(*h).map(|w| format!(" ({w})")).unwrap_or_default();
                extra.push(format!("not reached: runner {h} is registered but not reachable by ssh from here{w}; run on it: br scan --local --export {h}.brx   then here: br import {h}.brx --kind runner --owner @{org}/TEAM"));
            }
        }
    }
    refresh_advisories(ctx);
    // The registries docker has a login for. With --org they are read too (a private registry holds the images the org
    // builds), unless --no-registries; Docker Hub and ghcr.io are not (Hub is everyone's, ghcr.io is read with the org's token).
    // Secrets are never printed.
    let logged: Vec<String> =
        registry::docker_config_hosts().into_iter().filter(|h| st.source(h).is_none() && a.registry.as_deref().map(|r| r.split('/').next() != Some(h.as_str())).unwrap_or(true)).collect();
    let is_public = |h: &str| matches!(h, "docker.io" | "index.docker.io" | "registry-1.docker.io" | "ghcr.io");
    let (readable, offered): (Vec<String>, Vec<String>) = if use_gh && !a.no_registries { logged.into_iter().partition(|h| !is_public(h)) } else { (vec![], logged) };
    if !readable.is_empty() {
        let mut got = vec![];
        for h in &readable {
            match read_registry(&mut st, ctx, h) {
                Ok(_) => {
                    n_regs += 1;
                    got.push(h.clone());
                }
                Err(e) => {
                    gap_source(&mut st, ctx, h, "registry", "registry", &e.msg);
                    extra.push(format!("not reached: registry {h}: {}", e.msg));
                }
            }
        }
        if !got.is_empty() {
            extra.push(format!("also read the registries docker is logged into: {} (--no-registries skips them)", got.join(", ")));
        }
    }
    if !offered.is_empty() {
        extra.push(format!("docker has logins for {}; read one with: br scan --registry HOST", offered.join(", ")));
    }
    if a.org.is_none() && a.path.is_empty() && a.registry.is_none() {
        println!("created an empty index: {}", st.path.display());
        println!("nothing is indexed yet and this machine was not added; br scan --local --path DIR adds it, br import FILE.brx adds another machine");
        return Ok(0);
    }
    let mut parts = vec![];
    if n_repos > 0 {
        parts.push(plural(n_repos, "repo"));
    }
    if n_regs > 0 {
        parts.push(plural2(n_regs, "registry", "registries"));
    }
    if n_hosts > 0 {
        parts.push(plural(n_hosts, "host"));
    }
    parts.extend(reached);
    for e in extra {
        println!("{e}");
    }
    println!("Indexed {} in {}. Index: {}", parts.join(", "), secs(started.elapsed().as_secs()), st.path.display());
    Ok(0)
}

// ---- scan -------------------------------------------------------------------------------------------------------------
fn findings_of(v: &View, ctx: &Ctx, ioc: &I::Ioc) -> Vec<(String, Option<String>, bool)> {
    let ix = Index::new(v, &ctx.now);
    let q = H::Query { iocs: vec![ioc.clone()], ..Default::default() };
    match H::hunt(&ix, &q) {
        Ok(res) => H::findings(&res).iter().map(|f| (f.where_.clone(), f.from_repo.clone(), f.kind == H::FKind::Image)).collect(),
        Err(_) => vec![],
    }
}

fn change_parts(v: &View, name: &str, kind: &str, old: &str, new: &str) -> Vec<String> {
    let mut parts = vec![];
    let mut add = |c: usize, one: &str, many: &str| {
        if c > 0 {
            parts.push(format!("+{c} {}", if c == 1 { one } else { many }));
        }
    };
    let n = |t: &str| t > old && t <= new;
    match kind {
        "repo" => {
            if let Some(r) = v.repos.get(name) {
                add(r.commits.iter().filter(|x| n(&x.at)).count(), "commit", "commits");
                add(r.runs.iter().filter(|x| n(&x.at)).count(), "CI run", "CI runs");
                add(r.caches.iter().filter(|x| n(&x.created)).count(), "cache", "caches");
                add(r.artifacts.iter().filter(|x| n(&x.created)).count(), "artifact", "artifacts");
                add(r.releases.iter().filter(|x| n(&x.published)).count(), "release", "releases");
            }
        }
        "host" => {
            if let Some(h) = v.hosts.get(name) {
                add(h.items.iter().filter(|x| n(&x.at)).count(), "item", "items");
            }
        }
        "registry" => {
            let prefix = name.to_string();
            add(v.images.iter().filter(|b| (b.repository.starts_with(&prefix) || prefix.starts_with(b.repository.split('/').next().unwrap_or(""))) && n(&b.built)).count(), "image", "images");
        }
        _ => {}
    }
    parts
}

pub fn scan(ctx: &Ctx, a: &ScanArgs) -> BrResult<i32> {
    let started = std::time::Instant::now();
    if a.local {
        return scan_local(ctx, a);
    }
    let modes = [a.affected.is_some(), a.stale, a.all, a.repo.is_some(), a.host.is_some(), a.registry.is_some()];
    if modes.iter().filter(|m| **m).count() != 1 {
        return Err(BrError::new("say what to scan", Some("use --all, --affected npm:name@1.2.3, --stale, --repo R, --host H, --registry HOST or --local")));
    }
    let mut st = Store::open(ctx, false)?;
    let mut srcs = st.sources();
    progress::start(a.quiet);
    let _stop = StopProgress;
    let ioc = match &a.affected {
        Some(t) => Some(I::parse_ioc(t, None)?),
        None => None,
    };
    // a registered machine that ssh can reach and no scan has read is as good as stale
    let stale: Vec<String> = srcs.iter().filter(|(_, s)| is_stale(&ctx.now, &s.indexed_at).unwrap_or(false) || (never_scanned(s) && s.reach == "ssh")).map(|(n, _)| n.clone()).collect();
    let view_before = ctx.view()?;
    let targets: Vec<String>;
    if let Some(r) = &a.repo {
        if !srcs.get(r).map(|s| s.kind == "repo").unwrap_or(false) {
            let ex = srcs.iter().find(|(_, s)| s.kind == "repo").map(|(n, _)| n.clone()).unwrap_or_else(|| "org/name".into());
            return Err(BrError::new(format!("unknown repo {r}"), Some(&format!("use the org/name form, e.g. {ex}"))));
        }
        targets = vec![r.clone()];
    } else if let Some(h) = &a.host {
        if !srcs.get(h).map(|s| s.kind == "host").unwrap_or(false) {
            // registered before the index existed: it joins the index now
            if config::hosts(ctx).contains_key(h) {
                register_host(&mut st, ctx, h)?;
                srcs = st.sources();
            } else {
                return Err(unknown_host(ctx, &srcs, h));
            }
        }
        targets = vec![h.clone()];
    } else if let Some(r) = &a.registry {
        let name = r.trim_end_matches('/').to_string();
        if !srcs.contains_key(&name) {
            read_registry(&mut st, ctx, r)?;
            println!("Indexed {name} (new source)");
            return Ok(0);
        }
        targets = vec![name];
    } else if a.all {
        // Every source br can reach; the import-only and local ones come back as "skipped" rows, and the footer names them
        targets = srcs.keys().cloned().collect();
    } else if a.stale {
        // A repo that moved since it was indexed is as good as stale, even when it is young
        H::set_probe(ctx);
        let ixm = Index::new(&view_before, &ctx.now);
        let repos: Vec<String> = srcs.iter().filter(|(_, s)| s.kind == "repo").map(|(n, _)| n.clone()).collect();
        let mut t = stale.clone();
        for (n, _) in H::moved_repos(&ixm, &repos) {
            if !t.contains(&n) {
                t.push(n);
            }
        }
        targets = t;
    } else {
        let ioc = ioc.as_ref().unwrap();
        let mut hit: std::collections::BTreeSet<String> = Default::default();
        for (w, from, img) in findings_of(&view_before, ctx, ioc) {
            hit.insert(w);
            if img {
                if let Some(f) = from {
                    hit.insert(f);
                }
            }
        }
        targets = srcs.keys().filter(|n| hit.contains(*n) || stale.contains(n)).cloned().collect();
    }
    let old_findings = ioc.as_ref().map(|i| findings_of(&view_before, ctx, i)).unwrap_or_default();
    let gh = github::Gh::new(ctx);
    let mut rows: Vec<(String, String, String)> = vec![];
    let mut before: BTreeMap<String, String> = BTreeMap::new();
    let mut done: Vec<(String, String, String, bool)> = vec![]; // name, kind, old indexed_at, first scan
    for n in &targets {
        let s = srcs[n].clone();
        if s.kind == "host" && s.reach == "import-only" {
            let msg = if never_scanned(&s) {
                "skipped: import-only host, registered and never scanned; its .brx has to be imported".to_string()
            } else {
                format!("skipped: import-only host, last import {}", fmt(&s.indexed_at))
            };
            rows.push((n.clone(), "host".into(), msg));
            continue;
        }
        if s.kind == "host" && s.reach == "local" {
            rows.push((n.clone(), "host".into(), format!("skipped: scanned on that machine, last scan {}; run br scan --local there", fmt(&s.indexed_at))));
            continue;
        }
        before.insert(n.clone(), s.indexed_at.clone());
        match s.kind.as_str() {
            "repo" => {
                if ctx.token().is_none() {
                    return Err(BrError::with_code("no GitHub token found", Some(&format!("set {TOKEN_WORDS} (read-only is enough)")), 4));
                }
                let res = repo_info(&gh, n).and_then(|info| collect_repo_into(&mut st, ctx, &gh, &info));
                if let Err(e) = res {
                    if e.msg.contains("SSO") {
                        if a.repo.is_some() {
                            return Err(BrError::with_code(format!("{n}: token is not authorised for SSO"), Some(&format!("authorise the token for the org, then re-run br scan --repo {n}")), 4));
                        }
                        rows.push((n.clone(), s.kind.clone(), "unreachable: token is not authorised for SSO".into()));
                        before.remove(n);
                        continue;
                    }
                    if e.code == 4 || e.msg.starts_with(github::RATE_STOP) || a.repo.is_some() {
                        return Err(e);
                    }
                    gap_source(&mut st, ctx, n, "repo", "github", &e.msg);
                    rows.push((n.clone(), s.kind.clone(), format!("failed: {}", e.msg)));
                    before.remove(n);
                    continue;
                }
            }
            "host" => {
                if let Err(e) = read_ssh_host(&mut st, ctx, n) {
                    if a.host.is_some() {
                        return Err(e);
                    }
                    gap_source(&mut st, ctx, n, "host", "ssh", &e.msg);
                    rows.push((n.clone(), s.kind.clone(), format!("failed: {}", e.msg)));
                    before.remove(n);
                    continue;
                }
            }
            "registry" => {
                let reg = if s.reach == "registry" {
                    let org = n.split('/').nth(1).unwrap_or("").to_string();
                    registry::Reg::open(n, ctx.token().map(|t| (org, t)))
                } else {
                    registry::Reg::open(n, None)
                };
                if let Err(e) = put_registry(&mut st, ctx, n, &s.reach, &reg) {
                    if a.registry.is_some() {
                        return Err(e);
                    }
                    gap_source(&mut st, ctx, n, "registry", &s.reach, &e.msg);
                    rows.push((n.clone(), s.kind.clone(), format!("failed: {}", e.msg)));
                    before.remove(n);
                    continue;
                }
            }
            _ => {}
        }
        done.push((n.clone(), s.kind.clone(), s.indexed_at.clone(), never_scanned(&s)));
    }
    // The sources this scan read for the first time have no earlier state: `br diff` lists what they added
    let first: Vec<&String> = done.iter().filter(|d| d.3).map(|d| &d.0).collect();
    st.kv_set("last_scan", &json!({"at": ctx.now, "before": before, "first": first}))?;
    st.push("scans", &json!({"at": ctx.now, "before": before}))?;
    let view_after = ctx.view()?;
    let new_findings = ioc.as_ref().map(|i| findings_of(&view_after, ctx, i)).unwrap_or_default();
    let mut out: Vec<(String, String, String)> = vec![];
    for (n, kind, old, first) in &done {
        // The first scan of a registered machine has nothing to be "unchanged" from
        if *first && kind == "host" {
            let items = view_after.hosts.get(n).map(|h| h.items.len()).unwrap_or(0);
            out.push((n.clone(), kind.clone(), format!("first scan: {}", plural(items, "item"))));
            continue;
        }
        let mut parts = change_parts(&view_after, n, kind, old, &ctx.now);
        if ioc.is_some() {
            let d = new_findings.iter().filter(|f| &f.0 == n).count() as i64 - old_findings.iter().filter(|f| &f.0 == n).count() as i64;
            if d != 0 {
                parts.push(format!("{d:+} {}", if d.abs() == 1 { "finding" } else { "findings" }));
            }
        }
        out.push((n.clone(), kind.clone(), if parts.is_empty() { format!("unchanged (not modified since {})", fmt(old)) } else { format!("changed ({})", parts.join(", ")) }));
    }
    // keep the targets' order, with skipped rows where they were
    let mut ordered = vec![];
    for n in &targets {
        if let Some(r) = rows.iter().find(|r| &r.0 == n) {
            ordered.push(r.clone());
        } else if let Some(r) = out.iter().find(|r| &r.0 == n) {
            ordered.push(r.clone());
        }
    }
    // "Rescanned N" counts what was rescanned; sources left alone are counted apart
    let skipped = ordered.iter().filter(|r| r.2.starts_with("skipped")).count();
    let failed = ordered.iter().filter(|r| r.2.starts_with("failed") || r.2.starts_with("unreachable")).count();
    let mut apart = vec![];
    if skipped > 0 {
        apart.push(format!("{skipped} skipped"));
    }
    if failed > 0 {
        apart.push(format!("{failed} not reached"));
    }
    println!("Rescanned {} sources in {}{}", done.len(), secs(started.elapsed().as_secs()), if apart.is_empty() { String::new() } else { format!("; {}", apart.join(", ")) });
    let w = ordered.iter().map(|r| r.0.chars().count()).max().unwrap_or(1).max(1);
    for (n, kind, msg) in &ordered {
        println!("  {}  {}  {}", pad(n, w), pad(kind, 8), msg);
    }
    let apart_names: Vec<&str> = ordered.iter().filter(|r| r.2.starts_with("skipped")).map(|r| r.0.as_str()).collect();
    if !apart_names.is_empty() {
        println!();
        println!(
            "{}: br cannot reach {} from here; run br scan --local --export FILE on each machine, then br import FILE here",
            plural(apart_names.len(), "machine"),
            if apart_names.len() == 1 { "it" } else { "them" }
        );
        println!("  {}", apart_names.join(", "));
    }
    Ok(0)
}

/// An unknown name suggests the nearest registered one and the whole command that registers a new machine.
fn unknown_host(ctx: &Ctx, srcs: &BTreeMap<String, Source>, h: &str) -> BrError {
    let mut names: Vec<String> = srcs.iter().filter(|(_, s)| s.kind == "host").map(|(n, _)| n.clone()).collect();
    names.extend(config::hosts(ctx).keys().cloned());
    names.sort();
    names.dedup();
    let hint = match nearest(h, &names) {
        Some(n) => format!("did you mean {n}? To register a new machine: br hosts add {h} --reach ssh"),
        None => format!("br hosts lists the registered machines; to register one that ssh can reach: br hosts add {h} --reach ssh"),
    };
    BrError::new(format!("unknown host {h}"), Some(&hint))
}

fn pad(s: &str, w: usize) -> String {
    let n = s.chars().count();
    format!("{s}{}", " ".repeat(w.saturating_sub(n)))
}

fn repo_info(gh: &github::Gh, name: &str) -> BrResult<github::RepoInfo> {
    let v = gh.json(&format!("/repos/{name}"))?.ok_or_else(|| BrError::new(format!("unknown repo {name}"), Some("use the org/name form")))?;
    let Some(branch) = v["default_branch"].as_str().filter(|b| !b.is_empty()) else {
        return Err(BrError::new(format!("{name} has no default branch (an empty repository?)"), Some("push a first commit, then scan again")));
    };
    Ok(github::RepoInfo { name: name.to_string(), default_branch: branch.to_string(), archived: v["archived"].as_bool().unwrap_or(false) })
}

fn scan_local(ctx: &Ctx, a: &ScanArgs) -> BrResult<i32> {
    // The clock runs end to end (rules compiled, walk, hashing, rules matched, export), and --quiet drops the narration
    let started = std::time::Instant::now();
    progress::start(a.quiet);
    let _stop = StopProgress;
    let info = local::local_scan_with(ctx, &a.path, &a.hash, !a.quiet, a.yara.as_deref(), a.hash_all)?;
    if info.read_nothing() && !a.allow_empty {
        // a clock behind the files' dates leaves them out: say so, never a bare 0
        let future = info.future.as_ref().map(|w| format!(" ({w})")).unwrap_or_default();
        return Err(BrError::with_code(
            format!("the scan of {} hashed 0 files, so it proves nothing; no file was written{future}", info.host),
            Some("check that --path covers where files live (and --hash adds globs); --allow-empty writes the empty result anyway, and the host then stays NOT CHECKED"),
            1,
        ));
    }
    let Some(path) = &a.export else {
        // An explicit scan --local is how this machine joins an index
        if let Ok(mut st) = Store::open(ctx, true) {
            let mut src = source("host", "local", &ctx.now);
            src.empty = info.read_nothing();
            put_host_with(&mut st, ctx, &info.host, Some(host_os()), &info.items, &info.declared, &info.trust, &src, info.kind.as_deref())?;
            let g: Vec<Gap> = info.gaps.iter().map(|(s, r)| Gap { scope: s.clone(), reason: r.clone(), at: ctx.now.clone() }).collect();
            st.set_gaps(&info.host, &g)?;
            record_roots(&st, &info.host, &info.roots, true, local::scanning_home().as_deref())?;
            record_yara(&st, &info.host, &info.yara_hits, info.rules_sha256.as_deref(), &ctx.now)?;
            // A scan that goes straight into the index is a custody event, like one that is exported and imported
            let _ = st.push("custody", &json!({"event": "scanned", "at": ctx.now, "by": brx::who(ctx), "case_id": a.case.clone(), "host": info.host, "file_sha256": Value::Null, "requested_by": a.requested_by.clone().or_else(|| brx::requested_by_default(ctx))}));
            local::print_verdict(&info);
            println!("scanned {} in {} and added it to the index ({} hashed); add --export FILE to carry the result to another machine", info.host, secs(started.elapsed().as_secs()), info.hashed);
            return Ok(0);
        }
        local::print_verdict(&info);
        println!("scanned {} in {}; nothing written (there is no index here; add --export FILE to carry the result to another machine)", info.host, secs(started.elapsed().as_secs()));
        return Ok(0);
    };
    let scan = brx::ScanInfo {
        host: info.host.clone(),
        roots: info.roots.clone(),
        home: local::scanning_home(),
        items: info.items.clone(),
        stage1: info.stage1,
        hashed: info.hashed,
        simhashed: info.simhashed,
        secs: info.secs,
        os: Some(host_os()),
        kind: info.kind.clone(),
        gaps: info.gaps.clone(),
        rules_sha256: info.rules_sha256.clone(),
        yara_hits: info.yara_hits.clone(),
        yara_rules: info.yara.as_ref().map(|y| y.rules),
        declared: info.declared.clone(),
        trust: info.trust.clone(),
    };
    let p = brx::export(ctx, &scan, path, a.case.as_deref(), a.requested_by.as_deref())?;
    local::print_verdict(&info);
    println!("wrote {p}");
    if a.seal || a.sign.is_some() {
        for w in brx::write_seal(&p, std::slice::from_ref(&p), a.sign.as_deref())? {
            println!("wrote {w}");
        }
    } else {
        println!("not sealed: add --seal so the other side can check the file ({p}.sha256)");
    }
    if info.read_nothing() {
        println!("warning: this scan hashed 0 files and is marked empty; importing it leaves {} NOT CHECKED", info.host);
    }
    if !info.known {
        println!("{} will be registered as a new import-only host when this file is imported", info.host);
    }
    println!("scanned {} in {}", info.host, secs(started.elapsed().as_secs()));
    Ok(0)
}

// ---- import -------------------------------------------------------------------------------------------------------------
pub fn import(ctx: &Ctx, a: &ImportArgs) -> BrResult<i32> {
    if !a.file.ends_with(".brx") {
        return Err(BrError::new(format!("{} is not a scan file (.brx)", a.file), Some("scan the machine with br scan --local --export FILE.brx, then import that file")));
    }
    let (ok, msg, sha) = brx::check(&a.file)?;
    if !ok {
        return Err(BrError::with_code(format!("{} failed its integrity check ({msg}); nothing was imported", a.file), Some("ask for a fresh export; the file changed after it was sealed"), 1));
    }
    if msg.starts_with("not sealed") && !a.no_seal {
        return Err(BrError::with_code(
            format!("{} has no seal ({}.sha256 is missing); nothing was imported", a.file, a.file),
            Some("ask for a sealed export (br scan --local --export FILE --seal), or pass --no-seal to import it checked against its own manifest only"),
            1,
        ));
    }
    let ld = brx::load(&a.file)?;
    for k in ["host", "scanned_at", "hashed"] {
        if !ld.manifest.contains_key(k) {
            return Err(BrError::with_code(format!("{} is not a complete scan file (no {k})", a.file), Some("ask for a fresh export"), 1));
        }
    }
    let m = &ld.manifest;
    // Two machines can carry the same name ("MacBook-Pro"); --as says what this one is called in the index
    let host = a.as_name.clone().filter(|n| !n.trim().is_empty()).map(|n| n.trim().to_string()).unwrap_or_else(|| m["host"].clone());
    let scanned = norm_iso(&m["scanned_at"]).map_err(|e| {
        BrError::with_code(format!("{} has a scan time br cannot read ({}): {}", a.file, m["scanned_at"], e.msg), Some("ask for a fresh export; the time must look like 2026-05-11T14:00:00Z"), 1)
    })?;
    let hashed: usize = m["hashed"].parse().unwrap_or(0);
    // a file written by this br says whether the scan read nothing; an older one is empty when it hashed no file
    let empty = match m.get("empty") {
        Some(e) => e == "1",
        None => hashed == 0,
    };
    let mut merge_note: Option<String> = None;
    let owner_warn = a.owner.as_deref().and_then(|o| unknown_owner_warning(ctx, o));
    let mut st = Store::open(ctx, true)?;
    // a machine registered with br hosts add and never scanned is not data: its first import is its first scan
    let was_registered = st.source(&host).map(|s| never_scanned(&s)).unwrap_or(false);
    let cur = st.source(&host).filter(|s| !never_scanned(s));
    if a.owner.is_some() || a.kind.is_some() {
        let mut all = config::hosts(ctx);
        let e = all.entry(host.clone()).or_default();
        if let Some(o) = &a.owner {
            set_owner(e, o);
        }
        // A machine's kind is what the person says (or what it showed itself to be), never its name
        if let Some(k) = &a.kind {
            e.kind = Some(k.clone());
        }
        config::save_hosts(ctx, &all)?;
        if let Some(w) = &owner_warn {
            println!("{w}");
        }
    }
    // "this machine" is decided here, once, from the host name the scan was taken under and this machine's own name
    let me = ctx.host.clone().or_else(|| brx::local_host(ctx).ok());
    let this_machine = me.as_deref() == Some(m["host"].as_str());
    let roots: Vec<String> = m.get("roots").and_then(|r| serde_json::from_str(r).ok()).unwrap_or_default();
    let os = m.get("os").filter(|s| !s.is_empty()).cloned();
    let home = m.get("home").filter(|s| !s.is_empty()).cloned();
    if empty {
        if cur.is_some() {
            println!("kept the data already indexed for {host}: this scan hashed 0 files, so it proves nothing");
        } else {
            let mut src = source("host", "import-only", &scanned);
            src.empty = true;
            put_host(&mut st, ctx, &host, os, &[], &src, None)?;
            st.set_gaps(&host, &[])?; // the machine was scanned (empty): it is no longer only registered
            let mut r = roots.clone();
            r.sort();
            record_roots(&st, &host, &r, this_machine, home.as_deref())?;
            println!("{host} was not in the index: registered it as a new import-only host, marked empty");
        }
    } else {
        let new = cur.is_none();
        let mut items = ld.items.clone();
        let mut declared = ld.declared.clone();
        let mut indexed_at = scanned.clone();
        let mut g: Vec<Gap> = ld
            .manifest
            .get("gaps")
            .and_then(|g| serde_json::from_str::<Vec<(String, String)>>(g).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|(s, r)| Gap { scope: s, reason: r, at: scanned.clone() })
            .collect();
        // a lockfile the export names (or a format br cannot read) with no package behind it is a gap, as in a scan
        for it in &ld.items {
            for f in &it.files {
                let skip = f.path.split('/').rev().skip(1).any(|c| crate::collect::fs::LOCK_SKIP_DIRS.contains(&c));
                let why = if skip {
                    continue;
                } else if lock::is_unsupported_lock(&f.path) {
                    lock::NoPackages::Unsupported
                } else if crate::collect::fs::is_project_lock(&f.path) && !declared.iter().any(|d| d.loc == f.path && !d.packages.is_empty()) {
                    lock::NoPackages::NotInExport
                } else {
                    continue;
                };
                let (scope, reason) = lock::no_packages_gap(&f.path, &why);
                if !g.iter().any(|x| x.scope == scope) {
                    g.push(Gap { scope, reason, at: scanned.clone() });
                }
            }
        }
        // A host that already holds an import is not silently swapped: its files merge by path, the newer scan winning per
        // path; --replace swaps the whole host
        if let Some(c) = &cur {
            let old: Vec<HostItem> = st.present(&host, "item").into_values().filter_map(|v| serde_json::from_value(v).ok()).collect();
            let before: usize = old.iter().map(|i| i.files.len()).sum();
            if a.replace {
                let now_n: usize = items.iter().map(|i| i.files.len()).sum();
                merge_note = Some(format!("replaced the whole host: {before} files before, {now_n} now (--replace)"));
            } else {
                let mg = brx::merge_items(&old, &c.indexed_at, &items, &scanned);
                merge_note = Some(format!(
                    "merged: +{} files, {} replaced{} ({} files for {host} in the index now)",
                    mg.added,
                    mg.replaced,
                    if mg.kept > 0 { format!(", {} kept because they are newer in the index", mg.kept) } else { String::new() },
                    mg.total
                ));
                items = mg.items;
                // a lockfile the newer scan read replaces what the older one declared for it; one only the older scan read stays
                let old_decl: Vec<DeclaredLock> = st
                    .present(&host, "item")
                    .into_values()
                    .filter_map(|v| {
                        let loc = v["loc"].as_str()?.to_string();
                        let packages: Vec<LockPackage> = serde_json::from_value(v.get("declared")?.clone()).ok()?;
                        Some(DeclaredLock { loc, packages })
                    })
                    .collect();
                for od in old_decl {
                    if !declared.iter().any(|d| d.loc == od.loc) {
                        declared.push(od);
                    }
                }
                if c.indexed_at > indexed_at {
                    indexed_at = c.indexed_at.clone();
                }
                // what either scan could not read stays said
                for og in &c.gaps {
                    if !g.iter().any(|x| x.scope == og.scope && x.reason == og.reason) {
                        g.push(og.clone());
                    }
                }
            }
        }
        let src = source("host", "import-only", &indexed_at);
        // An import is a change of the index like a scan: `br diff` lists what it added. A host that was not in the
        // index before records "" as its earlier time, so everything it holds counts as added.
        let before = serde_json::json!({ host.clone(): cur.as_ref().map(|c| c.indexed_at.clone()).unwrap_or_default() });
        let mut trust = ld.trust.clone();
        if cur.is_some() && !a.replace {
            // a merge keeps the trust files only the older scan read; a file both read comes from the import
            for (_, v) in st.present(&host, "trust") {
                if let Ok(f) = serde_json::from_value::<TrustFile>(v) {
                    if !trust.files.iter().any(|x| x.path == f.path) {
                        trust.files.push(f);
                    }
                }
            }
        }
        put_host_with(&mut st, ctx, &host, os, &items, &declared, &trust, &src, ld.manifest.get("kind").map(|k| k.as_str()).filter(|k| !k.is_empty()))?;
        let change = json!({"at": ctx.now, "before": before, "kind": "import", "host": host});
        st.kv_set("last_scan", &change)?;
        st.push("scans", &change)?;
        st.set_gaps(&host, &g)?;
        let old: Vec<String> = st.imports().get(&host).and_then(|v| v["roots"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())).unwrap_or_default();
        let mut all: std::collections::BTreeSet<String> = old.into_iter().collect();
        all.extend(roots);
        record_roots(&st, &host, &all.into_iter().collect::<Vec<_>>(), this_machine, home.as_deref())?;
        // The rules' matches the file carries reach the index, with the rules' hash
        record_yara(&st, &host, &ld.yara_hits, m.get("rules_sha256").map(|r| r.as_str()).filter(|r| !r.is_empty()), &scanned)?;
        if new && was_registered {
            println!("{host} was registered and never scanned: this is its first scan");
        } else if new {
            println!("{host} was not in the index: registered it as a new import-only host");
            if this_machine {
                println!("  {host} is this machine, so it now counts as a source in every hunt and evidence file; to take it out again: br hosts --remove {host}");
            }
        }
    }
    let mut have: std::collections::BTreeSet<(String, String, Option<String>)> = Default::default();
    let custody = st.list("custody");
    for c in &custody {
        have.insert((c["event"].as_str().unwrap_or("").into(), c["at"].as_str().unwrap_or("").into(), c["case_id"].as_str().map(str::to_string)));
    }
    for (ev, at, by, case, fsha, req) in &ld.custody {
        let case = case.clone().filter(|c| !c.is_empty());
        if !have.contains(&(ev.clone(), at.clone(), case.clone())) {
            st.push("custody", &json!({"event": ev, "at": at, "by": by, "case_id": case, "host": host, "file_sha256": fsha, "requested_by": req}))?;
        }
    }
    let again = st.list("custody").iter().any(|c| c["event"] == "imported" && c["file_sha256"].as_str() == Some(sha.as_str()));
    if !again {
        let case = a.case.clone().or_else(|| m.get("case_id").cloned().filter(|c| !c.is_empty()));
        st.push(
            "custody",
            &json!({"event": "imported", "at": ctx.now, "by": brx::who(ctx), "case_id": case, "host": host, "file_sha256": sha, "requested_by": a.requested_by.clone().or_else(|| ld.custody.iter().find_map(|c| c.5.clone().filter(|r| !r.is_empty()))).or_else(|| brx::requested_by_default(ctx))}),
        )?;
    }
    if msg.starts_with("not sealed") {
        println!("note: the file was not sealed; it was checked against its own manifest only");
    }
    let has_owner = config::hosts(ctx).get(&host).map(|c| c.owner.is_some() || c.owner_team.is_some()).unwrap_or(false);
    if !has_owner {
        println!("{host} has no owner on record, so a hunt cannot say whose machine it is: br import {} --owner @login ties it to a person (or --owner @org/team)", a.file);
    }
    println!("Imported {host} (scanned {}): {} hashed, {}{}", fmtz(&scanned), plural(hashed, "file"), plural(ld.n_pkgs, "package"), merge_note.as_ref().map(|n| format!("; {n}")).unwrap_or_default());
    if empty {
        println!("warning: 0 files hashed. {host} stays NOT CHECKED until a scan that hashed files is imported (check --path when scanning)");
    } else if again {
        println!("this file was imported before; its chain-of-custody entry was not repeated");
    }
    Ok(0)
}

// ---- hosts ----------------------------------------------------------------------------------------------------------------
struct Pop {
    hosts: BTreeMap<String, Source>,
    runners: Vec<String>,
    laptops: Vec<String>,
    members: Vec<Person>,
    missing: Vec<Person>,
    /// where the member list comes from, as the tail of "12 members visible to this token in GitHub"
    source_label: String,
    /// Why each member in scope is, or is not, covered
    reasons: Vec<crate::query::coverage::MemberReason>,
}

fn host_kind(ctx: &Ctx, name: &str, v: &View) -> &'static str {
    if let Some(k) = config::hosts(ctx).get(name).and_then(|c| c.kind.clone()) {
        return view_kind(&k);
    }
    v.hosts.get(name).and_then(|h| h.kind.as_deref()).map(view_kind).unwrap_or("host")
}

fn population(ctx: &Ctx, v: &View) -> Pop {
    let hosts: BTreeMap<String, Source> = v.sources.iter().filter(|(_, s)| s.kind == "host").map(|(n, s)| (n.clone(), s.clone())).collect();
    let runners: Vec<String> = hosts.iter().filter(|(n, _)| host_kind(ctx, n, v) == "runner").map(|(n, _)| n.clone()).collect();
    let laptops: Vec<String> = hosts.iter().filter(|(n, _)| host_kind(ctx, n, v) == "laptop").map(|(n, _)| n.clone()).collect();
    // Who has a laptop scan here is decided in one place, the same one status, hunt, notify and evidence use
    let ix = crate::query::index::Index::new(v, &ctx.now);
    let mc = crate::query::coverage::members_covered(&ix, &crate::query::hunt::Query::default());
    let members: Vec<Person> = v.people.iter().filter(|p| !p.login.ends_with("[bot]")).cloned().collect();
    let missing = members.iter().filter(|m| mc.uncovered_ids.contains(&m.login)).cloned().collect();
    Pop { hosts, runners, laptops, members, missing, source_label: mc.source_label, reasons: mc.reasons }
}

fn population_line(v: &View, p: &Pop, self_listing: bool) -> String {
    let mut parts = vec![];
    if !p.runners.is_empty() {
        parts.push(plural(p.runners.len(), "runner"));
    }
    if !p.laptops.is_empty() {
        parts.push(plural(p.laptops.len(), "laptop"));
    }
    let mut line = format!("hosts: {} indexed", p.hosts.len());
    if !parts.is_empty() {
        line += &format!(" ({})", parts.join(", "));
    }
    if !p.members.is_empty() {
        let org = v.org.github.clone().unwrap_or_else(|| "the org".into());
        line += &format!("; {org} has {} {}, {} with no laptop scan here", plural(p.members.len(), "member"), p.source_label, p.missing.len());
        // br hosts prints the list right below, so it does not tell you to run itself
        if !p.missing.is_empty() && !self_listing {
            line += ": run br hosts to list them";
        }
    }
    line
}

/// Removing a host takes it out of every list it is in: the index (hunts, status, hosts) and the registered machines.
fn hosts_remove(ctx: &Ctx, name: &str) -> BrResult<i32> {
    let st = Store::open(ctx, false).ok();
    let in_index = st.as_ref().and_then(|s| s.source(name)).filter(|s| s.kind == "host").is_some();
    let mut all = config::hosts(ctx);
    let registered = all.remove(name).is_some();
    if !in_index && !registered {
        let known: Vec<String> = st.as_ref().map(|s| s.sources().into_iter().filter(|(_, x)| x.kind == "host").map(|(n, _)| n).collect()).unwrap_or_default();
        let hint = match nearest(name, &known) {
            Some(n) => format!("did you mean {n}? br hosts lists them"),
            None => "br hosts lists them".to_string(),
        };
        return Err(BrError::new(format!("{name} is not a host in the index"), Some(&hint)));
    }
    if let Some(st) = &st {
        if in_index {
            st.remove_source(name, &ctx.now)?;
            st.drop_import(name)?;
        }
        // Taking a machine out of the index is a custody event: who, when, and which machine
        st.push(
            "custody",
            &json!({"event": "host removed", "at": ctx.now, "by": brx::who(ctx), "case_id": Value::Null, "host": name, "file_sha256": Value::Null, "requested_by": brx::requested_by_default(ctx)}),
        )?;
    }
    if registered {
        config::save_hosts(ctx, &all)?;
    }
    println!("removed {name} from the index and from the registered machines; its chain-of-custody entries are kept");
    Ok(0)
}

/// `--owner @login` names a person or a team; when the index holds GitHub's people (or teams) and this one is not among
/// them, say so, with the nearest login, because a hunt can then never tie the machine to that person.
pub fn unknown_owner_warning(ctx: &Ctx, owner: &str) -> Option<String> {
    let v = ctx.view().ok()?;
    let o = owner.trim_start_matches('@');
    if o.contains('/') {
        if v.teams.is_empty() || v.teams.iter().any(|t| t.id.trim_start_matches('@').eq_ignore_ascii_case(o)) {
            return None;
        }
        let ids: Vec<String> = v.teams.iter().map(|t| t.id.clone()).collect();
        let near = config::teams(ctx).contains_key(&format!("@{o}")).then_some(()).map_or(String::new(), |_| " (teams.yaml knows it)".to_string());
        return Some(format!("warning: GitHub does not know the team @{o}{near}; the teams it lists are {}", ids.join(", ")));
    }
    let people: Vec<String> = v.people.iter().filter(|p| !p.login.ends_with("[bot]")).map(|p| p.login.clone()).collect();
    if people.is_empty() || people.iter().any(|p| p.eq_ignore_ascii_case(o)) {
        return None;
    }
    let near = nearest(&o.to_lowercase(), people.iter()).map(|n| format!("; did you mean @{n}?")).unwrap_or_default();
    Some(format!(
        "warning: GitHub does not know the login @{o} ({} people on record{near}). A hunt cannot tie this machine to someone it does not know: check the login, or set it again with --owner",
        people.len()
    ))
}

fn set_owner(e: &mut config::HostCfg, owner: &str) {
    let o = owner.trim_start_matches('@');
    if o.contains('/') {
        e.owner_team = Some(format!("@{o}"));
        e.owner = None;
    } else {
        e.owner = Some(o.to_string());
        e.owner_team = None;
    }
}

fn hosts_add(ctx: &Ctx, a: &HostsAdd) -> BrResult<i32> {
    let mut all = config::hosts(ctx);
    let e = all.entry(a.name.clone()).or_default();
    if let Some(o) = &a.owner {
        set_owner(e, o);
        if let Some(w) = unknown_owner_warning(ctx, o) {
            println!("{w}");
        }
    }
    if let Some(k) = &a.kind {
        e.kind = Some(k.clone());
    }
    if let Some(r) = &a.reach {
        e.reach = Some(r.clone());
    }
    if let Some(t) = &a.target {
        e.target = Some(t.clone());
    }
    if !a.roots.is_empty() {
        e.roots = a.roots.clone();
    }
    let reach = e.reach.clone();
    config::save_hosts(ctx, &all)?;
    // From here on it is a source, never scanned (with no index yet, br init registers it)
    let joined = match Store::open(ctx, false) {
        Ok(mut st) => {
            register_host(&mut st, ctx, &a.name)?;
            true
        }
        Err(_) => false,
    };
    let how = if reach.as_deref() == Some("ssh") {
        format!("br scan --host {} reads it over ssh", a.name)
    } else {
        format!("on it run br scan --local --export {0}.brx --seal, then here br import {0}.brx", a.name)
    };
    let state = if joined { "; never scanned, so every hunt lists it as not checked until it is" } else { "; it joins the index, never scanned, when you run br init" };
    println!("registered {}{state}: {how}", a.name);
    Ok(0)
}

pub fn hosts(ctx: &Ctx, a: &HostsArgs) -> BrResult<i32> {
    match &a.sub {
        Some(HostsSub::Add(x)) => return hosts_add(ctx, x),
        Some(HostsSub::Remove { name }) => return hosts_remove(ctx, name),
        _ => {}
    }
    if let Some(r) = &a.remove {
        return hosts_remove(ctx, r);
    }
    let v = ctx.view()?;
    let p = population(ctx, &v);
    let cfg = config::hosts(ctx);
    println!("{}", population_line(&v, &p, true));
    let mut rows = vec![];
    for (n, s) in &p.hosts {
        let c = cfg.get(n).cloned().unwrap_or_default();
        let owner = match c.owner.as_ref().and_then(|l| v.people.iter().find(|x| &x.login == l)) {
            Some(per) => per.name.clone().unwrap_or_else(|| per.login.clone()),
            None => c.owner.clone().or(c.owner_team.clone()).unwrap_or_else(|| "-".into()),
        };
        let state = if never_scanned(s) {
            "registered, never scanned"
        } else if s.empty {
            "empty scan: not checked"
        } else if is_stale(&ctx.now, &s.indexed_at)? {
            "stale"
        } else {
            "fresh"
        };
        let (at, age) = if never_scanned(s) { ("never".to_string(), "-".to_string()) } else { (fmt(&s.indexed_at), age_str(&ctx.now, &s.indexed_at)) };
        rows.push(vec![n.clone(), host_kind(ctx, n, &v).into(), owner, at, age, if s.reach.is_empty() { "-".into() } else { s.reach.clone() }, state.into()]);
    }
    println!();
    println!("{}", table(&["MACHINE", "KIND", "OWNER", "INDEXED", "AGE", "REACH", "STATE"], &rows, 0).join("\n"));
    if !p.missing.is_empty() {
        println!();
        println!("NO LAPTOP SCAN HERE ({} of {} members)", p.missing.len(), p.members.len());
        let mrows: Vec<Vec<String>> = p
            .missing
            .iter()
            .map(|m| {
                let why = p.reasons.iter().find(|r| r.login == m.login).map(|r| r.reason.clone()).unwrap_or_else(|| "-".into());
                vec![m.name.clone().unwrap_or_else(|| m.login.clone()), m.team.clone().unwrap_or_else(|| "-".into()), why]
            })
            .collect();
        println!("{}", table(&["MEMBER", "TEAM", "WHY NOT COVERED"], &mrows, 2).join("\n"));
        println!();
        println!("to add one: on their laptop run  br scan --local --export NAME.brx --seal ; here run  br import NAME.brx --owner @login");
    }
    println!();
    println!("a host scan reads the files under its scan roots that match the hash filter (br status --config); it does not read container layer caches");
    let _ = num;
    Ok(0)
}

// ---- teams, advisory, debug ----------------------------------------------------------------------------------------
pub fn teams(ctx: &Ctx, a: &TeamsArgs) -> BrResult<i32> {
    if let Some(t) = &a.team {
        return crate::cmd::status::team_show(ctx, t);
    }
    let (team, slack, jira) = match &a.sub {
        None | Some(TeamsSub::List) => return teams_list(ctx),
        Some(TeamsSub::Set { team, slack, jira }) => (team, slack, jira),
    };
    let id = if team.starts_with('@') { team.clone() } else { format!("@{team}") };
    if !id.contains('/') {
        return Err(BrError::new(format!("{team} is not a team id"), Some("write @org/team, e.g. @acme/web")));
    }
    config::set_team(ctx, &id, slack.as_deref(), jira.as_deref())?;
    println!("set {id}{}{}", slack.as_ref().map(|s| format!(" slack {s}")).unwrap_or_default(), jira.as_ref().map(|s| format!(" jira {s}")).unwrap_or_default());
    Ok(0)
}

fn teams_list(ctx: &Ctx) -> BrResult<i32> {
    let v = ctx.view().ok();
    let cfg = config::teams(ctx);
    let mut rows: Vec<Vec<String>> = vec![];
    let dash = |o: &Option<String>| o.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| "-".into());
    let mut seen: Vec<String> = vec![];
    // FROM names the source of each value: GitHub knows a team and its lead; Slack and Jira come from teams.yaml
    let from = |github: bool, lead: bool, slack: &Option<String>, jira: &Option<String>| -> String {
        let mut gh: Vec<&str> = vec![];
        let mut yaml: Vec<&str> = vec![];
        if github {
            gh.push("team");
            if lead {
                gh.push("lead");
            }
        } else {
            yaml.push("team");
        }
        if slack.as_ref().is_some_and(|x| !x.is_empty()) {
            yaml.push("slack");
        }
        if jira.as_ref().is_some_and(|x| !x.is_empty()) {
            yaml.push("jira");
        }
        let mut parts = vec![];
        if !gh.is_empty() {
            parts.push(format!("GitHub: {}", gh.join(", ")));
        }
        if !yaml.is_empty() {
            parts.push(format!("teams.yaml: {}", yaml.join(", ")));
        }
        if !github {
            parts.push("not in GitHub".to_string());
        }
        parts.join("; ")
    };
    for t in v.iter().flat_map(|v| v.teams.iter()) {
        let lead = t.lead.as_ref().map(|l| v.as_ref().and_then(|v| v.people.iter().find(|p| &p.login == l)).and_then(|p| p.name.clone()).unwrap_or_else(|| l.clone()));
        // the Slack channel and Jira project in the View come from teams.yaml, whatever GitHub lists
        rows.push(vec![t.id.clone(), dash(&t.slack), dash(&t.jira), dash(&lead), from(true, lead.is_some(), &t.slack, &t.jira)]);
        seen.push(t.id.clone());
    }
    for (id, c) in &cfg {
        if !seen.contains(id) {
            rows.push(vec![id.clone(), dash(&c.slack), dash(&c.jira), "-".into(), from(false, false, &c.slack, &c.jira)]);
        }
    }
    if rows.is_empty() {
        println!("no teams yet");
        println!("br init --org ORG reads GitHub's teams; br teams set @org/team --slack '#channel' --jira KEY says where one is told");
        return Ok(0);
    }
    println!("{}", table(&["TEAM", "SLACK", "JIRA", "LEAD", "FROM"], &rows, 0).join("\n"));
    let unset = rows.iter().filter(|r| r[1] == "-" && r[2] == "-").count();
    if unset > 0 {
        println!();
        println!("{unset} of these have no Slack channel or Jira project yet: br teams set @org/team --slack '#channel' --jira KEY");
    }
    Ok(0)
}

pub fn debug(ctx: &Ctx, a: &DebugArgs) -> BrResult<i32> {
    let DebugSub::View = a.sub;
    let v = ctx.view()?;
    let mut j = serde_json::to_value(&v).map_err(|e| BrError::with_code(e.to_string(), None, 1))?;
    if let Some(o) = j.as_object_mut() {
        if v.advisories.is_empty() {
            o.remove("advisories");
        }
    }
    println!("{}", crate::collect::util::py_dumps(&j, Some(1), true));
    let _: Option<Value> = None;
    Ok(0)
}

#[cfg(test)]
mod r65_tests {
    use super::*;

    // The runner hint carries --owner (and says what kind), so the registered machine can be told apart by owner in a hunt
    #[test]
    fn the_runner_hint_names_an_owner() {
        let t = unregistered_tail("acme", &["ci-1", "ci-2"]);
        assert!(t.contains("ci-1, ci-2") && t.contains("--kind runner --reach ssh --owner @acme/TEAM"), "{t}");
        assert!(t.contains("br import FILE.brx --kind runner --owner @acme/TEAM"), "{t}");
        assert_eq!(unregistered_tail("acme", &[]), "");
    }
}
