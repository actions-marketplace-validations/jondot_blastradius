//! `br hunt`.

use crate::cli::QueryArgs;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::out::render as R;
use crate::query::hunt::{self as H, FKind, HuntResult, Query};
use crate::query::index::Index;
use crate::query::iocs as I;
use crate::query::util::{parse_dur, parse_t, parse_window, plural, read_text_arg};
use crate::view::View;

#[derive(Debug, Default, clap::Args)]
pub struct HuntArgs {
    #[command(flatten)]
    pub q: QueryArgs,
    /// table (default; overview on a terminal), json, csv, md, summary (for execs and customers), overview (a short colored first screen), slack, jira, sarif (SARIF 2.1.0, for code scanning)
    #[arg(long, value_name = "FMT")]
    pub format: Option<String>,
    /// limit the sections shown, comma separated: repos, ci (alias runs), caches, artifacts, images, hosts, releases
    #[arg(long, value_name = "KINDS")]
    pub only: Option<String>,
    /// only this host
    #[arg(long, value_name = "NAME")]
    pub host: Option<String>,
    /// include versions that were bumped or reverted in commit history
    #[arg(long)]
    pub history: bool,
    #[arg(long, hide = true)]
    pub secrets: bool,
    /// hide the SECRETS TO ROTATE roll-up (shown by default)
    #[arg(long = "no-secrets")]
    pub no_secrets: bool,
    /// list the excluded near-misses (prereleases, look-alike names) with the reason
    #[arg(long = "near-misses")]
    pub near: bool,
    /// with --format summary: customers drops internal names and secret names
    #[arg(long, value_name = "WHO")]
    pub audience: Option<String>,
    /// refuse to answer (exit 5) if a source in scope is older than this
    #[arg(long = "max-age", value_name = "DUR")]
    pub max_age: Option<String>,
    /// exit 10 when found (default), or with none exit 11 when nothing is found
    #[arg(long = "fail-if", value_name = "found|none", default_value = "found")]
    pub fail_if: String,
    /// exit 3 when the answer is CLEAR WITH GAPS (some sources were not checked)
    #[arg(long)]
    pub strict: bool,
    /// print one line: verdict, indicator, count, index time
    #[arg(long)]
    pub quiet: bool,
    /// with table or md output: show full digests instead of 12 characters
    #[arg(long)]
    pub wide: bool,
    /// evaluate this YARA rules file against file content (needs --live or --path)
    #[arg(long, value_name = "FILE")]
    pub yara: Option<String>,
    /// with --yara: read the ssh-reachable hosts now
    #[arg(long)]
    pub live: bool,
    /// hunt the checkout in DIR: read its lockfiles and manifests (and installed packages) into a throwaway index, with no
    /// index of yours and no network (the CI gate for a checkout). With --yara: read this directory with the rules
    #[arg(long, value_name = "DIR")]
    pub path: Option<String>,
    /// per owner: what is open, fixed (and when) and new since the first hunt of this indicator
    #[arg(long)]
    pub progress: bool,
    /// text files similar to this sample (a file on disk, or an indexed file by hash)
    #[arg(long, value_name = "FILE|sha256:HASH[~0.85]")]
    pub similar: Option<String>,
    /// for a hash found inside a package's install, also look for files like the others shipped with it (reported apart as
    /// "similar, not identical")
    #[arg(long)]
    pub similar_related: bool,
}

const FORMATS: [&str; 9] = ["table", "json", "csv", "slack", "jira", "md", "summary", "sarif", "overview"];

pub fn validate(a: &HuntArgs) -> BrResult<()> {
    let fm = a.format.clone().unwrap_or_else(|| "table".into());
    if !FORMATS.contains(&fm.as_str()) {
        return Err(BrError::new(format!("unknown format \"{fm}\""), Some("choose table, json, csv, slack, jira, md, summary or sarif")));
    }
    if a.fail_if != "found" && a.fail_if != "none" {
        return Err(BrError::new(format!("--fail-if takes found or none (got \"{}\")", a.fail_if), Some("example: --fail-if none")));
    }
    if a.secrets {
        return Err(BrError::new("--secrets does nothing: the SECRETS TO ROTATE roll-up is always shown", Some("use --no-secrets to hide it")));
    }
    if let Some(au) = &a.audience {
        if au != "customers" {
            return Err(BrError::new(format!("unknown audience \"{au}\""), Some("the only audience is customers; use --format summary --audience customers")));
        }
        if fm != "summary" {
            return Err(BrError::new("--audience only changes --format summary", Some("add --format summary, or drop --audience")));
        }
    }
    if a.wide && (!(fm == "table" || fm == "md") || a.quiet || a.yara.is_some()) {
        return Err(BrError::new("--wide only changes the table and md output", Some("use --format table or --format md, or drop --wide")));
    }
    if a.live && a.yara.is_none() {
        return Err(BrError::new("--live only applies to --yara", Some("add --yara FILE, or drop --live (hunts read the index, which is already there)")));
    }
    if a.path.is_some() && a.yara.is_none() {
        for (flag, set) in [("--repo", a.q.repo.is_some()), ("--owner", a.q.owner.is_some()), ("--host", a.host.is_some()), ("--progress", a.progress), ("--similar", a.similar.is_some())] {
            if set {
                return Err(BrError::new(format!("{flag} does nothing with --path"), Some("--path hunts the one directory; drop the flag")));
            }
        }
    }
    if fm == "sarif" && a.yara.is_some() {
        return Err(BrError::new("--yara prints its own rule matches and has no SARIF form", Some("drop --format sarif, or drop --yara")));
    }
    if fm == "sarif" && a.progress {
        return Err(BrError::new("--progress prints a per-owner table and has no SARIF form", Some("drop --progress, or use --format sarif alone")));
    }
    if a.quiet && fm != "table" {
        return Err(BrError::new(format!("--quiet prints one line and ignores --format {fm}"), Some("drop --quiet or drop --format")));
    }
    Ok(())
}

pub fn not_built(what: &str) -> BrError {
    BrError::with_code(format!("{what} is not built yet"), Some("phase 2"), 1)
}

/// The query's inputs, shared by hunt and the commands that follow it (notify, fix, purge, ...).
pub struct QueryInputs<'a> {
    pub q: &'a QueryArgs,
    pub only: Option<&'a str>,
    pub host: Option<&'a str>,
    pub near: bool,
    pub no_secrets: bool,
    pub history: bool,
    pub similar: Option<&'a str>,
}

/// What reading `--text` found and could not read.
#[derive(Debug, Default, Clone)]
pub struct TextReport {
    /// package mentions the text makes that did not become an indicator, as written
    pub unread: Vec<String>,
    pub mentions: usize,
}

pub fn build_query(ctx: &Ctx, view: Option<&View>, a: &QueryInputs, announce: bool) -> BrResult<Query> {
    Ok(build_query_ex(ctx, view, a, announce)?.0)
}

/// A window that came from the advisory (OSV, a local file, or the operator's note on it), as opposed to `--window` or the text.
fn window_is_advisory(src: &Option<String>) -> bool {
    matches!(src.as_deref(), Some(s) if s == "advisory" || s.starts_with("your note") || s == "OSV")
}

pub fn build_query_ex(ctx: &Ctx, view: Option<&View>, a: &QueryInputs, announce: bool) -> BrResult<(Query, TextReport)> {
    let mut q = Query::default();
    let mut report = TextReport::default();
    let mut strs: Vec<String> = a.q.iocs.clone();
    let (mut adv, mut win, mut src) = (None, None, None);
    let mut hash_names: Vec<(String, String)> = vec![];
    let mut text_iocs: Vec<I::Ioc> = vec![];
    let mut text_fixed: Vec<(String, String, String)> = vec![];
    if let Some(id) = a.q.advisory.as_ref().filter(|x| !x.is_empty()) {
        let advs = view.map(|v| v.advisories.as_slice()).unwrap_or(&[]);
        // An id the index and the notes do not hold is asked of OSV before it is "not found"
        let r = crate::collect::lookup::resolve(ctx, advs, id)?;
        if r.packages.is_empty() {
            strs.extend(r.affected.iter().cloned());
        } else {
            // indicators that are not packages (hashes, simhashes, action commits) travel in `affected` beside `packages`
            strs.extend(r.affected.iter().filter(|x| x.starts_with("sha256:") || x.starts_with("simhash:") || (x.starts_with("action:") && x.contains('#'))).cloned());
        }
        if r.window.is_some() {
            win = r.window.clone();
            // the window says where it came from: the operator's note, or the advisory itself
            let from = view.and_then(|v| v.advisories.iter().find(|x| x.id == r.id)).and_then(|x| x.provenance.window.clone());
            src = Some(from.unwrap_or_else(|| "advisory".to_string()));
        }
        hash_names.extend(r.hash_names.iter().cloned());
        adv = Some(r);
    }
    if let Some(t) = a.q.text.as_ref().filter(|x| !x.is_empty()) {
        // Advisory ids in the text are fetched, and "fixed in X" in the text is the fixed version of the packages beside it
        let tr = crate::collect::lookup::read_text(ctx, view.map(|v| v.advisories.as_slice()).unwrap_or(&[]), &read_text_arg(t)?)?;
        let ex = tr.ex.clone();
        let (found, w) = (ex.iocs.clone(), ex.window.clone());
        let fix_lines = {
            let mut tmp: Vec<I::Ioc> = found.iter().filter_map(|s| I::parse_ioc(s, None).ok()).collect();
            crate::collect::lookup::apply_text_fixes(&mut tmp, &ex.fixed)
        };
        text_iocs = tr.pkg_iocs.clone();
        text_fixed = ex.fixed.clone();
        strs.extend(tr.strs.iter().cloned());
        if adv.is_none() {
            adv = tr.advisories.first().cloned();
        }
        report = TextReport { unread: ex.unread.clone(), mentions: ex.mentions };
        let say = |u: &String| format!("mentioned but not read: \"{u}\" (say it as eco:name@version)");
        if announce {
            // fewer packages read than the text mentions is said right on the stage line
            let tail = if ex.unread.is_empty() { String::new() } else { format!(" (read {} of {} package mentions; {} not read)", ex.mentions - ex.unread.len(), ex.mentions, ex.unread.len()) };
            if !found.is_empty() || tr.notes.is_empty() {
                println!("extracted {}{tail}", plural(found.len(), "indicator"));
            }
            for s in &found {
                println!("  {s}");
            }
            for u in &ex.unread {
                println!("{}", say(u));
            }
            for n in tr.notes.iter().chain(fix_lines.iter()) {
                println!("{n}");
            }
            println!();
        } else {
            for u in &ex.unread {
                eprintln!("{}", say(u));
            }
            for n in tr.notes.iter().chain(fix_lines.iter()) {
                eprintln!("{n}");
            }
        }
        strs.extend(found);
        hash_names.extend(ex.hash_names.iter().cloned());
        if w.is_some() && win.is_none() {
            win = w;
            src = Some("text".to_string());
        }
    }
    let ix = view.map(|v| Index::new(v, &ctx.now));
    if let Some(sp) = a.similar {
        strs.push(crate::cmd::similar::similar_ioc(ix.as_ref(), sp)?);
    }
    let lookup = |n: &str, v: &str| -> Vec<String> {
        match &ix {
            None => vec![],
            Some(ix) if v == "sha256-prefix" => H::hash_prefix_matches(ix, n),
            Some(ix) => ix.package_ecos(n),
        }
    };
    let mut parsed: Vec<I::Ioc> = vec![];
    if let Some(r) = &adv {
        // ruling 2: the advisory's own per-package versions and ranges decide a match
        for p in &r.packages {
            if I::br_eco(&p.ecosystem) == "action" {
                // an action's "versions" are its tags and commit shas
                for v in &p.versions {
                    let hex = v.len() == 40 && v.chars().all(|c| c.is_ascii_hexdigit());
                    let s = if hex { format!("action:{}#{v}", p.name) } else { format!("action:{}@{v}", p.name) };
                    if let Ok(i) = I::parse_ioc(&s, None) {
                        if !parsed.iter().any(|x| x.text == i.text) {
                            parsed.push(i);
                        }
                    }
                }
                continue;
            }
            if let Some(i) = I::Ioc::from_package(p) {
                if !parsed.iter().any(|x| x.text == i.text) {
                    parsed.push(i);
                }
            }
        }
        // ruling 1: an advisory with nothing to match on is an error, never a clear
        if parsed.is_empty() && r.affected.is_empty() {
            return Err(BrError::new(
                format!("advisory {} has no package br can match against", r.id),
                Some(&format!("it lists no package in npm, pypi, cargo or go with a version or range; pass indicators too (npm:name@1.2.3) or --text FILE, or add what you know: br advisory note {} --ioc eco:name@version", r.id)),
            ));
        }
    }
    for s in &strs {
        let p = I::parse_ioc(s, Some(&lookup))?;
        if !parsed.iter().any(|x| x.text == p.text) {
            parsed.push(p);
        }
    }
    // The packages of the advisories the text named, and the fixed versions the text states
    for i in text_iocs {
        if !parsed.iter().any(|x| x.text == i.text) {
            parsed.push(i);
        }
    }
    crate::collect::lookup::apply_text_fixes(&mut parsed, &text_fixed);
    // hashes recorded as benign with `br advisory note ID --benign sha256:H --why TEXT` leave the hunt
    let mut benign: Vec<(String, String, String)> = vec![];
    {
        let mut pool: Vec<(String, String, String)> = vec![];
        match &adv {
            Some(r) => {
                if let Some(a0) = view.and_then(|v| v.advisories.iter().find(|x| x.id == r.id)) {
                    pool.extend(a0.benign.iter().map(|b| (b.sha256.clone(), r.id.clone(), b.why.clone())));
                }
            }
            None => {
                for a0 in view.map(|v| v.advisories.as_slice()).unwrap_or(&[]) {
                    pool.extend(a0.benign.iter().map(|b| (b.sha256.clone(), a0.id.clone(), b.why.clone())));
                }
            }
        }
        for (h, id, why) in pool {
            if parsed.iter().any(|p| p.kind == I::IocKind::Sha256 && p.text == h) && !benign.iter().any(|b| b.0 == h) {
                benign.push((h, id, why));
            }
        }
        parsed.retain(|p| !benign.iter().any(|b| b.0 == p.text));
    }
    if let Some(w) = a.q.window.as_ref().filter(|x| !x.is_empty()) {
        win = Some(parse_window(w)?);
        src = Some("--window".to_string());
    }
    // --now asks what is present, so a window that only came from the advisory text does not narrow it
    if a.q.now && window_is_advisory(&src) {
        win = None;
        src = None;
    }
    q.iocs = parsed;
    q.benign = benign;
    hash_names.sort();
    hash_names.dedup();
    q.hash_names = hash_names;
    q.adv = adv;
    q.window = win;
    q.window_src = src;
    q.repo = match (view, a.q.repo.as_ref().filter(|r| !r.is_empty())) {
        (Some(v), Some(r)) => Some(resolve_repo(v, r).unwrap_or_else(|| r.clone())),
        _ => a.q.repo.clone(),
    };
    q.owner = a.q.owner.clone();
    q.host = a.host.map(str::to_string);
    q.now_only = a.q.now;
    q.since = a.q.since.clone();
    if let Some(only) = a.only.filter(|o| !o.is_empty()) {
        let sel: std::collections::BTreeSet<String> = only.split(',').map(|x| x.trim()).map(|x| if x == "runs" { "ci".to_string() } else { x.to_string() }).collect();
        if let Some(bad) = sel.iter().find(|x| !H::KINDS.contains(&x.as_str())) {
            return Err(BrError::new(format!("unknown section \"{bad}\""), Some(&format!("choose from: {} (runs is the same as ci)", H::KINDS.join(", ")))));
        }
        q.only = sel;
    }
    q.near = a.near;
    q.secrets = !a.no_secrets;
    q.history = a.history;
    Ok((q, report))
}

/// The lines that say a hash is benign (empty when none is).
pub fn benign_lines(q: &Query) -> Vec<String> {
    q.benign.iter().map(|(h, id, why)| format!("{h} is benign: {id} says {why}. Nothing to remove, nothing to rotate.")).collect()
}

/// The indexed spelling of a repo name: GitHub names are case-insensitive, so `Acme/Frontend` finds `acme/frontend`.
pub fn resolve_repo(view: &View, r: &str) -> Option<String> {
    if view.repos.contains_key(r) {
        return Some(r.to_string());
    }
    let lo = r.to_lowercase();
    view.repos.keys().find(|k| k.to_lowercase() == lo).cloned()
}

fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i];
        for j in 1..=b.len() {
            let sub = prev[j - 1] + usize::from(a[i - 1] != b[j - 1]);
            cur.push(sub.min(prev[j] + 1).min(cur[j - 1] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// The indexed repo closest to `r` by edit distance (case-insensitive), if any.
pub fn closest_repo(view: &View, r: &str) -> Option<String> {
    let lo = r.to_lowercase();
    view.repos.keys().min_by_key(|k| edit_distance(&lo, &k.to_lowercase())).cloned()
}

pub fn check_repo(view: &View, repo: &Option<String>) -> BrResult<()> {
    if let Some(r) = repo.as_ref().filter(|r| !r.is_empty()) {
        // A repo that only builds images (it is not itself indexed) is still a scope: --repo reaches the images built from it
        let builds_image = view.images.iter().any(|b| b.source.as_ref().and_then(|s| s.repo.as_deref()) == Some(r.as_str()));
        if !view.sources.is_empty() && resolve_repo(view, r).is_none() && !builds_image {
            let hint = match closest_repo(view, r) {
                Some(c) => format!("did you mean {c}? Use the org/name form"),
                None => "use the org/name form, e.g. acme/frontend".to_string(),
            };
            return Err(BrError::new(format!("unknown repo {r}"), Some(&hint)));
        }
    }
    Ok(())
}

pub fn exit_code(res: &HuntResult, a: &HuntArgs) -> i32 {
    // A check never passes while the bad version is present, whatever the window says
    let found = !H::findings(res).is_empty() || !res.present_after.is_empty();
    if a.fail_if == "none" {
        return if found { 0 } else { 11 };
    }
    if found {
        return 10;
    }
    if a.strict && (!res.gaps.is_empty() || !res.not_checked.is_empty()) {
        return 3;
    }
    0
}

/// With no --format, a terminal gets the overview; a pipe, a file, CI and every flag that shapes the table keep the table.
fn default_format(a: &HuntArgs) -> &'static str {
    use std::io::IsTerminal;
    let plain = !(a.quiet || a.wide || a.progress || a.history || a.near || a.yara.is_some() || a.similar.is_some() || a.similar_related || a.audience.is_some());
    if a.format.is_none() && plain && std::io::stdout().is_terminal() {
        "overview"
    } else {
        "table"
    }
}

pub fn run(a: &HuntArgs, ctx: &Ctx) -> BrResult<i32> {
    validate(a)?;
    let fm = a.format.clone().unwrap_or_else(|| default_format(a).into());
    if a.yara.is_some() {
        return crate::cmd::yara::run(a, ctx);
    }
    let q0 = &a.q;
    if q0.iocs.is_empty() && q0.advisory.is_none() && q0.text.is_none() && a.similar.is_none() {
        return Err(BrError::new("nothing to hunt for", Some("pass an indicator (npm:name@1.2.3), --advisory ID or --text FILE")));
    }
    // a home holding only an empty index file (case 52 writes index.json) is an empty index: NO DATA (exit 5); a home with
    // no index at all stays "no index at PATH"
    // --path DIR hunts the checkout in DIR in a throwaway index; nothing of the real index is read but its advisories
    let view = match (&a.path, ctx.view()) {
        (Some(dir), _) => crate::collect::checkout::checkout_view(ctx, dir),
        (None, Err(e)) if e.no_index && ctx.home.join("index.json").exists() => Ok(crate::view::View::default()),
        (None, v) => v,
    };
    let inputs = QueryInputs { q: q0, only: a.only.as_deref(), host: a.host.as_deref(), near: a.near, no_secrets: a.no_secrets, history: a.history, similar: a.similar.as_deref() };
    let (mut q, text_report) = build_query_ex(ctx, view.as_ref().ok(), &inputs, (fm == "table" || fm == "overview") && !a.quiet)?;
    let view = view?;
    q.similar_related = a.similar_related;
    if a.path.is_some() {
        q.now_only = true; // a checkout is what is there now
        q.checkout = true;
        if window_is_advisory(&q.window_src) {
            // the advisory's exposure window is about the past; a checkout has no past
            q.window = None;
            q.window_src = None;
        }
    }
    check_repo(&view, &q0.repo)?;
    if q.iocs.is_empty() && !q.benign.is_empty() {
        // asked for by hash: say it is benign, then still show where that exact file sits (informational)
        println!("{}\n", benign_lines(&q).join("\n"));
        for (h, _, _) in q.benign.clone() {
            q.iocs.push(I::parse_ioc(&h, None)?);
        }
        q.benign.clear();
    }
    if !q.benign.is_empty() && matches!(fm.as_str(), "table" | "summary" | "md" | "overview") {
        println!("{}\n", benign_lines(&q).join("\n"));
    }
    let ix = Index::new(&view, &ctx.now);
    if let Some(m) = &a.max_age {
        let limit = parse_dur(m)?;
        let names = H::scope_sources(&ix, &q)?;
        let old: Vec<&String> = names.iter().filter(|n| parse_t(&ctx.now) - parse_t(&ix.it(n)) > limit).collect();
        if !old.is_empty() {
            let named: Vec<String> = old.iter().map(|n| format!("{n} ({})", crate::collect::util::age_str(&ctx.now, &ix.it(n)))).collect();
            let reach: Vec<(String, String, String)> = old.iter().map(|n| ((*n).clone(), ix.srcs[*n].reach.clone(), ix.srcs[*n].indexed_at.clone())).collect();
            return Err(BrError::with_code(
                format!("index is stale: {} older than {m}: {}", plural(old.len(), "source"), crate::cmd::status::name_list(&named)),
                Some(&crate::cmd::status::max_age_hint(&ctx.now, &reach)),
                5,
            ));
        }
    }
    if a.q.now {
        H::set_probe(ctx);
    }
    if crate::query::secret_hunt::any_secret(&q) {
        return run_secret(a, &ix, &q, &fm);
    }
    let mut res = H::hunt(&ix, &q)?;
    // A checkout is not a source br can scan; the way to close its gap is to fix the file and hunt the directory again
    if let Some(dir) = &a.path {
        let mut again = format!("br hunt --path {}", crate::out::shell::shquote(dir));
        if let Some(adv) = a.q.advisory.as_ref().filter(|x| !x.is_empty()) {
            again += &format!(" --advisory {}", crate::out::shell::shquote(adv));
        }
        for i in &a.q.iocs {
            again += &format!(" {}", crate::out::shell::shquote(i));
        }
        for r in res.not_checked.iter_mut().filter(|r| r.name.starts_with("checkout/") || r.name.starts_with("checkout-files/")) {
            r.command = again.clone();
        }
    }
    if fm == "jira" {
        let fixed = q.adv.as_ref().and_then(|x| x.fixed.clone());
        print!("{}", crate::out::actions::notify(&ix, &q, &res, "jira", &fixed));
        return Ok(0);
    }
    // --strict also fails an answer built from a text that mentions packages br did not read (found still wins: 10)
    let code_of = |res: &HuntResult| {
        let c = exit_code(res, a);
        if c == 0 && a.strict && !text_report.unread.is_empty() {
            3
        } else {
            c
        }
    };
    if a.progress {
        println!("{}", crate::out::progress::run(ctx, &ix, &res)?);
        return Ok(code_of(&res));
    }
    let text = if fm == "slack" {
        R::render_slack(&res, &ix)
    } else if a.quiet {
        R::render_quiet(&res)
    } else {
        match fm.as_str() {
            "json" => R::render_json(&res, &ix),
            "csv" => R::render_csv(&res),
            "sarif" => crate::out::sarif::render_sarif(&res, &ix),
            "md" => R::render_md(&res, &ix, a.wide),
            "overview" => crate::out::overview::render_overview(&res, &ix, ctx.color, term_width()),
            "summary" => R::summary(&res, &ix, a.audience.as_deref() == Some("customers")),
            _ => R::render_table(&res, &ix, a.wide),
        }
    };
    println!("{text}");
    let _ = FKind::Repo;
    Ok(code_of(&res))
}

/// A `secret:NAME` question has its own report (rotation, not versions); it shares the exit codes of every other hunt.
fn run_secret(a: &HuntArgs, ix: &Index, q: &Query, fm: &str) -> BrResult<i32> {
    if !crate::query::secret_hunt::is_secret_query(&a.q.iocs) {
        return Err(BrError::new("secret:NAME cannot be mixed with package indicators", Some("ask one question at a time: br hunt secret:NAME, then br hunt npm:name@1.2.3")));
    }
    let rep = crate::query::secret_hunt::build(ix, q)?;
    let text = if a.quiet && fm != "sarif" && fm != "json" {
        crate::out::secretq::render_quiet(&rep)
    } else {
        match fm {
            "json" => crate::out::secretq::to_json(&rep).dumps(),
            "csv" => crate::out::secretq::render_csv(&rep),
            "sarif" => crate::out::secretq::render_sarif(&rep),
            "md" => crate::out::secretq::render_md(&rep),
            "slack" => crate::out::secretq::render_slack(&rep),
            "summary" => crate::out::secretq::summary(&rep, a.audience.as_deref() == Some("customers")),
            _ => crate::out::secretq::render_table(&rep),
        }
    };
    println!("{text}");
    Ok(secret_exit(&rep, a))
}

pub fn secret_exit(rep: &crate::query::secret_hunt::SecretReport, a: &HuntArgs) -> i32 {
    let found = rep.found();
    if a.fail_if == "none" {
        return if rep.stored.is_empty() && rep.images.is_empty() { 11 } else { 0 };
    }
    if found {
        return 10;
    }
    if a.strict && !rep.gaps.is_empty() {
        return 3;
    }
    0
}

fn term_width() -> usize {
    std::env::var("COLUMNS").ok().and_then(|c| c.trim().parse().ok()).unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> View {
        let mut v = View::default();
        v.repos.insert("acme/frontend".into(), Default::default());
        v.repos.insert("acme/backend".into(), Default::default());
        v.sources.insert("github".into(), Default::default());
        v
    }

    #[test]
    fn repo_names_match_case_insensitively_and_resolve_to_the_indexed_spelling() {
        let v = view();
        assert_eq!(resolve_repo(&v, "Acme/FrontEnd").as_deref(), Some("acme/frontend"));
        assert!(check_repo(&v, &Some("ACME/backend".into())).is_ok());
    }

    #[test]
    fn unknown_repo_suggests_the_closest_by_edit_distance() {
        let e = check_repo(&view(), &Some("acme/fronted".into())).unwrap_err();
        assert!(e.hint.unwrap().contains("acme/frontend"));
    }

    // A check never passes while the bad version is present, whatever the window says; --fail-if none agrees
    #[test]
    fn what_is_present_after_the_window_trips_the_gate() {
        let after = HuntResult { present_after: vec![H::Finding { where_: "acme/app".into(), ..Default::default() }], ..Default::default() };
        let args = |f: &str| HuntArgs { fail_if: f.to_string(), ..Default::default() };
        assert_eq!(exit_code(&after, &args("found")), 10);
        assert_eq!(exit_code(&after, &args("none")), 0);
        let clear = HuntResult::default();
        assert_eq!(exit_code(&clear, &args("found")), 0);
        assert_eq!(exit_code(&clear, &args("none")), 11);
    }

    // An advisory's window is about the past; a checkout has none, but an explicit --window stays
    #[test]
    fn only_an_advisory_window_is_dropped_for_a_checkout() {
        assert!(window_is_advisory(&Some("advisory".into())));
        assert!(window_is_advisory(&Some("your note 05-12 07:40Z".into())));
        assert!(!window_is_advisory(&Some("--window".into())));
        assert!(!window_is_advisory(&Some("text".into())));
    }

    #[test]
    fn a_missing_index_is_a_kind_not_a_message() {
        assert!(BrError::no_index(std::path::Path::new("/x")).no_index);
        assert!(!BrError::new("no index at /x", None).no_index);
    }
}
