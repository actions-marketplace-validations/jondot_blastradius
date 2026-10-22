//! `br evidence`. Writes FILE.json, FILE.md and the seal, and records the custody event.

use std::collections::{BTreeSet, HashSet};

use regex::Regex;
use std::path::Path;

use crate::cli::{EvidenceArgs, QueryArgs};
use crate::cmd::hunt::{build_query, check_repo, QueryInputs};
use crate::collect::brx;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::out::evidence::*;
use crate::out::json::J;
use crate::out::render::finding_json;
use crate::query::coverage::{coverage_state, examined_end, members_covered, CoverageState, MemberCoverage};
use crate::query::hunt::{self as H, HuntResult, NotChecked, Query};
use crate::query::index::Index;
use crate::query::iocs::IocKind;
use crate::query::util::{age_label, norm_iso, plural, plural_with};
use crate::store::Store;
use crate::view::View;

/// The earliest time anything in the index goes back to: the first commit, host item or image build it holds.
pub fn history_floor(ix: &Index) -> Option<String> {
    let mut ts: Vec<String> = vec![];
    for (n, src) in &ix.srcs {
        match src.kind.as_str() {
            "repo" => {
                if let Some(c) = ix.commits(n).first() {
                    ts.push(c.at.clone());
                }
            }
            "host" => ts.extend(ix.host_items(n).iter().map(|i| i.at.clone())),
            "registry" => ts.extend(ix.v.images.iter().filter(|b| b.built <= src.indexed_at).map(|b| b.built.clone())),
            _ => {}
        }
    }
    if ts.is_empty() {
        return ix.srcs.values().map(|s| s.indexed_at.clone()).min();
    }
    ts.into_iter().min()
}

/// The kind the operator recorded (br hosts add --kind) or detection set; anything else is plain "host".
/// A name never decides it, and neither does how the host is reached.
fn host_kind(ix: &Index, name: &str) -> &'static str {
    match ix.host_def(name).and_then(|h| h.kind.clone()).unwrap_or_default().as_str() {
        "runner" => "runner",
        "laptop" => "laptop",
        "server" => "server",
        _ => "host",
    }
}

fn src_empty(ix: &Index, n: &str) -> bool {
    ix.srcs.get(n).is_some_and(|s| s.empty)
}

/// A registered host nothing has scanned is not an empty scan.
fn src_unscanned(ix: &Index, n: &str) -> bool {
    ix.srcs.get(n).is_some_and(crate::collect::words::never_scanned)
}

fn nonempty(o: &Option<String>) -> bool {
    o.as_ref().is_some_and(|x| !x.is_empty())
}

/// `--owner` or `--repo` narrows the file to the sources the hunt examined.
fn scoped(q: &Query) -> bool {
    nonempty(&q.owner) || nonempty(&q.repo)
}

pub fn population_doc(_ctx: &Ctx, ix: &Index, floor: Option<&str>, res: &HuntResult) -> Pop {
    let q = &res.q;
    let sc = scoped(q);
    let in_scope = |n: &String| !sc || res.names.contains(n);
    let hosts: Vec<String> = ix.names("host").into_iter().filter(|n| in_scope(n)).collect();
    let runners = hosts.iter().filter(|n| host_kind(ix, n) == "runner").count();
    let servers = hosts.iter().filter(|n| host_kind(ix, n) == "server").count();
    let unknown = hosts.iter().filter(|n| host_kind(ix, n) == "host").count();
    let laptops: Vec<&String> = hosts.iter().filter(|n| host_kind(ix, n) == "laptop").collect();
    // Who has a laptop scan here is decided in one place (hosts, status, hunt, notify and this file use it).
    // A --repo question names no group of people, so it carries no member count.
    let mc = if nonempty(&q.repo) { MemberCoverage::default() } else { members_covered(ix, q) };
    let missing: Vec<String> = mc.uncovered_names.clone();
    let kinds = |k: &str| ix.srcs.iter().filter(|(n, s)| s.kind == k && in_scope(n)).count();
    let mut parts = vec![];
    if runners > 0 {
        parts.push(plural(runners, "runner"));
    }
    if !laptops.is_empty() {
        parts.push(plural(laptops.len(), "laptop"));
    }
    if servers > 0 {
        parts.push(plural(servers, "server"));
    }
    if unknown > 0 {
        parts.push(format!("{unknown} of unrecorded kind"));
    }
    let empty_scans: Vec<String> = hosts.iter().filter(|n| src_empty(ix, n) && !src_unscanned(ix, n)).cloned().collect();
    let mut line = format!("hosts: {} indexed{}", hosts.len(), if parts.is_empty() { String::new() } else { format!(" ({})", parts.join(", ")) });
    if !empty_scans.is_empty() {
        line += &format!("; {} hashed no files and {} not searched", plural(empty_scans.len(), "host"), if empty_scans.len() == 1 { "is" } else { "are" });
    }
    if mc.members > 0 {
        line += &format!(
            "; employee laptops: {} of {} checked ({} {}), {} with no laptop scan here{}",
            mc.covered,
            plural(mc.members, "member"),
            plural(mc.members, "member"),
            mc.source_label,
            missing.len(),
            if missing.is_empty() { "" } else { ": run br hosts to list them" }
        );
    }
    Pop {
        repos: kinds("repo"),
        registries: kinds("registry"),
        hosts: hosts.len(),
        runners,
        laptops: laptops.len(),
        servers,
        unknown,
        members: mc.members,
        members_covered: mc.covered,
        members_source: mc.source_label.clone(),
        members_partial: mc.reasons.iter().filter(|r| !r.covered && r.why == crate::query::coverage::GapWhy::Narrow).count(),
        members_stale: mc.reasons.iter().filter(|r| !r.covered && r.why == crate::query::coverage::GapWhy::Stale).count(),
        members_empty: mc.reasons.iter().filter(|r| !r.covered && r.why == crate::query::coverage::GapWhy::Empty).count(),
        member_reasons: mc.reasons.iter().filter(|r| !r.covered).map(|r| (r.name.clone(), r.reason.clone())).collect(),
        member_names_without_laptop_scan: missing,
        member_gaps: mc
            .reasons
            .iter()
            .filter(|r| !r.covered)
            .map(|r| {
                use crate::query::coverage::GapWhy as W;
                (
                    r.name.clone(),
                    match r.why {
                        W::Stale => "stale",
                        W::Narrow => "partial",
                        W::Empty => "empty",
                        W::NoScan | W::Unscanned => "not scanned",
                    },
                )
            })
            .collect(),
        empty_scans,
        history_begins: floor.map(str::to_string),
        statement: line,
    }
}

/// Where the window, the fixed version and each indicator of this question came from, as labels ready to print after
/// "from ": "OSV", "your note 05-12 07:40Z", "the advisory text", "the command line".
pub struct Prov {
    pub window: String,
    pub fixed: Option<(String, String)>,
    pub indicators: Vec<(String, String)>,
}

pub fn provenance(view: &View, q: &Query, given: &[String], has_text: bool) -> Prov {
    let adv = q.adv.as_ref();
    let rec = adv.and_then(|r| view.advisories.iter().find(|a| a.id == r.id));
    let window = match q.window_src.as_deref() {
        Some("advisory") | Some("OSV") => rec.and_then(|a| a.provenance.window.clone()).unwrap_or_else(|| if rec.is_some() { "OSV".into() } else { "the advisory file".into() }),
        Some(s) if s.starts_with("your note") => s.to_string(),
        Some("text") => "the advisory text".to_string(),
        Some("whole history") => "the whole history (a bare hash has no advisory window)".to_string(),
        _ => "the --window option".to_string(),
    };
    let fixed = adv.and_then(|r| r.fixed.clone()).map(|v| (v, rec.and_then(|a| a.provenance.fixed.clone()).unwrap_or_else(|| if rec.is_some() { "OSV".into() } else { "the advisory file".into() })));
    let typed: Vec<String> = given.iter().filter_map(|g| crate::query::iocs::parse_ioc(g, None).ok().map(|i| i.text)).collect();
    let indicators = q
        .iocs
        .iter()
        .map(|i| {
            let key = match (&i.eco, i.kind == IocKind::Pkg) {
                (Some(e), true) => crate::collect::config::fixed_key(e, &i.name),
                _ => i.text.clone(),
            };
            let from = if typed.contains(&i.text) {
                "the command line".to_string()
            } else if let Some(l) = rec.and_then(|a| a.provenance.indicators.get(&key).or_else(|| a.provenance.indicators.get(&i.text))) {
                l.clone()
            } else if adv.is_some_and(|r| r.affected.contains(&i.text) || r.packages.iter().any(|p| crate::collect::config::pkg_key(p) == key)) {
                "the advisory file".to_string()
            } else if has_text {
                "the advisory text".to_string()
            } else {
                "the command line".to_string()
            };
            (i.text.clone(), from)
        })
        .collect();
    Prov { window, fixed, indicators }
}

impl Prov {
    pub fn to_j(&self) -> J {
        J::obj(vec![
            ("window", J::obj(vec![("from", J::s(&self.window))])),
            (
                "fixed",
                match &self.fixed {
                    Some((v, f)) => J::obj(vec![("version", J::s(v)), ("from", J::s(f))]),
                    None => J::Null,
                },
            ),
            ("indicators", J::Arr(self.indicators.iter().map(|(i, f)| J::obj(vec![("indicator", J::s(i)), ("from", J::s(f))])).collect())),
        ])
    }

    /// The lines QUESTION prints under the indicators.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![];
        let mut head = format!("Where this came from: the window is from {}", self.window);
        if let Some((v, f)) = &self.fixed {
            head += &format!("; the fixed version {v} is from {f}");
        }
        out.push(format!("{head}."));
        let mut groups: Vec<(String, Vec<&str>)> = vec![];
        for (i, f) in &self.indicators {
            match groups.iter_mut().find(|g| &g.0 == f) {
                Some(g) => g.1.push(i),
                None => groups.push((f.clone(), vec![i])),
            }
        }
        for (f, is) in groups {
            out.push(format!("Indicators from {f}: {}.", is.join(", ")));
        }
        out
    }
}

/// The plain (window and freshness only) state is full: the only reason a source is partial is then its narrow roots.
fn cs_plain_full(ix: &Index, q: &Query, n: &str, confirmed: &BTreeSet<String>, res: &HuntResult) -> bool {
    coverage_state(ix, q, n, confirmed.contains(n), res.as_of.as_deref()) == CoverageState::Full
}

/// One row per source in scope. full, partial and none are decided by `coverage_state` against the examined end of
/// the window (the window end, clipped to the index time), the same rule in the table, PARTIAL COVERAGE and the appendix.
pub fn coverage_rows(ix: &Index, q: &Query, res: &HuntResult, confirmed: &BTreeSet<String>) -> Vec<Cov> {
    let (start, end) = q.window.clone().unwrap_or_default();
    let examined = examined_end(&end, res.as_of.as_deref());
    let mut rows = vec![];
    for n in &res.names {
        let t = ix.it(n);
        let empty = src_empty(ix, n);
        let kind = ix.srcs.get(n.as_str()).map_or_else(|| "source".to_string(), |s| s.kind.clone());
        let cs = crate::query::coverage::source_state(ix, q, n, confirmed.contains(n), res.as_of.as_deref());
        let full = cs == CoverageState::Full;
        let state: &'static str = cs.word();
        let stale = crate::query::hunt::stale_now(ix, n);
        let reason = if src_unscanned(ix, n) {
            Some("registered, never scanned, so nothing was checked".to_string())
        } else if empty {
            Some(if kind == "repo" {
                // the files and reasons that left it empty: hunt folds them into the one row, so the evidence says them here
                let files: Vec<String> =
                    ix.srcs.get(n.as_str()).map(|s| s.gaps.iter().filter(|g| g.scope.starts_with("lockfile ")).map(|g| format!("{}: {}", g.scope, g.reason)).collect()).unwrap_or_default();
                let tail = if files.is_empty() { String::new() } else { format!(" ({})", files.join("; ")) };
                format!("its lockfiles gave no packages, so nothing was checked{tail}")
            } else {
                "its scan hashed 0 files, so nothing was checked".to_string()
            })
        } else if state == "partial" && crate::query::coverage::is_narrow_laptop(ix, n) && cs_plain_full(ix, q, n, confirmed, res) {
            let roots = crate::query::coverage::narrow_roots(ix, n).unwrap_or_default();
            Some(format!("its scan read only {}, not the home or the package caches, so the rest of the machine is not known", roots.join(", ")))
        } else if state == "partial" {
            Some(format!("last scanned before the end of the examined window ({}); nothing after {} is known", fmtz(&examined), fmtz(&t)))
        } else if state == "none" {
            Some(format!("indexed before the window starts ({})", fmtz(&start)))
        } else if stale {
            Some("older than the staleness threshold".to_string())
        } else {
            None
        };
        let reach = ix.srcs.get(n.as_str()).map(|s| s.reach.clone());
        rows.push(Cov {
            source: n.clone(),
            kind: kind.clone(),
            indexed_at: t,
            covers_window: full,
            coverage: state,
            has_findings: confirmed.contains(n),
            stale,
            empty,
            unscanned: src_unscanned(ix, n),
            gap_reason: reason,
            narrow: state == "partial" && !empty && !src_unscanned(ix, n) && crate::query::coverage::is_narrow_laptop(ix, n) && cs_plain_full(ix, q, n, confirmed, res),
            close_with: if !full || stale { Some(H::close_command(&kind, n, reach.as_deref())) } else { None },
        });
    }
    rows
}

/// The kind of gap a source row is, in one place: `partial` (scanned before the end of the window), `stale` (before the
/// window began, or older than the staleness threshold), `empty` (the scan read nothing). The file's gap rows and the customer
/// statement both read it, so a gap has the same reason in both.
pub fn gap_state(c: &Cov) -> Option<&'static str> {
    if c.unscanned {
        None
    } else if c.empty {
        Some("empty")
    } else if c.coverage == "partial" {
        Some("partial")
    } else if c.coverage == "none" || c.stale {
        Some("stale")
    } else {
        None
    }
}

/// A gap state in the words a customer reads, after "was"/"were" (the auditor file's reason for the same state is
/// `Cov.gap_reason`).
fn gap_state_customer_words(state: &str) -> &'static str {
    match state {
        "partial" => "last checked before the end of the period examined, so later events are not known",
        "stale" => "last checked too long ago to count as current",
        "narrow" => "checked only in part, because the scan read less than the laptop's home folder and package caches",
        _ => "checked, but the scan read nothing",
    }
}

/// Every gap the file counts, once. A source's partial, stale or empty row is derived from its coverage row (the
/// one definition); the hunt's other rows (scan gaps, unscanned runners, unowned, kinds never indexed, laptops) are kept
/// as they are. The count in the headline and the lines under PARTIAL COVERAGE and NOT COVERED come from this list.
pub fn gap_rows(res: &HuntResult, cov: &[Cov]) -> Vec<NotChecked> {
    let mut rows: Vec<NotChecked> = vec![];
    for c in cov {
        let Some(state) = gap_state(c) else { continue };
        rows.push(NotChecked {
            name: c.source.clone(),
            kind: c.kind.clone(),
            state: state.into(),
            why: c.gap_reason.clone().unwrap_or_default(),
            indexed_at: Some(c.indexed_at.clone()),
            command: c.close_with.clone().unwrap_or_default(),
            people: vec![],
        });
    }
    for r in &res.not_checked {
        let from_cov = matches!(r.state.as_str(), "partial" | "stale" | "empty") && cov.iter().any(|c| c.source == r.name && !c.unscanned);
        if !from_cov {
            rows.push(r.clone());
        }
    }
    rows
}

/// What each kind of source was read for, and the matching rule, with the counts of what was left out.
pub fn method_lines(cov: &[Cov], res: &HuntResult) -> Vec<String> {
    let n = |k: &str| cov.iter().filter(|c| c.kind == k).count();
    let mut out = vec![];
    if n("repo") > 0 {
        out.push(format!(
            "{}: read for the packages in their lockfiles and manifests at every commit, the packages each CI run installed, and the files in their caches, build artifacts and release assets.",
            plural(n("repo"), "repo")
        ));
    }
    if n("registry") > 0 {
        out.push(format!(
            "{}: read for the packages and file hashes in every layer of every image, including files a later layer deleted.",
            plural_with(n("registry"), "registry", Some("registries"))
        ));
    }
    if n("host") > 0 {
        out.push(format!(
            "{}: read for the sha256 of the files found under the scanned paths and the packages detected in install trees; a scan that hashed no files counts as a gap.",
            plural(n("host"), "host")
        ));
    }
    out.push("A package matches on its ecosystem, exact name and exact version. A file matches on its sha256.".to_string());
    let kinds: Vec<&str> = res.near.iter().map(|x| x.why.as_str()).collect();
    out.push(if kinds.is_empty() {
        "Prereleases and look-alike names are not matches; none were seen.".to_string()
    } else {
        format!("Prereleases and look-alike names are not matches; {} were seen and left out (listed under near_misses in the JSON).", plural(kinds.len(), "such package"))
    });
    out
}

fn to_value(j: &J) -> serde_json::Value {
    use serde_json::Value;
    match j {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Int(i) => Value::from(*i),
        J::Str(s) => Value::String(s.clone()),
        J::Arr(a) => Value::Array(a.iter().map(to_value).collect()),
        J::Obj(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), to_value(v))).collect()),
    }
}

pub(crate) fn md_with_trailer(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let body = format!("{}\n", text.trim_end_matches('\n'));
    format!("{body}{}{} -->\n", brx::MD_TRAILER, hex::encode(Sha256::digest(body.as_bytes())))
}

fn drop_seal(main: &str) -> Vec<String> {
    let mut gone = vec![];
    for p in [format!("{main}.sha256"), format!("{main}.sha256.sig")] {
        if Path::new(&p).exists() && std::fs::remove_file(&p).is_ok() {
            gone.push(p);
        }
    }
    gone
}

fn nc_j(n: &NotChecked) -> J {
    J::obj(vec![("name", J::s(&n.name)), ("kind", J::s(&n.kind)), ("state", J::s(&n.state)), ("why", J::s(&n.why)), ("command", J::s(&n.command))])
}

/// Write beside the target and rename into place, so an interrupted run never leaves half a file under the real name.
pub(crate) fn write(path: &str, text: &str) -> BrResult<()> {
    let tmp = format!("{path}.tmp{}", std::process::id());
    std::fs::write(&tmp, text).map_err(|e| brx::io_err(e, &tmp))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        brx::io_err(e, path)
    })
}

/// `--out` names the evidence JSON. Without a .json ending one is added, and the report sits beside it as FILE.md.
pub fn out_paths(out: &str) -> BrResult<(String, String)> {
    let lower = out.to_lowercase();
    if lower.ends_with(".md") {
        return Err(BrError::new("--out must not end in .md", Some("name the evidence file FILE.json; the report is written beside it as FILE.md")));
    }
    let json = if lower.ends_with(".json") { out.to_string() } else { format!("{out}.json") };
    let md = format!("{}.md", &json[..json.len() - ".json".len()]);
    Ok((json, md))
}

/// The stored YARA hits on the hosts in scope. A hit is `present` when the host's newest scan still hit the file.
fn yara_rows(ix: &Index, res: &HuntResult) -> Vec<YaraRow> {
    let mut rows: Vec<YaraRow> = vec![];
    for y in &ix.v.state.yara_hits {
        let g = |k: &str| y.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let src = g("source_id");
        if !res.names.contains(&src) || ix.kind_of(&src) != "host" {
            continue;
        }
        let last = g("last_seen");
        let at = ix.i(&src).unwrap_or_default();
        let state = if last.is_empty() || at.is_empty() || last >= at { "present" } else { "not hit at the last scan" };
        rows.push(YaraRow { source: src, rule: g("rule"), path: g("path"), sha256: g("sha256"), rules_sha256: g("rules_sha256"), state: state.into(), first_seen: g("first_seen"), last_seen: last });
    }
    rows.sort_by(|a, b| (&a.source, &a.rule, &a.path).cmp(&(&b.source, &b.rule, &b.path)));
    rows
}

/// When no window can be found, say where it was looked for.
fn no_window_hint(a: &EvidenceArgs, view: &View, q: &Query) -> String {
    let mut looked: Vec<String> = vec![];
    if let Some(id) = a.q.advisory.as_ref().filter(|x| !x.is_empty()) {
        looked.push(format!("your advisory note for {id} (it has no window)"));
        looked.push(format!("the OSV record for {id} (OSV does not carry the exposure window)"));
    }
    if a.q.text.as_ref().is_some_and(|t| !t.is_empty()) {
        looked.push("the advisory text you passed (no window in it)".to_string());
    }
    // The window the advisory's own text states is offered, never taken: the operator confirms it
    let mut texts: Vec<(String, String)> = vec![];
    if let Some(r) = &q.adv {
        for t in [Some(r.text.clone()), Some(r.title.clone())].into_iter().flatten() {
            texts.push((format!("the text of {}", r.id), t));
        }
    }
    if let Some(id) = a.q.advisory.as_ref().filter(|x| !x.is_empty()) {
        for adv in view.advisories.iter().filter(|v| v.id.eq_ignore_ascii_case(id) || v.aliases.iter().any(|x| x.eq_ignore_ascii_case(id))) {
            for t in [adv.text.clone(), adv.title.clone()].into_iter().flatten() {
                texts.push((format!("the text of {}", adv.id), t));
            }
        }
    }
    if let Some(t) = a.q.text.as_ref().filter(|t| !t.is_empty()) {
        texts.push(("the advisory text you passed".to_string(), t.clone()));
    }
    let suggestion = texts.iter().find_map(|(from, t)| crate::query::iocs::extract_window(t).map(|w| (from.clone(), w)));
    let suggest = match &suggestion {
        Some((from, (f, t))) => {
            format!("; {from} states {} to {}, which may be the exposure window. This is a suggestion only: confirm it, then run with --window {}Z..{}Z", fmtz(f), fmtz(t), &f[..16], &t[..16])
        }
        None => String::new(),
    };
    let where_ = if looked.is_empty() { "no advisory or text was given, so there was nowhere to read one from".to_string() } else { format!("looked in {}", looked.join(", ")) };
    format!("{where_}{suggest}; add one with --window, or keep it with br advisory note ID --window FROM..TO. Example: --window 2026-05-11T14:00Z..2026-05-11T18:00Z")
}

/// The verdict words hunt uses.
fn verdict_of(found: bool, gaps: usize, possible: usize) -> &'static str {
    if found {
        "FOUND"
    } else if gaps > 0 || possible > 0 {
        "CLEAR WITH GAPS"
    } else {
        "CLEAR"
    }
}

/// The indicators with hits, and those without, counting what is present now but first seen after the window.
fn hit_split(res: &HuntResult) -> (Vec<String>, Vec<String>) {
    let mut hits = H::ioc_hits(res);
    for f in &res.present_after {
        for t in f.iocs_or_one() {
            if let Some(e) = hits.iter_mut().find(|(x, _)| *x == t) {
                e.1 += 1;
            }
        }
    }
    let with = hits.iter().filter(|(_, n)| *n > 0).map(|(t, _)| t.clone()).collect();
    let zero = hits.iter().filter(|(_, n)| *n == 0).map(|(t, _)| t.clone()).collect();
    (with, zero)
}

fn zero_clause(zero: &[String]) -> String {
    if zero.is_empty() {
        return String::new();
    }
    let shown: Vec<&str> = zero.iter().take(5).map(|s| s.as_str()).collect();
    let more = if zero.len() > 5 { format!(" and {} more", zero.len() - 5) } else { String::new() };
    format!("; 0 hits: {}{more}", shown.join(", "))
}

/// A finding belongs to the source that holds it: an image to its registry, everything else to its repo or host.
fn holder(ix: &Index, f: &H::Finding) -> String {
    if f.kind == H::FKind::Image {
        if let Some(r) = ix.registry_of(&f.where_) {
            return r;
        }
    }
    f.where_.clone()
}

/// An indicator the way a customer reads it: `npm:@scope/name@1.2.3` is "@scope/name 1.2.3 (npm)".
fn plain_ioc(t: &str) -> String {
    if let Some((eco, rest)) = t.split_once(':') {
        if !eco.is_empty() && eco.chars().all(|c| c.is_ascii_lowercase()) && !rest.is_empty() && eco != "sha256" {
            return match rest.rfind('@').filter(|i| *i > 0) {
                Some(i) => format!("{} {} ({eco})", &rest[..i], &rest[i + 1..]),
                None => format!("{rest} ({eco})"),
            };
        }
    }
    t.to_string()
}

/// What a customer's question names that the search covered: `(found, clear, unsearched)`. An indicator is named when its
/// package name is written in the question, or a hex run of 8 or more digits in the question starts the file's hash (or is
/// started by it). A hex run that matches no indicator is something the question names and the search did not cover.
fn question_names(question: &str, with: &[String], zero: &[String]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let q = question.to_lowercase();
    let hex = Regex::new(r"[0-9a-f]{8,64}").unwrap();
    // a hash prefix has digits and letters; a long number or a long word is not one
    let runs: Vec<String> = hex.find_iter(&q).map(|m| m.as_str().to_string()).filter(|r| r.chars().any(|c| c.is_ascii_digit()) && r.chars().any(|c| c.is_ascii_alphabetic())).collect();
    let mut used: HashSet<String> = HashSet::new();
    let mut named = |t: &str| -> bool {
        if let Some(h) = t.strip_prefix("sha256:") {
            let h = h.to_lowercase();
            let hits: Vec<&String> = runs.iter().filter(|r| h.starts_with(r.as_str()) || r.starts_with(&h)).collect();
            used.extend(hits.iter().map(|r| (*r).clone()));
            return !hits.is_empty();
        }
        let rest = t.split_once(':').map_or(t, |x| x.1);
        let name = match rest.rfind('@').filter(|i| *i > 0) {
            Some(i) => &rest[..i],
            None => rest,
        };
        !name.is_empty() && q.contains(&name.to_lowercase())
    };
    let found: Vec<String> = with.iter().filter(|t| named(t)).cloned().collect();
    let clear: Vec<String> = zero.iter().filter(|t| named(t)).cloned().collect();
    let unsearched: Vec<String> = runs.into_iter().filter(|r| !used.contains(r)).collect();
    (found, clear, unsearched)
}

/// The one clause for what could not be checked, said the way a customer reads it: systems (sources) and employee laptops.
fn coverage_caveat(systems: usize, laptops: usize) -> Option<String> {
    let lap = |l: usize| plural(l, "employee laptop");
    match (systems, laptops) {
        (0, 0) => None,
        (0, l) => Some(format!("{} not been checked, so there may be more", lap(l) + if l == 1 { " has" } else { " have" })),
        (g, 0) => Some(format!("{} could not be fully checked, so there may be more", plural(g, "system"))),
        (g, l) => Some(format!("{} and {} could not be fully checked, so there may be more", plural(g, "system"), lap(l))),
    }
}

/// The statement for a customer. It says what the index shows and what is recommended. It never says that anything
/// is being done: br records no action, so no action is claimed. The laptop gap is said in words, with its source.
///
/// With a question, the first sentence answers it (yes or no for what was asked, with the coverage caveat) and the
/// question follows; each gap has the reason the evidence file gives it; and the text holds no internal word (no token,
/// no command, no file name but the evidence file's own).
#[allow(clippy::too_many_arguments)]
fn customers_text(
    found: bool,
    what: &str,
    first_day: Option<String>,
    window: (&str, &str),
    examined: Option<&str>,
    as_of: Option<&str>,
    pop: &Pop,
    cov: &[Cov],
    gap_count: usize,
    case_id: Option<&str>,
    out_name: &str,
    sha: &str,
    now: &str,
    asked: (Option<&str>, Option<&str>),
    later: usize,
    hits: (&[String], &[String]),
) -> String {
    let mut out: Vec<String> = vec!["# Statement for customers".into(), String::new()];
    let question = asked.0.map(str::trim).filter(|q| !q.is_empty());
    let echo = question.map(|q| {
        let day = asked.1.map(|r| fmt(r).split(' ').next().unwrap_or("").to_string());
        format!("Your question{}: {}", day.map_or(String::new(), |d| format!(" (received {d})")), q)
    });
    let left_laptops = pop.members.saturating_sub(pop.members_covered);
    let caveat = coverage_caveat(gap_count.saturating_sub(usize::from(left_laptops > 0)), left_laptops);
    let named = question.map(|q| question_names(q, hits.0, hits.1));
    // what the question names, in the answer's own words
    let named_words = |names: &[String]| names.iter().map(|t| plain_ioc(t)).collect::<Vec<_>>().join(", ");
    let recommend = "Recommended next steps are to remove the affected packages and to rotate the credentials that those systems could read. This statement does not say that either has been done.";
    let mut body: Vec<String> = vec![];
    if found && later > 0 && first_day.is_none() {
        // Nothing inside the period, but the bad version is in the index now
        let mut first = format!("No installation of {what} was observed inside the period examined");
        if question.is_some() {
            if let Some(c) = &caveat {
                first += &format!(" ({c})");
            }
        }
        body.push(format!("{first}. However, {} in our systems carry it now; they first appeared after the period ended.", plural(later, "place")));
        body.push(recommend.into());
        body.push("We have not established whether any customer data was involved.".into());
    } else if found {
        let since = first_day.as_ref().map_or(String::new(), |d| format!(", starting on {d}"));
        let subject = match &named {
            Some((f, _, _)) if !f.is_empty() => format!("{} {} found in our internal systems", named_words(f), if f.len() == 1 { "was" } else { "were" }),
            _ => format!("Some of our internal systems contained or ran {what}"),
        };
        let mut first = format!("Yes. {subject}{since}");
        if question.is_some() {
            first += &match &caveat {
                Some(c) => format!("; {c}"),
                None => "; every system we hold records for was checked".to_string(),
            };
        }
        body.push(format!("{first}."));
        if let Some((_, clear, _)) = &named {
            if !clear.is_empty() {
                body.push(format!("{} {} not found in the systems we checked.", named_words(clear), if clear.len() == 1 { "was" } else { "were" }));
            }
        }
        body.push(recommend.into());
        body.push("We have not established whether any customer data was involved.".into());
    } else if gap_count > 0 || pop.members > pop.members_covered {
        let mut first = format!("No findings so far for {what}, but not every system could be checked, so we cannot say No for certain");
        if question.is_some() {
            if let Some(c) = &caveat {
                first += &format!(" ({c})");
            }
        }
        body.push(format!("{first}."));
    } else {
        body.push(format!("No. Nothing in the systems we checked contained or ran {what}."));
    }
    if let Some((_, _, unsearched)) = &named {
        if !unsearched.is_empty() {
            body.push(format!("Your question also names {}, which was not among the things we searched for.", unsearched.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(", ")));
        }
    }
    let mut it = body.into_iter();
    if let Some(first) = it.next() {
        out.push(first);
    }
    if let Some(e) = echo {
        out.push(e);
    }
    out.extend(it);
    out.push(String::new());
    let end = examined.unwrap_or(window.1);
    out.push(format!("Period examined: {}.", fmt_range_end(window.0, end)));
    if examined.is_some() {
        out.push(format!("The period requested ended later; we examined it to {}, the time of our latest data.", fmtz(end)));
    }
    let full = cov.iter().filter(|c| c.coverage == "full").count();
    // The count and the oldest scan time, then what "full" means in words
    let oldest = cov.iter().filter(|c| !c.indexed_at.is_empty()).map(|c| c.indexed_at.as_str()).min();
    // Each kind of source gap, in the words of the evidence file's own reason for it
    let mut kinds: Vec<(&'static str, usize)> = vec![];
    for c in cov {
        if let Some(st) = gap_state(c) {
            let st = if c.narrow && st == "partial" { "narrow" } else { st };
            match kinds.iter_mut().find(|k| k.0 == st) {
                Some(k) => k.1 += 1,
                None => kinds.push((st, 1)),
            }
        }
    }
    let kind_words = if kinds.is_empty() {
        String::new()
    } else {
        format!(" ({})", kinds.iter().map(|(st, n)| format!("{} {} {}", n, if *n == 1 { "was" } else { "were" }, gap_state_customer_words(st))).collect::<Vec<_>>().join("; "))
    };
    out.push(format!(
        "Population and coverage: we checked {} ({}, {} and {}){}. {} of them {} full: scanned after the end of the examined period, or fresh as of their last scan. {}.",
        plural(cov.len(), "system"),
        plural_with(pop.repos, "code repository", Some("code repositories")),
        plural_with(pop.registries, "container registry", Some("container registries")),
        plural(pop.hosts, "machine"),
        oldest.map_or(String::new(), |t| format!(", the oldest checked at {}", fmtz(t))),
        full,
        if full == 1 { "was" } else { "were" },
        if gap_count == 0 { "No gaps remain".to_string() } else { format!("{} remain where we could not check fully{kind_words}, so this statement can still change", plural(gap_count, "gap")) }
    ));
    if pop.members > 0 {
        let left = pop.members - pop.members_covered;
        let (partial, stale, empty) = (pop.members_partial, pop.members_stale, pop.members_empty);
        let known = (partial + stale + empty).min(left);
        let none = left - known;
        let tail = if left == 0 {
            String::new()
        } else if known == 0 {
            format!(" The other {left} laptops were not checked, and people outside that list are not counted.")
        } else {
            let mut bits = vec![];
            for (n, why) in [(stale, crate::query::coverage::GapWhy::Stale), (partial, crate::query::coverage::GapWhy::Narrow), (empty, crate::query::coverage::GapWhy::Empty)] {
                if n > 0 {
                    bits.push(format!("{n} {} {}", if n == 1 { "was" } else { "were" }, why.customer_words()));
                }
            }
            if none > 0 {
                bits.push(format!("{none} {} not checked", if none == 1 { "was" } else { "were" }));
            }
            format!(" Of the other {left} laptops, {}. People outside that list are not counted.", bits.join(", and "))
        };
        out.push(format!("Employee laptops: {} of {} checked.{}", pop.members_covered, plural_with(pop.members, "person", Some("people")), tail));
    }
    out.push(format!("Our findings are as of {}.", fmtz(as_of.unwrap_or(now))));
    out.push(String::new());
    let ids = match case_id.filter(|c| !c.is_empty()) {
        Some(c) => format!("Case {c}. "),
        None => String::new(),
    };
    out.push(format!(
        "{ids}Issued {}. The detailed evidence is held by us and is available to an auditor on request. The sealed evidence file is {out_name}, sha256 {sha}; whoever holds the file can use that checksum to confirm it has not been changed.",
        fmtz(now)
    ));
    out.join("\n") + "\n"
}

/// What the index's own chain of custody holds besides evidence: scans, exports and imports (with the .brx hashes),
/// YARA runs and their hits, and hosts taken out. A question about one owner or repo keeps the rows of its own hosts.
fn custody_rows(ix: &Index, res: &HuntResult, scoped: bool) -> Vec<CustodyRow> {
    let mut rows: Vec<CustodyRow> = vec![];
    let s = |r: &serde_json::Value, k: &str| r[k].as_str().filter(|x| !x.is_empty()).map(str::to_string);
    let view = ix.v;
    for r in &view.state.custody {
        let event = s(r, "event").unwrap_or_default();
        if event == "evidence" || event.is_empty() {
            continue;
        }
        let host = s(r, "host");
        if scoped && host.as_ref().is_some_and(|h| !res.names.contains(h)) {
            continue;
        }
        rows.push(CustodyRow {
            event,
            at: s(r, "at").unwrap_or_default(),
            by: s(r, "by").unwrap_or_default(),
            requested_by: s(r, "requested_by"),
            case_id: s(r, "case_id"),
            host,
            file_sha256: s(r, "file_sha256"),
            ..Default::default()
        });
    }
    // one row per YARA run: the rules file and how many hits in how many files
    let mut runs: std::collections::BTreeMap<(String, String), (usize, BTreeSet<String>)> = Default::default();
    for y in &view.state.yara_hits {
        let k = (s(y, "first_seen").unwrap_or_default(), s(y, "rules_sha256").unwrap_or_default());
        let e = runs.entry(k).or_default();
        e.0 += 1;
        e.1.insert(format!("{}:{}", s(y, "source_id").unwrap_or_default(), s(y, "path").unwrap_or_default()));
    }
    // hits a scanned machine carried in its scan file
    for n in res.names.iter().filter(|n| ix.srcs.get(n.as_str()).is_some_and(|x| x.kind == "host")) {
        let (mut hits, mut files) = (0usize, 0usize);
        for it in ix.host_items(n) {
            for f in &it.files {
                if !f.yara_hits.is_empty() {
                    hits += f.yara_hits.len();
                    files += 1;
                }
            }
        }
        if hits > 0 {
            rows.push(CustodyRow {
                event: "YARA hits".into(),
                at: ix.it(n),
                host: Some(n.clone()),
                by: "-".into(),
                detail: Some(format!("{} in {} in its scan file", plural(hits, "hit"), plural(files, "file"))),
                ..Default::default()
            });
        }
    }
    for ((at, rules), (hits, files)) in runs {
        rows.push(CustodyRow {
            event: "YARA hits".into(),
            at,
            by: "-".into(),
            detail: Some(format!("{} in {}; rules sha256 {}", plural(hits, "hit"), plural(files.len(), "file"), if rules.is_empty() { "not recorded".to_string() } else { rules })),
            ..Default::default()
        });
    }
    rows
}

pub fn run(a: &EvidenceArgs, ctx: &Ctx) -> BrResult<i32> {
    if a.cc.claimcheck {
        return crate::cmd::claimhand::evidence(a, ctx);
    }
    let Some(out_arg) = a.out.clone().filter(|o| !o.is_empty()) else {
        return Err(BrError::new("evidence needs --out FILE", Some("example: --out evidence.json")));
    };
    let (out_path, md_path) = out_paths(&out_arg)?;
    let question = a.question.clone().map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    let received = match a.received.as_ref().map(|r| r.trim()).filter(|r| !r.is_empty()) {
        Some(r) => Some(norm_iso(r).map_err(|_| BrError::with_code(format!("--received {r} is not a date"), Some("write it with its year, e.g. --received 2026-05-09"), 2))?),
        None => None,
    };
    if out_path != out_arg {
        println!("--out {out_arg} has no .json ending, so the evidence is written to {out_path}");
    }
    let qa = QueryArgs {
        iocs: a.q.iocs.clone(),
        advisory: a.q.advisory.clone(),
        text: a.q.text.clone(),
        repo: a.q.repo.clone(),
        owner: a.q.owner.clone(),
        now: false,
        window: a.q.window.clone(),
        since: a.since.clone(),
    };
    let view = ctx.view();
    let inputs = QueryInputs { q: &qa, only: None, host: None, near: false, no_secrets: false, history: false, similar: None };
    let mut q = build_query(ctx, view.as_ref().ok(), &inputs, false)?;
    if q.iocs.is_empty() {
        return Err(BrError::new("nothing to hunt for", Some("pass an indicator or --advisory ID")));
    }
    let view: View = view?;
    let ix = Index::new(&view, &ctx.now);
    if crate::query::secret_hunt::any_secret(&q) {
        return secret_evidence(a, ctx, &ix, &q, (&out_path, &md_path), (question.as_deref(), received.as_deref()));
    }
    let floor = history_floor(&ix);
    if q.window.is_none() {
        if q.iocs.iter().all(|i| matches!(i.kind, IocKind::Sha256 | IocKind::Cert)) {
            let fl = floor.clone().unwrap_or_default();
            q.window = Some((fl.clone(), ctx.now.clone()));
            q.window_src = Some("whole history".into());
            println!("window: the whole history, {} (history begins {}); a bare hash has no advisory window", fmt_range_end(&fl, &ctx.now), fmt_opt(floor.as_deref()));
        } else {
            return Err(BrError::new("evidence needs --window FROM..TO", Some(&no_window_hint(a, &view, &q))));
        }
    }
    if a.sign.is_some() && a.no_seal {
        return Err(BrError::new("--sign needs a seal to sign", Some("drop --no-seal, or drop --sign")));
    }
    let key = a.sign.clone();
    let fingerprint = match &key {
        Some(k) => Some(brx::key_fingerprint(k)?),
        None => None,
    };
    check_repo(&view, &a.q.repo)?;
    let res = H::hunt(&ix, &q)?;
    let confirmed = H::findings(&res);
    let possible = H::possible(&res);
    let counts = H::counts(&res);
    // What is present now but first seen after the window is a finding for the verdict, the statement and the gate
    let found_in_window = !confirmed.is_empty();
    let found = found_in_window || !res.present_after.is_empty();
    // The appendix FINDINGS column is derived from the findings table: the source that holds a finding, an image's registry included
    let mut confirmed_sources: BTreeSet<String> = confirmed.iter().map(|f| holder(&ix, f)).collect();
    confirmed_sources.extend(res.present_after.iter().map(|f| holder(&ix, f)));
    let cov = coverage_rows(&ix, &q, &res, &confirmed_sources);
    let requested_by = a.requested_by.clone().or_else(|| brx::requested_by_default(ctx));
    let case_id = a.case.clone();
    let by = brx::who(ctx);
    let pop = population_doc(ctx, &ix, floor.as_deref(), &res);
    let (start, end) = q.window.clone().unwrap();
    // A window that ends after the index time is examined only up to the index time
    let examined = examined_end(&end, res.as_of.as_deref());
    let clipped = examined != end;
    let ioc_texts: Vec<String> = q.iocs.iter().map(|i| i.text.clone()).collect();
    let (with_hits, zero_hits) = hit_split(&res);
    // The laptops row is the hunt's own (it respects --owner and --repo); only an unscoped file adds one itself
    let named = pop.member_names_without_laptop_scan.clone();
    let mut rows = gap_rows(&res, &cov);
    let hosts_in_scope = res.names.iter().any(|n| ix.srcs.get(n.as_str()).is_some_and(|s| s.kind == "host"));
    if !scoped(&q) && !named.is_empty() && hosts_in_scope && !rows.iter().any(|n| n.kind == "laptops" || n.name.starts_with("laptops")) {
        rows.push(NotChecked {
            name: "laptops".into(),
            kind: "laptops".into(),
            state: "laptops".into(),
            why: format!("{} of {} members have no laptop scan here", named.len(), pop.members),
            indexed_at: None,
            command: "br hosts".into(),
            people: vec![],
        });
    }
    let not_checked = rows;
    let verdict = verdict_of(found, not_checked.len(), possible.len() + res.floating.len());

    let mut statement = if !found_in_window && found {
        format!(
            "Nothing was found inside the window, but {} present now in the indexed sources carry {} and {} first seen after it{}.",
            plural(res.present_after.len(), "finding"),
            if with_hits.is_empty() { "the indicators".to_string() } else { with_hits.join(", ") },
            if res.present_after.len() == 1 { "was" } else { "were" },
            zero_clause(&zero_hits)
        )
    } else if found {
        let w = H::count_words(&res).replacen(" in ", &format!(" of {} in ", with_hits.join(", ")), 1);
        format!("{w} in the indexed sources within the window{}.", zero_clause(&zero_hits))
    } else {
        "No observation of the indicators was found in the sources listed, within the window. This is a statement about what the index holds, not proof of absence.".to_string()
    };
    let headline = statement.clone();
    if !res.present_after.is_empty() && found_in_window {
        statement += &format!(" {} in the window + {} present now, first seen after it.", counts.findings, res.present_after.len());
    }
    if !possible.is_empty() {
        let names: BTreeSet<&String> = possible.iter().map(|f| &f.where_).collect();
        statement += &format!(
            " {} ({}) may also be affected but could not be confirmed; they are listed under possible and are not counted.",
            H::possible_words(&counts),
            names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
    }
    if !res.floating.is_empty() {
        statement +=
            &format!(" {} floating {} not counted as found: {}.", res.floating.len(), if res.floating.len() == 1 { "reference is" } else { "references are" }, crate::out::render::FLOATING_WORDS);
    }
    if !named.is_empty() && hosts_in_scope {
        statement += &format!(" {} of {} members have no laptop scan here, so their laptops are not covered.", named.len(), pop.members);
    }
    if !pop.empty_scans.is_empty() {
        statement += &format!(" {} hashed no files and {} counted as searched.", plural(pop.empty_scans.len(), "host"), if pop.empty_scans.len() == 1 { "is not" } else { "are not" });
    }
    if clipped {
        statement += &format!(" The window ends after the index time, so it was examined to {}.", fmtz(&examined));
    }
    let who_ = format!("{}{}", named.iter().take(5).cloned().collect::<Vec<_>>().join(", "), if named.len() > 5 { format!(" and {} more", named.len() - 5) } else { String::new() });
    let mut limits = vec![];
    if scoped(&q) {
        let what = match (nonempty(&q.owner), nonempty(&q.repo)) {
            (true, true) => format!("--owner {} and --repo {}", q.owner.clone().unwrap_or_default(), q.repo.clone().unwrap_or_default()),
            (true, false) => format!("--owner {}", q.owner.clone().unwrap_or_default()),
            _ => format!("--repo {}", q.repo.clone().unwrap_or_default()),
        };
        limits.push(format!(
            "Scope: this file covers only what {what} selects ({} of {} indexed sources); nothing outside it was examined, and the gaps below are the ones inside it.",
            cov.len(),
            ix.srcs.len()
        ));
    }
    limits.extend([
        format!("History begins {}; nothing earlier is in the index.", fmt_opt(floor.as_deref())),
        format!(
            "This covers only the sources the index holds, not every machine. {}.{}",
            pop.statement,
            if named.is_empty() { String::new() } else { format!(" Members with no laptop scan: {who_}.") }
        ),
        "The index holds hashes, names and metadata; it holds no file content.".to_string(),
        "Sources are known only up to their indexed_at time; later events are not visible.".to_string(),
        "A removal on a host is known only to the scan interval.".to_string(),
        "Only the indicators named in the question were searched.".to_string(),
    ]);
    if clipped {
        limits.push(format!(
            "The window ends {}; the index runs to {} ({}), so later events are not covered: br scan --stale",
            if end >= ctx.now { "now" } else { "after the index time" },
            fmtz(&examined),
            age_label(&ctx.now, &examined)
        ));
    }
    if !pop.empty_scans.is_empty() {
        limits.push(format!("A scan that hashed 0 files proves nothing, so these stay not checked: {}.", pop.empty_scans.join(", ")));
    }
    let unscanned: Vec<String> = res.names.iter().filter(|n| src_unscanned(&ix, n)).cloned().collect();
    if !unscanned.is_empty() {
        limits.push(format!("Registered but never scanned, so nothing was checked there: {}.", unscanned.join(", ")));
    }
    if !not_checked.is_empty() {
        limits.push(format!("{} in not_checked: sources, kinds of source or machines that could not be checked.", plural(not_checked.len(), "row")));
    }
    let gaps = {
        let g = H::gap_words(&not_checked);
        if g.is_empty() {
            "0 gaps".to_string()
        } else {
            g
        }
    };
    let window_from = match q.window_src.as_deref() {
        Some("advisory") | Some("OSV") => "advisory".to_string(),
        Some(s) if s.starts_with("your note") => "advisory".to_string(),
        Some("text") => "advisory text".to_string(),
        Some("whole history") => "whole history, because a bare hash has no advisory window".to_string(),
        Some("--window") | None => "--window option".to_string(),
        Some(other) => other.to_string(),
    };
    let prov = provenance(&view, &q, &a.q.iocs, a.q.text.as_ref().is_some_and(|t| !t.is_empty()));
    let prov_lines = prov.lines();
    let yara = yara_rows(&ix, &res);
    let yara_js: Vec<J> = yara.iter().map(|y| y.to_j()).collect();
    let data_as_of = {
        let times: Vec<&Cov> = cov.iter().filter(|c| !c.indexed_at.is_empty()).collect();
        match (times.iter().min_by(|a, b| a.indexed_at.cmp(&b.indexed_at)), times.iter().map(|c| c.indexed_at.clone()).max()) {
            (Some(o), Some(n)) => Some(crate::query::coverage::DataAsOf { oldest: o.indexed_at.clone(), newest: n, oldest_source: o.source.clone() }.words()),
            _ => None,
        }
    };
    let fjs: Vec<J> = confirmed.iter().map(|f| finding_json(f)).collect();
    let pjs: Vec<J> = possible.iter().map(|f| finding_json(f)).collect();
    let ljs: Vec<J> = res.present_after.iter().map(finding_json).collect();
    let secrets = H::secrets_of(&res);
    let possible_hosts = possible.iter().map(|f| f.where_.clone()).collect::<BTreeSet<_>>().len();
    let method = method_lines(&cov, &res);
    // chain of custody: the earlier evidence for the same case, then this issue (a signed re-issue is its own event)
    let prior: Vec<serde_json::Value> = Store::open(ctx, false)
        .ok()
        .map(|st| st.list("custody"))
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r["event"] == "evidence" && case_id.as_deref().is_some_and(|c| !c.is_empty() && r["case_id"].as_str() == Some(c)))
        .collect();
    let reissue = !prior.is_empty();
    let mut custody: Vec<CustodyRow> = custody_rows(&ix, &res, scoped(&q));
    custody.extend(prior.iter().map(|r| {
        let s = |k: &str| r[k].as_str().map(str::to_string);
        CustodyRow {
            event: "evidence".into(),
            at: s("at").unwrap_or_default(),
            by: s("by").unwrap_or_default(),
            requested_by: s("requested_by"),
            case_id: s("case_id"),
            signed_with: s("signed_with"),
            reissue: r["reissue"].as_bool().unwrap_or(false),
            ..Default::default()
        }
    }));
    custody.sort_by(|x, y| x.at.cmp(&y.at));
    custody.push(CustodyRow {
        event: "evidence".into(),
        at: ctx.now.clone(),
        by: by.clone(),
        requested_by: requested_by.clone(),
        case_id: case_id.clone(),
        signed_with: fingerprint.clone(),
        reissue,
        ..Default::default()
    });
    let custody_json: Vec<J> = custody.iter().map(|c| c.to_j()).collect();
    let mut doc = J::obj(vec![
        ("schema", J::s("br-evidence/1")),
        (
            "question",
            J::obj(vec![
                ("iocs", J::strs(&ioc_texts)),
                ("window", J::obj(vec![("from", J::s(&start)), ("to", J::s(&end))])),
                ("window_from", J::s(&window_from)),
                ("examined_to", J::s(&examined)),
                ("asked", J::opt(question.as_deref())),
                ("received", J::opt(received.as_deref())),
            ]),
        ),
        ("provenance", prov.to_j()),
        ("generated_at", J::s(&ctx.now)),
        ("tool", J::s(concat!("br ", env!("CARGO_PKG_VERSION")))),
        ("index_as_of", J::opt(res.as_of.as_deref())),
        ("requested_by", J::opt(requested_by.as_deref())),
        ("case_id", J::opt(case_id.as_deref())),
        (
            "claim",
            J::obj(vec![
                ("result", J::s(if found_in_window { "found" } else { "none_observed" })),
                ("present_now_after_window", J::Int(res.present_after.len() as i64)),
                ("verdict", J::s(verdict)),
                ("statement", J::s(&statement)),
                ("findings", J::Int(counts.findings as i64)),
                ("places", J::Int(counts.locations as i64)),
                ("possible_hosts", J::Int(possible_hosts as i64)),
                ("indicators_with_hits", J::strs(&with_hits)),
                ("indicators_without_hits", J::strs(&zero_hits)),
            ]),
        ),
        ("findings", J::Arr(fjs.clone())),
        ("yara_hits", J::Arr(yara_js.clone())),
        ("data_as_of", J::opt(data_as_of.as_deref())),
        ("possible", J::Arr(pjs.clone())),
        ("floating", J::Arr(res.floating.iter().map(crate::out::render::floating_json).collect())),
        ("secrets_exposed", J::strs(&secrets)),
        ("not_checked", J::Arr(not_checked.iter().map(nc_j).collect())),
        ("gaps", J::s(&gaps)),
        ("population", pop.to_j()),
        ("coverage_definition", J::s(coverage_definition(&examined))),
        ("coverage", J::Arr(cov.iter().map(|c| c.to_j()).collect())),
        ("method", J::strs(&method)),
        ("near_misses", J::Arr(res.near.iter().map(|n| J::obj(vec![("repo", J::s(&n.repo)), ("found", J::s(&n.found)), ("why", J::s(&n.why))])).collect())),
        ("limits", J::strs(&limits)),
        ("custody", J::Arr(custody_json)),
    ]);
    if !ljs.is_empty() {
        doc.set("present_after_window", J::Arr(ljs.clone()));
    }
    let digest = brx::json_digest(&to_value(&doc));
    doc.set(
        "integrity",
        J::obj(vec![
            ("alg", J::s("sha256")),
            ("covers", J::s("every field except integrity")),
            // the exact byte form that is hashed, so a second implementation can recompute it
            ("canonicalization", J::s("Python json.dumps(doc_without_integrity, sort_keys=True) (default separators, ensure_ascii), UTF-8")),
            ("digest", J::s(&digest)),
        ]),
    );
    write(&out_path, &format!("{}\n", doc.dumps()))?;
    let md_doc = Doc {
        requested_by: requested_by.clone(),
        case_id: case_id.clone(),
        generated_at: ctx.now.clone(),
        window: (start.clone(), end.clone()),
        window_from: window_from.clone(),
        examined_to: clipped.then(|| examined.clone()),
        iocs: ioc_texts.clone(),
        statement: statement.clone(),
        headline: headline.clone(),
        verdict: verdict.to_string(),
        index_as_of: res.as_of.clone(),
        pop: &pop,
        method: &method,
        findings: &fjs,
        possible: &pjs,
        late: &ljs,
        yara: &yara,
        possible_words: H::possible_words(&counts),
        data_as_of: data_as_of.clone(),
        secrets_exposed: &secrets,
        cov: &cov,
        rows: &not_checked,
        gaps: gaps.clone(),
        limits: &limits,
        custody: &custody,
        question: question.clone(),
        received: received.clone(),
        provenance: &prov_lines,
    };
    let md = evidence_md(&md_doc, &ctx.now);
    write(&md_path, &md_with_trailer(&md))?;
    let sha = brx::sha_file(Path::new(&out_path)).map_err(|e| brx::io_err(e, &out_path))?;
    // B2: --audience customers also writes a plain statement for a customer: no repo, host or person names, no secrets
    let customers_path = (a.audience.as_deref() == Some("customers")).then(|| format!("{}.customers.md", &out_path[..out_path.len() - ".json".len()]));
    if let Some(cp) = &customers_path {
        let first_day = confirmed.iter().filter_map(|f| f.first_seen.as_deref()).min().map(|s| s.chars().take(10).collect::<String>());
        let what = if with_hits.is_empty() { ioc_texts.iter().map(|t| plain_ioc(t)).collect::<Vec<_>>().join(", ") } else { with_hits.iter().map(|t| plain_ioc(t)).collect::<Vec<_>>().join(", ") };
        let out_name = Path::new(&out_path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let text = customers_text(
            found,
            &what,
            first_day,
            (&start, &end),
            clipped.then_some(examined.as_str()),
            res.as_of.as_deref(),
            &pop,
            &cov,
            not_checked.len(),
            case_id.as_deref(),
            &out_name,
            &sha,
            &ctx.now,
            (question.as_deref(), received.as_deref()),
            res.present_after.len(),
            (&with_hits, &zero_hits),
        );
        write(cp, &text)?;
    }
    // the custody entry is best-effort when the index is a dev dump rather than a store
    if let Ok(st) = Store::open(ctx, false) {
        let _ = st.push(
            "custody",
            &serde_json::json!({
                "event": "evidence",
                "at": ctx.now,
                "by": by,
                "case_id": case_id,
                "file_sha256": sha,
                "requested_by": requested_by,
                "signed_with": fingerprint,
                "sealed": !a.no_seal,
                "reissue": reissue,
            }),
        );
    }
    println!("{verdict}  {}  window {}", ioc_texts.join(", "), crate::query::util::window_words(&start, &end, clipped.then_some(examined.as_str())));
    if !gaps.starts_with("0 ") {
        println!("{gaps}; the file lists them under PARTIAL COVERAGE and NOT COVERED");
    }
    println!("wrote {out_path}");
    println!("wrote {md_path}");
    if let Some(cp) = &customers_path {
        println!("wrote {cp}");
    }
    let base = |p: &str| Path::new(p).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if a.no_seal {
        for gone in drop_seal(&out_path) {
            println!("removed the old seal {gone}");
        }
        println!("not sealed (--no-seal): br verify will report UNVERIFIED for these files");
    } else {
        let mut sealed = vec![out_path.clone(), md_path.clone()];
        sealed.extend(customers_path.clone());
        for w in brx::write_seal(&out_path, &sealed, key.as_deref())? {
            println!("wrote {w}");
        }
        println!(
            "sealed {} together{}",
            sealed.iter().map(|p| base(p)).collect::<Vec<_>>().join(" and "),
            match (&key, &fingerprint) {
                (Some(k), Some(f)) => format!("; signed with {k} ({f})"),
                _ => String::new(),
            }
        );
        if key.is_some() {
            println!("the signature proves the key holder signed these files; whose key it is, br verify --allowed-signers FILE checks");
        } else {
            println!("the seal is an integrity check (the files are unchanged), not proof of who made them; add --sign KEY for that");
        }
    }
    // A written file is a success. The finding is in the file; --fail-if found asks for 10, --fail-if none for 11
    match a.fail_if.as_deref() {
        Some("found") if found => return Ok(10),
        Some("none") if !found => return Ok(11),
        _ => {}
    }
    if a.strict && (!not_checked.is_empty() || !possible.is_empty()) {
        return Ok(3);
    }
    Ok(0)
}

/// The evidence file for `secret:NAME`: the rotation state (names, scopes, updated_at; never a value), sealed like any other.
fn secret_evidence(a: &EvidenceArgs, ctx: &Ctx, ix: &Index, q: &Query, paths: (&str, &str), asked: (Option<&str>, Option<&str>)) -> BrResult<i32> {
    use crate::out::secretq as SQ;
    let (out_path, md_path) = paths;
    if !crate::query::secret_hunt::is_secret_query(&a.q.iocs) {
        return Err(BrError::new("secret:NAME cannot be mixed with package indicators", Some("write one evidence file per question")));
    }
    if a.sign.is_some() && a.no_seal {
        return Err(BrError::new("--sign needs a seal to sign", Some("drop --no-seal, or drop --sign")));
    }
    let key = a.sign.clone();
    let fingerprint = match &key {
        Some(k) => Some(brx::key_fingerprint(k)?),
        None => None,
    };
    let rep = crate::query::secret_hunt::build(ix, q)?;
    let requested_by = a.requested_by.clone().or_else(|| brx::requested_by_default(ctx));
    let by = brx::who(ctx);
    let mut doc = J::obj(vec![
        ("schema", J::s("br-evidence/1")),
        ("kind", J::s("secret-rotation")),
        (
            "question",
            J::obj(vec![("iocs", J::strs(&rep.asked)), ("cutoff", J::opt(rep.cutoff.as_deref())), ("cutoff_from", J::s(&rep.cutoff_src)), ("asked", J::opt(asked.0)), ("received", J::opt(asked.1))]),
        ),
        ("generated_at", J::s(&ctx.now)),
        ("tool", J::s(concat!("br ", env!("CARGO_PKG_VERSION")))),
        ("index_as_of", J::s(&rep.as_of)),
        ("requested_by", J::opt(requested_by.as_deref())),
        ("case_id", J::opt(a.case.as_deref())),
        ("claim", SQ::evidence_json(&rep)),
        (
            "limits",
            J::strs(&[
                "GitHub reports when a secret was last updated, not what it holds.".to_string(),
                "Only secrets stored in GitHub are listed.".to_string(),
                "The index holds names, dates and metadata; it holds no secret value.".to_string(),
            ]),
        ),
    ]);
    let digest = brx::json_digest(&to_value(&doc));
    doc.set(
        "integrity",
        J::obj(vec![
            ("alg", J::s("sha256")),
            ("covers", J::s("every field except integrity")),
            ("canonicalization", J::s("Python json.dumps(doc_without_integrity, sort_keys=True) (default separators, ensure_ascii), UTF-8")),
            ("digest", J::s(&digest)),
        ]),
    );
    write(out_path, &format!("{}\n", doc.dumps()))?;
    write(md_path, &md_with_trailer(&SQ::evidence_md(&rep, &ctx.now, a.case.as_deref(), requested_by.as_deref())))?;
    let sha = brx::sha_file(Path::new(out_path)).map_err(|e| brx::io_err(e, out_path))?;
    if let Ok(st) = Store::open(ctx, false) {
        let _ = st.push("custody", &serde_json::json!({"event": "evidence", "at": ctx.now, "by": by, "case_id": a.case, "file_sha256": sha, "requested_by": requested_by, "signed_with": fingerprint, "sealed": !a.no_seal, "reissue": false}));
    }
    println!("{}  {}  {}", rep.verdict(), rep.asked_words(), rep.headline());
    for g in &rep.gaps {
        println!("not checked: {}", g.1);
    }
    println!("wrote {out_path}");
    println!("wrote {md_path}");
    if a.no_seal {
        println!("not sealed (--no-seal): br verify will report UNVERIFIED for these files");
    } else {
        for w in brx::write_seal(out_path, &[out_path.to_string(), md_path.to_string()], key.as_deref())? {
            println!("wrote {w}");
        }
    }
    let found = rep.found();
    match a.fail_if.as_deref() {
        Some("found") if found => return Ok(10),
        Some("none") if rep.stored.is_empty() => return Ok(11),
        _ => {}
    }
    if a.strict && !rep.gaps.is_empty() {
        return Ok(3);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_without_json_gets_the_suffix() {
        assert_eq!(out_paths("ev").unwrap(), ("ev.json".to_string(), "ev.md".to_string()));
        assert_eq!(out_paths("dir/ev.JSON").unwrap().1, "dir/ev.md");
        assert_eq!(out_paths("a.txt").unwrap().0, "a.txt.json");
        assert!(out_paths("ev.md").is_err());
    }

    #[test]
    fn write_leaves_no_temp_file() {
        let d = std::env::temp_dir().join(format!("br-f4-write-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("x.json");
        write(p.to_str().unwrap(), "{}\n").unwrap();
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn md_trailer_covers_exactly_the_body() {
        let t = md_with_trailer("# report\nline\n\n");
        let i = t.rfind(brx::MD_TRAILER).unwrap();
        assert_eq!(&t[..i], "# report\nline\n");
        let want = t[i + brx::MD_TRAILER.len()..].split_whitespace().next().unwrap();
        assert_eq!(want.len(), 64);
        assert!(t.ends_with(" -->\n"));
    }

    #[test]
    fn json_digest_ignores_the_integrity_block() {
        let a = serde_json::json!({"a": 1, "b": [1, 2]});
        let b = serde_json::json!({"a": 1, "b": [1, 2], "integrity": {"digest": "x"}});
        assert_eq!(brx::json_digest(&a), brx::json_digest(&b));
        assert_ne!(brx::json_digest(&a), brx::json_digest(&serde_json::json!({"a": 2, "b": [1, 2]})));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn a_customer_reads_a_package_not_a_purl() {
        assert_eq!(plain_ioc("npm:@tanstack/react-router@1.120.3"), "@tanstack/react-router 1.120.3 (npm)");
        assert_eq!(plain_ioc("pypi:requests@2.0.0"), "requests 2.0.0 (pypi)");
        assert_eq!(plain_ioc("sha256:ab"), "sha256:ab");
    }

    fn pop12(partial: usize) -> Pop {
        Pop {
            repos: 1,
            registries: 0,
            hosts: 0,
            runners: 0,
            laptops: 0,
            servers: 0,
            unknown: 0,
            members: 12,
            members_covered: 2,
            members_source: "visible to this token in GitHub".into(),
            members_partial: partial,
            members_stale: 0,
            members_empty: 0,
            member_reasons: vec![],
            member_names_without_laptop_scan: vec![],
            member_gaps: vec![],
            empty_scans: vec![],
            history_begins: None,
            statement: String::new(),
        }
    }

    #[test]
    fn r67_the_customer_coverage_line_has_the_count_the_oldest_check_and_the_partial_laptops() {
        let mk = |at: &str, cov: &'static str| Cov {
            source: format!("s-{at}"),
            kind: "repo".into(),
            indexed_at: at.into(),
            covers_window: cov == "full",
            coverage: cov,
            has_findings: false,
            stale: false,
            empty: false,
            unscanned: false,
            gap_reason: None,
            narrow: false,
            close_with: None,
        };
        let cov = vec![mk("2026-05-12T04:00:00Z", "full"), mk("2026-05-12T09:00:00Z", "full")];
        let t = customers_text(
            false,
            "x",
            None,
            ("2026-05-01T00:00:00Z", "2026-05-12T10:00:00Z"),
            None,
            None,
            &pop12(3),
            &cov,
            0,
            None,
            "e.json",
            "00",
            "2026-05-12T10:00:00Z",
            (None, None),
            0,
            (&[], &[]),
        );
        assert!(t.contains("we checked 2 systems"), "{t}");
        assert!(t.contains("the oldest checked at 2026-05-12 04:00Z"), "{t}");
        assert!(t.contains("fresh as of their last scan"), "{t}");
        assert!(!t.contains("last scanned at or after the end"), "{t}");
        assert!(t.contains("Of the other 10 laptops, 3 were checked only in part"), "{t}");
        assert!(t.contains("7 were not checked"), "{t}");
    }

    fn pop_with(stale: usize, partial: usize, covered: usize) -> Pop {
        Pop { members_covered: covered, members_stale: stale, ..pop12(partial) }
    }

    fn mk_cov(at: &str, cov: &'static str, stale: bool) -> Cov {
        Cov {
            source: format!("s-{at}"),
            kind: "repo".into(),
            indexed_at: at.into(),
            covers_window: cov == "full",
            coverage: cov,
            has_findings: false,
            stale,
            empty: false,
            unscanned: false,
            gap_reason: None,
            narrow: false,
            close_with: None,
        }
    }

    // The customer statement gives each gap the reason the evidence file gives it: stale is stale, partial is partial
    #[test]
    fn r8_the_statement_calls_a_stale_laptop_stale_and_a_narrow_scan_partial() {
        let args = |pop: &Pop| {
            customers_text(false, "x", None, ("2026-05-01T00:00:00Z", "2026-05-12T10:00:00Z"), None, None, pop, &[], 1, None, "ev.json", "00", "2026-05-12T10:00:00Z", (None, None), 0, (&[], &[]))
        };
        let stale = args(&pop_with(1, 0, 2));
        assert!(stale.contains("1 was last checked before the end of the period examined (the scan is stale)"), "{stale}");
        assert!(!stale.contains("checked only in part"), "a stale scan is not a partial one: {stale}");
        assert!(stale.contains("9 were not checked"), "{stale}");
        let narrow = args(&pop_with(0, 2, 2));
        assert!(narrow.contains("2 were checked only in part, because the scan read less than the laptop's home folder and package caches"), "{narrow}");
        assert!(!narrow.contains("stale"), "{narrow}");
        // the source gaps use the file's own states
        let cov = vec![mk_cov("2026-05-08T10:00:00Z", "partial", true), mk_cov("2026-05-12T09:00:00Z", "full", false)];
        let t = customers_text(false, "x", None, ("a", "b"), None, None, &pop_with(0, 0, 12), &cov, 1, None, "ev.json", "00", "2026-05-12T10:00:00Z", (None, None), 0, (&[], &[]));
        assert!(t.contains("1 was last checked before the end of the period examined, so later events are not known"), "{t}");
    }

    // With a question, the first sentence answers it, with the coverage caveat
    #[test]
    fn r8_the_first_sentence_answers_the_question() {
        let h = format!("sha256:{}", "c81aea38".repeat(8));
        let pop = pop_with(0, 0, 12);
        let hits = vec![h.clone()];
        let ask = Some("Was the file c81aea38 that our EDR flagged on Mira's laptop part of this?");
        let t = customers_text(true, "the sample", Some("2026-08-19".into()), ("a", "b"), None, None, &pop, &[], 2, None, "ev.json", "00", "2026-08-21T09:00:00Z", (ask, None), 0, (&hits, &[]));
        let first = t.lines().nth(2).unwrap();
        assert!(first.starts_with("Yes. ") && first.contains("c81aea38") && first.contains("was found in our internal systems") && first.contains("could not be fully checked"), "{first}");
        assert!(t.lines().nth(3).unwrap().starts_with("Your question: Was the file c81aea38"), "{t}");
        // a file the question names and the search did not cover is said
        let other =
            customers_text(false, "x", None, ("a", "b"), None, None, &pop, &[], 0, None, "ev.json", "00", "2026-08-21T09:00:00Z", (Some("did you have deadbeef12345678?"), None), 0, (&[], &hits));
        assert!(other.contains("Your question also names deadbeef12345678, which was not among the things we searched for."), "{other}");
        // a no with gaps is not a flat no
        let no = customers_text(false, "x", None, ("a", "b"), None, None, &pop, &[], 3, None, "ev.json", "00", "2026-08-21T09:00:00Z", (Some("did x touch you?"), None), 0, (&[], &[]));
        assert!(no.lines().nth(2).unwrap().starts_with("No findings so far for x") && no.lines().nth(2).unwrap().contains("cannot say No for certain"), "{no}");
    }

    // Customer text holds no internal word: no token, no command, no file name but the evidence file
    #[test]
    fn r8_customer_text_has_no_internal_words() {
        let internal = Regex::new(r"(?i)\btoken\b|\bbr\b|\.brx|\.ya?ml|\.md\b|\.sha256|\bindex\b|hosts\.|--[a-z]").unwrap();
        let hits = vec!["npm:@a/b@1.0.0".to_string()];
        let cov = vec![mk_cov("2026-05-08T10:00:00Z", "partial", true), mk_cov("2026-05-12T09:00:00Z", "full", false)];
        for (found, later, asked) in [(true, 0, Some("did you have @a/b?")), (true, 2, None), (false, 0, None), (false, 0, Some("any?"))] {
            let t = customers_text(
                found,
                "@a/b 1.0.0 (npm)",
                if later > 0 { None } else { Some("2026-05-11".into()) },
                ("2026-05-01T00:00:00Z", "2026-05-12T10:00:00Z"),
                Some("2026-05-12T06:00:00Z"),
                Some("2026-05-12T06:00:00Z"),
                &pop_with(1, 1, 2),
                &cov,
                3,
                Some("C-1"),
                "evidence.json",
                "ab",
                "2026-05-12T10:00:00Z",
                (asked, Some("2026-05-12T00:00:00Z")),
                later,
                (&hits, &[]),
            );
            let stripped = t.replace("evidence.json", "");
            assert!(!internal.is_match(&stripped), "an internal word in: {t}");
            assert!(!t.contains("we have no record of it"), "{t}");
        }
    }

    #[test]
    fn the_statement_claims_no_action() {
        let pop = Pop {
            repos: 1,
            registries: 0,
            hosts: 0,
            runners: 0,
            laptops: 0,
            servers: 0,
            unknown: 0,
            members: 12,
            members_covered: 2,
            members_source: "visible to this token in GitHub".into(),
            members_partial: 0,
            members_stale: 0,
            members_empty: 0,
            member_reasons: vec![],
            member_names_without_laptop_scan: vec![],
            member_gaps: vec![],
            empty_scans: vec![],
            history_begins: None,
            statement: String::new(),
        };
        let t = customers_text(
            true,
            "x 1.0 (npm)",
            Some("2026-05-11".into()),
            ("a", "b"),
            None,
            None,
            &pop,
            &[],
            0,
            None,
            "e.json",
            "00",
            "2026-05-12T00:00:00Z",
            (Some("were you hit?"), Some("2026-05-12T00:00:00Z")),
            0,
            (&[], &[]),
        );
        assert!(!t.contains("We are removing") && !t.contains("We are rotating"));
        assert!(t.contains("Recommended next steps") && t.contains("does not say that either has been done"));
        assert!(t.contains("Employee laptops: 2 of 12 people checked."));
        assert!(t.contains("Your question (received 2026-05-12): were you hit?"));
    }
}
