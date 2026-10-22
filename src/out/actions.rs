//! notify, fix, purge, diff: what to tell, change and clean up, derived from a hunt result.
//!
//! Every number and row starts from `H::findings(res)` (confirmed, deduped); possible exposure is shown and never
//! counted. fix and notify share one plan per repo (`repo_plans`). Destructive commands are preceded by a
//! `# preserve first:` line from one function. Each command returns its whole stdout as one string.

use std::collections::{BTreeMap, HashMap, HashSet};

use regex::Regex;

use crate::cli::QueryArgs;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::out::json::J;
pub use crate::out::shell::shquote;
use crate::out::shell::{self, dir_of, file_safe, glob_escape, hash_cmd, is_win_path, leaf, psq, shpath, OwnerKind};
use crate::query::hunt::{self as H, CertHit, FKind, Finding, HuntResult, Query};
use crate::query::index::{parse_pkg, Index};
use crate::query::iocs::{self as I, IocKind};
use crate::query::secrets::secret_uses;
use crate::query::util::{basename, fmt, fmtz, parse_when, plural};
use crate::query::version;
use crate::view::{AffectedPackage, ImageBuild, Source, View};

#[cfg(test)]
#[path = "actions_tests.rs"]
mod plan_tests;

type Fs<'a> = [&'a Finding];

// ---- shared plumbing ------------------------------------------------------------------------------------
fn ns(x: &Option<String>) -> String {
    x.clone().unwrap_or_else(|| "None".into())
}

fn truthy(x: &Option<String>) -> bool {
    x.as_deref().is_some_and(|s| !s.is_empty())
}

/// Build the query and load the view the way every plan command does.
pub fn load(ctx: &Ctx, a: &QueryArgs) -> BrResult<(View, Query)> {
    use crate::cmd::hunt::{build_query, check_repo, QueryInputs};
    let view = ctx.view();
    let inputs = QueryInputs { q: a, only: None, host: None, near: false, no_secrets: false, history: false, similar: None };
    let q = build_query(ctx, view.as_ref().ok(), &inputs, false)?;
    if q.iocs.is_empty() && q.benign.is_empty() {
        return Err(BrError::new("nothing to hunt for", Some("pass an indicator (npm:name@1.2.3) or --advisory ID")));
    }
    let view = view?;
    check_repo(&view, &a.repo)?;
    Ok((view, q))
}

/// A plan checks the repos it names for commits made since they were indexed, unless `--offline`. One conditional
/// request per repo at most; the answer lands in `HuntResult::moved`.
pub fn prepare_probe(ctx: &Ctx, offline: bool) {
    if !offline {
        H::set_probe(ctx);
    }
    OFFLINE.with(|o| o.set(offline));
}

/// `--to` is a version (or a commit SHA for an action). One check for fix, notify and purge.
pub fn check_to(to: &Option<String>) -> BrResult<()> {
    if let Some(f) = to.as_ref().filter(|f| !f.is_empty()) {
        let ver = Regex::new(r"^v?\d[\w.+\-]*$").unwrap();
        if !(ver.is_match(f) || I::is_sha(f)) {
            return Err(BrError::new(format!("--to \"{f}\" is not a version"), Some("write a version such as 1.2.4, or a 40-hex commit SHA for an action")));
        }
    }
    Ok(())
}

/// The one fixed version every command starts from: what the operator chose with `--to`, else the advisory's own
/// single fixed version. Per-package, per-range answers come from `want`, after `set_plan` has been called with the same `to`.
pub fn plan_fixed(q: &Query, to: &Option<String>) -> Option<String> {
    set_plan(q, to);
    to.clone().filter(|t| !t.is_empty()).or_else(|| q.adv.as_ref().and_then(|a| a.fixed.clone()).filter(|f| !f.is_empty()))
}

/// `--out`: where the command's output goes. Checked before the command runs. A directory means DIR/notify.txt for notify.
pub fn prepare_out(out: &Option<String>, is_notify: bool) -> BrResult<Option<String>> {
    let Some(path) = out.as_ref().filter(|p| !p.is_empty()) else { return Ok(None) };
    let mut path = path.clone();
    let abs = |p: &str| std::fs::canonicalize(p).ok().or_else(|| std::env::current_dir().ok().map(|c| c.join(p)));
    let parent_of = |p: &str| -> Option<std::path::PathBuf> { abs(p).and_then(|a| a.parent().map(|x| x.to_path_buf())) };
    if std::path::Path::new(&path).is_dir() && is_notify {
        path = std::path::Path::new(&path).join("notify.txt").to_string_lossy().to_string();
    }
    let d = parent_of(&path);
    let ok = !std::path::Path::new(&path).is_dir() && d.as_ref().is_some_and(|d| d.is_dir() && std::fs::metadata(d).is_ok_and(|m| !m.permissions().readonly()));
    if !ok {
        return Err(BrError::new(format!("cannot write {path}"), Some("pass a file name in a writable directory")));
    }
    Ok(Some(path))
}

/// Print `text`, or write it to the `--out` path and say so.
pub fn emit(path: &Option<String>, mut text: String) -> BrResult<()> {
    match path {
        None => {
            print!("{text}");
            Ok(())
        }
        Some(p) => {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            std::fs::write(p, &text).map_err(|_| BrError::new(format!("cannot write {p}"), Some("pass a file name in a writable directory")))?;
            let n = text.matches('\n').count();
            println!("wrote {p} ({})", plural(n, "line"));
            if text.starts_with("#!/bin/sh") {
                println!("review it, then run: sh {}", shpath(p));
            }
            Ok(())
        }
    }
}

/// The paths a host finding's command removes whole, so a path under one of them goes with it: a package folder, a module
/// folder, a tree. A manager's cleaner or uninstall names no path, and a Windows host is not compared by POSIX paths.
fn removed_roots(f: &Finding) -> Vec<String> {
    if f.kind != FKind::Host || is_lockfile(f) || f.loc.is_empty() || win_host(f) {
        return vec![];
    }
    let d = host_del(f);
    if !d.path {
        return vec![];
    }
    match f.item_kind.as_str() {
        "node_modules" if !f.hit_pkgs.is_empty() && last_comp(&f.loc) == "node_modules" => f.hit_pkgs.iter().map(|p| join_loc(&f.loc, shell::split_pkg(p).1, false)).collect(),
        "site-packages" | "conda" => vec![],
        _ => vec![f.loc.clone()],
    }
}

/// One cleanup step per place, and no step on a path an earlier step removed. A host finding under a path another finding
/// of the same host removes whole is part of that step (its indicators join the step, and a malware hit makes the step a
/// malware step); two cache findings with the same cleaner command on one host are one step. An image reached through two
/// indicators is one story: the layer facts of the file hit (deleted layer, blob, the Dockerfile step, the build that ran it)
/// join the row of the package hit, so an advisory plan says what a hash plan says.
pub fn merge_findings(res: &mut HuntResult) {
    // a hit of the file (it has a path) is more exact than a hit of the package that carried it (it has none)
    let sources: Vec<Finding> = res.findings.iter().filter(|f| f.kind == FKind::Image && f.layer > 0 && !f.path.is_empty()).cloned().collect();
    for f in res.findings.iter_mut().filter(|f| f.kind == FKind::Image && f.path.is_empty()) {
        if let Some(src) = sources.iter().find(|s| s.digest == f.digest) {
            f.layer = src.layer;
            f.layer_cmd = src.layer_cmd.clone();
            f.layer_blob = src.layer_blob.clone();
            f.deleted_in = src.deleted_in;
            f.executed_in_layer = src.executed_in_layer;
            f.where_in = src.where_in.clone();
            f.path = src.path.clone();
        }
    }
    let n = res.findings.len();
    let roots: Vec<Vec<String>> = res.findings.iter().map(removed_roots).collect();
    let cleaner: Vec<Option<(String, String)>> =
        res.findings.iter().map(|f| (f.kind == FKind::Host && !is_lockfile(f) && !f.inferred && !win_host(f) && !host_del(f).path).then(|| (f.where_.clone(), host_del(f).cmd))).collect();
    let mut covered: Vec<Option<usize>> = vec![None; n];
    for i in 0..n {
        let f = &res.findings[i];
        if f.kind != FKind::Host || is_lockfile(f) {
            continue;
        }
        for j in 0..n {
            if i == j {
                continue;
            }
            let g = &res.findings[j];
            let inside = g.kind == FKind::Host && g.where_ == f.where_ && roots[j].iter().any(|r| crate::query::index::under(&f.loc, r) && f.loc.trim_end_matches('/') != r.trim_end_matches('/'));
            let same_cleaner = j < i && cleaner[i].is_some() && cleaner[i] == cleaner[j];
            if inside || same_cleaner {
                covered[i] = Some(j);
                break;
            }
        }
    }
    let target = |mut i: usize| {
        let mut hops = 0;
        while let Some(j) = covered[i] {
            i = j;
            hops += 1;
            if hops > n {
                break;
            }
        }
        i
    };
    let mut gone: Vec<usize> = vec![];
    for i in 0..n {
        if covered[i].is_none() {
            continue;
        }
        let t = target(i);
        if t == i {
            continue;
        }
        let b = res.findings[i].clone();
        let a = &mut res.findings[t];
        let mut all = a.iocs_or_one();
        for x in b.iocs_or_one() {
            if !all.contains(&x) {
                all.push(x);
            }
        }
        a.iocs = all;
        if is_malware(&b) && !is_malware(a) {
            a.ioc = b.ioc.clone();
            a.sha256 = b.sha256.clone();
            a.match_ = b.match_.clone();
            a.sim = b.sim;
        }
        gone.push(i);
    }
    if !gone.is_empty() {
        let mut k = 0;
        res.findings.retain(|_| {
            let keep = !gone.contains(&k);
            k += 1;
            keep
        });
    }
}

/// Confirmed findings plus, under --now, the past CI runs hunt keeps apart, plus what is present now but was first
/// seen after the window: a window labels a finding, it never hides one that is still there, so a plan covers it.
pub fn all_findings(res: &HuntResult) -> Vec<&Finding> {
    let mut v = H::findings(res);
    v.extend(H::past_runs(res));
    v.extend(res.present_after.iter().filter(|f| !f.possible && !f.past_run));
    v
}

/// The findings of a plan that the window alone would have hidden.
fn after_window_note(res: &HuntResult) -> Option<String> {
    let n = res.present_after.iter().filter(|f| !f.possible && !f.past_run).count();
    (n > 0).then(|| format!("{} present now but first seen after the window ended: included above, because they are still there", plural(n, "place")))
}

thread_local! {
    /// `--offline`: nothing is asked of GitHub or a package registry while planning.
    static OFFLINE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// `teams.yaml` entries (team id -> slack, jira) for teams GitHub did not resolve.
    /// host -> the login its ssh target names (`user@host`), from hosts.yaml
    static HOST_LOGIN: std::cell::RefCell<BTreeMap<String, String>> = const { std::cell::RefCell::new(BTreeMap::new()) };
    static TEAMS_CFG: std::cell::RefCell<BTreeMap<String, (Option<String>, Option<String>)>> = const { std::cell::RefCell::new(BTreeMap::new()) };
    /// (ecosystem, name, package) of the advisory being acted on: each package carries its own versions and ranges.
    static PKGS: std::cell::RefCell<Vec<(String, String, AffectedPackage)>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn norm_name(eco: &str, n: &str) -> String {
    if eco == "pypi" {
        n.to_lowercase().replace(['_', '.'], "-")
    } else {
        n.to_string()
    }
}

/// Remember the per-package truth of this query's advisory (cleared when the operator chose a version with --to).
/// Ruling 2: the fixed version is per package and per range, found by `version::fixed_for`.
pub fn set_plan(q: &Query, to: &Option<String>) {
    PKGS.with(|p| {
        let mut p = p.borrow_mut();
        p.clear();
        if to.as_deref().is_some_and(|t| !t.is_empty()) {
            return;
        }
        for i in &q.iocs {
            if let (IocKind::Pkg, Some(set)) = (i.kind, &i.set) {
                let eco = i.eco.clone().unwrap_or_else(|| set.ecosystem.clone());
                p.push((eco.clone(), norm_name(&eco, &i.name), set.clone()));
            }
        }
    });
}

fn has_pkg_fixes() -> bool {
    PKGS.with(|p| p.borrow().iter().any(|(_, _, k)| !k.ranges.is_empty()))
}

/// The version to move `f` to: the advisory's own per-package, per-range answer when it has one, else the legacy
/// single `fixed`. None = no fixed release on this line of the package.
pub fn want(f: &Finding, fixed: &Option<String>) -> Option<String> {
    let eco = eco_of(f);
    let nm = norm_name(&eco, &f.name);
    let per = PKGS.with(|p| p.borrow().iter().find(|(e, n, _)| *e == eco && *n == nm).map(|(_, _, k)| (k.ranges.is_empty(), version::fixed_for(k, &f.version))));
    let v = match per {
        Some((false, r)) => r,
        _ => fixed.clone().filter(|v| !v.is_empty()),
    };
    match v {
        Some(v) if eco == "go" && !v.starts_with('v') => Some(format!("v{v}")),
        x => x,
    }
}

/// What is known about the fix for one finding: a version, "this line has no fixed release", or "br was not told".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    To(String),
    NoRelease,
    Unknown,
}

pub fn fix_of(f: &Finding, fixed: &Option<String>) -> Fix {
    if let Some(v) = want(f, fixed) {
        return Fix::To(v);
    }
    let eco = eco_of(f);
    let nm = norm_name(&eco, &f.name);
    let ranged = PKGS.with(|p| p.borrow().iter().any(|(e, n, k)| *e == eco && *n == nm && !k.ranges.is_empty()));
    if ranged {
        Fix::NoRelease
    } else {
        Fix::Unknown
    }
}

/// The words for a finding with no version to move to. "No fixed release" only when the advisory's ranges say so.
fn no_version_words(f: &Finding, fixed: &Option<String>) -> String {
    match fix_of(f, fixed) {
        Fix::Unknown => format!("no fixed version is known for {} (pass --to VERSION, or an advisory that names one)", f.name),
        _ => format!("no fixed release is published on this line of {}", f.name),
    }
}

/// `want` as text for a sentence.
fn fx_text(w: &Option<String>) -> String {
    w.clone().unwrap_or_else(|| "a fixed release (none is published for this line)".into())
}

pub fn eco_of(f: &Finding) -> String {
    if !f.eco.is_empty() {
        return f.eco.clone();
    }
    match f.ioc.split_once(':') {
        Some((e, _)) => e.to_string(),
        None => "npm".into(),
    }
}

fn verify_cmd(a: &QueryArgs, q: &Query, repo: &str) -> String {
    let mut sel: Vec<String> = vec![];
    if let Some(adv) = a.advisory.as_ref().filter(|x| !x.is_empty()) {
        sel.push(format!("--advisory {}", shquote(adv)));
    }
    sel.extend(a.iocs.iter().map(|s| shquote(s)));
    if sel.is_empty() {
        sel = q.iocs.iter().map(|i| shquote(&i.text)).collect();
    }
    let r = shquote(repo);
    format!("br scan --repo {r} && br hunt {} --repo {r} --now --only repos --fail-if found", sel.join(" "))
}

fn not_checked_text(res: &HuntResult, prefix: &str) -> Vec<String> {
    if res.not_checked.is_empty() {
        return vec![];
    }
    let mut out = vec![format!("{prefix}NOT CHECKED (these could hold more than is listed here):")];
    for n in &res.not_checked {
        // The row that counts members without a laptop scan also names them (the one members_covered list)
        let who = if n.state == "laptops" && !n.people.is_empty() {
            let shown: Vec<&str> = n.people.iter().take(10).map(|p| p.as_str()).collect();
            let more = if n.people.len() > shown.len() { format!(" and {} more", n.people.len() - shown.len()) } else { String::new() };
            format!(" ({}{more})", shown.join(", "))
        } else {
            String::new()
        };
        out.push(format!("{prefix}  {}: {}{who}; to close: {}", n.name, n.why, n.command));
    }
    out
}

fn not_checked_json(res: &HuntResult) -> J {
    J::Arr(res.not_checked.iter().map(|n| J::obj(vec![("name", J::s(&n.name)), ("state", J::s(&n.state)), ("why", J::s(&n.why)), ("command", J::s(&n.command))])).collect())
}

// ---- owners ---------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    Person(String),
    Team(String),
    /// A team GitHub did not resolve whose address the operator gave with `br teams set`.
    Unresolved(String),
    None(String),
}

fn repo_key(f: &Finding) -> Option<String> {
    match f.kind {
        FKind::Image => f.from_repo.clone().filter(|r| !r.is_empty()),
        FKind::Host => None,
        _ => Some(f.where_.clone()),
    }
}

pub fn target_of(ix: &Index, f: &Finding) -> Target {
    target_with(ix, f, &f.owner)
}

/// Where the cleanup of a runner's workspace goes besides the runner's own owner: the owner of the repo whose checkout
/// it is, or whose run installed the package. None when the finding is not in a repo's workspace, or that repo has no owner.
fn workspace_target(ix: &Index, f: &Finding) -> Option<Target> {
    if f.kind != FKind::Host || is_package_cache(f) {
        return None;
    }
    let o = f.workspace_owner.as_ref()?;
    match target_with(ix, f, o) {
        Target::None(_) => None,
        t => Some(t),
    }
}

fn target_with(ix: &Index, f: &Finding, o: &crate::query::hunt::Owner) -> Target {
    if let Some(t) = o.team.as_ref().filter(|t| ix.is_team(t)) {
        return Target::Team(t.clone());
    }
    if let Some(p) = o.people.first() {
        return Target::Person(p.clone());
    }
    let repo = repo_key(f).unwrap_or_else(|| f.where_.clone());
    if let Some(t) = o.team.as_ref().filter(|t| !t.is_empty()) {
        if TEAMS_CFG.with(|c| c.borrow().get(t).is_some_and(|(s, j)| s.is_some() || j.is_some())) {
            return Target::Unresolved(t.clone());
        }
        return Target::None(format!("CODEOWNERS of {repo} names {t}, which br could not resolve (the token may lack read:org, or the team is secret or deleted)"));
    }
    if f.kind == FKind::Host {
        return Target::None(format!("no owner is recorded for host {}", f.where_));
    }
    if ix.v.repos.get(&repo).is_some_and(|r| r.codeowners.trim().is_empty()) {
        return Target::None(format!("{repo} has no CODEOWNERS file"));
    }
    Target::None(format!("no CODEOWNERS rule covers {repo}"))
}

fn team_slack(ix: &Index, id: &str) -> String {
    ix.v.teams.iter().find(|t| t.id == id).and_then(|t| t.slack.clone()).unwrap_or_else(|| id.to_string())
}

pub fn owner_label(ix: &Index, f: &Finding) -> String {
    match target_of(ix, f) {
        Target::Team(v) => team_slack(ix, &v),
        Target::Unresolved(v) => TEAMS_CFG.with(|c| c.borrow().get(&v).and_then(|x| x.0.clone())).unwrap_or(v),
        Target::Person(v) => match &f.owner.suggested {
            // A person br suggests (archiver, last committer, org admin) is labelled so, never presented as the owner
            Some(why) if f.owner.people.first() == Some(&v) => format!("@{v} (suggested: {why})"),
            _ => format!("@{v}"),
        },
        Target::None(_) => "NO OWNER FOUND".into(),
    }
}

/// A team by its short slug. Two orgs can both have `platform`: the one in `org` wins when the org is known.
fn team_by_short<'a>(ix: &'a Index, short: &str, org: Option<&str>) -> Option<&'a crate::view::Team> {
    let mut all = ix.v.teams.iter().filter(|t| t.id.rsplit('/').next() == Some(short));
    match org {
        Some(o) => {
            let pre = format!("{o}/");
            let v: Vec<&crate::view::Team> = all.collect();
            v.iter().copied().find(|t| t.id.starts_with(&pre)).or_else(|| v.first().copied())
        }
        None => all.next(),
    }
}

/// (header line, jira project) of a message to a team or a person.
fn header_for(ix: &Index, key: &Target) -> (String, Option<String>) {
    match key {
        Target::Team(v) => {
            let t = ix.v.teams.iter().find(|t| &t.id == v).cloned().unwrap_or_default();
            let lead = t.lead.as_ref().filter(|l| !l.is_empty()).map(|l| ix.person_name(l));
            let slack = t.slack.clone().unwrap_or_else(|| v.clone());
            let head = match lead {
                Some(l) => format!("To {slack} ({v}, lead {l})"),
                None => format!("To {slack} ({v})"),
            };
            (head, t.jira.clone())
        }
        Target::Unresolved(v) => {
            let (slack, jira) = TEAMS_CFG.with(|c| c.borrow().get(v).cloned()).unwrap_or_default();
            let to = slack.unwrap_or_else(|| v.clone());
            (format!("To {to} ({v}; GitHub does not resolve this team, the address is from teams.yaml)"), jira)
        }
        Target::Person(v) | Target::None(v) => {
            let p = ix.person(v);
            let t = p.and_then(|p| p.team.as_ref().filter(|t| !t.is_empty())).and_then(|s| team_by_short(ix, s, None));
            let mut extra: Vec<String> = vec![];
            if let Some(n) = p.and_then(|p| p.name.clone()).filter(|n| !n.is_empty()) {
                extra.push(n);
            }
            if let Some(s) = t.and_then(|t| t.slack.clone()).filter(|s| !s.is_empty()) {
                extra.push(s);
            }
            let head = if extra.is_empty() { format!("To @{v}") } else { format!("To @{v} ({})", extra.join(", ")) };
            (head, t.and_then(|t| t.jira.clone()))
        }
    }
}

fn last_committer(ix: &Index, repo: &str) -> Option<String> {
    let t = ix.i(repo);
    let mut cs: Vec<&crate::view::Commit> = ix.repo(repo).commits.iter().filter(|c| c.author.as_deref().is_some_and(|a| !a.is_empty())).filter(|c| t.as_ref().is_none_or(|t| c.at <= *t)).collect();
    cs.sort_by(|a, b| a.at.cmp(&b.at));
    cs.last().and_then(|c| c.author.clone())
}

fn no_owner_lines(ix: &Index, f: &Finding, reason: &str) -> Vec<String> {
    let repo = repo_key(f);
    let mut out = vec![format!("  - {}: {reason}", place_name(f))];
    let pid = repo.as_deref().and_then(|r| last_committer(ix, r));
    if let Some(pid) = pid {
        if let Some(p) = ix.person(&pid) {
            let name = p.name.clone().unwrap_or_else(|| pid.clone());
            let t = p.team.as_ref().and_then(|s| team_by_short(ix, s, repo.as_deref().and_then(|r| r.split('/').next())));
            let slack = |t: &crate::view::Team| t.slack.clone().unwrap_or_else(|| t.id.clone());
            let wh = t.map(|t| format!(" (now on {}, {})", t.id, slack(t))).unwrap_or_default();
            // The author is a person from the commits; br never invents a host name for them
            let scanned = ix.names("host").iter().any(|h| ix.host_def(h).and_then(|d| d.owner.as_deref()).and_then(|o| ix.person_by_ref(o)).as_deref() == Some(pid.as_str()));
            let machine = if scanned { String::new() } else { ": no machine of theirs is scanned".to_string() };
            out.push(format!("      last committer: {name} (@{pid}){machine}{wh}"));
            if let Some(t) = t {
                out.push(format!("      suggested: ask {name} in {}", slack(t)));
            }
        }
    }
    if !ix.v.org_admins.is_empty() {
        out.push(format!("      otherwise the org admins: {}", ix.v.org_admins.join(", ")));
    }
    out
}

fn no_owner_block(ix: &Index, orphans: &[(&Finding, String)]) -> Vec<String> {
    let mut groups: Vec<((String, String), Vec<&Finding>)> = vec![];
    for (f, reason) in orphans {
        let key = (place_name(f), reason.clone());
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(f),
            None => groups.push((key, vec![f])),
        }
    }
    let mut out = vec![];
    for ((_, reason), fl) in groups {
        let mut lines = no_owner_lines(ix, fl[0], &reason);
        if fl.len() > 1 {
            lines[0] += &format!(" ({})", plural(fl.len(), "finding"));
        }
        out.extend(lines);
    }
    out
}

fn sub_result(res: &HuntResult, fs: &[&Finding]) -> HuntResult {
    HuntResult {
        q: res.q.clone(),
        findings: fs.iter().map(|f| (*f).clone()).collect(),
        near: vec![],
        names: vec![],
        stale: vec![],
        gaps: vec![],
        never: vec![],
        not_checked: vec![],
        possible: vec![],
        window_ends_now: false,
        as_of: None,
        scope_total: 0,
        scope_stale: 0,
        moved: vec![],
        present_after: vec![],
        hash_advisories: vec![],
        ..Default::default()
    }
}

fn totals_line(res: &HuntResult, fs: &[&Finding]) -> String {
    // A look-alike file is planned for but never counted with the findings
    let now: Vec<&Finding> = fs.iter().copied().filter(|f| !f.past_run && f.match_ != "similar").collect();
    let sim = fs.iter().filter(|f| !f.past_run && f.match_ == "similar").count();
    let extra = if sim > 0 { format!("; plus {} that looks like it, not identical", plural(sim, "file")) } else { String::new() };
    format!("In all: {}{extra}.", H::count_words(&sub_result(res, &now)))
}

pub fn place_name(f: &Finding) -> String {
    if f.kind == FKind::Image {
        f.image.clone()
    } else {
        f.where_.clone()
    }
}

fn short(d: &str) -> String {
    d.chars().take(19).collect()
}

/// Identity of a place for rows that act on it.
fn place_id(f: &Finding) -> String {
    if f.kind == FKind::Host {
        return format!(
            "path\x01{}\x01{}",
            f.where_,
            if f.inferred {
                "inferred".to_string()
            } else if !f.loc.is_empty() {
                f.loc.clone()
            } else {
                f.path.clone()
            }
        );
    }
    fkey(f)
}

fn one_per_place(fs: Vec<&Finding>) -> Vec<&Finding> {
    let mut seen = HashSet::new();
    fs.into_iter().filter(|f| seen.insert(place_id(f))).collect()
}

// ---- destructive commands -------------------------------------------------------------------------------
/// Which package-manager cache a path is, from its path components (never from a substring of the whole path).
fn cache_kind(loc: &str, item_kind: &str) -> &'static str {
    match item_kind {
        "npm-cache" => return "npm",
        "pnpm-store" => return "pnpm",
        "yarn-cache" => return "yarn",
        "pip-cache" => return "pip",
        "go-modcache" => return "go",
        _ => {}
    }
    for c in loc.split(['/', '\\']).map(|c| c.to_lowercase()) {
        match c.as_str() {
            "pnpm" | "pnpm-store" | ".pnpm-store" | ".pnpm" => return "pnpm",
            ".yarn" | "yarn" | ".yarn-cache" => return "yarn",
            "pip" => return "pip",
            "mod" if loc.contains("pkg") => return "go",
            _ => {}
        }
    }
    "npm"
}

fn cache_clean(kind: &str) -> &'static str {
    match kind {
        "pnpm" => "pnpm store prune",
        "yarn" => "yarn cache clean",
        "pip" => "pip cache purge",
        "go" => "go clean -modcache",
        _ => "npm cache clean --force",
    }
}

fn cache_label(kind: &str) -> &'static str {
    match kind {
        "pnpm" => "pnpm store",
        "yarn" => "yarn cache",
        "pip" => "pip cache",
        "go" => "Go module cache",
        _ => "npm cache",
    }
}

fn win_host(f: &Finding) -> bool {
    is_win_path(&f.loc) || is_win_path(&f.path)
}

/// What removing a host finding is, and what it saves first.
struct HostDel {
    /// the command that removes it
    cmd: String,
    /// the command removes a path (or the package's own files): it is not a package manager's cleaner
    path: bool,
    /// set when the command removes more than the finding: what else goes
    wider: Option<String>,
    /// what to save first when that is not the whole `loc`
    keep: Option<Keep>,
}

struct Keep {
    /// a POSIX command that writes a tar.gz of the evidence to stdout
    tar: String,
    /// the same paths for PowerShell's Compress-Archive
    win_paths: Vec<String>,
    /// words for "preserves: ..."
    what: String,
}

/// A lockfile on a host is a file in someone's checkout. br never removes it: the change is a version bump there.
pub fn is_lockfile(f: &Finding) -> bool {
    f.kind == FKind::Host && f.item_kind == "lockfile"
}

fn last_comp(loc: &str) -> &str {
    loc.trim_end_matches(['/', '\\']).rsplit(['/', '\\']).next().unwrap_or("")
}

fn join_loc(loc: &str, name: &str, win: bool) -> String {
    if win {
        format!("{}\\{}", loc.trim_end_matches(['/', '\\']), name.replace('/', "\\"))
    } else {
        format!("{}/{}", loc.trim_end_matches('/'), name)
    }
}

/// On a Windows host the path form is PowerShell (Remove-Item -LiteralPath, so no wildcard is expanded:
/// https://learn.microsoft.com/powershell/module/microsoft.powershell.management/remove-item).
///
/// The delete is no wider than the finding. A package in `node_modules` is its own folder; a package in
/// `site-packages` is `pip uninstall` in the interpreter that owns the folder (it removes the files its RECORD lists); a
/// conda package is `conda remove`; a Go module is its folder and its download-cache entries; a pip cache entry is
/// `pip cache remove`. A manager's cleaner stays only where it has no narrower form, and then carries a `wider than the
/// finding` note.
fn host_del(f: &Finding) -> HostDel {
    let loc = &f.loc;
    let win = win_host(f);
    let hits: Vec<(&str, &str, &str)> = f.hit_pkgs.iter().map(|p| shell::split_pkg(p)).collect();
    let is_cache = f.inferred || matches!(f.item_kind.as_str(), "npm-cache" | "pnpm-store" | "yarn-cache" | "pip-cache" | "go-modcache");
    if is_cache {
        let kind = cache_kind(loc, if f.inferred { "" } else { &f.item_kind });
        if kind == "pip" && !f.inferred && !hits.is_empty() {
            let cmds: Vec<String> = hits.iter().map(|(_, n, v)| format!("pip cache remove {}", shquote(&format!("{}-{v}-*", shell::dist_name(n))))).collect();
            return HostDel { cmd: cmds.join(" && "), path: true, wider: None, keep: None };
        }
        return HostDel { cmd: cache_clean(kind).into(), path: false, wider: Some(cleaner_wider(kind).to_string()), keep: None };
    }
    let pip_hits: Vec<&(&str, &str, &str)> = hits.iter().filter(|h| h.0 == "pypi").collect();
    match f.item_kind.as_str() {
        "node_modules" if !hits.is_empty() && last_comp(loc) == "node_modules" => {
            let dirs: Vec<String> = hits.iter().map(|(_, n, _)| join_loc(loc, n, win)).collect();
            let names: Vec<&str> = hits.iter().map(|h| h.1).collect();
            let what = format!("{} (the package folder only, not the rest of node_modules)", dirs.join(", "));
            let cmd = if win {
                format!("Remove-Item -LiteralPath {} -Recurse -Force", dirs.iter().map(|d| psq(d)).collect::<Vec<_>>().join(","))
            } else {
                format!("rm -rf {}", dirs.iter().map(|d| shpath(d)).collect::<Vec<_>>().join(" "))
            };
            let tar = format!("tar czf - -C {} {}", shpath(loc), names.iter().map(|n| shquote(n)).collect::<Vec<_>>().join(" "));
            return HostDel { cmd, path: true, wider: None, keep: Some(Keep { tar, win_paths: dirs, what }) };
        }
        "site-packages" if !pip_hits.is_empty() => {
            let py = shell::python_for(loc);
            let names: Vec<String> = pip_hits.iter().map(|h| shquote(h.1)).collect();
            let pyq = if win { psq(&py) } else { shpath(&py) };
            let cmd = format!("{}{pyq} -m pip uninstall -y {}", if win { "& " } else { "" }, names.join(" "));
            let pats: Vec<String> = pip_hits.iter().map(|h| shquote(&shell::dist_info_pattern(h.1, h.2))).collect();
            let sel = if pats.len() == 1 { format!("-iname {}", pats[0]) } else { format!("\\( {} \\)", pats.iter().map(|p| format!("-iname {p}")).collect::<Vec<_>>().join(" -o ")) };
            let tar = format!("find {} -maxdepth 1 {sel} -exec cat {{}}/RECORD \\; | cut -d, -f1 | tar czf - -C {} -T -", shpath(loc), shpath(loc));
            let win_paths = pip_hits.iter().map(|h| join_loc(loc, &format!("{}-{}.dist-info", shell::dist_name(h.1), h.2), true)).collect();
            let what = format!(
                "the files listed in the RECORD of {} (the package's own files, not the rest of site-packages)",
                pip_hits.iter().map(|h| format!("{}-{}.dist-info", shell::dist_name(h.1), h.2)).collect::<Vec<_>>().join(", ")
            );
            return HostDel { cmd, path: true, wider: None, keep: Some(Keep { tar, win_paths, what }) };
        }
        "conda" if !pip_hits.is_empty() && !win => {
            let names: Vec<String> = pip_hits.iter().map(|h| shquote(h.1)).collect();
            let cmd = format!("conda remove -y -p {} {}", shpath(loc), names.join(" "));
            let globs: Vec<String> = pip_hits.iter().map(|h| format!("conda-meta/{}-{}-*.json", h.1, h.2)).collect();
            let tar = format!("tar czf - -C {} {}", shpath(loc), globs.iter().map(|g| shquote(g)).collect::<Vec<_>>().join(" "));
            let what = format!("the conda-meta record of {} (it lists the package's files); the files stay in the environment until conda removes them", names.join(", "));
            return HostDel { cmd, path: true, wider: None, keep: Some(Keep { tar, win_paths: vec![], what }) };
        }
        "go-mod-cache" if !win => {
            // the module's own folder, or one file inside it, and the module's download-cache files (the zip would bring the
            // file back on the next build); the folder is made writable first because the module cache is read-only
            if let Some((base, module, ver, moddir)) = shell::go_mod_parts(loc) {
                let dl = |ext: &str| shpath(&format!("{base}/cache/download/{module}/@v/{ver}.{ext}"));
                let cmd =
                    format!("chmod -R u+w {} && rm -rf {} && rm -f {}", shpath(&moddir), shpath(loc), ["info", "mod", "zip", "ziphash", "lock"].iter().map(|e| dl(e)).collect::<Vec<_>>().join(" "));
                return HostDel { cmd, path: true, wider: None, keep: None };
            }
        }
        _ => {}
    }
    let whole = matches!(last_comp(loc), "node_modules" | "site-packages" | "dist-packages");
    if win {
        return HostDel { cmd: format!("Remove-Item -LiteralPath {} -Recurse -Force", psq(loc)), path: true, wider: whole.then(|| whole_folder_note(loc)), keep: None };
    }
    // A path inside a package manager's own tree goes with that manager's cleaner; any other tree can hold read-only
    // directories (a Go module cache does), so it is made writable before it is removed
    if let Some(k) = path_cache_kind(loc) {
        return HostDel { cmd: cache_clean(k).into(), path: false, wider: Some(cleaner_wider(k).to_string()), keep: None };
    }
    HostDel { cmd: format!("chmod -R u+w {} && rm -rf {}", shpath(loc), shpath(loc)), path: true, wider: whole.then(|| whole_folder_note(loc)), keep: None }
}

fn whole_folder_note(loc: &str) -> String {
    format!("wider than the finding: removes the whole {} folder, not only the package; every other package in it goes too and must be installed again", last_comp(loc))
}

fn cleaner_wider(kind: &str) -> &'static str {
    match kind {
        "pnpm" => "wider than the finding: pnpm store prune also removes every other unreferenced package from the store",
        "yarn" => "wider than the finding: yarn cache clean also removes every clean entry in the cache",
        "pip" => "wider than the finding: pip cache purge also removes every cached wheel; they download again on the next install",
        "go" => "wider than the finding: go clean -modcache removes the whole module cache; modules download again on the next build",
        _ => "wider than the finding: npm cache clean --force also removes the clean entries; they download again on the next install",
    }
}

/// (command, is_cleanup_of_whole_path): see `host_del`.
fn host_cmd(f: &Finding) -> (String, bool) {
    let d = host_del(f);
    (d.cmd, d.path)
}

/// The package manager whose cache or store a path lies in, from its path components. Only trees with a cleaner of
/// their own: the Go module cache (`pkg/mod`), npm's `_cacache`, and pnpm's store.
fn path_cache_kind(loc: &str) -> Option<&'static str> {
    let c: Vec<String> = loc.split(['/', '\\']).map(|c| c.to_lowercase()).collect();
    if c.windows(2).any(|w| w[0] == "pkg" && w[1] == "mod") {
        return Some("go");
    }
    if c.iter().any(|x| x == "_cacache") {
        return Some("npm");
    }
    if c.iter().any(|x| x == ".pnpm-store" || x == "pnpm-store") {
        return Some("pnpm");
    }
    None
}

/// How br gets to a host: ssh, or import-only. Unknown counts as import-only.
fn host_reach(ix: &Index, host: &str) -> String {
    // The host that was scanned or imported as this machine is where br runs: its commands run here, whatever its source says
    if ix.host_def(host).is_some_and(|h| h.this_machine) {
        return "local".into();
    }
    ix.srcs.get(host).map(|s| s.reach.clone()).filter(|r| !r.is_empty()).unwrap_or_else(|| "import-only".into())
}

/// A runner's cache is cleaned by the manager's cleaner, which does not touch the `_work` checkouts or the tool cache. Say
/// which of those hold the package (scanned: they have their own entries), or that br cannot tell because the runner was not
/// scanned since the install.
fn runner_holds(ix: &Index, f: &Finding, hosts: &[&Finding]) -> Option<String> {
    if f.kind != FKind::Host || !is_package_cache(f) || ix.host_def(&f.where_).and_then(|h| h.kind.as_deref()) != Some("runner") {
        return None;
    }
    let others: Vec<String> = hosts
        .iter()
        .filter(|g| g.where_ == f.where_ && !is_package_cache(g) && !is_lockfile(g))
        .map(|g| match g.item_kind.as_str() {
            "tool-cache" => format!("tool cache {}", g.loc),
            _ if g.loc.contains("/_work/") => format!("_work checkout {}", g.loc),
            k => format!("{k} {}", g.loc),
        })
        .collect();
    if !others.is_empty() {
        return Some(format!("{} also holds it in {}; each has its own entry", f.where_, others.join("; ")));
    }
    if f.inferred {
        let repos = runner_repos(ix, &f.where_);
        let which = if repos.is_empty() { "the repos whose runs used it".to_string() } else { repos.join(", ") };
        return Some(format!(
            "{} was not scanned since the install: it may also hold it in the _work checkouts of {which} and in its tool cache (_work/_tool); scan it, then run br purge again to cover them",
            f.where_
        ));
    }
    None
}

/// A finding in a runner's workspace belongs to a repo too: say whose it is to fix, besides who cleans the machine.
fn workspace_words(ix: &Index, f: &Finding) -> Option<String> {
    if f.kind != FKind::Host || is_package_cache(f) || is_lockfile(f) {
        return None;
    }
    let repo = H::workspace_repo(ix, f)?;
    Some(match f.workspace_owner.as_ref() {
        Some(o) => format!("checkout of {repo}: its owner, {}, fixes the repo and rotates what its runs could read; this host's owner cleans the machine", H::owner_name(ix, o)),
        None => format!("checkout of {repo}: the repo has no owner br can name; this host's owner cleans the machine"),
    })
}

fn wider_note(f: &Finding) -> Option<String> {
    if f.kind != FKind::Host || is_lockfile(f) {
        return None;
    }
    host_del(f).wider
}

fn evidence_tgz(h: &str, loc: &str, win: bool) -> String {
    let base = leaf(loc);
    format!("evidence-{}-{}.{}", file_safe(h), if base.is_empty() { "root".to_string() } else { file_safe(base) }, if win { "zip" } else { "tgz" })
}

/// Does this finding's host command go over ssh from here? A Windows host is never driven with a POSIX ssh line.
fn via_ssh(f: &Finding, reach: Option<&str>) -> bool {
    reach == Some("ssh") && !win_host(f)
}

/// (preserve command, delete command) for a finding that has one. Every value is quoted for the shell.
/// `gh cache list --key` is a prefix match (https://cli.github.com/manual/gh_cache_list), so the saved list is filtered to
/// the exact key; `gh cache delete KEY` removes that exact key. `gh release download -p` is a glob, so glob characters
/// in the asset name are escaped.
pub fn destructive(f: &Finding, reach: Option<&str>) -> Option<(String, String)> {
    match f.kind {
        FKind::Cache => {
            let (r, key) = (shquote(&f.where_), &f.key);
            let name = format!("evidence-cache-{}.json", file_safe(key));
            let jq = format!("[.[] | select(.key == {})]", serde_json::to_string(key).unwrap_or_else(|_| "\"\"".into()));
            Some((
                format!(
                    "gh cache list -R {r} --key {} --limit 1000 --json id,key,ref,sizeInBytes,createdAt,lastAccessedAt --jq {} > {} && {}",
                    shquote(key),
                    shquote(&jq),
                    shquote(&name),
                    hash_cmd(&name)
                ),
                format!("gh cache delete {} -R {r}", shquote(key)),
            ))
        }
        FKind::Artifact => {
            let (r, i) = (shquote(&f.where_), f.id);
            let name = format!("evidence-artifact-{i}.zip");
            Some((format!("gh api repos/{r}/actions/artifacts/{i}/zip > {name} && {}", hash_cmd(&name)), format!("gh api -X DELETE repos/{r}/actions/artifacts/{i}")))
        }
        FKind::ReleaseAsset => {
            let r = shquote(&f.where_);
            let dir = format!("evidence-{}", file_safe(&f.tag));
            Some((
                format!("gh release download {} -p {} -R {r} -D {} && {}", shquote(&f.tag), shquote(&glob_escape(&f.asset)), shquote(&dir), hash_cmd(&format!("{dir}/{}", f.asset))),
                format!("gh release delete-asset {} {} -R {r}", shquote(&f.tag), shquote(&f.asset)),
            ))
        }
        FKind::Host => {
            if is_lockfile(f) {
                // a lockfile is a file in a checkout: nothing here removes it (the change is a version bump)
                return None;
            }
            let d = host_del(f);
            let (cmd, is_path) = (d.cmd.clone(), d.path);
            let (h, loc) = (&f.where_, &f.loc);
            // the evidence file is named for the package when only the package is saved
            let ev_loc = match (&d.keep, f.hit_pkgs.first()) {
                (Some(_), Some(p)) => format!("{}/{}", loc.trim_end_matches(['/', '\\']), shell::split_pkg(p).1),
                _ => loc.clone(),
            };
            if win_host(f) {
                let z = evidence_tgz(h, &ev_loc, true);
                let pre = if let Some(k) = d.keep.as_ref().filter(|k| !k.win_paths.is_empty()) {
                    format!(
                        "Compress-Archive -LiteralPath {} -DestinationPath {} -Force; Get-FileHash -Algorithm SHA256 -LiteralPath {}",
                        k.win_paths.iter().map(|p| psq(p)).collect::<Vec<_>>().join(","),
                        psq(&z),
                        psq(&z)
                    )
                } else if is_path {
                    format!("Compress-Archive -LiteralPath {} -DestinationPath {} -Force; Get-FileHash -Algorithm SHA256 -LiteralPath {}", psq(loc), psq(&z), psq(&z))
                } else {
                    format!("# {cmd} removes package-manager cache entries; there is no single path to archive")
                };
                return Some((pre, cmd));
            }
            let tgz = evidence_tgz(h, &ev_loc, false);
            let body = d.keep.as_ref().map(|k| k.tar.clone()).unwrap_or_else(|| format!("tar czf - {}", shpath(loc)));
            if via_ssh(f, reach) {
                // A path under another user's home is read and removed as that user, unless the ssh login already is them
                let login = HOST_LOGIN.with(|m| m.borrow().get(h).cloned());
                let user = host_user(loc).filter(|u| login.as_deref() != Some(u.as_str()));
                let as_user = |c: String| match &user {
                    // a chained command or a pipeline runs as that user as a whole, not only its first word
                    Some(u) if c.contains(" && ") || c.contains(" | ") => format!("sudo -u {} -H sh -c {}", shquote(u), shquote(&c)),
                    Some(u) => format!("sudo -u {} -H {c}", shquote(u)),
                    None => c,
                };
                Some((format!("ssh {} {} > {} && {}", shquote(h), shquote(&as_user(body)), shquote(&tgz), hash_cmd(&tgz)), format!("ssh {} {}", shquote(h), shquote(&as_user(cmd)))))
            } else if d.keep.is_some() {
                Some((format!("({body}) > {} && {}", shquote(&tgz), hash_cmd(&tgz)), cmd))
            } else {
                Some((format!("tar czf {} {} && {}", shquote(&tgz), shpath(loc), hash_cmd(&tgz)), cmd))
            }
        }
        _ => None,
    }
}

/// What the "preserve first" step saves, in words. For an Actions cache it is only metadata.
pub fn preserves(f: &Finding) -> Option<String> {
    match f.kind {
        FKind::Cache => Some("only the cache's metadata (key, ref, size, dates); the cached files are not downloaded".into()),
        FKind::Artifact => Some(format!("the artifact {} as a zip", f.id)),
        FKind::ReleaseAsset => Some(format!("the asset {} of release {}", f.asset, f.tag)),
        FKind::Host if is_lockfile(f) => None,
        FKind::Host => {
            let d = host_del(f);
            match d.keep {
                Some(k) => Some(k.what),
                None if d.path => Some(format!("everything under {}", f.loc)),
                None => Some("nothing: a cleaner empties package-manager cache entries and there is no single path to archive".into()),
            }
        }
        _ => None,
    }
}

/// A cache's metadata is not the cache. The second way to keep it is a workflow run that restores the key.
pub fn preserve_offer(f: &Finding) -> Option<String> {
    (f.kind == FKind::Cache).then(|| {
        format!(
            "to keep the contents too, before the delete: restore the key in a workflow run of {} (actions/cache/restore with key {}) and upload the restored path with actions/upload-artifact; the gh command above saves the metadata only",
            f.where_, f.key
        )
    })
}

fn preserve_lines(f: &Finding, indent: &str, reach: Option<&str>) -> Vec<String> {
    match destructive(f, reach) {
        None => vec![],
        Some((p, d)) => {
            let mut v = vec![];
            if let Some(w) = preserves(f) {
                v.push(format!("{indent}# preserves: {w}"));
            }
            v.push(format!("{indent}# preserve first: {p}"));
            if let Some(o) = preserve_offer(f) {
                v.push(format!("{indent}# {o}"));
            }
            v.push(format!("{indent}{d}"));
            v
        }
    }
}

/// A lockfile found on a host is a file in someone's checkout. The step is the version bump `br fix` gives for a
/// repo, run in that checkout. Lines (unindented): what the file pins, the bump, then the reminder not to delete it.
fn host_lock_steps(ix: &Index, f: &Finding, fixed: &Option<String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let decl = ix.v.hosts.get(&f.where_).and_then(|h| h.declared.iter().find(|d| d.loc == f.loc));
    for p in &f.hit_pkgs {
        let (eco, name, ver) = shell::split_pkg(p);
        let d = decl.and_then(|d| d.packages.iter().find(|x| &x.p == p));
        let syn = Finding {
            kind: FKind::Repo,
            where_: f.where_.clone(),
            ioc: f.ioc.clone(),
            eco: eco.into(),
            name: name.into(),
            version: ver.into(),
            file: f.loc.clone(),
            direct: d.is_none_or(|d| d.direct),
            dev: d.is_some_and(|d| d.dev),
            via: d.map(|d| d.via.clone()).unwrap_or_default(),
            ..Default::default()
        };
        let transitive = !syn.direct && !syn.via.is_empty();
        out.push(format!("pins {name} {ver}{}", if transitive { format!(" (through {})", syn.via.join(", ")) } else { String::new() }));
        if win_host(f) {
            out.push("move it to the fixed version in that checkout with its package manager, then reinstall".into());
            continue;
        }
        if want(&syn, fixed).is_none() {
            out.push(no_version_words(&syn, fixed));
            continue;
        }
        if transitive {
            let (file, entry, cmds, _) = override_plan(&syn, fixed);
            if let Some(e) = entry {
                out.push(format!("add to {file}: {e}"));
            }
            out.extend(cmds);
        } else {
            let (edit, cmds) = bump_cmds(&syn, fixed);
            if let Some(e) = edit {
                out.push(e);
            }
            out.extend(cmds);
        }
    }
    out.push("then reinstall in that checkout. The lockfile is changed, never deleted".into());
    out
}

// ---- one plan per repo, used by fix and notify ------------------------------------------------------------
fn lock_manager(file: &str) -> Option<&'static str> {
    Some(match basename(file) {
        "package-lock.json" | "npm-shrinkwrap.json" => "npm",
        "yarn.lock" => "yarn",
        "pnpm-lock.yaml" => "pnpm",
        "poetry.lock" => "poetry",
        "uv.lock" => "uv",
        "Pipfile.lock" => "pipenv",
        "Cargo.lock" => "cargo",
        "go.sum" | "go.mod" | "modules.txt" => "go",
        _ if crate::parse::lock::is_requirements(file) => "pip",
        _ => return None,
    })
}

/// The package manager of the lockfile this finding sits in (the repo's own manager, not npm by default).
pub fn manager(f: &Finding) -> &'static str {
    lock_manager(&f.file).unwrap_or_else(|| match eco_of(f).as_str() {
        "npm" => "npm",
        "pypi" => "pip",
        "cargo" => "cargo",
        "go" => "go",
        _ => "npm",
    })
}

/// Directory of the finding's lockfile inside the repo ("" = the repo root).
fn lock_dir(f: &Finding) -> &str {
    dir_of(&f.file)
}

/// The directory of the manifest that declares the dependency (the workspace member), else the lockfile's.
fn manifest_dir(f: &Finding) -> &str {
    f.manifest_path.as_deref().filter(|m| !m.is_empty()).map(dir_of).unwrap_or_else(|| lock_dir(f))
}

/// The workspace member below the lockfile's directory, relative to it. None when manifest and lockfile share a directory.
fn member_rel(f: &Finding) -> Option<String> {
    let (md, ld) = (manifest_dir(f), lock_dir(f));
    if md == ld {
        return None;
    }
    if ld.is_empty() {
        return Some(md.to_string());
    }
    md.strip_prefix(ld).and_then(|r| r.strip_prefix('/')).map(|r| r.to_string())
}

/// `(cd DIR && cmd)` for a path below the repo root; the bare command at the root.
fn indir(dir: &str, cmd: &str) -> String {
    if dir.is_empty() {
        cmd.to_string()
    } else {
        format!("(cd {} && {cmd})", shpath(dir))
    }
}

fn at(dir: &str, file: &str) -> String {
    if dir.is_empty() {
        file.to_string()
    } else {
        format!("{dir}/{file}")
    }
}

/// The command that rewrites only the lockfile, per manager. Sources: npm install --package-lock-only (npm docs);
/// pnpm install --lockfile-only (pnpm docs); yarn berry install --mode update-lockfile; poetry lock; uv lock;
/// cargo generate-lockfile.
pub fn lock_only_cmd(f: &Finding) -> String {
    let c = match manager(f) {
        "npm" => "npm install --package-lock-only",
        "yarn" => "yarn install   (Yarn 2 and later: yarn install --mode update-lockfile)",
        "pnpm" => "pnpm install --lockfile-only",
        "poetry" => "poetry lock",
        "uv" => "uv lock",
        "pipenv" => "pipenv lock",
        "cargo" => "cargo generate-lockfile",
        "go" => "go mod tidy",
        _ => return "pin the requirement to an exact version".into(),
    };
    indir(lock_dir(f), c)
}

/// (edit instruction or None, commands) that move a direct dependency to the fixed version, run in the lockfile's
/// directory with the repo's own manager and its workspace flag. Empty commands when there is no fixed release.
/// Syntax: npm install -w PATH (--workspace); pnpm --filter ./PATH add; yarn add run in the member directory;
/// poetry add --group dev; uv add --dev; pipenv install --dev; cargo update NAME@OLD --precise NEW (a bare -p is
/// ambiguous when two versions are locked); go get MODULE@vX.Y.Z then go mod tidy (the module path keeps its /vN).
pub fn bump_cmds(f: &Finding, fixed: &Option<String>) -> (Option<String>, Vec<String>) {
    let Some(v) = want(f, fixed) else { return (None, vec![]) };
    let (m, dev) = (manager(f), f.dev);
    let (ld, md) = (lock_dir(f), manifest_dir(f));
    let spec = shquote(&format!("{}@{v}", f.name));
    let pin = shquote(&format!("{}=={v}", f.name));
    let c = |s: String| (None, vec![s]);
    match m {
        "npm" => {
            let base = format!("npm install{} {spec}", if dev { " -D" } else { "" });
            match member_rel(f) {
                Some(r) => c(indir(ld, &format!("{base} -w {}", shpath(&r)))),
                None => c(indir(ld, &base)),
            }
        }
        "yarn" => c(indir(md, &format!("yarn add{} {spec}", if dev { " -D" } else { "" }))),
        "pnpm" => {
            let filt = member_rel(f).map(|r| format!(" --filter {}", shquote(&format!("./{r}")))).unwrap_or_default();
            c(indir(ld, &format!("pnpm{filt} add{} {spec}", if dev { " -D" } else { "" })))
        }
        "poetry" => c(indir(md, &format!("poetry add{} {pin}", if dev { " --group dev" } else { "" }))),
        "uv" => c(indir(md, &format!("uv add{} {pin}", if dev { " --dev" } else { "" }))),
        "pipenv" => c(indir(ld, &format!("pipenv install{} {pin}", if dev { " --dev" } else { "" }))),
        "pip" => {
            let wh = match (&f.manifest_path, f.manifest_line) {
                (mp, Some(l)) if l != 0 => format!("{} line {l}", ns(mp)),
                _ => {
                    if f.file.is_empty() {
                        "requirements.txt".to_string()
                    } else {
                        f.file.clone()
                    }
                }
            };
            let req = f.file.strip_prefix(&format!("{ld}/")).unwrap_or(&f.file).to_string();
            let req = if f.file.is_empty() { "requirements.txt".to_string() } else { req };
            (Some(format!("edit {wh}: {name}=={v}", name = f.name)), vec![indir(ld, &format!("pip install -r {}", shpath(&req)))])
        }
        "cargo" => c(indir(ld, &format!("cargo update {} --precise {}", shquote(&format!("{}@{}", f.name, f.version)), shquote(&v)))),
        "go" => (None, vec![indir(ld, &format!("go get {spec}")), indir(ld, "go mod tidy")]),
        _ => c(indir(ld, &format!("npm install {spec}"))),
    }
}

/// (file, entry text or None, commands, name of the entry to remove later) for a transitive dependency.
/// The entry sits where the manager reads it: npm overrides / yarn resolutions / pnpm.overrides in the ROOT package.json
/// (pnpm 10 also reads `overrides:` in pnpm-workspace.yaml), uv `override-dependencies` under [tool.uv] on its own lines.
pub fn override_plan(f: &Finding, fixed: &Option<String>) -> (String, Option<String>, Vec<String>, Option<&'static str>) {
    let (m, name) = (manager(f), &f.name);
    let (ld, md) = (lock_dir(f), manifest_dir(f));
    let Some(v) = want(f, fixed) else { return (at(ld, "package.json"), None, vec![], None) };
    let s = |x: &str| x.to_string();
    let pin = shquote(&format!("{name}=={v}"));
    match m {
        "npm" => (at(ld, "package.json"), Some(format!("\"overrides\": {{ \"{name}\": \"{v}\" }}")), vec![indir(ld, "npm install")], Some("overrides")),
        "yarn" => (at(ld, "package.json"), Some(format!("\"resolutions\": {{ \"{name}\": \"{v}\" }}")), vec![indir(ld, "yarn install")], Some("resolutions")),
        "pnpm" => (
            at(ld, "package.json"),
            Some(format!("\"pnpm\": {{ \"overrides\": {{ \"{name}\": \"{v}\" }} }}   (pnpm 10 and later: or under overrides: in pnpm-workspace.yaml)")),
            vec![indir(ld, "pnpm install")],
            Some("pnpm.overrides"),
        ),
        "poetry" => (
            at(md, "pyproject.toml"),
            Some(format!("{name}=={v} in the table the project uses: [project].dependencies (Poetry 2) or {name} = \"=={v}\" under [tool.poetry.dependencies] (Poetry 1)")),
            vec![indir(md, &format!("poetry add {pin}"))],
            Some("pin"),
        ),
        "uv" => (at(md, "pyproject.toml"), Some(format!("[tool.uv]\noverride-dependencies = [\"{name}=={v}\"]")), vec![indir(md, "uv lock")], Some("override-dependencies entry")),
        "pipenv" => (at(ld, "Pipfile"), Some(format!("{name} = \"=={v}\"")), vec![indir(ld, &format!("pipenv install {pin}"))], Some("pin")),
        "pip" => {
            let req = f.file.strip_prefix(&format!("{ld}/")).unwrap_or(&f.file).to_string();
            let req = if req.is_empty() { s("requirements.txt") } else { req };
            (at(ld, "constraints.txt"), Some(format!("{name}=={v}")), vec![indir(ld, &format!("pip install -r {} -c constraints.txt", shpath(&req)))], Some("constraints.txt line"))
        }
        "cargo" => (at(ld, "Cargo.lock"), None, vec![indir(ld, &format!("cargo update {} --precise {}", shquote(&format!("{name}@{}", f.version)), shquote(&v)))], None),
        "go" => (at(ld, "go.mod"), None, vec![indir(ld, &format!("go get {}", shquote(&format!("{name}@{v}")))), indir(ld, "go mod tidy")], None),
        _ => (at(ld, "package.json"), Some(format!("\"overrides\": {{ \"{name}\": \"{v}\" }}")), vec![indir(ld, "npm install")], Some("overrides")),
    }
}

/// Evidence that parent@fixed resolves child@fixed: a lockfile commit with that edge (any commit up to the clock).
pub fn bump_pulls(ix: &Index, parent: &str, child: &str, fixed: &Option<String>, only: Option<&[String]>) -> Option<(String, String)> {
    let fx = fixed.as_deref().unwrap_or("").trim_start_matches('v').to_string();
    let repos: Vec<String> = match only {
        Some(o) => {
            let mut v = o.to_vec();
            v.sort();
            v
        }
        None => ix.v.repos.keys().cloned().collect(),
    };
    for r in repos {
        let Some(rd) = ix.v.repos.get(&r) else { continue };
        let mut cs: Vec<&crate::view::Commit> = rd.commits.iter().collect();
        cs.sort_by(|a, b| a.at.cmp(&b.at));
        for c in cs {
            if c.at > ix.now {
                continue;
            }
            for p in c.packages.iter().flatten() {
                let (_, n, v) = parse_pkg(&p.p);
                if n != child || v.trim_start_matches('v') != fx || p.via.is_empty() {
                    continue;
                }
                let (_, pn, pv) = parse_pkg(p.via.last().unwrap());
                if pn == parent && pv.trim_start_matches('v') == fx {
                    return Some((r.clone(), c.sha.clone()));
                }
            }
        }
    }
    None
}

thread_local! {
    /// (parent, child) pairs the registry could not be asked about in this run, with the reason.
    static UNCHECKED: std::cell::RefCell<Vec<(String, String, String)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Does bumping `parent` to `fixed` also move `f`? From npm registry metadata (parent@fixed's dependencies), not from
/// lockfile edges, so no commit is cited. Under `BR_DEV_VIEW`, the lockfile edge is used.
/// A registry that cannot be reached is recorded in UNCHECKED and answers false (the override plan stays).
fn also_moves(ix: &Index, parent: &str, f: &Finding, fixed: &Option<String>) -> bool {
    if std::env::var_os("BR_DEV_VIEW").is_some() {
        return bump_pulls(ix, parent, &f.name, fixed, None).is_some();
    }
    if OFFLINE.with(|o| o.get()) {
        UNCHECKED.with(|u| {
            let mut u = u.borrow_mut();
            if !u.iter().any(|x| x.0 == parent && x.1 == f.name) {
                u.push((parent.to_string(), f.name.clone(), "--offline: the registry was not asked".to_string()));
            }
        });
        return false;
    }
    if eco_of(f) != "npm" {
        let why = match eco_of(f).as_str() {
            "pypi" => "br does not run the resolver offline; pip install --dry-run --report shows what a bump pulls",
            "cargo" => "br does not run the resolver offline; cargo tree -i shows what a bump pulls",
            "go" => "br does not run the resolver offline; go mod graph shows what a bump pulls",
            _ => "br has no resolver query for this ecosystem",
        };
        UNCHECKED.with(|u| {
            let mut u = u.borrow_mut();
            if !u.iter().any(|x| x.0 == parent && x.1 == f.name) {
                u.push((parent.to_string(), f.name.clone(), why.to_string()));
            }
        });
        return false;
    }
    let fx = fixed.as_deref().unwrap_or("");
    match crate::collect::npm::pulls(parent, &f.name, fx, &ix.now) {
        Ok(b) => b,
        Err(e) => {
            UNCHECKED.with(|u| {
                let mut u = u.borrow_mut();
                if !u.iter().any(|x| x.0 == parent && x.1 == f.name) {
                    u.push((parent.to_string(), f.name.clone(), format!("npm registry: {e}")));
                }
            });
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PK {
    Bump,
    Override,
    Lockfile,
}

#[derive(Debug, Clone)]
pub struct Plan<'a> {
    pub kind: PK,
    pub f: &'a Finding,
    pub also: Vec<&'a Finding>,
    pub after: Option<String>,
}

/// [(repo, plans)] from confirmed findings, repos sorted.
pub fn repo_plans<'a>(ix: &Index, fs: &Fs<'a>, fixed: &Option<String>) -> Vec<(String, Vec<Plan<'a>>)> {
    let rows: Vec<&'a Finding> = fs.iter().copied().filter(|f| f.kind == FKind::Repo && f.state != "removed" && f.rt.is_none()).collect();
    let mut repos: Vec<&str> = rows.iter().map(|f| f.where_.as_str()).collect();
    repos.sort();
    repos.dedup();
    let mut out = vec![];
    for repo in repos {
        let (mut rs, mut seen): (Vec<&'a Finding>, HashSet<String>) = (vec![], HashSet::new());
        for f in rows.iter().filter(|f| f.where_ == repo) {
            let k = f.p.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| f.name.clone());
            if seen.insert(k) {
                rs.push(f);
            }
        }
        let mut locked: Vec<&'a Finding> = rs.iter().copied().filter(|f| f.state != "install-only").collect();
        locked.sort_by_key(|f| f.via.len());
        let mut names: HashMap<&str, &Finding> = HashMap::new();
        for f in &locked {
            names.entry(f.name.as_str()).or_insert(f);
        }
        let mut plans: Vec<Plan<'a>> = vec![];
        let mut handled: HashMap<String, usize> = HashMap::new();
        for f in &locked {
            let anc: Vec<&String> = f.via.iter().filter(|n| names.contains_key(n.as_str()) && **n != f.name).collect();
            let parent = anc.last().map(|s| s.to_string());
            let pp = parent.as_ref().and_then(|p| handled.get(p)).copied();
            if let (false, Some(pi), Some(parent)) = (f.direct, pp, &parent) {
                if also_moves(ix, parent, f, fixed) {
                    plans[pi].also.push(f);
                    handled.insert(f.name.clone(), pi);
                    continue;
                }
                plans.push(Plan { kind: PK::Override, f, also: vec![], after: Some(parent.clone()) });
            } else {
                plans.push(Plan { kind: if f.direct { PK::Bump } else { PK::Override }, f, also: vec![], after: None });
            }
            handled.insert(f.name.clone(), plans.len() - 1);
        }
        for f in &rs {
            if f.state == "install-only" {
                plans.push(Plan { kind: PK::Lockfile, f, also: vec![], after: None });
            }
        }
        out.push((repo.to_string(), plans));
    }
    out
}

fn where_text(f: &Finding) -> String {
    match f.manifest_line {
        Some(l) if l != 0 => format!("{} line {l}", ns(&f.manifest_path)),
        _ => f.file.clone(),
    }
}

fn also_text(plan: &Plan, fixed: &Option<String>) -> String {
    if plan.also.is_empty() {
        return String::new();
    }
    let names: Vec<String> = plan.also.iter().map(|a| format!("{} {}", a.name, a.version)).collect();
    format!("; this also moves {} to {}", names.join(", "), fx_text(&want(plan.also[0], fixed)))
}

/// One line for a message to the owner (notify). The same decision fix prints in full.
fn plan_short(plan: &Plan, fixed: &Option<String>) -> String {
    let f = plan.f;
    let w = want(f, fixed);
    let fx = w.clone().unwrap_or_else(|| "a version without it".into());
    let arch = if f.archived { "; archived, unarchive first" } else { "" };
    if w.is_none() && plan.kind != PK::Lockfile {
        let why = match fix_of(f, fixed) {
            Fix::Unknown => "no fixed version is known to br; pass --to VERSION, or replace or remove it",
            _ => "no fixed release is published on this line; replace or remove it",
        };
        return format!("{}: {} {}: {why}{arch}", where_text(f), f.name, f.version);
    }
    match plan.kind {
        PK::Lockfile => format!("runs installed {} {} from a range with no lockfile; commit a lockfile or pin the range (br fix --repo {})", f.name, f.version, f.where_),
        PK::Bump => format!("{}: {} {} -> {fx}{arch}{}", where_text(f), f.name, f.version, also_text(plan, fixed)),
        PK::Override => {
            let (file, entry, cmds, _) = override_plan(f, fixed);
            let via = f.via.join(" > ");
            let why = match &plan.after {
                Some(a) => format!("{a} does not bring {} {fx} with it", f.name),
                None if via.is_empty() => "it is a transitive dependency; no direct dependency brings the fix with it".to_string(),
                None => format!("it comes in via {via}; bumping those alone does not fix it"),
            };
            let entry_t = match entry {
                Some(e) => format!("add {} to {file}", e.lines().collect::<Vec<_>>().join(" ")),
                None => format!("run {}", cmds.first().cloned().unwrap_or_default()),
            };
            format!("{}: {} {}: {entry_t} ({why}){arch}{}", f.file, f.name, f.version, also_text(plan, fixed))
        }
    }
}

// ---- fix ---------------------------------------------------------------------------------------------------
fn rotate_block(ix: &Index, res: &HuntResult, fs: &Fs) -> Vec<String> {
    // The one secrets table (query::secrets), the same rows hunt and notify read
    let sec = secret_uses(ix, &sub_result(res, fs));
    if sec.is_empty() {
        return vec![];
    }
    let mut out = vec![String::new(), format!("ROTATE SECRETS ({}): runs that installed the affected version could read these", sec.len())];
    if let Some(n) = crate::query::secrets::separate_note(&sec) {
        out.push(format!("  {n}"));
    }
    let w = sec.iter().map(|e| e.name.chars().count()).max().unwrap_or(0);
    let ws = sec.iter().map(|e| e.scope.chars().count()).max().unwrap_or(0);
    for u in &sec {
        let pad = " ".repeat(w - u.name.chars().count());
        let pads = " ".repeat(ws - u.scope.chars().count());
        // An org secret is owned by the org admins; the teams whose runs read it are "used by"
        let owners = if crate::query::secrets::is_org_scope(&u.scope) {
            u.owner_cell()
        } else if u.owners.is_empty() {
            "NO OWNER FOUND".to_string()
        } else {
            u.owners.join(", ")
        };
        // Where GitHub says the secret lives, so the person rotating it knows how far it reaches
        out.push(format!("  {}{pad}  {}{pads}  {} in {} (owner {owners})", u.name, u.scope, plural(u.runs, "run"), u.repos.join(", ")));
    }
    out
}

/// When a cleanup may run. fix and purge both ask this one function. A thing that a run on the unfixed code would
/// create again waits for the merge; a thing no run re-creates (an artifact, a release asset, a laptop's cache) goes now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    Now,
    AfterMerge,
}

/// Repos that still hold the affected version (present, not removed): a run on their code would put it back.
pub fn unfixed_repos(fs: &Fs) -> HashSet<String> {
    fs.iter().filter(|f| f.kind == FKind::Repo && f.state != "removed").map(|f| f.where_.clone()).collect()
}

/// `unfixed_repos`, but for a narrowed run (`--owner`, `--repo`) the question is still asked of every repo: a runner's cache is
/// filled again by a run in ANY repo that still holds the affected version, not only the ones in scope.
fn unfixed_everywhere(ix: &Index, q: &Query, fs: &Fs) -> HashSet<String> {
    let scoped = q.owner.as_ref().is_some_and(|o| !o.is_empty()) || q.repo.as_ref().is_some_and(|r| !r.is_empty());
    let mut set = unfixed_repos(fs);
    if scoped {
        let mut q2 = q.clone();
        q2.owner = None;
        q2.repo = None;
        q2.only = ["repos".to_string()].into();
        if let Ok(r) = H::hunt(ix, &q2) {
            set.extend(H::findings(&r).iter().filter(|f| f.kind == FKind::Repo && f.state != "removed").map(|f| f.where_.clone()));
        }
    }
    set
}

fn is_package_cache(f: &Finding) -> bool {
    f.inferred || matches!(f.item_kind.as_str(), "npm-cache" | "pnpm-store" | "yarn-cache" | "pip-cache" | "go-modcache")
}

/// The repos whose CI runs used this runner, from the runs the index holds (empty when no run names it).
pub fn runner_repos(ix: &Index, host: &str) -> Vec<String> {
    let mut v: Vec<String> = ix.runs_by_runner().get(&crate::query::index::runner_key(host)).map(|rs| rs.iter().map(|(r, _)| r.to_string()).collect()).unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

/// The repos that gate a runner's cleanup: those whose runs used it and that still hold the affected version. `None`
/// when no run names the runner, so br cannot narrow it and the whole scope gates it, as before.
pub fn runner_gate(ix: &Index, host: &str, unfixed: &HashSet<String>) -> Option<Vec<String>> {
    let used = runner_repos(ix, host);
    if used.is_empty() {
        return None;
    }
    Some(used.into_iter().filter(|r| unfixed.contains(r)).collect())
}

pub fn clean_when(ix: &Index, f: &Finding, unfixed: &HashSet<String>) -> When {
    match f.kind {
        FKind::Cache if unfixed.contains(&f.where_) => When::AfterMerge,
        FKind::Host if is_package_cache(f) && !unfixed.is_empty() && ix.host_def(&f.where_).and_then(|h| h.kind.as_deref()) == Some("runner") => match runner_gate(ix, &f.where_, unfixed) {
            Some(g) if g.is_empty() => When::Now,
            _ => When::AfterMerge,
        },
        FKind::Image => When::AfterMerge,
        _ => When::Now,
    }
}

/// Things that follow from fixing this repo: (clean up now, after the merge). Images, caches, artifacts and release assets
/// that hold the indicator, split by `clean_when`.
fn cleanups(ix: &Index, fs: &Fs, repo: &str, unfixed: &HashSet<String>) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let (mut now, mut after) = (vec![], vec![]);
    let mut seen = HashSet::new();
    for f in fs {
        if f.kind == FKind::Image && f.from_repo.as_deref() == Some(repo) {
            if seen.insert(f.digest.clone()) {
                let tags = if f.tags.is_empty() { short(&f.digest) } else { f.tags.join(", ") };
                after.push(vec![format!("rebuild {} ({tags}) from this repo, then delete the old digest {}", f.image, f.digest)]);
            }
        } else if matches!(f.kind, FKind::Cache | FKind::Artifact | FKind::ReleaseAsset) && f.where_ == repo {
            let what = match f.kind {
                FKind::Cache => format!("cache {}", f.key),
                FKind::Artifact => format!("artifact {}", f.name),
                _ => format!("release asset {} of {}", f.asset, f.tag),
            };
            let when = clean_when(ix, f, unfixed);
            let mut l = vec![match when {
                When::AfterMerge => format!("delete {what} (after the merge; one rebuilt from the old lockfile brings the package back):"),
                When::Now => format!("delete {what} (nothing builds it again from the old code, so it can go now):"),
            }];
            l.extend(preserve_lines(f, "", None));
            if when == When::Now {
                now.push(l)
            } else {
                after.push(l)
            }
        }
    }
    (now, after)
}

/// The range the parent asks of the child is not in the index (the lockfile records only what resolved), and the repo
/// `notes` field is free text no collector fills, so br does not quote a range it cannot see.
fn parent_range(_ix: &Index, _repo: &str, _f: &Finding) -> Option<String> {
    None
}

/// A git branch word: lower case, letters, digits, dots and single dashes (`@scope/pkg` becomes `scope-pkg`).
fn branch_word(s: &str) -> String {
    let mut o = String::new();
    for c in s.to_lowercase().chars() {
        let c = if c.is_ascii_alphanumeric() || c == '.' { c } else { '-' };
        if c == '-' && (o.is_empty() || o.ends_with('-')) {
            continue;
        }
        o.push(c);
    }
    o.trim_end_matches(['-', '.']).to_string()
}

/// The branch is named for what THIS repo changes: one package gives `br/fix-<pkg>-<version>`, several give
/// `br/fix-<advisory id>`. A name from another repo's package never appears.
fn branch_name(q: &Query, plans: &[Plan], fixed: &Option<String>) -> String {
    let mut changes: Vec<(String, String)> = vec![];
    for p in plans.iter().filter(|p| p.kind != PK::Lockfile) {
        if let Fix::To(v) = fix_of(p.f, fixed) {
            let c = (p.f.name.clone(), v);
            if !changes.contains(&c) {
                changes.push(c);
            }
        }
    }
    match changes.as_slice() {
        [(n, v)] => format!("br/fix-{}-{}", branch_word(n), branch_word(v.trim_start_matches('v'))),
        _ => {
            let id = q.adv.as_ref().map(|a| a.id.clone()).filter(|i| !i.is_empty()).unwrap_or_else(|| match changes.first() {
                Some((n, _)) if changes.len() > 1 => format!("{}-and-{}-more", n, changes.len() - 1),
                _ => "fix".into(),
            });
            format!("br/fix-{}", branch_word(&id))
        }
    }
}

/// The files each package manager's own commands change, defined once. (manifest files, in the directory of the
/// manifest that declares the dependency; lockfiles, in the directory of the lockfile). `pip` has neither: its
/// requirements file is the finding's own file.
fn staged_table(manager: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match manager {
        "npm" => (&["package.json"], &["package-lock.json"]),
        "yarn" => (&["package.json"], &["yarn.lock"]),
        "pnpm" => (&["package.json"], &["pnpm-lock.yaml"]),
        "poetry" => (&["pyproject.toml"], &["poetry.lock"]),
        "uv" => (&["pyproject.toml"], &["uv.lock"]),
        "pipenv" => (&["Pipfile"], &["Pipfile.lock"]),
        "cargo" => (&["Cargo.toml"], &["Cargo.lock"]),
        "go" => (&["go.mod"], &["go.sum"]),
        _ => (&[], &[]),
    }
}

/// Every file the plan's commands change, for `git add`: the manager's manifest and lockfile (from the table), the
/// finding's own lockfile and manifest, and any file the plan edits by hand (`extra`).
fn staged_files(f: &Finding, extra: &[String]) -> Vec<String> {
    let (mf, lk) = staged_table(manager(f));
    let (md, ld) = (manifest_dir(f), lock_dir(f));
    let mut files: Vec<String> = vec![];
    let mut push = |p: String| {
        if !p.is_empty() && !files.contains(&p) {
            files.push(p);
        }
    };
    for p in extra {
        push(p.clone());
    }
    if let Some(m) = &f.manifest_path {
        push(m.clone());
    }
    for n in mf {
        push(at(md, n));
    }
    push(f.file.clone());
    // the finding's own lockfile is already listed; a manager's other file (go.sum next to go.mod) is added from the table
    let own_lock = lock_manager(&f.file) == Some(manager(f)) && basename(&f.file) != "go.mod";
    if !own_lock {
        for n in lk {
            push(at(ld, n));
        }
    }
    files
}

fn add_cmd(f: &Finding, extra: &[String]) -> String {
    format!("git add {}", staged_files(f, extra).iter().map(|p| shpath(p)).collect::<Vec<_>>().join(" "))
}

/// `repo  (owner X)`: the first line of a repo's block in a plan. the owner is the one every screen shows (the CODEOWNERS
/// owner when GitHub resolves it, else the suggested owner, labelled), and a CODEOWNERS team GitHub does not resolve is said.
fn repo_head(ix: &Index, repo: &str, first: &Finding) -> String {
    let t = target_of(ix, first);
    let note = H::codeowners_note(ix, &first.owner).map(|n| format!("; {n}")).unwrap_or_default();
    match &t {
        Target::None(v) => format!("{repo}  (owner none: {v})"),
        _ => format!("{repo}  (owner {}{note})", H::owner_name(ix, &first.owner)),
    }
}

/// A repo with commits since it was indexed gets this line and nothing built on the old state.
fn moved_block(ix: &Index, a: &QueryArgs, q: &Query, repo: &str, at: &str, first: &Finding) -> Vec<String> {
    vec![
        repo_head(ix, repo, first),
        format!("  {}", H::moved_line(ix, repo, at)),
        "  nothing is planned for it until it is rescanned: the plan would be built on the old state, and it may already be fixed".into(),
        format!("  rescan and check:  {}", verify_cmd(a, q, repo)),
    ]
}

fn fix_repo(ix: &Index, a: &QueryArgs, q: &Query, fs: &Fs, repo: &str, plans: &[Plan], fixed: &Option<String>, unfixed: &HashSet<String>) -> Vec<String> {
    let first = plans[0].f;
    let mut out = vec![repo_head(ix, repo, first)];
    if first.archived {
        out.push("  archived: unarchive first (GitHub rejects pushes to an archived repo), then:".into());
    }
    let branch = branch_name(q, plans, fixed);
    if plans.iter().any(|p| p.kind != PK::Lockfile && want(p.f, fixed).is_some()) {
        out.push(format!("  in a checkout of {repo}, start a branch (the default branch is usually protected):  git switch -c {}", shquote(&branch)));
    }
    for pl in plans {
        let f = pl.f;
        let fx = fx_text(&want(f, fixed));
        if pl.kind != PK::Lockfile && want(f, fixed).is_none() {
            out.push(format!("  {}  {} {}: {}", where_text(f), f.name, f.version, no_version_words(f, fixed)));
            out.push("  replace it with another package, move to a line that has a fix, or pass --to VERSION if you know one".into());
            continue;
        }
        match pl.kind {
            PK::Lockfile => {
                out.push(format!("  no lockfile; run #{} on {} resolved {} {}", f.run_id.unwrap_or_default(), f.run_runner, f.name, f.version));
                out.push(if matches!(manager(f), "npm" | "yarn" | "pnpm" | "poetry" | "uv" | "pipenv" | "cargo") {
                    format!("  1. commit a lockfile ({}) or pin the range to an exact version", lock_only_cmd(f))
                } else {
                    "  1. commit a lockfile or pin the requirement to an exact version".into()
                });
                out.push(format!("  2. set {} to {fx}, so the next range install cannot pick the bad one again", f.name));
                continue;
            }
            PK::Bump => {
                let (edit, cmds) = bump_cmds(f, fixed);
                out.push(format!("  {}  {} {} -> {fx}", where_text(f), f.name, f.version));
                if let Some(e) = edit {
                    out.push(format!("  {e}"));
                }
                out.push("  commands:".into());
                out.extend(cmds.iter().map(|c| format!("    {c}")));
                out.push(format!("    {}", add_cmd(f, &[])));
                out.push(format!("    git commit -m {}", shquote(&format!("bump {} to {fx}", f.name))));
            }
            PK::Override => {
                let (file, entry, cmds, key) = override_plan(f, fixed);
                if f.via.is_empty() {
                    out.push(format!("  {}  {} {} is a transitive dependency", f.file, f.name, f.version));
                } else {
                    out.push(format!("  {}  {} {} comes in via {}", f.file, f.name, f.version, f.via.join(" > ")));
                }
                match &pl.after {
                    Some(a) => out.push(format!("  bumping {a} does not move {} to {fx}: pin it separately", f.name)),
                    None => {
                        let note = parent_range(ix, repo, f);
                        out.push(format!("  bumping the direct dependency alone does not fix this: {}", note.unwrap_or_else(|| "the parent still resolves the bad version".into())));
                    }
                }
                if let Some(e) = entry {
                    let mut ls = e.lines();
                    out.push(format!("  add to {file}:  {}", ls.next().unwrap_or("")));
                    out.extend(ls.map(|l| format!("      {l}")));
                }
                out.push(format!("  commands:{}", if cmds.len() == 1 { format!("  {}", cmds[0]) } else { String::new() }));
                if cmds.len() > 1 {
                    out.extend(cmds.iter().map(|c| format!("    {c}")));
                }
                match key {
                    Some(k) => {
                        let parent = f.via.last().cloned().unwrap_or_else(|| "the parent".into());
                        out.push(format!("  remove the {k} entry once {parent} releases a version that asks for {fx} or newer"));
                    }
                    None => out.push("  if a parent's version range excludes it, bump that parent instead".into()),
                }
                out.push(format!("    {}", add_cmd(f, std::slice::from_ref(&file))));
                out.push(format!("    git commit -m {}", shquote(&format!("pin {} to {fx}", f.name))));
                if let Some(parent) = &pl.after {
                    let why = UNCHECKED.with(|u| u.borrow().iter().find(|x| &x.0 == parent && x.1 == f.name).map(|x| x.2.clone()));
                    if let Some(why) = why {
                        out.push(format!("  could not check whether bumping {parent} also moves {} ({why}); override kept", f.name));
                    }
                }
            }
        }
        if !pl.also.is_empty() {
            let names: Vec<&str> = pl.also.iter().map(|a| a.name.as_str()).collect();
            let proof = if std::env::var_os("BR_DEV_VIEW").is_some() { bump_pulls(ix, &pl.f.name, &pl.also[0].name, fixed, Some(&[repo.to_string()])) } else { None };
            let seen = proof.map(|(r, s)| format!(" (seen in {r} at {s})")).unwrap_or_default();
            out.push(format!("  this also moves {} to {fx}{seen}; nothing more to change for it", names.join(", ")));
        }
    }
    let (now, after) = cleanups(ix, fs, repo, unfixed);
    for (title, items) in [("clean up now:", now), ("after you merge:", after)] {
        if !items.is_empty() {
            out.push(format!("  {title}"));
            for lines in items {
                out.push(format!("    - {}", lines[0]));
                out.extend(lines[1..].iter().map(|l| format!("      {l}")));
            }
        }
    }
    if plans.iter().any(|p| p.kind != PK::Lockfile && want(p.f, fixed).is_some()) {
        out.push("  open the pull request:  gh pr create --fill".into());
    }
    out.push(format!("  after you merge, check:  {}", verify_cmd(a, q, repo)));
    out
}

/// Earliest run in the index where this action ref resolved to a SHA that is not a bad one.
fn good_sha(ix: &Index, uses: &str, bad: &HashSet<String>, prefer: Option<&str>) -> (Option<String>, String) {
    let mut best: Option<((bool, String), String, String)> = None;
    let name = if uses.is_empty() { String::new() } else { I::split_use(uses).0 };
    for r in ix.names("repo") {
        for run in ix.runs(&r) {
            for (u, _via, sha) in H::run_resolved(run) {
                if (u == uses || uses.is_empty()) && !bad.contains(&sha) && (name.is_empty() || I::split_use(&u).0 == name) {
                    let key = (Some(r.as_str()) != prefer, run.at.clone());
                    if best.as_ref().is_none_or(|b| key < b.0) {
                        best = Some((key, sha, format!("{r}#{}", run.id)));
                    }
                }
            }
        }
    }
    match best {
        None => (None, String::new()),
        Some((key, sha, run)) => {
            let why = format!("seen resolving to {sha} in {run} on {}", fmt(&key.1));
            (Some(sha), why)
        }
    }
}

fn fix_actions(ix: &Index, q: &Query, fs: &Fs, to: &Option<String>) -> Vec<String> {
    let mut out = vec![];
    let bad: HashSet<String> = q.iocs.iter().filter(|i| i.kind == IocKind::ActionSha).map(|i| i.sha.clone()).collect();
    let to: Option<String> = to.clone().filter(|t| I::is_sha(t));
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let owner_or = |r: &str| H::owner_name(ix, &H::repo_owner_suggested(ix, r, None));
    for f in fs.iter().filter(|f| f.kind == FKind::WorkflowRef && !f.composite) {
        let (sha, why) = match &to {
            Some(t) => (Some(t.clone()), "you chose it with --to".to_string()),
            None => good_sha(ix, &f.uses, &bad, Some(&f.where_)),
        };
        let (name, _) = I::split_use(&f.uses);
        out.push(format!("{}  {}  (owner {})", f.where_, f.file, owner_or(&f.where_)));
        out.push(format!("  {}  ->  {name}@{}", f.uses, sha.clone().unwrap_or_else(|| "<40-hex SHA>".into())));
        match &sha {
            Some(s) => out.push(format!("  pin to {s} ({why})")),
            None => out.push("  no earlier run in the index shows a known good SHA; pass --to <40-hex>".into()),
        }
        out.push(format!("  change the line in {}, commit, and run the workflow again", f.file));
        out.push(String::new());
    }
    let mut shared: Vec<(&str, &Finding)> = vec![];
    for f in fs.iter().filter(|f| f.kind == FKind::WorkflowRef && f.composite) {
        match shared.iter_mut().find(|(k, _)| *k == f.where_.as_str()) {
            Some(e) => e.1 = f,
            None => shared.push((&f.where_, f)),
        }
    }
    let via_re = Regex::new(r"\(via ([^@)]+)").unwrap();
    for f in fs.iter().filter(|f| f.kind == FKind::CiRun && f.workflow.contains("(via ")) {
        let via = via_re.captures(&f.workflow).map(|m| m[1].to_string()).unwrap_or_default();
        let parts: Vec<&str> = via.split('/').collect();
        let repo = parts.iter().take(2).copied().collect::<Vec<_>>().join("/");
        let path = parts.iter().skip(2).copied().collect::<Vec<_>>().join("/");
        let owner = if ix.v.repos.contains_key(&repo) { Some(owner_or(&repo)) } else { None };
        if !seen.insert((f.where_.clone(), repo.clone())) {
            continue;
        }
        let comp = shared.iter().find(|(k, _)| *k == repo).map(|e| e.1);
        let file = comp.map(|c| c.file.clone()).unwrap_or_else(|| format!("{path}/action.yml"));
        let (sha, _why) = match &to {
            Some(t) => (Some(t.clone()), String::new()),
            None => good_sha(ix, comp.map(|c| c.uses.as_str()).unwrap_or(""), &bad, None),
        };
        let wf_file = run_workflow(ix, &f.where_, f.id).map(|(p, _)| p).unwrap_or_else(|| format!("(workflow \"{}\")", f.workflow.split(" (via ").next().unwrap_or("")));
        out.push(format!("{}  {wf_file}  (owner {})", f.where_, owner_or(&f.where_)));
        out.push(format!("  {}'s own workflow does not need to change: it reaches the action through {via}.", f.where_));
        out.push(format!("  the pin goes into {repo}, {file} (owner {}):", owner.unwrap_or_else(|| "unresolved".into())));
        let action = comp
            .map(|c| I::split_use(&c.uses).0)
            .filter(|n| !n.is_empty())
            .or_else(|| q.iocs.iter().find(|i| matches!(i.kind, IocKind::ActionRef | IocKind::ActionSha)).map(|i| i.name.clone()).filter(|n| !n.is_empty()))
            .unwrap_or_else(|| repo.clone());
        out.push(format!("    {action}@... -> {action}@{}", sha.unwrap_or_else(|| "<40-hex SHA>".into())));
        out.push(String::new());
    }
    out
}

/// Does the advisory behind this query say that installing it runs code?
pub fn risky_install(q: &Query) -> bool {
    q.adv.as_ref().is_some_and(|a| crate::query::risk::runs_at_install_parts(&a.id, &a.aliases, &a.title, &a.text))
}

/// A host finding that is a package-cache hit (the package was fetched there, whether or not a project uses it).
fn cache_hit(f: &Finding) -> bool {
    f.kind == FKind::Host && (f.note.contains("cache only") || is_package_cache(f))
}

/// The self-hosted runners and hosts where an install ran, with why: a package found in a checkout or an install
/// tree on the host, or a CI run on a self-hosted runner. A host's cache entry is listed by its own block.
fn install_ran_places(ix: &Index, fs: &Fs) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut add = |k: String, w: String| {
        let v = m.entry(k).or_default();
        if !v.contains(&w) {
            v.push(w);
        }
    };
    for f in fs {
        match f.kind {
            FKind::Host if !is_lockfile(f) && !is_malware(f) && !cache_hit(f) && !f.inferred && !f.hit_pkgs.is_empty() => {
                // The repo it belongs to, and who fixes that repo, as opposed to who owns the machine
                let repo = H::workspace_repo(ix, f)
                    .map(|r| match f.workspace_owner.as_ref() {
                        Some(o) => format!(" (checkout of {r}, whose owner {} fixes it)", H::owner_name(ix, o)),
                        None => format!(" (checkout of {r})"),
                    })
                    .unwrap_or_default();
                add(f.where_.clone(), format!("the package is installed in {}{repo}", f.loc));
            }
            FKind::CiRun if !f.runner.is_empty() && !crate::query::index::is_hosted_runner(&f.runner) => {
                add(f.runner.clone(), format!("the install ran here (CI run {}#{})", f.where_, f.id));
            }
            FKind::Host if !f.ci_installs.is_empty() => {
                for r in &f.ci_installs {
                    add(f.where_.clone(), format!("the install ran here (CI run {r})"));
                }
            }
            _ => {}
        }
    }
    m
}

/// The credentials line for a host where the install likely ran.
const HOME_ROTATE: &str = "rotate every credential reachable from that user's home directory (package-manager tokens, ssh keys, cloud logins, .env files)";

/// A sha256 that a known advisory lists gets the advisory's own command, so a hash never ends a plan at a dead end.
fn hash_advisory_offer(res: &HuntResult, verb: &str) -> Vec<String> {
    let hashes = res.q.iocs.iter().filter(|i| i.kind == IocKind::Sha256).count();
    res.hash_advisories
        .iter()
        .map(|(h, id, pk)| {
            let what = if hashes <= 1 { "this hash".to_string() } else { format!("sha256:{}...", h.trim_start_matches("sha256:").chars().take(12).collect::<String>()) };
            let names = if pk.is_empty() { String::new() } else { format!(", which names {}", pk.join(" ")) };
            format!("{what} is listed by {id}{names}; br {verb} --advisory {id} plans the package changes")
        })
        .collect()
}

/// A Dockerfile step that puts a file into an image from outside the build context: `ADD URL`, `COPY --from`, or a
/// `RUN` that downloads with curl or wget. Returns (the step as written, the fragment that finds its line).
pub fn fetch_step(cmd: &str) -> Option<(String, String)> {
    let mut c = cmd.trim();
    for p in ["/bin/sh -c #(nop)", "#(nop)"] {
        if let Some(r) = c.strip_prefix(p) {
            c = r.trim();
        }
    }
    let (word, rest) = match c.split_once(char::is_whitespace) {
        Some((w, r)) if matches!(w, "ADD" | "COPY" | "RUN") => (w, r.trim()),
        _ => ("RUN", c.strip_prefix("/bin/sh -c").unwrap_or(c).trim()),
    };
    let words: Vec<&str> = rest.split(|ch: char| ch.is_whitespace() || ch == ';' || ch == '&' || ch == '|').collect();
    let url = words.iter().find(|w| w.contains("://")).map(|w| w.trim_matches(|ch| ch == '"' || ch == '\'').to_string());
    let frag = match word {
        "ADD" => url?,
        "COPY" => words.iter().find(|w| w.starts_with("--from"))?.to_string(),
        _ => {
            if !words.iter().any(|w| *w == "curl" || *w == "wget") {
                return None;
            }
            url.unwrap_or_else(|| rest.chars().take(60).collect())
        }
    };
    Some((format!("{word} {rest}"), frag))
}

/// The Dockerfile steps that bring the bad file into an image. A lockfile bump does not remove these, so fix names
/// the step and how to find its line in the source repo.
fn dockerfile_steps(fs: &Fs) -> Vec<String> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut rows: Vec<String> = vec![];
    for f in fs.iter().filter(|f| f.kind == FKind::Image) {
        let Some((step, frag)) = f.layer_cmd.as_deref().and_then(fetch_step) else { continue };
        let repo = f.from_repo.clone().filter(|r| !r.is_empty());
        let who = repo.clone().unwrap_or_else(|| f.image.clone());
        if !seen.insert((who.clone(), step.clone())) {
            continue;
        }
        let what = if step.starts_with("COPY") {
            "change the stage it copies from (and the step that builds that stage) to a fixed version, or drop the copy"
        } else {
            "change it to a fixed version or drop it"
        };
        rows.push(format!("  {who}: layer {} of {} is `{}`: {what}, then rebuild", f.layer, f.image, step));
        let at = repo.map(|r| format!("in a checkout of {r}: ")).unwrap_or_default();
        rows.push(format!("    find the line to change, {at}git grep -n -F -e {} -- '*Dockerfile*'", shquote(&frag)));
    }
    if rows.is_empty() {
        return rows;
    }
    let mut out = vec!["DOCKERFILE STEPS THAT BRING IT IN (a version bump in a lockfile does not remove these)".to_string()];
    out.extend(rows);
    out
}

/// br fix: the whole stdout.
pub fn fix(ix: &Index, a: &QueryArgs, q: &Query, res: &HuntResult, to: &Option<String>) -> BrResult<String> {
    check_to(to)?;
    let fixed = plan_fixed(q, to);
    let every: Vec<&Finding> = all_findings(res).into_iter().filter(|f| !(f.kind == FKind::Repo && f.state == "removed")).collect();
    // A runtime version is moved, never bumped in a lockfile; its lines are their own block
    let rts: Vec<&Finding> = every.iter().copied().filter(|f| f.rt.is_some() && !f.possible).collect();
    let fs: Vec<&Finding> = every.into_iter().filter(|f| f.rt.is_none()).collect();
    let pkg_q = q.iocs.iter().any(|i| i.kind == IocKind::Pkg && i.rt.is_none());
    let act = q.iocs.iter().any(|i| matches!(i.kind, IocKind::ActionRef | IocKind::ActionSha));
    if pkg_q && !truthy(&fixed) && !has_pkg_fixes() && fs.iter().any(|f| f.kind == FKind::Repo) {
        return Err(BrError::new("no target version", Some("pass --to VERSION or --advisory ID")));
    }
    let unfixed = unfixed_repos(&fs);
    let moved_at = |repo: &str| res.moved.iter().find(|(r, _)| r == repo).map(|(_, at)| at.clone());
    let mut out: Vec<String> = hash_advisory_offer(res, "fix");
    if !out.is_empty() {
        out.push(String::new());
    }
    let lead = out.len();
    if pkg_q {
        // one block per repo, in name order: the repos with a version to change, and the repos whose fix is already in
        // but which still hold a cache, artifact, release asset or image
        let mut blocks: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let plans = repo_plans(ix, &fs, &fixed);
        for (repo, pls) in &plans {
            let b = match moved_at(repo) {
                Some(at) => moved_block(ix, a, q, repo, &at, pls[0].f),
                None => fix_repo(ix, a, q, &fs, repo, pls, &fixed, &unfixed),
            };
            blocks.insert(repo.clone(), b);
        }
        let mut left: BTreeMap<String, &Finding> = BTreeMap::new();
        for f in &fs {
            let r = match f.kind {
                FKind::Cache | FKind::Artifact | FKind::ReleaseAsset => Some(f.where_.clone()),
                FKind::Image => f.from_repo.clone().filter(|r| !r.is_empty()),
                // A fixed repo whose runs could read secrets still gets its line, so it never just disappears
                FKind::CiRun if !f.secrets.is_empty() => Some(f.where_.clone()),
                _ => None,
            };
            if let Some(r) = r.filter(|r| !blocks.contains_key(r)) {
                left.entry(r).or_insert(f);
            }
        }
        for (repo, first) in left {
            let b = match moved_at(&repo) {
                Some(at) => moved_block(ix, a, q, &repo, &at, first),
                None => {
                    let (now, after) = cleanups(ix, &fs, &repo, &unfixed);
                    let clean = !(now.is_empty() && after.is_empty());
                    let mut b = vec![
                        repo_head(ix, &repo, first),
                        if clean {
                            "  nothing to change in the code: the affected version is already gone from it. Still to clean:".to_string()
                        } else {
                            "  nothing to change: the affected version is already gone from it. Its CI runs could read secrets: see ROTATE SECRETS below".to_string()
                        },
                    ];
                    for lines in now.into_iter().chain(after) {
                        b.push(format!("    - {}", lines[0]));
                        b.extend(lines[1..].iter().map(|l| format!("      {l}")));
                    }
                    b.push(format!("  check:  {}", verify_cmd(a, q, &repo)));
                    b
                }
            };
            blocks.insert(repo, b);
        }
        for (_, b) in blocks {
            out.extend(b);
            out.push(String::new());
        }
        // The lockfiles a host scan read are checkouts too: the change is the same bump, never a delete
        let mut seen_locks = HashSet::new();
        let locks: Vec<&&Finding> = fs.iter().filter(|f| is_lockfile(f) && seen_locks.insert(place_id(f))).collect();
        if !locks.is_empty() {
            out.push("LOCKFILES ON HOSTS (a version bump in that checkout; the file is not deleted)".into());
            for f in locks {
                out.push(format!("  {}  {}", f.where_, f.loc));
                out.extend(host_lock_steps(ix, f, &fixed).into_iter().map(|l| format!("    {l}")));
            }
            out.push(String::new());
        }
    }
    if act {
        out.extend(fix_actions(ix, q, &fs, to));
    }
    let certs = fix_certs(&fs);
    let fs_nc: Vec<&Finding> = fs.iter().copied().filter(|f| f.cert.is_none()).collect();
    let rt_lines = fix_runtimes(&rts, res);
    if !rt_lines.is_empty() {
        while out.last().is_some_and(|l| l.is_empty()) {
            out.pop();
        }
        if out.len() > lead {
            out.push(String::new());
        }
        out.extend(rt_lines);
    }
    let steps = dockerfile_steps(&fs_nc);
    let no_bump = out.len() == lead;
    if !steps.is_empty() {
        while out.last().is_some_and(|l| l.is_empty()) {
            out.pop();
        }
        if out.len() > lead {
            out.push(String::new());
        }
        out.extend(steps);
    }
    if !certs.is_empty() {
        while out.last().is_some_and(|l| l.is_empty()) {
            out.pop();
        }
        if out.len() > lead {
            out.push(String::new());
        }
        out.extend(certs.iter().cloned());
    }
    if no_bump && certs.is_empty() {
        let others = fs.iter().filter(|f| f.kind != FKind::CiRun).count();
        let non_image = fs.iter().filter(|f| f.kind != FKind::CiRun && !(f.kind == FKind::Image && f.layer_cmd.as_deref().and_then(fetch_step).is_some())).count();
        if others > 0 && out.len() == lead {
            out.push(format!("No version to change in the indexed repos. {} to clean: run br purge.", plural(others, "other place")));
        } else if non_image > 0 {
            out.push(String::new());
            out.push(format!("No lockfile version to change. {} to clean: run br purge.", plural(others, "other place")));
        } else if fs.is_empty() && out.len() == lead {
            out.push("Nothing to fix in the indexed sources for this indicator.".into());
        }
    }
    let rot = rotate_block(ix, res, &fs);
    let nc = not_checked_text(res, "");
    while out.last().is_some_and(|l| l.is_empty()) {
        out.pop();
    }
    out.extend(rot);
    if risky_install(q) {
        // A host where a CI run installed it is in the block below, with the one verdict; this one is for caches nothing ran
        let ran_hosts: HashSet<String> = install_ran_places(ix, &fs).into_keys().collect();
        let hosts: Vec<&&Finding> = fs.iter().filter(|f| cache_hit(f) && !ran_hosts.contains(&f.where_)).collect();
        if !hosts.is_empty() {
            let mut names: Vec<String> = hosts.iter().map(|f| f.where_.clone()).collect();
            names.sort();
            names.dedup();
            out.push(String::new());
            out.push(format!("HOSTS WHERE THE INSTALL LIKELY RAN ({}): the advisory says installing it runs code, and a package cache holds it", names.len()));
            for n in names {
                out.push(format!("  {n}: isolate the machine from the network, keep a copy of the cache entry (br purge shows how), then {HOME_ROTATE}"));
            }
        }
        // A runner or host where an install ran is not only a laptop with a cache entry: a package in a checkout, or a
        // CI run on a self-hosted runner, ran the install script with that machine's credentials in reach
        let ran = install_ran_places(ix, &fs);
        if !ran.is_empty() {
            out.push(String::new());
            out.push(format!("RUNNERS AND HOSTS WHERE THE INSTALL RAN ({}): the advisory says installing it runs code", ran.len()));
            for (n, why) in ran {
                out.push(format!("  {n}: isolate the machine from the network; {}; rotate the credentials it held, and reimage the machine", why.join("; ")));
            }
        }
    }
    // An image whose build ran the file did not only carry it
    let mut built: Vec<String> = vec![];
    for f in fs.iter().filter(|f| f.kind == FKind::Image) {
        if let Some(n) = f.executed_in_layer {
            let tags = if f.tags.is_empty() { short(&f.digest) } else { f.tags.join(", ") };
            let l = format!(
                "  {} {}: layer {n} ran it during the build; rotate what the build could read (build secrets, registry and cloud tokens), then rebuild and delete the old digest",
                f.image, tags
            );
            if !built.contains(&l) {
                built.push(l);
            }
        }
    }
    if !built.is_empty() {
        out.push(String::new());
        out.push("IMAGES THAT RAN IT DURING THE BUILD".into());
        out.extend(built);
    }
    if let Some(n) = after_window_note(res) {
        out.push(String::new());
        out.push(n);
    }
    if !nc.is_empty() {
        out.push(String::new());
        out.extend(nc);
    }
    Ok(format!("{}\n", out.join("\n").trim_end()))
}

/// What to change for each runtime version found, by place: "php 8.3.20 → 8.3.36 in Dockerfile:1".
/// A version older than every listed fix has no fix on its line: the line says to move, never to bump.
fn fix_runtimes(rts: &[&Finding], res: &HuntResult) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let step = |r: &H::RtInfo, at: &str| -> String {
        if r.eol {
            match &r.move_to {
                Some(m) => format!("{} {} in {at}: no fixed release on this line: move to {m} or later", r.runtime, r.version),
                None => format!("{} {} in {at}: no fixed release on this line", r.runtime, r.version),
            }
        } else if let Some(l) = &r.line_fixed {
            format!("{} {} \u{2192} {l} in {at}", r.runtime, r.version)
        } else {
            format!("{} {} in {at}: affected, no fixed release is named", r.runtime, r.version)
        }
    };
    let mut repos: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut rest: Vec<String> = vec![];
    for f in rts {
        let Some(r) = &f.rt else { continue };
        match f.kind {
            FKind::Repo => {
                let at = match f.manifest_line {
                    Some(l) => format!("{}:{l}", f.file),
                    None => f.file.clone(),
                };
                let v = repos.entry(f.where_.clone()).or_default();
                let l = step(r, &at);
                if !v.contains(&l) {
                    v.push(l);
                }
            }
            FKind::Image => {
                let tag = f.tags.first().map(|t| format!(":{t}")).unwrap_or_default();
                let mut l = step(r, &format!("image {}{tag} ({})", f.image, r.seen_as));
                l.push_str("; rebuild it from a fixed base and delete the old digest");
                if !rest.contains(&l) {
                    rest.push(l);
                }
            }
            FKind::CiRun => {
                let l = step(r, &format!("CI run {} of {} ({})", f.id, f.where_, r.seen_as));
                if !rest.contains(&l) {
                    rest.push(l);
                }
            }
            _ => {
                let l = step(r, &format!("{} ({})", f.where_, r.seen_as));
                if !rest.contains(&l) {
                    rest.push(l);
                }
            }
        }
    }
    if !repos.is_empty() || !rest.is_empty() {
        out.push("RUNTIMES (move the version; nothing here is a lockfile)".into());
        for (repo, ls) in repos {
            out.push(format!("  {repo}"));
            out.extend(ls.into_iter().map(|l| format!("    {l}")));
        }
        out.extend(rest.into_iter().map(|l| format!("  {l}")));
    }
    if !res.floating.is_empty() {
        if !out.is_empty() {
            out.push(String::new());
        }
        out.push(format!("FLOATING (not counted as found; {})", crate::out::render::FLOATING_WORDS));
        for f in &res.floating {
            let at = if f.line > 0 { format!("{}:{}", f.file, f.line) } else { f.file.clone() };
            out.push(format!("  {} {at} {} ({})", f.repo, f.spec, f.seen_as));
        }
    }
    out
}

// ---- notify ------------------------------------------------------------------------------------------------
/// One bullet of a message. `key` is the repo (or host, or image source) it is about; lines with one key are printed under
/// it once. `lead` is the prefix a line carries when it stands alone.
struct Line {
    key: String,
    lead: Option<String>,
    body: String,
}

impl Line {
    fn full(&self) -> String {
        match &self.lead {
            Some(l) => format!("{l}: {}", self.body),
            None => self.body.clone(),
        }
    }
}

/// Lines grouped by repo. A repo with one line keeps it whole; a repo with several is named once.
fn render_lines(lines: &[Line]) -> Vec<String> {
    let mut groups: Vec<(&str, Vec<&Line>)> = vec![];
    for l in lines {
        match groups.iter_mut().find(|(k, _)| *k == l.key) {
            Some((_, v)) => v.push(l),
            None => groups.push((&l.key, vec![l])),
        }
    }
    let mut out = vec![];
    for (key, ls) in groups {
        if ls.len() == 1 {
            out.push(format!("  - {}", ls[0].full()));
        } else {
            out.push(format!("  - {key}:"));
            out.extend(ls.iter().map(|l| format!("      - {}", l.body)));
        }
    }
    out
}

/// What to do about a certificate in a trust store, by the kind of store. br changes nothing; these are the owner's steps.
pub fn cert_fix_text(f: &Finding, c: &CertHit) -> String {
    let old = |f: &Finding| if f.digest.is_empty() { String::new() } else { format!(", then delete the old digest {}", f.digest) };
    match f.kind {
        FKind::Image if c.deleted => format!("the running image is clean, but a layer that held it is still in the image's blobs and can be pulled by digest: delete the old digest {}", f.digest),
        FKind::Image => match c.store.as_str() {
            "certifi" => format!("upgrade certifi in the image (pip install --upgrade certifi), rebuild{}", old(f)),
            "java" => format!("remove it from the Java keystore in the image (keytool -delete -alias ALIAS -keystore {}), rebuild{}", c.file, old(f)),
            "system" => format!("rebuild on a base image with an updated ca-certificates, or remove the certificate in the Dockerfile, then rebuild{}", old(f)),
            _ => format!("stop copying {} into the image (or remove the certificate from it), rebuild{}", c.file, old(f)),
        },
        FKind::Host => match c.store.as_str() {
            "certifi" => "upgrade certifi on the machine (pip install --upgrade certifi)".to_string(),
            "java" => format!("remove it from the Java keystore (keytool -delete -alias ALIAS -keystore {})", c.file),
            "system" => "update the distro's ca-certificates package; delete any local copy under /usr/local/share/ca-certificates and run update-ca-certificates --fresh".to_string(),
            _ => format!("delete the certificate from {}", c.file),
        },
        _ => format!("delete the certificate from {} (a pull request that removes its block, or the whole file if it holds only this)", c.file),
    }
}

/// The fix block for certificates.
fn fix_certs(fs: &Fs) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut rows = vec![];
    for f in fs.iter().filter(|f| f.cert.is_some()) {
        let c = f.cert.as_ref().unwrap();
        let place = match f.kind {
            FKind::Image => format!("image {} {}", f.image, if f.tags.is_empty() { short(&f.digest) } else { f.tags.join(", ") }),
            FKind::Host => format!("host {}", f.where_),
            _ => format!("repo {}", f.where_),
        };
        let role = if c.root { "root" } else { "intermediate" };
        let fix = cert_fix_text(f, c);
        if !seen.insert((place.clone(), c.file.clone(), c.fp.clone(), fix.clone())) {
            continue;
        }
        rows.push(format!("  {place}: {} holds \"{}\" ({role})", c.file, c.subject));
        rows.push(format!("    {fix}"));
    }
    if rows.is_empty() {
        return rows;
    }
    let mut out = vec!["CERTIFICATES IN TRUST STORES (br changes nothing; each owner removes the certificate)".to_string()];
    out.extend(rows);
    out
}

fn line_for_finding(ix: &Index, f: &Finding, risky: bool, fixed: &Option<String>) -> Line {
    let repo_line = |body: String| Line { key: f.where_.clone(), lead: Some(f.where_.clone()), body };
    if let Some(c) = &f.cert {
        let role = if c.root { "root" } else { "intermediate" };
        let holds = format!("{} holds \"{}\" ({role}); {}", c.file, c.subject, cert_fix_text(f, c));
        let body = match f.kind {
            FKind::Image => format!("{} {}: {holds}", f.image, if f.tags.is_empty() { short(&f.digest) } else { f.tags.join(", ") }),
            _ => holds,
        };
        return match f.kind {
            FKind::Image => Line { key: f.from_repo.clone().filter(|r| !r.is_empty()).unwrap_or_else(|| f.image.clone()), lead: None, body },
            _ => repo_line(body),
        };
    }
    if let (Some(r), false) = (&f.rt, f.possible) {
        let words = fix_runtimes(&[f], &H::HuntResult::default());
        let one = words.get(1..).map(|v| v.iter().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && *l != f.where_).collect::<Vec<_>>().join("; ")).unwrap_or_default();
        let body = if one.is_empty() { crate::out::render::rt_fix_words(r) } else { one };
        return match f.kind {
            FKind::Repo => repo_line(body),
            FKind::Image => Line { key: f.from_repo.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| f.image.clone()), lead: None, body },
            _ => Line { key: f.where_.clone(), lead: None, body },
        };
    }
    match f.kind {
        FKind::CiRun => {
            let s = f.secrets.join(", ");
            Line {
                key: f.where_.clone(),
                lead: None,
                body: format!(
                    "{}#{} ran on {} at {}{}",
                    f.where_,
                    f.id,
                    f.runner,
                    fmt(&f.at),
                    if s.is_empty() { String::new() } else { format!(" and could read {s}; rotate {}", if f.secrets.len() == 1 { "it" } else { "them" }) }
                ),
            }
        }
        FKind::Cache | FKind::Artifact | FKind::ReleaseAsset => {
            let (pre, dele) = destructive(f, None).unwrap_or_default();
            let what = match f.kind {
                FKind::Cache => format!("cache {}", f.key),
                FKind::Artifact => format!("artifact {}", f.name),
                _ => format!("release {}", f.tag),
            };
            repo_line(format!("{what}: save the evidence ({}), then {dele}", pre.split(" && ").next().unwrap_or("")))
        }
        FKind::Image => Line {
            key: f.from_repo.clone().filter(|r| !r.is_empty()).unwrap_or_else(|| f.image.clone()),
            lead: None,
            body: {
                let tags = if f.tags.is_empty() { short(&f.digest) } else { f.tags.join(", ") };
                // A rebuild is from the fixed default branch, never from the bad commit
                let from = match f.from_repo.as_deref().filter(|r| !r.is_empty()) {
                    Some(r) => format!("rebuild from the fixed default branch of {r} once the fix is merged"),
                    None => "rebuild with the pipeline that builds it, once the fix is in".to_string(),
                };
                let step = f.layer_cmd.as_deref().and_then(fetch_step).map(|(st, _)| format!("; it came in through `{st}`, so change that Dockerfile step"));
                let ran =
                    f.executed_in_layer.map(|n| format!("; layer {n} ran it during the build, so rotate what the build could read (build secrets, registry and cloud tokens)")).unwrap_or_default();
                format!("{} {}: {from}{}{ran}, then delete the old digest {}", f.image, tags, step.unwrap_or_default(), f.digest)
            },
        },
        FKind::Host if is_lockfile(f) => {
            let steps = host_lock_steps(ix, f, fixed);
            repo_line(format!("{}: {}", f.loc, steps.join("; ")))
        }
        FKind::Host => {
            let (pre, dele) = destructive(f, None).unwrap_or_default();
            let mut base = if treat_as_malware(f, risky) {
                let why = if is_malware(f) {
                    String::new()
                } else if !f.ci_installs.is_empty() {
                    format!("the install ran here (CI run {}): ", f.ci_installs.join(", "))
                } else {
                    "the install likely ran here: ".to_string()
                };
                let reimage = if !f.ci_installs.is_empty() && !is_malware(f) { "; reimage the machine" } else { "" };
                format!("{}: {why}isolate the host from the network, preserve the file ({}), only then remove it ({dele}); {HOME_ROTATE}{reimage}", f.loc, pre.split(" && ").next().unwrap_or(""))
            } else {
                format!("{}: {dele} (first: {})", f.loc, pre.split(" && ").next().unwrap_or(""))
            };
            if !treat_as_malware(f, risky) {
                if f.note.contains("cache only") {
                    base += " (only in the cache; no project uses it)";
                } else if !f.ci_installs.is_empty() {
                    base += &format!(" (a CI run installed it here: {})", f.ci_installs.join(", "));
                }
            }
            if let Some(wn) = wider_note(f) {
                base += &format!(" ({wn})");
            }
            if let Some(l) = similar_label(f) {
                base = format!("{l}: {base}");
            }
            repo_line(base)
        }
        FKind::WorkflowRef => repo_line(match f.runs.parse::<usize>() {
            Err(_) => format!("{} uses {} ({}); possible: runs unknown, index {}", f.file, f.uses, f.ref_kind, fmt(&ix.i(&f.where_).unwrap_or_default())),
            Ok(n) => format!("{} uses {} ({}); {} in the window", f.file, f.uses, f.ref_kind, plural(n, "run")),
        }),
        FKind::Repo => repo_line(f.kind.name().to_string()),
    }
}

/// The line for the owner of the repo whose workspace holds the finding: the repo is theirs to fix and to rotate for;
/// the machine's cleanup is its own owner's.
fn workspace_line(ix: &Index, f: &Finding) -> Line {
    let repo = H::workspace_repo(ix, f).unwrap_or_else(|| f.where_.clone());
    let host_owner = owner_label(ix, f);
    let cleans = if host_owner == "NO OWNER FOUND" { format!("{} has no recorded owner", f.where_) } else { format!("{}'s owner, {host_owner}, cleans the machine", f.where_) };
    Line { key: repo.clone(), lead: Some(repo), body: format!("{} on the runner {} holds it; fix the repo and rotate what its runs could read ({cleans})", f.loc, f.where_) }
}

/// A similar file is not the sample itself, and a plan says so.
pub fn similar_label(f: &Finding) -> Option<String> {
    (f.kind == FKind::Host && f.match_ == "similar").then(|| match f.sim {
        Some(s) => format!("similar, not identical ({:.0}% like the sample)", s * 100.0),
        None => "similar, not identical".to_string(),
    })
}

/// A hash query also hunts the files that are similar to it, so a variant is not left behind. The similar hits join
/// the answer (labelled "similar, not identical"); an exact hit is never counted twice. A hash with no simhash adds none.
pub fn add_similar(ix: &Index, q: &Query, res: &mut HuntResult) {
    let mut have: HashSet<String> = res.findings.iter().map(|f| format!("{}\x01{}", f.where_, host_loc(f))).collect();
    // `--similar-related` already ran the similarity pass over the files that came with a hit; notify and purge plan for
    // those files too (labelled "similar, not identical", never counted)
    for f in res.similar.clone() {
        if f.kind == FKind::Host && !f.possible && !f.boilerplate && have.insert(format!("{}\x01{}", f.where_, host_loc(&f))) {
            res.findings.push(f);
        }
    }
    for ioc in q.iocs.iter().filter(|i| i.kind == IocKind::Sha256) {
        let Ok(spec) = crate::cmd::similar::similar_ioc(Some(ix), &ioc.text) else { continue };
        let Ok(sim) = crate::query::iocs::parse_ioc(&spec, None) else { continue };
        let mut q2 = q.clone();
        q2.iocs = vec![sim];
        q2.adv = None;
        q2.window = None;
        q2.now_only = false;
        let Ok(r) = H::hunt(ix, &q2) else { continue };
        for f in r.findings.into_iter().filter(|f| f.kind == FKind::Host && f.match_ == "similar" && !f.possible) {
            if !f.sha256.is_empty() && q.iocs.iter().any(|i| i.kind == IocKind::Sha256 && i.text.ends_with(f.sha256.trim_start_matches("sha256:"))) {
                continue;
            }
            if have.insert(format!("{}\x01{}", f.where_, host_loc(&f))) {
                res.findings.push(f);
            }
        }
    }
}

/// A hash, rule or similarity hit on a host is malware, not a stale package.
pub fn is_malware(f: &Finding) -> bool {
    f.kind == FKind::Host && (f.ioc.starts_with("sha256:") || f.ioc.starts_with("yara:") || f.ioc.starts_with("simhash:") || f.sim.is_some() || f.match_ == "rule" || f.match_ == "similar")
}

/// Act on it as on malware (isolate, preserve, then remove): a malware hit, or a package-cache hit of a version the
/// advisory says runs code at install time. The words come from the advisory, never from a package name.
fn treat_as_malware(f: &Finding, risky: bool) -> bool {
    is_malware(f) || (risky && (cache_hit(f) || !f.ci_installs.is_empty()))
}

/// Opening line of a message. "place" and "CI run" are counted apart.
fn intro(q: &Query, sub: &HuntResult, what: &str, rf: &str, fixed: &Option<String>, key: &Target, moved: &[(String, String)]) -> String {
    let fs = H::findings(sub);
    let risky = risky_install(q);
    let pkgs = fs.iter().any(|f| f.kind == FKind::Repo);
    // Only a repo that still has the bad version, and has not moved since it was indexed, is asked to move
    let live_pkgs = fs.iter().any(|f| f.kind == FKind::Repo && f.state != "removed" && !moved.iter().any(|(r, _)| *r == f.where_));
    let moved_pkgs = fs.iter().any(|f| f.kind == FKind::Repo && f.state != "removed" && moved.iter().any(|(r, _)| *r == f.where_));
    let cn = H::counts(sub);
    let (np, nr) = (cn.places, cn.ci_runs);
    // A person's message opens from the kind of place it is about; only a message about machines says "your machine"
    let only_hosts = !fs.is_empty() && fs.iter().all(|f| matches!(f.kind, FKind::Host | FKind::CiRun));
    let person = matches!(key, Target::Person(_));
    // A runtime version is moved to a fixed release, never removed, and nothing here ran from an install
    let rt_only = !fs.is_empty() && fs.iter().all(|f| f.rt.is_some());
    if person && only_hosts && rt_only {
        return format!("Hi, this is on your machine: {what}{rf}. Please move it to a fixed release as listed below.");
    }
    if person && only_hosts {
        if let Some(loc) = fs.iter().find(|f| f.kind == FKind::Host) {
            if let Some(w) = ci_ran_words(loc, risky).filter(|_| risky) {
                return format!(
                    "Hi, CI ran the install on {}: {what}{rf}. The advisory says it runs code when it is installed, so it ran there with that machine's credentials in reach. {w}.",
                    loc.where_
                );
            }
            if loc.note.contains("cache only") {
                let label = cache_label(cache_kind(&loc.loc, &loc.item_kind));
                if risky {
                    return format!(
                        "Hi, this is in your {label} on {}: {what}{rf}. The advisory says it runs code when it is installed, and a cache entry means something installed it on this machine, so the install likely ran. Do not just clear the cache: disconnect the machine from the network, keep a copy of the cache entry, then clear it with the command listed below, and {HOME_ROTATE}.",
                        loc.where_
                    );
                }
                return format!("Hi, this is in your {label} on {} only, and no project uses it: {what}{rf}. One command clears it, listed below.", loc.where_);
            }
        }
        if fs.iter().any(|f| treat_as_malware(f, risky)) {
            return format!(
                "Hi, this is on your machine: {what}{rf}. It is malware, so do not just delete it: disconnect the machine from the network, keep a copy of the file, then remove it as listed below."
            );
        }
        return format!("Hi, this is on your machine: {what}{rf}. Please remove it as listed below.");
    }
    let greeting = if person { "Hi," } else { "Hi team," };
    if !fs.is_empty() && fs.iter().all(|f| f.cert.is_some()) {
        return format!("{greeting} a certificate br was asked about is in trust stores you own: {what}{rf}. Please remove it as listed below (br changes nothing).");
    }
    let mut base = if np > 0 {
        let places = if person { kind_phrase(&fs) } else { plural(np, "place") };
        let mut b = format!("{greeting} this shows up in {places} you own: {what}{rf}.");
        if nr > 0 {
            b += &format!(" {} installed it.", plural(nr, "CI run"));
        }
        b
    } else {
        format!("{greeting} {} of repos you own installed this: {what}{rf}.", plural(nr, "CI run"))
    };
    if fs.iter().any(|f| treat_as_malware(f, risky)) {
        base += " This is malware: isolate the affected hosts and preserve the files before you remove anything.";
    }
    if rt_only {
        base += " Please move each runtime to a fixed release (listed below), then rebuild the images and re-run CI. Floating tags and specs depend on when they are built or run, so they pick up the fix only after a rebuild.";
        return base;
    }
    let versions: Vec<String> = {
        let mut v: Vec<String> = fs.iter().filter(|f| f.kind == FKind::Repo && f.state != "removed").filter_map(|f| want(f, fixed)).collect();
        v.sort();
        v.dedup();
        v
    };
    if live_pkgs && versions.len() == 1 {
        base += &format!(" Please move to {} and run CI again.", versions[0]);
    } else if live_pkgs && versions.len() > 1 {
        base += " Please move each package to its fixed version (listed below) and run CI again.";
    } else if live_pkgs && truthy(fixed) {
        base += &format!(" Please move to {} and run CI again.", fixed.clone().unwrap());
    } else if pkgs && !live_pkgs && moved_pkgs {
        base += " The repo has new commits since it was indexed: rescan it before changing anything, it may already be fixed.";
    } else if pkgs && !live_pkgs && nr > 0 {
        base += " The repos no longer have it; please rotate what those runs could read.";
    } else if q.iocs.first().is_some_and(|i| matches!(i.kind, IocKind::ActionRef | IocKind::ActionSha)) {
        base += " Please pin the action to a full commit SHA and rotate what the affected runs could read.";
    } else if np == 0 && nr > 0 {
        base += " Please rotate what those runs could read.";
    }
    base
}

/// The kinds of place a message is about, counted the way a reader says them: "1 repo", "2 images and 1 machine".
fn kind_phrase(fs: &[&Finding]) -> String {
    let mut seen: BTreeMap<usize, (&str, &str, HashSet<String>)> = BTreeMap::new();
    for f in fs {
        let (rank, one, many, key) = match f.kind {
            FKind::CiRun => continue,
            FKind::Repo | FKind::WorkflowRef => (0, "repo", "repos", f.where_.clone()),
            FKind::Image => (1, "image", "images", f.digest.clone()),
            FKind::Host => (2, "machine", "machines", f.where_.clone()),
            FKind::Cache => (3, "cache", "caches", format!("{}\x01{}", f.where_, f.key)),
            FKind::Artifact => (4, "build artifact", "build artifacts", format!("{}\x01{}", f.where_, f.id)),
            FKind::ReleaseAsset => (5, "release asset", "release assets", format!("{}\x01{}\x01{}", f.where_, f.tag, f.asset)),
        };
        seen.entry(rank).or_insert((one, many, HashSet::new())).2.insert(key);
    }
    let parts: Vec<String> = seen.values().map(|(one, many, set)| crate::query::util::plural_with(set.len(), one, Some(many))).collect();
    if parts.is_empty() {
        "places".to_string()
    } else {
        crate::query::util::join_and(&parts)
    }
}

struct Msg<'a> {
    head: String,
    jira: Option<String>,
    body: String,
    lines: Vec<Line>,
    secrets: Vec<String>,
    possible: Vec<&'a Finding>,
    n: usize,
    places: usize,
    /// The indicators found in this team's own places
    inds: Vec<String>,
}

/// Is a message addressed to `key` inside an `--owner` scope?
fn target_in_scope(ix: &Index, rs: &crate::query::index::OwnerSpec, key: &Target) -> bool {
    match key {
        Target::Team(t) | Target::Unresolved(t) => rs.teams.contains(t),
        Target::Person(p) => {
            if rs.is_team {
                ix.person_team_ids(p).iter().any(|t| rs.teams.contains(t))
            } else {
                rs.people.iter().any(|x| x.eq_ignore_ascii_case(p))
            }
        }
        Target::None(_) => false,
    }
}

/// The distinct indicators behind a set of findings, in the order the query named them.
fn indicators_of(q: &Query, fs: &[&Finding]) -> Vec<String> {
    let mut have: HashSet<&str> = HashSet::new();
    for f in fs {
        have.insert(f.ioc.as_str());
        have.extend(f.iocs.iter().map(|s| s.as_str()));
    }
    let mut out: Vec<String> = q.iocs.iter().filter(|i| have.contains(i.text.as_str())).map(|i| i.text.clone()).collect();
    for h in have {
        if !h.is_empty() && !out.iter().any(|o| o == h) {
            out.push(h.to_string());
        }
    }
    out
}

/// br notify with `--to`: the fixed version is computed by the same function fix uses.
pub fn notify_to(ix: &Index, q: &Query, res: &HuntResult, fm: &str, to: &Option<String>) -> BrResult<String> {
    check_to(to)?;
    let fixed = plan_fixed(q, to);
    Ok(notify_inner(ix, q, res, fm, &fixed))
}

/// br notify (and hunt --format jira): the whole stdout.
pub fn notify(ix: &Index, q: &Query, res: &HuntResult, fm: &str, fixed: &Option<String>) -> String {
    set_plan(q, &None);
    notify_inner(ix, q, res, fm, fixed)
}

/// Read the teams `br teams set` knows about, for teams GitHub does not resolve.
pub fn load_team_routes(ctx: &Ctx) {
    let cfg = crate::collect::config::teams(ctx);
    TEAMS_CFG.with(|c| *c.borrow_mut() = cfg.into_iter().map(|(k, v)| (k, (v.slack, v.jira))).collect());
    let hosts = crate::collect::config::hosts(ctx);
    HOST_LOGIN.with(|m| *m.borrow_mut() = hosts.into_iter().filter_map(|(k, v)| v.target.and_then(|t| t.split_once('@').map(|(u, _)| (k, u.to_string())))).collect());
}

fn notify_inner(ix: &Index, q: &Query, res: &HuntResult, fm: &str, fixed: &Option<String>) -> String {
    let fs = all_findings(res);
    let risky = risky_install(q);
    // Where each secret lives, from the one secrets table; a name not in it is shown without a scope
    let scope_of: BTreeMap<String, String> = secret_uses(ix, res).into_iter().map(|u| (u.name, u.scope)).collect();
    let scoped = |n: &str| match scope_of.get(n) {
        Some(sc) if !sc.is_empty() => format!("{n} ({sc})"),
        _ => n.to_string(),
    };
    // An org secret is owned by the org admins, not by the team whose runs read it
    let uses = secret_uses(ix, res);
    let org_uses: Vec<&crate::query::secrets::SecretUse> = uses.iter().filter(|u| crate::query::secrets::is_org_scope(&u.scope)).collect();
    let org_names: HashSet<&str> = org_uses.iter().map(|u| u.name.as_str()).collect();
    let admin_words = org_uses.first().map(|u| u.owner_label.trim_start_matches("org admins ").trim_matches(|c| c == '(' || c == ')').to_string()).unwrap_or_default();
    let rs = crate::query::hunt::owner_spec(ix, q).ok().flatten();
    let admin_in_scope = match &rs {
        None => true,
        Some(r) => org_uses.iter().any(|u| u.admins.iter().any(|a| r.people.iter().any(|x| x.eq_ignore_ascii_case(a)))),
    };
    let plans = repo_plans(ix, &fs, fixed);
    let mut plan_of: HashMap<*const Finding, Option<&Plan>> = HashMap::new();
    for (_, pls) in &plans {
        for p in pls {
            plan_of.insert(p.f as *const Finding, Some(p));
            for a in &p.also {
                plan_of.insert(*a as *const Finding, None);
            }
        }
    }
    let mut groups: BTreeMap<Target, Vec<&Finding>> = BTreeMap::new();
    let mut orphans: Vec<(&Finding, String)> = vec![];
    // A finding in a runner's workspace (or a package a repo's run installed) also goes to that repo's owner, who fixes
    // the repo and rotates what its runs could read; the runner's owner keeps the cleanup of the machine
    let mut ws_role: std::collections::BTreeSet<(usize, Target)> = Default::default();
    for f in &fs {
        if let Some(wt) = workspace_target(ix, f) {
            if wt != target_of(ix, f) {
                ws_role.insert((*f as *const Finding as usize, wt.clone()));
                groups.entry(wt).or_default().push(f);
            }
        }
        let t = target_of(ix, f);
        if f.kind == FKind::Repo && f.state == "removed" {
            if !matches!(t, Target::None(_)) {
                groups.entry(t).or_default().push(f);
            }
            continue;
        }
        match t {
            Target::None(reason) => orphans.push((f, reason)),
            t => groups.entry(t).or_default().push(f),
        }
    }
    // Under --owner a message addressed to someone else is not drafted; one line says it exists
    let mut outside: Vec<(Target, Vec<&Finding>)> = vec![];
    if let Some(rs) = &rs {
        let keys: Vec<Target> = groups.keys().cloned().collect();
        for k in keys {
            if !target_in_scope(ix, rs, &k) {
                if let Some(v) = groups.remove(&k) {
                    outside.push((k, v));
                }
            }
        }
        if !orphans.is_empty() {
            outside.push((Target::None("no owner found".into()), orphans.iter().map(|(f, _)| *f).collect()));
            orphans.clear();
        }
    }
    let mut msgs: Vec<Msg> = vec![];
    for (key, gf) in &groups {
        let (mut head, jira) = header_for(ix, key);
        // A person br only suggests (archiver, last committer, org admin) is told so, and may pass it on
        let whys: Vec<Option<String>> = gf
            .iter()
            .map(|f| if ws_role.contains(&(*f as *const Finding as usize, key.clone())) { f.workspace_owner.as_ref().and_then(|o| o.suggested.clone()) } else { f.owner.suggested.clone() })
            .collect();
        if matches!(key, Target::Person(_)) && !whys.is_empty() && whys.iter().all(|w| w.is_some()) {
            let mut u: Vec<String> = whys.into_iter().flatten().collect();
            u.sort();
            u.dedup();
            let co = gf.iter().find_map(|f| H::codeowners_note(ix, &f.owner)).unwrap_or_else(|| "CODEOWNERS names no one br can resolve".to_string());
            head += &format!(" (suggested owner: {}; {co}, so confirm or pass it on)", u.join("; "));
        }
        let sub = sub_result(res, gf);
        let inds = indicators_of(q, gf);
        let what = match &q.adv {
            Some(a) if !a.title.trim().is_empty() => a.title.clone(),
            Some(_) | None if inds.is_empty() => q.iocs.iter().map(|i| i.text.clone()).collect::<Vec<_>>().join(", "),
            Some(_) | None => inds.join(", "),
        };
        let mut rf = match &q.adv {
            Some(a) => format!(" ({}", a.id),
            None => String::new(),
        };
        if q.adv.is_some() {
            if inds.len() > 1 && inds.len() < q.iocs.len() {
                rf += &format!("; yours: {}", inds.join(", "));
            }
            rf += ")";
        }
        let mut lines: Vec<Line> = vec![];
        let mut seen_places = HashSet::new();
        let mut removed: Vec<(String, String, Vec<String>)> = vec![];
        let mut told_suggested: HashSet<String> = HashSet::new();
        for f in gf {
            if f.kind != FKind::Repo && !seen_places.insert(place_id(f)) {
                continue;
            }
            // A repo that is theirs only by suggestion says so once, whatever else the message holds
            let ws = ws_role.contains(&(*f as *const Finding as usize, key.clone()));
            let why = if ws { f.workspace_owner.as_ref().and_then(|o| o.suggested.clone()) } else { f.owner.suggested.clone() };
            if let (Some(why), Target::Person(_)) = (why, key) {
                let repo = if ws { H::workspace_repo(ix, f) } else { repo_key(f) };
                if let Some(repo) = repo.filter(|r| told_suggested.insert(r.clone())) {
                    lines.push(Line {
                        key: repo.clone(),
                        lead: Some(repo),
                        body: format!(
                            "you are the suggested owner ({why}): {}; confirm it is yours, or pass it on",
                            H::codeowners_note(ix, &f.owner).unwrap_or_else(|| "CODEOWNERS names no one br can resolve".to_string())
                        ),
                    });
                }
            }
            if f.cert.is_some() {
                lines.push(line_for_finding(ix, f, risky, fixed));
                continue;
            }
            if f.kind == FKind::Repo {
                if f.state == "removed" {
                    let at = fmt(f.removed_at.as_deref().unwrap_or(""));
                    let pkg = format!("{} {}", f.name, f.version);
                    match removed.iter_mut().find(|(r, t, _)| *r == f.where_ && *t == at) {
                        Some((_, _, v)) => v.push(pkg),
                        None => {
                            removed.push((f.where_.clone(), at, vec![pkg]));
                            // placeholder keeps the line where the first removed package stood
                            lines.push(Line { key: f.where_.clone(), lead: Some(f.where_.clone()), body: format!("\x00removed{}", removed.len() - 1) });
                        }
                    }
                    continue;
                }
                if let Some((_, at)) = res.moved.iter().find(|(r, _)| *r == f.where_) {
                    if f.rt.is_some() || plan_of.get(&(*f as *const Finding)).is_some_and(|p| p.is_some()) {
                        lines.push(Line {
                            key: f.where_.clone(),
                            lead: Some(f.where_.clone()),
                            body: format!("moved since indexed (new commits {}); it may already be on the fixed version: br scan --repo {} before acting", fmt(at), f.where_),
                        });
                    }
                    continue;
                }
                match plan_of.get(&(*f as *const Finding)) {
                    Some(Some(p)) => lines.push(Line { key: f.where_.clone(), lead: Some(f.where_.clone()), body: plan_short(p, fixed) }),
                    _ if f.rt.is_some() => lines.push(line_for_finding(ix, f, risky, fixed)),
                    _ => continue,
                }
            } else {
                if ws_role.contains(&(*f as *const Finding as usize, key.clone())) {
                    lines.push(workspace_line(ix, f));
                } else {
                    lines.push(line_for_finding(ix, f, risky, fixed));
                }
            }
        }
        // One "nothing to change" line per repo and removal time, however many packages it had
        for l in lines.iter_mut() {
            if let Some(i) = l.body.strip_prefix("\x00removed").and_then(|n| n.parse::<usize>().ok()) {
                let (_, at, pk) = &removed[i];
                l.body = format!("had {} until {at}; nothing to change", pk.join(", "));
            }
        }
        let cn = H::counts(&sub);
        msgs.push(Msg {
            head,
            jira,
            body: intro(q, &sub, &what, &rf, fixed, key, &res.moved),
            lines,
            secrets: secret_uses(ix, &sub).into_iter().map(|u| u.name).collect(),
            possible: gf.iter().copied().filter(|f| f.kind == FKind::WorkflowRef && f.runs.parse::<usize>().is_err()).collect(),
            n: if cn.places > 0 { cn.places } else { cn.ci_runs },
            places: cn.places,
            inds,
        });
    }
    let given: Vec<&String> = msgs.iter().flat_map(|m| m.secrets.iter()).collect();
    let mut orphan_secrets: Vec<String> = vec![];
    for (f, _) in &orphans {
        for s in &f.secrets {
            if !given.contains(&s) && !orphan_secrets.contains(s) {
                orphan_secrets.push(s.clone());
            }
        }
    }
    if rs.is_none() {
        for s in secret_uses(ix, res).into_iter().map(|u| u.name) {
            if !given.contains(&&s) && !orphan_secrets.contains(&s) {
                orphan_secrets.push(s);
            }
        }
    }
    let poss = H::possible(res);
    let scope_word = q.owner.clone().filter(|o| !o.is_empty());
    let outside_lines = |ix: &Index| -> Vec<String> {
        if outside.is_empty() {
            return vec![];
        }
        let mut o = vec![format!("NOT DRAFTED, outside --owner {}: br notify without --owner writes these", scope_word.clone().unwrap_or_default())];
        for (k, v) in &outside {
            let c = H::counts(&sub_result(res, v));
            let n = if c.places > 0 { plural(c.places, "place") } else { plural(c.ci_runs, "CI run") };
            let who = match k {
                Target::None(_) => "no owner found".to_string(),
                k => header_for(ix, k).0.trim_start_matches("To ").to_string(),
            };
            o.push(format!("  - {who}: {n}"));
        }
        o
    };
    if fm == "json" {
        let doc = J::obj(vec![
            (
                "messages",
                J::Arr(
                    msgs.iter()
                        .map(|m| {
                            J::obj(vec![
                                ("to", J::s(&m.head)),
                                ("text", J::s(&m.body)),
                                ("indicators", J::strs(&m.inds)),
                                ("items", J::Arr(m.lines.iter().map(|l| J::s(l.full())).collect())),
                                ("secrets_to_rotate", J::strs(&m.secrets.iter().filter(|n| !org_names.contains(n.as_str())).cloned().collect::<Vec<_>>())),
                                ("org_secrets", J::strs(&m.secrets.iter().filter(|n| org_names.contains(n.as_str())).cloned().collect::<Vec<_>>())),
                                ("secrets", J::Arr(m.secrets.iter().map(|n| J::obj(vec![("name", J::s(n)), ("scope", J::s(scope_of.get(n).cloned().unwrap_or_default()))])).collect())),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "org_admins",
                J::Arr(
                    org_uses
                        .iter()
                        .filter(|_| admin_in_scope)
                        .map(|u| J::obj(vec![("secret", J::s(&u.name)), ("scope", J::s(&u.scope)), ("owner", J::s(&u.owner_label)), ("admins", J::strs(&u.admins)), ("used_by", J::strs(&u.used_by))]))
                        .collect(),
                ),
            ),
            ("no_owner", J::Arr(orphans.iter().map(|(f, r)| J::obj(vec![("place", J::s(place_name(f))), ("reason", J::s(r))])).collect())),
            ("no_owner_secrets", J::strs(&orphan_secrets)),
            (
                "outside_scope",
                J::Arr(
                    outside
                        .iter()
                        .map(|(k, v)| {
                            J::obj(vec![
                                (
                                    "to",
                                    J::s(match k {
                                        Target::None(_) => "no owner found".to_string(),
                                        k => header_for(ix, k).0.trim_start_matches("To ").to_string(),
                                    }),
                                ),
                                ("findings", J::Int(v.len() as i64)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("possible", J::Arr(poss.iter().map(|p| J::obj(vec![("host", J::s(&p.where_)), ("reason", J::s(&p.reason))])).collect())),
            ("hash_advisories", J::Arr(res.hash_advisories.iter().map(|(h, id, pk)| J::obj(vec![("hash", J::s(h)), ("advisory", J::s(id)), ("packages", J::strs(pk))])).collect())),
            ("present_after_window", J::Arr(res.present_after.iter().map(|f| J::s(place_name(f))).collect())),
            ("not_checked", not_checked_json(res)),
        ]);
        return format!("{}\n", doc.dumps());
    }
    let what_all = match &q.adv {
        Some(a) if !a.title.trim().is_empty() => a.title.clone(),
        _ => q.iocs.iter().map(|i| i.text.clone()).collect::<Vec<_>>().join(", "),
    };
    let mut out: Vec<String> = vec![];
    for m in &msgs {
        if fm == "jira" {
            let Some(j) = m.jira.as_ref().filter(|j| !j.is_empty()) else { continue };
            let what = if m.inds.is_empty() {
                what_all.clone()
            } else if q.adv.is_some() {
                what_all.clone()
            } else {
                m.inds.join(", ")
            };
            out.push(if m.places > 0 {
                format!("JIRA project={j}  summary: Remove {what} from {} your team owns", plural(m.n, "place"))
            } else {
                format!("JIRA project={j}  summary: Rotate secrets that {what} could read")
            });
            out.push(format!("  {}", m.head));
        } else {
            out.push(m.head.clone());
        }
        out.push(m.body.clone());
        out.extend(render_lines(&m.lines));
        let (org_s, own_s): (Vec<&String>, Vec<&String>) = m.secrets.iter().partition(|n| org_names.contains(n.as_str()));
        if !own_s.is_empty() {
            out.push(format!("Secrets that were in reach of those runs, rotate: {}", own_s.iter().map(|n| scoped(n)).collect::<Vec<_>>().join(", ")));
        }
        if !org_s.is_empty() && fm != "jira" {
            out.push(format!(
                "Org secrets that were in reach of those runs: {}. The org admins ({}) own and rotate them; tell them which of your runs read them.",
                org_s.iter().map(|n| scoped(n)).collect::<Vec<_>>().join(", "),
                admin_words
            ));
        }
        if !m.possible.is_empty() {
            let win = q.window.as_ref().map(|(a, b)| format!(" between {}Z and {}Z", fmt(a), fmt(b))).unwrap_or_default();
            out.push(format!("To check: look at your own run history{win}; if a run used the affected reference, rotate the secrets that workflow can read."));
        }
        out.push(String::new());
    }
    if !org_uses.is_empty() && admin_in_scope && fm != "jira" {
        out.push(format!("To the org admins ({admin_words})"));
        out.push("Hi, these org secrets were in reach of the CI runs that installed it. You own them as org admins, so rotating them is yours; the teams whose runs read each are listed.".into());
        for u in &org_uses {
            out.push(format!("  - {} ({}); used by {}", u.name, u.scope, if u.used_by.is_empty() { "no team br can name".to_string() } else { u.used_by.join(", ") }));
        }
        out.push(String::new());
    }
    if (!orphans.is_empty() || !orphan_secrets.is_empty()) && fm != "jira" {
        out.push("NO OWNER FOUND".into());
        out.extend(no_owner_block(ix, &orphans));
        if !orphan_secrets.is_empty() {
            out.push(format!("  secrets that were in reach of runs with no owner, rotate: {}", orphan_secrets.iter().map(|n| scoped(n)).collect::<Vec<_>>().join(", ")));
        }
        out.push(String::new());
    }
    if fm != "jira" {
        let outl = outside_lines(ix);
        if !outl.is_empty() {
            out.extend(outl);
            out.push(String::new());
        }
        let in_scope: Vec<&Finding> = if rs.is_some() { groups.values().flatten().copied().collect() } else { fs.clone() };
        out.push(totals_line(res, &in_scope));
        out.push(String::new());
    }
    if !poss.is_empty() && fm != "jira" {
        out.push("POSSIBLE, not counted (verify first):".into());
        for p in &poss {
            out.push(format!("  - {} possible: {}", p.where_, p.reason));
        }
        out.push(String::new());
    }
    for l in hash_advisory_offer(res, "notify") {
        out.push(l);
    }
    if let Some(n) = after_window_note(res) {
        out.push(n);
    }
    out.extend(not_checked_text(res, ""));
    format!("{}\n", out.join("\n").trim_end())
}

// ---- purge ------------------------------------------------------------------------------------------------
fn image_build<'a>(ix: &Index<'a>, f: &Finding) -> Option<&'a ImageBuild> {
    let v: &'a View = ix.v;
    v.images.iter().find(|b| b.digest == f.digest && b.repository == f.image)
}

/// Base-image lookup over every indexed build: by digest, and by cumulative layer diff-id chain.
pub struct BaseIdx {
    by_digest: HashMap<String, String>,
    by_chain: HashMap<String, String>,
}

fn chain_step(prev: &str, diff: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(diff.as_bytes());
    hex::encode(h.finalize())
}

impl BaseIdx {
    /// One pass over the builds: O(layers) in total, so 2000 images are cheap.
    pub fn new(v: &View) -> BaseIdx {
        let mut by_digest = HashMap::new();
        let mut by_chain = HashMap::new();
        for b in &v.images {
            by_digest.entry(b.digest.clone()).or_insert_with(|| b.repository.clone());
            let mut h = String::new();
            let mut full = true;
            for l in &b.layers {
                match &l.diff_id {
                    Some(d) if !d.is_empty() => h = chain_step(&h, d),
                    _ => {
                        full = false;
                        break;
                    }
                }
            }
            if full && !b.layers.is_empty() {
                by_chain.entry(h).or_insert_with(|| b.repository.clone());
            }
        }
        BaseIdx { by_digest, by_chain }
    }
}

/// `registry/repo` of an image reference with its tag and digest removed.
fn repo_of_ref(r: &str) -> String {
    let no_digest = r.split('@').next().unwrap_or(r);
    match no_digest.rfind(':') {
        Some(i) if !no_digest[i..].contains('/') => no_digest[..i].to_string(),
        _ => no_digest.to_string(),
    }
}

/// The repository this build was made FROM, or None. Sources, in order: the OCI annotations
/// `org.opencontainers.image.base.digest` / `.base.name` (https://github.com/opencontainers/image-spec/blob/main/annotations.md),
/// then the longest leading run of layer diff-ids shared with another indexed image. Never the text of a FROM line.
pub fn base_of(idx: &BaseIdx, b: Option<&ImageBuild>) -> Option<String> {
    let b = b?;
    if let Some(r) = b.base_digest.as_deref().and_then(|d| idx.by_digest.get(d)) {
        return Some(r.clone());
    }
    if let Some(n) = b.base_name.as_deref().filter(|n| !n.is_empty()) {
        return Some(repo_of_ref(n));
    }
    let mut h = String::new();
    let mut found: Option<&String> = None;
    for (i, l) in b.layers.iter().enumerate() {
        match &l.diff_id {
            Some(d) if !d.is_empty() => h = chain_step(&h, d),
            _ => break,
        }
        if i + 1 < b.layers.len() {
            if let Some(r) = idx.by_chain.get(&h) {
                if *r != b.repository {
                    found = Some(r);
                }
            }
        }
    }
    found.cloned()
}

/// (workflow file path, has a workflow_dispatch trigger) of one run, from the runs API path and the parsed workflow.
pub fn run_workflow(ix: &Index, repo: &str, run_id: u64) -> Option<(String, bool)> {
    let rd = ix.v.repos.get(repo)?;
    let run = rd.runs.iter().find(|r| r.id == run_id)?;
    let path = run.path.clone().filter(|p| !p.is_empty())?;
    let b = basename(&path);
    let dispatch = rd.workflows.iter().any(|w| (w.file == path || basename(&w.file) == b) && w.dispatch);
    Some((path, dispatch))
}

/// How to build again: `gh workflow run FILE` (by file path, never the display name) only when the workflow has
/// workflow_dispatch, which `gh workflow run` needs (https://cli.github.com/manual/gh_workflow_run). `gh run rerun` is never
/// offered: it repeats the run on its OLD commit, and an image that holds the indicator was built from a commit that holds it.
/// With no dispatchable workflow the step is to push the fix: the next build on the default branch replaces the image.
fn dispatch_cmd(ix: &Index, repo: &str, run_id: u64) -> Option<String> {
    let r = shquote(repo);
    match run_workflow(ix, repo, run_id) {
        Some((p, true)) => {
            let refspec = ix.v.repos.get(repo).and_then(|x| x.default_branch.clone()).filter(|b| !b.is_empty()).map(|b| format!(" --ref {}", shquote(&b))).unwrap_or_default();
            Some(format!("gh workflow run {} -R {r}{refspec}", shquote(basename(&p))))
        }
        _ => None,
    }
}

/// Said where an image has a source repo but no workflow that can be started by hand.
const PUSH_FIX_NOTE: &str = "push the fix; the next build on the default branch replaces this image (re-running the old build would bring the bad version back)";

pub type Step<'a> = (Option<String>, Option<String>, Vec<&'a Finding>);

/// (steps, edges): one step per source repo and workflow, base images before the images built on them.
fn rebuild_plan<'a>(ix: &Index, imgs: &[&'a Finding]) -> (Vec<Step<'a>>, BTreeMap<String, String>) {
    let idx = BaseIdx::new(ix.v);
    let mut repos: BTreeMap<String, Vec<&'a Finding>> = BTreeMap::new();
    for f in imgs {
        repos.entry(f.image.clone()).or_default().push(f);
    }
    let mut edges: BTreeMap<String, String> = BTreeMap::new();
    for (r, fl) in &repos {
        if let Some(b) = base_of(&idx, image_build(ix, fl[0])) {
            if repos.contains_key(&b) && &b != r {
                edges.insert(r.clone(), b);
            }
        }
    }
    let (mut order, mut seen): (Vec<String>, HashSet<String>) = (vec![], HashSet::new());
    fn visit(r: &str, edges: &BTreeMap<String, String>, seen: &mut HashSet<String>, order: &mut Vec<String>) {
        if !seen.insert(r.to_string()) {
            return;
        }
        if let Some(b) = edges.get(r) {
            visit(b, edges, seen, order);
        }
        order.push(r.to_string());
    }
    for r in repos.keys() {
        visit(r, &edges, &mut seen, &mut order);
    }
    let mut steps: Vec<Step> = vec![];
    let mut done: HashMap<(Option<String>, Option<String>, String), usize> = HashMap::new();
    for r in &order {
        for f in &repos[r] {
            let src = f.from_repo.clone().filter(|s| !s.is_empty());
            let wf = match (&src, f.run_id) {
                (Some(s), Some(rid)) => dispatch_cmd(ix, s, rid),
                _ => None,
            };
            let key = (src.clone(), wf.clone(), r.clone());
            match done.get(&key) {
                Some(&i) => steps[i].2.push(f),
                None => {
                    done.insert(key, steps.len());
                    steps.push((src, wf, vec![f]));
                }
            }
        }
    }
    (steps, edges)
}

/// The indicator words every command the script prints starts from: `--advisory ID` and the indicators as typed.
fn selectors(q: &Query, a: &QueryArgs) -> String {
    let mut sel: Vec<String> = vec![];
    if let Some(adv) = a.advisory.as_ref().filter(|x| !x.is_empty()) {
        sel.push(format!("--advisory {}", shquote(adv)));
    }
    sel.extend(a.iocs.iter().map(|s| shquote(s)));
    if sel.is_empty() {
        sel = q.iocs.iter().map(|i| shquote(&i.text)).collect();
    }
    sel.join(" ")
}

/// Does a merge guard make sense? Only for an indicator a lockfile can show (a package or an action).
fn has_guard(q: &Query) -> bool {
    q.iocs.iter().any(|i| matches!(i.kind, IocKind::Pkg | IocKind::ActionRef | IocKind::ActionSha))
}

/// The flags of this run that narrow what it covers. A guard repeats them, so it checks what the run covers.
fn narrowing(a: &QueryArgs) -> String {
    let mut n = String::new();
    if let Some(o) = a.owner.as_ref().filter(|o| !o.is_empty()) {
        n += &format!(" --owner {}", shquote(o));
    }
    if let Some(r) = a.repo.as_ref().filter(|r| !r.is_empty()) {
        n += &format!(" --repo {}", shquote(r));
    }
    n
}

/// One image's (or cache's) guard is its own source repo's check, never an org-wide one. `repo` is a shell word.
fn repo_guard(q: &Query, a: &QueryArgs, repo: &str) -> String {
    format!("br scan --repo {repo} && br hunt {} --repo {repo} --now --only repos --fail-if found", selectors(q, a))
}

/// The guard for a step that belongs to no one repo (a runner's cache): the run's own scope, narrowing included.
fn scope_guard(q: &Query, a: &QueryArgs) -> String {
    // rescan what matched first: a guard that reads a stale (or, in CI, a missing) index would pass on old data
    let scan = match a.repo.as_ref().filter(|r| !r.is_empty()) {
        Some(r) => format!("br scan --repo {} && ", shquote(r)),
        None => a.advisory.as_ref().filter(|x| !x.is_empty()).map(|_| String::new()).or_else(|| q.iocs.first().map(|i| format!("br scan --affected {} && ", shquote(&i.text)))).unwrap_or_default(),
    };
    format!("{scan}br hunt {}{} --now --only repos --fail-if found", selectors(q, a), narrowing(a))
}

/// The registry source an image lives in (the name `br scan --registry` takes), from the index; the host part otherwise.
fn registry_source(ix: &Index, image: &str) -> String {
    let mut best: Option<&String> = None;
    for (n, s) in &ix.srcs {
        if s.kind == "registry" && (image == n || image.starts_with(&format!("{n}/"))) && best.is_none_or(|b| n.len() > b.len()) {
            best = Some(n);
        }
    }
    best.cloned().unwrap_or_else(|| image.split('/').next().unwrap_or(image).to_string())
}

fn layer_words(f: &Finding) -> String {
    format!("in an earlier image layer (layer {}), deleted later but still downloadable by digest: rebuild, then delete the old digest", f.layer)
}

fn deleted(f: &Finding) -> bool {
    f.deleted_in.is_some_and(|d| d != 0)
}

/// Owner type of a registry namespace, from what the index knows: the org, its teams, its people.
fn owner_kind(ix: &Index, owner: &str) -> OwnerKind {
    let o = owner.to_lowercase();
    if ix.v.org.github.as_deref().is_some_and(|g| g.to_lowercase() == o) || ix.v.teams.iter().any(|t| t.id.to_lowercase().starts_with(&format!("{o}/"))) {
        return OwnerKind::Org;
    }
    if ix.v.people.iter().any(|p| p.login.to_lowercase() == o) {
        return OwnerKind::User;
    }
    OwnerKind::Unknown
}

/// (command, note or None) deleting one digest (a literal, or a shell expression such as "$x") in the registry that holds it.
pub fn registry_delete_parts(ix: &Index, f: &Finding, digest: &str) -> (String, Option<String>) {
    let ok = match shell::classify(&f.image) {
        shell::Registry::Ghcr { owner, .. } => owner_kind(ix, &owner),
        _ => OwnerKind::Unknown,
    };
    shell::delete_cmd(&f.image, digest, &f.tags, ok)
}

fn registry_delete(ix: &Index, f: &Finding) -> String {
    let (cmd, note) = registry_delete_parts(ix, f, &f.digest);
    match note {
        Some(n) => format!("{cmd}   ({n})"),
        None => cmd,
    }
}

/// The shell lines that read an image layer's blob digest from the manifest at run time. The index keeps a layer's
/// diff_id (the digest of the uncompressed tar), not the registry's blob digest, so the digest is read from the manifest
/// by the layer's position. Run before the manifest is deleted.
fn blob_prep(f: &Finding, ind: &str) -> Vec<String> {
    // The scan recorded the layer's blob digest (the registry's own, from the manifest), so the script names it
    if let Some(d) = f.layer_blob.as_deref().filter(|d| !d.is_empty()) {
        return vec![format!("{ind}# layer {} of this image holds the file as a blob of its own (digest from the scan)", f.layer), format!("{ind}blob={}", shquote(d))];
    }
    let mut cmd = format!(
        "{ind}bm=$(crane manifest {}@{}) || {{ echo {}; return 1; }}",
        shquote(&f.image),
        shquote(&f.digest),
        shquote(&format!("{}: crane could not read the manifest to find the layer blob; nothing was deleted", f.image))
    );
    let pick = format!("{ind}blob=$(printf '%s' \"$bm\" | tr -d '\\n' | grep -o '\"layers\".*' | grep -o 'sha256:[0-9a-f]\\{{64\\}}' | sed -n '{}p') || blob=''", f.layer);
    vec![format!("{ind}# layer {} of this image holds the file as a blob of its own: its digest is read from the manifest first", f.layer), std::mem::take(&mut cmd), pick]
}

/// What happens to that blob. The OCI distribution spec has an optional `DELETE /v2/NAME/blobs/DIGEST`; the big hosted
/// registries have no such call and remove a blob when no image version uses it any more.
fn blob_drop(f: &Finding, ind: &str) -> Vec<String> {
    match shell::classify(&f.image) {
        shell::Registry::Other { host } => {
            let name = f.image.strip_prefix(&format!("{host}/")).unwrap_or(&f.image);
            vec![
                format!("{ind}# the OCI distribution spec's optional blob DELETE; registries often turn it off, and it needs $REGISTRY_TOKEN for this registry"),
                format!("{ind}[ -z \"$blob\" ] || curl -fsS -X DELETE -H \"Authorization: Bearer $REGISTRY_TOKEN\" https://{host}/v2/{name}/blobs/\"$blob\""),
            ]
        }
        _ => vec![format!("{ind}echo \"layer blob ${{blob:-unknown}}: this registry has no blob-delete call; it is removed once no image version uses it\"")],
    }
}

/// The lines (indented) that delete an old digest and, for a multi-arch image, the platform manifests its index lists.
/// A manifest list is recognised by its media type; its children are the `"digest"` values in the index (not the
/// config or layers of a single image, and not annotations). A deleted-layer hit also drops its layer blob.
fn delete_lines(ix: &Index, f: &Finding, ind: &str) -> Vec<String> {
    let img = shquote(&f.image);
    let d = shquote(&f.digest);
    let hub = matches!(shell::classify(&f.image), shell::Registry::DockerHub { .. });
    let (one, note) = registry_delete_parts(ix, f, "$x");
    let blobs = deleted(f);
    let mut out = vec![];
    if blobs {
        out.extend(blob_prep(f, ind));
    }
    if let Some(n) = note {
        out.push(format!("{ind}# {n}"));
    }
    if hub {
        // Docker Hub deletes by tag; the loop would repeat the same call
        let (c, _) = registry_delete_parts(ix, f, &f.digest);
        out.push(format!("{ind}{c}"));
    } else {
        out.push(format!("{ind}d={d}"));
        // A manifest that cannot be read stops the delete: a multi-arch index deleted without its children leaves them pullable
        out.push(format!(
            "{ind}m=$(crane manifest {img}@\"$d\") || {{ echo {}; return 1; }}",
            shquote(&format!("{}: crane could not read the manifest of the old digest; nothing was deleted", f.image))
        ));
        out.push(format!("{ind}kids=''"));
        out.push(format!("{ind}case \"$m\" in *image.index*|*manifest.list*)"));
        out.push(format!("{ind}  kids=$(printf '%s\\n' \"$m\" | grep -o '\"digest\": *\"sha256:[0-9a-f]*\"' | grep -o 'sha256:[0-9a-f]*' | sort -u) || kids=''"));
        out.push(format!("{ind}  [ -n \"$kids\" ] || {{ echo {}; return 1; }};;", shquote(&format!("{}: its index lists no manifests; nothing was deleted", f.image))));
        out.push(format!("{ind}esac"));
        out.push(format!("{ind}for x in \"$d\" $kids; do"));
        out.push(format!("{ind}  {{ {one}; }} || {{ echo \"{}: could not delete $x; stopping\"; return 1; }}", f.image.replace('"', "")));
        out.push(format!("{ind}done"));
    }
    if blobs {
        out.extend(blob_drop(f, ind));
    }
    out
}

fn host_loc(f: &Finding) -> String {
    if !f.loc.is_empty() {
        f.loc.clone()
    } else {
        f.path.clone()
    }
}

/// What the plan says about a deleted-layer blob.
fn blob_words(f: &Finding) -> String {
    let how = match shell::classify(&f.image) {
        shell::Registry::Other { .. } if f.layer_blob.is_some() => "the script sends the registry's optional blob DELETE",
        shell::Registry::Other { .. } => "the script reads its digest from the manifest and sends the registry's optional blob DELETE",
        _ => "this registry has no blob-delete call: deleting the old digest unlists it, and the registry removes the blob once no image version uses it",
    };
    let digest = f.layer_blob.as_deref().filter(|d| !d.is_empty()).map(|d| format!(" {d}")).unwrap_or_default();
    format!("layer {} is a blob of its own{digest}, still downloadable by its digest; {how}", f.layer)
}

/// A person's export is named by login: `Lena Fischer (@lfischer)` gives `lfischer`.
pub fn export_name(host: &str) -> String {
    let re = Regex::new(r"\(@([A-Za-z0-9][A-Za-z0-9_.-]*)\)").unwrap();
    match re.captures(host) {
        Some(m) => m[1].to_string(),
        None => file_safe(host),
    }
}

/// The user whose home a scanned path sits in (`/home/runner/...`, `/Users/dana/...`), when the path says so.
pub fn host_user(loc: &str) -> Option<String> {
    let c: Vec<&str> = loc.split('/').collect();
    match c.as_slice() {
        ["", "home", u, ..] | ["", "Users", u, ..] if !u.is_empty() && *u != "Shared" => Some(u.to_string()),
        ["", "root", ..] => Some("root".to_string()),
        _ => None,
    }
}

/// The tools a script's commands call, found from the command lines themselves (quoted text and comments left out).
fn tools_used(body: &[String]) -> Vec<&'static str> {
    const TOOLS: &[&str] = &["gh", "ssh", "crane", "curl", "aws", "gcloud", "az", "br", "sudo"];
    let quoted = Regex::new(r#"'[^']*'|"[^"]*""#).unwrap();
    let mut found: Vec<&'static str> = vec![];
    for l in body.iter().filter(|l| !l.trim_start().starts_with('#')) {
        let bare = quoted.replace_all(l, "''");
        for w in bare.split(|c: char| c.is_whitespace() || ";&|(){}$`".contains(c)) {
            if let Some(t) = TOOLS.iter().find(|t| **t == w) {
                if !found.contains(t) {
                    found.push(t);
                }
            }
        }
    }
    found
}

fn need_line(t: &str, ind: &str) -> String {
    format!("{ind}command -v {t} >/dev/null 2>&1 || {{ echo \"br purge: this script needs {t}, and it is not installed\" >&2; exit 1; }}")
}

/// Each tool is checked where the script first needs it. A step that sits in an `if` block or a function is checked
/// at the start of that block (inside a function, so defining it needs nothing), and a tool checked once is not checked
/// again. So a script run without `--verified` never asks for `crane`.
fn with_tool_checks(body: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let mut checked: HashSet<&'static str> = HashSet::new();
    let mut i = 0;
    while i < body.len() {
        let l = &body[i];
        let top = !l.starts_with(' ') && !l.starts_with('#');
        let func = top && l.ends_with("() {");
        let end = if func {
            body[i..].iter().position(|x| x == "}").map(|k| i + k)
        } else if top && l.starts_with("if ") {
            body[i..].iter().position(|x| x == "fi").map(|k| i + k)
        } else {
            None
        }
        .unwrap_or(i);
        let blk = &body[i..=end];
        let tools = tools_used(blk);
        if func {
            out.push(l.clone());
            out.extend(tools.into_iter().map(|t| need_line(t, "  ")));
            out.extend(blk[1..].iter().cloned());
        } else {
            out.extend(tools.into_iter().filter(|t| checked.insert(*t)).map(|t| need_line(t, "")));
            out.extend(blk.iter().cloned());
        }
        i = end + 1;
    }
    out
}

/// The commands of one deletion: preserve, then delete, chained so a failed save stops the delete.
/// Returns (lines, preserve step could not be automated).
fn chain(f: &Finding, reach: Option<&str>, no_preserve: bool) -> (Vec<String>, bool) {
    let Some((pre, del)) = destructive(f, reach) else { return (vec![], false) };
    if no_preserve {
        return (vec![del], false);
    }
    let mut notes: Vec<String> = vec![];
    if let Some(w) = preserves(f) {
        notes.push(format!("# preserves: {w}"));
    }
    if let Some(o) = preserve_offer(f) {
        notes.push(format!("# {o}"));
    }
    if pre.starts_with('#') {
        notes.push(pre);
        notes.push(del);
        return (notes, true);
    }
    // A step whose save or delete fails stops the script and says so (a failed non-last command in `a && b` is not seen by `set -e`)
    notes.push(format!("{pre} && {del} || {{ echo {} >&2; exit 1; }}", shquote(&format!("br purge: FAILED on {}: the save or the delete did not succeed; stopping", place_name(f)))));
    (notes, false)
}

struct Sh {
    body: Vec<String>,
    /// steps left as comments for a person to do
    manual: usize,
}

impl Sh {
    fn p(&mut self, s: impl Into<String>) {
        self.body.push(s.into());
    }
    /// A step br cannot run for you: it is a comment, and the header counts it.
    fn note_manual(&mut self) {
        self.manual += 1;
    }
    /// Lines that run only once `cond` passes; if it fails the script notes it and goes on.
    fn guarded(&mut self, cond: Option<String>, lines: Vec<String>) {
        let runs = lines.iter().any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'));
        match cond {
            Some(c) if runs => {
                self.p(format!("if {c}; then"));
                for l in lines {
                    self.p(if l.is_empty() { l } else { format!("  {l}") });
                }
                self.p("else");
                self.p("  skipped=1");
                self.p("fi");
            }
            _ => lines.into_iter().for_each(|l| self.p(l)),
        }
    }
}

/// The verdict for a host where a CI run installed the package: one sentence, on every screen. With an advisory that runs
/// code at install it is "the install ran here ... isolate, rotate, reimage"; without one it only says a CI run installed it.
fn ci_ran_words(f: &Finding, risky: bool) -> Option<String> {
    if f.ci_installs.is_empty() {
        return None;
    }
    let runs = f.ci_installs.join(", ");
    Some(if risky {
        format!("the install ran here (CI run {runs}): isolate the machine from the network, keep a copy of the cache entry first, {HOME_ROTATE}, and reimage the machine; clearing the cache is not enough")
    } else {
        format!("a CI run installed it here ({runs})")
    })
}

/// The "install ran" line for a host where a cache hit means the install ran.
fn install_ran_words(f: &Finding, risky: bool) -> Option<String> {
    if let Some(w) = ci_ran_words(f, risky) {
        return Some(w);
    }
    (treat_as_malware(f, risky) && !is_malware(f))
        .then(|| format!("the install likely ran here: isolate this machine from the network and keep a copy of the cache entry first; clearing the cache is not enough, {HOME_ROTATE}"))
}

/// br purge: the whole stdout.
pub fn purge(ix: &Index, a: &QueryArgs, q: &Query, res: &HuntResult, commands: bool, format: &Option<String>, no_preserve: bool) -> String {
    let s = purge_inner(ix, a, q, res, commands, format, no_preserve);
    // A certificate in a trust store is never deleted by a command br prints; br fix lists the steps
    let certs = all_findings(res).iter().filter(|f| f.cert.is_some()).count();
    let is_json = format.as_deref() == Some("json");
    if certs == 0 || is_json || commands {
        return s;
    }
    format!("{}\n\n{} in trust stores: br purge deletes nothing there. br fix lists what each owner does.\n", s.trim_end(), plural(certs, "certificate"))
}

fn purge_inner(ix: &Index, a: &QueryArgs, q: &Query, res: &HuntResult, commands: bool, format: &Option<String>, no_preserve: bool) -> String {
    let all: Vec<&Finding> = all_findings(res).into_iter().filter(|f| f.cert.is_none()).collect();
    let unfixed = unfixed_everywhere(ix, q, &all);
    let risky = risky_install(q);
    let fixed_plan = plan_fixed(q, &None);
    // A repo that has new commits since it was indexed gets the "index is behind" line, and nothing is planned from the old state
    let mut withheld: Vec<String> = vec![];
    let held = |f: &Finding| -> Option<String> {
        let repo = match f.kind {
            FKind::Cache | FKind::Artifact | FKind::ReleaseAsset => Some(f.where_.as_str()),
            FKind::Image => f.from_repo.as_deref().filter(|r| !r.is_empty()),
            _ => None,
        }?;
        res.moved.iter().find(|(r, _)| r == repo).map(|(r, at)| H::moved_line(ix, r, at))
    };
    let fs: Vec<&Finding> = one_per_place(all.clone())
        .into_iter()
        .filter(|f| match held(f) {
            Some(l) => {
                if !withheld.contains(&l) {
                    withheld.push(l);
                }
                false
            }
            None => true,
        })
        .collect();
    let by = |k: FKind| -> Vec<&Finding> { fs.iter().copied().filter(|f| f.kind == k).collect() };
    let poss = H::possible(res);
    let mut fm = format.clone().unwrap_or_else(|| "text".into());
    if commands && fm == "text" {
        fm = "sh".into();
    }
    let mut caches = by(FKind::Cache);
    caches.sort_by(|x, y| (&x.where_, &x.key).cmp(&(&y.where_, &y.key)));
    let (caches_now, caches_after): (Vec<&Finding>, Vec<&Finding>) = caches.iter().copied().partition(|f| clean_when(ix, f, &unfixed) == When::Now);
    let mut arts = by(FKind::Artifact);
    arts.sort_by(|x, y| (&x.where_, x.id.to_string()).cmp(&(&y.where_, y.id.to_string())));
    let mut rel = by(FKind::ReleaseAsset);
    rel.sort_by(|x, y| (&x.where_, &x.tag, &x.asset).cmp(&(&y.where_, &y.tag, &y.asset)));
    let mut hosts = by(FKind::Host);
    hosts.sort_by(|x, y| (&x.where_, host_loc(x)).cmp(&(&y.where_, host_loc(y))));
    let (hosts_now, hosts_after): (Vec<&Finding>, Vec<&Finding>) = hosts.iter().copied().partition(|f| clean_when(ix, f, &unfixed) == When::Now);
    let mut imgs = by(FKind::Image);
    imgs.sort_by(|x, y| (&x.image, &x.built).cmp(&(&y.image, &y.built)));
    let nc = not_checked_text(res, "");
    let adv_offer = hash_advisory_offer(res, "purge");
    let win_note = after_window_note(res);
    let (steps, edges) = rebuild_plan(ix, &imgs);
    let reach = |f: &Finding| host_reach(ix, &f.where_);
    let ordered = !edges.is_empty();
    let guard = has_guard(q);
    if fm == "json" {
        let mut cmds = vec![];
        for (f, when) in caches_now
            .iter()
            .map(|f| (f, "now"))
            .chain(arts.iter().map(|f| (f, "now")))
            .chain(rel.iter().map(|f| (f, "now")))
            .chain(hosts_now.iter().map(|f| (f, "now")))
            .chain(caches_after.iter().map(|f| (f, "after the merge")))
            .chain(hosts_after.iter().map(|f| (f, "after the merge")))
        {
            let r = reach(f);
            let Some((pre, run)) = destructive(f, Some(&r)) else { continue };
            cmds.push(J::obj(vec![
                ("kind", J::s(f.kind.name())),
                ("place", J::s(&f.where_)),
                ("when", J::s(when)),
                ("reach", if f.kind == FKind::Host { J::s(&r) } else { J::Null }),
                ("preserve_first", J::s(pre)),
                ("preserves", J::opt(preserves(f).as_deref())),
                ("preserve_also", J::opt(preserve_offer(f).as_deref())),
                ("run", J::s(run)),
                ("note", J::opt(wider_note(f).as_deref())),
                ("install_likely_ran", J::opt(install_ran_words(f, risky).as_deref())),
            ]));
        }
        let mut images = vec![];
        for (src, wf, fl) in &steps {
            for f in fl {
                images.push(J::obj(vec![
                    ("image", J::s(&f.image)),
                    ("tags", J::strs(&f.tags)),
                    ("digest", J::s(&f.digest)),
                    ("rebuild_from", J::opt(f.from_repo.as_deref())),
                    (
                        "rebuild",
                        match wf {
                            Some(c) => J::s(c),
                            None => J::Null,
                        },
                    ),
                    ("rebuild_note", if wf.is_none() && src.is_some() { J::s(PUSH_FIX_NOTE) } else { J::Null }),
                    ("guard", if guard { src.as_ref().map_or(J::Null, |s| J::s(repo_guard(q, a, &shquote(s)))) } else { J::Null }),
                    ("layer_blob", if deleted(f) { J::s(blob_words(f)) } else { J::Null }),
                    ("delete", J::s(registry_delete(ix, f))),
                ]));
            }
        }
        let doc = J::obj(vec![
            ("commands", J::Arr(cmds)),
            ("images", J::Arr(images)),
            ("rebuild_order", J::s(if ordered { "base images first" } else { "no dependency between these images; any order" })),
            ("verify_first", J::Arr(poss.iter().map(|p| J::obj(vec![("host", J::s(&p.where_)), ("reason", J::s(&p.reason))])).collect())),
            ("not_planned", J::strs(&withheld)),
            ("hash_advisories", J::Arr(res.hash_advisories.iter().map(|(h, id, pk)| J::obj(vec![("hash", J::s(h)), ("advisory", J::s(id)), ("packages", J::strs(pk))])).collect())),
            ("present_after_window", J::Arr(res.present_after.iter().map(|f| J::s(place_name(f))).collect())),
            (
                "lockfiles",
                J::Arr(
                    hosts
                        .iter()
                        .filter(|f| is_lockfile(f))
                        .map(|f| J::obj(vec![("host", J::s(&f.where_)), ("file", J::s(&f.loc)), ("steps", J::strs(&host_lock_steps(ix, f, &fixed_plan)))]))
                        .collect(),
                ),
            ),
            (
                "similar",
                J::Arr(
                    fs.iter()
                        .filter(|f| f.match_ == "similar")
                        .map(|f| J::obj(vec![("place", J::s(&f.where_)), ("path", J::s(host_loc(f))), ("label", J::opt(similar_label(f).as_deref()))]))
                        .collect(),
                ),
            ),
            ("not_checked", not_checked_json(res)),
        ]);
        return format!("{}\n", doc.dumps());
    }
    if fm == "sh" {
        let mut sh = Sh { body: vec![], manual: 0 };
        let item_label = |f: &Finding| match f.kind {
            FKind::Cache => format!("# cache {} in {}", f.key, f.where_),
            FKind::Artifact => format!("# artifact {} in {}", f.id, f.where_),
            _ => format!("# release asset {} of {} in {}", f.asset, f.tag, f.where_),
        };
        sh.p("# PART 1, NOW (before the merge): artifacts, release assets and what no run on the unfixed code will create again.");
        for f in caches_now.iter().chain(&arts).chain(&rel) {
            sh.p(String::new());
            sh.p(item_label(f));
            let (lines, manual) = chain(f, None, no_preserve);
            if manual {
                sh.note_manual();
            }
            lines.into_iter().for_each(|l| sh.p(l));
        }
        let host_block = |sh: &mut Sh, f: &Finding| -> Vec<String> {
            let mut lines: Vec<String> = vec![];
            if destructive(f, None).is_none() {
                return lines;
            }
            let ssh = reach(f) == "ssh" && !win_host(f);
            let local = reach(f) == "local";
            let (mut head, mut cmds) = (vec![], vec![]);
            if let Some(l) = similar_label(f) {
                head.push(format!("# {l}"));
            }
            if let Some(n) = runner_holds(ix, f, &hosts) {
                head.push(format!("# {n}"));
            }
            if let Some(n) = workspace_words(ix, f) {
                head.push(format!("# {n}"));
            }
            if local {
                head.push(format!("# on this machine ({}), {}:", f.where_, host_loc(f)));
                if let Some(n) = wider_note(f) {
                    head.push(format!("# {n}"));
                }
                if let Some(n) = install_ran_words(f, risky) {
                    head.push(format!("# {n}"));
                }
                let (c, manual) = chain(f, None, no_preserve);
                if manual {
                    sh.note_manual();
                }
                cmds = c;
            } else if ssh {
                head.push(format!("# on {}, over ssh from here  ({}):", f.where_, host_loc(f)));
                if let Some(n) = wider_note(f) {
                    head.push(format!("# {n}"));
                }
                if let Some(n) = install_ran_words(f, risky) {
                    head.push(format!("# {n}"));
                }
                let (c, manual) = chain(f, Some("ssh"), no_preserve);
                if manual {
                    sh.note_manual();
                }
                cmds = c;
            } else {
                sh.note_manual();
                let who = host_user(&host_loc(f)).map(|u| format!(" as {u}")).unwrap_or_default();
                head.push(format!("# run on {}{who} (br cannot reach it; run these there, or send them to its owner, {}):", f.where_, owner_label(ix, f)));
                if let Some(n) = wider_note(f) {
                    head.push(format!("#   {n}"));
                }
                if let Some(n) = install_ran_words(f, risky) {
                    head.push(format!("#   {n}"));
                }
                let (c, _) = chain(f, None, no_preserve);
                head.extend(c.into_iter().map(|l| format!("#   {}", l.strip_prefix("# ").unwrap_or(&l))));
            }
            lines.extend(head);
            lines.extend(cmds);
            lines
        };
        for f in &hosts_now {
            let l = host_block(&mut sh, f);
            if !l.is_empty() {
                sh.p(String::new());
                l.into_iter().for_each(|x| sh.p(x));
            }
        }
        // A lockfile on a host is changed, never removed: the steps are comments for the person who owns the checkout
        for f in hosts_now.iter().chain(hosts_after.iter()).filter(|f| is_lockfile(f)) {
            sh.note_manual();
            sh.p(String::new());
            sh.p(format!("# lockfile on {}: {} (not deleted; change the version in that checkout)", f.where_, f.loc));
            for l in host_lock_steps(ix, f, &fixed_plan) {
                sh.p(format!("#   {l}"));
            }
        }
        sh.p(String::new());
        sh.p("# PART 2, AFTER THE MERGE: what a run on the unfixed code would create again, and what depends on the merged fix (rebuilds and image deletes).");
        if guard {
            sh.p("# merge guard: each step waits for its own repo. merged REPO rescans it and stops while the affected packages are still in its");
            sh.p("# default branch; the other repos' steps still run. Delete a call only if you are purging before merging on purpose (caches");
            sh.p("# and images rebuilt from the old lockfile bring it back).");
            sh.p("skipped=0");
            sh.p("merged() {");
            sh.p(format!("  {{ {}; }} || {{ echo \"merge the fixes first: $1 still has it (or fix the error above)\"; return 1; }}", repo_guard(q, a, "\"$1\"")));
            sh.p("}");
            sh.p("merged_scope() {");
            sh.p(format!(
                "  {{ {}; }} || {{ echo \"merge the fixes first: the affected packages are still in the default branches in scope (or fix the error above)\"; return 1; }}",
                scope_guard(q, a)
            ));
            sh.p("}");
        } else {
            sh.p("# no merge guard: this indicator is not a package, so no lockfile can show that a fix was merged. Remove the");
            sh.p("# file from the source that builds each image before you rebuild it, or the rebuild brings it back.");
        }
        let mut by_repo: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
        for f in &caches_after {
            by_repo.entry(f.where_.as_str()).or_default().push(f);
        }
        for (repo, cs) in by_repo {
            sh.p(String::new());
            let mut lines: Vec<String> = vec![];
            for f in cs {
                lines.push(item_label(f));
                let (c, manual) = chain(f, None, no_preserve);
                if manual {
                    sh.note_manual();
                }
                lines.extend(c);
            }
            let cond = guard.then(|| format!("merged {}", shquote(repo)));
            sh.guarded(cond, lines);
        }
        // A runner waits only for the repos whose runs used it; with no run recorded for it, the whole scope
        let mut by_gate: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for f in &hosts_after {
            let l = host_block(&mut sh, f);
            if l.is_empty() {
                continue;
            }
            let mut cond = String::new();
            let mut note = String::new();
            if guard {
                match runner_gate(ix, &f.where_, &unfixed) {
                    Some(g) => {
                        cond = g.iter().map(|r| format!("merged {}", shquote(r))).collect::<Vec<_>>().join(" && ");
                        note = format!("# {} waits only for the repos whose runs used it: {}", f.where_, g.join(", "));
                    }
                    None => {
                        cond = "merged_scope".into();
                        note = format!("# no run is recorded on {}, so br cannot narrow it: it waits for every repo in scope", f.where_);
                    }
                }
            }
            let e = by_gate.entry(cond).or_default();
            e.push(String::new());
            if !note.is_empty() && !e.contains(&note) {
                e.push(note);
            }
            e.extend(l);
        }
        for (cond, lines) in by_gate {
            sh.guarded((!cond.is_empty()).then_some(cond), lines);
        }
        if !steps.is_empty() {
            sh.p(String::new());
            sh.p(format!(
                "# rebuild the images that hold it (the fix must be merged first). {}",
                if ordered { "Base images first, in this order:" } else { "No dependency between these images; any order:" }
            ));
            for (src, wf, fl) in &steps {
                let mut lines: Vec<String> = vec![];
                for f in fl {
                    lines.push(format!(
                        "# {} ({}), rebuild from the fixed default branch of {}; old digest {}",
                        f.image,
                        if f.tags.is_empty() { "-".to_string() } else { f.tags.join(", ") },
                        src.clone().unwrap_or_else(|| "its source".into()),
                        f.digest
                    ));
                    if deleted(f) {
                        lines.push(format!("#   {}", layer_words(f)));
                        lines.push(format!("#   {}", blob_words(f)));
                    }
                }
                match (wf, src) {
                    (Some(c), _) => lines.push(c.clone()),
                    (None, Some(_)) => {
                        sh.note_manual();
                        lines.push(format!("# {PUSH_FIX_NOTE}"));
                    }
                    (None, None) => {
                        sh.note_manual();
                        lines.push(format!("# no build workflow is recorded for {}: rebuild it with the pipeline that builds it", fl[0].image));
                    }
                }
                let cond = match (guard, src) {
                    (true, Some(s)) => Some(format!("merged {}", shquote(s))),
                    _ => None,
                };
                sh.guarded(cond, lines);
            }
            sh.p(String::new());
            if guard {
                sh.p("[ \"$skipped\" = 0 ] || { echo \"some steps were skipped because their repos still hold the affected version: merge the fixes, then run this again\" >&2; exit 1; }");
            }
            let verify: Vec<&Finding> = steps.iter().flat_map(|s| s.2.iter().copied()).collect();
            sh.p("# verify first: each rebuilt image no longer holds the indicator (br scan --registry SOURCE, then br hunt ... --only images). The old");
            sh.p("# digests are deleted only when you run this script as: sh purge.sh --verified");
            sh.p("verify_first() {");
            for f in &verify {
                // The rebuild may ship under a new tag, so the check reads the registry again and compares the NEWEST image
                // of this repository, whatever its tag, with the old digest; it never asks about the old tag
                let sql = format!("SELECT digest FROM images WHERE repository = '{}' ORDER BY built DESC LIMIT 1", f.image.replace('\'', "''"));
                sh.p(format!("  # {}: the newest image, under any tag, must not be the old one {}", f.image, f.digest));
                sh.p(format!("  br scan --registry {} || {{ echo {}; return 1; }}", shquote(&registry_source(ix, &f.image)), shquote(&format!("{}: the registry could not be read again", f.image))));
                // Every command a check runs is tested on its own exit status; a pipe into grep or tail would hide a failure
                sh.p(format!(
                    "  rows=$(br sql --format csv {}) || {{ echo {}; return 1; }}",
                    shquote(&sql),
                    shquote(&format!("{}: br sql failed, so the newest image is not known; nothing was deleted", f.image))
                ));
                sh.p("  new=$(printf '%s\\n' \"$rows\" | tail -n 1)");
                sh.p("  [ \"$new\" != digest ] || new=''");
                sh.p(format!(
                    "  if [ -z \"$new\" ] || [ \"$new\" = {d} ]; then echo {msg}; return 1; fi",
                    d = shquote(&f.digest),
                    msg = shquote(&format!("{}: its newest image (any tag) is still the old digest {}: rebuild it first", f.image, f.digest))
                ));
                let repo_flag = f.from_repo.as_ref().filter(|r| !r.is_empty()).map(|r| format!(" --repo {}", shquote(r))).unwrap_or_default();
                sh.p(format!(
                    "  held=$(br hunt {}{repo_flag} --only images --now --format csv) || {{ echo {}; return 1; }}",
                    selectors(q, a),
                    shquote(&format!("{}: the check that its newest image is clean could not run (br hunt failed); nothing was deleted", f.image))
                ));
                sh.p(format!(
                    "  case \"$held\" in *\"$new\"*) echo {}; return 1;; esac",
                    shquote(&format!("{}: its newest image still holds the indicator: rebuild it from the fixed code first", f.image))
                ));
                for l in delete_lines(ix, f, "  ") {
                    sh.p(l);
                }
            }
            sh.p("}");
            sh.p("if [ \"${1:-}\" = \"--verified\" ]; then");
            sh.p("  verify_first");
            sh.p("else");
            sh.p(format!("  echo \"skipped {} verify-first step{}: rerun with --verified after checking\"", verify.len(), if verify.len() == 1 { "" } else { "s" }));
            sh.p("fi");
        } else if guard {
            sh.p(String::new());
            sh.p("[ \"$skipped\" = 0 ] || { echo \"some steps were skipped because their repos still hold the affected version: merge the fixes, then run this again\" >&2; exit 1; }");
        }
        if !poss.is_empty() {
            sh.p(String::new());
            let mut names: Vec<String> = poss.iter().map(|h| h.where_.clone()).collect();
            names.dedup();
            sh.p(format!("# verify first: {} possible, not counted (not scanned since the exposure); check before cleaning:", names.join(", ")));
            for h in &poss {
                sh.note_manual();
                sh.p(format!("#   {} possible: {}", h.where_, h.reason));
                let rc = host_reach(ix, &h.where_);
                if h.item_kind == "inferred" {
                    let c = host_cmd(h).0;
                    if rc == "ssh" {
                        sh.p(format!("#   after saving what is there: ssh {} {}", h.where_, shquote(&c)));
                    } else {
                        sh.p(format!("#   {} is not scanned; after saving what is there, run on {}: {c}", h.where_, h.where_));
                    }
                    let mut hh = (*h).clone();
                    hh.kind = FKind::Host;
                    if let Some(wn) = wider_note(&hh) {
                        sh.p(format!("#   {wn}"));
                    }
                    if let Some(rn) = runner_holds(ix, &hh, &hosts) {
                        sh.p(format!("#   {rn}"));
                    }
                } else if rc == "ssh" {
                    sh.p(format!("#   br scan --host {}, then run this again", h.where_));
                } else if rc == "local" {
                    sh.p("#   this machine: run br scan --local, then run this again".to_string());
                } else {
                    sh.p(format!("#   run br scan --local --export {} on it, then br import", shell::shquote(&format!("{}.brx", export_name(&h.where_)))));
                }
            }
        }
        for l in &withheld {
            sh.note_manual();
            sh.p(format!("# not planned: {l}"));
        }
        for l in &nc {
            sh.p(format!("# {l}"));
        }
        // the header goes on last: it counts what the body turned out to hold
        let mut head: Vec<String> = vec![
            "#!/bin/sh".into(),
            format!("# generated by br from {}; index as of {}", q.iocs.iter().map(|i| i.text.clone()).collect::<Vec<_>>().join(", "), fmtz(res.as_of.as_deref().unwrap_or(""))),
            "set -eu".into(),
            // A pipe fails when any command in it fails (sh that has no pipefail goes on; every check also tests its own status)
            "(set -o pipefail) 2>/dev/null && set -o pipefail".into(),
        ];
        // A tool is checked where it is first needed, so Part 1 never asks for what only the verify step uses
        if no_preserve {
            head.push("# --no-preserve: the deletions below do NOT save the evidence first. Nothing is kept of what they remove.".into());
        } else {
            head.push("# preserve first: every deletion runs as: save the evidence && delete it; the hash of the saved file is printed, keep it with the case file.".into());
        }
        head.push("# Commands for a host start with ssh HOST; a host br cannot reach is a commented block to run there. Image rebuilds come last:".into());
        head.push("# a rebuild before the fix is merged brings it back.".into());
        head.push(format!("# steps left as comments for you to do by hand: {}", sh.manual));
        for l in adv_offer.iter().chain(win_note.iter()) {
            head.push(format!("# {l}"));
        }
        head.push(String::new());
        head.extend(with_tool_checks(sh.body));
        return format!("{}\n", head.join("\n"));
    }
    if fs.is_empty() && poss.is_empty() && withheld.is_empty() {
        let mut o = adv_offer.clone();
        o.push("Nothing to purge in the indexed sources.".to_string());
        o.extend(nc);
        return format!("{}\n", o.join("\n"));
    }
    let mut text: Vec<String> = vec![];
    for l in &adv_offer {
        text.push(l.clone());
    }
    if !adv_offer.is_empty() {
        text.push(String::new());
    }
    text.push("Each deletion below is preceded by a '# preserve first:' line: run it, keep the hash, then delete.".into());
    if let Some(n) = &win_note {
        text.push(n.clone());
    }
    let example = {
        let first_src = imgs.iter().find_map(|f| f.from_repo.clone().filter(|r| !r.is_empty()));
        match first_src {
            Some(r) => repo_guard(q, a, &shquote(&r)),
            None => scope_guard(q, a),
        }
    };
    text.push(format!(
        "The script (br purge --commands) has two parts. Part 1, artifacts, release assets and what no run on the unfixed code will create again, can run now. Part 2, caches a run would save again, rebuilds and image deletes, runs after the fixes are merged{}",
        if guard {
            format!("; merge the fixes first. Each step starts with the guard for its own repo, for example: {example}")
        } else {
            "; this indicator is not a package, so there is no merge guard: check each rebuild source first".into()
        }
    ));
    if !withheld.is_empty() {
        text.push(String::new());
        text.push("NOT PLANNED (these repos have new commits since they were indexed; rescan them, then run br purge again):".into());
        for l in &withheld {
            text.push(format!("  {l}"));
        }
    }
    for (title, list) in
        [("ACTIONS CACHES", &caches_now), ("ACTIONS CACHES, AFTER THE MERGE (a run on the unfixed code would save them again)", &caches_after), ("ARTIFACTS", &arts), ("RELEASE ASSETS", &rel)]
    {
        if !list.is_empty() {
            text.push(String::new());
            text.push(title.into());
            for f in list.iter() {
                text.extend(preserve_lines(f, "  ", None));
            }
        }
    }
    for (title, list) in [("HOSTS", &hosts_now), ("HOSTS, AFTER THE MERGE (a run on the unfixed code would fill the cache again)", &hosts_after)] {
        if list.is_empty() {
            continue;
        }
        text.push(String::new());
        text.push(title.into());
        for f in list.iter() {
            if destructive(f, None).is_none() {
                continue;
            }
            let ssh = reach(f) == "ssh";
            let local = reach(f) == "local";
            let who = host_user(&host_loc(f)).map(|u| format!(" as {u}")).unwrap_or_default();
            text.push(format!(
                "  {}  ({}), {}",
                f.where_,
                host_loc(f),
                if local {
                    "this machine; run these here:".to_string()
                } else if ssh {
                    "over ssh from here:".to_string()
                } else {
                    format!("not reachable from here; run these on {}{who}, or send them to its owner, {}:", f.where_, owner_label(ix, f))
                }
            ));
            if let Some(l) = similar_label(f) {
                text.push(format!("    # {l}"));
            }
            if title.contains("AFTER THE MERGE") && guard {
                match runner_gate(ix, &f.where_, &unfixed) {
                    Some(g) => text.push(format!("    # waits only for the repos whose runs used this runner: {}", g.join(", "))),
                    None => text.push("    # no run is recorded on this runner, so it waits for every repo in scope".to_string()),
                }
            }
            if let Some(n) = wider_note(f) {
                text.push(format!("    # {n}"));
            }
            if let Some(n) = runner_holds(ix, f, &hosts) {
                text.push(format!("    # {n}"));
            }
            if let Some(n) = workspace_words(ix, f) {
                text.push(format!("    # {n}"));
            }
            if let Some(n) = install_ran_words(f, risky) {
                text.push(format!("    # {n}"));
            }
            text.extend(preserve_lines(f, "    ", if ssh { Some("ssh") } else { None }));
        }
    }
    let locks: Vec<&&Finding> = hosts.iter().filter(|f| is_lockfile(f)).collect();
    if !locks.is_empty() {
        text.push(String::new());
        text.push("LOCKFILES ON HOSTS (changed, never deleted: move the version in that checkout, then reinstall)".into());
        for f in locks {
            text.push(format!("  {}  {}", f.where_, f.loc));
            for l in host_lock_steps(ix, f, &fixed_plan) {
                text.push(format!("    {l}"));
            }
        }
    }
    if !imgs.is_empty() {
        text.push(String::new());
        text.push("IMAGES TO REBUILD".into());
        let mut order: Vec<String> = vec![];
        for f in &imgs {
            if let Some(r) = f.from_repo.as_ref().filter(|r| !r.is_empty()) {
                if !order.contains(r) {
                    order.push(r.clone());
                }
            }
        }
        if !order.is_empty() {
            text.push(format!("  fix the source repos first: {}; then rebuild", order.join(", ")));
        }
        let mut names: Vec<String> = vec![];
        for f in steps.iter().flat_map(|s| s.2.iter()) {
            if !names.contains(&f.image) {
                names.push(f.image.clone());
            }
        }
        text.push(format!("  rebuild order: {}", if ordered { format!("{} (base images first)", names.join(" -> ")) } else { "no dependency between these images; any order".to_string() }));
        for (src, wf, fl) in &steps {
            for f in fl {
                // A rebuild is from the fixed default branch, never from the commit that built the bad image
                let s2 = f.from_repo.clone().filter(|r| !r.is_empty()).map(|r| format!("the fixed default branch of {r}")).unwrap_or_else(|| "the fixed source".into());
                text.push(format!("  rebuild {}  {}  from {s2}", f.image, if f.tags.is_empty() { "-".to_string() } else { f.tags.join(", ") }));
                let was = f.commit.as_ref().filter(|c| !c.is_empty()).map(|c| format!(" (built from {}@{c}, which still has the bad version)", ns(&f.from_repo))).unwrap_or_default();
                text.push(format!("    old digest {}{was}", f.digest));
                if deleted(f) {
                    text.push(format!("    {}", layer_words(f)));
                    text.push(format!("    {}", blob_words(f)));
                }
            }
            text.push(format!(
                "    {}",
                match (wf, src) {
                    (Some(c), _) => c.clone(),
                    (None, Some(_)) => PUSH_FIX_NOTE.to_string(),
                    (None, None) => "no build workflow is recorded for this image: rebuild it with the pipeline that builds it".into(),
                }
            ));
            if let (true, Some(s)) = (guard, src) {
                text.push(format!("    guard before it: {}", repo_guard(q, a, &shquote(s))));
            }
            for f in fl {
                let repo_flag = f.from_repo.as_ref().filter(|r| !r.is_empty()).map(|r| format!(" --repo {}", shquote(r))).unwrap_or_default();
                text.push(format!(
                    "    # verify first: the rebuilt image no longer holds the indicator (br scan --registry {}, then br hunt {}{repo_flag} --only images --now --fail-if found), then delete the old digest:",
                    shquote(&registry_source(ix, &f.image)),
                    selectors(q, a)
                ));
                text.push(format!("    #   {}", registry_delete(ix, f)));
            }
        }
    }
    if !poss.is_empty() {
        text.push(String::new());
        text.push("# verify first: possible, not counted. These hosts were not scanned after the exposure:".into());
        for h in &poss {
            let rc = host_reach(ix, &h.where_);
            text.push(format!("  {} possible: {}", h.where_, h.reason));
            if h.item_kind == "inferred" {
                let c = host_cmd(h).0;
                let wh = if rc == "ssh" { format!("ssh {} {}", h.where_, shquote(&c)) } else { c };
                text.push(format!("    after you have saved what is there{}: {wh}", if rc == "ssh" { String::new() } else { format!(" (on {})", h.where_) }));
                let mut hh = (*h).clone();
                hh.kind = FKind::Host;
                if let Some(wn) = wider_note(&hh) {
                    text.push(format!("    {wn}"));
                }
                if let Some(rn) = runner_holds(ix, &hh, &hosts) {
                    text.push(format!("    {rn}"));
                }
            } else if rc == "ssh" {
                text.push(format!("    br scan --host {}   (then run br purge again)", h.where_));
            } else if rc == "local" {
                text.push("    this machine: br scan --local   (then run br purge again)".to_string());
            } else {
                text.push(format!("    run on {}: br scan --local --export {}   (then br import it here)", h.where_, shell::shquote(&format!("{}.brx", export_name(&h.where_)))));
            }
        }
    }
    if !nc.is_empty() {
        text.push(String::new());
        text.extend(nc);
    }
    format!("{}\n", text.join("\n").trim_start_matches('\n'))
}

// ---- diff ---------------------------------------------------------------------------------------------------
/// Identity of a place, not of an observation: a package that stays in a repo is the same row if its state moves.
pub fn fkey(f: &Finding) -> String {
    let k = f.kind.name();
    let w = &f.where_;
    match f.kind {
        FKind::Repo => format!("{k}\x01{w}\x01{}", f.p.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| format!("{}{}", f.name, f.version))),
        FKind::CiRun => format!("{k}\x01{w}\x01{}", f.id),
        FKind::Cache => format!("{k}\x01{w}\x01{}", f.key),
        FKind::Artifact => format!("{k}\x01{w}\x01{}", f.id),
        FKind::Image => format!("{k}\x01{}", f.digest),
        FKind::Host => format!("{k}\x01{w}\x01{}", if f.inferred { "inferred" } else { f.loc.as_str() }),
        FKind::ReleaseAsset => format!("{k}\x01{w}\x01{}\x01{}", f.tag, f.asset),
        FKind::WorkflowRef => format!("{k}\x01{w}\x01{}\x01{}", f.file, if f.uses.is_empty() { &f.ref_ } else { &f.uses }),
    }
}

fn fstate(f: &Finding) -> String {
    match f.kind {
        FKind::Host => if f.possible { "possible" } else { "confirmed" }.into(),
        FKind::Repo => f.state.clone(),
        _ => "present".into(),
    }
}

fn describe(f: &Finding) -> String {
    match f.kind {
        FKind::Repo => format!("{}  {} {}", f.where_, f.name, f.version),
        FKind::CiRun => format!("{}#{}  {}", f.where_, f.id, fmt(&f.at)),
        FKind::Cache => format!("{}  cache {}", f.where_, f.key),
        FKind::Artifact => format!("{}  artifact {}", f.where_, f.name),
        FKind::Image => format!("{}  {}", f.image, short(&f.digest)),
        FKind::Host => format!("{}  {}", f.where_, f.loc),
        _ => format!("{}  {}", f.where_, if !f.file.is_empty() { &f.file } else { &f.asset }),
    }
}

fn val_str(v: Option<&serde_json::Value>) -> String {
    v.and_then(|x| x.as_str()).unwrap_or("").to_string()
}

/// The index as it was known at t0: each source rewound to the indexed_at it had then, from the scan history.
/// Sources first indexed after t0 were not known at all.
pub fn known_at(ix: &Index, t0: &str) -> BTreeMap<String, Source> {
    let mut srcs = ix.srcs.clone();
    let mut hist: Vec<&serde_json::Value> = ix.v.state.scans.iter().collect();
    if let Some(ls) = &ix.v.state.last_scan {
        if !hist.iter().any(|h| h.get("at") == ls.get("at")) {
            hist.push(ls);
        }
    }
    hist.sort_by_key(|h| val_str(h.get("at")));
    let names: Vec<String> = srcs.keys().cloned().collect();
    for n in names {
        let mut cur = srcs[&n].indexed_at.clone();
        for sc in hist.iter().rev() {
            if val_str(sc.get("at")).as_str() > t0 {
                if let Some(b) = sc.get("before").and_then(|b| b.get(&n)).and_then(|x| x.as_str()) {
                    cur = b.to_string();
                }
            }
        }
        // an empty earlier time is "not in the index before that import": it was not known at t0
        if cur.is_empty() || cur.as_str() > t0 {
            srcs.remove(&n);
            continue;
        }
        srcs.get_mut(&n).unwrap().indexed_at = cur;
    }
    srcs
}

/// The earliest time any source in the index had been indexed: the first time `diff --since` can compare from.
pub fn earliest_index_time(ix: &Index) -> Option<String> {
    let mut all: Vec<String> = ix.srcs.values().map(|s| s.indexed_at.clone()).collect();
    let hist = ix.v.state.scans.iter().chain(ix.v.state.last_scan.iter());
    for h in hist {
        if let Some(b) = h.get("before").and_then(|b| b.as_object()) {
            all.extend(b.values().filter_map(|t| t.as_str().map(str::to_string)));
        }
    }
    all.into_iter().filter(|t| !t.is_empty()).min()
}

/// The sources a diff is about when `--owner` or `--repo` narrows it; None means all of them.
fn diff_scope(ix: &Index, q: &Query) -> BrResult<Option<HashSet<String>>> {
    let set = |o: &Option<String>| o.as_ref().is_some_and(|x| !x.is_empty());
    if !set(&q.owner) && !set(&q.repo) {
        return Ok(None);
    }
    Ok(Some(H::scope_sources(ix, q)?.into_iter().collect()))
}

/// Index-level changes: (changed [(name, texts)], unchanged count, new sources).
fn source_changes(ix: &Index, old_srcs: &BTreeMap<String, Source>, scope: &Option<HashSet<String>>) -> (Vec<(String, Vec<String>)>, usize, Vec<String>) {
    let (mut changed, mut quiet, mut fresh) = (vec![], 0, vec![]);
    for (n, s) in &ix.srcs {
        if scope.as_ref().is_some_and(|sc| !sc.contains(n)) {
            continue;
        }
        let new_t = &s.indexed_at;
        let Some(old) = old_srcs.get(n) else {
            fresh.push(n.clone());
            continue;
        };
        let old_t = &old.indexed_at;
        if new_t <= old_t {
            quiet += 1;
            continue;
        }
        let hi = if *new_t < ix.now { new_t.clone() } else { ix.now.clone() };
        let between = |t: &str| old_t.as_str() < t && t <= hi.as_str();
        let mut parts: Vec<(usize, &str)> = vec![];
        match s.kind.as_str() {
            "repo" => {
                let rd = ix.repo(n);
                let c = rd.commits.iter().filter(|x| between(&x.at)).count();
                let r = rd.runs.iter().filter(|x| between(&x.at)).count();
                let it = rd.caches.iter().filter(|x| between(&x.created)).count()
                    + rd.artifacts.iter().filter(|x| between(&x.created)).count()
                    + rd.releases.iter().filter(|x| between(&x.published)).count();
                parts = vec![(c, "commit"), (r, "CI run"), (it, "stored item")];
            }
            "host" => {
                let it = ix.v.hosts.get(n).map_or(0, |h| h.items.iter().filter(|x| between(&x.at)).count());
                parts = vec![(it, "item")];
            }
            "registry" => parts = vec![(ix.v.images.iter().filter(|b| between(&b.built)).count(), "image build")],
            _ => {}
        }
        let txt: Vec<String> = parts.iter().filter(|(c, _)| *c > 0).map(|(c, u)| format!("+{}", plural(*c, u))).collect();
        changed.push((n.clone(), if txt.is_empty() { vec!["re-indexed, nothing new".to_string()] } else { txt }));
    }
    (changed, quiet, fresh)
}

/// The items a diff line counts, one per line, for `br diff -v`: the commits, CI runs and stored items of a repo, the items of
/// a host, the image builds of a registry that came in after `old_t` (or all of them for a source read for the first time).
fn source_change_items(ix: &Index, n: &str, old_t: Option<&str>) -> Vec<String> {
    let Some(s) = ix.srcs.get(n) else { return vec![] };
    let hi = if s.indexed_at < ix.now { s.indexed_at.clone() } else { ix.now.clone() };
    let between = |t: &str| old_t.is_none_or(|o| o < t) && t <= hi.as_str();
    let mut out: Vec<String> = vec![];
    match s.kind.as_str() {
        "repo" => {
            let rd = ix.repo(n);
            out.extend(rd.commits.iter().filter(|x| between(&x.at)).map(|x| {
                format!("commit {} {}{}", x.sha.chars().take(7).collect::<String>(), fmt(&x.at), x.author.as_deref().map(|a| format!(" by @{}", a.trim_start_matches('@'))).unwrap_or_default())
            }));
            out.extend(rd.runs.iter().filter(|x| between(&x.at)).map(|x| format!("CI run {}#{} {}", n, x.id, fmt(&x.at))));
            out.extend(rd.caches.iter().filter(|x| between(&x.created)).map(|x| format!("cache {} {}", x.key, fmt(&x.created))));
            out.extend(rd.artifacts.iter().filter(|x| between(&x.created)).map(|x| format!("artifact {} {}", x.name, fmt(&x.created))));
            out.extend(rd.releases.iter().filter(|x| between(&x.published)).map(|x| format!("release {} {}", x.tag, fmt(&x.published))));
        }
        "host" => {
            if let Some(h) = ix.v.hosts.get(n) {
                out.extend(h.items.iter().filter(|x| between(&x.at)).map(|x| format!("{} {} {}", x.kind, x.loc, fmt(&x.at))));
            }
        }
        "registry" => {
            out.extend(
                ix.v.images
                    .iter()
                    .filter(|b| between(&b.built) && ix.registry_of(&b.repository).as_deref() == Some(n))
                    .map(|b| format!("image {}{} {}", b.repository, b.tags.first().map(|t| format!(":{t}")).unwrap_or_default(), fmt(&b.built))),
            );
        }
        _ => {}
    }
    out
}

/// What a source read for the first time holds, in the words of the diff lines (`first scan: +3 items`).
fn first_scan_words(ix: &Index, n: &str) -> String {
    let s = &ix.srcs[n];
    let what = match s.kind.as_str() {
        "repo" => {
            let rd = ix.repo(n);
            format!("{}, {}", plural(rd.commits.len(), "commit"), plural(rd.runs.len(), "CI run"))
        }
        "host" => plural(ix.v.hosts.get(n).map_or(0, |h| h.items.len()), "item"),
        "registry" => plural(ix.v.images.iter().filter(|b| ix.registry_of(&b.repository).as_deref() == Some(n)).count(), "image build"),
        _ => "its contents".to_string(),
    };
    format!("first scan: +{what}")
}

/// The index source a finding was read from, or None when it cannot be told.
fn source_of(ix: &Index, f: &Finding) -> Option<String> {
    if f.kind == FKind::Image {
        let mut best: Option<&String> = None;
        for (n, s) in &ix.srcs {
            if s.kind == "registry" && f.image.starts_with(&format!("{}/", n.trim_end_matches('/'))) && best.is_none_or(|b| n.len() > b.len()) {
                best = Some(n);
            }
        }
        return best.cloned();
    }
    Some(f.where_.clone())
}

fn names_or_count(names: &[String], verbose: bool, what: &str) -> String {
    if verbose {
        format!("{} ({})", plural(names.len(), what), names.join(", "))
    } else {
        plural(names.len(), what)
    }
}

fn names_hint(verbose: bool) -> &'static str {
    if verbose {
        ""
    } else {
        "; br diff -v lists them"
    }
}

fn ljust(s: &str, w: usize) -> String {
    format!("{s}{}", " ".repeat(w.saturating_sub(s.chars().count())))
}

/// An insertion-ordered map where a repeated key keeps its first position and takes the last value.
fn keyed(fs: Vec<&Finding>) -> Vec<(String, &Finding)> {
    let mut out: Vec<(String, &Finding)> = vec![];
    for f in fs {
        let k = fkey(f);
        match out.iter_mut().find(|(x, _)| *x == k) {
            Some(e) => e.1 = f,
            None => out.push((k, f)),
        }
    }
    out
}

fn last_by_where(v: Vec<&Finding>) -> Vec<(String, &Finding)> {
    let mut m: Vec<(String, &Finding)> = vec![];
    for p in v {
        match m.iter_mut().find(|(k, _)| *k == p.where_) {
            Some(e) => e.1 = p,
            None => m.push((p.where_.clone(), p)),
        }
    }
    m
}

/// br diff: the whole stdout.
/// A time that starts with four digits and a dash carries its year; `05-11T14:00Z` does not.
fn has_year(s: &str) -> bool {
    let b = s.trim().as_bytes();
    b.len() >= 5 && b[..4].iter().all(|c| c.is_ascii_digit()) && b[4] == b'-'
}

pub fn diff(ctx: &Ctx, ix: &Index, q: &Query, since: &Option<String>, verbose: bool, format: &Option<String>) -> BrResult<String> {
    let mut o = String::new();
    let mut p = |s: String| {
        o.push_str(&s);
        o.push('\n');
    };
    let mut old_srcs = ix.srcs.clone();
    let (t0, label);
    if let Some(s) = since.as_ref().filter(|s| !s.is_empty()) {
        let bad = || BrError::new(format!("cannot read --since \"{s}\""), Some("use 2026-05-11 or 2026-05-11T14:00Z"));
        if !has_year(s) {
            return Err(BrError::new(format!("--since \"{s}\" has no year"), Some("write the full form, e.g. 2026-05-11 or 2026-05-11T14:00Z")));
        }
        t0 = parse_when(s, false).map_err(|_| bad())?;
        if t0 > ctx.now {
            return Err(BrError::new(format!("--since {} is in the future", fmtz(&t0)), Some(&format!("the index is as of {}; pick an earlier time", fmtz(&ctx.now)))));
        }
        old_srcs = known_at(ix, &t0);
        label = format!("since {}", fmtz(&t0));
        if old_srcs.is_empty() {
            let first = earliest_index_time(ix).map_or(String::new(), |t| format!("; the earliest time with an index is {}", fmtz(&t)));
            return Err(BrError::with_code(format!("no index existed at {}", fmtz(&t0)), Some(&format!("pick a later time{first}, or use br diff --last")), 5));
        }
    } else {
        let Some(ls) = ix.v.state.last_scan.as_ref().filter(|l| !l.is_null()) else {
            return Ok("No scan has run since the index was built, so there is nothing to compare.\n".into());
        };
        if let Some(b) = ls.get("before").and_then(|b| b.as_object()) {
            for (n, t) in b {
                if let (Some(s), Some(t)) = (old_srcs.get_mut(n), t.as_str()) {
                    s.indexed_at = t.to_string();
                }
            }
        }
        // A source this scan read for the first time was not in the index before: what it holds is what the scan added
        for n in ls.get("first").and_then(|f| f.as_array()).into_iter().flatten().filter_map(|x| x.as_str()) {
            old_srcs.remove(n);
        }
        t0 = val_str(ls.get("at"));
        // An import is a change of the index too, and says so
        let what = if ls.get("kind").and_then(|k| k.as_str()) == Some("import") { "import" } else { "scan" };
        label = format!("made by the {what} at {}", fmtz(&t0));
    }
    let fm = format.clone().unwrap_or_else(|| "text".into());
    let is_since = since.as_ref().is_some_and(|s| !s.is_empty());
    let scope = diff_scope(ix, q)?;
    let in_scope = |n: &str| scope.as_ref().is_none_or(|sc| sc.contains(n));
    if q.iocs.is_empty() {
        let (changed, quiet, fresh) = source_changes(ix, &old_srcs, &scope);
        if fm == "json" {
            let doc = J::obj(vec![
                ("since", J::s(&t0)),
                ("changed", J::Arr(changed.iter().map(|(n, t)| J::obj(vec![("source", J::s(n)), ("added", J::strs(t))])).collect())),
                ("unchanged", J::Int(quiet as i64)),
                ("first_indexed_after", J::strs(&fresh)),
            ]);
            p(doc.dumps());
            return Ok(o);
        }
        let total = ix.srcs.keys().filter(|n| in_scope(n)).count();
        // After a scan (not --since) a source with no earlier state is a first scan: say what it holds
        let mut changed = changed;
        let mut fresh = fresh;
        if !is_since {
            for n in std::mem::take(&mut fresh) {
                changed.push((n.clone(), vec![first_scan_words(ix, &n)]));
            }
        }
        // a source that was only re-indexed gained nothing: the header counts what its lines show
        let gained = changed.iter().filter(|(_, t)| t.as_slice() != ["re-indexed, nothing new"]).count();
        let reindexed = changed.len() - gained;
        if gained == 0 && fresh.is_empty() {
            p(format!("No change {label}: none of the {} holds anything new{}.", plural(total, "source"), if reindexed > 0 { format!(" ({} re-indexed)", reindexed) } else { String::new() }));
            return Ok(o);
        }
        p(format!(
            "Index changes {label}: {} of {} gained something{}{}",
            gained,
            plural(total, "source"),
            if reindexed > 0 { format!(", {} re-indexed with nothing new", reindexed) } else { String::new() },
            if !fresh.is_empty() && is_since { format!(", {} first indexed after that time", fresh.len()) } else { String::new() }
        ));
        let w = changed.iter().map(|(n, _)| n.chars().count()).max().unwrap_or(0);
        for (n, txt) in &changed {
            p(format!("  {}  {}", ljust(n, w), txt.join(", ")));
            // -v lists the items the line counts
            if verbose {
                let old_t = old_srcs.get(n).map(|s| s.indexed_at.clone());
                for it in source_change_items(ix, n, old_t.as_deref()) {
                    p(format!("      {it}"));
                }
            }
        }
        if !verbose && gained > 0 {
            p("br diff -v lists the items each line counts".to_string());
        }
        if !fresh.is_empty() && is_since {
            p(format!(
                "note: {} {} not in the index at that time, so what {} {} counts as new{}",
                names_or_count(&fresh, verbose, "source"),
                if fresh.len() == 1 { "was" } else { "were" },
                if fresh.len() == 1 { "it" } else { "they" },
                if fresh.len() == 1 { "holds" } else { "hold" },
                names_hint(verbose)
            ));
        }
        if quiet > 0 {
            p(format!("{} unchanged.", plural(quiet, "source")));
        }
        p(format!("To see what this means for one indicator: br diff INDICATOR {}", if is_since { "--since TIME" } else { "--last" }));
        return Ok(o);
    }
    let old_ix = ix.with_srcs(old_srcs.clone());
    let old_res = H::hunt(&old_ix, q)?;
    let new_res = H::hunt(ix, q)?;
    let before = keyed(H::findings(&old_res));
    let after = keyed(H::findings(&new_res));
    let poss_before = last_by_where(H::possible(&old_res));
    let poss_after = last_by_where(H::possible(&new_res));
    let get = |m: &[(String, &'_ Finding)], k: &str| -> bool { m.iter().any(|(x, _)| x == k) };
    let (mut new, mut gone, mut chg): (Vec<&Finding>, Vec<&Finding>, Vec<(&Finding, &Finding)>) = (vec![], vec![], vec![]);
    for (k, f) in &after {
        if let Some((_, b)) = before.iter().find(|(x, _)| x == k) {
            if fstate(b) != fstate(f) {
                chg.push((b, f));
            }
        } else if f.kind == FKind::Host && get(&poss_before, &f.where_) {
            chg.push((poss_before.iter().find(|(x, _)| *x == f.where_).unwrap().1, f));
        } else {
            new.push(f);
        }
    }
    for (k, f) in &before {
        if get(&after, k) {
            continue;
        }
        if f.kind == FKind::Host && get(&poss_after, &f.where_) {
            chg.push((f, poss_after.iter().find(|(x, _)| *x == f.where_).unwrap().1));
        } else {
            gone.push(f);
        }
    }
    let unknown: Vec<String> = if is_since { ix.srcs.keys().filter(|n| !old_srcs.contains_key(*n) && in_scope(n)).cloned().collect() } else { vec![] };
    let (late, new): (Vec<&Finding>, Vec<&Finding>) = new.into_iter().partition(|f| source_of(ix, f).is_some_and(|s| unknown.contains(&s)));
    if fm == "json" {
        let mut doc = J::obj(vec![
            ("since", J::s(&t0)),
            ("new", J::Arr(new.iter().map(|f| J::s(describe(f))).collect())),
            ("gone", J::Arr(gone.iter().map(|f| J::s(describe(f))).collect())),
            ("changed", J::Arr(chg.iter().map(|(b, a)| J::obj(vec![("place", J::s(describe(b))), ("was", J::s(fstate(b))), ("now", J::s(fstate(a)))])).collect())),
        ]);
        if !late.is_empty() {
            doc.set("new_source_first_indexed_after", J::Arr(late.iter().map(|f| J::s(describe(f))).collect()));
        }
        p(doc.dumps());
        return Ok(o);
    }
    let note = if unknown.is_empty() {
        None
    } else {
        Some(format!("note: {} first indexed after that time, so the index cannot say what they held then{}", names_or_count(&unknown, verbose, "source"), names_hint(verbose)))
    };
    if new.is_empty() && gone.is_empty() && chg.is_empty() && late.is_empty() {
        p(format!("No change {label}: the same {} in both views.", plural(after.len(), "finding")));
        if let Some(n) = note {
            p(n);
        }
        return Ok(o);
    }
    p(format!(
        "Changes {label}: {} new, {} gone, {} changed{}",
        new.len(),
        gone.len(),
        chg.len(),
        if late.is_empty() { String::new() } else { format!(" (and {} in sources first indexed after that time)", plural(late.len(), "finding")) }
    ));
    if let Some(n) = note {
        p(n);
    }
    let mut rows: Vec<(&str, String, String)> = vec![];
    rows.extend(new.iter().map(|f| ("NEW", describe(f), String::new())));
    rows.extend(gone.iter().map(|f| ("GONE", describe(f), String::new())));
    rows.extend(chg.iter().map(|(b, a)| ("CHANGED", describe(b), format!("{} -> {}", fstate(b), fstate(a)))));
    for (tag, d, extra) in rows {
        p(format!("  {}  {d}{}", ljust(tag, 7), if extra.is_empty() { String::new() } else { format!("  {extra}") }));
    }
    if !late.is_empty() {
        let places: HashSet<String> = late.iter().map(|f| place_id(f)).collect();
        p(format!(
            "  NEW (source first indexed after {})  {} in {}{}",
            fmtz(&t0),
            plural(late.len(), "finding"),
            plural(places.len(), "place"),
            if verbose { "" } else { "; br diff -v lists them; br hunt shows what is there now" }
        ));
        if verbose {
            for f in &late {
                p(format!("      {}", describe(f)));
            }
        }
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_time_needs_its_year() {
        assert!(has_year("2026-05-11"));
        assert!(has_year("2026-05-11T14:00Z"));
        assert!(!has_year("05-11T14:00Z"));
        assert!(!has_year("05-11"));
    }

    use super::*;

    fn pkg(name: &str, ver: &str, file: &str, eco: &str) -> Finding {
        Finding { kind: FKind::Repo, name: name.into(), version: ver.into(), file: file.into(), eco: eco.into(), state: "present".into(), ..Default::default() }
    }

    #[test]
    fn shlex_quote_matches_python() {
        assert_eq!(shquote("npm:name@1.2.3"), "npm:name@1.2.3");
        assert_eq!(shquote("a b"), "'a b'");
        assert_eq!(shquote("a*b"), "'a*b'");
        assert_eq!(shquote("x; rm -rf /"), "'x; rm -rf /'");
    }

    #[test]
    fn bump_runs_in_the_lockfile_directory_with_its_manager() {
        let fx = Some("1.2.4".to_string());
        let f = pkg("left-pad", "1.2.3", "package-lock.json", "npm");
        assert!(bump_cmds(&f, &fx).1.iter().any(|c| c == "npm install left-pad@1.2.4"), "{:?}", bump_cmds(&f, &fx));
        let mut sub = pkg("left-pad", "1.2.3", "services/api/pnpm-lock.yaml", "npm");
        sub.dev = true;
        let c = bump_cmds(&sub, &fx).1.join(" && ");
        assert!(c.contains("cd services/api") && c.contains("pnpm add -D left-pad@1.2.4"), "{c}");
        let y = pkg("x y", "1", "web/yarn.lock", "npm");
        let c = bump_cmds(&y, &fx).1.join(" && ");
        assert!(c.contains("cd web") && c.contains("'x y@1.2.4'"), "{c}");
        let g = pkg("example.com/m", "v1.0.0", "svc/go.sum", "go");
        let c = bump_cmds(&g, &fx).1.join(" && ");
        assert!(c.contains("cd svc") && c.contains("go get example.com/m@v1.2.4"), "{c}");
    }

    #[test]
    fn registry_delete_forms() {
        let mk = |image: &str| Finding { kind: FKind::Image, image: image.into(), digest: "sha256:ab".into(), tags: vec!["v1".into()], ..Default::default() };
        let v = View::default();
        let ix = Index::new(&v, "2026-05-11T00:00:00Z");
        let (c, _) = registry_delete_parts(&ix, &mk("ghcr.io/acme/web/api"), "sha256:ab");
        assert!(c.contains("--paginate") && c.contains("web%2Fapi") && c.contains("[ -n \"$id\" ]"), "{c}");
        assert!(registry_delete_parts(&ix, &mk("123456789012.dkr.ecr.eu-west-1.amazonaws.com/web"), "sha256:ab").0.starts_with("aws ecr batch-delete-image"));
        assert!(registry_delete_parts(&ix, &mk("europe-docker.pkg.dev/p/r/img"), "sha256:ab").0.starts_with("gcloud artifacts docker images delete"));
        assert!(registry_delete_parts(&ix, &mk("acme.azurecr.io/web"), "sha256:ab").0.starts_with("az acr repository delete"));
        let (c, n) = registry_delete_parts(&ix, &mk("registry.acme.io/web"), "sha256:ab");
        assert_eq!(c, "crane delete registry.acme.io/web@sha256:ab");
        assert!(n.is_some());
    }

    #[test]
    fn destructive_host_forms() {
        let h = Finding { kind: FKind::Host, where_: "dev-1".into(), loc: "/home/a/.npm/_cacache".into(), item_kind: "npm-cache".into(), ..Default::default() };
        let (pre, del) = destructive(&h, None).unwrap();
        assert!(pre.starts_with("tar czf evidence-dev-1-_cacache.tgz /home/a/.npm/_cacache && "), "{pre}");
        assert!(pre.contains("sha256sum"), "{pre}");
        assert_eq!(del, "npm cache clean --force");
        let (pre, del) = destructive(&h, Some("ssh")).unwrap();
        assert!(pre.starts_with("ssh dev-1 'sudo -u a -H tar czf - /home/a/.npm/_cacache' > evidence-dev-1-_cacache.tgz"), "{pre}");
        assert_eq!(del, "ssh dev-1 'sudo -u a -H npm cache clean --force'");
        assert!(wider_note(&h).unwrap().starts_with("wider than the finding: npm cache clean"));
        let sp = Finding { kind: FKind::Host, where_: "h".into(), loc: "/Users/John Smith/x".into(), item_kind: "dir".into(), ..Default::default() };
        assert!(destructive(&sp, None).unwrap().0.contains("'/Users/John Smith/x'"));
        let w = Finding { kind: FKind::Host, where_: "win-1".into(), loc: "C:\\Users\\a\\AppData\\evil-dir".into(), item_kind: "dir".into(), ..Default::default() };
        let (pre, _) = destructive(&w, Some("ssh")).unwrap();
        assert!(pre.contains("Compress-Archive -LiteralPath"), "{pre}");
    }

    #[test]
    fn cache_delete_is_by_exact_key_and_quoted() {
        let c = Finding { kind: FKind::Cache, where_: "acme/web".into(), key: "npm cache; x".into(), ..Default::default() };
        let (pre, del) = destructive(&c, None).unwrap();
        assert!(pre.contains("--limit 1000") && pre.contains("'npm cache; x'"), "{pre}");
        assert_eq!(del, "gh cache delete 'npm cache; x' -R acme/web");
    }

    #[test]
    fn a_rebuild_is_a_command_only_with_dispatch_and_never_a_rerun() {
        use crate::view::{Repo, Run, Workflow};
        let mut v = View::default();
        let mk = |dispatch: bool| Repo {
            workflows: vec![Workflow { file: ".github/workflows/build-image.yml".into(), dispatch, ..Default::default() }],
            runs: vec![Run { id: 7, workflow: "Build image".into(), path: Some(".github/workflows/build-image.yml".into()), ..Default::default() }],
            ..Default::default()
        };
        v.repos.insert("acme/web".into(), mk(true));
        v.repos.insert("acme/api".into(), mk(false));
        let ix = Index::new(&v, "2026-05-11T00:00:00Z");
        assert!(dispatch_cmd(&ix, "acme/web", 7).unwrap().starts_with("gh workflow run build-image.yml -R acme/web"));
        assert_eq!(dispatch_cmd(&ix, "acme/api", 7), None);
    }

    #[test]
    fn known_at_rewinds_from_scan_history() {
        let mut v = View::default();
        let src = |t: &str| Source { kind: "repo".into(), reach: "github".into(), indexed_at: t.into(), empty: false, gaps: vec![] };
        v.sources.insert("a/x".into(), src("2026-05-10T10:00:00Z"));
        v.sources.insert("a/y".into(), src("2026-05-10T10:00:00Z"));
        v.state.last_scan = Some(serde_json::json!({"at": "2026-05-10T10:00:00Z", "before": {"a/x": "2026-05-09T10:00:00Z"}}));
        let ix = Index::new(&v, "2026-05-11T00:00:00Z");
        let k = known_at(&ix, "2026-05-09T12:00:00Z");
        assert_eq!(k.keys().collect::<Vec<_>>(), vec!["a/x"]);
        assert_eq!(k["a/x"].indexed_at, "2026-05-09T10:00:00Z");
        assert_eq!(known_at(&ix, "2026-05-10T12:00:00Z").len(), 2);
    }

    #[test]
    fn base_image_from_annotations_or_shared_layers_never_from_text() {
        use crate::view::Layer;
        let ly = |d: &[&str]| {
            d.iter().enumerate().map(|(n, x)| Layer { n: n as u32, diff_id: Some(x.to_string()), created_by: Some("FROM ghcr.io/lie/base:1".into()), ..Default::default() }).collect::<Vec<_>>()
        };
        let base = ImageBuild { repository: "ghcr.io/acme/base".into(), digest: "sha256:b".into(), layers: ly(&["sha256:1", "sha256:2"]), ..Default::default() };
        let app = ImageBuild { repository: "ghcr.io/acme/app".into(), digest: "sha256:a".into(), layers: ly(&["sha256:1", "sha256:2", "sha256:3"]), ..Default::default() };
        let named = ImageBuild { repository: "x".into(), base_name: Some("ghcr.io/acme/other:2".into()), ..Default::default() };
        let mut v = View::default();
        v.images = vec![base.clone(), app.clone()];
        let idx = BaseIdx::new(&v);
        assert_eq!(base_of(&idx, Some(&app)).as_deref(), Some("ghcr.io/acme/base"));
        assert_eq!(base_of(&idx, Some(&base)), None);
        assert_eq!(base_of(&idx, Some(&named)).as_deref(), Some("ghcr.io/acme/other"));
        assert_eq!(base_of(&idx, None), None);
    }

    #[test]
    fn plans_group_a_transitive_under_its_parent_only_with_proof() {
        let mut v = View::default();
        v.sources.insert("a/x".into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: "2026-05-10T10:00:00Z".into(), empty: false, gaps: vec![] });
        let ix = Index::new(&v, "2026-05-11T00:00:00Z");
        let mut direct = pkg("parent", "1.0.0", "package-lock.json", "npm");
        direct.where_ = "a/x".into();
        direct.direct = true;
        direct.p = Some("npm:parent@1.0.0".into());
        let mut child = pkg("child", "1.0.0", "package-lock.json", "npm");
        child.where_ = "a/x".into();
        child.via = vec!["parent".into()];
        child.p = Some("npm:child@1.0.0".into());
        let fs = vec![&direct, &child];
        let plans = repo_plans(&ix, &fs, &Some("1.0.1".into()));
        assert_eq!(plans.len(), 1);
        let pl = &plans[0].1;
        assert_eq!((pl[0].kind, pl[1].kind), (PK::Bump, PK::Override));
        assert_eq!(pl[1].after.as_deref(), Some("parent"));
    }
}

#[cfg(test)]
mod r6_diff_tests {
    use super::*;
    use crate::view::{Commit, Repo, State};

    const NOW: &str = "2026-10-01T00:00:00Z";

    fn view() -> View {
        let mut v = View { now: NOW.into(), ..Default::default() };
        for (n, t) in [("acme/a", "2026-09-20T00:00:00Z"), ("acme/b", "2026-09-20T00:00:00Z"), ("acme/c", "2026-09-20T00:00:00Z")] {
            v.sources.insert(n.into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: t.into(), ..Default::default() });
        }
        // a was rescanned and has a new commit; b was rescanned and holds nothing new; c was not rescanned
        v.repos.insert("acme/a".into(), Repo { commits: vec![Commit { sha: "1".into(), at: "2026-09-15T00:00:00Z".into(), ..Default::default() }], ..Default::default() });
        v.repos.insert("acme/b".into(), Repo::default());
        v.repos.insert("acme/c".into(), Repo::default());
        v.state = State { scans: vec![serde_json::json!({"at": "2026-09-20T00:00:00Z", "before": {"acme/a": "2026-09-10T00:00:00Z", "acme/b": "2026-09-10T00:00:00Z"}})], ..Default::default() };
        v
    }

    // The earliest time with an index is the earliest a source was ever indexed
    #[test]
    fn the_earliest_valid_since_is_the_first_time_a_source_was_indexed() {
        let v = view();
        let ix = Index::new(&v, NOW);
        assert_eq!(earliest_index_time(&ix).as_deref(), Some("2026-09-10T00:00:00Z"));
    }

    // The header counts what its lines show: a source that was only re-indexed is not "gained something"
    #[test]
    fn the_diff_header_counts_agree_with_its_lines() {
        let v = view();
        let ix = Index::new(&v, NOW);
        let old = known_at(&ix, "2026-09-12T00:00:00Z");
        let (changed, quiet, fresh) = source_changes(&ix, &old, &None);
        assert_eq!(changed.len(), 2);
        assert_eq!((quiet, fresh.len()), (0, 1));
        assert_eq!(changed.iter().filter(|(_, t)| t.as_slice() != ["re-indexed, nothing new"]).count(), 1);
    }

    // --owner/--repo narrow which sources a diff counts
    #[test]
    fn a_scope_narrows_the_sources_a_diff_counts() {
        let v = view();
        let ix = Index::new(&v, NOW);
        let old = known_at(&ix, "2026-09-12T00:00:00Z");
        let scope: Option<HashSet<String>> = Some(["acme/a".to_string()].into());
        let (changed, quiet, _) = source_changes(&ix, &old, &scope);
        assert_eq!((changed.len(), quiet), (1, 0));
        assert_eq!(changed[0].0, "acme/a");
    }
}
