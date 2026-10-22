//! The hunt engine: answers an indicator query from the index view. No rendering here.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use regex::Regex;

use super::index::{parse_pkg, CommitRef, Index, LockObs};
use super::iocs::{self as I, Ioc, IocKind, ResolvedAdvisory};
use super::util::{basename, dirname, fmt, is_stale, plural};
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::view::*;

pub const KINDS: [&str; 7] = ["repos", "ci", "caches", "artifacts", "images", "hosts", "releases"];

#[derive(Debug, Clone)]
pub struct Query {
    pub iocs: Vec<Ioc>,
    pub adv: Option<ResolvedAdvisory>,
    pub window: Option<(String, String)>,
    pub window_src: Option<String>,
    pub now_only: bool,
    pub only: BTreeSet<String>,
    pub repo: Option<String>,
    pub host: Option<String>,
    pub owner: Option<String>,
    pub near: bool,
    pub secrets: bool,
    pub history: bool,
    pub yara: bool,
    /// Hashes an advisory marks benign: (indicator, advisory id, why)
    pub benign: Vec<(String, String, String)>,
    /// Ties between a sha256 indicator and a file name that the input gave (advisory text, a note, an affected
    /// package's files): (indicator text, file name). Used only for the "not a match" hint on a zero-hit hash.
    pub hash_names: Vec<(String, String)>,
    /// The query runs on a throwaway index of one checkout (`hunt --path`): gaps are only for what it reads
    pub checkout: bool,
    /// Run the similarity pass on the files that came with a hash hit (`--similar-related`)
    pub similar_related: bool,
    /// `--since DATE`, the rotation cutoff of a `secret:NAME` question
    pub since: Option<String>,
}

impl Default for Query {
    fn default() -> Self {
        Query {
            iocs: vec![],
            adv: None,
            window: None,
            window_src: None,
            now_only: false,
            only: KINDS.iter().map(|s| s.to_string()).collect(),
            repo: None,
            host: None,
            owner: None,
            near: false,
            secrets: true,
            history: false,
            yara: false,
            benign: vec![],
            hash_names: vec![],
            checkout: false,
            similar_related: false,
            since: None,
        }
    }
}

impl Query {
    pub fn has(&self, kind: &str) -> bool {
        self.only.contains(kind)
    }
}

/// A point event inside the window.
pub fn in_window_pt(q: &Query, t: &str) -> bool {
    match &q.window {
        None => true,
        Some((a, b)) => !t.is_empty() && a.as_str() <= t && t <= b.as_str(),
    }
}

/// An interval; `end` None = still present.
pub fn in_window_iv(q: &Query, start: &str, end: Option<&str>) -> bool {
    match &q.window {
        None => true,
        Some((a, b)) => !start.is_empty() && start <= b.as_str() && end.is_none_or(|e| e > a.as_str()),
    }
}

#[derive(Debug, Clone, Default)]
pub struct Owner {
    /// The first team that owns it; `also` holds the other teams CODEOWNERS names on the same rule.
    pub team: Option<String>,
    pub also: Vec<String>,
    pub people: Vec<String>,
    /// Set when CODEOWNERS names nothing br can resolve and `people` holds the suggested owner instead; the reason
    /// the person was suggested ("archived it 03-02", "last committer 04-11", "org admin").
    pub suggested: Option<String>,
}

impl Owner {
    pub fn teams(&self) -> impl Iterator<Item = &String> {
        self.team.iter().chain(self.also.iter())
    }

    pub fn is_empty(&self) -> bool {
        self.team.is_none() && self.also.is_empty() && self.people.is_empty()
    }

    fn of(c: super::index::CoOwners) -> Owner {
        let mut t = c.teams.into_iter();
        Owner { team: t.next(), also: t.collect(), people: c.people, suggested: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FKind {
    #[default]
    Repo,
    CiRun,
    Cache,
    Artifact,
    Image,
    Host,
    ReleaseAsset,
    WorkflowRef,
}

impl FKind {
    pub fn name(&self) -> &'static str {
        match self {
            FKind::Repo => "repo",
            FKind::CiRun => "ci_run",
            FKind::Cache => "cache",
            FKind::Artifact => "artifact",
            FKind::Image => "image",
            FKind::Host => "host",
            FKind::ReleaseAsset => "release_asset",
            FKind::WorkflowRef => "workflow_ref",
        }
    }
}

/// What a certificate finding adds to the place it sits in (an image layer, a host, a repo file).
#[derive(Debug, Clone, Default)]
pub struct CertHit {
    pub fp: String,
    pub subject: String,
    pub issuer: String,
    pub not_after: Option<String>,
    /// a root (it signed itself); otherwise an intermediate
    pub root: bool,
    /// the trust store file
    pub file: String,
    /// `system` (an OS bundle), `certifi`, `java`, `file`, or `repo file`
    pub store: String,
    /// only a deleted layer still holds it
    pub deleted: bool,
}

/// One finding. A flat record: each kind uses its own fields (see the constructors below).
#[derive(Debug, Clone, Default)]
pub struct Finding {
    /// Set on a finding of a certificate in a trust store
    pub cert: Option<CertHit>,
    pub kind: FKind,
    pub ioc: String,
    pub iocs: Vec<String>,
    pub where_: String,
    pub state: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub removed_at: Option<String>,
    pub secrets: Vec<String>,
    pub run_ids: Vec<u64>,
    pub carried_by: Option<String>,
    pub owner: Owner,
    pub possible: bool,
    /// A possible row that names a person (no machine of theirs is scanned), not a machine
    pub person: bool,
    pub past_run: bool,
    pub inferred: bool,
    pub reason: String,
    pub note: String,
    pub source: String,
    pub location: String,
    // repo
    pub file: String,
    pub version: String,
    pub depth: String,
    pub via: Vec<String>,
    pub name: String,
    pub explain: String,
    pub p: Option<String>,
    pub added_by: Option<CommitRef>,
    pub removed_by: Option<CommitRef>,
    // ci_run
    pub id: u64,
    pub at: String,
    pub runner: String,
    pub workflow: String,
    pub resolved_from: String,
    // cache / artifact
    pub key: String,
    pub created: String,
    pub last_used: Option<String>,
    pub size_mb: Option<u64>,
    pub expires: String,
    /// the artifact has no recorded expiry: br cannot say it expired (A2 #24)
    pub expires_unknown: bool,
    // image
    pub image: String,
    pub tags: Vec<String>,
    pub digest: String,
    pub built: String,
    pub from_repo: Option<String>,
    pub commit: Option<String>,
    pub where_in: String,
    pub layer: u32,
    pub layer_cmd: Option<String>,
    pub deleted_in: Option<u32>,
    pub path: String,
    // host
    pub loc: String,
    pub item_kind: String,
    pub sim: Option<f64>,
    pub match_: String,
    pub sha256: String,
    pub item_pkgs: Vec<String>,
    /// The packages of the item that the indicator matched (`eco:name@version`), so a plan removes those and no more
    pub hit_pkgs: Vec<String>,
    pub rule: Option<String>,
    // release asset
    pub tag: String,
    pub asset: String,
    pub published: String,
    // workflow ref
    pub ref_: String,
    pub ref_kind: String,
    pub runs: String,
    pub uses: String,
    // for actions: what a finding carries besides the above
    pub eco: String,
    pub direct: bool,
    pub dev: bool,
    pub archived: bool,
    pub manifest_path: Option<String>,
    pub manifest_line: Option<u32>,
    pub composite: bool,
    /// the run a finding came from: an install-only package (with `run_runner`) or an image build
    pub run_id: Option<u64>,
    pub run_runner: String,
    /// image: the compressed blob digest of the layer the hit sits in (what a registry deletes by)
    pub layer_blob: Option<String>,
    /// who owns it, as the tables print it: a team the index knows, `@login`, or `unresolved`
    pub owner_label: String,
    /// The repo a runner-host finding belongs to (its checkout under `_work`, or the repo whose run installed it)
    pub workspace_repo: Option<String>,
    /// The owner of `workspace_repo` (what `owner_label` shows); `owner` stays the host's owner
    pub workspace_owner: Option<Owner>,
    /// The layer whose `created_by` ran a path that this finding holds (`RUN /opt/tools/x`), the build-time execution
    pub executed_in_layer: Option<u32>,
    /// The CI runs (`repo#id`) that installed the package on this runner: with one, the install ran here
    pub ci_installs: Vec<String>,
    /// A similarity hit that is boilerplate (a package manifest, an OS file): listed, but last and never planned
    pub boilerplate: bool,
    /// The related file (a file that came with the hit) this similarity hit resembles
    pub like_file: String,
    /// For a runtime hit, which version was seen, where, and how its line is fixed
    pub rt: Option<RtInfo>,
}

/// What a runtime finding says beyond the place: the version, how it was seen, the fix on its line.
#[derive(Debug, Clone, Default)]
pub struct RtInfo {
    pub runtime: String,
    pub version: String,
    pub seen_as: String,
    /// the release that fixes this version's line (None: end of life, or the indicator names no fix)
    pub line_fixed: Option<String>,
    pub eol: bool,
    /// end of life: the lowest listed fix above the version
    pub move_to: Option<String>,
}

/// A runtime named by a floating tag or spec ("php:8.3-apache", "node-version: 22"): not found, not clear.
#[derive(Debug, Clone, Default)]
pub struct Floating {
    pub repo: String,
    pub file: String,
    pub line: usize,
    pub runtime: String,
    pub spec: String,
    pub seen_as: String,
    pub first_seen: Option<String>,
    pub ioc: String,
}

impl Finding {
    pub fn new(kind: FKind, ioc: &Ioc, where_: &str) -> Finding {
        Finding { kind, ioc: ioc.text.clone(), where_: where_.to_string(), ..Default::default() }
    }

    pub fn iocs_or_one(&self) -> Vec<String> {
        if self.iocs.is_empty() {
            vec![self.ioc.clone()]
        } else {
            self.iocs.clone()
        }
    }
}

// ---- owners and scope --------------------------------------------------------------------------
pub fn host_owner(ix: &Index, host: &str) -> Owner {
    match ix.host_def(host) {
        Some(h) if h.owner_team.as_deref().is_some_and(|t| !t.is_empty()) => Owner { team: h.owner_team.clone(), ..Default::default() },
        Some(h) if h.owner.as_deref().is_some_and(|t| !t.is_empty()) => Owner { people: vec![h.owner.clone().unwrap()], ..Default::default() },
        _ => Owner::default(),
    }
}

/// The owner as every table prints it: a team the index knows (GitHub or teams.yaml), else `@login`, else `unresolved`.
/// A team that only a CODEOWNERS line names is never shown as a team.
pub fn owner_name(ix: &Index, o: &Owner) -> String {
    if let (Some(why), Some(p)) = (&o.suggested, o.people.first()) {
        return format!("@{p} (suggested: {why})");
    }
    if let Some(t) = &o.team {
        return if ix.team_ids().contains(&t.as_str()) { t.clone() } else { "unresolved".into() };
    }
    if let Some(p) = o.people.first() {
        return format!("@{p}");
    }
    "unresolved".into()
}

/// Every owner `owner_name` would stand behind, for a row that can have more than one (a secret read by two teams' runs):
/// each team the index knows when CODEOWNERS names teams (none when it names only ones GitHub does not resolve), else the
/// person (the suggested one too). Empty is `unresolved`. For one owner it is exactly `owner_name`'s answer.
pub fn owner_names(ix: &Index, o: &Owner) -> Vec<String> {
    if o.suggested.is_some() && !o.people.is_empty() {
        return vec![format!("@{}", o.people[0])];
    }
    if o.team.is_some() {
        let ids = ix.team_ids();
        return o.teams().filter(|t| ids.contains(&t.as_str())).cloned().collect();
    }
    o.people.first().map(|p| vec![format!("@{p}")]).unwrap_or_default()
}

pub fn owner_for(ix: &Index, f: &Finding) -> Owner {
    if f.kind == FKind::Host {
        // The host's owner stays the owner of the host (the cleanup on the machine); who owns the finding in a
        // runner's workspace is `workspace_owner`, which the tables show and the plans route to
        return host_owner(ix, &f.where_);
    }
    let mut repo = f.where_.clone();
    if f.kind == FKind::Image {
        if let Some(r) = f.from_repo.as_ref().filter(|r| !r.is_empty()) {
            repo = r.clone();
        }
    }
    repo_owner_suggested(ix, &repo, if f.kind == FKind::Repo { Some(f.file.as_str()) } else { None })
}

/// The repo a host finding belongs to: the checkout it sits in (`.../_work/<repo>/...`), the repo recorded on the
/// finding, or the one repo whose runs installed the package on that runner.
pub fn workspace_repo(ix: &Index, f: &Finding) -> Option<String> {
    if let Some(r) = f.workspace_repo.as_ref().filter(|r| ix.v.repos.contains_key(r.as_str())) {
        return Some(r.clone());
    }
    if let Some(seg) = work_segment(&f.loc) {
        let hits: Vec<String> = ix.names("repo").into_iter().filter(|n| n.rsplit('/').next().is_some_and(|s| s.eq_ignore_ascii_case(&seg))).collect();
        if hits.len() == 1 {
            return hits.into_iter().next();
        }
    }
    if f.item_pkgs.is_empty() {
        return None;
    }
    let runs = ix.runs_by_runner().get(&super::index::runner_key(&f.where_))?;
    let mut repos: BTreeSet<&str> = BTreeSet::new();
    for (r, run) in runs {
        if run.installed.iter().any(|p| f.item_pkgs.contains(p)) {
            repos.insert(*r);
        }
    }
    if repos.len() == 1 {
        repos.into_iter().next().map(str::to_string)
    } else {
        None
    }
}

/// The owner of the repo a runner-host finding belongs to (see `workspace_repo`): the team that fixes the repo and
/// rotates what its runs could read. None when no repo can be named or its owner cannot be told.
pub fn workspace_owner(ix: &Index, f: &Finding) -> Option<Owner> {
    let r = workspace_repo(ix, f)?;
    let o = repo_owner_suggested(ix, &r, None);
    (!o.is_empty() && owner_name(ix, &o) != "unresolved").then_some(o)
}

/// The directory name under a runner's `_work` that a path sits in: `/srv/actions/_work/web/web/node_modules` -> `web`.
fn work_segment(path: &str) -> Option<String> {
    let rest = path.split("/_work/").nth(1)?;
    let seg = rest.split('/').next()?;
    if seg.is_empty() || seg.starts_with('_') {
        None
    } else {
        Some(seg.to_string())
    }
}

/// When CODEOWNERS names a team GitHub does not resolve, the sentence that says so (the owner shown is then the suggested one).
pub fn codeowners_note(ix: &Index, o: &Owner) -> Option<String> {
    let teams: Vec<&String> = o.teams().filter(|t| !ix.is_team(t.as_str())).collect();
    if teams.is_empty() || o.team.is_none() {
        return None;
    }
    Some(format!("CODEOWNERS names {}, which GitHub does not resolve", teams.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", ")))
}

/// `repo_owner`, and when CODEOWNERS names nothing br can resolve, the suggested owner.
pub fn repo_owner_suggested(ix: &Index, repo: &str, path: Option<&str>) -> Owner {
    let key = (repo.to_string(), path.unwrap_or_default().to_string());
    if let Some(o) = ix.owner_sugg.borrow().get(&key) {
        return o.clone();
    }
    let o = repo_owner_suggested_uncached(ix, repo, path);
    ix.owner_sugg.borrow_mut().insert(key, o.clone());
    o
}

fn repo_owner_suggested_uncached(ix: &Index, repo: &str, path: Option<&str>) -> Owner {
    let mut o = repo_owner(ix, repo, path);
    if owner_name(ix, &o) == "unresolved" {
        if let Some((login, why)) = super::index::suggested_owner(ix, repo) {
            o.people = vec![login];
            o.suggested = Some(why);
        }
    }
    o
}

/// Who owns a repo (at `path`, or at its lockfile): every owner of the last matching CODEOWNERS rule.
pub fn repo_owner(ix: &Index, repo: &str, path: Option<&str>) -> Owner {
    if !ix.v.repos.contains_key(repo) {
        return Owner::default();
    }
    let path = match path {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => ix.lockfile(repo).unwrap_or_default(),
    };
    Owner::of(ix.owners_of(repo, &path))
}

/// Every full sha256 the index holds that starts with `prefix`.
pub fn hash_prefix_matches(ix: &Index, prefix: &str) -> Vec<String> {
    let p = prefix.to_lowercase();
    let mut found = BTreeSet::new();
    let mut see = |h: &str| {
        if !h.is_empty() && h.starts_with(&p) {
            found.insert(h.to_string());
        }
    };
    for h in ix.names("host") {
        for it in ix.host_items(&h) {
            it.files.iter().for_each(|f| see(&f.sha256));
        }
    }
    for b in ix.images() {
        for l in &b.layers {
            l.files.iter().for_each(|f| see(&f.sha256));
        }
    }
    for r in ix.names("repo") {
        for rel in ix.releases(&r) {
            rel.assets.iter().for_each(|a| see(&a.sha256));
        }
    }
    found.into_iter().collect()
}

pub fn owner_spec(ix: &Index, q: &Query) -> BrResult<Option<super::index::OwnerSpec>> {
    let Some(o) = q.owner.as_ref().filter(|o| !o.is_empty()) else { return Ok(None) };
    match ix.resolve_owner(o) {
        Some(rs) => Ok(Some(rs)),
        None if !ix.ambiguous_owner(o).is_empty() => {
            Err(BrError::new(format!("\"{o}\" is ambiguous: it could be {}", ix.ambiguous_owner(o).join(", ")), Some("write the full team (@org/team) or the exact login (@login)")))
        }
        None => {
            let teams: Vec<String> = ix.team_ids().iter().map(|t| format!("{} ({t})", t.rsplit('/').next().unwrap_or(t))).collect();
            let hint = if teams.is_empty() {
                "an owner is a team or a person".to_string()
            } else {
                let ex = ix.team_ids().first().map(|t| format!("{t} or {}", t.rsplit('/').next().unwrap_or(t))).unwrap_or_default();
                format!("an owner is a team ({ex}) or a person (a login such as @login, or a full name). Teams: {}", teams.join(", "))
            };
            Err(BrError::new(format!("unknown owner \"{o}\""), Some(&hint)))
        }
    }
}

pub fn owner_match(ix: &Index, rs: &super::index::OwnerSpec, o: &Owner) -> bool {
    if o.teams().any(|t| rs.teams.contains(t)) {
        return true;
    }
    for p in &o.people {
        if !rs.is_team {
            if rs.people.iter().any(|x| x.eq_ignore_ascii_case(p)) {
                return true;
            }
        } else if ix.person_team_ids(p).iter().any(|t| rs.teams.contains(t)) {
            return true;
        }
    }
    false
}

pub fn scope_sources(ix: &Index, q: &Query) -> BrResult<Vec<String>> {
    if ix.srcs.is_empty() {
        return Err(BrError::with_code(
            "NO DATA: the index has no sources, so nothing can be said either way",
            Some(&format!("run br init --org ORG (needs {}) or br init --path DIR, then hunt again", crate::collect::words::TOKEN_WORDS)),
            5,
        ));
    }
    let hint_all = "br status --all lists what is indexed";
    if let Some(r) = q.repo.as_ref().filter(|r| !r.is_empty()) {
        // --repo also scopes the images built from the repo, which can be a repo that is not itself indexed
        let builds_images = q.has("images") && ix.images().iter().any(|b| b.source.as_ref().and_then(|s| s.repo.as_deref()) == Some(r.as_str()));
        if ix.kind_of(r) != "repo" && !builds_images {
            return Err(BrError::new(format!("{r} is not an indexed repo, so this scope would search nothing"), Some(hint_all)));
        }
    }
    if let Some(h) = q.host.as_ref().filter(|r| !r.is_empty()) {
        if ix.kind_of(h) != "host" {
            return Err(BrError::new(
                format!("{h} is not an indexed host, so this scope would search nothing"),
                Some(&format!("{hint_all}; a machine joins the index with br scan --local --export H.brx there, then br import H.brx here")),
            ));
        }
    }
    let rs = owner_spec(ix, q)?;
    let mut out = vec![];
    for (n, s) in &ix.srcs {
        let k = s.kind.as_str();
        if k == "repo" && !["repos", "ci", "caches", "artifacts", "releases"].iter().any(|x| q.has(x)) {
            continue;
        }
        if k == "registry" && !q.has("images") {
            continue;
        }
        if k == "host" && !q.has("hosts") {
            continue;
        }
        if let Some(r) = q.repo.as_ref().filter(|r| !r.is_empty()) {
            if k == "host" || (k == "repo" && n != r) {
                continue;
            }
        }
        if let Some(h) = q.host.as_ref().filter(|r| !r.is_empty()) {
            if k != "host" || n != h {
                continue;
            }
        }
        if let Some(rs) = &rs {
            if k == "repo" && !ix.lock_paths(n).iter().map(|p| Some(p.as_str())).chain(std::iter::once(None)).any(|p| owner_match(ix, rs, &repo_owner_suggested(ix, n, p))) {
                continue;
            }
            if k == "host" && !owner_match(ix, rs, &host_owner(ix, n)) {
                continue;
            }
        }
        out.push(n.clone());
    }
    let has = |o: &Option<String>| o.as_ref().is_some_and(|x| !x.is_empty());
    // A registry source holds the images built from --repo, so `--repo X --only images` is a scope that can hold X
    let images_by_repo = has(&q.repo) && !has(&q.host) && q.has("images") && out.iter().any(|n| ix.kind_of(n) == "registry");
    if (has(&q.repo) || has(&q.host) || has(&q.owner)) && !images_by_repo && !out.iter().any(|n| ix.kind_of(n) != "registry") {
        let mut what = vec![];
        for (k, v) in [("repo", &q.repo), ("host", &q.host), ("owner", &q.owner)] {
            if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
                what.push(format!("--{k} {v}"));
            }
        }
        return Err(BrError::new(
            format!("nothing in the index matches {}, so this scope would search nothing", what.join(" ")),
            Some(&format!("{hint_all}; combine it only with --only sections that can hold it")),
        ));
    }
    Ok(out)
}

pub fn stale_now(ix: &Index, name: &str) -> bool {
    is_stale(&ix.now, &ix.it(name))
}

/// A window whose end is at or after everything the index holds.
/// Decided per source in `coverage`: the window end is "now" when it is at or after the clock the
/// index runs on. A source indexed before the window end is partial unless that holds (A2 #15).
pub fn window_ends_now(ix: &Index, q: &Query, _names: &[String]) -> bool {
    super::coverage::window_ends_now(ix, q)
}

#[derive(Debug, Clone, Default)]
pub struct Gap {
    pub name: String,
    pub indexed_at: String,
    pub kind: String,
    pub reach: Option<String>,
    pub stale: bool,
    pub empty: bool,
    pub partial: bool,
    pub window_end: Option<String>,
    /// The window ends at or after the index time, so "partial" means stale
    pub window_ends_now: bool,
    /// commits whose time could not be read; they are left out of every window
    pub undated: usize,
}

pub fn coverage(ix: &Index, q: &Query, names: &[String], _ends_now: bool, confirmed: &HashSet<String>) -> (Vec<Gap>, Vec<Gap>) {
    let (mut stale, mut gaps) = (vec![], vec![]);
    let index_time = super::coverage::index_time(ix);
    for n in names {
        let t = ix.it(n);
        let st = stale_now(ix, n);
        // A source is a gap when it could not have seen the window, whichever word the row then uses (a stale source
        // says "stale"; a source scanned inside a past window but before its end says "partial")
        let state = super::coverage::coverage_state(ix, q, n, confirmed.contains(n), index_time.as_deref());
        let win_gap = state != super::coverage::CoverageState::Full;
        // the word follows the question: a window makes a source "partial"; with no window, a stale source is just stale
        let partial = state == super::coverage::CoverageState::Partial && q.window.is_some();
        let ends_now = super::coverage::window_ends_now(ix, q);
        let empty = ix.srcs[n].empty;
        let d = Gap {
            name: n.clone(),
            indexed_at: t,
            kind: ix.srcs[n].kind.clone(),
            reach: Some(ix.srcs[n].reach.clone()),
            stale: st,
            empty,
            partial,
            window_end: q.window.as_ref().map(|w| w.1.clone()),
            window_ends_now: ends_now,
            undated: if ix.srcs[n].kind == "repo" { ix.repo(n).commits.iter().filter(|c| c.at.is_empty()).count() } else { 0 },
        };
        if st {
            stale.push(d.clone());
        }
        if st || win_gap || partial || empty || d.undated > 0 {
            gaps.push(d);
        }
    }
    (stale, gaps)
}

/// Source kinds that matter for this query but that the index has never held.
pub fn never_indexed(ix: &Index, q: &Query) -> Vec<(String, String)> {
    // A checkout reads its own lockfiles and files; registries, runners and laptops are not part of that question
    if q.checkout {
        return vec![];
    }
    let kinds: BTreeSet<IocKind> = BTreeSet::new();
    let _ = kinds;
    let has_kind = |ks: &[IocKind]| q.iocs.iter().any(|i| ks.contains(&i.kind));
    let mut need: Vec<&str> = vec![];
    if q.host.as_ref().is_some_and(|h| !h.is_empty()) {
        need.push("host");
    } else {
        if ["repos", "ci", "caches", "artifacts", "releases"].iter().any(|x| q.has(x)) {
            need.push("repo");
        }
        if q.has("images") && has_kind(&[IocKind::Pkg, IocKind::Sha256, IocKind::Cert]) {
            need.push("registry");
        }
        if q.has("hosts") && q.repo.as_ref().is_none_or(|r| r.is_empty()) && q.iocs.iter().any(|i| i.kind != IocKind::ActionRef) {
            need.push("host");
        }
    }
    let label = |k: &str| match k {
        "repo" => "repos",
        "registry" => "container registries",
        _ => "hosts",
    };
    need.into_iter().filter(|k| !ix.has_kind(k)).map(|k| (k.to_string(), label(k).to_string())).collect()
}

pub fn close_command(kind: &str, name: &str, reach: Option<&str>) -> String {
    match kind {
        "repo" => format!("br scan --repo {name}"),
        "registry" => format!("br scan --registry {name}"),
        "host" => {
            if matches!(reach, Some("import-only") | Some("local")) {
                format!("on {name}: br scan --local --export {name}.brx   then here: br import {name}.brx")
            } else {
                format!("br scan --host {name}")
            }
        }
        _ => "br scan --stale".to_string(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct NotChecked {
    pub name: String,
    pub kind: String,
    pub state: String,
    pub why: String,
    pub indexed_at: Option<String>,
    pub command: String,
    pub people: Vec<String>,
}

/// The registry host an index's images and CI builds name: the first path segment when it looks like a host, else docker.io.
fn registry_host(ix: &Index) -> Option<String> {
    let first = ix.v.images.first().map(|b| b.repository.clone()).or_else(|| ix.v.repos.values().flat_map(|r| r.runs.iter()).flat_map(|r| r.produced_images.iter()).next().cloned())?;
    let seg = first.split('/').next().unwrap_or("");
    Some(if first.contains('/') && (seg.contains('.') || seg.contains(':') || seg == "localhost") { seg.to_string() } else { "docker.io".to_string() })
}

pub fn never_command(ix: &Index, kind: &str) -> String {
    match kind {
        "registry" => {
            let host = registry_host(ix).unwrap_or_else(|| "HOST".to_string());
            format!("br scan --registry {host}   (reads the docker credential store; run docker login {host} first)")
        }
        "repo" => format!("br init --org ORG   (needs {})", crate::collect::words::TOKEN_WORDS),
        _ => "on each machine: br scan --local --export HOST.brx   then here: br import HOST.brx".to_string(),
    }
}

/// A gap that exists only because of undated commits has no window problem.
fn win_gap_like(g: &Gap) -> bool {
    g.stale || g.partial || g.empty || g.window_end.as_deref().is_some_and(|w| g.indexed_at.as_str() < w)
}

pub fn not_checked_rows(ix: &Index, gaps: &[Gap], never: &[(String, String)]) -> Vec<NotChecked> {
    let mut rows = vec![];
    for g in gaps {
        // A registered host that was never scanned is one row (source_gap_rows says so), not an "empty" scan too
        if ix.srcs.get(&g.name).is_some_and(crate::collect::words::never_scanned) {
            continue;
        }
        let undated = if g.undated > 0 { format!("{} commit(s) have no readable timestamp and were not checked", g.undated) } else { String::new() };
        let why = if g.empty {
            match g.kind.as_str() {
                "registry" => "its last scan listed 0 images".to_string(),
                "repo" => "its last scan read nothing".to_string(),
                _ => "its last scan hashed 0 files".to_string(),
            }
        } else if g.partial && g.window_ends_now {
            format!("partial: indexed {}, stale while the window ends now", fmt(&g.indexed_at))
        } else if g.partial {
            format!("partial: indexed {}, before the window ends {}{}", fmt(&g.indexed_at), fmt(g.window_end.as_deref().unwrap_or("")), if g.stale { "; also stale" } else { "" })
        } else if g.stale {
            format!("stale: indexed {}", fmt(&g.indexed_at))
        } else if g.undated > 0 && !win_gap_like(g) {
            undated.clone()
        } else {
            format!("indexed {}, before the window starts", fmt(&g.indexed_at))
        };
        rows.push(NotChecked {
            name: g.name.clone(),
            kind: g.kind.clone(),
            state: if g.empty {
                "empty"
            } else if g.partial {
                "partial"
            } else if g.undated > 0 && !win_gap_like(g) {
                "undated"
            } else {
                "stale"
            }
            .to_string(),
            why,
            indexed_at: Some(g.indexed_at.clone()),
            command: close_command(&g.kind, &g.name, g.reach.as_deref()),
            people: vec![],
        });
    }
    for (k, label) in never {
        rows.push(NotChecked {
            name: label.clone(),
            kind: k.clone(),
            state: "not indexed".into(),
            why: "not indexed: this index has never held one".into(),
            indexed_at: None,
            command: never_command(ix, k),
            people: vec![],
        });
    }
    rows
}

// ---- the engine --------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct Near {
    pub repo: String,
    pub found: String,
    pub why: String,
}

/// A zero-hit hash and the indexed files that carry a tied name under another hash.
#[derive(Debug, Clone)]
pub struct NotMatch {
    pub ioc: String,
    pub name: String,
    pub count: usize,
    /// the commonest other hash among them
    pub other: String,
}

#[derive(Debug, Clone, Default)]
pub struct HuntResult {
    pub q: Query,
    pub findings: Vec<Finding>,
    pub near: Vec<Near>,
    pub names: Vec<String>,
    pub stale: Vec<Gap>,
    pub gaps: Vec<Gap>,
    pub never: Vec<(String, String)>,
    pub not_checked: Vec<NotChecked>,
    pub possible: Vec<Finding>,
    pub window_ends_now: bool,
    pub as_of: Option<String>,
    pub scope_total: usize,
    pub scope_stale: usize,
    pub moved: Vec<(String, String)>,
    /// Present now but first seen after the window ended. Computed once, for every scope, and shown by every view;
    /// `--fail-if found` trips on it. A window labels a finding, it never hides one that is still there.
    pub present_after: Vec<Finding>,
    /// Sha256 indicators that a known advisory lists: (hash, advisory id, the packages the advisory names as iocs)
    pub hash_advisories: Vec<(String /*hash*/, String /*advisory id*/, Vec<String> /*package iocs*/)>,
    /// Indexed files that share a tied name with a zero-hit hash and carry another hash (a hint, never a finding)
    pub not_match: Vec<NotMatch>,
    /// With `--only`, the sources outside the shown sections that have a gap of their own: (name, why)
    pub hidden_gaps: Vec<(String, String)>,
    /// With `--only`, the finding count of the whole answer (the shown one is a part of it)
    pub full_findings: Option<usize>,
    /// With `--now`, the possible rows that the same question without `--now` lists and this one does not
    pub possible_dropped: Vec<String>,
    /// With `--owner`, the owner's other repos in scope that hold nothing (and had no gap)
    pub other_clear: Option<usize>,
    /// For each hash hit inside a package's install tree, the other files of that tree that have a simhash
    pub related: Vec<super::related::Related>,
    /// With `--similar-related`, host files similar to a related file but not identical: reported apart, never counted
    pub similar: Vec<Finding>,
    /// With `--similar-related`, what was compared and, when nothing was, why: printed under SIMILAR, NOT IDENTICAL
    pub similar_notes: Vec<String>,
    /// How many separate secrets the secret names are (a name set in 3 repos is 3), beside `secrets_of(res).len()` names
    pub secrets_separate: usize,
    /// Runtimes named by a floating tag or spec that could resolve to an affected release; reported apart
    pub floating: Vec<Floating>,
}

/// The similarity a lookalike needs to be listed under SIMILAR, NOT IDENTICAL.
pub const SIMILAR_THRESHOLD: f64 = 0.90;

pub fn hunt(ix: &Index, q: &Query) -> BrResult<HuntResult> {
    hunt_inner(ix, q, true)
}

/// `deep` lets the answer ask the same question again with one narrowing removed (`--only`, `--now`), to say what the
/// narrowing hid. Those re-asks run with `deep` off.
fn hunt_inner(ix: &Index, q: &Query, deep: bool) -> BrResult<HuntResult> {
    let names = scope_sources(ix, q)?;
    let rs = owner_spec(ix, q)?;
    let repos: Vec<String> = names.iter().filter(|n| ix.kind_of(n) == "repo").cloned().collect();
    let (mut findings, mut near) = (vec![], vec![]);
    for ioc in &q.iocs {
        findings.extend(find_ioc(ix, q, ioc, &repos, &names));
        near.extend(near_misses(ix, ioc, &repos));
    }
    let mut findings = dedupe_all(findings);
    if q.now_only && q.has("ci") {
        // --now narrows places to clean; past runs that could read a secret stay, marked past_run, uncounted
        let mut q2 = q.clone();
        q2.now_only = false;
        q2.only = ["ci".to_string()].into();
        let have: HashSet<(String, u64)> = findings.iter().filter(|f| f.kind == FKind::CiRun).map(|f| (f.where_.clone(), f.id)).collect();
        let mut all = vec![];
        for ioc in &q.iocs {
            all.extend(find_ioc(ix, &q2, ioc, &repos, &names));
        }
        for f in dedupe_all(all) {
            if f.kind == FKind::CiRun && !have.contains(&(f.where_.clone(), f.id)) {
                let mut f = f;
                f.past_run = true;
                findings.push(f);
            }
        }
    }
    // The CI runs of this owner's runners belong to the owner even when the repo is someone else's
    let mut cov_names = names.clone();
    let mut cov_set: HashSet<String> = names.iter().cloned().collect();
    if let Some(r) = &rs {
        if q.has("ci") && q.repo.as_ref().is_none_or(|x| x.is_empty()) {
            let runners = owner_runners(ix, r);
            if !runners.is_empty() {
                let others: Vec<String> = ix.srcs.iter().filter(|(n, s)| s.kind == "repo" && !repos.contains(n)).map(|(n, _)| n.clone()).collect();
                let mut q2 = q.clone();
                q2.only = ["ci".to_string()].into();
                let have: HashSet<(String, u64)> = findings.iter().filter(|f| f.kind == FKind::CiRun).map(|f| (f.where_.clone(), f.id)).collect();
                let mut extra = vec![];
                for ioc in &q.iocs {
                    extra.extend(find_ioc(ix, &q2, ioc, &others, &names));
                }
                for f in dedupe_all(extra) {
                    if f.kind == FKind::CiRun && runners.iter().any(|r| super::index::runner_key(r) == super::index::runner_key(&f.runner)) && !have.contains(&(f.where_.clone(), f.id)) {
                        findings.push(f);
                    }
                }
                if !q.has("hosts") {
                    for n in runners {
                        if cov_set.insert(n.clone()) {
                            cov_names.push(n);
                        }
                    }
                }
            }
        }
    }
    if rs.is_some() || q.repo.as_ref().is_some_and(|r| !r.is_empty()) {
        let rk = rs.as_ref().map(|r| runner_keys(ix, r)).unwrap_or_default();
        findings.retain(|f| scope_ok(ix, q, rs.as_ref(), &rk, f));
    }
    let ends_now = window_ends_now(ix, q, &names);
    let never = never_indexed(ix, q);
    let lap = laptop_gap(ix, q)?;
    if q.adv.is_some() || q.yara {
        findings.extend(rule_findings(ix, q, &names)?);
    }
    for f in findings.iter_mut() {
        f.owner = owner_for(ix, f);
        finalize(ix, f);
    }
    // The same partial rule evidence uses; a source holding a confirmed finding counts as having findings
    let confirmed_sources: HashSet<String> = findings.iter().filter(|f| !f.possible && !f.past_run).map(|f| f.source.clone()).collect();
    let (stale, gaps) = coverage(ix, q, &cov_names, ends_now, &confirmed_sources);
    let mut seen_near = HashSet::new();
    let mut near_u = vec![];
    for n in near {
        if seen_near.insert((n.repo.clone(), n.found.clone())) {
            near_u.push(n);
        }
    }
    let (mut poss, confirmed): (Vec<Finding>, Vec<Finding>) = findings.iter().cloned().partition(|f| f.possible);
    // --now narrows what is shown, never who may have been exposed. A repo that took the bad version and has since
    // fixed it still leaves its author's laptop in POSSIBLE until a scan of that laptop says otherwise.
    let mut exposure = confirmed.clone();
    // A hash that a known advisory lists reaches that advisory's packages: the people whose commits brought those
    // packages in are possible, though the hash itself was not found there
    let hash_adv = hash_advisories(ix, q);
    if !hash_adv.is_empty() {
        let rk = rs.as_ref().map(|r| runner_keys(ix, r)).unwrap_or_default();
        let scoped = rs.is_some() || q.repo.as_ref().is_some_and(|r| !r.is_empty());
        for mut f in hash_package_exposure(ix, q, &repos, &hash_adv) {
            if scoped && !scope_ok(ix, q, rs.as_ref(), &rk, &f) {
                continue;
            }
            f.owner = owner_for(ix, &f);
            exposure.push(f);
        }
    }
    if q.now_only {
        let mut q2 = q.clone();
        q2.now_only = false;
        q2.only = ["repos", "images", "releases"].iter().filter(|k| q.has(k)).map(|k| k.to_string()).collect();
        let have: HashSet<String> = exposure.iter().map(finding_key).collect();
        let rk = rs.as_ref().map(|r| runner_keys(ix, r)).unwrap_or_default();
        let scoped = rs.is_some() || q.repo.as_ref().is_some_and(|r| !r.is_empty());
        let mut all = vec![];
        for ioc in &q.iocs {
            all.extend(find_ioc(ix, &q2, ioc, &repos, &names));
        }
        for mut f in dedupe_all(all) {
            if f.possible || have.contains(&finding_key(&f)) || (scoped && !scope_ok(ix, q, rs.as_ref(), &rk, &f)) {
                continue;
            }
            f.owner = owner_for(ix, &f);
            exposure.push(f);
        }
    }
    poss.extend(possible_by_owner(ix, &names, &exposure, &poss));
    let times: Vec<String> = ix.srcs.keys().filter_map(|n| ix.i(n)).collect();
    let mut rows = not_checked_rows(ix, &gaps, &never);
    rows.extend(super::certs::gap_rows(ix, q, &names));
    if let Some(l) = lap {
        rows.push(l);
    }
    // one row per source: an empty source's own gaps are the reason it read nothing, so they join its row
    let mut gap_rows = source_gap_rows(ix, q, &cov_names);
    for er in rows.iter_mut().filter(|r| r.state == "empty") {
        if let Some(src) = ix.srcs.get(&er.name) {
            let mine: Vec<&crate::view::Gap> = src.gaps.iter().filter(|g| gap_applies(q, &g.scope)).collect();
            if !mine.is_empty() {
                er.why = format!("{}: {}", er.why, gap_list(&mine));
                gap_rows.retain(|g| g.name != er.name);
            }
        }
    }
    rows.extend(gap_rows);
    if let Some(r) = &rs {
        rows.extend(unowned_rows(ix, q, r));
    }
    rows.extend(runner_rows(ix, &findings));
    let mut q_all = q.clone();
    q_all.only = KINDS.iter().map(|s| s.to_string()).collect();
    let names_all = scope_sources(ix, &q_all)?;
    let probe = probe_repos(ix, &names);
    for (repo, why) in &probe.unknown {
        rows.push(NotChecked {
            name: repo.clone(),
            kind: "repo".into(),
            state: "freshness".into(),
            why: format!("freshness unknown: {why}"),
            indexed_at: ix.i(repo),
            command: close_command("repo", repo, None),
            people: vec![],
        });
    }
    let moved = probe.moved;
    let present_after = present_after_findings(ix, q, &names, &repos, rs.as_ref(), &findings);
    // One list of possible rows, one row per place, whichever IOC pointed at it
    let poss = dedupe_possible(poss);
    rows.extend(rt_host_rows(ix, q, &names));
    let floating = floating_refs(ix, q, &repos);
    let not_match = not_match_hints(ix, q, &names, &findings);
    let (mut hidden_gaps, mut full_findings, mut possible_dropped) = (vec![], None, vec![]);
    let only_narrow = q.only.len() < KINDS.len();
    if deep && only_narrow {
        let mut qa = q.clone();
        qa.only = KINDS.iter().map(|s| s.to_string()).collect();
        if let Ok(all) = hunt_inner(ix, &qa, false) {
            full_findings = Some(counts(&all).findings);
            let mine: HashSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
            hidden_gaps = all.not_checked.iter().filter(|r| !mine.contains(r.name.as_str()) && r.state != "unowned").map(|r| (r.name.clone(), r.state.clone())).collect();
        }
    }
    if deep && q.now_only {
        let mut qa = q.clone();
        qa.now_only = false;
        if let Ok(all) = hunt_inner(ix, &qa, false) {
            let have: HashSet<&str> = poss.iter().map(|f| f.where_.as_str()).collect();
            possible_dropped = all.possible.iter().filter(|f| !have.contains(f.where_.as_str())).map(|f| f.where_.clone()).collect();
        }
    }
    let other_clear = if rs.is_some() {
        let hit: HashSet<&str> = findings.iter().filter(|f| !f.possible).map(|f| f.where_.as_str()).collect();
        let gap: HashSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        Some(repos.iter().filter(|r| !hit.contains(r.as_str()) && !gap.contains(r.as_str())).count())
    } else {
        None
    };
    // A hash hit leads to what shipped with it; with --similar-related the similarity pass runs here
    let mut related: Vec<super::related::Related> = vec![];
    for f in findings.iter().filter(|f| !f.possible) {
        for r in super::related::related_for(ix, f) {
            if !related.iter().any(|x| x.host == r.host && x.path == r.path && x.hit_path == r.hit_path) {
                related.push(r);
            }
        }
    }
    // From a hash, the text files that came with it (beside it in its install tree) and the package's own install scripts
    // are compared with every simhashed file in the index
    if q.similar_related && deep {
        let mut pk: Vec<Ioc> = q.iocs.iter().filter(|i| i.kind == IocKind::Pkg).cloned().collect();
        for (_, _, pks) in &hash_adv {
            for p in pks {
                if let Ok(i) = I::parse_ioc(p, None) {
                    if i.kind == IocKind::Pkg && !pk.iter().any(|x| x.eco == i.eco && x.name == i.name) {
                        pk.push(i);
                    }
                }
            }
        }
        for ioc in &pk {
            for r in package_install_files(ix, &names, ioc) {
                if !related.iter().any(|x| x.host == r.host && x.path == r.path) {
                    related.push(r);
                }
            }
        }
    }
    let (similar, similar_notes) = if q.similar_related && deep { similar_of_related(ix, q, &names, &related, &findings) } else { (vec![], vec![]) };
    let mut res = HuntResult {
        q: q.clone(),
        findings,
        near: near_u,
        names,
        stale,
        gaps,
        never,
        not_checked: rows,
        possible: poss,
        window_ends_now: ends_now,
        as_of: times.into_iter().max(),
        scope_total: names_all.len(),
        scope_stale: names_all.iter().filter(|n| stale_now(ix, n)).count(),
        moved,
        present_after,
        hash_advisories: hash_adv,
        not_match,
        hidden_gaps,
        full_findings,
        possible_dropped,
        other_clear,
        related,
        similar,
        similar_notes,
        secrets_separate: 0,
        floating,
    };
    res.secrets_separate = super::secrets::secret_uses(ix, &res).iter().map(|u| u.separate).sum();
    Ok(res)
}

/// The text files of an affected package's own install on the hosts in scope (its install scripts and manifest): the files
/// of the package's folder in `node_modules`, its module folder in `site-packages`, or the whole install for the kinds whose
/// item is one install already. Only files with a simhash (text) can be compared.
fn package_install_files(ix: &Index, names: &[String], ioc: &Ioc) -> Vec<super::related::Related> {
    let mut out = vec![];
    let norm = |x: &str| x.to_lowercase().replace(['-', '.'], "_");
    for h in names.iter().filter(|n| ix.kind_of(n) == "host") {
        for it in ix.host_items(h) {
            if !it.pkgs.iter().any(|p| pkg_match(ioc, p)) {
                continue;
            }
            for o in &it.files {
                let Some(sh) = o.simhash.as_ref().filter(|s| !s.is_empty()) else { continue };
                let path = full_path(it, o);
                let inside = match it.kind.as_str() {
                    "node_modules" => path.to_lowercase().contains(&format!("/node_modules/{}/", ioc.name.to_lowercase())),
                    "site-packages" => path
                        .split("/site-packages/")
                        .nth(1)
                        .or_else(|| path.split("/dist-packages/").nth(1))
                        .is_some_and(|rest| norm(rest.split('/').next().unwrap_or("")).starts_with(&norm(&ioc.name))),
                    "go-mod-cache" | "cargo-registry" | "tool-cache" | "action-checkout" => true,
                    _ => false,
                };
                if !inside {
                    continue;
                }
                let tree = super::related::install_tree(it, &path).unwrap_or_else(|| it.loc.clone());
                let file = path.strip_prefix(&format!("{}/", tree.trim_end_matches('/'))).unwrap_or(&path).to_string();
                out.push(super::related::Related {
                    ioc: ioc.text.clone(),
                    host: h.to_string(),
                    hit_path: String::new(),
                    tree,
                    path,
                    file,
                    sha256: o.sha256.clone(),
                    simhash: sh.clone(),
                    package: ioc.name.clone(),
                });
            }
        }
    }
    out.sort_by(|a, b| (&a.host, &a.path).cmp(&(&b.host, &b.path)));
    out
}

/// A file every package or system ships, which says nothing about a carrier: a manifest, a licence, a file under a system
/// directory. A lookalike of one is listed last and never planned.
const SYSTEM_DIRS: [&str; 6] = ["/etc/", "/usr/share/", "/usr/lib/", "/var/lib/", "/System/", "/Library/"];

pub fn is_boilerplate_path(path: &str) -> bool {
    is_package_metadata(basename(path)) || SYSTEM_DIRS.iter().any(|d| path.starts_with(d))
}

/// Host files whose simhash is close (at least `SIMILAR_THRESHOLD`) to a related file's, that are neither that file
/// nor a file already found or listed. One pass per distinct simhash; the rows are labelled `similar` and never counted in the
/// headline. Boilerplate hits (a manifest looks like every manifest) are marked and sorted last. The second value says what was
/// compared, or why nothing could be.
fn similar_of_related(ix: &Index, q: &Query, names: &[String], related: &[super::related::Related], found: &[Finding]) -> (Vec<Finding>, Vec<String>) {
    let mut out: Vec<Finding> = vec![];
    let mut notes: Vec<String> = vec![];
    let have: HashSet<(String, String)> = found.iter().map(|f| (f.where_.clone(), f.loc.clone())).collect();
    let listed: HashSet<(String, String)> = related.iter().map(|r| (r.host.clone(), r.path.clone())).collect();
    let mut done: HashSet<&str> = HashSet::new();
    for r in related {
        if !done.insert(r.simhash.as_str()) {
            continue;
        }
        let Ok(ioc) = I::parse_ioc(&format!("simhash:{}~{:.2}", r.simhash, SIMILAR_THRESHOLD), None) else { continue };
        // the exposure window is about the past; a lookalike written after it is the lead (a dropper dropped after the yank)
        let mut qs = q.clone();
        qs.window = None;
        qs.now_only = false;
        for mut f in file_findings(ix, &qs, &ioc, &[], names) {
            if f.kind != FKind::Host || f.sha256 == r.sha256 || have.contains(&(f.where_.clone(), f.loc.clone())) || listed.contains(&(f.where_.clone(), f.loc.clone())) || f.loc == r.path {
                continue;
            }
            if out.iter().any(|o| o.where_ == f.where_ && o.loc == f.loc) {
                continue;
            }
            f.owner = owner_for(ix, &f);
            finalize(ix, &mut f);
            f.like_file = r.file.clone();
            f.boilerplate = is_boilerplate_path(&f.loc) || is_boilerplate_path(&r.path);
            out.push(f);
        }
    }
    out.sort_by(|a, b| {
        a.boilerplate
            .cmp(&b.boilerplate)
            .then_with(|| b.sim.unwrap_or(0.0).partial_cmp(&a.sim.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| (&a.where_, &a.loc).cmp(&(&b.where_, &b.loc)))
    });
    let pct = (SIMILAR_THRESHOLD * 100.0).round() as u32;
    let hits: Vec<&Finding> = found.iter().filter(|f| !f.possible && f.iocs_or_one().iter().any(|i| i.starts_with("sha256:"))).collect();
    let on_hosts = hits.iter().filter(|f| f.kind == FKind::Host).count();
    let elsewhere: BTreeSet<&str> = hits
        .iter()
        .filter(|f| f.kind != FKind::Host)
        .map(|f| match f.kind {
            FKind::Image => "images",
            FKind::ReleaseAsset => "release assets",
            FKind::Repo | FKind::WorkflowRef => "repos",
            _ => "other places",
        })
        .collect();
    if related.is_empty() {
        let has_pkg = q.iocs.iter().any(|i| i.kind == IocKind::Pkg);
        let has_hash = q.iocs.iter().any(|i| i.kind == IocKind::Sha256);
        let why = if !has_hash && !has_pkg {
            "this question names no hash and no package, and --similar-related starts from a file hash hit or an affected package".to_string()
        } else if on_hosts == 0 && !hits.is_empty() {
            format!(
                "the hash was found only in {}, and those keep no similarity record of their text files; scan a machine that holds the package, or give the file itself with --similar FILE",
                elsewhere.iter().copied().collect::<Vec<_>>().join(" and ")
            )
        } else if on_hosts > 0 {
            "no text file beside the hit in its install folder, and none of the affected package's own files, has a similarity record on a scanned machine (a scan records text files up to 1 MB that its hash filter selects)".to_string()
        } else {
            "no machine in scope holds a hash hit or the files of an affected package, so there is no text file to start from".to_string()
        };
        notes.push(format!("nothing to compare: {why}"));
    } else if out.is_empty() {
        let total: usize =
            names.iter().filter(|n| ix.kind_of(n) == "host").flat_map(|h| ix.host_items(h)).map(|it| it.files.iter().filter(|f| f.simhash.as_ref().is_some_and(|s| !s.is_empty())).count()).sum();
        let from: BTreeSet<&str> = related.iter().map(|r| basename(&r.path)).collect();
        notes.push(format!(
            "compared {} ({}) with all {} in the index; none is {pct}% or more alike without being identical",
            plural(done.len(), "text file"),
            from.iter().copied().collect::<Vec<_>>().join(", "),
            plural(total, "text file")
        ));
    } else {
        let main = out.iter().filter(|f| !f.boilerplate).count();
        let bp = out.len() - main;
        notes.push(format!(
            "compared {} from {} with every text file in the index: {} {} {pct}% or more alike without being identical{}",
            plural(done.len(), "text file"),
            plural(related.iter().map(|r| (r.host.clone(), r.tree.clone())).collect::<BTreeSet<_>>().len(), "install"),
            plural(out.len(), "file"),
            if out.len() == 1 { "is" } else { "are" },
            if bp > 0 { format!(" ({bp} of them {} like boilerplate and {} listed last)", if bp == 1 { "looks" } else { "look" }, if bp == 1 { "is" } else { "are" }) } else { String::new() }
        ));
    }
    (out, notes)
}

/// Two rows for one place (two indicators reaching the same host) are one possible.
fn dedupe_possible(poss: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = vec![];
    for f in poss {
        match out.iter_mut().find(|o| o.where_ == f.where_ && o.digest == f.digest) {
            Some(o) => {
                for i in f.iocs_or_one() {
                    if !o.iocs_or_one().contains(&i) {
                        let mut v = o.iocs_or_one();
                        v.push(i);
                        o.iocs = v;
                    }
                }
            }
            None => out.push(f),
        }
    }
    out
}

/// Names that every package ships and that say nothing about a carrier: one row per ecosystem, plus the generic ones.
const PACKAGE_METADATA: [(&str, &[&str]); 5] = [
    ("npm", &["package.json", "package-lock.json", ".npmignore", "index.d.ts"]),
    ("pypi", &["metadata", "record", "wheel", "installer", "top_level.txt", "entry_points.txt", "direct_url.json", "requested", "pkg-info", "sources.txt", "__init__.py"]),
    ("cargo", &["cargo.toml", "cargo.lock", ".cargo_vcs_info.json", "cargo.toml.orig"]),
    ("go", &["go.mod", "go.sum"]),
    ("", &[".gitignore", "makefile"]),
];

/// Image layers record no simhash, so a file is taken for text by its extension (one row per kind of text file).
const TEXT_EXTS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "jsx", "tsx", "json", "md", "txt", "py", "pyi", "rb", "sh", "bash", "yml", "yaml", "toml", "cfg", "ini", "html", "css", "map", "lock", "rs", "go", "c", "h", "cc", "cpp",
    "java", "php", "pl", "lua", "xml", "csv",
];

fn has_text_extension(path: &str) -> bool {
    basename(path).rsplit_once('.').is_some_and(|(_, e)| TEXT_EXTS.contains(&e.to_lowercase().as_str()))
}

fn is_package_metadata(name: &str) -> bool {
    let n = name.to_lowercase();
    ["readme", "license", "licence", "changelog", "notice", "copying", "authors", "history"].iter().any(|p| n.starts_with(p)) || PACKAGE_METADATA.iter().any(|(_, names)| names.contains(&n.as_str()))
}

/// When a sha256 indicator has no hit, and the input ties a file name to it, say which indexed files carry that
/// name under another hash. The ties are `Query.hash_names` plus the files inside an affected package's install tree in a
/// host or an image, and only files that are not text (no simhash): a package's text files say nothing about a binary's
/// hash. A name alone, with no tie, never produces a hint.
fn not_match_hints(ix: &Index, q: &Query, names: &[String], findings: &[Finding]) -> Vec<NotMatch> {
    let hit: HashSet<String> = findings.iter().filter(|f| !f.possible).flat_map(|f| f.iocs_or_one()).collect();
    let zero: Vec<&Ioc> = q.iocs.iter().filter(|i| i.kind == IocKind::Sha256 && !hit.contains(&i.text)).collect();
    if zero.is_empty() {
        return vec![];
    }
    let mut ties: Vec<(String, String)> = q.hash_names.iter().filter(|(i, _)| zero.iter().any(|z| &z.text == i)).cloned().collect();
    let pkgs: Vec<&Ioc> = q.iocs.iter().filter(|i| i.kind == IocKind::Pkg).collect();
    if !pkgs.is_empty() {
        let mut carried: BTreeSet<String> = BTreeSet::new();
        for h in names.iter().filter(|n| ix.kind_of(n) == "host") {
            for it in ix.host_items(h) {
                if pkgs.iter().any(|p| it.pkgs.iter().any(|x| pkg_match(p, x))) {
                    carried.extend(it.files.iter().filter(|f| f.simhash.is_none()).map(|f| basename(&f.path).to_string()));
                }
            }
        }
        for b in ix.images() {
            for l in &b.layers {
                for p in pkgs.iter().filter(|p| l.packages.iter().any(|x| pkg_match(p, x))) {
                    let seg = format!("/{}/", p.name.to_lowercase());
                    carried.extend(l.files.iter().filter(|f| !has_text_extension(&f.path) && f.path.to_lowercase().contains(&seg)).map(|f| basename(&f.path).to_string()));
                }
            }
        }
        for n in carried.into_iter().filter(|n| !is_package_metadata(n)) {
            for z in &zero {
                ties.push((z.text.clone(), n.clone()));
            }
        }
    }
    ties.sort();
    ties.dedup();
    if ties.is_empty() {
        return vec![];
    }
    // every indexed file by name: (hash)
    let wanted: HashSet<&str> = ties.iter().map(|(_, n)| n.as_str()).collect();
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut see = |name: &str, hash: &str| {
        if wanted.contains(name) && !hash.is_empty() {
            by_name.entry(name.to_string()).or_default().push(hash.to_string());
        }
    };
    for h in ix.names("host") {
        for it in ix.host_items(&h) {
            it.files.iter().for_each(|f| see(basename(&f.path), &f.sha256));
        }
    }
    for b in ix.images() {
        for l in &b.layers {
            l.files.iter().for_each(|f| see(basename(&f.path), &f.sha256));
        }
    }
    for r in ix.names("repo") {
        for rel in ix.releases(&r) {
            rel.assets.iter().for_each(|a| see(&a.name, &a.sha256));
        }
    }
    let mut out = vec![];
    for (i, n) in ties {
        let want = zero.iter().find(|z| z.text == i).map(|z| z.sha.clone()).unwrap_or_default();
        let others: Vec<&String> = by_name.get(&n).map(|v| v.iter().filter(|h| **h != want).collect()).unwrap_or_default();
        if others.is_empty() {
            continue;
        }
        let mut freq: BTreeMap<&String, usize> = BTreeMap::new();
        others.iter().for_each(|h| *freq.entry(*h).or_default() += 1);
        let other = freq.iter().max_by_key(|(h, c)| (**c, std::cmp::Reverse(h.to_string()))).map(|(h, _)| h.to_string()).unwrap_or_default();
        out.push(NotMatch { ioc: i, name: n, count: others.len(), other });
    }
    out
}

/// For each sha256 indicator, the recorded advisories that list it (other than the one the hunt already uses) and
/// the packages each names, as `eco:name`.
pub fn hash_advisories(ix: &Index, q: &Query) -> Vec<(String, String, Vec<String>)> {
    let mut out = vec![];
    for i in q.iocs.iter().filter(|i| i.kind == IocKind::Sha256) {
        let want = i.text.to_lowercase();
        for a in &ix.v.advisories {
            if q.adv.as_ref().is_some_and(|x| x.id == a.id) || !I::advisory_hashes(a).contains(&want) {
                continue;
            }
            let mut pk: Vec<String> = a.packages.iter().map(|p| format!("{}:{}", I::br_eco(&p.ecosystem), p.name)).collect();
            if pk.is_empty() {
                pk = a.affected.iter().filter(|x| !x.starts_with("sha256:") && !x.starts_with("simhash:")).map(|x| x.rsplit_once('@').map_or(x.clone(), |(n, _)| n.to_string())).collect();
            }
            pk.sort();
            pk.dedup();
            out.push((i.text.clone(), a.id.clone(), pk));
        }
    }
    out
}

/// What the packages of those advisories did in the repos in scope, as exposure events (never findings): the people
/// whose commits brought them in are possible on their laptops.
fn hash_package_exposure(ix: &Index, q: &Query, repos: &[String], hash_adv: &[(String, String, Vec<String>)]) -> Vec<Finding> {
    let mut q2 = q.clone();
    q2.now_only = false;
    q2.only = ["repos"].iter().filter(|k| q.has(k)).map(|k| k.to_string()).collect();
    let mut out = vec![];
    for (_, id, _) in hash_adv {
        let Some(a) = ix.v.advisories.iter().find(|a| &a.id == id) else { continue };
        for p in &a.packages {
            let Some(ioc) = Ioc::from_package(p) else { continue };
            out.extend(find_ioc(ix, &q2, &ioc, repos, &[]).into_iter().filter(|f| f.kind == FKind::Repo));
        }
    }
    dedupe_all(out)
}

/// Whether a recorded scan gap touches a section of this query.
fn gap_applies(q: &Query, scope: &str) -> bool {
    let s = scope.to_lowercase();
    let secs: &[&str] = if s.contains("cache") {
        &["caches"]
    } else if s.contains("artifact") {
        &["artifacts"]
    } else if s.contains("release") {
        &["releases"]
    } else if s.contains("run") || s.contains("log") || s.contains("job") {
        &["ci"]
    } else if s.contains("image") || s.contains("manifest") || s.contains("tags") || s.contains("blob") {
        &["images"]
    } else if s.contains("tree") || s.contains("lockfile") || s.contains("workflow") || s.contains("codeowners") {
        &["repos"]
    } else {
        return true;
    };
    secs.iter().any(|x| q.has(x))
}

/// The first three gaps of a source in one line, and how many more there are.
fn gap_list(mine: &[&crate::view::Gap]) -> String {
    let shown: Vec<String> = mine.iter().take(3).map(|g| format!("{}: {}", g.scope, g.reason)).collect();
    let more = if mine.len() > 3 { format!("; and {} more", mine.len() - 3) } else { String::new() };
    format!("{}{}", shown.join("; "), more)
}

/// Ruling 1: what a source's last scan could not check is part of the answer, one row per source.
fn source_gap_rows(ix: &Index, q: &Query, names: &[String]) -> Vec<NotChecked> {
    let mut rows = vec![];
    for n in names {
        let Some(src) = ix.srcs.get(n) else { continue };
        if crate::collect::words::never_scanned(src) {
            rows.push(NotChecked {
                name: n.clone(),
                kind: src.kind.clone(),
                state: "gap".into(),
                why: "registered, never scanned".into(),
                indexed_at: None,
                command: close_command(&src.kind, n, Some(&src.reach)),
                people: vec![],
            });
            continue;
        }
        let mine: Vec<&crate::view::Gap> = src.gaps.iter().filter(|g| gap_applies(q, &g.scope)).collect();
        if mine.is_empty() {
            continue;
        }
        rows.push(NotChecked {
            name: n.clone(),
            kind: src.kind.clone(),
            state: "gap".into(),
            why: format!("{} could not be checked at the last scan ({})", plural(mine.len(), "thing"), gap_list(&mine)),
            indexed_at: Some(src.indexed_at.clone()),
            command: close_command(&src.kind, n, Some(&src.reach)),
            people: vec![],
        });
    }
    rows
}

/// `--owner` never drops a source silently: repos and hosts nobody owns are a gap in the answer.
fn unowned_rows(ix: &Index, q: &Query, rs: &super::index::OwnerSpec) -> Vec<NotChecked> {
    let _ = rs;
    let mut repos = 0usize;
    let mut hosts = 0usize;
    let mut sample = vec![];
    for (n, s) in &ix.srcs {
        let unowned = match s.kind.as_str() {
            "repo" if ["repos", "ci", "caches", "artifacts", "releases"].iter().any(|x| q.has(x)) => {
                ix.lock_paths(n).iter().map(|p| Some(p.as_str())).chain(std::iter::once(None)).all(|p| repo_owner(ix, n, p).is_empty())
            }
            "host" if q.has("hosts") => host_owner(ix, n).is_empty(),
            _ => false,
        };
        if unowned {
            if s.kind == "repo" {
                repos += 1
            } else {
                hosts += 1
            }
            if sample.len() < 3 {
                sample.push(n.clone());
            }
        }
    }
    if repos + hosts == 0 {
        return vec![];
    }
    let mut what = vec![];
    if repos > 0 {
        what.push(plural(repos, "repo"));
    }
    if hosts > 0 {
        what.push(plural(hosts, "host"));
    }
    sample.sort();
    vec![NotChecked {
        name: what.join(" and "),
        kind: "repo".into(),
        state: "unowned".into(),
        why: format!("no owner on record, so --owner could not include them (e.g. {})", sample.join(", ")),
        indexed_at: None,
        command: "add CODEOWNERS to the repo, or br hosts add NAME --owner LOGIN".into(),
        people: vec![],
    }]
}

/// Self-hosted runners that ran an affected install but have no scan in the index: the machine itself is unchecked.
fn runner_rows(ix: &Index, findings: &[Finding]) -> Vec<NotChecked> {
    let known: HashSet<String> = ix.srcs.iter().filter(|(_, s)| s.kind == "host").map(|(n, _)| super::index::runner_key(n)).collect();
    let mut by: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.kind == FKind::CiRun && !f.past_run && !f.possible) {
        if f.runner.is_empty() || super::index::is_hosted_runner(&f.runner) || known.contains(&super::index::runner_key(&f.runner)) {
            continue;
        }
        let e = by.entry(f.runner.clone()).or_insert((0, f.where_.clone()));
        e.0 += 1;
    }
    by.into_iter()
        .map(|(runner, (n, repo))| NotChecked {
            name: runner.clone(),
            kind: "host".into(),
            state: "runner".into(),
            why: format!("unscanned runner: {} on it ran an affected install (first in {repo}), and no scan of this machine is in the index", plural(n, "run")),
            indexed_at: None,
            command: format!(
                "br hosts add {runner} --kind runner --reach ssh   then br scan --host {runner}   (no ssh: on it br scan --local --export {runner}.brx, then here br import {runner}.brx)"
            ),
            people: vec![],
        })
        .collect()
}

/// B8: the age of the oldest source in scope, when it is older than the newest one ("oldest source 7d old").
pub fn oldest_source_note(ix: &Index, names: &[String]) -> Option<String> {
    let oldest = names.iter().filter_map(|n| ix.i(n).map(|t| (t, n))).min()?;
    let newest = names.iter().filter_map(|n| ix.i(n)).max()?;
    if oldest.0 == newest {
        return None;
    }
    Some(format!("oldest source: {}, {} old", oldest.1, super::util::age_str(&ix.now, &oldest.0)))
}

/// What the window filter would hide but is still there now, for every kind of place and every scope. A finding is
/// here when it is present now (`present_now`), was first seen after the window ended, and is not already a finding.
fn present_after_findings(ix: &Index, q: &Query, names: &[String], repos: &[String], rs: Option<&super::index::OwnerSpec>, have: &[Finding]) -> Vec<Finding> {
    let Some((_, wend)) = &q.window else { return vec![] };
    let mut q3 = q.clone();
    q3.window = None;
    q3.now_only = false;
    let have: HashSet<String> = have.iter().map(finding_key).collect();
    let mut all = vec![];
    for ioc in &q.iocs {
        all.extend(find_ioc(ix, &q3, ioc, repos, names));
    }
    let rk = rs.map(|r| runner_keys(ix, r)).unwrap_or_default();
    let mut out = vec![];
    for mut f in dedupe_all(all) {
        if f.possible || f.past_run || !present_now(&f) {
            continue;
        }
        if !f.first_seen.as_deref().is_some_and(|t| t > wend.as_str()) || have.contains(&finding_key(&f)) {
            continue;
        }
        if (rs.is_some() || q.repo.as_ref().is_some_and(|r| !r.is_empty())) && !scope_ok(ix, q, rs, &rk, &f) {
            continue;
        }
        f.owner = owner_for(ix, &f);
        finalize(ix, &mut f);
        out.push(f);
    }
    out
}

/// Org members with no laptop scan are part of what was not checked.
fn laptop_gap(ix: &Index, q: &Query) -> BrResult<Option<NotChecked>> {
    let empty = |o: &Option<String>| o.as_ref().is_none_or(|x| x.is_empty());
    if !q.has("hosts") || !empty(&q.repo) || !empty(&q.host) {
        return Ok(None);
    }
    if !q.iocs.iter().any(|i| i.kind != IocKind::ActionRef) {
        return Ok(None);
    }
    // The same laptop-coverage truth hosts, status, notify and evidence use
    let p = host_population_for(ix, q);
    if p.no_laptop.is_empty() {
        return Ok(None);
    }
    Ok(Some(NotChecked {
        name: "laptops".into(),
        kind: "laptops".into(),
        state: "laptops".into(),
        why: format!("{} of {} members {} have no laptop scan here", p.no_laptop.len(), p.members, p.source_label),
        indexed_at: None,
        command: "br hosts lists them; on each laptop: br scan --local --export NAME.brx   then here: br import NAME.brx".into(),
        // A member whose scan exists but reads less than the home and the caches says why
        people: p.no_laptop_reasons.iter().map(|(_, name, why)| if why.starts_with("no machine") || why.starts_with("only ") { name.clone() } else { format!("{name} ({why})") }).collect(),
    }))
}

/// The one sentence for gap counts: '3 stale + 1 not indexed = 4 gaps'.
pub fn gap_words(rows: &[NotChecked]) -> String {
    let label = [
        ("stale", "stale"),
        ("partial", "partial"),
        ("empty", "empty"),
        ("not indexed", "not indexed"),
        ("laptops", "laptop gap"),
        ("gap", "scan gap"),
        ("unowned", "unowned"),
        ("freshness", "freshness unknown"),
        ("runner", "unscanned runner"),
        ("trust store", "trust store gap"),
    ];
    let mut parts = vec![];
    for (state, word) in label {
        let n = rows.iter().filter(|r| r.state == state).count();
        if n > 0 {
            parts.push(format!("{n} {word}"));
        }
    }
    match rows.len() {
        0 => String::new(),
        1 => "1 gap".to_string(),
        t => format!("{} = {t} gaps", parts.join(" + ")),
    }
}

/// How a NOT CHECKED row is named in a sentence.
pub fn row_label(r: &NotChecked) -> String {
    if r.state == "laptops" {
        format!("{}: {}", r.name, r.why)
    } else {
        r.name.clone()
    }
}

/// Runner hosts the owner spec covers.
fn owner_runners(ix: &Index, rs: &super::index::OwnerSpec) -> Vec<String> {
    ix.srcs.iter().filter(|(n, s)| s.kind == "host" && ix.host_def(n).is_some_and(|h| h.kind.as_deref() == Some("runner")) && owner_match(ix, rs, &host_owner(ix, n))).map(|(n, _)| n.clone()).collect()
}

/// Runner host keys (see `runner_key`), computed once per hunt, so a CI run joins its runner without an exact name.
fn runner_keys(ix: &Index, rs: &super::index::OwnerSpec) -> HashSet<String> {
    owner_runners(ix, rs).iter().map(|n| super::index::runner_key(n)).collect()
}

fn scope_ok(ix: &Index, q: &Query, rs: Option<&super::index::OwnerSpec>, runners: &HashSet<String>, f: &Finding) -> bool {
    if let Some(rs) = rs {
        if f.kind == FKind::CiRun && !f.runner.is_empty() && runners.contains(&super::index::runner_key(&f.runner)) {
            return true;
        }
        if !owner_match(ix, rs, &owner_for(ix, f)) {
            return false;
        }
    }
    if let Some(r) = q.repo.as_ref().filter(|r| !r.is_empty()) {
        if f.kind == FKind::Image {
            return f.from_repo.as_ref() == Some(r);
        }
    }
    true
}

// ---- one finding = one row ---------------------------------------------------------------------
fn finding_key(f: &Finding) -> String {
    let rt = f.rt.as_ref().map(|r| format!("\x01rt\x01{}\x01{}", r.version, r.seen_as)).unwrap_or_default();
    format!("{}{rt}", finding_key_base(f))
}

fn finding_key_base(f: &Finding) -> String {
    let w = &f.where_;
    if let Some(c) = &f.cert {
        return format!("cert\x01{w}\x01{}\x01{}\x01{}\x01{:?}", f.digest, c.file, c.fp, f.kind);
    }
    let o = |x: &Option<String>| x.clone().unwrap_or_default();
    match f.kind {
        FKind::Repo => format!("repo\x01{w}\x01{}\x01{}\x01{}\x01{}", f.file, f.p.clone().unwrap_or_else(|| format!("{}@{}", f.name, f.version)), o(&f.first_seen), f.state == "install-only"),
        FKind::CiRun => format!("ci_run\x01{w}\x01{}", f.id),
        FKind::Cache => format!("cache\x01{w}\x01{}", f.key),
        FKind::Artifact => format!("artifact\x01{w}\x01{}", f.id),
        FKind::Image => format!("image\x01{}\x01{}\x01{}", f.digest, f.where_in, f.path),
        FKind::Host => format!("host\x01{w}\x01{}", if f.inferred { "inferred".to_string() } else { f.loc.clone() }),
        FKind::ReleaseAsset => format!("release_asset\x01{w}\x01{}\x01{}", f.tag, f.asset),
        FKind::WorkflowRef => format!("workflow_ref\x01{w}\x01{}\x01{}", f.file, f.uses),
    }
}

pub fn dedupe_all(findings: Vec<Finding>) -> Vec<Finding> {
    let mut idx: BTreeMap<String, usize> = BTreeMap::new();
    let mut out: Vec<Finding> = vec![];
    for mut f in findings {
        let key = finding_key(&f);
        if let Some(&i) = idx.get(&key) {
            if !out[i].iocs.contains(&f.ioc) {
                out[i].iocs.push(f.ioc.clone());
            }
            continue;
        }
        f.iocs = vec![f.ioc.clone()];
        idx.insert(key, out.len());
        out.push(f);
    }
    out
}

fn src_time(ix: &Index, f: &Finding) -> Option<String> {
    if f.kind == FKind::Image {
        return ix.registry_of(&f.where_).and_then(|r| ix.i(&r));
    }
    if ix.srcs.contains_key(&f.where_) {
        ix.i(&f.where_)
    } else {
        None
    }
}

/// Fill the fields every consumer wants on every row.
pub fn finalize(ix: &Index, f: &mut Finding) {
    f.owner_label = owner_name(ix, &f.owner);
    if f.kind == FKind::Host && f.workspace_repo.is_none() {
        f.workspace_repo = workspace_repo(ix, f);
    }
    // A finding in a runner's workspace also goes to the repo's owner. the label stays the one owner every screen
    // shows, the owner of the place (a runner's owner is its host entry's), so no screen files it under another team
    if f.kind == FKind::Host {
        if let Some(o) = workspace_owner(ix, f) {
            f.workspace_owner = Some(o);
        }
    }
    let t = src_time(ix, f);
    f.source = f.where_.clone();
    match f.kind {
        FKind::Repo => {
            f.location = f.file.clone();
            if !(f.state == "install-only" && f.last_seen.is_some()) {
                f.last_seen = f.removed_at.clone().or(t);
            }
        }
        FKind::CiRun => {
            f.location = f.workflow.clone();
            f.last_seen = Some(f.at.clone());
            if f.state.is_empty() {
                f.state = "ran".into();
            }
        }
        FKind::Cache => {
            f.location = f.key.clone();
            f.last_seen = f.last_used.clone().filter(|x| !x.is_empty()).or(t);
            if f.state.is_empty() {
                f.state = "present".into();
            }
        }
        FKind::Artifact => {
            f.location = f.name.clone();
            let live = f.expires_unknown || f.expires > ix.now;
            f.last_seen = if live { t } else { Some(f.expires.clone()) };
            if f.expires_unknown && f.note.is_empty() {
                f.note = "expiry unknown".into();
            }
            if f.state.is_empty() {
                f.state = if live { "present" } else { "expired" }.into();
            }
        }
        FKind::Image => {
            f.location = format!("{}{}", f.digest, if f.path.is_empty() { String::new() } else { format!(":{}", f.path) });
            f.last_seen = t;
            if f.state.is_empty() {
                f.state = f.where_in.clone();
            }
        }
        FKind::Host => {
            f.location = f.loc.clone();
            f.last_seen = if f.inferred { f.first_seen.clone() } else { t };
        }
        FKind::ReleaseAsset => {
            f.location = f.asset.clone();
            f.last_seen = t;
            if f.state.is_empty() {
                f.state = "present".into();
            }
        }
        FKind::WorkflowRef => {
            f.location = f.file.clone();
            f.last_seen = t;
            if f.state.is_empty() {
                f.state = "present".into();
            }
        }
    }
    f.run_ids = if f.kind == FKind::CiRun { vec![f.id] } else { vec![] };
    f.carried_by = carrier(f);
}

/// Go's module cache writes upper-case letters as `!` plus the lower-case letter (A2 #30).
pub fn go_decode(s: &str) -> String {
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

/// Which package version or release carried a file, when the index knows it.
fn carrier(f: &Finding) -> Option<String> {
    match f.kind {
        FKind::ReleaseAsset => return Some(format!("release {} of {}", f.tag, f.where_)),
        FKind::Image => {
            let cmd = f.layer_cmd.as_ref().filter(|c| !c.is_empty())?;
            if f.path.is_empty() {
                return None;
            }
            let shown = if cmd.chars().count() <= 90 { cmd.clone() } else { format!("{}...", cmd.chars().take(87).collect::<String>()) };
            return Some(format!("layer {}: {}", f.layer, shown));
        }
        _ => {}
    }
    if f.kind != FKind::Host || f.inferred || f.match_ == "rule" || f.sha256.is_empty() {
        return None;
    }
    for p in &f.item_pkgs {
        let (_, name, _) = parse_pkg(p);
        if f.loc.contains(&format!("/{name}/")) {
            return Some(p.clone());
        }
    }
    let re1 = super::util::re(r"/pkg/mod/(.+?)@(v[^/]+)/");
    if let Some(m) = re1.captures(&f.loc) {
        return Some(format!("go:{}@{}", go_decode(&m[1]), go_decode(&m[2])));
    }
    let re2 = super::util::re(r"/hostedtoolcache/([^/]+)/([^/]+)/");
    if let Some(m) = re2.captures(&f.loc) {
        return Some(format!("{} {} (runner tool cache)", &m[1], &m[2]));
    }
    let re3 = super::util::re(r"/([^/@]+)@(v?\d[^/]*)/");
    if let Some(m) = re3.captures(&f.loc) {
        return Some(format!("{} {}", &m[1], &m[2]));
    }
    None
}

/// The one deduped list of confirmed findings.
pub fn findings(res: &HuntResult) -> Vec<&Finding> {
    res.findings.iter().filter(|f| !f.possible && !f.past_run).collect()
}

pub fn past_runs(res: &HuntResult) -> Vec<&Finding> {
    res.findings.iter().filter(|f| f.past_run && !f.possible).collect()
}

pub fn possible(res: &HuntResult) -> Vec<&Finding> {
    res.possible.iter().collect()
}

struct Event {
    repo: String,
    at: String,
    ioc: String,
    iocs: Vec<String>,
    what: String,
}

fn exposure_events(confirmed: &[Finding]) -> Vec<Event> {
    let mut ev = vec![];
    for f in confirmed {
        match f.kind {
            FKind::Repo if f.state != "install-only" => {
                let sha = f.added_by.as_ref().map(|a| a.sha.clone()).unwrap_or_default();
                ev.push(Event {
                    repo: f.where_.clone(),
                    at: f.first_seen.clone().unwrap_or_default(),
                    ioc: f.ioc.clone(),
                    iocs: f.iocs.clone(),
                    what: format!("took the affected {}@{}{}", f.name, f.version, if sha.is_empty() { String::new() } else { format!(" in {sha}") }),
                });
            }
            FKind::Image if f.from_repo.as_ref().is_some_and(|r| !r.is_empty()) => {
                let tag = f.tags.first().cloned().unwrap_or_default();
                let dg: String = f.digest.chars().take(19).collect();
                ev.push(Event {
                    repo: f.from_repo.clone().unwrap(),
                    at: f.built.clone(),
                    ioc: f.ioc.clone(),
                    iocs: f.iocs.clone(),
                    what: format!("built {}{} ({dg}), which holds the affected file or package", f.image, if tag.is_empty() { String::new() } else { format!(":{tag}") }),
                });
            }
            FKind::ReleaseAsset => ev.push(Event {
                repo: f.where_.clone(),
                at: f.published.clone(),
                ioc: f.ioc.clone(),
                iocs: f.iocs.clone(),
                what: format!("published {} in {}, which has the affected hash", f.asset, f.tag),
            }),
            _ => {}
        }
    }
    ev
}

/// A host whose last index predates the exposure, owned by someone who works in a repo that took, built or published it.
fn possible_by_owner(ix: &Index, names: &[String], confirmed: &[Finding], already: &[Finding]) -> Vec<Finding> {
    let mut out = vec![];
    let mut have: HashSet<String> = confirmed.iter().filter(|f| f.kind == FKind::Host).map(|f| f.where_.clone()).collect();
    have.extend(already.iter().map(|f| f.where_.clone()));
    let events = exposure_events(confirmed);
    if events.is_empty() {
        return out;
    }
    for h in names.iter().filter(|n| ix.kind_of(n) == "host" && !have.contains(*n)) {
        let Some(owner) = ix.host_def(h).and_then(|d| d.owner.clone()).filter(|o| !o.is_empty()) else { continue };
        let t = ix.it(h);
        // A scan that read less than the home and the package caches does not clear its owner, whenever it was taken
        let narrow = super::coverage::narrow_roots(ix, h);
        let cands: Vec<&Event> = events.iter().filter(|e| (e.at > t || narrow.is_some()) && ix.commit_authors(&e.repo).contains(&owner.to_lowercase())).collect();
        let Some(e) = cands.iter().min_by(|a, b| a.at.cmp(&b.at)) else { continue };
        let who = ix.person_name(&owner);
        let reason = match &narrow {
            Some(r) if e.at <= t => {
                format!("{who} works in {}, which {} on {}; the scan of {h} ({}) read only {}, not their home or package caches", e.repo, e.what, fmt(&e.at), fmt(&t), r.join(", "))
            }
            _ => format!("{who} works in {}, which {} on {}; host last indexed {}", e.repo, e.what, fmt(&e.at), fmt(&t)),
        };
        out.push(Finding {
            kind: FKind::Host,
            ioc: e.ioc.clone(),
            iocs: e.iocs.clone(),
            where_: h.clone(),
            loc: "-".into(),
            item_kind: "possible".into(),
            state: "possible".into(),
            possible: true,
            reason,
            first_seen: Some(e.at.clone()),
            last_seen: Some(t),
            source: h.clone(),
            location: "-".into(),
            owner: host_owner(ix, h),
            ..Default::default()
        });
    }
    // The author of the commit that brought the bad version in is possible on their own laptop, unless a scan of a
    // machine they own says otherwise (a scan after the commit would be a finding, an older one is handled above).
    let mut member_memo: HashMap<(String, String), super::coverage::MemberReason> = HashMap::new();
    for f in confirmed.iter().filter(|f| f.kind == FKind::Repo && f.state != "install-only") {
        let Some(c) = &f.added_by else { continue };
        let Some(login) = c.author.clone().filter(|a| !a.is_empty()) else { continue };
        // A scan after the exposure that read the home or the package caches says the laptop is clear. A narrow scan, or
        // one from before the exposure, is the machine's own possible row (see `possible_by_owner`); a scan that read
        // nothing, or no machine at all, leaves the person possible here
        let exposed_at = f.first_seen.clone().unwrap_or_default();
        // one answer per (person, exposure time): thousands of findings share a few authors
        let r = member_memo.entry((login.clone(), exposed_at.clone())).or_insert_with(|| super::coverage::member_reason_since(ix, &login, &exposed_at));
        if r.covered || r.partial {
            continue;
        }
        if login.ends_with("[bot]") || ix.person(&login).is_none() {
            continue;
        }
        let who = ix.person_name(&login);
        // br never invents a host name: the row names the person
        let name = format!("{who} (@{login})");
        if out.iter().any(|o| o.where_ == name) {
            continue;
        }
        let at = f.first_seen.clone().unwrap_or_default();
        out.push(Finding {
            kind: FKind::Host,
            ioc: f.ioc.clone(),
            iocs: f.iocs.clone(),
            where_: name.clone(),
            loc: "-".into(),
            item_kind: "possible".into(),
            state: "possible".into(),
            possible: true,
            person: true,
            reason: format!("no machine of theirs is scanned; {who} authored {} in {}, which took the affected {}@{} on {}", c.sha, f.where_, f.name, f.version, fmt(&at)),
            first_seen: Some(at),
            source: name.clone(),
            location: "-".into(),
            owner: Owner { people: vec![login.clone()], ..Default::default() },
            ..Default::default()
        });
    }
    out
}

/// Stored YARA matches on hosts in scope.
fn rule_findings(ix: &Index, q: &Query, names: &[String]) -> BrResult<Vec<Finding>> {
    let mut out = vec![];
    let rs = owner_spec(ix, q)?;
    for y in &ix.v.state.yara_hits {
        let g = |k: &str| y.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let h = g("source_id");
        if !names.contains(&h) || ix.kind_of(&h) != "host" {
            continue;
        }
        if !in_window_pt(q, &g("first_seen")) {
            continue;
        }
        let rule = g("rule");
        if let Some(rs) = &rs {
            if !owner_match(ix, rs, &host_owner(ix, &h)) {
                continue;
            }
        }
        out.push(Finding {
            kind: FKind::Host,
            ioc: format!("yara:{rule}"),
            iocs: vec![format!("yara:{rule}")],
            where_: h.clone(),
            loc: g("path"),
            item_kind: "yara".into(),
            state: "present".into(),
            first_seen: Some(g("first_seen")),
            note: format!("matches YARA rule {rule}"),
            match_: "rule".into(),
            rule: Some(rule),
            ..Default::default()
        });
    }
    Ok(out)
}

// ---- the clock and the freshness probe ---------------------------------------------------
pub fn moved_since(ix: &Index, repo: &str) -> Option<String> {
    let t = ix.i(repo)?;
    ix.repo(repo).commits.iter().filter(|c| t < c.at && c.at <= ix.now).map(|c| c.at.clone()).max()
}

/// The live freshness probe (one GitHub call per repo), installed by the command that has a Ctx.
static PROBE: std::sync::Mutex<Option<Ctx>> = std::sync::Mutex::new(None);

pub fn set_probe(ctx: &Ctx) {
    if let Ok(mut g) = PROBE.lock() {
        *g = Some(ctx.clone());
    }
}

/// The result of one freshness probe: repos with newer commits, and repos whose freshness could not be learned.
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub moved: Vec<(String, String)>,
    pub unknown: Vec<(String, String)>,
}

/// One answer per repo for the life of the process, so the re-entrant hunts (`changed_since_scan`, renderers) never probe twice.
static MEMO: std::sync::Mutex<Option<std::collections::HashMap<String, Result<Option<String>, String>>>> = std::sync::Mutex::new(None);

fn probe_one(ctx: &Ctx, repo: &str, indexed_at: &str) -> Result<Option<String>, String> {
    use crate::collect::github::{Cond, Gh};
    let gh = Gh::new(ctx);
    // the stored ETag of the default-branch commits probe, when a scan left one (B9)
    let stored: std::collections::BTreeMap<String, String> = crate::store::Store::open(ctx, false).ok().and_then(|st| st.kv_get(&format!("etag:{repo}"))).unwrap_or_default();
    // the branch the scan probed, asked again as of this clock: the same URL when the clock did not move, so the stored ETag can answer 304
    let branch = stored.keys().find(|k| k.contains("/commits?sha=")).and_then(|k| k.split("sha=").nth(1).map(|t| t.split('&').next().unwrap_or("").to_string())).filter(|b| !b.is_empty());
    let path = match branch {
        Some(b) => format!("/repos/{repo}/commits?sha={b}&until={}&per_page=1", ctx.now),
        None => format!("/repos/{repo}/commits?until={}&per_page=1", ctx.now),
    };
    gh.load_etags(stored);
    match gh.json_cond(&path) {
        Ok(Cond::NotModified) => Ok(None),
        Ok(Cond::Missing) => Err("HTTP 404: missing, or the token cannot read it".to_string()),
        Ok(Cond::Fresh(v)) => {
            let at = v.as_array().and_then(|a| a.first()).and_then(|c| c["commit"]["committer"]["date"].as_str().or_else(|| c["commit"]["author"]["date"].as_str())).map(str::to_string);
            Ok(at.filter(|t| t.as_str() > indexed_at && t.as_str() <= ctx.now.as_str()))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// The freshness probe. Under BR_DEV_VIEW, or without a live Ctx (a hunt without --now), the answer comes from the commits
/// in the view and nothing touches the network. A failed probe is "unknown", never "unmoved".
pub fn probe_repos(ix: &Index, names: &[String]) -> Probe {
    let live = if std::env::var_os("BR_DEV_VIEW").is_some() { None } else { PROBE.lock().ok().and_then(|g| g.clone()) };
    let mut out = Probe::default();
    for n in names.iter().filter(|n| ix.kind_of(n) == "repo") {
        let Some(t) = ix.i(n) else { continue };
        match &live {
            None => {
                if let Some(at) = moved_since(ix, n) {
                    out.moved.push((n.clone(), at));
                }
            }
            Some(ctx) => {
                let cached = MEMO.lock().ok().and_then(|g| g.as_ref().and_then(|m| m.get(n).cloned()));
                let r = match cached {
                    Some(r) => r,
                    None => {
                        let r = probe_one(ctx, n, &t);
                        if let Ok(mut g) = MEMO.lock() {
                            g.get_or_insert_with(Default::default).insert(n.clone(), r.clone());
                        }
                        r
                    }
                };
                match r {
                    Ok(Some(at)) => out.moved.push((n.clone(), at)),
                    Ok(None) => {}
                    Err(e) => out.unknown.push((n.clone(), e)),
                }
            }
        }
    }
    out
}

/// Kept for `scan --stale`: the repos with newer commits.
pub fn moved_repos(ix: &Index, names: &[String]) -> Vec<(String, String)> {
    probe_repos(ix, names).moved
}

pub fn moved_line(ix: &Index, repo: &str, at: &str) -> String {
    let mut when = fmt(at);
    if when[..5] == fmt(&ix.now)[..5] {
        when = when[6..].to_string();
    }
    format!("{repo} moved since indexed (new commits {when}); br scan --repo {repo} before acting")
}

fn find_ioc(ix: &Index, q: &Query, ioc: &Ioc, repos: &[String], names: &[String]) -> Vec<Finding> {
    match ioc.kind {
        IocKind::Pkg => {
            let mut out = if ioc.rt.is_some() { rt_repo_findings(ix, q, ioc, repos) } else { pkg_repo_findings(ix, q, ioc, repos) };
            out.extend(pkg_other(ix, q, ioc, repos, names));
            if ioc.rt.is_some() {
                out.extend(rt_distro_possible(ix, q, ioc, names));
            }
            out
        }
        IocKind::ActionRef | IocKind::ActionSha => action_findings(ix, q, ioc, repos, names),
        IocKind::Sha256 | IocKind::Simhash => file_findings(ix, q, ioc, repos, names),
        IocKind::Secret => vec![], // answered by query::secret_hunt, not by finding rows
        IocKind::Cert => super::certs::cert_findings(ix, q, ioc, repos, names),
    }
}

// ---- packages ----------------------------------------------------------------------------------
fn pkg_match(ioc: &Ioc, p: &str) -> bool {
    let (e, n, v) = parse_pkg(p);
    I::match_pkg(ioc, e, n, v)
}

fn pkg_repo_findings(ix: &Index, q: &Query, ioc: &Ioc, repos: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    if !q.has("repos") {
        return out;
    }
    for r in repos {
        let hist = ix.lock_hist(r);
        let ioc_eco = ioc.eco.clone().unwrap_or_default();
        let cands: Vec<&LockObs> = hist.named(&ioc_eco, &ioc.name).collect();
        for o in cands.iter().copied() {
            if !pkg_match(ioc, &o.p) {
                continue;
            }
            if q.now_only && o.removed_at.is_some() {
                continue;
            }
            if !in_window_iv(q, &o.first_seen, o.removed_at.as_deref()) {
                continue;
            }
            out.push(repo_finding(ix, r, ioc, o));
        }
        if !q.now_only {
            // installs of an affected version the lockfile never held (one row per such version, earliest run)
            let lock_vers: HashSet<String> = cands.iter().filter(|o| pkg_match(ioc, &o.p)).map(|o| parse_pkg(&o.p).2.to_string()).collect();
            let mut by_ver: std::collections::BTreeMap<String, (&Run, String)> = Default::default();
            for run in ix.runs(r) {
                if !in_window_iv(q, &run.at, Some(&run.at)) {
                    continue;
                }
                for p in run.installed.iter().filter(|p| pkg_match(ioc, p)) {
                    let ver = parse_pkg(p).2.to_string();
                    if lock_vers.iter().any(|l| crate::query::version::same(&ioc_eco, l, &ver)) {
                        continue;
                    }
                    let e = by_ver.entry(ver).or_insert((run, run.at.clone()));
                    if run.at < e.0.at {
                        e.0 = run;
                    }
                    if run.at > e.1 {
                        e.1 = run.at.clone();
                    }
                }
            }
            for (ver, (run, last_run)) in by_ver {
                let mut f = Finding::new(FKind::Repo, ioc, r);
                f.state = "install-only".into();
                f.file = "-".into();
                f.version = ver.clone();
                f.depth = "-".into();
                f.first_seen = Some(run.at.clone());
                // The last run that installed this version, not the time of the last scan; a later run that
                // installed another version has ended it, and it never was a place that a scan could see
                f.last_seen = Some(last_run);
                f.name = ioc.name.clone();
                f.run_id = Some(run.id);
                f.run_runner = run.runner.clone().unwrap_or_default();
                f.explain = format!(
                    "{r} has no lockfile entry for {}@{ver}; run #{} resolved it on {} ({})",
                    ioc.name,
                    run.id,
                    run.runner.clone().unwrap_or_default(),
                    run.resolved_from.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| "source unknown".into())
                );
                out.push(f);
            }
        }
    }
    out
}

fn repo_finding(ix: &Index, r: &str, ioc: &Ioc, o: &LockObs) -> Finding {
    let p = &o.pkg;
    let (eco, name, ver) = parse_pkg(&o.p);
    let archived = ix.repo(r).archived;
    let state = if o.removed_at.is_some() {
        "removed"
    } else if archived {
        "present (archived)"
    } else {
        "present"
    };
    let via: Vec<String> = p.via.iter().map(|x| parse_pkg(x).1.to_string()).collect();
    let mut depth = if p.direct {
        "direct".to_string()
    } else if !via.is_empty() {
        format!("via {}", via.join(" > "))
    } else {
        "transitive".to_string()
    };
    if p.direct && p.dev {
        depth = "direct (dev)".into();
    } else if p.dev && !p.direct {
        depth += " (dev)";
    }
    let mut f = Finding::new(FKind::Repo, ioc, r);
    f.state = state.into();
    f.file = if !o.file.is_empty() { o.file.clone() } else { ix.lockfile(r).unwrap_or_else(|| "-".into()) };
    f.version = ver.to_string();
    f.depth = depth;
    f.via = via;
    f.first_seen = Some(o.first_seen.clone());
    f.removed_at = o.removed_at.clone();
    f.name = name.to_string();
    f.added_by = Some(o.added_by.clone());
    f.removed_by = o.removed_by.clone();
    f.p = Some(o.p.clone());
    f.eco = eco.to_string();
    f.direct = p.direct;
    f.dev = p.dev;
    f.archived = archived;
    if p.direct {
        if let Some(m) = ix.manifest_at(r, &o.first_seen) {
            for (dn, dv) in &m.deps {
                if I::name_key(eco, dn) == I::name_key(eco, name) {
                    f.manifest_line = dv.line;
                    f.manifest_path = Some(m.path.clone());
                }
            }
        }
    }
    f
}

fn pkg_other(ix: &Index, q: &Query, ioc: &Ioc, repos: &[String], names: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    for r in repos {
        if q.has("ci") && !q.now_only {
            for run in ix.runs(r) {
                if run.installed.iter().any(|p| pkg_match(ioc, p)) && in_window_iv(q, &run.at, Some(&run.at)) {
                    let mut f = run_finding(ix, r, run, ioc, None);
                    if ioc.rt.is_some() {
                        // a runtime in a run's log is not code that ran from an install: no secrets are named for it
                        f.secrets.clear();
                        f.rt = run.installed.iter().find(|p| pkg_match(ioc, p)).and_then(|p| rt_from_pkg(ioc, p, &f.resolved_from));
                    }
                    out.push(f);
                }
            }
        }
        if q.has("caches") {
            for c in ix.caches(r) {
                if c.contains.iter().any(|p| pkg_match(ioc, p)) && in_window_pt(q, &c.created) {
                    let mut f = Finding::new(FKind::Cache, ioc, r);
                    f.key = c.key.clone();
                    f.created = c.created.clone();
                    f.last_used = c.last_used.clone();
                    f.size_mb = c.size_mb;
                    f.first_seen = Some(c.created.clone());
                    out.push(f);
                }
            }
        }
        if q.has("artifacts") {
            for a in ix.artifacts(r) {
                if !a.contains.iter().any(|p| pkg_match(ioc, p)) {
                    continue;
                }
                let expires = a.expires.clone().unwrap_or_default();
                if q.now_only && !expires.is_empty() && expires <= ix.now {
                    continue;
                }
                if in_window_pt(q, &a.created) {
                    let mut f = Finding::new(FKind::Artifact, ioc, r);
                    f.name = a.name.clone();
                    f.id = a.id;
                    f.created = a.created.clone();
                    f.expires_unknown = expires.is_empty();
                    f.expires = expires;
                    f.first_seen = Some(a.created.clone());
                    f.size_mb = a.size_mb;
                    out.push(f);
                }
            }
        }
    }
    if q.has("images") && images_in_scope(ix, q, names) {
        if ioc.rt.is_some() {
            out.extend(rt_image_findings(ix, q, ioc, names));
        } else {
            out.extend(image_findings(ix, q, ioc, names, &|layer, _b| {
                if layer.packages.iter().any(|p| pkg_match(ioc, p)) {
                    Some(String::new())
                } else {
                    None
                }
            }));
        }
    }
    if q.has("hosts") {
        out.extend(host_pkg_findings(ix, q, ioc, names));
    }
    out
}

fn images_in_scope(ix: &Index, q: &Query, names: &[String]) -> bool {
    q.repo.as_ref().is_some_and(|r| !r.is_empty()) || names.iter().any(|n| ix.kind_of(n) == "registry")
}

fn run_finding(ix: &Index, repo: &str, run: &Run, ioc: &Ioc, via: Option<&str>) -> Finding {
    let mut wf = run.workflow.clone();
    if let Some(v) = via {
        wf = format!("{wf} (via {v})");
    }
    let sec = if !run.secrets.is_empty() { run.secrets.clone() } else { workflow_secrets(ix, repo, &run.workflow) };
    let mut f = Finding::new(FKind::CiRun, ioc, repo);
    f.id = run.id;
    f.at = run.at.clone();
    f.runner = run.runner.clone().unwrap_or_default();
    f.workflow = wf;
    f.secrets = sec;
    f.resolved_from = run.resolved_from.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| "source unknown".into());
    f.first_seen = Some(run.at.clone());
    f.commit = run.commit.clone();
    f
}

fn workflow_secrets(ix: &Index, repo: &str, wf: &str) -> Vec<String> {
    ix.repo(repo).workflows.iter().find(|w| basename(&w.file) == wf).map(|w| w.secrets.clone()).unwrap_or_default()
}

/// Layer number that deletes what `layer_n` added, or None when it survives in the final image.
fn whiteout_hits_pkg(eco: &str, name: &str, w: &str) -> bool {
    let w = w.trim_end_matches('/');
    let k = I::name_key(eco, name);
    match eco {
        "npm" => w.ends_with(&format!("node_modules/{name}")),
        "pypi" => {
            let last = w.rsplit('/').next().unwrap_or("");
            let stem = last.split(".dist-info").next().unwrap_or(last);
            let stem = stem.split(".egg-info").next().unwrap_or(stem);
            let base = stem.rsplit_once('-').filter(|(_, v)| v.chars().next().is_some_and(|c| c.is_ascii_digit())).map_or(stem, |(n, _)| n);
            w.contains("site-packages") && I::name_key("pypi", base) == k
        }
        "cargo" => {
            let last = w.rsplit('/').next().unwrap_or("");
            w.contains("registry") && last.rsplit_once('-').is_some_and(|(n, _)| I::name_key("cargo", n) == k)
        }
        "go" => w.contains("pkg/mod") && go_decode(w).contains(&name.to_lowercase()),
        _ => false,
    }
}

fn deleted_layer(build: &ImageBuild, layer_n: u32, path: Option<&str>, pkg: Option<(&str, &str)>) -> Option<u32> {
    let later: Vec<&Layer> = build.layers.iter().filter(|l| l.n > layer_n && !l.whiteouts.is_empty()).collect();
    for l in &later {
        for w in &l.whiteouts {
            if let Some(p) = path {
                if w == p || p.starts_with(&format!("{}/", w.trim_end_matches('/'))) {
                    return Some(l.n);
                }
            }
            if let Some((eco, k)) = pkg {
                if whiteout_hits_pkg(eco, k, w) {
                    return Some(l.n);
                }
            }
        }
    }
    if let Some((eco, k)) = pkg {
        if let Some(fs) = &build.final_fs_has {
            if !fs.iter().any(|x| {
                let (e, n, _) = parse_pkg(x);
                (e.is_empty() || e == eco) && I::name_key(eco, n) == I::name_key(eco, k)
            }) {
                return later.first().map(|l| l.n);
            }
        }
    }
    None
}

fn image_findings(ix: &Index, q: &Query, ioc: &Ioc, names: &[String], layer_match: &dyn Fn(&Layer, &ImageBuild) -> Option<String>) -> Vec<Finding> {
    let mut out = vec![];
    let by_repo = q.repo.as_ref().is_some_and(|r| !r.is_empty());
    for b in ix.images() {
        if !in_window_pt(q, &b.built) {
            continue;
        }
        if !by_repo {
            match ix.registry_of(&b.repository) {
                Some(reg) if names.contains(&reg) => {}
                _ => continue,
            }
        }
        let mut hit: Option<(u32, Option<&Layer>, String)> = None;
        for layer in &b.layers {
            if let Some(m) = layer_match(layer, b) {
                hit = Some((layer.n, Some(layer), m));
                break;
            }
        }
        if hit.is_none() && ioc.kind == IocKind::Pkg && b.packages.iter().any(|p| pkg_match(ioc, p)) {
            hit = Some((0, None, String::new()));
        }
        let Some((n, layer, path)) = hit else { continue };
        let mut dl = None;
        if n != 0 {
            dl = deleted_layer(
                b,
                n,
                if path.is_empty() { None } else { Some(path.as_str()) },
                if ioc.kind == IocKind::Pkg { Some((ioc.eco.as_deref().unwrap_or("npm"), ioc.name.as_str())) } else { None },
            );
        }
        let where_in = match dl {
            None => "final image".to_string(),
            Some(d) => format!("layer {n} (deleted in layer {d})"),
        };
        let src = b.source.clone().unwrap_or_default();
        let mut f = Finding::new(FKind::Image, ioc, &b.repository);
        f.image = b.repository.clone();
        f.tags = b.tags.clone();
        f.digest = b.digest.clone();
        f.built = b.built.clone();
        f.from_repo = src.repo;
        f.commit = src.commit;
        f.where_in = where_in;
        f.layer = n;
        f.run_id = src.run;
        f.layer_cmd = layer.and_then(|l| l.created_by.clone());
        f.layer_blob = layer.and_then(|l| l.blob.clone());
        f.deleted_in = dl;
        f.executed_in_layer = if path.is_empty() { None } else { super::related::executed_in_layer(b, n, &path) };
        f.path = path;
        f.first_seen = Some(b.built.clone());
        out.push(f);
    }
    out
}

/// A cache hit of a package that runs code at install is an execution, so the note says the install likely ran.
pub fn install_ran_note(note: &str) -> bool {
    note.contains("the install likely ran") || note.starts_with("the install ran here")
}

/// The CI runs that installed a package matching `ioc` on this runner. A runner where a CI run installed it is a place where
/// the install ran, whatever else holds the package.
fn ci_installs_on(ix: &Index, host: &str, ioc: &Ioc) -> Vec<String> {
    let Some(runs) = ix.runs_by_runner().get(&super::index::runner_key(host)) else { return vec![] };
    let mut v: Vec<String> = runs.iter().filter(|(_, r)| r.installed.iter().any(|p| pkg_match(ioc, p))).map(|(repo, r)| format!("{repo}#{}", r.id)).collect();
    v.sort();
    v.dedup();
    v
}

/// The host note when CI runs installed the package there: one verdict, which fix, purge and notify repeat.
fn ci_install_note(q: &Query, ci: &[String]) -> String {
    if q.adv.as_ref().is_some_and(|a| crate::query::risk::runs_at_install_parts(&a.id, &a.aliases, &a.title, &a.text)) {
        format!("the install ran here (CI run {})", ci.join(", "))
    } else {
        format!("a CI run installed it here ({})", ci.join(", "))
    }
}

fn cache_only_note(q: &Query) -> &'static str {
    if q.adv.as_ref().is_some_and(|a| crate::query::risk::runs_at_install_parts(&a.id, &a.aliases, &a.title, &a.text)) {
        "cache only; the install likely ran"
    } else {
        "cache only, no project references it"
    }
}

fn host_pkg_findings(ix: &Index, q: &Query, ioc: &Ioc, names: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    let mut seen_hosts: HashSet<String> = HashSet::new();
    let hosts: Vec<&String> = names.iter().filter(|n| ix.kind_of(n) == "host").collect();
    for h in &hosts {
        for it in ix.host_items(h) {
            if it.pkgs.iter().any(|p| pkg_match(ioc, p)) && in_window_pt(q, &it.at) {
                let mut f = Finding::new(FKind::Host, ioc, h);
                f.loc = it.loc.clone();
                f.item_kind = it.kind.clone();
                f.state = "present".into();
                f.first_seen = Some(it.at.clone());
                f.ci_installs = ci_installs_on(ix, h, ioc);
                f.note = if !f.ci_installs.is_empty() && is_cache_only(ix, h, it, ioc) {
                    ci_install_note(q, &f.ci_installs)
                } else if is_cache_only(ix, h, it, ioc) {
                    cache_only_note(q).into()
                } else {
                    String::new()
                };
                f.item_pkgs = it.pkgs.clone();
                f.hit_pkgs = it.pkgs.iter().filter(|p| pkg_match(ioc, p)).cloned().collect();
                if ioc.rt.is_some() {
                    f.rt = f.hit_pkgs.first().and_then(|p| rt_from_pkg(ioc, p, &it.loc));
                }
                out.push(f);
                seen_hosts.insert(h.to_string());
            }
        }
    }
    // inference: a run on this self-hosted runner after the last scan (one pass over the runner index)
    let by_runner = ix.runs_by_runner();
    for h in &hosts {
        if seen_hosts.contains(*h) {
            continue;
        }
        let Some(runs) = by_runner.get(&super::index::runner_key(h)) else { continue };
        let scanned = ix.it(h);
        let mut best: Option<(&str, &Run)> = None;
        for (r, run) in runs {
            if run.at.as_str() <= scanned.as_str() || !in_window_pt(q, &run.at) {
                continue;
            }
            if !run.installed.iter().any(|p| pkg_match(ioc, p)) {
                continue;
            }
            if best.is_none_or(|(_, b)| run.at < b.at) {
                best = Some((*r, *run));
            }
        }
        let Some((r, run)) = best else { continue };
        let inst = ix.repo(r).workflows.iter().find(|w| basename(&w.file) == run.workflow).and_then(|w| w.install.clone()).unwrap_or_default();
        let loc = match ioc.eco.as_deref().unwrap_or("npm") {
            "pypi" => {
                if inst.contains("uv ") || inst.starts_with("uv") {
                    "uv cache"
                } else if inst.contains("poetry") {
                    "poetry cache"
                } else {
                    "pip cache"
                }
            }
            "cargo" => "cargo registry",
            "go" => "go module cache",
            "runtime" => "tool cache",
            _ => {
                if inst.contains("pnpm") {
                    "pnpm store"
                } else if inst.contains("yarn") {
                    "yarn cache"
                } else {
                    "npm cache"
                }
            }
        };
        let mut f = Finding::new(FKind::Host, ioc, h);
        f.loc = loc.into();
        f.item_kind = "inferred".into();
        f.state = format!("inferred (from {r}#{}; host last scanned {})", run.id, fmt(&scanned));
        f.inferred = true;
        f.possible = true;
        f.first_seen = Some(run.at.clone());
        f.reason = format!("run {r}#{} on {h} resolved the affected package on {}; host last indexed {}", run.id, fmt(&run.at), fmt(&scanned));
        out.push(f);
        seen_hosts.insert(h.to_string());
    }
    out
}

fn is_cache_only(ix: &Index, host: &str, item: &HostItem, ioc: &Ioc) -> bool {
    if !item.kind.contains("cache") && !item.kind.contains("store") {
        return false;
    }
    !ix.host_items(host).iter().any(|i| !std::ptr::eq(*i, item) && i.pkgs.iter().any(|p| pkg_match(ioc, p)) && !i.kind.contains("cache") && !i.kind.contains("store"))
}

// ---- runtimes ---------------------------------------------------------------------------------------
fn rt_floor(ioc: &Ioc) -> usize {
    super::runtime::lookup(&ioc.name).map_or(1, |r| r.line_depth)
}

/// The sighting `pkg` (`runtime:node@22.22.9`) judged against the indicator.
fn rt_from_pkg(ioc: &Ioc, pkg: &str, seen_as: &str) -> Option<RtInfo> {
    let (_, name, ver) = parse_pkg(pkg);
    rt_info(ioc, name, ver, seen_as)
}

fn rt_info(ioc: &Ioc, runtime: &str, version: &str, seen_as: &str) -> Option<RtInfo> {
    let hit = ioc.rt.as_ref()?.eval(version, rt_floor(ioc))?;
    Some(RtInfo { runtime: runtime.to_string(), version: version.to_string(), seen_as: seen_as.to_string(), line_fixed: hit.line_fixed, eol: hit.eol, move_to: hit.move_to })
}

/// Repos: the exact runtime versions their files name, now and in the history that was read.
fn rt_repo_findings(ix: &Index, q: &Query, ioc: &Ioc, repos: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    if !q.has("repos") {
        return out;
    }
    for r in repos {
        let repo = ix.repo(r);
        for x in repo.runtimes.iter().filter(|x| x.runtime == ioc.name && !x.floating) {
            let Some(v) = x.version.as_deref() else { continue };
            let Some(info) = rt_info(ioc, &x.runtime, v, &x.seen_as) else { continue };
            if q.now_only && x.removed_at.is_some() {
                continue;
            }
            let first = x.first_seen.clone().unwrap_or_else(|| ix.it(r));
            if !in_window_iv(q, &first, x.removed_at.as_deref()) {
                continue;
            }
            let mut f = Finding::new(FKind::Repo, ioc, r);
            f.state = if x.removed_at.is_some() {
                "removed"
            } else if repo.archived {
                "present (archived)"
            } else {
                "present"
            }
            .into();
            f.file = x.file.clone();
            f.version = v.to_string();
            f.depth = "-".into();
            f.name = ioc.name.clone();
            f.eco = "runtime".into();
            f.first_seen = Some(first);
            f.removed_at = x.removed_at.clone();
            f.archived = repo.archived;
            f.p = Some(super::runtime::pseudo(&ioc.name, v));
            f.manifest_path = Some(x.file.clone());
            f.manifest_line = Some(x.line as u32).filter(|l| *l > 0);
            f.added_by = x.commit.as_ref().map(|c| CommitRef { sha: c.clone(), author: x.author.clone(), message: None });
            f.explain = format!("{} names {} {}", x.seen_as, ioc.name, v);
            f.rt = Some(info);
            out.push(f);
        }
    }
    out
}

/// Floating references (`php:8.3-apache`, `node-version: 22`, `lts/*`): what they run depends on when they were built or run.
fn floating_refs(ix: &Index, q: &Query, repos: &[String]) -> Vec<Floating> {
    let mut out: Vec<Floating> = vec![];
    if !q.has("repos") {
        return out;
    }
    for ioc in q.iocs.iter().filter(|i| i.rt.is_some()) {
        let Some(sp) = &ioc.rt else { continue };
        for r in repos {
            for x in ix.repo(r).runtimes.iter().filter(|x| x.runtime == ioc.name && x.floating && x.removed_at.is_none()) {
                if !sp.floating_may_hit(&x.spec, rt_floor(ioc)) {
                    continue;
                }
                if out.iter().any(|o| o.repo == *r && o.file == x.file && o.line == x.line && o.spec == x.spec && o.seen_as == x.seen_as && o.runtime == x.runtime) {
                    continue;
                }
                out.push(Floating {
                    repo: r.clone(),
                    file: x.file.clone(),
                    line: x.line,
                    runtime: x.runtime.clone(),
                    spec: x.spec.clone(),
                    seen_as: x.seen_as.clone(),
                    first_seen: x.first_seen.clone(),
                    ioc: ioc.text.clone(),
                });
            }
        }
    }
    out.sort_by(|a, b| (&a.repo, &a.file, a.line).cmp(&(&b.repo, &b.file, b.line)));
    out
}

fn deleted_layer_rt(b: &ImageBuild, layer_n: u32, pk: &str) -> Option<u32> {
    let (_, name, ver) = parse_pkg(pk);
    let later: Vec<&Layer> = b.layers.iter().filter(|l| l.n > layer_n && !l.whiteouts.is_empty()).collect();
    for l in &later {
        for w in &l.whiteouts {
            if let Some((rn, rv, _)) = super::runtime::install_root(&format!("{}/", w.trim_end_matches('/'))) {
                if rn == name && rv == ver {
                    return Some(l.n);
                }
            }
        }
    }
    if let Some(fs) = &b.final_fs_has {
        if !fs.iter().any(|x| x == pk) {
            return later.first().map(|l| l.n);
        }
    }
    None
}

/// Images: the runtime in the config Env, or an install directory in a layer. One row per version; a version that only a
/// deleted layer held is listed as deleted, and only when the image's final filesystem no longer has it.
fn rt_image_findings(ix: &Index, q: &Query, ioc: &Ioc, names: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    let by_repo = q.repo.as_ref().is_some_and(|r| !r.is_empty());
    for b in ix.images() {
        if !in_window_pt(q, &b.built) {
            continue;
        }
        if !by_repo {
            match ix.registry_of(&b.repository) {
                Some(reg) if names.contains(&reg) => {}
                _ => continue,
            }
        }
        let mut cands: Vec<(u32, Option<&Layer>, &String)> = vec![];
        for l in &b.layers {
            for p in l.packages.iter().filter(|p| pkg_match(ioc, p)) {
                cands.push((l.n, Some(l), p));
            }
        }
        for p in b.packages.iter().filter(|p| pkg_match(ioc, p)) {
            cands.push((0, None, p));
        }
        let mut done: Vec<&String> = vec![];
        for (_, _, pk) in cands.iter() {
            if done.contains(pk) {
                continue;
            }
            done.push(pk);
            // the occurrence that survives wins; else the first
            let with_dl: Vec<(&(u32, Option<&Layer>, &String), Option<u32>)> = cands.iter().filter(|c| c.2 == *pk).map(|c| (c, if c.0 == 0 { None } else { deleted_layer_rt(b, c.0, pk) })).collect();
            let (c, dl) = with_dl.iter().find(|(_, d)| d.is_none()).or_else(|| with_dl.first()).copied().unwrap();
            let (n, layer, _) = *c;
            let src = b.source.clone().unwrap_or_default();
            let mut f = Finding::new(FKind::Image, ioc, &b.repository);
            f.image = b.repository.clone();
            f.tags = b.tags.clone();
            f.digest = b.digest.clone();
            f.built = b.built.clone();
            f.from_repo = src.repo;
            f.commit = src.commit;
            f.where_in = match dl {
                None => "final image".to_string(),
                Some(d) => format!("layer {n} (deleted in layer {d})"),
            };
            f.layer = n;
            f.run_id = src.run;
            f.layer_cmd = layer.and_then(|l| l.created_by.clone());
            f.layer_blob = layer.and_then(|l| l.blob.clone());
            f.deleted_in = dl;
            f.first_seen = Some(b.built.clone());
            let seen = if n == 0 { "image config Env".to_string() } else { format!("install directory in layer {n}") };
            f.rt = rt_from_pkg(ioc, pk, &seen);
            out.push(f);
        }
    }
    out
}

/// Distro packages (`distro:php8.3@8.3.6-0ubuntu0.24.04.2`): the distro backports fixes without changing the upstream version,
/// so br cannot tell. They are possible, never found, and never make the answer clear.
fn rt_distro_possible(ix: &Index, q: &Query, ioc: &Ioc, names: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    let hits = |pkgs: &[String]| -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = vec![];
        for p in pkgs {
            let (e, n, ver) = parse_pkg(p);
            if e == super::runtime::DISTRO && super::runtime::distro_runtime(n) == Some(ioc.name.as_str()) && !v.iter().any(|x| x.0 == n && x.1 == ver) {
                v.push((n.to_string(), ver.to_string()));
            }
        }
        v
    };
    let words = |v: &[(String, String)]| v.iter().map(|(n, ver)| format!("distro package {n} {ver}: check your distro's advisory")).collect::<Vec<_>>().join("; ");
    if q.has("images") && images_in_scope(ix, q, names) {
        let by_repo = q.repo.as_ref().is_some_and(|r| !r.is_empty());
        for b in ix.images() {
            if !in_window_pt(q, &b.built) {
                continue;
            }
            if !by_repo {
                match ix.registry_of(&b.repository) {
                    Some(reg) if names.contains(&reg) => {}
                    _ => continue,
                }
            }
            let mut all: Vec<String> = vec![];
            for l in &b.layers {
                all.extend(l.packages.iter().cloned());
            }
            all.extend(b.packages.iter().cloned());
            let mut v = hits(&all);
            if let Some(fs) = &b.final_fs_has {
                v.retain(|(n, ver)| fs.contains(&super::runtime::pseudo_distro(n, ver)));
            }
            if v.is_empty() {
                continue;
            }
            let mut f = Finding::new(FKind::Image, ioc, &b.repository);
            f.possible = true;
            f.image = b.repository.clone();
            f.tags = b.tags.clone();
            f.digest = b.digest.clone();
            f.built = b.built.clone();
            f.first_seen = Some(b.built.clone());
            let tag = b.tags.first().map(|t| format!(":{t}")).unwrap_or_default();
            f.reason = format!("image {}{tag} ({}): {}", b.repository, b.digest.chars().take(19).collect::<String>(), words(&v));
            out.push(f);
        }
    }
    if q.has("hosts") {
        for h in names.iter().filter(|n| ix.kind_of(n) == "host") {
            let mut all: Vec<String> = vec![];
            let mut at = None;
            for it in ix.host_items(h) {
                let before = all.len();
                all.extend(it.pkgs.iter().cloned());
                if all.len() != before && at.is_none() {
                    at = Some(it);
                }
            }
            let v = hits(&all);
            if v.is_empty() {
                continue;
            }
            let mut f = Finding::new(FKind::Host, ioc, h);
            f.possible = true;
            f.loc = at.map(|i| i.loc.clone()).unwrap_or_default();
            f.item_kind = "distro-packages".into();
            f.first_seen = at.map(|i| i.at.clone());
            f.reason = words(&v);
            out.push(f);
        }
    }
    out
}

/// A scanned host with no install directory for a queried runtime is a gap: br reads install directories, never a binary on PATH.
fn rt_host_rows(ix: &Index, q: &Query, names: &[String]) -> Vec<NotChecked> {
    let mut rows = vec![];
    if !q.has("hosts") {
        return rows;
    }
    for ioc in q.iocs.iter().filter(|i| i.rt.is_some()) {
        let prefix = format!("{}:{}@", super::runtime::ECO, ioc.name);
        for h in names.iter().filter(|n| ix.kind_of(n) == "host") {
            if ix.srcs.get(h).is_some_and(crate::collect::words::never_scanned) {
                continue;
            }
            if ix.host_items(h).iter().any(|it| it.pkgs.iter().any(|p| p.starts_with(&prefix))) {
                continue;
            }
            if rows.iter().any(|r: &NotChecked| r.name == *h && r.why.contains(&format!("for {} ", ioc.name))) {
                continue;
            }
            rows.push(NotChecked {
                name: h.clone(),
                kind: "host".into(),
                state: "no install directory".into(),
                why: format!("no install directory found for {} (a binary on PATH from elsewhere is not checked)", ioc.name),
                indexed_at: ix.i(h),
                command: close_command("host", h, ix.srcs.get(h).map(|s| s.reach.as_str())),
                people: vec![],
            });
        }
    }
    rows
}

// ---- files (sha256, simhash) -------------------------------------------------------------------
fn hamming_sim(a: &str, b: &str) -> f64 {
    match (u64::from_str_radix(a.trim_start_matches("0x"), 16), u64::from_str_radix(b.trim_start_matches("0x"), 16)) {
        (Ok(x), Ok(y)) => 1.0 - (x ^ y).count_ones() as f64 / 64.0,
        _ => -1.0,
    }
}

fn file_match(ioc: &Ioc, f: &HostFile) -> (bool, Option<f64>) {
    if ioc.kind == IocKind::Sha256 {
        return (f.sha256 == ioc.sha, None);
    }
    if let Some(sh) = f.simhash.as_ref().filter(|s| !s.is_empty()) {
        let s = hamming_sim(&ioc.sha, sh);
        if s < 0.0 {
            return (false, None);
        }
        return (s >= ioc.thr - 1e-9, Some(s));
    }
    (false, None)
}

fn full_path(it: &HostItem, f: &HostFile) -> String {
    if f.path.starts_with('/') {
        f.path.clone()
    } else {
        format!("{}/{}", it.loc.trim_end_matches('/'), f.path)
    }
}

fn file_findings(ix: &Index, q: &Query, ioc: &Ioc, repos: &[String], names: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    if q.has("hosts") {
        for h in names.iter().filter(|n| ix.kind_of(n) == "host") {
            for it in ix.host_items(h) {
                for f in &it.files {
                    let (ok, sim) = file_match(ioc, f);
                    // presence in a window is decided by when the scans saw the file, never by its mtime
                    let when = it.at.clone();
                    let last = ix.i(h);
                    if ok && in_window_iv(q, &when, last.as_deref()) {
                        let mut x = Finding::new(FKind::Host, ioc, h);
                        x.loc = full_path(it, f);
                        x.item_kind = it.kind.clone();
                        x.state = "present".into();
                        x.first_seen = Some(when);
                        x.sim = sim;
                        x.match_ = if ioc.kind == IocKind::Simhash { "similar" } else { "exact" }.into();
                        x.sha256 = f.sha256.clone();
                        x.item_pkgs = it.pkgs.clone();
                        out.push(x);
                    }
                }
            }
        }
    }
    if ioc.kind == IocKind::Sha256 {
        if q.has("images") && images_in_scope(ix, q, names) {
            out.extend(image_findings(ix, q, ioc, names, &|layer, _b| layer.files.iter().find(|f| f.sha256 == ioc.sha).map(|f| f.path.clone())));
        }
        if q.has("releases") {
            for r in repos {
                for rel in ix.releases(r) {
                    for a in &rel.assets {
                        if a.sha256 == ioc.sha && in_window_pt(q, &rel.published) {
                            let mut f = Finding::new(FKind::ReleaseAsset, ioc, r);
                            f.tag = rel.tag.clone();
                            f.asset = a.name.clone();
                            f.sha256 = a.sha256.clone();
                            f.published = rel.published.clone();
                            f.first_seen = Some(rel.published.clone());
                            out.push(f);
                        }
                    }
                }
            }
        }
    }
    out
}

// ---- actions -----------------------------------------------------------------------------------
/// [(uses-text, via or None, sha)] from a run's action_resolved map.
pub fn run_resolved(run: &Run) -> Vec<(String, Option<String>, String)> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?s)^(.+?) \(via (.+)\)$").unwrap());
    run.action_resolved
        .iter()
        .map(|(k, sha)| match re.captures(k) {
            Some(m) => (m[1].to_string(), Some(m[2].to_string()), sha.clone()),
            None => (k.clone(), None, sha.clone()),
        })
        .collect()
}

fn ioc_run_match(ioc: &Ioc, uses: &str, sha: &str) -> bool {
    let (name, r) = I::split_use(uses);
    if !I::action_name_matches(&ioc.name, &name) {
        return false;
    }
    if ioc.kind == IocKind::ActionRef {
        I::action_ref_matches(ioc, &r)
    } else {
        sha.eq_ignore_ascii_case(&ioc.sha)
    }
}

fn action_findings(ix: &Index, q: &Query, ioc: &Ioc, repos: &[String], names: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    for r in repos {
        if q.has("ci") && !q.now_only {
            for run in ix.runs(r) {
                for (uses, via, sha) in run_resolved(run) {
                    if ioc_run_match(ioc, &uses, &sha) && in_window_iv(q, &run.at, Some(&run.at)) {
                        out.push(run_finding(ix, r, run, ioc, via.as_deref()));
                        break;
                    }
                }
            }
        }
        if ioc.kind == IocKind::ActionRef && q.has("repos") {
            out.extend(workflow_ref_findings(ix, q, ioc, r));
        }
    }
    if q.has("hosts") && ioc.kind == IocKind::ActionSha {
        for h in names.iter().filter(|n| ix.kind_of(n) == "host") {
            for it in ix.host_items(h) {
                if it.loc.trim_end_matches('/').to_lowercase().ends_with(&ioc.sha.to_lowercase()) && in_window_pt(q, &it.at) {
                    let mut f = Finding::new(FKind::Host, ioc, h);
                    f.loc = it.loc.clone();
                    f.item_kind = it.kind.clone();
                    f.state = "present".into();
                    f.first_seen = Some(it.at.clone());
                    f.item_pkgs = it.pkgs.clone();
                    out.push(f);
                }
            }
        }
    }
    out
}

fn workflow_ref_findings(ix: &Index, q: &Query, ioc: &Ioc, r: &str) -> Vec<Finding> {
    let mut out = vec![];
    let rep = ix.repo(r);
    let mut entries: Vec<(&str, &Vec<String>, bool)> = rep.workflows.iter().map(|w| (w.file.as_str(), &w.uses, false)).collect();
    entries.extend(rep.composite_actions.iter().map(|c| (c.path.as_str(), &c.uses, true)));
    for (file, uses, composite) in entries {
        for u in uses {
            let (name, rf) = I::split_use(u);
            if !I::action_name_matches(&ioc.name, &name) || !I::action_ref_matches(ioc, &rf) {
                continue;
            }
            let n = count_runs(ix, q, r, file, composite, u);
            let t = ix.it(r);
            let stale_unknown = q.window.as_ref().is_some_and(|w| t < w.1);
            let mut f = Finding::new(FKind::WorkflowRef, ioc, r);
            f.file = file.to_string();
            f.ref_ = rf.clone();
            f.ref_kind = I::action_kind(&rf, if composite { Some(file) } else { None }).to_string();
            f.runs = if stale_unknown { "unknown (stale)".to_string() } else { n.to_string() };
            f.uses = u.clone();
            f.composite = composite;
            out.push(f);
        }
    }
    out
}

fn count_runs(ix: &Index, q: &Query, repo: &str, file: &str, composite: bool, uses: &str) -> usize {
    let mut n = 0;
    if composite {
        let comp = format!("{repo}/{}", dirname(file));
        return ix.composite_runs().get(&(uses.to_string(), comp)).map_or(0, |ts| ts.iter().filter(|t| in_window_pt(q, t)).count());
    }
    let base = basename(file);
    for run in ix.runs(repo) {
        if run.workflow != base || !in_window_pt(q, &run.at) {
            continue;
        }
        if run_resolved(run).iter().any(|(u, via, _)| u == uses && via.is_none()) {
            n += 1;
        }
    }
    n
}

// ---- near misses -------------------------------------------------------------------------------
fn near_misses(ix: &Index, ioc: &Ioc, repos: &[String]) -> Vec<Near> {
    let (mut out, mut seen) = (vec![], HashSet::new());
    match ioc.kind {
        IocKind::Pkg => {
            for r in repos {
                for o in ix.lock_hist(r).obs.iter() {
                    let (eco, name, ver) = parse_pkg(&o.p);
                    if let Some(why) = I::near_pkg(ioc, eco, name, ver) {
                        if seen.insert((r.clone(), o.p.clone())) {
                            out.push(Near { repo: r.clone(), found: format!("{name}@{ver}"), why: why.into() });
                        }
                    }
                }
            }
        }
        IocKind::ActionRef | IocKind::ActionSha => {
            for r in repos {
                let rep = ix.repo(r);
                let mut uses: Vec<&String> = rep.workflows.iter().flat_map(|w| w.uses.iter()).collect();
                uses.extend(rep.composite_actions.iter().flat_map(|c| c.uses.iter()));
                for u in uses {
                    if let Some(why) = I::action_near(ioc, u) {
                        if seen.insert((r.clone(), u.clone())) {
                            let found = if u.chars().count() < 60 { u.clone() } else { format!("{}...", u.chars().take(40).collect::<String>()) };
                            out.push(Near { repo: r.clone(), found, why: why.into() });
                        }
                    }
                }
            }
        }
        _ => {}
    }
    out
}

// ---- verdict helpers ---------------------------------------------------------------------------
pub fn verdict(res: &HuntResult) -> &'static str {
    if !findings(res).is_empty() || !res.present_after.is_empty() {
        "FOUND"
    } else if !res.gaps.is_empty() || !res.never.is_empty() || !res.possible.is_empty() || !res.not_checked.is_empty() || !res.floating.is_empty() {
        "CLEAR WITH GAPS"
    } else {
        "CLEAR"
    }
}

pub fn secrets_of(res: &HuntResult) -> Vec<String> {
    let mut seen: Vec<String> = vec![];
    for f in findings(res).into_iter().chain(past_runs(res)) {
        if f.kind == FKind::CiRun {
            for s in &f.secrets {
                if !seen.contains(s) {
                    seen.push(s.clone());
                }
            }
        }
    }
    seen
}

#[derive(Debug, Clone, Default)]
pub struct Counts {
    pub repos: usize,
    pub repo_rows: usize,
    /// (present, removed, install-only)
    pub repo_states: (usize, usize, usize),
    pub ci_runs: usize,
    pub caches: usize,
    pub artifacts: usize,
    pub images: usize,
    pub image_rows: usize,
    pub hosts: usize,
    pub host_rows: usize,
    pub possible: usize,
    pub releases: usize,
    pub workflow_refs: usize,
    pub secrets: usize,
    pub teams: usize,
    pub places: usize,
    pub total: usize,
    pub near: usize,
    pub findings: usize,
    pub locations: usize,
    pub findings_now: usize,
    pub findings_all: usize,
    pub locations_now: usize,
    pub rule_matches: usize,
    pub unowned_repos: usize,
    /// Rows present now whose first sighting is after the window (counted beside the headline, never inside it)
    pub present_after: usize,
    /// Everything that is still there, by kind, whichever view asks (in the window or first seen after it)
    pub now: PresentNow,
    /// Possible rows that name a machine, and those that name a person
    pub possible_machines: usize,
    pub possible_people: usize,
    /// Files that look like the sample but are not it: listed under SIMILARITY, never counted as places to clean
    pub similar: usize,
    /// Separate secrets (a name set in 3 repos is 3), beside `secrets`, the names
    pub secrets_separate: usize,
    /// Floating runtime references (reported apart, never counted as found)
    pub floating: usize,
}

impl Counts {
    /// "9 secrets", or "9 secret names, 11 secrets" when a name stands for more than one secret.
    pub fn secret_words(&self) -> String {
        super::secrets::secret_words(self.secrets, self.secrets_separate)
    }
}

/// The one place "present now" is counted: distinct places that are still there, by kind.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PresentNow {
    pub repos: usize,
    pub images: usize,
    pub hosts: usize,
    pub caches: usize,
    pub artifacts: usize,
    pub releases: usize,
    pub workflow_refs: usize,
}

impl PresentNow {
    pub fn total(&self) -> usize {
        self.repos + self.images + self.hosts + self.caches + self.artifacts + self.releases + self.workflow_refs
    }

    /// "2 repos", "1 image", "3 machines", ...: every kind that has a count
    pub fn bits(&self) -> Vec<String> {
        [
            (self.repos, "repo"),
            (self.images, "image"),
            (self.hosts, "machine"),
            (self.caches, "cache"),
            (self.artifacts, "build artifact"),
            (self.releases, "release asset"),
            (self.workflow_refs, "workflow reference"),
        ]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, w)| plural(*n, w))
        .collect()
    }
}

/// Possible rows say what they are, from the one renderer (`util::people_and_machines`).
pub fn possible_words(c: &Counts) -> String {
    super::util::people_and_machines(c.possible_people, c.possible_machines)
}

impl Counts {
    /// By its identity key (for the "changed since the last scan" delta).
    pub fn get(&self, key: &str) -> usize {
        match key {
            "repos" => self.repos,
            "ci runs" => self.ci_runs,
            "caches" => self.caches,
            "artifacts" => self.artifacts,
            "images" => self.images,
            "hosts" => self.hosts,
            "releases" => self.releases,
            "secrets" => self.secrets,
            _ => 0,
        }
    }
}

/// A file that only looks like the sample (a similarity hit below 100%) is listed, never counted as something to clean.
pub fn is_lookalike(f: &Finding) -> bool {
    f.match_ == "similar" && f.sim.is_none_or(|s| s < 0.9999)
}

pub fn counts(res: &HuntResult) -> Counts {
    let all = findings(res);
    let fs: Vec<&Finding> = all.iter().copied().filter(|f| !is_lookalike(f)).collect();
    let n = |k: FKind| fs.iter().filter(|f| f.kind == k).count();
    let set = |k: FKind, g: &dyn Fn(&Finding) -> String| fs.iter().filter(|f| f.kind == k).map(|f| g(f)).collect::<BTreeSet<_>>().len();
    let mut c = Counts::default();
    c.similar = all.iter().filter(|f| is_lookalike(f)).map(|f| format!("{}\x01{}", f.where_, f.loc)).collect::<BTreeSet<_>>().len();
    c.repos = set(FKind::Repo, &|f| f.where_.clone());
    c.repo_rows = n(FKind::Repo);
    let mut byrepo: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for f in &fs {
        if f.kind == FKind::Repo {
            byrepo.entry(f.where_.as_str()).or_default().push(f.state.as_str());
        }
    }
    for sts in byrepo.values() {
        if sts.iter().any(|x| x.starts_with("present")) {
            c.repo_states.0 += 1;
        } else if sts.contains(&"removed") {
            c.repo_states.1 += 1;
        } else {
            c.repo_states.2 += 1;
        }
    }
    c.ci_runs = n(FKind::CiRun);
    c.caches = n(FKind::Cache);
    c.artifacts = n(FKind::Artifact);
    c.images = set(FKind::Image, &|f| f.digest.clone());
    c.image_rows = n(FKind::Image);
    c.hosts = set(FKind::Host, &|f| f.where_.clone());
    c.host_rows = n(FKind::Host);
    c.possible = res.possible.iter().map(|f| f.where_.clone()).collect::<BTreeSet<_>>().len();
    c.releases = n(FKind::ReleaseAsset);
    c.workflow_refs = n(FKind::WorkflowRef);
    c.secrets = secrets_of(res).len();
    c.secrets_separate = res.secrets_separate.max(c.secrets);
    c.floating = res.floating.len();
    c.teams = fs.iter().filter(|f| f.kind == FKind::Repo).filter_map(|f| f.owner.team.clone()).collect::<BTreeSet<_>>().len();
    c.total = fs.len();
    c.near = res.near.len();
    c.findings = fs.iter().map(|f| f.iocs_or_one().len()).sum();
    c.locations = fs.iter().filter(|f| f.kind != FKind::CiRun).map(|f| place_key(f)).collect::<BTreeSet<_>>().len();
    let now: Vec<&&Finding> = fs.iter().filter(|f| present_now(f)).collect();
    // What is present now includes what was first seen after the window; the history is everything shown
    let after_iocs: usize = res.present_after.iter().map(|f| f.iocs_or_one().len()).sum();
    c.findings_now = now.iter().map(|f| f.iocs_or_one().len()).sum::<usize>() + after_iocs;
    c.findings_all = c.findings + after_iocs;
    c.locations_now = now.iter().map(|f| &***f).chain(res.present_after.iter()).filter(|f| f.kind != FKind::CiRun).map(place_key).collect::<BTreeSet<_>>().len();
    c.places = c.locations;
    c.rule_matches = fs.iter().filter(|f| f.match_ == "rule").count();
    c.present_after = res.present_after.len();
    {
        // Present now, from one place: every kind, the window's findings and those first seen after it
        let mut still: Vec<&Finding> = fs.iter().copied().filter(|f| present_now(f)).collect();
        still.extend(res.present_after.iter());
        let by = |k: FKind| still.iter().filter(|f| f.kind == k).map(|f| place_key(f)).collect::<BTreeSet<_>>().len();
        c.now = PresentNow {
            repos: by(FKind::Repo),
            images: by(FKind::Image),
            hosts: by(FKind::Host),
            caches: by(FKind::Cache),
            artifacts: by(FKind::Artifact),
            releases: by(FKind::ReleaseAsset),
            workflow_refs: by(FKind::WorkflowRef),
        };
        let mut seen = BTreeSet::new();
        for f in &res.possible {
            if seen.insert(f.where_.clone()) {
                if f.person {
                    c.possible_people += 1
                } else {
                    c.possible_machines += 1
                }
            }
        }
    }
    c.unowned_repos = fs.iter().filter(|f| f.kind == FKind::Repo && f.owner.team.is_none()).map(|f| f.where_.clone()).collect::<BTreeSet<_>>().len();
    c
}

/// An indicator with no version (`npm:name`) is a search for any version of the package; only an advisory or a version the
/// user wrote says which versions are affected.
pub fn ioc_any_version(i: &Ioc) -> bool {
    i.kind == IocKind::Pkg && i.versions.is_none() && i.set.is_none() && i.rt.as_ref().is_none_or(|s| matches!(s, super::runtime::RtSpec::Any))
}

/// Every indicator of the question is an any-version search, so nothing in the answer is "to clean" or "to rotate" yet.
pub fn any_version_only(res: &HuntResult) -> bool {
    !res.q.iocs.is_empty() && res.q.iocs.iter().all(ioc_any_version)
}

/// The packages searched in any version (names as written, `eco:name`).
pub fn any_version_names(res: &HuntResult) -> Vec<String> {
    res.q.iocs.iter().filter(|i| ioc_any_version(i)).map(|i| i.text.clone()).collect()
}

/// One location: what 'a place' means everywhere.
pub fn place_key(f: &Finding) -> String {
    let w = &f.where_;
    match f.kind {
        FKind::Repo => format!("repo\x01{w}"),
        FKind::CiRun => format!("run\x01{w}\x01{}", f.id),
        FKind::Cache => format!("cache\x01{w}\x01{}", f.key),
        FKind::Artifact => format!("artifact\x01{w}\x01{}", f.id),
        FKind::Image => format!("image\x01{}", f.digest),
        FKind::Host => format!("host\x01{w}"),
        FKind::ReleaseAsset => format!("release\x01{w}\x01{}\x01{}", f.tag, f.asset),
        FKind::WorkflowRef => format!("workflow_ref\x01{w}\x01{}\x01{}", f.file, f.uses),
    }
}

/// Is this finding still there?
pub fn present_now(f: &Finding) -> bool {
    !(f.kind == FKind::CiRun || f.removed_at.is_some() || matches!(f.state.as_str(), "removed" | "install-only" | "expired"))
}

/// The one phrase for the headline number: '45 findings in 15 places and 8 CI runs'.
pub fn count_words(res: &HuntResult) -> String {
    let c = counts(res);
    let runs = if c.ci_runs > 0 { format!(" and {}", plural(c.ci_runs, "CI run")) } else { String::new() };
    format!("{} in {}{}", plural(c.findings, "finding"), plural(c.locations, "place"), runs)
}

/// {indicator text: number of findings} in the order asked.
pub fn ioc_hits(res: &HuntResult) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = vec![];
    for i in &res.q.iocs {
        if !out.iter().any(|(t, _)| *t == i.text) {
            out.push((i.text.clone(), 0));
        }
    }
    for f in findings(res).into_iter().chain(res.present_after.iter()) {
        for t in f.iocs_or_one() {
            if let Some(e) = out.iter_mut().find(|(x, _)| *x == t) {
                e.1 += 1;
            }
        }
    }
    out
}

/// The indicators with no hit, in a clause of their own (`0 hits: sha256:3d34…`), never inside the headline.
/// With `--only`, a zero means none in the sections shown, and the clause says so.
pub fn no_hit_note(res: &HuntResult) -> Option<String> {
    if res.q.iocs.len() < 2 {
        return None;
    }
    let zero: Vec<String> = ioc_hits(res).into_iter().filter(|(_, n)| *n == 0).map(|(t, _)| t).collect();
    if zero.is_empty() || zero.len() == res.q.iocs.len() {
        return None;
    }
    let scope = if res.q.only.len() < KINDS.len() { " in the sections shown" } else { "" };
    Some(format!("0 hits{scope}: {}", zero.join(", ")))
}

// ---- host population ---------------------------------------------------------------------
#[derive(Debug, Clone, Default)]
pub struct Population {
    pub hosts: usize,
    pub kinds: Vec<(String, usize)>,
    pub org: Option<String>,
    pub members: usize,
    pub member_ids: Vec<String>,
    pub no_laptop: Vec<String>,
    pub no_laptop_names: Vec<String>,
    /// (login, name, reason) for each member without a covering scan
    pub no_laptop_reasons: Vec<(String, String, String)>,
    /// Where the member list comes from ("visible to this token in GitHub")
    pub source_label: String,
}

pub fn host_population(ix: &Index) -> Population {
    host_population_with(ix, &|_| true, &|_| true)
}

/// The population a query's scope covers: with `--owner`, only that owner's hosts and people.
pub fn host_population_for(ix: &Index, q: &Query) -> Population {
    match owner_spec(ix, q) {
        Ok(Some(rs)) => host_population_with(ix, &|h| owner_match(ix, &rs, &host_owner(ix, h)), &|pid| owner_match(ix, &rs, &Owner { people: vec![pid.to_string()], ..Default::default() })),
        _ => host_population(ix),
    }
}

fn host_population_with(ix: &Index, host_ok: &dyn Fn(&str) -> bool, person_ok: &dyn Fn(&str) -> bool) -> Population {
    let mut kinds: Vec<(String, usize)> = vec![];
    let mut hosts = 0usize;
    for n in ix.names("host").into_iter().filter(|n| host_ok(n)) {
        hosts += 1;
        let hd = ix.host_def(&n);
        let k = crate::store::view_kind(hd.and_then(|h| h.kind.as_deref()).unwrap_or("")).to_string();
        match kinds.iter_mut().find(|(x, _)| *x == k) {
            Some(e) => e.1 += 1,
            None => kinds.push((k, 1)),
        }
    }
    // Who has a laptop scan is decided in one place
    let m = super::coverage::members_covered_with(ix, host_ok, person_ok);
    let member_ids: Vec<String> = ix.v.people.iter().filter(|p| !p.login.ends_with("[bot]") && person_ok(&p.login)).map(|p| p.login.clone()).collect();
    Population {
        hosts,
        kinds,
        org: ix.v.org.github.clone(),
        members: m.members,
        no_laptop_names: m.uncovered_names.clone(),
        no_laptop_reasons: m.reasons.iter().filter(|r| !r.covered).map(|r| (r.login.clone(), r.name.clone(), r.reason.clone())).collect(),
        member_ids,
        no_laptop: m.uncovered_ids.clone(),
        source_label: m.source_label.clone(),
    }
}

/// 'hosts: 3 indexed (2 runners, 1 laptop); acme has 12 members, 10 with no laptop scan here: run br hosts to list them'.
pub fn population_line(ix: &Index) -> Option<String> {
    population_text(&host_population(ix), false)
}

/// The same line for a scoped query: `--owner` counts only that owner's hosts and people.
pub fn population_line_for(ix: &Index, q: &Query) -> Option<String> {
    population_text(&host_population_for(ix, q), q.owner.as_ref().is_some_and(|o| !o.is_empty()))
}

fn population_text(p: &Population, scoped: bool) -> Option<String> {
    let p = p.clone();
    if p.hosts == 0 && p.members == 0 {
        return None;
    }
    let mut ks = p.kinds.clone();
    ks.sort_by_key(|k| std::cmp::Reverse(k.1));
    let kinds: Vec<String> = ks.iter().map(|(k, n)| plural(*n, k)).collect();
    let mut line = format!("hosts: {} indexed{}", p.hosts, if kinds.is_empty() { String::new() } else { format!(" ({})", kinds.join(", ")) });
    if p.members > 0 {
        let org = p.org.clone().filter(|o| !o.is_empty()).unwrap_or_else(|| "the org".into());
        let who = if scoped { format!("your scope in {org} has") } else { format!("{org} has") };
        line += &format!("; {who} {} {}, {} with no laptop scan here: run br hosts to list them", plural(p.members, "member"), p.source_label, p.no_laptop.len());
    }
    Some(line)
}

// ---- why a number changed ----------------------------------------------------------------
pub struct Changed {
    pub was: Counts,
    pub delta: Vec<(String, usize, usize)>,
    pub sources: Vec<String>,
    pub gained: Vec<String>,
    pub at: String,
    /// When the "was" numbers are from: the "index as of" the earlier answer printed.
    pub was_at: String,
    /// "scan" or "import": what changed the index
    pub kind: String,
}

/// What the last scan changed in this answer: the same query on the index as it was before the last scan.
pub fn changed_since_scan(ix: &Index, q: &Query, res: &HuntResult) -> Option<Changed> {
    let ls = ix.v.state.last_scan.as_ref().filter(|v| !v.is_null())?;
    let before = ls.get("before").and_then(|b| b.as_object()).filter(|b| !b.is_empty())?;
    let mut old = ix.srcs.clone();
    for (n, t) in before {
        if let (Some(s), Some(t)) = (old.get_mut(n), t.as_str()) {
            s.indexed_at = t.to_string();
        }
    }
    let ix0 = ix.with_srcs(old);
    let r0 = hunt(&ix0, q).ok()?;
    let (a, b) = (counts(&r0), counts(res));
    let mut delta = vec![];
    for k in ["repos", "ci runs", "caches", "artifacts", "images", "hosts", "releases", "secrets"] {
        if a.get(k) != b.get(k) {
            delta.push((k.to_string(), a.get(k), b.get(k)));
        }
    }
    if delta.is_empty() && a.findings == b.findings {
        return None;
    }
    let old_at: BTreeSet<String> = findings(&r0).iter().map(|f| f.where_.clone()).collect();
    let now_at: BTreeSet<String> = findings(res).iter().map(|f| f.where_.clone()).collect();
    let gained: Vec<String> = now_at.difference(&old_at).cloned().collect();
    let mut sources: Vec<String> = before.keys().cloned().collect();
    sources.sort();
    let was_at = r0.as_of.clone().unwrap_or_default();
    Some(Changed {
        was: a,
        delta,
        sources,
        gained,
        at: ls.get("at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        was_at,
        kind: ls.get("kind").and_then(|x| x.as_str()).unwrap_or("scan").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_cache_bang_is_upper_case() {
        assert_eq!(go_decode("github.com/!azure/go-ansiterm"), "github.com/Azure/go-ansiterm");
        assert_eq!(go_decode("plain"), "plain");
    }
}

#[cfg(test)]
mod scale_tests {
    use super::*;
    use crate::view::{Commit, LockPackage, Repo, Run, Source, View};
    use std::time::Instant;

    #[test]
    fn hunt_over_5000_repos_with_20_runs_each_is_fast() {
        let now = "2026-10-01T00:00:00Z";
        let mut v = View { now: now.to_string(), ..Default::default() };
        for i in 0..5000 {
            let name = format!("acme/r{i}");
            v.sources.insert(name.clone(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: now.to_string(), ..Default::default() });
            let pkgs = vec![
                LockPackage { p: "npm:left-pad@1.0.0".into(), ..Default::default() },
                LockPackage { p: if i % 50 == 0 { "npm:evil@1.2.3".into() } else { "npm:evil@0.0.1".into() }, ..Default::default() },
            ];
            let commits = (0..3).map(|k| Commit { sha: format!("{i:04}{k}"), at: format!("2026-09-0{}T00:00:00Z", k + 1), packages: Some(pkgs.clone()), ..Default::default() }).collect();
            let runs = (0..20)
                .map(|k| Run {
                    id: (i * 20 + k) as u64,
                    workflow: "ci".into(),
                    at: format!("2026-09-{:02}T10:00:00Z", k + 1),
                    installed: vec!["npm:evil@1.2.3".into()],
                    runner: Some("github-hosted".into()),
                    ..Default::default()
                })
                .collect();
            v.repos.insert(name, Repo { commits, runs, ..Default::default() });
        }
        let ix = Index::new(&v, now);
        let q = Query { iocs: vec![crate::query::iocs::parse_ioc("npm:evil@1.2.3", None).unwrap()], ..Default::default() };
        let t = Instant::now();
        let res = hunt(&ix, &q).unwrap();
        let took = t.elapsed();
        assert!(!findings(&res).is_empty());
        assert!(took.as_secs_f64() < 5.0, "hunt took {took:?}");
    }
}

#[cfg(test)]
mod r6_tests {
    use super::*;
    use crate::view::{Host, HostFile, HostItem, Repo, Run, Source, View};

    const NOW: &str = "2026-10-01T00:00:00Z";
    const H_BAD: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const H_OTHER: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn run(id: u64, at: &str, installed: &str) -> Run {
        Run { id, workflow: "ci".into(), at: at.into(), installed: vec![installed.into()], runner: Some("github-hosted".into()), resolved_from: Some("registry".into()), ..Default::default() }
    }

    fn q(iocs: &[&str]) -> Query {
        Query { iocs: iocs.iter().map(|i| crate::query::iocs::parse_ioc(i, None).unwrap()).collect(), ..Default::default() }
    }

    fn host_view(items: Vec<HostItem>, hosts: &[&str]) -> View {
        let mut v = View { now: NOW.into(), ..Default::default() };
        for h in hosts {
            v.sources.insert(h.to_string(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: NOW.into(), ..Default::default() });
            v.hosts.insert(h.to_string(), Host { kind: Some("laptop".into()), ..Default::default() });
        }
        v.hosts.get_mut(hosts[0]).unwrap().items = items;
        v
    }

    fn file(path: &str, sha: &str) -> HostFile {
        HostFile { path: path.into(), sha256: sha.into(), ..Default::default() }
    }

    // Install-only last seen is the last run that installed the bad version, not the scan time
    #[test]
    fn install_only_last_seen_is_the_last_run_that_installed_it() {
        let mut v = View { now: NOW.into(), ..Default::default() };
        v.sources.insert("acme/app".into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: "2026-09-30T00:00:00Z".into(), ..Default::default() });
        v.repos.insert(
            "acme/app".into(),
            Repo {
                runs: vec![run(1, "2026-09-01T10:00:00Z", "npm:evil@1.2.3"), run(2, "2026-09-02T10:00:00Z", "npm:evil@1.2.3"), run(3, "2026-09-03T10:00:00Z", "npm:evil@1.0.0")],
                ..Default::default()
            },
        );
        let ix = Index::new(&v, NOW);
        let res = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
        let f: Vec<&Finding> = findings(&res).into_iter().filter(|f| f.state == "install-only").collect();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].first_seen.as_deref(), Some("2026-09-01T10:00:00Z"));
        assert_eq!(f[0].last_seen.as_deref(), Some("2026-09-02T10:00:00Z"), "not the scan time 09-30");
    }

    // A zero-hit hash and a file inside an affected package's tree with another hash: a hint, not a finding
    #[test]
    fn a_zero_hit_hash_names_the_files_with_the_same_name_and_another_hash() {
        let items = vec![HostItem {
            at: "2026-09-01T00:00:00Z".into(),
            kind: "node_modules".into(),
            loc: "/home/a/app/node_modules/evil".into(),
            pkgs: vec!["npm:evil@1.2.3".into()],
            files: vec![file("bin/evil-linux-amd64", H_OTHER), file("package.json", H_OTHER)],
            hidden: false,
        }];
        let mut v = host_view(items, &["laptop-a", "laptop-b"]);
        v.hosts.get_mut("laptop-b").unwrap().items =
            vec![HostItem { at: "2026-09-01T00:00:00Z".into(), kind: "dir".into(), loc: "/tmp".into(), pkgs: vec![], files: vec![file("evil-linux-amd64", H_OTHER)], hidden: false }];
        let ix = Index::new(&v, NOW);
        let res = hunt(&ix, &q(&["npm:evil@1.2.3", &format!("sha256:{H_BAD}")])).unwrap();
        assert_eq!(res.not_match.len(), 1, "{:?}", res.not_match);
        assert_eq!((res.not_match[0].name.as_str(), res.not_match[0].count), ("evil-linux-amd64", 2));
        assert_eq!(res.not_match[0].other, H_OTHER);
        // package metadata is never a tie
        assert!(res.not_match.iter().all(|m| m.name != "package.json"));
        // the hint is never a finding
        assert!(findings(&res).iter().all(|f| f.ioc != format!("sha256:{H_BAD}")));
    }

    // A registered host nothing has scanned is one NOT CHECKED row, "registered, never scanned", never also an empty scan
    #[test]
    fn a_registered_host_is_one_row_saying_it_was_never_scanned() {
        let mut v = host_view(vec![], &["laptop-a", "build-box"]);
        let s = v.sources.get_mut("build-box").unwrap();
        s.empty = true;
        s.gaps = vec![crate::view::Gap { scope: "registered".into(), reason: "never scanned".into(), at: NOW.into() }];
        let ix = Index::new(&v, NOW);
        let res = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
        let rows: Vec<&NotChecked> = res.not_checked.iter().filter(|r| r.name == "build-box").collect();
        assert_eq!(rows.len(), 1, "{:?}", res.not_checked);
        assert_eq!(rows[0].why, "registered, never scanned");
        assert!(res.not_checked.iter().all(|r| !r.why.contains("hashed 0 files")));
    }

    // A package's own text files (they have a simhash) say nothing about a binary's hash, so they make no hint
    #[test]
    fn a_package_script_is_not_a_tie() {
        let mut script = file("lib/postinstall.js", H_OTHER);
        script.simhash = Some("9f3ac6e1d2047b58".into());
        let items = vec![HostItem {
            at: "2026-09-01T00:00:00Z".into(),
            kind: "node_modules".into(),
            loc: "/home/a/app/node_modules/evil".into(),
            pkgs: vec!["npm:evil@1.2.3".into()],
            files: vec![script, file("bin/evil-linux-amd64", H_OTHER)],
            hidden: false,
        }];
        let v = host_view(items, &["laptop-a"]);
        let ix = Index::new(&v, NOW);
        let res = hunt(&ix, &q(&["npm:evil@1.2.3", &format!("sha256:{H_BAD}")])).unwrap();
        let names: Vec<&str> = res.not_match.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["evil-linux-amd64"], "the script has a simhash, the binary has none");
        assert!(has_text_extension("a/b/index.js") && !has_text_extension("a/b/tool-linux-amd64"));
    }

    // A name alone, with no tie to the hash, makes no hint
    #[test]
    fn a_file_name_alone_is_not_a_tie() {
        let items = vec![HostItem { at: "2026-09-01T00:00:00Z".into(), kind: "dir".into(), loc: "/tmp".into(), pkgs: vec![], files: vec![file("evil-linux-amd64", H_OTHER)], hidden: false }];
        let v = host_view(items, &["laptop-a"]);
        let ix = Index::new(&v, NOW);
        let res = hunt(&ix, &q(&[&format!("sha256:{H_BAD}")])).unwrap();
        assert!(res.not_match.is_empty());
        // a tie the input gave (advisory text, a note) does
        let mut q2 = q(&[&format!("sha256:{H_BAD}")]);
        q2.hash_names = vec![(format!("sha256:{H_BAD}"), "evil-linux-amd64".into())];
        let res = hunt(&ix, &q2).unwrap();
        assert_eq!(res.not_match.len(), 1);
    }

    // Possible is one list: two indicators reaching one place are one row
    #[test]
    fn possible_is_one_row_per_place() {
        let mk = |ioc: &str| Finding { kind: FKind::Host, where_: "laptop-a".into(), ioc: ioc.into(), iocs: vec![ioc.into()], possible: true, ..Default::default() };
        let out = dedupe_possible(vec![mk("npm:a@1"), mk("npm:b@1"), Finding { where_: "laptop-b".into(), ..mk("npm:a@1") }]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].iocs, vec!["npm:a@1".to_string(), "npm:b@1".to_string()]);
    }

    // The zero-hit indicators are their own clause, and under --only it says what the zero means
    #[test]
    fn zero_hit_indicators_are_a_clause_of_their_own() {
        let mut res = HuntResult { q: q(&["npm:a@1.0.0", "npm:b@1.0.0"]), ..Default::default() };
        res.findings =
            vec![Finding { kind: FKind::Cache, ioc: "npm:a@1.0.0".into(), iocs: vec!["npm:a@1.0.0".into()], where_: "acme/x".into(), key: "k".into(), state: "present".into(), ..Default::default() }];
        assert_eq!(no_hit_note(&res).as_deref(), Some("0 hits: npm:b@1.0.0"));
        res.q.only = ["images".to_string()].into();
        assert_eq!(no_hit_note(&res).as_deref(), Some("0 hits in the sections shown: npm:b@1.0.0"));
    }

    // The owner's name for a team only CODEOWNERS names is `unresolved`, never a team
    #[test]
    fn a_team_that_only_codeowners_names_is_unresolved() {
        let mut v = View::default();
        v.teams = vec![crate::view::Team { id: "@acme/web".into(), ..Default::default() }];
        let ix = Index::new(&v, NOW);
        assert_eq!(owner_name(&ix, &Owner { team: Some("@acme/web".into()), ..Default::default() }), "@acme/web");
        assert_eq!(owner_name(&ix, &Owner { team: Some("@acme/ghost".into()), ..Default::default() }), "unresolved");
        assert_eq!(owner_name(&ix, &Owner { people: vec!["dana".into()], ..Default::default() }), "@dana");
    }
}
