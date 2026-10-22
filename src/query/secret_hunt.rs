//! `secret:NAME` (globs allowed): every place a matching secret is stored, who reads it, whether it was rotated.
//! Read-only on the index; it never sees a secret's value (GitHub does not give one, and image and file readers keep names).

use std::collections::{BTreeMap, BTreeSet};

use super::hunt::{self as H, Query};
use super::index::Index;
use super::iocs::{self as I, IocKind};
use super::util::{parse_t, parse_when, plural};

/// Most rows a list shows before saying how many more there are (counts and JSON always carry everything).
pub const SHOW: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rot {
    /// updated_at is before the cutoff
    NotRotated,
    /// updated_at is at or after the cutoff
    Rotated,
    /// no cutoff was given, or GitHub gave no date
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Stored {
    pub name: String,
    /// `repo`, `org (all repos)`, `org (selected repos)`, `environment NAME`
    pub scope: String,
    /// the repo it is stored in, or `org`
    pub place: String,
    /// repos a selected org secret reaches
    pub repos: Vec<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub rot: Rot,
    /// who rotates it: the repo's owners, or the org admins for an org secret
    pub owner: Vec<String>,
    /// teams whose workflows read an org secret
    pub used_by: Vec<String>,
}

impl Stored {
    pub fn is_org(&self) -> bool {
        super::secrets::is_org_scope(&self.scope)
    }
    pub fn last_update(&self) -> String {
        self.updated_at.as_deref().or(self.created_at.as_deref()).map(day).unwrap_or_else(|| "unknown".into())
    }
    /// "NOT ROTATED (last updated 2025-01-01)", "rotated 2026-06-02", "rotation unknown (...)".
    pub fn rot_words(&self) -> String {
        match self.rot {
            Rot::NotRotated => format!("NOT ROTATED (last updated {})", self.last_update()),
            Rot::Rotated => format!("rotated {}", self.last_update()),
            Rot::Unknown if self.updated_at.is_none() && self.created_at.is_none() => "NOT ROTATED (GitHub gave no update date)".into(),
            Rot::Unknown => format!("rotation unknown without a cutoff (last updated {}); pass --since DATE", self.last_update()),
        }
    }
    /// A secret is still to rotate unless it was rotated after the cutoff.
    pub fn to_rotate(&self) -> bool {
        self.rot != Rot::Rotated
    }
}

#[derive(Debug, Clone)]
pub struct Reader {
    pub repo: String,
    pub file: String,
    /// the matching names this workflow reads
    pub names: Vec<String>,
    /// file:line places, one per read
    pub lines: Vec<(String, u32)>,
    /// the workflow reads every secret (`secrets: inherit`, `toJSON(secrets)`)
    pub all: bool,
    pub owner: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecretRun {
    pub repo: String,
    pub workflow: String,
    pub id: u64,
    pub at: String,
    pub names: Vec<String>,
    pub owner: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ImageHit {
    pub repository: String,
    pub digest: String,
    pub tags: Vec<String>,
    pub built: String,
    pub from_repo: Option<String>,
    pub names: Vec<String>,
    pub owner: Vec<String>,
    /// built before the cutoff (or no cutoff): the old value may be in it
    pub stale: bool,
}

#[derive(Debug, Clone)]
pub struct FileRef {
    pub repo: String,
    pub file: String,
    pub line: u32,
    pub name: String,
    pub owner: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SecretReport {
    /// the patterns asked for, as `secret:NAME`
    pub asked: Vec<String>,
    pub cutoff: Option<String>,
    /// where the cutoff came from: `--since`, `the advisory window start`, `--window`
    pub cutoff_src: String,
    pub window: Option<(String, String)>,
    pub as_of: String,
    pub stored: Vec<Stored>,
    pub readers: Vec<Reader>,
    pub runs: Vec<SecretRun>,
    pub images: Vec<ImageHit>,
    pub files: Vec<FileRef>,
    /// what was not checked: (scope, why)
    pub gaps: Vec<(String, String)>,
}

pub fn day(t: &str) -> String {
    t.chars().take(10).collect()
}

/// Did the person type only `secret:` indicators? An advisory given alongside adds package indicators of its own; those only
/// supply the window, so they are not a mix. A typed mix is refused by the caller.
pub fn is_secret_query(typed: &[String]) -> bool {
    !typed.is_empty() && typed.iter().all(|t| t.trim().to_lowercase().starts_with("secret:"))
}

pub fn any_secret(q: &Query) -> bool {
    q.iocs.iter().any(|i| i.kind == IocKind::Secret)
}

impl SecretReport {
    pub fn matched_names(&self) -> BTreeSet<String> {
        self.stored.iter().map(|s| s.name.to_uppercase()).collect()
    }
    pub fn to_rotate(&self) -> Vec<&Stored> {
        self.stored.iter().filter(|s| s.to_rotate()).collect()
    }
    pub fn stale_images(&self) -> Vec<&ImageHit> {
        self.images.iter().filter(|i| i.stale).collect()
    }
    /// FOUND while any matching secret is not rotated, or an image built before the cutoff still names it.
    pub fn found(&self) -> bool {
        !self.to_rotate().is_empty() || !self.stale_images().is_empty()
    }
    pub fn verdict(&self) -> &'static str {
        if self.found() {
            "FOUND"
        } else if !self.gaps.is_empty() {
            "CLEAR WITH GAPS"
        } else {
            "CLEAR"
        }
    }
    pub fn cutoff_day(&self) -> String {
        self.cutoff.as_deref().map(day).unwrap_or_default()
    }
    pub fn asked_words(&self) -> String {
        self.asked.join(", ")
    }
    /// The line under the verdict.
    pub fn headline(&self) -> String {
        let n = self.stored.len();
        let open = self.to_rotate().len();
        let img = self.stale_images().len();
        let mut parts: Vec<String> = vec![];
        if n == 0 {
            parts.push(format!("no secret matching {} is stored where this token can see", self.asked_words()));
        } else if self.cutoff.is_none() {
            parts.push(format!("{} stored, rotation not checked: pass --since DATE (or --window, or an advisory with a window)", plural(n, "matching secret")));
        } else if open == 0 {
            parts.push(format!("all {n} rotated since {}", self.cutoff_day()));
        } else {
            parts.push(format!("{open} of {} NOT ROTATED since {}", plural(n, "matching secret"), self.cutoff_day()));
        }
        if img > 0 {
            parts.push(if img == 1 {
                "1 image built before then still names it in its env, so the old value may be baked in".to_string()
            } else {
                format!("{img} images built before then still name it in their env, so the old value may be baked in")
            });
        }
        parts.join("; ")
    }
}

fn match_any(pats: &[String], n: &str) -> bool {
    pats.iter().any(|p| I::glob_match(p, n))
}

/// The cutoff: `--since`, else the advisory window's start, else the `--window` start.
pub fn cutoff_of(q: &Query) -> crate::error::BrResult<(Option<String>, String)> {
    if let Some(s) = q.since.as_ref().filter(|s| !s.is_empty()) {
        let t = parse_when(s, false).map_err(|_| crate::error::BrError::new(format!("\"{s}\" is not a date"), Some("write --since YYYY-MM-DD or YYYY-MM-DDTHH:MMZ, e.g. --since 2026-05-11")))?;
        return Ok((Some(t), "--since".into()));
    }
    if let Some((a, _)) = &q.window {
        let src = match q.window_src.as_deref() {
            Some("--window") => "the --window start".to_string(),
            Some(s) if s == "advisory" || s == "OSV" || s.starts_with("your note") => "the advisory window start".to_string(),
            Some(s) => format!("the window start ({s})"),
            None => "the window start".to_string(),
        };
        return Ok((Some(a.clone()), src));
    }
    Ok((None, String::new()))
}

fn classify(cutoff: &Option<String>, updated: &Option<String>, created: &Option<String>) -> Rot {
    let Some(c) = cutoff else { return Rot::Unknown };
    match updated.as_ref().or(created.as_ref()) {
        None => Rot::Unknown,
        Some(u) if parse_t(u) < parse_t(c) => Rot::NotRotated,
        Some(_) => Rot::Rotated,
    }
}

fn owners_of(ix: &Index, repo: &str) -> Vec<String> {
    let o = H::repo_owner_suggested(ix, repo, None);
    let n = H::owner_names(ix, &o);
    if n.is_empty() {
        vec![H::owner_name(ix, &o)]
    } else {
        n
    }
}

pub fn build(ix: &Index, q: &Query) -> crate::error::BrResult<SecretReport> {
    let pats: Vec<String> = q.iocs.iter().filter(|i| i.kind == IocKind::Secret).map(|i| i.name.clone()).collect();
    let (cutoff, cutoff_src) = cutoff_of(q)?;
    let mut rep =
        SecretReport { asked: q.iocs.iter().filter(|i| i.kind == IocKind::Secret).map(|i| i.text.clone()).collect(), cutoff: cutoff.clone(), cutoff_src, as_of: ix.now.clone(), ..Default::default() };
    // the runs window: the window given, else from the cutoff to now
    rep.window = q.window.clone().or_else(|| cutoff.clone().map(|c| (c, ix.now.clone())));
    let rs = H::owner_spec(ix, q)?;
    let repo_in_scope = |r: &str| -> bool {
        if let Some(want) = q.repo.as_ref().filter(|x| !x.is_empty()) {
            if r != want {
                return false;
            }
        }
        match &rs {
            Some(rs) => H::owner_match(ix, rs, &H::repo_owner_suggested(ix, r, None)),
            None => true,
        }
    };
    let scoped = q.repo.as_ref().is_some_and(|r| !r.is_empty()) || rs.is_some();
    let repos: Vec<&String> = ix.v.repos.keys().filter(|r| repo_in_scope(r)).collect();

    // ---- where it is stored
    let org_unreadable = ix.v.secrets_unreadable.iter().any(|x| x == "org");
    for s in ix.v.secret_scopes.iter().filter(|s| match_any(&pats, &s.name)) {
        // an org secret reaches the repos it names (selected) or every repo (all)
        let reach: Vec<&String> = if s.scope.contains("selected") { ix.v.repos.keys().filter(|r| s.repos.contains(r)).collect() } else { ix.v.repos.keys().collect() };
        if scoped && !reach.iter().any(|r| repo_in_scope(r)) {
            continue;
        }
        rep.stored.push(Stored {
            name: s.name.clone(),
            scope: s.scope.clone(),
            place: "org".into(),
            repos: s.repos.clone(),
            created_at: s.created_at.clone(),
            updated_at: s.updated_at.clone(),
            rot: classify(&cutoff, &s.updated_at, &s.created_at),
            owner: vec![],
            used_by: vec![],
        });
    }
    for r in &repos {
        for s in ix.v.repos[*r].secret_scopes.iter().filter(|s| match_any(&pats, &s.name)) {
            rep.stored.push(Stored {
                name: s.name.clone(),
                scope: s.scope.clone(),
                place: (*r).clone(),
                repos: vec![],
                created_at: s.created_at.clone(),
                updated_at: s.updated_at.clone(),
                rot: classify(&cutoff, &s.updated_at, &s.created_at),
                owner: owners_of(ix, r),
                used_by: vec![],
            });
        }
    }
    // an org secret index from before dates were kept still lists its names
    for n in ix.v.org_secrets.iter().filter(|n| match_any(&pats, n) && !ix.v.secret_scopes.iter().any(|s| &s.name == *n)) {
        rep.stored.push(Stored {
            name: n.clone(),
            scope: "org (scope not recorded)".into(),
            place: "org".into(),
            repos: vec![],
            created_at: None,
            updated_at: None,
            rot: Rot::Unknown,
            owner: vec![],
            used_by: vec![],
        });
    }

    // ---- workflows that read it
    let mut read_somewhere = 0usize; // workflows reading a matching name no repo-level list holds
    let mut gap_repos: BTreeSet<String> = BTreeSet::new();
    for r in &repos {
        let rp = &ix.v.repos[*r];
        let stored_here: BTreeSet<String> = rp.secret_scopes.iter().map(|s| s.name.to_uppercase()).collect();
        let unreadable = repo_unreadable(ix, r);
        for w in &rp.workflows {
            let names: Vec<String> = w.secrets.iter().filter(|n| n.as_str() != "*" && match_any(&pats, n)).cloned().collect();
            let all = w.secrets.iter().any(|n| n == "*");
            if names.is_empty() && !all {
                continue;
            }
            let mut lines: Vec<(String, u32)> = vec![];
            for n in names.iter().map(|n| n.as_str()).chain(all.then_some("*")) {
                for l in w.secret_lines.get(n).into_iter().flatten() {
                    lines.push((w.file.clone(), *l));
                }
            }
            lines.sort();
            lines.dedup();
            if names.iter().any(|n| !stored_here.contains(&n.to_uppercase())) {
                read_somewhere += 1;
                if unreadable {
                    gap_repos.insert((*r).clone());
                }
            }
            rep.readers.push(Reader { repo: (*r).clone(), file: w.file.clone(), names, lines, all, owner: owners_of(ix, r) });
        }
    }
    // an org secret's teams: whose workflows read it
    let readers = rep.readers.clone();
    for s in rep.stored.iter_mut().filter(|s| s.is_org()) {
        let mut used: BTreeSet<String> = BTreeSet::new();
        for r in readers.iter().filter(|r| r.names.iter().any(|n| n.eq_ignore_ascii_case(&s.name)) && (!s.scope.contains("selected") || s.repos.contains(&r.repo))) {
            used.extend(r.owner.iter().cloned());
        }
        s.used_by = used.into_iter().collect();
        let admins: Vec<String> = ix.v.org_admins.iter().map(|a| ix.person_name(a.trim_start_matches('@'))).collect();
        s.owner = vec![if admins.is_empty() { "org admins (not on record)".to_string() } else { format!("org admins ({})", admins.join(", ")) }];
    }

    // ---- CI runs that could read it, in the window
    for r in &repos {
        let rp = &ix.v.repos[*r];
        for run in &rp.runs {
            let from_run: Vec<String> = run.secrets.clone();
            let from_wf: Vec<String> = rp
                .workflows
                .iter()
                .find(|w| run.workflow == w.file.rsplit('/').next().unwrap_or(&w.file) || run.path.as_deref() == Some(w.file.as_str()))
                .map(|w| w.secrets.clone())
                .unwrap_or_default();
            let all = !from_run.is_empty() || !from_wf.is_empty();
            if !all {
                continue;
            }
            let src = if from_run.is_empty() { from_wf } else { from_run };
            let names: Vec<String> = src.iter().filter(|n| n.as_str() != "*" && match_any(&pats, n)).cloned().collect();
            let star = src.iter().any(|n| n == "*");
            if names.is_empty() && !star {
                continue;
            }
            if let Some((a, b)) = &rep.window {
                if !(a.as_str() <= run.at.as_str() && run.at.as_str() <= b.as_str()) {
                    continue;
                }
            }
            rep.runs.push(SecretRun { repo: (*r).clone(), workflow: run.workflow.clone(), id: run.id, at: run.at.clone(), names, owner: owners_of(ix, r) });
        }
    }
    rep.runs.sort_by(|a, b| b.at.cmp(&a.at).then(a.repo.cmp(&b.repo)));

    // ---- images whose config env carries the name
    for b in &ix.v.images {
        let names: Vec<String> = b.env_names.iter().filter(|n| match_any(&pats, n)).cloned().collect();
        if names.is_empty() {
            continue;
        }
        let from = b.source.as_ref().and_then(|s| s.repo.clone());
        if let Some(want) = q.repo.as_ref().filter(|x| !x.is_empty()) {
            if from.as_ref() != Some(want) {
                continue;
            }
        }
        if let (Some(rs), Some(f)) = (&rs, &from) {
            if !H::owner_match(ix, rs, &H::repo_owner_suggested(ix, f, None)) {
                continue;
            }
        }
        let stale = match &cutoff {
            None => true,
            Some(c) => parse_t(&b.built) < parse_t(c),
        };
        let owner = from.as_deref().map(|f| owners_of(ix, f)).unwrap_or_else(|| vec!["unresolved".into()]);
        rep.images.push(ImageHit { repository: b.repository.clone(), digest: b.digest.clone(), tags: b.tags.clone(), built: b.built.clone(), from_repo: from, names, owner, stale });
    }

    // ---- repo files at HEAD that name it
    for r in &repos {
        for e in ix.v.repos[*r].env_refs.iter().filter(|e| match_any(&pats, &e.name)) {
            rep.files.push(FileRef { repo: (*r).clone(), file: e.file.clone(), line: e.line, name: e.name.clone(), owner: owners_of(ix, r) });
        }
    }

    // ---- gaps: scopes this token could not read
    if org_unreadable {
        rep.gaps.push((
            "org secrets".into(),
            if read_somewhere == 0 {
                "org secrets not readable with this token: an org-level copy of a matching secret cannot be ruled out".to_string()
            } else {
                format!("org secrets not readable with this token: {} read names that could be org secrets", plural(read_somewhere, "workflow"))
            },
        ));
    }
    for r in &gap_repos {
        let n = rep.readers.iter().filter(|x| &x.repo == r).count();
        rep.gaps.push((format!("secrets of {r}"), format!("repo and environment secrets of {r} not readable with this token: {} read matching names", plural(n, "workflow"))));
    }
    for r in repos.iter().filter(|r| repo_unreadable(ix, r) && !gap_repos.contains(**r)) {
        rep.gaps.push((format!("secrets of {r}"), format!("repo and environment secrets of {r} not readable with this token: a secret stored there would not show here")));
    }
    // the scope lists that exist at all but are empty because nothing was ever listed
    if rep.stored.is_empty() && ix.v.secret_scopes.is_empty() && !org_unreadable && ix.v.repos.values().all(|r| r.secret_scopes.is_empty()) && !ix.v.repos.is_empty() {
        rep.gaps.push(("secrets".into(), "no secret list was read from any source (the index holds no secret names at all)".into()));
    }
    // sources that are stale or have their own gaps on secret lists are named by status; here only the secret ones matter
    let mut by_scope: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in rep.gaps.drain(..) {
        by_scope.entry(k).or_insert(v);
    }
    rep.gaps = by_scope.into_iter().collect();
    Ok(rep)
}

/// The repo's secret lists were refused (a gap on its source, or the index says so).
fn repo_unreadable(ix: &Index, repo: &str) -> bool {
    ix.v.secrets_unreadable.iter().any(|x| x == repo) || ix.v.sources.get(repo).is_some_and(|s| s.gaps.iter().any(|g| g.scope == "repo secrets" || g.scope.starts_with("environment secrets")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{ImageBuild, Repo, SecretScope, View, Workflow};

    fn q(pats: &[&str], since: Option<&str>) -> Query {
        Query { iocs: pats.iter().map(|p| I::parse_ioc(p, None).unwrap()).collect(), since: since.map(str::to_string), ..Default::default() }
    }

    fn world() -> View {
        let mut v = View { now: "2026-10-01T00:00:00Z".into(), ..Default::default() };
        v.secret_scopes = vec![SecretScope {
            name: "PLAT_TOKEN".into(),
            scope: "org (selected repos)".into(),
            repos: vec!["acme/api".into()],
            updated_at: Some("2025-01-01T00:00:00Z".into()),
            ..Default::default()
        }];
        let mut wf = Workflow { file: ".github/workflows/deploy.yml".into(), secrets: vec!["PLAT_TOKEN".into()], ..Default::default() };
        wf.secret_lines.insert("PLAT_TOKEN".into(), vec![14, 22]);
        v.repos.insert(
            "acme/api".into(),
            Repo {
                workflows: vec![wf],
                secret_scopes: vec![
                    SecretScope { name: "PLAT_TOKEN".into(), scope: "repo".into(), updated_at: Some("2026-06-02T10:00:00Z".into()), ..Default::default() },
                    SecretScope { name: "OTHER".into(), scope: "repo".into(), updated_at: Some("2024-01-01T00:00:00Z".into()), ..Default::default() },
                ],
                ..Default::default()
            },
        );
        v.images = vec![ImageBuild {
            repository: "ghcr.io/acme/api".into(),
            digest: "sha256:aa".into(),
            built: "2026-03-01T00:00:00Z".into(),
            env_names: vec!["PATH".into(), "PLAT_TOKEN".into()],
            ..Default::default()
        }];
        v
    }

    #[test]
    fn rotation_is_decided_by_updated_at_against_the_cutoff() {
        let v = world();
        let ix = Index::new(&v, &v.now);
        let r = build(&ix, &q(&["secret:PLAT_*"], Some("2026-05-11"))).unwrap();
        assert_eq!(r.stored.len(), 2);
        let org = r.stored.iter().find(|s| s.is_org()).unwrap();
        let repo = r.stored.iter().find(|s| !s.is_org()).unwrap();
        assert_eq!(org.rot, Rot::NotRotated);
        assert_eq!(repo.rot, Rot::Rotated);
        assert!(org.rot_words().contains("NOT ROTATED (last updated 2025-01-01)"));
        assert_eq!(repo.rot_words(), "rotated 2026-06-02");
        assert_eq!(r.verdict(), "FOUND");
        assert_eq!(r.readers.len(), 1);
        assert_eq!(r.readers[0].lines, vec![(".github/workflows/deploy.yml".to_string(), 14), (".github/workflows/deploy.yml".to_string(), 22)]);
        assert_eq!(r.images.len(), 1);
        assert!(r.images[0].stale, "built before the cutoff");
        // everything rotated: the headline says so
        let late = build(&ix, &q(&["secret:PLAT_TOKEN"], Some("2024-01-01"))).unwrap();
        assert!(!late.found());
        assert!(late.headline().starts_with("all 2 rotated since 2024-01-01"), "{}", late.headline());
        // a name nothing matches is CLEAR, not an error
        assert_eq!(build(&ix, &q(&["secret:NOPE_*"], Some("2026-05-11"))).unwrap().verdict(), "CLEAR");
    }

    #[test]
    fn no_cutoff_never_calls_a_secret_rotated() {
        let v = world();
        let ix = Index::new(&v, &v.now);
        let r = build(&ix, &q(&["secret:OTHER"], None)).unwrap();
        assert_eq!(r.stored[0].rot, Rot::Unknown);
        assert!(r.found());
        assert!(r.stored[0].rot_words().contains("pass --since"));
    }

    #[test]
    fn an_unreadable_org_list_is_a_gap_with_the_count_of_workflows_that_could_use_it() {
        let mut v = world();
        v.secret_scopes.clear();
        v.secrets_unreadable = vec!["org".into()];
        v.repos.get_mut("acme/api").unwrap().secret_scopes.clear();
        let ix = Index::new(&v, &v.now);
        let r = build(&ix, &q(&["secret:PLAT_TOKEN"], Some("2026-05-11"))).unwrap();
        assert!(r.stored.is_empty());
        assert_eq!(r.verdict(), "FOUND", "the image still names it");
        assert!(r.gaps.iter().any(|g| g.1 == "org secrets not readable with this token: 1 workflow read names that could be org secrets"), "{:?}", r.gaps);
    }
}
