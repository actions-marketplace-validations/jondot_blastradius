//! The time-bounded view of the index that hunts read.

use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::sync::OnceLock;

use super::iocs::name_key;
use crate::view::*;
use regex::Regex;

/// 'npm:@a/b@1.2.3' -> ('npm', '@a/b', '1.2.3').
pub fn parse_pkg(p: &str) -> (&str, &str, &str) {
    let (eco, rest) = p.split_once(':').unwrap_or(("", p));
    match rest.rfind('@') {
        Some(i) if i > 0 => (eco, &rest[..i], &rest[i + 1..]),
        _ => (eco, rest, ""),
    }
}

#[derive(Debug, Clone, Default)]
pub struct CommitRef {
    pub sha: String,
    pub author: Option<String>,
    pub message: Option<String>,
}

impl CommitRef {
    fn of(c: &Commit) -> CommitRef {
        CommitRef { sha: c.sha.clone(), author: c.author.clone(), message: c.message.clone() }
    }
}

/// One continuous presence of a package in a lockfile's history.
#[derive(Debug, Clone)]
pub struct LockObs {
    pub p: String,
    pub pkg: LockPackage,
    pub first_seen: String,
    pub added_by: CommitRef,
    pub removed_at: Option<String>,
    pub removed_by: Option<CommitRef>,
    /// The lockfile this was read from; empty when only the union list was recorded.
    pub file: String,
}

#[derive(Debug, Clone)]
pub struct OwnerSpec {
    pub is_team: bool,
    pub teams: BTreeSet<String>,
    pub people: BTreeSet<String>,
}

#[derive(Clone)]
pub struct Index<'a> {
    pub v: &'a View,
    pub now: String,
    pub srcs: BTreeMap<String, Source>,
    hist: RefCell<HashMap<String, Rc<LockHist>>>,
    co: RefCell<HashMap<String, Rc<Vec<CoRule>>>>,
    people: OnceCell<HashMap<String, usize>>,
    runner_runs: OnceCell<HashMap<String, Vec<(&'a str, &'a Run)>>>,
    authors: RefCell<HashMap<String, Rc<HashSet<String>>>>,
    comp_runs: OnceCell<HashMap<(String, String), Vec<String>>>,
    /// The suggested owner of a repo, worked out once
    sugg: RefCell<HashMap<String, Option<(String, String)>>>,
    /// `repo_owner_suggested` per (repo, path), worked out once (one finding per run would repeat it 100k times)
    pub(crate) owner_sugg: RefCell<HashMap<(String, String), crate::query::hunt::Owner>>,
}

/// One CODEOWNERS rule, compiled once per repo.
#[derive(Debug)]
pub struct CoRule {
    re: Regex,
    owners: Vec<String>,
}

/// Who CODEOWNERS names for a path: teams (as the View's team ids) and people (logins, or raw emails).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CoOwners {
    pub teams: Vec<String>,
    pub people: Vec<String>,
}

/// A repo's lockfile history with a name index, so one indicator is a hash lookup.
#[derive(Debug, Default)]
pub struct LockHist {
    pub obs: Vec<LockObs>,
    by_key: HashMap<String, Vec<usize>>,
}

impl LockHist {
    /// Observations of the package an indicator names (any version).
    pub fn named<'s>(&'s self, eco: &str, name: &str) -> impl Iterator<Item = &'s LockObs> {
        let key = format!("{eco}:{}", name_key(eco, name));
        self.by_key.get(&key).into_iter().flatten().map(move |i| &self.obs[*i])
    }
}

fn build_hist(commits: &[&Commit]) -> LockHist {
    // open observations per lockfile path ("" when a commit only carries the union list)
    let mut open: HashMap<String, HashMap<String, usize>> = HashMap::new();
    let mut obs: Vec<LockObs> = Vec::new();
    for c in commits {
        let groups: Vec<(&str, &Vec<LockPackage>)> = if !c.lock_packages.is_empty() {
            c.lock_packages.iter().map(|(k, v)| (k.as_str(), v)).collect()
        } else if let Some(p) = &c.packages {
            vec![("", p)]
        } else {
            continue;
        };
        for (path, pkgs) in groups {
            let mut order: Vec<&str> = Vec::new();
            let mut cur: HashMap<&str, &LockPackage> = HashMap::new();
            for p in pkgs {
                if cur.insert(p.p.as_str(), p).is_none() {
                    order.push(p.p.as_str());
                }
            }
            let op = open.entry(path.to_string()).or_default();
            for pid in &order {
                let p = cur[pid];
                match op.get(*pid) {
                    None => {
                        obs.push(LockObs { p: pid.to_string(), pkg: p.clone(), first_seen: c.at.clone(), added_by: CommitRef::of(c), removed_at: None, removed_by: None, file: path.to_string() });
                        op.insert(pid.to_string(), obs.len() - 1);
                    }
                    Some(&i) => obs[i].pkg = p.clone(),
                }
            }
            let gone: Vec<String> = op.keys().filter(|k| !cur.contains_key(k.as_str())).cloned().collect();
            for k in gone {
                let i = op.remove(&k).unwrap();
                obs[i].removed_at = Some(c.at.clone());
                obs[i].removed_by = Some(CommitRef::of(c));
            }
        }
    }
    let mut by_key: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, o) in obs.iter().enumerate() {
        let (e, n, _) = parse_pkg(&o.p);
        by_key.entry(format!("{e}:{}", name_key(e, n))).or_default().push(i);
    }
    LockHist { obs, by_key }
}

/// A runner or host name reduced to what two sources agree on: lower case, without the domain (`runner-1.ci.internal`
/// and `runner-1` are the same machine). An IP address stays whole.
pub fn runner_key(name: &str) -> String {
    let n = name.trim().to_lowercase();
    if n.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':') {
        return n;
    }
    n.split('.').next().unwrap_or(&n).to_string()
}

/// GitHub-hosted runners have no machine to scan.
pub fn is_hosted_runner(name: &str) -> bool {
    let n = name.trim().to_lowercase();
    n.is_empty() || n == "github-hosted" || n.starts_with("github actions") || n.starts_with("hosted agent") || n.starts_with("github-hosted")
}

static EMPTY_REPO: OnceLock<Repo> = OnceLock::new();

impl<'a> Index<'a> {
    pub fn new(v: &'a View, now: &str) -> Index<'a> {
        Index {
            v,
            now: now.to_string(),
            srcs: v.sources.clone(),
            hist: RefCell::new(HashMap::new()),
            co: RefCell::new(HashMap::new()),
            people: OnceCell::new(),
            runner_runs: OnceCell::new(),
            authors: RefCell::new(HashMap::new()),
            comp_runs: OnceCell::new(),
            sugg: RefCell::new(HashMap::new()),
            owner_sugg: RefCell::new(HashMap::new()),
        }
    }

    /// (uses, composite action dir) -> times of the runs that resolved that `uses` through it. Built once.
    pub fn composite_runs(&self) -> &HashMap<(String, String), Vec<String>> {
        self.comp_runs.get_or_init(|| {
            let mut m: HashMap<(String, String), Vec<String>> = HashMap::new();
            for rr in self.names("repo") {
                for run in self.runs(&rr) {
                    for (u, via, _) in crate::query::hunt::run_resolved(run) {
                        if let Some(v) = via {
                            let comp = v.split('@').next().unwrap_or("").to_string();
                            m.entry((u, comp)).or_default().push(run.at.clone());
                        }
                    }
                }
            }
            m
        })
    }

    /// When this source was indexed, never later than the clock.
    pub fn i(&self, name: &str) -> Option<String> {
        let s = self.srcs.get(name)?;
        let t = &s.indexed_at;
        if t.is_empty() {
            return None;
        }
        Some(if !self.now.is_empty() && *t > self.now { self.now.clone() } else { t.clone() })
    }

    /// `i` for a source known to exist.
    pub fn it(&self, name: &str) -> String {
        self.i(name).unwrap_or_default()
    }

    pub fn names(&self, kind: &str) -> Vec<String> {
        self.srcs.iter().filter(|(_, s)| s.kind == kind).map(|(n, _)| n.clone()).collect()
    }

    pub fn kind_of(&self, name: &str) -> &str {
        self.srcs.get(name).map_or("", |s| s.kind.as_str())
    }

    pub fn has_kind(&self, kind: &str) -> bool {
        self.srcs.values().any(|s| s.kind == kind)
    }

    /// The first registry source (kept for callers that want any one); images use `registry_of`.
    pub fn registry(&self) -> Option<String> {
        self.names("registry").into_iter().next()
    }

    /// The registry source an image repository belongs to: the longest registry source name that prefixes it, or the
    /// only registry when there is just one.
    pub fn registry_of(&self, repository: &str) -> Option<String> {
        let mut best: Option<&String> = None;
        let mut only: Option<&String> = None;
        let mut n = 0;
        for (name, s) in &self.srcs {
            if s.kind != "registry" {
                continue;
            }
            n += 1;
            only = Some(name);
            let pre = name.trim_end_matches('/');
            if (repository == pre || repository.starts_with(&format!("{pre}/"))) && best.is_none_or(|b| name.len() > b.len()) {
                best = Some(name);
            }
        }
        best.cloned().or_else(|| if n == 1 { only.cloned() } else { None })
    }

    // ---- repos ---------------------------------------------------------------------------------
    pub fn repo(&self, name: &str) -> &Repo {
        self.v.repos.get(name).unwrap_or_else(|| EMPTY_REPO.get_or_init(Repo::default))
    }

    /// Index over the same view with other source times (used to ask "what did the old scan see").
    pub fn with_srcs(&self, srcs: BTreeMap<String, Source>) -> Index<'a> {
        Index {
            v: self.v,
            now: self.now.clone(),
            srcs,
            hist: RefCell::new(HashMap::new()),
            co: RefCell::new(HashMap::new()),
            people: OnceCell::new(),
            runner_runs: OnceCell::new(),
            authors: RefCell::new(HashMap::new()),
            comp_runs: OnceCell::new(),
            sugg: RefCell::new(HashMap::new()),
            owner_sugg: RefCell::new(HashMap::new()),
        }
    }

    pub fn commits(&self, name: &str) -> Vec<&Commit> {
        let Some(t) = self.i(name) else { return vec![] };
        let mut cs: Vec<&Commit> = self.repo(name).commits.iter().filter(|c| !c.at.is_empty() && c.at <= t).collect();
        if !cs.windows(2).all(|w| w[0].at <= w[1].at) {
            cs.sort_by(|a, b| a.at.cmp(&b.at));
        }
        cs
    }

    /// Lower-cased logins that authored a commit in the repo, computed once.
    pub fn commit_authors(&self, name: &str) -> Rc<HashSet<String>> {
        if let Some(a) = self.authors.borrow().get(name) {
            return a.clone();
        }
        let set: HashSet<String> = self.commits(name).iter().filter_map(|c| c.author.as_ref()).map(|a| a.trim_start_matches('@').to_lowercase()).collect();
        let rc = Rc::new(set);
        self.authors.borrow_mut().insert(name.to_string(), rc.clone());
        rc
    }

    /// Every run of every indexed repo, keyed by the normalised runner name (see `runner_key`).
    pub fn runs_by_runner(&self) -> &HashMap<String, Vec<(&'a str, &'a Run)>> {
        self.runner_runs.get_or_init(|| {
            let mut m: HashMap<String, Vec<(&'a str, &'a Run)>> = HashMap::new();
            let v: &'a View = self.v;
            for (name, repo) in &v.repos {
                let Some(t) = self.i(name) else { continue };
                for run in repo.runs.iter().filter(|r| r.at <= t) {
                    let mut keys: Vec<String> = run.runners.iter().map(|r| runner_key(r)).collect();
                    if let Some(r) = &run.runner {
                        keys.push(runner_key(r));
                    }
                    keys.sort();
                    keys.dedup();
                    for k in keys {
                        m.entry(k).or_default().push((name.as_str(), run));
                    }
                }
            }
            m
        })
    }

    pub fn runs(&self, name: &str) -> Vec<&Run> {
        let Some(t) = self.i(name) else { return vec![] };
        self.repo(name).runs.iter().filter(|r| r.at <= t).collect()
    }

    pub fn caches(&self, name: &str) -> Vec<&Cache> {
        let Some(t) = self.i(name) else { return vec![] };
        self.repo(name).caches.iter().filter(|c| c.created <= t).collect()
    }

    pub fn artifacts(&self, name: &str) -> Vec<&Artifact> {
        let Some(t) = self.i(name) else { return vec![] };
        self.repo(name).artifacts.iter().filter(|c| c.created <= t).collect()
    }

    pub fn releases(&self, name: &str) -> Vec<&Release> {
        let Some(t) = self.i(name) else { return vec![] };
        self.repo(name).releases.iter().filter(|c| c.published <= t).collect()
    }

    pub fn lockfile(&self, name: &str) -> Option<String> {
        let r = self.repo(name);
        if let Some(l) = r.lockfile.as_ref().filter(|l| !l.is_empty()) {
            return Some(l.clone());
        }
        r.commits.iter().find_map(|c| c.manifest.as_ref().map(|m| m.path.clone()))
    }

    /// Latest manifest at or before `at`.
    pub fn manifest_at(&self, name: &str, at: &str) -> Option<&Manifest> {
        let mut m = None;
        for c in self.commits(name) {
            if c.at.as_str() <= at {
                if let Some(x) = &c.manifest {
                    m = Some(x);
                }
            }
        }
        m
    }

    /// Every lockfile path a repo has held (default lockfile first).
    pub fn lock_paths(&self, name: &str) -> Vec<String> {
        let mut out: Vec<String> = self.lockfile(name).into_iter().collect();
        for c in &self.repo(name).commits {
            for k in c.lock_packages.keys() {
                if !out.contains(k) {
                    out.push(k.clone());
                }
            }
        }
        out
    }

    /// Package observations in the lockfile history: one per continuous presence. Computed once per repo.
    pub fn lock_obs(&self, name: &str) -> Vec<LockObs> {
        self.lock_hist(name).obs.clone()
    }

    /// The lockfile history of a repo, built once per Index and indexed by package name.
    pub fn lock_hist(&self, name: &str) -> Rc<LockHist> {
        if let Some(h) = self.hist.borrow().get(name) {
            return h.clone();
        }
        let h = Rc::new(build_hist(&self.commits(name)));
        self.hist.borrow_mut().insert(name.to_string(), h.clone());
        h
    }

    pub fn owner_of(&self, name: &str, path: Option<&str>) -> Option<String> {
        let path = match path {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => self.lockfile(name).unwrap_or_default(),
        };
        self.codeowner(name, &path)
    }

    /// The first team CODEOWNERS names for `path` (last matching rule wins). See `owners_of` for every owner.
    pub fn codeowner(&self, repo: &str, path: &str) -> Option<String> {
        self.owners_of(repo, path).teams.into_iter().next()
    }

    /// Every owner of the last matching rule, teams and people apart. An ownerless rule clears ownership.
    pub fn owners_of(&self, repo: &str, path: &str) -> CoOwners {
        let rules = {
            let mut cache = self.co.borrow_mut();
            cache.entry(repo.to_string()).or_insert_with(|| Rc::new(compile_codeowners(self.v.repos.get(repo).map(|r| r.codeowners.as_str()).unwrap_or("")))).clone()
        };
        let path = path.trim_start_matches("./").trim_start_matches('/');
        let mut hit: Option<&CoRule> = None;
        for r in rules.iter() {
            if r.re.is_match(path) {
                hit = Some(r);
            }
        }
        let mut out = CoOwners::default();
        for o in hit.map(|r| r.owners.as_slice()).unwrap_or(&[]) {
            if let Some(rest) = o.strip_prefix('@') {
                if rest.contains('/') {
                    let id = self.v.teams.iter().find(|t| t.id.eq_ignore_ascii_case(o)).map(|t| t.id.clone()).unwrap_or_else(|| o.clone());
                    if !out.teams.contains(&id) {
                        out.teams.push(id);
                    }
                } else {
                    let l = self.person(rest).map(|p| p.login.clone()).unwrap_or_else(|| rest.to_string());
                    if !out.people.contains(&l) {
                        out.people.push(l);
                    }
                }
            } else if o.contains('@') {
                let l = self.person_by_email(o).unwrap_or_else(|| o.clone());
                if !out.people.contains(&l) {
                    out.people.push(l);
                }
            }
        }
        out
    }

    fn person_by_email(&self, email: &str) -> Option<String> {
        let e = email.to_lowercase();
        self.v.people.iter().find(|p| p.login.to_lowercase() == e || p.name.as_deref().map(|n| n.to_lowercase()) == Some(e.clone())).map(|p| p.login.clone())
    }

    // ---- hosts ---------------------------------------------------------------------------------
    pub fn host_def(&self, name: &str) -> Option<&Host> {
        self.v.hosts.get(name)
    }

    pub fn host_items(&self, name: &str) -> Vec<&HostItem> {
        let Some(t) = self.i(name) else { return vec![] };
        let Some(h) = self.v.hosts.get(name) else { return vec![] };
        let mut items: Vec<&HostItem> = h.items.iter().filter(|i| i.at <= t).collect();
        items.sort_by(|a, b| a.at.cmp(&b.at));
        items
    }

    // ---- images --------------------------------------------------------------------------------
    /// Images of every registry, each cut at its own registry's scan time. An image no registry claims (several
    /// registries, none a prefix) is cut at the clock rather than dropped.
    pub fn images(&self) -> Vec<&ImageBuild> {
        if !self.has_kind("registry") {
            return vec![];
        }
        self.v
            .images
            .iter()
            .filter(|b| match self.registry_of(&b.repository) {
                Some(r) => self.i(&r).is_some_and(|t| b.built <= t),
                None => self.now.is_empty() || b.built <= self.now,
            })
            .collect()
    }

    /// Ecosystems in which this index has seen a package called `name`.
    pub fn package_ecos(&self, name: &str) -> Vec<String> {
        let mut found = BTreeSet::new();
        let mut see = |p: &str| {
            let (e, n, _) = parse_pkg(p);
            if name_key(e, n) == name_key(e, name) {
                found.insert(e.to_string());
            }
        };
        for r in self.names("repo") {
            for o in self.lock_hist(&r).obs.iter() {
                see(&o.p);
            }
            for run in self.runs(&r) {
                run.installed.iter().for_each(|p| see(p));
            }
            for c in self.caches(&r) {
                c.contains.iter().for_each(|p| see(p));
            }
            for a in self.artifacts(&r) {
                a.contains.iter().for_each(|p| see(p));
            }
        }
        for h in self.names("host") {
            for it in self.host_items(&h) {
                it.pkgs.iter().for_each(|p| see(p));
            }
        }
        for b in self.images() {
            b.packages.iter().for_each(|p| see(p));
            for l in &b.layers {
                l.packages.iter().for_each(|p| see(p));
            }
        }
        found.into_iter().collect()
    }

    // ---- people and teams ----------------------------------------------------------------------
    pub fn team_ids(&self) -> Vec<&str> {
        self.v.teams.iter().map(|t| t.id.as_str()).collect()
    }

    pub fn is_team(&self, id: &str) -> bool {
        self.v.teams.iter().any(|t| t.id == id)
    }

    /// A person by login; logins compare case-insensitively.
    pub fn person(&self, login: &str) -> Option<&Person> {
        let m = self.people.get_or_init(|| self.v.people.iter().enumerate().map(|(i, p)| (p.login.to_lowercase(), i)).collect());
        m.get(&login.trim_start_matches('@').to_lowercase()).map(|&i| &self.v.people[i])
    }

    pub fn person_name(&self, login: &str) -> String {
        self.person(login).and_then(|p| p.name.clone()).unwrap_or_else(|| login.to_string())
    }

    fn team_by_short(&self, t: &str) -> Option<String> {
        let tl = t.to_lowercase();
        self.v
            .teams
            .iter()
            .find(|x| x.id.to_lowercase() == tl)
            .or_else(|| {
                let hits: Vec<&Team> = self.v.teams.iter().filter(|x| x.id.rsplit('/').next().map(|s| s.to_lowercase()) == Some(tl.clone())).collect();
                if hits.len() == 1 {
                    Some(hits[0])
                } else {
                    None
                }
            })
            .map(|x| x.id.clone())
    }

    /// Every team id of a person (a person can be on several).
    pub fn person_team_ids(&self, login: &str) -> Vec<String> {
        let Some(p) = self.person(login) else { return vec![] };
        let mut out: Vec<String> = vec![];
        for t in p.team.iter().chain(p.teams.iter()) {
            if let Some(id) = self.team_by_short(t) {
                if !out.contains(&id) {
                    out.push(id);
                }
            }
        }
        out
    }

    /// First team id of a person.
    pub fn person_team_id(&self, login: &str) -> Option<String> {
        self.person_team_ids(login).into_iter().next()
    }

    /// People who match a reference: a login or full name (case-insensitive), or a first name. Several = ambiguous.
    pub fn people_by_ref(&self, r: &str) -> Vec<String> {
        let r = r.trim_start_matches('@').to_lowercase();
        let exact: Vec<String> = self.v.people.iter().filter(|p| r == p.login.to_lowercase() || p.name.as_ref().map(|n| n.to_lowercase()) == Some(r.clone())).map(|p| p.login.clone()).collect();
        if !exact.is_empty() {
            return exact;
        }
        self.v.people.iter().filter(|p| p.name.as_ref().and_then(|n| n.split_whitespace().next().map(|f| f.to_lowercase())) == Some(r.clone())).map(|p| p.login.clone()).collect()
    }

    /// A person from a GitHub handle (with or without @), a full name or, when unique, a first name.
    pub fn person_by_ref(&self, r: &str) -> Option<String> {
        let hits = self.people_by_ref(r);
        if hits.len() == 1 {
            hits.into_iter().next()
        } else {
            None
        }
    }

    /// Several people or teams answer to this --owner value.
    pub fn ambiguous_owner(&self, spec: &str) -> Vec<String> {
        let low = spec.trim().to_lowercase();
        let teams: Vec<String> = self.v.teams.iter().filter(|t| t.id.rsplit('/').next().map(|s| s.to_lowercase()) == Some(low.clone())).map(|t| t.id.clone()).collect();
        if teams.len() > 1 {
            return teams;
        }
        let ppl = self.people_by_ref(spec);
        if ppl.len() > 1 {
            return ppl.into_iter().map(|l| format!("@{l}")).collect();
        }
        vec![]
    }

    /// --owner value -> team or person. None when it names nobody.
    pub fn resolve_owner(&self, spec: &str) -> Option<OwnerSpec> {
        let s = spec.trim();
        let low = s.to_lowercase();
        for t in &self.v.teams {
            let tl = t.id.to_lowercase();
            if low == tl || low == tl.trim_start_matches('@') {
                return Some(OwnerSpec { is_team: true, teams: [t.id.clone()].into(), people: BTreeSet::new() });
            }
        }
        if !self.ambiguous_owner(s).is_empty() {
            return None;
        }
        if let Some(t) = self.v.teams.iter().find(|t| t.id.rsplit('/').next().map(|x| x.to_lowercase()) == Some(low.clone())) {
            return Some(OwnerSpec { is_team: true, teams: [t.id.clone()].into(), people: BTreeSet::new() });
        }
        if let Some(pid) = self.person_by_ref(s) {
            let teams: BTreeSet<String> = self.person_team_ids(&pid).into_iter().collect();
            return Some(OwnerSpec { is_team: false, teams, people: [pid].into() });
        }
        if s.starts_with('@') && s.contains('/') {
            return Some(OwnerSpec { is_team: true, teams: [s.to_string()].into(), people: BTreeSet::new() });
        }
        None
    }
}

/// Translate one CODEOWNERS (gitignore) pattern to a regex over a repo-relative path.
pub fn co_regex(pat: &str) -> Option<Regex> {
    let dir_only = pat.ends_with('/') && pat.len() > 1;
    let trimmed = pat.trim_end_matches('/');
    let anchored = pat.starts_with('/') || trimmed.contains('/');
    let body = trimmed.trim_start_matches('/');
    if body.is_empty() {
        return Regex::new("^.*$").ok();
    }
    let cs: Vec<char> = body.chars().collect();
    let mut out = String::from("(?s)^");
    if !anchored {
        out.push_str("(?:.*/)?");
    }
    let mut i = 0;
    let mut wild_last = false;
    while i < cs.len() {
        let c = cs[i];
        let seg_start = i == 0 || cs[i - 1] == '/';
        if c == '/' {
            wild_last = false;
        }
        if c == '*' && cs.get(i + 1) == Some(&'*') {
            if seg_start && cs.get(i + 2) == Some(&'/') {
                out.push_str("(?:.*/)?");
                i += 3;
                continue;
            }
            if seg_start && i + 2 == cs.len() {
                out.push_str(".*");
                i += 2;
                wild_last = false;
                continue;
            }
            out.push_str(".*");
            i += 2;
            wild_last = true;
            continue;
        }
        match c {
            '*' => {
                out.push_str("[^/]*");
                wild_last = true;
            }
            '?' => {
                out.push_str("[^/]");
                wild_last = true;
            }
            '\\' if i + 1 < cs.len() => {
                out.push_str(&regex::escape(&cs[i + 1].to_string()));
                i += 1;
            }
            '[' => {
                if let Some(j) = cs[i + 1..].iter().position(|&x| x == ']') {
                    let inner: String = cs[i + 1..i + 1 + j].iter().collect();
                    let inner = inner.strip_prefix('!').map(|r| format!("^{r}")).unwrap_or(inner);
                    out.push('[');
                    out.push_str(&inner.replace('\\', "\\\\"));
                    out.push(']');
                    i += j + 1;
                    wild_last = true;
                } else {
                    out.push_str("\\[");
                }
            }
            _ => out.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    if dir_only || !wild_last {
        out.push_str("(?:/.*)?");
        if dir_only {
            // a directory pattern needs something below it
            out.truncate(out.len() - "(?:/.*)?".len());
            out.push_str("/.*");
        }
    }
    out.push('$');
    Regex::new(&out).ok()
}

fn compile_codeowners(text: &str) -> Vec<CoRule> {
    // compiled once for the process: a regex build per repo is quadratic-looking work at 5000 repos
    static COMMENT: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let comment = COMMENT.get_or_init(|| Regex::new(r"(^|\s)#.*$").unwrap());
    let mut out = vec![];
    for line in text.lines() {
        let line = comment.replace(line, "");
        let mut parts = line.split_whitespace();
        let Some(pat) = parts.next() else { continue };
        if pat.starts_with('!') {
            continue;
        }
        let Some(re) = co_regex(pat) else { continue };
        out.push(CoRule { re, owners: parts.map(|s| s.to_string()).collect() });
    }
    out
}

/// A person to ask about a repo whose CODEOWNERS names nothing br can resolve (no rule, or only teams the index does
/// not know). In this order: the person who archived it (audit log), the last committer, then the org admins. Returns
/// `(login, why)`; `why` is ready to print after "suggested: ". None when CODEOWNERS resolves, or nobody is on record.
pub fn suggested_owner(ix: &Index, repo: &str) -> Option<(String, String)> {
    if let Some(c) = ix.sugg.borrow().get(repo) {
        return c.clone();
    }
    let got = suggested_owner_uncached(ix, repo);
    ix.sugg.borrow_mut().insert(repo.to_string(), got.clone());
    got
}

fn suggested_owner_uncached(ix: &Index, repo: &str) -> Option<(String, String)> {
    let rp = ix.v.repos.get(repo)?;
    let path = ix.lockfile(repo).unwrap_or_default();
    let co = ix.owners_of(repo, &path);
    if !co.people.is_empty() || co.teams.iter().any(|t| ix.is_team(t) || ix.v.routed_teams.contains(t)) {
        return None;
    }
    let real = |l: &str| !l.is_empty() && !l.ends_with("[bot]");
    let day = |t: &str| crate::query::util::fmt(t).chars().take(5).collect::<String>();
    if let Some(a) = rp.archived_by.as_deref().map(|a| a.trim_start_matches('@')).filter(|a| real(a)) {
        let login = ix.person(a).map(|p| p.login.clone()).unwrap_or_else(|| a.to_string());
        let when = rp.archived_at.as_deref().filter(|t| !t.is_empty()).map(|t| format!(" {}", day(t))).unwrap_or_default();
        return Some((login, format!("archived it{when}")));
    }
    let last = rp.commits.iter().filter(|c| c.author.as_deref().is_some_and(real)).max_by(|a, b| a.at.cmp(&b.at));
    if let Some(c) = last {
        let a = c.author.as_deref().unwrap_or_default().trim_start_matches('@');
        let login = ix.person(a).map(|p| p.login.clone()).unwrap_or_else(|| a.to_string());
        return Some((login, format!("last committer {}", day(&c.at))));
    }
    let admins: Vec<&String> = ix.v.org_admins.iter().collect();
    admins.first().map(|a| (a.trim_start_matches('@').to_string(), "org admins".to_string()))
}

/// Is `path` equal to or below `root`?
pub fn under(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    path == root || path.starts_with(&format!("{root}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_key_drops_domain_and_case() {
        assert_eq!(runner_key("Runner-1.ci.internal"), "runner-1");
        assert_eq!(runner_key("10.0.0.7"), "10.0.0.7");
    }

    #[test]
    fn hosted_runners_have_no_machine() {
        assert!(is_hosted_runner("GitHub Actions 3"));
        assert!(!is_hosted_runner("gx-runner-a"));
    }

    #[test]
    fn codeowners_patterns_follow_gitignore() {
        let r = co_regex("/docs/").unwrap();
        assert!(r.is_match("docs/a/b.md") || r.is_match("docs/"));
        assert!(!r.is_match("x/docs/a.md"));
        let r = co_regex("*.js").unwrap();
        assert!(r.is_match("src/a/b.js"));
        assert!(!r.is_match("src/a/b.jsx"));
    }
}
