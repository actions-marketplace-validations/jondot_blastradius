//! `br claimcheck`: which of the names your org resolves privately could a stranger have claimed on a public registry?
//! br reads manifests, lockfiles, registry configs and shipped source maps (in the org's repos and CI artifacts, or in a
//! checkout with --path), then asks each public registry about each name with read-only GETs. It never publishes,
//! claims or changes anything: the guidance it prints is for a person to act on.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::collect::github::Gh;
use crate::collect::public::{self, Eco, Lookup, ScopeLookup};
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::query::claims::{self, Claim, Collected, Facts, Flag, Kind, Row, ScopeFact, Seen, Status, Strength, Tree};

#[derive(clap::Args, Debug)]
pub struct ClaimcheckArgs {
    /// check the checkout in DIR (repeatable) instead of the org's repos: no index and no GitHub token needed
    #[arg(long, value_name = "DIR")]
    pub path: Vec<String>,
    /// only this repo of the index (repeatable)
    #[arg(long, value_name = "ORG/REPO")]
    pub repo: Vec<String>,
    /// the GitHub org whose packages count as yours (repeatable; default: the org of the index)
    #[arg(long, value_name = "ORG")]
    pub org: Vec<String>,
    /// table (default), json, md, slack, summary, sarif (SARIF 2.1.0: a result on each file where an exposed name was seen; gaps as notifications)
    #[arg(long, value_name = "FMT")]
    pub format: Option<String>,
    /// exit 3 when some names, scopes or files could not be checked
    #[arg(long)]
    pub strict: bool,
    /// exit 10 when any name is FREE, SQUATTED or SCOPE UNCLAIMED
    #[arg(long = "fail-if", value_name = "exposed")]
    pub fail_if: Option<String>,
    /// most names to ask the public registries about (default 400); the rest are counted and listed as not checked, and
    /// under --fail-if a run that checked nothing exits 3
    #[arg(long = "max-names", value_name = "N", default_value_t = 400)]
    pub max_names: usize,
    /// judge each public package by the versions published on or before this date (a registry's own publish times; a
    /// registry that gives none is named per name)
    #[arg(long = "as-of", value_name = "DATE")]
    pub as_of: Option<String>,
    /// store this run as a snapshot under BR_HOME, so br diff --claimcheck can show what changed later (without it br writes nothing)
    #[arg(long)]
    pub record: bool,
}

/// `--claimcheck` and its options, for the commands that hand a claimcheck result on (notify, evidence, diff).
#[derive(clap::Args, Debug, Default, Clone)]
pub struct ClaimHand {
    /// work from br claimcheck instead of an incident: no indicator or advisory is needed
    #[arg(long)]
    pub claimcheck: bool,
    /// with --claimcheck: check the checkout in DIR (repeatable) instead of the org's repos
    #[arg(long = "path", value_name = "DIR", requires = "claimcheck")]
    pub path: Vec<String>,
    /// with --claimcheck: the GitHub org whose packages count as yours (repeatable)
    #[arg(long = "org", value_name = "ORG", requires = "claimcheck")]
    pub org: Vec<String>,
    /// with --claimcheck: most names to ask the public registries about (default 400)
    #[arg(long = "max-names", value_name = "N", requires = "claimcheck")]
    pub max_names: Option<usize>,
    /// with --claimcheck: judge public packages as of this date
    #[arg(long = "as-of", value_name = "DATE", requires = "claimcheck")]
    pub as_of: Option<String>,
}

impl ClaimHand {
    /// The claimcheck run these options ask for (`repo` is the command's own --repo).
    pub fn args(&self, repo: Option<&String>) -> ClaimcheckArgs {
        ClaimcheckArgs {
            path: self.path.clone(),
            repo: repo.cloned().into_iter().collect(),
            org: self.org.clone(),
            format: None,
            strict: false,
            fail_if: None,
            max_names: self.max_names.unwrap_or(400),
            as_of: self.as_of.clone(),
            record: false,
        }
    }
}

// ---- trees -----------------------------------------------------------------------------------------------------------
struct LocalTree {
    label: String,
    root: std::path::PathBuf,
}

impl Tree for LocalTree {
    fn label(&self) -> String {
        self.label.clone()
    }
    fn paths(&self) -> Vec<String> {
        let mut out = vec![];
        let mut stack = vec![self.root.clone()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() {
                    if !matches!(name.as_str(), "node_modules" | ".git" | "target" | "site-packages" | "__pycache__" | ".venv" | "venv") {
                        stack.push(p);
                    }
                } else if ft.is_file() {
                    if let Ok(r) = p.strip_prefix(&self.root) {
                        out.push(r.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
            if out.len() > 500_000 {
                break;
            }
        }
        out.sort();
        out
    }
    fn read(&self, path: &str) -> Result<Option<String>, String> {
        match std::fs::read(self.root.join(path)) {
            Ok(b) => Ok(Some(String::from_utf8_lossy(&b).to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("cannot read ({e})")),
        }
    }
}

struct GhTree<'a> {
    gh: &'a Gh,
    repo: String,
    branch: String,
    truncated: std::cell::Cell<bool>,
}

fn enc(p: &str) -> String {
    let mut o = String::new();
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

impl Tree for GhTree<'_> {
    fn label(&self) -> String {
        self.repo.clone()
    }
    fn paths(&self) -> Vec<String> {
        let q = format!("/repos/{}/git/trees/{}?recursive=1", self.repo, enc(&self.branch).replace('/', "%2F"));
        match self.gh.json_need(&q, "git tree") {
            Ok(Some(t)) => {
                self.truncated.set(t["truncated"].as_bool() == Some(true));
                t["tree"].as_array().into_iter().flatten().filter(|x| x["type"] == "blob").filter_map(|x| x["path"].as_str().map(str::to_string)).collect()
            }
            _ => vec![],
        }
    }
    fn read(&self, path: &str) -> Result<Option<String>, String> {
        match self.gh.text(&format!("/repos/{}/contents/{}?ref={}", self.repo, enc(path), enc(&self.branch).replace('/', "%2F"))) {
            Ok(t) => Ok(t),
            Err(e) => Err(e.msg),
        }
    }
}

/// A CI artifact (a zip of a build): its manifests, lockfiles and source maps.
struct ZipTree {
    label: String,
    files: BTreeMap<String, Vec<u8>>,
}

impl ZipTree {
    fn open(label: String, bytes: Vec<u8>) -> Result<ZipTree, String> {
        use std::io::Read;
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| format!("not a readable zip ({e})"))?;
        let mut files = BTreeMap::new();
        for i in 0..z.len() {
            let Ok(mut f) = z.by_index(i) else { continue };
            let name = f.name().to_string();
            if f.is_dir() || claims::priority(&name).is_none() || f.size() > 40 * 1024 * 1024 {
                continue;
            }
            let mut b = vec![];
            if f.read_to_end(&mut b).is_ok() {
                files.insert(name, b);
            }
        }
        Ok(ZipTree { label, files })
    }
}

impl Tree for ZipTree {
    fn label(&self) -> String {
        self.label.clone()
    }
    fn paths(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }
    fn read(&self, path: &str) -> Result<Option<String>, String> {
        Ok(self.files.get(path).map(|b| String::from_utf8_lossy(b).to_string()))
    }
}

// ---- the report ------------------------------------------------------------------------------------------------------
#[derive(Default)]
pub struct GapRow {
    pub what: String,
    pub why: String,
    pub to_close: String,
    /// how many names this gap leaves unchecked (0: a file or a repo that could not be read, whose names are unknown)
    pub names: usize,
}

#[derive(Default)]
pub struct Report {
    pub now: String,
    pub orgs: Vec<String>,
    pub rows: Vec<Row>,
    pub gaps: Vec<GapRow>,
    pub trees: usize,
    /// how many of `trees` are CI artifacts
    pub artifact_trees: usize,
    /// manifest dependencies no private registry setting covers, treated as public and not asked about
    pub treated_public: usize,
    /// the oldest and newest time a repo of the index this run used was last scanned; None: no index was used
    pub index: Option<(String, String)>,
    /// `--as-of`: the cut-off instant (a date is the end of that day, UTC)
    pub as_of_at: Option<String>,
    /// `--as-of`: CI artifacts created after the date (they did not exist then) and the names seen only in them, left out
    pub late_artifacts: Vec<String>,
    pub rewound: Vec<String>,
    pub files_read: usize,
    pub maps_read: usize,
    pub unreferenced_private: usize,
    pub go_public_skipped: usize,
    /// names only a source map, an extra index or a manifest with no lockfile put on the list that a public registry has, as expected
    pub public_expected: usize,
    pub indexes: Vec<(String, String, String)>,
    pub registries_asked: Vec<&'static str>,
    pub calls: u64,
    /// how many `--path` checkouts were read (0 for the index and GitHub): decides how SARIF names files
    pub checkout_roots: usize,
    /// `--as-of`, as the person wrote it
    pub as_of: Option<String>,
    /// the answers came from the sample registry inside the binary (`br demo claimcheck`)
    pub sample: bool,
    pub max_names: usize,
    /// dependencies a manifest declares in a checkout that sets a private registry and has no lockfile, that a public registry
    /// also has: br cannot tell which registry they resolve from, so they are not cleared and not called exposed
    pub undetermined: Vec<(Eco, String)>,
}

pub fn deps_word(n: usize) -> String {
    if n == 1 {
        "1 dependency".to_string()
    } else {
        format!("{n} dependencies")
    }
}

pub fn names_word(n: usize) -> String {
    if n == 1 {
        "1 name".to_string()
    } else {
        format!("{n} names")
    }
}

impl Report {
    pub fn exposed(&self) -> Vec<&Row> {
        self.rows.iter().filter(|r| r.status.exposed()).collect()
    }
    pub fn count(&self, s: Status) -> usize {
        self.rows.iter().filter(|r| r.status == s).count()
    }
    pub fn n_exposed(&self) -> usize {
        self.rows.iter().filter(|r| r.status.exposed()).count()
    }
    /// Names that were not checked, in the one unit every gap is counted in.
    pub fn not_checked_names(&self) -> usize {
        self.count(Status::NotChecked) + self.undetermined.len()
    }
    /// Files or repos that could not be read (their names are unknown, so they are not counted as names).
    pub fn files_not_read(&self) -> usize {
        self.gaps.iter().filter(|g| g.names == 0).count()
    }
    /// Scopes with public packages under them, whose holder the registry shows.
    pub fn held_scopes_shown(&self) -> usize {
        self.rows.iter().filter(|r| r.status == Status::ScopeUnclaimed && r.held_by().is_some_and(|b| !b.is_empty())).count()
    }
    /// All names the run found in the sources: the ones listed in the table, and the ones left out as ordinary public
    /// dependencies. A run cut by --max-names finds the same total (the cut names are listed as not checked instead of left out).
    pub fn names_found(&self) -> usize {
        self.rows.len() + self.public_expected
    }
    pub fn held_scopes(&self) -> usize {
        self.rows.iter().filter(|r| r.status == Status::ScopeUnclaimed && r.held_by().is_some()).count()
    }
    pub fn ours_by(&self, s: Strength) -> usize {
        self.rows.iter().filter(|r| r.status == Status::Ours && r.strength == Some(s)).count()
    }
    pub fn checked_any(&self) -> bool {
        self.rows.iter().any(|r| r.status != Status::NotChecked)
    }
    pub fn verdict(&self) -> &'static str {
        if self.n_exposed() > 0 {
            "EXPOSED"
        } else if !self.gaps.is_empty() {
            "CLEAR WITH GAPS"
        } else {
            "CLEAR"
        }
    }
    /// " (sample registry)" when the answers are the demo's sample, else nothing: put it on every line that states a registry fact.
    pub fn reg(&self) -> &'static str {
        if self.sample {
            " (sample registry)"
        } else {
            ""
        }
    }
    /// The exposed names, most urgent first (the one rule in `claims::urgency`).
    pub fn urgent(&self) -> Vec<&Row> {
        let mut v = self.exposed();
        v.sort_by_key(|x| (claims::urgency(x), x.eco, x.name.clone()));
        v
    }
}

fn gap_to_close(why: &str) -> &'static str {
    if why.contains("rate limited") {
        "run it again later; the public registries limit how fast names can be asked about"
    } else if why.contains("unreachable") || why.starts_with("HTTP 5") {
        "check the network, then run it again"
    } else if why.contains("rate limit") {
        "wait for the GitHub quota to reset, then run it again"
    } else if why.contains("not valid") {
        "fix the file or check those names by hand"
    } else {
        "check these by hand, or run it again"
    }
}

fn cut_stamp(t: &str) -> String {
    t.chars().take(19).collect()
}

/// The clock law: a public version published after the clock does not exist yet, so a name whose every version is newer is free.
pub fn apply_clock(look: Lookup, now: &str) -> Lookup {
    match look {
        Lookup::Found(mut p) => {
            let before = p.versions.len();
            let cut = cut_stamp(now);
            p.versions.retain(|v| v.time.as_deref().map(|t| cut_stamp(t) <= cut).unwrap_or(true));
            if before > 0 && p.versions.is_empty() {
                Lookup::Free
            } else {
                Lookup::Found(p)
            }
        }
        o => o,
    }
}

/// `--as-of`: judge a public package by the versions published on or before `as_of`. What the date did to this name, and
/// what the registry did not say, is returned as notes for the name.
pub fn apply_as_of(look: Lookup, as_of: &str, shown: &str) -> (Lookup, Vec<String>) {
    match look {
        Lookup::Found(mut p) => {
            let cut = cut_stamp(as_of);
            let before = p.versions.len();
            let no_time = p.versions.iter().filter(|v| v.time.is_none()).count();
            let mut notes = vec![];
            p.versions.retain(|v| v.time.as_deref().map(|t| cut_stamp(t) <= cut).unwrap_or(true));
            let dropped = before - p.versions.len();
            if before > 0 && p.versions.is_empty() {
                notes.push(format!("every public version was published after {shown}, so on that date no public package had this name"));
                return (Lookup::Free, notes);
            }
            if dropped > 0 {
                notes.push(format!(
                    "judged as of {shown}: {} published later {} left out",
                    if dropped == 1 { "1 version".to_string() } else { format!("{dropped} versions") },
                    if dropped == 1 { "was" } else { "were" }
                ));
            }
            if no_time > 0 {
                notes.push(format!(
                    "the registry gives no publish time for {} of its {}, so --as-of {shown} could not be applied to {}; {} counted as published",
                    if no_time == 1 { "1 version".to_string() } else { format!("{no_time} versions") },
                    before,
                    if no_time == 1 { "it" } else { "them" },
                    if no_time == 1 { "it is" } else { "they are" }
                ));
            }
            (Lookup::Found(p), notes)
        }
        o => (o, vec![]),
    }
}

/// `--as-of DATE`: a date is the end of that day (UTC); a full time is that instant. Returns the cut-off.
pub fn parse_as_of(s: &str, now: &str) -> BrResult<String> {
    let raw = s.trim();
    let iso = crate::collect::util::norm_iso(raw).map_err(|e| BrError::new(format!("--as-of {raw}: {}", e.msg), Some("write a date with its year, e.g. --as-of 2026-06-09")))?;
    let cut = if raw.len() == 10 { format!("{}T23:59:59Z", &raw[..10]) } else { iso };
    if cut_stamp(&cut) > cut_stamp(now) {
        return Err(BrError::new(format!("--as-of {raw} is after the clock ({now})"), Some("a registry cannot show what is not published yet; use a date up to today")));
    }
    Ok(cut)
}

struct MemTree {
    label: String,
    files: BTreeMap<String, String>,
}

impl Tree for MemTree {
    fn label(&self) -> String {
        self.label.clone()
    }
    fn paths(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }
    fn read(&self, path: &str) -> Result<Option<String>, String> {
        Ok(self.files.get(path).cloned())
    }
}

/// The repo a tree label stands for: a CI artifact is labelled "org/repo (artifact NAME)".
pub fn repo_of_label(label: &str) -> &str {
    label.split(" (artifact").next().unwrap_or(label)
}

/// Lookups with the rate-limit streak, the cache of scope answers and the record of what could not be answered.
struct Asker {
    blocked: BTreeSet<Eco>,
    streak: BTreeMap<Eco, u32>,
    asked: BTreeSet<&'static str>,
    unknown_by: BTreeMap<(Eco, String), Vec<String>>,
    scopes: BTreeMap<String, ScopeLookup>,
}

impl Asker {
    fn tally(&mut self, eco: Eco, limited: bool) {
        // three rate-limited answers in a row stop the questions to that registry (one limited name is not a limited registry)
        *self.streak.entry(eco).or_default() = if limited { self.streak.get(&eco).copied().unwrap_or(0) + 1 } else { 0 };
        if self.streak[&eco] >= 3 {
            self.blocked.insert(eco);
        }
    }
    fn scope(&mut self, s: &str, record: bool) -> ScopeLookup {
        if let Some(l) = self.scopes.get(s) {
            return l.clone();
        }
        let look = if self.blocked.contains(&Eco::Npm) {
            ScopeLookup::Unknown("skipped: the registry had already rate limited this run".into())
        } else {
            self.asked.insert(Eco::Npm.registry());
            public::scope(s)
        };
        let limited = matches!(&look, ScopeLookup::Unknown(w) if w.starts_with("rate limited"));
        self.tally(Eco::Npm, limited);
        if record {
            if let ScopeLookup::Unknown(w) = &look {
                self.unknown_by.entry((Eco::Npm, w.clone())).or_default().push(format!("@{s}"));
            }
        }
        self.scopes.insert(s.to_string(), look.clone());
        look
    }
    fn name(&mut self, eco: Eco, name: &str) -> Lookup {
        let look = if self.blocked.contains(&eco) {
            Lookup::Unknown("skipped: the registry had already rate limited this run".into())
        } else {
            self.asked.insert(eco.registry());
            public::lookup(eco, name)
        };
        let limited = matches!(&look, Lookup::Unknown(w) if w.starts_with("rate limited"));
        self.tally(eco, limited);
        if let Lookup::Unknown(w) = &look {
            self.unknown_by.entry((eco, w.clone())).or_default().push(name.to_string());
        }
        look
    }
}

fn scope_fact(row: &Row) -> ScopeFact {
    match row.status {
        Status::Ours => ScopeFact::Ours,
        Status::ScopeUnclaimed => match row.held_by() {
            Some(by) => ScopeFact::Held(by),
            None => ScopeFact::Unheld,
        },
        _ => ScopeFact::Unknown,
    }
}

fn list_some(v: &[String], n: usize) -> String {
    let mut s = v.iter().take(n).cloned().collect::<Vec<_>>().join(", ");
    if v.len() > n {
        s += ", ...";
    }
    s
}

pub fn build(ctx: &Ctx, a: &ClaimcheckArgs) -> BrResult<Report> {
    let sample = public::sample();
    let as_of_cut = match &a.as_of {
        Some(s) => Some(parse_as_of(s, &ctx.now)?),
        None => None,
    };
    // who we are
    let mut orgs: Vec<String> = a.org.iter().map(|o| o.to_lowercase()).collect();
    let mut members: BTreeSet<String> = BTreeSet::new();
    let mut view = None;
    let have_index = crate::store::exists(ctx);
    if a.path.is_empty() || have_index {
        match ctx.view() {
            Ok(v) => view = Some(v),
            Err(e) if a.path.is_empty() => return Err(e),
            Err(_) => {}
        }
    }
    if let Some(v) = &view {
        if orgs.is_empty() {
            if let Some(o) = &v.org.github {
                orgs.push(o.to_lowercase());
            }
        }
        members = v.people.iter().map(|p| p.login.to_lowercase()).collect();
    }
    if let Some(s) = &sample {
        if orgs.is_empty() {
            orgs.push(s.org.to_lowercase());
        }
        if !a.path.is_empty() {
            return Err(BrError::new("the demo reads its own sample manifests, not a checkout", Some("drop --path, or run br claimcheck --path DIR on your own machine")));
        }
    }

    let mut c = Collected::default();
    let mut late_labels: BTreeSet<String> = BTreeSet::new();
    let mut gh_gaps: Vec<(String, String)> = vec![];
    if let Some(s) = &sample {
        for r in &a.repo {
            if !s.repos.contains_key(r) {
                return Err(BrError::new(format!("{r} is not in the sample org"), Some("br demo claimcheck lists the sample repos in its output")));
            }
        }
        for (repo, files) in &s.repos {
            if a.repo.is_empty() || a.repo.contains(repo) {
                claims::collect_tree(&mut c, &MemTree { label: repo.clone(), files: files.clone() });
            }
        }
    } else if !a.path.is_empty() {
        for d in &a.path {
            let root = std::path::PathBuf::from(d);
            if !root.is_dir() {
                return Err(BrError::new(format!("--path {d}: not a directory"), Some("example: br claimcheck --path ./my-repo")));
            }
            let label = root.canonicalize().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_else(|| d.clone());
            claims::collect_tree(&mut c, &LocalTree { label, root });
        }
    } else {
        let v = view.as_ref().unwrap();
        let mut names: Vec<&String> = v.repos.keys().collect();
        if !a.repo.is_empty() {
            for r in &a.repo {
                if !v.repos.contains_key(r) {
                    return Err(BrError::new(format!("{r} is not in the index"), Some("br status lists the sources; or check a checkout with --path DIR")));
                }
            }
            names.retain(|n| a.repo.contains(n));
        }
        if names.is_empty() {
            return Err(BrError::new("the index holds no repos to read", Some("br init --org ORG first, or check a checkout with --path DIR")));
        }
        if ctx.token().is_none() {
            return Err(BrError::with_code(
                "claimcheck reads each repo's manifests and lockfiles from GitHub, and no token is set",
                Some(&format!("set {} (read-only is enough), or check a checkout with --path DIR", crate::collect::words::TOKEN_WORDS)),
                4,
            ));
        }
        let gh = Gh::new(ctx);
        let mut stopped = false;
        for n in names {
            if stopped {
                gh_gaps.push((n.clone(), "not read: GitHub's rate limit stopped the run".into()));
                continue;
            }
            let repo = &v.repos[n];
            let branch = repo.default_branch.clone().unwrap_or_else(|| "HEAD".into());
            let t = GhTree { gh: &gh, repo: n.clone(), branch, truncated: Default::default() };
            let before = c.gaps.len();
            claims::collect_tree(&mut c, &t);
            if t.truncated.get() {
                c.gaps.push((n.clone(), "the repo is too large for one tree listing: some files were not seen".into()));
            }
            for g in gh.take_gaps(&ctx.now) {
                c.gaps.push((format!("{n}: {}", g.scope), g.reason));
            }
            if c.gaps[before..].iter().any(|(_, w)| w.contains(crate::collect::github::RATE_STOP)) {
                stopped = true;
            }
            // CI artifacts: a build's source maps and manifests
            if stopped {
                continue;
            }
            let arts = readable_artifacts(repo, &ctx.now, usize::MAX);
            for (i, art) in arts.iter().enumerate() {
                if let Some(cut) = &as_of_cut {
                    if cut_stamp(&art.created) > cut_stamp(cut) {
                        late_labels.insert(format!("{n} (artifact {})", art.name));
                    }
                }
                if i >= 8 {
                    c.gaps.push((format!("{n}: artifacts"), format!("{} more artifact(s) were not opened (newest 8 per repo)", arts.len() - 8)));
                    break;
                }
                if art.size_mb.unwrap_or(0) > 200 {
                    c.gaps.push((format!("{n}: artifact {}", art.name), "larger than 200 MB, not opened".into()));
                    continue;
                }
                match gh.download(&format!("/repos/{n}/actions/artifacts/{}/zip", art.id)) {
                    Ok(Some(b)) => match ZipTree::open(format!("{n} (artifact {})", art.name), b) {
                        Ok(z) => claims::collect_tree(&mut c, &z),
                        Err(e) => c.gaps.push((format!("{n}: artifact {}", art.name), e)),
                    },
                    Ok(None) => {}
                    Err(e) => {
                        c.gaps.push((format!("{n}: artifact {}", art.name), e.msg.clone()));
                        if e.msg.contains(crate::collect::github::RATE_STOP) {
                            stopped = true;
                            break;
                        }
                    }
                }
            }
            for g in gh.take_gaps(&ctx.now) {
                c.gaps.push((format!("{n}: {}", g.scope), g.reason));
            }
        }
    }
    c.finish();
    // --as-of, the org's side: a CI artifact created after the date did not exist then, so a name seen only in such artifacts
    // is left out (and counted). Repos are read as they are today: the index keeps no older state of a repo's files.
    let mut rewound: Vec<String> = vec![];
    if !late_labels.is_empty() {
        let only_late = |seen: &BTreeSet<Seen>| !seen.is_empty() && seen.iter().all(|x| late_labels.contains(&x.repo));
        let gone: Vec<(Eco, String)> = c.claims.iter().filter(|(_, cl)| only_late(&cl.seen)).map(|(k, _)| k.clone()).collect();
        for k in gone {
            c.claims.remove(&k);
            rewound.push(k.1);
        }
        let gone: Vec<String> = c.scopes.iter().filter(|(_, su)| only_late(&su.seen)).map(|(k, _)| k.clone()).collect();
        for k in gone {
            c.scopes.remove(&k);
            rewound.push(format!("@{k}"));
        }
        for places in c.bin_cmds.values_mut() {
            if places.iter().any(|x| !late_labels.contains(&x.repo)) {
                places.retain(|x| !late_labels.contains(&x.repo));
            }
        }
        c.bin_cmds.retain(|_, places| places.iter().any(|x| !late_labels.contains(&x.repo)));
        rewound.sort();
        rewound.dedup();
    }

    // ---- ask the public registries ----
    let bin_set: BTreeSet<String> = c.bin_cmds.keys().cloned().collect();
    let facts = Facts { orgs: orgs.clone(), members, bin_cmds: &bin_set };
    let mut rows: Vec<Row> = vec![];
    let mut gaps: Vec<GapRow> = vec![];
    let mut ask = Asker { blocked: BTreeSet::new(), streak: BTreeMap::new(), asked: BTreeSet::new(), unknown_by: BTreeMap::new(), scopes: BTreeMap::new() };
    let mut public_expected = 0usize;
    let mut undetermined: Vec<(Eco, String)> = vec![];
    let shown_as_of = a.as_of.clone().map(|s| s.trim().to_string());
    // the date every public answer is judged by: the clock, or --as-of
    let judge = |look: Lookup| -> (Lookup, Vec<String>) {
        match (&as_of_cut, &shown_as_of) {
            (Some(cut), Some(shown)) => apply_as_of(apply_clock(look, &ctx.now), cut, shown),
            _ => (apply_clock(look, &ctx.now), vec![]),
        }
    };

    // scopes: every scope an own or privately-resolved name lives under, and every scope mapped to a private registry
    let mut scope_names: BTreeSet<String> = BTreeSet::new();
    for ((e, n), cl) in &c.claims {
        if *e == Eco::Npm && cl.kinds.iter().any(|k| matches!(k, Kind::Own | Kind::Private)) {
            if let Some(s) = n.strip_prefix('@').and_then(|r| r.split('/').next()) {
                scope_names.insert(s.to_string());
            }
        }
    }
    for (s, su) in &c.scopes {
        if !su.mapped.is_empty() {
            scope_names.insert(s.clone());
        }
    }
    for s in scope_names {
        let su = c.scopes.get(&s).cloned().unwrap_or_default();
        let look = ask.scope(&s, true);
        let mut row = claims::classify_scope(&s, &su, &look, &facts);
        if let Some(shown) = &shown_as_of {
            row.as_of_notes.push(format!("npm shows no dates for a scope's packages, so --as-of {shown} could not be applied to this scope"));
        }
        rows.push(row);
    }
    // names that earn a lookup first: own and privately-resolved, then commands, then the rest
    let mut order: Vec<(&(Eco, String), &Claim)> = c.claims.iter().collect();
    order.sort_by_key(|(k, cl)| (cl.kinds.iter().next().copied().map(|k| k as u8).unwrap_or(9), k.0, k.1.clone()));
    let mut left = a.max_names;
    let mut over: Vec<String> = vec![];
    for ((eco, name), cl) in order {
        if left == 0 {
            // cut by --max-names: a name that was not asked about is a name not checked, listed as one
            let why = format!("not asked: beyond --max-names {}", a.max_names);
            rows.push(claims::classify(*eco, name, cl, &Lookup::Unknown(why), &facts));
            over.push(name.clone());
            continue;
        }
        left -= 1;
        let raw = ask.name(*eco, name);
        let (look, notes) = judge(raw);
        let mut row = claims::classify(*eco, name, cl, &look, &facts);
        row.as_of_notes = notes;
        // a name only a source map, an extra index or a manifest with no lockfile put here matters when no public package has it
        let weak_only = cl.kinds.iter().all(|k| matches!(k, Kind::SourceMap | Kind::ExtraIndex | Kind::Declared));
        if weak_only && matches!(look, Lookup::Found(_)) {
            if cl.kinds.contains(&Kind::Declared) {
                undetermined.push((*eco, name.clone()));
            } else {
                public_expected += 1;
            }
            continue;
        }
        if weak_only && row.status == Status::Free {
            row.note = Some("a name your code or index uses that no public registry has: an internal package".into());
        }
        rows.push(row);
    }
    // a scoped name: what is known of its scope (a scope br has not asked about is asked now, once)
    let scope_rows: BTreeMap<String, ScopeFact> = rows.iter().filter(|r| r.is_scope).map(|r| (r.name.trim_start_matches('@').to_string(), scope_fact(r))).collect();
    let mut facts_by_scope: BTreeMap<String, ScopeFact> = scope_rows;
    for r in rows.iter_mut().filter(|r| !r.is_scope && r.eco == Eco::Npm) {
        let Some(s) = r.name.strip_prefix('@').and_then(|x| x.split('/').next()).map(str::to_string) else { continue };
        if r.status == Status::NotChecked {
            continue;
        }
        let fact = match facts_by_scope.get(&s) {
            Some(f) => f.clone(),
            None => {
                let look = ask.scope(&s, false);
                let f = scope_fact(&claims::classify_scope(&s, &Default::default(), &look, &facts));
                facts_by_scope.insert(s.clone(), f.clone());
                f
            }
        };
        r.under_scope = Some((s, fact));
    }
    if !over.is_empty() {
        gaps.push(GapRow {
            what: format!("{} beyond --max-names {}", names_word(over.len()), a.max_names),
            why: format!("not asked about: {}", list_some(&over, 5)),
            to_close: "raise --max-names".into(),
            names: over.len(),
        });
    }
    if !undetermined.is_empty() {
        let list: Vec<String> = undetermined.iter().map(|(_, n)| n.clone()).collect();
        gaps.push(GapRow {
            what: format!("{} declared in a checkout with a private registry setting and no lockfile", names_word(list.len())),
            why: format!("a public registry has them too, and br cannot tell whether yours resolve from it or from your private registry: {}", list_some(&list, 8)),
            to_close: "add the lockfile, or hashes for pip (they record where each one resolves), or run claimcheck on the repo".into(),
            names: list.len(),
        });
    }
    for ((eco, why), names) in std::mem::take(&mut ask.unknown_by) {
        gaps.push(GapRow {
            what: format!("{} on {}", names_word(names.len()), eco.registry()),
            why: format!("{why}: {}", list_some(&names, 5)),
            to_close: gap_to_close(&why).into(),
            names: names.len(),
        });
    }
    for (w, why) in c.gaps.iter().chain(gh_gaps.iter()) {
        gaps.push(GapRow { what: w.clone(), why: why.clone(), to_close: gap_to_close(why).into(), names: 0 });
    }
    // owners: the repo each name was seen in, through the one owner resolver
    if let Some(v) = &view {
        let ix = crate::query::index::Index::new(v, &ctx.now);
        for r in rows.iter_mut() {
            r.owners = owners_of(&ix, &r.seen);
        }
    }
    rows.sort_by_key(|x| (x.status, claims::urgency(x), x.is_scope, x.eco, x.name.clone()));
    let indexes = c.indexes.iter().map(|i| (i.what.to_string(), i.url.clone(), i.seen.show())).collect::<BTreeSet<_>>().into_iter().collect();
    Ok(Report {
        now: ctx.now.clone(),
        orgs,
        rows,
        gaps,
        trees: c.trees,
        artifact_trees: c.artifact_trees,
        treated_public: c.treated_public,
        index: index_range(view.as_ref(), &a.repo),
        as_of_at: as_of_cut.clone(),
        late_artifacts: late_labels.into_iter().collect(),
        rewound,
        files_read: c.files_read,
        maps_read: c.maps_read,
        unreferenced_private: c.unreferenced_private,
        go_public_skipped: c.go_public_skipped,
        public_expected,
        indexes,
        registries_asked: ask.asked.into_iter().collect(),
        calls: public::calls(),
        checkout_roots: a.path.len(),
        as_of: shown_as_of,
        sample: sample.is_some(),
        max_names: a.max_names,
        undetermined,
    })
}

/// The CI artifacts of a repo that have not expired, newest first. claimcheck opens the newest 8 of them per repo; `br status`
/// counts the same ones, so both name their sources the same way.
pub fn readable_artifacts<'a>(repo: &'a crate::view::Repo, now: &str, limit: usize) -> Vec<&'a crate::view::Artifact> {
    let mut arts: Vec<&crate::view::Artifact> = repo.artifacts.iter().filter(|x| x.expires.as_deref().map(|e| e > now).unwrap_or(true)).collect();
    arts.sort_by(|x, y| y.created.cmp(&x.created));
    arts.truncate(limit);
    arts
}

/// When the repos of the index this run used were last scanned: the oldest and the newest.
fn index_range(view: Option<&crate::view::View>, only: &[String]) -> Option<(String, String)> {
    let v = view?;
    let times: Vec<&String> = v.sources.iter().filter(|(n, s)| s.kind == "repo" && (only.is_empty() || only.contains(*n))).map(|(_, s)| &s.indexed_at).collect();
    Some((times.iter().min()?.to_string(), times.iter().max()?.to_string()))
}

/// The teams (or people) that own the places a name was seen in: `hunt::repo_owner_suggested` for each repo and file, the
/// same resolver the hunt uses. A place the index does not know has no owner here.
fn owners_of(ix: &crate::query::index::Index, seen: &[Seen]) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for s in seen {
        let artifact = s.repo.contains(" (artifact");
        let repo = repo_of_label(&s.repo);
        let o = crate::query::hunt::repo_owner_suggested(ix, repo, if artifact { None } else { Some(s.file.as_str()) });
        out.extend(crate::query::hunt::owner_names(ix, &o));
    }
    out.into_iter().collect()
}

pub fn owner_label(r: &Row) -> String {
    if r.owners.is_empty() {
        "unresolved".into()
    } else {
        r.owners.join(", ")
    }
}

// ---- text ------------------------------------------------------------------------------------------------------------
fn yn(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "not shown",
    }
}

fn day(t: &str) -> String {
    t.chars().take(10).collect()
}

/// ", name first claimed 2025-01-01": when the name first appeared on the public registry, next to the newest version's date.
fn first_claimed(r: &Row) -> String {
    match &r.first_published {
        Some(t) => format!(", name first claimed {}", day(t)),
        None if r.public_max.is_some() => ", first publish time not shown by the registry".to_string(),
        None => String::new(),
    }
}

fn seen_list(r: &Row, max: usize) -> String {
    let mut s: Vec<String> = r.seen.iter().take(max).map(Seen::show).collect();
    if r.seen.len() > max {
        s.push(format!("and {} more", r.seen.len() - max));
    }
    s.join("; ")
}

fn why_listed(r: &Row) -> String {
    if r.is_scope {
        return if r.mapped.is_empty() { "scope of a package you use".into() } else { format!("scope mapped to {}", r.mapped.join(", ")) };
    }
    r.kinds.iter().map(|k| k.word()).collect::<Vec<_>>().join(", ")
}

fn row_lines(r: &Row, rep: &Report) -> Vec<String> {
    let mut l = vec![];
    let head = format!("{}  {}", if r.is_scope { "npm scope" } else { r.eco.word() }, r.name);
    l.push(head);
    if r.status.exposed() || r.status == Status::NotChecked {
        l.push(format!("what it means: {}", claims::plain(r)));
    }
    match r.status {
        Status::Squatted | Status::Ours => {
            let mut p = format!("public{}: {}", rep.reg(), r.public_max.as_deref().unwrap_or("no versions"));
            if let Some(t) = &r.published {
                p += &format!(", published {} (newest version)", day(t));
            }
            p += &first_claimed(r);
            p += &format!(", install script: {}", yn(r.install_script));
            if !r.publishers.is_empty() {
                p += &format!(", publisher: {}", r.publishers.join(", "));
            }
            if r.status == Status::Squatted && r.publishers.is_empty() {
                p += "; owner not shown";
            }
            l.push(p);
            if let (Some(pr), Some(st)) = (&r.proof, r.strength) {
                l.push(format!("shown to be yours ({}): {pr}", st.words()));
            }
        }
        Status::Free => l.push(format!("public{}: no package has this name", rep.reg())),
        _ => {}
    }
    if r.is_scope {
        if let (Some(p), Some(st)) = (&r.proof, r.strength) {
            l.push(format!("shown to be yours ({}): {p}", st.words()));
        }
        if !r.scope_pkgs.is_empty() {
            l.push(format!("public packages under it{}: {}", rep.reg(), list_some(&r.scope_pkgs, 10)));
        }
    }
    if r.is_scope || r.status == Status::Free {
        if let Some(n) = &r.note {
            l.push(n.clone());
        }
    }
    for f in &r.flags {
        l.push(format!("FLAG {}: {}", f.key(), f.text()));
    }
    for n in &r.as_of_notes {
        l.push(format!("as of: {n}"));
    }
    if let Some(y) = &r.yours {
        l.push(format!("highest version you use: {y}"));
    }
    l.push(format!("why listed: {}", why_listed(r)));
    l.push(format!("seen: {}", seen_list(r, 4)));
    l.push(format!("owner: {}", owner_label(r)));
    if !r.pinned.is_empty() {
        l.push(format!("pinned to your registry: {}", r.pinned.iter().take(3).cloned().collect::<Vec<_>>().join("; ")));
    }
    if !r.unpinned.is_empty() && !r.is_scope && r.eco != Eco::Go {
        l.push(format!("not pinned in: {}", r.unpinned.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
    }
    l
}

/// The steps for a set of exposed rows (the whole report, or one team's part of it): `claims::remediation`, chosen by status.
pub fn guidance_for(rows: &[&Row]) -> Vec<String> {
    let mut out = claims::remediation(rows);
    if !out.is_empty() {
        out.push("br did not publish, claim or change anything. These steps are for a person to take.".into());
    }
    out
}

pub fn guidance(rep: &Report) -> Vec<String> {
    guidance_for(&rep.exposed())
}

pub fn limits(rep: &Report) -> Vec<String> {
    let mut l = vec![
        "br read manifests, lockfiles, registry settings and source maps in repos and CI artifacts (or the --path checkout). It did not open image layers, caches or laptops, so a name that shows up only there is not on this list.".to_string(),
        "A public registry shows a name and its metadata, not who really owns it. A name is OURS only on the proof printed beside it; otherwise it is SQUATTED, and \"owner not shown\" means the registry did not say.".to_string(),
        "OURS comes in two strengths. Verified by the registry: the registry lists your GitHub team or a verified member as an owner. Declared by the publisher: the package's own metadata points at your GitHub, which anyone can type. A result that rests only on declared names is not a clean CLEAR.".to_string(),
        "The contents of your private registries and how they proxy a public one are not visible, so a name pinned to a private registry is still listed.".to_string(),
        "npm does not show whether a scope with no public package is registered; such a scope is listed as unclaimed.".to_string(),
    ];
    if rep.orgs.is_empty() {
        l.push("No org was named (no index, no --org), so no name could be shown to be yours.".into());
    }
    if rep.go_public_skipped > 0 {
        l.push(format!("{} Go module(s) live on public hosts you cannot be confused on, so they were not asked about.", rep.go_public_skipped));
    }
    if rep.unreferenced_private > 0 {
        l.push(format!("{} private, unpublished package(s) that nothing in the org depends on were not asked about.", rep.unreferenced_private));
    }
    if rep.public_expected > 0 {
        l.push(format!(
            "{} name(s) that only a source map or an extra index listed, and that a public registry has, were left out: they are most likely ordinary public dependencies.",
            rep.public_expected
        ));
    }
    if !rep.undetermined.is_empty() || rep.rows.iter().any(|r| r.kinds.contains(&Kind::Declared)) {
        l.push("Some names come from a manifest in a checkout that sets a private registry and has no lockfile: br cannot tell which of its dependencies resolve privately, so it asked about all of them, listed the ones no public registry has, and counted the ones a public registry also has as not checked. This covers npm; pip, uv and poetry with a private index and no lock or hashes; cargo with a private source replacement and no Cargo.lock; and Go modules a GOPRIVATE pattern names with no go.sum.".into());
    }
    l.push("A private index br is not shown is not covered: one set only in the environment (PIP_INDEX_URL, UV_INDEX_URL, CARGO_REGISTRIES_*, or GOPRIVATE kept in a shell profile, `go env -w` or a CI setting outside the repo), and a cargo `[registries]` entry that no dependency names (a dependency without `registry =` resolves from crates.io). Go's GOPRIVATE is read from go.env, .envrc, Makefiles, Dockerfiles and CI files only.".into());
    if rep.treated_public > 0 {
        l.push(format!(
            "{} the manifests declare {} treated as public and not asked about: no private registry setting or lockfile says they resolve from yours.",
            if rep.treated_public == 1 { "1 dependency that".to_string() } else { format!("{} dependencies that", rep.treated_public) },
            if rep.treated_public == 1 { "was" } else { "were" }
        ));
    }
    l.extend(as_of_lines(rep));
    if rep.sample {
        l.push("The answers are the sample registry inside this binary, not a public registry: nothing was asked over the network.".into());
    }
    l
}

/// `--as-of`, said plainly: what was rewound (the public side, and the CI artifacts that did not exist yet) and what was not (repos).
pub fn as_of_lines(rep: &Report) -> Vec<String> {
    let Some(d) = &rep.as_of else { return vec![] };
    let mut l = vec![format!(
        "--as-of {d}: each public package is judged by the versions published on or before that date, from the registry's own publish times. A registry that gives no time for a version is named on that name, and the version counts as published. npm shows no dates for the packages under a scope, so scopes are as of today."
    )];
    if !rep.late_artifacts.is_empty() {
        l.push(format!(
            "--as-of {d}: {} created after that date did not exist then and {} set aside; that leaves out {} seen only there{}.",
            if rep.late_artifacts.len() == 1 { "1 CI artifact".to_string() } else { format!("{} CI artifacts", rep.late_artifacts.len()) },
            if rep.late_artifacts.len() == 1 { "was" } else { "were" },
            if rep.rewound.len() == 1 { "1 name".to_string() } else { format!("{} names", rep.rewound.len()) },
            if rep.rewound.is_empty() { String::new() } else { format!(" ({})", list_some(&rep.rewound, 8)) }
        ));
    }
    l.push(format!("--as-of {d}: repos are read as they are today, because the index keeps no older state of a repo's files. A name added to a repo after {d} is still listed."));
    l
}

/// Where the run read its sources from, named the way `br status` names them: "9 repos and 1 CI artifact".
pub fn sources_words(rep: &Report) -> String {
    let others = rep.trees.saturating_sub(rep.artifact_trees);
    if rep.checkout_roots > 0 {
        crate::collect::util::count_words(&[(others, "checkout", "checkouts"), (rep.artifact_trees, "CI artifact", "CI artifacts")])
    } else {
        crate::collect::util::count_words(&[(others, "repo", "repos"), (rep.artifact_trees, "CI artifact", "CI artifacts")])
    }
}

/// How old the index was when the run read it.
pub fn index_line(rep: &Report) -> String {
    let at = |t: &str| format!("{}Z", t.chars().take(16).collect::<String>().replace('T', " "));
    let ago = |t: &str| match crate::collect::util::age_str(&rep.now, t).as_str() {
        "just now" => "just now".to_string(),
        a => format!("{a} before this run"),
    };
    if rep.sample {
        return "no index: the manifests and the registry answers are the sample inside this binary".into();
    }
    match &rep.index {
        Some((o, n)) => {
            let who = if rep.checkout_roots > 0 { " (used only to name owners; the checkout was read as it is now)" } else { "" };
            if o == n {
                format!("index: repos last scanned {} ({}){who}", at(o), ago(o))
            } else {
                format!("index: repos last scanned between {} and {} (the oldest {}){who}", at(o), at(n), ago(o))
            }
        }
        None => "no index was used: the checkout was read as it is now".into(),
    }
}

/// The names that could not be checked, each with its repo and owner when there are few; a count and a pointer when there are many.
pub fn not_checked_text(rep: &Report) -> Option<String> {
    let mut items: Vec<String> = rep
        .rows
        .iter()
        .filter(|r| r.status == Status::NotChecked)
        .map(|r| {
            let repo = r.seen.first().map(|x| repo_of_label(&x.repo).to_string());
            match repo {
                Some(p) => format!("{} ({p}, owner {})", r.name, owner_label(r)),
                None => format!("{} (owner {})", r.name, owner_label(r)),
            }
        })
        .collect();
    items.extend(rep.undetermined.iter().map(|(_, n)| format!("{n} (declared in a checkout; repo and owner unknown)")));
    let n = items.len();
    match n {
        0 => None,
        1..=8 => Some(format!("Not checked: {}.", items.join("; "))),
        _ => Some(format!("{} not checked: too many to list here. The full list, with repo and owner, is the NOT CHECKED part of br claimcheck.", names_word(n))),
    }
}

/// The limits for a reader who is not an engineer (a customer, a board): plain words, one voice ("we"), and no command, flag,
/// environment variable or file name of the tool.
pub fn limits_plain(rep: &Report) -> Vec<String> {
    let mut l = vec![
        "We read the package lists, lockfiles, registry settings and shipped source maps of our repositories and build outputs. We did not look inside container images, caches or staff laptops, so a name that appears only there is not covered.".to_string(),
        "A public registry shows a package name and its details, not who truly owns it. We count a name as ours only when the registry's own records show it; any other public package with one of our names is reported as not shown to be ours.".to_string(),
        "Some of the names we count as ours are backed by the registry's own records. Others rest only on what the package's publisher wrote, which anyone can write. A result that rests only on the second kind is not a clean bill of health.".to_string(),
        "We cannot see inside our private registries or how they pass requests on to public ones, so a name served by a private registry is still listed.".to_string(),
        "The npm registry does not show whether a scope with no public package is registered, so we list such a scope as unclaimed.".to_string(),
    ];
    if rep.orgs.is_empty() {
        l.push("We named no organisation to check, so no name could be shown to be ours.".into());
    }
    if rep.go_public_skipped > 0 {
        l.push(format!("{} of our Go modules are hosted on public code hosts where a name cannot be confused, so we did not ask about them.", rep.go_public_skipped));
    }
    if rep.unreferenced_private > 0 {
        l.push(format!("{} private, unpublished package(s) that nothing of ours depends on were not asked about.", rep.unreferenced_private));
    }
    if rep.public_expected > 0 {
        l.push(format!(
            "{} name(s) that only a source map or an extra package index listed, and that a public registry has, were left out: they are most likely ordinary public dependencies.",
            rep.public_expected
        ));
    }
    if rep.treated_public > 0 {
        l.push(format!(
            "{} that our manifests declare {} treated as public and not asked about, because no private registry setting or lockfile says they come from ours.",
            if rep.treated_public == 1 { "1 dependency".to_string() } else { format!("{} dependencies", rep.treated_public) },
            if rep.treated_public == 1 { "was" } else { "were" }
        ));
    }
    l.push(
        "A private package index that was not made known to the check is not covered, for example one that is configured only on a developer's machine or in a build setting outside our repositories."
            .into(),
    );
    if let Some(d) = &rep.as_of {
        l.push(format!("This statement is as of {d}. For each public package we used the versions published on or before that date, from the registry's own publish times; where a registry gives no time for a version we counted it as published, and npm shows no dates for packages under a scope, so scopes are as of today."));
        if !rep.late_artifacts.is_empty() {
            l.push(format!(
                "Build outputs created after {d} did not exist then, so we set them aside; that leaves out {} seen only there.",
                if rep.rewound.len() == 1 { "1 name".to_string() } else { format!("{} names", rep.rewound.len()) }
            ));
        }
        l.push(format!("Our repositories are read as they are today, because we keep no older state of their files, so a name added after {d} is still listed."));
    }
    if rep.sample {
        l.push("The registry answers here are a sample, not a public registry: nothing was asked over the network.".into());
    }
    l
}

fn ours_clause(rep: &Report) -> Option<String> {
    let (v, d) = (rep.ours_by(Strength::Verified), rep.ours_by(Strength::Declared));
    let n = rep.count(Status::Ours);
    if n == 0 {
        return None;
    }
    let mut parts = vec![];
    if v > 0 {
        parts.push(format!("{v} verified by the registry"));
    }
    if d > 0 {
        parts.push(format!("{d} declared by the publisher"));
    }
    Some(format!("{n} shown to be yours ({})", parts.join(", ")))
}

/// The one line that carries the verdict and every count: `EXPOSED: 14 names (6 squatted, 7 free, 1 scope held by someone else); 6 names not checked`.
/// Under `--as-of` it opens with the date the answer is for.
pub fn headline(rep: &Report) -> String {
    match &rep.as_of {
        Some(d) => format!("As of {d}: {}", headline_core(rep)),
        None => headline_core(rep),
    }
}

/// The headline without the as-of date.
pub fn headline_core(rep: &Report) -> String {
    let verdict = rep.verdict();
    let nx = rep.n_exposed();
    let nc = rep.not_checked_names();
    let files = rep.files_not_read();
    let (ver, dec) = (rep.ours_by(Strength::Verified), rep.ours_by(Strength::Declared));
    let mut tail: Vec<String> = vec![];
    if nc > 0 {
        tail.push(format!("{} not checked", names_word(nc)));
    }
    if files > 0 {
        tail.push(format!("{} could not be read", if files == 1 { "1 file or repo".to_string() } else { format!("{files} files or repos") }));
    }
    if nx > 0 {
        let mut p = vec![];
        for (s, w) in [(Status::Squatted, "squatted"), (Status::Free, "free")] {
            let n = rep.count(s);
            if n > 0 {
                p.push(format!("{n} {w}"));
            }
        }
        let held = rep.held_scopes_shown();
        let unshown = rep.held_scopes() - held;
        let unheld = rep.count(Status::ScopeUnclaimed) - rep.held_scopes();
        if held > 0 {
            p.push(format!("{held} {} held by someone else", if held == 1 { "scope" } else { "scopes" }));
        }
        if unshown > 0 {
            p.push(format!("{unshown} {} with public packages not shown to be yours", if unshown == 1 { "scope" } else { "scopes" }));
        }
        if unheld > 0 {
            p.push(format!("{unheld} {} unclaimed", if unheld == 1 { "scope" } else { "scopes" }));
        }
        tail.extend(ours_clause(rep));
        let mut s = format!("{verdict}: {} ({})", names_word(nx), p.join(", "));
        for t in tail {
            s += &format!("; {t}");
        }
        return s;
    }
    if dec > 0 && rep.gaps.is_empty() {
        // clear, but only on the publisher's word for some names: never a bare CLEAR
        let mut s = format!("CLEAR, but {} {} ours only by the publisher's word", names_word(dec), if dec == 1 { "is" } else { "are" });
        if ver > 0 {
            s += &format!("; {ver} verified by the registry");
        }
        return s;
    }
    let mut s = format!("{verdict}: no name is exposed");
    if dec > 0 {
        tail.push(format!("{} {} ours only by the publisher's word", names_word(dec), if dec == 1 { "is" } else { "are" }));
        if ver > 0 {
            tail.push(format!("{ver} verified by the registry"));
        }
    } else {
        tail.extend(ours_clause(rep));
    }
    for t in tail {
        s += &format!("; {t}");
    }
    s
}

fn urgent_lines(rep: &Report, n: usize) -> Vec<String> {
    rep.urgent().iter().take(n).map(|r| format!("{} ({})", r.name, claims::plain(r))).collect()
}

fn scanned_line(rep: &Report) -> String {
    // a name cut by --max-names was not asked about
    let not_asked = |r: &&Row| r.status == Status::NotChecked && r.note.as_deref().is_some_and(|n| n.starts_with("not asked"));
    let names = rep.rows.iter().filter(|r| !r.is_scope).filter(|r| !not_asked(r)).count();
    let scopes = rep.rows.iter().filter(|r| r.is_scope).count();
    format!(
        "read {} file(s) from {} ({} source map(s)); asked {} about {} name(s) and {} scope(s), read-only{}",
        rep.files_read,
        sources_words(rep),
        rep.maps_read,
        if rep.sample {
            "the sample registry inside this binary".to_string()
        } else if rep.registries_asked.is_empty() {
            "no public registry".to_string()
        } else {
            rep.registries_asked.join(", ")
        },
        names,
        scopes,
        if rep.orgs.is_empty() { String::new() } else { format!("; yours: github.com/{}", rep.orgs.join(", github.com/")) }
    ) + &format!(
        "; {} found in all ({} listed, {} left out as ordinary public dependencies{})",
        names_word(rep.names_found()),
        rep.rows.len(),
        rep.public_expected,
        if rep.treated_public > 0 { format!("; {} declared in manifests treated as public and not asked about", deps_word(rep.treated_public)) } else { String::new() }
    )
}

fn section_title(s: Status) -> &'static str {
    match s {
        Status::Squatted => "SQUATTED: a public package has a name you use, and nothing shows it is yours",
        Status::ScopeUnclaimed => "SCOPE UNCLAIMED: an npm scope you use that the public registry does not show as yours",
        Status::Free => "FREE: no public package has this name; each name says who could publish it",
        Status::NotChecked => "NOT CHECKED",
        Status::Ours => "OURS: public, and shown to be yours",
    }
}

fn first_line(rep: &Report) -> String {
    match &rep.as_of {
        Some(d) => format!("CLAIMCHECK  as of {d}, clock {}{}", rep.now, rep.reg()),
        None => format!("CLAIMCHECK  clock {}{}", rep.now, rep.reg()),
    }
}

pub fn render_table(rep: &Report) -> String {
    let mut o = vec![];
    o.push(first_line(rep));
    o.push(headline(rep));
    o.push(index_line(rep));
    let urgent = urgent_lines(rep, 3);
    if !urgent.is_empty() {
        o.push("MOST URGENT:".into());
        o.extend(urgent.iter().map(|x| format!("  {x}")));
    }
    o.push(scanned_line(rep));
    o.push("br only read. It published, claimed and changed nothing.".into());
    if !rep.indexes.is_empty() {
        o.push(String::new());
        o.push("PRIVATE REGISTRIES AND INDEXES SEEN".into());
        for (w, u, s) in &rep.indexes {
            o.push(format!("  {w}  {u}  ({s})"));
        }
    }
    for st in [Status::Squatted, Status::ScopeUnclaimed, Status::Free, Status::Ours] {
        let rows: Vec<&Row> = rep.rows.iter().filter(|r| r.status == st).collect();
        if rows.is_empty() {
            continue;
        }
        o.push(String::new());
        o.push(format!("{} ({})", section_title(st), rows.len()));
        for r in rows {
            let l = row_lines(r, rep);
            if st == Status::Ours {
                let how = r.strength.map(|s| s.words()).unwrap_or("");
                o.push(format!("  {}  [{how}]  ({})  owner: {}", l[0], r.proof.clone().unwrap_or_default(), owner_label(r)));
            } else {
                o.push(format!("  {}", l[0]));
                o.extend(l[1..].iter().map(|x| format!("      {x}")));
            }
        }
    }
    let g = guidance(rep);
    if !g.is_empty() {
        o.push(String::new());
        o.push("WHAT TO DO".into());
        o.extend(g.iter().map(|x| format!("  {x}")));
    }
    if !rep.gaps.is_empty() {
        o.push(String::new());
        o.push("NOT CHECKED:".into());
        let rows: Vec<Vec<String>> = rep.gaps.iter().map(|g| vec![g.what.clone(), g.why.clone(), g.to_close.clone()]).collect();
        o.extend(crate::collect::util::table(&["WHAT", "WHY", "TO CLOSE"], &rows, 2));
    }
    o.push(String::new());
    o.push("LIMITS".into());
    o.extend(limits(rep).iter().map(|x| format!("  - {x}")));
    o.join("\n")
}

pub fn render_md(rep: &Report) -> String {
    let mut o = vec![
        format!("# Claimcheck, {}", first_line(rep).trim_start_matches("CLAIMCHECK  ")),
        String::new(),
        format!("**{}**", headline(rep)),
        String::new(),
        scanned_line(rep) + ". br only read; it published, claimed and changed nothing.",
        String::new(),
        format!("{}.", index_line(rep)),
    ];
    let urgent = urgent_lines(rep, 3);
    if !urgent.is_empty() {
        o.push(String::new());
        o.push("**Most urgent**".into());
        o.extend(urgent.iter().map(|x| format!("- {x}")));
    }
    for st in [Status::Squatted, Status::ScopeUnclaimed, Status::Free, Status::Ours] {
        let rows: Vec<&Row> = rep.rows.iter().filter(|r| r.status == st).collect();
        if rows.is_empty() {
            continue;
        }
        o.push(String::new());
        o.push(format!("## {} ({})", section_title(st).split(':').next().unwrap_or(""), rows.len()));
        o.push(String::new());
        o.push(section_title(st).split_once(": ").map(|x| x.1.to_string() + ".").unwrap_or_default());
        o.push(String::new());
        o.push("| NAME | PUBLIC | WHAT IT MEANS | FLAGS | OWNER | SEEN |".into());
        o.push("|---|---|---|---|---|---|".into());
        for r in rows {
            let public = match r.status {
                Status::Free => format!("none{}", rep.reg()),
                _ if r.is_scope => {
                    let mut t = r.note.clone().unwrap_or_default();
                    if !r.scope_pkgs.is_empty() {
                        t += &format!(": {}", list_some(&r.scope_pkgs, 10));
                    }
                    t
                }
                _ => format!(
                    "{}{}{}, install script: {}{}",
                    r.public_max.clone().unwrap_or_else(|| "no versions".into()),
                    r.published.as_deref().map(|t| format!(" ({} newest version{})", day(t), first_claimed(r))).unwrap_or_default(),
                    rep.reg(),
                    yn(r.install_script),
                    if r.status == Status::Ours {
                        format!("; {} ({})", r.proof.clone().unwrap_or_default(), r.strength.map(|s| s.words()).unwrap_or(""))
                    } else if r.publishers.is_empty() {
                        "; owner not shown".into()
                    } else {
                        format!("; publisher {}", r.publishers.join(", "))
                    }
                ),
            };
            let flags = r.flags.iter().map(|f| f.text()).collect::<Vec<_>>().join("; ");
            o.push(format!(
                "| {} `{}` | {} | {} | {} | {} | {} |",
                if r.is_scope { "scope" } else { r.eco.word() },
                r.name,
                public.replace('|', "/"),
                claims::plain(r).replace('|', "/"),
                flags.replace('|', "/"),
                owner_label(r).replace('|', "/"),
                seen_list(r, 3).replace('|', "/")
            ));
        }
    }
    let g = guidance(rep);
    if !g.is_empty() {
        o.push(String::new());
        o.push("## What to do".into());
        o.extend(g.iter().map(|x| format!("- {x}")));
    }
    if !rep.gaps.is_empty() {
        o.push(String::new());
        o.push("## NOT CHECKED".into());
        o.push(String::new());
        o.push("| WHAT | WHY | TO CLOSE |".into());
        o.push("|---|---|---|".into());
        for g in &rep.gaps {
            o.push(format!("| {} | {} | {} |", g.what.replace('|', "/"), g.why.replace('|', "/"), g.to_close));
        }
    }
    o.push(String::new());
    o.push("## LIMITS".into());
    o.extend(limits(rep).iter().map(|x| format!("- {x}")));
    o.join("\n")
}

pub fn render_slack(rep: &Report) -> String {
    let when = match &rep.as_of {
        Some(d) => format!("Run on {}, as of {d}", day(&rep.now)),
        None => format!("Run on {}", day(&rep.now)),
    };
    let mut o = vec![format!("*Claimcheck: {}*{}", headline(rep), rep.reg()), format!("_{when}; {}._", index_line(rep))];
    for st in [Status::Squatted, Status::ScopeUnclaimed, Status::Free] {
        for r in rep.rows.iter().filter(|r| r.status == st) {
            let fl = if r.flags.is_empty() { String::new() } else { format!(" [{}]", r.flags.iter().map(|f| f.key()).collect::<Vec<_>>().join(", ")) };
            let pubv = match (st, &r.public_max) {
                (Status::Squatted, Some(v)) => {
                    format!(" public {v}{}, install script: {}", r.published.as_deref().map(|t| format!(" ({} newest version{})", day(t), first_claimed(r))).unwrap_or_default(), yn(r.install_script))
                }
                _ => String::new(),
            };
            o.push(format!("- {}: {} `{}`{}{}  seen {}  owner {}", st.word(), if r.is_scope { "npm scope" } else { r.eco.word() }, r.name, pubv, fl, seen_list(r, 1), owner_label(r)));
        }
    }
    if let Some(t) = not_checked_text(rep) {
        o.push(format!("_{t}_"));
    }
    if rep.files_not_read() > 0 {
        o.push(format!("_{} could not be read._", if rep.files_not_read() == 1 { "1 file or repo".to_string() } else { format!("{} files or repos", rep.files_not_read()) }));
    }
    if rep.as_of.is_some() {
        o.push("_As of: public versions after the date are left out, and so are CI artifacts created after it; repos are read as they are today._".to_string());
    }
    if rep.treated_public > 0 {
        o.push(format!("_{} declared in manifests {} treated as public and not asked about._", deps_word(rep.treated_public), if rep.treated_public == 1 { "was" } else { "were" }));
    }
    o.push("_Limits: manifests, lockfiles, registry settings and source maps only, not images, caches or laptops; a public registry does not show who really owns a name._".into());
    o.push("_br only read; nothing was published or claimed._".into());
    o.join("\n")
}

pub fn render_summary(rep: &Report) -> String {
    let lead = match &rep.as_of {
        Some(d) => format!("Dependency-confusion check as of {d} (run on {})", day(&rep.now)),
        None => format!("Dependency-confusion check, {}", day(&rep.now)),
    };
    let mut o = vec![format!("{lead}: {}.", headline_core(rep))];
    o.push(format!("{}.", index_line(rep)));
    let top = urgent_lines(rep, 3);
    if !top.is_empty() {
        o.push(format!("Most urgent: {}.", top.join("; ")));
    }
    if !rep.gaps.is_empty() {
        let nc = rep.not_checked_names();
        let mut parts = vec![];
        if nc > 0 {
            parts.push(format!("{} could not be checked", names_word(nc)));
        }
        if rep.files_not_read() > 0 {
            parts.push(format!("{} could not be read", if rep.files_not_read() == 1 { "1 file or repo".to_string() } else { format!("{} files or repos", rep.files_not_read()) }));
        }
        o.push(format!("{}, so this is not a clean bill of health.", parts.join(" and ")));
    }
    if let Some(t) = not_checked_text(rep) {
        o.push(t);
    }
    if let Some(d) = &rep.as_of {
        o.push(format!("Judged as of {d}."));
        o.extend(as_of_lines(rep).into_iter().skip(1));
    }
    if rep.treated_public > 0 {
        o.push(format!("{} declared in manifests {} treated as public and not asked about.", deps_word(rep.treated_public), if rep.treated_public == 1 { "was" } else { "were" }));
    }
    if rep.sample {
        o.push("The answers are from a sample registry, not a public one.".into());
    }
    o.push("Limits: br read manifests, lockfiles, registry settings and source maps; it did not open images, caches or laptops, and a public registry does not show who really owns a name.".into());
    o.push("Nothing was published, claimed or changed.".into());
    o.join("\n")
}

pub fn row_json(r: &Row, rep: &Report) -> Value {
    json!({
        "ecosystem": if r.is_scope { "npm" } else { r.eco.word() },
        "kind": if r.is_scope { "scope" } else { "package" },
        "name": r.name,
        "status": r.status.word(),
        "urgency": claims::urgency(r),
        "what_it_means": claims::plain(r),
        "owners": r.owners,
        "proof": r.proof,
        "ours_strength": r.strength.map(|s| s.key()),
        "public": if matches!(r.status, Status::Squatted | Status::Ours) { json!({
            "max_version": r.public_max, "published": r.published, "first_published": r.first_published, "install_script": yn(r.install_script), "publishers": r.publishers,
            "owner_shown": !r.publishers.is_empty() || r.proof.is_some(),
            "source": if rep.sample { "sample registry" } else { "public registry" },
        }) } else { Value::Null },
        "highest_version_you_use": r.yours,
        "why_listed": r.kinds.iter().map(|k| k.word()).collect::<Vec<_>>(),
        "flags": r.flags.iter().map(|f| json!({"flag": f.key(), "detail": f.text(), "command": if let Flag::BinMatch{command} = f { json!(command) } else { Value::Null }})).collect::<Vec<_>>(),
        "seen": r.seen.iter().map(|s| json!({"repo": s.repo, "file": s.file})).collect::<Vec<_>>(),
        "pinned": r.pinned,
        "not_pinned_in": r.unpinned,
        "mapped_to": r.mapped,
        "scope_packages": r.scope_pkgs,
        "under_scope": r.under_scope.as_ref().map(|(s, f)| json!({"scope": format!("@{s}"), "state": match f { ScopeFact::Held(_) => "held_by_someone_else", ScopeFact::Unheld => "unheld", ScopeFact::Ours => "yours", ScopeFact::Unknown => "not_checked" },
            "holders": if let ScopeFact::Held(by) = f { json!(by) } else { Value::Null }})),
        "as_of": r.as_of_notes,
        "not_checked_reason": if r.status == Status::NotChecked { json!(r.note) } else { Value::Null },
        "note": r.note,
    })
}

pub fn counts_json(rep: &Report) -> Value {
    json!({
        "exposed": rep.n_exposed(),
        "squatted": rep.count(Status::Squatted), "free": rep.count(Status::Free), "scope_unclaimed": rep.count(Status::ScopeUnclaimed),
        "scope_held": rep.held_scopes(),
        "ours": rep.count(Status::Ours), "ours_verified": rep.ours_by(Strength::Verified), "ours_declared": rep.ours_by(Strength::Declared),
        "not_checked": rep.not_checked_names(),
        "undetermined_declared": rep.undetermined.len(),
        "files_not_read": rep.files_not_read(),
        "names_found": rep.names_found(),
        "left_out_as_public": rep.public_expected,
        "treated_public_dependencies": rep.treated_public,
        "unit": "names",
    })
}

pub fn render_json(rep: &Report) -> String {
    let v = json!({
        "command": "claimcheck",
        "clock": rep.now,
        "as_of": rep.as_of,
        "as_of_at": rep.as_of_at,
        "sample_registry": rep.sample,
        "verdict": rep.verdict(),
        "headline": headline(rep),
        "exposed": rep.n_exposed(),
        "max_names": rep.max_names,
        "counts": counts_json(rep),
        "most_urgent": rep.urgent().iter().take(3).map(|r| json!({"name": r.name, "what_it_means": claims::plain(r)})).collect::<Vec<_>>(),
        "orgs": rep.orgs,
        "read": {"sources": rep.trees, "ci_artifacts": rep.artifact_trees, "sources_words": sources_words(rep), "files": rep.files_read, "source_maps": rep.maps_read, "registries_asked": rep.registries_asked},
        "index": {"oldest_scan": rep.index.as_ref().map(|x| x.0.clone()), "newest_scan": rep.index.as_ref().map(|x| x.1.clone()), "line": index_line(rep)},
        "as_of_rewind": if rep.as_of.is_some() { json!({"public_versions": "left out when published after the date", "ci_artifacts_set_aside": rep.late_artifacts, "names_left_out": rep.rewound, "repos": "read as they are today"}) } else { Value::Null },
        "private_registries": rep.indexes.iter().map(|(w, u, s)| json!({"what": w, "url": u, "seen": s})).collect::<Vec<_>>(),
        "names": rep.rows.iter().map(|r| row_json(r, rep)).collect::<Vec<_>>(),
        "gaps": rep.gaps.iter().map(|g| json!({"what": g.what, "why": g.why, "to_close": g.to_close, "names": g.names})).collect::<Vec<_>>(),
        "guidance": guidance(rep),
        "limits": limits(rep),
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

/// The exit code. Found wins over gaps, as in hunt. Under `--fail-if exposed` a run that checked nothing never exits 0
/// (it exits 3 even without `--strict`): a gate that passes because nothing was asked is no gate.
pub fn gate(a: &ClaimcheckArgs, rep: &Report) -> (i32, Option<String>) {
    if a.fail_if.is_some() {
        if rep.n_exposed() > 0 {
            return (10, None);
        }
        if !rep.checked_any() {
            let why = if rep.not_checked_names() > 0 {
                format!("--fail-if exposed: no name was checked ({} not checked), so br cannot say none is exposed", names_word(rep.not_checked_names()))
            } else {
                "--fail-if exposed: br found no name to check, so it cannot say none is exposed".to_string()
            };
            return (3, Some(why));
        }
    }
    if a.strict && !rep.gaps.is_empty() {
        return (3, None);
    }
    (0, None)
}

pub fn run(a: &ClaimcheckArgs, ctx: &Ctx) -> BrResult<i32> {
    let fmt = a.format.clone().unwrap_or_else(|| "table".into());
    if !["table", "json", "md", "slack", "summary", "sarif"].contains(&fmt.as_str()) {
        return Err(BrError::new(format!("unknown format \"{fmt}\""), Some("choose table, json, md, slack, summary or sarif")));
    }
    if let Some(f) = &a.fail_if {
        if f != "exposed" {
            return Err(BrError::new(format!("--fail-if takes exposed (got \"{f}\")"), Some("example: --fail-if exposed")));
        }
    }
    if !a.path.is_empty() && !a.repo.is_empty() {
        return Err(BrError::new("--path reads a checkout and --repo picks repos of the index", Some("use one of them")));
    }
    if a.record && public::sample().is_some() {
        return Err(BrError::new("the demo keeps nothing, so --record has nowhere to store a snapshot", Some("run br claimcheck --record on your own org")));
    }
    let rep = build(ctx, a)?;
    let out = match fmt.as_str() {
        "json" => render_json(&rep),
        "md" => render_md(&rep),
        "slack" => render_slack(&rep),
        "summary" => render_summary(&rep),
        "sarif" => crate::out::sarif::render_claims(&rep),
        _ => render_table(&rep),
    };
    println!("{out}");
    if a.record {
        let p = crate::cmd::claimhand::record(ctx, &rep)?;
        eprintln!("recorded this run as a snapshot: {}  (br diff --claimcheck shows what changed since)", p.display());
    }
    let (code, why) = gate(a, &rep);
    if let Some(w) = why {
        eprintln!("{w}");
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::claims::Claim;

    fn row(status: Status, flags: Vec<Flag>) -> Row {
        let mut cl = Claim::default();
        cl.kinds.insert(Kind::Own);
        let mut r = claims::classify(Eco::Npm, "corp-core", &cl, &Lookup::Free, &Facts { orgs: vec![], members: Default::default(), bin_cmds: &Default::default() });
        r.status = status;
        r.flags = flags;
        r.seen = vec![Seen { repo: "org/web".into(), file: "package.json".into() }];
        r
    }

    fn report(rows: Vec<Row>, gaps: Vec<GapRow>) -> Report {
        Report { now: "2026-05-12T07:10:00Z".into(), orgs: vec!["acme".into()], rows, gaps, trees: 2, files_read: 5, maps_read: 1, registries_asked: vec!["npmjs.org"], calls: 1, ..Default::default() }
    }

    fn named(name: &str, status: Status) -> Row {
        let mut r = row(status, vec![]);
        r.name = name.into();
        r
    }

    fn gap(names: usize) -> GapRow {
        GapRow { what: format!("{names} names on npmjs.org"), why: "rate limited (HTTP 429)".into(), to_close: "later".into(), names }
    }

    #[test]
    fn versions_after_the_clock_do_not_exist_yet() {
        use crate::collect::public::{PubVersion, Public};
        let v = |n: &str, t: &str| PubVersion { v: n.into(), time: Some(t.into()), install_script: None };
        let p = Public { versions: vec![v("1.0.0", "2026-06-09T12:00:00.000Z")], ..Default::default() };
        assert_eq!(apply_clock(Lookup::Found(p.clone()), "2026-06-05T08:00:00Z"), Lookup::Free);
        assert!(matches!(apply_clock(Lookup::Found(p.clone()), "2026-06-10T08:00:00Z"), Lookup::Found(_)));
        let two = Public { versions: vec![v("1.0.0", "2026-01-01T00:00:00Z"), v("9999.0.0", "2026-06-09T12:00:00Z")], ..Default::default() };
        match apply_clock(Lookup::Found(two), "2026-06-05T08:00:00Z") {
            Lookup::Found(q) => assert_eq!(q.versions.len(), 1),
            o => panic!("{o:?}"),
        }
        assert_eq!(apply_clock(Lookup::Unknown("x".into()), "2026-06-05T08:00:00Z"), Lookup::Unknown("x".into()));
    }

    #[test]
    fn verdict_words_follow_exposure_and_gaps() {
        assert_eq!(report(vec![row(Status::Ours, vec![])], vec![]).verdict(), "CLEAR");
        let gap = || GapRow { what: "w".into(), why: "rate limited (HTTP 429)".into(), to_close: "later".into(), names: 1 };
        assert_eq!(report(vec![row(Status::Ours, vec![])], vec![gap()]).verdict(), "CLEAR WITH GAPS");
        assert_eq!(report(vec![row(Status::Free, vec![])], vec![gap()]).verdict(), "EXPOSED");
        // not checked is never exposure and never clear
        let r = report(vec![row(Status::NotChecked, vec![])], vec![gap()]);
        assert_eq!(r.verdict(), "CLEAR WITH GAPS");
    }

    #[test]
    fn every_format_names_the_flags_and_says_it_only_read() {
        let r = report(vec![row(Status::Squatted, vec![Flag::HigherVersion { public: "9999.0.0".into(), yours: "1.0.0".into() }])], vec![]);
        for out in [render_table(&r), render_md(&r), render_slack(&r), render_summary(&r)] {
            assert!(out.contains("EXPOSED"), "{out}");
            assert!(out.contains("higher") || out.contains("highest"), "{out}");
            assert!(out.to_lowercase().contains("only read") || out.contains("Nothing was published"), "{out}");
        }
        let j: Value = serde_json::from_str(&render_json(&r)).unwrap();
        assert_eq!(j["verdict"], "EXPOSED");
        assert_eq!(j["names"][0]["flags"][0]["flag"], "higher_version");
        assert_eq!(j["names"][0]["status"], "SQUATTED");
        assert!(render_table(&r).contains("WHAT TO DO") && render_table(&r).contains("LIMITS"));
    }

    #[test]
    fn guidance_is_text_for_each_ecosystem() {
        let mut py = row(Status::Free, vec![]);
        py.eco = Eco::Pypi;
        py.name = "corp-lib".into();
        let mut go = row(Status::Squatted, vec![]);
        go.eco = Eco::Go;
        go.name = "git.corp.example/x".into();
        let r = report(vec![row(Status::Free, vec![]), py, go], vec![]);
        let g = guidance(&r).join("\n");
        assert!(g.contains("--index-url") && g.contains("GOPRIVATE") && g.contains("placeholder") && g.contains("did not publish"));
    }

    #[test]
    fn gaps_print_a_not_checked_table_and_close_hints_differ() {
        let r = report(vec![], vec![GapRow { what: "3 names on npmjs.org".into(), why: "unreachable".into(), to_close: gap_to_close("unreachable").into(), names: 3 }]);
        let t = render_table(&r);
        assert!(t.contains("NOT CHECKED:") && t.contains("WHAT") && t.contains("unreachable"), "{t}");
        assert_ne!(gap_to_close("rate limited (HTTP 429)"), gap_to_close("unreachable"));
    }

    fn pad(rep: &mut Report, n: usize, status: Status, prefix: &str) {
        for i in 0..n {
            rep.rows.push(named(&format!("{prefix}{i}"), status));
        }
    }

    #[test]
    fn the_headline_gives_the_total_and_counts_gaps_in_names_everywhere() {
        let mut r = report(vec![], vec![gap(6)]);
        pad(&mut r, 6, Status::Squatted, "s");
        pad(&mut r, 7, Status::Free, "f");
        let mut held = named("@org", Status::ScopeUnclaimed);
        held.is_scope = true;
        held.flags = vec![Flag::ScopeHeld { by: vec!["tom-t".into()] }];
        r.rows.push(held);
        pad(&mut r, 6, Status::NotChecked, "n");
        assert_eq!(headline(&r), "EXPOSED: 14 names (6 squatted, 7 free, 1 scope held by someone else); 6 names not checked");
        // one unit in every format: names, never "thing(s)" or rows
        for out in [render_summary(&r), render_slack(&r), render_table(&r), render_md(&r)] {
            assert!(out.contains("14 names"), "{out}");
            assert!(out.contains("6 names"), "{out}");
            assert!(!out.contains("thing(s)"), "{out}");
        }
        let j: Value = serde_json::from_str(&render_json(&r)).unwrap();
        assert_eq!(j["counts"]["not_checked"], 6);
        assert_eq!(j["counts"]["scope_held"], 1);
        assert_eq!(j["exposed"], 14);
        assert_eq!(j["counts"]["unit"], "names");
    }

    #[test]
    fn names_cut_by_max_names_are_names_not_checked_and_the_gate_does_not_pass_on_nothing() {
        let mut cut = named("cut", Status::NotChecked);
        cut.note = Some("not asked: beyond --max-names 0".into());
        let r = report(vec![cut], vec![GapRow { what: "1 name beyond --max-names 0".into(), why: "x".into(), to_close: "raise --max-names".into(), names: 1 }]);
        assert_eq!(r.not_checked_names(), 1);
        assert!(headline(&r).contains("1 name not checked"));
        let a = |strict: bool| ClaimcheckArgs { path: vec![], repo: vec![], org: vec![], format: None, strict, fail_if: Some("exposed".into()), max_names: 0, as_of: None, record: false };
        let (code, why) = gate(&a(false), &r);
        assert_eq!(code, 3, "a gate that checked nothing must not exit 0");
        assert!(why.unwrap().contains("1 name not checked"));
        // without --fail-if the same run is only a report
        let plain = ClaimcheckArgs { fail_if: None, ..a(false) };
        assert_eq!(gate(&plain, &r).0, 0);
        // something checked and clear: 0 without --strict, 3 with it
        let ok = report(vec![named("ok", Status::Ours), named("cut", Status::NotChecked)], vec![gap(1)]);
        assert_eq!(gate(&a(false), &ok).0, 0);
        assert_eq!(gate(&a(true), &ok).0, 3);
        // exposed wins
        assert_eq!(gate(&a(true), &report(vec![named("x", Status::Free)], vec![gap(1)])).0, 10);
        // no names at all is nothing checked as well
        assert_eq!(gate(&a(false), &report(vec![], vec![])).0, 3);
    }

    #[test]
    fn urgency_is_one_ordered_rule_and_says_it_in_plain_words() {
        let mut script = named("script", Status::Squatted);
        script.install_script = Some(true);
        script.public_max = Some("9999.0.0".into());
        script.publishers = vec!["mallory".into()];
        let mut higher = named("higher", Status::Squatted);
        higher.flags = vec![Flag::HigherVersion { public: "99.0".into(), yours: "1.0".into() }];
        let mut scope = named("@held", Status::ScopeUnclaimed);
        scope.is_scope = true;
        scope.flags = vec![Flag::ScopeHeld { by: vec!["tom-t".into()] }];
        let mut bin = named("bin", Status::Squatted);
        bin.flags = vec![Flag::BinMatch { command: "tool".into() }];
        let free = named("free", Status::Free);
        // a harmless 0.0.1 bin match must not outrank a stranger's 9999.0.0 with an install script
        let r = report(vec![free, bin, scope, higher, script], vec![]);
        let order: Vec<&str> = r.urgent().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(order, vec!["script", "higher", "@held", "bin", "free"]);
        let top = urgent_lines(&r, 3).join("; ");
        assert!(top.contains("a stranger published 9999.0.0, and it runs code when installed"), "{top}");
        assert!(!top.contains("bin match") && !top.contains("higher_version"), "{top}");
        assert!(render_summary(&r).contains("Most urgent: script (a stranger published 9999.0.0"), "{}", render_summary(&r));
    }

    #[test]
    fn a_name_under_a_held_scope_can_only_be_published_by_the_holder_and_the_scope_lists_its_packages() {
        let mut ui = named("@org/ui", Status::Free);
        ui.under_scope = Some(("org".into(), ScopeFact::Held(vec!["tom-t".into()])));
        let p = claims::plain(&ui);
        assert!(p.contains("only the scope's holder (tom-t) could publish it"), "{p}");
        assert!(!p.contains("anyone could"), "{p}");
        let mut open = named("@free/x", Status::Free);
        open.under_scope = Some(("free".into(), ScopeFact::Unheld));
        assert!(claims::plain(&open).contains("anyone could claim the scope"));
        let mut scope = named("@org", Status::ScopeUnclaimed);
        scope.is_scope = true;
        scope.flags = vec![Flag::ScopeHeld { by: vec!["tom-t".into()] }];
        scope.scope_pkgs = vec!["@org/legacy".into()];
        let r = report(vec![scope, ui], vec![]);
        let t = render_table(&r);
        assert!(t.contains("public packages under it: @org/legacy"), "{t}");
        assert!(t.contains("only the scope's holder (tom-t) could publish it"), "{t}");
        assert!(!t.contains("claim the scope on npmjs.org with an org"), "a held scope cannot be claimed: {t}");
        assert!(t.contains("someone else holds the scope"), "{t}");
    }

    #[test]
    fn ours_resting_only_on_the_publishers_word_is_never_a_bare_clear() {
        let mut v = named("v", Status::Ours);
        v.strength = Some(Strength::Verified);
        v.proof = Some("the registry lists the org's team".into());
        let mut d = named("d", Status::Ours);
        d.strength = Some(Strength::Declared);
        d.proof = Some("repository URL".into());
        let only_verified = report(vec![v.clone()], vec![]);
        assert!(headline(&only_verified).starts_with("CLEAR: no name is exposed; 1 shown to be yours (1 verified by the registry)"), "{}", headline(&only_verified));
        let declared = report(vec![v.clone(), d.clone()], vec![]);
        let h = headline(&declared);
        assert!(h.starts_with("CLEAR, but 1 name is ours only by the publisher's word"), "{h}");
        assert_ne!(h, "CLEAR");
        for out in [render_table(&declared), render_summary(&declared), render_md(&declared), render_slack(&declared)] {
            assert!(out.contains("ours only by the publisher's word"), "{out}");
        }
        // with gaps it says both
        let both = report(vec![d, named("n", Status::NotChecked)], vec![gap(1)]);
        let h = headline(&both);
        assert!(h.starts_with("CLEAR WITH GAPS") && h.contains("1 name not checked") && h.contains("ours only by the publisher's word"), "{h}");
        let j: Value = serde_json::from_str(&render_json(&declared)).unwrap();
        assert_eq!(j["counts"]["ours_declared"], 1);
        assert_eq!(j["counts"]["ours_verified"], 1);
        assert_eq!(j["names"][0]["ours_strength"], "verified_by_registry");
    }

    #[test]
    fn as_of_judges_by_the_versions_published_by_that_date_and_says_when_the_registry_gives_no_time() {
        use crate::collect::public::{PubVersion, Public};
        let v = |n: &str, t: Option<&str>| PubVersion { v: n.into(), time: t.map(str::to_string), install_script: None };
        let p = Public { versions: vec![v("1.0.0", Some("2026-01-01T00:00:00Z")), v("9999.0.0", Some("2026-06-09T12:00:00Z"))], ..Default::default() };
        let cut = parse_as_of("2026-06-05", "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(cut, "2026-06-05T23:59:59Z");
        let (l, notes) = apply_as_of(Lookup::Found(p.clone()), &cut, "2026-06-05");
        match l {
            Lookup::Found(q) => assert_eq!(q.versions.len(), 1),
            o => panic!("{o:?}"),
        }
        assert!(notes[0].contains("judged as of 2026-06-05") && notes[0].contains("1 version published later was left out"), "{notes:?}");
        // every version later: free on that date
        let late = Public { versions: vec![v("1.0.0", Some("2026-06-09T12:00:00Z"))], ..Default::default() };
        let (l, notes) = apply_as_of(Lookup::Found(late), &cut, "2026-06-05");
        assert_eq!(l, Lookup::Free);
        assert!(notes[0].contains("after 2026-06-05"));
        // no publish time (a Go proxy list): said per name, and the version counts as published
        let go = Public { versions: vec![v("v1.0.0", None), v("v2.0.0", Some("2026-01-01T00:00:00Z"))], ..Default::default() };
        let (l, notes) = apply_as_of(Lookup::Found(go), &cut, "2026-06-05");
        assert!(matches!(l, Lookup::Found(_)));
        assert!(notes.iter().any(|n| n.contains("gives no publish time for 1 version") && n.contains("--as-of 2026-06-05")), "{notes:?}");
        // a date after the clock is refused; a bad date too
        assert!(parse_as_of("2026-07-01", "2026-06-10T08:00:00Z").is_err());
        assert!(parse_as_of("06-01", "2026-06-10T08:00:00Z").is_err());
    }

    #[test]
    fn the_sample_registry_is_named_on_every_line_that_states_a_registry_fact() {
        let mut sq = row(Status::Squatted, vec![]);
        sq.public_max = Some("9999.0.0".into());
        let mut r = report(vec![sq, named("f", Status::Free)], vec![]);
        r.sample = true;
        for line in render_table(&r).lines().filter(|l| l.trim_start().starts_with("public")) {
            assert!(line.contains("sample registry"), "{line}");
        }
        assert!(render_table(&r).lines().next().unwrap().contains("sample registry"));
        assert!(render_summary(&r).contains("sample registry"));
        assert!(render_slack(&r).contains("sample registry"));
        let j: Value = serde_json::from_str(&render_json(&r)).unwrap();
        assert_eq!(j["sample_registry"], true);
        assert_eq!(j["names"][0]["public"]["source"], "sample registry");
    }

    #[test]
    fn an_npm_dependency_in_a_checkout_with_a_private_registry_and_no_lockfile_is_asked_about() {
        let tree = |files: Vec<(&'static str, &'static str)>| {
            let mut c = Collected::default();
            claims::collect_tree(&mut c, &MemTree { label: "co".into(), files: files.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect() });
            c.finish();
            c
        };
        let pkg = r#"{"name":"app","private":true,"version":"1.0.0","dependencies":{"@corp/sdk":"^1","internal-thing":"^2","react":"18"}}"#;
        let c = tree(vec![("package.json", pkg), (".npmrc", "@corp:registry=https://npm.corp.example/\nregistry=https://npm.corp.example/\n")]);
        // the scoped name resolves privately; the others might, so all are asked about
        assert!(c.claims[&(Eco::Npm, "@corp/sdk".into())].kinds.contains(&Kind::Private));
        for n in ["internal-thing", "react"] {
            assert!(c.claims[&(Eco::Npm, n.into())].kinds.contains(&Kind::Declared), "{n}");
        }
        // a lockfile beside the manifest says where each resolves, so nothing is guessed
        let lock = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/react":{"version":"18.0.0","resolved":"https://registry.npmjs.org/react/-/react-18.0.0.tgz"}}}"#;
        let c = tree(vec![("package.json", pkg), ("package-lock.json", lock), (".npmrc", "registry=https://npm.corp.example/\n")]);
        assert!(!c.claims.contains_key(&(Eco::Npm, "internal-thing".into())));
        // no private registry set: nothing to be confused about
        let c = tree(vec![("package.json", pkg)]);
        assert!(!c.claims.contains_key(&(Eco::Npm, "internal-thing".into())));
        // a lockfile in another directory does not cover this manifest
        let c = tree(vec![("package.json", pkg), ("other/package-lock.json", lock), (".npmrc", "registry=https://npm.corp.example/\n")]);
        assert!(c.claims[&(Eco::Npm, "internal-thing".into())].kinds.contains(&Kind::Declared));
    }

    fn tree_of(files: Vec<(&'static str, &'static str)>) -> Collected {
        let mut c = Collected::default();
        claims::collect_tree(&mut c, &MemTree { label: "co".into(), files: files.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect() });
        c.finish();
        c
    }

    #[test]
    fn r10_private_coverage_pip_uv_poetry_without_a_lock_or_hashes_is_asked_about() {
        let conf = ("pip.conf", "[global]\nindex-url = https://pypi.corp.example/simple\n");
        // requirements without hashes beside a private index
        let c = tree_of(vec![conf, ("requirements.txt", "requests==2.31.0\ncorp-utils==1.0\n")]);
        for n in ["requests", "corp-utils"] {
            assert!(c.claims[&(Eco::Pypi, n.into())].kinds.contains(&Kind::Declared), "{n}");
        }
        // the same file with hashes: the hash binds each name to one artifact
        let c = tree_of(vec![conf, ("requirements.txt", "requests==2.31.0 \\\n    --hash=sha256:abc\n")]);
        assert!(!c.claims.contains_key(&(Eco::Pypi, "requests".into())));
        // pyproject with a uv index, no uv.lock
        let py = "[project]\nname=\"app\"\nversion=\"1\"\ndependencies=[\"flask>=2\"]\n[[tool.uv.index]]\nname=\"corp\"\nurl=\"https://pypi.corp.example/simple\"\n";
        let c = tree_of(vec![("pyproject.toml", py)]);
        assert!(c.claims[&(Eco::Pypi, "flask".into())].kinds.contains(&Kind::Declared));
        // a uv.lock beside it records the index of each package
        let c = tree_of(vec![("pyproject.toml", py), ("uv.lock", "version = 1\n")]);
        assert!(!c.claims.contains_key(&(Eco::Pypi, "flask".into())));
        // poetry: a dependency that names its source is pinned, the rest are asked about; python is not a package
        let po = "[tool.poetry]\nname=\"app\"\nversion=\"1\"\n[tool.poetry.dependencies]\npython=\"^3.11\"\nflask=\"^2\"\ncorp-lib={version=\"1\", source=\"corp\"}\n[[tool.poetry.source]]\nname=\"corp\"\nurl=\"https://pypi.corp.example/simple\"\npriority=\"supplemental\"\n";
        let c = tree_of(vec![("pyproject.toml", po)]);
        assert!(c.claims[&(Eco::Pypi, "corp-lib".into())].kinds.contains(&Kind::Private));
        assert!(c.claims[&(Eco::Pypi, "flask".into())].kinds.contains(&Kind::Declared));
        assert!(!c.claims.contains_key(&(Eco::Pypi, "python".into())));
        // no private index: nothing to be confused about
        let c = tree_of(vec![("requirements.txt", "requests==2.31.0\n")]);
        assert!(!c.claims.contains_key(&(Eco::Pypi, "requests".into())));
        // an explicit-only index serves only the names that pick it
        let ex = po.replace("supplemental", "explicit");
        let c = tree_of(vec![("pyproject.toml", Box::leak(ex.into_boxed_str()))]);
        assert!(!c.claims.contains_key(&(Eco::Pypi, "flask".into())));
    }

    #[test]
    fn r10_private_coverage_cargo_source_replacement_without_cargo_lock_is_asked_about() {
        let cfg = "[source.crates-io]\nreplace-with = \"corp\"\n[source.corp]\nregistry = \"sparse+https://cargo.corp.example/index/\"\n";
        let man = "[package]\nname=\"app\"\nversion=\"0.1.0\"\n[dependencies]\nserde=\"1\"\nlocal={path=\"../local\"}\n";
        let c = tree_of(vec![(".cargo/config.toml", cfg), ("Cargo.toml", man)]);
        assert!(c.claims[&(Eco::Cargo, "serde".into())].kinds.contains(&Kind::Declared));
        assert!(!c.claims.get(&(Eco::Cargo, "local".into())).is_some_and(|cl| cl.kinds.contains(&Kind::Declared)), "a path dependency is not looked up");
        let c = tree_of(vec![(".cargo/config.toml", cfg), ("Cargo.toml", man), ("Cargo.lock", "version = 3\n")]);
        assert!(!c.claims.contains_key(&(Eco::Cargo, "serde".into())));
        // a [registries] entry alone does not change where a dependency without `registry =` resolves
        let only = "[registries.corp]\nindex = \"sparse+https://cargo.corp.example/index/\"\n";
        let c = tree_of(vec![(".cargo/config.toml", only), ("Cargo.toml", man)]);
        assert!(!c.claims.contains_key(&(Eco::Cargo, "serde".into())));
    }

    #[test]
    fn r10_private_coverage_goprivate_names_are_asked_about_without_a_go_sum() {
        let gomod = "module corp.example/app\n\ngo 1.22\n\nrequire (\n\tcorp.example/lib v1.2.0\n\tgithub.com/acme/internal v0.3.0\n\tgolang.org/x/text v0.14.0\n)\n";
        let env = ("Dockerfile", "FROM golang:1.22\nENV GOPRIVATE=github.com/acme/*,gitlab.example/**\nRUN go build\n");
        let c = tree_of(vec![("go.mod", gomod), env]);
        assert!(c.claims[&(Eco::Go, "github.com/acme/internal".into())].kinds.contains(&Kind::Declared));
        assert!(!c.claims.contains_key(&(Eco::Go, "golang.org/x/text".into())), "a module GOPRIVATE does not name is public");
        // a go.sum beside go.mod records the hash of each version
        let c = tree_of(vec![("go.mod", gomod), ("go.sum", ""), env]);
        assert!(!c.claims.contains_key(&(Eco::Go, "github.com/acme/internal".into())));
        // GOPRIVATE in a workflow's env
        let wf = (".github/workflows/ci.yml", "env:\n  GOPRIVATE: corp.example/*\n");
        let c = tree_of(vec![("go.mod", gomod), wf]);
        assert!(c.claims.contains_key(&(Eco::Go, "corp.example/lib".into())));
        // no GOPRIVATE anywhere: nothing is known to be private
        let c = tree_of(vec![("go.mod", gomod)]);
        assert!(!c.claims.contains_key(&(Eco::Go, "github.com/acme/internal".into())));
    }

    #[test]
    fn r10_claimcheck_path_names_a_lockfile_that_gave_no_names() {
        let c = tree_of(vec![
            ("package-lock.json", r#"{"lockfileVersion":3,"packages":{"":{"name":"x"}}}"#),
            ("yarn.lock", "not a lockfile\n"),
            ("bun.lockb", "bin"),
            ("good/package-lock.json", r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}"#),
        ]);
        let g = |f: &str| c.gaps.iter().find(|g| g.0 == format!("co: {f}")).map(|g| g.1.clone());
        assert!(g("package-lock.json").unwrap().starts_with("no packages read: the lockfile lists no packages"), "{:?}", c.gaps);
        assert!(g("bun.lockb").unwrap().contains("not supported"), "{:?}", c.gaps);
        assert!(g("good/package-lock.json").is_none(), "{:?}", c.gaps);
    }

    #[test]
    fn a_checkout_is_read_from_disk() {
        let d = std::env::temp_dir().join(format!("br-claim-{}", std::process::id()));
        std::fs::create_dir_all(d.join("pkg")).unwrap();
        std::fs::create_dir_all(d.join("node_modules/x")).unwrap();
        std::fs::write(d.join("pkg/package.json"), r#"{"name":"@corp/a","version":"1.0.0"}"#).unwrap();
        std::fs::write(d.join("node_modules/x/package.json"), r#"{"name":"ignored"}"#).unwrap();
        let t = LocalTree { label: "co".into(), root: d.clone() };
        assert_eq!(t.paths(), vec!["pkg/package.json"]);
        assert!(t.read("nope").unwrap().is_none());
        let mut c = Collected::default();
        claims::collect_tree(&mut c, &t);
        assert!(c.claims.contains_key(&(Eco::Npm, "@corp/a".to_string())));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_zip_artifact_keeps_only_what_claimcheck_reads() {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let o = zip::write::SimpleFileOptions::default();
            z.start_file("dist/app.js.map", o).unwrap();
            z.write_all(br#"{"sources":["webpack:///node_modules/internal-sdk/x.js"]}"#).unwrap();
            z.start_file("dist/app.js", o).unwrap();
            z.write_all(b"code").unwrap();
            z.finish().unwrap();
        }
        let t = ZipTree::open("r (artifact build)".into(), buf.into_inner()).unwrap();
        assert_eq!(t.paths(), vec!["dist/app.js.map"]);
        let mut c = Collected::default();
        claims::collect_tree(&mut c, &t);
        assert!(c.claims.contains_key(&(Eco::Npm, "internal-sdk".to_string())));
        assert!(ZipTree::open("x".into(), b"not a zip".to_vec()).is_err());
    }

    fn squatted(name: &str, eco: Eco, v: &str, publishers: &[&str]) -> Row {
        let mut r = named(name, Status::Squatted);
        r.eco = eco;
        r.public_max = Some(v.into());
        r.publishers = publishers.iter().map(|s| s.to_string()).collect();
        r
    }

    #[test]
    fn r10_remediation_is_chosen_by_status_and_a_squatted_name_never_gets_a_placeholder() {
        let sq = squatted("taken", Eco::Npm, "9999.0.0", &["mallory"]);
        let py = squatted("taken-py", Eco::Pypi, "99.0", &[]);
        let free = named("open", Status::Free);
        let mut under = named("@held/x", Status::Free);
        under.under_scope = Some(("held".into(), ScopeFact::Held(vec!["tom-t".into()])));
        let mut scope = named("@held", Status::ScopeUnclaimed);
        scope.is_scope = true;
        scope.flags = vec![Flag::ScopeHeld { by: vec!["tom-t".into()] }];
        let g = guidance_for(&[&sq, &py, &free, &under, &scope]);
        let line = |p: &str| g.iter().find(|l| l.starts_with(p)).cloned().unwrap_or_else(|| panic!("{p} in {g:?}"));
        for l in [line("taken:"), line("taken-py:")] {
            assert!(!l.contains("placeholder"), "{l}");
            assert!(l.contains("you cannot claim it") && l.contains("rename") && l.contains("Report the package"), "{l}");
        }
        assert!(line("taken:").contains("br hunt npm:taken@9999.0.0"));
        assert!(line("taken-py:").contains("br hunt pypi:taken-py@99.0") && line("taken-py:").contains("pypi.org"));
        assert!(line("open:").contains("placeholder"));
        // free but under a scope someone else holds: only the holder can publish it, so nothing here says to claim it
        let u = line("@held/x:");
        assert!(u.contains("you cannot claim them") && !u.contains("placeholder"), "{u}");
        let sc = line("@held:");
        assert!(sc.contains("rename the scope") && sc.contains("Pin the scope"), "{sc}");
        // the three hand-offs use the same function
        assert_eq!(guidance_for(&[&sq]), guidance(&report(vec![sq.clone()], vec![])));
    }

    #[test]
    fn r10_no_claim_about_who_published_without_the_publisher_shown() {
        let shown = squatted("a", Eco::Pypi, "99.0", &["mallory"]);
        let hidden = squatted("b", Eco::Pypi, "99.0", &[]);
        assert_eq!(claims::plain(&shown), "a stranger already owns this name on the public registry (version 99.0)");
        let p = claims::plain(&hidden);
        assert!(p.contains("an owner the registry does not show") && !p.contains("stranger") && !p.contains("someone else"), "{p}");
        let mut with_script = hidden.clone();
        with_script.install_script = Some(true);
        assert_eq!(claims::plain(&with_script), "99.0 was published by an owner the registry does not show, and it runs code when installed");
        let mut scope = named("@x", Status::ScopeUnclaimed);
        scope.is_scope = true;
        scope.flags = vec![Flag::ScopeHeld { by: vec![] }];
        let t = claims::plain(&scope);
        assert!(!t.contains("someone else") && t.contains("does not show who holds it"), "{t}");
        assert!(!scope.flags[0].text().contains("someone else"));
        assert!(headline(&report(vec![scope], vec![])).contains("1 scope with public packages not shown to be yours"));
    }

    #[test]
    fn r10_squatted_since_shows_the_first_publish_next_to_the_newest() {
        use crate::collect::public::{PubVersion, Public};
        let v = |n: &str, t: Option<&str>| PubVersion { v: n.into(), time: t.map(str::to_string), install_script: None };
        let p = Public { versions: vec![v("9999.0.0", Some("2026-05-28T10:00:00.000Z")), v("1.0.0", Some("2025-01-01T00:00:00.000Z"))], ..Default::default() };
        assert_eq!(p.first_published().as_deref(), Some("2025-01-01T00:00:00.000Z"));
        // a version without a time may be the oldest: the first claim is then not known
        let q = Public { versions: vec![v("1.0.0", None), v("2.0.0", Some("2026-01-01T00:00:00Z"))], ..Default::default() };
        assert_eq!(q.first_published(), None);
        let mut r = squatted("taken", Eco::Npm, "9999.0.0", &["mallory"]);
        r.published = Some("2026-05-28T10:00:00.000Z".into());
        r.first_published = p.first_published();
        let t = render_table(&report(vec![r.clone()], vec![]));
        assert!(t.contains("published 2026-05-28 (newest version), name first claimed 2025-01-01"), "{t}");
        assert!(render_slack(&report(vec![r.clone()], vec![])).contains("name first claimed 2025-01-01"));
        assert!(render_md(&report(vec![r], vec![])).contains("name first claimed 2025-01-01"));
    }

    #[test]
    fn r10_as_of_names_its_date_first_and_says_what_is_not_rewound() {
        let mut r = report(vec![named("x", Status::Free)], vec![]);
        r.as_of = Some("2026-05-01".into());
        r.late_artifacts = vec!["org/web (artifact b-1)".into()];
        r.rewound = vec!["gone".into()];
        assert!(headline(&r).starts_with("As of 2026-05-01: EXPOSED"), "{}", headline(&r));
        assert!(render_summary(&r).starts_with("Dependency-confusion check as of 2026-05-01 (run on 2026-05-12): EXPOSED"), "{}", render_summary(&r));
        let l = limits(&r).join("\n");
        assert!(l.contains("1 CI artifact created after that date") && l.contains("leaves out 1 name seen only there (gone)"), "{l}");
        assert!(l.contains("repos are read as they are today"), "{l}");
    }

    #[test]
    fn r10_every_format_carries_the_date_and_the_index_age_and_names_the_unchecked() {
        let mut r = report(vec![named("a", Status::Free), named("cut", Status::NotChecked)], vec![gap(1)]);
        r.index = Some(("2026-05-12T05:00:00Z".into(), "2026-05-12T06:00:00Z".into()));
        r.rows[1].owners = vec!["@org/sec".into()];
        for out in [render_table(&r), render_md(&r), render_slack(&r), render_summary(&r)] {
            assert!(out.contains("2026-05-12"), "{out}");
            assert!(out.contains("index: repos last scanned between 2026-05-12 05:00Z and 2026-05-12 06:00Z (the oldest 2h10m before this run)"), "{out}");
        }
        for out in [render_slack(&r), render_summary(&r)] {
            assert!(out.contains("Not checked: cut (org/web, owner @org/sec)"), "{out}");
        }
        // many: a count and a pointer, not a wall of names
        let mut many = report(vec![], vec![gap(9)]);
        pad(&mut many, 9, Status::NotChecked, "n");
        assert!(render_slack(&many).contains("9 names not checked: too many to list here"), "{}", render_slack(&many));
        let j: Value = serde_json::from_str(&render_json(&r)).unwrap();
        assert_eq!(j["index"]["oldest_scan"], "2026-05-12T05:00:00Z");
        assert!(crate::out::sarif::render_claims(&r).contains("\"indexAge\""));
    }

    #[test]
    fn r10_the_customer_limits_are_plain_words_in_one_voice() {
        let mut r = report(vec![named("a", Status::Free)], vec![]);
        r.as_of = Some("2026-05-01".into());
        r.treated_public = 2;
        r.go_public_skipped = 1;
        r.unreferenced_private = 1;
        r.public_expected = 1;
        r.late_artifacts = vec!["x (artifact y)".into()];
        for l in limits_plain(&r) {
            for bad in ["br ", "--", "_URL", "_INDEX", "GOPRIVATE", "GOPROXY", ".npmrc", "PIP", "CARGO_", " you", "your "] {
                assert!(!l.contains(bad), "{bad:?} in {l}");
            }
        }
    }

    #[test]
    fn r10_totals_count_names_found_the_same_with_or_without_the_cut() {
        let mut full = report(vec![named("a", Status::Free), named("b", Status::Ours)], vec![]);
        full.public_expected = 2;
        // the cut run lists the two weak names as not checked instead of leaving them out
        let cut = report(vec![named("a", Status::Free), named("b", Status::Ours), named("c", Status::NotChecked), named("d", Status::NotChecked)], vec![gap(2)]);
        assert_eq!(full.names_found(), cut.names_found());
        assert!(render_table(&cut).contains("4 names found in all"));
    }

    #[test]
    fn r10_sources_are_named_by_kind() {
        let mut r = report(vec![], vec![]);
        r.trees = 10;
        r.artifact_trees = 1;
        assert_eq!(sources_words(&r), "9 repos and 1 CI artifact");
        r.artifact_trees = 0;
        r.trees = 1;
        r.checkout_roots = 1;
        assert_eq!(sources_words(&r), "1 checkout");
    }
}
