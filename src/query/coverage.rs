//! The single home of the coverage definitions. `coverage_state` answers "could this source have seen it" for
//! hunt, evidence, status and the gap count; `members_covered` answers "which people have a laptop scan here" for hosts,
//! status, hunt, notify, purge and evidence.

use std::sync::Mutex;

use super::hunt::{host_owner, owner_match, owner_spec, Owner, Query};
use super::index::Index;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageState {
    /// the source could have seen everything in the window
    Full,
    /// scanned inside the window but before the end of a past window, or stale while the window ends now
    Partial,
    /// the scan read nothing, or came before the window began
    None,
}

impl CoverageState {
    pub fn word(self) -> &'static str {
        match self {
            CoverageState::Full => "full",
            CoverageState::Partial => "partial",
            CoverageState::None => "none",
        }
    }
}

/// The latest time any indexed source was scanned: the clock the index itself can speak for.
pub fn index_time(ix: &Index) -> Option<String> {
    ix.srcs.keys().filter_map(|n| ix.i(n)).max()
}

/// A window that ends after the index time is examined only up to the index time (how the window is worded, not how
/// coverage is decided).
pub fn examined_end(window_end: &str, index_time: Option<&str>) -> String {
    match index_time {
        Some(t) if !t.is_empty() && t < window_end => t.to_string(),
        _ => window_end.to_string(),
    }
}

/// The one definition. A source is `Full` when its last scan is at or after the end of the window, or when the window
/// ends at or after the index time and the source is fresh (younger than the stale threshold that `br status` uses). It is
/// `Partial` when it was scanned inside the window but before the end of a past window, or when the window ends now and
/// the source is stale. It is `None` when the scan read nothing, or came before the window began (a source that holds a
/// finding did see something, so it is partial). No window is a window that ends now.
pub fn state_at(ix_now: &str, indexed_at: &str, window: Option<(&str, &str)>, index_time: Option<&str>, empty: bool, has_findings: bool) -> CoverageState {
    if empty {
        return CoverageState::None;
    }
    let fresh = !super::util::is_stale(ix_now, indexed_at);
    let Some((start, end)) = window else {
        return if fresh { CoverageState::Full } else { CoverageState::Partial };
    };
    let ends_now = index_time.map_or(end >= ix_now, |t| end >= t);
    if indexed_at >= end || (ends_now && fresh) {
        CoverageState::Full
    } else if indexed_at < start && !has_findings {
        CoverageState::None
    } else {
        CoverageState::Partial
    }
}

/// The state of one source for the query's window.
pub fn coverage_state(ix: &Index, q: &Query, name: &str, has_findings: bool, index_time: Option<&str>) -> CoverageState {
    let empty = ix.srcs.get(name).is_some_and(|s| s.empty);
    let w = q.window.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
    state_at(&ix.now, &ix.it(name), w, index_time, empty, has_findings)
}

/// `coverage_state` for a source row that names what it covered (the evidence appendix). One definition of "narrow":
/// a laptop scan that read only some folders (not the home, not the package caches) is partial here exactly as `br hosts`
/// and the members' coverage say, however fresh it is. A hunt's own gap list keeps `coverage_state` (it words a gap as
/// stale, which a narrow scan is not); it names that laptop in its laptops row.
pub fn source_state(ix: &Index, q: &Query, name: &str, has_findings: bool, index_time: Option<&str>) -> CoverageState {
    let state = coverage_state(ix, q, name, has_findings, index_time);
    if state == CoverageState::Full && is_narrow_laptop(ix, name) {
        return CoverageState::Partial;
    }
    state
}

/// A host that is not a runner or server and whose scan roots are narrower than the home and the package caches.
pub fn is_narrow_laptop(ix: &Index, name: &str) -> bool {
    let Some(hd) = ix.host_def(name) else { return false };
    if matches!(crate::store::view_kind(hd.kind.as_deref().unwrap_or("")), "runner" | "server") {
        return false;
    }
    narrow_roots(ix, name).is_some()
}

/// The window ends at or after the index time (the "window ends now" case).
pub fn window_ends_now(ix: &Index, q: &Query) -> bool {
    let Some((_, end)) = &q.window else { return false };
    match index_time(ix) {
        Some(t) => *end >= t,
        None => *end >= ix.now,
    }
}

/// The sentence every view uses to say what partial and full mean. a source that is full because it is fresh is
/// "fresh as of T", never "scanned at or after the end".
pub fn definition(examined: &str) -> String {
    format!(
        "A source is full when it was scanned at or after the end of the window ({}), or when the window ends now and the source is fresh (\"fresh as of\" its last scan); it is partial when it was scanned inside the window but before its end, or is stale while the window ends now.",
        crate::out::evidence::fmtz(examined)
    )
}

/// Why a source is full, in words. Scanned after the end of the examined window, or fresh as of its last scan (which
/// may be before that end, when the window ends now).
pub fn full_words(indexed_at: &str, examined_end: &str) -> String {
    if indexed_at >= examined_end {
        format!("scanned {}, after the end of the window", crate::out::evidence::fmtz(indexed_at))
    } else {
        format!("fresh as of {}", crate::out::evidence::fmtz(indexed_at))
    }
}

/// The range of scan times behind an answer: the oldest and the newest source, and which source is the oldest. It is
/// worded one way wherever "data as of" appears (summary, slack, md, evidence).
#[derive(Debug, Clone, PartialEq)]
pub struct DataAsOf {
    pub oldest: String,
    pub newest: String,
    pub oldest_source: String,
}

pub fn data_as_of(ix: &Index, names: &[String]) -> Option<DataAsOf> {
    let times: Vec<(String, &String)> = names.iter().filter_map(|n| ix.i(n).filter(|t| !t.is_empty()).map(|t| (t, n))).collect();
    let (oldest, src) = times.iter().min_by(|a, b| a.0.cmp(&b.0))?;
    let newest = times.iter().map(|x| x.0.clone()).max()?;
    Some(DataAsOf { oldest: oldest.clone(), newest, oldest_source: (*src).clone() })
}

impl DataAsOf {
    /// `05-12 04:00–09:00Z` on one day, `05-11 22:00Z–05-12 09:00Z` across days, `05-12 06:30Z` for one time.
    pub fn range(&self) -> String {
        use crate::query::util::{fmtz, norm_iso};
        if self.oldest == self.newest {
            return fmtz(&self.newest);
        }
        match (norm_iso(&self.oldest), norm_iso(&self.newest)) {
            (Ok(a), Ok(b)) if a[..10] == b[..10] => format!("{} {}–{}Z", &a[5..10], &a[11..16], &b[11..16]),
            _ => format!("{}–{}", fmtz(&self.oldest), fmtz(&self.newest)),
        }
    }

    /// The range, and for a range the oldest source: `05-12 04:00–09:00Z (oldest: registry)`.
    pub fn words(&self) -> String {
        if self.oldest == self.newest {
            self.range()
        } else {
            format!("{} (oldest: {})", self.range(), self.oldest_source)
        }
    }
}

// ---- Laptop coverage ------------------------------------------------------------------------------------------

/// The person running br. A scan of "this machine" (`Host.this_machine`, decided once at scan or import time, never from a
/// name) with no `--owner` belongs to them.
static OPERATOR: Mutex<Option<String>> = Mutex::new(None);

/// Installed by `Ctx::view()`, so every command that reads the index sees the same operator.
pub fn set_operator(user: Option<&str>) {
    if let Ok(mut g) = OPERATOR.lock() {
        *g = user.filter(|u| !u.is_empty()).map(str::to_string);
    }
}

fn operator() -> Option<String> {
    OPERATOR.lock().ok().and_then(|g| g.clone())
}

/// Who has a laptop scan here, and who does not.
#[derive(Debug, Clone, Default)]
pub struct MemberCoverage {
    /// members in scope (bots are not members)
    pub members: usize,
    /// of them, members with a fresh scan of a machine of theirs that read their home or the package caches
    pub covered: usize,
    /// the display names of the members with none
    pub uncovered_names: Vec<String>,
    /// the logins of the same members
    pub uncovered_ids: Vec<String>,
    /// where the member list comes from, as the tail of "12 members visible to this token in GitHub"
    pub source_label: String,
    /// The reason for every member in scope, covered or not (see `member_reason`)
    pub reasons: Vec<MemberReason>,
}

impl MemberCoverage {
    /// "12 members visible to this token in GitHub"
    pub fn members_phrase(&self) -> String {
        format!("{} {}", crate::query::util::plural(self.members, "member"), self.source_label)
    }

    /// The reason recorded for one member (by login, case-insensitive).
    pub fn reason_of(&self, login: &str) -> Option<&MemberReason> {
        self.reasons.iter().find(|r| r.login.eq_ignore_ascii_case(login))
    }
}

/// Why a laptop scan does not cover a person. One classification, read by the evidence file and by the customer
/// statement, so a stale scan is called stale and a narrow one is called partial in both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GapWhy {
    /// no machine of theirs is scanned (or the only one is a runner or server)
    #[default]
    NoScan,
    /// a scan exists but reads less than the home folder and the package caches
    Narrow,
    /// the scan is older than the staleness threshold, or came before the exposure
    Stale,
    /// the scan read nothing
    Empty,
    /// the machine is registered and never scanned
    Unscanned,
}

impl GapWhy {
    /// The words a customer reads, after "was"/"were": the same facts `MemberReason.reason` gives the auditor file.
    pub fn customer_words(self) -> &'static str {
        match self {
            GapWhy::Stale => "last checked before the end of the period examined (the scan is stale), so anything installed since is not known",
            GapWhy::Narrow => "checked only in part, because the scan read less than the laptop's home folder and package caches",
            GapWhy::Empty => "scanned, but the scan read nothing",
            GapWhy::NoScan | GapWhy::Unscanned => "not checked",
        }
    }
}

/// Why one member is, or is not, covered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemberReason {
    /// The kind of gap when the member is not covered
    pub why: GapWhy,
    pub login: String,
    pub name: String,
    pub covered: bool,
    /// a scan exists but reads less than the home and the package caches (or is stale or empty): the owner stays possible
    pub partial: bool,
    /// plain words: `fresh as of 05-12 09:00Z (host dana-mbp)`, `partial (scanned: /home/dana/code)`, `no machine of theirs is scanned`
    pub reason: String,
    /// the host that decided it, when there is one
    pub host: Option<String>,
}

/// What a set of scan roots reads of a user's machine.
#[derive(Debug, Clone, PartialEq)]
pub enum RootsRead {
    /// the home directory or an ancestor of it, or a package cache
    Covers,
    /// every root is a place inside the home (or elsewhere) that is not a package cache: a narrow scan
    Narrow(Vec<String>),
    /// the scan did not record its roots, or they cannot be placed: br does not judge them narrow
    Unknown,
}

/// Where package managers keep what they installed: one row per ecosystem or manager. A scan root inside one of these reads
/// a package cache or an install tree, which is what exposure is judged on.
const CACHE_MARKERS: &[&str] = &[
    // npm, pnpm, yarn, bun
    "/.npm",
    "/_cacache",
    "/.pnpm-store",
    "/pnpm/store",
    "/.local/share/pnpm",
    "/.yarn",
    "/.cache/yarn",
    "/.bun",
    "/node_modules",
    // pip, uv, poetry, conda
    "/.cache/pip",
    "/.cache/uv",
    "/.cache/pypoetry",
    "/site-packages",
    "/dist-packages",
    "/.conda",
    "/miniconda",
    "/anaconda",
    // cargo, go, jvm, nuget, ruby, php
    "/.cargo",
    "/go/pkg/mod",
    "/pkg/mod",
    "/.m2",
    "/.gradle",
    "/.nuget",
    "/.gem",
    "/.composer",
    // os cache homes
    "/Library/Caches",
    "/AppData/Local",
    "/AppData/Roaming",
];

fn norm_root(r: &str) -> String {
    let mut x = r.trim().replace('\\', "/");
    while x.len() > 1 && x.ends_with('/') {
        x.pop();
    }
    x
}

/// A directory that is every user's parent (`/`, `/home`, `/Users`, `C:/Users`): a scan of it reads the home.
fn is_homes_parent(r: &str) -> bool {
    let low = r.to_lowercase();
    r == "/" || r.is_empty() || low == "/home" || low == "/users" || low == "/root" || (low.len() == 8 && low.ends_with(":/users")) || low == "~" || low == "$home" || low == "%userprofile%"
}

/// `/home/dana`, `/Users/dana`, `C:/Users/dana`: a home directory by its shape.
fn is_home_shape(r: &str) -> bool {
    let c: Vec<&str> = r.trim_start_matches('/').split('/').collect();
    let win = r.len() > 2 && r.as_bytes()[1] == b':';
    if win {
        let c: Vec<&str> = r[3..].split('/').collect();
        return c.len() == 2 && c[0].eq_ignore_ascii_case("users");
    }
    (c.len() == 2 && (c[0] == "home" || c[0] == "Users")) || r == "/root"
}

/// Inside a home by its shape, but deeper than the home itself.
fn deeper_than_home_shape(r: &str) -> bool {
    let c: Vec<&str> = r.trim_start_matches('/').split('/').collect();
    c.len() > 2 && (c[0] == "home" || c[0] == "Users")
}

fn is_relative(r: &str) -> bool {
    let b = r.as_bytes();
    !(r.starts_with('/') || r.starts_with('~') || r.starts_with('$') || r.starts_with('%') || (b.len() >= 2 && b[1] == b':'))
}

fn is_cache_root(r: &str) -> bool {
    let probe = format!("{r}/");
    CACHE_MARKERS.iter().any(|m| probe.contains(&format!("{m}/")))
}

/// Does a scan with these roots read the user's home or the package caches? `home` is the scanning user's home when it
/// is known (recorded by the scan, or the operator's own `$HOME` for this machine). With no roots recorded the answer is
/// `Unknown`, which br does not call narrow.
pub fn roots_read(roots: &[String], home: &[String]) -> RootsRead {
    let roots: Vec<String> = roots.iter().map(|r| norm_root(r)).filter(|r| !r.is_empty()).collect();
    if roots.is_empty() {
        return RootsRead::Unknown;
    }
    let homes: Vec<String> = home.iter().map(|h| norm_root(h)).filter(|h| !h.is_empty()).collect();
    let mut narrow = vec![];
    let mut unplaced = false;
    for r in &roots {
        let covers = is_homes_parent(r) || is_home_shape(r) || is_cache_root(r) || homes.iter().any(|h| r == h || h.starts_with(&format!("{}/", r.trim_end_matches('/'))));
        if covers {
            return RootsRead::Covers;
        }
        // a root written relative to the folder the scan ran in is a folder, not the home
        if is_relative(r) {
            narrow.push(r.clone());
            continue;
        }
        let inside_home = homes.iter().any(|h| r.starts_with(&format!("{h}/"))) || deeper_than_home_shape(r);
        if inside_home || !homes.is_empty() {
            narrow.push(r.clone());
        } else {
            unplaced = true;
        }
    }
    if narrow.is_empty() && unplaced {
        RootsRead::Unknown
    } else {
        RootsRead::Narrow(narrow)
    }
}

/// The roots a host's scans read: from the View, or for an imported host from the import record.
pub fn host_roots(ix: &Index, host: &str) -> Vec<String> {
    if let Some(h) = ix.host_def(host).filter(|h| !h.roots.is_empty()) {
        return h.roots.clone();
    }
    ix.v.state.imports.get(host).and_then(|v| v["roots"].as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// The scan roots of this host, when they are narrower than the home and the package caches.
pub fn narrow_roots(ix: &Index, host: &str) -> Option<Vec<String>> {
    match roots_read(&host_roots(ix, host), &host_homes(ix, host)) {
        RootsRead::Narrow(r) => Some(r),
        _ => None,
    }
}

/// Known home directories for a host: the one its scan recorded, and, on the operator's own machine, `$HOME`.
fn host_homes(ix: &Index, host: &str) -> Vec<String> {
    let mut out: Vec<String> = ix.host_def(host).and_then(|h| h.home.clone()).into_iter().collect();
    let mine = ix.host_def(host).is_some_and(|h| h.this_machine);
    if mine {
        if let Ok(h) = std::env::var("HOME") {
            out.push(h);
        }
    }
    out
}

/// One host's contribution to a member's coverage: `(covered, partial, reason)`.
fn host_verdict(ix: &Index, host: &str, not_before: Option<&str>) -> (bool, bool, String, GapWhy) {
    let src = &ix.srcs[host];
    if crate::collect::words::never_scanned(src) {
        return (false, false, format!("{host} is registered and never scanned"), GapWhy::Unscanned);
    }
    if src.empty {
        return (false, false, format!("{host} was scanned and read nothing"), GapWhy::Empty);
    }
    let roots = host_roots(ix, host);
    let at = crate::query::util::fmtz(&src.indexed_at);
    if let RootsRead::Narrow(r) = roots_read(&roots, &host_homes(ix, host)) {
        return (false, true, format!("partial (scanned: {})", r.join(", ")), GapWhy::Narrow);
    }
    // fresh: young enough to speak for now, or (when the question is about one moment) scanned after that moment
    let old = match not_before {
        Some(t) => src.indexed_at.as_str() < t,
        None => super::util::is_stale(&ix.now, &src.indexed_at),
    };
    if old {
        return (false, true, format!("{host} was last scanned {at}, {}", if not_before.is_some() { "before the exposure" } else { "which is stale" }), GapWhy::Stale);
    }
    (true, false, format!("fresh as of {at} ({host})"), GapWhy::NoScan)
}

/// Why a member is, or is not, covered. A member is covered only by a host that is theirs, is a laptop or of unknown
/// kind (never a runner or server), was scanned and read something, is fresh, and whose scan roots include their home or the
/// package caches. A scan narrower than that is `partial (scanned: ROOTS)`: it keeps the owner possible. `host_ok` narrows
/// the hosts considered (an `--owner` scope).
pub fn member_reason(ix: &Index, login: &str) -> MemberReason {
    member_reason_with(ix, login, &|_| true, None)
}

/// The same, for a question about one moment: a scan counts when it was taken at or after `t` (the commit or build that
/// exposed the person), however long ago that is.
pub fn member_reason_since(ix: &Index, login: &str, t: &str) -> MemberReason {
    member_reason_with(ix, login, &|_| true, Some(t))
}

pub fn member_reason_with(ix: &Index, login: &str, host_ok: &dyn Fn(&str) -> bool, not_before: Option<&str>) -> MemberReason {
    let op = operator();
    let mut best: Option<(u8, bool, bool, String, String, GapWhy)> = None;
    let mut other_kind: Option<String> = None;
    for n in ix.names("host").into_iter().filter(|n| host_ok(n)) {
        let hd = ix.host_def(&n);
        let who = match hd.and_then(|h| h.owner.clone()).filter(|o| !o.is_empty()) {
            Some(o) => Some(ix.person_by_ref(&o).unwrap_or(o)),
            None => match &op {
                Some(u) if hd.is_some_and(|h| h.this_machine) => ix.person_by_ref(u),
                _ => None,
            },
        };
        if !who.is_some_and(|w| w.trim_start_matches('@').eq_ignore_ascii_case(login)) {
            continue;
        }
        if matches!(crate::store::view_kind(hd.and_then(|h| h.kind.as_deref()).unwrap_or("")), "runner" | "server") {
            other_kind = Some(format!("only {n}, a runner or server, is theirs"));
            continue;
        }
        let (covered, partial, reason, why) = host_verdict(ix, &n, not_before);
        // covered beats partial beats a stale or empty scan
        let rank = if covered {
            3
        } else if partial {
            2
        } else {
            1
        };
        if best.as_ref().is_none_or(|b| rank > b.0) {
            best = Some((rank, covered, partial, reason, n, why));
        }
    }
    let name = ix.person_name(login);
    match best {
        Some((_, covered, partial, reason, host, why)) => MemberReason { why, login: login.to_string(), name, covered, partial, reason, host: Some(host) },
        None => MemberReason {
            why: GapWhy::NoScan,
            login: login.to_string(),
            name,
            covered: false,
            partial: false,
            reason: other_kind.unwrap_or_else(|| "no machine of theirs is scanned".to_string()),
            host: None,
        },
    }
}

/// A member is covered when `member_reason` says so. `scope` narrows the members and the hosts by `--owner`.
pub fn members_covered(ix: &Index, scope: &Query) -> MemberCoverage {
    match owner_spec(ix, scope) {
        Ok(Some(rs)) => members_covered_with(ix, &|h| owner_match(ix, &rs, &host_owner(ix, h)), &|pid| owner_match(ix, &rs, &Owner { people: vec![pid.to_string()], ..Default::default() })),
        _ => members_covered_with(ix, &|_| true, &|_| true),
    }
}

pub fn members_covered_with(ix: &Index, host_ok: &dyn Fn(&str) -> bool, person_ok: &dyn Fn(&str) -> bool) -> MemberCoverage {
    let members: Vec<&crate::view::Person> = ix.v.people.iter().filter(|p| !p.login.ends_with("[bot]") && person_ok(&p.login)).collect();
    let reasons: Vec<MemberReason> = members.iter().map(|p| member_reason_with(ix, &p.login, host_ok, None)).collect();
    let uncovered: Vec<&MemberReason> = reasons.iter().filter(|r| !r.covered).collect();
    MemberCoverage {
        members: members.len(),
        covered: members.len() - uncovered.len(),
        uncovered_names: uncovered.iter().map(|r| r.name.clone()).collect(),
        uncovered_ids: uncovered.iter().map(|r| r.login.clone()).collect(),
        source_label: if ix.v.org.github.as_deref().is_some_and(|o| !o.is_empty()) { "visible to this token in GitHub".to_string() } else { "on record in the index".to_string() },
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{Host, Person, Source, View};

    const NOW: &str = "2026-05-12T12:00:00Z";

    #[test]
    fn a_window_ending_after_the_index_is_examined_to_the_index_time() {
        assert_eq!(examined_end("2026-05-12T23:59:00Z", Some("2026-05-12T12:00:00Z")), "2026-05-12T12:00:00Z");
        assert_eq!(examined_end("2026-05-12T10:00:00Z", Some("2026-05-12T12:00:00Z")), "2026-05-12T10:00:00Z");
        assert_eq!(examined_end("2026-05-12T10:00:00Z", None), "2026-05-12T10:00:00Z");
    }

    // Full when scanned at or after the end, or when the window ends now and the source is fresh
    #[test]
    fn full_partial_none_by_the_r55_definition() {
        let (s, e) = ("2026-05-11T14:00:00Z", "2026-05-11T20:00:00Z");
        let st = |at: &str, w: Option<(&str, &str)>, it: Option<&str>, empty, hf| state_at(NOW, at, w, it, empty, hf);
        // a past window: scanned after its end is full, inside it is partial, before it began is none
        assert_eq!(st("2026-05-12T09:00:00Z", Some((s, e)), Some(NOW), false, false), CoverageState::Full);
        assert_eq!(st("2026-05-11T16:00:00Z", Some((s, e)), Some(NOW), false, false), CoverageState::Partial);
        assert_eq!(st("2026-05-10T09:00:00Z", Some((s, e)), Some(NOW), false, false), CoverageState::None);
        assert_eq!(st("2026-05-10T09:00:00Z", Some((s, e)), Some(NOW), false, true), CoverageState::Partial);
        // the window ends now: a fresh source is full even when it is older than the newest scan
        let open = ("2026-05-11T14:00:00Z", "2026-05-13T00:00:00Z");
        assert_eq!(st("2026-05-12T01:00:00Z", Some(open), Some(NOW), false, false), CoverageState::Full, "refreshing another source must not make this one worse");
        assert_eq!(st("2026-05-12T11:59:00Z", Some(open), Some(NOW), false, false), CoverageState::Full);
        // ... a stale one scanned inside the window is partial, and one scanned before the window began is none
        let wide = ("2026-05-10T00:00:00Z", "2026-05-13T00:00:00Z");
        assert_eq!(st("2026-05-11T09:00:00Z", Some(wide), Some(NOW), false, false), CoverageState::Partial);
        assert_eq!(st("2026-05-09T09:00:00Z", Some(wide), Some(NOW), false, false), CoverageState::None);
        // an empty scan is none, whatever the time
        assert_eq!(st(NOW, Some(open), Some(NOW), true, false), CoverageState::None);
        // no window is a window that ends now: status's fresh is evidence's full
        assert_eq!(st("2026-05-12T01:00:00Z", None, Some(NOW), false, false), CoverageState::Full);
        assert_eq!(st("2026-05-10T01:00:00Z", None, Some(NOW), false, false), CoverageState::Partial);
    }

    // The index time moving (another source rescanned) never makes a fresh source worse
    #[test]
    fn rescanning_one_source_does_not_change_another() {
        let open = Some(("2026-05-11T00:00:00Z", "2026-05-13T00:00:00Z"));
        let before = state_at(NOW, "2026-05-12T02:00:00Z", open, Some("2026-05-12T02:00:00Z"), false, false);
        let after = state_at(NOW, "2026-05-12T02:00:00Z", open, Some(NOW), false, false);
        assert_eq!((before, after), (CoverageState::Full, CoverageState::Full));
    }

    fn member_view() -> View {
        let mut v = View { now: NOW.into(), ..Default::default() };
        v.org.github = Some("acme".into());
        for l in ["dana", "lena", "omar", "kim", "ci[bot]"] {
            v.people.push(Person { login: l.into(), ..Default::default() });
        }
        let mut host = |name: &str, kind: Option<&str>, owner: Option<&str>, empty: bool| {
            v.sources.insert(name.into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: NOW.into(), empty, ..Default::default() });
            v.hosts.insert(name.into(), Host { kind: kind.map(str::to_string), owner: owner.map(str::to_string), ..Default::default() });
        };
        host("dana-mbp", Some("laptop"), Some("dana"), false);
        // an imported host has no kind: it counts (laptop or unknown)
        host("lena-box", None, Some("Lena"), false);
        // a runner and a server never cover a person
        host("runner-1", Some("runner"), Some("omar"), false);
        // a scan that read nothing covers no one
        host("kim-mbp", Some("laptop"), Some("kim"), true);
        v
    }

    // A scan of the operator's own machine with no owner covers the operator, in hunt as in status
    #[test]
    fn the_operators_own_unowned_scan_covers_the_operator() {
        let mut v = member_view();
        v.sources.insert("op-laptop-unit".into(), Source { kind: "host".into(), reach: "local".into(), indexed_at: NOW.into(), ..Default::default() });
        v.hosts.insert("op-laptop-unit".into(), Host { this_machine: true, ..Default::default() });
        let ix = Index::new(&v, NOW);
        set_operator(Some("omar"));
        let with = members_covered(&ix, &Query::default());
        set_operator(None);
        let without = members_covered(&ix, &Query::default());
        assert_eq!(with.covered, without.covered + 1, "{with:?} {without:?}");
    }

    // Laptop or unknown kind, never runner or server, never an empty scan; bots are not members
    #[test]
    fn a_member_is_covered_by_a_scanned_laptop_or_unknown_host_they_own() {
        let v = member_view();
        let ix = Index::new(&v, NOW);
        let m = members_covered(&ix, &Query::default());
        assert_eq!((m.members, m.covered), (4, 2), "{m:?}");
        assert_eq!(m.uncovered_ids, vec!["omar".to_string(), "kim".to_string()]);
        assert_eq!(m.members_phrase(), "4 members visible to this token in GitHub");
    }
}
