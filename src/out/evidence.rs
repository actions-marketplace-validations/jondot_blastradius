//! The evidence report: year-bearing dates, the coverage rows and the Markdown file.

use crate::out::json::J;
use crate::query::hunt::NotChecked;
use crate::query::util::{age_label, norm_iso, plural, plural_with, table};

fn long(s: &str) -> String {
    norm_iso(s).unwrap_or_else(|_| s.to_string())
}

/// `2026-05-11 14:00`; "-" when empty. A file outlives the week it was written in, so every date carries its year.
pub fn fmt(s: &str) -> String {
    if s.is_empty() {
        return "-".into();
    }
    let n = long(s);
    match (n.get(..10), n.get(11..16)) {
        (Some(d), Some(t)) => format!("{d} {t}"),
        _ => n,
    }
}

pub fn fmt_opt(s: Option<&str>) -> String {
    s.map_or("-".into(), fmt)
}

pub fn fmtz(s: &str) -> String {
    format!("{}Z", fmt(s))
}

pub fn fmt_range_end(a: &str, b: &str) -> String {
    let (na, nb) = (long(a), long(b));
    if let (Some(da), Some(db), Some(tb)) = (na.get(..10), nb.get(..10), nb.get(11..16)) {
        if da == db {
            return format!("{}..{tb}Z", fmtz(a));
        }
    }
    format!("{}..{}", fmtz(a), fmtz(b))
}

fn t_or_dash(t: Option<&str>) -> String {
    match t {
        Some(x) if !x.is_empty() => fmtz(x),
        _ => "-".into(),
    }
}

#[derive(Debug, Clone)]
pub struct Cov {
    pub source: String,
    pub kind: String,
    pub indexed_at: String,
    pub covers_window: bool,
    pub coverage: &'static str,
    pub has_findings: bool,
    pub stale: bool,
    /// the source's last scan read nothing, so it is a gap and never counted as searched
    pub empty: bool,
    /// registered but never scanned: the hunt's own "registered, never scanned" row stands for it
    pub unscanned: bool,
    pub gap_reason: Option<String>,
    pub close_with: Option<String>,
    /// Partial only because the scan read some folders of a laptop, not its home or the package caches
    pub narrow: bool,
}

impl Cov {
    pub fn to_j(&self) -> J {
        J::obj(vec![
            ("source", J::s(&self.source)),
            ("kind", J::s(&self.kind)),
            ("indexed_at", J::s(&self.indexed_at)),
            ("covers_window", J::Bool(self.covers_window)),
            ("coverage", J::s(self.coverage)),
            ("has_findings", J::Bool(self.has_findings)),
            ("stale", J::Bool(self.stale)),
            ("gap_reason", J::opt(self.gap_reason.as_deref())),
            ("close_with", J::opt(self.close_with.as_deref())),
        ])
    }
}

pub use crate::query::coverage::definition as coverage_definition;

/// One line of the chain of custody: an evidence issue, a scan, an export, an import, a YARA run or a host removal.
#[derive(Debug, Clone, Default)]
pub struct CustodyRow {
    pub event: String,
    pub at: String,
    pub by: String,
    pub requested_by: Option<String>,
    pub case_id: Option<String>,
    pub host: Option<String>,
    pub file_sha256: Option<String>,
    pub signed_with: Option<String>,
    pub reissue: bool,
    /// free words after the event (a YARA row: which rules, how many hits)
    pub detail: Option<String>,
}

impl CustodyRow {
    pub fn to_j(&self) -> J {
        let mut o = J::obj(vec![
            ("event", J::s(&self.event)),
            ("at", J::s(&self.at)),
            ("by", J::s(&self.by)),
            ("requested_by", J::opt(self.requested_by.as_deref())),
            ("case_id", J::opt(self.case_id.as_deref())),
        ]);
        if let Some(h) = &self.host {
            o.set("host", J::s(h));
        }
        if let Some(f) = &self.file_sha256 {
            o.set("file_sha256", J::s(f));
        }
        if let Some(k) = &self.signed_with {
            o.set("signed_with", J::s(k));
        }
        if self.reissue {
            o.set("reissue", J::Bool(true));
        }
        if let Some(d) = &self.detail {
            o.set("detail", J::s(d));
        }
        o
    }

    pub fn line(&self) -> String {
        let mut line = format!("- {}", self.event);
        if self.reissue {
            line += " (re-issue)";
        }
        if let Some(k) = &self.signed_with {
            line += &format!(", signed with key {k}");
        }
        if let Some(h) = &self.host {
            line += &format!(" {h}");
        }
        line += &if self.by.is_empty() || self.by == "-" { format!(" {}", self.at) } else { format!(" {} by {}", self.at, self.by) };
        if let Some(d) = &self.detail {
            line += &format!(": {d}");
        }
        if let Some(f) = self.file_sha256.as_ref().filter(|f| !f.is_empty()) {
            line += &format!(", file sha256 {f}");
        }
        if let Some(r) = self.requested_by.as_ref().filter(|r| !r.is_empty()) {
            line += &format!(", requested by {r}");
        }
        if let Some(c) = self.case_id.as_ref().filter(|c| !c.is_empty()) {
            line += &format!(", case {c}");
        }
        line
    }
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// A pipe table. A column named in `optional` is left out when it holds only "-".
pub fn pipe_table(headers: &[&str], rows: &[Vec<String>], optional: &[&str]) -> Vec<String> {
    let keep: Vec<usize> = (0..headers.len()).filter(|&i| !optional.contains(&headers[i]) || rows.iter().any(|r| r[i] != "-")).collect();
    let mut out = vec![format!("| {} |", keep.iter().map(|&i| headers[i]).collect::<Vec<_>>().join(" | ")), format!("|{}|", keep.iter().map(|_| " --- ").collect::<Vec<_>>().join("|"))];
    for r in rows {
        out.push(format!("| {} |", keep.iter().map(|&i| cell(&r[i])).collect::<Vec<_>>().join(" | ")));
    }
    out
}

/// One `### KIND (n)` heading and pipe table per kind of finding, in the order the kinds first appear.
fn findings_by_kind(list: &[J], full: bool) -> Vec<String> {
    let or_dash = |s: String| if s.is_empty() { "-".to_string() } else { s };
    let mut kinds: Vec<String> = vec![];
    for f in list {
        let k = jstr(f, "kind").unwrap_or_default();
        if !kinds.contains(&k) {
            kinds.push(k);
        }
    }
    let mut out = vec![];
    for k in kinds {
        let of: Vec<&J> = list.iter().filter(|f| jstr(f, "kind").unwrap_or_default() == k).collect();
        out.push(format!("### {k} ({})", of.len()));
        out.push(String::new());
        let rows: Vec<Vec<String>> = of
            .iter()
            .map(|f| {
                let mut r = vec![
                    jstr(f, "source").unwrap_or_default(),
                    or_dash(jstr(f, "location").unwrap_or_default()),
                    or_dash(jlist(f, "indicators").join(", ")),
                    jstr(f, "state").unwrap_or_default(),
                    t_or_dash(jstr(f, "first_seen").as_deref()),
                    t_or_dash(jstr(f, "last_seen").as_deref()),
                ];
                if full {
                    r.push(t_or_dash(jstr(f, "removed_at").as_deref()));
                    r.push(or_dash(jlist(f, "run_ids").join(", ")));
                    r.push(or_dash(jlist(f, "secrets").join(", ")));
                }
                r
            })
            .collect();
        let heads: &[&str] = if full {
            &["SOURCE", "LOCATION", "INDICATORS", "STATE", "FIRST SEEN", "LAST SEEN", "REMOVED", "RUNS", "SECRETS"]
        } else {
            &["SOURCE", "LOCATION", "INDICATORS", "STATE", "FIRST SEEN", "LAST SEEN"]
        };
        out.extend(pipe_table(heads, &rows, &["LOCATION", "REMOVED", "RUNS", "SECRETS"]));
        out.push(String::new());
    }
    out
}

pub struct Pop {
    pub repos: usize,
    pub registries: usize,
    pub hosts: usize,
    pub runners: usize,
    pub laptops: usize,
    /// hosts registered as servers, and hosts whose kind nobody recorded (a name never decides it)
    pub servers: usize,
    pub unknown: usize,
    pub members: usize,
    /// Members with a scan of a machine of theirs here, and where the member list comes from
    pub members_covered: usize,
    pub members_source: String,
    /// Members whose scan exists but reads less than their home and the package caches
    pub members_partial: usize,
    /// Members whose scan is stale, and members whose scan read nothing (each gap has one reason)
    pub members_stale: usize,
    pub members_empty: usize,
    /// (member, reason) for every member that is not covered
    pub member_reasons: Vec<(String, String)>,
    pub member_names_without_laptop_scan: Vec<String>,
    /// (member, why) for every member that is not covered, `why` being `not scanned`, `stale`, `partial` or `empty`: the
    /// words the customer statement uses for the same gap
    pub member_gaps: Vec<(String, &'static str)>,
    pub empty_scans: Vec<String>,
    pub history_begins: Option<String>,
    pub statement: String,
}

impl Pop {
    pub fn to_j(&self) -> J {
        J::obj(vec![
            ("repos", J::Int(self.repos as i64)),
            ("registries", J::Int(self.registries as i64)),
            ("hosts", J::Int(self.hosts as i64)),
            ("runners", J::Int(self.runners as i64)),
            ("laptops", J::Int(self.laptops as i64)),
            ("servers", J::Int(self.servers as i64)),
            ("kind_unknown", J::Int(self.unknown as i64)),
            ("members", J::Int(self.members as i64)),
            ("members_covered", J::Int(self.members_covered as i64)),
            ("members_source", J::s(&self.members_source)),
            ("members_partial", J::Int(self.members_partial as i64)),
            ("members_stale", J::Int(self.members_stale as i64)),
            ("members_empty", J::Int(self.members_empty as i64)),
            ("member_reasons", J::Arr(self.member_reasons.iter().map(|(m, r)| J::obj(vec![("member", J::s(m)), ("reason", J::s(r))])).collect())),
            ("members_without_laptop_scan", J::Int(self.member_names_without_laptop_scan.len() as i64)),
            ("member_names_without_laptop_scan", J::strs(&self.member_names_without_laptop_scan)),
            ("empty_scans", J::strs(&self.empty_scans)),
            ("history_begins", J::opt(self.history_begins.as_deref())),
            ("statement", J::s(&self.statement)),
            ("covers", J::s("indexed sources only")),
        ])
    }
}

/// One stored YARA hit on a host in scope: the rule, the file, the file's sha256 and the sha256 of the rules file that
/// found it. `state` is `present` when the host's newest scan still hit the file, else `not hit at the last scan`.
#[derive(Debug, Clone, Default)]
pub struct YaraRow {
    pub source: String,
    pub rule: String,
    pub path: String,
    pub sha256: String,
    pub rules_sha256: String,
    pub state: String,
    pub first_seen: String,
    pub last_seen: String,
}

impl YaraRow {
    pub fn to_j(&self) -> J {
        J::obj(vec![
            ("source", J::s(&self.source)),
            ("rule", J::s(&self.rule)),
            ("path", J::s(&self.path)),
            ("sha256", J::s(&self.sha256)),
            ("rules_sha256", J::s(&self.rules_sha256)),
            ("state", J::s(&self.state)),
            ("first_seen", J::s(&self.first_seen)),
            ("last_seen", J::s(&self.last_seen)),
        ])
    }
}

/// Everything the Markdown report reads (the same facts the JSON carries).
pub struct Doc<'a> {
    pub requested_by: Option<String>,
    pub case_id: Option<String>,
    pub generated_at: String,
    pub window: (String, String),
    pub window_from: String,
    /// where the examination stopped when the window ends after the index time
    pub examined_to: Option<String>,
    pub iocs: Vec<String>,
    pub statement: String,
    /// the one-sentence answer the report opens with
    pub headline: String,
    pub verdict: String,
    pub index_as_of: Option<String>,
    pub pop: &'a Pop,
    pub method: &'a [String],
    pub findings: &'a [J],
    pub possible: &'a [J],
    pub late: &'a [J],
    /// YARA hits on the hosts in scope, a table of their own (not counted in the verdict)
    pub yara: &'a [YaraRow],
    /// "2 people and 1 machine", from the one renderer
    pub possible_words: String,
    /// The range of scan times behind the answer, with its oldest source
    pub data_as_of: Option<String>,
    pub secrets_exposed: &'a [String],
    pub cov: &'a [Cov],
    /// every gap the file counts, each listed once below
    pub rows: &'a [NotChecked],
    pub gaps: String,
    pub limits: &'a [String],
    pub custody: &'a [CustodyRow],
    /// The customer's own question and the date it came in, as given
    pub question: Option<String>,
    pub received: Option<String>,
    /// Where the window, the fixed version and the indicators came from
    pub provenance: &'a [String],
}

fn jget<'a>(j: &'a J, k: &str) -> Option<&'a J> {
    match j {
        J::Obj(o) => o.iter().find(|(x, _)| x == k).map(|(_, v)| v),
        _ => None,
    }
}

fn jstr(j: &J, k: &str) -> Option<String> {
    match jget(j, k) {
        Some(J::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn jlist(j: &J, k: &str) -> Vec<String> {
    match jget(j, k) {
        Some(J::Arr(a)) => a
            .iter()
            .map(|x| match x {
                J::Str(s) => s.clone(),
                J::Int(i) => i.to_string(),
                _ => String::new(),
            })
            .collect(),
        _ => vec![],
    }
}

/// Wrap lines in a code fence longer than any run of backticks inside them, so a name holding ``` cannot close it early.
fn fenced(lines: Vec<String>) -> Vec<String> {
    let fence = "`".repeat(lines.iter().map(|l| crate::out::render::longest_ticks(l)).max().unwrap_or(0).max(2) + 1);
    let mut out = vec![fence.clone()];
    out.extend(lines);
    out.push(fence);
    out
}

fn kinds_line(cs: &[&Cov]) -> String {
    let mut kinds: std::collections::BTreeMap<&str, usize> = Default::default();
    for c in cs {
        *kinds.entry(c.kind.as_str()).or_default() += 1;
    }
    if kinds.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = kinds.iter().map(|(k, n)| plural_with(*n, k, if *k == "registry" { Some("registries") } else { None })).collect();
    format!(": {}", parts.join(", "))
}

/// A row that came from a source's coverage (partial, stale, empty) is described from that source; any other row from its own words.
fn gap_line(r: &NotChecked, cov: &[Cov], pop: &Pop, possible_names: &[String]) -> String {
    let close = |x: &str| if x.is_empty() { String::new() } else { format!(". To close: {x}") };
    if matches!(r.state.as_str(), "partial" | "stale" | "empty") {
        if let Some(c) = cov.iter().find(|c| c.source == r.name) {
            let reason = c.gap_reason.clone().unwrap_or_default();
            let mut line = if r.state == "partial" {
                if c.has_findings {
                    format!("- {} ({}): findings up to {}; {reason}", c.source, c.kind, fmtz(&c.indexed_at))
                } else {
                    format!("- {} ({}): indexed {}; {reason}", c.source, c.kind, fmtz(&c.indexed_at))
                }
            } else {
                format!("- {} ({}), indexed {}: {reason}", c.source, c.kind, fmtz(&c.indexed_at))
            };
            if possible_names.contains(&c.source) {
                line += " (possible exposure: see POSSIBLE)";
            }
            return line + &close(c.close_with.as_deref().unwrap_or(&r.command));
        }
    }
    if r.state == "laptops" {
        let names = &pop.member_names_without_laptop_scan;
        let more = if names.len() > 5 { format!(" and {} more", names.len() - 5) } else { String::new() };
        // Each member with the kind of gap it is: a stale scan is stale, a narrow one is partial, no scan is not scanned
        let shown: Vec<String> = if pop.member_gaps.is_empty() { names.iter().take(5).cloned().collect() } else { pop.member_gaps.iter().take(5).map(|(n, w)| format!("{n}: {w}")).collect() };
        let tail = if names.is_empty() { String::new() } else { format!(" (not covered: {}{more})", shown.join(", ")) };
        return format!("- laptops: {}; to close: {}{tail}", r.why, r.command);
    }
    format!("- {}: {}{}", r.name, r.why, close(&r.command))
}

pub fn evidence_md(d: &Doc, now: &str) -> String {
    let mut out: Vec<String> = vec!["# Evidence report".into(), String::new()];
    // The file opens with the answer in one sentence
    let first = d.headline.trim_end_matches('.');
    out.push(format!("**{first}.**"));
    out.push(String::new());
    out.push(format!(
        "{}{}. Generated {}.",
        match &d.requested_by {
            Some(r) if !r.is_empty() => format!("Requested by {r}"),
            _ => "Requested by: not recorded (pass --requested-by)".to_string(),
        },
        match &d.case_id {
            Some(c) if !c.is_empty() => format!(", case {c}"),
            _ => String::new(),
        },
        fmtz(&d.generated_at)
    ));
    out.push(String::new());
    out.push("## QUESTION".into());
    out.push(format!(
        "Were any of these indicators present in the indexed sources in the window {}? (window taken from the {})",
        crate::query::util::window_words(&d.window.0, &d.window.1, d.examined_to.as_deref()),
        d.window_from
    ));
    out.extend(d.iocs.iter().map(|i| format!("- {i}")));
    if d.question.is_some() || d.received.is_some() {
        out.push(String::new());
        let day = |r: &str| fmt(r).split(' ').next().unwrap_or("").to_string();
        out.push(match (&d.question, &d.received) {
            (Some(q), Some(r)) => format!("The customer's question, received {}: {}", day(r), q.trim()),
            (Some(q), None) => format!("The customer's question (the date it was received is not recorded): {}", q.trim()),
            (None, Some(r)) => format!("A customer question was received {}; its text is not recorded.", day(r)),
            _ => String::new(),
        });
    }
    if !d.provenance.is_empty() {
        out.push(String::new());
        out.extend(d.provenance.iter().cloned());
    }
    let pop = d.pop;
    out.push(String::new());
    out.push("## RESULT".into());
    out.push(format!("Verdict: {}.", d.verdict));
    out.push(d.statement.clone());
    out.push(format!(
        "Index as of {}.{}",
        d.data_as_of.clone().unwrap_or_else(|| d.index_as_of.as_deref().map_or("unknown".to_string(), fmtz)),
        match &d.examined_to {
            Some(t) => format!(" Examined to {}.", fmtz(t)),
            None => String::new(),
        }
    ));
    out.push(String::new());
    out.push("## POPULATION".into());
    out.push(format!(
        "The index holds {}, {} and {}{}; history begins {}. {}.",
        plural(pop.repos, "repo"),
        plural_with(pop.registries, "registry", Some("registries")),
        plural(pop.hosts, "host"),
        if pop.empty_scans.is_empty() {
            String::new()
        } else {
            format!(" ({} of them hashed no files, so {} not searched)", pop.empty_scans.len(), if pop.empty_scans.len() == 1 { "it was" } else { "they were" })
        },
        fmt_opt(pop.history_begins.as_deref()),
        pop.statement
    ));
    out.push("Machines, registries and clouds that are not indexed are not covered by this file.".into());
    out.push(String::new());
    out.push("## METHOD".into());
    out.extend(d.method.iter().map(|m| format!("- {m}")));
    out.push(String::new());
    if !d.findings.is_empty() || !d.yara.is_empty() {
        out.push("## FINDINGS".into());
        out.extend(findings_by_kind(d.findings, true));
        if !d.secrets_exposed.is_empty() {
            out.push(format!("Secrets that in-window CI runs could read: {}.", d.secrets_exposed.join(", ")));
            out.push(String::new());
        }
        if !d.yara.is_empty() {
            out.push(format!("### YARA hits ({})", d.yara.len()));
            out.push(String::new());
            out.push("Hits of YARA rules that were run on these hosts. The rules are not among the indicators of the question, so these are not counted in the RESULT line. RULES SHA256 names the rules file that found each one.".into());
            out.push(String::new());
            let rows: Vec<Vec<String>> = d
                .yara
                .iter()
                .map(|y| vec![y.source.clone(), y.rule.clone(), y.path.clone(), y.sha256.clone(), y.rules_sha256.clone(), y.state.clone(), fmtz(&y.first_seen), fmtz(&y.last_seen)])
                .collect();
            out.extend(pipe_table(&["SOURCE", "RULE", "PATH", "SHA256", "RULES SHA256", "STATE", "FIRST SEEN", "LAST SEEN"], &rows, &["SHA256", "RULES SHA256"]));
            out.push(String::new());
        }
    }
    if !d.late.is_empty() {
        out.push("## PRESENT NOW, FIRST SEEN AFTER THE WINDOW".into());
        out.push("These were not in the window, but they are in the index now and carry the indicator. They are counted in the RESULT line and are not dropped.".into());
        out.push(String::new());
        out.extend(findings_by_kind(d.late, false));
    }
    if !d.possible.is_empty() {
        out.push("## POSSIBLE (not counted)".into());
        out.push(format!("These {} have evidence of exposure that the index cannot confirm.", if d.possible_words.is_empty() { "machines".to_string() } else { d.possible_words.clone() }));
        for f in d.possible {
            let r = jstr(f, "reason").filter(|r| !r.is_empty()).unwrap_or_else(|| "possible exposure".into());
            out.push(format!("- {}: {r}", jstr(f, "source").unwrap_or_default()));
        }
        out.push(String::new());
    }
    let cov = d.cov;
    let examined = d.examined_to.clone().unwrap_or_else(|| d.window.1.clone());
    let full: Vec<&Cov> = cov.iter().filter(|c| c.coverage == "full").collect();
    let possible_names: Vec<String> = d.possible.iter().filter_map(|f| jstr(f, "source")).collect();
    let partial: Vec<&NotChecked> = d.rows.iter().filter(|r| r.state == "partial").collect();
    let others: Vec<&NotChecked> = d.rows.iter().filter(|r| r.state != "partial").collect();
    out.push("## WHAT WAS SCANNED".into());
    let oldest = full.iter().min_by(|a, b| a.indexed_at.cmp(&b.indexed_at));
    out.push(format!(
        "{} of {} in scope are full: each was scanned after the end of the examined window ({}) or is fresh as of its last scan{}{}. The complete list is in the appendix.",
        plural(full.len(), "source"),
        cov.len(),
        fmtz(&examined),
        match oldest {
            Some(o) => format!(" (oldest: {}, {})", o.source, crate::query::coverage::full_words(&o.indexed_at, &examined)),
            None => String::new(),
        },
        kinds_line(&full)
    ));
    if let Some(at) = &d.examined_to {
        out.push(format!(
            "The window ends {}; the index runs to {} ({}), so later events are not covered: br scan --stale",
            if d.window.1.as_str() >= now { "now" } else { "after the index time" },
            fmtz(at),
            age_label(now, at)
        ));
    }
    out.push(if d.rows.is_empty() { "No gaps.".to_string() } else { format!("{}.", d.gaps) });
    out.push(String::new());
    out.push("## PARTIAL COVERAGE".into());
    if !partial.is_empty() {
        out.push(format!("{} Events after a source's last scan are not visible.", coverage_definition(&examined)));
        out.extend(partial.iter().map(|r| gap_line(r, cov, pop, &possible_names)));
    } else {
        out.push("None.".into());
    }
    out.push(String::new());
    out.push("## NOT COVERED".into());
    if !others.is_empty() {
        out.extend(others.iter().map(|r| gap_line(r, cov, pop, &possible_names)));
    } else {
        out.push(if d.examined_to.is_some() { "Nothing beyond the window-end note above.".into() } else { "Every source in scope was indexed at or after the end of the window.".into() });
    }
    out.push(String::new());
    out.push("## LIMITS".into());
    out.extend(d.limits.iter().map(|l| format!("- {l}")));
    out.push(String::new());
    out.push("## CUSTODY".into());
    out.extend(d.custody.iter().map(|c| c.line()));
    out.push(String::new());
    out.push("## APPENDIX: SOURCES IN SCOPE".into());
    out.push(format!("COVERAGE: {} FINDINGS is yes when the FINDINGS table above holds a row for the source.", coverage_definition(&examined)));
    let rows: Vec<Vec<String>> =
        cov.iter().map(|c| vec![c.source.clone(), c.kind.clone(), fmtz(&c.indexed_at), c.coverage.to_string(), if c.has_findings { "yes" } else { "no" }.to_string()]).collect();
    out.extend(fenced(table(&["SOURCE", "KIND", "INDEXED", "COVERAGE", "FINDINGS"], &rows, 0)));
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_outgrows_the_content() {
        let f = fenced(vec!["a ``` b".into()]);
        assert_eq!(f[0], "````");
        assert_eq!(f[2], "````");
        assert_eq!(fenced(vec!["x".into()])[0], "```");
    }

    #[test]
    fn short_dates_do_not_panic() {
        assert_eq!(fmt("2026"), "2026");
        assert_eq!(fmt_range_end("x", "y"), "xZ..yZ");
    }

    #[test]
    fn dates_carry_the_year() {
        assert_eq!(fmt("2026-05-11T14:00:00Z"), "2026-05-11 14:00");
        assert_eq!(fmt(""), "-");
        assert_eq!(fmt_range_end("2026-05-11T14:00:00Z", "2026-05-11T18:00:00Z"), "2026-05-11 14:00Z..18:00Z");
        assert_eq!(fmt_range_end("2026-05-11T14:00:00Z", "2026-05-12T18:00:00Z"), "2026-05-11 14:00Z..2026-05-12 18:00Z");
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn pipe_table_escapes_pipes_and_drops_empty_optional_columns() {
        let rows = vec![vec!["a|b".to_string(), "-".to_string()]];
        let t = pipe_table(&["SOURCE", "RUNS"], &rows, &["RUNS"]);
        assert_eq!(t, vec!["| SOURCE |", "| --- |", "| a\\|b |"]);
        let kept = pipe_table(&["SOURCE", "RUNS"], &[vec!["x".into(), "7".into()]], &["RUNS"]);
        assert_eq!(kept[0], "| SOURCE | RUNS |");
    }

    #[test]
    fn custody_line_names_host_hash_and_case() {
        let r = CustodyRow {
            event: "imported".into(),
            at: "2026-05-12T09:00:00Z".into(),
            by: "pv".into(),
            case_id: Some("C-1".into()),
            host: Some("laptop-jun".into()),
            file_sha256: Some("ab".repeat(32)),
            ..Default::default()
        };
        assert_eq!(r.line(), format!("- imported laptop-jun 2026-05-12T09:00:00Z by pv, file sha256 {}, case C-1", "ab".repeat(32)));
        let y = CustodyRow { event: "YARA hits".into(), at: "t".into(), by: "-".into(), detail: Some("1 hit in 1 file".into()), ..Default::default() };
        assert_eq!(y.line(), "- YARA hits t: 1 hit in 1 file");
    }
}
