//! `br sql`: the tables, the in-memory SQLite built from the View, and the three output shapes.

use std::collections::HashSet;

use rusqlite::types::Value;
use rusqlite::Connection;

use crate::out::json::J;
use crate::query::index::{parse_pkg, Index};
use crate::query::util::table;
use crate::view::{HostFile, HostItem};

pub const SCHEMA: &str = "sources(source_id, kind, name, indexed_at, reach, owner)
scans(scan_id, source_id, started_at, finished_at, stage1_files, hashed, simhashed)
packages(eco, name, version, source_id, location, file, depth, via, dev, first_seen, last_seen, removed_at)
files(source_id, path, size, mtime, sha256, simhash, layer, deleted_in_layer, first_seen, last_seen, removed_at, image_digest)
ci_runs(run_id, repo, workflow, at, runner, commit_sha, resolved_from)
run_packages(run_id, eco, name, version)
run_secrets(run_id, name)
action_refs(repo, file, action, ref, kind, resolved_sha, run_id, first_seen, last_seen)
caches(repo, key, created, last_used, size_mb)
artifacts(repo, name, id, created, expires)
images(digest, repository, tags, built, repo, commit_sha)
image_layers(digest, n, created_by)
yara_hits(source_id, path, rule, rules_sha256, first_seen, sha256, last_seen)
host_roots(source_id, root, this_machine)
owners(source_id, path, team, people)
custody(event, at, by, case_id, file_sha256, requested_by, host)";

fn t(s: &str) -> Value {
    Value::Text(s.to_string())
}
fn to(s: Option<&str>) -> Value {
    s.map_or(Value::Null, t)
}
fn n(x: Option<u64>) -> Value {
    x.map_or(Value::Null, |v| Value::Integer(v as i64))
}

/// Python's `json.dumps(list_of_strings)`: `["a", "b"]`.
fn py_list(xs: &[String]) -> String {
    format!("[{}]", xs.iter().map(|x| J::s(x.clone()).dumps()).collect::<Vec<_>>().join(", "))
}

fn full_path(it: &HostItem, f: &HostFile) -> String {
    if f.path.starts_with('/') {
        f.path.clone()
    } else {
        format!("{}/{}", it.loc.trim_end_matches('/'), f.path)
    }
}

/// The registry collector stores layer paths without the leading slash; the table shows them as the image has them.
fn abs_path(p: &str) -> String {
    if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    }
}

fn jstr(v: &serde_json::Value, k: &str) -> Value {
    match v.get(k) {
        Some(serde_json::Value::String(s)) => Value::Text(s.clone()),
        Some(serde_json::Value::Number(x)) => x.as_i64().map_or(Value::Null, Value::Integer),
        _ => Value::Null,
    }
}

struct Sink<'a> {
    db: &'a Connection,
    seen: HashSet<String>,
}

impl Sink<'_> {
    /// One row is one fact: the same row from two walks of the index is stored once.
    fn ins(&mut self, table: &str, row: Vec<Value>) {
        if !self.seen.insert(format!("{table}{row:?}")) {
            return;
        }
        let qs = vec!["?"; row.len()].join(",");
        let _ = self.db.execute(&format!("INSERT INTO {table} VALUES({qs})"), rusqlite::params_from_iter(row.iter()));
    }
}

pub fn build(ix: &Index) -> rusqlite::Result<Connection> {
    let db = Connection::open_in_memory()?;
    for line in SCHEMA.lines() {
        db.execute(&format!("CREATE TABLE {line}"), [])?;
    }
    let mut s = Sink { db: &db, seen: HashSet::new() };
    for (name, src) in &ix.srcs {
        let owner = match src.kind.as_str() {
            "repo" => ix.owner_of(name, None),
            "host" => ix.host_def(name).and_then(|h| h.owner_team.clone().filter(|x| !x.is_empty()).or_else(|| h.owner.clone().filter(|x| !x.is_empty()))),
            _ => None,
        };
        let reach = if src.reach.is_empty() { None } else { Some(src.reach.as_str()) };
        s.ins("sources", vec![t(name), t(&src.kind), t(name), t(&src.indexed_at), to(reach), to(owner.as_deref())]);
        // The index keeps one time per source (when it was last written), not the start of the scan: started_at is
        // NULL rather than invented. The counts are counted from the files held; a repo has no file counts.
        if src.kind == "host" {
            let (mut c, mut hashed, mut simhashed) = (0i64, 0i64, 0i64);
            for it in ix.host_items(name) {
                for f in &it.files {
                    c += 1;
                    hashed += !f.sha256.is_empty() as i64;
                    simhashed += f.simhash.as_deref().is_some_and(|x| !x.is_empty()) as i64;
                }
            }
            s.ins("scans", vec![t(&format!("scan-{name}")), t(name), Value::Null, t(&src.indexed_at), Value::Integer(c), Value::Integer(hashed), Value::Integer(simhashed)]);
        } else {
            s.ins("scans", vec![t(&format!("scan-{name}")), t(name), Value::Null, t(&src.indexed_at), Value::Null, Value::Null, Value::Null]);
        }
    }
    for r in ix.names("repo") {
        let lock = ix.lockfile(&r);
        let at = ix.i(&r);
        for o in ix.lock_obs(&r) {
            let (eco, name, ver) = parse_pkg(&o.p);
            let via: Vec<String> = o.pkg.via.iter().map(|x| parse_pkg(x).1.to_string()).collect();
            s.ins(
                "packages",
                vec![
                    t(eco),
                    t(name),
                    t(ver),
                    t(&r),
                    to(lock.as_deref()),
                    to(lock.as_deref()),
                    t(if o.pkg.direct { "direct" } else { "transitive" }),
                    Value::Text(py_list(&via)),
                    Value::Integer(o.pkg.dev as i64),
                    t(&o.first_seen),
                    to(at.as_deref()),
                    to(o.removed_at.as_deref()),
                ],
            );
        }
        let repo = ix.repo(&r);
        for run in ix.runs(&r) {
            let rid = format!("{r}#{}", run.id);
            s.ins("ci_runs", vec![t(&rid), t(&r), t(&run.workflow), t(&run.at), to(run.runner.as_deref()), to(run.commit.as_deref()), to(run.resolved_from.as_deref())]);
            for p in &run.installed {
                let (e, nm, v) = parse_pkg(p);
                s.ins("run_packages", vec![t(&rid), t(e), t(nm), t(v)]);
            }
            // by the workflow file path from the runs API; a run without one matches on the display name only when the
            // file is named the same, never by suffix (`ci.yml` is not `release-ci.yml`)
            let wf = repo.workflows.iter().find(|x| match run.path.as_deref().filter(|p| !p.is_empty()) {
                Some(p) => x.file == p,
                None => x.file == run.workflow,
            });
            let secrets: Vec<String> = if !run.secrets.is_empty() { run.secrets.clone() } else { wf.map(|w| w.secrets.clone()).unwrap_or_default() };
            for sn in &secrets {
                s.ins("run_secrets", vec![t(&rid), t(sn)]);
            }
            for (usev, sha) in &run.action_resolved {
                let head = usev.split(' ').next().unwrap_or("");
                let (a, rf) = head.split_once('@').unwrap_or((head, ""));
                let file = wf.map(|w| w.file.as_str()).unwrap_or(run.workflow.as_str());
                let kind = if rf.len() == 40 && rf.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) { "sha" } else { "mutable tag" };
                s.ins("action_refs", vec![t(&r), t(file), t(a), t(rf), t(kind), t(sha), t(&rid), t(&run.at), t(&run.at)]);
            }
        }
        for c in ix.caches(&r) {
            s.ins("caches", vec![t(&r), t(&c.key), t(&c.created), to(c.last_used.as_deref()), n(c.size_mb)]);
        }
        for a in ix.artifacts(&r) {
            s.ins("artifacts", vec![t(&r), t(&a.name), Value::Integer(a.id as i64), t(&a.created), to(a.expires.as_deref())]);
        }
        for rel in ix.releases(&r) {
            for a in &rel.assets {
                let sha = if a.sha256.is_empty() { Value::Null } else { t(&a.sha256) };
                s.ins(
                    "files",
                    vec![
                        t(&r),
                        t(&format!("{}/{}", rel.tag, a.name)),
                        n(a.size),
                        t(&rel.published),
                        sha,
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        t(&rel.published),
                        to(at.as_deref()),
                        Value::Null,
                        Value::Null,
                    ],
                );
            }
        }
    }
    for h in ix.names("host") {
        let at = ix.i(&h);
        for it in ix.host_items(&h) {
            for f in &it.files {
                let sh = if f.sha256.is_empty() { Value::Null } else { t(&f.sha256) };
                s.ins(
                    "files",
                    vec![
                        t(&h),
                        t(&full_path(it, f)),
                        n(f.size),
                        to(f.mtime.as_deref()),
                        sh,
                        to(f.simhash.as_deref()),
                        Value::Null,
                        Value::Null,
                        t(&it.at),
                        to(at.as_deref()),
                        Value::Null,
                        Value::Null,
                    ],
                );
            }
            for p in &it.pkgs {
                let (e, nm, v) = parse_pkg(p);
                // A package a lockfile on the host declares has the lockfile's own depth, chain and dev flag
                let decl =
                    if it.kind == "lockfile" { ix.v.hosts.get(&h).and_then(|hh| hh.declared.iter().find(|d| d.loc == it.loc)).and_then(|d| d.packages.iter().find(|x| &x.p == p)) } else { None };
                match decl {
                    Some(lp) => {
                        let via: Vec<String> = lp.via.iter().map(|x| parse_pkg(x).1.to_string()).collect();
                        s.ins(
                            "packages",
                            vec![
                                t(e),
                                t(nm),
                                t(v),
                                t(&h),
                                t(&it.loc),
                                t(&it.loc),
                                t(if lp.direct { "direct" } else { "transitive" }),
                                Value::Text(py_list(&via)),
                                Value::Integer(lp.dev as i64),
                                t(&it.at),
                                to(at.as_deref()),
                                Value::Null,
                            ],
                        );
                    }
                    None => s.ins("packages", vec![t(e), t(nm), t(v), t(&h), t(&it.loc), Value::Null, Value::Null, t("[]"), Value::Integer(0), t(&it.at), to(at.as_deref()), Value::Null]),
                }
            }
        }
    }
    for b in ix.images() {
        // the registry this image lives in is the host of its own reference, not the one registry the index happens to hold
        let host = b.repository.split('/').next().unwrap_or("").to_string();
        let reg = ix.names("registry").into_iter().find(|n| n == &host || n.starts_with(&format!("{host}/"))).or_else(|| if host.is_empty() { None } else { Some(host.clone()) });
        let regat = reg.as_deref().and_then(|r| ix.i(r));
        let (srepo, scommit) = b.source.as_ref().map_or((None, None), |x| (x.repo.as_deref(), x.commit.as_deref()));
        s.ins("images", vec![t(&b.digest), t(&b.repository), Value::Text(py_list(&b.tags)), t(&b.built), to(srepo), to(scommit)]);
        for ly in &b.layers {
            s.ins("image_layers", vec![t(&b.digest), Value::Integer(ly.n as i64), to(ly.created_by.as_deref())]);
            for f in &ly.files {
                let gone = b.layers.iter().find(|x| x.n > ly.n && x.whiteouts.iter().any(|w| w == &f.path)).map(|x| x.n);
                let sha = if f.sha256.is_empty() { Value::Null } else { t(&f.sha256) };
                s.ins(
                    "files",
                    vec![
                        to(reg.as_deref()),
                        t(&abs_path(&f.path)),
                        Value::Null,
                        t(&b.built),
                        sha,
                        Value::Null,
                        Value::Integer(ly.n as i64),
                        gone.map_or(Value::Null, |g| Value::Integer(g as i64)),
                        t(&b.built),
                        to(regat.as_deref()),
                        Value::Null,
                        t(&b.digest),
                    ],
                );
            }
        }
    }
    for y in &ix.v.state.yara_hits {
        s.ins("yara_hits", vec![jstr(y, "source_id"), jstr(y, "path"), jstr(y, "rule"), jstr(y, "rules_sha256"), jstr(y, "first_seen"), jstr(y, "sha256"), jstr(y, "last_seen")]);
    }
    // The directories each host's scans read, and the one decision about which host is this machine
    for (hn, hh) in &ix.v.hosts {
        for r in &hh.roots {
            s.ins("host_roots", vec![t(hn), t(r), Value::Integer(hh.this_machine as i64)]);
        }
    }
    for c in &ix.v.state.custody {
        s.ins("custody", vec![jstr(c, "event"), jstr(c, "at"), jstr(c, "by"), jstr(c, "case_id"), jstr(c, "file_sha256"), jstr(c, "requested_by"), jstr(c, "host")]);
    }
    // team short name -> logins, built once
    let mut members: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for p in &ix.v.people {
        let ts: Vec<&String> = if p.teams.is_empty() { p.team.iter().collect() } else { p.teams.iter().collect() };
        for tm in ts {
            members.entry(tm.to_lowercase()).or_default().push(p.login.clone());
        }
    }
    for r in ix.names("repo") {
        if let Some(team) = ix.owner_of(&r, None) {
            let short = team.rsplit('/').next().unwrap_or(&team).trim_start_matches('@').to_lowercase();
            let mut who = members.get(&short).cloned().unwrap_or_default();
            who.sort();
            // `path` is the CODEOWNERS file the owner came from, which the index does not record: NULL, not the lockfile
            s.ins("owners", vec![t(&r), Value::Null, t(&team), Value::Text(py_list(&who))]);
        }
    }
    drop(s);
    Ok(db)
}

/// An RFC 3339 / ISO 8601 timestamp: `2026-05-11T14:00:00Z`, with optional fraction and `Z` or `+hh:mm` offset.
fn is_iso(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 || !(b[10] == b'T' || b[10] == b't') {
        return false;
    }
    let d = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit());
    let shape = (0..4).all(d) && b[4] == b'-' && d(5) && d(6) && b[7] == b'-' && d(8) && d(9) && d(11) && d(12) && b[13] == b':' && d(14) && d(15) && b[16] == b':' && d(17) && d(18);
    if !shape {
        return false;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let st = i;
        while d(i) {
            i += 1;
        }
        if i == st {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z') | Some(b'z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => b.len() == i + 6 && d(i + 1) && d(i + 2) && b[i + 3] == b':' && d(i + 4) && d(i + 5),
        _ => false,
    }
}

/// Python's `str(float)`.
fn py_float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

fn plain(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => py_float(*f),
        Value::Text(s) => s.clone(),
        Value::Blob(b) => format!("b{:?}", String::from_utf8_lossy(b)),
    }
}

fn cell(v: &Value) -> String {
    match v {
        Value::Null => "NULL".to_string(),
        // only the human table shortens a time; json and csv keep the raw value. Seconds stay, so ORDER BY ties are visible.
        Value::Text(s) if is_iso(s) => s.replacen('T', " ", 1).trim_end_matches(['Z', 'z']).to_string() + if s.ends_with('Z') || s.ends_with('z') { " UTC" } else { "" },
        v => plain(v),
    }
}

fn jval(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => py_float(*f),
        Value::Text(s) => J::s(s.clone()).dumps(),
        Value::Blob(_) => "null".into(),
    }
}

pub fn render_json(cols: &[String], rows: &[Vec<Value>]) -> String {
    if rows.is_empty() {
        return "[]".to_string();
    }
    let objs: Vec<String> = rows
        .iter()
        .map(|r| {
            if cols.is_empty() {
                return "  {}".to_string();
            }
            let kv: Vec<String> = cols.iter().zip(r).map(|(c, v)| format!("    {}: {}", J::s(c.clone()).dumps(), jval(v))).collect();
            format!("  {{\n{}\n  }}", kv.join(",\n"))
        })
        .collect();
    format!("[\n{}\n]", objs.join(",\n"))
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_row(fields: Vec<String>) -> String {
    if fields.len() == 1 && fields[0].is_empty() {
        return "\"\"".to_string();
    }
    fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(",")
}

/// RFC 4180 quoting of one field.
pub fn csv_quote(s: &str) -> String {
    csv_field(s)
}

/// A cell that a spreadsheet would run as a formula gets a leading `'` so Excel and Sheets show it as text: a leading
/// `=`, `+`, `-`, tab or CR, or an `@` followed by a function-like token (`@SUM(A1)`). An owner such as `@team` or a
/// package such as `@scope/name` is not a formula and is left as it is. Numbers written by br itself (a bare `-3`) are
/// not touched.
pub fn csv_safe(s: &str) -> String {
    let first = s.chars().next();
    let numeric = s.parse::<f64>().is_ok();
    let formula = match first {
        Some('=') | Some('+') | Some('-') | Some('\t') | Some('\r') => !numeric,
        Some('@') => at_function(&s[1..]),
        _ => false,
    };
    if formula {
        format!("'{s}")
    } else {
        s.to_string()
    }
}

/// `SUM(` in `@SUM(A1)`: a name made of letters, digits, `_` and `.`, then an opening parenthesis.
fn at_function(rest: &str) -> bool {
    let name: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.').collect();
    !name.is_empty() && rest[name.len()..].starts_with('(')
}

pub fn render_csv(cols: &[String], rows: &[Vec<Value>]) -> String {
    let mut lines = vec![csv_row(cols.to_vec())];
    for r in rows {
        lines.push(csv_row(r.iter().map(|v| csv_safe(&plain(v))).collect()));
    }
    lines.join("\n")
}

pub fn render_table(cols: &[String], rows: &[Vec<Value>]) -> String {
    let heads: Vec<String> = cols.iter().map(|c| c.to_uppercase()).collect();
    let hs: Vec<&str> = heads.iter().map(|s| s.as_str()).collect();
    let body: Vec<Vec<String>> = rows.iter().map(|r| r.iter().map(cell).collect()).collect();
    format!("{}\n\n{} rows", table(&hs, &body, 0).join("\n"), rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_and_json_shapes() {
        let cols = vec!["a".to_string(), "b".to_string()];
        let rows = vec![vec![Value::Text("x,y".into()), Value::Null], vec![Value::Integer(2), Value::Real(1.0)]];
        assert_eq!(render_csv(&cols, &rows), "a,b\n\"x,y\",\n2,1.0");
        assert_eq!(render_json(&cols, &rows[1..]), "[\n  {\n    \"a\": 2,\n    \"b\": 1.0\n  }\n]");
        assert_eq!(render_json(&cols, &[]), "[]");
    }

    #[test]
    fn timestamps_of_any_rfc3339_form_are_recognised() {
        assert!(is_iso("2026-05-11T14:00:00Z"));
        assert!(is_iso("2026-05-11T14:00:00.123Z"));
        assert!(is_iso("2026-05-11T14:00:00+00:00"));
        assert!(!is_iso("2026-05-11"));
        assert!(!is_iso("v2026-05-11T14:00:00Z"));
        assert_eq!(cell(&Value::Text("2026-05-11T14:00:07Z".into())), "2026-05-11 14:00:07 UTC");
    }

    #[test]
    fn csv_cells_that_start_a_formula_are_neutralised() {
        assert_eq!(csv_safe("=1+1"), "'=1+1");
        assert_eq!(csv_safe("@SUM(A1)"), "'@SUM(A1)");
        // An owner and a scoped package are not formulas
        assert_eq!(csv_safe("@acme/web"), "@acme/web");
        assert_eq!(csv_safe("@dana"), "@dana");
        assert_eq!(csv_safe("@types/node"), "@types/node");
        assert_eq!(csv_safe("@acme/web (archived)"), "@acme/web (archived)");
        assert_eq!(csv_safe("-3"), "-3");
        assert_eq!(csv_safe("left-pad"), "left-pad");
        assert_eq!(csv_quote("a\"b\nc"), "\"a\"\"b\nc\"");
    }

    #[test]
    fn schema_creates() {
        let v = crate::view::View::default();
        let ix = Index::new(&v, "2026-01-01T00:00:00Z");
        let db = build(&ix).unwrap();
        let c: i64 = db.query_row("select count(*) from sources", [], |r| r.get(0)).unwrap();
        assert_eq!(c, 0);
    }
}
