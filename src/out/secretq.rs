//! Every output of a `secret:NAME` question: table, md, json, csv, slack, summary, sarif, quiet, and the notify drafts.
//! The data is `query::secret_hunt::SecretReport`; nothing here reads a value, because the report holds none.

use std::collections::BTreeMap;

use crate::out::json::J;
use crate::query::secret_hunt::{day, ImageHit, Reader, SecretReport, Stored, SHOW};
use crate::query::util::{plural, table};

fn cap<T>(rows: &[T]) -> (&[T], usize) {
    if rows.len() > SHOW {
        (&rows[..SHOW], rows.len() - SHOW)
    } else {
        (rows, 0)
    }
}

fn more(n: usize) -> Option<String> {
    (n > 0).then(|| format!("  ... and {n} more (--format json lists them all)"))
}

fn where_words(s: &Stored) -> String {
    if s.is_org() {
        if s.scope.contains("selected") {
            format!("org, {}", plural(s.repos.len(), "repo"))
        } else {
            "org, every repo".to_string()
        }
    } else {
        s.place.clone()
    }
}

fn owner_cell(s: &Stored) -> String {
    let mut o = s.owner.join(", ");
    if o.is_empty() {
        o = "unresolved".into();
    }
    if !s.used_by.is_empty() {
        o += &format!("; read by {}", s.used_by.join(", "));
    }
    o
}

fn places(r: &Reader) -> String {
    let mut by: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    for (f, l) in &r.lines {
        by.entry(f.as_str()).or_default().push(*l);
    }
    if by.is_empty() {
        return r.file.clone();
    }
    by.iter().map(|(f, ls)| format!("{f}:{}", ls.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(","))).collect::<Vec<_>>().join(" ")
}

fn reader_names(r: &Reader) -> String {
    let mut n = r.names.join(", ");
    if r.all {
        n += if n.is_empty() { "every secret (secrets: inherit)" } else { ", and every secret (secrets: inherit)" };
    }
    n
}

fn image_ref(i: &ImageHit) -> String {
    format!("{}@{}", i.repository, i.digest.chars().take(19).collect::<String>())
}

pub const IN_IMAGE: &str = "the value may be in the image: rotate it, and rebuild without it";

fn head(rep: &SecretReport) -> Vec<String> {
    let mut out = vec![format!("{}  {}", rep.verdict(), rep.asked_words())];
    out.push(rep.headline());
    out.push(match &rep.cutoff {
        Some(c) => format!("rotation cutoff {} (from {}); index as of {}", day(c), rep.cutoff_src, crate::query::util::fmtz(&rep.as_of)),
        None => format!("no rotation cutoff; index as of {}", crate::query::util::fmtz(&rep.as_of)),
    });
    out
}

/// The sections as plain (title, lines) pairs; the table and md forms both print these.
struct Section {
    title: String,
    headers: Vec<&'static str>,
    rows: Vec<Vec<String>>,
    extra: Option<String>,
}

fn sections(rep: &SecretReport) -> Vec<Section> {
    let mut out = vec![];
    if !rep.stored.is_empty() {
        let (shown, n) = cap(&rep.stored);
        out.push(Section {
            title: format!("STORED ({})", rep.stored.len()),
            headers: vec!["SECRET", "SCOPE", "WHERE", "LAST UPDATED", "ROTATION", "OWNER"],
            rows: shown.iter().map(|s| vec![s.name.clone(), s.scope.clone(), where_words(s), s.last_update(), s.rot_words(), owner_cell(s)]).collect(),
            extra: more(n),
        });
    }
    if !rep.readers.is_empty() {
        let (shown, n) = cap(&rep.readers);
        out.push(Section {
            title: format!("READ BY WORKFLOWS ({})", rep.readers.len()),
            headers: vec!["REPO", "READS", "FILE:LINE", "OWNER"],
            rows: shown.iter().map(|r| vec![r.repo.clone(), reader_names(r), places(r), r.owner.join(", ")]).collect(),
            extra: more(n),
        });
    }
    if !rep.runs.is_empty() {
        let (shown, n) = cap(&rep.runs);
        let w = rep.window.as_ref().map(|(a, b)| format!(" {}..{}", day(a), day(b))).unwrap_or_default();
        out.push(Section {
            title: format!("CI RUNS THAT COULD READ IT ({}{})", rep.runs.len(), if w.is_empty() { String::new() } else { format!(", window{w}") }),
            headers: vec!["REPO", "RUN", "WORKFLOW", "AT", "OWNER"],
            rows: shown.iter().map(|r| vec![r.repo.clone(), format!("#{}", r.id), r.workflow.clone(), r.at.clone(), r.owner.join(", ")]).collect(),
            extra: more(n),
        });
    }
    if !rep.images.is_empty() {
        let (shown, n) = cap(&rep.images);
        out.push(Section {
            title: format!("IMAGES WITH THE NAME IN THEIR ENV ({})", rep.images.len()),
            headers: vec!["IMAGE", "BUILT", "NAME", "OWNER"],
            rows: shown.iter().map(|i| vec![image_ref(i), day(&i.built), i.names.join(", "), i.owner.join(", ")]).collect(),
            extra: Some(format!("  {IN_IMAGE}{}", more(n).map(|m| format!("\n{m}")).unwrap_or_default())),
        });
    }
    if !rep.files.is_empty() {
        let (shown, n) = cap(&rep.files);
        out.push(Section {
            title: format!("FILES AT HEAD THAT NAME IT ({})", rep.files.len()),
            headers: vec!["REPO", "FILE:LINE", "NAME", "OWNER"],
            rows: shown.iter().map(|f| vec![f.repo.clone(), format!("{}:{}", f.file, f.line), f.name.clone(), f.owner.join(", ")]).collect(),
            extra: more(n),
        });
    }
    out
}

pub fn render_table(rep: &SecretReport) -> String {
    let mut out = head(rep);
    for s in sections(rep) {
        out.push(String::new());
        out.push(s.title);
        out.extend(table(&s.headers, &s.rows, 2));
        out.extend(s.extra);
    }
    if !rep.gaps.is_empty() {
        out.push(String::new());
        out.push("NOT CHECKED".into());
        out.extend(rep.gaps.iter().map(|g| format!("  {}", g.1)));
    }
    let to_rotate = rep.to_rotate();
    if !to_rotate.is_empty() {
        out.push(String::new());
        out.push(format!("next: rotate the {} above marked NOT ROTATED, then run this again; br notify {} drafts a message per owner", plural(to_rotate.len(), "secret"), rep.asked_words()));
    }
    out.join("\n")
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

pub fn render_md(rep: &SecretReport) -> String {
    let mut out = vec![format!("# {} {}", rep.verdict(), rep.asked_words()), String::new(), rep.headline(), String::new()];
    out.push(match &rep.cutoff {
        Some(c) => format!("Rotation cutoff {} (from {}). Index as of {}.", day(c), rep.cutoff_src, crate::query::util::fmtz(&rep.as_of)),
        None => format!("No rotation cutoff. Index as of {}.", crate::query::util::fmtz(&rep.as_of)),
    });
    for s in sections(rep) {
        out.push(String::new());
        out.push(format!("## {}", s.title));
        out.push(String::new());
        out.push(format!("| {} |", s.headers.join(" | ")));
        out.push(format!("|{}|", s.headers.iter().map(|_| "---").collect::<Vec<_>>().join("|")));
        for r in &s.rows {
            out.push(format!("| {} |", r.iter().map(|c| md_cell(c)).collect::<Vec<_>>().join(" | ")));
        }
        if let Some(e) = s.extra {
            out.push(String::new());
            out.push(e.trim().to_string());
        }
    }
    if !rep.gaps.is_empty() {
        out.push(String::new());
        out.push("## Not checked".into());
        out.push(String::new());
        out.extend(rep.gaps.iter().map(|g| format!("- {}", g.1)));
    }
    out.join("\n")
}

pub fn render_csv(rep: &SecretReport) -> String {
    let mut rows: Vec<Vec<String>> = vec![["kind", "name", "scope", "where", "file", "line", "updated_at", "rotation", "owner"].iter().map(|s| s.to_string()).collect()];
    for s in &rep.stored {
        let rot = match s.rot {
            crate::query::secret_hunt::Rot::NotRotated => "not-rotated",
            crate::query::secret_hunt::Rot::Rotated => "rotated",
            crate::query::secret_hunt::Rot::Unknown => "unknown",
        };
        rows.push(vec!["secret".into(), s.name.clone(), s.scope.clone(), where_words(s), String::new(), String::new(), s.updated_at.clone().unwrap_or_default(), rot.into(), s.owner.join(" ")]);
    }
    for r in &rep.readers {
        for (f, l) in &r.lines {
            rows.push(vec!["workflow".into(), r.names.join(" "), String::new(), r.repo.clone(), f.clone(), l.to_string(), String::new(), String::new(), r.owner.join(" ")]);
        }
        if r.lines.is_empty() {
            rows.push(vec!["workflow".into(), r.names.join(" "), String::new(), r.repo.clone(), r.file.clone(), String::new(), String::new(), String::new(), r.owner.join(" ")]);
        }
    }
    for r in &rep.runs {
        rows.push(vec!["ci_run".into(), r.names.join(" "), String::new(), r.repo.clone(), r.workflow.clone(), String::new(), r.at.clone(), String::new(), r.owner.join(" ")]);
    }
    for i in &rep.images {
        rows.push(vec![
            "image".into(),
            i.names.join(" "),
            String::new(),
            image_ref(i),
            String::new(),
            String::new(),
            i.built.clone(),
            if i.stale { "old-value-may-be-baked-in".into() } else { String::new() },
            i.owner.join(" "),
        ]);
    }
    for f in &rep.files {
        rows.push(vec!["file".into(), f.name.clone(), String::new(), f.repo.clone(), f.file.clone(), f.line.to_string(), String::new(), String::new(), f.owner.join(" ")]);
    }
    rows.iter().map(|r| r.iter().map(|c| crate::out::sqlcmd::csv_quote(&crate::out::sqlcmd::csv_safe(c))).collect::<Vec<_>>().join(",")).collect::<Vec<_>>().join("\n")
}

/// One line: verdict, what was asked, the count of secrets to rotate, the index time.
pub fn render_quiet(rep: &SecretReport) -> String {
    let mut l = format!("{}  {}  {}", rep.verdict(), rep.asked_words(), count_words(rep));
    if !rep.gaps.is_empty() {
        l += &format!("  {}", plural(rep.gaps.len(), "gap"));
    }
    l + &format!("  index {}", crate::query::util::fmtz(&rep.as_of))
}

fn count_words(rep: &SecretReport) -> String {
    let n = rep.stored.len();
    match &rep.cutoff {
        None => format!("{} stored, rotation not checked", plural(n, "secret")),
        Some(c) if rep.to_rotate().is_empty() && n > 0 => format!("all {n} rotated since {}", day(c)),
        Some(c) => format!("{} of {} not rotated since {}", rep.to_rotate().len(), plural(n, "secret"), day(c)),
    }
}

pub fn summary(rep: &SecretReport, customers: bool) -> String {
    let what = if customers { "the named secrets".to_string() } else { rep.asked_words() };
    let mut s = format!("{}: {what}: {}", rep.verdict(), count_words(rep));
    let stale = rep.stale_images().len();
    if stale > 0 {
        s += &format!("; {} still carry the name in their env", plural(stale, "old image"));
    }
    if !rep.gaps.is_empty() {
        s += &format!("; {} not checked", plural(rep.gaps.len(), "scope"));
    }
    s + &format!(" (index as of {})", crate::query::util::fmtz(&rep.as_of))
}

pub fn render_slack(rep: &SecretReport) -> String {
    let mut out = vec![format!("*{}*  {}  {}  (data as of {})", rep.verdict(), rep.asked_words(), count_words(rep), crate::query::util::fmtz(&rep.as_of))];
    for s in rep.to_rotate().iter().take(SHOW) {
        out.push(format!("• {} ({}, {}): {}", s.name, s.scope, where_words(s), s.rot_words()));
    }
    if !rep.readers.is_empty() {
        out.push(format!("• Read by {}", plural(rep.readers.len(), "workflow")));
    }
    if !rep.images.is_empty() {
        out.push(format!("• {} carry the name in their env: {IN_IMAGE}", plural(rep.images.len(), "image")));
    }
    for g in &rep.gaps {
        out.push(format!("• NOT CHECKED: {}", g.1));
    }
    out.join("\n")
}

// ---- json ---------------------------------------------------------------------------------------------------------

fn rot_word(s: &Stored) -> &'static str {
    match s.rot {
        crate::query::secret_hunt::Rot::NotRotated => "not_rotated",
        crate::query::secret_hunt::Rot::Rotated => "rotated",
        crate::query::secret_hunt::Rot::Unknown => "unknown",
    }
}

pub fn stored_json(s: &Stored) -> J {
    J::obj(vec![
        ("name", J::s(&s.name)),
        ("scope", J::s(&s.scope)),
        ("place", J::s(&s.place)),
        ("repos", J::strs(&s.repos)),
        ("created_at", J::opt(s.created_at.as_deref())),
        ("updated_at", J::opt(s.updated_at.as_deref())),
        ("rotation", J::s(rot_word(s))),
        ("rotation_words", J::s(s.rot_words())),
        ("owner", J::strs(&s.owner)),
        ("read_by", J::strs(&s.used_by)),
    ])
}

pub fn to_json(rep: &SecretReport) -> J {
    let lines = |r: &Reader| J::Arr(r.lines.iter().map(|(f, l)| J::obj(vec![("file", J::s(f)), ("line", J::Int(*l as i64))])).collect());
    J::obj(vec![
        ("indicators", J::strs(&rep.asked)),
        ("verdict", J::s(rep.verdict())),
        ("summary", J::s(rep.headline())),
        ("cutoff", J::opt(rep.cutoff.as_deref())),
        ("cutoff_from", J::s(&rep.cutoff_src)),
        ("index_as_of", J::s(&rep.as_of)),
        (
            "counts",
            J::obj(vec![
                ("stored", J::Int(rep.stored.len() as i64)),
                ("not_rotated", J::Int(rep.to_rotate().len() as i64)),
                ("rotated", J::Int((rep.stored.len() - rep.to_rotate().len()) as i64)),
                ("readers", J::Int(rep.readers.len() as i64)),
                ("runs", J::Int(rep.runs.len() as i64)),
                ("images", J::Int(rep.images.len() as i64)),
                ("files", J::Int(rep.files.len() as i64)),
            ]),
        ),
        ("secrets", J::Arr(rep.stored.iter().map(stored_json).collect())),
        (
            "workflows",
            J::Arr(
                rep.readers
                    .iter()
                    .map(|r| {
                        J::obj(vec![
                            ("repo", J::s(&r.repo)),
                            ("file", J::s(&r.file)),
                            ("names", J::strs(&r.names)),
                            ("reads_every_secret", J::Bool(r.all)),
                            ("lines", lines(r)),
                            ("owner", J::strs(&r.owner)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "runs",
            J::Arr(
                rep.runs
                    .iter()
                    .map(|r| {
                        J::obj(vec![
                            ("repo", J::s(&r.repo)),
                            ("id", J::Int(r.id as i64)),
                            ("workflow", J::s(&r.workflow)),
                            ("at", J::s(&r.at)),
                            ("names", J::strs(&r.names)),
                            ("owner", J::strs(&r.owner)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "images",
            J::Arr(
                rep.images
                    .iter()
                    .map(|i| {
                        J::obj(vec![
                            ("repository", J::s(&i.repository)),
                            ("digest", J::s(&i.digest)),
                            ("tags", J::strs(&i.tags)),
                            ("built", J::s(&i.built)),
                            ("from_repo", J::opt(i.from_repo.as_deref())),
                            ("env_names", J::strs(&i.names)),
                            ("old_value_may_be_baked_in", J::Bool(i.stale)),
                            ("action", J::s(IN_IN_IMAGE_JSON)),
                            ("owner", J::strs(&i.owner)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "files",
            J::Arr(
                rep.files
                    .iter()
                    .map(|f| J::obj(vec![("repo", J::s(&f.repo)), ("file", J::s(&f.file)), ("line", J::Int(f.line as i64)), ("name", J::s(&f.name)), ("owner", J::strs(&f.owner))]))
                    .collect(),
            ),
        ),
        ("not_checked", J::Arr(rep.gaps.iter().map(|g| J::obj(vec![("scope", J::s(&g.0)), ("why", J::s(&g.1))])).collect())),
    ])
}

const IN_IN_IMAGE_JSON: &str = IN_IMAGE;

// ---- sarif --------------------------------------------------------------------------------------------------------

fn rule(id: &str, name: &str, text: &str) -> J {
    J::obj(vec![("id", J::s(id)), ("name", J::s(name)), ("shortDescription", J::obj(vec![("text", J::s(text))]))])
}

fn logical(name: &str, kind: &str) -> J {
    J::Arr(vec![J::obj(vec![("name", J::s(name)), ("fullyQualifiedName", J::s(format!("{kind}:{name}"))), ("kind", J::s(kind))])])
}

fn phys(file: &str, line: Option<u32>) -> J {
    let mut p = J::obj(vec![("artifactLocation", J::obj(vec![("uri", J::s(file))]))]);
    if let Some(l) = line.filter(|l| *l > 0) {
        p.set("region", J::obj(vec![("startLine", J::Int(l as i64))]));
    }
    p
}

pub fn render_sarif(rep: &SecretReport) -> String {
    let mut results: Vec<J> = vec![];
    for s in &rep.stored {
        let (level, id) = if s.to_rotate() { ("error", "br.secret.not-rotated") } else { ("note", "br.secret.rotated") };
        results.push(J::obj(vec![
            ("ruleId", J::s(id)),
            ("level", J::s(level)),
            ("message", J::obj(vec![("text", J::s(format!("Secret {} ({}, {}): {}", s.name, s.scope, where_words(s), s.rot_words())))])),
            ("locations", J::Arr(vec![J::obj(vec![("logicalLocations", logical(&format!("{}/{}", s.place, s.name), "secret"))])])),
            ("properties", J::obj(vec![("scope", J::s(&s.scope)), ("updatedAt", J::opt(s.updated_at.as_deref())), ("rotation", J::s(rot_word(s)))])),
        ]));
    }
    for r in &rep.readers {
        let locs: Vec<J> = if r.lines.is_empty() {
            vec![J::obj(vec![("physicalLocation", phys(&r.file, None)), ("logicalLocations", logical(&r.repo, "repository"))])]
        } else {
            r.lines.iter().map(|(f, l)| J::obj(vec![("physicalLocation", phys(f, Some(*l))), ("logicalLocations", logical(&r.repo, "repository"))])).collect()
        };
        results.push(J::obj(vec![
            ("ruleId", J::s("br.secret.read-by-workflow")),
            ("level", J::s("note")),
            ("message", J::obj(vec![("text", J::s(format!("{} reads {} in {}", r.repo, reader_names(r), r.file)))])),
            ("locations", J::Arr(locs)),
        ]));
    }
    for i in &rep.images {
        results.push(J::obj(vec![
            ("ruleId", J::s("br.secret.in-image-env")),
            ("level", J::s(if i.stale { "error" } else { "warning" })),
            ("message", J::obj(vec![("text", J::s(format!("Image {} carries {} in its env: {IN_IMAGE}", image_ref(i), i.names.join(", "))))])),
            ("locations", J::Arr(vec![J::obj(vec![("logicalLocations", logical(&image_ref(i), "image"))])])),
        ]));
    }
    for f in &rep.files {
        results.push(J::obj(vec![
            ("ruleId", J::s("br.secret.named-in-file")),
            ("level", J::s("note")),
            ("message", J::obj(vec![("text", J::s(format!("{} names {} at line {} (the name only, never a value)", f.file, f.name, f.line)))])),
            ("locations", J::Arr(vec![J::obj(vec![("physicalLocation", phys(&f.file, Some(f.line))), ("logicalLocations", logical(&f.repo, "repository"))])])),
        ]));
    }
    let notes: Vec<J> = rep
        .gaps
        .iter()
        .map(|g| {
            J::obj(vec![
                ("level", J::s("warning")),
                ("message", J::obj(vec![("text", J::s(format!("Not checked: {}", g.1)))])),
                ("locations", J::Arr(vec![J::obj(vec![("logicalLocations", logical(&g.0, "source"))])])),
                ("properties", J::obj(vec![("gap", J::Bool(true))])),
            ])
        })
        .collect();
    let driver = J::obj(vec![
        ("name", J::s("blastradius")),
        ("semanticVersion", J::s(env!("CARGO_PKG_VERSION"))),
        ("informationUri", J::s(crate::out::sarif::INFO_URI)),
        (
            "rules",
            J::Arr(vec![
                rule("br.secret.not-rotated", "SecretNotRotated", "A matching secret was last updated before the rotation cutoff"),
                rule("br.secret.rotated", "SecretRotated", "A matching secret was updated after the rotation cutoff"),
                rule("br.secret.read-by-workflow", "WorkflowReadsSecret", "A workflow at HEAD reads a matching secret"),
                rule("br.secret.in-image-env", "SecretNameInImageEnv", "An image's config env carries a matching name, so the value may be baked in"),
                rule("br.secret.named-in-file", "SecretNamedInFile", "A config file at HEAD names a matching secret"),
            ]),
        ),
    ]);
    let mut run =
        J::obj(vec![("tool", J::obj(vec![("driver", driver)])), ("invocations", J::Arr(vec![J::obj(vec![("executionSuccessful", J::Bool(true)), ("toolExecutionNotifications", J::Arr(notes))])]))]);
    run.set("results", J::Arr(results));
    run.set(
        "properties",
        J::obj(vec![
            (
                "verdict",
                J::s(match rep.verdict() {
                    "FOUND" => "found",
                    "CLEAR" => "clear",
                    _ => "clear_with_gaps",
                }),
            ),
            ("indicators", J::strs(&rep.asked)),
            ("cutoff", J::opt(rep.cutoff.as_deref())),
            ("notChecked", J::Int(rep.gaps.len() as i64)),
            ("indexAsOf", J::s(&rep.as_of)),
        ]),
    );
    J::obj(vec![("$schema", J::s(crate::out::sarif::SCHEMA_URI)), ("version", J::s("2.1.0")), ("runs", J::Arr(vec![run]))]).dumps()
}

// ---- notify: one draft per owning team -----------------------------------------------------------------------------

#[derive(Default)]
pub struct Draft<'a> {
    rotate: Vec<&'a Stored>,
    readers: Vec<&'a Reader>,
    images: Vec<&'a ImageHit>,
    files: Vec<(&'a str, &'a str, u32, &'a str)>,
}

/// The owner as a notify key: a team id or `@login` or `unresolved`.
fn clean(o: &str) -> String {
    o.split(" (suggested").next().unwrap_or(o).to_string()
}

pub fn drafts<'a>(rep: &'a SecretReport) -> BTreeMap<String, Draft<'a>> {
    let mut m: BTreeMap<String, Draft> = BTreeMap::new();
    let owners = |o: &[String]| -> Vec<String> {
        if o.is_empty() {
            vec!["unresolved".to_string()]
        } else {
            o.iter().map(|x| clean(x)).collect()
        }
    };
    for s in rep.to_rotate() {
        if s.is_org() {
            m.entry("org admins".to_string()).or_default().rotate.push(s);
            for t in &s.used_by {
                m.entry(clean(t)).or_default().rotate.push(s);
            }
        } else {
            for o in owners(&s.owner) {
                m.entry(o).or_default().rotate.push(s);
            }
        }
    }
    for r in &rep.readers {
        for o in owners(&r.owner) {
            m.entry(o).or_default().readers.push(r);
        }
    }
    for i in &rep.images {
        for o in owners(&i.owner) {
            m.entry(o).or_default().images.push(i);
        }
    }
    for f in &rep.files {
        for o in owners(&f.owner) {
            m.entry(o).or_default().files.push((&f.repo, &f.file, f.line, &f.name));
        }
    }
    m
}

pub fn notify_text(rep: &SecretReport, headers: &dyn Fn(&str) -> String, fm: &str) -> String {
    if fm == "json" {
        let d = drafts(rep);
        return J::Arr(
            d.iter()
                .map(|(k, v)| {
                    J::obj(vec![
                        ("to", J::s(k)),
                        ("rotate", J::Arr(v.rotate.iter().map(|s| stored_json(s)).collect())),
                        ("workflows", J::Arr(v.readers.iter().map(|r| J::obj(vec![("repo", J::s(&r.repo)), ("places", J::s(places(r)))])).collect())),
                        ("images", J::Arr(v.images.iter().map(|i| J::s(image_ref(i))).collect())),
                    ])
                })
                .collect(),
        )
        .dumps()
            + "\n";
    }
    let mut out: Vec<String> = vec![format!("{}  {}  {}", rep.verdict(), rep.asked_words(), count_words(rep)), String::new()];
    let d = drafts(rep);
    let mut orphan = false;
    for (to, v) in &d {
        if v.rotate.is_empty() && v.images.iter().all(|i| !i.stale) {
            continue;
        }
        if to == "unresolved" {
            orphan = true;
            continue;
        }
        let head = match v.rotate.iter().find(|s| s.is_org()) {
            Some(s) if to == "org admins" => format!("To the {}", s.owner.first().cloned().unwrap_or_else(|| "org admins".into())),
            _ => headers(to),
        };
        out.extend(one_draft(rep, &head, v, to == "org admins"));
        out.push(String::new());
    }
    if orphan {
        let v = &d["unresolved"];
        out.push("NO OWNER FOUND".into());
        for s in &v.rotate {
            out.push(format!("  - {} ({}, {}): {}", s.name, s.scope, s.place, s.rot_words()));
        }
        for i in v.images.iter().filter(|i| i.stale) {
            out.push(format!("  - image {}: {IN_IMAGE}", image_ref(i)));
        }
        out.push("  find the owner (br owners), or rotate these yourself".into());
        out.push(String::new());
    }
    if d.is_empty() || out.len() <= 2 {
        out.push(match &rep.cutoff {
            Some(c) if rep.stored.is_empty() => format!("Nothing to send: no secret matching {} is stored where this token can see (cutoff {}).", rep.asked_words(), day(c)),
            Some(c) => format!("Nothing to send: all {} rotated since {}.", rep.stored.len(), day(c)),
            None => "Nothing to send yet: pass --since DATE so br can tell which secrets were not rotated.".to_string(),
        });
        out.push(String::new());
    }
    for g in &rep.gaps {
        out.push(format!("NOT CHECKED: {}", g.1));
    }
    out.join("\n").trim_end().to_string() + "\n"
}

fn one_draft(rep: &SecretReport, header: &str, v: &Draft, admins: bool) -> Vec<String> {
    let mut out = vec![header.to_string()];
    let since = rep.cutoff.as_deref().map(|c| format!(" since {}", day(c))).unwrap_or_default();
    out.push(if admins {
        format!("Hi, these org secrets matching {} are not rotated{since}. You own them as org admins, so rotating them is yours; the teams whose workflows read each are listed.", rep.asked_words())
    } else {
        format!("Hi, these secrets matching {} were not rotated{since}. Rotate them where they are stored, then rebuild what carries them.", rep.asked_words())
    });
    if !v.rotate.is_empty() {
        out.push("Secrets to rotate:".into());
        for s in &v.rotate {
            let who = if s.is_org() && !admins { format!("; the org admins rotate it ({})", s.owner.join(", ")) } else { String::new() };
            out.push(format!("  - {}: {} ({}), {}{who}", s.name, s.scope, s.place, s.rot_words()));
        }
    }
    if !v.readers.is_empty() {
        out.push("Workflows that read them:".into());
        for r in v.readers.iter().take(SHOW) {
            out.push(format!("  - {} {} ({})", r.repo, places(r), reader_names(r)));
        }
    }
    let imgs: Vec<&&ImageHit> = v.images.iter().filter(|i| i.stale).collect();
    if !imgs.is_empty() {
        out.push(format!("Images to rebuild ({IN_IMAGE}):"));
        for i in imgs {
            out.push(format!("  - {} ({}, built {})", image_ref(i), i.names.join(", "), day(&i.built)));
        }
    }
    if !v.files.is_empty() {
        out.push("Files that name them (names only):".into());
        for (r, f, l, n) in v.files.iter().take(SHOW) {
            out.push(format!("  - {r} {f}:{l} {n}"));
        }
    }
    out
}

/// The statement and per-secret lines the evidence file seals.
pub fn evidence_statement(rep: &SecretReport) -> String {
    let n = rep.stored.len();
    match &rep.cutoff {
        None => format!("{} of {} are stored; no rotation cutoff was given, so rotation was not assessed.", rep.asked_words(), plural(n, "matching secret")),
        Some(c) if n == 0 => format!("No secret matching {} is stored in the scopes br could read. This is a statement about what the index holds.", rep.asked_words()),
        Some(c) if rep.to_rotate().is_empty() => format!("All {n} secrets matching {} were rotated since {}.", rep.asked_words(), day(c)),
        Some(c) => format!("{} of {} secrets matching {} were NOT rotated since {}.", rep.to_rotate().len(), n, rep.asked_words(), day(c)),
    }
}

pub fn evidence_md(rep: &SecretReport, generated: &str, case_id: Option<&str>, requested_by: Option<&str>) -> String {
    let mut out = vec![format!("# Secret rotation evidence: {}", rep.asked_words()), String::new()];
    out.push(format!("Generated {generated}. Index as of {}.", crate::query::util::fmtz(&rep.as_of)));
    if let Some(c) = case_id {
        out.push(format!("Case {c}."));
    }
    if let Some(r) = requested_by {
        out.push(format!("Requested by {r}."));
    }
    out.push(String::new());
    out.push(format!("## Verdict: {}", rep.verdict()));
    out.push(String::new());
    out.push(evidence_statement(rep));
    out.push(match &rep.cutoff {
        Some(c) => format!("Rotation cutoff: {} (from {}). A secret last updated before it is NOT ROTATED.", day(c), rep.cutoff_src),
        None => "Rotation cutoff: none given.".to_string(),
    });
    out.push(String::new());
    out.push("## Secrets (names, scopes, last update; never values)".into());
    out.push(String::new());
    out.push("| Secret | Scope | Where | Last updated | State |".into());
    out.push("|---|---|---|---|---|".into());
    for s in &rep.stored {
        out.push(format!("| {} | {} | {} | {} | {} |", s.name, s.scope, md_cell(&where_words(s)), s.last_update(), s.rot_words()));
    }
    if !rep.images.is_empty() {
        out.push(String::new());
        out.push("## Images whose env carries the name".into());
        out.push(String::new());
        for i in &rep.images {
            out.push(format!("- {} built {}: {}", image_ref(i), day(&i.built), if i.stale { IN_IMAGE } else { "built after the cutoff; the name is still in its env" }));
        }
    }
    out.push(String::new());
    out.push("## Not checked".into());
    out.push(String::new());
    if rep.gaps.is_empty() {
        out.push("Nothing: every secret list in scope was readable.".into());
    } else {
        out.extend(rep.gaps.iter().map(|g| format!("- {}", g.1)));
    }
    out.push(String::new());
    out.push("## Limits".into());
    out.push(String::new());
    out.push("- GitHub reports when a secret was last updated, not what it holds; a secret updated after the cutoff is taken as rotated.".into());
    out.push("- Only secrets stored in GitHub are listed. A copy kept in a vault, a cloud console or a laptop is not seen here.".into());
    out.push("- The index holds names, dates and metadata; it holds no secret value.".into());
    out.join("\n") + "\n"
}

pub fn evidence_json(rep: &SecretReport) -> J {
    J::obj(vec![
        ("result", J::s(if rep.found() { "found" } else { "none_observed" })),
        ("verdict", J::s(rep.verdict())),
        ("statement", J::s(evidence_statement(rep))),
        ("cutoff", J::opt(rep.cutoff.as_deref())),
        ("cutoff_from", J::s(&rep.cutoff_src)),
        ("stored", J::Int(rep.stored.len() as i64)),
        ("not_rotated", J::Int(rep.to_rotate().len() as i64)),
        ("secrets", J::Arr(rep.stored.iter().map(stored_json).collect())),
        (
            "images",
            J::Arr(
                rep.images
                    .iter()
                    .map(|i| J::obj(vec![("image", J::s(image_ref(i))), ("built", J::s(&i.built)), ("env_names", J::strs(&i.names)), ("old_value_may_be_baked_in", J::Bool(i.stale))]))
                    .collect(),
            ),
        ),
        ("not_checked", J::Arr(rep.gaps.iter().map(|g| J::obj(vec![("scope", J::s(&g.0)), ("why", J::s(&g.1))])).collect())),
    ])
}
