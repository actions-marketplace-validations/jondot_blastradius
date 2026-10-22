//! What happens to a claimcheck result after `br claimcheck` has printed it: a snapshot to compare with later
//! (`br claimcheck --record`, `br diff --claimcheck`), one message per owning team (`br notify --claimcheck`), and a sealed
//! evidence file with a customer statement (`br evidence --claimcheck`). Every function here takes the finished `Report`;
//! the questions to public registries are asked once, in `claimcheck::build`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::cli::{DiffArgs, EvidenceArgs, NotifyArgs};
use crate::cmd::claimcheck::{self as cc, Report};
use crate::collect::brx;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::query::claims::{self, Row, Status, Strength};

// ---- snapshots ---------------------------------------------------------------------------------------------------
pub fn snap_dir(ctx: &Ctx) -> PathBuf {
    ctx.home.join("claimcheck")
}

fn key_of(r: &Row) -> String {
    format!("{}:{}", if r.is_scope { "npm-scope" } else { r.eco.word() }, r.name)
}

pub fn snapshot_json(rep: &Report) -> Value {
    json!({
        "schema": "br-claimcheck-snapshot/1",
        "clock": rep.now,
        "as_of": rep.as_of,
        "as_of_at": rep.as_of_at,
        "index": cc::index_line(rep),
        "sample_registry": rep.sample,
        "verdict": rep.verdict(),
        "counts": cc::counts_json(rep),
        "names": rep.rows.iter().map(|r| json!({
            "key": key_of(r), "name": r.name, "ecosystem": r.eco.word(), "scope": r.is_scope, "status": r.status.word(),
            "ours_strength": r.strength.map(|s| s.key()), "flags": r.flags.iter().map(|f| f.key()).collect::<Vec<_>>(),
            "public_max": r.public_max, "owners": r.owners,
        })).collect::<Vec<_>>(),
    })
}

/// Store the run under BR_HOME/claimcheck/CLOCK.json. This is the only thing claimcheck ever writes, and only with --record.
pub fn record(ctx: &Ctx, rep: &Report) -> BrResult<PathBuf> {
    let dir = snap_dir(ctx);
    let fail = |e: std::io::Error, p: &std::path::Path| BrError::with_code(format!("cannot write {}: {e}", p.display()), Some("check that BR_HOME is writable"), 1);
    std::fs::create_dir_all(&dir).map_err(|e| fail(e, &dir))?;
    let path = dir.join(format!("{}.json", rep.now.replace([':', ' '], "-")));
    let text = serde_json::to_string_pretty(&snapshot_json(rep)).unwrap_or_default();
    std::fs::write(&path, text + "\n").map_err(|e| fail(e, &path))?;
    Ok(path)
}

/// The newest snapshot recorded at or before `at` (or the newest of all). Err: there is none.
pub fn load_snapshot(ctx: &Ctx, at: Option<&str>) -> BrResult<Value> {
    let dir = snap_dir(ctx);
    let mut all: Vec<Value> = vec![];
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if let Some(v) = std::fs::read_to_string(e.path()).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
                if v["schema"] == "br-claimcheck-snapshot/1" {
                    all.push(v);
                }
            }
        }
    }
    all.sort_by(|a, b| a["clock"].as_str().cmp(&b["clock"].as_str()));
    let pick = match at {
        Some(t) => {
            let cut: String = t.chars().take(19).collect();
            all.iter().rev().find(|v| v["clock"].as_str().map(|c| c.chars().take(19).collect::<String>() <= cut).unwrap_or(false)).cloned()
        }
        None => all.last().cloned(),
    };
    pick.ok_or_else(|| match (at, all.first()) {
        (Some(t), Some(first)) => BrError::with_code(
            format!("no claimcheck snapshot was recorded at or before {t}"),
            Some(&format!("the earliest is {}; record one with br claimcheck --record", first["clock"].as_str().unwrap_or("?"))),
            5,
        ),
        _ => BrError::with_code("no claimcheck snapshot has been recorded yet", Some("br claimcheck --record stores one; run it again later and br diff --claimcheck shows what changed"), 5),
    })
}

// ---- diff --------------------------------------------------------------------------------------------------------
pub struct Change {
    pub group: &'static str,
    pub line: String,
    pub name: String,
}

/// Forward: what happened since the snapshot.
const GROUPS: &[(&str, &str)] = &[
    ("newly_squatted", "NEWLY SQUATTED: a public package now has a name you use, and nothing shows it is yours"),
    ("newly_free", "NEWLY FREE: no public package has this name, and it is now open"),
    ("newly_unclaimed_scope", "NEWLY UNCLAIMED SCOPE"),
    ("now_ours", "NOW OURS: shown to be yours"),
    ("newly_not_checked", "NEWLY NOT CHECKED"),
    ("changed", "CHANGED: same status, different facts"),
    ("no_longer_listed", "NO LONGER LISTED: not found in the sources this time"),
];

/// Backward (the run is as of a date before the snapshot's): differences between two dates, never "newly".
const GROUPS_BACK: &[(&str, &str)] = &[
    ("then_squatted", "SQUATTED ON THE EARLIER DATE: a public package already had the name then, and nothing showed it was yours"),
    ("then_free", "FREE ON THE EARLIER DATE: no public package had the name then"),
    ("then_unclaimed_scope", "UNCLAIMED SCOPE ON THE EARLIER DATE"),
    ("then_ours", "OURS ON THE EARLIER DATE: shown to be yours"),
    ("then_not_checked", "NOT CHECKED THIS TIME"),
    ("changed", "CHANGED: same status, different facts"),
    ("not_yet_listed", "NOT YET LISTED ON THE EARLIER DATE: in the snapshot, not in the sources then"),
];

fn cut19(t: &str) -> String {
    t.chars().take(19).collect()
}

/// The instant a snapshot (or a run) describes: its `--as-of` instant, else its clock.
fn snap_effective(v: &Value) -> String {
    let clock = v["clock"].as_str().unwrap_or("").to_string();
    if let Some(a) = v["as_of_at"].as_str() {
        return a.to_string();
    }
    match v["as_of"].as_str().map(str::trim) {
        Some(d) if d.len() == 10 => format!("{d}T23:59:59Z"),
        Some(d) => crate::collect::util::norm_iso(d).unwrap_or(clock),
        None => clock,
    }
}

fn run_effective(rep: &Report) -> String {
    rep.as_of_at.clone().unwrap_or_else(|| rep.now.clone())
}

/// Does this run describe an earlier date than the snapshot? Then a difference is not something that happened since.
pub fn is_backward(old: &Value, rep: &Report) -> bool {
    cut19(&run_effective(rep)) < cut19(&snap_effective(old))
}

pub fn changes(old: &Value, rep: &Report) -> (Vec<Change>, usize) {
    let back = is_backward(old, rep);
    let (then_day, now_day): (String, String) = (snap_effective(old).chars().take(10).collect(), run_effective(rep).chars().take(10).collect());
    let mut before: BTreeMap<String, &Value> = BTreeMap::new();
    for n in old["names"].as_array().into_iter().flatten() {
        if let Some(k) = n["key"].as_str() {
            before.insert(k.to_string(), n);
        }
    }
    let mut out = vec![];
    let mut same = 0usize;
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();
    for r in &rep.rows {
        let k = key_of(r);
        seen_keys.insert(k.clone());
        let was = before.get(&k).and_then(|o| o["status"].as_str()).map(str::to_string);
        let now = r.status.word();
        let owner = cc::owner_label(r);
        let mk =
            |group: &'static str, text: String| Change { group, line: format!("{}  {}  {} (owner: {owner})", if r.is_scope { "npm scope" } else { r.eco.word() }, r.name, text), name: r.name.clone() };
        let from = if back {
            match &was {
                Some(w) => format!("the snapshot, for {then_day}, has it as {w}; on {now_day} it was"),
                None => format!("not in the snapshot (for {then_day}); on {now_day} it was"),
            }
        } else {
            was.clone().map(|w| format!("was {w}, now")).unwrap_or_else(|| "not listed before, now".to_string())
        };
        if was.as_deref() == Some(now) {
            let o = before[&k];
            let old_flags: Vec<String> = o["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str().map(str::to_string)).collect();
            let new_flags: Vec<String> = r.flags.iter().map(|f| f.key().to_string()).collect();
            let old_max = o["public_max"].as_str().map(str::to_string);
            let old_strength = o["ours_strength"].as_str().map(str::to_string);
            let mut diffs = vec![];
            if old_max != r.public_max {
                diffs.push(format!("public version {} -> {}", old_max.unwrap_or_else(|| "none".into()), r.public_max.clone().unwrap_or_else(|| "none".into())));
            }
            for f in new_flags.iter().filter(|f| !old_flags.contains(f)) {
                diffs.push(format!("{} flag {f}", if back { "extra" } else { "new" }));
            }
            if old_strength != r.strength.map(|s| s.key().to_string()) && r.status == Status::Ours {
                diffs.push(format!("proof {} -> {}", old_strength.unwrap_or_else(|| "none".into()), r.strength.map(|s| s.key()).unwrap_or("none")));
            }
            if diffs.is_empty() {
                same += 1;
            } else {
                out.push(mk("changed", format!("{now}: {}", diffs.join("; "))));
            }
            continue;
        }
        let (group, text) = match (r.status, back) {
            (Status::Squatted, false) => ("newly_squatted", format!("{from} SQUATTED: {}", claims::plain(r))),
            (Status::Free, false) => ("newly_free", format!("{from} FREE: {}", claims::plain(r))),
            (Status::ScopeUnclaimed, false) => ("newly_unclaimed_scope", format!("{from} SCOPE UNCLAIMED: {}", claims::plain(r))),
            (Status::Ours, false) => ("now_ours", format!("{from} OURS ({})", r.strength.map(|s| s.words()).unwrap_or(""))),
            (Status::NotChecked, false) => ("newly_not_checked", format!("{from} NOT CHECKED: {}", claims::plain(r))),
            (Status::Squatted, true) => ("then_squatted", format!("{from} SQUATTED: {}", claims::plain(r))),
            (Status::Free, true) => ("then_free", format!("{from} FREE: {}", claims::plain(r))),
            (Status::ScopeUnclaimed, true) => ("then_unclaimed_scope", format!("{from} SCOPE UNCLAIMED: {}", claims::plain(r))),
            (Status::Ours, true) => ("then_ours", format!("{from} OURS ({})", r.strength.map(|s| s.words()).unwrap_or(""))),
            (Status::NotChecked, true) => ("then_not_checked", format!("{from} NOT CHECKED: {}", claims::plain(r))),
        };
        out.push(mk(group, text));
    }
    for (k, o) in &before {
        if !seen_keys.contains(k) {
            out.push(Change {
                group: if back { "not_yet_listed" } else { "no_longer_listed" },
                line: format!(
                    "{}  {}  {} {}",
                    o["ecosystem"].as_str().unwrap_or(""),
                    o["name"].as_str().unwrap_or(k),
                    if back { "is in the snapshot as" } else { "was" },
                    o["status"].as_str().unwrap_or("")
                ),
                name: o["name"].as_str().unwrap_or(k).to_string(),
            });
        }
    }
    (out, same)
}

pub fn diff(a: &DiffArgs, ctx: &Ctx) -> BrResult<i32> {
    no_incident_input(&a.q.iocs, &a.q.advisory, &a.q.text)?;
    if a.last && a.since.is_some() {
        return Err(BrError::new("--last and --since together", Some("choose one: --last compares with the newest snapshot")));
    }
    let at = match &a.since {
        Some(s) => Some(crate::collect::util::norm_iso(s)?),
        None => None,
    };
    let old = load_snapshot(ctx, at.as_deref())?;
    let rep = cc::build(ctx, &a.cc.args(a.q.repo.as_ref()))?;
    let (list, same) = changes(&old, &rep);
    let back = is_backward(&old, &rep);
    let groups_table = if back { GROUPS_BACK } else { GROUPS };
    let then = old["clock"].as_str().unwrap_or("?").to_string();
    let (then_day, now_day): (String, String) = (snap_effective(&old).chars().take(10).collect(), run_effective(&rep).chars().take(10).collect());
    let n = list.len();
    if a.format.as_deref() == Some("json") {
        let mut groups = serde_json::Map::new();
        for (g, _) in groups_table {
            groups.insert((*g).to_string(), json!(list.iter().filter(|c| c.group == *g).map(|c| c.name.clone()).collect::<Vec<_>>()));
        }
        let v = json!({"command": "diff --claimcheck", "since": then, "snapshot_describes": snap_effective(&old), "now": rep.now, "run_describes": run_effective(&rep), "direction": if back { "backward" } else { "forward" },
            "changes": n, "unchanged": same, "groups": groups, "lines": list.iter().map(|c| json!({"group": c.group, "line": c.line})).collect::<Vec<_>>(),
            "headline": cc::headline(&rep), "not_checked": rep.not_checked_names(), "index": cc::index_line(&rep)});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(0);
    }
    let mut o = if back {
        vec![
            format!("CLAIMCHECK DIFF  the snapshot recorded at {then} describes {then_day}; this run describes {now_day} (--as-of), which is EARLIER{}", rep.reg()),
            format!("Going back in time: nothing below is new. Each line says how {now_day} differs from the snapshot for {then_day}."),
        ]
    } else {
        vec![format!("CLAIMCHECK DIFF  since the snapshot recorded at {then}; now {}{}", rep.now, rep.reg())]
    };
    o.push(cc::index_line(&rep));
    if list.is_empty() {
        o.push(format!("Nothing {}: {same} {} the same as in the snapshot.", if back { "differs" } else { "changed" }, if same == 1 { "name is" } else { "names are" }));
    } else if back {
        o.push(format!("{} between the two dates ({same} the same).", if n == 1 { "1 difference".to_string() } else { format!("{n} differences") }));
    } else {
        o.push(format!("{} since the snapshot ({same} unchanged).", if n == 1 { "1 change".to_string() } else { format!("{n} changes") }));
    }
    for (g, title) in groups_table {
        let rows: Vec<&Change> = list.iter().filter(|c| c.group == *g).collect();
        if rows.is_empty() {
            continue;
        }
        o.push(String::new());
        o.push(format!("{title} ({})", rows.len()));
        o.extend(rows.iter().map(|c| format!("  {}", c.line)));
    }
    o.push(String::new());
    o.push(format!("Now: {}", cc::headline(&rep)));
    if let Some(t) = cc::not_checked_text(&rep) {
        o.push(t);
    }
    o.push("br only read. It published, claimed and changed nothing.".into());
    println!("{}", o.join("\n"));
    Ok(0)
}

// ---- notify ------------------------------------------------------------------------------------------------------
fn no_incident_input(iocs: &[String], adv: &Option<String>, text: &Option<String>) -> BrResult<()> {
    if !iocs.is_empty() || adv.is_some() || text.is_some() {
        return Err(BrError::new("--claimcheck takes no indicator, --advisory or --text", Some("drop them: the names come from your manifests, not from an incident")));
    }
    Ok(())
}

/// "To #billing (@acme/billing, lead Jo Lee)" for a team the index knows; a person; or the words for a name with no owner.
fn header_for(view: Option<&crate::view::View>, owner: &str) -> (String, Option<String>) {
    if owner == "unresolved" {
        return ("To nobody br can name (no CODEOWNERS owner it can resolve for the repos these names were seen in)".into(), None);
    }
    if let Some(t) = view.and_then(|v| v.teams.iter().find(|t| t.id == owner)) {
        let lead = t.lead.as_ref().filter(|l| !l.is_empty()).map(|l| view.and_then(|v| v.people.iter().find(|p| &p.login == l)).and_then(|p| p.name.clone()).unwrap_or_else(|| l.clone()));
        let slack = t.slack.clone().unwrap_or_else(|| owner.to_string());
        let head = match lead {
            Some(l) => format!("To {slack} ({owner}, lead {l})"),
            None => format!("To {slack} ({owner})"),
        };
        return (head, t.jira.clone());
    }
    (format!("To {owner}"), None)
}

/// The rows each owner is told about: its exposed names and the names it owns that could not be checked.
pub fn by_owner(rep: &Report) -> BTreeMap<String, Vec<&Row>> {
    let mut m: BTreeMap<String, Vec<&Row>> = BTreeMap::new();
    for r in rep.rows.iter().filter(|r| r.status.exposed() || r.status == Status::NotChecked) {
        if r.owners.is_empty() {
            m.entry("unresolved".into()).or_default().push(r);
        }
        for o in &r.owners {
            m.entry(o.clone()).or_default().push(r);
        }
    }
    for v in m.values_mut() {
        v.sort_by_key(|a| (claims::urgency(a), a.name.clone()));
    }
    m
}

fn bullet(r: &Row, rep: &Report, md: bool) -> String {
    let seen: Vec<String> = r.seen.iter().take(2).map(|s| s.show()).collect();
    let flags = if r.flags.is_empty() { String::new() } else { format!(" [{}]", r.flags.iter().map(|f| f.key()).collect::<Vec<_>>().join(", ")) };
    let name = if md { format!("`{}`", r.name) } else { r.name.clone() };
    format!("- {name} ({}): {}{flags}. Seen in {}{}", if r.is_scope { "npm scope" } else { r.eco.word() }, claims::plain(r), seen.join("; "), if rep.sample { " (sample registry)" } else { "" })
}

fn team_text(view: Option<&crate::view::View>, owner: &str, rows: &[&Row], rep: &Report, fm: &str) -> String {
    let (head, jira) = header_for(view, owner);
    let md = fm != "slack";
    let nx = rows.iter().filter(|r| r.status.exposed()).count();
    let nc = rows.iter().filter(|r| r.status == Status::NotChecked).count();
    let mut o = vec![head];
    if fm == "jira" {
        if let Some(j) = jira {
            o.push(format!("Jira project: {j}"));
        }
    }
    let as_of = rep.as_of.clone().map(|d| format!(", as of {d}")).unwrap_or_default();
    let mut intro = format!(
        "Hi team, br checked the package names your repos resolve privately against the public registries for dependency confusion{}, on {}{as_of}. {} {} exposed: a public registry already has the name, or nobody holds it there.",
        rep.reg(),
        rep.now.chars().take(10).collect::<String>(),
        cc::names_word(nx),
        if nx == 1 { "is" } else { "are" }
    );
    intro += &format!(" {}.", cc::index_line(rep));
    if nc > 0 {
        intro += &format!(" {} could not be checked, so they are not cleared.", cc::names_word(nc));
    }
    o.push(intro);
    o.push(String::new());
    for r in rows {
        o.push(bullet(r, rep, md));
    }
    let g = cc::guidance_for(rows);
    if !g.is_empty() {
        o.push(String::new());
        o.push("What to do".into());
        o.extend(g.iter().map(|x| format!("- {x}")));
    }
    o.push(String::new());
    o.push("br only read; it published, claimed and changed nothing.".into());
    o.join("\n")
}

pub fn notify(a: &NotifyArgs, ctx: &Ctx) -> BrResult<i32> {
    use crate::out::actions as A;
    no_incident_input(&a.q.iocs, &a.q.advisory, &a.q.text)?;
    let fm = a.format.clone().unwrap_or_else(|| "slack".into());
    if !["slack", "jira", "md", "json"].contains(&fm.as_str()) {
        return Err(BrError::new(format!("unknown format \"{fm}\""), Some("choose slack, jira, md or json")));
    }
    let path = A::prepare_out(&a.out, true)?;
    let rep = cc::build(ctx, &a.cc.args(a.q.repo.as_ref()))?;
    let view = ctx.view().ok();
    let mut groups = by_owner(&rep);
    if let Some(want) = a.q.owner.as_ref().map(|o| o.trim_start_matches('@').to_lowercase()) {
        groups.retain(|k, _| k.to_lowercase().contains(&want));
    }
    // a team with only names that could not be checked is not told to act; it is counted in the last line
    let told: Vec<(&String, &Vec<&Row>)> = groups.iter().filter(|(_, v)| v.iter().any(|r| r.status.exposed())).collect();
    let text = if fm == "json" {
        let v = json!({
            "command": "notify --claimcheck", "clock": rep.now, "headline": cc::headline(&rep),
            "messages": told.iter().map(|(o, rows)| json!({
                "to": header_for(view.as_ref(), o).0, "owner": o,
                "names": rows.iter().map(|r| json!({"name": r.name, "status": r.status.word(), "what_it_means": claims::plain(r)})).collect::<Vec<_>>(),
                "what_to_do": cc::guidance_for(rows),
            })).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&v).unwrap_or_default() + "\n"
    } else if told.is_empty() {
        format!("No name is exposed, so there is nothing to tell any team.\n{}\n", cc::headline(&rep))
    } else {
        let mut parts: Vec<String> = told.iter().map(|(o, rows)| team_text(view.as_ref(), o, rows, &rep, &fm)).collect();
        let quiet: Vec<&String> = groups.iter().filter(|(_, v)| !v.iter().any(|r| r.status.exposed())).map(|(k, _)| k).collect();
        let mut last = format!(
            "In all: {} for {}; {} not checked.",
            cc::names_word(rep.n_exposed()),
            if told.len() == 1 { "1 team".to_string() } else { format!("{} teams", told.len()) },
            cc::names_word(rep.not_checked_names())
        );
        if !quiet.is_empty() {
            last += &format!(" Not drafted (only names that could not be checked): {}.", quiet.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
        }
        parts.push(last);
        parts.join("\n\n---\n\n") + "\n"
    };
    A::emit(&path, text)?;
    Ok(0)
}

// ---- evidence ----------------------------------------------------------------------------------------------------
/// The first sentence of the statement: the answer to "are you exposed to dependency confusion?" in the customer's terms.
pub fn answer_sentence(rep: &Report) -> String {
    let day: String = rep.now.chars().take(10).collect();
    let when = match &rep.as_of {
        Some(d) => format!("as of {d}"),
        None => format!("on {day}"),
    };
    let checked = rep.rows.iter().filter(|r| r.status != Status::NotChecked).count();
    let nx = rep.n_exposed();
    let nc = rep.not_checked_names();
    let dec = rep.ours_by(Strength::Declared);
    if nx > 0 {
        let mut p = vec![];
        for (s, w) in [
            (Status::Squatted, "already on a public registry and not shown to be ours"),
            (Status::Free, "not taken, so open to whoever can publish them"),
            (Status::ScopeUnclaimed, "under an npm scope that is not shown to be ours"),
        ] {
            let n = rep.count(s);
            if n > 0 {
                p.push(format!("{n} {w}"));
            }
        }
        format!(
            "Yes: {when}, {} that we use inside our own systems {} exposed to dependency confusion on a public registry ({}).",
            cc::names_word(nx),
            if nx == 1 { "is" } else { "are" },
            p.join("; ")
        )
    } else if nc > 0 {
        format!("Not that we found, but this is not a full answer: {when}, none of the {checked} names we checked was exposed, and {} could not be checked.", cc::names_word(nc))
    } else if dec > 0 {
        format!("Not that we found, but {} of the {checked} we checked {} ours only by the publisher's word.", cc::names_word(dec), if dec == 1 { "is" } else { "are" })
    } else {
        format!("No: {when}, none of the {checked} package names we use inside our own systems was exposed to dependency confusion on a public registry.")
    }
}

fn md_of_evidence(rep: &Report, answer: &str, q: Option<&str>, received: Option<&str>, case: Option<&str>) -> String {
    let mut o = vec!["# Dependency-confusion evidence".to_string(), String::new(), answer.to_string(), String::new()];
    match (q, received) {
        (Some(q), Some(r)) => o.push(format!("The question, received {}: {}", r.chars().take(10).collect::<String>(), q.trim())),
        (Some(q), None) => o.push(format!("The question: {}", q.trim())),
        _ => {}
    }
    if let Some(c) = case {
        o.push(format!("Case: {c}"));
    }
    o.push(String::new());
    o.push(format!("Verdict: **{}**", cc::headline(rep)));
    let ours: Vec<&Row> = rep.rows.iter().filter(|r| r.status == Status::Ours).collect();
    if !ours.is_empty() {
        o.push(String::new());
        o.push("## OURS, with the proof for each".into());
        o.push(String::new());
        o.push("| NAME | HOW STRONG | PROOF |".into());
        o.push("|---|---|---|".into());
        for r in ours {
            o.push(format!("| {} `{}` | {} | {} |", r.eco.word(), r.name, r.strength.map(|s| s.words()).unwrap_or(""), r.proof.clone().unwrap_or_default().replace('|', "/")));
        }
    }
    o.push(String::new());
    o.push("## The full result".into());
    o.push(String::new());
    o.push(cc::render_md(rep));
    o.join("\n")
}

fn customers_md(rep: &Report, answer: &str, q: Option<&str>, received: Option<&str>, case: Option<&str>, file: &str, sha: &str) -> String {
    let mut o = vec!["# Statement on dependency confusion".to_string(), String::new(), answer.to_string(), String::new()];
    match (q, received) {
        (Some(q), Some(r)) => o.push(format!("Your question, received {}: {}", r.chars().take(10).collect::<String>(), q.trim())),
        (Some(q), None) => o.push(format!("Your question: {}", q.trim())),
        _ => {}
    }
    o.push(String::new());
    o.push("## What was checked".into());
    o.push(format!(
        "We read the package manifests, lockfiles and registry settings of {}, then asked the public package registries{} whether anyone else holds each package name we resolve privately. The questions were read-only: nothing was published, claimed or changed.",
        cc::sources_words(rep),
        rep.reg()
    ));
    o.push(format!(
        "This statement is dated {}{}. {}.",
        rep.now.chars().take(10).collect::<String>(),
        rep.as_of.as_ref().map(|d| format!(" and describes the position as of {d}")).unwrap_or_default(),
        cc::index_line(rep)
    ));
    o.push(String::new());
    o.push("## The result".into());
    o.push(format!("- {}", cc::headline(rep)));
    o.push(format!("- Names shown to be ours: {} verified by the registry, {} resting on what the package's publisher declared.", rep.ours_by(Strength::Verified), rep.ours_by(Strength::Declared)));
    o.push(format!("- Names not checked: {}.", rep.not_checked_names()));
    let treated = rep.treated_public;
    if treated > 0 {
        o.push(format!("- Dependencies treated as public and not asked about: {treated}."));
    }
    o.push(String::new());
    o.push("## What this does not cover".into());
    o.extend(cc::limits_plain(rep).iter().map(|x| format!("- {x}")));
    o.push(String::new());
    if let Some(c) = case {
        o.push(format!("Case: {c}"));
    }
    o.push(format!("Evidence file: {file} (sha256 {sha}); it is sealed, and br verify checks it. Generated {}.", rep.now));
    o.join("\n")
}

pub fn evidence(a: &EvidenceArgs, ctx: &Ctx) -> BrResult<i32> {
    use crate::cmd::evidence as E;
    no_incident_input(&a.q.iocs, &a.q.advisory, &a.q.text)?;
    let Some(out_arg) = a.out.clone().filter(|o| !o.is_empty()) else {
        return Err(BrError::new("evidence needs --out FILE", Some("example: br evidence --claimcheck --out claimcheck.json")));
    };
    let (out_path, md_path) = E::out_paths(&out_arg)?;
    let question = a.question.clone().map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    let received = match a.received.as_ref().map(|r| r.trim()).filter(|r| !r.is_empty()) {
        Some(r) => Some(crate::collect::util::norm_iso(r).map_err(|_| BrError::with_code(format!("--received {r} is not a date"), Some("write it with its year, e.g. --received 2026-05-09"), 2))?),
        None => None,
    };
    if a.sign.is_some() && a.no_seal {
        return Err(BrError::new("--sign needs a seal to sign", Some("drop --no-seal, or drop --sign")));
    }
    let key = a.sign.clone();
    let fingerprint = match &key {
        Some(k) => Some(brx::key_fingerprint(k)?),
        None => None,
    };
    let rep = cc::build(ctx, &a.cc.args(a.q.repo.as_ref()))?;
    let answer = answer_sentence(&rep);
    let requested_by = a.requested_by.clone().or_else(|| brx::requested_by_default(ctx));
    let by = brx::who(ctx);
    let found = rep.n_exposed() > 0;
    let statement = format!("{answer} {}", cc::headline(&rep));
    let mut doc = json!({
        "schema": "br-evidence/1",
        "subject": "claimcheck",
        "question": {"asked": question, "received": received, "clock": rep.now, "as_of": rep.as_of},
        "generated_at": ctx.now,
        "tool": concat!("br ", env!("CARGO_PKG_VERSION")),
        "requested_by": requested_by,
        "case_id": a.case,
        "claim": {
            "result": if found { "found" } else { "none_observed" },
            "verdict": rep.verdict(),
            "answer": answer,
            "statement": statement,
            "findings": rep.n_exposed(),
            "places": rep.exposed().iter().map(|r| r.seen.len()).sum::<usize>(),
            "counts": cc::counts_json(&rep),
            "headline": cc::headline(&rep),
        },
        "sample_registry": rep.sample,
        "names": rep.rows.iter().map(|r| cc::row_json(r, &rep)).collect::<Vec<_>>(),
        "ours_proofs": rep.rows.iter().filter(|r| r.status == Status::Ours).map(|r| json!({"name": r.name, "ecosystem": r.eco.word(), "strength": r.strength.map(|s| s.key()), "proof": r.proof})).collect::<Vec<_>>(),
        "not_checked": rep.gaps.iter().map(|g| json!({"what": g.what, "why": g.why, "to_close": g.to_close, "names": g.names})).collect::<Vec<_>>(),
        "guidance": cc::guidance(&rep),
        "limits": cc::limits(&rep),
        "read": {"sources": rep.trees, "ci_artifacts": rep.artifact_trees, "sources_words": cc::sources_words(&rep), "files": rep.files_read, "source_maps": rep.maps_read, "registries_asked": rep.registries_asked},
        "index": cc::index_line(&rep),
        "as_of_at": rep.as_of_at,
        "custody": [{"event": "evidence", "at": ctx.now, "by": by, "requested_by": requested_by, "case_id": a.case, "signed_with": fingerprint}],
    });
    let digest = brx::json_digest(&doc);
    doc["integrity"] = json!({
        "alg": "sha256",
        "covers": "every field except integrity",
        "canonicalization": "Python json.dumps(doc_without_integrity, sort_keys=True) (default separators, ensure_ascii), UTF-8",
        "digest": digest,
    });
    E::write(&out_path, &format!("{}\n", crate::collect::util::py_dumps(&doc, Some(2), false)))?;
    let md = md_of_evidence(&rep, &answer, question.as_deref(), received.as_deref(), a.case.as_deref());
    E::write(&md_path, &E::md_with_trailer(&md))?;
    let sha = brx::sha_file(std::path::Path::new(&out_path)).map_err(|e| brx::io_err(e, &out_path))?;
    let customers_path = (a.audience.as_deref() == Some("customers")).then(|| format!("{}.customers.md", &out_path[..out_path.len() - ".json".len()]));
    if let Some(cp) = &customers_path {
        let name = std::path::Path::new(&out_path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        E::write(cp, &customers_md(&rep, &answer, question.as_deref(), received.as_deref(), a.case.as_deref(), &name, &sha))?;
    }
    if let Ok(st) = crate::store::Store::open(ctx, false) {
        let _ = st.push("custody", &json!({"event": "evidence", "at": ctx.now, "by": by, "case_id": a.case, "file_sha256": sha, "requested_by": requested_by, "signed_with": fingerprint, "sealed": !a.no_seal, "reissue": false}));
    }
    println!("{}", cc::headline(&rep));
    println!("{answer}");
    println!("wrote {out_path}");
    println!("wrote {md_path}");
    if let Some(cp) = &customers_path {
        println!("wrote {cp}");
    }
    let base = |p: &str| std::path::Path::new(p).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if a.no_seal {
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
        if key.is_none() {
            println!("the seal is an integrity check (the files are unchanged), not proof of who made them; add --sign KEY for that");
        }
    }
    match a.fail_if.as_deref() {
        Some("found") if found => return Ok(10),
        Some("none") if !found => return Ok(11),
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
    use crate::collect::public::Eco;
    use crate::query::claims::{Flag, ScopeFact};

    fn row(name: &str, status: Status, owners: &[&str]) -> Row {
        Row {
            eco: Eco::Npm,
            name: name.into(),
            is_scope: false,
            kinds: vec![],
            status,
            proof: None,
            public_max: Some("1.0.0".into()),
            published: None,
            first_published: None,
            install_script: None,
            publishers: vec![],
            yours: Some("1.0.0".into()),
            flags: vec![],
            seen: vec![claims::Seen { repo: "org/web".into(), file: "package.json".into() }],
            pinned: vec![],
            unpinned: vec![],
            mapped: vec![],
            note: None,
            strength: None,
            owners: owners.iter().map(|s| s.to_string()).collect(),
            scope_pkgs: vec![],
            under_scope: None,
            as_of_notes: vec![],
        }
    }

    fn rep(rows: Vec<Row>) -> Report {
        Report { now: "2026-06-10T08:00:00Z".into(), rows, ..Default::default() }
    }

    #[test]
    fn each_owning_team_gets_its_own_names_and_a_name_with_two_owners_goes_to_both() {
        let mut squat = row("a", Status::Squatted, &["@org/billing"]);
        squat.install_script = Some(true);
        squat.public_max = Some("9999.0.0".into());
        squat.publishers = vec!["mallory".into()];
        let both = row("b", Status::Free, &["@org/billing", "@org/security"]);
        let lost = row("c", Status::Free, &[]);
        let nc = row("d", Status::NotChecked, &["@org/security"]);
        let ours = row("e", Status::Ours, &["@org/security"]);
        let r = rep(vec![squat, both, lost, nc, ours]);
        let g = by_owner(&r);
        assert_eq!(g["@org/billing"].iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
        assert_eq!(g["@org/security"].iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["b", "d"]);
        assert_eq!(g["unresolved"].len(), 1);
        assert!(!g.values().any(|v| v.iter().any(|r| r.name == "e")), "OURS names are told to no one");
        let t = team_text(None, "@org/billing", &g["@org/billing"], &r, "slack");
        assert!(t.contains("a stranger published 9999.0.0, and it runs code when installed") && t.contains("What to do"), "{t}");
    }

    #[test]
    fn the_statement_starts_with_the_answer() {
        let ex = rep(vec![row("a", Status::Squatted, &[])]);
        assert!(answer_sentence(&ex).starts_with("Yes: on 2026-06-10, 1 name"), "{}", answer_sentence(&ex));
        let mut ours = row("o", Status::Ours, &[]);
        ours.strength = Some(Strength::Verified);
        assert!(answer_sentence(&rep(vec![ours.clone()])).starts_with("No: on 2026-06-10, none of the 1 package names"));
        ours.strength = Some(Strength::Declared);
        assert!(answer_sentence(&rep(vec![ours])).starts_with("Not that we found, but 1 name"));
        assert!(answer_sentence(&rep(vec![row("n", Status::NotChecked, &[])])).starts_with("Not that we found, but this is not a full answer"));
    }

    #[test]
    fn a_diff_names_what_became_squatted_free_or_ours() {
        let before = rep(vec![row("late", Status::Free, &[]), row("keep", Status::Squatted, &[]), row("gone", Status::Free, &[]), row("mine", Status::Squatted, &[])]);
        let snap = snapshot_json(&before);
        let mut now = vec![row("late", Status::Squatted, &[]), row("keep", Status::Squatted, &[]), row("fresh", Status::Free, &[])];
        let mut mine = row("mine", Status::Ours, &[]);
        mine.strength = Some(Strength::Verified);
        now.push(mine);
        let mut up = row("keep", Status::Squatted, &[]);
        up.public_max = Some("9999.0.0".into());
        up.flags = vec![Flag::HigherVersion { public: "9999.0.0".into(), yours: "1.0.0".into() }];
        now[1] = up;
        let (list, same) = changes(&snap, &rep(now));
        let g = |k: &str| list.iter().filter(|c| c.group == k).map(|c| c.name.clone()).collect::<Vec<_>>();
        assert_eq!(g("newly_squatted"), vec!["late"]);
        assert_eq!(g("newly_free"), vec!["fresh"]);
        assert_eq!(g("now_ours"), vec!["mine"]);
        assert_eq!(g("no_longer_listed"), vec!["gone"]);
        assert_eq!(g("changed"), vec!["keep"]);
        assert_eq!(same, 0);
        let _ = ScopeFact::Unknown;
    }

    #[test]
    fn r10_a_backward_diff_compares_snapshots_by_their_own_dates_and_never_says_newly() {
        let mut then = rep(vec![row("late", Status::Squatted, &[])]);
        then.now = "2026-06-10T08:00:00Z".into();
        let snap = snapshot_json(&then);
        let mut now = rep(vec![row("late", Status::Free, &[])]);
        now.as_of = Some("2026-06-01".into());
        now.as_of_at = Some("2026-06-01T23:59:59Z".into());
        assert!(is_backward(&snap, &now));
        let (list, _) = changes(&snap, &now);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].group, "then_free");
        assert!(!list[0].line.contains("newly") && !list[0].line.contains("now FREE"), "{}", list[0].line);
        assert!(list[0].line.contains("the snapshot, for 2026-06-10, has it as SQUATTED; on 2026-06-01 it was FREE"), "{}", list[0].line);
        // the same pair of runs read forward is the ordinary change
        let fwd = rep(vec![row("late", Status::Free, &[])]);
        let mut earlier = rep(vec![row("late", Status::Squatted, &[])]);
        earlier.now = "2026-06-01T08:00:00Z".into();
        assert!(!is_backward(&snapshot_json(&earlier), &fwd));
        assert_eq!(changes(&snapshot_json(&earlier), &fwd).0[0].group, "newly_free");
        // a snapshot recorded with --as-of describes that date, not its clock
        let mut old_as_of = rep(vec![]);
        old_as_of.as_of = Some("2026-05-01".into());
        old_as_of.as_of_at = Some("2026-05-01T23:59:59Z".into());
        assert!(!is_backward(&snapshot_json(&old_as_of), &now));
    }

    #[test]
    fn r10_the_notify_message_for_a_name_with_no_owner_shown_makes_no_claim_about_a_publisher() {
        let hidden = row("h", Status::Squatted, &["@org/billing"]);
        let r = rep(vec![hidden]);
        let g = by_owner(&r);
        let t = team_text(None, "@org/billing", &g["@org/billing"], &r, "slack");
        assert!(t.contains("an owner the registry does not show") && !t.contains("stranger"), "{t}");
        assert!(!t.contains("placeholder"), "{t}");
    }
}
