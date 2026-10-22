//! Renderers for hunt results: table, json, csv, md, summary, quiet, slack.

use std::collections::BTreeMap;

use super::json::J;
use crate::query::hunt::{self as H, FKind, Finding, HuntResult};
use crate::query::index::Index;
use crate::query::iocs::IocKind;
use crate::query::secrets::secret_uses;
use crate::query::util::*;

pub fn owner_str(ix: &Index, f: &Finding) -> String {
    H::owner_name(ix, &f.owner)
}

pub fn ioc_label(res: &HuntResult) -> String {
    let q = &res.q;
    if q.iocs.len() == 1 {
        // No version written is a search for any version
        if H::ioc_any_version(&q.iocs[0]) {
            return format!("any version of {}", q.iocs[0].name);
        }
        return q.iocs[0].text.clone();
    }
    // When only some of the indicators have hits, the headline says how many (an indicator asked twice is one)
    let per = H::ioc_hits(res);
    let (hits, total) = (per.iter().filter(|(_, n)| *n > 0).count(), per.len());
    let adv = q.adv.as_ref().map_or(String::new(), |a| format!(" ({})", a.id));
    if hits > 0 && hits < total {
        return format!("{hits} of {total} indicators{adv}");
    }
    format!("{} indicators{adv}", q.iocs.len())
}

/// What is still there, in words, from the one place that counts it ("5 repos, 2 images and 3 machines").
pub fn present_now_words(c: &H::Counts) -> String {
    let bits = c.now.bits();
    if bits.is_empty() {
        "nothing".to_string()
    } else {
        join_and(&bits)
    }
}

/// The headline clause and the heading of the section, worded once for every view.
pub const PRESENT_AFTER_CELL: &str = "+ {n} present now, first seen after the window";
pub const PRESENT_AFTER_TITLE: &str = "PRESENT NOW, FIRST SEEN AFTER THE WINDOW";

pub fn count_line(res: &HuntResult) -> String {
    let c = H::counts(res);
    let only = &res.q.only;
    let mut cells: Vec<String> = vec![];
    if c.findings > 0 {
        cells.push(H::count_words(res));
    }
    if c.repos > 0 && only.contains("repos") {
        let mut st = vec![];
        for (k, n) in [("present", c.repo_states.0), ("removed", c.repo_states.1), ("install-only", c.repo_states.2)] {
            if n > 0 {
                st.push(format!("{n} {k}"));
            }
        }
        cells.push(format!("repos {} ({})", c.repos, st.join(", ")));
    }
    for (key, kind, n) in [("ci runs", "ci", c.ci_runs), ("caches", "caches", c.caches), ("artifacts", "artifacts", c.artifacts), ("images", "images", c.images)] {
        if n > 0 && only.contains(kind) {
            cells.push(format!("{key} {n}"));
        }
    }
    if c.hosts > 0 && only.contains("hosts") {
        cells.push(format!("hosts {}", c.hosts));
    }
    if c.present_after > 0 {
        cells.push(PRESENT_AFTER_CELL.replace("{n}", &c.present_after.to_string()));
    }
    if c.possible > 0 {
        cells.push(format!("possible {} (not counted above)", H::possible_words(&c)));
    }
    if c.floating > 0 {
        cells.push(format!("floating {} (not counted above)", c.floating));
    }
    if c.releases > 0 {
        cells.push(format!("releases {}", c.releases));
    }
    if c.workflow_refs > 0 {
        cells.push(format!("workflow refs {}", c.workflow_refs));
    }
    if c.rule_matches > 0 {
        cells.push(format!("yara rule matches {}", c.rule_matches));
    }
    if c.similar > 0 {
        cells.push(format!("similar, not identical {} (not counted above)", c.similar));
    }
    cells.join(" | ")
}

pub fn human_sentence(res: &HuntResult) -> Option<String> {
    let c = H::counts(res);
    if c.total == 0 && c.similar == 0 {
        return None;
    }
    let mut parts: Vec<String> = vec![];
    if c.repos > 0 {
        let mut s = plural(c.repos, "repo");
        if c.teams > 0 {
            s += &format!(" owned by {}", plural(c.teams, "team"));
            if c.unowned_repos > 0 {
                s += &format!(" ({} with no owner)", c.unowned_repos);
            }
        } else if c.unowned_repos > 0 {
            s += &format!(" ({} with no owner)", c.unowned_repos);
        }
        parts.push(format!("In {s}"));
    }
    if c.ci_runs > 0 {
        let mut s = format!("ran in {}", plural(c.ci_runs, "CI run"));
        if c.secrets > 0 {
            s += &format!(" that could read {}", c.secret_words());
        }
        parts.push(s);
    }
    let mut clean = vec![];
    for (n, lbl) in [(c.images, "image"), (c.hosts, "host"), (c.caches, "cache"), (c.artifacts, "build artifact")] {
        if n > 0 {
            clean.push(plural(n, lbl));
        }
    }
    if c.releases > 0 {
        clean.push(plural(c.releases, "release asset"));
    }
    if !clean.is_empty() {
        // An any-version search has not said which versions are bad, so nothing is "to clean" yet
        parts.push(format!("{} {}", join_and(&clean), if H::any_version_only(res) { "hold it" } else { "to clean" }));
    }
    if c.workflow_refs > 0 && parts.is_empty() {
        parts.push(format!("{} to change", plural(c.workflow_refs, "workflow reference")));
    }
    if c.similar > 0 {
        // A lookalike is a lead to review, not a place to clean
        parts.push(format!(
            "{} that look{} like the sample but {} not identical to it (review; not counted as to clean)",
            plural(c.similar, "file"),
            if c.similar == 1 { "s" } else { "" },
            if c.similar == 1 { "is" } else { "are" }
        ));
    }
    if parts.is_empty() {
        return None;
    }
    let mut s = parts.join("; ");
    if !s.starts_with("In ") {
        let mut ch = s.chars();
        s = ch.next().map(|f| f.to_uppercase().collect::<String>() + ch.as_str()).unwrap_or_default();
    }
    Some(s + ".")
}

fn uniq_count<T: Ord>(it: impl Iterator<Item = T>) -> usize {
    it.collect::<std::collections::BTreeSet<_>>().len()
}

pub fn per_ioc_table(res: &HuntResult) -> Vec<String> {
    let only = &res.q.only;
    type F = fn(&[&Finding]) -> usize;
    let cols: Vec<(&str, &str, F)> = vec![
        ("REPOS", "repos", |s| uniq_count(s.iter().filter(|f| matches!(f.kind, FKind::Repo | FKind::WorkflowRef)).map(|f| f.where_.clone()))),
        ("RUNS", "ci", |s| uniq_count(s.iter().filter(|f| f.kind == FKind::CiRun).map(|f| (f.where_.clone(), f.id)))),
        ("CACHES", "caches", |s| uniq_count(s.iter().filter(|f| f.kind == FKind::Cache).map(|f| (f.where_.clone(), f.key.clone())))),
        ("ARTIFACTS", "artifacts", |s| uniq_count(s.iter().filter(|f| f.kind == FKind::Artifact).map(|f| (f.where_.clone(), f.id)))),
        ("IMAGES", "images", |s| uniq_count(s.iter().filter(|f| f.kind == FKind::Image).map(|f| f.digest.clone()))),
        ("HOSTS", "hosts", |s| uniq_count(s.iter().filter(|f| f.kind == FKind::Host).map(|f| f.where_.clone()))),
    ];
    let cols: Vec<_> = cols.into_iter().filter(|c| only.contains(c.1)).collect();
    let fs = H::findings(res);
    let mut data: Vec<Vec<usize>> = vec![];
    for ioc in &res.q.iocs {
        let sel: Vec<&Finding> = fs.iter().copied().filter(|f| f.iocs_or_one().contains(&ioc.text)).collect();
        data.push(cols.iter().map(|c| (c.2)(&sel)).collect());
    }
    let keep: Vec<usize> = (0..cols.len()).filter(|&i| data.iter().any(|r| r[i] > 0) || cols[i].0 == "REPOS").collect();
    let mut hdr = vec!["INDICATOR"];
    hdr.extend(keep.iter().map(|&i| cols[i].0));
    let rows: Vec<Vec<String>> = res
        .q
        .iocs
        .iter()
        .zip(&data)
        .map(|(ioc, r)| {
            let mut row = vec![ioc.text.clone()];
            row.extend(keep.iter().map(|&i| r[i].to_string()));
            row
        })
        .collect();
    table(&hdr, &rows, 0)
}

pub fn header_lines(res: &HuntResult, ix: &Index) -> Vec<String> {
    let mut out = header_core(res, ix);
    out.extend(blocks_text(&header_blocks(res)));
    out
}

/// The summary lines of the answer: verdict, counts, coverage, scope facts. No tables.
pub fn header_core(res: &HuntResult, ix: &Index) -> Vec<String> {
    let q = &res.q;
    let v = H::verdict(res);
    let mut out: Vec<String> = vec![];
    if let Some(a) = &q.adv {
        if let Some(al) = &a.alias_used {
            out.push(format!("advisory {al} = {}: {}", a.id, a.title));
            out.push(String::new());
        }
    }
    out.push(format!("{v}  {}", ioc_label(res)));
    if let Some(hs) = human_sentence(res) {
        out.push(hs);
    }
    let mut parts: Vec<String> = vec![];
    if let Some(a) = &res.as_of {
        // The data behind the answer is a range, oldest source to newest; one time when they agree
        match crate::query::coverage::data_as_of(ix, &res.names).filter(|d| d.oldest != d.newest) {
            Some(d) => parts.push(format!("index as of {} (oldest: {}; newest {})", d.range(), d.oldest_source, age_label(&ix.now, a))),
            None => parts.push(format!("index as of {} ({})", fmtz(a), age_label(&ix.now, a))),
        }
    }
    let n = res.scope_total;
    let empties = res.not_checked.iter().filter(|r| r.state == "empty").count();
    if res.scope_stale > 0 {
        parts.push(format!("{} of {} sources stale", res.scope_stale, n));
    } else if empties > 0 {
        parts.push(format!("{} fresh, {} not checked", plural(n.saturating_sub(empties), "source"), empties));
    } else {
        parts.push(format!("{} fresh", plural(n, "source")));
    }
    if res.names.len() != n {
        let l = parts.len() - 1;
        parts[l] += &format!(" (--only reads {} of them)", res.names.len());
    }
    if !res.not_checked.is_empty() && res.not_checked.len() != res.scope_stale {
        parts.push(H::gap_words(&res.not_checked));
    }
    if let Some(w) = &q.window {
        // The window is shown one way: FROM..TO, and (examined to T) when the index stops before its end
        let src = q.window_src.clone().unwrap_or_default();
        let clipped = window_words(&w.0, &w.1, res.as_of.as_deref());
        let plain = window_words(&w.0, &w.1, None);
        parts.push(match clipped.strip_prefix(&plain).and_then(|t| t.trim().strip_prefix("(examined to ")).and_then(|t| t.strip_suffix(')')) {
            Some(to) => format!("window {plain} (examined to {to}; from {src})"),
            None => format!("window {plain} (from {src})"),
        });
    }
    if q.now_only {
        parts.push("present now only".into());
    }
    out.push(parts.join(" | "));
    if let Some(nh) = H::no_hit_note(res) {
        out.push(nh);
    }
    out.extend(hash_advisory_lines(res));
    let cl = count_line(res);
    if !cl.is_empty() {
        out.push(cl);
    } else {
        out.push(nothing_found_line(res, ix));
    }
    out.extend(only_lines(res));
    if v == "FOUND" && !H::any_version_names(res).is_empty() {
        // The headline above says "any version"; the versions found are in the tables, and nothing is called bad yet
        let names = H::any_version_names(res).join(", ");
        out.push(format!("{names}: any version matches, so each finding shows the version it has; name the affected version (eco:name@VERSION) or an advisory before anything is removed or rotated"));
    }
    let pr = H::past_runs(res);
    if !pr.is_empty() {
        out.push(format!("{} listed below for the secrets they could read; not counted, and not part of the verdict", plural(pr.len(), "past CI run")));
    }
    if q.window.is_some() {
        out.push(in_window_line(res, ix).unwrap_or_default());
        if out.last().is_some_and(|l| l.is_empty()) {
            out.pop();
        }
    }
    if res.window_ends_now {
        let a = res.as_of.clone().unwrap_or_default();
        out.push(format!("events after {} ({}) are not covered: br scan --stale", fmtz(&a), age_label(&ix.now, &a)));
    }
    let stale_gaps: Vec<&H::Gap> = res.gaps.iter().filter(|g| !(g.empty && !g.stale)).collect();
    if !stale_gaps.is_empty() {
        out.push(format!("stale sources that could change this answer: {}", stale_gaps.iter().map(|g| format!("{} ({})", g.name, fmt(&g.indexed_at))).collect::<Vec<_>>().join(", ")));
    }
    out.extend(moved_lines(res, ix));
    out.extend(changed_lines(res, ix));
    if let Some(k) = res.other_clear {
        out.push(match k {
            0 => "no other repo of yours is in scope".to_string(),
            1 => "1 other repo of yours is clear".to_string(),
            k => format!("{k} other repos of yours are clear"),
        });
    }
    if q.has("hosts") && q.repo.as_ref().is_none_or(|r| r.is_empty()) && q.host.as_ref().is_none_or(|r| r.is_empty()) {
        if let Some(pl) = H::population_line_for(ix, q) {
            out.push(pl);
        }
    }
    out.extend(not_match_lines(res));
    out
}

/// What a narrowed answer hides, in one place: `--only` against the whole answer, and `--now` against possible.
fn only_lines(res: &HuntResult) -> Vec<String> {
    let mut out = vec![];
    let q = &res.q;
    if q.only.len() < H::KINDS.len() {
        let shown = H::counts(res).findings;
        let mut line = format!("--only {} shows {} of the whole answer's {}", q.only.iter().cloned().collect::<Vec<_>>().join(","), shown, plural(res.full_findings.unwrap_or(shown), "finding"));
        if !res.hidden_gaps.is_empty() {
            let names: Vec<String> = res.hidden_gaps.iter().filter(|(_, st)| st != "laptops").take(4).map(|(n, _)| n.clone()).collect();
            let more = if res.hidden_gaps.len() > 4 { format!(" and {} more", res.hidden_gaps.len() - 4) } else { String::new() };
            line += &format!("; {} outside it{}{more}", plural(res.hidden_gaps.len(), "gap"), if names.is_empty() { String::new() } else { format!(": {}", names.join(", ")) });
        }
        out.push(line + "; leave --only out to see them");
    }
    if !res.possible_dropped.is_empty() {
        out.push(format!("{} fewer possible than without --now: {} no longer rests on a present exposure", res.possible_dropped.len(), res.possible_dropped.join(", ")));
    }
    out
}

/// "nothing found in 3 repos, 2 hosts": only sources that were searched are counted. A host whose scan hashed no
/// files is named apart, because nothing in it was looked at.
fn nothing_found_line(res: &HuntResult, ix: &Index) -> String {
    let mut kinds: Vec<(String, usize)> = vec![];
    let mut empty: Vec<String> = vec![];
    let mut unscanned: Vec<String> = vec![];
    for nme in &res.names {
        let src = ix.srcs.get(nme.as_str());
        if src.is_some_and(crate::collect::words::never_scanned) {
            // A registered host nothing has scanned yet is not "an empty scan"
            unscanned.push(nme.clone());
            continue;
        }
        if src.is_some_and(|x| x.empty) {
            empty.push(nme.clone());
            continue;
        }
        let k = src.map_or_else(|| "source".to_string(), |x| x.kind.clone());
        match kinds.iter_mut().find(|(x, _)| *x == k) {
            Some(e) => e.1 += 1,
            None => kinds.push((k, 1)),
        }
    }
    let desc: Vec<String> = kinds
        .iter()
        .map(|(k, c)| match k.as_str() {
            "registry" => plural_with(*c, "registry", Some("registries")),
            "host" => plural(*c, "host"),
            _ => plural(*c, "repo"),
        })
        .collect();
    let mut line = if desc.is_empty() { "nothing was searched".to_string() } else { format!("nothing found in {}", desc.join(", ")) };
    if !unscanned.is_empty() {
        line += &format!("; {} registered, never scanned, so {} not searched", unscanned.join(", "), if unscanned.len() == 1 { "it is" } else { "they are" });
    }
    if !empty.is_empty() {
        // a repo read nothing because its lockfiles gave no package; a host or registry because its scan hashed or listed nothing
        let why = if empty.iter().all(|n| ix.srcs.get(n.as_str()).is_some_and(|x| x.kind == "repo")) { "its lockfiles gave no packages" } else { "its scan hashed no files" };
        line += &format!("; {} had nothing to read ({why}), so {} not searched", empty.join(", "), if empty.len() == 1 { "it is" } else { "they are" });
    }
    line
}

/// A hash that a known advisory lists says so, and where the packages are hunted.
pub fn hash_advisory_lines(res: &HuntResult) -> Vec<String> {
    let hashes = res.q.iocs.iter().filter(|i| i.kind == IocKind::Sha256).count();
    res.hash_advisories
        .iter()
        .map(|(h, id, pk)| {
            let what = if hashes <= 1 { "this hash".to_string() } else { format!("sha256:{}…", h.trim_start_matches("sha256:").chars().take(12).collect::<String>()) };
            let names = if pk.is_empty() { String::new() } else { format!(", which names {}", pk.join(" ")) };
            format!("{what} is listed by {id}{names}; br hunt --advisory {id} covers the packages")
        })
        .collect()
}

/// "not a match: 3 files named X with another hash (br hunt sha256:c81a… to see them)".
fn not_match_lines(res: &HuntResult) -> Vec<String> {
    res.not_match
        .iter()
        .map(|m| {
            let short: String = m.other.trim_start_matches("sha256:").chars().take(12).collect();
            format!("not a match: {} named {} with another hash (br hunt sha256:{short}… to see them)", plural(m.count, "file"), m.name)
        })
        .collect()
}

pub fn moved_lines(res: &HuntResult, ix: &Index) -> Vec<String> {
    if res.moved.is_empty() {
        return vec![];
    }
    let hit: std::collections::BTreeSet<&str> = H::findings(res).iter().filter(|f| f.kind == FKind::Repo).map(|f| f.where_.as_str()).collect();
    let mut all = res.moved.clone();
    all.sort();
    let (show, others): (Vec<_>, Vec<_>) = all.into_iter().partition(|(r, _)| hit.contains(r.as_str()) || res.names.len() <= 3);
    let mut out: Vec<String> = show.iter().map(|(r, at)| H::moved_line(ix, r, at)).collect();
    if !others.is_empty() {
        let names: Vec<&str> = others.iter().map(|(r, _)| r.as_str()).collect();
        let shown = names.iter().take(4).copied().collect::<Vec<_>>().join(", ");
        let tail = if names.len() > 4 { format!(" and {} more: br status --all lists them", names.len() - 4) } else { String::new() };
        out.push(format!("{} also moved since indexed ({shown}{tail}); br scan --stale before acting", plural(others.len(), "other repo")));
    }
    out
}

pub fn rescanned_why(ch: &H::Changed) -> String {
    if !ch.gained.is_empty() {
        let tail = if ch.gained.len() > 4 { format!(" and {} more (br diff lists them)", ch.gained.len() - 4) } else { String::new() };
        return format!("new findings in {}{tail}", ch.gained.iter().take(4).cloned().collect::<Vec<_>>().join(", "));
    }
    if ch.kind == "import" {
        return format!("imported {}", ch.sources.join(", "));
    }
    format!("rescanned {}", plural(ch.sources.len(), "source"))
}

pub fn changed_lines(res: &HuntResult, ix: &Index) -> Vec<String> {
    let Some(ch) = H::changed_since_scan(ix, &res.q, res) else { return vec![] };
    let now = H::counts(res);
    let mut bits: Vec<String> = ch.delta.iter().map(|(k, a, b)| format!("{k} {b} (was {a})")).collect();
    if bits.is_empty() {
        bits.push(format!("findings {} (was {})", now.findings, ch.was.findings));
    }
    vec![format!("changed since the {} at {}: {}; the earlier numbers are the index as of {}; {}", ch.kind, fmtz(&ch.at), bits.join(", "), fmtz(&ch.was_at), rescanned_why(&ch))]
}

/// A titled part of the answer below the header. The table, md and slack views render the same blocks, so a
/// section cannot say one thing in one format and another in the next.
#[derive(Debug, Clone, Default)]
pub struct Block {
    pub title: Option<String>,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone)]
pub enum Part {
    /// a table: header, rows
    Table(Vec<String>, Vec<Vec<String>>),
    /// the text view prints these lines as given; md prints the table
    Alt(Vec<String>, Vec<String>, Vec<Vec<String>>),
    /// "note: ..." (indented in text)
    Note(String),
    /// a line as it stands
    Line(String),
}

fn tbl(hdr: &[&str], rows: Vec<Vec<String>>) -> Part {
    Part::Table(hdr.iter().map(|h| h.to_string()).collect(), rows)
}

/// The text view of blocks: a blank line, the title, then each part (tables indented by two).
pub fn blocks_text(blocks: &[Block]) -> Vec<String> {
    let mut out = vec![];
    for b in blocks {
        out.push(String::new());
        if let Some(t) = &b.title {
            out.push(t.clone());
        }
        for p in &b.parts {
            match p {
                Part::Table(h, r) => {
                    let hs: Vec<&str> = h.iter().map(|x| x.as_str()).collect();
                    out.extend(table(&hs, r, 2));
                }
                Part::Alt(t, _, _) => out.extend(t.iter().cloned()),
                Part::Note(n) => out.push(format!("  {n}")),
                Part::Line(l) => out.push(l.clone()),
            }
        }
    }
    out
}

fn md_cell(c: &str) -> String {
    c.replace('\\', "\\\\").replace('|', "\\|").replace('\n', " ")
}

fn md_table(h: &[String], r: &[Vec<String>]) -> Vec<String> {
    let mut out = vec![format!("| {} |", h.iter().map(|x| md_cell(x)).collect::<Vec<_>>().join(" | ")), format!("|{}|", vec!["---"; h.len()].join("|"))];
    for row in r {
        let mut cells: Vec<String> = row.iter().map(|x| md_cell(x)).collect();
        cells.resize(h.len(), String::new());
        out.push(format!("| {} |", cells.join(" | ")));
    }
    out
}

/// The markdown view: `##` headings and pipe tables, no code fence and no empty bullets.
pub fn blocks_md(blocks: &[Block]) -> Vec<String> {
    let mut out = vec![];
    for b in blocks {
        out.push(String::new());
        if let Some(t) = &b.title {
            out.push(format!("## {}", t.trim_end_matches(':')));
            out.push(String::new());
        }
        for p in &b.parts {
            match p {
                Part::Table(h, r) | Part::Alt(_, h, r) => out.extend(md_table(h, r)),
                Part::Note(n) => out.push(n.clone()),
                Part::Line(l) => out.push(l.trim_start().to_string()),
            }
        }
    }
    out
}

pub fn not_checked_block(res: &HuntResult) -> Option<Block> {
    if res.not_checked.is_empty() {
        return None;
    }
    let rows: Vec<Vec<String>> = res.not_checked.iter().map(|n| vec![n.name.clone(), n.why.clone(), n.command.clone()]).collect();
    Some(Block { title: Some("NOT CHECKED:".to_string()), parts: vec![tbl(&["SOURCE", "WHY", "TO CLOSE"], rows)] })
}

pub fn possible_block(res: &HuntResult) -> Option<Block> {
    let mut ps = H::possible(res);
    if ps.is_empty() {
        return None;
    }
    ps.sort_by(|a, b| a.where_.cmp(&b.where_));
    let text: Vec<String> = ps.iter().map(|p| format!("  {} possible: {}", p.where_, p.reason)).collect();
    let rows: Vec<Vec<String>> = ps.iter().map(|p| vec![p.where_.clone(), p.reason.clone()]).collect();
    Some(Block {
        title: Some("POSSIBLE (evidence of exposure on a host the index cannot confirm; not counted as found):".to_string()),
        parts: vec![Part::Alt(text, vec!["PLACE".into(), "WHY".into()], rows)],
    })
}

pub fn header_blocks(res: &HuntResult) -> Vec<Block> {
    not_checked_block(res).into_iter().chain(possible_block(res)).chain(floating_block(res)).collect()
}

/// Runtimes named by a floating tag or spec: not found, and not clear either.
pub const FLOATING_WORDS: &str = "floating: what it runs depends on when it was built or run; rebuild or re-run after the fix ships";

pub fn floating_block(res: &HuntResult) -> Option<Block> {
    if res.floating.is_empty() {
        return None;
    }
    let place = |f: &H::Floating| if f.line > 0 { format!("{}:{}", f.file, f.line) } else { f.file.clone() };
    let text: Vec<String> = res.floating.iter().map(|f| format!("  {} {} {} ({})", f.repo, place(f), f.spec, f.seen_as)).collect();
    let rows: Vec<Vec<String>> = res.floating.iter().map(|f| vec![f.repo.clone(), place(f), f.runtime.clone(), f.spec.clone(), f.seen_as.clone()]).collect();
    Some(Block {
        title: Some(format!("FLOATING (not counted as found; {FLOATING_WORDS}):")),
        parts: vec![Part::Alt(text, vec!["REPO".into(), "FILE".into(), "RUNTIME".into(), "SPEC".into(), "SEEN AS".into()], rows)],
    })
}

/// One line per runtime version found, saying how its line is fixed.
pub fn rt_fix_words(r: &H::RtInfo) -> String {
    if r.eol {
        format!("{} {}: no fixed release on its line (end of life){}", r.runtime, r.version, r.move_to.as_ref().map_or(String::new(), |m| format!("; move to {m} or later")))
    } else if let Some(l) = &r.line_fixed {
        format!("{} {}: fixed in {l} on its line", r.runtime, r.version)
    } else {
        format!("{} {}: affected", r.runtime, r.version)
    }
}

fn runtime_block(fs: &[&Finding]) -> Option<Block> {
    let lines = uniq(fs.iter().filter_map(|f| f.rt.as_ref()).map(rt_fix_words));
    if lines.is_empty() {
        return None;
    }
    Some(Block { title: Some("RUNTIMES".to_string()), parts: lines.into_iter().map(Part::Line).collect() })
}

pub fn in_window_line(res: &HuntResult, ix: &Index) -> Option<String> {
    let mut q0 = res.q.clone();
    q0.window = None;
    let tot = H::hunt(ix, &q0).ok()?;
    let (a, b) = (H::counts(res), H::counts(&tot));
    let mut parts = vec![];
    if b.repos > 0 {
        parts.push(format!("{} of {} repos", a.repos, b.repos));
    }
    if b.ci_runs > 0 {
        parts.push(format!("{} of {} runs", a.ci_runs, b.ci_runs));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("in window: {}", parts.join(", ")))
    }
}

fn repo_order(s: &str) -> u8 {
    match s {
        "present" => 0,
        "present (archived)" => 1,
        "removed" => 2,
        _ => 3,
    }
}

fn uniq(xs: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for x in xs {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

pub fn sections(res: &HuntResult, ix: &Index, wide: bool) -> Vec<String> {
    blocks_text(&section_blocks(res, ix, wide))
}

/// The tables of the answer, as blocks: the text and md views both print these.
pub fn section_blocks(res: &HuntResult, ix: &Index, wide: bool) -> Vec<Block> {
    let q = &res.q;
    let mut fs: Vec<&Finding> = H::findings(res);
    fs.extend(H::past_runs(res));
    let mut out: Vec<Block> = vec![];
    // A certificate in a trust store has its own table below; the kind tables hold everything else
    let by = |k: FKind| -> Vec<&Finding> { fs.iter().copied().filter(|f| f.kind == k && f.cert.is_none()).collect() };
    let multi = q.iocs.len() > 1;
    let dg = |d: &str| short_digest(d, wide);
    let ic = |f: &Finding| f.iocs_or_one().join(", ");
    let ls = |f: &Finding| f.last_seen.as_deref().filter(|s| !s.is_empty()).map_or("-".to_string(), fmt);
    let ind = |mut hdr: Vec<&'static str>| {
        if multi {
            hdr.push("INDICATORS");
        }
        hdr
    };
    let block = |title: &str, parts: Vec<Part>| Block { title: Some(title.to_string()), parts };

    let mut rp = by(FKind::Repo);
    rp.sort_by(|a, b| {
        let ka = (repo_order(&a.state), &a.where_, if a.depth.starts_with("direct") { 0 } else { 1 }, &a.ioc);
        let kb = (repo_order(&b.state), &b.where_, if b.depth.starts_with("direct") { 0 } else { 1 }, &b.ioc);
        ka.cmp(&kb)
    });
    if !rp.is_empty() {
        let mut order: Vec<&str> = vec![];
        let mut groups: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
        for f in &rp {
            if !groups.contains_key(f.where_.as_str()) {
                order.push(f.where_.as_str());
            }
            groups.entry(f.where_.as_str()).or_default().push(f);
        }
        let mut rows = vec![];
        for repo in order {
            let gf = &groups[repo];
            let best = gf[0];
            let st = if best.state != "removed" { best.state.clone() } else { format!("removed {}", fmt_opt(best.removed_at.as_deref())) };
            let lasts: Vec<&String> = gf.iter().filter_map(|x| x.last_seen.as_ref().filter(|s| !s.is_empty())).collect();
            let mut row = vec![repo.to_string()];
            if multi {
                row.push(uniq(gf.iter().map(|x| x.name.clone())).join(", "));
            }
            row.extend([
                st,
                uniq(gf.iter().map(|x| match (&x.rt, x.manifest_line) {
                    (Some(_), Some(l)) => format!("{}:{l}", x.file),
                    _ => x.file.clone(),
                }))
                .join(", "),
                uniq(gf.iter().map(|x| x.version.clone())).join(", "),
                best.depth.clone(),
                fmt(gf.iter().filter_map(|x| x.first_seen.as_deref()).min().unwrap_or("")),
                lasts.iter().max().map_or("-".to_string(), |s| fmt(s)),
                owner_str(ix, best),
            ]);
            rows.push(row);
        }
        let mut hdr = vec!["REPO"];
        if multi {
            hdr.push("PACKAGES");
        }
        hdr.extend(["STATE", "FILE", "VERSION", "DEPTH", "FIRST SEEN", "LAST SEEN", "OWNER"]);
        let mut parts = vec![tbl(&hdr, rows)];
        if let Some(f) = rp.iter().find(|f| f.state == "install-only") {
            parts.push(Part::Note(format!("note: {}. The range had no lockfile to pin it, so only the CI run shows the version.", f.explain)));
        }
        out.push(block("REPOS", parts));
        if q.history {
            out.push(block("HISTORY", history_lines(ix, &rp).into_iter().map(Part::Line).collect()));
        }
    }
    let mut runs = by(FKind::CiRun);
    runs.sort_by(|a, b| (&a.at, &a.where_).cmp(&(&b.at, &b.where_)));
    if !runs.is_empty() {
        let rows: Vec<Vec<String>> = runs
            .iter()
            .map(|f| {
                let mut r = vec![
                    format!("{}#{}", f.where_, f.id),
                    fmt(&f.at),
                    f.runner.clone(),
                    format!("{}{}", f.workflow, if f.past_run { " (past run)" } else { "" }),
                    f.secrets.join(", "),
                    match &f.rt {
                        Some(r) => format!("{} ({} {})", f.resolved_from, r.runtime, r.version),
                        None => f.resolved_from.clone(),
                    },
                ];
                if multi {
                    r.push(ic(f));
                }
                r
            })
            .collect();
        out.push(block("CI RUNS", vec![tbl(&ind(vec!["RUN", "WHEN", "RUNNER", "WORKFLOW", "SECRETS", "RESOLVED FROM"]), rows)]));
    }
    let ca = by(FKind::Cache);
    if !ca.is_empty() {
        let rows: Vec<Vec<String>> = ca
            .iter()
            .map(|f| {
                let mut r = vec![
                    f.where_.clone(),
                    f.key.clone(),
                    fmt(&f.created),
                    fmt_opt(f.last_used.as_deref()),
                    match f.size_mb {
                        Some(n) if n > 0 => format!("{n} MB"),
                        _ => "-".into(),
                    },
                ];
                if multi {
                    r.push(ic(f));
                }
                r
            })
            .collect();
        out.push(block("CACHES", vec![tbl(&ind(vec!["REPO", "KEY", "CREATED", "LAST USED", "SIZE"]), rows)]));
    }
    let ar = by(FKind::Artifact);
    if !ar.is_empty() {
        let rows: Vec<Vec<String>> = ar
            .iter()
            .map(|f| {
                let mut r = vec![f.where_.clone(), f.name.clone(), f.id.to_string(), fmt(&f.created), fmt(&f.expires)];
                if multi {
                    r.push(ic(f));
                }
                r
            })
            .collect();
        out.push(block("ARTIFACTS", vec![tbl(&ind(vec!["REPO", "NAME", "ID", "CREATED", "EXPIRES"]), rows)]));
    }
    let mut im = by(FKind::Image);
    if !im.is_empty() {
        let has_path = im.iter().any(|f| !f.path.is_empty());
        let has_blob = im.iter().any(|f| f.deleted_in.is_some_and(|d| d > 0) && f.layer_blob.is_some());
        im.sort_by(|a, b| (&a.image, &a.built).cmp(&(&b.image, &b.built)));
        let mut rows = vec![];
        for f in &im {
            let frm = match f.commit.as_deref().filter(|c| !c.is_empty()) {
                Some(c) => format!("{}@{}", f.from_repo.clone().unwrap_or_else(|| "None".into()), c),
                None => f.from_repo.clone().filter(|r| !r.is_empty()).unwrap_or_else(|| "-".into()),
            };
            let tags = f.tags.join(", ");
            let mut row = vec![f.image.clone(), if tags.is_empty() { "-".into() } else { tags }, dg(&f.digest), fmt_opt(f.first_seen.as_deref()), ls(f), frm];
            if has_path {
                row.push(if f.path.is_empty() { "-".into() } else { f.path.clone() });
            }
            row.push(match &f.rt {
                Some(r) => format!("{} ({} {}, {})", where_in_words(f), r.runtime, r.version, r.seen_as),
                None => where_in_words(f),
            });
            if has_blob {
                row.push(if f.deleted_in.is_some_and(|d| d > 0) { f.layer_blob.as_deref().map_or("-".to_string(), dg) } else { "-".into() });
            }
            row.push(owner_str(ix, f));
            if multi {
                row.push(ic(f));
            }
            rows.push(row);
        }
        let mut hdr = vec!["IMAGE", "TAGS", "DIGEST", "FIRST SEEN", "LAST SEEN", "FROM"];
        if has_path {
            hdr.push("PATH");
        }
        hdr.push("WHERE");
        if has_blob {
            hdr.push("LAYER BLOB");
        }
        hdr.push("OWNER");
        let mut parts = vec![tbl(&ind(hdr), rows)];
        parts.push(Part::Note("note: FIRST SEEN is the build time; LAST SEEN is when the registry was last read".into()));
        if im.iter().any(|f| f.deleted_in.is_some_and(|d| d > 0)) {
            parts.push(Part::Note("note: 'layer N (deleted in layer M)' means the file is in an earlier image layer, deleted later but still downloadable by digest".into()));
        }
        out.push(block("IMAGES", parts));
    }
    let ho = by(FKind::Host);
    let simh = q.iocs.iter().any(|i| i.kind == IocKind::Simhash);
    let sim_rows: Vec<&Finding> = if simh { ho.iter().copied().filter(|f| f.match_ == "similar").collect() } else { vec![] };
    let ho_other: Vec<&Finding> = if !sim_rows.is_empty() { ho.iter().copied().filter(|f| f.match_ != "similar").collect() } else { ho.clone() };
    if !sim_rows.is_empty() {
        let mut sr = sim_rows.clone();
        // Boilerplate (a manifest, a system file) is listed last, whatever its score
        sr.sort_by(|a, b| {
            let (sa, sb) = (a.sim.unwrap_or(0.0), b.sim.unwrap_or(0.0));
            H::is_boilerplate_path(&a.loc)
                .cmp(&H::is_boilerplate_path(&b.loc))
                .then_with(|| sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| (&a.where_, &a.loc).cmp(&(&b.where_, &b.loc)))
        });
        let rows: Vec<Vec<String>> = sr
            .iter()
            .map(|f| {
                let pct = format!("{:.1}%{}", f.sim.unwrap_or(0.0) * 100.0, if H::is_boilerplate_path(&f.loc) { " (boilerplate)" } else { "" });
                vec![pct, f.where_.clone(), f.loc.clone(), dg(&f.sha256), fmt_opt(f.first_seen.as_deref()), ls(f)]
            })
            .collect();
        let mut parts = vec![tbl(&["SIMILARITY", "HOST", "PATH", "SHA256", "FIRST SEEN", "LAST SEEN"], rows)];
        if sim_rows.iter().any(|f| H::is_lookalike(f)) {
            parts.push(Part::Note("note: a file below 100% is similar, not identical; it is a lead to review and is not counted as a place to clean".into()));
        }
        out.push(block("SIMILARITY", parts));
    }
    if !ho_other.is_empty() {
        let has_note = ho_other.iter().any(|f| !f.note.is_empty());
        let mut hs = ho_other.clone();
        hs.sort_by(|a, b| (&a.where_, &a.first_seen).cmp(&(&b.where_, &b.first_seen)));
        let rows: Vec<Vec<String>> = hs
            .iter()
            .map(|f| {
                let kind = ix.host_def(&f.where_).and_then(|h| h.kind.clone()).filter(|k| !k.is_empty()).unwrap_or_else(|| "host".into());
                let mut r = vec![f.where_.clone(), kind, f.loc.clone(), fmt_opt(f.first_seen.as_deref()), ls(f), f.state.clone(), owner_str(ix, f)];
                if has_note {
                    r.push(f.note.clone());
                }
                if multi {
                    r.push(ic(f));
                }
                r
            })
            .collect();
        let mut hdr = vec!["HOST", "KIND", "LOCATION", "FIRST SEEN", "LAST SEEN", "STATE", "OWNER"];
        if has_note {
            hdr.push("NOTE");
        }
        out.push(block("HOSTS", vec![tbl(&ind(hdr), rows)]));
    }
    if let Some(b) = trust_block(&fs, ix, multi, wide) {
        out.push(b);
    }
    if let Some(b) = runtime_block(&fs) {
        out.push(b);
    }
    if let Some(b) = related_block(res) {
        out.push(b);
    }
    if let Some(b) = similar_related_block(res) {
        out.push(b);
    }
    let rel = by(FKind::ReleaseAsset);
    if !rel.is_empty() {
        let rows: Vec<Vec<String>> = rel.iter().map(|f| vec![f.where_.clone(), f.tag.clone(), f.asset.clone(), dg(&f.sha256), fmt(&f.published), ls(f), owner_str(ix, f)]).collect();
        out.push(block("RELEASES", vec![tbl(&["REPO", "TAG", "ASSET", "SHA256", "PUBLISHED", "LAST SEEN", "OWNER"], rows)]));
    }
    if let Some(b) = present_after_block(res, ix, wide) {
        out.push(b);
    }
    let carried = carried_rows(&fs, q);
    if !carried.is_empty() {
        out.push(block("CARRIED BY (what the index knows brought the file there)", vec![tbl(&["PLACE", "CARRIED BY"], carried)]));
    }
    let wr = by(FKind::WorkflowRef);
    if !wr.is_empty() {
        let rows: Vec<Vec<String>> = wr.iter().map(|f| vec![f.where_.clone(), f.file.clone(), f.ref_.clone(), f.ref_kind.clone(), f.runs.clone()]).collect();
        out.push(block("WORKFLOW REFERENCES", vec![tbl(&["REPO", "FILE", "REF", "KIND", "RUNS IN WINDOW"], rows)]));
    }
    if !res.near.is_empty() && !q.near {
        out.push(Block {
            title: None,
            parts: vec![Part::Line(format!("excluded {} (different package or prerelease): see --near-misses", plural_with(res.near.len(), "near-miss", Some("near-misses"))))],
        });
    }
    if !res.near.is_empty() && q.near {
        let rows: Vec<Vec<String>> = res.near.iter().map(|n| vec![n.repo.clone(), n.found.clone(), n.why.clone()]).collect();
        out.push(block("NEAR MISSES", vec![tbl(&["REPO", "FOUND", "WHY EXCLUDED"], rows)]));
    }
    if q.secrets {
        let sec = secret_uses(ix, res);
        if !sec.is_empty() {
            let rows: Vec<Vec<String>> = sec.iter().map(|u| vec![u.name.clone(), u.scope.clone(), u.runs.to_string(), u.repos.join(", "), u.owner_cell()]).collect();
            let title = if H::any_version_only(res) { "SECRETS THE RUNS COULD READ" } else { "SECRETS TO ROTATE" };
            let mut parts = vec![tbl(&["SECRET", "SCOPE", "RUNS", "REPOS", "OWNER"], rows)];
            if let Some(n) = crate::query::secrets::separate_note(&sec) {
                parts.push(Part::Note(format!("note: {n}")));
            }
            out.push(block(&format!("{title} ({})", sec.len()), parts));
        }
    }
    out
}

/// The certificates found in trust stores: the place, the file, the subject, root or intermediate, and where in the place it is.
fn trust_block(fs: &[&Finding], ix: &Index, multi: bool, wide: bool) -> Option<Block> {
    let mut cs: Vec<&Finding> = fs.iter().copied().filter(|f| f.cert.is_some()).collect();
    if cs.is_empty() {
        return None;
    }
    cs.sort_by(|a, b| (a.kind.name(), &a.where_, &a.digest, a.cert.as_ref().map(|c| &c.file)).cmp(&(b.kind.name(), &b.where_, &b.digest, b.cert.as_ref().map(|c| &c.file))));
    let rows: Vec<Vec<String>> = cs
        .iter()
        .map(|f| {
            let c = f.cert.as_ref().unwrap();
            let (place, wh) = match f.kind {
                FKind::Image => (format!("image {}:{} {}", f.image, f.tags.first().cloned().unwrap_or_else(|| "-".into()), short_digest(&f.digest, wide)), where_in_words(f)),
                FKind::Host => (format!("host {}", f.where_), "on the machine".to_string()),
                _ => (format!("repo {}", f.where_), "committed at HEAD".to_string()),
            };
            let mut r = vec![
                place,
                c.file.clone(),
                c.subject.clone(),
                if c.root { "root".to_string() } else { "intermediate".to_string() },
                c.not_after.as_deref().map_or("-".to_string(), |s| s.chars().take(10).collect()),
                wh,
                owner_str(ix, f),
            ];
            if multi {
                r.push(f.iocs_or_one().join(", "));
            }
            r
        })
        .collect();
    let mut hdr = vec!["PLACE", "FILE", "SUBJECT", "ROLE", "EXPIRES", "WHERE", "OWNER"];
    if multi {
        hdr.push("INDICATORS");
    }
    let mut parts = vec![tbl(&hdr, rows)];
    if cs.iter().any(|f| f.cert.as_ref().is_some_and(|c| c.deleted)) {
        parts.push(Part::Note("note: a certificate in a deleted layer is not in the running image, but the layer is still in the image's blobs and can be pulled by digest".into()));
    }
    Some(Block { title: Some("TRUST STORES".to_string()), parts })
}

/// Where an image finding sits, and when a layer's RUN executed the file during the build.
pub fn where_in_words(f: &Finding) -> String {
    match f.executed_in_layer {
        Some(n) => format!("{}; executed during build in layer {n}", f.where_in),
        None => f.where_in.clone(),
    }
}

/// The other files that shipped in the same install tree as a hash hit, each with the command that hunts for it.
pub fn related_lines(res: &HuntResult) -> Vec<String> {
    res.related
        .iter()
        .map(|r| {
            let hit = r.hit_path.strip_prefix(&format!("{}/", r.tree.trim_end_matches('/'))).unwrap_or(&r.hit_path);
            if r.hit_path.is_empty() {
                format!("related: {}  (a file of the affected package {} on {})", r.words(), r.package, r.host)
            } else {
                format!("related: {}  (shipped beside {hit} on {})", r.words(), r.host)
            }
        })
        .collect()
}

fn related_block(res: &HuntResult) -> Option<Block> {
    let lines = related_lines(res);
    if lines.is_empty() {
        return None;
    }
    Some(Block { title: Some("RELATED FILES (the same install as a hash hit)".to_string()), parts: lines.into_iter().map(Part::Line).collect() })
}

/// With `--similar-related`, hits that are close to a related file but not identical to it, below their stated
/// threshold, boilerplate last; or, when nothing could be compared, why.
fn similar_related_block(res: &HuntResult) -> Option<Block> {
    if res.similar.is_empty() && res.similar_notes.is_empty() {
        return None;
    }
    let pct = (H::SIMILAR_THRESHOLD * 100.0).round() as u32;
    let mut sr: Vec<&Finding> = res.similar.iter().collect();
    sr.sort_by(|a, b| {
        a.boilerplate
            .cmp(&b.boilerplate)
            .then_with(|| b.sim.unwrap_or(0.0).partial_cmp(&a.sim.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| (&a.where_, &a.loc).cmp(&(&b.where_, &b.loc)))
    });
    let mut parts: Vec<Part> = vec![];
    if !sr.is_empty() {
        let rows: Vec<Vec<String>> = sr
            .iter()
            .map(|f| {
                vec![
                    format!("{:.1}%{}", f.sim.unwrap_or(0.0) * 100.0, if f.boilerplate { " (boilerplate)" } else { "" }),
                    f.where_.clone(),
                    f.loc.clone(),
                    short_digest(&f.sha256, false),
                    f.like_file.clone(),
                ]
            })
            .collect();
        parts.push(tbl(&["SIMILARITY", "HOST", "PATH", "SHA256", "LIKE"], rows));
    }
    parts.extend(res.similar_notes.iter().map(|n| Part::Note(format!("note: {n}"))));
    Some(Block { title: Some(format!("SIMILAR, NOT IDENTICAL ({pct}% or more alike to files that came with a hash hit; not counted above)")), parts })
}

/// What one present-after row says about the place, by kind.
fn present_after_detail(f: &Finding, wide: bool) -> String {
    match f.kind {
        FKind::Repo => format!("{}@{} in {}", f.name, f.version, f.file),
        FKind::Cache => f.key.clone(),
        FKind::Artifact => f.name.clone(),
        FKind::Image => format!("{}{} {}", f.image, f.tags.first().map_or(String::new(), |t| format!(":{t}")), short_digest(&f.digest, wide)),
        FKind::Host => f.loc.clone(),
        FKind::ReleaseAsset => format!("{} {}", f.tag, f.asset),
        FKind::WorkflowRef => format!("{} {}", f.file, f.ref_),
        FKind::CiRun => format!("#{}", f.id),
    }
}

/// The findings that are present now but were first seen after the window ended. One heading, every view.
pub fn present_after_block(res: &HuntResult, ix: &Index, wide: bool) -> Option<Block> {
    if res.present_after.is_empty() {
        return None;
    }
    let multi = res.q.iocs.len() > 1;
    let mut fs: Vec<&Finding> = res.present_after.iter().collect();
    fs.sort_by(|a, b| (a.kind.name(), &a.where_, &a.first_seen).cmp(&(b.kind.name(), &b.where_, &b.first_seen)));
    let rows: Vec<Vec<String>> = fs
        .iter()
        .map(|f| {
            let mut r = vec![f.kind.name().replace('_', " "), f.where_.clone(), present_after_detail(f, wide), fmt_opt(f.first_seen.as_deref()), owner_str(ix, f)];
            if multi {
                r.push(f.iocs_or_one().join(", "));
            }
            r
        })
        .collect();
    let mut hdr = vec!["KIND", "PLACE", "DETAIL", "FIRST SEEN", "OWNER"];
    if multi {
        hdr.push("INDICATORS");
    }
    Some(Block {
        title: Some(PRESENT_AFTER_TITLE.to_string()),
        parts: vec![tbl(&hdr, rows), Part::Note("note: the window ends before these were first seen, but they are still there; they trip --fail-if found".into())],
    })
}

fn carried_rows(fs: &[&Finding], q: &H::Query) -> Vec<Vec<String>> {
    if !q.iocs.iter().any(|i| i.kind == IocKind::Sha256) {
        return vec![];
    }
    let mut rows: Vec<Vec<String>> = vec![];
    for f in fs {
        let Some(c) = f.carried_by.as_ref().filter(|c| !c.is_empty()) else { continue };
        let place = if f.kind == FKind::Image { f.image.clone() } else { f.where_.clone() };
        if !rows.iter().any(|r| r[0] == place && r[1] == *c) {
            rows.push(vec![place, c.clone()]);
        }
    }
    rows
}

fn person(ix: &Index, pid: &Option<String>) -> String {
    match pid {
        Some(p) => ix.person_name(p),
        None => "None".into(),
    }
}

fn history_lines(ix: &Index, rp: &[&Finding]) -> Vec<String> {
    let mut out = vec![];
    for f in rp {
        if f.state == "install-only" {
            continue;
        }
        out.push(format!("  {}  {}@{}", f.where_, f.name, f.version));
        if let Some(a) = &f.added_by {
            out.push(format!("    {}  added    {}  {}  {}", fmt_opt(f.first_seen.as_deref()), a.sha, person(ix, &a.author), a.message.clone().unwrap_or_default()));
        }
        if let Some(r) = &f.removed_by {
            out.push(format!("    {}  removed  {}  {}  {}", fmt_opt(f.removed_at.as_deref()), r.sha, person(ix, &r.author), r.message.clone().unwrap_or_default()));
        }
    }
    out
}

pub fn render_table(res: &HuntResult, ix: &Index, wide: bool) -> String {
    let mut lines = header_lines(res, ix);
    if res.q.iocs.len() > 1 {
        lines.push(String::new());
        lines.extend(per_ioc_table(res));
    }
    lines.extend(sections(res, ix, wide));
    lines.join("\n")
}

pub fn render_quiet(res: &HuntResult) -> String {
    let c = H::counts(res);
    let mut line = format!("{}  {}  {}", H::verdict(res), ioc_label(res), H::count_words(res));
    if c.findings > 0 || c.present_after > 0 {
        line += &format!(" (present now: {})", present_now_words(&c));
    }
    if c.present_after > 0 {
        line += &format!("  {}", PRESENT_AFTER_CELL.replace("{n}", &c.present_after.to_string()));
    }
    let n = res.not_checked.len();
    if n > 0 {
        line += &format!("  {}", plural(n, "gap"));
    }
    if c.possible > 0 {
        line += &format!("  {} possible", c.possible);
    }
    line + &format!("  index {}", fmtz(res.as_of.as_deref().unwrap_or("")))
}

pub fn finding_json(f: &Finding) -> J {
    let mut d = J::Obj(vec![]);
    d.set("kind", J::s(f.kind.name()));
    d.set("ioc", J::s(&f.ioc));
    d.set("where", J::s(&f.where_));
    d.set("first_seen", J::opt(f.first_seen.as_deref()));
    d.set("state", J::s(if f.state.is_empty() { "present" } else { f.state.as_str() }));
    if f.kind == FKind::Repo {
        d.set("version", J::s(&f.version));
        d.set("depth", J::s(&f.depth));
    }
    if f.kind == FKind::Image {
        d.set("path", J::s(&f.path));
    }
    if let Some(r) = &f.rt {
        // A runtime finding says the runtime, the version, how it was seen and how its line is fixed
        d.set("kind", J::s("runtime"));
        d.set("place_kind", J::s(f.kind.name()));
        d.set("runtime", J::s(&r.runtime));
        d.set("version", J::s(&r.version));
        d.set("seen_as", J::s(&r.seen_as));
        d.set("line_fixed", J::opt(r.line_fixed.as_deref()));
        d.set("eol", J::Bool(r.eol));
        d.set("move_to", J::opt(r.move_to.as_deref()));
    }
    d.set("secrets", J::strs(&f.secrets));
    d.set("removed_at", J::opt(f.removed_at.as_deref()));
    if let Some(c) = &f.cert {
        // The certificate and the trust store file it was read from
        d.set(
            "certificate",
            J::obj(vec![
                ("fingerprint", J::s(&c.fp)),
                ("subject", J::s(&c.subject)),
                ("issuer", J::s(&c.issuer)),
                ("role", J::s(if c.root { "root" } else { "intermediate" })),
                ("not_after", J::opt(c.not_after.as_deref())),
                ("file", J::s(&c.file)),
                ("store", J::s(&c.store)),
                ("in_deleted_layer", J::Bool(c.deleted)),
            ]),
        );
    }
    match f.kind {
        FKind::CiRun => {
            d.set("id", J::Int(f.id as i64));
            d.set("runner", J::s(&f.runner));
            d.set("at", J::s(&f.at));
            d.set("workflow", J::s(&f.workflow));
        }
        FKind::Host => d.set("path", J::s(&f.loc)),
        FKind::Image => {
            d.set("digest", J::s(&f.digest));
            d.set("tags", J::strs(&f.tags));
            d.set("path", J::s(&f.path));
            d.set("state", J::s(&f.where_in));
        }
        FKind::Cache => d.set("key", J::s(&f.key)),
        FKind::Artifact => {
            d.set("name", J::s(&f.name));
            d.set("id", J::Int(f.id as i64));
        }
        FKind::Repo => d.set("via", J::strs(&f.via)),
        _ => {}
    }
    d.set("owner", J::obj(vec![("team", J::opt(f.owner.team.as_deref())), ("people", J::strs(&f.owner.people))]));
    if let Some(c) = f.carried_by.as_ref().filter(|c| !c.is_empty()) {
        d.set("carried_by", J::s(c));
    }
    d.set("owner_label", J::s(if f.owner_label.is_empty() { "unresolved" } else { f.owner_label.as_str() }));
    if let Some(b) = f.layer_blob.as_ref().filter(|b| !b.is_empty()) {
        d.set("layer_blob", J::s(b));
    }
    if let Some(n) = f.executed_in_layer {
        d.set("executed_in_layer", J::Int(n as i64));
    }
    if let Some(w) = f.owner.suggested.as_ref() {
        d.set("owner_suggested", J::s(w));
    }
    if let Some(r) = f.workspace_repo.as_ref() {
        d.set("workspace_repo", J::s(r));
    }
    d.set("source", J::s(&f.source));
    d.set("location", J::s(&f.location));
    d.set("indicators", J::strs(&f.iocs_or_one()));
    d.set("last_seen", J::opt(f.last_seen.as_deref()));
    d.set("run_ids", J::Arr(f.run_ids.iter().map(|i| J::Int(*i as i64)).collect()));
    if f.possible {
        d.set("reason", J::s(&f.reason));
    }
    if f.match_ == "similar" || f.match_ == "rule" {
        d.set("match", J::s(&f.match_));
        if let Some(r) = f.rule.as_ref().filter(|r| !r.is_empty()) {
            d.set("rule", J::s(r));
        }
    }
    d
}

pub fn floating_json(f: &H::Floating) -> J {
    J::obj(vec![
        ("kind", J::s("runtime")),
        ("runtime", J::s(&f.runtime)),
        ("spec", J::s(&f.spec)),
        ("repo", J::s(&f.repo)),
        ("file", J::s(&f.file)),
        ("line", J::Int(f.line as i64)),
        ("seen_as", J::s(&f.seen_as)),
        ("floating", J::Bool(true)),
        ("note", J::s(FLOATING_WORDS)),
    ])
}

pub fn render_json(res: &HuntResult, ix: &Index) -> String {
    let q = &res.q;
    let v = match H::verdict(res) {
        "FOUND" => "found",
        "CLEAR" => "clear",
        _ => "clear_with_gaps",
    };
    let c = H::counts(res);
    let n = |x: usize| J::Int(x as i64);
    let pop = H::host_population(ix);
    let kinds = J::Obj(pop.kinds.iter().map(|(k, n)| (k.clone(), J::Int(*n as i64))).collect());
    let doc = J::obj(vec![
        (
            "query",
            J::obj(vec![
                ("iocs", J::Arr(q.iocs.iter().map(|i| J::s(&i.text)).collect())),
                ("window", q.window.as_ref().map_or(J::Null, |w| J::obj(vec![("from", J::s(&w.0)), ("to", J::s(&w.1))]))),
                ("when", J::s(if q.now_only { "now" } else { "ever" })),
                ("now", J::s(&ix.now)),
                ("index_as_of", J::opt(res.as_of.as_deref())),
            ]),
        ),
        ("verdict", J::s(v)),
        (
            "counts",
            J::obj(vec![
                ("repos", n(c.repos)),
                ("ci runs", n(c.ci_runs)),
                ("caches", n(c.caches)),
                ("artifacts", n(c.artifacts)),
                ("images", n(c.images)),
                ("hosts", n(c.hosts)),
                ("possible", n(c.possible)),
                ("releases", n(c.releases)),
                ("workflow refs", n(c.workflow_refs)),
                ("gaps", n(res.not_checked.len())),
                ("secrets", n(c.secrets)),
                ("secrets_separate", n(c.secrets_separate)),
                ("teams", n(c.teams)),
                ("places", n(c.places)),
                ("findings", n(c.findings)),
                ("locations", n(c.locations)),
                ("present_after_window", n(c.present_after)),
                ("findings_now", n(c.findings_now)),
                ("locations_now", n(c.locations_now)),
                ("rule matches", n(c.rule_matches)),
            ]),
        ),
        (
            "present_now",
            J::obj(vec![
                ("repos", n(c.now.repos)),
                ("images", n(c.now.images)),
                ("hosts", n(c.now.hosts)),
                ("caches", n(c.now.caches)),
                ("artifacts", n(c.now.artifacts)),
                ("releases", n(c.now.releases)),
                ("workflow refs", n(c.now.workflow_refs)),
            ]),
        ),
        ("window_ends_now", J::Bool(res.window_ends_now)),
        ("any_version", J::strs(&H::any_version_names(res))),
        ("moved_since_indexed", J::Arr(res.moved.iter().map(|(r, at)| J::obj(vec![("repo", J::s(r)), ("newest_commit", J::s(at))])).collect())),
        (
            "hosts_population",
            J::obj(vec![("hosts", n(pop.hosts)), ("kinds", kinds), ("org", J::opt(pop.org.as_deref())), ("members", n(pop.members)), ("no_laptop_names", J::strs(&pop.no_laptop_names))]),
        ),
        (
            "coverage",
            J::obj(vec![("sources_total", n(res.names.len())), ("stale", J::Arr(res.gaps.iter().map(|g| J::obj(vec![("source", J::s(&g.name)), ("indexed_at", J::s(&g.indexed_at))])).collect()))]),
        ),
        ("not_a_match", J::Arr(res.not_match.iter().map(|m| J::obj(vec![("indicator", J::s(&m.ioc)), ("file_name", J::s(&m.name)), ("files", n(m.count)), ("other_hash", J::s(&m.other))])).collect())),
        ("findings", J::Arr(H::findings(res).into_iter().map(finding_json).collect())),
        ("present_after_window", J::Arr(res.present_after.iter().map(finding_json).collect())),
        ("hash_advisories", J::Arr(res.hash_advisories.iter().map(|(h, id, pk)| J::obj(vec![("hash", J::s(h)), ("advisory", J::s(id)), ("packages", J::strs(pk))])).collect())),
        (
            "related",
            J::Arr(
                res.related
                    .iter()
                    .map(|r| {
                        J::obj(vec![
                            ("indicator", J::s(&r.ioc)),
                            ("host", J::s(&r.host)),
                            ("hit_path", J::s(&r.hit_path)),
                            ("tree", J::s(&r.tree)),
                            ("path", J::s(&r.path)),
                            ("sha256", J::s(&r.sha256)),
                            ("simhash", J::s(&r.simhash)),
                            ("hunt", J::s(format!("br hunt --similar sha256:{}", r.sha256.trim_start_matches("sha256:")))),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "similar_not_identical",
            J::Arr(
                res.similar
                    .iter()
                    .map(|f| {
                        let mut d = finding_json(f);
                        d.set("boilerplate", J::Bool(f.boilerplate));
                        d.set("like_file", J::s(&f.like_file));
                        d
                    })
                    .collect(),
            ),
        ),
        ("similar_threshold", J::Int((H::SIMILAR_THRESHOLD * 100.0).round() as i64)),
        ("similar_note", J::strs(&res.similar_notes)),
        ("past_runs", J::Arr(H::past_runs(res).into_iter().map(finding_json).collect())),
        ("possible", J::Arr(H::possible(res).into_iter().map(finding_json).collect())),
        ("floating", J::Arr(res.floating.iter().map(floating_json).collect())),
        (
            "not_checked",
            J::Arr(
                res.not_checked
                    .iter()
                    .map(|r| J::obj(vec![("name", J::s(&r.name)), ("kind", J::s(&r.kind)), ("state", J::s(&r.state)), ("why", J::s(&r.why)), ("command", J::s(&r.command))]))
                    .collect(),
            ),
        ),
    ]);
    doc.dumps()
}

/// One state vocabulary for the csv: present, removed, install-only, expired, ran, possible.
fn csv_state(f: &Finding) -> &'static str {
    if f.possible {
        return "possible";
    }
    match f.kind {
        FKind::CiRun => "ran",
        FKind::Repo => match f.state.as_str() {
            "removed" => "removed",
            "install-only" => "install-only",
            _ => "present",
        },
        _ => match f.state.as_str() {
            "expired" => "expired",
            _ => "present",
        },
    }
}

pub fn render_csv(res: &HuntResult) -> String {
    let hdr = ["kind", "ioc", "where", "detail", "first_seen", "state", "last_seen", "owner", "secrets", "indicators", "depth", "via", "file"];
    let mut rows: Vec<Vec<String>> = vec![hdr.iter().map(|s| s.to_string()).collect()];
    // What is present now but first seen after the window is a row too, in its own state
    let rows_in: Vec<(&Finding, bool)> = H::findings(res).into_iter().chain(H::past_runs(res)).chain(H::possible(res)).map(|f| (f, false)).chain(res.present_after.iter().map(|f| (f, true))).collect();
    for (f, after) in rows_in {
        let detail = match f.kind {
            _ if f.possible => f.reason.clone(),
            FKind::Host => f.loc.clone(),
            FKind::Cache => f.key.clone(),
            FKind::Repo | FKind::Artifact => f.name.clone(),
            FKind::Image => format!("{} ({})", f.digest, f.where_in),
            FKind::CiRun => format!("#{}", f.id),
            FKind::ReleaseAsset => format!("{} {}", f.tag, f.asset),
            FKind::WorkflowRef => f.file.clone(),
        };
        let owner = if f.owner_label.is_empty() { "unresolved".to_string() } else { f.owner_label.clone() };
        rows.push(vec![
            f.kind.name().into(),
            f.ioc.clone(),
            f.where_.clone(),
            detail,
            f.first_seen.clone().unwrap_or_default(),
            if after { "present-after-window".to_string() } else { csv_state(f).to_string() },
            f.last_seen.clone().unwrap_or_default(),
            owner,
            f.secrets.join(" "),
            f.iocs_or_one().join(" "),
            // How a package got in (direct or transitive, and through what), and the file that says so
            if f.kind == FKind::Repo { f.depth.clone() } else { String::new() },
            if f.kind == FKind::Repo { f.via.join(" > ") } else { String::new() },
            match f.kind {
                FKind::Repo | FKind::WorkflowRef => f.file.clone(),
                FKind::Host => f.loc.clone(),
                FKind::Image => f.path.clone(),
                FKind::ReleaseAsset => f.asset.clone(),
                _ => String::new(),
            },
        ]);
    }
    rows.iter().map(|r| r.iter().map(|c| crate::out::sqlcmd::csv_quote(&crate::out::sqlcmd::csv_safe(c))).collect::<Vec<_>>().join(",")).collect::<Vec<_>>().join("\n")
}

/// The longest run of backticks in `s`.
pub fn longest_ticks(s: &str) -> usize {
    let (mut best, mut run) = (0, 0);
    for c in s.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        best = best.max(run);
    }
    best
}

pub fn render_md(res: &HuntResult, ix: &Index, wide: bool) -> String {
    let core: Vec<String> = header_core(res, ix).into_iter().filter(|l| !l.is_empty()).collect();
    let verdict = H::verdict(res);
    let head = core.iter().position(|l| l.starts_with(verdict)).unwrap_or(0);
    let mut out = vec![format!("# {}", core.get(head).cloned().unwrap_or_default()), String::new()];
    out.extend(core.iter().enumerate().filter(|(i, _)| *i != head).map(|(_, l)| format!("- {l}")));
    let mut blocks = header_blocks(res);
    blocks.extend(section_blocks(res, ix, wide));
    out.extend(blocks_md(&blocks));
    out.join("\n")
}

fn changed_sentence(res: &HuntResult, ix: &Index) -> Option<String> {
    let ch = H::changed_since_scan(ix, &res.q, res)?;
    if ch.delta.is_empty() {
        return None;
    }
    let bits: Vec<String> = ch
        .delta
        .iter()
        .map(|(k, a, b)| {
            let w = match k.as_str() {
                "ci runs" => "CI runs",
                "secrets" => "secret names",
                o => o,
            };
            format!("{w} {b}, {} from {a}", if b > a { "up" } else { "down" })
        })
        .collect();
    Some(format!("The numbers changed since the last {} ({}): {}; the earlier numbers are the index as of {}; {}.", ch.kind, fmtz(&ch.at), bits.join("; "), fmtz(&ch.was_at), rescanned_why(&ch)))
}

/// Every indicator of the question is a certificate (nothing to rotate, nothing to uninstall).
pub fn cert_only(res: &HuntResult) -> bool {
    !res.q.iocs.is_empty() && res.q.iocs.iter().all(|i| i.kind == IocKind::Cert)
}

pub fn summary(res: &HuntResult, ix: &Index, customers: bool) -> String {
    let q = &res.q;
    let fs = H::findings(res);
    let c = H::counts(res);
    let adv = q.adv.as_ref().map_or(String::new(), |a| format!(" ({})", a.id));
    let what = if q.adv.is_some() { "the affected packages".to_string() } else { ioc_label(res) };
    let mut out: Vec<String> = vec![];
    let unchecked = &res.not_checked;
    let as_of = res.as_of.clone().unwrap_or_default();
    let range = crate::query::coverage::data_as_of(ix, &res.names);
    let asof = if customers {
        let long = |t: &str| {
            let a = norm_iso(t).unwrap_or_else(|_| t.to_string());
            match (a.get(..10), a.get(11..16)) {
                (Some(d), Some(t)) => Some(format!("{d} {t} UTC")),
                _ => None,
            }
        };
        match long(&as_of) {
            // When the sources were checked at different times, the oldest is said too
            Some(n) => match range.as_ref().filter(|d| d.oldest != d.newest).and_then(|d| long(&d.oldest)) {
                Some(o) => format!("as of {n} (the oldest source was checked at {o})"),
                None => format!("as of {n}"),
            },
            None => "as of an unrecorded time".to_string(),
        }
    } else {
        format!("Data as of {}", range.as_ref().map_or_else(|| fmtz(&as_of), |d| d.words()))
    };
    let v = H::verdict(res);
    if v == "FOUND" {
        let mut bits = vec![];
        if c.repos > 0 {
            bits.push(plural(c.repos, "repo"));
        }
        if c.images > 0 {
            bits.push(plural(c.images, "image"));
        }
        if c.hosts > 0 {
            bits.push(plural(c.hosts, "machine"));
        }
        for (n, lbl) in [(c.caches, "cache"), (c.artifacts, "build artifact"), (c.releases, "release asset")] {
            if n > 0 {
                bits.push(plural(n, lbl));
            }
        }
        if c.workflow_refs > 0 {
            bits.push(plural(c.workflow_refs, "workflow reference"));
        }
        let first = fs.iter().filter(|f| f.first_seen.is_some()).min_by(|a, b| a.first_seen.cmp(&b.first_seen));
        if customers {
            let d = first.and_then(|f| f.first_seen.as_deref()).map_or(String::new(), |s| s.chars().take(10).collect());
            if d.is_empty() {
                out.push(format!("Yes. Some of our internal systems contained or ran {what}{adv}."));
            } else {
                out.push(format!("Yes. Some of our internal systems contained or ran {what}{adv}, starting on {d}."));
            }
            if cert_only(res) {
                out.push("Recommended next step is to remove the certificate from the trust stores that hold it.".into());
            } else if H::any_version_only(res) {
                out.push("No affected version has been named, so we have not established what to remove or rotate.".into());
            } else {
                out.push("Recommended next steps are to remove them and to rotate any credentials that those systems could read.".into());
            }
            out.push("We have not established whether any customer data was involved.".into());
            if unchecked.is_empty() {
                out.push(format!("Our findings are {asof}."));
            } else {
                out.push(format!("Our findings are {asof}. Some systems have not been fully checked yet, so this statement can still change."));
            }
            return out.join("\n");
        }
        if bits.is_empty() {
            bits = c.now.bits();
        }
        out.push(format!("Yes. {} contain or contained {what}{adv}.", join_and(&bits)));
        if c.possible > 0 {
            out.push(format!("{} may also be affected but could not be confirmed.", H::possible_words(&c)));
        }
        // Every kind, from the one place that counts what is present now
        if c.now.total() > 0 {
            out.push(format!("Still present: {}.", present_now_words(&c)));
        }
        if c.present_after > 0 {
            out.push(format!("Also present now, first seen after the window: {}.", uniq(res.present_after.iter().map(|f| f.where_.clone())).join(", ")));
        }
        let mut line = String::new();
        if let Some(f) = first {
            line = format!("First seen {}Z ({}).", fmt_opt(f.first_seen.as_deref()), f.where_);
        }
        if c.ci_runs > 0 {
            let sec = H::secrets_of(res);
            line += &format!(
                " {} saw it{}",
                plural(c.ci_runs, "CI run"),
                if sec.is_empty() {
                    ".".to_string()
                } else {
                    format!(
                        "; {} were in reach.",
                        if res.secrets_separate > sec.len() { format!("{} secret names, {} secrets", sec.len(), res.secrets_separate) } else { plural(sec.len(), "secret name") }
                    )
                }
            );
        }
        out.push(line.trim().to_string());
        // A cache hit of a package that runs code at install is an execution
        let ran = uniq_count(fs.iter().filter(|f| f.kind == FKind::Host && H::install_ran_note(&f.note)).map(|f| f.where_.clone()));
        let ci_ran = uniq_count(fs.iter().filter(|f| f.kind == FKind::Host && f.note.starts_with("the install ran here")).map(|f| f.where_.clone()));
        if ran > 0 {
            // A machine where a CI run installed it is told apart from one with a cache entry only
            let how = if ci_ran == ran { "the install ran".to_string() } else { "the install likely ran".to_string() };
            let ci_note = if ci_ran > 0 && ci_ran < ran { format!("; on {ci_ran} of them a CI run installed it") } else { String::new() };
            out.push(format!(
                "On {} {how} (the advisory says installing it runs code{ci_note}): isolate {}, keep a copy of the cache, and rotate what the user could read.{}",
                plural(ran, "machine"),
                if ran == 1 { "it" } else { "them" },
                if ci_ran > 0 { " A runner where a CI run installed it is reimaged." } else { "" }
            ));
        }
        if cert_only(res) {
            out.push("Recommended next steps: the owning teams rebuild the images on an updated base, update ca-certificates on the machines and delete the certificate from files in repos (br fix lists each). br changes nothing.".into());
        } else if H::any_version_only(res) {
            out.push("This is a search for any version. Name the affected version (eco:name@VERSION) or an advisory before anything is removed or rotated.".into());
        } else if !fs.is_empty() && fs.iter().all(|f| f.rt.is_some()) {
            out.push(
                "Recommended next steps: the owning teams move each runtime to the fixed release of its line and rebuild the images (br fix lists each). None of this is known to be done.".into(),
            );
        } else {
            out.push("Recommended next steps: the owning teams remove the packages, rebuild the images and rotate the secrets (br notify lists who). None of this is known to be done.".into());
        }
    } else if v == "CLEAR WITH GAPS" {
        out.push(format!("No findings, but not every source could be checked, so we cannot say No for certain{adv}."));
    } else {
        out.push(format!("No. Nothing in the checked sources contains {what}{adv}."));
    }
    if !res.floating.is_empty() {
        out.push(format!("{} could not be judged: {FLOATING_WORDS}.", plural(res.floating.len(), "floating runtime reference")));
    }
    if customers {
        if unchecked.is_empty() {
            out.push(format!("Our findings are {asof}."));
        } else {
            out.push(format!("Our findings are {asof}. Some systems have not been fully checked yet, so this statement can still change."));
        }
    } else if !unchecked.is_empty() {
        out.push(format!("{asof}. Not checked: {} ({}). The number can still change.", plural(unchecked.len(), "source"), unchecked.iter().map(H::row_label).collect::<Vec<_>>().join("; ")));
    } else {
        out.push(format!("{asof}. All sources were checked. The number can still change if new data arrives."));
    }
    if !customers {
        if let Some(ch) = changed_sentence(res, ix) {
            out.push(ch);
        }
    }
    out.join("\n")
}

/// The hunt that reproduces this result, for "N more" tails.
fn hunt_cmd(res: &HuntResult) -> String {
    match &res.q.adv {
        Some(a) => format!("br hunt --advisory {}", crate::out::shell::shquote(&a.id)),
        None => format!("br hunt {}", res.q.iocs.iter().map(|i| crate::out::shell::shquote(&i.text)).collect::<Vec<_>>().join(" ")),
    }
}

/// "a, b, c and N more (CMD lists them)": a list may be shortened in a post only with its count and where the rest is.
fn short_list(items: &[String], max: usize, cmd: &str) -> String {
    if items.len() <= max {
        return items.join(", ");
    }
    format!("{} and {} more ({cmd} lists them)", items[..max].join(", "), items.len() - max)
}

/// An ordered list a post may shorten only from the bottom, and never past an item that matters (`keep` of them are the
/// first ones: the places where the install likely ran). The count of the rest and the command that lists them stay.
fn short_ordered(items: &[String], keep: usize, max: usize, cmd: &str) -> String {
    short_list(items, max.max(keep), cmd)
}

/// The rank of a place in a post: where the install likely ran, then what is present, then the rest.
fn place_rank(f: &Finding) -> u8 {
    if H::install_ran_note(&f.note) {
        0
    } else if H::present_now(f) {
        1
    } else {
        2
    }
}

pub fn render_slack(res: &HuntResult, ix: &Index) -> String {
    let c = H::counts(res);
    let v = H::verdict(res);
    let head = match &res.q.adv {
        None => format!("*{v}*  {}", ioc_label(res)),
        Some(a) => {
            let hits = H::ioc_hits(res).iter().filter(|(_, n)| *n > 0).count();
            let n = res.q.iocs.len();
            let what = if hits > 0 && hits < n { format!("{hits} of {n} indicators") } else { plural(n, "indicator") };
            format!("*{v}*  {} ({what})", a.id)
        }
    };
    let md_cmd = format!("{} --format md", hunt_cmd(res));
    let mut out = vec![format!(
        "{head}{}  (data as of {})",
        if c.findings > 0 { format!("  {}", H::count_words(res)) } else { String::new() },
        crate::query::coverage::data_as_of(ix, &res.names).map_or_else(|| fmtz(res.as_of.as_deref().unwrap_or("")), |d| d.words())
    )];
    if let Some(nh) = H::no_hit_note(res) {
        out.push(format!("• {nh}"));
    }
    if v == "FOUND" {
        if let Some(hs) = human_sentence(res) {
            out.push(format!("• {hs}"));
        }
        if c.findings > 0 || c.present_after > 0 {
            out.push(format!("• Present now: {}; the rest is history", present_now_words(&c)));
        }
        if c.present_after > 0 {
            let names: Vec<String> = uniq(res.present_after.iter().map(|f| format!("{} ({})", f.where_, owner_str(ix, f))));
            out.push(format!("• {PRESENT_AFTER_TITLE}: {} ({})", short_list(&names, 8, &md_cmd), PRESENT_AFTER_CELL.replace("{n}", &c.present_after.to_string())));
        }
        // Pasteable. Every repo that still has it (archived and install-only ones too) with its owners, every
        // other present place, and every secret name: a post may shorten a list of places, never the repos or secrets.
        let mut repos: Vec<(String, String)> = vec![];
        for f in H::findings(res) {
            if f.kind == FKind::Repo && (f.state.starts_with("present") || f.state == "install-only") && !repos.iter().any(|r| r.1 == f.where_) {
                let tag = if f.state == "install-only" {
                    ", install-only"
                } else if f.archived {
                    ", archived"
                } else {
                    ""
                };
                repos.push((format!("{} ({}{tag})", f.where_, owner_str(ix, f)), f.where_.clone()));
            }
        }
        if !repos.is_empty() {
            let shown = repos.iter().map(|r| r.0.clone()).collect::<Vec<_>>().join(", ");
            out.push(format!("• {}: {shown}", if H::any_version_only(res) { "In repos" } else { "Fix in" }));
        }
        // Each place once (a host or an image is one place however many of its files hit), in the order likely-ran,
        // present, rest; the list is cut only from the bottom and never past a place where the install likely ran
        let mut placed: Vec<(u8, String, String)> = vec![];
        let mut fs_sorted: Vec<&Finding> = H::findings(res);
        fs_sorted.sort_by_key(|f| place_rank(f));
        for f in fs_sorted {
            let (key, item) = match f.kind {
                FKind::Image => (f.digest.clone(), format!("image {}:{} ({})", f.image, f.tags.first().cloned().unwrap_or_else(|| "-".into()), where_in_words(f))),
                FKind::Host => (
                    f.where_.clone(),
                    format!(
                        "host {} ({}){}",
                        f.where_,
                        f.loc,
                        if f.note.starts_with("the install ran here") {
                            " - the install ran"
                        } else if H::install_ran_note(&f.note) {
                            " - the install likely ran"
                        } else {
                            ""
                        }
                    ),
                ),
                FKind::Cache => (format!("{}\x01{}", f.where_, f.key), format!("cache {} ({})", f.key, f.where_)),
                FKind::Artifact => (format!("{}\x01{}", f.where_, f.id), format!("artifact {} ({})", f.name, f.where_)),
                FKind::ReleaseAsset => (format!("{}\x01{}\x01{}", f.where_, f.tag, f.asset), format!("release asset {} ({} {})", f.asset, f.where_, f.tag)),
                _ => continue,
            };
            let key = format!("{}\x01{key}", f.kind.name());
            if !placed.iter().any(|p| p.1 == key) {
                placed.push((place_rank(f), key, item));
            }
        }
        let clean: Vec<String> = placed.iter().map(|p| p.2.clone()).collect();
        let likely = placed.iter().filter(|p| p.0 == 0).count();
        if !clean.is_empty() {
            out.push(format!("• {}: {}", if H::any_version_only(res) { "Where it is" } else { "To clean" }, short_ordered(&clean, likely, 8, &md_cmd)));
        }
        if c.ci_runs > 0 {
            // Each run lists the secrets it could read
            let runs: Vec<String> = H::findings(res)
                .into_iter()
                .filter(|f| f.kind == FKind::CiRun)
                .map(|f| if f.secrets.is_empty() { format!("{}#{} (no secrets)", f.where_, f.id) } else { format!("{}#{} ({})", f.where_, f.id, f.secrets.join(", ")) })
                .collect();
            out.push(format!("• CI runs: {} ran it{}: {}", c.ci_runs, if c.secrets > 0 { format!(" and could read {}", c.secret_words()) } else { String::new() }, short_list(&runs, 10, &md_cmd)));
        }
        let sec = secret_uses(ix, res);
        if !sec.is_empty() {
            let shown = sec
                .iter()
                .map(|u| {
                    let mut tags: Vec<String> = vec![];
                    if u.scope != "unknown" {
                        tags.push(u.scope.clone());
                    }
                    tags.push(u.owner_cell());
                    if tags.is_empty() {
                        u.name.clone()
                    } else {
                        format!("{} ({})", u.name, tags.join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            out.push(format!("• {}: {shown}", if H::any_version_only(res) { "Secrets the runs could read" } else { "Secrets to rotate" }));
        }
    } else if v == "CLEAR" {
        out.push("• Nothing found in the checked sources.".into());
    } else {
        out.push("• Nothing found, but not everything could be checked.".into());
    }
    if c.possible > 0 {
        // A machine where a run installed it comes first and is never cut, then the other machines, then the people
        let mut ps: Vec<&Finding> = H::possible(res);
        ps.sort_by_key(|f| {
            if f.inferred {
                0
            } else if f.person {
                2
            } else {
                1
            }
        });
        let ran = ps.iter().filter(|f| f.inferred).count();
        let names: Vec<String> = ps.iter().map(|f| f.where_.clone()).collect();
        out.push(format!("• Possible, not confirmed: {} (verify first): {}", H::possible_words(&c), short_ordered(&names, ran, 8, &md_cmd)));
    }
    let nc = &res.not_checked;
    if !nc.is_empty() {
        let names: Vec<String> = nc.iter().map(|n| n.name.clone()).collect();
        out.push(format!("• Not checked: {} ({})", short_list(&names, 5, &md_cmd), plural(nc.len(), "gap")));
    }
    for l in not_match_lines(res).into_iter().chain(hash_advisory_lines(res)) {
        out.push(format!("• {l}"));
    }
    if v == "FOUND" && H::any_version_only(res) {
        out.push("• No affected version is named: hunt with eco:name@VERSION or --advisory ID before anything is removed or rotated".to_string());
    } else if v == "FOUND" {
        let cmd = match &res.q.adv {
            Some(a) => format!("br notify --advisory {}", a.id),
            None => format!("br notify {}", res.q.iocs.iter().map(|i| i.text.clone()).collect::<Vec<_>>().join(" ")),
        };
        out.push(format!("• Next: {cmd} (one message per owning team)"));
    }
    out.join("\n")
}

#[cfg(test)]
mod f4_tests {
    use super::*;

    #[test]
    fn ticks_are_counted() {
        assert_eq!(longest_ticks("a ```` b ` c"), 4);
        assert_eq!(longest_ticks("none"), 0);
    }
}

#[cfg(test)]
mod r6_render_tests {
    use super::*;
    use crate::query::hunt::{NotChecked, Owner};
    use crate::view::{Source, Team, View};

    const NOW: &str = "2026-10-01T00:00:00Z";

    fn q1(ioc: &str) -> H::Query {
        H::Query { iocs: vec![crate::query::iocs::parse_ioc(ioc, None).unwrap()], ..Default::default() }
    }

    fn repo_hit(repo: &str, state: &str, archived: bool) -> Finding {
        Finding {
            kind: FKind::Repo,
            ioc: "npm:evil@1.2.3".into(),
            iocs: vec!["npm:evil@1.2.3".into()],
            where_: repo.into(),
            state: state.into(),
            file: "package-lock.json".into(),
            version: "1.2.3".into(),
            depth: "direct".into(),
            name: "evil".into(),
            archived,
            first_seen: Some("2026-09-01T00:00:00Z".into()),
            owner_label: "@acme/web".into(),
            owner: Owner { team: Some("@acme/web".into()), ..Default::default() },
            ..Default::default()
        }
    }

    fn run_hit(repo: &str, id: u64, secrets: &[&str]) -> Finding {
        Finding {
            kind: FKind::CiRun,
            ioc: "npm:evil@1.2.3".into(),
            iocs: vec!["npm:evil@1.2.3".into()],
            where_: repo.into(),
            id,
            at: "2026-09-02T00:00:00Z".into(),
            runner: "github-hosted".into(),
            workflow: "ci".into(),
            state: "ran".into(),
            secrets: secrets.iter().map(|s| s.to_string()).collect(),
            owner_label: "@acme/web".into(),
            owner: Owner { team: Some("@acme/web".into()), ..Default::default() },
            ..Default::default()
        }
    }

    fn view() -> View {
        let mut v = View { now: NOW.into(), ..Default::default() };
        v.teams = vec![Team { id: "@acme/web".into(), ..Default::default() }];
        for n in ["acme/a", "acme/b", "acme/c"] {
            v.sources.insert(n.into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: NOW.into(), ..Default::default() });
        }
        v
    }

    fn result() -> HuntResult {
        HuntResult {
            q: q1("npm:evil@1.2.3"),
            findings: vec![
                repo_hit("acme/a", "present", false),
                repo_hit("acme/b", "present (archived)", true),
                repo_hit("acme/c", "install-only", false),
                run_hit("acme/a", 7, &["NPM_TOKEN", "A|B"]),
            ],
            names: vec!["acme/a".into(), "acme/b".into(), "acme/c".into()],
            scope_total: 3,
            as_of: Some(NOW.into()),
            ..Default::default()
        }
    }

    // The slack post keeps archived and install-only repos in "Fix in", every secret name, and the CI runs
    #[test]
    fn slack_keeps_every_present_repo_every_secret_and_the_runs() {
        let v = view();
        let ix = Index::new(&v, NOW);
        let s = render_slack(&result(), &ix);
        assert!(s.contains("acme/a (@acme/web)") && s.contains("acme/b (@acme/web, archived)") && s.contains("acme/c (@acme/web, install-only)"), "{s}");
        assert!(s.contains("NPM_TOKEN") && s.contains("A|B"), "{s}");
        assert!(s.contains("CI runs: 1 ran it"), "{s}");
    }

    // Md renders tables as tables, with no code fence and no empty bullet
    #[test]
    fn md_has_pipe_tables_no_fence_and_no_empty_bullets() {
        let v = view();
        let ix = Index::new(&v, NOW);
        let mut res = result();
        res.not_checked = vec![NotChecked { name: "acme/b".into(), state: "stale".into(), why: "stale: indexed 09-01".into(), command: "br scan --repo acme/b".into(), ..Default::default() }];
        let md = render_md(&res, &ix, false);
        assert!(!md.contains("```"), "{md}");
        assert!(md.lines().all(|l| l.trim() != "-"), "{md}");
        assert!(md.contains("| REPO | STATE |") && md.contains("|---|"), "{md}");
        assert!(md.contains("## NOT CHECKED") && md.contains("| SOURCE | WHY | TO CLOSE |"), "{md}");
        assert!(md.contains("A\\|B"), "a pipe in a cell is escaped: {md}");
        assert!(md.starts_with("# FOUND"), "{md}");
    }

    // Csv has an owner column, one state vocabulary, and the secrets of each run
    #[test]
    fn csv_has_owner_state_and_secrets() {
        let csv = render_csv(&result());
        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), "kind,ioc,where,detail,first_seen,state,last_seen,owner,secrets,indicators,depth,via,file");
        let rows: Vec<&str> = lines.collect();
        assert!(rows.iter().any(|r| r.starts_with("repo,npm:evil@1.2.3,acme/b,evil,") && r.contains(",present,")), "archived is present: {rows:?}");
        assert!(rows.iter().any(|r| r.contains(",install-only,")), "{rows:?}");
        assert!(rows.iter().any(|r| r.starts_with("ci_run,") && r.contains(",ran,") && r.contains("@acme/web") && r.contains("NPM_TOKEN")), "{rows:?}");
    }

    // An empty host is not "searched"
    #[test]
    fn a_host_that_hashed_nothing_is_not_counted_as_searched() {
        let mut v = View { now: NOW.into(), ..Default::default() };
        v.sources.insert("h1".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: NOW.into(), ..Default::default() });
        v.sources.insert("h2".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: NOW.into(), empty: true, ..Default::default() });
        let ix = Index::new(&v, NOW);
        let res = HuntResult { q: q1("npm:x@1.0.0"), names: vec!["h1".into(), "h2".into()], ..Default::default() };
        let line = nothing_found_line(&res, &ix);
        assert!(line.starts_with("nothing found in 1 host;"), "{line}");
        assert!(line.contains("h2 had nothing to read") && line.contains("not searched"), "{line}");
    }

    // --only keeps a one-line footer with what it hides
    #[test]
    fn only_says_what_it_hides() {
        let mut res = result();
        res.q.only = ["repos".to_string()].into();
        res.full_findings = Some(9);
        res.hidden_gaps = vec![("ghcr.io".into(), "stale".into())];
        let l = only_lines(&res);
        assert_eq!(l.len(), 1);
        assert!(l[0].contains("shows 4 of the whole answer's 9 findings") && l[0].contains("1 gap outside it: ghcr.io"), "{l:?}");
    }

    // Present now but first seen after the window has one heading and one headline clause in every view
    #[test]
    fn present_after_has_one_heading_and_one_clause_in_every_view() {
        let v = view();
        let ix = Index::new(&v, NOW);
        let mut res = result();
        res.findings.clear();
        res.present_after = vec![repo_hit("acme/c", "present", false)];
        assert_eq!(H::verdict(&res), "FOUND");
        let table = render_table(&res, &ix, false);
        assert!(table.contains("PRESENT NOW, FIRST SEEN AFTER THE WINDOW") && table.contains("+ 1 present now, first seen after the window"), "{table}");
        assert!(render_md(&res, &ix, false).contains("## PRESENT NOW, FIRST SEEN AFTER THE WINDOW"));
        assert!(render_slack(&res, &ix).contains("PRESENT NOW, FIRST SEEN AFTER THE WINDOW: acme/c"));
        assert!(summary(&res, &ix, false).contains("Also present now, first seen after the window: acme/c."));
        assert!(render_quiet(&res).contains("+ 1 present now, first seen after the window"));
        assert!(render_csv(&res).lines().any(|l| l.starts_with("repo,") && l.contains(",present-after-window,")));
        assert!(render_json(&res, &ix).contains("\"present_after_window\": ["));
    }

    // A hash that an advisory lists says which advisory, and which packages
    #[test]
    fn a_listed_hash_names_its_advisory_and_packages() {
        let h = format!("sha256:{}", "ab".repeat(32));
        let mut res = HuntResult { q: H::Query { iocs: vec![crate::query::iocs::parse_ioc(&h, None).unwrap()], ..Default::default() }, ..Default::default() };
        res.hash_advisories = vec![(h, "GHSA-aaaa-bbbb-cccc".into(), vec!["npm:evil".into(), "pypi:evil-py".into()])];
        assert_eq!(
            hash_advisory_lines(&res),
            vec!["this hash is listed by GHSA-aaaa-bbbb-cccc, which names npm:evil pypi:evil-py; br hunt --advisory GHSA-aaaa-bbbb-cccc covers the packages".to_string()]
        );
    }

    // A --now answer says which possible rows it dropped
    #[test]
    fn now_says_why_possible_shrank() {
        let mut res = result();
        res.possible_dropped = vec!["Dana (@dana)".into(), "Lena (@lena)".into()];
        let l = only_lines(&res);
        assert!(l[0].starts_with("2 fewer possible than without --now: Dana (@dana), Lena (@lena)"), "{l:?}");
    }
}
