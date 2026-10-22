//! `--format overview`: a compact, colored first screen for `br hunt`. Every number comes from `H::counts`, the function
//! the table and the summary count with, so the three views agree. Kinds that are not in the known list below are counted
//! generically from the findings, so a new `FKind` shows up here without a change.

use std::collections::BTreeSet;

use crate::query::hunt::{self as H, FKind, Finding, HuntResult};
use crate::query::index::Index;
use crate::query::util::*;

/// ANSI styling that switches off as a whole.
#[derive(Clone, Copy)]
pub struct Pal(pub bool);

impl Pal {
    fn w(&self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.w("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.w("2", s)
    }
    fn red(&self, s: &str) -> String {
        self.w("31", s)
    }
    fn amber(&self, s: &str) -> String {
        self.w("33", s)
    }
    fn cyan(&self, s: &str) -> String {
        self.w("36", s)
    }
}

/// One count in the grid.
#[derive(Debug, Clone, PartialEq)]
pub struct Card {
    pub glyph: &'static str,
    pub n: usize,
    pub label: String,
    pub sub: Option<String>,
    /// the key `count_line` writes for the same number (for the parity test)
    pub key: &'static str,
}

fn card(glyph: &'static str, n: usize, label: &str, sub: Option<String>, key: &'static str) -> Option<Card> {
    (n > 0).then(|| Card { glyph, n, label: label.to_string(), sub, key })
}

fn one_or(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        one.to_string()
    } else {
        many.to_string()
    }
}

/// The grid, in a fixed order, zero counts left out.
pub fn cards(res: &HuntResult) -> Vec<Card> {
    let c = H::counts(res);
    let fs = H::findings(res);
    let mut out: Vec<Card> = vec![];
    let sub_now = |n: usize| (n > 0).then(|| format!("{n} still present"));
    out.extend(card("▣", c.repos, &one_or(c.repos, "repo", "repos"), sub_now(c.now.repos), "repos"));
    out.extend(card("⚙", c.ci_runs, &one_or(c.ci_runs, "CI run", "CI runs"), None, "ci runs"));
    let deleted = fs.iter().any(|f| f.kind == FKind::Image && f.deleted_in.is_some());
    let img_sub = if deleted { Some("layer deleted".to_string()) } else { sub_now(c.now.images) };
    out.extend(card("⬢", c.images, &one_or(c.images, "image", "images"), img_sub, "images"));
    out.extend(card("◆", c.caches, &one_or(c.caches, "cache", "caches"), None, "caches"));
    out.extend(card("◇", c.artifacts, &one_or(c.artifacts, "artifact", "artifacts"), None, "artifacts"));
    out.extend(card("●", c.hosts, &one_or(c.hosts, "machine", "machines"), None, "hosts"));
    out.extend(card("▲", c.releases, &one_or(c.releases, "release asset", "release assets"), None, "releases"));
    out.extend(card("◈", c.workflow_refs, &one_or(c.workflow_refs, "workflow ref", "workflow refs"), None, "workflow refs"));
    // kinds this file does not know by name: counted as distinct places, so a new kind is never silent
    let known = |k: FKind| matches!(k, FKind::Repo | FKind::CiRun | FKind::Image | FKind::Cache | FKind::Artifact | FKind::Host | FKind::ReleaseAsset | FKind::WorkflowRef);
    let mut other: Vec<FKind> = vec![];
    for f in fs.iter().filter(|f| !H::is_lookalike(f) && !known(f.kind)) {
        if !other.contains(&f.kind) {
            other.push(f.kind);
        }
    }
    for k in other {
        let n = fs.iter().filter(|f| f.kind == k && !H::is_lookalike(f)).map(|f| H::place_key(f)).collect::<BTreeSet<_>>().len();
        out.extend(card("■", n, &k.name().replace('_', " "), None, "other"));
    }
    out.extend(card("⚿", c.secrets, &one_or(c.secrets, "secret to rotate", "secrets to rotate"), None, "secrets"));
    out.extend(card("◉", c.teams, &one_or(c.teams, "team to notify", "teams to notify"), None, "teams"));
    out.extend(card("◐", c.present_after, "present now, first seen after the window", None, "present_after"));
    out.extend(card("?", c.possible, "possible, not counted", None, "possible"));
    out
}

struct Place {
    present: bool,
    kind_ord: u8,
    place: String,
    owner: String,
    state: String,
    detail: String,
}

fn place_of(f: &Finding, owner: &dyn Fn(&Finding) -> String) -> Place {
    let present = H::present_now(f);
    let (kind_ord, place, detail) = match f.kind {
        FKind::Repo => (0, f.where_.clone(), format!("{}@{} in {}", f.name, f.version, f.file)),
        FKind::Image => (1, format!("{}{}", f.image, f.tags.first().map_or(String::new(), |t| format!(":{t}"))), f.layer_cmd.clone().unwrap_or_else(|| f.digest.chars().take(19).collect())),
        FKind::Host => (2, f.where_.clone(), f.location.clone()),
        FKind::Cache => (3, f.where_.clone(), f.key.clone()),
        FKind::Artifact => (3, f.where_.clone(), format!("#{}", f.id)),
        FKind::ReleaseAsset => (4, f.where_.clone(), format!("{} {}", f.tag, f.asset)),
        FKind::WorkflowRef => (4, f.where_.clone(), format!("{} {}", f.file, f.ref_)),
        FKind::CiRun => (5, f.where_.clone(), format!("run #{} {}", f.id, f.workflow)),
    };
    let state = match f.kind {
        FKind::CiRun => "ran".to_string(),
        FKind::Image if f.deleted_in.is_some() => "layer deleted".to_string(),
        _ => f.state.clone(),
    };
    Place { present, kind_ord, place, owner: owner(f), state, detail }
}

fn fit(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w {
        format!("{s}{}", " ".repeat(w - n))
    } else if w == 0 {
        String::new()
    } else {
        format!("{}…", s.chars().take(w - 1).collect::<String>())
    }
}

fn clip(s: &str, w: usize) -> String {
    fit(s, w).trim_end().to_string()
}

fn shq(s: &str) -> String {
    crate::out::shell::shquote(s)
}

/// The indicator arguments, as the person typed them.
fn args_of(res: &HuntResult) -> String {
    match &res.q.adv {
        Some(a) => format!("--advisory {}", shq(&a.id)),
        None => res.q.iocs.iter().map(|i| shq(&i.text)).collect::<Vec<_>>().join(" "),
    }
}

/// What the layout needs from the index, so it can be tested without one.
pub struct Env<'a> {
    pub now: String,
    pub oldest: Option<String>,
    pub owner: &'a dyn Fn(&Finding) -> String,
}

pub fn render_overview(res: &HuntResult, ix: &Index, color: bool, width: usize) -> String {
    let owner = |f: &Finding| crate::out::render::owner_str(ix, f);
    let oldest = crate::query::coverage::data_as_of(ix, &res.names).map(|d| d.oldest).or_else(|| res.as_of.clone());
    build(res, &Env { now: ix.now.clone(), oldest, owner: &owner }, Pal(color), width)
}

pub fn build(res: &HuntResult, env: &Env, p: Pal, width: usize) -> String {
    let width = width.clamp(70, 100);
    let mut out: Vec<String> = vec![];
    let verdict = H::verdict(res);
    let gaps = res.not_checked.len();

    // 1. banner
    let (badge, badge_w) = match verdict {
        "FOUND" => (p.w("1;97;41", " ✖ FOUND "), 9),
        "CLEAR" => (p.w("1;30;42", " ✔ CLEAR "), 9),
        _ => (p.w("1;30;43", " ⚠ CLEAR WITH GAPS "), 19),
    };
    let label = match &res.q.adv {
        Some(a) => format!("{}  {}", a.id, a.title),
        None => crate::out::render::ioc_label(res),
    };
    let mut right_bits = vec![];
    if let Some(o) = &env.oldest {
        right_bits.push(format!("index {}", age_label(&env.now, o)));
    }
    if gaps > 0 {
        right_bits.push(plural(gaps, "gap"));
    }
    let right = right_bits.join(" · ");
    let rw = right.chars().count();
    let label = clip(&label, width.saturating_sub(badge_w + 2 + rw + 2));
    let pad = width.saturating_sub(badge_w + 1 + label.chars().count() + rw).max(1);
    out.push(format!("{} {}{}{}", badge, p.bold(&label), " ".repeat(pad), p.dim(&right)));
    out.push(String::new());

    // 2. grid
    let cs = cards(res);
    let cols = if width >= 90 { 3 } else { 2 };
    let cw = width / cols;
    for row in cs.chunks(cols) {
        let mut line = String::new();
        for c in row {
            let used = c.glyph.chars().count() + 1 + c.n.to_string().len() + 1;
            let room = cw.saturating_sub(used + 2);
            let lab = clip(&c.label, room);
            let sb = match &c.sub {
                Some(s) if room > lab.chars().count() + 4 => clip(&format!(" ({s})"), room - lab.chars().count()),
                _ => String::new(),
            };
            let cell_w = used + lab.chars().count() + sb.chars().count();
            let glyph = if matches!(c.key, "secrets" | "present_after" | "possible") {
                p.amber(c.glyph)
            } else if verdict == "FOUND" {
                p.red(c.glyph)
            } else {
                p.cyan(c.glyph)
            };
            line += &format!("{} {} {}{}{}", glyph, p.bold(&c.n.to_string()), lab, p.dim(&sb), " ".repeat(cw.saturating_sub(cell_w)));
        }
        out.push(line.trim_end().to_string());
    }

    // 3. where
    let mut seen = BTreeSet::new();
    let mut places: Vec<Place> = vec![];
    let mut fs: Vec<&Finding> = H::findings(res).into_iter().filter(|f| !H::is_lookalike(f)).collect();
    fs.extend(res.present_after.iter());
    for f in fs {
        let pl = place_of(f, env.owner);
        if seen.insert(H::place_key(f)) {
            places.push(pl);
        }
    }
    places.sort_by_key(|a| (!a.present, a.kind_ord));
    if !places.is_empty() {
        out.push(String::new());
        out.push(p.bold("WHERE"));
        let (w_place, w_owner, w_state) = (width * 28 / 100, width * 16 / 100, 14);
        let w_detail = width.saturating_sub(2 + w_place + w_owner + w_state + 3);
        for pl in places.iter().take(8) {
            // a place that held it and no longer does (a past run, a removed line) was still exposed: never a green tick
            let g = if pl.present { p.red("✖") } else { p.amber("◷") };
            let state = fit(&pl.state, w_state);
            let state = if pl.present { p.red(&state) } else { p.amber(&state) };
            let row = format!("{} {} {} {} {}", g, fit(&pl.place, w_place), p.dim(&fit(&pl.owner, w_owner)), state, p.dim(&clip(&pl.detail, w_detail)));
            out.push(row.trim_end().to_string());
        }
        if places.len() > 8 {
            out.push(p.dim(&format!("  …{} more (br hunt {} --format table)", places.len() - 8, args_of(res))));
        }
    }

    // 4. secrets
    let secrets = H::secrets_of(res);
    if !secrets.is_empty() {
        let c = H::counts(res);
        let top: Vec<&str> = secrets.iter().take(5).map(|s| s.as_str()).collect();
        let more = if secrets.len() > top.len() { format!(" +{} more", secrets.len() - top.len()) } else { String::new() };
        out.push(String::new());
        let head = format!("SECRETS TO ROTATE ({})", c.secrets);
        let tail = clip(&format!(" {}{more}", top.join(", ")), width.saturating_sub(head.chars().count() + 2));
        out.push(format!("{} {}{}", p.amber("⚿"), p.bold(&head), tail));
    }

    // 5. not checked
    if gaps > 0 {
        let names: Vec<String> = res.not_checked.iter().take(4).map(|n| n.name.clone()).collect();
        let more = if gaps > names.len() { format!(" +{} more", gaps - names.len()) } else { String::new() };
        let first = res.not_checked.first().map(|n| n.why.clone()).unwrap_or_default();
        let text = format!("NOT CHECKED ({gaps}): {}{more}; {first}", names.join(", "));
        out.push(p.amber(&format!("⚠ {}", clip(&text, width - 2))));
    }

    // 6. next
    let a = args_of(res);
    out.push(String::new());
    out.push(p.bold("NEXT"));
    if gaps > 0 {
        if let Some(n) = res.not_checked.iter().find(|n| !n.command.is_empty()) {
            out.push(format!("  {}", clip(n.command.split("   (").next().unwrap_or(&n.command), width - 2)));
        }
    }
    if verdict == "FOUND" {
        out.push(format!("  br notify {a} --format slack"));
        out.push(format!("  br fix {a}"));
    }
    out.push(format!("  br evidence {a} --out evidence.json"));
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(kind: FKind, w: &str, state: &str) -> Finding {
        Finding {
            kind,
            where_: w.into(),
            state: state.into(),
            ioc: "npm:x@1.0.0".into(),
            name: "x".into(),
            version: "1.0.0".into(),
            file: "package-lock.json".into(),
            key: format!("k-{w}"),
            id: 7,
            digest: format!("sha256:{w}"),
            ..Default::default()
        }
    }

    fn sample() -> HuntResult {
        let mut ci = f(FKind::CiRun, "acme/web", "ran");
        ci.secrets = vec!["NPM_TOKEN".into(), "AWS_KEY".into()];
        HuntResult {
            findings: vec![f(FKind::Repo, "acme/web", "present"), f(FKind::Repo, "acme/api", "removed"), f(FKind::Cache, "acme/web", "present"), f(FKind::Host, "laptop-1", "present"), ci],
            not_checked: vec![H::NotChecked { name: "laptop-2".into(), why: "never scanned".into(), command: "br scan --local".into(), ..Default::default() }],
            ..Default::default()
        }
    }

    fn env<'a>(o: &'a dyn Fn(&Finding) -> String) -> Env<'a> {
        Env { now: "2026-05-12T07:10:00Z".into(), oldest: Some("2026-05-12T06:00:00Z".into()), owner: o }
    }

    #[test]
    fn counts_agree_with_the_table_counts() {
        let res = sample();
        let c = H::counts(&res);
        let line = crate::out::render::count_line(&res);
        for cd in cards(&res) {
            // each card's number is the one count_line prints under the same key
            if !matches!(cd.key, "other" | "teams" | "secrets") {
                assert!(line.contains(&format!("{} {}", cd.key, cd.n)), "{} {} not in {line}", cd.key, cd.n);
            }
        }
        let n = |k: &str| cards(&res).iter().find(|x| x.key == k).map(|x| x.n);
        assert_eq!(n("repos"), Some(c.repos));
        assert_eq!(n("caches"), Some(c.caches));
        assert_eq!(n("hosts"), Some(c.hosts));
        assert_eq!(n("ci runs"), Some(c.ci_runs));
        assert_eq!(n("secrets"), Some(c.secrets));
        assert_eq!(n("images"), None, "zero counts are left out");
        let o = |_: &Finding| "web".to_string();
        let text = build(&res, &env(&o), Pal(false), 100);
        assert!(text.contains("FOUND") && text.contains("1 gap") && text.contains("NOT CHECKED (1)"), "{text}");
        assert!(text.contains("SECRETS TO ROTATE (2)"));
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn color_adds_ansi_and_fits_the_width() {
        let res = sample();
        let o = |_: &Finding| "web".to_string();
        assert!(build(&res, &env(&o), Pal(true), 100).contains("\x1b["));
        for w in [80, 100] {
            for l in build(&res, &env(&o), Pal(false), w).lines() {
                assert!(l.chars().count() <= w, "{w}: {l}");
            }
        }
    }

    #[test]
    fn no_color_and_the_flag() {
        use crate::ctx::resolve_color as r;
        assert!(!r(None, true, true), "NO_COLOR beats a terminal");
        assert!(!r(Some("auto"), false, false), "a pipe is plain");
        assert!(r(None, false, true));
        assert!(r(Some("always"), true, false), "an explicit flag wins");
        assert!(!r(Some("never"), false, true));
    }

    #[test]
    fn a_clean_answer_with_gaps_is_never_plain_clear() {
        let mut res = sample();
        res.findings.clear();
        let o = |_: &Finding| String::new();
        let t = build(&res, &env(&o), Pal(false), 100);
        assert!(t.contains("CLEAR WITH GAPS") && t.contains("NOT CHECKED"), "{t}");
    }

    #[test]
    fn a_place_that_no_longer_holds_it_is_never_ticked() {
        let o = |_: &Finding| String::new();
        let t = build(&sample(), &env(&o), Pal(false), 100);
        assert!(!t.contains('✔'), "a removed repo or a past run was still exposed: {t}");
        assert!(t.lines().any(|l| l.starts_with('◷') && l.contains("acme/api")), "{t}");
    }
}
