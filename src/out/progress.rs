//! `br hunt --progress` (backlog B1): per owner, what is still open, what was fixed and when, and what is new since the
//! first hunt of this indicator. The first progress hunt records the baseline; later ones compare against it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;
use crate::error::BrResult;
use crate::query::hunt::{self as H, FKind, Finding, HuntResult};
use crate::query::index::Index;
use crate::query::secrets::secret_uses;
use crate::query::util::{fmt, fmtz, plural, table};

/// One open item: what it is (repo, cache, image, host, secret, ...), what it is called, and who it is filed under.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Item {
    pub owner: String,
    pub kind: String,
    pub name: String,
}

impl Item {
    /// "cache acme/web npm-abc": the kind first, so two things with one name are two lines.
    pub fn label(&self) -> String {
        format!("{} {}", self.kind, self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    /// when the first hunt ran
    pub at: String,
    /// the scope the baseline was taken under (`--owner`, `--repo`, `--host`, `--only`): another scope is another baseline
    #[serde(default)]
    pub scope: String,
    /// item key -> item
    pub items: BTreeMap<String, Item>,
}

/// The owner a row is filed under: a team the index knows, a person, or `unresolved`. A team that only a CODEOWNERS file
/// names is never shown as a team.
pub fn owner_label(f: &Finding) -> String {
    // A suggested owner is the person, in the same row as the person's own items; the table says "suggested"
    if let (Some(_), Some(p)) = (&f.owner.suggested, f.owner.people.first()) {
        return format!("@{p}");
    }
    if f.owner_label.is_empty() {
        "unresolved".to_string()
    } else {
        f.owner_label.clone()
    }
}

fn scope_key(res: &HuntResult) -> String {
    let q = &res.q;
    let mut bits = vec![];
    for (k, v) in [("owner", &q.owner), ("repo", &q.repo), ("host", &q.host)] {
        if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
            bits.push(format!("{k} {v}"));
        }
    }
    if q.only.len() < H::KINDS.len() {
        bits.push(format!("only {}", q.only.iter().cloned().collect::<Vec<_>>().join(",")));
    }
    bits.join(", ")
}

fn kv_key(res: &HuntResult) -> String {
    let id = res.q.adv.as_ref().map(|a| a.id.clone()).unwrap_or_else(|| res.q.iocs.iter().map(|i| i.text.clone()).collect::<Vec<_>>().join(" "));
    let scope = scope_key(res);
    if scope.is_empty() {
        format!("progress2:{id}")
    } else {
        format!("progress2:{id}:{scope}")
    }
}

fn short(d: &str) -> String {
    d.trim_start_matches("sha256:").chars().take(12).collect()
}

/// The open items of an answer: each place that still has it once, with its kind, and each secret to rotate once.
pub fn items(ix: &Index, res: &HuntResult) -> BTreeMap<String, Item> {
    let mut out = BTreeMap::new();
    // What is present now counts as open even when the window says it was first seen later
    for f in H::findings(res).into_iter().chain(res.present_after.iter()).filter(|f| H::present_now(f)) {
        let (kind, name) = match f.kind {
            FKind::Repo => ("repo", f.where_.clone()),
            FKind::Cache => ("cache", format!("{} {}", f.where_, f.key)),
            FKind::Artifact => ("artifact", format!("{} {}", f.where_, f.name)),
            FKind::Image => ("image", format!("{}@{}", f.image, short(&f.digest))),
            FKind::Host => ("host", f.where_.clone()),
            FKind::ReleaseAsset => ("release", format!("{} {} {}", f.where_, f.tag, f.asset)),
            FKind::WorkflowRef => ("workflow", format!("{} {}", f.where_, f.file)),
            FKind::CiRun => continue,
        };
        out.insert(H::place_key(f), Item { owner: owner_label(f), kind: kind.into(), name });
    }
    for u in secret_uses(ix, res) {
        // A secret nobody owns is filed under "no owner", not under "several owners"
        // Nobody found is "unresolved", the word the hunt tables use; an org secret is the org admins'
        // The secret's own label, from the one owner resolver: the org admins for an org secret, else every owner of the
        // runs that read it (two teams are both named), else unresolved. Never "several owners".
        let owner = u.owner_label.clone();
        out.insert(format!("secret\x01{}", u.name), Item { owner, kind: "secret".into(), name: u.name });
    }
    out
}

/// What changed per owner, given the baseline and today's result. Pure, so it is testable.
pub struct Progress {
    pub baseline_at: String,
    pub first: bool,
    /// the scope the numbers are for, empty for the whole index
    pub scope: String,
    /// owner -> (open items, fixed (item, when), new items)
    pub by_owner: BTreeMap<String, (Vec<Item>, Vec<(Item, String)>, Vec<Item>)>,
}

pub fn compare(ix: &Index, res: &HuntResult, base: &Baseline, first: bool) -> Progress {
    let now_items = items(ix, res);
    let any: BTreeMap<String, &Finding> = res.findings.iter().filter(|f| !f.possible && !f.past_run).map(|f| (H::place_key(f), f)).collect();
    let mut by_owner: BTreeMap<String, (Vec<Item>, Vec<(Item, String)>, Vec<Item>)> = BTreeMap::new();
    for (k, it) in &base.items {
        let e = by_owner.entry(it.owner.clone()).or_default();
        if now_items.contains_key(k) {
            e.0.push(it.clone());
        } else {
            let when = any
                .get(k)
                .and_then(|f| f.removed_at.clone())
                .or_else(|| ix.i(it.name.split(' ').next().unwrap_or("")))
                .or_else(|| res.as_of.clone())
                .map(|t| fmt(&t))
                .unwrap_or_else(|| "-".to_string());
            e.1.push((it.clone(), when));
        }
    }
    for (k, it) in &now_items {
        if !base.items.contains_key(k) {
            by_owner.entry(it.owner.clone()).or_default().2.push(it.clone());
        }
    }
    Progress { baseline_at: base.at.clone(), first, scope: scope_key(res), by_owner }
}

pub fn render(p: &Progress, id: &str) -> String {
    let mut out = vec![];
    let (mut o, mut f, mut n) = (0, 0, 0);
    let mut rows = vec![];
    for (owner, (open, fixed, new)) in &p.by_owner {
        o += open.len();
        f += fixed.len();
        n += new.len();
        rows.push(vec![owner.clone(), open.len().to_string(), fixed.len().to_string(), new.len().to_string()]);
    }
    out.push(format!(
        "{id}: {} open, {} fixed, {} new since {}{}",
        o,
        f,
        n,
        // "first" only when no baseline exists for this scope; otherwise name the baseline's time
        if p.first { "no earlier baseline (this is the first --progress for this scope: it is now the baseline)".to_string() } else { format!("the baseline of {}", fmtz(&p.baseline_at)) },
        if p.scope.is_empty() { String::new() } else { format!("; scope: {}", p.scope) }
    ));
    if rows.is_empty() {
        out.push("nothing was found, so there is nothing to track".to_string());
        return out.join("\n");
    }
    out.push(String::new());
    out.extend(table(&["OWNER", "OPEN", "FIXED", "NEW"], &rows, 2));
    for (owner, (open, fixed, new)) in &p.by_owner {
        out.push(String::new());
        out.push(format!("{owner}: {}, {}, {}", plural(open.len(), "open item"), plural(fixed.len(), "fixed item"), plural(new.len(), "new item")));
        for x in open {
            out.push(format!("  open   {}", x.label()));
        }
        for (x, when) in fixed {
            out.push(format!("  fixed  {} (by {when})", x.label()));
        }
        for x in new {
            out.push(format!("  new    {}", x.label()));
        }
    }
    out.join("\n")
}

/// Compare with the stored baseline (or record it) and print the report.
pub fn run(ctx: &Ctx, ix: &Index, res: &HuntResult) -> BrResult<String> {
    let key = kv_key(res);
    let st = crate::store::Store::open(ctx, true)?;
    let stored: Option<Baseline> = st.kv_get(&key);
    let (base, first) = match stored {
        Some(b) => (b, false),
        None => {
            let b = Baseline { at: ctx.now.clone(), scope: scope_key(res), items: items(ix, res) };
            st.kv_set(&key, &b)?;
            (b, true)
        }
    };
    let id = res.q.adv.as_ref().map(|a| a.id.clone()).unwrap_or_else(|| "this indicator".to_string());
    Ok(render(&compare(ix, res, &base, first), &id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: &str, name: &str, owner: &str) -> Item {
        Item { owner: owner.into(), kind: kind.into(), name: name.into() }
    }

    #[test]
    fn render_counts_per_owner() {
        let mut p = Progress { baseline_at: "2026-10-01T00:00:00Z".into(), first: false, scope: String::new(), by_owner: BTreeMap::new() };
        p.by_owner.insert("platform".into(), (vec![item("repo", "acme/api", "platform")], vec![(item("repo", "acme/web", "platform"), "10-05 09:00".into())], vec![]));
        let s = render(&p, "GHSA-x");
        assert!(s.contains("1 open, 1 fixed, 0 new"), "{s}");
        assert!(s.contains("fixed  repo acme/web (by 10-05 09:00)"), "{s}");
    }

    // Two items with one name (a repo and its cache) are two lines, each with its kind
    #[test]
    fn an_item_is_listed_once_with_its_kind() {
        let mut p = Progress { baseline_at: String::new(), first: true, scope: String::new(), by_owner: BTreeMap::new() };
        p.by_owner.insert("web".into(), (vec![item("repo", "acme/web", "web"), item("cache", "acme/web npm-1", "web"), item("secret", "NPM_TOKEN", "web")], vec![], vec![]));
        let s = render(&p, "X");
        assert_eq!(s.matches("open   repo acme/web").count(), 1, "{s}");
        assert!(s.contains("open   cache acme/web npm-1") && s.contains("open   secret NPM_TOKEN"), "{s}");
        assert!(s.contains("3 open, 0 fixed, 0 new"), "{s}");
    }

    #[test]
    fn a_scope_is_part_of_the_baseline_and_the_header() {
        let p = Progress { baseline_at: String::new(), first: true, scope: "owner @acme/web".into(), by_owner: BTreeMap::new() };
        assert!(render(&p, "X").contains("scope: owner @acme/web"));
    }

    // A secret that no owner can be found for is filed under "unresolved", never "several owners"
    #[test]
    fn a_secret_with_no_owner_is_filed_under_unresolved() {
        use crate::view::View;
        let v = View { now: "2026-10-01T00:00:00Z".into(), ..Default::default() };
        let ix = Index::new(&v, "2026-10-01T00:00:00Z");
        let run = Finding { kind: FKind::CiRun, where_: "acme/x".into(), id: 3, secrets: vec!["NPM_TOKEN".into()], state: "ran".into(), ..Default::default() };
        let res = HuntResult { findings: vec![run], ..Default::default() };
        let got = items(&ix, &res);
        let s = got.get("secret\u{1}NPM_TOKEN").expect("the secret is an open item");
        assert_eq!(s.owner, "unresolved");
    }

    // "first" only when no baseline exists for the scope; otherwise the baseline's time is named
    #[test]
    fn the_first_claim_is_made_only_without_a_baseline() {
        let mut p = Progress { baseline_at: "2026-10-01T09:00:00Z".into(), first: true, scope: String::new(), by_owner: BTreeMap::new() };
        p.by_owner.insert("web".into(), (vec![item("repo", "acme/web", "web")], vec![], vec![]));
        let s = render(&p, "X");
        assert!(s.contains("no earlier baseline") && !s.contains("first hunt"), "{s}");
        p.first = false;
        let s = render(&p, "X");
        assert!(s.contains("since the baseline of 10-01 09:00Z") && !s.contains("no earlier baseline") && !s.contains("is the first"), "{s}");
    }

    // An org secret is filed under the org admins, a suggested owner under the person
    #[test]
    fn an_org_secret_is_filed_under_the_org_admins() {
        use crate::view::{Person, SecretScope, View};
        let mut v = View { now: "2026-10-01T00:00:00Z".into(), org_admins: vec!["root".into()], ..Default::default() };
        v.people = vec![Person { login: "root".into(), name: Some("Rhea Root".into()), ..Default::default() }];
        v.secret_scopes = vec![SecretScope { name: "NPM_TOKEN".into(), scope: "org (all repos)".into(), repos: vec![], ..Default::default() }];
        let ix = Index::new(&v, "2026-10-01T00:00:00Z");
        let run = Finding { kind: FKind::CiRun, where_: "acme/x".into(), id: 3, secrets: vec!["NPM_TOKEN".into()], state: "ran".into(), ..Default::default() };
        let res = HuntResult { findings: vec![run], ..Default::default() };
        let got = items(&ix, &res);
        assert_eq!(got.get("secret\u{1}NPM_TOKEN").unwrap().owner, "org admins (Rhea Root)");
        let f = Finding {
            kind: FKind::Repo,
            owner: crate::query::hunt::Owner { people: vec!["lena".into()], suggested: Some("archived it 03-02".into()), ..Default::default() },
            owner_label: "@lena (suggested: archived it 03-02)".into(),
            ..Default::default()
        };
        assert_eq!(owner_label(&f), "@lena");
    }

    #[test]
    fn empty_progress_says_nothing_to_track() {
        let p = Progress { baseline_at: String::new(), first: true, scope: String::new(), by_owner: BTreeMap::new() };
        assert!(render(&p, "X").contains("nothing to track"));
    }

    // A secret two teams' runs read is filed under both teams, not "several owners"; the label is the secret table's
    #[test]
    fn a_secret_used_by_two_teams_is_filed_under_both() {
        use crate::query::hunt::Owner;
        use crate::view::{Team, View};
        let mut v = View { now: "2026-10-01T00:00:00Z".into(), ..Default::default() };
        v.teams = vec![Team { id: "@acme/web".into(), ..Default::default() }, Team { id: "@acme/growth".into(), ..Default::default() }];
        let ix = Index::new(&v, "2026-10-01T00:00:00Z");
        let run = |repo: &str, team: &str, id: u64| Finding {
            kind: FKind::CiRun,
            where_: repo.into(),
            id,
            secrets: vec!["NPM_TOKEN".into()],
            state: "ran".into(),
            owner: Owner { team: Some(team.into()), ..Default::default() },
            ..Default::default()
        };
        let res = HuntResult { findings: vec![run("acme/web", "@acme/web", 1), run("acme/site", "@acme/growth", 2)], ..Default::default() };
        let got = items(&ix, &res);
        let owner = &got.get("secret\u{1}NPM_TOKEN").expect("open item").owner;
        assert_eq!(owner, "@acme/growth, @acme/web");
        assert!(!owner.contains("several"));
    }
}
