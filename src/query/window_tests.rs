//! Query-layer tests: present now is always shown, counts and words, a hash reaches its packages. Real-format samples only.

use std::collections::BTreeSet;

use super::hunt::*;
use super::index::Index;
use crate::view::{Advisory, AffectedPackage, Commit, LockPackage, Person, Repo, Source, View};

const NOW: &str = "2026-10-01T00:00:00Z";

fn lock(p: &str) -> LockPackage {
    LockPackage { p: p.into(), direct: true, ..Default::default() }
}

fn q(iocs: &[&str]) -> Query {
    Query { iocs: iocs.iter().map(|i| crate::query::iocs::parse_ioc(i, None).unwrap()).collect(), ..Default::default() }
}

/// acme/app took evil@1.2.3 on 09-05 (author dana); acme/old took it on 09-01 and moved off it on 09-02 (author lena).
fn repo_view() -> View {
    let mut v = View { now: NOW.into(), ..Default::default() };
    for n in ["acme/app", "acme/old"] {
        v.sources.insert(n.into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: NOW.into(), ..Default::default() });
    }
    v.repos.insert(
        "acme/app".into(),
        Repo {
            commits: vec![Commit { sha: "a1".into(), at: "2026-09-05T00:00:00Z".into(), author: Some("dana".into()), packages: Some(vec![lock("npm:evil@1.2.3")]), ..Default::default() }],
            ..Default::default()
        },
    );
    v.repos.insert(
        "acme/old".into(),
        Repo {
            commits: vec![
                Commit { sha: "o1".into(), at: "2026-09-01T00:00:00Z".into(), author: Some("lena".into()), packages: Some(vec![lock("npm:evil@1.2.3")]), ..Default::default() },
                Commit { sha: "o2".into(), at: "2026-09-02T00:00:00Z".into(), author: Some("lena".into()), packages: Some(vec![lock("npm:evil@1.2.4")]), ..Default::default() },
            ],
            ..Default::default()
        },
    );
    v.people = vec![Person { login: "dana".into(), ..Default::default() }, Person { login: "lena".into(), ..Default::default() }];
    v
}

// A window labels, it never hides: a version first seen after the window is present_after, and the verdict is FOUND
#[test]
fn a_version_first_seen_after_the_window_is_present_after_and_found() {
    let v = repo_view();
    let ix = Index::new(&v, NOW);
    let mut qq = q(&["npm:evil@1.2.3"]);
    qq.window = Some(("2026-09-01T00:00:00Z".into(), "2026-09-03T00:00:00Z".into()));
    let res = hunt(&ix, &qq).unwrap();
    assert_eq!(findings(&res).iter().map(|f| f.where_.as_str()).collect::<Vec<_>>(), vec!["acme/old"], "only the old repo is in the window");
    assert_eq!(res.present_after.iter().map(|f| f.where_.as_str()).collect::<Vec<_>>(), vec!["acme/app"]);
    assert_eq!(verdict(&res), "FOUND");
    // a window that holds nothing still reports what is there
    qq.window = Some(("2026-08-01T00:00:00Z".into(), "2026-08-02T00:00:00Z".into()));
    let res = hunt(&ix, &qq).unwrap();
    assert!(findings(&res).is_empty());
    assert_eq!(res.present_after.len(), 1, "a version that was removed is history, not present now");
    assert_eq!(verdict(&res), "FOUND");
    assert_eq!(counts(&res).present_after, 1);
    // no window, nothing to add
    assert!(hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap().present_after.is_empty());
}

// --repo scopes present_after as it scopes everything else
#[test]
fn present_after_follows_the_repo_scope() {
    let v = repo_view();
    let ix = Index::new(&v, NOW);
    let mut qq = q(&["npm:evil@1.2.3"]);
    qq.window = Some(("2026-08-01T00:00:00Z".into(), "2026-08-02T00:00:00Z".into()));
    qq.repo = Some("acme/old".into());
    assert!(hunt(&ix, &qq).unwrap().present_after.is_empty());
    qq.repo = Some("acme/app".into());
    assert_eq!(hunt(&ix, &qq).unwrap().present_after.len(), 1);
}

// --now never drops a person from POSSIBLE because a repo was fixed
#[test]
fn now_keeps_the_author_of_a_fixed_repo_in_possible() {
    let v = repo_view();
    let ix = Index::new(&v, NOW);
    let all = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
    let mut qn = q(&["npm:evil@1.2.3"]);
    qn.now_only = true;
    let now = hunt(&ix, &qn).unwrap();
    let who = |r: &HuntResult| r.possible.iter().map(|f| f.where_.clone()).collect::<BTreeSet<_>>();
    assert!(who(&all).iter().any(|w| w.contains("lena")), "{:?}", who(&all));
    assert!(who(&now).iter().any(|w| w.contains("lena")), "lena's repo is fixed, her laptop is not: {:?}", who(&now));
    assert!(who(&now).iter().any(|w| w.contains("dana")));
    assert!(now.possible_dropped.is_empty(), "{:?}", now.possible_dropped);
}

// A hash that a recorded advisory lists names the advisory and its packages, and the authors are possible
#[test]
fn a_hash_listed_by_an_advisory_reaches_its_packages() {
    let mut v = repo_view();
    let h = format!("sha256:{}", "ab".repeat(32));
    v.advisories = vec![Advisory {
        id: "GHSA-aaaa-bbbb-cccc".into(),
        affected: vec!["npm:evil@1.2.3".into(), h.clone()],
        packages: vec![AffectedPackage { ecosystem: "npm".into(), name: "evil".into(), versions: vec!["1.2.3".into()], ranges: vec![] }],
        ..Default::default()
    }];
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&[&h])).unwrap();
    assert_eq!(res.hash_advisories, vec![(h.clone(), "GHSA-aaaa-bbbb-cccc".to_string(), vec!["npm:evil".to_string()])]);
    assert!(findings(&res).is_empty(), "the hash itself was not found");
    let who: BTreeSet<String> = res.possible.iter().map(|f| f.where_.clone()).collect();
    assert!(who.iter().any(|w| w.contains("dana")) && who.iter().any(|w| w.contains("lena")), "{who:?}");
    // an advisory the hunt already uses is not offered again
    let mut qa = q(&[&h]);
    qa.adv = Some(crate::query::iocs::ResolvedAdvisory { id: "GHSA-aaaa-bbbb-cccc".into(), ..Default::default() });
    assert!(hunt(&ix, &qa).unwrap().hash_advisories.is_empty());
}

// Present now is counted by kind, from one place, and people are not machines
#[test]
fn present_now_counts_every_kind_and_possible_says_machines_or_people() {
    let mk = |kind: FKind, w: &str, key: &str| Finding { kind, where_: w.into(), key: key.into(), id: 1, state: "present".into(), ioc: "npm:a@1".into(), ..Default::default() };
    let res = HuntResult {
        q: q(&["npm:a@1.0.0"]),
        findings: vec![mk(FKind::Repo, "acme/a", ""), mk(FKind::Cache, "acme/a", "k1"), mk(FKind::Cache, "acme/a", "k2"), mk(FKind::Artifact, "acme/a", ""), mk(FKind::ReleaseAsset, "acme/a", "")],
        present_after: vec![mk(FKind::Host, "laptop-x", "")],
        possible: vec![
            Finding { where_: "laptop-y".into(), possible: true, ..Default::default() },
            Finding { where_: "Dana (@dana)".into(), possible: true, person: true, ..Default::default() },
            Finding { where_: "Lena (@lena)".into(), possible: true, person: true, ..Default::default() },
        ],
        ..Default::default()
    };
    let c = counts(&res);
    assert_eq!((c.now.repos, c.now.caches, c.now.artifacts, c.now.releases, c.now.hosts), (1, 2, 1, 1, 1));
    assert_eq!(c.now.bits().join(", "), "1 repo, 1 machine, 2 caches, 1 build artifact, 1 release asset");
    assert_eq!(possible_words(&c), "2 people and 1 machine");
}

// A checkout hunt asks only about what it reads: no registries, runners or laptops are gaps
#[test]
fn a_checkout_has_no_org_gaps() {
    let v = repo_view();
    let ix = Index::new(&v, NOW);
    let mut qq = q(&["npm:evil@1.2.3"]);
    assert!(!never_indexed(&ix, &qq).is_empty(), "an org index without a registry or a host has them as gaps");
    qq.checkout = true;
    assert!(never_indexed(&ix, &qq).is_empty());
}
