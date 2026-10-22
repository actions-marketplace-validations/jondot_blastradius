//! Query-layer tests: coverage words and member coverage, owners that fit the job, a post that never cuts what
//! matters, an indicator with no version, a hash that leads to what came with it. Real-format samples only.

use super::coverage::*;
use super::hunt::*;
use super::index::{suggested_owner, Index};
use crate::out::render;
use crate::view::*;

const NOW: &str = "2026-05-12T12:00:00Z";

fn lock(p: &str) -> LockPackage {
    LockPackage { p: p.into(), direct: true, ..Default::default() }
}

fn q(iocs: &[&str]) -> Query {
    Query { iocs: iocs.iter().map(|i| crate::query::iocs::parse_ioc(i, None).unwrap()).collect(), ..Default::default() }
}

fn repo_src(v: &mut View, name: &str, repo: Repo) {
    v.sources.insert(name.into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: NOW.into(), ..Default::default() });
    v.repos.insert(name.into(), repo);
}

fn commit(sha: &str, at: &str, author: &str, pkgs: &[&str]) -> Commit {
    Commit { sha: sha.into(), at: at.into(), author: Some(author.into()), packages: if pkgs.is_empty() { None } else { Some(pkgs.iter().map(|p| lock(p)).collect()) }, ..Default::default() }
}

// ---- Suggested owner ----------------------------------------------------------------------

fn orphan_view() -> View {
    let mut v = View { now: NOW.into(), org_admins: vec!["root".into()], ..Default::default() };
    v.people = ["dana", "lena", "root"].iter().map(|l| Person { login: l.to_string(), name: Some(l.to_uppercase()), ..Default::default() }).collect();
    v.teams = vec![Team { id: "@acme/web".into(), ..Default::default() }];
    // archived by lena (audit log); CODEOWNERS names a team that no longer exists
    repo_src(
        &mut v,
        "acme/archived",
        Repo {
            archived: true,
            archived_by: Some("lena".into()),
            archived_at: Some("2026-03-02T10:00:00Z".into()),
            codeowners: "* @acme/gone\n".into(),
            commits: vec![commit("c1", "2026-01-05T00:00:00Z", "dana", &["npm:evil@1.2.3"])],
            ..Default::default()
        },
    );
    // not archived, no CODEOWNERS: the last committer
    repo_src(&mut v, "acme/quiet", Repo { commits: vec![commit("c1", "2026-02-01T00:00:00Z", "dana", &["npm:evil@1.2.3"]), commit("c2", "2026-04-11T00:00:00Z", "lena", &[])], ..Default::default() });
    // nobody on record: the org admins
    repo_src(&mut v, "acme/bare", Repo::default());
    // a team the index knows owns it: nothing to suggest
    repo_src(&mut v, "acme/owned", Repo { codeowners: "* @acme/web\n".into(), commits: vec![commit("c1", "2026-02-01T00:00:00Z", "dana", &["npm:evil@1.2.3"])], ..Default::default() });
    v
}

// The order is the archiver, the last committer, the org admins; a resolved CODEOWNERS suggests nothing
#[test]
fn a_suggested_owner_follows_the_archiver_then_the_last_committer_then_the_org_admins() {
    let v = orphan_view();
    let ix = Index::new(&v, NOW);
    assert_eq!(suggested_owner(&ix, "acme/archived"), Some(("lena".into(), "archived it 03-02".into())));
    assert_eq!(suggested_owner(&ix, "acme/quiet"), Some(("lena".into(), "last committer 04-11".into())));
    assert_eq!(suggested_owner(&ix, "acme/bare"), Some(("root".into(), "org admins".into())));
    assert_eq!(suggested_owner(&ix, "acme/owned"), None);
}

// The finding carries the suggestion, marked as one, and --owner for that person includes the repo
#[test]
fn an_orphaned_repo_is_labelled_suggested_and_reaches_the_suggested_person() {
    let v = orphan_view();
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
    let f = findings(&res).into_iter().find(|f| f.where_ == "acme/archived").unwrap().clone();
    assert_eq!(f.owner_label, "@lena (suggested: archived it 03-02)");
    let owned = findings(&res).into_iter().find(|f| f.where_ == "acme/owned").unwrap().clone();
    assert_eq!(owned.owner_label, "@acme/web");
    let mut qo = q(&["npm:evil@1.2.3"]);
    qo.owner = Some("lena".into());
    let by_lena = hunt(&ix, &qo).unwrap();
    let got: Vec<&str> = findings(&by_lena).iter().map(|f| f.where_.as_str()).collect();
    assert!(got.contains(&"acme/archived"), "{got:?}");
    assert!(!got.contains(&"acme/owned"), "{got:?}");
}

// ---- Workspace to repo --------------------------------------------------------------------

#[test]
fn a_finding_in_a_runners_workspace_goes_to_the_repos_owner_and_the_runner_owner_still_sees_it() {
    let mut v = View { now: NOW.into(), ..Default::default() };
    v.teams = vec![Team { id: "@acme/web".into(), ..Default::default() }, Team { id: "@acme/ops".into(), ..Default::default() }];
    repo_src(&mut v, "acme/web", Repo { codeowners: "* @acme/web\n".into(), ..Default::default() });
    v.sources.insert("runner-1".into(), Source { kind: "host".into(), reach: "ssh".into(), indexed_at: NOW.into(), ..Default::default() });
    v.hosts.insert(
        "runner-1".into(),
        Host {
            kind: Some("runner".into()),
            owner_team: Some("@acme/ops".into()),
            items: vec![HostItem {
                at: "2026-05-10T00:00:00Z".into(),
                kind: "node_modules".into(),
                loc: "/srv/actions/_work/web/web/node_modules".into(),
                pkgs: vec!["npm:evil@1.2.3".into()],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
    let f = findings(&res).into_iter().find(|f| f.kind == FKind::Host).unwrap().clone();
    assert_eq!(f.workspace_repo.as_deref(), Some("acme/web"));
    assert_eq!(f.owner_label, "@acme/ops", "every screen names the runner's own owner; the repo's team is the workspace owner");
    assert_eq!(f.workspace_owner.as_ref().and_then(|o| o.team.clone()).as_deref(), Some("@acme/web"));
    assert_eq!(f.owner.team.as_deref(), Some("@acme/ops"), "the runner's owner keeps the host cleanup");
    // the runner's owner keeps the host: --owner ops still lists it
    let mut qo = q(&["npm:evil@1.2.3"]);
    qo.owner = Some("@acme/ops".into());
    assert!(findings(&hunt(&ix, &qo).unwrap()).iter().any(|f| f.kind == FKind::Host));
    assert_eq!(host_owner(&ix, "runner-1").team.as_deref(), Some("@acme/ops"));
}

// ---- Member coverage ----------------------------------------------------------------------

fn member_view(roots: &[&str], at: &str) -> View {
    let mut v = View { now: NOW.into(), ..Default::default() };
    v.org.github = Some("acme".into());
    v.people = vec![Person { login: "dana".into(), name: Some("Dana".into()), ..Default::default() }, Person { login: "kim".into(), ..Default::default() }];
    v.sources.insert("dana-mbp".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: at.into(), ..Default::default() });
    v.hosts.insert("dana-mbp".into(), Host { kind: Some("laptop".into()), owner: Some("dana".into()), roots: roots.iter().map(|r| r.to_string()).collect(), ..Default::default() });
    v
}

// A scan of one folder is partial and says what it scanned; the owner is not covered
#[test]
fn a_one_folder_scan_is_partial_and_names_its_roots() {
    let v = member_view(&["/home/dana/scratch/test-1"], "2026-05-12T11:00:00Z");
    let ix = Index::new(&v, NOW);
    let r = member_reason(&ix, "dana");
    assert!(!r.covered && r.partial, "{r:?}");
    assert_eq!(r.reason, "partial (scanned: /home/dana/scratch/test-1)");
    let mc = members_covered(&ix, &Query::default());
    assert_eq!((mc.members, mc.covered), (2, 0));
    assert_eq!(mc.reason_of("dana").map(|r| r.reason.as_str()), Some("partial (scanned: /home/dana/scratch/test-1)"));
    assert_eq!(mc.reason_of("kim").map(|r| r.reason.as_str()), Some("no machine of theirs is scanned"));
    // a root written relative to where the scan ran is a folder; a path nothing can place is not judged
    assert_eq!(roots_read(&["files".to_string()], &[]), RootsRead::Narrow(vec!["files".to_string()]));
    assert_eq!(roots_read(&["/srv/data".to_string()], &[]), RootsRead::Unknown);
    assert_eq!(roots_read(&["/srv/data".to_string()], &["/home/dana".to_string()]), RootsRead::Narrow(vec!["/srv/data".to_string()]));
    assert_eq!(roots_read(&["/home/dana".to_string(), "/srv/data".to_string()], &[]), RootsRead::Covers);
}

// The home, an ancestor of it, or a package cache is a covering scan
#[test]
fn the_home_or_a_package_cache_covers_a_member_and_a_stale_scan_does_not() {
    for roots in [vec!["/home/dana"], vec!["/Users/dana", "/Users/dana/.npm"], vec!["/home"], vec!["/home/dana/.cache/pip"], vec!["C:\\Users\\dana"]] {
        let v = member_view(&roots, "2026-05-12T11:00:00Z");
        let ix = Index::new(&v, NOW);
        let r = member_reason(&ix, "dana");
        assert!(r.covered, "{roots:?}: {r:?}");
        assert_eq!(r.reason, "fresh as of 05-12 11:00Z (dana-mbp)");
    }
    // the same roots, scanned three days ago: stale is not checked
    let v = member_view(&["/home/dana"], "2026-05-09T11:00:00Z");
    let ix = Index::new(&v, NOW);
    let r = member_reason(&ix, "dana");
    assert!(!r.covered, "{r:?}");
    assert!(r.reason.contains("stale") && r.reason.contains("05-09 11:00Z"), "{}", r.reason);
    // no roots recorded: br does not call the scan narrow
    let v = member_view(&[], "2026-05-12T11:00:00Z");
    assert!(member_reason(&Index::new(&v, NOW), "dana").covered);
}

// The scan roots narrower than the home keep the owner in POSSIBLE even though the scan is after the exposure
#[test]
fn a_narrow_scan_keeps_the_owner_possible() {
    let mut v = member_view(&["/home/dana/scratch/test-1"], "2026-05-12T11:00:00Z");
    repo_src(&mut v, "acme/app", Repo { commits: vec![commit("c1", "2026-05-01T00:00:00Z", "dana", &["npm:evil@1.2.3"])], ..Default::default() });
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
    let who: Vec<String> = res.possible.iter().map(|f| f.where_.clone()).collect();
    assert!(who.iter().any(|w| w == "dana-mbp"), "{who:?}");
    let reason = &res.possible.iter().find(|f| f.where_ == "dana-mbp").unwrap().reason;
    assert!(reason.contains("/home/dana/scratch/test-1") && reason.contains("not their home"), "{reason}");
    // the laptop row names the reason, not just the name
    let gap = res.not_checked.iter().find(|r| r.state == "laptops").unwrap();
    assert!(gap.people.iter().any(|p| p.contains("partial (scanned: /home/dana/scratch/test-1)")), "{:?}", gap.people);
    // with a covering scan the same person is not possible
    let mut v2 = member_view(&["/home/dana"], "2026-05-12T11:00:00Z");
    repo_src(&mut v2, "acme/app", Repo { commits: vec![commit("c1", "2026-05-01T00:00:00Z", "dana", &["npm:evil@1.2.3"])], ..Default::default() });
    let ix2 = Index::new(&v2, NOW);
    let res2 = hunt(&ix2, &q(&["npm:evil@1.2.3"])).unwrap();
    assert!(res2.possible.iter().all(|f| f.where_ != "dana-mbp"), "{:?}", res2.possible.iter().map(|f| &f.where_).collect::<Vec<_>>());
}

// A narrow laptop scan is "partial" in the source row (evidence appendix) exactly as it is in `br hosts`: one definition
#[test]
fn r9_a_narrow_laptop_scan_is_partial_in_the_source_row_and_for_the_member() {
    use crate::query::coverage::{source_state, CoverageState};
    for (roots, state, covered) in [(vec!["/home/dana/scratch/test-1"], CoverageState::Partial, false), (vec!["/home/dana"], CoverageState::Full, true), (vec![], CoverageState::Full, true)] {
        let v = member_view(&roots, "2026-05-12T11:00:00Z");
        let ix = Index::new(&v, NOW);
        let got = source_state(&ix, &q(&["npm:evil@1.2.3"]), "dana-mbp", false, None);
        assert_eq!(got, state, "{roots:?}");
        assert_eq!(member_reason(&ix, "dana").covered, covered, "{roots:?}");
        // the source row is full exactly when the member is covered
        assert_eq!(got == CoverageState::Full, covered, "{roots:?}: the two definitions disagree");
    }
}

// "data as of" is a range and names the oldest source
#[test]
fn data_as_of_is_a_range_with_the_oldest_source() {
    let mut v = View { now: NOW.into(), ..Default::default() };
    for (n, k, t) in [("registry.example", "registry", "2026-05-12T04:00:00Z"), ("acme/a", "repo", "2026-05-12T09:00:00Z"), ("acme/b", "repo", "2026-05-12T08:00:00Z")] {
        v.sources.insert(n.into(), Source { kind: k.into(), reach: "github".into(), indexed_at: t.into(), ..Default::default() });
    }
    let ix = Index::new(&v, NOW);
    let names: Vec<String> = v.sources.keys().cloned().collect();
    let d = data_as_of(&ix, &names).unwrap();
    assert_eq!(d.words(), "05-12 04:00–09:00Z (oldest: registry.example)");
    assert_eq!(data_as_of(&ix, &["acme/a".to_string()]).unwrap().words(), "05-12 09:00Z");
    // across days
    v.sources.get_mut("registry.example").unwrap().indexed_at = "2026-05-11T22:00:00Z".into();
    let ix = Index::new(&v, NOW);
    assert_eq!(data_as_of(&ix, &names).unwrap().range(), "05-11 22:00Z–05-12 09:00Z");
    // the words a source being full because it is fresh
    assert_eq!(full_words("2026-05-12T04:00:00Z", "2026-05-12T12:00:00Z"), "fresh as of 2026-05-12 04:00Z");
    assert_eq!(full_words("2026-05-12T13:00:00Z", "2026-05-12T12:00:00Z"), "scanned 2026-05-12 13:00Z, after the end of the window");
}

// ---- an indicator with no version ----------------------------------------------------------------------------------------

fn found_view() -> View {
    let mut v = View { now: NOW.into(), ..Default::default() };
    repo_src(&mut v, "acme/app", Repo { codeowners: "* @acme/web\n".into(), commits: vec![commit("c1", "2026-05-01T00:00:00Z", "dana", &["npm:evil@1.2.3"])], ..Default::default() });
    v.teams = vec![Team { id: "@acme/web".into(), ..Default::default() }];
    v.people = vec![Person { login: "dana".into(), ..Default::default() }];
    v
}

// No version written is a search for any version, and the answer says so and calls nothing "to clean" or "to rotate"
#[test]
fn an_indicator_with_no_version_is_an_any_version_search() {
    let v = found_view();
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&["npm:evil"])).unwrap();
    assert!(any_version_only(&res));
    assert_eq!(render::ioc_label(&res), "any version of evil");
    let table = render::render_table(&res, &ix, false);
    assert!(table.contains("FOUND  any version of evil"), "{table}");
    assert!(table.contains("any version matches"), "{table}");
    let sentence = render::human_sentence(&res).unwrap_or_default();
    assert!(!sentence.contains("to clean"), "{sentence}");
    let slack = render::render_slack(&res, &ix);
    assert!(!slack.contains("To clean") && !slack.contains("Secrets to rotate") && !slack.contains("Next: br notify"), "{slack}");
    assert!(slack.contains("No affected version is named"), "{slack}");
    let summary = render::summary(&res, &ix, false);
    assert!(summary.contains("any version") && !summary.contains("rotate the secrets"), "{summary}");
    // a version written is not an any-version search
    let named = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
    assert!(!any_version_only(&named));
    assert_eq!(render::ioc_label(&named), "npm:evil@1.2.3");
}

// ---- people and machines ----------------------------------------------------------------------------------------

// Only some indicators hit: the headline says how many
#[test]
fn the_headline_counts_the_indicators_that_hit() {
    let v = found_view();
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&["npm:evil@1.2.3", "npm:other@9.9.9", "npm:third@8.8.8"])).unwrap();
    assert_eq!(render::ioc_label(&res), "1 of 3 indicators");
    assert!(render::render_table(&res, &ix, false).contains("FOUND  1 of 3 indicators"));
    let none = hunt(&ix, &q(&["npm:other@9.9.9", "npm:third@8.8.8"])).unwrap();
    assert_eq!(render::ioc_label(&none), "2 indicators");
    // every indicator hits: the plain count
    let all = hunt(&ix, &q(&["npm:evil@1.2.3", "npm:evil@1.2.3", "npm:evil"])).unwrap();
    assert_eq!(render::ioc_label(&all), "3 indicators");
    // one of them asked twice is still one indicator
    let twice = hunt(&ix, &q(&["npm:evil@1.2.3", "npm:evil@1.2.3", "npm:other@9.9.9"])).unwrap();
    assert_eq!(render::ioc_label(&twice), "1 of 2 indicators");
}

// The window is shown one way, with the clip said
#[test]
fn a_clipped_window_is_shown_as_from_to_examined_to() {
    let v = found_view();
    let ix = Index::new(&v, NOW);
    let mut qq = q(&["npm:evil@1.2.3"]);
    qq.window = Some(("2026-05-01T00:00:00Z".into(), "2026-05-12T23:59:00Z".into()));
    qq.window_src = Some("--window".into());
    let res = hunt(&ix, &qq).unwrap();
    let head = render::header_core(&res, &ix).join("\n");
    assert!(head.contains("window 05-01 00:00Z..05-12 23:59Z (examined to 05-12 12:00Z; from --window)"), "{head}");
    assert!(!head.contains("the window ends now"), "{head}");
}

// Csv has depth, via and file
#[test]
fn csv_has_depth_via_and_file_columns() {
    let mut v = found_view();
    v.repos.get_mut("acme/app").unwrap().commits[0].packages =
        Some(vec![LockPackage { p: "npm:top@1.0.0".into(), direct: true, ..Default::default() }, LockPackage { p: "npm:evil@1.2.3".into(), via: vec!["npm:top@1.0.0".into()], ..Default::default() }]);
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
    let csv = render::render_csv(&res);
    let mut lines = csv.lines();
    let hdr = lines.next().unwrap();
    assert!(hdr.ends_with(",depth,via,file"), "{hdr}");
    let row = lines.next().unwrap();
    assert!(row.contains("via top") && row.contains("top"), "{row}");
}

// Slack lists a place where the install likely ran first and never cuts it; each place is listed once
#[test]
fn slack_keeps_the_likely_ran_host_and_lists_each_place_once() {
    let mut res = HuntResult { q: q(&["npm:evil@1.2.3"]), ..Default::default() };
    // the same image twice (once for the package, once for the file)
    for path in ["", "usr/bin/x"] {
        res.findings.push(Finding {
            kind: FKind::Image,
            image: "ghcr.io/acme/web".into(),
            where_: "ghcr.io/acme/web".into(),
            digest: "sha256:aaaa".into(),
            where_in: "final image".into(),
            path: path.into(),
            state: "final image".into(),
            ioc: "npm:evil@1.2.3".into(),
            ..Default::default()
        });
    }
    for i in 0..12 {
        res.findings.push(Finding { kind: FKind::Host, where_: format!("host-{i:02}"), loc: format!("/h/{i}/a"), ioc: "npm:evil@1.2.3".into(), state: "present".into(), ..Default::default() });
    }
    // a second file on the same host is the same place
    res.findings.push(Finding { kind: FKind::Host, where_: "host-00".into(), loc: "/h/0/b".into(), ioc: "npm:evil@1.2.3".into(), state: "present".into(), ..Default::default() });
    res.findings.push(Finding {
        kind: FKind::Host,
        where_: "zz-runner".into(),
        loc: "/home/ci/.npm".into(),
        ioc: "npm:evil@1.2.3".into(),
        state: "present".into(),
        note: "cache only; the install likely ran".into(),
        ..Default::default()
    });
    let v = View { now: NOW.into(), ..Default::default() };
    let ix = Index::new(&v, NOW);
    let slack = render::render_slack(&res, &ix);
    let clean = slack.lines().find(|l| l.contains("To clean")).unwrap();
    assert!(clean.contains("zz-runner"), "the likely-ran host leads the list and is never cut: {clean}");
    assert!(clean.find("zz-runner").unwrap() < clean.find("host-00").unwrap(), "{clean}");
    assert_eq!(clean.matches("host-00").count(), 1, "{clean}");
    assert_eq!(clean.matches("ghcr.io/acme/web").count(), 1, "{clean}");
    assert!(clean.contains(" more ("), "the bottom is cut with a count: {clean}");
}

// Each CI run in slack lists the secrets it could read
#[test]
fn slack_lists_the_secrets_of_each_ci_run() {
    let mut res = HuntResult { q: q(&["npm:evil@1.2.3"]), ..Default::default() };
    for (id, secs) in [(11u64, vec!["NPM_TOKEN", "DEPLOY"]), (12, vec!["NPM_TOKEN"])] {
        res.findings.push(Finding {
            kind: FKind::CiRun,
            where_: "acme/app".into(),
            id,
            workflow: "ci.yml".into(),
            secrets: secs.iter().map(|s| s.to_string()).collect(),
            ioc: "npm:evil@1.2.3".into(),
            state: "ran".into(),
            ..Default::default()
        });
    }
    let v = View { now: NOW.into(), ..Default::default() };
    let ix = Index::new(&v, NOW);
    let slack = render::render_slack(&res, &ix);
    let line = slack.lines().find(|l| l.starts_with("• CI runs")).unwrap();
    assert!(line.contains("acme/app#11 (NPM_TOKEN, DEPLOY)") && line.contains("acme/app#12 (NPM_TOKEN)"), "{line}");
}

// ---- what came with a hash ----------------------------------------------------------------------------------------

fn hf(path: &str, sha: &str, sim: Option<&str>) -> HostFile {
    HostFile { path: path.into(), sha256: sha.into(), simhash: sim.map(str::to_string), ..Default::default() }
}

fn tree_view(bin_sha: &str) -> View {
    let mut v = View { now: NOW.into(), ..Default::default() };
    v.sources.insert("dev-mbp".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: NOW.into(), ..Default::default() });
    let base = "/home/dev/app/node_modules/evil-pkg";
    v.hosts.insert(
        "dev-mbp".into(),
        Host {
            kind: Some("laptop".into()),
            owner: Some("dev".into()),
            items: vec![HostItem {
                at: "2026-05-11T00:00:00Z".into(),
                kind: "node_modules".into(),
                loc: "/home/dev/app/node_modules".into(),
                pkgs: vec!["npm:evil-pkg@1.0.0".into()],
                files: vec![
                    hf(&format!("{base}/bin/probe"), bin_sha, None),
                    hf(&format!("{base}/postinstall.js"), &"b".repeat(64), Some("0123456789abcdef")),
                    hf("/home/dev/app/node_modules/other/index.js", &"d".repeat(64), Some("1111111111111111")),
                    hf("/home/dev/notes/readme.md", &"e".repeat(64), Some("2222222222222222")),
                ],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    v
}

// A hash hit inside a package's install tree lists the other files of the tree that have a simhash
#[test]
fn a_hash_hit_in_an_install_tree_lists_the_related_files() {
    let sha = "a".repeat(64);
    let v = tree_view(&sha);
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&[&format!("sha256:{sha}")])).unwrap();
    assert_eq!(res.related.len(), 1, "{:?}", res.related);
    let r = &res.related[0];
    assert_eq!((r.file.as_str(), r.host.as_str()), ("postinstall.js", "dev-mbp"));
    assert_eq!(r.tree, "/home/dev/app/node_modules/evil-pkg");
    let table = render::render_table(&res, &ix, true);
    assert!(table.contains("related: postinstall.js (sha256:bbbbbbbbbbbb…; br hunt --similar sha256:bbbbbbbbbbbb…)"), "{table}");
    let json = render::render_json(&res, &ix);
    assert!(json.contains("\"related\"") && json.contains("postinstall.js"), "{json}");
    // a hit with no package tree (a loose file) has nothing related
    let mut v2 = tree_view(&sha);
    v2.hosts.get_mut("dev-mbp").unwrap().items[0].kind = "loose-file".into();
    let ix2 = Index::new(&v2, NOW);
    assert!(hunt(&ix2, &q(&[&format!("sha256:{sha}")])).unwrap().related.is_empty());
}

// --similar-related runs the similarity pass itself and reports apart, not counted
#[test]
fn similar_related_reports_close_files_apart_from_the_findings() {
    let sha = "a".repeat(64);
    let mut v = tree_view(&sha);
    // another machine holds a repacked copy of the postinstall script (one bit off) under another hash
    v.sources.insert("other-box".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: NOW.into(), ..Default::default() });
    v.hosts.insert(
        "other-box".into(),
        Host {
            items: vec![HostItem {
                at: "2026-05-11T00:00:00Z".into(),
                kind: "loose-file".into(),
                loc: "/tmp".into(),
                files: vec![hf("/tmp/p.js", &"c".repeat(64), Some("0123456789abcdee"))],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let ix = Index::new(&v, NOW);
    let mut qq = q(&[&format!("sha256:{sha}")]);
    let plain = hunt(&ix, &qq).unwrap();
    assert!(plain.similar.is_empty());
    qq.similar_related = true;
    let res = hunt(&ix, &qq).unwrap();
    let got: Vec<(&str, &str)> = res.similar.iter().map(|f| (f.where_.as_str(), f.loc.as_str())).collect();
    assert_eq!(got, vec![("other-box", "/tmp/p.js")], "the related file itself and the exact hit are not 'similar'");
    assert_eq!(counts(&res).findings, counts(&plain).findings, "similar hits are not counted in the headline");
    let table = render::render_table(&res, &ix, false);
    assert!(table.contains("SIMILAR, NOT IDENTICAL"), "{table}");
}

// An image layer whose RUN executes a path a finding holds is reported as executed during the build
#[test]
fn a_run_that_executes_the_found_file_is_executed_during_build() {
    let sha = "f".repeat(64);
    let mut v = View { now: NOW.into(), ..Default::default() };
    v.sources.insert("ghcr.io/acme".into(), Source { kind: "registry".into(), reach: "registry".into(), indexed_at: NOW.into(), ..Default::default() });
    let layer = |n, by: &str, files: Vec<LayerFile>| Layer { n, created_by: Some(by.into()), files, ..Default::default() };
    v.images = vec![ImageBuild {
        repository: "ghcr.io/acme/etl".into(),
        digest: "sha256:e908d33b82f4".into(),
        built: "2026-05-10T00:00:00Z".into(),
        tags: vec!["latest".into()],
        layers: vec![
            layer(1, "ADD base.tar /", vec![]),
            layer(2, "COPY netprobe /opt/tools/netprobe", vec![LayerFile { path: "opt/tools/netprobe".into(), sha256: sha.clone() }]),
            layer(3, "RUN /opt/tools/netprobe --init", vec![]),
        ],
        ..Default::default()
    }];
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&[&format!("sha256:{sha}")])).unwrap();
    let f = findings(&res).into_iter().find(|f| f.kind == FKind::Image).unwrap().clone();
    assert_eq!((f.layer, f.executed_in_layer), (2, Some(3)));
    let table = render::render_table(&res, &ix, false);
    assert!(table.contains("executed during build in layer 3"), "{table}");
    // a file only copied is not executed
    v.images[0].layers[2].created_by = Some("RUN chmod +x /opt/tools/netprobe".into());
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&[&format!("sha256:{sha}")])).unwrap();
    assert_eq!(findings(&res).into_iter().find(|f| f.kind == FKind::Image).unwrap().executed_in_layer, None);
}

// ---- regressions -------------------------------------------------------------------------------

/// A binary dropped in a tool cache (the hash hit, with no text beside it), and the affected package's own install elsewhere on
/// the machine: its postinstall script and manifest. Another laptop holds a repacked copy of the script under another hash.
fn pivot_view(bin: &str) -> View {
    let mut v = View { now: NOW.into(), ..Default::default() };
    for h in ["runner", "kenji"] {
        v.sources.insert(h.into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: NOW.into(), ..Default::default() });
    }
    v.hosts.insert(
        "runner".into(),
        Host {
            kind: Some("runner".into()),
            owner_team: Some("@acme/ops".into()),
            items: vec![
                HostItem {
                    at: "2026-05-11T00:00:00Z".into(),
                    kind: "tool-cache".into(),
                    loc: "/opt/hostedtoolcache/probe/1.0/x64".into(),
                    files: vec![hf("/opt/hostedtoolcache/probe/1.0/x64/probe", bin, None)],
                    ..Default::default()
                },
                HostItem {
                    at: "2026-05-11T00:00:00Z".into(),
                    kind: "node_modules".into(),
                    loc: "/home/runner/work/app/node_modules".into(),
                    pkgs: vec!["npm:evil-pkg@1.0.0".into(), "npm:left-pad@1.0.0".into()],
                    files: vec![
                        hf("/home/runner/work/app/node_modules/evil-pkg/postinstall.js", &"b".repeat(64), Some("0123456789abcdef")),
                        hf("/home/runner/work/app/node_modules/evil-pkg/package.json", &"c".repeat(64), Some("aaaaaaaaaaaaaaaa")),
                        hf("/home/runner/work/app/node_modules/left-pad/package.json", &"d".repeat(64), Some("aaaaaaaaaaaaaaab")),
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    v.hosts.insert(
        "kenji".into(),
        Host {
            kind: Some("laptop".into()),
            owner: Some("kenji".into()),
            items: vec![HostItem {
                at: "2026-05-12T00:00:00Z".into(),
                kind: "loose-file".into(),
                loc: "/tmp".into(),
                files: vec![hf("/tmp/.cache/upd.js", &"e".repeat(64), Some("0123456789abcdee"))],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    v.advisories = vec![Advisory {
        id: "GHSA-aaaa-bbbb-cccc".into(),
        affected: vec![format!("sha256:{bin}"), "npm:evil-pkg@1.0.0".into()],
        packages: vec![AffectedPackage { ecosystem: "npm".into(), name: "evil-pkg".into(), versions: vec!["1.0.0".into()], ranges: vec![] }],
        ..Default::default()
    }];
    v
}

// --similar-related from a binary hash compares the package's own install scripts (not only the files beside the hit)
#[test]
fn r8_similar_related_from_a_binary_hash_reaches_the_dropper_beside_the_package_scripts() {
    let bin = "a".repeat(64);
    let v = pivot_view(&bin);
    let ix = Index::new(&v, NOW);
    let mut qq = q(&[&format!("sha256:{bin}")]);
    assert!(hunt(&ix, &qq).unwrap().similar.is_empty(), "without the flag nothing is compared");
    qq.similar_related = true;
    let res = hunt(&ix, &qq).unwrap();
    assert!(res.related.iter().any(|r| r.file == "postinstall.js" && r.package == "evil-pkg"), "{:?}", res.related);
    let got: Vec<(&str, &str, bool)> = res.similar.iter().map(|f| (f.where_.as_str(), f.loc.as_str(), f.boilerplate)).collect();
    assert_eq!(got[0], ("kenji", "/tmp/.cache/upd.js", false), "{got:?}");
    assert!(got.iter().skip(1).all(|g| g.2), "only boilerplate follows: {got:?}");
    assert!(got.iter().any(|g| g.1.ends_with("left-pad/package.json")), "a manifest looks like every manifest, and is listed last: {got:?}");
    let c = counts(&res);
    assert_eq!((c.similar, c.hosts), (0, 1), "a lookalike is never a place to clean");
    let table = render::render_table(&res, &ix, false);
    assert!(table.contains("SIMILAR, NOT IDENTICAL (90% or more alike"), "{table}");
    assert!(table.contains("(boilerplate)"), "{table}");
    // the exposure window is about the past: a dropper written after it is the lead
    let mut qw = qq.clone();
    qw.window = Some(("2026-05-01T00:00:00Z".into(), "2026-05-11T12:00:00Z".into()));
    let rw = hunt(&ix, &qw).unwrap();
    assert!(rw.similar.iter().any(|f| f.loc == "/tmp/.cache/upd.js"), "{:?}", rw.similar.iter().map(|f| &f.loc).collect::<Vec<_>>());
}

// When there is nothing to compare, the answer says why
#[test]
fn r8_similar_related_says_why_when_there_is_nothing_to_compare() {
    // the hash sits on a host that has no text file with a similarity record
    let bin = "a".repeat(64);
    let mut v = pivot_view(&bin);
    v.advisories.clear();
    v.hosts.get_mut("runner").unwrap().items.truncate(1);
    let ix = Index::new(&v, NOW);
    let mut qq = q(&[&format!("sha256:{bin}")]);
    qq.similar_related = true;
    let res = hunt(&ix, &qq).unwrap();
    assert!(res.similar.is_empty());
    assert_eq!(res.similar_notes.len(), 1);
    assert!(res.similar_notes[0].starts_with("nothing to compare: no text file beside the hit"), "{:?}", res.similar_notes);
    let table = render::render_table(&res, &ix, false);
    assert!(table.contains("note: nothing to compare"), "{table}");
    // the hash is in an image layer only: those keep no similarity record
    let mut vi = View { now: NOW.into(), ..Default::default() };
    vi.sources.insert("ghcr.io/acme".into(), Source { kind: "registry".into(), reach: "registry".into(), indexed_at: NOW.into(), ..Default::default() });
    vi.images = vec![ImageBuild {
        repository: "ghcr.io/acme/etl".into(),
        digest: "sha256:e908d33b82f4".into(),
        built: "2026-05-10T00:00:00Z".into(),
        layers: vec![Layer { n: 1, files: vec![LayerFile { path: "opt/probe".into(), sha256: bin.clone() }], ..Default::default() }],
        ..Default::default()
    }];
    let ixi = Index::new(&vi, NOW);
    let res = hunt(&ixi, &qq).unwrap();
    assert!(res.similar_notes[0].contains("nothing to compare") && res.similar_notes[0].contains("only in images"), "{:?}", res.similar_notes);
    // a question with no hash and no package has nothing to start from
    let mut qn = q(&["go:example.com/x@v1.0.0"]);
    qn.similar_related = true;
    let none = hunt(&Index::new(&v, NOW), &qn).unwrap();
    assert!(none.similar_notes[0].contains("nothing to compare"), "{:?}", none.similar_notes);
    // a comparison that finds nothing says what it compared
    let mut v2 = pivot_view(&bin);
    v2.hosts.remove("kenji");
    v2.sources.remove("kenji");
    v2.hosts.get_mut("runner").unwrap().items[1].files.truncate(1);
    let res = hunt(&Index::new(&v2, NOW), &qq).unwrap();
    assert!(res.similar.is_empty() && res.similar_notes[0].starts_with("compared 1 text file (postinstall.js)"), "{:?}", res.similar_notes);
}

// A similarity hit below 100% is a lead, never a place to clean
#[test]
fn r8_a_lookalike_is_not_counted_to_clean() {
    let look = |loc: &str, sim: f64| Finding {
        kind: FKind::Host,
        where_: "box".into(),
        loc: loc.into(),
        ioc: "simhash:0123456789abcdef~0.40".into(),
        match_: "similar".into(),
        sim: Some(sim),
        state: "present".into(),
        ..Default::default()
    };
    let res = HuntResult { q: q(&["npm:x@1.0.0"]), findings: vec![look("/tmp/a.js", 1.0), look("/tmp/b.js", 0.953), look("/etc/os-release", 0.547)], ..Default::default() };
    let c = counts(&res);
    assert_eq!((c.hosts, c.locations, c.similar), (1, 1, 2));
    let v = View { now: NOW.into(), ..Default::default() };
    let line = render::human_sentence(&res).unwrap();
    assert!(line.starts_with("1 host to clean; 2 files that look like the sample but are not identical to it"), "{line}");
    assert!(is_boilerplate_path("/etc/os-release") && is_boilerplate_path("/x/node_modules/y/package.json") && !is_boilerplate_path("/tmp/.cache/upd.js"));
    let _ = v;
}

// A place has one owner on every screen; a runner's is its host entry's, never its workspace repo's team
#[test]
fn r8_one_owner_for_a_place_on_every_screen() {
    let v = orphan_view();
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
    assert!(!findings(&res).is_empty());
    for f in findings(&res) {
        let table = owner_name(&ix, &f.owner);
        assert_eq!(f.owner_label, table, "{}", f.where_);
        assert_eq!(render::owner_str(&ix, f), table);
        assert_eq!(crate::out::progress::owner_label(f).trim_start_matches('@'), table.split(" (").next().unwrap().trim_start_matches('@'));
        // GitHub does not resolve CODEOWNERS' team: it is never the owner, and the text says so
        if f.where_ == "acme/archived" {
            assert_eq!(table, "@lena (suggested: archived it 03-02)");
            assert_eq!(codeowners_note(&ix, &f.owner).as_deref(), Some("CODEOWNERS names @acme/gone, which GitHub does not resolve"));
            assert!(!table.contains("gone"));
        }
    }
    // a runner with a workspace repo of another team keeps its own owner in the label
    let mut w = View { now: NOW.into(), ..Default::default() };
    w.teams = vec![Team { id: "@acme/web".into(), ..Default::default() }, Team { id: "@acme/ops".into(), ..Default::default() }];
    repo_src(&mut w, "acme/web", Repo { codeowners: "* @acme/web\n".into(), ..Default::default() });
    w.sources.insert("runner-1".into(), Source { kind: "host".into(), reach: "ssh".into(), indexed_at: NOW.into(), ..Default::default() });
    w.hosts.insert(
        "runner-1".into(),
        Host {
            kind: Some("runner".into()),
            owner_team: Some("@acme/ops".into()),
            items: vec![HostItem {
                at: "2026-05-10T00:00:00Z".into(),
                kind: "node_modules".into(),
                loc: "/srv/actions/_work/web/web/node_modules".into(),
                pkgs: vec!["npm:evil@1.2.3".into()],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let ixw = Index::new(&w, NOW);
    let rw = hunt(&ixw, &q(&["npm:evil@1.2.3"])).unwrap();
    for f in findings(&rw) {
        assert_eq!(crate::out::progress::owner_label(f), f.owner_label);
        if f.kind == FKind::Host {
            assert_eq!(f.owner_label, "@acme/ops");
        }
    }
}

// A runner where a CI run installed the package says so, and is not "cache only, no project references it"
#[test]
fn r8_a_runner_that_ran_the_install_is_not_cache_only() {
    let mut v = View { now: NOW.into(), ..Default::default() };
    repo_src(
        &mut v,
        "acme/app",
        Repo {
            runs: vec![Run {
                id: 4112,
                at: "2026-05-11T15:30:00Z".into(),
                workflow: "deploy.yml".into(),
                runner: Some("ci-runner-3".into()),
                installed: vec!["npm:evil@1.2.3".into()],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    v.sources.insert("ci-runner-3".into(), Source { kind: "host".into(), reach: "ssh".into(), indexed_at: NOW.into(), ..Default::default() });
    v.hosts.insert(
        "ci-runner-3".into(),
        Host {
            kind: Some("runner".into()),
            items: vec![HostItem { at: "2026-05-11T15:31:00Z".into(), kind: "npm-cache".into(), loc: "/home/runner/.npm/_cacache".into(), pkgs: vec!["npm:evil@1.2.3".into()], ..Default::default() }],
            ..Default::default()
        },
    );
    let ix = Index::new(&v, NOW);
    let res = hunt(&ix, &q(&["npm:evil@1.2.3"])).unwrap();
    let h = findings(&res).into_iter().find(|f| f.kind == FKind::Host).unwrap().clone();
    assert_eq!(h.ci_installs, vec!["acme/app#4112".to_string()]);
    assert_eq!(h.note, "a CI run installed it here (acme/app#4112)");
    assert!(!h.note.contains("cache only") && !h.note.contains("no project"));
    assert!(install_ran_note("the install ran here (CI run acme/app#4112)") && install_ran_note("cache only; the install likely ran") && !install_ran_note(&h.note));
}
