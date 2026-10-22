//! Unit tests for the plan builders in `actions.rs`. Real-format samples only.

use super::*;

fn repo_finding(name: &str, version: &str, file: &str) -> Finding {
    Finding { kind: FKind::Repo, name: name.into(), version: version.into(), file: file.into(), where_: "o/r".into(), direct: true, ..Default::default() }
}

fn plan<'a>(f: &'a Finding) -> Plan<'a> {
    Plan { kind: PK::Bump, f, also: vec![], after: None }
}

#[test]
fn a_branch_is_named_for_what_its_repo_changes() {
    let q = Query::default();
    let fixed = Some("0.4.3".to_string());
    let (a, b) = (repo_finding("netprobe-py", "0.4.2", "poetry.lock"), repo_finding("@scope/other", "1.0.0", "package-lock.json"));
    assert_eq!(branch_name(&q, &[plan(&a)], &fixed), "br/fix-netprobe-py-0.4.3");
    // two different packages: the advisory id, or with none the first package and a count
    assert_eq!(branch_name(&q, &[plan(&a), plan(&b)], &fixed), "br/fix-netprobe-py-and-1-more");
    let go = repo_finding("github.com/x/y", "v1.2.0", "go.sum");
    assert_eq!(branch_name(&q, &[plan(&go)], &Some("v1.2.1".into())), "br/fix-github.com-x-y-1.2.1");
    assert_eq!(branch_word("@Scope/Pkg_Name"), "scope-pkg-name");
}

#[test]
fn the_stage_list_comes_from_the_manager_table() {
    // go: the lockfile finding is go.sum; go.mod is the manifest the commands change
    let go = repo_finding("github.com/x/y", "v1.2.0", "go.sum");
    assert_eq!(staged_files(&go, &[]), vec!["go.mod", "go.sum"]);
    // a finding in go.mod still stages go.sum, which `go mod tidy` rewrites
    let gomod = repo_finding("github.com/x/y", "v1.2.0", "go.mod");
    assert_eq!(staged_files(&gomod, &[]), vec!["go.mod", "go.sum"]);
    // cargo workspace member: the member's Cargo.toml and the root Cargo.lock
    let mut cargo = repo_finding("serde", "1.0.1", "Cargo.lock");
    cargo.manifest_path = Some("crates/a/Cargo.toml".into());
    assert_eq!(staged_files(&cargo, &[]), vec!["crates/a/Cargo.toml", "Cargo.lock"]);
    // npm shrinkwrap is the lockfile it is; package-lock.json is not invented next to it
    let sw = repo_finding("left-pad", "1.0.0", "npm-shrinkwrap.json");
    assert_eq!(staged_files(&sw, &[]), vec!["package.json", "npm-shrinkwrap.json"]);
    // poetry: pyproject.toml and poetry.lock; a hand-edited file leads
    let po = repo_finding("requests", "2.0.0", "svc/poetry.lock");
    assert_eq!(staged_files(&po, &["svc/extra.txt".to_string()]), vec!["svc/extra.txt", "svc/pyproject.toml", "svc/poetry.lock"]);
}

#[test]
fn no_fixed_release_is_only_said_when_the_ranges_say_so() {
    let f = repo_finding("netprobe-py", "0.4.2", "poetry.lock");
    PKGS.with(|p| p.borrow_mut().clear());
    assert_eq!(fix_of(&f, &None), Fix::Unknown);
    assert_eq!(fix_of(&f, &Some("0.4.3".into())), Fix::To("0.4.3".into()));
    let pkg = AffectedPackage {
        ecosystem: "pypi".into(),
        name: "netprobe-py".into(),
        versions: vec![],
        ranges: vec![crate::view::VersionRange { introduced: Some("0".into()), fixed: None, last_affected: Some("0.9.0".into()) }],
    };
    PKGS.with(|p| p.borrow_mut().push(("pypi".into(), "netprobe-py".into(), pkg)));
    let mut g = f.clone();
    g.eco = "pypi".into();
    assert_eq!(fix_of(&g, &None), Fix::NoRelease);
    PKGS.with(|p| p.borrow_mut().clear());
}

#[test]
fn an_export_is_named_by_login_and_a_runner_path_has_its_user() {
    assert_eq!(export_name("Lena Fischer (@lfischer)"), "lfischer");
    assert_eq!(export_name("laptop-omar"), "laptop-omar");
    assert_eq!(export_name("D. Okafor / Q (2)"), "D._Okafor_Q_2");
    assert_eq!(host_user("/home/runner/.npm/_cacache").as_deref(), Some("runner"));
    assert_eq!(host_user("/Users/dana/Library/pnpm").as_deref(), Some("dana"));
    assert_eq!(host_user("/root/.cache/pip").as_deref(), Some("root"));
    assert_eq!(host_user("/opt/hostedtoolcache/x"), None);
    assert_eq!(host_user("C:\\Users\\dana\\x"), None);
}

#[test]
fn the_script_checks_the_tools_it_calls_and_not_the_ones_it_only_mentions() {
    let body: Vec<String> = vec![
        "# gh and crane are only named in this comment".into(),
        "echo 'run ssh later'".into(),
        "gh cache delete k -R o/r".into(),
        "{ br scan --repo o/r && br hunt x; } || { echo no; }".into(),
        "ssh h 'sudo -u runner -H rm -rf /home/runner/x'".into(),
        "id=$(gh api x) && crane delete y".into(),
    ];
    assert_eq!(tools_used(&body), vec!["gh", "br", "ssh", "crane"]);
}

#[test]
fn a_guarded_block_of_comments_has_no_empty_then() {
    let mut sh = Sh { body: vec![], manual: 0 };
    sh.guarded(Some("merged o/r".into()), vec!["# only a comment".into()]);
    assert_eq!(sh.body, vec!["# only a comment"]);
    let mut sh = Sh { body: vec![], manual: 0 };
    sh.guarded(Some("merged o/r".into()), vec!["# c".into(), "gh cache delete k".into()]);
    assert_eq!(sh.body, vec!["if merged o/r; then", "  # c", "  gh cache delete k", "else", "  skipped=1", "fi"]);
}

#[test]
fn lines_of_one_repo_are_printed_under_it_once() {
    let l = |k: &str, b: &str| Line { key: k.into(), lead: Some(k.into()), body: b.into() };
    let out = render_lines(&[l("o/a", "one"), l("o/b", "two"), l("o/a", "three")]);
    assert_eq!(out, vec!["  - o/a:", "      - one", "      - three", "  - o/b: two"]);
}

#[test]
fn only_the_dispatchable_rebuild_is_a_command() {
    // gh run rerun is never offered, in any text the purge builds
    assert!(!PUSH_FIX_NOTE.contains("gh run rerun"));
}

// The blob digest the scan recorded is used as it is; only an index with none falls back to reading the manifest
#[test]
fn a_recorded_layer_blob_is_named_and_the_manifest_is_the_fallback() {
    let d = format!("sha256:{}", "ab".repeat(32));
    let f = Finding { kind: FKind::Image, image: "reg.example/team/app".into(), digest: "sha256:cd".into(), layer: 3, layer_blob: Some(d.clone()), ..Default::default() };
    let with = blob_prep(&f, "");
    assert_eq!(with[1], format!("blob={d}"));
    assert!(with.iter().all(|l| !l.contains("crane manifest")), "{with:?}");
    assert!(blob_words(&f).contains(&d));
    let without = Finding { layer_blob: None, ..f };
    let fb = blob_prep(&without, "");
    // The manifest is read on its own line, so a failed crane stops the script; the blob is cut from it on the next
    let fb_all = fb.join("\n");
    assert!(fb[1].contains("bm=$(crane manifest") && fb[1].contains("return 1"), "{fb:?}");
    assert!(fb_all.contains("sed -n '3p'") && !fb_all.contains("crane manifest reg.example/team/app@sha256:cd | "), "{fb:?}");
}

// Fix names the secrets from the one table, with the runs and owners hunt prints
#[test]
fn fix_rotates_the_secrets_of_the_shared_table() {
    use crate::view::{Team, View};
    let mut v = View::default();
    v.teams = vec![Team { id: "@acme/web".into(), ..Default::default() }, Team { id: "@acme/growth".into(), ..Default::default() }];
    let ix = Index::new(&v, "2026-05-12T00:00:00Z");
    let run = |repo: &str, id: u64, team: &str| Finding {
        kind: FKind::CiRun,
        where_: repo.into(),
        id,
        secrets: vec!["NPM_TOKEN".into()],
        owner: crate::query::hunt::Owner { team: Some(team.into()), ..Default::default() },
        ..Default::default()
    };
    let (a, b, c) = (run("acme/a", 1, "@acme/web"), run("acme/b", 2, "@acme/growth"), run("acme/a", 3, "@acme/web"));
    let res = HuntResult { findings: vec![a.clone(), b.clone(), c.clone()], ..Default::default() };
    let lines = rotate_block(&ix, &res, &[&a, &b, &c]);
    let table = crate::query::secrets::secret_uses(&ix, &res);
    assert_eq!(table.len(), 1);
    assert!(lines[1].contains("(1)"), "{lines:?}");
    // A name set in two repos is two secrets, and the table says so
    assert!(lines[2].contains("1 secret name, 2 secrets: NPM_TOKEN (2 repos) is stored separately"), "{lines:?}");
    let row = lines.iter().find(|l| l.contains("NPM_TOKEN") && l.contains("runs in")).unwrap();
    assert!(row.contains("3 runs in acme/a, acme/b") && row.contains("@acme/growth, @acme/web"), "{lines:?}");
}

// ---- plans and scripts -------------------------------------------------------------------------------------------
fn host_hit(loc: &str) -> Finding {
    Finding { kind: FKind::Host, where_: "laptop-a".into(), loc: loc.into(), item_kind: "install".into(), ..Default::default() }
}

#[test]
fn r54_a_plan_covers_what_is_present_now_but_first_seen_after_the_window() {
    let mut res = HuntResult::default();
    res.findings = vec![repo_finding("a", "1.0.0", "package-lock.json")];
    res.present_after = vec![repo_finding("b", "1.0.0", "package-lock.json")];
    let names: Vec<&str> = all_findings(&res).iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b"]);
    assert!(after_window_note(&res).unwrap().contains("first seen after the window"));
    res.present_after.clear();
    assert!(after_window_note(&res).is_none());
}

#[test]
fn r63_a_dockerfile_step_that_fetches_or_copies_is_named() {
    // BuildKit history and the legacy `#(nop)` form
    let (s, frag) = fetch_step("ADD https://dl.example/0.4.2/tool-linux-amd64 /usr/local/bin/tool").unwrap();
    assert_eq!(s, "ADD https://dl.example/0.4.2/tool-linux-amd64 /usr/local/bin/tool");
    assert_eq!(frag, "https://dl.example/0.4.2/tool-linux-amd64");
    let (s, frag) = fetch_step("/bin/sh -c #(nop)  COPY --from=tools /tool /opt/tools/tool").unwrap();
    assert!(s.starts_with("COPY --from=tools"), "{s}");
    assert_eq!(frag, "--from=tools");
    let (s, frag) = fetch_step("RUN curl -fsSL https://dl.example/v1.2.3/tool.tgz | tar xz -C /usr/local/bin").unwrap();
    assert!(s.starts_with("RUN curl"), "{s}");
    assert_eq!(frag, "https://dl.example/v1.2.3/tool.tgz");
    // steps that bring nothing in from outside the build are not named
    assert!(fetch_step("COPY ./tool /usr/local/bin/tool").is_none());
    assert!(fetch_step("ADD tool.tgz /opt/").is_none());
    assert!(fetch_step("RUN apt-get install -y ca-certificates").is_none());
}

#[test]
fn r63_removal_uses_the_managers_cleaner_or_makes_the_tree_writable() {
    // the Go module cache is read-only: its own cleaner
    assert_eq!(host_cmd(&host_hit("/Users/k/go/pkg/mod/example.com/x@v1.0.0")).0, "go clean -modcache");
    assert_eq!(host_cmd(&host_hit("/home/r/.npm/_cacache/content-v2")).0, "npm cache clean --force");
    // any other tree is made writable first, and the path is quoted
    let (cmd, is_path) = host_cmd(&host_hit("/opt/tool cache/x"));
    assert!(is_path);
    assert_eq!(cmd, "chmod -R u+w '/opt/tool cache/x' && rm -rf '/opt/tool cache/x'");
    // a Windows host keeps PowerShell, which needs no chmod
    assert!(host_cmd(&host_hit("C:\\Users\\k\\tool")).0.starts_with("Remove-Item"));
}

#[test]
fn r63_a_tool_is_checked_where_it_is_first_needed() {
    let body: Vec<String> = [
        "# PART 1",
        "gh release delete-asset v1 a -R o/r",
        "gh release delete-asset v1 b -R o/r",
        "skipped=0",
        "if merged o/r; then",
        "  ssh host 'rm -rf /x'",
        "else",
        "  skipped=1",
        "fi",
        "verify_first() {",
        "  crane digest img",
        "}",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out = with_tool_checks(body);
    let at = |needle: &str| out.iter().position(|l| l.contains(needle)).unwrap_or(usize::MAX);
    // gh once, before its first use; ssh before the whole `if` block; crane inside the function, not before it
    assert_eq!(out.iter().filter(|l| l.contains("command -v gh ")).count(), 1);
    assert!(at("command -v gh ") < at("gh release delete-asset v1 a"));
    assert!(at("command -v ssh ") < at("if merged o/r"));
    assert!(at("verify_first() {") < at("command -v crane "));
    assert!(out.iter().filter(|l| !l.starts_with(' ')).all(|l| !l.contains("command -v crane ")), "crane must not be checked at the top level");
}

#[test]
fn r63_a_runner_waits_only_for_the_repos_whose_runs_used_it() {
    use crate::view::{Repo, Run, Source, View};
    let mut v = View::default();
    let run = |id: u64, runner: &str| Run { id, at: "2026-01-02T00:00:00Z".into(), runner: Some(runner.into()), ..Default::default() };
    let mut a = Repo::default();
    a.runs = vec![run(1, "runner-1.ci.internal")];
    let mut b = Repo::default();
    b.runs = vec![run(2, "runner-2")];
    v.repos.insert("o/a".into(), a);
    v.repos.insert("o/b".into(), b);
    for n in ["o/a", "o/b"] {
        v.sources.insert(n.into(), Source { kind: "repo".into(), indexed_at: "2026-01-03T00:00:00Z".into(), ..Default::default() });
    }
    let ix = Index::new(&v, "2026-01-04T00:00:00Z");
    // the runner name is matched as `runner_key` does (no domain, lower case)
    assert_eq!(runner_repos(&ix, "runner-1"), vec!["o/a".to_string()]);
    let unfixed: HashSet<String> = ["o/a".to_string(), "o/b".to_string()].into();
    assert_eq!(runner_gate(&ix, "runner-1", &unfixed), Some(vec!["o/a".to_string()]));
    // o/a is fixed: runner-1 no longer waits for anyone
    let only_b: HashSet<String> = ["o/b".to_string()].into();
    assert_eq!(runner_gate(&ix, "runner-1", &only_b), Some(vec![]));
    // no run names this runner: br cannot narrow it
    assert_eq!(runner_gate(&ix, "runner-9", &unfixed), None);
}

#[test]
fn r62_a_similar_hit_is_labelled_not_identical() {
    let mut f = host_hit("/tmp/.cache/upd.js");
    assert!(similar_label(&f).is_none());
    f.match_ = "similar".into();
    f.sim = Some(0.953);
    assert_eq!(similar_label(&f).unwrap(), "similar, not identical (95% like the sample)");
}

#[test]
fn r62_a_hash_offers_the_advisory_for_the_verb_it_was_asked_with() {
    let mut res = HuntResult::default();
    res.hash_advisories = vec![("sha256:ab".into(), "GHSA-aaaa-bbbb-cccc".into(), vec!["npm:evil".into()])];
    let l = hash_advisory_offer(&res, "fix");
    assert_eq!(l, vec!["this hash is listed by GHSA-aaaa-bbbb-cccc, which names npm:evil; br fix --advisory GHSA-aaaa-bbbb-cccc plans the package changes".to_string()]);
}

#[test]
fn r57_the_laptops_row_names_who_is_not_covered() {
    let mut res = HuntResult::default();
    res.not_checked = vec![crate::query::hunt::NotChecked {
        name: "laptops".into(),
        kind: "laptops".into(),
        state: "laptops".into(),
        why: "2 of 4 members visible to this token in GitHub have no laptop scan here".into(),
        indexed_at: None,
        command: "br hosts lists them".into(),
        people: vec!["Mira Szabo".into(), "Sofia Alvarez".into()],
    }];
    let t = not_checked_text(&res, "").join("\n");
    assert!(t.contains("have no laptop scan here (Mira Szabo, Sofia Alvarez); to close"), "{t}");
}

// ---- hosts and caches -------------------------------------------------------------------------------------------
fn pkg_hit(kind: &str, loc: &str, pkgs: &[&str]) -> Finding {
    Finding {
        kind: FKind::Host,
        where_: "laptop-a".into(),
        loc: loc.into(),
        item_kind: kind.into(),
        hit_pkgs: pkgs.iter().map(|p| p.to_string()).collect(),
        item_pkgs: pkgs.iter().map(|p| p.to_string()).collect(),
        ..Default::default()
    }
}

// A package in node_modules is its own folder, not the whole node_modules
#[test]
fn r69_a_node_modules_package_is_removed_alone() {
    let f = pkg_hit("node_modules", "/home/dev/app/node_modules", &["npm:@tanstack/react-router@1.120.3", "npm:evil-pkg@1.0.0"]);
    let (pre, del) = destructive(&f, None).unwrap();
    assert_eq!(del, "rm -rf /home/dev/app/node_modules/@tanstack/react-router /home/dev/app/node_modules/evil-pkg");
    assert!(pre.starts_with("(tar czf - -C /home/dev/app/node_modules @tanstack/react-router evil-pkg) > "), "{pre}");
    assert!(wider_note(&f).is_none());
    assert!(preserves(&f).unwrap().contains("the package folder only, not the rest of node_modules"));
    // over ssh, as the user whose home it is
    let (pre, del) = destructive(&f, Some("ssh")).unwrap();
    assert!(pre.contains("tar czf - -C /home/dev/app/node_modules @tanstack/react-router evil-pkg"), "{pre}");
    assert!(del.starts_with("ssh laptop-a 'sudo -u dev -H rm -rf /home/dev/app/node_modules/@tanstack/react-router"), "{del}");
    // a Windows host gets PowerShell, one literal path per package
    let w = pkg_hit("node_modules", "C:\\Users\\dev\\app\\node_modules", &["npm:evil-pkg@1.0.0"]);
    let (_, del) = destructive(&w, None).unwrap();
    assert_eq!(del, "Remove-Item -LiteralPath 'C:\\Users\\dev\\app\\node_modules\\evil-pkg' -Recurse -Force");
    // nothing says which package matched: the whole folder goes and the line says so
    let mut whole = f.clone();
    whole.hit_pkgs.clear();
    assert!(host_cmd(&whole).0.ends_with("rm -rf /home/dev/app/node_modules"));
    assert!(wider_note(&whole).unwrap().starts_with("wider than the finding: removes the whole node_modules folder"));
}

// A package in site-packages is pip uninstall in the interpreter that owns the folder
#[test]
fn r69_a_site_packages_package_is_uninstalled_not_the_folder() {
    let f = pkg_hit("site-packages", "/home/dev/.local/lib/python3.11/site-packages", &["pypi:netprobe-py@0.4.2"]);
    let (pre, del) = destructive(&f, None).unwrap();
    assert_eq!(del, "python3.11 -m pip uninstall -y netprobe-py");
    assert!(!del.contains("rm -rf"), "{del}");
    assert!(pre.contains("-iname 'netprobe?py?0.4.2.dist-info' -exec cat {}/RECORD"), "{pre}");
    assert!(preserves(&f).unwrap().contains("RECORD of netprobe_py-0.4.2.dist-info"));
    assert!(wider_note(&f).is_none());
    // a virtualenv has its own python
    let v = pkg_hit("site-packages", "/srv/app/.venv/lib/python3.12/site-packages", &["pypi:netprobe-py@0.4.2"]);
    assert_eq!(destructive(&v, None).unwrap().1, "/srv/app/.venv/bin/python -m pip uninstall -y netprobe-py");
    // the same over ssh as another user: the pipeline runs as that user as a whole
    let (pre, _) = destructive(&f, Some("ssh")).unwrap();
    assert!(pre.contains("sudo -u dev -H sh -c"), "{pre}");
    // conda: the manager's own remove, for that prefix
    let c = pkg_hit("conda", "/opt/conda/envs/ml", &["pypi:netprobe-py@0.4.2"]);
    assert_eq!(destructive(&c, None).unwrap().1, "conda remove -y -p /opt/conda/envs/ml netprobe-py");
    // no package named: the folder goes, with the note
    let mut whole = f.clone();
    whole.hit_pkgs.clear();
    assert!(wider_note(&whole).unwrap().contains("removes the whole site-packages folder"));
}

// A Go module is its folder and its download-cache files, not the whole module cache; a pip cache entry goes by name
#[test]
fn r69_a_go_module_and_a_pip_wheel_are_removed_by_name() {
    let g = Finding { kind: FKind::Host, where_: "h".into(), loc: "/Users/kenji/go/pkg/mod/github.com/nprobe-dev/netprobe@v0.4.2".into(), item_kind: "go-mod-cache".into(), ..Default::default() };
    let del = destructive(&g, None).unwrap().1;
    assert!(del.starts_with("chmod -R u+w /Users/kenji/go/pkg/mod/github.com/nprobe-dev/netprobe@v0.4.2 && rm -rf /Users/kenji/go/pkg/mod/github.com/nprobe-dev/netprobe@v0.4.2 && rm -f "), "{del}");
    assert!(del.contains("/Users/kenji/go/pkg/mod/cache/download/github.com/nprobe-dev/netprobe/@v/v0.4.2.zip"), "{del}");
    assert!(!del.contains("go clean"), "{del}");
    assert!(wider_note(&g).is_none());
    // a chained command over ssh runs as the user whose home it is, as a whole
    assert!(destructive(&g, Some("ssh")).unwrap().1.starts_with("ssh h 'sudo -u kenji -H sh -c "), "{:?}", destructive(&g, Some("ssh")));
    // one file inside the module: the file goes (not the cache), the folder is made writable first
    let mut gf = g.clone();
    gf.loc = format!("{}/prebuilt/netprobe-linux-amd64", g.loc);
    let del = destructive(&gf, None).unwrap().1;
    assert!(del.starts_with(&format!("chmod -R u+w {} && rm -rf {} && rm -f ", g.loc, gf.loc)), "{del}");
    assert!(!del.contains("go clean") && wider_note(&gf).is_none(), "{del}");
    let p = pkg_hit("pip-cache", "/home/dev/.cache/pip", &["pypi:netprobe-py@0.4.2"]);
    assert_eq!(destructive(&p, None).unwrap().1, "pip cache remove 'netprobe_py-0.4.2-*'");
    assert!(wider_note(&p).is_none());
    // a cache with no named package keeps the cleaner and says what else it removes
    let mut all = p.clone();
    all.hit_pkgs.clear();
    assert_eq!(host_cmd(&all).0, "pip cache purge");
    assert!(wider_note(&all).unwrap().starts_with("wider than the finding: pip cache purge"));
}

// An Actions cache's "preserve first" is metadata, and says so, and offers the contents
#[test]
fn r69_a_cache_preserve_says_it_is_metadata_and_offers_the_contents() {
    let c = Finding { kind: FKind::Cache, where_: "acme/web".into(), key: "npm-abc".into(), ..Default::default() };
    assert!(preserves(&c).unwrap().starts_with("only the cache's metadata"));
    assert!(preserve_offer(&c).unwrap().contains("actions/cache/restore with key npm-abc"));
    let (lines, _) = chain(&c, None, false);
    assert!(lines[0].starts_with("# preserves: only the cache's metadata"), "{lines:?}");
    assert!(lines[1].contains("to keep the contents too"), "{lines:?}");
    assert!(lines[2].starts_with("gh cache list"), "{lines:?}");
    // --no-preserve drops all of it
    assert_eq!(chain(&c, None, true).0.len(), 1);
}

fn lock_view() -> View {
    let now = "2026-05-12T12:00:00Z";
    let mut v = View { now: now.into(), ..Default::default() };
    v.sources.insert("dev-mbp".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: "2026-05-12T10:00:00Z".into(), ..Default::default() });
    let item = |loc: &str, p: &str| crate::view::HostItem { at: "2026-05-11T00:00:00Z".into(), kind: "lockfile".into(), loc: loc.into(), pkgs: vec![p.into()], ..Default::default() };
    v.hosts.insert(
        "dev-mbp".into(),
        crate::view::Host {
            kind: Some("laptop".into()),
            owner: Some("dev".into()),
            items: vec![item("/home/dev/app/package-lock.json", "npm:evil-pkg@1.0.0"), item("/home/dev/app/requirements.txt", "pypi:netprobe-py@0.4.2")],
            declared: vec![crate::view::DeclaredLock {
                loc: "/home/dev/app/package-lock.json".into(),
                packages: vec![crate::view::LockPackage { p: "npm:evil-pkg@1.0.0".into(), direct: true, ..Default::default() }],
            }],
            ..Default::default()
        },
    );
    v
}

// A lockfile on a host is changed, never removed
#[test]
fn a_host_command_never_removes_a_lockfile() {
    for loc in ["/home/dev/app/package-lock.json", "/home/dev/app/requirements.txt", "/home/dev/svc/Cargo.lock", "/home/dev/svc/go.sum", "C:\\Users\\dev\\app\\yarn.lock"] {
        let f = pkg_hit("lockfile", loc, &["npm:evil-pkg@1.0.0"]);
        assert!(is_lockfile(&f));
        assert!(destructive(&f, None).is_none(), "{loc}");
        assert!(destructive(&f, Some("ssh")).is_none(), "{loc}");
        assert!(wider_note(&f).is_none());
        assert!(preserves(&f).is_none());
    }
    // the whole plan: no command of purge (script, text, json), notify or fix removes the lockfile or its folder
    let v = lock_view();
    let ix = Index::new(&v, "2026-05-12T12:00:00Z");
    let q = Query { iocs: ["npm:evil-pkg@1.0.0", "pypi:netprobe-py@0.4.2"].iter().map(|i| crate::query::iocs::parse_ioc(i, None).unwrap()).collect(), ..Default::default() };
    let res = H::hunt(&ix, &q).unwrap();
    assert!(all_findings(&res).iter().any(|f| is_lockfile(f)), "the hunt must find the lockfiles");
    let a = QueryArgs::default();
    let fixed = Some("1.0.1".to_string());
    for (fm, commands) in [(None, true), (None, false), (Some("json".to_string()), false)] {
        let t = purge(&ix, &a, &q, &res, commands, &fm, false);
        for l in t.lines().filter(|l| !l.trim_start().starts_with('#')) {
            assert!(!((l.contains("rm ") || l.contains("Remove-Item")) && l.contains("/home/dev/app")), "{l}");
        }
        assert!(t.contains("/home/dev/app/package-lock.json"), "the lockfile is named: {t}");
    }
    let n = notify_to(&ix, &q, &res, "slack", &fixed).unwrap();
    assert!(!n.contains("rm -rf"), "{n}");
    assert!(n.contains("/home/dev/app/package-lock.json") && n.contains("pins evil-pkg 1.0.0"), "{n}");
    let fx = fix(&ix, &a, &q, &res, &fixed).unwrap();
    assert!(fx.contains("LOCKFILES ON HOSTS") && fx.contains("npm install evil-pkg@1.0.1"), "{fx}");
    assert!(!fx.contains("rm -rf"), "{fx}");
}

fn run_finding(repo: &str, id: u64, secrets: &[&str]) -> Finding {
    Finding { kind: FKind::CiRun, where_: repo.into(), id, runner: "ci-runner-9".into(), secrets: secrets.iter().map(|s| s.to_string()).collect(), ..Default::default() }
}

// A repo that dropped the bad version but whose runs read secrets still gets its line in fix
#[test]
fn r73_a_fixed_repo_that_still_has_secrets_gets_a_nothing_to_change_line() {
    let mut v = View { now: "2026-05-12T12:00:00Z".into(), ..Default::default() };
    v.sources.insert("acme/old".into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: "2026-05-12T10:00:00Z".into(), ..Default::default() });
    v.repos.insert("acme/old".into(), crate::view::Repo::default());
    let ix = Index::new(&v, "2026-05-12T12:00:00Z");
    let q = Query { iocs: vec![crate::query::iocs::parse_ioc("npm:foo@1.0.0", None).unwrap()], ..Default::default() };
    let mut res = HuntResult::default();
    let mut gone = repo_finding("foo", "1.0.0", "package-lock.json");
    gone.where_ = "acme/old".into();
    gone.state = "removed".into();
    res.findings = vec![gone, run_finding("acme/old", 7, &["DEPLOY_KEY"])];
    let fx = fix(&ix, &QueryArgs::default(), &q, &res, &Some("1.0.1".into())).unwrap();
    assert!(fx.contains("acme/old"), "{fx}");
    assert!(fx.contains("nothing to change: the affected version is already gone from it. Its CI runs could read secrets: see ROTATE SECRETS below"), "{fx}");
    assert!(fx.contains("DEPLOY_KEY"), "{fx}");
}

// The owner of the repo whose checkout holds a runner finding is told too; the runner's owner keeps the cleanup
#[test]
fn r68_a_runner_workspace_finding_goes_to_the_repo_owner_and_the_runner_owner() {
    let now = "2026-05-12T12:00:00Z";
    let mut v = View { now: now.into(), ..Default::default() };
    v.sources.insert("acme/web".into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: now.into(), ..Default::default() });
    v.repos.insert("acme/web".into(), crate::view::Repo { codeowners: "* @webowner\n".into(), ..Default::default() });
    v.sources.insert("ci-1".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: now.into(), ..Default::default() });
    v.hosts.insert(
        "ci-1".into(),
        crate::view::Host {
            kind: Some("runner".into()),
            owner: Some("runnerowner".into()),
            items: vec![crate::view::HostItem {
                at: "2026-05-11T00:00:00Z".into(),
                kind: "node_modules".into(),
                loc: "/srv/actions/_work/web/web/node_modules".into(),
                pkgs: vec!["npm:evil-pkg@1.0.0".into()],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let ix = Index::new(&v, now);
    let q = Query { iocs: vec![crate::query::iocs::parse_ioc("npm:evil-pkg@1.0.0", None).unwrap()], ..Default::default() };
    let res = H::hunt(&ix, &q).unwrap();
    let n = notify_to(&ix, &q, &res, "slack", &None).unwrap();
    let (to_runner, to_repo) = (n.find("To @runnerowner"), n.find("To @webowner"));
    assert!(to_runner.is_some() && to_repo.is_some(), "{n}");
    assert!(n.contains("holds it; fix the repo and rotate what its runs could read (ci-1's owner, @runnerowner, cleans the machine)"), "{n}");
    assert!(n.contains("rm -rf /srv/actions/_work/web/web/node_modules/evil-pkg"), "{n}");
}

// A runner's cache cleanup names the checkouts and tool caches on the same runner that hold the package
#[test]
fn r69_a_runner_plan_names_the_checkouts_and_tool_caches_that_hold_the_package() {
    let now = "2026-05-12T12:00:00Z";
    let mut v = View { now: now.into(), ..Default::default() };
    v.hosts.insert("ci-1".into(), crate::view::Host { kind: Some("runner".into()), ..Default::default() });
    let ix = Index::new(&v, now);
    let cache = Finding { where_: "ci-1".into(), ..pkg_hit("npm-cache", "/home/runner/.npm/_cacache", &["npm:x@1.0.0"]) };
    let work = Finding { where_: "ci-1".into(), ..pkg_hit("node_modules", "/srv/_work/web/web/node_modules", &["npm:x@1.0.0"]) };
    let tool = Finding { where_: "ci-1".into(), ..pkg_hit("tool-cache", "/opt/hostedtoolcache/x/1.0.0/x64", &["npm:x@1.0.0"]) };
    let hosts = vec![&cache, &work, &tool];
    let n = runner_holds(&ix, &cache, &hosts).unwrap();
    assert_eq!(n, "ci-1 also holds it in _work checkout /srv/_work/web/web/node_modules; tool cache /opt/hostedtoolcache/x/1.0.0/x64; each has its own entry");
    // the checkout and the tool cache are not themselves caches: nothing to add to them
    assert!(runner_holds(&ix, &work, &hosts).is_none());
    // a runner that was not scanned since the install is told to scan it
    let inferred = Finding { kind: FKind::Host, where_: "ci-1".into(), inferred: true, item_kind: "inferred".into(), loc: "npm cache".into(), ..Default::default() };
    let n = runner_holds(&ix, &inferred, &[]).unwrap();
    assert!(n.starts_with("ci-1 was not scanned since the install: it may also hold it in the _work checkouts of"), "{n}");
}

// An org secret is told to the org admins, and the team's message says who rotates it
#[test]
fn r68_an_org_secret_goes_to_the_org_admins() {
    let now = "2026-05-12T12:00:00Z";
    let mut v = View { now: now.into(), ..Default::default() };
    v.org_admins = vec!["adminone".into()];
    v.sources.insert("acme/web".into(), Source { kind: "repo".into(), reach: "github".into(), indexed_at: now.into(), ..Default::default() });
    v.repos.insert(
        "acme/web".into(),
        crate::view::Repo {
            codeowners: "* @webowner\n".into(),
            secret_scopes: vec![crate::view::SecretScope { name: "ORG_TOKEN".into(), scope: "org (all repos)".into(), ..Default::default() }],
            ..Default::default()
        },
    );
    let ix = Index::new(&v, now);
    let mut res = HuntResult::default();
    res.findings = vec![repo_finding("foo", "1.0.0", "package-lock.json"), run_finding("acme/web", 3, &["ORG_TOKEN"])];
    res.findings[0].where_ = "acme/web".into();
    res.findings[0].owner = crate::query::hunt::Owner { people: vec!["webowner".into()], ..Default::default() };
    res.findings[1].owner = res.findings[0].owner.clone();
    let q = Query { iocs: vec![crate::query::iocs::parse_ioc("npm:foo@1.0.0", None).unwrap()], ..Default::default() };
    let n = notify_to(&ix, &q, &res, "slack", &Some("1.0.1".into())).unwrap();
    assert!(n.contains("To the org admins (adminone)"), "{n}");
    assert!(n.contains("- ORG_TOKEN (org (all repos)); used by "), "{n}");
    assert!(n.contains("Org secrets that were in reach of those runs: ORG_TOKEN (org (all repos)). The org admins (adminone) own and rotate them"), "{n}");
    assert!(!n.contains("rotate: ORG_TOKEN"), "the team is not asked to rotate an org secret: {n}");
}

// A suggested owner is worded as a suggestion
#[test]
fn r68_a_suggested_owner_is_labelled_a_suggestion() {
    let mut f = repo_finding("foo", "1.0.0", "package-lock.json");
    f.owner = crate::query::hunt::Owner { people: vec!["dokafor".into()], suggested: Some("archived it 05-11".into()), ..Default::default() };
    let v = View::default();
    let ix = Index::new(&v, "2026-05-12T12:00:00Z");
    assert_eq!(owner_label(&ix, &f), "@dokafor (suggested: archived it 05-11)");
    f.owner.suggested = None;
    assert_eq!(owner_label(&ix, &f), "@dokafor");
}

// The host that was scanned or imported as this machine runs its commands here
#[test]
fn r73_this_machine_runs_its_commands_here() {
    let now = "2026-05-12T12:00:00Z";
    let mut v = View { now: now.into(), ..Default::default() };
    v.sources.insert("dev-mbp".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: now.into(), ..Default::default() });
    v.hosts.insert(
        "dev-mbp".into(),
        crate::view::Host {
            kind: Some("laptop".into()),
            owner: Some("dev".into()),
            this_machine: true,
            items: vec![crate::view::HostItem {
                at: "2026-05-11T00:00:00Z".into(),
                kind: "node_modules".into(),
                loc: "/home/dev/app/node_modules".into(),
                pkgs: vec!["npm:evil-pkg@1.0.0".into()],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let mut ix_view = v.clone();
    let ix = Index::new(&ix_view, now);
    assert_eq!(host_reach(&ix, "dev-mbp"), "local");
    let q = Query { iocs: vec![crate::query::iocs::parse_ioc("npm:evil-pkg@1.0.0", None).unwrap()], ..Default::default() };
    let res = H::hunt(&ix, &q).unwrap();
    let a = QueryArgs::default();
    let text = purge(&ix, &a, &q, &res, false, &None, false);
    assert!(text.contains("this machine; run these here:") && !text.contains("not reachable from here"), "{text}");
    let sh = purge(&ix, &a, &q, &res, true, &None, false);
    assert!(sh.contains("# on this machine (dev-mbp), /home/dev/app/node_modules:"), "{sh}");
    assert!(sh.lines().any(|l| l.contains("&& rm -rf /home/dev/app/node_modules/evil-pkg || { echo ")), "{sh}");
    // not this machine: import-only, commands for its owner to run
    ix_view.hosts.get_mut("dev-mbp").unwrap().this_machine = false;
    let ix2 = Index::new(&ix_view, now);
    let text = purge(&ix2, &a, &q, &H::hunt(&ix2, &q).unwrap(), false, &None, false);
    assert!(text.contains("not reachable from here"), "{text}");
}

// The look-alike files that --similar-related found are planned for, and never counted
#[test]
fn r72_similar_related_hits_join_notify_and_purge_without_being_counted() {
    let now = "2026-05-12T12:00:00Z";
    let mut v = View { now: now.into(), ..Default::default() };
    v.sources.insert("box".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: now.into(), ..Default::default() });
    v.hosts.insert("box".into(), crate::view::Host { owner: Some("dev".into()), ..Default::default() });
    let ix = Index::new(&v, now);
    let h = "a".repeat(64);
    let exact = Finding { ioc: format!("sha256:{h}"), match_: "exact".into(), sha256: h.clone(), ..pkg_hit("loose-file", "/tmp/a.js", &[]) };
    let like = Finding { match_: "similar".into(), sim: Some(0.97), ..pkg_hit("loose-file", "/tmp/b.js", &[]) };
    let own = crate::query::hunt::Owner { people: vec!["dev".into()], ..Default::default() };
    let (exact, like) = (Finding { where_: "box".into(), owner: own.clone(), ..exact }, Finding { where_: "box".into(), owner: own, ..like });
    let mut res = HuntResult::default();
    res.findings = vec![exact];
    res.similar = vec![like];
    let q = Query { iocs: vec![crate::query::iocs::parse_ioc(&format!("sha256:{h}"), None).unwrap()], ..Default::default() };
    add_similar(&ix, &q, &mut res);
    assert_eq!(res.findings.len(), 2, "the look-alike joins the plan");
    let n = notify_to(&ix, &q, &res, "slack", &None).unwrap();
    assert!(n.contains("similar, not identical (97% like the sample): /tmp/b.js"), "{n}");
    assert!(n.contains("In all: 1 finding in 1 place; plus 1 file that looks like it, not identical."), "{n}");
    let p = purge(&ix, &QueryArgs::default(), &q, &res, false, &None, false);
    assert!(p.contains("/tmp/b.js") && p.contains("similar, not identical"), "{p}");
}

// ---- regressions --------------------------------------------------------------------------------------------
fn r8_image_view(now: &str) -> View {
    let mut v = View { now: now.into(), ..Default::default() };
    v.sources.insert("ghcr.io/acme".into(), Source { kind: "registry".into(), reach: "docker".into(), indexed_at: now.into(), ..Default::default() });
    v.images = vec![ImageBuild {
        repository: "ghcr.io/acme/app".into(),
        digest: format!("sha256:{}", "cd".repeat(32)),
        built: "2026-05-11T10:00:00Z".into(),
        tags: vec!["latest".into()],
        source: Some(crate::view::ImageSource { repo: Some("acme/app".into()), commit: Some("abc1234".into()), run: None }),
        layers: vec![crate::view::Layer { n: 1, packages: vec!["npm:evil@1.0.0".into()], ..Default::default() }],
        ..Default::default()
    }];
    v
}

fn run_sh(dir: &std::path::Path, script: &str) -> (i32, String) {
    let out = std::process::Command::new("sh").arg("-c").arg(script).current_dir(dir).output().unwrap();
    (out.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

// Every check in the script fails closed; the generated verify step, run against a `br` that exits 2, refuses
#[test]
fn r8_the_verify_step_refuses_when_br_fails() {
    let now = "2026-05-12T12:00:00Z";
    let v = r8_image_view(now);
    let ix = Index::new(&v, now);
    let q = Query { iocs: vec![crate::query::iocs::parse_ioc("npm:evil@1.0.0", None).unwrap()], ..Default::default() };
    let res = H::hunt(&ix, &q).unwrap();
    assert_eq!(H::findings(&res).iter().filter(|f| f.kind == FKind::Image).count(), 1);
    let sh = purge(&ix, &QueryArgs::default(), &q, &res, true, &None, false);
    // no check pipes a command into grep, and the script asks for pipefail where the shell has it
    assert!(sh.contains("set -o pipefail"), "{sh}");
    for l in sh.lines().filter(|l| !l.trim_start().starts_with('#')) {
        assert!(!l.contains("| grep -q"), "a check that hides the exit status of its first command: {l}");
    }
    let body: Vec<&str> = sh.lines().skip_while(|l| !l.starts_with("verify_first() {")).collect();
    assert!(body.len() > 5, "{sh}");
    let dir = std::env::temp_dir().join(format!("br-r8-verify-{}", std::process::id()));
    let stub = dir.join("stub");
    std::fs::create_dir_all(&stub).unwrap();
    let w = |n: &str, t: &str| {
        std::fs::write(stub.join(n), format!("#!/bin/sh\n{t}\n")).unwrap();
        std::process::Command::new("chmod").arg("+x").arg(stub.join(n)).status().unwrap();
    };
    std::fs::write(dir.join("v.sh"), body.join("\n")).unwrap();
    w("gh", "echo RAN gh $*");
    w("crane", "echo sha256:newdigest");
    // br: scan and sql work, hunt exits 2
    w("br", "if [ \"$1\" = sql ]; then echo digest; echo sha256:newdigest; elif [ \"$1\" = scan ]; then exit 0; else echo error >&2; exit 2; fi");
    let go = |t: &str| run_sh(&dir, &format!("PATH={}:$PATH sh v.sh {t}", stub.display()));
    let (code, out) = go("--verified");
    assert_ne!(code, 0, "the step must refuse: {out}");
    assert!(out.contains("could not run") && !out.contains("RAN gh api -X DELETE"), "{out}");
    // sql fails: refuse
    w("br", "if [ \"$1\" = sql ]; then exit 2; else exit 0; fi");
    let (code, out) = go("--verified");
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("br sql failed") && !out.contains("RAN gh"), "{out}");
    // everything works and the hunt finds nothing: it deletes
    w("br", "if [ \"$1\" = sql ]; then echo digest; echo sha256:newdigest; else exit 0; fi");
    let (code, out) = go("--verified");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("RAN gh api -X DELETE"), "{out}");
    // and the new digest is in the hunt's answer: refuse
    w("br", "if [ \"$1\" = sql ]; then echo digest; echo sha256:newdigest; else echo ghcr.io/acme/app@sha256:newdigest; fi");
    let (code, out) = go("--verified");
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("still holds the indicator") && !out.contains("RAN gh api -X DELETE"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

// A path an earlier step removed is not acted on again, and one place is one step
#[test]
fn r8_a_file_inside_a_removed_module_is_one_step() {
    let module = "/Users/k/go/pkg/mod/github.com/x/probe@v0.4.2";
    let a = Finding {
        ioc: "go:github.com/x/probe@v0.4.2".into(),
        item_kind: "go-mod-cache".into(),
        hit_pkgs: vec!["go:github.com/x/probe@v0.4.2".into()],
        ..pkg_hit("go-mod-cache", module, &["go:github.com/x/probe@v0.4.2"])
    };
    let h = "a".repeat(64);
    let b = Finding { ioc: format!("sha256:{h}"), sha256: h.clone(), match_: "exact".into(), ..pkg_hit("go-mod-cache", &format!("{module}/prebuilt/probe"), &[]) };
    let mut res = HuntResult { findings: vec![a, b], ..Default::default() };
    merge_findings(&mut res);
    assert_eq!(res.findings.len(), 1, "{:?}", res.findings.iter().map(|f| &f.loc).collect::<Vec<_>>());
    assert_eq!(res.findings[0].loc, module);
    assert!(is_malware(&res.findings[0]), "a hash hit inside the module makes the step a malware step");
    assert!(res.findings[0].iocs_or_one().iter().any(|i| i.starts_with("sha256:")));
    // two cache findings with one cleaner on one host are one step
    let c = |loc: &str| Finding { where_: "ci".into(), ..pkg_hit("npm-cache", loc, &["npm:evil@1.0.0"]) };
    let mut r2 = HuntResult { findings: vec![c("/home/runner/.npm/_cacache"), c("/home/runner/.npm/_cacache2/_cacache")], ..Default::default() };
    merge_findings(&mut r2);
    assert_eq!(r2.findings.len(), 1);
    // a package folder inside node_modules is not covered by a sibling folder
    let n = |p: &str| Finding { ..pkg_hit("node_modules", "/w/node_modules", &[p]) };
    let mut r3 = HuntResult { findings: vec![n("npm:a@1.0.0")], ..Default::default() };
    merge_findings(&mut r3);
    assert_eq!(r3.findings.len(), 1);
}

// Notify opens from the kind of place, never "on your machine" for a repo
#[test]
fn r8_notify_opens_from_the_kind_of_place() {
    let q = Query { iocs: vec![crate::query::iocs::parse_ioc("npm:foo@1.0.0", None).unwrap()], ..Default::default() };
    let mut f = repo_finding("foo", "1.0.0", "package-lock.json");
    f.where_ = "acme/legacy".into();
    f.state = "present".into();
    let sub = HuntResult { q: q.clone(), findings: vec![f], ..Default::default() };
    let person = Target::Person("dokafor".into());
    let t = intro(&q, &sub, "foo", "", &Some("1.0.1".into()), &person, &[]);
    assert!(!t.contains("on your machine"), "{t}");
    assert!(t.starts_with("Hi, this shows up in 1 repo you own"), "{t}");
    // a machine is a machine
    let mut h = host_hit("/Users/dana/.npm/_cacache");
    h.note = "cache only, no project references it".into();
    let sub2 = HuntResult { q: q.clone(), findings: vec![h], ..Default::default() };
    assert!(intro(&q, &sub2, "foo", "", &None, &person, &[]).contains("your npm cache on laptop-a"));
    // an image and a repo
    let img = Finding { kind: FKind::Image, image: "ghcr.io/acme/web".into(), digest: "sha256:aa".into(), ..Default::default() };
    let mut r = repo_finding("foo", "1.0.0", "package-lock.json");
    r.state = "present".into();
    let sub3 = HuntResult { q: q.clone(), findings: vec![r, img], ..Default::default() };
    assert!(intro(&q, &sub3, "foo", "", &None, &person, &[]).starts_with("Hi, this shows up in 1 repo and 1 image you own"));
}

// A runner where a CI run installed the package has one verdict on every screen
#[test]
fn r8_a_runner_where_ci_ran_the_install_has_one_verdict() {
    let mut f = host_hit("/home/runner/.npm/_cacache");
    f.where_ = "ci-runner-3".into();
    f.item_kind = "npm-cache".into();
    f.ci_installs = vec!["acme/web#4112".into()];
    f.note = "the install ran here (CI run acme/web#4112)".into();
    let w = install_ran_words(&f, true).unwrap();
    assert!(w.starts_with("the install ran here (CI run acme/web#4112): isolate the machine") && w.contains("reimage the machine"), "{w}");
    let v = View::default();
    let ix = Index::new(&v, "2026-05-12T12:00:00Z");
    let line = line_for_finding(&ix, &f, true, &None).full();
    assert!(line.contains("the install ran here (CI run acme/web#4112)") && line.contains("reimage the machine"), "{line}");
    assert!(!line.contains("no project uses it") && !line.contains("only in the cache"), "{line}");
    // without an advisory that runs code the line only says a CI run installed it
    let plain = line_for_finding(&ix, &f, false, &None).full();
    assert!(plain.contains("a CI run installed it here: acme/web#4112") && !plain.contains("no project uses it"), "{plain}");
    // fix lists the runner once, in the block that says reimage
    let ran = install_ran_places(&ix, &[&f]);
    assert_eq!(ran["ci-runner-3"], vec!["the install ran here (CI run acme/web#4112)".to_string()]);
}

// An advisory plan for an image says what a hash plan says (the Dockerfile step, the build that ran it)
#[test]
fn r8_an_advisory_image_row_takes_the_file_hits_layer_facts() {
    let digest = "sha256:e908d33b82f4".to_string();
    let pkg = Finding {
        kind: FKind::Image,
        image: "reg.example/batch/etl".into(),
        where_: "reg.example/batch/etl".into(),
        digest: digest.clone(),
        layer: 2,
        layer_cmd: Some("RUN pip install netprobe-py==0.4.2".into()),
        from_repo: Some("acme/etl".into()),
        ..Default::default()
    };
    let file = Finding {
        path: "opt/tools/netprobe".into(),
        layer: 3,
        deleted_in: Some(4),
        executed_in_layer: Some(4),
        layer_cmd: Some("COPY --from=tools /netprobe /opt/tools/netprobe".into()),
        layer_blob: Some(format!("sha256:{}", "ab".repeat(32))),
        ..pkg.clone()
    };
    let mut res = HuntResult { findings: vec![pkg, file], ..Default::default() };
    merge_findings(&mut res);
    let v = View::default();
    let ix = Index::new(&v, "2026-05-12T12:00:00Z");
    let line = line_for_finding(&ix, &res.findings[0], false, &None).full();
    assert!(line.contains("so change that Dockerfile step"), "{line}");
    assert!(line.contains("layer 4 ran it during the build"), "{line}");
    assert!(deleted(&res.findings[0]));
}

// The head of a repo block names the owner every screen names, and says the CODEOWNERS team no longer resolves
#[test]
fn r8_the_fix_head_does_not_name_a_team_github_does_not_resolve() {
    let mut f = repo_finding("foo", "1.0.0", "package-lock.json");
    f.where_ = "acme/legacy-admin".into();
    f.owner = crate::query::hunt::Owner { team: Some("@acme/legacy-team".into()), people: vec!["dokafor".into()], suggested: Some("archived it 05-11".into()), ..Default::default() };
    let mut v = View::default();
    v.repos.insert("acme/legacy-admin".into(), Default::default());
    let ix = Index::new(&v, "2026-05-12T12:00:00Z");
    let head = repo_head(&ix, "acme/legacy-admin", &f);
    assert_eq!(head, "acme/legacy-admin  (owner @dokafor (suggested: archived it 05-11); CODEOWNERS names @acme/legacy-team, which GitHub does not resolve)");
    // a team GitHub does resolve is the owner, with no remark
    v.teams.push(crate::view::Team { id: "@acme/web".into(), ..Default::default() });
    let ix2 = Index::new(&v, "2026-05-12T12:00:00Z");
    f.owner = crate::query::hunt::Owner { team: Some("@acme/web".into()), ..Default::default() };
    assert_eq!(repo_head(&ix2, "acme/legacy-admin", &f), "acme/legacy-admin  (owner @acme/web)");
}
