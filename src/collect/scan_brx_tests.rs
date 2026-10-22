//! What a scan records, what a host carries and the .brx format that moves it.

use std::io::Cursor;

use crate::collect::brx::{self, ScanInfo};
use crate::collect::fs::{Analyzer, FileMeta};
use crate::collect::local::{self, YaraHit};
use crate::ctx::Ctx;
use crate::view::*;

const T: i64 = 1_780_000_000;

fn add(an: &mut Analyzer, path: &str, body: &str) {
    let mut r = Cursor::new(body.as_bytes().to_vec());
    an.add(FileMeta { path: path.into(), size: body.len() as u64, mtime: T }, Some(&mut r));
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("br-r8-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn ctx(home: &std::path::Path) -> Ctx {
    Ctx { now: "2099-01-01T00:00:00Z".into(), home: home.to_path_buf(), user: None, host: Some("laptop-r8".into()), color: false }
}

const LOCK: &str = r#"{"name":"proj","lockfileVersion":3,"packages":{"":{"name":"proj","dependencies":{"@acme/router":"1.2.3"}},"node_modules/@acme/router":{"version":"1.2.3"},"node_modules/leaf":{"version":"0.1.0"}}}"#;

// A host scan reads the lockfiles under its roots like `hunt --path` does, so a checkout on a laptop is packages it declares
#[test]
fn r66_a_lockfile_under_the_roots_is_a_declared_item() {
    let mut an = Analyzer::new(&["**/*.js"], None);
    add(&mut an, "/home/u/proj/package-lock.json", LOCK);
    // another package's own lockfile, inside node_modules, is not the project's
    add(&mut an, "/home/u/proj/node_modules/dep/package-lock.json", LOCK);
    an.note_dir("/home/u/proj/api", ["requirements.txt", "base.txt", "package-lock.json"]);
    add(&mut an, "/home/u/proj/api/requirements.txt", "flask==2.0.0\n-r base.txt\n");
    add(&mut an, "/home/u/proj/api/base.txt", "click==8.1.0\n");
    add(&mut an, "/home/u/proj/web/package-lock.json", "{ not json");
    let items = an.items();
    let lock: Vec<&HostItem> = items.iter().filter(|i| i.kind == "lockfile").collect();
    let locs: Vec<&str> = lock.iter().map(|i| i.loc.as_str()).collect();
    assert!(locs.contains(&"/home/u/proj/package-lock.json"), "{locs:?}");
    assert!(!locs.iter().any(|l| l.contains("node_modules")), "{locs:?}");
    let top = lock.iter().find(|i| i.loc == "/home/u/proj/package-lock.json").unwrap();
    assert_eq!(top.pkgs, vec!["npm:@acme/router@1.2.3", "npm:leaf@0.1.0"]);
    let decl = an.declared();
    let d = decl.iter().find(|d| d.loc == "/home/u/proj/package-lock.json").unwrap();
    let router = d.packages.iter().find(|p| p.p == "npm:@acme/router@1.2.3").unwrap();
    let leaf = d.packages.iter().find(|p| p.p == "npm:leaf@0.1.0").unwrap();
    assert!(router.direct && !leaf.direct, "depth is the lockfile's own");
    // a requirements file's -r include is followed
    let req = lock.iter().find(|i| i.loc == "/home/u/proj/api/requirements.txt").unwrap();
    assert!(req.pkgs.iter().any(|p| p.starts_with("pypi:click@")), "{:?}", req.pkgs);
    // a lockfile that cannot be parsed is a named gap, never an empty list
    let gaps = an.lock_gaps();
    assert!(gaps.iter().any(|(s, r)| s.contains("/home/u/proj/web/package-lock.json") && r.contains("could not be parsed")), "{gaps:?}");
}

// The same parsers as `hunt --path`: a folder gives the same package list either way
#[test]
fn r66_the_host_scan_and_the_checkout_read_a_lockfile_the_same_way() {
    let d = scratch("same");
    std::fs::write(d.join("package-lock.json"), LOCK).unwrap();
    let (repo, commit, _) = crate::collect::checkout::checkout_repo(&d, "2099-01-01T00:00:00Z");
    assert_eq!(repo.lockfiles, vec!["package-lock.json"]);
    let from_checkout: Vec<(String, bool)> = commit.lock_packages["package-lock.json"].iter().map(|p| (p.p.clone(), p.direct)).collect();
    let mut an = Analyzer::new(&["**/*.js"], None);
    add(&mut an, "/x/package-lock.json", LOCK);
    let from_scan: Vec<(String, bool)> = an.declared()[0].packages.iter().map(|p| (p.p.clone(), p.direct)).collect();
    assert_eq!(from_checkout, from_scan);
    let _ = std::fs::remove_dir_all(&d);
}

// The rules read files the filter does not select; only a file that hits is hashed on top of the filter. --hash-all hashes all.
#[test]
fn r66_rules_read_everything_but_only_hits_are_hashed_beyond_the_filter() {
    let d = scratch("yara");
    std::fs::create_dir_all(d.join("t")).unwrap();
    std::fs::write(d.join("t/payload.txt"), "contains evilmarker here").unwrap();
    std::fs::write(d.join("t/notes.txt"), "plain notes").unwrap();
    std::fs::write(d.join("t/run.js"), "console.log(1)").unwrap();
    std::fs::write(d.join("rules.yar"), "rule Evil { strings: $a = \"evilmarker\" condition: $a }\n").unwrap();
    let c = ctx(&d.join("home"));
    let root = d.join("t").to_string_lossy().to_string();
    let rules = d.join("rules.yar").to_string_lossy().to_string();
    let info = local::local_scan_with(&c, std::slice::from_ref(&root), &[], false, Some(&rules), false).unwrap();
    assert_eq!(info.yara.as_ref().map(|y| (y.rules, y.hits, y.files, y.evaluated)), Some((1, 1, 1, 3)));
    assert_eq!(info.yara_hits.len(), 1);
    assert_eq!(info.yara_hits[0].rule, "Evil");
    assert!(info.yara_hits[0].path.ends_with("t/payload.txt"));
    assert_eq!(info.yara_hits[0].sha256.len(), 64);
    // run.js (selected by the filter) and payload.txt (a hit) are hashed; notes.txt is not
    assert_eq!(info.hashed, 2, "{:?}", info.items.iter().flat_map(|i| i.files.iter().map(|f| f.path.clone())).collect::<Vec<_>>());
    assert!(!info.hash_all);
    // the filter off: everything
    let all = local::local_scan_with(&c, std::slice::from_ref(&root), &[], false, None, true).unwrap();
    assert_eq!(all.hashed, 3);
    assert!(all.hash_all);
    // no rules, no hits recorded, and the filter holds
    let plain = local::local_scan_with(&c, &[root], &[], false, None, false).unwrap();
    assert_eq!((plain.hashed, plain.yara.is_none(), plain.yara_hits.len()), (1, true, 0));
    // roots are absolute, whatever was typed
    assert!(plain.roots.iter().all(|r| r.starts_with('/')), "{:?}", plain.roots);
    let _ = std::fs::remove_dir_all(&d);
}

fn scan_info(hits: Vec<YaraHit>, declared: Vec<DeclaredLock>) -> ScanInfo {
    let item = HostItem {
        at: "2026-05-01T00:00:00Z".into(),
        kind: "loose-file".into(),
        loc: "/home/u/t".into(),
        pkgs: vec![],
        files: vec![HostFile { path: "/home/u/t/payload.txt".into(), sha256: "ab".repeat(32), size: Some(3), mtime: None, simhash: None, yara_hits: vec!["Evil".into()] }],
        hidden: false,
    };
    ScanInfo {
        host: "laptop-r8".into(),
        roots: vec!["/home/u".into()],
        home: Some("/home/u".into()),
        items: vec![item],
        stage1: 1,
        hashed: 1,
        simhashed: 0,
        secs: 0,
        os: None,
        kind: None,
        gaps: vec![],
        rules_sha256: Some("cd".repeat(32)),
        yara_hits: hits,
        yara_rules: Some(1),
        declared,
        trust: Default::default(),
    }
}

// The .brx gains a yara table (rule, path, sha256, rules' sha256) and a declared table; the file still verifies
#[test]
fn r66_the_brx_carries_yara_hits_and_declared_packages() {
    let d = scratch("brx");
    let hit = YaraHit { rule: "Evil".into(), path: "/home/u/t/payload.txt".into(), sha256: "ab".repeat(32) };
    let decl = DeclaredLock {
        loc: "/home/u/t/package-lock.json".into(),
        packages: vec![
            LockPackage { p: "npm:x@1.0.0".into(), direct: true, ..Default::default() },
            LockPackage { p: "npm:y@2.0.0".into(), via: vec!["npm:x@1.0.0".into()], lock_line: Some(7), ..Default::default() },
        ],
    };
    let path = d.join("a.brx").to_string_lossy().to_string();
    brx::export(&ctx(&d), &scan_info(vec![hit.clone()], vec![decl.clone()]), &path, None, None).unwrap();
    assert!(brx::check_internal(&path).0, "the digest covers the new tables");
    let l = brx::load(&path).unwrap();
    assert_eq!(l.yara_hits, vec![hit]);
    assert_eq!(l.declared, vec![decl]);
    assert_eq!(l.manifest["yara_rules"], "1");
    assert_eq!(l.manifest["rules_sha256"], "cd".repeat(32));
    // tampering with the table is caught by the internal manifest
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("UPDATE yara_hits SET rule = 'Other'", []).unwrap();
    drop(db);
    assert!(!brx::check_internal(&path).0);
    let _ = std::fs::remove_dir_all(&d);
}

// An export written before the table existed still loads: the hit is read from the files table's yara column
#[test]
fn r66_an_old_brx_without_the_tables_still_loads() {
    let d = scratch("old");
    let path = d.join("old.brx").to_string_lossy().to_string();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE manifest(k TEXT, v TEXT);
         CREATE TABLE files(path TEXT, size INT, mtime TEXT, sha256 TEXT, simhash TEXT, item_kind TEXT, loc TEXT, at TEXT, yara TEXT);
         CREATE TABLE packages(p TEXT, loc TEXT, item_kind TEXT, at TEXT);
         CREATE TABLE custody(event TEXT, at TEXT, by TEXT, case_id TEXT, file_sha256 TEXT, requested_by TEXT);
         INSERT INTO files VALUES('/h/a.js', 3, NULL, 'aa', NULL, 'loose-file', '/h', '2026-05-01T00:00:00Z', '[\"Evil\"]');
         INSERT INTO files VALUES('/h/b.js', 3, NULL, 'bb', NULL, 'loose-file', '/h', '2026-05-01T00:00:00Z', '[]');",
    )
    .unwrap();
    let digest = brx::content_digest(&db).unwrap();
    db.execute("INSERT INTO manifest VALUES('digest', ?)", [digest]).unwrap();
    db.execute("INSERT INTO manifest VALUES('host', 'h')", []).unwrap();
    drop(db);
    assert!(brx::check_internal(&path).0, "an old file's digest is the one it was written with");
    let l = brx::load(&path).unwrap();
    assert_eq!(l.yara_hits, vec![YaraHit { rule: "Evil".into(), path: "/h/a.js".into(), sha256: "aa".into() }]);
    assert!(l.declared.is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

// --hash-all and `teams NAME` parse; --hash-all without --local is a usage error
#[test]
fn r73_cli_takes_hash_all_and_a_team_name() {
    use clap::Parser;
    let c = crate::cli::Cli::try_parse_from(["br", "scan", "--local", "--hash-all"]).unwrap();
    assert!(matches!(c.cmd, Some(crate::cli::Cmd::Scan(ref a)) if a.hash_all));
    let c = crate::cli::Cli::try_parse_from(["br", "scan", "--hash-all"]).unwrap();
    assert!(crate::cli::validate(&c.cmd.unwrap()).is_err());
    let c = crate::cli::Cli::try_parse_from(["br", "teams", "web"]).unwrap();
    assert!(matches!(c.cmd, Some(crate::cli::Cmd::Teams(ref a)) if a.team.as_deref() == Some("web") && a.sub.is_none()));
    assert!(crate::cli::Cli::try_parse_from(["br", "teams", "set", "@a/b", "--slack", "#x"]).is_ok());
}

// A checkout with a lockfile and no file the filter selects has been read; only a scan that found nothing at all is empty
#[test]
fn r66_a_scan_that_read_a_lockfile_is_not_an_empty_scan() {
    let mut an = Analyzer::new(&["**/*.js"], None);
    add(&mut an, "/home/u/proj/package-lock.json", LOCK);
    assert_eq!(an.hashed(), 0);
    assert!(!crate::collect::fs::read_nothing(an.hashed(), &an.items()));
    let none = Analyzer::new(&["**/*.js"], None);
    assert!(crate::collect::fs::read_nothing(none.hashed(), &none.items()));
}

// A lockfile found and not read is a gap with ONE reason text, whichever reader found it (checkout, host scan)
#[test]
fn r10_every_reader_names_an_unread_lockfile_with_the_same_reason() {
    let d = scratch("nopkgs");
    std::fs::write(d.join("package-lock.json"), r#"{"name":"a","lockfileVersion":3,"packages":{"":{"name":"a"}}}"#).unwrap();
    std::fs::write(d.join("bun.lockb"), "bin").unwrap();
    std::fs::create_dir_all(d.join("web")).unwrap();
    std::fs::write(d.join("web/package-lock.json"), "{ not json").unwrap();
    let (_, _, cg) = crate::collect::checkout::checkout_repo(&d, "2099-01-01T00:00:00Z");
    let from_checkout: std::collections::BTreeSet<(String, String)> = cg.into_iter().map(|g| (g.scope.rsplit('/').next().unwrap().to_string() + &g.scope.len().to_string(), g.reason)).collect();
    let mut an = Analyzer::new(&["**/*.js"], None);
    add(&mut an, "/x/package-lock.json", r#"{"name":"a","lockfileVersion":3,"packages":{"":{"name":"a"}}}"#);
    add(&mut an, "/x/bun.lockb", "bin");
    add(&mut an, "/x/web/package-lock.json", "{ not json");
    let from_scan = an.lock_gaps();
    assert_eq!(from_scan.len(), 3, "{from_scan:?}");
    // the reasons (not the paths) are the same set
    let reasons = |v: Vec<String>| v.into_iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(reasons(from_checkout.into_iter().map(|x| x.1).collect()), reasons(from_scan.iter().map(|g| g.1.clone()).collect()));
    assert!(from_scan.iter().all(|g| g.1.starts_with(crate::parse::lock::NO_PACKAGES)), "{from_scan:?}");
    let _ = std::fs::remove_dir_all(&d);
}
