//! A checkout as a throwaway index: `br hunt IOC --path DIR` reads the lockfiles and manifests under DIR, and the
//! installed packages and files there, the way `br init --path DIR` indexes a machine. It writes to a temporary directory
//! that is removed afterwards, never touches BR_HOME, and makes no network call.

use std::path::{Path, PathBuf};

use crate::collect::local;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::parse::lock;
use crate::store::{Row, Store};
use crate::view::*;

/// Directories that hold other people's code or build output, never the project's own lockfiles.
const SKIP_DIRS: &[&str] = &["node_modules", ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "site-packages", "target", ".tox"];

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every lockfile under `root` (relative paths with `/`), in a stable order.
pub fn find_lockfiles(root: &Path) -> Vec<String> {
    let mut out = walk(root, lock::is_lockfile);
    out.sort();
    shadow_filter(out)
}

/// Lockfiles under `root` that br finds by name and cannot read (a gap each).
pub fn find_unsupported(root: &Path) -> Vec<String> {
    let mut out = walk(root, lock::is_unsupported_lock);
    out.sort();
    out
}

fn walk(root: &Path, want: fn(&str) -> bool) -> Vec<String> {
    let mut out = vec![];
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if ft.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push(p);
                }
            } else if ft.is_file() {
                let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                if want(&rel) {
                    out.push(rel);
                }
            }
        }
    }
    out
}

fn want_cert(rel: &str) -> bool {
    crate::parse::x509::store_path(rel, true).is_some()
}

/// The certificate files under a checkout (any `.pem`, `.crt`, `.cer` and the bundle names), read up to the same caps as elsewhere.
fn checkout_trust(root: &Path, mut set: TrustSet) -> TrustSet {
    let mut rels = walk(root, want_cert);
    rels.sort();
    for rel in rels {
        let shown = root.join(&rel).to_string_lossy().to_string();
        if set.files.iter().any(|f| f.path == shown) {
            continue;
        }
        if set.files.len() >= crate::parse::x509::MAX_FILES {
            let n = format!("more than {} certificate files: the rest were not read", crate::parse::x509::MAX_FILES);
            if !set.notes.contains(&n) {
                set.notes.push(n);
            }
            break;
        }
        let known = crate::parse::x509::store_path(&rel, true).unwrap_or(false);
        let size = std::fs::metadata(root.join(&rel)).map(|m| m.len()).unwrap_or(0);
        if size > crate::parse::x509::MAX_BYTES {
            set.files.push(TrustFile {
                path: shown,
                certs: vec![],
                gaps: vec![format!("{size} bytes is over the {} MiB br reads of a trust store file", crate::parse::x509::MAX_BYTES / (1024 * 1024))],
            });
            continue;
        }
        match std::fs::read(root.join(&rel)) {
            Ok(b) => {
                let r = crate::parse::x509::read_store(&b, known);
                if r.store {
                    set.files.push(TrustFile { path: shown, certs: r.certs, gaps: r.gaps });
                }
            }
            Err(e) => set.files.push(TrustFile { path: shown, certs: vec![], gaps: vec![format!("the file could not be read ({e})")] }),
        }
    }
    set.files.sort_by(|a, b| a.path.cmp(&b.path));
    set
}

fn shadow_filter(out: Vec<String>) -> Vec<String> {
    // At one directory the lockfiles that duplicate each other are read once, in the order the parsers list them
    // (`go.mod` states which modules are direct, `go.sum` only a hash record; a shrinkwrap replaces package-lock.json)
    let shadowed = |p: &str| -> bool {
        let (dir, base) = match p.rfind('/') {
            Some(i) => (&p[..=i], &p[i + 1..]),
            None => ("", p),
        };
        let has = |n: &str| out.iter().any(|o| *o == format!("{dir}{n}"));
        (base == "go.sum" && has("go.mod")) || (base == "package-lock.json" && has("npm-shrinkwrap.json"))
    };
    let keep: Vec<String> = out.iter().filter(|p| !shadowed(p)).cloned().collect();
    keep
}

/// The direct dependencies (name -> is dev) from the manifest that goes with a lockfile, when it is on disk and parses.
fn manifest_beside(root: &Path, lockfile: &str) -> Option<std::collections::BTreeMap<String, bool>> {
    let base = lockfile.rsplit('/').next().unwrap_or(lockfile);
    let rel = if lock::is_requirements(base) {
        lockfile.to_string()
    } else {
        let m = lock::manifest_for(lockfile)?;
        match lockfile.rfind('/') {
            Some(i) => format!("{}/{m}", &lockfile[..i]),
            None => m.to_string(),
        }
    };
    let text = std::fs::read_to_string(root.join(&rel)).ok()?;
    let man = crate::parse::manifest::try_parse(&rel, &text).ok()?;
    Some(man.deps.iter().map(|(k, d)| (k.clone(), d.section.as_deref().map(|s| s.to_lowercase().contains("dev")).unwrap_or(false))).collect())
}

/// The repo a checkout looks like to the query: one commit holding the packages of every lockfile under `root`.
pub fn checkout_repo(root: &Path, now: &str) -> (Repo, Commit, Vec<Gap>) {
    let mut gaps = vec![];
    let gap = |lp: &str, why: lock::NoPackages| {
        let (scope, reason) = lock::no_packages_gap(lp, &why);
        Gap { scope, reason, at: now.to_string() }
    };
    for lp in find_unsupported(root) {
        gaps.push(gap(&lp, lock::NoPackages::Unsupported));
    }
    let files = find_lockfiles(root);
    let mut union: Vec<LockPackage> = vec![];
    let mut seen = std::collections::BTreeSet::new();
    let mut by_lock: std::collections::BTreeMap<String, Vec<LockPackage>> = Default::default();
    for lp in &files {
        let text = match std::fs::read_to_string(root.join(lp)) {
            Ok(t) => t,
            Err(e) => {
                gaps.push(gap(lp, lock::NoPackages::Unreadable(&e.to_string())));
                continue;
            }
        };
        let base = root.to_path_buf();
        let parsed = lock::parse_with(lp, &text, &mut |p: &str| {
            // a requirements file's -r includes are relative to the file
            let rel = Path::new(lp).parent().map(|d| d.join(p)).unwrap_or_else(|| PathBuf::from(p));
            std::fs::read_to_string(base.join(rel)).ok().or_else(|| std::fs::read_to_string(base.join(p)).ok())
        });
        match parsed {
            Some(l) => {
                // The manifest beside the lockfile says which packages are direct, as it does for an indexed repo; without it
                // every package nothing else depends on would be called direct and a transitive one would read as direct
                let md = manifest_beside(root, lp);
                let pk = lock::packages(&l, md.as_ref());
                if pk.is_empty() {
                    gaps.push(gap(lp, lock::NoPackages::Empty));
                }
                for p in &pk {
                    if seen.insert(p.p.clone()) {
                        union.push(p.clone());
                    }
                }
                by_lock.insert(lp.clone(), pk);
            }
            None => gaps.push(gap(lp, lock::NoPackages::Unparsed)),
        }
    }
    let repo = Repo { default_branch: Some("checkout".into()), lockfile: files.first().cloned(), lockfiles: files, ..Default::default() };
    let commit = Commit {
        sha: "checkout".into(),
        at: now.to_string(),
        message: Some("the working tree as it is on disk".into()),
        packages: if by_lock.is_empty() { None } else { Some(union) },
        lock_packages: by_lock,
        ..Default::default()
    };
    (repo, commit, gaps)
}

/// The View of the checkout at `dir`: a repo source (its lockfiles) and a host source (what is installed and hashed there).
/// Advisories come from the caller's real index and notes.
pub fn checkout_view(ctx: &Ctx, dir: &str) -> BrResult<View> {
    let root = std::fs::canonicalize(dir).ok().filter(|p| p.is_dir()).ok_or_else(|| BrError::new(format!("{dir} is not a directory"), Some("pass the checkout's directory, e.g. --path .")))?;
    let base = root.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "root".into());
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = TempDir(std::env::temp_dir().join(format!("br-checkout-{}-{nanos}", std::process::id())));
    std::fs::create_dir_all(&tmp.0).map_err(|e| BrError::with_code(format!("cannot make a scratch directory: {e}"), None, 1))?;
    let mut cx = ctx.clone();
    cx.home = tmp.0.clone();
    let repo_name = format!("checkout/{base}");
    let host_name = format!("checkout-files/{base}");
    cx.host = Some(host_name.clone());
    let mut st = Store::open(&cx, true)?;

    let (repo, commit, gaps) = checkout_repo(&root, &ctx.now);
    // a lockfile found and not read still makes the checkout a repo source: it is NOT CHECKED, never absent
    let have_locks = !repo.lockfiles.is_empty() || !gaps.is_empty();
    if have_locks {
        let read_none = commit.packages.as_ref().is_none_or(|p| p.is_empty());
        let src = Source { kind: "repo".into(), reach: "checkout".into(), indexed_at: ctx.now.clone(), empty: read_none, gaps: vec![] };
        st.set_source(&repo_name, &src, &ctx.now)?;
        st.replace(&repo_name, &["repo", "commit"], vec![Row::new("repo", repo_name.clone(), &repo), Row::new("commit", commit.sha.clone(), &commit)], &ctx.now)?;
        st.set_gaps(&repo_name, &gaps)?;
    }
    let info = local::local_scan(&cx, &[root.to_string_lossy().to_string()], &[], false)?;
    if info.hashed > 0 || !have_locks {
        let src = Source { kind: "host".into(), reach: "local".into(), indexed_at: ctx.now.clone(), empty: info.hashed == 0, gaps: vec![] };
        st.set_source(&host_name, &src, &ctx.now)?;
        let host = Host { kind: Some("host".into()), os: Some(std::env::consts::OS.to_string()), ..Default::default() };
        let mut rows = vec![Row::new("host", host_name.clone(), &host)];
        rows.extend(crate::collect::cmds::trust_rows(&checkout_trust(&root, info.trust.clone())));
        // the lockfiles are already the repo source above; a second `lockfile` item would count every package twice
        for it in info.items.iter().filter(|it| it.kind != "lockfile") {
            rows.push(Row::new("item", format!("{}|{}|{}", it.at, it.kind, it.loc), it));
        }
        st.replace(&host_name, &["host", "item", "trust"], rows, &ctx.now)?;
        let g: Vec<Gap> = info.gaps.iter().map(|(s, r)| Gap { scope: s.clone(), reason: r.clone(), at: ctx.now.clone() }).collect();
        st.set_gaps(&host_name, &g)?;
    }
    if !have_locks && info.hashed == 0 {
        let future = info.future.as_ref().map(|w| format!(" ({w})")).unwrap_or_default();
        return Err(BrError::with_code(
            format!("nothing to read under {dir}: no lockfile, no installed package and no file the hash filter selects{future}"),
            Some("run it from the project's root, or pass --path to the directory that holds package-lock.json, Cargo.lock, go.sum, poetry.lock or similar"),
            5,
        ));
    }
    let mut v = cx.view()?;
    // the advisories are the real ones: the caller's index (OSV records) and notes
    v.advisories = match Store::open(ctx, false) {
        Ok(real) => crate::collect::config::advisories(ctx, &real),
        Err(_) => crate::collect::config::advisories_from(ctx, vec![]),
    };
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_checkout_is_one_commit_of_every_lockfile_and_skips_vendored_trees() {
        let d = std::env::temp_dir().join(format!("br-co-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("app")).unwrap();
        std::fs::create_dir_all(d.join("node_modules/x")).unwrap();
        std::fs::write(
            d.join("app/package-lock.json"),
            r#"{"name":"a","lockfileVersion":3,"packages":{"":{"name":"a","dependencies":{"left-pad":"1.0.0"}},"node_modules/left-pad":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        std::fs::write(d.join("node_modules/x/package-lock.json"), "{}").unwrap();
        let (repo, commit, gaps) = checkout_repo(&d, "2026-05-12T07:10:00Z");
        assert_eq!(repo.lockfiles, vec!["app/package-lock.json".to_string()]);
        assert!(gaps.is_empty(), "{gaps:?}");
        let pk = commit.packages.unwrap();
        assert!(pk.iter().any(|p| p.p == "npm:left-pad@1.0.0"), "{pk:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    // The manifest beside a lockfile says what is direct, and go.mod is read instead of go.sum
    #[test]
    fn depth_comes_from_the_manifest_and_go_mod_replaces_go_sum() {
        let d = std::env::temp_dir().join(format!("br-co-depth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("y")).unwrap();
        std::fs::create_dir_all(d.join("g")).unwrap();
        std::fs::write(d.join("y/package.json"), r#"{"name":"a","dependencies":{"top-lib":"1.0.0"}}"#).unwrap();
        std::fs::write(
            d.join("y/yarn.lock"),
            "# yarn lockfile v1\n\n\npeer-lib@^2.0.0:\n  version \"2.1.0\"\n  resolved \"https://r/peer-lib-2.1.0.tgz#a\"\n\ntop-lib@1.0.0:\n  version \"1.0.0\"\n  resolved \"https://r/top-lib-1.0.0.tgz#b\"\n",
        )
        .unwrap();
        std::fs::write(d.join("g/go.mod"), "module example.com/app\n\ngo 1.21\n\nrequire (\n\texample.com/top v1.0.0\n\texample.com/evil v1.2.3 // indirect\n)\n").unwrap();
        std::fs::write(d.join("g/go.sum"), "example.com/top v1.0.0 h1:a=\nexample.com/evil v1.2.3 h1:c=\n").unwrap();
        assert_eq!(find_lockfiles(&d), vec!["g/go.mod".to_string(), "y/yarn.lock".to_string()]);
        let (_, commit, _) = checkout_repo(&d, "2026-05-12T07:10:00Z");
        let pk = commit.packages.unwrap();
        let depth = |p: &str| pk.iter().find(|x| x.p == p).map(|x| x.direct);
        assert_eq!(depth("npm:top-lib@1.0.0"), Some(true));
        assert_eq!(depth("npm:peer-lib@2.1.0"), Some(false), "only the manifest can say peer-lib is not direct: {pk:?}");
        assert_eq!(depth("go:example.com/top@v1.0.0"), Some(true));
        assert_eq!(depth("go:example.com/evil@v1.2.3"), Some(false));
        let _ = std::fs::remove_dir_all(&d);
    }
}
