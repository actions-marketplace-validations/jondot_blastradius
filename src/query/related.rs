//! What came with a hash. A hash hit inside a package's install tree leads to the other files of that tree that have a
//! simhash (the postinstall script shipped beside the binary), and an image layer that runs a path a finding holds is
//! reported as executed during the build. The rules come from the layouts of the package managers, one row per layout.

use super::hunt::{FKind, Finding};
use super::index::Index;
use crate::view::{HostFile, HostItem, ImageBuild};

/// One file that shares an install tree with a hash hit.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Related {
    /// the indicator that hit (`sha256:...`)
    pub ioc: String,
    pub host: String,
    /// the file the hash hit, as the finding shows it
    pub hit_path: String,
    /// the install tree both files sit in (`/home/dev/app/node_modules/pkg`)
    pub tree: String,
    /// this file's path, in full
    pub path: String,
    /// this file's name inside the tree (`postinstall.js`)
    pub file: String,
    pub sha256: String,
    pub simhash: String,
    /// The affected package whose own install holds this file (the pivot from a package, not from a hit beside it)
    pub package: String,
}

impl Related {
    /// `postinstall.js (sha256:c81a0b3f9d12…; br hunt --similar sha256:c81a0b3f9d12…)`
    pub fn words(&self) -> String {
        let short: String = self.sha256.trim_start_matches("sha256:").chars().take(12).collect();
        format!("{} (sha256:{short}…; br hunt --similar sha256:{short}…)", self.file)
    }
}

/// The install tree a file sits in, by the layout of its package manager. `item` is the host item the file was grouped into;
/// kinds whose item already is one install (a go module, a crate, a tool-cache version) use the item's own place.
pub fn install_tree(item: &HostItem, path: &str) -> Option<String> {
    let comps: Vec<&str> = path.split('/').collect();
    match item.kind.as_str() {
        "node_modules" => {
            // the package directory after the last node_modules; a scope takes two components
            let i = comps.iter().rposition(|c| *c == "node_modules")?;
            let first = comps.get(i + 1)?;
            let n = if first.starts_with('@') { 2 } else { 1 };
            if comps.len() <= i + 1 + n {
                return None;
            }
            Some(comps[..i + 1 + n].join("/"))
        }
        "site-packages" => {
            let i = comps.iter().rposition(|c| *c == "site-packages" || *c == "dist-packages")?;
            let top = comps.get(i + 1)?;
            // a module directory is a tree; a lone module file at the top is not
            if comps.len() <= i + 2 {
                return None;
            }
            let _ = top;
            Some(comps[..i + 2].join("/"))
        }
        "go-mod-cache" | "cargo-registry" | "tool-cache" | "action-checkout" => Some(item.loc.clone()),
        _ => None,
    }
}

fn full_path(it: &HostItem, f: &HostFile) -> String {
    if f.path.starts_with('/') {
        f.path.clone()
    } else {
        format!("{}/{}", it.loc.trim_end_matches('/'), f.path)
    }
}

/// The other files of the tree that holds a hash hit (a host finding on a sha256 indicator): those with a simhash, which are
/// the text files (scripts, manifests) a reader can compare. The hit itself and files with the same hash are left out.
pub fn related_for(ix: &Index, f: &Finding) -> Vec<Related> {
    let hashes: Vec<String> = f.iocs_or_one().into_iter().filter(|i| i.starts_with("sha256:")).collect();
    if f.kind != FKind::Host || hashes.is_empty() || f.match_ == "similar" {
        return vec![];
    }
    let mut out: Vec<Related> = vec![];
    for it in ix.host_items(&f.where_) {
        // the item that holds the hit
        let Some((hit, ioc)) =
            it.files.iter().filter(|h| !h.sha256.is_empty() && full_path(it, h) == f.loc).find_map(|h| hashes.iter().find(|i| i.ends_with(h.sha256.as_str())).map(|i| (h, i.clone())))
        else {
            continue;
        };
        let Some(tree) = install_tree(it, &f.loc) else { continue };
        for o in &it.files {
            let p = full_path(it, o);
            if o.sha256 == hit.sha256 || p == f.loc || !crate::query::index::under(&p, &tree) {
                continue;
            }
            let Some(sh) = o.simhash.as_ref().filter(|s| !s.is_empty()) else { continue };
            let file = p.strip_prefix(&format!("{}/", tree.trim_end_matches('/'))).unwrap_or(&p).to_string();
            let r =
                Related { ioc: ioc.clone(), host: f.where_.clone(), hit_path: f.loc.clone(), tree: tree.clone(), path: p, file, sha256: o.sha256.clone(), simhash: sh.clone(), package: String::new() };
            if !out.iter().any(|x| x.path == r.path) {
                out.push(r);
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Interpreters whose first non-flag argument is the file they run.
const INTERPRETERS: [&str; 10] = ["sh", "bash", "dash", "zsh", "node", "python", "python3", "perl", "ruby", "php"];
/// Words that wrap a command without being it.
const WRAPPERS: [&str; 6] = ["sudo", "exec", "nohup", "time", "env", "command"];

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// Does this `created_by` run `path`? Only a RUN counts (COPY and ADD name a path without running it, and ENTRYPOINT or CMD
/// run at container start, not during the build). The path must be the command, or the script an interpreter is given.
pub fn runs_path(created_by: &str, path: &str) -> bool {
    let cb = created_by.trim();
    let body = if let Some(b) = cb.strip_prefix("RUN ") {
        b
    } else if cb.contains("#(nop)") {
        return false;
    } else if let Some(i) = cb.find("/bin/sh -c ") {
        &cb[i + "/bin/sh -c ".len()..]
    } else {
        return false;
    };
    let body = body.trim_end_matches("# buildkit").trim();
    let want = format!("/{}", path.trim_start_matches('/'));
    let mut cwd = String::new();
    for seg in body.split([';', '\n']).flat_map(|s| s.split("&&")).flat_map(|s| s.split("||")).flat_map(|s| s.split('|')) {
        let words: Vec<&str> = seg.split_whitespace().map(|w| w.trim_matches(|c| c == '"' || c == '\'' || c == '(' || c == ')')).collect();
        let mut i = 0;
        while i < words.len() && (is_assignment(words[i]) || WRAPPERS.contains(&words[i])) {
            i += 1;
        }
        let Some(&cmd) = words.get(i) else { continue };
        if cmd == "cd" {
            cwd = words.get(i + 1).map(|d| d.trim_end_matches('/').to_string()).unwrap_or_default();
            continue;
        }
        let resolve = |w: &str| -> String {
            if w.starts_with('/') {
                w.to_string()
            } else if let Some(rel) = w.strip_prefix("./") {
                format!("{}/{}", cwd, rel)
            } else {
                String::new()
            }
        };
        if resolve(cmd) == want {
            return true;
        }
        let base = cmd.rsplit('/').next().unwrap_or(cmd);
        if INTERPRETERS.contains(&base) {
            if let Some(arg) = words[i + 1..].iter().find(|w| !w.starts_with('-')) {
                if resolve(arg) == want {
                    return true;
                }
            }
        }
    }
    false
}

/// The first layer of the build, from the layer the file arrived in on, whose RUN executes `path`.
pub fn executed_in_layer(b: &ImageBuild, from_layer: u32, path: &str) -> Option<u32> {
    if path.is_empty() {
        return None;
    }
    b.layers.iter().filter(|l| l.n >= from_layer).find(|l| l.created_by.as_deref().is_some_and(|c| runs_path(c, path))).map(|l| l.n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{Host, Layer, Source, View};

    fn f(path: &str, sha: &str, sim: Option<&str>) -> HostFile {
        HostFile { path: path.into(), sha256: sha.into(), simhash: sim.map(str::to_string), ..Default::default() }
    }

    // The layouts of the package managers decide the tree, not the names in a world
    #[test]
    fn the_install_tree_follows_the_package_manager_layout() {
        let nm = HostItem { kind: "node_modules".into(), loc: "/home/dev/app/node_modules".into(), ..Default::default() };
        assert_eq!(install_tree(&nm, "/home/dev/app/node_modules/evil-pkg/bin/probe").as_deref(), Some("/home/dev/app/node_modules/evil-pkg"));
        assert_eq!(install_tree(&nm, "/home/dev/app/node_modules/@scope/pkg/lib/a.js").as_deref(), Some("/home/dev/app/node_modules/@scope/pkg"));
        assert_eq!(install_tree(&nm, "/a/node_modules/x/node_modules/y/i.js").as_deref(), Some("/a/node_modules/x/node_modules/y"));
        let sp = HostItem { kind: "site-packages".into(), loc: "/v/lib/python3.12/site-packages".into(), ..Default::default() };
        assert_eq!(install_tree(&sp, "/v/lib/python3.12/site-packages/dist/mod/x.so").as_deref(), Some("/v/lib/python3.12/site-packages/dist"));
        let go = HostItem { kind: "go-mod-cache".into(), loc: "/g/pkg/mod/example.org/m@v1.0.0".into(), ..Default::default() };
        assert_eq!(install_tree(&go, "/g/pkg/mod/example.org/m@v1.0.0/a.go").as_deref(), Some("/g/pkg/mod/example.org/m@v1.0.0"));
        let loose = HostItem { kind: "loose-file".into(), loc: "/tmp".into(), ..Default::default() };
        assert_eq!(install_tree(&loose, "/tmp/x"), None);
    }

    #[test]
    fn a_hash_hit_lists_the_scripts_beside_it() {
        let mut v = View::default();
        v.sources.insert("dev-mbp".into(), Source { kind: "host".into(), reach: "import-only".into(), indexed_at: "2026-05-12T00:00:00Z".into(), ..Default::default() });
        let base = "/home/dev/app/node_modules/evil-pkg";
        v.hosts.insert(
            "dev-mbp".into(),
            Host {
                items: vec![HostItem {
                    at: "2026-05-11T00:00:00Z".into(),
                    kind: "node_modules".into(),
                    loc: "/home/dev/app/node_modules".into(),
                    files: vec![
                        f(&format!("{base}/bin/probe"), &"a".repeat(64), None),
                        f(&format!("{base}/postinstall.js"), &"b".repeat(64), Some("0123456789abcdef")),
                        f(&format!("{base}/lib/x.js"), &"c".repeat(64), Some("fedcba9876543210")),
                        f("/home/dev/app/node_modules/other/index.js", &"d".repeat(64), Some("1111111111111111")),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let ix = Index::new(&v, "2026-05-12T00:00:00Z");
        let hit = Finding { kind: FKind::Host, where_: "dev-mbp".into(), ioc: format!("sha256:{}", "a".repeat(64)), loc: format!("{base}/bin/probe"), ..Default::default() };
        let r = related_for(&ix, &hit);
        assert_eq!(r.iter().map(|x| x.file.as_str()).collect::<Vec<_>>(), vec!["lib/x.js", "postinstall.js"]);
        assert!(r[1].words().starts_with("postinstall.js (sha256:bbbbbbbbbbbb…; br hunt --similar sha256:bbbbbbbbbbbb…)"), "{}", r[1].words());
    }

    // Only a RUN that executes the path counts; a COPY of it, a mention as an argument, and a start command do not
    #[test]
    fn only_a_run_that_executes_the_path_is_build_time_execution() {
        let p = "opt/tools/netprobe";
        assert!(runs_path("RUN /opt/tools/netprobe --init", p));
        assert!(runs_path("/bin/sh -c /opt/tools/netprobe --init", p));
        assert!(runs_path("RUN chmod +x /opt/tools/netprobe && /opt/tools/netprobe", p));
        assert!(runs_path("RUN cd /opt/tools && ./netprobe --x", p));
        assert!(runs_path("RUN FOO=1 sudo /opt/tools/netprobe", p));
        assert!(runs_path("RUN sh /opt/tools/netprobe", p));
        assert!(!runs_path("COPY netprobe /opt/tools/netprobe # buildkit", p));
        assert!(!runs_path("/bin/sh -c #(nop) COPY file:abc in /opt/tools/netprobe", p));
        assert!(!runs_path("RUN chmod +x /opt/tools/netprobe", p));
        assert!(!runs_path("ENTRYPOINT [\"/opt/tools/netprobe\"]", p));
        assert!(!runs_path("RUN /opt/tools/netprobe-other", p));
    }

    #[test]
    fn the_layer_is_found_from_the_layer_the_file_arrived_in() {
        let l = |n, c: &str| Layer { n, created_by: Some(c.into()), ..Default::default() };
        let b = ImageBuild { layers: vec![l(1, "RUN /opt/tools/netprobe"), l(2, "COPY netprobe /opt/tools/netprobe"), l(3, "RUN /opt/tools/netprobe --init")], ..Default::default() };
        assert_eq!(executed_in_layer(&b, 2, "/opt/tools/netprobe"), Some(3));
        assert_eq!(executed_in_layer(&b, 4, "/opt/tools/netprobe"), None);
    }
}
