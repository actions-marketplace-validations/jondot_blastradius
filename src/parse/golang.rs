//! Go: the build list comes from `go.mod` (Go 1.17+ lists every module the build needs, `// indirect` for the transitive ones)
//! with its `replace` directives applied, or from `vendor/modules.txt` when the repo vendors. `go.sum` is a record of hashes
//! for every version MVS ever looked at, not the build list, so it is only a fallback. `go.work` adds workspace members and
//! workspace-wide replaces.
use std::collections::{BTreeMap, BTreeSet};

use super::lock::{Entry, Lock};

#[derive(Debug, Clone, PartialEq)]
pub struct Require {
    pub path: String,
    pub version: String,
    pub indirect: bool,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Replace {
    pub old: String,
    /// None replaces every version of `old`.
    pub old_version: Option<String>,
    pub new: String,
    pub new_version: Option<String>,
    pub line: u32,
}

impl Replace {
    /// A replacement by a directory on disk, not a module.
    pub fn is_local(&self) -> bool {
        let p = self.new.as_str();
        p.starts_with("./") || p.starts_with("../") || p.starts_with('/') || p.starts_with(".\\") || p.starts_with("..\\") || p.as_bytes().get(1) == Some(&b':') || p == "." || p == ".."
    }
}

#[derive(Debug, Clone, Default)]
pub struct GoMod {
    pub module: String,
    pub go: Option<String>,
    pub requires: Vec<Require>,
    pub replaces: Vec<Replace>,
}

fn unq(s: &str) -> String {
    s.trim().trim_matches(|c| c == '"' || c == '`').to_string()
}

/// Statements of a go.mod/go.work style file: (directive, words, line, comment).
fn statements(text: &str) -> Vec<(String, Vec<String>, u32, String)> {
    let mut out = vec![];
    let mut block: Option<String> = None;
    for (i, raw) in text.lines().enumerate() {
        let (code, comment) = match raw.find("//") {
            Some(ix) => (&raw[..ix], raw[ix + 2..].trim().to_string()),
            None => (raw, String::new()),
        };
        let code = code.trim();
        if code.is_empty() {
            continue;
        }
        let line = i as u32 + 1;
        if let Some(b) = &block {
            if code == ")" {
                block = None;
            } else {
                out.push((b.clone(), code.split_whitespace().map(unq).collect(), line, comment));
            }
            continue;
        }
        let mut w = code.split_whitespace();
        let dir = w.next().unwrap_or("").to_string();
        let rest: Vec<String> = w.map(unq).collect();
        if rest.first().map(String::as_str) == Some("(") {
            block = Some(dir);
        } else {
            out.push((dir, rest, line, comment));
        }
    }
    out
}

fn replace_of(words: &[String], line: u32) -> Option<Replace> {
    let arrow = words.iter().position(|w| w == "=>")?;
    let (l, r) = (&words[..arrow], &words[arrow + 1..]);
    Some(Replace { old: l.first()?.clone(), old_version: l.get(1).cloned(), new: r.first()?.clone(), new_version: r.get(1).cloned(), line })
}

pub fn parse_go_mod(text: &str) -> GoMod {
    let mut m = GoMod::default();
    for (dir, w, line, comment) in statements(text) {
        match dir.as_str() {
            "module" => m.module = w.first().cloned().unwrap_or_default(),
            "go" => m.go = w.first().cloned(),
            "require" => {
                if let (Some(p), Some(v)) = (w.first(), w.get(1)) {
                    m.requires.push(Require { path: p.clone(), version: v.clone(), indirect: comment.split_whitespace().next() == Some("indirect"), line });
                }
            }
            "replace" => m.replaces.extend(replace_of(&w, line)),
            _ => {}
        }
    }
    m
}

#[derive(Debug, Clone, Default)]
pub struct GoWork {
    pub go: Option<String>,
    /// `use` directories, as written.
    pub uses: Vec<String>,
    pub replaces: Vec<Replace>,
}

pub fn parse_go_work(text: &str) -> GoWork {
    let mut g = GoWork::default();
    for (dir, w, line, _) in statements(text) {
        match dir.as_str() {
            "go" => g.go = w.first().cloned(),
            "use" => g.uses.extend(w.first().cloned()),
            "replace" => g.replaces.extend(replace_of(&w, line)),
            _ => {}
        }
    }
    g
}

/// Compare Go module versions (semver with pseudo-versions; `+incompatible` and other build metadata are ignored).
pub fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn split(v: &str) -> (Vec<u64>, Option<String>) {
        let v = v.trim_start_matches('v');
        let v = v.split('+').next().unwrap_or(v);
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p.to_string())),
            None => (v, None),
        };
        (core.split('.').map(|x| x.parse().unwrap_or(0)).collect(), pre)
    }
    let ((ca, pa), (cb, pb)) = (split(a), split(b));
    let n = ca.len().max(cb.len());
    for i in 0..n {
        let o = ca.get(i).copied().unwrap_or(0).cmp(&cb.get(i).copied().unwrap_or(0));
        if o != std::cmp::Ordering::Equal {
            return o;
        }
    }
    match (pa, pb) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(x), Some(y)) => {
            // dot-separated identifiers: numeric ones numerically and below alphanumeric ones
            let (xs, ys): (Vec<&str>, Vec<&str>) = (x.split('.').collect(), y.split('.').collect());
            for i in 0..xs.len().max(ys.len()) {
                match (xs.get(i), ys.get(i)) {
                    (None, Some(_)) => return std::cmp::Ordering::Less,
                    (Some(_), None) => return std::cmp::Ordering::Greater,
                    (Some(p), Some(q)) => {
                        let o = match (p.parse::<u64>(), q.parse::<u64>()) {
                            (Ok(a), Ok(b)) => a.cmp(&b),
                            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                            _ => p.cmp(q),
                        };
                        if o != std::cmp::Ordering::Equal {
                            return o;
                        }
                    }
                    (None, None) => {}
                }
            }
            std::cmp::Ordering::Equal
        }
    }
}

fn go_minor(v: &str) -> Option<(u32, u32)> {
    let mut p = v.split('.');
    Some((p.next()?.parse().ok()?, p.next()?.parse().ok()?))
}

/// What `path version` becomes after `replace`: Some((path, version)) for a module, None when it is replaced by a local directory.
fn apply_replace(path: &str, ver: &str, replaces: &[Replace]) -> Option<(String, String)> {
    let r = replaces.iter().rev().find(|r| r.old == path && r.old_version.as_deref() == Some(ver)).or_else(|| replaces.iter().rev().find(|r| r.old == path && r.old_version.is_none()));
    match r {
        None => Some((path.to_string(), ver.to_string())),
        Some(r) if r.is_local() => None,
        Some(r) => Some((r.new.clone(), r.new_version.clone().unwrap_or_else(|| ver.to_string()))),
    }
}

/// The build list of a go.mod, `replace` applied. `extra` are workspace-level replaces (they win over the module's own).
pub fn build_from_go_mod(m: &GoMod, extra: &[Replace]) -> Lock {
    let mut reps: Vec<Replace> = m.replaces.clone();
    reps.extend(extra.iter().cloned());
    let mut lock = Lock::default();
    let mut direct = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for r in &m.requires {
        match apply_replace(&r.path, &r.version, &reps) {
            Some((p, v)) => {
                let id = format!("go:{p}@{v}");
                if !seen.insert(id.clone()) {
                    continue;
                }
                if !r.indirect {
                    direct.insert(id.clone());
                }
                lock.entries.push(Entry { id, line: r.line, ..Default::default() });
            }
            None => lock.members.push(format!("{} (replaced by a local directory)", r.path)),
        }
    }
    lock.direct_ids = Some(direct);
    match m.go.as_deref().and_then(go_minor) {
        Some(v) if v >= (1, 17) => {}
        other => lock.gaps.push(format!(
            "go.mod declares {}: before Go 1.17 it does not list indirect modules, so the build list here is incomplete",
            match other {
                Some(_) => format!("go {}", m.go.as_deref().unwrap_or("")),
                None => "no go version".to_string(),
            }
        )),
    }
    lock
}

/// `go.sum` as a fallback: the highest version recorded for each module. It over-reports (go.sum keeps modules MVS dropped).
pub fn parse_go_sum(text: &str) -> Lock {
    let mut best: BTreeMap<String, (String, u32)> = BTreeMap::new();
    for (i, l) in text.lines().enumerate() {
        let mut p = l.split_whitespace();
        let (Some(m), Some(v)) = (p.next(), p.next()) else { continue };
        let v = v.strip_suffix("/go.mod").unwrap_or(v);
        match best.get(m) {
            Some((bv, _)) if cmp(bv, v) != std::cmp::Ordering::Less => {}
            _ => {
                best.insert(m.to_string(), (v.to_string(), i as u32 + 1));
            }
        }
    }
    let mut lock = Lock::default();
    let mut rows: Vec<(String, String, u32)> = best.into_iter().map(|(m, (v, l))| (m, v, l)).collect();
    rows.sort_by_key(|r| r.2);
    for (m, v, l) in rows {
        lock.entries.push(Entry { id: format!("go:{m}@{v}"), line: l, ..Default::default() });
    }
    lock.gaps.push("go.sum is a hash record, not the build list: the highest version of each module in it is used, which can include modules the build no longer needs".to_string());
    lock
}

/// `vendor/modules.txt`: `# path version [=> path2 [version2]]` headers, `## explicit` markers, then package lines.
pub fn parse_vendor_modules(text: &str) -> Lock {
    let mut lock = Lock::default();
    let mut seen = BTreeSet::new();
    for (i, l) in text.lines().enumerate() {
        let Some(h) = l.strip_prefix("# ") else { continue };
        if h.starts_with('#') {
            continue;
        }
        let w: Vec<&str> = h.split_whitespace().collect();
        let Some(arrow) = w.iter().position(|x| *x == "=>") else {
            if let (Some(p), Some(v)) = (w.first(), w.get(1)) {
                let id = format!("go:{p}@{v}");
                if seen.insert(id.clone()) {
                    lock.entries.push(Entry { id, line: i as u32 + 1, ..Default::default() });
                }
            }
            continue;
        };
        // replaced: the code in vendor/ is the replacement
        let rep = Replace { old: String::new(), old_version: None, new: w.get(arrow + 1).unwrap_or(&"").to_string(), new_version: w.get(arrow + 2).map(|s| s.to_string()), line: 0 };
        match (rep.is_local(), rep.new_version) {
            (false, Some(v)) => {
                let id = format!("go:{}@{v}", rep.new);
                if seen.insert(id.clone()) {
                    lock.entries.push(Entry { id, line: i as u32 + 1, ..Default::default() });
                }
            }
            _ => lock.members.push(format!("{} (replaced by a local directory)", w.first().unwrap_or(&""))),
        }
    }
    lock
}

/// The build list for a repo: vendor/modules.txt when present, else go.mod (with go.sum filling in the transitive modules only when
/// go.mod predates Go 1.17), else go.sum alone. `work_replaces` come from a go.work that covers this module.
pub fn build_list(go_mod: Option<&str>, go_sum: Option<&str>, vendor: Option<&str>, work_replaces: &[Replace]) -> Option<Lock> {
    if let Some(v) = vendor {
        return Some(parse_vendor_modules(v));
    }
    let Some(gm) = go_mod else { return go_sum.map(parse_go_sum) };
    let m = parse_go_mod(gm);
    let mut lock = build_from_go_mod(&m, work_replaces);
    if !lock.gaps.is_empty() {
        if let Some(s) = go_sum {
            let have: BTreeSet<String> = lock.entries.iter().filter_map(|e| e.id.strip_prefix("go:").and_then(|x| x.rsplit_once('@')).map(|x| x.0.to_string())).collect();
            let mut reps = m.replaces.clone();
            reps.extend(work_replaces.iter().cloned());
            for e in parse_go_sum(s).entries {
                let Some((p, v)) = e.id.strip_prefix("go:").and_then(|x| x.rsplit_once('@')) else { continue };
                if have.contains(p) {
                    continue;
                }
                if let Some((p, v)) = apply_replace(p, v, &reps) {
                    lock.entries.push(Entry { id: format!("go:{p}@{v}"), line: e.line, ..Default::default() });
                }
            }
            lock.gaps = vec![format!(
                "go.mod declares go {}: modules needed only by dependencies were taken from go.sum (highest version recorded), which can over-report",
                m.go.as_deref().unwrap_or("(none)")
            )];
        }
    }
    Some(lock)
}

/// The build list of a go.work workspace: each module's list merged, the highest version of a module winning (MVS).
pub fn workspace_union(members: Vec<Lock>) -> Lock {
    let mut best: BTreeMap<String, (String, u32, bool)> = BTreeMap::new();
    let mut out = Lock::default();
    let mut direct_modules = BTreeSet::new();
    for l in &members {
        let dids = l.direct_ids.clone().unwrap_or_default();
        for e in &l.entries {
            let Some((p, v)) = e.id.strip_prefix("go:").and_then(|x| x.rsplit_once('@')) else { continue };
            if dids.contains(&e.id) {
                direct_modules.insert(p.to_string());
            }
            match best.get(p) {
                Some((bv, _, _)) if cmp(bv, v) != std::cmp::Ordering::Less => {}
                _ => {
                    best.insert(p.to_string(), (v.to_string(), e.line, false));
                }
            }
        }
        out.gaps.extend(l.gaps.iter().cloned());
        out.members.extend(l.members.iter().cloned());
    }
    let mut direct = BTreeSet::new();
    for (p, (v, line, _)) in best {
        let id = format!("go:{p}@{v}");
        if direct_modules.contains(&p) {
            direct.insert(id.clone());
        }
        out.entries.push(Entry { id, line, ..Default::default() });
    }
    out.direct_ids = Some(direct);
    out.gaps.sort();
    out.gaps.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    /// A trimmed go.mod from a real Go 1.21 service (modelled on prometheus-style layouts): direct block, indirect block, replace.
    const GO_MOD: &str = "module github.com/acme/billing\n\ngo 1.21\n\ntoolchain go1.21.5\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.1\n\tgolang.org/x/net v0.23.0\n\tgithub.com/acme/internal v0.0.0-00010101000000-000000000000\n)\n\nrequire (\n\tgithub.com/cespare/xxhash/v2 v2.2.0 // indirect\n\tgolang.org/x/text v0.14.0 // indirect\n\tgithub.com/old/lib v1.0.0 // indirect\n)\n\nreplace github.com/acme/internal => ../internal\n\nreplace (\n\tgithub.com/old/lib v1.0.0 => github.com/fork/lib v1.0.1\n\tgolang.org/x/text => golang.org/x/text v0.15.0\n)\n";
    /// go.sum for the same module: it still holds the versions MVS passed over.
    const GO_SUM: &str = "github.com/cespare/xxhash/v2 v2.2.0 h1:a=\ngithub.com/cespare/xxhash/v2 v2.2.0/go.mod h1:b=\ngolang.org/x/net v0.0.0-20190620200207-3b0461eec859/go.mod h1:c=\ngolang.org/x/net v0.23.0 h1:d=\ngolang.org/x/net v0.23.0/go.mod h1:e=\ngolang.org/x/net v0.10.0 h1:f=\ngolang.org/x/net v0.10.0/go.mod h1:g=\n";

    #[test]
    fn go_mod_is_the_build_list_with_replace() {
        let m = parse_go_mod(GO_MOD);
        assert_eq!(m.go.as_deref(), Some("1.21"));
        let l = build_from_go_mod(&m, &[]);
        let ids: Vec<_> = l.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["go:github.com/gorilla/mux@v1.8.1", "go:golang.org/x/net@v0.23.0", "go:github.com/cespare/xxhash/v2@v2.2.0", "go:golang.org/x/text@v0.15.0", "go:github.com/fork/lib@v1.0.1"]
        );
        let d = l.direct_ids.as_ref().unwrap();
        assert!(d.contains("go:golang.org/x/net@v0.23.0") && !d.contains("go:golang.org/x/text@v0.15.0"));
        assert_eq!(l.members.len(), 1, "the local replace is a workspace-like member, not a registry module");
        assert!(l.gaps.is_empty());
        assert_eq!(l.entries[0].line, 8);
    }

    #[test]
    fn go_sum_alone_is_collapsed_and_flagged() {
        let l = parse_go_sum(GO_SUM);
        let ids: Vec<_> = l.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["go:github.com/cespare/xxhash/v2@v2.2.0", "go:golang.org/x/net@v0.23.0"], "old versions MVS passed over must not appear");
        assert_eq!(l.gaps.len(), 1);
    }

    #[test]
    fn old_go_mod_takes_transitive_modules_from_sum() {
        let gm = "module x\n\ngo 1.16\n\nrequire golang.org/x/net v0.23.0\n";
        let l = build_list(Some(gm), Some(GO_SUM), None, &[]).unwrap();
        let ids: Vec<_> = l.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["go:golang.org/x/net@v0.23.0", "go:github.com/cespare/xxhash/v2@v2.2.0"]);
        assert!(l.gaps[0].contains("go.sum"));
        // without go.sum the gap says the list is incomplete
        let l = build_list(Some(gm), None, None, &[]).unwrap();
        assert!(l.gaps[0].contains("incomplete"), "{:?}", l.gaps);
    }

    #[test]
    fn vendor_modules_txt() {
        let v = "# github.com/gorilla/mux v1.8.1\n## explicit; go 1.20\ngithub.com/gorilla/mux\n# golang.org/x/net v0.0.0-20190620200207-3b0461eec859 => golang.org/x/net v0.23.0\n## explicit; go 1.18\ngolang.org/x/net/http2\n# github.com/acme/internal v0.0.0-00010101000000-000000000000 => ../internal\n## explicit\ngithub.com/acme/internal\n";
        let l = parse_vendor_modules(v);
        assert_eq!(l.entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec!["go:github.com/gorilla/mux@v1.8.1", "go:golang.org/x/net@v0.23.0"]);
        assert_eq!(l.members.len(), 1);
    }

    #[test]
    fn go_work_uses_and_replaces() {
        let w = "go 1.22.0\n\nuse (\n\t./services/api\n\t./libs/common\n)\n\nuse ./tools\n\nreplace golang.org/x/net v0.10.0 => golang.org/x/net v0.23.0\n";
        let g = parse_go_work(w);
        assert_eq!(g.uses, vec!["./services/api", "./libs/common", "./tools"]);
        let m = parse_go_mod("module a\ngo 1.22\nrequire golang.org/x/net v0.10.0\n");
        let l = build_from_go_mod(&m, &g.replaces);
        assert_eq!(l.entries[0].id, "go:golang.org/x/net@v0.23.0");
    }

    #[test]
    fn workspace_union_takes_the_highest() {
        let a = build_from_go_mod(&parse_go_mod("module a\ngo 1.22\nrequire golang.org/x/net v0.10.0\n"), &[]);
        let b = build_from_go_mod(&parse_go_mod("module b\ngo 1.22\nrequire golang.org/x/net v0.23.0 // indirect\nrequire github.com/x/y v1.0.0\n"), &[]);
        let u = workspace_union(vec![a, b]);
        assert_eq!(u.entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec!["go:github.com/x/y@v1.0.0", "go:golang.org/x/net@v0.23.0"]);
        assert!(u.direct_ids.unwrap().contains("go:golang.org/x/net@v0.23.0"));
    }

    #[test]
    fn version_order() {
        assert_eq!(cmp("v1.9.0", "v1.10.0"), Less);
        assert_eq!(cmp("v1.0.0-rc.1", "v1.0.0"), Less);
        assert_eq!(cmp("v0.0.0-20190620200207-3b0461eec859", "v0.0.0-20220715151400-c0bba94af5f7"), Less);
        assert_eq!(cmp("v2.0.0+incompatible", "v2.0.0"), Equal);
        assert_eq!(cmp("v1.0.0-rc.2", "v1.0.0-rc.10"), Less);
    }
}
