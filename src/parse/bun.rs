//! `bun.lock`, the text lockfile Bun 1.2+ writes by default. It is JSONC: trailing commas are allowed.
//!
//! ```text
//! {
//!   "lockfileVersion": 1,
//!   "workspaces": { "": { "name": "app", "dependencies": { "left-pad": "^1.3.0" } } },
//!   "packages": {
//!     "left-pad": ["left-pad@1.3.0", "", {}, "sha512-..."],
//!     "string-width-cjs": ["string-width@4.2.3", "", { "dependencies": { ... } }, "sha512-..."],
//!   }
//! }
//! ```
//! The key is the install path (nested installs are `parent/child`), the first array element is `name@version` of what is
//! really installed (so an alias key still gives the real package).
use std::collections::{BTreeSet, HashMap};

use serde_json::Value;

use super::idx::{join_path, json_paths};
use super::lock::{Entry, Lock};

/// Remove trailing commas (before `}` or `]`) and comments outside strings.
pub fn strip_jsonc(text: &str) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 1;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '/' if b.get(i + 1) == Some(&'/') => {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            ',' => {
                let mut j = i + 1;
                while j < b.len() && b[j].is_whitespace() {
                    j += 1;
                }
                if !matches!(b.get(j), Some('}') | Some(']')) {
                    out.push(c);
                }
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

/// Package-name segments of an install path: `@s/x/y` is `["@s/x", "y"]`.
fn segments(path: &str) -> Vec<String> {
    let mut out = vec![];
    let mut it = path.split('/');
    while let Some(s) = it.next() {
        if s.starts_with('@') {
            match it.next() {
                Some(n) => out.push(format!("{s}/{n}")),
                None => out.push(s.to_string()),
            }
        } else {
            out.push(s.to_string());
        }
    }
    out
}

pub fn parse(text: &str) -> Option<Lock> {
    let v: Value = serde_json::from_str(&strip_jsonc(text)).ok()?;
    let pk = v["packages"].as_object()?;
    let lines = json_paths(text);
    let mut lock = Lock::default();
    // key -> id, for resolving edges
    let mut id_of: HashMap<&str, String> = HashMap::new();
    for (k, e) in pk {
        let Some(first) = e.get(0).and_then(|x| x.as_str()) else { continue };
        let Some(at) = first.char_indices().skip(1).filter(|(_, c)| *c == '@').map(|x| x.0).next() else { continue };
        let (name, ver) = (&first[..at], &first[at + 1..]);
        // workspace packages, links and local files are not registry packages
        if ["workspace:", "link:", "file:", "root:"].iter().any(|p| ver.starts_with(p)) {
            lock.members.push(first.to_string());
            continue;
        }
        let ver = ver.strip_prefix("npm:").unwrap_or(ver);
        id_of.insert(k.as_str(), format!("npm:{name}@{ver}"));
    }
    // direct: every workspace's dependency names, resolved at the top level (key == name)
    let mut direct = BTreeSet::new();
    let mut dev_names = BTreeSet::new();
    let mut prod_names = BTreeSet::new();
    if let Some(ws) = v["workspaces"].as_object() {
        for w in ws.values() {
            for sec in ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"] {
                if let Some(o) = w[sec].as_object() {
                    for k in o.keys() {
                        if sec == "devDependencies" {
                            dev_names.insert(k.clone());
                        } else {
                            prod_names.insert(k.clone());
                        }
                        if let Some(id) = id_of.get(k.as_str()) {
                            direct.insert(id.clone());
                        }
                    }
                }
            }
        }
    }
    let dev_only: BTreeSet<String> = dev_names.difference(&prod_names).cloned().collect();
    for (k, e) in pk {
        let Some(id) = id_of.get(k.as_str()) else { continue };
        let segs = segments(k);
        let mut deps = vec![];
        if let Some(meta) = e.get(2) {
            for sec in ["dependencies", "optionalDependencies"] {
                if let Some(o) = meta[sec].as_object() {
                    for d in o.keys() {
                        // nearest install first: k/d, then up the tree, then top level
                        let mut depth = segs.len();
                        loop {
                            let cand = if depth == 0 { d.clone() } else { format!("{}/{d}", segs[..depth].join("/")) };
                            if let Some(i) = id_of.get(cand.as_str()) {
                                deps.push(i.clone());
                                break;
                            }
                            if depth == 0 {
                                break;
                            }
                            depth -= 1;
                        }
                    }
                }
            }
        }
        lock.entries.push(Entry { id: id.clone(), line: lines.get(&join_path(&["packages", k])).copied().unwrap_or(0), deps, ..Default::default() });
    }
    lock.entries.sort_by_key(|e| e.line);
    for n in &dev_only {
        if let Some(id) = id_of.get(n.as_str()) {
            lock.direct_dev_ids.insert(id.clone());
        }
    }
    lock.direct_ids = Some(direct);
    super::lock::mark_dev_by_reach(&mut lock);
    Some(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// bun.lock as `bun install` 1.2 writes it: trailing commas, an alias key, a nested install, a workspace package.
    const BUN: &str = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"app\",\n      \"dependencies\": {\n        \"left-pad\": \"^1.3.0\",\n        \"string-width-cjs\": \"npm:string-width@^4.2.0\",\n      },\n      \"devDependencies\": {\n        \"typescript\": \"^5.4.0\",\n      },\n    },\n    \"packages/lib\": {\n      \"name\": \"@acme/lib\",\n    },\n  },\n  \"packages\": {\n    \"@acme/lib\": [\"@acme/lib@workspace:packages/lib\"],\n\n    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-aaa\"],\n\n    \"string-width-cjs\": [\"string-width@4.2.3\", \"\", { \"dependencies\": { \"emoji-regex\": \"^8.0.0\", \"strip-ansi\": \"^6.0.1\" } }, \"sha512-bbb\"],\n\n    \"emoji-regex\": [\"emoji-regex@8.0.0\", \"\", {}, \"sha512-ccc\"],\n\n    \"strip-ansi\": [\"strip-ansi@6.0.1\", \"\", { \"dependencies\": { \"ansi-regex\": \"^5.0.1\" } }, \"sha512-ddd\"],\n\n    \"strip-ansi/ansi-regex\": [\"ansi-regex@5.0.1\", \"\", {}, \"sha512-eee\"],\n\n    \"typescript\": [\"typescript@5.4.5\", \"\", { \"bin\": { \"tsc\": \"bin/tsc\" } }, \"sha512-fff\"],\n  }\n}\n";

    #[test]
    fn bun_text_lock() {
        let l = parse(BUN).unwrap();
        let ids: Vec<_> = l.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["npm:left-pad@1.3.0", "npm:string-width@4.2.3", "npm:emoji-regex@8.0.0", "npm:strip-ansi@6.0.1", "npm:ansi-regex@5.0.1", "npm:typescript@5.4.5"]);
        assert_eq!(l.entries[1].deps, vec!["npm:emoji-regex@8.0.0", "npm:strip-ansi@6.0.1"]);
        assert_eq!(l.entries[3].deps, vec!["npm:ansi-regex@5.0.1"], "the nested install wins over a top-level one");
        assert_eq!(l.entries[0].line, 21);
        assert_eq!(l.members, vec!["@acme/lib@workspace:packages/lib"]);
        let p = super::super::lock::packages(&l, None);
        let by = |id: &str| p.iter().find(|x| x.p == id).unwrap();
        assert!(by("npm:string-width@4.2.3").direct && !by("npm:string-width@4.2.3").dev, "alias key still gives the real package");
        assert!(by("npm:typescript@5.4.5").direct && by("npm:typescript@5.4.5").dev);
        assert!(!by("npm:ansi-regex@5.0.1").direct);
        assert_eq!(by("npm:ansi-regex@5.0.1").via, vec!["npm:string-width@4.2.3", "npm:strip-ansi@6.0.1"]);
    }

    #[test]
    fn jsonc_commas_and_strings() {
        assert_eq!(strip_jsonc("{\"a\": [1, 2,], \"b\": \"x,}\",}"), "{\"a\": [1, 2], \"b\": \"x,}\"}");
    }
}
