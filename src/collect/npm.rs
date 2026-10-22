//! npm registry metadata: which dependencies a published version asks for.
//! `GET {BR_NPM_REGISTRY}/{name}` (default https://registry.npmjs.org), scoped names as `@scope%2fname`.
//! Package metadata is public, so versions published after the clock are listed by the registry and dropped here.
use regex::Regex;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static CACHE: RefCell<HashMap<String, Result<Option<Value>, String>>> = RefCell::new(HashMap::new());
}

fn base() -> String {
    std::env::var("BR_NPM_REGISTRY").unwrap_or_else(|_| "https://registry.npmjs.org".into()).trim_end_matches('/').to_string()
}

/// `key=value` lines of the user's and the project's .npmrc (project wins), with ${ENV} expanded.
fn npmrc() -> Vec<(String, String)> {
    let mut out = vec![];
    let mut files = vec![];
    if let Some(h) = dirs::home_dir() {
        files.push(h.join(".npmrc"));
    }
    files.push(std::path::PathBuf::from(".npmrc"));
    for f in files {
        let Ok(t) = std::fs::read_to_string(f) else { continue };
        for l in t.lines() {
            let l = l.trim();
            if l.starts_with('#') || l.starts_with(';') {
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                let mut v = v.trim().to_string();
                while let (Some(a), Some(b)) = (v.find("${"), v.find('}')) {
                    if b < a {
                        break;
                    }
                    let var = v[a + 2..b].to_string();
                    v.replace_range(a..=b, &std::env::var(&var).unwrap_or_default());
                }
                out.push((k.trim().to_string(), v));
            }
        }
    }
    out
}

/// The registry that serves this package: `@scope:registry` from .npmrc, else BR_NPM_REGISTRY / registry= / npmjs.
fn registry_for(name: &str) -> String {
    if std::env::var("BR_NPM_REGISTRY").is_ok() {
        return base();
    }
    let rc = npmrc();
    if let Some(sc) = name.strip_prefix('@').and_then(|r| r.split('/').next()) {
        if let Some((_, v)) = rc.iter().rev().find(|(k, _)| *k == format!("@{sc}:registry")) {
            return v.trim_end_matches('/').to_string();
        }
    }
    rc.iter().rev().find(|(k, _)| k == "registry").map(|(_, v)| v.trim_end_matches('/').to_string()).unwrap_or_else(base)
}

/// The bearer token .npmrc holds for a registry URL (`//host/path/:_authToken=...`).
fn token_for(reg: &str) -> Option<String> {
    let rc = npmrc();
    let bare = reg.split_once(':').map(|(_, r)| r).unwrap_or(reg).trim_end_matches('/').to_string();
    rc.iter().rev().find(|(k, _)| k.starts_with("//") && k.ends_with(":_authToken") && bare.starts_with(k[..k.len() - 11].trim_end_matches('/'))).map(|(_, v)| v.clone()).filter(|v| !v.is_empty())
}

fn url(name: &str) -> String {
    format!("{}/{}", registry_for(name), name.replacen('/', "%2f", 1))
}

fn fetch(name: &str) -> Result<Option<Value>, String> {
    let key = format!("{}|{name}", base());
    if let Some(r) = CACHE.with(|c| c.borrow().get(&key).cloned()) {
        return r;
    }
    let reg = registry_for(name);
    let mut req = ureq::get(&url(name)).timeout(std::time::Duration::from_secs(30));
    if let Some(t) = token_for(&reg) {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let r = match req.call() {
        Ok(r) => r.into_json::<Value>().map(Some).map_err(|e| format!("unreadable answer ({e})")),
        // npmjs answers 404 for a private scoped package it will not show: that is "unknown", not "does not exist"
        Err(ureq::Error::Status(404, _)) if name.starts_with('@') && reg.contains("registry.npmjs.org") => {
            Err("404 on a scoped package: private or missing; set its registry and token in .npmrc".into())
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(ureq::Error::Status(c, _)) => Err(format!("HTTP {c}")),
        Err(_) => Err("unreachable".into()),
    };
    CACHE.with(|c| c.borrow_mut().insert(key, r.clone()));
    r
}

/// Test hook: pre-load a packument as if the registry had served it.
#[cfg(test)]
pub fn seed(name: &str, v: Value) {
    let key = format!("{}|{name}", base());
    CACHE.with(|c| c.borrow_mut().insert(key, Ok(Some(v))));
}

/// A possibly partial version: `1`, `1.2`, `1.2.3`, `1.x`, `*`.
fn partial(s: &str) -> Option<[Option<u64>; 3]> {
    let core = s.trim().trim_start_matches(['v', '=']).split(['-', '+']).next().unwrap_or("");
    if core.is_empty() {
        return Some([None, None, None]);
    }
    let mut out = [None, None, None];
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() > 3 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] = match *p {
            "x" | "X" | "*" => None,
            n => Some(n.parse::<u64>().ok()?),
        };
        if out[i].is_none() {
            // everything after a wildcard is a wildcard
            break;
        }
    }
    Some(out)
}

fn lo(p: &[Option<u64>; 3]) -> [u64; 3] {
    [p[0].unwrap_or(0), p[1].unwrap_or(0), p[2].unwrap_or(0)]
}

/// The smallest version above everything the partial version covers: `1.2` -> 1.3.0, `1` -> 2.0.0, `1.2.3` -> 1.2.4.
fn above(p: &[Option<u64>; 3]) -> Option<[u64; 3]> {
    match (p[0], p[1], p[2]) {
        (None, _, _) => None,
        (Some(a), None, _) => Some([a + 1, 0, 0]),
        (Some(a), Some(b), None) => Some([a, b + 1, 0]),
        (Some(a), Some(b), Some(c)) => Some([a, b, c + 1]),
    }
}

/// One comparator (`^1.2.0`, `>=1`, `1.x`) against a version: Some(answer), or None when the syntax is not one we read.
fn comparator(c: &str, cur: [u64; 3]) -> Option<bool> {
    let c = c.trim();
    if c.is_empty() || c == "*" || c == "x" || c == "X" || c == "latest" {
        return Some(true);
    }
    for (op, f) in [(">=", 0), ("<=", 1), (">", 2), ("<", 3)] {
        if let Some(r) = c.strip_prefix(op) {
            let p = partial(r)?;
            return Some(match f {
                0 => cur >= lo(&p),
                1 => match above(&p) {
                    Some(h) => cur < h,
                    None => true,
                },
                2 => match above(&p) {
                    Some(h) => cur >= h,
                    None => false,
                },
                _ => cur < lo(&p),
            });
        }
    }
    if let Some(r) = c.strip_prefix('^') {
        let p = partial(r)?;
        let l = lo(&p);
        let h = match (p[0], p[1], p[2]) {
            (Some(0), Some(0), Some(z)) => [0, 0, z + 1],
            (Some(0), Some(y), _) => [0, y + 1, 0],
            (Some(x), _, _) => [x + 1, 0, 0],
            (None, _, _) => return Some(true),
        };
        return Some(cur >= l && cur < h);
    }
    if let Some(r) = c.strip_prefix('~') {
        let p = partial(r)?;
        let h = match (p[0], p[1]) {
            (Some(x), Some(y)) => [x, y + 1, 0],
            (Some(x), None) => [x + 1, 0, 0],
            (None, _) => return Some(true),
        };
        return Some(cur >= lo(&p) && cur < h);
    }
    // exact or x-range
    let p = partial(c)?;
    let l = lo(&p);
    Some(match above(&p) {
        Some(h) => cur >= l && cur < h,
        None => true,
    })
}

/// Does a dependency spec admit this version? None when the spec is something we do not read (a tag, a git URL, an alias,
/// `workspace:`), so the caller can say "cannot tell" instead of "no".
pub fn sat(spec: &str, v: &str) -> Option<bool> {
    let spec = spec.trim();
    let v = v.trim_start_matches('v');
    if spec.contains("://") || spec.contains(':') || spec.starts_with("git") || spec.contains('/') && !spec.contains(' ') {
        return None;
    }
    let prerelease = v.contains('-');
    let cur = {
        let p = partial(v)?;
        lo(&p)
    };
    let mut any = false;
    for set in spec.split("||") {
        let set = set.trim();
        let ok = if let Some((a, b)) = set.split_once(" - ") {
            let (pa, pb) = (partial(a)?, partial(b)?);
            cur >= lo(&pa)
                && match above(&pb) {
                    Some(h) => cur < h,
                    None => true,
                }
        } else {
            // "> 1.0.0" written with a space after the operator
            let fixed = Regex::new(r"(>=|<=|>|<|\^|~)\s+").unwrap().replace_all(set, "$1").to_string();
            let mut all = true;
            for c in fixed.split_whitespace() {
                all &= comparator(c, cur)?;
            }
            all
        };
        any |= ok;
    }
    // a prerelease only satisfies a spec that names that exact version (node-semver's default)
    if prerelease && any {
        return Some(spec.trim_start_matches(['=', 'v']) == v);
    }
    Some(any)
}

/// Does a dependency spec (an exact version or a range) admit this version? Unreadable syntax answers false.
pub fn satisfies(spec: &str, v: &str) -> bool {
    sat(spec, v).unwrap_or(false)
}

/// Does `parent@fixed` ask for a `child` that `fixed` satisfies, per the registry as of `now`?
/// Ok(false) when the registry does not know the package or that version (or it was published after `now`).
pub fn pulls(parent: &str, child: &str, fixed: &str, now: &str) -> Result<bool, String> {
    let fx = fixed.trim_start_matches('v');
    let Some(pk) = fetch(parent)? else { return Ok(false) };
    let Some(ver) = pk["versions"].get(fx) else { return Ok(false) };
    if let Some(t) = pk["time"][fx].as_str() {
        if !now.is_empty() && t > now {
            return Ok(false);
        }
    }
    match ver["dependencies"][child].as_str() {
        None => Ok(false),
        Some(spec) => sat(spec, fx).ok_or_else(|| format!("cannot tell whether {child}@{spec} admits {fx}: the spec is not a version range")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert!(satisfies("1.2.3", "1.2.3"));
        assert!(!satisfies("1.2.3", "1.2.4"));
        assert!(satisfies("^1.2.0", "1.9.0"));
        assert!(!satisfies("^1.2.0", "2.0.0"));
        assert!(satisfies("~1.2.0", "1.2.9"));
        assert!(!satisfies("~1.2.0", "1.3.0"));
        assert!(satisfies(">=1.0.0 <2.0.0", "1.5.0"));
        assert!(satisfies("1.x", "1.4.0"));
        assert!(!satisfies("workspace:*", "1.0.0"));
        assert_eq!(sat("workspace:*", "1.0.0"), None);
        assert_eq!(sat("github:a/b", "1.0.0"), None);
        assert_eq!(sat("^1.2", "1.9.0"), Some(true));
        assert_eq!(sat("^0.2.3", "0.3.0"), Some(false));
        assert_eq!(sat("~1", "1.9.9"), Some(true));
        assert_eq!(sat("1.2.3 - 2.3.4", "2.0.0"), Some(true));
        assert_eq!(sat(">= 1.0.0 < 2", "1.5.0"), Some(true));
        assert_eq!(sat("^1.0.0 || ^3.0.0", "3.1.0"), Some(true));
        assert_eq!(sat("^1.0.0", "1.1.0-beta.1"), Some(false));
    }

    #[test]
    fn packument_pull_and_clock() {
        seed(
            "@s/p",
            serde_json::json!({"versions":{"1.0.1":{"dependencies":{"c":"1.0.1"}},"1.0.2":{"dependencies":{"c":"1.0.2"}}},
                "time":{"1.0.1":"2026-01-01T00:00:00Z","1.0.2":"2026-09-01T00:00:00Z"}}),
        );
        assert_eq!(pulls("@s/p", "c", "1.0.1", "2026-05-01T00:00:00Z"), Ok(true));
        assert_eq!(pulls("@s/p", "c", "1.0.2", "2026-05-01T00:00:00Z"), Ok(false));
        assert_eq!(pulls("@s/p", "d", "1.0.1", "2026-05-01T00:00:00Z"), Ok(false));
    }

    #[test]
    fn scoped_url() {
        assert!(url("@tanstack/react-router").ends_with("/@tanstack%2freact-router"));
    }
}
