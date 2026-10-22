//! Version semantics per ecosystem.
//! npm and cargo: semver (prerelease ordering, build metadata ignored). pypi: PEP 440 (normalised: 2.31 == 2.31.0,
//! 1.0rc1 == 1.0.0rc1). go: semver with a leading v, +incompatible, pseudo-versions. action: refs compare as strings.
//!
//! OSV range semantics (`VersionRange`): a version v is inside a range when `introduced <= v` (a missing introduced or
//! "0" means from the first version) and, when `fixed` is set, `v < fixed`, or, when `last_affected` is set,
//! `v <= last_affected`. A range with neither bound is open ended. A version that does not parse is never inside a
//! range (only an exact string match against `versions` can flag it).
use crate::view::{AffectedPackage, VersionRange};
use regex::Regex;
use std::cmp::Ordering;
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Semver,
    Pep440,
    Str,
}

fn kind(eco: &str) -> Kind {
    match eco.to_ascii_lowercase().as_str() {
        "npm" | "cargo" | "crates.io" | "go" | "golang" => Kind::Semver,
        "pypi" => Kind::Pep440,
        _ => Kind::Str,
    }
}

// ---------- semver (npm, cargo, go) ----------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Semver {
    /// numeric parts as digit strings without leading zeros (so huge numbers never overflow)
    nums: [String; 3],
    pre: Vec<String>,
}

fn strip0(s: &str) -> String {
    let t = s.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.into()
    }
}

fn cmp_num(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

fn parse_semver(s: &str) -> Option<Semver> {
    let mut s = s.trim();
    s = s.strip_prefix('=').unwrap_or(s).trim();
    s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    let s = s.split('+').next()?; // build metadata (and Go's +incompatible) never orders
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 || !parts.iter().all(|p| all_digits(p)) {
        return None;
    }
    let mut nums = [String::from("0"), String::from("0"), String::from("0")];
    for (i, p) in parts.iter().enumerate() {
        nums[i] = strip0(p);
    }
    let pre = match pre {
        None => vec![],
        Some(p) => {
            let ids: Vec<String> = p.split('.').map(|x| x.to_string()).collect();
            if ids.iter().any(|x| x.is_empty() || !x.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')) {
                return None;
            }
            ids
        }
    };
    Some(Semver { nums, pre })
}

fn cmp_semver(a: &Semver, b: &Semver) -> Ordering {
    for i in 0..3 {
        let o = cmp_num(&a.nums[i], &b.nums[i]);
        if o != Ordering::Equal {
            return o;
        }
    }
    match (a.pre.is_empty(), b.pre.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    for (x, y) in a.pre.iter().zip(b.pre.iter()) {
        let o = match (all_digits(x), all_digits(y)) {
            (true, true) => cmp_num(&strip0(x), &strip0(y)),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => x.cmp(y),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    a.pre.len().cmp(&b.pre.len())
}

// ---------- PEP 440 ----------

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalSeg {
    Alpha(String),
    Num(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pep {
    epoch: String,
    release: Vec<String>, // trailing zeros stripped
    /// (rank a=0 b=1 rc=2, number)
    pre: Option<(u8, String)>,
    post: Option<String>,
    dev: Option<String>,
    local: Option<Vec<LocalSeg>>,
}

fn pep_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?ix)^\s*v?
            (?:(?P<epoch>[0-9]+)!)?
            (?P<release>[0-9]+(?:\.[0-9]+)*)
            (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
            (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
            (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
            (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
            \s*$",
        )
        .unwrap()
    })
}

fn parse_pep(s: &str) -> Option<Pep> {
    let c = pep_re().captures(s)?;
    let num = |m: Option<regex::Match>| strip0(m.map(|m| m.as_str()).unwrap_or("0"));
    let epoch = num(c.name("epoch"));
    let mut release: Vec<String> = c.name("release")?.as_str().split('.').map(strip0).collect();
    while release.len() > 1 && release.last().map(|x| x == "0").unwrap_or(false) {
        release.pop();
    }
    let pre = c.name("pre_l").map(|l| {
        let rank = match l.as_str().to_ascii_lowercase().as_str() {
            "a" | "alpha" => 0,
            "b" | "beta" => 1,
            _ => 2, // c, rc, pre, preview
        };
        (rank, num(c.name("pre_n")))
    });
    let post = if c.name("post").is_some() { Some(num(c.name("post_n1").or(c.name("post_n2")))) } else { None };
    let dev = c.name("dev_l").map(|_| num(c.name("dev_n")));
    let local =
        c.name("local").map(|l| l.as_str().to_ascii_lowercase().split(['-', '_', '.']).map(|p| if all_digits(p) { LocalSeg::Num(strip0(p)) } else { LocalSeg::Alpha(p.to_string()) }).collect());
    Some(Pep { epoch, release, pre, post, dev, local })
}

fn cmp_pep(a: &Pep, b: &Pep) -> Ordering {
    let o = cmp_num(&a.epoch, &b.epoch);
    if o != Ordering::Equal {
        return o;
    }
    for i in 0..a.release.len().max(b.release.len()) {
        let z = "0".to_string();
        let o = cmp_num(a.release.get(i).unwrap_or(&z), b.release.get(i).unwrap_or(&z));
        if o != Ordering::Equal {
            return o;
        }
    }
    // pre: a dev-only release sorts before every prerelease; no pre sorts after any pre
    fn pre_key(p: &Pep) -> (i8, u8, String) {
        match &p.pre {
            None if p.post.is_none() && p.dev.is_some() => (-1, 0, String::new()),
            None => (1, 0, String::new()),
            Some((r, n)) => (0, *r, n.clone()),
        }
    }
    let (ka, kb) = (pre_key(a), pre_key(b));
    let o = ka.0.cmp(&kb.0).then(ka.1.cmp(&kb.1)).then_with(|| cmp_num(&ka.2, &kb.2));
    if o != Ordering::Equal {
        return o;
    }
    let o = match (&a.post, &b.post) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(x), Some(y)) => cmp_num(x, y),
    };
    if o != Ordering::Equal {
        return o;
    }
    let o = match (&a.dev, &b.dev) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => cmp_num(x, y),
    };
    if o != Ordering::Equal {
        return o;
    }
    match (&a.local, &b.local) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(x), Some(y)) => {
            for (p, q) in x.iter().zip(y.iter()) {
                let o = match (p, q) {
                    (LocalSeg::Num(m), LocalSeg::Num(n)) => cmp_num(m, n),
                    (LocalSeg::Alpha(m), LocalSeg::Alpha(n)) => m.cmp(n),
                    (LocalSeg::Num(_), LocalSeg::Alpha(_)) => Ordering::Greater,
                    (LocalSeg::Alpha(_), LocalSeg::Num(_)) => Ordering::Less,
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
            x.len().cmp(&y.len())
        }
    }
}

// ---------- public interface ----------

/// Compare two versions of `eco`. None when either does not parse as a version of that ecosystem.
/// Actions (and unknown ecosystems) compare refs as strings: equal only when identical, otherwise None for unknown
/// ecosystems and the string order for actions.
pub fn cmp(eco: &str, a: &str, b: &str) -> Option<Ordering> {
    match kind(eco) {
        Kind::Semver => Some(cmp_semver(&parse_semver(a)?, &parse_semver(b)?)),
        Kind::Pep440 => Some(cmp_pep(&parse_pep(a)?, &parse_pep(b)?)),
        Kind::Str => {
            if a == b {
                Some(Ordering::Equal)
            } else if eco.eq_ignore_ascii_case("action") || eco.eq_ignore_ascii_case("github-actions") {
                Some(a.cmp(b))
            } else {
                None
            }
        }
    }
}

/// True when `a` and `b` are the same version of `eco` (normalised), or identical strings.
pub fn same(eco: &str, a: &str, b: &str) -> bool {
    a == b || cmp(eco, a, b) == Some(Ordering::Equal)
}

fn is_zero(s: &str) -> bool {
    let t = s.trim();
    t == "0" || t.is_empty()
}

/// Is `version` inside this OSV range of `eco`?
fn in_range(eco: &str, r: &VersionRange, version: &str) -> bool {
    if kind(eco) == Kind::Str {
        return false; // ranges mean nothing for action refs
    }
    if let Some(i) = r.introduced.as_deref() {
        if !is_zero(i) {
            match cmp(eco, version, i) {
                Some(Ordering::Less) | None => return false,
                _ => {}
            }
        } else if cmp(eco, version, "0").is_none() {
            return false; // does not parse
        }
    } else if cmp(eco, version, "0").is_none() {
        return false;
    }
    if let Some(f) = r.fixed.as_deref() {
        return matches!(cmp(eco, version, f), Some(Ordering::Less));
    }
    if let Some(l) = r.last_affected.as_deref() {
        return matches!(cmp(eco, version, l), Some(Ordering::Less | Ordering::Equal));
    }
    true
}

/// Is `version` of this package affected (listed, or inside any range)?
pub fn is_affected(pkg: &AffectedPackage, version: &str) -> bool {
    pkg.versions.iter().any(|v| same(&pkg.ecosystem, v, version)) || pkg.ranges.iter().any(|r| in_range(&pkg.ecosystem, r, version))
}

/// The version to move to from `current`: the lowest `fixed` above `current` among the ranges that contain it.
/// None when no range containing `current` has a fix. When that fixed version is itself inside another range of the
/// package, the next fix up is taken, so the advice never lands on an affected version.
pub fn fixed_for(pkg: &AffectedPackage, current: &str) -> Option<String> {
    let eco = pkg.ecosystem.as_str();
    let mut cur = current.to_string();
    let mut answer: Option<String> = None;
    for _ in 0..=pkg.ranges.len() {
        let mut best: Option<&str> = None;
        for r in pkg.ranges.iter().filter(|r| in_range(eco, r, &cur)) {
            if let Some(f) = r.fixed.as_deref() {
                if best.map(|b| cmp(eco, f, b) == Some(Ordering::Less)).unwrap_or(true) {
                    best = Some(f);
                }
            }
        }
        match best {
            None => return answer,
            Some(f) => {
                answer = Some(f.to_string());
                if !pkg.ranges.iter().any(|r| in_range(eco, r, f)) {
                    return answer;
                }
                cur = f.to_string();
            }
        }
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    fn pk(eco: &str, versions: &[&str], ranges: &[(Option<&str>, Option<&str>, Option<&str>)]) -> AffectedPackage {
        AffectedPackage {
            ecosystem: eco.into(),
            name: "x".into(),
            versions: versions.iter().map(|s| s.to_string()).collect(),
            ranges: ranges.iter().map(|(i, f, l)| VersionRange { introduced: i.map(String::from), fixed: f.map(String::from), last_affected: l.map(String::from) }).collect(),
        }
    }
    fn lt(eco: &str, a: &str, b: &str) {
        assert_eq!(cmp(eco, a, b), Some(Less), "{a} < {b}");
        assert_eq!(cmp(eco, b, a), Some(Greater), "{b} > {a}");
    }
    fn eq(eco: &str, a: &str, b: &str) {
        assert_eq!(cmp(eco, a, b), Some(Equal), "{a} == {b}");
        assert_eq!(cmp(eco, b, a), Some(Equal));
    }

    #[test]
    fn semver_core_order() {
        for eco in ["npm", "cargo"] {
            lt(eco, "1.2.3", "1.2.4");
            lt(eco, "1.2.9", "1.10.0");
            lt(eco, "1.9.9", "2.0.0");
            lt(eco, "0.0.0", "0.0.1");
            eq(eco, "1.2.3", "v1.2.3");
            eq(eco, "1.2.3+build.5", "1.2.3+other");
            eq(eco, "1.2", "1.2.0");
            lt(eco, "99999999999999999999.0.0", "100000000000000000000.0.0");
        }
    }

    #[test]
    fn semver_prerelease_order() {
        // the order from the semver spec, item 11
        let order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"];
        for eco in ["npm", "cargo"] {
            for w in order.windows(2) {
                lt(eco, w[0], w[1]);
            }
        }
        lt("npm", "1.0.0-rc.1", "1.0.0");
        lt("npm", "0.9.9", "1.0.0-0");
        eq("npm", "1.0.0-rc.1+a", "1.0.0-rc.1+b");
        lt("cargo", "1.0.0-1", "1.0.0-a"); // numeric ids sort below alphanumeric
        lt("npm", "1.0.0-2", "1.0.0-10");
    }

    #[test]
    fn semver_rejects_garbage() {
        assert_eq!(cmp("npm", "latest", "1.0.0"), None);
        assert_eq!(cmp("npm", "1.0.0", "git+https://x/y"), None);
        assert_eq!(cmp("cargo", "1.x", "1.0.0"), None);
        assert_eq!(cmp("npm", "1.2.3.4", "1.2.3"), None);
        assert_eq!(cmp("npm", "", "1.2.3"), None);
        assert_eq!(cmp("npm", "1.0.0-", "1.0.0"), None);
    }

    #[test]
    fn pep440_normalisation() {
        eq("pypi", "2.31", "2.31.0");
        eq("pypi", "2.31", "2.31.0.0");
        eq("pypi", "1.0rc1", "1.0.0rc1");
        eq("pypi", "1.0rc1", "1.0-rc1");
        eq("pypi", "1.0rc1", "1.0.rc1");
        eq("pypi", "1.0RC1", "1.0rc1");
        eq("pypi", "1.0c1", "1.0rc1");
        eq("pypi", "1.0preview1", "1.0rc1");
        eq("pypi", "1.0alpha1", "1.0a1");
        eq("pypi", "1.0beta2", "1.0b2");
        eq("pypi", "1.0a", "1.0a0");
        eq("pypi", "1.0.post1", "1.0-1");
        eq("pypi", "1.0.post1", "1.0post1");
        eq("pypi", "1.0.post1", "1.0.rev1");
        eq("pypi", "1.0.post1", "1.0r1");
        eq("pypi", "1.0.post", "1.0.post0");
        eq("pypi", "1.0.dev1", "1.0dev1");
        eq("pypi", "1.0-dev1", "1.0.dev1");
        eq("pypi", "1.0.dev", "1.0.dev0");
        eq("pypi", "v1.0", "1.0");
        eq("pypi", "0!1.0", "1.0");
        eq("pypi", "1.0+Ubuntu.1", "1.0+ubuntu-1");
        eq("pypi", "001.002", "1.2");
    }

    #[test]
    fn pep440_order() {
        // the order from PEP 440
        let order = [
            "1.0.dev456",
            "1.0a1",
            "1.0a2.dev456",
            "1.0a12.dev456",
            "1.0a12",
            "1.0b1.dev456",
            "1.0b2",
            "1.0b2.post345.dev456",
            "1.0b2.post345",
            "1.0rc1.dev456",
            "1.0rc1",
            "1.0",
            "1.0+abc.5",
            "1.0+abc.7",
            "1.0+5",
            "1.0.post456.dev34",
            "1.0.post456",
            "1.1.dev1",
        ];
        for w in order.windows(2) {
            lt("pypi", w[0], w[1]);
        }
        lt("pypi", "1.0.9", "1.0.10");
        lt("pypi", "2.9", "2.10");
        lt("pypi", "1.0", "1.0.1");
        lt("pypi", "1.0.1.dev1", "1.0.1");
    }

    #[test]
    fn pep440_epochs() {
        lt("pypi", "2.0", "1!1.0");
        lt("pypi", "1!1.0", "2!0.1");
        eq("pypi", "0!2.0", "2.0");
        lt("pypi", "1!1.0a1", "1!1.0");
        lt("pypi", "99.0", "1!0.0.1");
    }

    #[test]
    fn pep440_local_versions() {
        lt("pypi", "1.0", "1.0+local");
        lt("pypi", "1.0+abc", "1.0+abc.1");
        lt("pypi", "1.0+abc", "1.0+5"); // numeric segments sort above alphabetic
        lt("pypi", "1.0+2", "1.0+10");
        lt("pypi", "1.0+local", "1.0.1");
        lt("pypi", "2.0.0", "2.0.0+cu118");
    }

    #[test]
    fn pep440_rejects_garbage() {
        assert_eq!(cmp("pypi", "latest", "1.0"), None);
        assert_eq!(cmp("pypi", "1.0.*", "1.0"), None);
        assert_eq!(cmp("pypi", "1.0-final", "1.0"), None);
        assert_eq!(cmp("pypi", "", "1.0"), None);
        assert_eq!(cmp("PyPI", "1.0", "1.0.0"), Some(Equal)); // ecosystem id is case-insensitive
    }

    #[test]
    fn go_versions() {
        eq("go", "v1.2.3", "1.2.3");
        eq("go", "v2.0.0+incompatible", "v2.0.0");
        eq("go", "v2.0.0+incompatible", "2.0.0");
        lt("go", "v1.2.3", "v1.10.0");
        lt("go", "v1.0.0-rc.1", "v1.0.0");
        // pseudo-versions
        lt("go", "v0.0.0-20210101000000-abcdef123456", "v0.0.0-20210201000000-abcdef123456");
        lt("go", "v0.0.0-20210101000000-abcdef123456", "v0.0.1");
        lt("go", "v1.2.4-0.20210101000000-abcdef123456", "v1.2.4");
        lt("go", "v1.2.3", "v1.2.4-0.20210101000000-abcdef123456");
        lt("go", "v1.2.4-pre.0.20210101000000-abcdef123456", "v1.2.4-pre.0.20210102000000-abcdef123456");
        lt("go", "v0.0.0-20210101000000-abcdef123456", "v1.0.0");
        eq("go", "v1.2.3+incompatible", "v1.2.3");
        assert_eq!(cmp("go", "master", "v1.0.0"), None);
        assert_eq!(cmp("golang", "v1.0.0", "1.0.1"), Some(Less));
    }

    #[test]
    fn action_refs_are_strings() {
        assert_eq!(cmp("action", "v4", "v4"), Some(Equal));
        assert_eq!(cmp("action", "v4", "main"), Some(Greater));
        assert_eq!(cmp("unknown", "a", "a"), Some(Equal));
        assert_eq!(cmp("unknown", "a", "b"), None);
        let p = pk("action", &["v4", "abc123"], &[(Some("0"), Some("v5"), None)]);
        assert!(is_affected(&p, "v4"));
        assert!(!is_affected(&p, "v3")); // ranges mean nothing for refs
        assert!(!is_affected(&p, "V4"));
    }

    #[test]
    fn exact_versions_listed() {
        let p = pk("pypi", &["2.31.0", "1.0rc1"], &[]);
        assert!(is_affected(&p, "2.31"));
        assert!(is_affected(&p, "1.0.0-rc1"));
        assert!(!is_affected(&p, "2.31.1"));
        let g = pk("go", &["1.2.2"], &[]);
        assert!(is_affected(&g, "v1.2.2"));
        let n = pk("npm", &["1.2.3"], &[]);
        assert!(!is_affected(&n, "1.2.30"));
        // unparseable but identical strings still match
        let w = pk("npm", &["weird"], &[]);
        assert!(is_affected(&w, "weird"));
        assert!(!is_affected(&w, "other"));
    }

    #[test]
    fn osv_introduced_zero_fixed() {
        let p = pk("cargo", &[], &[(Some("0"), Some("1.2.3"), None)]);
        assert!(is_affected(&p, "0.0.1"));
        assert!(is_affected(&p, "1.2.2"));
        assert!(is_affected(&p, "1.2.3-rc.1")); // a prerelease of the fix is below it
        assert!(!is_affected(&p, "1.2.3"));
        assert!(!is_affected(&p, "1.2.3+build"));
        assert!(!is_affected(&p, "2.0.0"));
        assert!(!is_affected(&p, "not a version"));
        let q = pk("cargo", &[], &[(None, Some("1.2.3"), None)]);
        assert!(is_affected(&q, "1.0.0"));
    }

    #[test]
    fn osv_introduced_and_fixed_window() {
        let p = pk("npm", &[], &[(Some("1.5.0"), Some("1.5.9"), None)]);
        assert!(!is_affected(&p, "1.4.99"));
        assert!(is_affected(&p, "1.5.0"));
        assert!(is_affected(&p, "1.5.8"));
        assert!(!is_affected(&p, "1.5.9"));
        assert!(!is_affected(&p, "1.6.0"));
        // introduced is inclusive of its prerelease boundary
        assert!(!is_affected(&p, "1.5.0-rc.1"));
    }

    #[test]
    fn osv_last_affected_is_inclusive() {
        let p = pk("pypi", &[], &[(Some("2.0"), None, Some("2.4"))]);
        assert!(is_affected(&p, "2.0"));
        assert!(is_affected(&p, "2.4.0"));
        assert!(is_affected(&p, "2.3.9"));
        assert!(!is_affected(&p, "2.4.1"));
        assert!(!is_affected(&p, "1.9"));
    }

    #[test]
    fn osv_open_ended_and_multiple_ranges() {
        let open = pk("go", &[], &[(Some("v1.3.0"), None, None)]);
        assert!(is_affected(&open, "1.3.0"));
        assert!(is_affected(&open, "v9.0.0"));
        assert!(!is_affected(&open, "v1.2.9"));
        let two = pk("npm", &[], &[(Some("0"), Some("1.2.3"), None), (Some("2.0.0"), Some("2.0.5"), None)]);
        assert!(is_affected(&two, "1.0.0"));
        assert!(!is_affected(&two, "1.9.0"));
        assert!(is_affected(&two, "2.0.4"));
        assert!(!is_affected(&two, "2.0.5"));
        // versions and ranges combine
        let mixed = pk("npm", &["3.0.0"], &[(Some("0"), Some("1.0.0"), None)]);
        assert!(is_affected(&mixed, "3.0.0"));
        assert!(is_affected(&mixed, "0.5.0"));
        assert!(!is_affected(&mixed, "2.0.0"));
    }

    #[test]
    fn osv_go_and_pypi_ranges() {
        let g = pk("go", &[], &[(Some("0"), Some("1.2.3"), None)]); // OSV Go has no v
        assert!(is_affected(&g, "v1.2.2"));
        assert!(is_affected(&g, "v0.0.0-20210101000000-abcdef123456"));
        assert!(!is_affected(&g, "v1.2.3"));
        assert!(!is_affected(&g, "v2.0.0+incompatible"));
        let y = pk("pypi", &[], &[(Some("0"), Some("2.31.0"), None)]);
        assert!(is_affected(&y, "2.30"));
        assert!(!is_affected(&y, "2.31"));
        assert!(is_affected(&y, "2.31.0rc1"));
        assert!(is_affected(&y, "2.31.0.dev1"));
        assert!(!is_affected(&y, "1!0.1")); // epoch outranks the fix
        assert!(!is_affected(&y, "2.31.0.post1"));
    }

    #[test]
    fn fixed_for_picks_the_range_containing_current() {
        let p = pk("npm", &[], &[(Some("0"), Some("1.2.3"), None), (Some("2.0.0"), Some("2.0.5"), None)]);
        assert_eq!(fixed_for(&p, "1.0.0").as_deref(), Some("1.2.3"));
        assert_eq!(fixed_for(&p, "2.0.1").as_deref(), Some("2.0.5"));
        assert_eq!(fixed_for(&p, "1.5.0"), None); // not affected
        assert_eq!(fixed_for(&p, "2.0.5"), None);
    }

    #[test]
    fn fixed_for_lowest_of_overlapping_and_chained() {
        let p = pk("cargo", &[], &[(Some("0"), Some("1.5.0"), None), (Some("1.0.0"), Some("1.2.0"), None)]);
        // 1.1.0 is in both; 1.2.0 is the lowest fix but still inside the first range, so the advice goes to 1.5.0
        assert_eq!(fixed_for(&p, "1.1.0").as_deref(), Some("1.5.0"));
        assert_eq!(fixed_for(&p, "0.5.0").as_deref(), Some("1.5.0"));
    }

    #[test]
    fn fixed_for_none_without_fix() {
        let p = pk("pypi", &[], &[(Some("1.0"), None, Some("1.9"))]);
        assert_eq!(fixed_for(&p, "1.5"), None);
        let q = pk("npm", &["1.0.0"], &[]);
        assert_eq!(fixed_for(&q, "1.0.0"), None);
        let a = pk("action", &["v1"], &[]);
        assert_eq!(fixed_for(&a, "v1"), None);
    }

    #[test]
    fn fixed_for_is_per_package_and_normalised() {
        let go = pk("go", &[], &[(Some("0"), Some("1.4.2"), None)]);
        assert_eq!(fixed_for(&go, "v1.3.0").as_deref(), Some("1.4.2"));
        let py = pk("pypi", &[], &[(Some("0"), Some("8.3.42"), None)]);
        assert_eq!(fixed_for(&py, "8.3.41").as_deref(), Some("8.3.42"));
        assert_eq!(fixed_for(&py, "8.3.42"), None);
    }
}
