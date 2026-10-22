//! Indicators: parsing, name matching, near-miss logic, text extraction, advisory lookup.

use fancy_regex::Regex as FRegex;
use regex::Regex;

use super::util::{add_days, err, norm_iso};
use super::version;
use crate::error::{BrError, BrResult};
use crate::view::{Advisory, AffectedPackage, VersionRange};

pub const ECOS: [&str; 4] = ["npm", "pypi", "cargo", "go"];
pub const SUPPORTED: &str = "npm, pypi, cargo, go, action, sha256, simhash, secret, cert, runtime";
pub const NOT_IOC_HINT: &str = "write eco:name@version, e.g. npm:lodash@4.17.21 (a bare 64-hex sha256 also works)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    Pkg,
    Sha256,
    Simhash,
    ActionRef,
    ActionSha,
    /// A secret by name (`secret:NAME`, `*` globs allowed): where it is stored and whether it was rotated.
    Secret,
    /// A certificate in a trust store, by SHA-256 fingerprint (`sha` set) or by a piece of its subject or issuer (`name` set, `sha` empty)
    Cert,
}

#[derive(Debug, Clone)]
pub struct Ioc {
    pub text: String,
    pub kind: IocKind,
    pub eco: Option<String>,
    pub name: String,
    /// None = any version; Some(empty) matches nothing.
    pub versions: Option<Vec<String>>,
    pub ref_: Option<String>,
    pub sha: String,
    pub thr: f64,
    /// Per-package truth (versions and OSV ranges) from an advisory; matching goes through version::is_affected.
    pub set: Option<AffectedPackage>,
    /// `runtime:NAME@SPEC`: the parsed spec (eco is "runtime", name the canonical runtime).
    pub rt: Option<super::runtime::RtSpec>,
}

impl Ioc {
    fn blank(text: String, kind: IocKind) -> Ioc {
        Ioc { text, kind, eco: None, name: String::new(), versions: None, ref_: None, sha: String::new(), thr: 0.9, set: None, rt: None }
    }
}

/// br's ecosystem id for an OSV/GHSA ecosystem name.
pub fn br_eco(e: &str) -> String {
    let l = e.to_lowercase();
    let base = l.split(':').next().unwrap_or(&l);
    match base {
        "crates.io" | "cargo" => "cargo",
        "golang" | "go" => "go",
        "pypi" => "pypi",
        "npm" => "npm",
        "github actions" | "actions" | "action" => "action",
        other => return other.to_string(),
    }
    .to_string()
}

fn range_label(r: &VersionRange) -> String {
    let lo = r.introduced.as_deref().filter(|x| *x != "0" && !x.is_empty());
    let mut parts = vec![];
    if let Some(l) = lo {
        parts.push(format!(">={l}"));
    }
    if let Some(f) = &r.fixed {
        parts.push(format!("<{f}"));
    } else if let Some(l) = &r.last_affected {
        parts.push(format!("<={l}"));
    }
    if parts.is_empty() {
        "*".into()
    } else {
        parts.join(" ")
    }
}

impl Ioc {
    /// An indicator for one advisory package: its own versions and ranges decide a match.
    pub fn from_package(p: &AffectedPackage) -> Option<Ioc> {
        let eco = br_eco(&p.ecosystem);
        if p.name.is_empty() || !ECOS.contains(&eco.as_str()) || (p.versions.is_empty() && p.ranges.is_empty()) {
            return None;
        }
        let mut bits: Vec<String> = p.versions.clone();
        // GHSA states a single bad version as "v up to the next patch"; that range names no other release, so the label keeps just v
        bits.extend(p.ranges.iter().filter(|r| !only_listed(r, &p.versions)).map(range_label));
        let mut i = Ioc::blank(format!("{eco}:{}@{}", p.name, bits.join(", ")), IocKind::Pkg);
        i.eco = Some(eco.clone());
        i.name = p.name.clone();
        i.versions = if p.ranges.is_empty() { Some(p.versions.clone()) } else { None };
        i.set = Some(AffectedPackage { ecosystem: eco, ..p.clone() });
        Some(i)
    }
}

/// True when a range is [v, next patch of v) for a listed v: it adds no release beyond v itself.
fn only_listed(r: &VersionRange, listed: &[String]) -> bool {
    let (Some(i), Some(f), None) = (r.introduced.as_deref(), r.fixed.as_deref(), r.last_affected.as_deref()) else { return false };
    if !listed.iter().any(|v| v == i) {
        return false;
    }
    let parts = |s: &str| -> Option<(String, u64)> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let (head, patch) = s.rsplit_once('.')?;
        (head.split('.').count() == 2 && head.split('.').all(|x| x.parse::<u64>().is_ok())).then_some(())?;
        Some((head.to_string(), patch.parse().ok()?))
    };
    matches!((parts(i), parts(f)), (Some((hi, pi)), Some((hf, pf))) if hi == hf && pf == pi + 1)
}

pub type Lookup<'a> = &'a dyn Fn(&str, &str) -> Vec<String>;

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn rx(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

fn frx(p: &str) -> FRegex {
    FRegex::new(p).unwrap()
}

fn bare(s: &str, lookup: Option<Lookup>) -> BrResult<Option<String>> {
    if s.len() == 64 && is_hex(s) {
        return Ok(Some(format!("sha256:{}", s.to_lowercase())));
    }
    if let Some(l) = lookup {
        if (12..64).contains(&s.len()) && is_hex(s) && !l(&s.to_lowercase(), "sha256-prefix").is_empty() {
            return Ok(Some(format!("sha256:{}", s.to_lowercase())));
        }
    }
    if rx(r"^@[\w.\-]+/[\w.\-]+(@[\w.\-+,]+)?$").is_match(s) {
        return Ok(Some(format!("npm:{s}")));
    }
    if let Some(m) = rx(r"^([^\s@:]+)@([\w.\-+,]+)$").captures(s) {
        if let Some(l) = lookup {
            let ecos = l(&m[1], &m[2]);
            if ecos.len() == 1 {
                err(&format!("note: {s} read as {}:{s} (the only ecosystem in the index with that name)", ecos[0]));
                return Ok(Some(format!("{}:{s}", ecos[0])));
            }
            if ecos.len() > 1 {
                let say: Vec<String> = ecos.iter().map(|e| format!("{e}:{s}")).collect();
                return Err(BrError::new(format!("\"{s}\" matches more than one ecosystem in the index: {}", ecos.join(", ")), Some(&format!("say which: {}", say.join(" or ")))));
            }
            return Err(BrError::new(format!("\"{s}\" is not an indicator and no indexed package has that name"), Some(NOT_IOC_HINT)));
        }
    }
    Ok(None)
}

pub fn parse_ioc(s: &str, lookup: Option<Lookup>) -> BrResult<Ioc> {
    let mut s = s.trim().to_string();
    // a certificate fingerprint written as openssl prints it (AA:BB:...) stands for cert:AA:BB:...
    if crate::parse::x509::colon_fingerprint(&s).is_some() {
        s = format!("cert:{s}");
    }
    if !s.contains(':') {
        match bare(&s, lookup)? {
            Some(full) => s = full,
            None => return Err(BrError::new(format!("\"{s}\" is not an indicator"), Some(NOT_IOC_HINT))),
        }
    }
    let (eco, rest) = s.split_once(':').unwrap();
    let eco = eco.to_lowercase();
    let rest = rest.to_string();
    if eco == "sha256" {
        let h = rest.to_lowercase();
        if let Some(l) = lookup {
            if (12..64).contains(&h.len()) && is_hex(&h) {
                let full = l(&h, "sha256-prefix");
                if full.len() == 1 {
                    err(&format!("note: sha256:{h} read as sha256:{} (the only indexed file with that prefix)", full[0]));
                    let mut i = Ioc::blank(format!("sha256:{}", full[0]), IocKind::Sha256);
                    i.sha = full[0].clone();
                    return Ok(i);
                }
                if full.len() > 1 {
                    let more: Vec<String> = full.iter().take(3).map(|x| x.chars().take(20).collect()).collect();
                    return Err(BrError::new(format!("sha256:{h} starts {} different files in the index", full.len()), Some(&format!("use more digits: {}", more.join(", ")))));
                }
                return Err(BrError::new(format!("no indexed file has a sha256 starting sha256:{h}"), Some("check the hash, or give all 64 hex digits to hunt for a file the index has not seen")));
            }
        }
        if h.len() != 64 || !is_hex(&h) {
            return Err(BrError::new(format!("sha256 must be 64 hex characters (got {})", rest.chars().count()), Some(&format!("example: sha256:{}", "ab".repeat(32)))));
        }
        let mut i = Ioc::blank(format!("sha256:{h}"), IocKind::Sha256);
        i.sha = h;
        return Ok(i);
    }
    if eco == "cert" {
        if let Some(sub) = rest.strip_prefix("subject:").or_else(|| rest.strip_prefix("SUBJECT:")).or_else(|| rest.strip_prefix("Subject:")) {
            let t = sub.trim();
            if t.is_empty() {
                return Err(BrError::new("cert:subject: needs some text of the certificate's subject or issuer", Some("example: cert:subject:Example Root CA")));
            }
            let mut i = Ioc::blank(format!("cert:subject:{t}"), IocKind::Cert);
            i.name = t.to_lowercase();
            return Ok(i);
        }
        let h = crate::parse::x509::normalize_fp(&rest).unwrap_or_default();
        if h.len() != 64 || !is_hex(&h) {
            return Err(BrError::new(
                format!("a certificate fingerprint is the SHA-256 of the certificate: 64 hex characters, colons allowed (got {})", rest.chars().filter(|c| c.is_ascii_hexdigit()).count()),
                Some(&format!("example: cert:{}  or  cert:subject:Example Root CA", "ab".repeat(32))),
            ));
        }
        let mut i = Ioc::blank(format!("cert:{h}"), IocKind::Cert);
        i.sha = h;
        return Ok(i);
    }
    if eco == "simhash" {
        let (h, t) = match rest.split_once('~') {
            Some((h, t)) => (h.to_string(), t.to_string()),
            None => (rest.clone(), String::new()),
        };
        if h.chars().count() != 16 || !is_hex(&h) {
            return Err(BrError::new(format!("simhash must be 16 hex characters (got {})", h.chars().count()), Some("example: simhash:9f3ac6e1d2047b58~0.90")));
        }
        let thr = if t.is_empty() {
            0.90
        } else {
            t.trim().parse::<f64>().map_err(|_| BrError::new(format!("\"{t}\" is not a similarity threshold"), Some("write a number between 0 and 1, e.g. ~0.90")))?
        };
        let mut i = Ioc::blank(format!("simhash:{}~{:.2}", h.to_lowercase(), thr), IocKind::Simhash);
        i.sha = h.to_lowercase();
        i.thr = thr;
        return Ok(i);
    }
    if eco == "secret" {
        let name = rest.trim().to_uppercase();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '*') {
            return Err(BrError::new(
                format!("\"{s}\" is not a secret name"),
                Some("write secret:NAME with letters, digits and _, and * for any run of characters, e.g. secret:DEPLOY_TOKEN or secret:DEPLOY_*"),
            ));
        }
        let mut i = Ioc::blank(format!("secret:{name}"), IocKind::Secret);
        i.name = name;
        return Ok(i);
    }
    if eco == "action" {
        if let Some((name, sha)) = rest.split_once('#') {
            if sha.chars().count() != 40 || !is_hex(sha) {
                return Err(BrError::new(format!("action commit must be 40 hex characters (got {})", sha.chars().count()), Some("example: action:owner/repo#<40 hex>")));
            }
            let mut i = Ioc::blank(format!("action:{name}#{}", sha.to_lowercase()), IocKind::ActionSha);
            i.eco = Some("action".into());
            i.name = name.to_string();
            i.sha = sha.to_lowercase();
            return Ok(i);
        }
        let (name, ref_) = match rest.rfind('@') {
            Some(p) => (rest[..p].to_string(), rest[p + 1..].to_string()),
            None => (rest.clone(), String::new()),
        };
        let text = format!("action:{name}{}", if ref_.is_empty() { String::new() } else { format!("@{ref_}") });
        let mut i = Ioc::blank(text, IocKind::ActionRef);
        i.eco = Some("action".into());
        i.name = name;
        i.ref_ = if ref_.is_empty() { None } else { Some(ref_) };
        return Ok(i);
    }
    if eco == "runtime" {
        let (n, spec) = match rest.split_once('@') {
            Some((n, sp)) => (n, sp),
            None => (rest.as_str(), ""),
        };
        let Some(r) = super::runtime::lookup(n) else {
            return Err(BrError::new(format!("unknown runtime \"{n}\""), Some(&format!("runtime names: {}", super::runtime::names()))));
        };
        let sp = super::runtime::parse_spec(spec).map_err(|e| {
            BrError::new(
                format!("\"{s}\": {e}"),
                Some(&format!("write runtime:{0}@8.3.20, a range like runtime:{0}@\">=8.3.0,<8.3.36\", or runtime:{0}@fixed:V1,V2 (one fixed release per line)", r.name)),
            )
        })?;
        let text = if spec.trim().is_empty() { format!("runtime:{}", r.name) } else { format!("runtime:{}@{}", r.name, spec.trim()) };
        let mut i = Ioc::blank(text, IocKind::Pkg);
        i.eco = Some("runtime".into());
        i.name = r.name.into();
        i.rt = Some(sp);
        return Ok(i);
    }
    if !ECOS.contains(&eco.as_str()) {
        return Err(BrError::new(format!("unknown ecosystem \"{eco}\""), Some(&format!("supported: {SUPPORTED}"))));
    }
    let (name, vers) = match rest.rfind('@') {
        Some(p) if p > 0 => (rest[..p].to_string(), Some(rest[p + 1..].split(',').filter(|v| !v.is_empty()).map(str::to_string).collect::<Vec<_>>())),
        _ => (rest.clone(), None),
    };
    if name.is_empty() {
        return Err(BrError::new(format!("\"{s}\" is not an indicator"), Some(NOT_IOC_HINT)));
    }
    if matches!(&vers, Some(v) if v.is_empty()) {
        return Err(BrError::new(
            format!("\"{s}\" names no version after the @"),
            Some(&format!("write {eco}:{name}@1.2.3, a range like {eco}:{name}@\">=1.0.0,<1.2.3\", or drop the @ for any version")),
        ));
    }
    if let Some(v) = &vers {
        if v.iter().any(|x| x.starts_with(['<', '>'])) {
            let mut r = VersionRange::default();
            let mut exact = vec![];
            for x in v {
                if let Some(b) = x.strip_prefix(">=") {
                    r.introduced = Some(b.trim().to_string());
                } else if let Some(b) = x.strip_prefix('>') {
                    r.introduced = Some(b.trim().to_string());
                } else if let Some(b) = x.strip_prefix("<=") {
                    r.last_affected = Some(b.trim().to_string());
                } else if let Some(b) = x.strip_prefix('<') {
                    r.fixed = Some(b.trim().to_string());
                } else {
                    exact.push(x.clone());
                }
            }
            let p = AffectedPackage { ecosystem: eco.clone(), name: name.clone(), versions: exact, ranges: vec![r] };
            let mut i = Ioc::from_package(&p).unwrap_or_else(|| Ioc::blank(format!("{eco}:{name}"), IocKind::Pkg));
            i.text = format!("{eco}:{name}@{}", v.join(","));
            return Ok(i);
        }
    }
    let text = format!(
        "{eco}:{name}{}",
        match &vers {
            Some(v) if !v.is_empty() => format!("@{}", v.join(",")),
            _ => String::new(),
        }
    );
    let mut i = Ioc::blank(text, IocKind::Pkg);
    i.eco = Some(eco);
    i.name = name;
    i.versions = vers;
    Ok(i)
}

/// Does a secret name match a pattern whose `*` stands for any run of characters? Names compare without case,
/// as GitHub keeps them upper case.
pub fn glob_match(pat: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pat.to_uppercase().chars().collect(), name.to_uppercase().chars().collect());
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn name_key(eco: &str, name: &str) -> String {
    match eco {
        "pypi" => rx(r"[-_.]+").replace_all(name, "-").to_lowercase(),
        "cargo" => name.replace('_', "-").to_lowercase(),
        "action" => name.to_lowercase(),
        _ => name.to_string(),
    }
}

pub fn match_pkg(ioc: &Ioc, eco: &str, name: &str, version: &str) -> bool {
    if ioc.kind != IocKind::Pkg || ioc.eco.as_deref() != Some(eco) || name_key(eco, name) != name_key(eco, &ioc.name) {
        return false;
    }
    if let Some(sp) = &ioc.rt {
        return super::runtime::lookup(name).is_some_and(|r| sp.eval(version, r.line_depth).is_some());
    }
    if let Some(set) = &ioc.set {
        return version::is_affected(set, version);
    }
    match &ioc.versions {
        None => true,
        Some(v) => v.iter().any(|x| version::same(eco, x, version)),
    }
}

fn tokens(s: &str) -> Vec<String> {
    rx(r"[^a-z0-9]+").split(&s.to_lowercase()).filter(|t| !t.is_empty()).map(str::to_string).collect()
}

fn contains(seq: &[String], sub: &[String]) -> bool {
    let n = sub.len();
    n > 0 && seq.len() >= n && (0..=seq.len() - n).any(|i| seq[i..i + n] == *sub)
}

fn last_seg(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// Reason a package nearly matches the indicator, or None.
pub fn near_pkg(ioc: &Ioc, eco: &str, name: &str, version: &str) -> Option<&'static str> {
    if ioc.kind != IocKind::Pkg || Some(eco) != ioc.eco.as_deref() {
        return None;
    }
    if name_key(eco, name) == name_key(eco, &ioc.name) {
        let listed: Vec<&String> = ioc.versions.iter().flatten().chain(ioc.set.iter().flat_map(|s| s.versions.iter())).collect();
        for v in listed {
            if version != v && version.starts_with(v.as_str()) {
                let c = version[v.len()..].chars().next();
                if c == Some('-') || c == Some('+') {
                    return Some("prerelease or build suffix on the same version");
                }
            }
        }
        return None;
    }
    if eco == "go" {
        let strip = |n: &str| rx(r"/v\d+$").replace(n, "").to_string();
        if strip(name) == strip(&ioc.name) && name != ioc.name {
            return Some("different module path (a /vN suffix is another module)");
        }
        return None;
    }
    if let Some(set) = &ioc.set {
        if !version::is_affected(set, version) {
            return None;
        }
    } else if let Some(v) = &ioc.versions {
        if !v.is_empty() && !v.iter().any(|x| version::same(eco, x, version)) {
            return None;
        }
    }
    if contains(&tokens(name), &tokens(last_seg(&ioc.name))) {
        return Some("different package: name differs by prefix, scope or separator");
    }
    None
}

/// 'octofix/changed-files@v44' -> ('octofix/changed-files', 'v44').
pub fn split_use(uses: &str) -> (String, String) {
    match uses.rfind('@') {
        Some(p) => (uses[..p].to_string(), uses[p + 1..].to_string()),
        None => (uses.to_string(), String::new()),
    }
}

pub fn is_sha(r: &str) -> bool {
    r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit())
}

/// Does a workflow's `uses:` name (possibly `owner/repo/sub/action` or a reusable workflow path) belong to the indicator's
/// action (`owner/repo`)? Names compare case-insensitively; a deeper path is a sub-action of the same repo.
pub fn action_name_matches(ioc_name: &str, use_name: &str) -> bool {
    let (a, b) = (ioc_name.trim_end_matches('/').to_lowercase(), use_name.to_lowercase());
    b == a || b.starts_with(&format!("{a}/"))
}

/// An indicator ref of None matches any ref.
pub fn action_ref_matches(ioc: &Ioc, r: &str) -> bool {
    match ioc.ref_.as_deref() {
        None | Some("") => true,
        Some(x) => x == r,
    }
}

pub fn action_kind(r: &str, path: Option<&str>) -> &'static str {
    if let Some(p) = path {
        if p.ends_with("action.yml") || p.ends_with("action.yaml") {
            return "composite step";
        }
    }
    if is_sha(r) {
        return "pinned sha";
    }
    if rx(r"^[vV]?\d+(\.\d+)*([-+._][\w.\-]*)?$").is_match(r) {
        return "mutable tag";
    }
    // without the repo's real refs a name like "stable" could be either
    if matches!(r.to_lowercase().as_str(), "main" | "master" | "develop" | "dev" | "trunk" | "head") || r.contains('/') {
        return "branch";
    }
    "tag or branch"
}

pub fn action_near(ioc: &Ioc, uses: &str) -> Option<&'static str> {
    if !matches!(ioc.kind, IocKind::ActionRef | IocKind::ActionSha) {
        return None;
    }
    let (name, r) = split_use(uses);
    if action_name_matches(&ioc.name, &name) {
        if ioc.kind == IocKind::ActionRef && ioc.ref_.is_some() && is_sha(&r) {
            return Some("pinned to a full commit, not the tag");
        }
        return None;
    }
    if contains(&tokens(&name), &tokens(last_seg(&ioc.name))) {
        return Some("different action: name differs by owner or suffix");
    }
    None
}

// ---- text extraction ---------------------------------------------------------------------------
/// The words advisories use for an ecosystem (lowercase) and br's id for it. An empty id is an ecosystem br knows by name
/// but cannot match (a mention of one is reported, never dropped). The OSV ecosystem names are among them.
const ECO_WORDS: &[(&str, &str)] = &[
    ("crates.io", "cargo"),
    ("rubygems", ""),
    ("ruby gem", ""),
    ("ruby gems", ""),
    ("go modules", "go"),
    ("go module", "go"),
    ("golang", "go"),
    ("github actions", "action"),
    ("github action", "action"),
    ("packagist", ""),
    ("composer", ""),
    ("nuget", ""),
    ("maven", ""),
    ("hackage", ""),
    ("cocoapods", ""),
    ("pypi", "pypi"),
    ("pip", "pypi"),
    ("npm", "npm"),
    ("cargo", "cargo"),
    ("crates", "cargo"),
    ("crate", "cargo"),
    ("gems", ""),
    ("gem", ""),
    ("go", "go"),
];

/// Words that sit between an ecosystem word and a name ("PyPI package X", "npm install X", "Go module X").
const NOUNS: &[&str] =
    &["packages", "package", "modules", "module", "crates", "crate", "libraries", "library", "distribution", "release", "install", "add", "get", "i", "named", "called", "dependency"];

/// Ordinary words that are never a package name, so "npm packages" or "the PyPI registry" is not a mention.
const NOT_NAMES: &[&str] = &[
    "the",
    "a",
    "an",
    "and",
    "or",
    "of",
    "in",
    "on",
    "to",
    "for",
    "with",
    "from",
    "by",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "this",
    "that",
    "these",
    "those",
    "it",
    "its",
    "registry",
    "registries",
    "ecosystem",
    "ecosystems",
    "project",
    "projects",
    "users",
    "user",
    "versions",
    "version",
    "releases",
    "publish",
    "published",
    "installs",
    "installed",
    "using",
    "used",
    "uses",
    "dependencies",
    "maintainers",
    "maintainer",
    "account",
    "accounts",
    "token",
    "tokens",
    "malicious",
    "compromised",
    "affected",
    "also",
    "as",
    "at",
    "all",
    "any",
    "both",
    "here",
    "there",
    "such",
    "other",
    "more",
    "not",
    "no",
    "which",
    "who",
    "has",
    "have",
    "had",
    "will",
    "would",
    "can",
    "could",
    "may",
    "might",
    "if",
    "when",
    "while",
    "after",
    "before",
    "then",
    "than",
    "so",
    "but",
    "only",
    "one",
    "two",
    "three",
    "four",
    "five",
    "some",
    "many",
    "several",
    "each",
    "every",
    "side",
    "ahead",
    "back",
    "live",
    "now",
    "out",
    "up",
    "off",
    "over",
    "into",
    "via",
    "per",
    "advisory",
    "advisories",
];

fn eco_alternation() -> String {
    let mut w: Vec<&str> = ECO_WORDS.iter().map(|(w, _)| *w).collect();
    w.sort_by_key(|x| std::cmp::Reverse(x.len()));
    w.iter().map(|x| fancy_regex::escape(x).replace(' ', r"\s+")).collect::<Vec<_>>().join("|")
}

/// Does `name` follow the ecosystem's own naming rules?
fn name_ok(eco: &str, name: &str) -> bool {
    let m = |p: &str| Regex::new(p).unwrap().is_match(name);
    match eco {
        "npm" => m(r"^(@[a-z0-9][a-z0-9._~\-]*/[a-z0-9][a-z0-9._~\-]*|[a-z0-9][a-z0-9._~\-]*)$"),
        "pypi" => m(r"^[A-Za-z0-9][A-Za-z0-9._\-]*$"),
        "cargo" => m(r"^[A-Za-z0-9][A-Za-z0-9_\-]*$"),
        "go" => m(r"^[A-Za-z0-9][\w.\-~]*\.[\w.\-~]+(/[\w.\-~]+)+$"),
        "action" => m(r"^[\w.\-]+/[\w.\-]+(/[\w.\-/]+)?$"),
        _ => m(r"^[@\w][\w.\-/~]*$"),
    }
}

/// The result of reading advisory prose.
#[derive(Debug, Default, Clone)]
pub struct Extracted {
    pub iocs: Vec<String>,
    pub window: Option<(String, String)>,
    /// packages the prose mentions that were not read, as written ("PyPI foo")
    pub unread: Vec<String>,
    /// distinct package mentions found (read or not)
    pub mentions: usize,
    /// (sha256 indicator, file name) pairs the prose ties together
    pub hash_names: Vec<(String, String)>,
    /// (ecosystem, package name, fixed version) the prose gives: "fixed in X" / "upgrade to X" in the sentence of the
    /// package, else in its paragraph when the paragraph names one fixed version
    pub fixed: Vec<(String, String, String)>,
    /// Advisory ids the prose names (GHSA-, MAL-, CVE-, ...), as OSV writes them
    pub advisory_ids: Vec<String>,
}

/// The id shapes OSV serves: one row per id family.
const ADVISORY_ID_FAMILIES: &[&str] = &["MAL", "CVE", "GO", "PYSEC", "RUSTSEC", "OSV"];

/// Advisory ids in prose, normalised the way OSV writes them (GHSA-xxxx-xxxx-xxxx lowercase after the prefix, the others upper).
pub fn advisory_ids_in(text: &str) -> Vec<String> {
    let re = Regex::new(&format!(r"(?i)\b(GHSA-[0-9a-z]{{4}}-[0-9a-z]{{4}}-[0-9a-z]{{4}}|(?:{})-\d{{4}}-\d{{3,}})\b", ADVISORY_ID_FAMILIES.join("|"))).unwrap();
    let mut out: Vec<String> = vec![];
    for m in re.captures_iter(text) {
        let raw = &m[1];
        let id = if raw.len() > 4 && raw[..4].eq_ignore_ascii_case("GHSA") { format!("GHSA-{}", raw[5..].to_lowercase()) } else { raw.to_uppercase() };
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// Every sha256 in the text, as `sha256:HEX` (lowercase).
pub fn text_hashes(text: &str) -> Vec<String> {
    let sha_re = frx(r"(?<![0-9a-fA-F])(?:sha256:)?([0-9a-fA-F]{64})(?![0-9a-fA-F])");
    let mut out: Vec<String> = vec![];
    for m in sha_re.captures_iter(text).flatten() {
        let h = format!("sha256:{}", m[1].to_lowercase());
        if !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// Every certificate fingerprint written in colon-hex (the way openssl and browsers print it), as `cert:HEX` (lowercase).
pub fn text_cert_fingerprints(text: &str) -> Vec<String> {
    let re = frx(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}(?![0-9a-fA-F:])");
    let mut out: Vec<String> = vec![];
    for m in re.find_iter(text).flatten() {
        let h = format!("cert:{}", crate::parse::x509::normalize_fp(m.as_str()).unwrap_or_default());
        if !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// File extensions that make a word in prose a file name (executables, scripts, archives, libraries, configs), one row
/// per kind of file. A table of formats, never of names.
const FILE_EXTS: &[&str] = &[
    "exe", "dll", "so", "dylib", "sys", "node", "bin", "elf", "apk", "msi", "dmg", "pkg", "deb", "rpm", "jar", "class", "wasm", "sh", "bash", "zsh", "ps1", "bat", "cmd", "vbs", "hta", "lnk", "js",
    "mjs", "cjs", "ts", "py", "pyc", "pyd", "rb", "pl", "php", "lua", "zip", "tgz", "gz", "tar", "whl", "egg", "iso", "img", "json", "yml", "yaml", "ini", "conf", "cfg", "plist", "service", "scr",
    "dat", "tmp", "log", "txt",
];

/// Words that point at the file name that follows ("the binary netprobe-linux-amd64", "a file named x.js").
const FILE_CUES: &str = r"file|filename|binary|executable|payload|dropper|script|library|artifact|implant|loader|installer|archive|named|called";

/// Words a file-name candidate is never.
const NOT_A_NAME: &[&str] = &[
    "sha-256", "sha-1", "sha1", "sha512", "sha-512", "md5", "checksum", "is", "was", "the", "this", "that", "with", "has", "and", "for", "its", "are", "hash", "sha256", "named", "called", "a", "an",
];

fn plausible_file_name(t: &str) -> bool {
    let t = t.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.' && c != '-' && c != '/' && c != '\\');
    let b = t.rsplit(['/', '\\']).next().unwrap_or(t);
    b.len() >= 3
        && b.chars().any(|c| c.is_alphabetic())
        && !NOT_A_NAME.contains(&b.to_lowercase().as_str())
        && !(b.len() >= 32 && b.chars().all(|c| c.is_ascii_hexdigit()))
        && !b.contains(':')
        && !b.contains('@')
        && !b.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// The file-name candidates in one sentence or line with their offsets: a word in backticks or quotes, a word with a
/// file extension, a path (its last segment), or a word that follows a cue like "binary" or "named".
fn file_names_in(seg: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = vec![];
    let mut add = |at: usize, t: &str| {
        let t = t.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.' && c != '-' && c != '/' && c != '\\');
        if plausible_file_name(t) {
            let b = t.rsplit(['/', '\\']).next().unwrap_or(t).to_string();
            if !out.iter().any(|o| o.1 == b) {
                out.push((at, b));
            }
        }
    };
    let quoted = frx(r#"[`"']([^`"'\s]{3,})[`"']"#);
    for c in quoted.captures_iter(seg).flatten() {
        if let Some(m) = c.get(1) {
            let t = m.as_str();
            let ext = t.rsplit_once('.').map(|(_, e)| e.to_lowercase());
            // a quoted word is a name when it looks like one: an extension, a path, or a dash or underscore
            if ext.is_some_and(|e| FILE_EXTS.contains(&e.as_str())) || t.contains('/') || t.contains('-') || t.contains('_') {
                add(m.start(), t);
            }
        }
    }
    let cue = frx(&format!(r"(?i)\b(?:{FILE_CUES})\s+(?:(?:named|called)\s+)?([A-Za-z0-9_][\w.+\-]*[\-_.0-9][\w.+\-]*)"));
    for c in cue.captures_iter(seg).flatten() {
        if let Some(m) = c.get(1) {
            add(m.start(), m.as_str());
        }
    }
    // a name written right beside a hash, as in a table row or `name: sha256 ...`
    let beside = frx(r"([A-Za-z0-9_][\w.+\-]*[\-_.][\w.+\-]*)\s*[:=|,(\[]*\s*(?:sha-?256\s*[:=]?\s*)?\x01|\x01\s*[:=|,)\]]*\s*([A-Za-z0-9_][\w.+\-]*[\-_.][\w.+\-]*)");
    for c in beside.captures_iter(seg).flatten() {
        if let Some(m) = c.get(1).or_else(|| c.get(2)) {
            add(m.start(), m.as_str());
        }
    }
    let word = frx(r"[A-Za-z0-9_./\\~][\w.+\-/\\~]*");
    for m in word.find_iter(seg).flatten() {
        let t = m.as_str().trim_end_matches(['.', ',', ';']);
        if let Some((_, e)) = t.rsplit_once('.') {
            if FILE_EXTS.contains(&e.to_lowercase().as_str()) {
                add(m.start(), t);
            }
        }
    }
    out
}

/// The file name a sentence or line of prose ties to each sha256 in it: the nearest file name in the same sentence
/// or on the same line. Returns (`sha256:HEX`, name).
pub fn text_hash_ties(text: &str) -> Vec<(String, String)> {
    let split = frx(r"(?<=[.!?])\s+(?=[A-Z@`])");
    let sha_re = frx(r"(?<![0-9a-fA-F])(?:sha256:)?([0-9a-fA-F]{64})(?![0-9a-fA-F])");
    let mut out: Vec<(String, String)> = vec![];
    for line in text.split('\n') {
        let mut segs: Vec<&str> = vec![];
        let mut last = 0;
        for m in split.find_iter(line).flatten() {
            segs.push(&line[last..m.start()]);
            last = m.end();
        }
        segs.push(&line[last..]);
        for seg in segs {
            let found: Vec<String> = sha_re.captures_iter(seg).flatten().filter_map(|c| c.get(1).map(|m| format!("sha256:{}", m.as_str().to_lowercase()))).collect();
            if found.is_empty() {
                continue;
            }
            // each hash becomes one marker character, so a name beside it can be found by position
            let scrubbed = sha_re.replace_all(seg, "\u{1}").to_string();
            let marks: Vec<usize> = scrubbed.match_indices('\u{1}').map(|(i, _)| i).collect();
            let names = file_names_in(&scrubbed);
            for (h, at) in found.iter().zip(marks.iter()) {
                if let Some((_, n)) = names.iter().min_by_key(|(a, n)| if *at < *a { *a - *at } else { at.saturating_sub(a + n.len()) }) {
                    if !out.contains(&(h.clone(), n.clone())) {
                        out.push((h.clone(), n.clone()));
                    }
                }
            }
        }
    }
    out
}

/// Returns (indicator strings, window).
pub fn extract_text(text: &str) -> BrResult<(Vec<String>, Option<(String, String)>)> {
    let e = extract_prose(text)?;
    Ok((e.iocs, e.window))
}

type Mentions = Vec<(String, String, bool)>;

/// Record a package mention once: key (eco:name), the words as written, and whether an indicator came of it.
fn note_mention(ms: &mut Mentions, key: String, label: String, read: bool) {
    match ms.iter_mut().find(|m| m.0 == key) {
        Some(m) => m.2 |= read,
        None => ms.push((key, label, read)),
    }
}

/// Read advisory prose: hashes, `eco:name@version` forms, scoped npm names, and a package mentioned in words (an ecosystem
/// word, a name and a version in the same sentence). A mention that did not resolve is listed in `unread`, never dropped.
pub fn extract_prose(text: &str) -> BrResult<Extracted> {
    let fix = frx(r"(?i)\b(upgrade|update|bump|fixed|patched|fix)\b[^.]*?\bv?\d+\.\d+(?:\.\d+)*[\w.\-]*");
    let ver = frx(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)*(?:(?:[-+.]?(?:a|b|rc|post|dev)\d*)|(?:[-+][\w.]+))*)(?![\w])");
    let name_re = frx(r"(?<![\w@/])(@[a-z0-9][\w.\-]*/[a-z0-9][\w.\-]*)");
    let eco_re = frx(r"(?i)\b(npm|pypi|cargo|go):(@?[\w.\-/]+?)(?:@(v?[\w.\-,]+))?(?=[\s,;)]|$)");
    let split_re = frx(r"(?<=[.!?])\s+(?=[A-Z@])|\n+|;\s*|,?\s+but\s+");
    let unaffected = frx(r"\bnot affected\b|\bunaffected\b|\bnot impacted\b|\bis safe\b");
    let date_start = rx(r"^\d{4}-\d\d-\d\d");
    let word_re = frx(&format!(r"(?i)(?<![\w.\-/@:])({})(?![\w\-/@:])\s+((?:(?:{})\s+)*)(@?[A-Za-z0-9_][\w.\-/~]*)", eco_alternation(), NOUNS.join("|")));
    let attached = frx(r"^(?:@|===?|~=|\s+versions?\s+|\s*\(\s*|\s+)v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.\-+]*)");
    // "1.0.0, 1.1.0 and 2.0.0": more versions of the same name follow the first
    let more = frx(r"^\s*(?:,\s*(?:and\s+|or\s+)?|\s+and\s+|\s+or\s+|\s*&\s*)v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.\-+]*)");

    let mut iocs: Vec<String> = Vec::new();
    let add = |s: String, iocs: &mut Vec<String>| {
        if !iocs.contains(&s) {
            iocs.push(s);
        }
    };
    let mut mentions: Mentions = vec![];
    for h in text_hashes(text) {
        add(h, &mut iocs);
    }
    for h in text_cert_fingerprints(text) {
        add(h, &mut iocs);
    }
    // A fixed version is read from the sentence of the package, else from its paragraph (only when the paragraph names one)
    let fix_cap = frx(r"(?i)\b(?:upgrade|update|bump|fixed|patched|fix)\b[^.]*?\bv?(\d+\.\d+(?:\.\d+)*[\w.\-]*)");
    let para_breaks: Vec<usize> = rx(r"\n[ \t]*\n").find_iter(text).map(|m| m.start()).collect();
    let mut para_fix: std::collections::BTreeMap<usize, Vec<String>> = Default::default();
    let mut pending: Vec<(usize, Option<String>, Vec<(String, String)>)> = vec![];
    // re.split
    let mut sents: Vec<&str> = Vec::new();
    let mut last = 0;
    for m in split_re.find_iter(text).flatten() {
        sents.push(&text[last..m.start()]);
        last = m.end();
    }
    sents.push(&text[last..]);
    for sent in sents {
        let low = sent.to_lowercase();
        if unaffected.is_match(&low).unwrap_or(false) {
            continue;
        }
        let scrubbed = fix.replace_all(sent, " ").to_string();
        let para = {
            let at = (sent.as_ptr() as usize).saturating_sub(text.as_ptr() as usize);
            para_breaks.iter().filter(|b| **b < at).count()
        };
        let mut sent_fixes: Vec<String> = vec![];
        for c in fix_cap.captures_iter(sent).flatten() {
            let v = c[1].trim_end_matches(['.', ',', '-']).to_string();
            if !v.is_empty() && !sent_fixes.contains(&v) {
                sent_fixes.push(v);
            }
        }
        for v in &sent_fixes {
            let e = para_fix.entry(para).or_default();
            if !e.contains(v) {
                e.push(v.clone());
            }
        }
        // a sentence that names two different fixes does not say which belongs to which package
        let sent_fix: Option<String> = if sent_fixes.len() == 1 { sent_fixes.first().cloned() } else { None };
        let mut sent_keys: Vec<(String, String)> = vec![];
        let mut versions: Vec<String> = Vec::new();
        for m in ver.captures_iter(&scrubbed).flatten() {
            let v = m[1].to_string();
            if !date_start.is_match(&v) && !versions.contains(&v) {
                versions.push(v);
            }
        }
        let mut found = false;
        for m in eco_re.captures_iter(sent).flatten() {
            let ver_part = m.get(3).map(|x| format!("@{}", x.as_str())).unwrap_or_default();
            let e = m[1].to_lowercase();
            add(format!("{}:{}{}", e, &m[2], ver_part), &mut iocs);
            sent_keys.push((e.clone(), m[2].to_string()));
            note_mention(&mut mentions, format!("{e}:{}", m[2].to_lowercase()), m[0].to_string(), true);
            found = true;
        }
        // a package in words: an ecosystem word, then a name, then a version in the same sentence. A version written
        // right after a name belongs to that name; a version nobody claimed is shared by the names without one.
        struct Cand {
            word: String,
            eco: &'static str,
            name: String,
            lname: String,
            label_word: String,
            attached: Option<Vec<String>>,
        }
        let mut cands: Vec<Cand> = vec![];
        for m in word_re.captures_iter(&scrubbed).flatten() {
            let (Some(w), Some(raw)) = (m.get(1), m.get(3)) else { continue };
            let nouns = m.get(2).map(|x| x.as_str()).unwrap_or("");
            let word = w.as_str().to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
            let Some(&(_, eco)) = ECO_WORDS.iter().find(|(x, _)| *x == word) else { continue };
            let mut name = raw.as_str().trim_end_matches(['.', '-', '/', '~']).to_string();
            let lname = name.to_lowercase();
            if name.is_empty() || NOT_NAMES.contains(&lname.as_str()) || NOUNS.contains(&lname.as_str()) {
                continue;
            }
            let after = &scrubbed[raw.start() + name.len()..];
            let attached_v = attached.captures(after).ok().flatten().map(|c| {
                let mut vs = vec![c[1].trim_end_matches(['.', ',']).to_string()];
                let mut at = c.get(0).map(|m| m.end()).unwrap_or(0);
                while let Some(n) = more.captures(&after[at..]).ok().flatten() {
                    let v = n[1].trim_end_matches(['.', ',']).to_string();
                    if !vs.contains(&v) {
                        vs.push(v);
                    }
                    at += n.get(0).map(|m| m.end()).unwrap_or(0);
                }
                vs
            });
            // the bare word "go" is a verb unless a module path follows; "pip" needs "install" or a version beside the name
            if word == "go" && !(name.contains('/') && name.contains('.')) {
                continue;
            }
            if word == "pip" && nouns.is_empty() && versions.is_empty() && !after.starts_with(['=', '@']) {
                continue;
            }
            if eco == "go" || eco == "action" {
                name = name.trim_end_matches(".git").to_string();
            }
            if !name_ok(eco, &name) && !name_ok(eco, &lname) {
                continue;
            }
            cands.push(Cand { word, eco, lname, name, label_word: w.as_str().to_string(), attached: attached_v });
        }
        let claimed: Vec<&String> = cands.iter().filter_map(|c| c.attached.as_ref()).flatten().collect();
        let spare: Vec<String> = versions.iter().filter(|v| !claimed.contains(v)).cloned().collect();
        for c in &cands {
            let vs: Vec<String> = match &c.attached {
                Some(v) => v.clone(),
                None => spare.clone(),
            };
            let label = format!("{} {}{}", c.label_word, c.name, vs.first().map(|v| format!(" {v}")).unwrap_or_default());
            let ecoid = if c.eco.is_empty() { c.word.clone() } else { c.eco.to_string() };
            let norm = if c.eco == "pypi" || c.eco == "cargo" { c.lname.replace(['_', '.'], "-") } else { c.name.clone() };
            let key = format!("{ecoid}:{norm}");
            if c.eco.is_empty() || vs.is_empty() {
                note_mention(&mut mentions, key, label, false);
                continue;
            }
            add(format!("{}:{}@{}", c.eco, c.name, vs.join(",")), &mut iocs);
            sent_keys.push((c.eco.to_string(), c.name.clone()));
            note_mention(&mut mentions, key, label, true);
            found = true;
        }
        if found {
            pending.push((para, sent_fix.clone(), sent_keys));
            continue;
        }
        for m in name_re.captures_iter(&scrubbed).flatten() {
            let v = if versions.is_empty() { String::new() } else { format!("@{}", versions.join(",")) };
            add(format!("npm:{}{}", &m[1], v), &mut iocs);
            sent_keys.push(("npm".to_string(), m[1].to_string()));
            note_mention(&mut mentions, format!("npm:{}", m[1].to_lowercase()), m[1].to_string(), true);
        }
        pending.push((para, sent_fix, sent_keys));
    }
    let mut fixed: Vec<(String, String, String)> = vec![];
    for (para, sfix, keys) in &pending {
        let v = sfix.clone().or_else(|| para_fix.get(para).filter(|f| f.len() == 1).map(|f| f[0].clone()));
        let Some(v) = v else { continue };
        for (e, n) in keys {
            if !fixed.iter().any(|f| f.0 == *e && f.1 == *n) {
                fixed.push((e.clone(), n.clone(), v.clone()));
            }
        }
    }
    let advisory_ids = advisory_ids_in(text);
    let unread: Vec<String> = mentions.iter().filter(|m| !m.2).map(|m| m.1.clone()).collect();
    if iocs.is_empty() && advisory_ids.is_empty() {
        let hint = if unread.is_empty() {
            "write them as eco:name@version (npm:lodash@4.17.21), @scope/name or a 64-hex sha256, or pass --advisory ID".to_string()
        } else {
            format!("mentioned but not read: {}; say each as eco:name@version, or pass --advisory ID", unread.iter().map(|u| format!("\"{u}\"")).collect::<Vec<_>>().join(", "))
        };
        return Err(BrError::new("no indicators found in the text", Some(&hint)));
    }
    Ok(Extracted { iocs, window: extract_window(text), unread, mentions: mentions.len(), hash_names: text_hash_ties(text), fixed, advisory_ids })
}
pub fn extract_window(text: &str) -> Option<(String, String)> {
    let pairs_re = rx(r"(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d)\s*(?:UTC|Z)");
    let pairs: Vec<(usize, usize, String)> = pairs_re
        .captures_iter(text)
        .filter_map(|m| {
            let w = m.get(0)?;
            Some((w.start(), w.end(), norm_iso(&format!("{}T{}Z", &m[1], &m[2])).ok()?))
        })
        .collect();
    // two instants joined by "to"/"until"/a dash are the window; a publish time elsewhere is not
    let joined = pairs.windows(2).find(|w| {
        let gap = text[w[0].1..w[1].0].trim().to_lowercase();
        matches!(gap.as_str(), "to" | "until" | "through" | "and" | "-" | "\u{2013}" | "\u{2014}" | "till")
    });
    if let Some(w) = joined {
        let (mut a, mut b) = (w[0].2.clone(), w[1].2.clone());
        if b < a {
            std::mem::swap(&mut a, &mut b);
        }
        return Some((a, b));
    }
    if pairs.len() >= 2 {
        let (mut a, mut b) = (pairs[0].2.clone(), pairs[1].2.clone());
        if b < a {
            std::mem::swap(&mut a, &mut b);
        }
        return Some((a, b));
    }
    let dates: Vec<&str> = rx(r"\d{4}-\d\d-\d\d").find_iter(text).map(|m| m.as_str()).collect();
    let mut times: Vec<String> = rx(r"(\d\d:\d\d)\s*UTC").captures_iter(text).map(|m| m[1].to_string()).collect();
    if times.len() < 2 {
        // "14:00-18:00 UTC": one zone after a range
        times = rx(r"(\d\d:\d\d)\s*[-\u{2013}\u{2014}]\s*(\d\d:\d\d)\s*UTC").captures_iter(text).flat_map(|m| vec![m[1].to_string(), m[2].to_string()]).collect();
    }
    if !dates.is_empty() && times.len() >= 2 {
        let a = norm_iso(&format!("{}T{}Z", dates[0], times[0])).ok()?;
        let mut b = norm_iso(&format!("{}T{}Z", dates[0], times[1])).ok()?;
        if b < a {
            b = add_days(&b, 1);
        }
        return Some((a, b));
    }
    None
}

// ---- advisories --------------------------------------------------------------------------------
/// What a hunt knows about an advisory.
#[derive(Debug, Clone, Default)]
pub struct ResolvedAdvisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub title: String,
    pub affected: Vec<String>,
    pub packages: Vec<AffectedPackage>,
    pub fixed: Option<String>,
    pub window: Option<(String, String)>,
    pub text: String,
    pub alias_used: Option<String>,
    /// (sha256 indicator, file name) ties from the record's prose, its `database_specific` and the operator's note
    pub hash_names: Vec<(String, String)>,
}

fn sv(v: &serde_json::Value, k: &str) -> Vec<String> {
    v.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// Packages from a local advisory file: `packages` (br's shape) or OSV/GHSA `affected` objects.
/// Strings in `affected` are legacy indicators; anything else that is not a package object is an error.
fn json_packages(a: &serde_json::Value, path: &str) -> BrResult<(Vec<AffectedPackage>, Vec<String>)> {
    let bad = |what: &str| BrError::new(format!("{path}: {what}"), Some("affected entries are strings (npm:name@1.2.3) or OSV package objects"));
    let mut pkgs: Vec<AffectedPackage> = vec![];
    let mut legacy: Vec<String> = vec![];
    if let Some(list) = a.get("packages").filter(|x| !x.is_null()) {
        pkgs = serde_json::from_value(list.clone()).map_err(|e| bad(&format!("\"packages\" is not a list of packages ({e})")))?;
    }
    match a.get("affected") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Array(items)) => {
            for it in items {
                if let Some(t) = it.as_str() {
                    legacy.push(t.to_string());
                } else if let Some(obj) = it.as_object() {
                    let pk = obj.get("package").and_then(|x| x.as_object()).ok_or_else(|| bad("an affected entry has no \"package\""))?;
                    let eco = pk.get("ecosystem").and_then(|x| x.as_str()).unwrap_or("");
                    let name = pk.get("name").and_then(|x| x.as_str()).unwrap_or("");
                    let mut ap = AffectedPackage { ecosystem: br_eco(eco), name: name.to_string(), ..Default::default() };
                    ap.versions = obj.get("versions").and_then(|x| x.as_array()).map(|v| v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                    for r in obj.get("ranges").and_then(|x| x.as_array()).into_iter().flatten() {
                        let mut cur = VersionRange::default();
                        let mut open = false;
                        for ev in r.get("events").and_then(|x| x.as_array()).into_iter().flatten() {
                            let g = |k: &str| ev.get(k).and_then(|x| x.as_str()).map(str::to_string);
                            if let Some(i) = g("introduced") {
                                if open {
                                    ap.ranges.push(std::mem::take(&mut cur));
                                }
                                cur.introduced = Some(i);
                                open = true;
                            } else if let Some(f) = g("fixed") {
                                cur.fixed = Some(f);
                                ap.ranges.push(std::mem::take(&mut cur));
                                open = false;
                            } else if let Some(l) = g("last_affected") {
                                cur.last_affected = Some(l);
                                ap.ranges.push(std::mem::take(&mut cur));
                                open = false;
                            }
                        }
                        if open {
                            ap.ranges.push(cur);
                        }
                    }
                    pkgs.push(ap);
                } else {
                    return Err(bad("an affected entry is neither a string nor a package object"));
                }
            }
        }
        Some(_) => return Err(bad("\"affected\" is not a list")),
    }
    Ok((pkgs, legacy))
}

fn jwindow(v: &serde_json::Value) -> Option<(String, String)> {
    let w = v.get("exposure_window").filter(|x| !x.is_null()).or_else(|| v.get("window").filter(|x| !x.is_null()))?;
    Some((w.get("from")?.as_str()?.to_string(), w.get("to")?.as_str()?.to_string()))
}

pub fn resolve_advisory(advisories: &[Advisory], r: &str) -> BrResult<ResolvedAdvisory> {
    if std::path::Path::new(r).is_file() {
        let text = std::fs::read_to_string(r).map_err(|_| BrError::new(format!("{r} is not valid JSON"), Some("pass a local advisory JSON file or --text FILE")))?;
        let a: serde_json::Value = serde_json::from_str(&text).map_err(|_| BrError::new(format!("{r} is not valid JSON"), Some("pass a local advisory JSON file or --text FILE")))?;
        let s = |k: &str| a.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let (packages, mut affected) = json_packages(&a, r)?;
        // hashes stated in prose (details, text) or under database_specific are indicators too
        let mut prose = crate::collect::osv::hashes_in(&a);
        if let Some(t) = a.get("text").and_then(|x| x.as_str()) {
            prose.extend(text_hashes(t));
        }
        for h in prose {
            if !affected.contains(&h) {
                affected.push(h);
            }
        }
        return Ok(ResolvedAdvisory {
            id: s("id").unwrap_or_else(|| r.to_string()),
            aliases: sv(&a, "aliases"),
            title: s("title").unwrap_or_default(),
            affected,
            packages,
            fixed: s("fixed"),
            window: jwindow(&a),
            text: s("text").unwrap_or_default(),
            alias_used: None,
            hash_names: {
                let mut t = crate::collect::osv::hash_ties_in(&a);
                if let Some(x) = a.get("text").and_then(|x| x.as_str()) {
                    t.extend(text_hash_ties(x));
                }
                t.dedup();
                t
            },
        });
    }
    for a in advisories {
        let mut ids = vec![a.id.clone()];
        ids.extend(a.aliases.iter().cloned());
        if ids.iter().any(|i| i.to_lowercase() == r.to_lowercase()) {
            return Ok(ResolvedAdvisory {
                id: a.id.clone(),
                aliases: a.aliases.clone(),
                title: a.title.clone().unwrap_or_default(),
                affected: a.affected.clone(),
                packages: a.packages.clone(),
                fixed: a.fixed.clone(),
                window: a.exposure_window.as_ref().map(|w| (w.from.clone(), w.to.clone())),
                text: a.text.clone().unwrap_or_default(),
                alias_used: if r.to_lowercase() != a.id.to_lowercase() { Some(r.to_string()) } else { None },
                hash_names: {
                    let mut t = a.hash_names.clone();
                    t.extend(text_hash_ties(a.text.as_deref().unwrap_or("")));
                    t.sort();
                    t.dedup();
                    t
                },
            });
        }
    }
    Err(BrError::new(format!("advisory {r} not found"), Some(&format!("pass --text FILE or a local advisory JSON file, or say what you know: br advisory note {r} --ioc eco:name@version"))))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_secret_indicator_parses_and_globs_match_names() {
        let i = parse_ioc("secret:deploy_*", None).unwrap();
        assert_eq!(i.kind, IocKind::Secret);
        assert_eq!(i.text, "secret:DEPLOY_*");
        assert!(glob_match(&i.name, "DEPLOY_TOKEN") && glob_match("*_TOKEN", "deploy_token") && glob_match("A*B*C", "AxxBxC"));
        assert!(!glob_match("DEPLOY_*", "XDEPLOY_A") && !glob_match("A*B", "ABC") && glob_match("*", "ANY"));
        assert!(parse_ioc("secret:bad name", None).is_err());
        assert!(parse_ioc("secret:", None).is_err());
    }

    use super::*;

    fn range_pkg(eco: &str, name: &str, intro: &str, fixed: &str) -> AffectedPackage {
        AffectedPackage { ecosystem: eco.into(), name: name.into(), versions: vec![], ranges: vec![VersionRange { introduced: Some(intro.into()), fixed: Some(fixed.into()), last_affected: None }] }
    }

    #[test]
    fn package_ranges_decide_matches() {
        let i = Ioc::from_package(&range_pkg("npm", "left-pad", "1.0.0", "1.3.0")).unwrap();
        assert!(match_pkg(&i, "npm", "left-pad", "1.2.9"));
        assert!(!match_pkg(&i, "npm", "left-pad", "1.3.0"));
        assert!(!match_pkg(&i, "npm", "left-pad", "0.9.0"));
        assert!(!match_pkg(&i, "npm", "other", "1.2.0"));
    }

    #[test]
    fn exact_versions_compare_normalised() {
        let i = parse_ioc("go:github.com/a/b@v1.2.3", None).unwrap();
        assert!(match_pkg(&i, "go", "github.com/a/b", "1.2.3"));
        let p = parse_ioc("pypi:Foo_Bar@1.0", None).unwrap();
        assert!(match_pkg(&p, "pypi", "foo-bar", "1.0.0"));
    }

    #[test]
    fn empty_version_list_is_an_error() {
        assert!(parse_ioc("npm:lodash@", None).is_err());
        assert!(parse_ioc("npm:lodash@,", None).is_err());
    }

    #[test]
    fn comparator_form_is_a_range() {
        let i = parse_ioc("npm:x@>=1.0.0,<1.2.0", None).unwrap();
        assert!(match_pkg(&i, "npm", "x", "1.1.0"));
        assert!(!match_pkg(&i, "npm", "x", "1.2.0"));
        assert!(!match_pkg(&i, "npm", "x", "0.9.0"));
    }

    #[test]
    fn osv_objects_in_a_local_file_become_packages() {
        let j: serde_json::Value = serde_json::json!({"affected":[{"package":{"ecosystem":"PyPI","name":"requests"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.31.0"},{"introduced":"3.0"},{"last_affected":"3.1"}]}]}]});
        let (p, legacy) = json_packages(&j, "f.json").unwrap();
        assert!(legacy.is_empty());
        assert_eq!(p[0].ecosystem, "pypi");
        assert_eq!(p[0].ranges.len(), 2);
        let bad = serde_json::json!({"affected":[1]});
        assert!(json_packages(&bad, "f.json").is_err());
    }

    #[test]
    fn next_patch_range_of_a_listed_version_stays_out_of_the_label_but_still_matches() {
        let mut p = range_pkg("npm", "@t/r", "1.120.3", "1.120.4");
        p.versions = vec!["1.120.3".into()];
        let i = Ioc::from_package(&p).unwrap();
        assert!(!i.text.contains(">="), "{}", i.text);
        assert!(match_pkg(&i, "npm", "@t/r", "1.120.3"));
        p.ranges[0].fixed = Some("1.121.0".into());
        assert!(Ioc::from_package(&p).unwrap().text.contains(">=1.120.3 <1.121.0"));
        let mut q = range_pkg("pypi", "mlflow", "2.14.0rc0", "3.13.0rc0");
        q.versions = vec!["2.14.0rc0".into()];
        assert!(Ioc::from_package(&q).unwrap().text.contains(">=2.14.0rc0"));
    }

    #[test]
    fn nothing_matchable_gives_no_ioc() {
        assert!(Ioc::from_package(&AffectedPackage { ecosystem: "npm".into(), name: "x".into(), ..Default::default() }).is_none());
    }
}

#[cfg(test)]
mod extract_tests {
    use super::*;

    #[test]
    fn window_is_ordered_and_skips_the_publish_time() {
        let t = "Published 2026-05-12 09:00 UTC. Malicious versions were live 2026-05-11 14:00 UTC to 2026-05-11 18:00 UTC. npm:lodash@4.17.1";
        let (_, w) = extract_text(t).unwrap();
        let (a, b) = w.unwrap();
        assert!(a < b && a.starts_with("2026-05-11T14:00"), "{a} {b}");
    }

    #[test]
    fn not_affected_is_scoped_to_its_clause() {
        let (i, _) = extract_text("@acme/core 1.4.2 is affected; 1.4.1 is not affected.").unwrap();
        assert!(i.iter().any(|x| x.contains("1.4.2")), "{i:?}");
        assert!(!i.iter().any(|x| x.contains("1.4.1")), "{i:?}");
    }

    // A file name in the same sentence or on the same line ties to the hash; a name elsewhere does not
    #[test]
    fn a_hash_is_tied_to_the_file_name_in_its_sentence_or_line() {
        let h = "a".repeat(64);
        let t = |s: &str| text_hash_ties(s);
        let want = |n: &str| vec![(format!("sha256:{h}"), n.to_string())];
        assert_eq!(t(&format!("The loader is the binary netprobe-linux-amd64 with sha256 {h} on Linux.")), want("netprobe-linux-amd64"));
        assert_eq!(t(&format!("netprobe-linux-amd64: {h}")), want("netprobe-linux-amd64"));
        assert_eq!(t(&format!("| evil.dll | sha256:{h} |")), want("evil.dll"));
        assert_eq!(t(&format!("Dropped `payload-x64` (SHA-256 {h}).")), want("payload-x64"));
        assert_eq!(t(&format!("It writes C:\\Windows\\Temp\\svc_update.exe, hash {h}.")), want("svc_update.exe"));
        // a name in another sentence or line is not a tie
        assert!(t(&format!("The file netprobe-linux-amd64 is shipped. The hash {h} was in a log.")).is_empty());
        assert!(t(&format!("The file netprobe-linux-amd64 is shipped.\nThe hash {h} was in a log.")).is_empty());
        // plain words are not names
        assert!(t(&format!("This is the hash {h} of the sample.")).is_empty());
        // two hashes, two names, each tied to the nearer one
        let h2 = "b".repeat(64);
        let both = t(&format!("a-linux.bin {h} and a-darwin.bin {h2}"));
        assert_eq!(both, vec![(format!("sha256:{h}"), "a-linux.bin".to_string()), (format!("sha256:{h2}"), "a-darwin.bin".to_string())]);
    }

    #[test]
    fn ecosystem_tokens_ignore_case_and_two_part_versions_read() {
        let (i, _) = extract_text("PyPI:requests@2.31 and Cargo:serde@1.0").unwrap();
        assert!(i.contains(&"pypi:requests@2.31".to_string()), "{i:?}");
        assert!(i.contains(&"cargo:serde@1.0".to_string()), "{i:?}");
        let (i, _) = extract_text("@acme/x 2.31 is malicious").unwrap();
        assert!(i.iter().any(|x| x.ends_with("@2.31")), "{i:?}");
    }

    #[test]
    fn r42_packages_named_in_words_are_read_and_the_rest_is_listed() {
        let t = "Version 0.4.2 is malicious (PyPI netprobe-py, crates.io netprobe-sys, Go module example.com/org/netprobe, npm @scope/netprobe-bin).";
        let e = extract_prose(t).unwrap();
        for want in ["pypi:netprobe-py@0.4.2", "cargo:netprobe-sys@0.4.2", "go:example.com/org/netprobe@0.4.2", "npm:@scope/netprobe-bin@0.4.2"] {
            assert!(e.iocs.contains(&want.to_string()), "{want} in {:?}", e.iocs);
        }
        assert!(e.unread.is_empty());
        // a version written beside another name is not lent to a name without one; an unsupported ecosystem is listed
        let e = extract_prose("npm lodash 4.17.21 was trojaned. RubyGems evilgem 1.0.0 too, and PyPI mystery-pkg.").unwrap();
        assert_eq!(e.iocs, vec!["npm:lodash@4.17.21".to_string()]);
        assert_eq!(e.mentions, 3);
        assert_eq!(e.unread.len(), 2, "{:?}", e.unread);
        // words that are not names do not make mentions
        let e = extract_prose("Go ahead and upgrade. The npm packages are affected: npm:left-pad@1.0.0").unwrap();
        assert!(e.unread.is_empty(), "{:?}", e.unread);
        // pip install form and the bare 'go' verb
        let e = extract_prose("Run pip install requests==2.0.0 now, then go to the console. cargo serde 1.0.1 too").unwrap();
        assert!(e.iocs.contains(&"pypi:requests@2.0.0".to_string()) && e.iocs.contains(&"cargo:serde@1.0.1".to_string()), "{:?}", e.iocs);
        assert!(e.unread.is_empty(), "{:?}", e.unread);
    }

    #[test]
    fn time_range_with_one_zone() {
        let w = extract_window("On 2026-05-11 between 14:00-18:00 UTC").unwrap();
        assert!(w.0 < w.1);
    }
}

/// The sha256 hashes a recorded advisory lists: its indicators, the ties from its record and the operator's note, the
/// hashes its provenance names, and the ones its prose states. Lower case, `sha256:HEX`, in order, once each.
pub fn advisory_hashes(a: &Advisory) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let mut add = |h: &str| {
        let h = h.trim().to_lowercase();
        if h.starts_with("sha256:") && !out.contains(&h) {
            out.push(h);
        }
    };
    a.affected.iter().for_each(|x| add(x));
    a.hash_names.iter().for_each(|(h, _)| add(h));
    a.provenance.indicators.keys().for_each(|k| add(k));
    text_hashes(a.text.as_deref().unwrap_or("")).iter().for_each(|h| add(h));
    out
}

#[cfg(test)]
mod advisory_hash_tests {
    use super::*;

    // Every place an advisory can state a hash is read
    #[test]
    fn advisory_hashes_come_from_indicators_ties_and_prose() {
        let h = |c: char| c.to_string().repeat(64);
        let a = Advisory {
            id: "GHSA-aaaa-bbbb-cccc".into(),
            affected: vec!["npm:evil@1.0.0".into(), format!("sha256:{}", h('a'))],
            hash_names: vec![(format!("sha256:{}", h('B')), "evil.bin".into())],
            text: Some(format!("The payload hashes to {} and is dropped by the install.", h('c'))),
            ..Default::default()
        };
        assert_eq!(advisory_hashes(&a), vec![format!("sha256:{}", h('a')), format!("sha256:{}", h('b')), format!("sha256:{}", h('c'))]);
    }
}

#[cfg(test)]
mod ct_tests {
    use super::*;

    const FP: &str = "9bdb8037dd9272d38953bd651a3eeee304a5ecb106e1f3f478e305c101a621ac";

    fn colon(h: &str) -> String {
        (0..64).step_by(2).map(|i| &h[i..i + 2]).collect::<Vec<_>>().join(":")
    }

    #[test]
    fn cert_fingerprint_takes_colons_and_any_case() {
        for s in [format!("cert:{FP}"), format!("cert:{}", colon(FP)), format!("cert:{}", colon(FP).to_uppercase())] {
            let i = parse_ioc(&s, None).unwrap();
            assert!(matches!(i.kind, IocKind::Cert));
            assert_eq!(i.sha, FP);
            assert_eq!(i.text, format!("cert:{FP}"));
        }
    }

    #[test]
    fn cert_fingerprint_must_be_64_hex() {
        assert!(parse_ioc("cert:abcd", None).is_err());
        assert!(parse_ioc("cert:subject:", None).is_err());
    }

    #[test]
    fn cert_subject_is_a_lowercase_substring() {
        let i = parse_ioc("cert:subject:Example Root CA", None).unwrap();
        assert!(matches!(i.kind, IocKind::Cert));
        assert_eq!(i.name, "example root ca");
        assert!(i.sha.is_empty());
    }

    #[test]
    fn colon_fingerprints_in_prose_are_found_once() {
        let t = format!("Distrusted: {} (SHA-256), again {}.", colon(FP).to_uppercase(), colon(FP));
        assert_eq!(text_cert_fingerprints(&t), vec![format!("cert:{FP}")]);
        assert!(text_cert_fingerprints("aa:bb:cc not a fingerprint").is_empty());
    }
}
