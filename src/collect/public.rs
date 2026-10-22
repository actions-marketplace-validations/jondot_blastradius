//! Public package registries, read-only: what a name means on npm, PyPI, crates.io and the Go module proxy.
//! Only `br claimcheck` calls this; a hunt never does. Every call is a GET.
//!
//! Endpoints (each can be moved with an env var, the way the rig does):
//!   npm      `{BR_NPM_REGISTRY}/{name}` (default https://registry.npmjs.org), scope search `/-/v1/search?text=scope:S`
//!   PyPI     `{BR_PYPI_API}/pypi/{name}/json` (default https://pypi.org)
//!   crates   `{BR_CRATES_API}/api/v1/crates/{name}` and `/owners` (default https://crates.io)
//!   Go       `{BR_GOPROXY}/{module}/@v/list` and `@latest` (default https://proxy.golang.org)
//! A registry that cannot answer (unreachable, rate limited, a server error) is `Unknown`, never "free".
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;

use serde_json::Value;

use crate::query::version;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Eco {
    Npm,
    Pypi,
    Cargo,
    Go,
}

impl Eco {
    pub fn word(self) -> &'static str {
        match self {
            Eco::Npm => "npm",
            Eco::Pypi => "pypi",
            Eco::Cargo => "cargo",
            Eco::Go => "go",
        }
    }
    pub fn registry(self) -> &'static str {
        match self {
            Eco::Npm => "npmjs.org",
            Eco::Pypi => "pypi.org",
            Eco::Cargo => "crates.io",
            Eco::Go => "proxy.golang.org",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PubVersion {
    pub v: String,
    pub time: Option<String>,
    /// Some(true): the release runs code at install (npm install scripts, a PyPI sdist with no wheel). None: the registry does not say.
    pub install_script: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Public {
    pub versions: Vec<PubVersion>,
    /// Repository / homepage URLs the publisher declared.
    pub repo_urls: Vec<String>,
    /// Command names the package installs (npm `bin`).
    pub bins: Vec<String>,
    /// Publisher accounts the registry shows (npm maintainers, crates.io owners as `login`, `github:org:team` for a team).
    pub publishers: Vec<String>,
    /// true when the publisher list came from an owners call (crates.io) that identifies GitHub accounts or teams.
    pub publishers_are_github: bool,
}

impl Public {
    /// When the name was first claimed: the earliest publish time among its versions. None when the registry gives no
    /// time for some version (the earliest one may be among them) or lists no version.
    pub fn first_published(&self) -> Option<String> {
        if self.versions.is_empty() || self.versions.iter().any(|v| v.time.is_none()) {
            return None;
        }
        self.versions.iter().filter_map(|v| v.time.clone()).min_by(|a, b| a.chars().take(19).collect::<String>().cmp(&b.chars().take(19).collect::<String>()))
    }
    pub fn max(&self, eco: Eco) -> Option<&PubVersion> {
        let e = eco.word();
        let mut best: Option<&PubVersion> = None;
        for v in &self.versions {
            best = match best {
                None => Some(v),
                Some(b) => match version::cmp(e, &v.v, &b.v) {
                    Some(Ordering::Greater) => Some(v),
                    Some(_) => Some(b),
                    None => Some(b),
                },
            };
        }
        best
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    Free,
    Found(Public),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScopePkg {
    pub name: String,
    pub repo_urls: Vec<String>,
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScopeLookup {
    Packages(Vec<ScopePkg>),
    Empty,
    Unknown(String),
}

// ---- transport -------------------------------------------------------------------------------------------------
thread_local! {
    static CACHE: RefCell<HashMap<String, Result<Option<String>, String>>> = RefCell::new(HashMap::new());
    static CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

pub fn calls() -> u64 {
    CALLS.with(|c| c.get())
}

fn env_base(var: &str, default: &str) -> String {
    std::env::var(var).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string()).trim_end_matches('/').to_string()
}

pub fn npm_base() -> String {
    env_base("BR_NPM_REGISTRY", "https://registry.npmjs.org")
}
fn pypi_base() -> String {
    env_base("BR_PYPI_API", "https://pypi.org")
}
fn crates_base() -> String {
    env_base("BR_CRATES_API", "https://crates.io")
}
fn goproxy_base() -> String {
    env_base("BR_GOPROXY", "https://proxy.golang.org")
}

/// GET url. Ok(None): the registry says there is no such thing (404, 410). Err: it could not say.
fn get(url: &str) -> Result<Option<String>, String> {
    if let Some(r) = CACHE.with(|c| c.borrow().get(url).cloned()) {
        return r;
    }
    if let Some(f) = std::env::var_os("BR_HTTP_TRACE") {
        use std::io::Write;
        if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(f) {
            let _ = writeln!(fh, "GET {url}");
        }
    }
    CALLS.with(|c| c.set(c.get() + 1));
    let ua = format!("blastradius/{} (+https://github.com/jondot/blastradius; read-only)", env!("CARGO_PKG_VERSION"));
    let r = match ureq::get(url).set("User-Agent", &ua).set("Accept", "application/json").timeout(std::time::Duration::from_secs(20)).call() {
        Ok(r) => r.into_string().map(Some).map_err(|e| format!("unreadable answer ({e})")),
        Err(ureq::Error::Status(404 | 410, _)) => Ok(None),
        Err(ureq::Error::Status(429, _)) => Err("rate limited (HTTP 429)".to_string()),
        Err(ureq::Error::Status(c, _)) => Err(format!("HTTP {c}")),
        Err(_) => Err("unreachable".to_string()),
    };
    CACHE.with(|c| c.borrow_mut().insert(url.to_string(), r.clone()));
    r
}

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Go module proxy path escaping: an upper-case letter becomes `!` and its lower-case letter.
pub fn go_escape(m: &str) -> String {
    m.chars().map(|c| if c.is_ascii_uppercase() { format!("!{}", c.to_ascii_lowercase()) } else { c.to_string() }).collect()
}

// ---- parsers (one per registry answer shape) -----------------------------------------------------------------------
fn repo_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(_) => v["url"].as_str().map(str::to_string),
        _ => None,
    }
}

fn bin_names(v: &Value, pkg: &str) -> Vec<String> {
    match v {
        Value::String(_) => vec![pkg.rsplit('/').next().unwrap_or(pkg).to_string()],
        Value::Object(m) => m.keys().cloned().collect(),
        _ => vec![],
    }
}

/// npm packument (full or abbreviated-plus-time).
pub fn parse_npm(name: &str, j: &Value) -> Public {
    let mut p = Public::default();
    let time = &j["time"];
    if let Some(vs) = j["versions"].as_object() {
        for (v, d) in vs {
            let scripts = &d["scripts"];
            let script = ["preinstall", "install", "postinstall"].iter().any(|k| scripts[*k].is_string());
            let has = d["hasInstallScript"].as_bool();
            p.versions.push(PubVersion { v: v.clone(), time: time[v.as_str()].as_str().map(str::to_string), install_script: Some(script || has == Some(true)) });
            for b in bin_names(&d["bin"], name) {
                if !p.bins.contains(&b) {
                    p.bins.push(b);
                }
            }
            if let Some(r) = repo_of(&d["repository"]) {
                if !p.repo_urls.contains(&r) {
                    p.repo_urls.push(r);
                }
            }
        }
    }
    if let Some(r) = repo_of(&j["repository"]) {
        if !p.repo_urls.contains(&r) {
            p.repo_urls.insert(0, r);
        }
    }
    for b in bin_names(&j["bin"], name) {
        if !p.bins.contains(&b) {
            p.bins.push(b);
        }
    }
    if let Some(ms) = j["maintainers"].as_array() {
        p.publishers = ms.iter().filter_map(|m| m["name"].as_str().or(m.as_str()).map(str::to_string)).collect();
    }
    p
}

/// PyPI JSON API (`/pypi/NAME/json`).
pub fn parse_pypi(j: &Value) -> Public {
    let mut p = Public::default();
    if let Some(rs) = j["releases"].as_object() {
        for (v, files) in rs {
            let files = files.as_array().cloned().unwrap_or_default();
            let live: Vec<&Value> = files.iter().filter(|f| f["yanked"].as_bool() != Some(true)).collect();
            if live.is_empty() && !files.is_empty() {
                continue;
            }
            let time = files.iter().filter_map(|f| f["upload_time_iso_8601"].as_str().or(f["upload_time"].as_str())).min().map(str::to_string);
            let sdist = live.iter().any(|f| f["packagetype"] == "sdist");
            let wheel = live.iter().any(|f| f["packagetype"] == "bdist_wheel");
            // an sdist-only release runs the project's build backend (setup.py) on the installing machine
            let ins = if live.is_empty() { None } else { Some(sdist && !wheel) };
            p.versions.push(PubVersion { v: v.clone(), time, install_script: ins });
        }
    }
    let info = &j["info"];
    for k in ["home_page", "project_url", "download_url"] {
        if let Some(u) = info[k].as_str().filter(|s| !s.is_empty()) {
            p.repo_urls.push(u.to_string());
        }
    }
    if let Some(m) = info["project_urls"].as_object() {
        p.repo_urls.extend(m.values().filter_map(|v| v.as_str()).map(str::to_string));
    }
    p
}

/// crates.io `/api/v1/crates/NAME`.
pub fn parse_crates(j: &Value) -> Public {
    let mut p = Public::default();
    for v in j["versions"].as_array().into_iter().flatten() {
        if v["yanked"].as_bool() == Some(true) {
            continue;
        }
        if let Some(n) = v["num"].as_str() {
            // build.rs is not in the API answer, so install-time code is "not shown"
            p.versions.push(PubVersion { v: n.to_string(), time: v["created_at"].as_str().map(str::to_string), install_script: None });
        }
    }
    for k in ["repository", "homepage"] {
        if let Some(u) = j["crate"][k].as_str().filter(|s| !s.is_empty()) {
            p.repo_urls.push(u.to_string());
        }
    }
    p
}

/// crates.io `/owners`: users by GitHub login, teams as `github:ORG:TEAM`.
pub fn parse_crate_owners(j: &Value) -> Vec<String> {
    j["users"].as_array().into_iter().flatten().filter_map(|u| u["login"].as_str().map(str::to_string)).collect()
}

pub fn parse_go_list(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()
}

pub fn parse_npm_search(j: &Value) -> Vec<ScopePkg> {
    j["objects"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|o| {
            let p = &o["package"];
            let name = p["name"].as_str()?.to_string();
            let mut repo_urls: Vec<String> = vec![];
            for k in ["repository", "homepage"] {
                if let Some(u) = p["links"][k].as_str() {
                    repo_urls.push(u.to_string());
                }
            }
            let publisher = p["publisher"]["username"].as_str().map(str::to_string);
            Some(ScopePkg { name, repo_urls, publisher })
        })
        .collect()
}

/// `github.com/ORG/...` in a repository or homepage URL (https, git+https, ssh, git://, shorthand `github:org/repo`).
pub fn github_org_of(url: &str) -> Option<String> {
    let u = url.trim().trim_start_matches("git+");
    let rest = if let Some(r) = u.strip_prefix("github:") {
        r.to_string()
    } else {
        let i = u.match_indices("github.com").map(|(i, _)| i).find(|i| *i == 0 || matches!(u.as_bytes()[i - 1], b'/' | b'@' | b'.'))?;
        let after = &u[i + "github.com".len()..];
        after.trim_start_matches([':', '/']).to_string()
    };
    let org = rest.split('/').next()?.trim();
    (!org.is_empty()).then(|| org.to_lowercase())
}

// ---- the sample registry (br demo claimcheck) ----------------------------------------------------------------------
/// One public package of the sample registry: `versions` are (version, published, runs code at install).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SampleEntry {
    #[serde(default)]
    pub versions: Vec<(String, Option<String>, Option<bool>)>,
    #[serde(default)]
    pub repo: Vec<String>,
    #[serde(default)]
    pub bins: Vec<String>,
    #[serde(default)]
    pub by: Vec<String>,
    /// the publishers are GitHub accounts or teams (crates.io owners)
    #[serde(default)]
    pub gh: bool,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SampleScopePkg {
    pub name: String,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub repo: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SampleRegistry {
    #[serde(default)]
    pub npm: std::collections::BTreeMap<String, SampleEntry>,
    #[serde(default)]
    pub pypi: std::collections::BTreeMap<String, SampleEntry>,
    #[serde(default)]
    pub crates: std::collections::BTreeMap<String, SampleEntry>,
    #[serde(default)]
    pub go: std::collections::BTreeMap<String, SampleEntry>,
    #[serde(default)]
    pub npm_scopes: std::collections::BTreeMap<String, Vec<SampleScopePkg>>,
}

/// A small set of manifests and a registry snapshot that ship inside the binary, so `br demo claimcheck` needs no network.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Sample {
    pub org: String,
    /// repo -> (path -> file text)
    pub repos: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    pub registry: SampleRegistry,
}

thread_local! {
    static SAMPLE: RefCell<Option<std::rc::Rc<Sample>>> = const { RefCell::new(None) };
}

/// Answer every lookup from this snapshot instead of the network (None: back to the network).
pub fn use_sample(s: Option<Sample>) {
    SAMPLE.with(|c| *c.borrow_mut() = s.map(std::rc::Rc::new));
}

pub fn sample() -> Option<std::rc::Rc<Sample>> {
    SAMPLE.with(|c| c.borrow().clone())
}

fn sample_public(e: &SampleEntry) -> Public {
    Public {
        versions: e.versions.iter().map(|(v, t, s)| PubVersion { v: v.clone(), time: t.clone(), install_script: *s }).collect(),
        repo_urls: e.repo.clone(),
        bins: e.bins.clone(),
        publishers: e.by.clone(),
        publishers_are_github: e.gh,
    }
}

fn sample_lookup(s: &Sample, eco: Eco, name: &str) -> Lookup {
    let m = match eco {
        Eco::Npm => &s.registry.npm,
        Eco::Pypi => &s.registry.pypi,
        Eco::Cargo => &s.registry.crates,
        Eco::Go => &s.registry.go,
    };
    let key = if eco == Eco::Pypi { name.to_lowercase().replace(['_', '.'], "-") } else { name.to_string() };
    match m.get(&key) {
        Some(e) => Lookup::Found(sample_public(e)),
        None => Lookup::Free,
    }
}

// ---- lookups -----------------------------------------------------------------------------------------------------
pub fn lookup(eco: Eco, name: &str) -> Lookup {
    if let Some(s) = sample() {
        return sample_lookup(&s, eco, name);
    }
    match eco {
        Eco::Npm => {
            let url = format!("{}/{}", npm_base(), pct(name).replacen("%40", "@", 1).replacen("%2F", "%2f", 1));
            match get(&url) {
                Ok(None) => Lookup::Free,
                Ok(Some(t)) => match serde_json::from_str::<Value>(&t) {
                    Ok(j) => Lookup::Found(parse_npm(name, &j)),
                    Err(_) => Lookup::Unknown("unreadable answer".into()),
                },
                Err(e) => Lookup::Unknown(e),
            }
        }
        Eco::Pypi => {
            let n: String = name.to_lowercase().replace(['_', '.'], "-");
            match get(&format!("{}/pypi/{}/json", pypi_base(), pct(&n))) {
                Ok(None) => Lookup::Free,
                Ok(Some(t)) => match serde_json::from_str::<Value>(&t) {
                    Ok(j) => Lookup::Found(parse_pypi(&j)),
                    Err(_) => Lookup::Unknown("unreadable answer".into()),
                },
                Err(e) => Lookup::Unknown(e),
            }
        }
        Eco::Cargo => {
            let base = format!("{}/api/v1/crates/{}", crates_base(), pct(name));
            match get(&base) {
                Ok(None) => Lookup::Free,
                Ok(Some(t)) => match serde_json::from_str::<Value>(&t) {
                    Ok(j) => {
                        let mut p = parse_crates(&j);
                        // owners are fetched only for a crate that exists; a failure leaves them unshown
                        if let Ok(Some(o)) = get(&format!("{base}/owners")) {
                            if let Ok(oj) = serde_json::from_str::<Value>(&o) {
                                p.publishers = parse_crate_owners(&oj);
                                p.publishers_are_github = true;
                            }
                        }
                        Lookup::Found(p)
                    }
                    Err(_) => Lookup::Unknown("unreadable answer".into()),
                },
                Err(e) => Lookup::Unknown(e),
            }
        }
        Eco::Go => {
            let base = format!("{}/{}", goproxy_base(), go_escape(name).split('/').map(pct).collect::<Vec<_>>().join("/"));
            let list = match get(&format!("{base}/@v/list")) {
                Ok(None) => return Lookup::Free,
                Ok(Some(t)) => parse_go_list(&t),
                Err(e) => return Lookup::Unknown(e),
            };
            let mut p = Public::default();
            for v in &list {
                p.versions.push(PubVersion { v: v.clone(), time: None, install_script: Some(false) });
            }
            if list.is_empty() {
                // the module exists but tags no release: its newest pseudo-version
                match get(&format!("{base}/@latest")) {
                    Ok(None) => return Lookup::Free,
                    Ok(Some(t)) => {
                        if let Ok(j) = serde_json::from_str::<Value>(&t) {
                            if let Some(v) = j["Version"].as_str() {
                                p.versions.push(PubVersion { v: v.to_string(), time: j["Time"].as_str().map(str::to_string), install_script: Some(false) });
                            }
                        }
                    }
                    Err(e) => return Lookup::Unknown(e),
                }
            } else if let Some(m) = p.max(Eco::Go).map(|m| m.v.clone()) {
                if let Ok(Some(t)) = get(&format!("{base}/@v/{}.info", pct(&m))) {
                    if let Ok(j) = serde_json::from_str::<Value>(&t) {
                        let when = j["Time"].as_str().map(str::to_string);
                        if let Some(pv) = p.versions.iter_mut().find(|x| x.v == m) {
                            pv.time = when;
                        }
                    }
                }
            }
            Lookup::Found(p)
        }
    }
}

/// Packages a public npm scope holds (the registry's search by scope).
pub fn scope(name: &str) -> ScopeLookup {
    if let Some(s) = sample() {
        return match s.registry.npm_scopes.get(name.trim_start_matches('@')) {
            Some(ps) if !ps.is_empty() => ScopeLookup::Packages(ps.iter().map(|p| ScopePkg { name: p.name.clone(), repo_urls: p.repo.clone(), publisher: p.publisher.clone() }).collect()),
            _ => ScopeLookup::Empty,
        };
    }
    let url = format!("{}/-/v1/search?text=scope:{}&size=250", npm_base(), pct(name.trim_start_matches('@')));
    match get(&url) {
        Ok(None) => ScopeLookup::Empty,
        Ok(Some(t)) => match serde_json::from_str::<Value>(&t) {
            Ok(j) => {
                let ps = parse_npm_search(&j);
                if ps.is_empty() {
                    ScopeLookup::Empty
                } else {
                    ScopeLookup::Packages(ps)
                }
            }
            Err(_) => ScopeLookup::Unknown("unreadable answer".into()),
        },
        Err(e) => ScopeLookup::Unknown(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn npm_packument_gives_versions_scripts_bins_and_repo() {
        let j = json!({"name":"x","repository":{"type":"git","url":"git+https://github.com/acme/x.git"},
            "maintainers":[{"name":"someone","email":"a@b"}],
            "time":{"created":"2026-01-01T00:00:00.000Z","9999.0.0":"2026-05-01T10:00:00.000Z","1.0.0":"2025-01-01T00:00:00.000Z"},
            "versions":{"1.0.0":{"bin":{"acme-cli":"cli.js"}},"9999.0.0":{"scripts":{"postinstall":"node p.js"}}}});
        let p = parse_npm("x", &j);
        let m = p.max(Eco::Npm).unwrap();
        assert_eq!(m.v, "9999.0.0");
        assert_eq!(m.time.as_deref(), Some("2026-05-01T10:00:00.000Z"));
        assert_eq!(m.install_script, Some(true));
        assert_eq!(p.versions.iter().find(|v| v.v == "1.0.0").unwrap().install_script, Some(false));
        assert_eq!(p.bins, vec!["acme-cli"]);
        assert_eq!(p.publishers, vec!["someone"]);
        assert_eq!(github_org_of(&p.repo_urls[0]).as_deref(), Some("acme"));
    }

    #[test]
    fn npm_bin_string_is_the_package_name_and_has_install_script_counts() {
        let j = json!({"versions":{"1.0.0":{"bin":"cli.js","hasInstallScript":true}}});
        let p = parse_npm("@s/tool", &j);
        assert_eq!(p.bins, vec!["tool"]);
        assert_eq!(p.versions[0].install_script, Some(true));
    }

    #[test]
    fn pypi_sdist_only_runs_setup_and_yanked_is_ignored() {
        let j = json!({"info":{"name":"p","home_page":"https://github.com/Acme/p","project_urls":{"Source":"https://example.com"}},
            "releases":{"1.0":[{"packagetype":"sdist","upload_time_iso_8601":"2026-02-01T00:00:00Z"},{"packagetype":"bdist_wheel","upload_time_iso_8601":"2026-02-01T00:00:00Z"}],
                        "99.0":[{"packagetype":"sdist","upload_time_iso_8601":"2026-05-01T00:00:00Z"}],
                        "100.0":[{"packagetype":"sdist","yanked":true,"upload_time_iso_8601":"2026-05-02T00:00:00Z"}]}});
        let p = parse_pypi(&j);
        let m = p.max(Eco::Pypi).unwrap();
        assert_eq!(m.v, "99.0");
        assert_eq!(m.install_script, Some(true));
        assert_eq!(p.versions.iter().find(|v| v.v == "1.0").unwrap().install_script, Some(false));
        assert!(p.repo_urls.iter().any(|u| github_org_of(u).as_deref() == Some("acme")));
    }

    #[test]
    fn crates_owners_and_yanked() {
        let j = json!({"crate":{"repository":"https://github.com/acme/c"},"versions":[{"num":"0.1.0","created_at":"2026-01-01T00:00:00Z"},{"num":"9.9.9","yanked":true}]});
        let p = parse_crates(&j);
        assert_eq!(p.versions.len(), 1);
        assert_eq!(p.versions[0].install_script, None);
        assert_eq!(parse_crate_owners(&json!({"users":[{"login":"github:acme:core","kind":"team"},{"login":"jo"}]})), vec!["github:acme:core", "jo"]);
    }

    #[test]
    fn go_paths_and_lists() {
        assert_eq!(go_escape("git.corp.example/Acme/Tool"), "git.corp.example/!acme/!tool");
        assert_eq!(parse_go_list("v1.0.0\nv1.2.0\n\n"), vec!["v1.0.0", "v1.2.0"]);
        let p = Public { versions: ["v1.2.0", "v1.10.0", "v1.9.0"].iter().map(|v| PubVersion { v: v.to_string(), time: None, install_script: Some(false) }).collect(), ..Default::default() };
        assert_eq!(p.max(Eco::Go).unwrap().v, "v1.10.0");
    }

    #[test]
    fn github_org_forms() {
        for (u, o) in [
            ("git+https://github.com/Acme/x.git", Some("acme")),
            ("git@github.com:acme/x.git", Some("acme")),
            ("github:acme/x", Some("acme")),
            ("git://github.com/acme/x", Some("acme")),
            ("https://gitlab.com/acme/x", None),
            ("https://example.com/github.com", None),
            ("https://notgithub.com/acme/x", None),
        ] {
            let got = github_org_of(u);
            assert_eq!(got.as_deref(), o, "{u}");
        }
    }

    #[test]
    fn search_answer_lists_scope_packages() {
        let j = json!({"objects":[{"package":{"name":"@acme/a","links":{"repository":"https://github.com/other/a"},"publisher":{"username":"zed"}}}],"total":1});
        let ps = parse_npm_search(&j);
        assert_eq!(ps[0].publisher.as_deref(), Some("zed"));
        assert_eq!(ps[0].repo_urls, vec!["https://github.com/other/a"]);
    }
}
