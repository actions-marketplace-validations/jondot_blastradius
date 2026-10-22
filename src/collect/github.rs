//! The GitHub REST collector: org, people, teams, repos with their lockfiles, workflows, runs, caches, artifacts, releases.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use regex::Regex;
use serde_json::Value;

use crate::collect::fs::{Analyzer, FileMeta};
use crate::collect::util::{norm_api_time, plural};
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::parse::{ci, lock, manifest};
use crate::store::Row;
use crate::view::*;

pub struct Gh {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
    /// `X-RateLimit-Remaining` of the last response; br stops before the quota is spent (`BR_RATE_FLOOR`, default 150).
    remaining: std::cell::Cell<Option<u64>>,
    floor: u64,
    /// What this client could not check since the last `take_gaps` (scope, reason).
    gaps: std::cell::RefCell<Vec<(String, String)>>,
    /// Stored ETags per URL, loaded by the caller (B9); `etags_out` collects the fresh ones.
    etags: std::cell::RefCell<BTreeMap<String, String>>,
    calls: std::cell::Cell<u64>,
    /// While set, misses are not recorded (the caller counts them and records one gap).
    quiet: std::cell::Cell<bool>,
    last_status: std::cell::Cell<u16>,
}

/// The error prefix of a rate-limit stop; callers that loop over repos stop the loop on it.
pub const RATE_STOP: &str = "GitHub rate limit";

pub enum Got {
    Ok(Value),
    Missing,
}

/// A conditional GET (If-None-Match): unchanged since the stored ETag, fresh content, or missing.
pub enum Cond {
    NotModified,
    Fresh(Value),
    Missing,
}

/// Read-only law: GET and HEAD are the only methods br may send to GitHub.
pub fn guard_method(method: &str) -> BrResult<()> {
    match method.to_ascii_uppercase().as_str() {
        "GET" | "HEAD" => Ok(()),
        m => Err(BrError::with_code(format!("refusing {m} to GitHub: br is read-only"), Some("only GET and HEAD are allowed"), 1)),
    }
}

fn net(e: impl std::fmt::Display) -> BrError {
    BrError::with_code(format!("cannot reach GitHub ({e})"), Some("check the network and BR_GITHUB_API"), 3)
}

/// The path of a URL without its host or query, for gap scopes.
fn scope_of(url: &str) -> String {
    let p = url.split('?').next().unwrap_or(url);
    match p.find("://") {
        Some(i) => p[i + 3..].find('/').map(|j| p[i + 3 + j..].to_string()).unwrap_or_default(),
        None => p.to_string(),
    }
}

impl Gh {
    pub fn new(ctx: &Ctx) -> Gh {
        let base = std::env::var("BR_GITHUB_API").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "https://api.github.com".into());
        // no total timeout: a large download may take minutes; a stalled connection still fails after the read timeout
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(20))
            .timeout_read(std::time::Duration::from_secs(60))
            .timeout_write(std::time::Duration::from_secs(60))
            .user_agent("br")
            .build();
        Gh {
            base: base.trim_end_matches('/').to_string(),
            token: ctx.token(),
            agent,
            remaining: std::cell::Cell::new(None),
            floor: std::env::var("BR_RATE_FLOOR").ok().and_then(|v| v.parse().ok()).unwrap_or(150),
            gaps: Default::default(),
            etags: Default::default(),
            calls: Default::default(),
            quiet: Default::default(),
            last_status: Default::default(),
        }
    }

    /// Use this token instead of the environment's.
    pub fn with_token(mut self, t: Option<String>) -> Gh {
        self.token = t;
        self
    }

    /// Record that something could not be checked.
    pub fn note(&self, scope: impl Into<String>, reason: impl Into<String>) {
        if self.quiet.get() {
            return;
        }
        let (scope, reason) = (scope.into(), reason.into());
        let mut g = self.gaps.borrow_mut();
        if !g.iter().any(|(s, _)| *s == scope) {
            g.push((scope, reason));
        }
    }

    /// Record a gap, replacing any earlier one of the same scope (the later, fuller reason wins).
    pub fn note_replace(&self, scope: impl Into<String>, reason: impl Into<String>) {
        if self.quiet.get() {
            return;
        }
        let (scope, reason) = (scope.into(), reason.into());
        let mut g = self.gaps.borrow_mut();
        g.retain(|(s, _)| *s != scope);
        g.push((scope, reason));
    }

    /// The reason recorded so far for a scope.
    pub fn gap_reason(&self, scope: &str) -> Option<String> {
        self.gaps.borrow().iter().find(|(s, _)| s == scope).map(|(_, r)| r.clone())
    }

    /// The gaps recorded since the last call, as `Gap` rows stamped `at`.
    pub fn take_gaps(&self, at: &str) -> Vec<Gap> {
        self.gaps.take().into_iter().map(|(scope, reason)| Gap { scope, reason, at: at.to_string() }).collect()
    }

    /// Requests sent so far (the harness and the re-scan budget count them).
    pub fn calls(&self) -> u64 {
        self.calls.get()
    }

    /// Run `f` without recording misses; returns its result.
    pub fn quietly<T>(&self, f: impl FnOnce() -> T) -> T {
        let was = self.quiet.replace(true);
        let r = f();
        self.quiet.set(was);
        r
    }

    pub fn load_etags(&self, m: BTreeMap<String, String>) {
        *self.etags.borrow_mut() = m;
    }

    pub fn etags(&self) -> BTreeMap<String, String> {
        self.etags.borrow().clone()
    }

    /// The only way to build a request: `br` never writes to GitHub, so only GET and HEAD pass `guard_method`.
    fn build(&self, method: &str, url: &str, accept: &str) -> BrResult<ureq::Request> {
        guard_method(method)?;
        // BR_HTTP_TRACE=FILE appends "METHOD url" per request (never headers): the live harness audits it for read-only
        if let Some(f) = std::env::var_os("BR_HTTP_TRACE") {
            use std::io::Write;
            if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(f) {
                let _ = writeln!(fh, "{method} {url}");
            }
        }
        self.calls.set(self.calls.get() + 1);
        Ok(self.req(method, url, accept))
    }

    fn req(&self, method: &str, url: &str, accept: &str) -> ureq::Request {
        let mut r = self.agent.request(method, url).set("Accept", accept).set("X-GitHub-Api-Version", "2022-11-28");
        if let Some(t) = &self.token {
            r = r.set("Authorization", &format!("Bearer {t}"));
        }
        r
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{}", self.base, path)
        }
    }

    fn call(&self, url: &str, accept: &str) -> BrResult<Option<ureq::Response>> {
        match self.call_cond(url, accept, None)? {
            Reply::Resp(r) => Ok(Some(r)),
            _ => Ok(None),
        }
    }

    fn call_cond(&self, url: &str, accept: &str, etag: Option<&str>) -> BrResult<Reply> {
        let mut waited = 0;
        loop {
            if let Some(n) = self.remaining.get() {
                if n <= self.floor && self.base.contains("api.github.com") {
                    return Err(self.rate_stop(n));
                }
            }
            let mut rq = self.build("GET", url, accept)?;
            if let Some(e) = etag {
                rq = rq.set("If-None-Match", e);
            }
            let res = rq.call();
            let hdr = match &res {
                Ok(r) => Some(r),
                Err(ureq::Error::Status(_, r)) => Some(r),
                _ => None,
            };
            if let Some(n) = hdr.and_then(|r| r.header("X-RateLimit-Remaining")).and_then(|v| v.parse::<u64>().ok()) {
                self.remaining.set(Some(n));
            }
            return match res {
                // ureq hands 3xx back as a response, not as an error
                Ok(r) if r.status() == 304 => Ok(Reply::NotModified),
                Ok(r) => Ok(Reply::Resp(r)),
                Err(ureq::Error::Status(304, _)) => Ok(Reply::NotModified),
                Err(ureq::Error::Status(c @ (404 | 409), _)) => {
                    self.last_status.set(c);
                    Ok(Reply::Missing)
                }
                Err(ureq::Error::Status(410, _)) => {
                    self.note(scope_of(url), "HTTP 410: the resource is gone (expired or removed)");
                    Ok(Reply::Missing)
                }
                Err(ureq::Error::Status(401, _)) => {
                    Err(BrError::with_code("the GitHub token was refused", Some(&format!("set {} to a valid token (read-only is enough)", crate::collect::words::TOKEN_WORDS)), 4))
                }
                Err(ureq::Error::Status(code @ (403 | 429), r)) => {
                    if r.header("X-GitHub-SSO").is_some() {
                        return Err(BrError::with_code("token is not authorised for SSO", Some("authorise the token for the org, then re-run"), 4));
                    }
                    let retry: Option<u64> = r.header("Retry-After").and_then(|v| v.trim().parse().ok());
                    let reset: Option<u64> = r.header("X-RateLimit-Reset").and_then(|v| v.trim().parse().ok());
                    let limited = code == 429 || r.header("X-RateLimit-Remaining") == Some("0") || retry.is_some();
                    if limited {
                        // the secondary limit asks to wait a short while; wait once or twice, then stop
                        let wait = retry.or_else(|| {
                            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                            reset.map(|t| t.saturating_sub(now) + 1)
                        });
                        if let Some(w) = wait.filter(|w| *w <= 60 && waited < 2) {
                            std::thread::sleep(std::time::Duration::from_secs(w));
                            waited += 1;
                            continue;
                        }
                        return Err(self.rate_stop(0));
                    }
                    let need = r.header("X-Accepted-GitHub-Permissions").map(|h| format!("; needs {h}")).unwrap_or_default();
                    self.note(scope_of(url), format!("HTTP 403: the token cannot read this{need}"));
                    Ok(Reply::Missing)
                }
                Err(ureq::Error::Status(code, _)) => {
                    self.note(scope_of(url), format!("HTTP {code} from GitHub"));
                    Ok(Reply::Missing)
                }
                Err(e) => Err(net(e)),
            };
        }
    }

    fn rate_stop(&self, left: u64) -> BrError {
        BrError::with_code(
            format!("{RATE_STOP} nearly spent ({left} calls left); stopped before it ran out"),
            Some("wait for the hourly reset (gh api rate_limit shows when), then run br scan again"),
            1,
        )
    }

    pub fn get(&self, path: &str) -> BrResult<Got> {
        match self.call(&self.url(path), "application/vnd.github+json")? {
            Some(r) => Ok(Got::Ok(r.into_json::<Value>().map_err(net)?)),
            None => Ok(Got::Missing),
        }
    }

    pub fn json(&self, path: &str) -> BrResult<Option<Value>> {
        Ok(match self.get(path)? {
            Got::Ok(v) => Some(v),
            Got::Missing => None,
        })
    }

    /// Like `json`, but a missing answer is recorded as a gap for `scope` (GitHub answers 404 for what a token may not read).
    pub fn json_need(&self, path: &str, scope: &str) -> BrResult<Option<Value>> {
        self.last_status.set(0);
        let v = self.json(path)?;
        // 409 is an empty repository: nothing to check
        if v.is_none() && self.last_status.get() != 409 {
            self.note(scope, "HTTP 404: missing, or the token cannot read it");
        }
        Ok(v)
    }

    /// A conditional GET: the stored ETag for this URL is sent, and the fresh one is kept.
    pub fn json_cond(&self, path: &str) -> BrResult<Cond> {
        let url = self.url(path);
        let old = self.etags.borrow().get(&url).cloned();
        match self.call_cond(&url, "application/vnd.github+json", old.as_deref())? {
            Reply::NotModified => Ok(Cond::NotModified),
            Reply::Missing => Ok(Cond::Missing),
            Reply::Resp(r) => {
                if let Some(e) = r.header("ETag") {
                    self.etags.borrow_mut().insert(url, e.to_string());
                }
                Ok(Cond::Fresh(r.into_json::<Value>().map_err(net)?))
            }
        }
    }

    /// Every page of a list; `key` names the array inside an object response (e.g. `workflow_runs`).
    pub fn list(&self, path: &str, key: Option<&str>) -> BrResult<Vec<Value>> {
        Ok(self.list_opt(path, key)?.unwrap_or_default())
    }

    /// Every page; None when the first page is missing.
    pub fn list_opt(&self, path: &str, key: Option<&str>) -> BrResult<Option<Vec<Value>>> {
        Ok(self.list_max(path, key, usize::MAX)?.0)
    }

    /// Pages until `max` items; the flag says the list was cut short.
    pub fn list_max(&self, path: &str, key: Option<&str>, max: usize) -> BrResult<(Option<Vec<Value>>, bool)> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut url = self.url(&format!("{path}{sep}per_page=100"));
        let mut out = vec![];
        let mut first = true;
        loop {
            let Some(r) = self.call(&url, "application/vnd.github+json")? else {
                if first {
                    return Ok((None, false));
                }
                self.note(scope_of(&url), "a later page of the list could not be read");
                break;
            };
            first = false;
            let next = r.header("Link").and_then(next_link);
            let v: Value = r.into_json().map_err(net)?;
            let arr = match key {
                Some(k) => v[k].as_array().cloned().unwrap_or_default(),
                None => v.as_array().cloned().unwrap_or_default(),
            };
            let empty = arr.is_empty();
            out.extend(arr);
            if out.len() >= max {
                let cut = next.is_some();
                out.truncate(max);
                return Ok((Some(out), cut));
            }
            match next {
                Some(n) if !empty => url = n,
                _ => break,
            }
        }
        Ok((Some(out), false))
    }

    /// A list whose absence is a gap for `scope`.
    pub fn list_need(&self, path: &str, key: Option<&str>, scope: &str) -> BrResult<Vec<Value>> {
        match self.list_opt(path, key)? {
            Some(v) => Ok(v),
            None => {
                self.note(scope, "HTTP 404: missing, or the token cannot read it");
                Ok(vec![])
            }
        }
    }

    /// A file's bytes. Files above the cap are not read; the caller gets None and a gap is recorded.
    pub fn raw(&self, path: &str) -> BrResult<Option<Vec<u8>>> {
        const CAP: u64 = 600 * 1024 * 1024;
        let Some(r) = self.call(&self.url(path), "application/vnd.github.raw+json")? else { return Ok(None) };
        if r.header("Content-Length").and_then(|v| v.parse::<u64>().ok()).map(|n| n > CAP).unwrap_or(false) {
            self.note(scope_of(path), "file larger than 600 MB was not read");
            return Ok(None);
        }
        let mut b = vec![];
        r.into_reader().take(CAP + 1).read_to_end(&mut b).map_err(net)?;
        if b.len() as u64 > CAP {
            self.note(scope_of(path), "file larger than 600 MB was not read");
            return Ok(None);
        }
        Ok(Some(b))
    }

    /// A file's first `cap` bytes, and whether the file was longer.
    pub fn raw_upto(&self, path: &str, cap: u64) -> BrResult<Option<(Vec<u8>, bool)>> {
        let Some(r) = self.call(&self.url(path), "application/vnd.github.raw+json")? else { return Ok(None) };
        let mut b = vec![];
        r.into_reader().take(cap + 1).read_to_end(&mut b).map_err(net)?;
        let more = b.len() as u64 > cap;
        b.truncate(cap as usize);
        Ok(Some((b, more)))
    }

    pub fn text(&self, path: &str) -> BrResult<Option<String>> {
        Ok(self.raw(path)?.map(|b| String::from_utf8_lossy(&b).to_string()))
    }

    pub fn download(&self, url: &str) -> BrResult<Option<Vec<u8>>> {
        const CAP: u64 = 600 * 1024 * 1024;
        let Some(r) = self.call(&self.url(url), "application/octet-stream")? else { return Ok(None) };
        if r.header("Content-Length").and_then(|v| v.parse::<u64>().ok()).map(|n| n > CAP).unwrap_or(false) {
            self.note(scope_of(url), "download larger than 600 MB was not opened");
            return Ok(None);
        }
        let mut b = vec![];
        r.into_reader().take(CAP + 1).read_to_end(&mut b).map_err(net)?;
        if b.len() as u64 > CAP {
            self.note(scope_of(url), "download larger than 600 MB was not opened");
            return Ok(None);
        }
        Ok(Some(b))
    }

    /// Stream a download through sha256 without holding it (the whole body, never a prefix).
    pub fn download_hash(&self, url: &str) -> BrResult<Option<(String, u64)>> {
        use sha2::{Digest, Sha256};
        let Some(r) = self.call(&self.url(url), "application/octet-stream")? else { return Ok(None) };
        let mut rd = r.into_reader();
        let (mut h, mut n, mut buf) = (Sha256::new(), 0u64, vec![0u8; 256 * 1024]);
        loop {
            let k = rd.read(&mut buf).map_err(net)?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            n += k as u64;
        }
        Ok(Some((format!("{:x}", h.finalize()), n)))
    }
}

enum Reply {
    Resp(ureq::Response),
    NotModified,
    Missing,
}

fn next_link(h: &str) -> Option<String> {
    h.split(',').find(|p| p.contains("rel=\"next\"")).and_then(|p| {
        let a = p.find('<')?;
        let b = p.find('>')?;
        Some(p[a + 1..b].to_string())
    })
}

pub(crate) fn s(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_string)
}

fn ts(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().and_then(norm_api_time)
}

// ---- the org -----------------------------------------------------------------------------------------------------
pub struct OrgData {
    pub org: Org,
    pub people: Vec<Person>,
    pub teams: Vec<Team>,
    pub admins: Vec<String>,
    pub secrets: Vec<String>,
    /// Each org secret with its scope label (`org (all repos)`, `org (selected repos)`) and the repos a selected one reaches.
    pub secret_scopes: Vec<SecretScope>,
    /// false when the token could not read the org's secret list
    pub secrets_readable: bool,
}

/// Org secret names with their visibility. An unreadable list is a gap; `selected` ones list their repositories.
fn org_secrets(gh: &Gh, name: &str) -> BrResult<(Vec<String>, Vec<SecretScope>, bool)> {
    let Some(v) = gh.json(&format!("/orgs/{name}/actions/secrets"))? else {
        gh.note("org secrets", "org secrets not readable: needs admin:org");
        return Ok((vec![], vec![], false));
    };
    let (mut names, mut scopes) = (vec![], vec![]);
    for x in v["secrets"].as_array().cloned().unwrap_or_default() {
        let Some(n) = s(&x, "name") else { continue };
        let vis = s(&x, "visibility").unwrap_or_else(|| "all".into());
        let mut repos = vec![];
        if vis == "selected" {
            match gh.json(&format!("/orgs/{name}/actions/secrets/{n}/repositories"))? {
                Some(r) => repos = r["repositories"].as_array().cloned().unwrap_or_default().iter().filter_map(|y| s(y, "full_name")).collect(),
                None => gh.note(format!("org secret {n}"), "selected repositories not readable"),
            }
        }
        names.push(n.clone());
        // GitHub's visibility: all or private (every, or every private, repo) and selected (a list)
        let label = if vis == "selected" { "org (selected repos)" } else { "org (all repos)" };
        scopes.push(SecretScope { name: n, scope: label.into(), repos, created_at: s(&x, "created_at"), updated_at: s(&x, "updated_at") });
    }
    Ok((names, scopes, true))
}

pub fn org(gh: &Gh, name: &str) -> BrResult<OrgData> {
    let Some(o) = gh.json(&format!("/orgs/{name}"))? else {
        // a personal account: its repos are indexed, there are no members or teams
        if let Some(u) = gh.json(&format!("/users/{name}"))?.filter(|u| u["type"] == "User") {
            let login = s(&u, "login").unwrap_or_else(|| name.to_string());
            let nm = s(&u, "name").filter(|n| !n.is_empty());
            let person = Person { login: login.clone(), name: nm.clone(), team: None, teams: vec![] };
            return Ok(OrgData {
                org: Org { github: Some(login.clone()), name: nm },
                people: vec![person],
                teams: vec![],
                admins: vec![login],
                secrets: vec![],
                secret_scopes: vec![],
                secrets_readable: true,
            });
        }
        return Err(BrError::with_code(format!("organisation {name} not found"), Some("check the name; the token must be able to read it"), 4));
    };
    let login = s(&o, "login").unwrap_or_else(|| name.to_string());
    let org = Org { github: Some(login.clone()), name: s(&o, "name").filter(|n| !n.is_empty()) };
    let mut people: BTreeMap<String, Person> = BTreeMap::new();
    for m in gh.list(&format!("/orgs/{name}/members"), None)? {
        if let Some(l) = s(&m, "login") {
            let name = gh.json(&format!("/users/{l}"))?.and_then(|u| s(&u, "name")).filter(|n| !n.is_empty());
            people.insert(l.clone(), Person { login: l, name, team: None, teams: vec![] });
        }
    }
    let admins: Vec<String> = gh.list(&format!("/orgs/{name}/members?role=admin"), None)?.iter().filter_map(|m| s(m, "login")).collect();
    // An admin is named wherever the admins are listed ("org admins (Dana Lee, Sam Ito)"), so each one is a person with a name
    for l in &admins {
        if !people.contains_key(l) {
            let nm = gh.json(&format!("/users/{l}"))?.and_then(|u| s(&u, "name")).filter(|n| !n.is_empty());
            people.insert(l.clone(), Person { login: l.clone(), name: nm, team: None, teams: vec![] });
        }
    }
    let mut teams = vec![];
    for t in gh.list(&format!("/orgs/{name}/teams"), None)? {
        let Some(slug) = s(&t, "slug") else { continue };
        let lead = gh.list(&format!("/orgs/{name}/teams/{slug}/members?role=maintainer"), None)?.iter().filter_map(|m| s(m, "login")).next();
        for m in gh.list(&format!("/orgs/{name}/teams/{slug}/members"), None)? {
            if let Some(l) = s(&m, "login") {
                let p = people.entry(l.clone()).or_insert_with(|| Person { login: l, ..Default::default() });
                if p.team.is_none() {
                    p.team = Some(slug.clone());
                }
                if !p.teams.contains(&slug) {
                    p.teams.push(slug.clone());
                }
            }
        }
        teams.push(Team { id: format!("@{login}/{slug}"), slack: None, jira: None, lead });
    }
    teams.sort_by(|a, b| a.id.cmp(&b.id));
    let (secrets, secret_scopes, secrets_readable) = org_secrets(gh, name)?;
    Ok(OrgData { org, people: people.into_values().collect(), teams, admins, secrets, secret_scopes, secrets_readable })
}

pub struct RepoInfo {
    pub name: String,
    pub default_branch: String,
    pub archived: bool,
}

pub fn repos(gh: &Gh, org: &str) -> BrResult<Vec<RepoInfo>> {
    let is_org = gh.json(&format!("/orgs/{org}"))?.is_some();
    // a personal account: the repos it owns, not its forks (those are other people's code)
    let list = if is_org { gh.list(&format!("/orgs/{org}/repos?type=all"), None)? } else { gh.list(&format!("/users/{org}/repos?type=owner"), None)? };
    let mut out: Vec<RepoInfo> = vec![];
    for r in list.iter().filter(|r| is_org || r["fork"].as_bool() != Some(true)) {
        let Some(name) = s(r, "full_name") else { continue };
        // the listing normally carries the default branch; when it does not, ask the repo itself, never assume "main"
        let default_branch = match s(r, "default_branch") {
            Some(b) => b,
            None => match gh.json(&format!("/repos/{name}"))?.and_then(|v| s(&v, "default_branch")) {
                Some(b) => b,
                None => {
                    gh.note(&name, "default branch unknown: the repository listing and the repo itself did not name one");
                    "HEAD".to_string()
                }
            },
        };
        out.push(RepoInfo { name, default_branch, archived: r["archived"].as_bool().unwrap_or(false) });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// ---- one repo ----------------------------------------------------------------------------------------------------
/// Percent-encode a path for a URL, keeping `/`.
pub(crate) fn enc(p: &str) -> String {
    let mut o = String::with_capacity(p.len());
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Percent-encode one URL segment or query value (also `/`).
pub(crate) fn enc_ref(p: &str) -> String {
    enc(p).replace('/', "%2F")
}

/// `owner/repo/sub/path@ref` -> `owner/repo@ref`.
fn strip_sub(u: &str) -> String {
    let (p, r) = u.split_once('@').unwrap_or((u, ""));
    let seg: Vec<&str> = p.split('/').take(2).collect();
    if r.is_empty() {
        seg.join("/")
    } else {
        format!("{}@{r}", seg.join("/"))
    }
}

fn sub_path(u: &str) -> String {
    let p = u.split('@').next().unwrap_or("");
    p.split('/').skip(2).collect::<Vec<_>>().join("/")
}

/// Record what a lockfile parse could not tell as one gap on the repo.
fn lock_note(gh: &Gh, lp: &str, l: &lock::Lock) {
    // go.sum falling back to "highest version of each module" only over-reports; it never hides a module, so it is not a gap
    let mut parts: Vec<String> = l.gaps.iter().filter(|g| !g.starts_with("go.sum is a hash record")).cloned().collect();
    if let Some(u) = l.unpinned.first() {
        parts.push(format!("{} requirement(s) are not pinned to one version and cannot be checked, e.g. {} {} (line {})", l.unpinned.len(), u.name, u.spec, u.line));
    }
    if !parts.is_empty() {
        gh.note(format!("lockfile {lp}"), parts.join("; "));
    }
}

/// The lockfiles an install command reads, out of every lockfile in the repo. All of them when the command is not recognised.
fn relevant_locks<'a>(install: &str, locks: &'a [String]) -> Vec<&'a String> {
    let i = install;
    let mut want: Vec<&str> = vec![];
    let mut prefix_req = false;
    if i.contains("npm") {
        want.extend(["package-lock.json", "npm-shrinkwrap.json"]);
    }
    if i.contains("yarn") {
        want.push("yarn.lock");
    }
    if i.contains("pnpm") {
        want.push("pnpm-lock.yaml");
    }
    if i.contains("bun") {
        want.extend(["bun.lock", "bun.lockb"]);
    }
    if i.contains("poetry") {
        want.push("poetry.lock");
    }
    if i.contains("uv ") || i.contains("uv.") {
        want.push("uv.lock");
    }
    if i.contains("pipenv") {
        want.push("Pipfile.lock");
    }
    if (i.contains("pip install") || i.contains("pip3 install")) && !i.contains("pipenv") || i.contains("requirements") {
        prefix_req = true;
    }
    if i.contains("cargo") {
        want.push("Cargo.lock");
    }
    if i.contains("go ") {
        want.push("go.sum");
    }
    let pick: Vec<&String> = locks.iter().filter(|l| want.contains(&base_of(l)) || (prefix_req && base_of(l).starts_with("requirements") && base_of(l).ends_with(".txt"))).collect();
    if pick.is_empty() {
        locks.iter().collect()
    } else {
        pick
    }
}

fn base_of(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn dir_of(p: &str) -> &str {
    p.rfind('/').map(|i| &p[..i]).unwrap_or("")
}

fn manifest_direct(m: &Manifest) -> BTreeMap<String, bool> {
    m.deps.iter().map(|(k, d)| (k.clone(), d.section.as_deref().map(|s| s.to_lowercase().contains("dev")).unwrap_or(false))).collect()
}

pub(crate) fn skipped_dir(p: &str) -> bool {
    p.split('/').any(|s| s == "node_modules" || s == ".git" || s == "vendor" || s == "third_party")
}

fn is_lock_path(p: &str) -> bool {
    !skipped_dir(p) && (lock::LOCKFILES.contains(&base_of(p)) || lock::is_requirements(base_of(p)))
}

const COMMITS_PER_PATH: usize = 300;
pub use crate::parse::lock::NO_PACKAGES;
pub const RUNS_PAGE_CAP: usize = 1000;

/// Every blob path of the branch. When GitHub says the recursive listing was cut short, the tree is walked one subtree
/// at a time; a subtree that is still cut short is a gap.
fn tree_blobs(gh: &Gh, r: &str, branch: &str) -> BrResult<Option<Vec<String>>> {
    let scope = "git tree";
    let Some(t) = gh.json_need(&format!("/repos/{r}/git/trees/{}?recursive=1", enc_ref(branch)), scope)? else { return Ok(None) };
    let blobs =
        |t: &Value, prefix: &str| -> Vec<String> { t["tree"].as_array().into_iter().flatten().filter(|x| x["type"] == "blob").filter_map(|x| s(x, "path")).map(|p| format!("{prefix}{p}")).collect() };
    if t["truncated"].as_bool() != Some(true) {
        return Ok(Some(blobs(&t, "")));
    }
    // too large for one answer: root entries one by one
    let Some(root) = gh.json(&format!("/repos/{r}/git/trees/{}", enc_ref(branch)))? else { return Ok(Some(blobs(&t, ""))) };
    let mut out = blobs(&root, "");
    let mut stack: Vec<(String, String)> = root["tree"].as_array().into_iter().flatten().filter(|x| x["type"] == "tree").filter_map(|x| Some((s(x, "sha")?, format!("{}/", s(x, "path")?)))).collect();
    while let Some((sha, prefix)) = stack.pop() {
        let Some(sub) = gh.json(&format!("/repos/{r}/git/trees/{sha}?recursive=1"))? else {
            gh.note("git tree", format!("directory {prefix} could not be listed"));
            continue;
        };
        if sub["truncated"].as_bool() == Some(true) {
            let Some(flat) = gh.json(&format!("/repos/{r}/git/trees/{sha}"))? else { continue };
            out.extend(blobs(&flat, &prefix));
            for x in flat["tree"].as_array().into_iter().flatten().filter(|x| x["type"] == "tree") {
                if let (Some(h), Some(p)) = (s(x, "sha"), s(x, "path")) {
                    stack.push((h, format!("{prefix}{p}/")));
                }
            }
        } else {
            out.extend(blobs(&sub, &prefix));
        }
    }
    Ok(Some(out))
}

/// All workflow runs created up to `until`. GitHub returns at most 1000 results for one query, so a full answer is
/// continued by asking again for the runs created at or before the oldest one received, until a query comes back short.
pub fn runs_all(gh: &Gh, r: &str, until: &str) -> BrResult<Vec<Value>> {
    let mut out: Vec<Value> = vec![];
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut upper = until.to_string();
    loop {
        let path = format!("/repos/{r}/actions/runs?created=%3C%3D{upper}");
        let Some(batch) = gh.list_opt(&path, Some("workflow_runs"))? else {
            if out.is_empty() {
                gh.note("actions runs", "HTTP 404: no Actions access with this token, or the repo has no runs");
            }
            break;
        };
        let full = batch.len() >= RUNS_PAGE_CAP;
        let oldest = batch.iter().filter_map(|x| x["created_at"].as_str().map(str::to_string)).min();
        let before = seen.len();
        for x in batch {
            if let Some(id) = x["id"].as_u64() {
                if seen.insert(id) {
                    out.push(x);
                }
            }
        }
        if !full {
            break;
        }
        match oldest {
            Some(o) if o != upper && seen.len() > before => upper = o,
            _ => {
                gh.note("actions runs", format!("more than {RUNS_PAGE_CAP} runs share the moment {upper}; older runs were not listed"));
                break;
            }
        }
    }
    Ok(out)
}

/// What the store already holds for a repo, so an unchanged commit, artifact or release asset is not read again.
#[derive(Default)]
pub struct Known {
    pub commits: BTreeMap<String, Value>,
    pub artifacts: BTreeMap<String, Value>,
    pub releases: BTreeMap<String, Value>,
}

/// Collect one repository as the rows of `kinds`. What could not be checked is left in `gh` (see `Gh::take_gaps`).
pub fn collect_repo(gh: &Gh, ctx: &Ctx, info: &RepoInfo, known: &Known) -> BrResult<Vec<Row>> {
    let r = &info.name;
    let branch = &info.default_branch;
    let now = ctx.now.as_str();
    let mut repo = Repo { default_branch: Some(branch.clone()), archived: info.archived, ..Default::default() };
    if info.archived {
        let org = r.split('/').next().unwrap_or("");
        // one call, filtered to this repo on the server
        let q = format!("/orgs/{org}/audit-log?phrase={}", enc_ref(&format!("action:repo.archived repo:{r}")));
        if let Some(Value::Array(entries)) = gh.json(&q)? {
            let hit = entries.iter().filter(|e| e["repo"].as_str().map(|x| x == r.as_str()).unwrap_or(true)).max_by_key(|e| e["@timestamp"].as_i64().unwrap_or(0));
            if let Some(e) = hit {
                repo.archived_by = e["actor"].as_str().map(str::to_string);
                repo.archived_at = e["@timestamp"].as_i64().map(|ms| crate::collect::util::iso(ms / 1000));
            }
        }
    }
    let mut head_sha: Option<String> = None;
    // The owner of last resort for a repo nobody is named for: who pushed to it last (one call; the clock law applies)
    if let Some(Value::Array(cs)) = gh.json(&format!("/repos/{r}/commits?sha={}&per_page=1&until={}", enc_ref(branch), enc_ref(now)))? {
        if let Some(c) = cs.first() {
            head_sha = s(c, "sha");
            repo.last_committer = c["author"]["login"].as_str().map(str::to_string);
            repo.last_commit_at = ts(&c["commit"]["committer"], "date").or_else(|| ts(&c["commit"]["author"], "date"));
        }
    }
    let tree: Vec<String> = tree_blobs(gh, r, branch)?.unwrap_or_default();
    let tset: BTreeSet<&str> = tree.iter().map(|x| x.as_str()).collect();
    let file = |p: &str, rf: &str| gh.text(&format!("/repos/{r}/contents/{}?ref={}", enc(p), enc_ref(rf)));
    for c in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"] {
        if tset.contains(c) {
            repo.codeowners = file(c, branch)?.unwrap_or_default();
            break;
        }
    }

    // every lockfile at any depth, each with its manifest
    let mut lock_paths: Vec<String> = tree.iter().filter(|p| is_lock_path(p)).cloned().collect();
    lock_paths.sort_by(|a, b| (a.matches('/').count(), a.as_str()).cmp(&(b.matches('/').count(), b.as_str())));
    for p in tree.iter().filter(|p| !skipped_dir(p) && lock::is_unsupported_lock(p)) {
        let (sc, why) = lock::no_packages_gap(p, &lock::NoPackages::Unsupported);
        gh.note(sc, why);
    }
    let manifest_of = |lp: &str| -> Option<String> {
        if lock::is_requirements(base_of(lp)) {
            return Some(lp.to_string());
        }
        let m = lock::manifest_for(lp)?;
        let d = dir_of(lp);
        let full = if d.is_empty() { m.to_string() } else { format!("{d}/{m}") };
        tset.contains(full.as_str()).then_some(full)
    };
    repo.lockfiles = lock_paths.clone();
    repo.lockfile = lock_paths.first().cloned().or_else(|| if tset.contains("package.json") { Some("package.json".to_string()) } else { None });
    let primary_manifest: Option<String> = match repo.lockfile.as_deref() {
        Some("package.json") => Some("package.json".to_string()),
        Some(l) => manifest_of(l),
        None => None,
    };
    let mut tracked: Vec<(String, bool)> = lock_paths.iter().map(|l| (l.clone(), true)).collect();
    for m in lock_paths.iter().filter_map(|l| manifest_of(l)).chain(primary_manifest.clone()) {
        if !tracked.iter().any(|(p, _)| *p == m) {
            tracked.push((m, false));
        }
    }

    // workflows and composite actions
    let mut wf_text: BTreeMap<String, String> = BTreeMap::new();
    for p in tree.iter().filter(|p| p.starts_with(".github/workflows/") && (p.ends_with(".yml") || p.ends_with(".yaml")) && p.matches('/').count() == 2) {
        if let Some(t) = file(p, branch)? {
            match ci::workflow_checked(p, &t) {
                Ok(w) => repo.workflows.push(w),
                Err(e) => gh.note(format!("workflow {p}"), format!("the file is not valid YAML, so its install step, secrets and runners are unknown ({})", e.lines().next().unwrap_or(""))),
            }
            wf_text.insert(p.clone(), t);
        }
    }
    for p in tree.iter().filter(|p| p.ends_with("/action.yml") || p.ends_with("/action.yaml") || *p == "action.yml" || *p == "action.yaml") {
        if skipped_dir(p) {
            continue;
        }
        if let Some(t) = file(p, branch)? {
            if let Some(c) = ci::composite(p, &t) {
                repo.composite_actions.push(c);
            }
        }
    }
    // Config files at HEAD that name environment variables (names and lines only, a capped set)
    {
        let mut cfg: Vec<&String> = tree.iter().filter(|p| crate::parse::envfile::is_config_path(p)).collect();
        cfg.sort_by(|a, b| (a.matches('/').count(), a.as_str()).cmp(&(b.matches('/').count(), b.as_str())));
        if cfg.len() > crate::parse::envfile::MAX_FILES {
            gh.note(format!("config files of {r}"), format!("only the first {} of {} config files were read for secret names", crate::parse::envfile::MAX_FILES, cfg.len()));
        }
        for p in cfg.into_iter().take(crate::parse::envfile::MAX_FILES) {
            if let Some(t) = file(p, branch)? {
                let t: String = t.chars().take(crate::parse::envfile::MAX_BYTES).collect();
                repo.env_refs.extend(crate::parse::envfile::env_names(p, &t));
            }
        }
    }
    if !repo.workflows.is_empty() {
        let list = |p: &str| secret_names(gh, r, p);
        // A repo-level secret is `repo`; an environment's secrets carry the environment's name. Org secrets are
        // scoped in `View.secret_scopes` (the org list says all or selected repos). each keeps GitHub's dates
        let dated = secret_items(gh, r, "secrets")?;
        let mut all: Vec<String> = dated.iter().map(|i| i.0.clone()).collect();
        let mut scopes: Vec<SecretScope> = dated.iter().map(|(n, c, u)| SecretScope { name: n.clone(), scope: "repo".into(), repos: vec![], created_at: c.clone(), updated_at: u.clone() }).collect();
        all.extend(list("organization-secrets")?);
        // environment secrets: every environment's names
        let envs = env_secret_items(gh, r)?;
        for (e, items) in &envs {
            for (n, c, u) in items {
                all.push(n.clone());
                scopes.push(SecretScope { name: n.clone(), scope: format!("environment {e}"), repos: vec![], created_at: c.clone(), updated_at: u.clone() });
            }
        }
        all.sort();
        all.dedup();
        repo.secret_scopes = scopes;
        if !all.is_empty() {
            for w in &repo.workflows {
                repo.secrets_all.insert(w.file.rsplit('/').next().unwrap_or(&w.file).to_string(), all.clone());
            }
        }
    }

    // commits that touched a lockfile or a manifest
    let mut commits: BTreeMap<String, (Value, BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    let mut with_history: BTreeSet<String> = BTreeSet::new();
    for (path, is_lock) in &tracked {
        let (list, cut) = gh.list_max(&format!("/repos/{r}/commits?sha={}&path={}&until={now}", enc_ref(branch), enc_ref(path)), None, COMMITS_PER_PATH)?;
        if cut {
            gh.note(format!("history of {path}"), format!("only the newest {COMMITS_PER_PATH} commits of this file were read"));
        }
        let list = list.unwrap_or_default();
        if *is_lock && !list.is_empty() {
            with_history.insert(path.clone());
        }
        for c in list {
            let Some(sha) = s(&c, "sha") else { continue };
            let e = commits.entry(sha).or_insert((c, BTreeSet::new(), BTreeSet::new()));
            if *is_lock {
                e.1.insert(path.clone());
            } else {
                e.2.insert(path.clone());
            }
        }
    }
    // recent commits that touch neither (their authors are possible hosts): first page only
    if let Ok(Got::Ok(v)) = gh.get(&format!("/repos/{r}/commits?sha={}&until={now}", enc_ref(branch))) {
        for c in v.as_array().cloned().unwrap_or_default() {
            if let Some(sha) = s(&c, "sha") {
                commits.entry(sha).or_insert((c, BTreeSet::new(), BTreeSet::new()));
            }
        }
    }
    // a lockfile in the tree that no commit of the branch lists for its path (history the host does not give, a squashed or
    // shallow import): read the file as it is at HEAD, and say so. Never an empty answer.
    let no_history: Vec<String> = lock_paths.iter().filter(|l| !with_history.contains(*l)).cloned().collect();
    if let Some(h) = &head_sha {
        if !no_history.is_empty() {
            let e = commits.entry(h.clone()).or_insert((serde_json::json!({"sha": h}), BTreeSet::new(), BTreeSet::new()));
            for l in &no_history {
                e.1.insert(l.clone());
            }
        }
    }
    let mut rows: Vec<Row> = vec![];
    let mut cl: Vec<Commit> = vec![];
    let mut file_at: BTreeMap<(String, String), Option<String>> = BTreeMap::new();
    let mut undated = 0usize;
    for (sha, (c, lock_touched, man_touched)) in commits {
        let at = c["commit"]["committer"]["date"].as_str().and_then(norm_api_time).or_else(|| c["commit"]["author"]["date"].as_str().and_then(norm_api_time));
        // no readable date: the commit is kept with an empty time (never an invented one) and the gap says so
        if at.is_none() {
            undated += 1;
        }
        let at = at.unwrap_or_default();
        if at.as_str() > now {
            continue;
        }
        if let Some(old) = known.commits.get(&sha) {
            if let Ok(cm) = serde_json::from_value::<Commit>(old.clone()) {
                // reusable when it already holds every lockfile this scan sees touched by the commit
                let legacy_ok = cm.lock_packages.is_empty() && lock_touched.len() <= 1 && (lock_touched.is_empty() || cm.packages.is_some());
                if lock_touched.iter().all(|l| cm.lock_packages.contains_key(l)) && (legacy_ok || !cm.lock_packages.is_empty() || lock_touched.is_empty()) {
                    cl.push(cm);
                    continue;
                }
            }
        }
        let mut cm = Commit {
            sha: sha.clone(),
            at,
            author: c["author"]["login"].as_str().map(str::to_string).or_else(|| c["commit"]["author"]["name"].as_str().map(str::to_string)),
            message: c["commit"]["message"].as_str().map(|m| m.lines().next().unwrap_or("").to_string()),
            ..Default::default()
        };
        let mut get = |p: &str| -> BrResult<Option<String>> {
            let k = (sha.clone(), p.to_string());
            if let Some(v) = file_at.get(&k) {
                return Ok(v.clone());
            }
            let t = file(p, &sha)?;
            file_at.insert(k, t.clone());
            Ok(t)
        };
        if let Some(mp) = &primary_manifest {
            if man_touched.contains(mp) {
                cm.manifest = get(mp)?.and_then(|t| parse_manifest(gh, mp, &t, &sha));
            }
        }
        let mut union: Vec<LockPackage> = vec![];
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for lp in &lock_touched {
            let man = match manifest_of(lp) {
                Some(mp) => get(&mp)?.and_then(|t| parse_manifest(gh, &mp, &t, &sha)),
                None => None,
            };
            let Some(t) = get(lp)? else { continue };
            match lock::parse_with(lp, &t, &mut |p: &str| get(p).ok().flatten()) {
                Some(l) => {
                    lock_note(gh, lp, &l);
                    let md = man.as_ref().map(manifest_direct);
                    let pk = lock::packages(&l, md.as_ref());
                    for p in &pk {
                        if seen.insert(p.p.clone()) {
                            union.push(p.clone());
                        }
                    }
                    cm.lock_packages.insert(lp.clone(), pk);
                }
                None => gh.note(format!("lockfile {lp}"), format!("could not be parsed at commit {}", &sha[..sha.len().min(7)])),
            }
        }
        if !lock_touched.is_empty() && !cm.lock_packages.is_empty() {
            cm.packages = Some(union);
        }
        cl.push(cm);
    }
    for lp in &lock_paths {
        let scope = format!("lockfile {lp}");
        let packages: usize = cl.iter().filter_map(|c| c.lock_packages.get(lp)).map(|v| v.len()).sum();
        let listed = cl.iter().any(|c| c.lock_packages.contains_key(lp));
        let hist = no_history.contains(lp);
        if packages == 0 {
            use lock::NoPackages as N;
            let why = match (hist, listed) {
                (true, false) => N::NoHistoryUnread,
                (true, true) => N::NoHistoryEmpty,
                (false, false) => N::HistoryUnread,
                (false, true) => N::Empty,
            };
            let (_, why) = lock::no_packages_gap(lp, &why);
            let why = why.strip_prefix(&format!("{NO_PACKAGES}: ")).unwrap_or(&why).to_string();
            let why = match gh.gap_reason(&scope).filter(|r| !r.starts_with(NO_PACKAGES)) {
                Some(r) => format!("{why} ({r})"),
                None => why,
            };
            gh.note_replace(scope, format!("{NO_PACKAGES}: {why}"));
        } else if hist {
            gh.note_replace(scope, "the host gives no commit history for this path, so it was read at HEAD only: when its packages arrived is unknown");
        }
    }
    if undated > 0 {
        gh.note("commit dates", format!("{undated} commits carry no readable date and are kept undated"));
    }
    cl.sort_by(|a, b| (a.at.as_str(), a.sha.as_str()).cmp(&(b.at.as_str(), b.sha.as_str())));
    for c in cl {
        rows.push(Row::new("commit", c.sha.clone(), &c));
    }

    // runs
    let mut installed_by_key: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let re_img = Regex::new(r"pushing manifest for ([^\s@]+?)(?::[^/@\s]+)?@(sha256:[0-9a-f]{64})").unwrap();
    let mut lock_at: BTreeMap<(String, String), Option<Vec<LockPackage>>> = BTreeMap::new();
    let mut run_rows: Vec<Run> = vec![];
    let mut composite_cache: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen_images: BTreeSet<String> = BTreeSet::new();
    let (mut no_log, mut no_wf, mut total_runs) = (0usize, 0usize, 0usize);
    let mut unnamed_self_hosted = 0usize;
    for run in runs_all(gh, r, now)? {
        let id = run["id"].as_u64().unwrap_or(0);
        let at = run["run_started_at"]
            .as_str()
            .and_then(norm_api_time)
            .or_else(|| run["created_at"].as_str().and_then(norm_api_time))
            .or_else(|| run["updated_at"].as_str().and_then(norm_api_time))
            .unwrap_or_default();
        if at.as_str() > now || id == 0 {
            continue;
        }
        total_runs += 1;
        let path = run["path"].as_str().unwrap_or("").split('@').next().unwrap_or("").to_string();
        let wf_file = path.rsplit('/').next().unwrap_or("").to_string();
        let head = s(&run, "head_sha");
        let mut x = Run { id, workflow: wf_file.clone(), path: if path.is_empty() { None } else { Some(path.clone()) }, at, commit: head.clone(), ..Default::default() };
        // jobs: which runner took each job, and the logs
        let mut log = String::new();
        let mut runners: Vec<String> = vec![];
        let mut hosted = false;
        let mut run_missed = false;
        for j in gh.list(&format!("/repos/{r}/actions/runs/{id}/jobs"), Some("jobs"))? {
            let rn = s(&j, "runner_name").filter(|n| !n.is_empty());
            if rn.is_none() && j["conclusion"].as_str() != Some("skipped") && j["labels"].as_array().map(|l| l.iter().any(|x| x.as_str() == Some("self-hosted"))).unwrap_or(false) {
                unnamed_self_hosted += 1;
            }
            let is_hosted = j["runner_group_name"].as_str() == Some("GitHub Actions") || rn.as_deref().map(|n| n.starts_with("GitHub Actions") || n.starts_with("github-actions")).unwrap_or(false);
            match rn {
                Some(n) if !is_hosted => {
                    if !runners.contains(&n) {
                        runners.push(n);
                    }
                }
                _ => hosted = true,
            }
            if let Some(jid) = j["id"].as_u64() {
                match gh.quietly(|| gh.text(&format!("/repos/{r}/actions/jobs/{jid}/logs")))? {
                    Some(t) => {
                        log.push_str(&t);
                        log.push('\n');
                    }
                    None => run_missed = true,
                }
            }
        }
        if run_missed {
            no_log += 1;
        }
        x.runner = Some(runners.first().cloned().unwrap_or_else(|| {
            let _ = hosted;
            "github-hosted".into()
        }));
        x.runners = runners;
        // the workflow at that commit; today's file is not a stand-in for it
        let wf = match &head {
            Some(h) if !path.is_empty() => match file(&path, h)? {
                Some(t) => match ci::workflow_checked(&path, &t) {
                    Ok(w) => Some(w),
                    Err(e) => {
                        gh.note(
                            format!("workflow {path} at a run commit"),
                            format!("the file is not valid YAML there, so its install step and secrets are unknown ({})", e.lines().next().unwrap_or("")),
                        );
                        None
                    }
                },
                None => None,
            },
            _ => None,
        };
        if wf.is_none() {
            no_wf += 1;
        }
        if let Some(w) = &wf {
            x.secrets = w.secrets.clone();
        }
        let install = wf.as_ref().and_then(|w| w.install.clone());
        let is_frozen = install.as_deref().map(ci::frozen_install).unwrap_or(false);
        // A frozen install of a lockfile br parsed is decided by the lockfile (`resolved_from: lockfile`); the log is only a
        // cross-check only (it still decides when the lockfile cannot be read). Any other install keeps the log, which is what ran.
        let mut lock_pkgs: Option<Vec<String>> = None;
        if is_frozen && !lock_paths.is_empty() {
            if let Some(h) = &head {
                let mut all: Vec<String> = vec![];
                let mut ok = true;
                for lp in relevant_locks(install.as_deref().unwrap_or(""), &lock_paths) {
                    let pk = lock_at.entry((h.clone(), lp.clone())).or_insert_with(|| {
                        let t = gh.text(&format!("/repos/{r}/contents/{}?ref={}", enc(lp), enc_ref(h))).ok().flatten()?;
                        let Some(l) = lock::parse_with(lp, &t, &mut |p: &str| gh.text(&format!("/repos/{r}/contents/{}?ref={}", enc(p), enc_ref(h))).ok().flatten()) else {
                            gh.note(format!("lockfile {lp}"), format!("could not be parsed at run commit {}; what that run installed comes from its log instead", &h[..h.len().min(7)]));
                            return None;
                        };
                        lock_note(gh, lp, &l);
                        Some(lock::packages(&l, None))
                    });
                    match pk {
                        Some(pk) => all.extend(pk.iter().map(|p| p.p.clone())),
                        None => ok = false,
                    }
                }
                if ok {
                    lock_pkgs = Some(all);
                }
            }
        }
        if let Some((pkgs, from)) = ci::run_installed(install.as_deref(), lock_pkgs, &log) {
            x.installed = pkgs;
            x.resolved_from = Some(from.into());
        }
        for k in ci::cache_keys(&log) {
            if !x.caches_saved.contains(&k) {
                x.caches_saved.push(k);
            }
        }
        for c in re_img.captures_iter(&log) {
            let imgref = format!("{}@{}", &c[1], &c[2]);
            if seen_images.insert(format!("{id}{imgref}")) {
                x.produced_images.push(imgref);
            }
        }
        let wf_uses: Vec<String> = wf.as_ref().map(|w| w.uses.clone()).unwrap_or_default();
        for (a, sha) in ci::action_downloads(&log) {
            let Some(sha) = sha else { continue };
            let direct = |u: &str| strip_sub(u) == a;
            let mut key = a.clone();
            if !wf_uses.iter().any(|u| direct(u)) {
                for u in wf_uses.iter().filter(|u| strip_sub(u) != **u) {
                    let (repo_ref, sub) = (strip_sub(u), sub_path(u));
                    let (or, rf) = repo_ref.split_once('@').unwrap_or((&repo_ref, ""));
                    let path = if sub.is_empty() { "action.yml".to_string() } else { format!("{sub}/action.yml") };
                    let cached = composite_cache.entry(u.clone()).or_insert_with(|| {
                        gh.text(&format!("/repos/{or}/contents/{}?ref={}", enc(&path), enc_ref(rf))).ok().flatten().and_then(|t| ci::composite(&path, &t)).map(|c| c.uses).unwrap_or_default()
                    });
                    if cached.iter().any(|c| strip_sub(c) == a) {
                        key = format!("{a} (via {u})");
                        break;
                    }
                }
            }
            if let Some((n, rf)) = key.split_once('@') {
                if rf.len() == 40 && rf.chars().all(|c| c.is_ascii_hexdigit()) {
                    key = format!("{n}@{}...", &rf[..7]);
                }
            }
            x.action_resolved.insert(key, sha);
        }
        for k in &x.caches_saved {
            installed_by_key.insert(k.clone(), x.installed.clone());
        }
        // Runtimes the runner log states (tool cache paths, setup action output); added after the cache keys above
        // so a cache does not claim them
        let mut rts: Vec<String> = log.lines().flat_map(crate::query::runtime::log_versions).map(|(n, v)| crate::query::runtime::pseudo(n, &v)).collect();
        rts.sort();
        rts.dedup();
        if !rts.is_empty() {
            if x.resolved_from.is_none() {
                x.resolved_from = Some("runner log (runtimes)".into());
            }
            x.installed.extend(rts);
        }
        run_rows.push(x);
    }
    if no_log > 0 {
        gh.note(
            "run logs",
            format!("{no_log} of {total_runs} runs have no readable log (expired after retention, or the token cannot read logs); what they installed is unknown unless the install was frozen"),
        );
    }
    if unnamed_self_hosted > 0 {
        gh.note("job runners", format!("{unnamed_self_hosted} self-hosted job(s) report no runner name, so the machine that ran them is unknown"));
    }
    if no_wf > 0 {
        gh.note("workflow files at run commits", format!("{no_wf} of {total_runs} runs had no workflow file at their commit; their secrets and install step are unknown"));
    }
    run_rows.sort_by(|a, b| (a.at.as_str(), a.id).cmp(&(b.at.as_str(), b.id)));
    for x in &run_rows {
        rows.push(Row::new("run", x.id.to_string(), x));
    }

    // caches
    for c in gh.list_need(&format!("/repos/{r}/actions/caches"), Some("actions_caches"), "actions caches")? {
        let Some(key) = s(&c, "key") else { continue };
        let created = ts(&c, "created_at").unwrap_or_default();
        if created.as_str() > now {
            continue;
        }
        let x = Cache {
            key: key.clone(),
            created,
            last_used: ts(&c, "last_accessed_at"),
            size_mb: c["size_in_bytes"].as_u64().map(|b| (b + 524_288) / 1_048_576),
            contains: installed_by_key.get(&key).cloned().unwrap_or_default(),
        };
        rows.push(Row::new("cache", key, &x));
    }

    // artifacts
    for a in gh.list_need(&format!("/repos/{r}/actions/artifacts"), Some("artifacts"), "actions artifacts")? {
        let id = a["id"].as_u64().unwrap_or(0);
        let created = ts(&a, "created_at").unwrap_or_default();
        if created.as_str() > now || id == 0 {
            continue;
        }
        let mut contains = vec![];
        let mut unread: Vec<(String, String)> = vec![];
        if a["expired"].as_bool() != Some(true) {
            // an artifact never changes after upload: what was read from it before is reused
            if let Some(old) = known
                .artifacts
                .get(&id.to_string())
                .and_then(|o| serde_json::from_value::<Artifact>(o.clone()).ok())
                .filter(|o| o.size_mb == a["size_in_bytes"].as_u64().map(|b| (b + 524_288) / 1_048_576))
            {
                contains = old.contains;
                for (sc, why) in &old.unread {
                    gh.note(format!("artifact {id} {sc}"), why.clone());
                }
                unread = old.unread;
            } else if let Some(url) = s(&a, "archive_download_url") {
                match gh.download(&url)? {
                    Some(z) => (contains, unread) = packages_in_zip(&z, ctx, gh, &format!("artifact {id}")),
                    None => gh.note(format!("artifact {id}"), "the archive could not be downloaded, so its contents were not checked"),
                }
            }
        }
        let x = Artifact {
            id,
            name: s(&a, "name").unwrap_or_default(),
            run: a["workflow_run"]["id"].as_u64(),
            created,
            expires: ts(&a, "expires_at"),
            size_mb: a["size_in_bytes"].as_u64().map(|b| (b + 524_288) / 1_048_576),
            contains,
            unread,
        };
        rows.push(Row::new("artifact", id.to_string(), &x));
    }

    // releases
    for rel in gh.list_need(&format!("/repos/{r}/releases"), None, "releases")? {
        let published = ts(&rel, "published_at").unwrap_or_default();
        let Some(tag) = s(&rel, "tag_name") else { continue };
        if published.is_empty() || published.as_str() > now {
            continue;
        }
        let old: Option<Release> = known.releases.get(&tag).and_then(|o| serde_json::from_value(o.clone()).ok());
        let mut assets = vec![];
        for a in rel["assets"].as_array().cloned().unwrap_or_default() {
            let name = s(&a, "name").unwrap_or_default();
            let size = a["size"].as_u64();
            // the digest GitHub computed at upload; else one it stored before for the same name and size; else stream it
            let api = a["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")).map(str::to_string);
            let cached = old.as_ref().and_then(|o| o.assets.iter().find(|x| x.name == name && x.size == size && size.is_some())).map(|x| x.sha256.clone());
            if let Some(sha) = api.or(cached) {
                assets.push(ReleaseAsset { name, sha256: sha, size });
                continue;
            }
            let Some(url) = s(&a, "url").or_else(|| s(&a, "browser_download_url")) else { continue };
            match gh.download_hash(&url)? {
                Some((sha, n)) => assets.push(ReleaseAsset { name, sha256: sha, size: Some(n) }),
                None => gh.note(format!("release {tag}"), format!("asset {name} could not be downloaded, so it was not hashed")),
            }
        }
        rows.push(Row::new("release", tag.clone(), &Release { tag, published, assets }));
    }
    // Certificate files at HEAD (capped; the cap and the calls it cost are recorded)
    let calls_before = gh.calls();
    let mut trust = read_repo_trust(gh, r, branch, &tree)?;
    trust.api_calls = (gh.calls() - calls_before) as u32;
    rows.extend(crate::collect::cmds::trust_rows(&trust));
    repo.runtimes = crate::collect::runtimes::collect(gh, r, branch, now, &tree)?;
    rows.insert(0, Row::new("repo", r.clone(), &repo));
    Ok(rows)
}

/// Most certificate files read from one repo, and the most bytes read from one.
pub const REPO_TRUST_FILES: usize = 25;
const REPO_TRUST_BYTES: u64 = crate::parse::x509::MAX_BYTES;

/// The files in the tree that name a trust store (bundles first, then any certificate file), read from the default branch.
fn read_repo_trust(gh: &Gh, r: &str, branch: &str, tree: &[String]) -> BrResult<crate::view::TrustSet> {
    let mut set = crate::view::TrustSet { read: true, ..Default::default() };
    let mut cands: Vec<(bool, &String)> = tree.iter().filter(|p| !p.split('/').any(|c| c == ".git")).filter_map(|p| crate::parse::x509::store_path(p, true).map(|k| (!k, p))).collect();
    cands.sort();
    for (i, (known, p)) in cands.iter().enumerate() {
        if i >= REPO_TRUST_FILES {
            set.notes.push(format!("{} more certificate files at HEAD were not read (br reads {REPO_TRUST_FILES} per repo)", cands.len() - REPO_TRUST_FILES));
            break;
        }
        match gh.raw_upto(&format!("/repos/{r}/contents/{}?ref={}", enc(p), enc_ref(branch)), REPO_TRUST_BYTES)? {
            None => set.files.push(crate::view::TrustFile { path: (*p).clone(), certs: vec![], gaps: vec!["the file could not be fetched".into()] }),
            Some((_, true)) => set.files.push(crate::view::TrustFile {
                path: (*p).clone(),
                certs: vec![],
                gaps: vec![format!("the file is over the {} MiB br reads of a trust store file", REPO_TRUST_BYTES / (1024 * 1024))],
            }),
            Some((b, false)) => {
                let rd = crate::parse::x509::read_store(&b, !*known);
                if rd.store {
                    set.files.push(crate::view::TrustFile { path: (*p).clone(), certs: rd.certs, gaps: rd.gaps });
                }
            }
        }
    }
    Ok(set)
}

fn packages_in_zip(z: &[u8], ctx: &Ctx, gh: &Gh, scope: &str) -> (Vec<String>, Vec<(String, String)>) {
    let mut ar = match zip::ZipArchive::new(std::io::Cursor::new(z)) {
        Ok(a) => a,
        Err(e) => {
            gh.note(scope, format!("the archive could not be opened ({e}), so its contents were not checked"));
            return (vec![], vec![]);
        }
    };
    let globs: Vec<String> = crate::collect::config::hash_filter(ctx);
    let mut an = Analyzer::new(&globs, Some(&ctx.now));
    let mut unreadable = 0;
    for i in 0..ar.len() {
        let Ok(mut f) = ar.by_index(i) else {
            unreadable += 1;
            continue;
        };
        if f.is_dir() {
            continue;
        }
        let meta = FileMeta { path: format!("/{}", f.name()), size: f.size(), mtime: 0 };
        an.add(meta, Some(&mut f));
    }
    if unreadable > 0 {
        gh.note(scope, format!("{unreadable} entries of the archive could not be read"));
    }
    // a lockfile inside the archive that gave no packages is a gap, worded as for a repo's own lockfiles
    let unread = an.lock_gaps();
    for (lock_scope, why) in &unread {
        gh.note(format!("{scope} {lock_scope}"), why.clone());
    }
    let mut set = BTreeSet::new();
    for it in an.items() {
        set.extend(it.pkgs);
    }
    (set.into_iter().collect(), unread)
}

pub fn count_label(n: usize) -> String {
    plural(n, "repo")
}

/// The freshness probe: the newest commit on the repo's default branch dated after `indexed_at` and at or before the clock
/// (one GitHub call). None when nothing moved, or when the repo cannot be reached.
pub fn moved_since(ctx: &Ctx, repo: &str, indexed_at: &str) -> Option<String> {
    let gh = Gh::new(ctx);
    let path = format!("/repos/{repo}/commits?since={indexed_at}&until={}", ctx.now);
    let v = gh.list(&path, None).ok()?;
    let (lo, hi) = (crate::collect::util::epoch(indexed_at)?, crate::collect::util::epoch(&ctx.now)?);
    v.iter()
        .filter_map(|c| c["commit"]["committer"]["date"].as_str().or_else(|| c["commit"]["author"]["date"].as_str()))
        .filter_map(|t| crate::collect::util::epoch(t).map(|e| (e, t)))
        .filter(|(e, _)| *e > lo && *e <= hi)
        .max_by_key(|(e, _)| *e)
        .map(|(_, t)| t.to_string())
}

/// A manifest that cannot be parsed is a gap naming the file, never a repo with no dependencies.
fn parse_manifest(gh: &Gh, path: &str, text: &str, sha: &str) -> Option<crate::view::Manifest> {
    match manifest::try_parse(path, text) {
        Ok(m) => Some(m),
        Err(e) => {
            gh.note(format!("manifest {path}"), format!("could not be parsed at commit {} ({}); its direct dependencies are unknown", &sha[..sha.len().min(7)], e.lines().next().unwrap_or("")));
            None
        }
    }
}

/// A secret with the dates GitHub gives it: name, created_at, updated_at.
type SecretItem = (String, Option<String>, Option<String>);

fn items_of(v: &Value) -> Vec<SecretItem> {
    v["secrets"].as_array().cloned().unwrap_or_default().iter().filter_map(|x| Some((s(x, "name")?, s(x, "created_at"), s(x, "updated_at")))).collect()
}

/// Secret names from one actions endpoint. A token without admin scope gets 403/404 here, which is not the same as "no secrets".
fn secret_names(gh: &Gh, r: &str, p: &str) -> BrResult<Vec<String>> {
    Ok(secret_items(gh, r, p)?.into_iter().map(|i| i.0).collect())
}

fn secret_items(gh: &Gh, r: &str, p: &str) -> BrResult<Vec<SecretItem>> {
    let v = gh.json(&format!("/repos/{r}/actions/{p}"))?;
    if v.is_none() {
        gh.note("repo secrets", "repo secrets not readable: needs admin");
    }
    Ok(v.map(|v| items_of(&v)).unwrap_or_default())
}

/// Secret names of every deployment environment of a repo, by environment. An unreadable list or environment is a gap, not "no secrets".
#[cfg(test)]
fn env_secret_names(gh: &Gh, r: &str) -> BrResult<Vec<(String, Vec<String>)>> {
    Ok(env_secret_items(gh, r)?.into_iter().map(|(e, i)| (e, i.into_iter().map(|x| x.0).collect())).collect())
}

fn env_secret_items(gh: &Gh, r: &str) -> BrResult<Vec<(String, Vec<SecretItem>)>> {
    let mut all = vec![];
    // listing environments needs only read access: a 404 means the repo has none (or the plan has no environments); 401/403 is a gap
    gh.last_status.set(0);
    let Some(envs) = gh.json(&format!("/repos/{r}/environments"))? else {
        if matches!(gh.last_status.get(), 401 | 403) {
            gh.note("environment secrets", "environments not readable: the token is refused");
        }
        return Ok(all);
    };
    for e in envs["environments"].as_array().into_iter().flatten().filter_map(|e| s(e, "name")) {
        match gh.json(&format!("/repos/{r}/environments/{}/secrets", enc_ref(&e)))? {
            Some(v) => all.push((e, items_of(&v))),
            None => gh.note(format!("environment secrets of {e}"), "environment secrets not readable: needs admin"),
        }
    }
    Ok(all)
}

/// The three cheap URLs whose ETags say whether a repo moved.
pub fn probe_urls(info: &RepoInfo, now: &str) -> Vec<String> {
    let r = &info.name;
    vec![
        format!("/repos/{r}/commits?sha={}&until={now}&per_page=1", info.default_branch.replace('/', "%2F")),
        format!("/repos/{r}/actions/runs?created=%3C%3D{now}&per_page=1"),
        format!("/repos/{r}/releases?per_page=1"),
    ]
}

/// Read the probe ETags fresh, ahead of the scan. A failure leaves the map short, which only costs the next scan its shortcut.
pub fn snapshot_etags(gh: &Gh, info: &RepoInfo, now: &str) -> BTreeMap<String, String> {
    gh.load_etags(BTreeMap::new());
    for u in probe_urls(info, now) {
        let _ = gh.json_cond(&u);
    }
    let out = gh.etags();
    gh.load_etags(BTreeMap::new());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_get_and_head_pass() {
        assert!(guard_method("GET").is_ok());
        assert!(guard_method("head").is_ok());
        for m in ["POST", "PUT", "PATCH", "DELETE", "post", "OPTIONS", ""] {
            assert!(guard_method(m).is_err(), "{m} must be refused");
        }
    }

    #[test]
    fn built_requests_refuse_writes() {
        let ctx = Ctx { now: "2026-01-01T00:00:00Z".into(), home: ".".into(), user: None, host: None, color: false };
        let gh = Gh::new(&ctx);
        for m in ["POST", "PUT", "PATCH", "DELETE"] {
            let e = gh.build(m, "http://127.0.0.1:1/repos/x/y/issues", "x").expect_err("refused");
            assert!(e.to_string().contains("read-only"), "{e}");
        }
        assert!(gh.build("GET", "http://127.0.0.1:1/x", "x").is_ok());
    }

    #[test]
    fn link_header_next() {
        let h = "<https://api.github.com/x?page=2>; rel=\"next\", <https://api.github.com/x?page=5>; rel=\"last\"";
        assert_eq!(next_link(h).as_deref(), Some("https://api.github.com/x?page=2"));
        assert_eq!(next_link("<https://a/x?page=1>; rel=\"prev\", <https://a/x?page=5>; rel=\"last\""), None);
    }

    /// A one-shot-per-route HTTP/1.1 server: (path-and-query prefix, status, extra header, body). Returns its base URL.
    fn mock(routes: Vec<(&'static str, u16, String, String)>) -> String {
        use std::io::{BufRead, BufReader, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in l.incoming().flatten() {
                let mut rd = BufReader::new(conn.try_clone().unwrap());
                let mut first = String::new();
                rd.read_line(&mut first).unwrap();
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).unwrap_or(0) <= 2 {
                        break;
                    }
                }
                let target = first.split_whitespace().nth(1).unwrap_or("").to_string();
                assert!(first.starts_with("GET "), "non-GET request: {first}");
                let (st, hdr, body) = routes.iter().find(|r| target.starts_with(r.0)).map(|r| (r.1, r.2.clone(), r.3.clone())).unwrap_or((404, String::new(), "{}".into()));
                let mut c = conn;
                let _ = write!(c, "HTTP/1.1 {st} X\r\nContent-Type: application/json\r\n{hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn gh_at(base: String) -> Gh {
        Gh {
            base,
            token: None,
            agent: ureq::AgentBuilder::new().build(),
            remaining: std::cell::Cell::new(None),
            floor: 150,
            gaps: Default::default(),
            etags: Default::default(),
            calls: Default::default(),
            quiet: Default::default(),
            last_status: Default::default(),
        }
    }

    /// An ETag-aware server: 200 with `ETag: "v1"` the first time, 304 when If-None-Match carries it. Counts requests.
    fn etag_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{BufRead, BufReader, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n2 = n.clone();
        std::thread::spawn(move || {
            for conn in l.incoming().flatten() {
                n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut rd = BufReader::new(conn.try_clone().unwrap());
                let mut first = String::new();
                rd.read_line(&mut first).unwrap();
                let mut inm = false;
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).unwrap_or(0) <= 2 {
                        break;
                    }
                    if h.to_ascii_lowercase().starts_with("if-none-match:") && h.contains("\"v1\"") {
                        inm = true;
                    }
                }
                let mut c = conn;
                if inm {
                    let _ = write!(c, "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n");
                } else {
                    let body = "[{}]";
                    let _ = write!(c, "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                }
            }
        });
        (format!("http://127.0.0.1:{port}"), n)
    }

    #[test]
    fn stored_etag_makes_an_unchanged_probe_a_304() {
        let (base, hits) = etag_server();
        let gh = gh_at(base.clone());
        let urls = ["/repos/o/r/commits?per_page=1", "/repos/o/r/actions/runs?per_page=1", "/repos/o/r/releases?per_page=1"];
        for u in urls {
            assert!(matches!(gh.json_cond(u).unwrap(), Cond::Fresh(_)));
        }
        let stored = gh.etags();
        assert_eq!(stored.len(), 3);
        // the next scan loads the stored ETags: three calls, all 304, so the repo is unchanged
        let again = gh_at(base);
        again.load_etags(stored);
        for u in urls {
            assert!(matches!(again.json_cond(u).unwrap(), Cond::NotModified));
        }
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 6);
    }

    #[test]
    fn environment_and_org_secrets_are_read_and_gaps_when_unreadable() {
        let base = mock(vec![
            ("/repos/o/r/environments/prod/secrets", 200, String::new(), r#"{"secrets":[{"name":"PROD_KEY"}]}"#.into()),
            ("/repos/o/r/environments/stage/secrets", 403, String::new(), "{}".into()),
            ("/repos/o/r/environments", 200, String::new(), r#"{"environments":[{"name":"prod"},{"name":"stage"}]}"#.into()),
            ("/orgs/acme/actions/secrets/B/repositories", 200, String::new(), r#"{"repositories":[{"full_name":"acme/x"}]}"#.into()),
            ("/orgs/acme/actions/secrets", 200, String::new(), r#"{"secrets":[{"name":"A","visibility":"all"},{"name":"B","visibility":"selected"}]}"#.into()),
        ]);
        let gh = gh_at(base);
        assert_eq!(env_secret_names(&gh, "o/r").unwrap(), vec![("prod".to_string(), vec!["PROD_KEY".to_string()])]);
        let gaps = gh.take_gaps("t");
        assert!(gaps.iter().any(|g| g.scope.contains("stage")), "{gaps:?}");
        let (names, scopes, readable) = org_secrets(&gh, "acme").unwrap();
        assert_eq!(names, vec!["A", "B"]);
        assert!(readable);
        // The scope is GitHub's visibility, in words
        assert_eq!(scopes[0].scope, "org (all repos)");
        assert_eq!(scopes[1], SecretScope { name: "B".into(), scope: "org (selected repos)".into(), repos: vec!["acme/x".to_string()], ..Default::default() });
        let none = gh_at(mock(vec![("/repos/o/q/environments", 404, String::new(), "{}".into())]));
        assert!(env_secret_names(&none, "o/q").unwrap().is_empty());
        assert!(none.take_gaps("t").is_empty(), "no environments is not a gap");
        let refused = gh_at(mock(vec![("/repos/o/q/environments", 403, String::new(), "{}".into())]));
        assert!(env_secret_names(&refused, "o/q").unwrap().is_empty());
        assert!(!refused.take_gaps("t").is_empty());
        let denied = gh_at(mock(vec![("/orgs/acme/actions/secrets", 403, String::new(), "{}".into())]));
        let (n, _, readable) = org_secrets(&denied, "acme").unwrap();
        assert!(n.is_empty() && !readable, "an unreadable list is not an empty one");
        assert!(denied.take_gaps("t").iter().any(|g| g.scope == "org secrets"));
    }

    #[test]
    fn unreadable_repo_secrets_are_a_gap_not_none() {
        let base = mock(vec![("/repos/o/r/actions/secrets", 403, String::new(), r#"{"message":"Resource not accessible"}"#.into())]);
        let gh = gh_at(base);
        assert!(secret_names(&gh, "o/r", "secrets").unwrap().is_empty());
        let gaps = gh.take_gaps("2026-01-01T00:00:00Z");
        assert!(gaps.iter().any(|g| g.reason.contains("needs admin")), "{gaps:?}");
        let ok = mock(vec![("/repos/o/r/actions/secrets", 200, String::new(), r#"{"secrets":[{"name":"A"}]}"#.into())]);
        let gh = gh_at(ok);
        assert_eq!(secret_names(&gh, "o/r", "secrets").unwrap(), vec!["A".to_string()]);
        assert!(gh.take_gaps("2026-01-01T00:00:00Z").is_empty());
    }

    #[test]
    fn a_push_during_the_scan_changes_the_stored_etags() {
        use std::io::{BufRead, BufReader, Write};
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let ver = std::sync::Arc::new(AtomicUsize::new(1));
        let v2 = ver.clone();
        std::thread::spawn(move || {
            for conn in l.incoming().flatten() {
                let mut rd = BufReader::new(conn.try_clone().unwrap());
                let mut first = String::new();
                rd.read_line(&mut first).unwrap();
                let tag = format!("\"v{}\"", v2.load(SeqCst));
                let mut inm = false;
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).unwrap_or(0) <= 2 {
                        break;
                    }
                    if h.to_ascii_lowercase().starts_with("if-none-match:") && h.contains(&tag) {
                        inm = true;
                    }
                }
                let mut c = conn;
                if inm {
                    let _ = write!(c, "HTTP/1.1 304 Not Modified\r\nETag: {tag}\r\nConnection: close\r\n\r\n");
                } else {
                    let _ = write!(c, "HTTP/1.1 200 OK\r\nETag: {tag}\r\nContent-Type: application/json\r\nContent-Length: 4\r\nConnection: close\r\n\r\n[{{}}]");
                }
            }
        });
        let base = format!("http://127.0.0.1:{port}");
        let info = RepoInfo { name: "o/r".into(), default_branch: "main".into(), archived: false };
        // the snapshot is taken first; the repo is pushed to while the scan reads rows
        let snap = snapshot_etags(&gh_at(base.clone()), &info, "2026-01-01T00:00:00Z");
        assert_eq!(snap.len(), 3);
        ver.store(2, SeqCst);
        // the next scan loads that snapshot and must see the repo as changed
        let next = gh_at(base);
        next.load_etags(snap);
        let moved = probe_urls(&info, "2026-01-01T00:00:00Z").iter().any(|u| !matches!(next.json_cond(u).unwrap(), Cond::NotModified));
        assert!(moved);
    }

    #[test]
    fn a_403_on_a_core_endpoint_is_a_gap_not_missing() {
        let base = mock(vec![("/repos/o/r/git/trees", 403, String::new(), r#"{"message":"Resource not accessible"}"#.into())]);
        let gh = gh_at(base);
        let _ = gh.json_need("/repos/o/r/git/trees/main?recursive=1", "tree o/r");
        assert!(!gh.take_gaps("2026-01-01T00:00:00Z").is_empty());
    }

    #[test]
    fn pagination_follows_link_and_stops() {
        // GitHub's real shape: the next URL is absolute, and the last page has no rel="next"
        // page 1 must advertise page 2 with the mock's own port, so serve it from a second mock built with the right URL
        let base2 = mock(vec![("/orgs/o/repos?per_page=100&page=2", 200, String::new(), r#"[{"full_name":"o/c"}]"#.into())]);
        let first = mock(vec![(
            "/orgs/o/repos",
            200,
            format!("Link: <{base2}/orgs/o/repos?per_page=100&page=2>; rel=\"next\", <{base2}/orgs/o/repos?per_page=100&page=2>; rel=\"last\"\r\n"),
            r#"[{"full_name":"o/a"},{"full_name":"o/b"}]"#.into(),
        )]);
        let got = gh_at(first).list("/orgs/o/repos", None).unwrap();
        let names: Vec<_> = got.iter().map(|v| v["full_name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["o/a", "o/b", "o/c"]);
    }

    #[test]
    fn empty_repo_409_is_missing_not_an_error() {
        // GET /repos/o/empty/git/trees/main answers 409 "Git Repository is empty."; commits answer 409 too
        let base = mock(vec![("/repos/o/empty", 409, String::new(), r#"{"message":"Git Repository is empty."}"#.into())]);
        let gh = gh_at(base);
        assert!(gh.json("/repos/o/empty/git/trees/main?recursive=1").unwrap().is_none());
        assert!(gh.list("/repos/o/empty/commits?sha=main", None).unwrap().is_empty());
    }

    #[test]
    fn user_repos_skip_forks_and_keep_archived_flag() {
        let body = r#"[{"full_name":"jondot/mine","default_branch":"main","archived":false,"fork":false},
                       {"full_name":"jondot/old","default_branch":"master","archived":true,"fork":false},
                       {"full_name":"jondot/forked","default_branch":"main","archived":false,"fork":true}]"#;
        let base = mock(vec![("/users/jondot/repos", 200, String::new(), body.into())]);
        let gh = gh_at(base);
        let r = repos(&gh, "jondot").unwrap();
        let got: Vec<_> = r.iter().map(|x| (x.name.as_str(), x.default_branch.as_str(), x.archived)).collect();
        assert_eq!(got, vec![("jondot/mine", "main", false), ("jondot/old", "master", true)]);
    }

    #[test]
    fn rate_limit_stops_before_zero() {
        let base = mock(vec![("/x", 200, "X-RateLimit-Remaining: 151\r\n".into(), "{}".into())]);
        let gh = gh_at(base); // the floor applies to api.github.com only
        assert!(gh.json("/x").unwrap().is_some());
        assert_eq!(gh.remaining.get(), Some(151));
        // against the real host the same header would now stop the run; the stop is an error with the shared prefix
        let e = gh.rate_stop(10);
        assert!(e.msg.starts_with(RATE_STOP), "{}", e.msg);
    }
}
