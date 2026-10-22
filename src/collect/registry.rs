//! OCI distribution v2 collector (BR_REGISTRY_MIRROR, DOCKER_CONFIG).
//!
//! Reads every repository under a registry (or registry/prefix), every tag, every platform image of a multi-arch
//! index, and every layer, streaming the layers through the analyzer. Whatever could not be read is returned as a
//! gap: a registry listing that was capped or refused, a layer that failed its digest check, an image with no
//! readable filesystem. Nothing that was not read is ever reported as clean.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::rc::Rc;

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::collect::fs::{sha256_hex, Analyzer, FileMeta};
use crate::collect::util::norm_api_time;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::view::*;

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
const PAGE: usize = 1000;
/// Pages read from one listing before it is called capped (and a gap is recorded).
const MAX_PAGES: usize = 200;

// ---- credentials ---------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
pub enum Cred {
    Basic(String, String),
    /// A docker `identitytoken`: exchanged for a bearer token with the refresh_token grant.
    Identity(String),
}

fn config_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("DOCKER_CONFIG").map(std::path::PathBuf::from).or_else(|| dirs::home_dir().map(|h| h.join(".docker")))
}

fn docker_config() -> Option<Value> {
    let p = config_dir()?.join("config.json");
    serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
}

fn is_hub(host: &str) -> bool {
    matches!(host, "docker.io" | "index.docker.io" | "registry-1.docker.io" | "hub.docker.com")
}

/// The host part of a config key (`https://ghcr.io/acme/` is `ghcr.io`), with Docker Hub's aliases folded into `docker.io`.
fn key_host(k: &str) -> String {
    let h = k.trim_start_matches("https://").trim_start_matches("http://");
    let h = h.split('/').next().unwrap_or(h);
    if is_hub(h) {
        "docker.io".to_string()
    } else {
        h.to_string()
    }
}

/// What `docker-credential-NAME get` knows for SERVER. Err carries why the helper could not answer.
fn helper_get(helper: &str, server: &str) -> Result<Option<Cred>, String> {
    let bin = format!("docker-credential-{helper}");
    let mut child = std::process::Command::new(&bin)
        .arg("get")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{bin} could not run ({e})"))?;
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(server.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| format!("{bin} failed ({e})"))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // the protocol's "credentials not found" is an answer, not a failure
        if msg.contains("not found") {
            return Ok(None);
        }
        return Err(format!("{bin} get failed: {}", if msg.is_empty() { String::from_utf8_lossy(&out.stderr).trim().to_string() } else { msg }));
    }
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("{bin} answered something that is not JSON ({e})"))?;
    let (u, s) = (v["Username"].as_str().unwrap_or(""), v["Secret"].as_str().unwrap_or(""));
    if s.is_empty() {
        return Ok(None);
    }
    Ok(Some(if u == "<token>" { Cred::Identity(s.to_string()) } else { Cred::Basic(u.to_string(), s.to_string()) }))
}

fn entry_cred(e: &Value) -> Option<Cred> {
    if let Some(t) = e["identitytoken"].as_str().filter(|t| !t.is_empty()) {
        return Some(Cred::Identity(t.to_string()));
    }
    if let Some(a) = e["auth"].as_str().filter(|a| !a.is_empty()) {
        let d = base64::engine::general_purpose::STANDARD.decode(a.trim()).ok()?;
        let s = String::from_utf8(d).ok()?;
        let (u, p) = s.split_once(':')?;
        return Some(Cred::Basic(u.to_string(), p.to_string()));
    }
    if let (Some(u), Some(p)) = (e["username"].as_str(), e["password"].as_str()) {
        if !p.is_empty() {
            return Some(Cred::Basic(u.to_string(), p.to_string()));
        }
    }
    None
}

/// The credential docker would use for HOST: an `auths` entry (auth, identitytoken, username/password), then
/// `credHelpers[host]`, then `credsStore`. Err carries why a configured helper failed.
pub fn resolve_creds(host: &str) -> Result<Option<Cred>, String> {
    let Some(v) = docker_config() else { return Ok(None) };
    let want = key_host(host);
    if let Some(auths) = v["auths"].as_object() {
        // the most specific key wins: an exact host match before a host/path one
        let mut keys: Vec<&String> = auths.keys().filter(|k| key_host(k) == want).collect();
        keys.sort_by_key(|k| k.contains("//") as u8 + k.trim_start_matches("https://").contains('/') as u8);
        for k in keys {
            if let Some(c) = entry_cred(&auths[k]) {
                return Ok(Some(c));
            }
        }
    }
    let server = if want == "docker.io" { "https://index.docker.io/v1/".to_string() } else { host.to_string() };
    if let Some(h) = v["credHelpers"].as_object().and_then(|m| m.iter().find(|(k, _)| key_host(k) == want).map(|(_, h)| h)).and_then(|h| h.as_str()) {
        return helper_get(h, &server);
    }
    if let Some(h) = v["credsStore"].as_str().filter(|s| !s.is_empty()) {
        return helper_get(h, &server);
    }
    Ok(None)
}

/// Back-compat: the basic credential for HOST, if any.
pub fn docker_creds(host: &str) -> Option<(String, String)> {
    match resolve_creds(host) {
        Ok(Some(Cred::Basic(u, p))) => Some((u, p)),
        _ => None,
    }
}

/// Every registry host the docker config knows credentials for (B6): `auths`, `credHelpers`, and what the
/// `credsStore` helper lists. Docker Hub is `docker.io`.
pub fn docker_config_hosts() -> Vec<String> {
    let Some(v) = docker_config() else { return vec![] };
    let mut out = BTreeSet::new();
    if let Some(a) = v["auths"].as_object() {
        out.extend(a.keys().map(|k| key_host(k)));
    }
    if let Some(a) = v["credHelpers"].as_object() {
        out.extend(a.keys().map(|k| key_host(k)));
    }
    if let Some(h) = v["credsStore"].as_str().filter(|s| !s.is_empty()) {
        if let Ok(o) = std::process::Command::new(format!("docker-credential-{h}")).arg("list").stderr(std::process::Stdio::null()).output() {
            if let Ok(m) = serde_json::from_slice::<Value>(&o.stdout) {
                if let Some(m) = m.as_object() {
                    out.extend(m.keys().map(|k| key_host(k)));
                }
            }
        }
    }
    out.into_iter().filter(|h| !h.is_empty()).collect()
}

// ---- the client ----------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Flavor {
    Ghcr,
    Hub,
    Ecr,
    Gar,
    Plain,
}

pub fn flavor(host: &str) -> Flavor {
    if host == "ghcr.io" {
        Flavor::Ghcr
    } else if is_hub(host) {
        Flavor::Hub
    } else if host.contains(".ecr.") && host.ends_with(".amazonaws.com") {
        Flavor::Ecr
    } else if host.ends_with(".pkg.dev") || host == "gcr.io" || host.ends_with(".gcr.io") {
        Flavor::Gar
    } else {
        Flavor::Plain
    }
}

pub struct Reg {
    pub host: String,
    pub prefix: String,
    base: String,
    creds: Option<Cred>,
    /// why the configured credential helper could not answer
    pub cred_err: Option<String>,
    agent: ureq::Agent,
    tokens: RefCell<HashMap<String, String>>,
    calls: Cell<u64>,
}

fn mirror_for(host: &str) -> Option<String> {
    let m = std::env::var("BR_REGISTRY_MIRROR").ok()?;
    m.split(',').filter_map(|p| p.split_once('=')).find(|(h, _)| h.trim() == host).map(|(_, u)| u.trim().trim_end_matches('/').to_string())
}

/// The scope a bearer token for this path needs.
fn scope_for(path: &str) -> String {
    let p = path.split('?').next().unwrap_or(path);
    let p = match p.find("://") {
        Some(i) => p[i + 3..].find('/').map(|j| &p[i + 3 + j..]).unwrap_or(""),
        None => p,
    };
    let rest = p.trim_start_matches("/v2/");
    for m in ["/manifests/", "/blobs/", "/tags/list"] {
        if let Some(i) = rest.find(m) {
            return format!("repository:{}:pull", &rest[..i]);
        }
    }
    "registry:catalog:*".to_string()
}

/// The URL with rel="next" in a Link header.
pub fn next_link(link: &str) -> Option<String> {
    for part in link.split(',') {
        let part = part.trim();
        if part.contains("rel=\"next\"") || part.contains("rel=next") {
            let a = part.find('<')?;
            let b = part.find('>')?;
            return Some(part[a + 1..b].to_string());
        }
    }
    None
}

pub enum Got {
    Ok { body: Vec<u8>, digest: Option<String>, link: Option<String> },
    Missing,
    Denied(u16),
}

impl Reg {
    /// `spec` is HOST or HOST/PREFIX (e.g. ghcr.io/acme). `creds` overrides the docker config.
    pub fn open(spec: &str, creds: Option<(String, String)>) -> Reg {
        let spec = spec.trim_end_matches('/');
        let (host, prefix) = spec.split_once('/').map(|(h, p)| (h.to_string(), p.to_string())).unwrap_or((spec.to_string(), String::new()));
        let host = if is_hub(&host) { "docker.io".to_string() } else { host };
        let base = mirror_for(&host).unwrap_or_else(|| if host == "docker.io" { "https://registry-1.docker.io".to_string() } else { format!("https://{host}") });
        let (creds, cred_err) = match creds {
            Some((u, p)) => (Some(Cred::Basic(u, p)), None),
            None => match resolve_creds(&host) {
                Ok(c) => (c, None),
                Err(e) => (None, Some(e)),
            },
        };
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(20))
            .timeout_read(std::time::Duration::from_secs(120))
            .timeout_write(std::time::Duration::from_secs(120))
            .user_agent("br")
            .build();
        Reg { host, prefix, base, creds, cred_err, agent, tokens: Default::default(), calls: Cell::new(0) }
    }

    pub fn has_creds(&self) -> bool {
        self.creds.is_some()
    }

    pub fn calls(&self) -> u64 {
        self.calls.get()
    }

    /// The secret as a GitHub token (ghcr.io logins are a GitHub token).
    fn secret(&self) -> Option<String> {
        match &self.creds {
            Some(Cred::Basic(_, p)) => Some(p.clone()),
            _ => None,
        }
    }

    fn basic(&self) -> Option<String> {
        match &self.creds {
            Some(Cred::Basic(u, p)) => Some(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))),
            _ => None,
        }
    }

    /// One authenticated GET. Ok(Err(status)) for an HTTP status that is not success.
    fn send(&self, path: &str, accept: &str) -> BrResult<Result<ureq::Response, u16>> {
        let url = if path.starts_with("http") { path.to_string() } else { format!("{}{}", self.base, path) };
        let scope = scope_for(path);
        let mut refreshed = false;
        let mut retries = 0;
        loop {
            self.calls.set(self.calls.get() + 1);
            let mut r = self.agent.get(&url).set("Accept", accept);
            if let Some(t) = self.tokens.borrow().get(&scope) {
                r = r.set("Authorization", &format!("Bearer {t}"));
            } else if let Some(b) = self.basic() {
                r = r.set("Authorization", &b);
            }
            match r.call() {
                Ok(resp) => return Ok(Ok(resp)),
                Err(ureq::Error::Status(401, resp)) if !refreshed => {
                    refreshed = true;
                    let ch = resp.header("WWW-Authenticate").unwrap_or("").to_string();
                    match self.bearer(&ch)? {
                        Some(t) => {
                            self.tokens.borrow_mut().insert(scope.clone(), t);
                            continue;
                        }
                        None => return Ok(Err(401)),
                    }
                }
                Err(ureq::Error::Status(c @ (429 | 502 | 503 | 504), resp)) if retries < 3 => {
                    retries += 1;
                    let wait = resp.header("Retry-After").and_then(|v| v.parse::<u64>().ok()).unwrap_or(1 << retries).min(20);
                    std::thread::sleep(std::time::Duration::from_secs(wait));
                    let _ = c;
                    continue;
                }
                Err(ureq::Error::Status(c, _)) => return Ok(Err(c)),
                Err(e) => return Err(net(&self.host, e)),
            }
        }
    }

    /// Fetch a small body.
    fn get(&self, path: &str, accept: &str) -> BrResult<Got> {
        match self.send(path, accept)? {
            Ok(resp) => {
                let digest = resp.header("Docker-Content-Digest").map(str::to_string);
                let link = resp.header("Link").map(str::to_string);
                let mut b = vec![];
                resp.into_reader().take(256 * 1024 * 1024).read_to_end(&mut b).map_err(|e| net(&self.host, e))?;
                Ok(Got::Ok { body: b, digest, link })
            }
            Err(404) => Ok(Got::Missing),
            Err(c) => Ok(Got::Denied(c)),
        }
    }

    fn bearer(&self, challenge: &str) -> BrResult<Option<String>> {
        if !challenge.to_lowercase().starts_with("bearer") {
            return Ok(None);
        }
        let param = |k: &str| -> Option<String> {
            let i = challenge.find(&format!("{k}=\""))? + k.len() + 2;
            Some(challenge[i..].split('"').next()?.to_string())
        };
        let Some(realm) = param("realm") else { return Ok(None) };
        let (service, scope) = (param("service"), param("scope"));
        self.calls.set(self.calls.get() + 1);
        let res = if let Some(Cred::Identity(t)) = &self.creds {
            let mut form = vec![("grant_type", "refresh_token".to_string()), ("refresh_token", t.clone()), ("client_id", "br".to_string())];
            if let Some(s) = &service {
                form.push(("service", s.clone()));
            }
            if let Some(s) = &scope {
                form.push(("scope", s.clone()));
            }
            let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
            self.agent.post(&realm).send_form(&pairs)
        } else {
            let mut url = realm;
            let mut sep = if url.contains('?') { '&' } else { '?' };
            for (k, v) in [("service", &service), ("scope", &scope)] {
                if let Some(v) = v {
                    url.push_str(&format!("{sep}{k}={v}"));
                    sep = '&';
                }
            }
            let mut r = self.agent.get(&url);
            if let Some(b) = self.basic() {
                r = r.set("Authorization", &b);
            }
            r.call()
        };
        match res {
            Ok(resp) => {
                let v: Value = resp.into_json().map_err(|e| net(&self.host, e))?;
                Ok(v["token"].as_str().or(v["access_token"].as_str()).map(str::to_string))
            }
            Err(ureq::Error::Status(_, _)) => Err(refused(&self.host)),
            Err(e) => Err(net(&self.host, e)),
        }
    }

    fn json(&self, path: &str, accept: &str) -> BrResult<Option<(Value, Option<String>, Vec<u8>)>> {
        Ok(match self.get(path, accept)? {
            Got::Ok { body, digest, .. } => serde_json::from_slice(&body).ok().map(|v| (v, digest, body)),
            _ => None,
        })
    }

    /// A paged name list (`_catalog`, `tags/list`): follows Link, or `last=` when a full page came back.
    /// Returns the names, whether the listing was cut short (cap or an error after the first page), and the first failure.
    fn names(&self, first: &str, key: &str) -> BrResult<(Vec<String>, Option<String>, bool)> {
        let mut out = vec![];
        let mut path = first.to_string();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for page in 0..MAX_PAGES {
            let (names, link) = match self.get(&path, "application/json")? {
                Got::Ok { body, link, .. } => {
                    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    (v[key].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect::<Vec<_>>()).unwrap_or_default(), link)
                }
                Got::Missing => return Ok((out, if page == 0 { Some("HTTP 404".into()) } else { Some("HTTP 404 on a later page".into()) }, page > 0)),
                Got::Denied(c) => return Ok((out, Some(format!("HTTP {c}")), page > 0)),
            };
            let n = names.len();
            let last = names.last().cloned();
            for x in names {
                seen.insert(x.clone());
                out.push(x);
            }
            if let Some(nx) = link.as_deref().and_then(next_link) {
                path = nx;
            } else if n >= PAGE {
                let Some(l) = last else { break };
                let base = first.split('?').next().unwrap_or(first);
                path = format!("{base}?n={PAGE}&last={}", l.replace('/', "%2F"));
            } else {
                return Ok((out, None, false));
            }
            if seen.len() != out.len() {
                // a registry that ignores `last` repeats itself
                out.sort();
                out.dedup();
                return Ok((out, Some("the registry repeated a page".into()), true));
            }
        }
        Ok((out, None, true))
    }

    /// Stream a blob.
    fn blob(&self, repo: &str, digest: &str) -> BrResult<Result<Box<dyn Read + Send + Sync>, String>> {
        match self.send(&format!("/v2/{repo}/blobs/{digest}"), "application/octet-stream")? {
            Ok(r) => Ok(Ok(r.into_reader())),
            Err(404) => Ok(Err("HTTP 404: the layer is missing".into())),
            Err(c) => Ok(Err(format!("HTTP {c}"))),
        }
    }
}

fn net(host: &str, e: impl std::fmt::Display) -> BrError {
    BrError::with_code(format!("cannot read {host} ({e})"), Some("check the network and BR_REGISTRY_MIRROR"), 3)
}

pub fn refused(host: &str) -> BrError {
    BrError::with_code(format!("the credentials stored for {host} were refused"), Some(&format!("run docker login {host} again, then re-run this command")), 4)
}

pub fn no_creds(host: &str) -> BrError {
    no_creds_why(host, None)
}

pub fn no_creds_why(host: &str, why: Option<&str>) -> BrError {
    let m = match why {
        Some(w) => format!("no docker credentials for {host}: {w}"),
        None => format!("no docker credentials for {host}"),
    };
    BrError::with_code(m, Some(&format!("run docker login {host}, then re-run this command")), 4)
}

// ---- listing -------------------------------------------------------------------------------------------------
pub struct Listing {
    /// repository (without the host) and digests the registry knows besides its tags
    pub repos: Vec<(String, Vec<(String, Vec<String>)>)>,
    pub gaps: Vec<(String, String)>,
}

fn hub_api() -> String {
    std::env::var("BR_DOCKERHUB_API").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "https://hub.docker.com".into())
}

impl Reg {
    fn in_prefix(&self, r: &str) -> bool {
        self.prefix.is_empty() || r == self.prefix || r.starts_with(&format!("{}/", self.prefix))
    }

    fn list_catalog(&self, lst: &mut Listing) -> BrResult<bool> {
        let (names, fail, capped) = self.names(&format!("/v2/_catalog?n={PAGE}"), "repositories")?;
        let ok = fail.is_none() || !names.is_empty();
        if let Some(f) = &fail {
            lst.gaps.push(("registry listing".into(), format!("{} did not finish listing its repositories ({f}); the ones after that point were not read", self.host)));
        } else if capped {
            lst.gaps.push(("registry listing".into(), format!("the listing of {} was cut at {} pages; later repositories were not read", self.host, MAX_PAGES)));
        }
        for r in names {
            if self.in_prefix(&r) {
                lst.repos.push((r, vec![]));
            }
        }
        Ok(ok)
    }

    fn list_hub(&self, lst: &mut Listing) -> BrResult<()> {
        let ns = self.prefix.split('/').next().unwrap_or("");
        if ns.is_empty() {
            return Err(BrError::with_code("Docker Hub has no catalog, so br needs a namespace".to_string(), Some("run br init --registry docker.io/NAMESPACE"), 2));
        }
        if self.prefix.contains('/') {
            lst.repos.push((self.prefix.clone(), vec![]));
            return Ok(());
        }
        let mut url = format!("{}/v2/repositories/{ns}/?page_size=100", hub_api());
        let mut jwt: Option<String> = None;
        if let Some(Cred::Basic(u, p)) = &self.creds {
            if let Ok(r) = self.agent.post(&format!("{}/v2/users/login", hub_api())).send_json(json!({"username": u, "password": p})) {
                jwt = r.into_json::<Value>().ok().and_then(|v| v["token"].as_str().map(str::to_string));
            }
        }
        for page in 0..MAX_PAGES {
            let mut r = self.agent.get(&url);
            if let Some(t) = &jwt {
                r = r.set("Authorization", &format!("JWT {t}"));
            }
            self.calls.set(self.calls.get() + 1);
            match r.call() {
                Ok(resp) => {
                    let v: Value = resp.into_json().map_err(|e| net(&self.host, e))?;
                    for x in v["results"].as_array().cloned().unwrap_or_default() {
                        if let Some(n) = x["name"].as_str() {
                            lst.repos.push((format!("{ns}/{n}"), vec![]));
                        }
                    }
                    match v["next"].as_str() {
                        Some(n) if !n.is_empty() => url = n.to_string(),
                        _ => return Ok(()),
                    }
                }
                Err(ureq::Error::Status(c, _)) => {
                    lst.gaps.push(("registry listing".into(), format!("Docker Hub refused the namespace listing for {ns} (HTTP {c}); private repositories need docker login")));
                    return Ok(());
                }
                Err(e) => return Err(net(&self.host, e)),
            }
            if page + 1 == MAX_PAGES {
                lst.gaps.push(("registry listing".into(), format!("the Docker Hub listing for {ns} was cut at {MAX_PAGES} pages")));
            }
        }
        Ok(())
    }

    /// ghcr.io lists packages only through the GitHub API, for a user or an organisation owner.
    fn list_ghcr(&self, ctx: &Ctx, lst: &mut Listing) -> BrResult<()> {
        let owner = self.prefix.split('/').next().unwrap_or("").to_lowercase();
        let token = self.secret().or_else(|| ctx.token());
        if owner.is_empty() {
            return Err(BrError::with_code("ghcr.io has no catalog, so br needs an owner".to_string(), Some("run br init --registry ghcr.io/OWNER"), 2));
        }
        let single = self.prefix.contains('/');
        let Some(token) = token else {
            if single {
                lst.repos.push((self.prefix.to_lowercase(), vec![]));
            } else if !self.list_catalog(lst)? {
                lst.gaps.push(("registry listing".into(), "ghcr.io lists packages only through the GitHub API and no token is set (read:packages)".into()));
            }
            return Ok(());
        };
        let gh = crate::collect::github::Gh::new(ctx).with_token(Some(token));
        // the owner is an organisation or a user: ask the organisation route first
        let mut kind = "orgs";
        let mut pk = gh.list_opt(&format!("/orgs/{owner}/packages?package_type=container&per_page=100"), None)?;
        if pk.is_none() {
            kind = "users";
            pk = gh.list_opt(&format!("/users/{owner}/packages?package_type=container&per_page=100"), None)?;
        }
        let Some(pk) = pk else {
            // not a GitHub owner we can see: a plain registry may still answer _catalog
            if single {
                lst.repos.push((self.prefix.to_lowercase(), vec![]));
            } else if !self.list_catalog(lst)? {
                lst.gaps.push(("registry listing".into(), format!("the packages of {owner} could not be listed (HTTP 404/403): the token needs read:packages and access to {owner}")));
            }
            return Ok(());
        };
        for p in pk {
            let Some(name) = p["name"].as_str() else { continue };
            let repo = format!("{owner}/{}", name.to_lowercase());
            if single && !self.in_prefix(&repo) {
                continue;
            }
            let enc = name.replace('/', "%2F");
            let mut vers = vec![];
            match gh.list_opt(&format!("/{kind}/{owner}/packages/container/{enc}/versions?per_page=100"), None)? {
                Some(vs) => {
                    for v in vs {
                        if let Some(d) = v["name"].as_str().filter(|d| d.starts_with("sha256:")) {
                            let tags: Vec<String> = v["metadata"]["container"]["tags"].as_array().map(|a| a.iter().filter_map(|t| t.as_str().map(str::to_string)).collect()).unwrap_or_default();
                            vers.push((d.to_string(), tags));
                        }
                    }
                }
                None => lst.gaps.push((format!("repository {repo}"), "the package versions could not be listed (HTTP 404/403); untagged builds were not seen".into())),
            }
            lst.repos.push((repo, vers));
        }
        for (s, r) in gh.take_gaps("").into_iter().map(|g| (g.scope, g.reason)) {
            lst.gaps.push((s, r));
        }
        Ok(())
    }

    pub fn list(&self, ctx: &Ctx) -> BrResult<Listing> {
        let mut lst = Listing { repos: vec![], gaps: vec![] };
        match flavor(&self.host) {
            Flavor::Ghcr => self.list_ghcr(ctx, &mut lst)?,
            Flavor::Hub => self.list_hub(&mut lst)?,
            f => {
                let ok = self.list_catalog(&mut lst)?;
                if !ok && !self.prefix.is_empty() {
                    // ECR and Artifact Registry may refuse the catalog: the prefix is read as one repository
                    lst.repos.push((self.prefix.clone(), vec![]));
                    let which = if f == Flavor::Ecr {
                        "ECR"
                    } else if f == Flavor::Gar {
                        "Artifact Registry"
                    } else {
                        "the registry"
                    };
                    lst.gaps.push(("registry listing".into(), format!("{which} did not list repositories; only {} was read", self.prefix)));
                } else if !ok {
                    lst.gaps.push(("registry listing".into(), format!("{} did not list its repositories; name a repository: br init --registry {}/NAME", self.host, self.host)));
                }
            }
        }
        lst.repos.sort();
        lst.repos.dedup_by(|a, b| a.0 == b.0);
        Ok(lst)
    }
}

// ---- images --------------------------------------------------------------------------------------------------
pub struct Found {
    pub images: Vec<ImageBuild>,
    pub repos: usize,
    pub gaps: Vec<Gap>,
    pub calls: u64,
}

#[derive(Default)]
struct Entry {
    tags: BTreeSet<String>,
    index: Option<String>,
    platform: Option<String>,
    manifest: Option<Value>,
    ann: BTreeMap<String, String>,
}

fn platform_of(p: &Value) -> Option<String> {
    let os = p["platform"]["os"].as_str()?;
    let arch = p["platform"]["architecture"].as_str()?;
    let v = p["platform"]["variant"].as_str().map(|v| format!("/{v}")).unwrap_or_default();
    Some(format!("{os}/{arch}{v}"))
}

fn is_attestation(m: &Value) -> bool {
    m["annotations"]["vnd.docker.reference.type"] == "attestation-manifest"
        || m["platform"]["os"] == "unknown"
        || m["layers"].as_array().map(|l| l.first().map(|x| x["mediaType"].as_str().unwrap_or("").contains("in-toto")).unwrap_or(false)).unwrap_or(false)
}

fn filter_key(globs: &[String]) -> String {
    // the layer results carry trust stores, runtime install directories and distro package databases
    sha256_hex(format!("{}\ntrust-v1\nrt1", globs.join("\n")).as_bytes())[..8].to_string()
}

/// Read every image under the registry. `run_for(repo, image_ref)` finds the CI run that pushed an image;
/// `known(repository, digest)` returns an image read on an earlier scan (its layers are not read again).
pub fn images(reg: &Reg, ctx: &Ctx, run_for: &dyn Fn(&str, &str) -> Option<u64>, known: &dyn Fn(&str, &str) -> Option<ImageBuild>) -> BrResult<Found> {
    let lst = reg.list(ctx)?;
    let mut gaps: Vec<(String, String)> = lst.gaps;
    let n_repos = lst.repos.len();
    let globs = crate::collect::config::hash_filter(ctx);
    let fkey = filter_key(&globs);
    let mut out = vec![];
    for (repo, extra) in lst.repos {
        let full = format!("{}/{repo}", reg.host);
        let (tags, fail, capped) = reg.names(&format!("/v2/{repo}/tags/list?n={PAGE}"), "tags")?;
        if let Some(f) = fail {
            gaps.push((format!("repository {full}"), format!("tags could not be listed ({f})")));
        } else if capped {
            gaps.push((format!("repository {full}"), format!("the tag listing was cut at {MAX_PAGES} pages")));
        }
        let mut found: BTreeMap<String, Entry> = BTreeMap::new();
        for t in &tags {
            let got = match reg.get(&format!("/v2/{repo}/manifests/{t}"), ACCEPT) {
                Ok(g) => g,
                Err(e) => {
                    gaps.push((format!("image {full}:{t}"), e.msg));
                    continue;
                }
            };
            let (body, dg) = match got {
                Got::Ok { body, digest, .. } => (body, digest),
                Got::Missing => continue,
                Got::Denied(c) => {
                    gaps.push((format!("image {full}:{t}"), format!("the manifest was refused (HTTP {c})")));
                    continue;
                }
            };
            let Ok(m) = serde_json::from_slice::<Value>(&body) else {
                gaps.push((format!("image {full}:{t}"), "the manifest is not JSON".into()));
                continue;
            };
            let digest = dg.unwrap_or_else(|| format!("sha256:{}", sha256_hex(&body)));
            add_manifest(&mut found, &digest, t, &m, None);
        }
        for (d, vtags) in extra {
            let e = found.entry(d).or_default();
            e.tags.extend(vtags);
        }
        // an untagged digest that is itself an index (ghcr versions): expand it
        let pending: Vec<String> = found.iter().filter(|(_, e)| e.manifest.is_none()).map(|(d, _)| d.clone()).collect();
        let mut skip: BTreeSet<String> = BTreeSet::new();
        for d in pending {
            if known(&full, &d).map(|k| k.final_fs_has.is_some() && k.trust_read).unwrap_or(false) {
                continue;
            }
            match reg.get(&format!("/v2/{repo}/manifests/{d}"), ACCEPT) {
                Ok(Got::Ok { body, .. }) => {
                    let Ok(m) = serde_json::from_slice::<Value>(&body) else {
                        gaps.push((format!("image {full}@{d}"), "the manifest is not JSON".into()));
                        continue;
                    };
                    if m["manifests"].is_array() {
                        let tags = found.get(&d).map(|e| e.tags.clone()).unwrap_or_default();
                        for t in &tags {
                            add_manifest(&mut found, &d, t, &m, None);
                        }
                        if tags.is_empty() {
                            add_manifest(&mut found, &d, "", &m, None);
                        }
                        // the index is a pointer, not an image
                        skip.insert(d.clone());
                    } else if is_attestation(&m) {
                        skip.insert(d.clone());
                    } else if let Some(e) = found.get_mut(&d) {
                        e.manifest = Some(m);
                    }
                }
                Ok(Got::Missing) => {
                    skip.insert(d);
                }
                Ok(Got::Denied(c)) => {
                    gaps.push((format!("image {full}@{d}"), format!("the manifest was refused (HTTP {c})")));
                    skip.insert(d);
                }
                Err(e) => {
                    gaps.push((format!("image {full}@{d}"), e.msg));
                    skip.insert(d);
                }
            }
        }
        for d in &skip {
            // an index that was expanded leaves its tags on the platform images
            if let Some(e) = found.get(d) {
                if e.manifest.is_none() && e.index.is_none() {
                    found.remove(d);
                }
            }
        }
        for (digest, e) in found {
            if skip.contains(&digest) && e.manifest.is_none() {
                continue;
            }
            let scope = format!("image {full}@{digest}");
            if let Some(mut k) = known(&full, &digest) {
                if k.final_fs_has.is_some() && k.trust_read {
                    k.tags = e.tags.iter().filter(|t| !t.is_empty()).cloned().collect();
                    k.index = e.index.clone();
                    k.platform = e.platform.clone();
                    out.push(k);
                    continue;
                }
            }
            let m = match e.manifest.clone() {
                Some(m) => m,
                None => match reg.get(&format!("/v2/{repo}/manifests/{digest}"), ACCEPT) {
                    Ok(Got::Ok { body, .. }) => match serde_json::from_slice::<Value>(&body) {
                        Ok(m) if !is_attestation(&m) => m,
                        Ok(_) => continue,
                        Err(_) => {
                            gaps.push((scope, "the manifest is not JSON".into()));
                            continue;
                        }
                    },
                    Ok(Got::Missing) => continue,
                    Ok(Got::Denied(c)) => {
                        gaps.push((scope, format!("the manifest was refused (HTTP {c})")));
                        continue;
                    }
                    Err(er) => {
                        gaps.push((scope, er.msg));
                        continue;
                    }
                },
            };
            match build_image(reg, ctx, &repo, &full, &digest, &m, &e, &globs, &fkey, run_for, known) {
                Ok((img, g)) => {
                    for r in g {
                        gaps.push((scope.clone(), r));
                    }
                    if let Some(i) = img {
                        out.push(i);
                    }
                }
                Err(er) => gaps.push((scope, er.msg)),
            }
        }
    }
    out.sort_by(|a, b| (a.built.as_str(), a.repository.as_str(), a.digest.as_str()).cmp(&(b.built.as_str(), b.repository.as_str(), b.digest.as_str())));
    // one gap per scope, the first reason
    let mut seen = BTreeSet::new();
    let gaps = gaps.into_iter().filter(|(s, _)| seen.insert(s.clone())).map(|(scope, reason)| Gap { scope, reason, at: ctx.now.clone() }).collect();
    Ok(Found { images: out, repos: n_repos, gaps, calls: reg.calls() })
}

fn add_manifest(found: &mut BTreeMap<String, Entry>, digest: &str, tag: &str, m: &Value, _p: Option<&str>) {
    if let Some(list) = m["manifests"].as_array() {
        let ann: BTreeMap<String, String> = m["annotations"].as_object().map(|o| o.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect()).unwrap_or_default();
        for p in list {
            if is_attestation(p) {
                continue;
            }
            let Some(pd) = p["digest"].as_str() else { continue };
            let e = found.entry(pd.to_string()).or_default();
            if !tag.is_empty() {
                e.tags.insert(tag.to_string());
            }
            e.index = Some(digest.to_string());
            e.platform = platform_of(p);
            e.ann = ann.clone();
        }
        // the index digest stays so a later pass can see it was expanded
        let e = found.entry(digest.to_string()).or_default();
        if !tag.is_empty() {
            e.tags.insert(tag.to_string());
        }
    } else {
        let e = found.entry(digest.to_string()).or_default();
        if !tag.is_empty() {
            e.tags.insert(tag.to_string());
        }
        e.manifest = Some(m.clone());
    }
}

/// The image config's build time. Absent, or the epoch that reproducible builders (ko, rules_oci, nix) write, means unknown.
fn real_created(cfg: &Value) -> Option<String> {
    let ok = |s: &str| norm_api_time(s).filter(|t| !t.starts_with("1970-"));
    cfg["created"].as_str().and_then(ok).or_else(|| cfg["history"].as_array().and_then(|h| h.iter().filter_map(|x| x["created"].as_str().and_then(ok)).max()))
}

#[allow(clippy::too_many_arguments)]
fn build_image(
    reg: &Reg,
    ctx: &Ctx,
    repo: &str,
    full: &str,
    digest: &str,
    m: &Value,
    e: &Entry,
    globs: &[String],
    fkey: &str,
    run_for: &dyn Fn(&str, &str) -> Option<u64>,
    known: &dyn Fn(&str, &str) -> Option<ImageBuild>,
) -> BrResult<(Option<ImageBuild>, Vec<String>)> {
    let mut gaps: Vec<String> = vec![];
    let cfg_d = m["config"]["digest"].as_str().unwrap_or("");
    let Some((cfg, _, _)) = reg.json(&format!("/v2/{repo}/blobs/{cfg_d}"), "application/json")? else {
        return Ok((None, vec!["the image config could not be read".into()]));
    };
    let created = real_created(&cfg);
    let built = match created {
        Some(c) => c,
        None => {
            let seen = known(full, digest).map(|k| k.built).unwrap_or_else(|| ctx.now.clone());
            gaps.push(format!("the image records no build time (created is absent or 1970-01-01, as reproducible builds write); {seen} is when br first saw it, not when it was built"));
            seen
        }
    };
    if built.as_str() > ctx.now.as_str() {
        return Ok((None, vec![format!("the image is dated {built}, after the clock; it was ignored")]));
    }
    let labels = &cfg["config"]["Labels"];
    let ann = |k: &str| -> Option<String> { m["annotations"][k].as_str().map(str::to_string).or_else(|| e.ann.get(k).cloned()).or_else(|| labels[k].as_str().map(str::to_string)) };
    let source_repo = labels["org.opencontainers.image.source"]
        .as_str()
        .or(m["annotations"]["org.opencontainers.image.source"].as_str())
        .map(|u| u.trim_end_matches(".git").trim_start_matches("https://github.com/").trim_start_matches("http://github.com/").to_string());
    let commit = labels["org.opencontainers.image.revision"].as_str().or(m["annotations"]["org.opencontainers.image.revision"].as_str()).map(str::to_string);
    let run = source_repo.as_deref().and_then(|sr| run_for(sr, &format!("{full}@{digest}")));
    let source = if source_repo.is_some() || commit.is_some() || run.is_some() { Some(ImageSource { repo: source_repo, commit, run }) } else { None };
    let blobs: Vec<Value> = m["layers"].as_array().cloned().unwrap_or_default();
    let diff_ids: Vec<String> = cfg["rootfs"]["diff_ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    // the history rows that made a layer, in order
    let hist: Vec<(usize, Option<String>)> = cfg["history"]
        .as_array()
        .map(|h| h.iter().enumerate().filter(|(_, x)| !x["empty_layer"].as_bool().unwrap_or(false)).map(|(i, x)| (i, x["created_by"].as_str().map(str::to_string))).collect())
        .unwrap_or_default();
    let aligned = hist.len() == blobs.len();
    let mut layers = vec![];
    let mut fs_files: BTreeMap<String, String> = BTreeMap::new();
    let mut fs_pkgs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut complete = true;
    for (bi, b) in blobs.iter().enumerate() {
        let bd = b["digest"].as_str().unwrap_or("");
        let mt = b["mediaType"].as_str().unwrap_or("");
        let n = if aligned { hist[bi].0 as u32 + 1 } else { bi as u32 + 1 };
        let created_by = if aligned { hist[bi].1.as_deref().map(redact_assignments) } else { None };
        if mt.contains("zstd") {
            gaps.push(format!("layer {n} is zstd compressed and br cannot unpack it"));
            complete = false;
            continue;
        }
        let (mut l, pp) = match layer_cached(ctx, fkey, bd).or(None) {
            Some(c) => c,
            None => {
                let rd = match reg.blob(repo, bd)? {
                    Ok(r) => r,
                    Err(why) => {
                        gaps.push(format!("layer {n} ({bd}) could not be read: {why}"));
                        complete = false;
                        continue;
                    }
                };
                match read_layer(rd, globs, &ctx.now, Some(bd)) {
                    Ok((l, pp, notes)) => {
                        gaps.extend(notes.into_iter().map(|x| format!("layer {n}: {x}")));
                        layer_store(ctx, fkey, bd, &l, &pp);
                        (l, pp)
                    }
                    Err(why) => {
                        gaps.push(format!("layer {n} ({bd}) could not be unpacked: {why}"));
                        complete = false;
                        continue;
                    }
                }
            }
        };
        l.n = n;
        l.created_by = created_by;
        l.diff_id = diff_ids.get(bi).cloned();
        l.blob = Some(bd.to_string());
        for w in &l.whiteouts {
            let pre = format!("{w}/");
            fs_files.retain(|p, _| p != w && !p.starts_with(&pre));
            fs_pkgs.retain(|_, ps| {
                ps.retain(|p| p != w && !p.starts_with(&pre));
                !ps.is_empty()
            });
        }
        for f in &l.files {
            fs_files.insert(f.path.clone(), f.sha256.clone());
        }
        for (pk, path) in pp {
            fs_pkgs.entry(pk).or_default().insert(path);
        }
        layers.push(l);
    }
    let mut hashes: Vec<String> = fs_files.values().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    hashes.sort();
    let (env_names, env_runtimes) = env_facts(&cfg);
    let img = ImageBuild {
        env_names,
        packages: env_runtimes,
        repository: full.to_string(),
        digest: digest.to_string(),
        built,
        tags: e.tags.iter().filter(|t| !t.is_empty()).cloned().collect(),
        source,
        layers,
        final_fs_has: complete.then(|| fs_pkgs.keys().cloned().collect()),
        final_fs_has_hash: if complete { hashes } else { vec![] },
        base_name: ann("org.opencontainers.image.base.name"),
        base_digest: ann("org.opencontainers.image.base.digest"),
        index: e.index.clone(),
        platform: e.platform.clone(),
        trust_read: true,
    };
    Ok((Some(img), gaps))
}

/// A build command in the image history (`ENV NAME=value`, `RUN NAME=value make`) can carry a value. The index keeps the
/// command and the NAME, never the value after the `=`.
fn redact_assignments(cmd: &str) -> String {
    static ASSIGN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#"(^|\s)([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S*)"#).unwrap());
    // `pip install name==1.2` and `--flag=x` are not assignments: a value starting with `=` is a version pin
    ASSIGN.replace_all(cmd, |c: &regex::Captures| if c[3].starts_with('=') { c[0].to_string() } else { format!("{}{}=<value not kept>", &c[1], &c[2]) }).into_owned()
}

#[cfg(test)]
fn env_var_names(cfg: &Value) -> Vec<String> {
    env_facts(cfg).0
}

/// The image config's `Env`: every variable NAME (never a value), and the runtime versions the table's version variables
/// (PHP_VERSION, NODE_VERSION, ...) state. No other value is read.
pub fn env_facts(cfg: &Value) -> (Vec<String>, Vec<String>) {
    let mut names = BTreeSet::new();
    let mut rts = BTreeSet::new();
    for e in cfg["config"]["Env"].as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
        let (name, rest) = match e.split_once('=') {
            Some((n, _)) => (n, Some(&e[n.len() + 1..])),
            None => (e, None),
        };
        if name.is_empty() {
            continue;
        }
        names.insert(name.to_string());
        if let (true, Some(v)) = (crate::query::runtime::is_version_var(name), rest) {
            if let Some((n, ver)) = crate::query::runtime::env_version(name, v) {
                rts.insert(crate::query::runtime::pseudo(n, &ver));
            }
        }
    }
    (names.into_iter().collect(), rts.into_iter().collect())
}

// ---- layer cache (blobs are immutable: keyed by digest and the hash filter) ----------------------------------
fn cache_path(ctx: &Ctx, fkey: &str, digest: &str) -> Option<std::path::PathBuf> {
    let hex = digest.strip_prefix("sha256:")?;
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(ctx.home.join("cache").join("layers").join(format!("{hex}-{fkey}.json")))
}

fn layer_cached(ctx: &Ctx, fkey: &str, digest: &str) -> Option<(Layer, Vec<(String, String)>)> {
    let p = cache_path(ctx, fkey, digest)?;
    let v: Value = serde_json::from_slice(&std::fs::read(p).ok()?).ok()?;
    let l: Layer = serde_json::from_value(v["layer"].clone()).ok()?;
    let pp: Vec<(String, String)> = serde_json::from_value(v["paths"].clone()).ok()?;
    Some((l, pp))
}

fn layer_store(ctx: &Ctx, fkey: &str, digest: &str, l: &Layer, pp: &[(String, String)]) {
    let Some(p) = cache_path(ctx, fkey, digest) else { return };
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, serde_json::to_vec(&json!({"layer": l, "paths": pp})).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}

// ---- one layer ------------------------------------------------------------------------------------------------
struct Tee<R> {
    inner: R,
    h: Rc<RefCell<Sha256>>,
}

impl<R: Read> Read for Tee<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.h.borrow_mut().update(&buf[..n]);
        Ok(n)
    }
}

/// Stream a layer through the analyzer. `digest` (when sha256) is checked against the bytes read: a layer that
/// does not match was truncated or altered, and is an error. Returns the layer, the (package, path) pairs, and notes.
pub fn read_layer<R: Read>(raw: R, globs: &[String], now: &str, digest: Option<&str>) -> Result<(Layer, Vec<(String, String)>, Vec<String>), String> {
    let h = Rc::new(RefCell::new(Sha256::new()));
    let tee = Tee { inner: raw, h: h.clone() };
    let mut br = std::io::BufReader::new(tee);
    let gz = {
        use std::io::BufRead;
        let b = br.fill_buf().map_err(|e| e.to_string())?;
        b.len() > 2 && b[0] == 0x1f && b[1] == 0x8b
    };
    let rd: Box<dyn Read> = if gz { Box::new(flate2::read::MultiGzDecoder::new(br)) } else { Box::new(br) };
    let mut an = Analyzer::new(globs, Some(now));
    an.wide_trust = true;
    let mut whiteouts: Vec<String> = vec![];
    let mut links: Vec<(String, String)> = vec![];
    let mut notes = vec![];
    let mut ar = tar::Archive::new(rd);
    {
        let ents = ar.entries().map_err(|e| e.to_string())?;
        for e in ents {
            let mut e = e.map_err(|e| e.to_string())?;
            let path = {
                let p = e.path_bytes();
                String::from_utf8_lossy(&p).trim_start_matches("./").trim_start_matches('/').trim_end_matches('/').to_string()
            };
            let base = path.rsplit('/').next().unwrap_or("").to_string();
            let dir = path.rsplit_once('/').map(|x| x.0).unwrap_or("").to_string();
            if base == ".wh..wh..opq" {
                // an opaque directory hides everything below it in the lower layers
                if !dir.is_empty() {
                    whiteouts.push(dir);
                }
                continue;
            }
            if let Some(w) = base.strip_prefix(".wh.") {
                whiteouts.push(if dir.is_empty() { w.to_string() } else { format!("{dir}/{w}") });
                continue;
            }
            let et = e.header().entry_type();
            if et.is_hard_link() {
                if let Ok(Some(t)) = e.link_name() {
                    links.push((path, t.to_string_lossy().trim_start_matches("./").trim_start_matches('/').to_string()));
                }
                continue;
            }
            if !et.is_file() {
                continue;
            }
            let mtime = e.header().mtime().unwrap_or(0) as i64;
            let meta = FileMeta { path: format!("/{path}"), size: e.header().size().unwrap_or(0), mtime };
            if an.needs_content(&meta) {
                an.add(meta, Some(&mut e));
            } else {
                an.add(meta, None);
            }
        }
    }
    // drain what the tar reader left (padding), so the digest covers every byte
    let mut rest = ar.into_inner();
    std::io::copy(&mut rest, &mut std::io::sink()).map_err(|e| e.to_string())?;
    drop(rest);
    if let Some(d) = digest.and_then(|d| d.strip_prefix("sha256:")) {
        let got = hex::encode(h.borrow().clone().finalize());
        if got != d {
            return Err(format!("the bytes read hash to sha256:{got}, not the layer's digest: truncated or altered"));
        }
    }
    for (p, why) in &an.skipped {
        notes.push(format!("{p} was not read ({why})"));
    }
    let (mut trust, trust_notes) = an.trust_stores();
    for t in trust.iter_mut() {
        t.path = t.path.trim_start_matches('/').to_string();
    }
    notes.extend(trust_notes);
    let mut pk = BTreeSet::new();
    let mut files = vec![];
    for it in an.items() {
        pk.extend(it.pkgs);
    }
    let by_path: HashMap<String, String> = an.files.iter().filter_map(|f| f.sha256.clone().map(|s| (f.path.trim_start_matches('/').to_string(), s))).collect();
    for f in &an.files {
        if let Some(sha) = &f.sha256 {
            files.push(LayerFile { path: f.path.trim_start_matches('/').to_string(), sha256: sha.clone() });
        }
    }
    // a hard link has the content of its target; the target is read when it lies in this layer
    let mut loose = 0;
    let globset = crate::collect::util::Globs::new(globs);
    for (l, t) in links {
        match by_path.get(&t) {
            Some(s) => files.push(LayerFile { path: l, sha256: s.clone() }),
            None if globset.matches(&format!("/{l}")) || globset.matches(&format!("/{t}")) => loose += 1,
            None => {}
        }
    }
    if loose > 0 {
        notes.push(format!("{loose} hard link(s) point outside this layer and were not hashed"));
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.dedup_by(|a, b| a.path == b.path);
    whiteouts.sort();
    whiteouts.dedup();
    let pp: Vec<(String, String)> = an.package_paths().into_iter().map(|(p, f)| (p, f.trim_start_matches('/').to_string())).collect();
    Ok((Layer { n: 0, created_by: None, diff_id: None, blob: None, packages: pk.into_iter().collect(), files, whiteouts, trust }, pp, notes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn image_env_keeps_names_and_drops_values() {
        let cfg = serde_json::json!({"config": {"Env": ["PATH=/usr/bin", "PLAT_TOKEN=sk-made-up-value-123", "EMPTY=", "NOEQ"]}});
        let names = env_var_names(&cfg);
        assert_eq!(names, vec!["EMPTY", "NOEQ", "PATH", "PLAT_TOKEN"]);
        assert!(!format!("{names:?}").contains("sk-made-up"));
        assert!(env_var_names(&serde_json::json!({"config": {}})).is_empty());
    }

    use super::*;

    #[test]
    fn a_build_command_keeps_the_name_and_loses_the_value() {
        let c = redact_assignments("/bin/sh -c #(nop)  ENV PLAT_TOKEN=made-up-value-9 NODE_ENV=\"prod mode\" && npm ci --prefix=app");
        assert!(c.contains("PLAT_TOKEN=<value not kept>") && c.contains("NODE_ENV=<value not kept>"), "{c}");
        assert!(!c.contains("made-up") && !c.contains("prod mode"), "{c}");
        assert!(c.contains("--prefix=app"), "a flag is not an assignment: {c}");
        let p = redact_assignments("/bin/sh -c pip install certifi==2024.2.2 urllib3==2.2.1");
        assert_eq!(p, "/bin/sh -c pip install certifi==2024.2.2 urllib3==2.2.1", "a version pin is not an assignment");
    }

    #[test]
    fn epoch_or_missing_created_is_unknown_not_a_build_time() {
        assert_eq!(real_created(&serde_json::json!({"created": "1970-01-01T00:00:00Z"})), None);
        assert_eq!(real_created(&serde_json::json!({})), None);
        assert_eq!(real_created(&serde_json::json!({"created": "1970-01-01T00:00:00Z", "history": [{"created": "2026-03-01T10:00:00Z"}]})).as_deref(), Some("2026-03-01T10:00:00Z"));
        assert_eq!(real_created(&serde_json::json!({"created": "2026-03-02T10:00:00Z"})).as_deref(), Some("2026-03-02T10:00:00Z"));
    }
    #[test]
    fn env_facts_keep_names_and_only_the_runtime_version_values() {
        let cfg = serde_json::json!({"config": {"Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2-secret", "PHP_VERSION=8.3.20", "NODE_VERSION=latest", "EMPTY=", "=x"]}});
        let (names, rts) = env_facts(&cfg);
        assert_eq!(names, vec!["DB_PASSWORD", "EMPTY", "NODE_VERSION", "PATH", "PHP_VERSION"]);
        assert_eq!(rts, vec!["runtime:php@8.3.20"]);
        let all = format!("{names:?}{rts:?}");
        assert!(!all.contains("hunter2") && !all.contains("/usr/bin"));
    }
    use std::sync::Mutex;

    static ENV: Mutex<()> = Mutex::new(());

    fn tar_of(entries: Vec<(&str, Vec<u8>, Option<&str>)>) -> Vec<u8> {
        let mut b = tar::Builder::new(vec![]);
        for (p, data, link) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_mtime(1_700_000_000);
            h.set_mode(0o644);
            match link {
                Some(t) => {
                    h.set_entry_type(tar::EntryType::Link);
                    h.set_size(0);
                    b.append_link(&mut h, p, t).unwrap();
                }
                None => {
                    h.set_size(data.len() as u64);
                    b.append_data(&mut h, p, &data[..]).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn next_link_parses_relative_and_absolute() {
        assert_eq!(next_link("</v2/_catalog?last=b&n=100>; rel=\"next\"").as_deref(), Some("/v2/_catalog?last=b&n=100"));
        assert_eq!(next_link("<http://x/a>; rel=\"prev\", <http://x/b>; rel=\"next\"").as_deref(), Some("http://x/b"));
        assert_eq!(next_link("<http://x/a>; rel=\"prev\""), None);
    }

    #[test]
    fn flavors() {
        assert_eq!(flavor("ghcr.io"), Flavor::Ghcr);
        assert_eq!(flavor("index.docker.io"), Flavor::Hub);
        assert_eq!(flavor("123456789012.dkr.ecr.us-east-1.amazonaws.com"), Flavor::Ecr);
        assert_eq!(flavor("us-docker.pkg.dev"), Flavor::Gar);
        assert_eq!(flavor("reg.example.com"), Flavor::Plain);
        assert_eq!(key_host("https://index.docker.io/v1/"), "docker.io");
        assert_eq!(key_host("ghcr.io/acme"), "ghcr.io");
    }

    #[test]
    fn layer_opaque_whiteout_and_hardlink() {
        let t = tar_of(vec![
            ("app/node_modules/x/index.js", b"console.log(1)".to_vec(), None),
            ("app/node_modules/x/copy.js", vec![], Some("app/node_modules/x/index.js")),
            ("old/.wh..wh..opq", vec![], None),
            ("gone/.wh.file", vec![], None),
        ]);
        let want = sha256_hex(b"console.log(1)");
        let (l, _, _) = read_layer(&gz(&t)[..], &["**/*.js".to_string()], "2030-01-01T00:00:00Z", None).unwrap();
        assert_eq!(l.whiteouts, vec!["gone/file".to_string(), "old".to_string()]);
        let got: Vec<_> = l.files.iter().map(|f| (f.path.as_str(), f.sha256.as_str())).collect();
        assert!(got.contains(&("app/node_modules/x/index.js", want.as_str())));
        assert!(got.contains(&("app/node_modules/x/copy.js", want.as_str())), "hard link carries its target's hash: {got:?}");
    }

    #[test]
    fn layer_digest_mismatch_is_an_error() {
        let t = tar_of(vec![("a.js", b"x".to_vec(), None)]);
        let z = gz(&t);
        let good = format!("sha256:{}", sha256_hex(&z));
        assert!(read_layer(&z[..], &["**/*.js".to_string()], "2030-01-01T00:00:00Z", Some(&good)).is_ok());
        let e = read_layer(&z[..], &["**/*.js".to_string()], "2030-01-01T00:00:00Z", Some(&format!("sha256:{}", "0".repeat(64)))).unwrap_err();
        assert!(e.contains("truncated or altered"), "{e}");
        // a stream cut short fails too
        assert!(read_layer(&z[..z.len() / 2], &["**/*.js".to_string()], "2030-01-01T00:00:00Z", Some(&good)).is_err());
    }

    #[test]
    fn big_file_is_hashed_in_full() {
        let big: Vec<u8> = (0..(3 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
        let t = tar_of(vec![("opt/big.js", big.clone(), None)]);
        let (l, _, _) = read_layer(&t[..], &["**/*.js".to_string()], "2030-01-01T00:00:00Z", None).unwrap();
        assert_eq!(l.files[0].sha256, sha256_hex(&big));
    }

    #[test]
    fn credentials_from_helpers_and_identity_tokens() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("br-reg-creds-{}", std::process::id()));
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let script = bin.join("docker-credential-fake");
        std::fs::write(&script, "#!/bin/sh\nread s\nif [ \"$1\" = list ]; then echo '{\"stored.example.com\":\"u\"}'; exit 0; fi\ncase \"$s\" in\n helped.example.com) echo '{\"Username\":\"hu\",\"Secret\":\"hp\"}';;\n tok.example.com) echo '{\"Username\":\"<token>\",\"Secret\":\"idt\"}';;\n *) echo 'credentials not found in native keychain'; exit 1;;\nesac\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", bin.display()));
        std::env::set_var("DOCKER_CONFIG", &dir);
        let auth = base64::engine::general_purpose::STANDARD.encode("alice:s3cret");
        std::fs::write(
            dir.join("config.json"),
            format!(r#"{{"auths":{{"https://index.docker.io/v1/":{{"auth":"{auth}"}},"ghcr.io":{{"identitytoken":"refresh"}},"plain.example.com":{{"username":"pu","password":"pp"}}}},"credHelpers":{{"helped.example.com":"fake","tok.example.com":"fake"}},"credsStore":"fake"}}"#),
        )
        .unwrap();
        assert_eq!(resolve_creds("docker.io").unwrap(), Some(Cred::Basic("alice".into(), "s3cret".into())));
        assert_eq!(resolve_creds("registry-1.docker.io").unwrap(), Some(Cred::Basic("alice".into(), "s3cret".into())));
        assert_eq!(resolve_creds("ghcr.io").unwrap(), Some(Cred::Identity("refresh".into())));
        assert_eq!(resolve_creds("plain.example.com").unwrap(), Some(Cred::Basic("pu".into(), "pp".into())));
        assert_eq!(resolve_creds("helped.example.com").unwrap(), Some(Cred::Basic("hu".into(), "hp".into())));
        assert_eq!(resolve_creds("tok.example.com").unwrap(), Some(Cred::Identity("idt".into())));
        assert_eq!(resolve_creds("nowhere.example.com").unwrap(), None);
        let hosts = docker_config_hosts();
        for h in ["docker.io", "ghcr.io", "helped.example.com", "stored.example.com"] {
            assert!(hosts.contains(&h.to_string()), "{h} in {hosts:?}");
        }
        std::env::set_var("PATH", old_path);
        // a configured helper that is not installed is an error with the reason, not "no credentials"
        assert!(resolve_creds("helped.example.com").is_err());
        std::env::remove_var("DOCKER_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
