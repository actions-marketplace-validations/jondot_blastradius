//! The View: what the index knows, as `br view-dump` prints it. Collectors fill the store; the store
//! loads into a View; hunt, render, actions and evidence read only the View plus br's own state. Field names match
//! the dump so `br debug view` can be diffed against it. Every source is already cut at its own `indexed_at`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct View {
    pub now: String,
    pub org: Org,
    pub people: Vec<Person>,
    pub teams: Vec<Team>,
    pub org_admins: Vec<String>,
    /// Teams that only `br teams set` (teams.yaml) knows: GitHub does not resolve them, but the operator gave them an
    /// address, so a repo that names one has an owner and needs no suggestion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_teams: Vec<String>,
    #[serde(default)]
    pub org_secrets: Vec<String>,
    /// Where each org secret lives, as GitHub said (`org (all repos)` or `org (selected repos)`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_scopes: Vec<SecretScope>,
    /// The secret lists the token could not read: `org`, or a repo's `org/name`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets_unreadable: Vec<String>,
    pub sources: BTreeMap<String, Source>,
    pub repos: BTreeMap<String, Repo>,
    pub hosts: BTreeMap<String, Host>,
    pub images: Vec<ImageBuild>,
    /// Advisories the index knows (OSV + `BR_HOME/advisories/*.yaml` notes). `view-dump` does not emit it.
    #[serde(default)]
    pub advisories: Vec<Advisory>,
    /// br's own state, not observations. Kept loose here; each reader types the parts it reads.
    #[serde(default)]
    pub state: State,
}

/// One secret and where it lives. `scope` is the label as printed: `repo`, `org (all repos)`, `org (selected repos)`
/// or `environment NAME`. `repos` is the repos a `selected` org secret reaches.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SecretScope {
    pub name: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
    /// When GitHub says the secret was created and last updated (its rotation date); None when GitHub did not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// A secret NAME that a config file at HEAD mentions (`.env.example`, compose, deploy config): file and line, never a value.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EnvRef {
    pub file: String,
    pub line: u32,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub title: Option<String>,
    /// `eco:name@version` indicators.
    #[serde(default)]
    pub affected: Vec<String>,
    pub fixed: Option<String>,
    pub exposure_window: Option<AdvisoryWindow>,
    pub text: Option<String>,
    /// Per-package truth from OSV/GHSA: each package's own versions, ranges and fixed version.
    /// `affected`/`fixed` above are the flattened legacy view; matching and fix advice use this.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<AffectedPackage>,
    /// Hashes the operator recorded as benign with `br advisory note ID --benign sha256:H --why TEXT`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub benign: Vec<BenignMark>,
    /// Where the window, the fixed version and each indicator came from ("from OSV", "from your note 05-12 07:40Z").
    #[serde(default, skip_serializing_if = "Provenance::is_empty")]
    pub provenance: Provenance,
    /// (sha256 indicator, file name) ties from the record's details and `database_specific`, and from the operator's note
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash_names: Vec<(String, String)>,
}

/// Where each part of a merged advisory came from. Labels are ready to print after "from ".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    /// indicator (`eco:name`, `sha256:HEX`) -> label
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub indicators: BTreeMap<String, String>,
}

impl Provenance {
    pub fn is_empty(&self) -> bool {
        self.window.is_none() && self.fixed.is_none() && self.indicators.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AffectedPackage {
    /// npm | pypi | cargo | go | action (br's ecosystem ids)
    pub ecosystem: String,
    pub name: String,
    /// Explicitly listed affected versions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
    /// OSV SEMVER/ECOSYSTEM ranges: a version is affected when introduced <= v < fixed (or <= last_affected).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<VersionRange>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BenignMark {
    pub sha256: String,
    pub why: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct VersionRange {
    /// "0" means from the first version.
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

/// Something br could not check in a source. A gap is never reported as clear.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Gap {
    /// what was not checked: "actions runs", "lockfile apps/web/yarn.lock", "registry listing", ...
    pub scope: String,
    /// why, in words a reader can act on: "token lacks actions:read (HTTP 403)"
    pub reason: String,
    pub at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AdvisoryWindow {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    /// host -> {roots, ...} for imported .brx hosts
    #[serde(default)]
    pub imports: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub custody: Vec<serde_json::Value>,
    #[serde(default)]
    pub scans: Vec<serde_json::Value>,
    #[serde(default)]
    pub yara_hits: Vec<serde_json::Value>,
    /// {at, before, ...}: the index before the last scan, for "numbers changed"
    pub last_scan: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Org {
    pub github: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Person {
    pub login: String,
    pub name: Option<String>,
    /// Short team name (`frontend`), as the world's `team:`.
    pub team: Option<String>,
    /// Every team the person belongs to (short names), the first of which is `team`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub teams: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Team {
    /// `@acme/frontend`
    pub id: String,
    pub slack: Option<String>,
    pub jira: Option<String>,
    /// Login of the lead.
    pub lead: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Source {
    /// repo | registry | host
    pub kind: String,
    /// github | registry | ssh | import-only | docker-creds | ...
    pub reach: String,
    pub indexed_at: String,
    /// A host scan that hashed 0 files: it counts as not checked.
    #[serde(default)]
    pub empty: bool,
    /// What this source's last scan could not check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<Gap>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Repo {
    pub default_branch: Option<String>,
    #[serde(default)]
    pub archived: bool,
    pub archived_at: Option<String>,
    pub archived_by: Option<String>,
    #[serde(default)]
    pub codeowners: String,
    /// The author of the newest commit on the default branch, and when (the owner of last resort for an orphan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_committer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_commit_at: Option<String>,
    pub lockfile: Option<String>,
    /// Every lockfile found in the tree at any depth (`lockfile` stays the first, for older readers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lockfiles: Vec<String>,
    #[serde(default)]
    pub workflows: Vec<Workflow>,
    #[serde(default)]
    pub composite_actions: Vec<CompositeAction>,
    /// workflow file name -> every secret name it can read
    #[serde(default)]
    pub secrets_all: BTreeMap<String, Vec<String>>,
    /// The repo-level and environment secrets of this repo with their scope (org secrets are in `View.secret_scopes`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_scopes: Vec<SecretScope>,
    #[serde(default)]
    pub commits: Vec<Commit>,
    #[serde(default)]
    pub runs: Vec<Run>,
    #[serde(default)]
    pub caches: Vec<Cache>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub releases: Vec<Release>,
    /// Free text about the repo (the world's `notes`); `br fix` quotes a parent's range from it. Collectors leave it empty.
    #[serde(default)]
    pub notes: Option<String>,
    /// Secret-like names that config files at HEAD mention (names and lines only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_refs: Vec<EnvRef>,
    /// Every language runtime the repo's files name (image tags, setup steps, version files), at HEAD and in history.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtimes: Vec<RuntimeRef>,
    /// The certificate files at the default branch's HEAD (capped; the cap and API cost are in `trust.notes`).
    #[serde(default, skip_serializing_if = "TrustSet::is_empty")]
    pub trust: TrustSet,
}

/// One place a repo names a runtime: a Dockerfile `FROM`, a compose image, a workflow setup step, a version file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRef {
    pub runtime: String,
    /// As written ("8.3.20-apache", "22", "lts/*").
    pub spec: String,
    /// The exact release when the text names one; floating references have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub floating: bool,
    pub file: String,
    #[serde(default)]
    pub line: usize,
    /// What the line is: "FROM php:8.3.20-apache", "setup-node node-version", ".nvmrc".
    pub seen_as: String,
    /// When the commit that introduced it landed (HEAD-only scans: the newest commit's time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    /// Set when a later commit dropped it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// A certificate seen in a trust store.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CertRec {
    /// SHA-256 of the DER encoding, lowercase hex without colons.
    pub fp: String,
    pub subject: String,
    pub issuer: String,
    pub not_after: Option<String>,
    /// Subject equals issuer (a root); false is an intermediate.
    #[serde(default)]
    pub root: bool,
}

/// One file recognised as a trust store, with the certificates read from it and what could not be read.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TrustFile {
    pub path: String,
    #[serde(default)]
    pub certs: Vec<CertRec>,
    /// Plain-words lines about what in this file could not be read (never a silent clear).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<String>,
}

/// The trust stores read at one place (a repo's HEAD or a host).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TrustSet {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<TrustFile>,
    /// Gaps that belong to the place, not one file (a cap reached, a store kind br does not read on this OS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Extra API calls the read cost (repos).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub api_calls: u32,
    /// The place was read for trust stores (a place with no files and no read is one br never looked at).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read: bool,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl TrustSet {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.notes.is_empty() && self.api_calls == 0 && !self.read
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Commit {
    pub sha: String,
    pub at: String,
    /// Login.
    pub author: Option<String>,
    pub message: Option<String>,
    pub manifest: Option<Manifest>,
    /// Present only on commits that touched the lockfile: the complete package list after the commit.
    pub packages: Option<Vec<LockPackage>>,
    /// The same packages keyed by the lockfile they came from (`packages` is their union, for older readers).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub lock_packages: BTreeMap<String, Vec<LockPackage>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub path: String,
    #[serde(default)]
    pub deps: BTreeMap<String, ManifestDep>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ManifestDep {
    pub spec: Option<String>,
    pub line: Option<u32>,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LockPackage {
    /// `eco:name@version`
    pub p: String,
    #[serde(default)]
    pub direct: bool,
    #[serde(default)]
    pub dev: bool,
    #[serde(default)]
    pub via: Vec<String>,
    pub lock_line: Option<u32>,
    pub as_written: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Workflow {
    pub file: String,
    #[serde(default)]
    pub uses: Vec<String>,
    pub runs_on: Option<String>,
    pub install: Option<String>,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub paths_ignore: Vec<String>,
    /// Secret name -> the lines of the workflow that read it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_lines: BTreeMap<String, Vec<u32>>,
    /// The workflow has a `workflow_dispatch:` trigger, so `gh workflow run` can start it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dispatch: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CompositeAction {
    pub path: String,
    #[serde(default)]
    pub uses: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Run {
    pub id: u64,
    pub workflow: String,
    /// The workflow file path from the runs API (`.github/workflows/ci.yml`); `workflow` is only the display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub at: String,
    pub commit: Option<String>,
    pub runner: Option<String>,
    /// Every self-hosted runner a job of this run used (`runner` is the first, or "github-hosted").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runners: Vec<String>,
    /// lockfile | registry
    pub resolved_from: Option<String>,
    #[serde(default)]
    pub installed: Vec<String>,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub caches_saved: Vec<String>,
    #[serde(default)]
    pub artifacts: Vec<serde_json::Value>,
    #[serde(default)]
    pub produced_images: Vec<String>,
    /// `owner/repo@ref` as written (possibly with a ` (via ...)` suffix) -> what it resolved to
    #[serde(default)]
    pub action_resolved: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Cache {
    pub key: String,
    pub created: String,
    pub last_used: Option<String>,
    pub size_mb: Option<u64>,
    #[serde(default)]
    pub contains: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Artifact {
    pub id: u64,
    pub name: String,
    pub run: Option<u64>,
    pub created: String,
    pub expires: Option<String>,
    pub size_mb: Option<u64>,
    #[serde(default)]
    pub contains: Vec<String>,
    /// Lockfiles inside the archive that gave no packages: (scope, reason), kept so a re-scan that reuses the archive still says so.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unread: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Release {
    pub tag: String,
    pub published: String,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ReleaseAsset {
    pub name: String,
    pub sha256: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Host {
    /// laptop | runner | ...
    pub kind: Option<String>,
    pub os: Option<String>,
    /// Login.
    pub owner: Option<String>,
    pub owner_team: Option<String>,
    /// The directories the scans of this host read (the union over its imported and local scans; an ssh host's configured
    /// roots, `/` when none). A member counts as covered only when these include the user's home or the package caches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<String>,
    /// This host is the machine br runs on, decided once when the scan was taken or the file imported (the host name
    /// against `BR_HOST` or the system hostname), never again from the name.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub this_machine: bool,
    /// What the lockfiles found under the scan roots declare, with direct/dev/via/line as the lockfile parser gives them.
    /// Each has a `lockfile` item in `items` (`loc` = the lockfile's path) whose `pkgs` are the same packages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared: Vec<DeclaredLock>,
    #[serde(default)]
    pub items: Vec<HostItem>,
    /// The scanning user's home directory when the scan recorded it, so a narrow root can be told from the home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    /// The trust stores read on this host (system trust dirs, certifi bundles) and the store kinds br cannot read here.
    #[serde(default, skip_serializing_if = "TrustSet::is_empty")]
    pub trust: TrustSet,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DeclaredLock {
    /// The lockfile's path on the host.
    pub loc: String,
    pub packages: Vec<LockPackage>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HostItem {
    pub at: String,
    pub kind: String,
    pub loc: String,
    #[serde(default)]
    pub pkgs: Vec<String>,
    #[serde(default)]
    pub files: Vec<HostFile>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HostFile {
    pub path: String,
    pub sha256: String,
    pub size: Option<u64>,
    pub mtime: Option<String>,
    pub simhash: Option<String>,
    #[serde(default)]
    pub yara_hits: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ImageBuild {
    /// `ghcr.io/acme/web`
    pub repository: String,
    pub digest: String,
    pub built: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub source: Option<ImageSource>,
    #[serde(default)]
    pub layers: Vec<Layer>,
    /// Packages in the final filesystem (when known per image, not per layer).
    #[serde(default)]
    pub packages: Vec<String>,
    /// None when the collector did not list the final filesystem (the dump omits the key); Some(vec![]) when it did and found nothing.
    #[serde(default)]
    pub final_fs_has: Option<Vec<String>>,
    #[serde(default)]
    pub final_fs_has_hash: Vec<String>,
    /// OCI annotation `org.opencontainers.image.base.name` (the base image reference).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_name: Option<String>,
    /// OCI annotation `org.opencontainers.image.base.digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_digest: Option<String>,
    /// Digest of the multi-arch index this platform image was found through (delete the index, not just this digest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    /// `linux/amd64`, `linux/arm64/v8`: set for a platform image of an index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// The NAMES of the environment variables in the image config (`Env`), never their values.
    #[serde(default)]
    pub env_names: Vec<String>,
    /// The layers' trust stores were read when this image was indexed (older indexes lack them, so are read again).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trust_read: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ImageSource {
    pub repo: Option<String>,
    pub commit: Option<String>,
    pub run: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Layer {
    pub n: u32,
    pub created_by: Option<String>,
    /// The layer's diff_id (`sha256:...`); a shared leading run of these marks a common base image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_id: Option<String>,
    /// The compressed layer blob's digest (`sha256:...`), what a registry deletes or downloads by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub files: Vec<LayerFile>,
    #[serde(default)]
    pub whiteouts: Vec<String>,
    /// The trust-store files this layer adds, with the certificates read from them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust: Vec<TrustFile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LayerFile {
    pub path: String,
    pub sha256: String,
}

impl View {
    /// Load from a `view-dump` JSON file (the `BR_DEV_VIEW` seam).
    pub fn from_json_file(path: &std::path::Path) -> anyhow::Result<View> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every world's dump must load and round-trip without losing fields.
    #[test]
    fn dumps_round_trip() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/views");
        let entries = std::fs::read_dir(&dir).expect("tests/views");
        for e in entries.flatten() {
            let text = std::fs::read_to_string(e.path()).unwrap();
            let v: View = serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", e.path().display()));
            let back: serde_json::Value = serde_json::to_value(&v).unwrap();
            let orig: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(strip_nulls(back), strip_nulls(orig), "{}", e.path().display());
        }
    }

    fn strip_nulls(v: serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match v {
            Value::Object(m) => Value::Object(
                m.into_iter()
                    .filter(|(_, v)| !v.is_null() && v != &Value::Bool(false) && v != &Value::Array(vec![]) && v != &Value::Object(Default::default()) && v != &Value::String(String::new()))
                    .map(|(k, v)| (k, strip_nulls(v)))
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
            v => v,
        }
    }
}
