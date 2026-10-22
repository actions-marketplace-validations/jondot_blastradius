//! Files br reads from BR_HOME that people (or the rig) edit: teams.yaml, hosts.yaml, advisories/<ID>.yaml, config.yaml.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::store::Store;
use crate::view::{Advisory, AdvisoryWindow, AffectedPackage};

fn read_yaml<T: for<'a> Deserialize<'a> + Default>(p: &PathBuf) -> T {
    // Only an absent file means "default". A file that exists but does not parse stops br with the file named.
    match std::fs::read_to_string(p) {
        Err(_) => T::default(),
        Ok(t) if t.trim().is_empty() => T::default(),
        Ok(t) => match serde_yaml::from_str(&t) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("br: {} is not valid: {e}\n  hint: fix the file or move it aside; br will not guess at its contents", p.display());
                std::process::exit(2);
            }
        },
    }
}

/// `stale_after` from config.yaml under the default home (BR_HOME, else ~/.blastradius), if set.
pub fn stale_after_setting() -> Option<String> {
    let home = std::env::var("BR_HOME").ok().filter(|s| !s.is_empty()).map(PathBuf::from).or_else(|| dirs::home_dir().map(|h| h.join(".blastradius")))?;
    let t = std::fs::read_to_string(home.join("config.yaml")).ok()?;
    let c: Config = serde_yaml::from_str(&t).ok()?;
    c.stale_after
}

fn write_yaml<T: Serialize>(ctx: &Ctx, p: &PathBuf, v: &T) -> BrResult<()> {
    std::fs::create_dir_all(p.parent().unwrap_or(&ctx.home))
        .and_then(|_| std::fs::write(p, serde_yaml::to_string(v).unwrap_or_default()))
        .map_err(|e| BrError::with_code(format!("{}: {e}", p.display()), Some("check BR_HOME and its permissions"), 1))
}

// ---- teams --------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TeamCfg {
    pub slack: Option<String>,
    pub jira: Option<String>,
}

pub fn teams(ctx: &Ctx) -> BTreeMap<String, TeamCfg> {
    read_yaml(&ctx.home.join("teams.yaml"))
}

pub fn set_team(ctx: &Ctx, id: &str, slack: Option<&str>, jira: Option<&str>) -> BrResult<()> {
    let mut t = teams(ctx);
    let e = t.entry(id.to_string()).or_default();
    if let Some(s) = slack {
        e.slack = Some(s.to_string());
    }
    if let Some(j) = jira {
        e.jira = Some(j.to_string());
    }
    write_yaml(ctx, &ctx.home.join("teams.yaml"), &t)
}

// ---- hosts --------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostCfg {
    /// login (no @)
    pub owner: Option<String>,
    pub owner_team: Option<String>,
    /// runner | laptop
    pub kind: Option<String>,
    /// ssh | import-only
    pub reach: Option<String>,
    /// ssh target (user@host); defaults to the name
    pub target: Option<String>,
    /// scan roots on that host
    #[serde(default)]
    pub roots: Vec<String>,
}

pub fn hosts(ctx: &Ctx) -> BTreeMap<String, HostCfg> {
    read_yaml(&ctx.home.join("hosts.yaml"))
}

pub fn save_hosts(ctx: &Ctx, h: &BTreeMap<String, HostCfg>) -> BrResult<()> {
    write_yaml(ctx, &ctx.home.join("hosts.yaml"), h)
}

// ---- advisory notes -------------------------------------------------------------------------------------------
/// One record per advisory id in `BR_HOME/advisories/<ID>.yaml`: what the operator knows that OSV does not say. Every reader
/// (hunt, fix, notify, purge, evidence, diff) takes it merged with the OSV data by `advisories()`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Note {
    /// `FROM..TO`
    pub window: Option<String>,
    pub fixed: Option<String>,
    pub note: Option<String>,
    #[serde(default)]
    pub benign: Vec<crate::view::BenignMark>,
    /// when each part was noted (UTC), for "from your note 05-12 07:40Z"
    #[serde(default)]
    pub window_at: Option<String>,
    #[serde(default)]
    pub fixed_at: Option<String>,
    /// indicators added with `--ioc eco:name@ver`: text -> when
    #[serde(default)]
    pub iocs: BTreeMap<String, String>,
    /// hashes added with `--hash sha256:H`: `sha256:H` -> when
    #[serde(default)]
    pub hashes: BTreeMap<String, String>,
    /// file names given with `--hash sha256:H=NAME`: `sha256:H` -> NAME
    #[serde(default)]
    pub hash_names: BTreeMap<String, String>,
    /// fixed versions for one package (`--fixed eco:name@V`): `eco:name` -> version and when
    #[serde(default)]
    pub fixed_pkgs: BTreeMap<String, NoteFixed>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoteFixed {
    pub version: String,
    #[serde(default)]
    pub at: Option<String>,
}

pub fn note_path(ctx: &Ctx, id: &str) -> PathBuf {
    ctx.home.join("advisories").join(format!("{id}.yaml"))
}

pub fn note(ctx: &Ctx, id: &str) -> Option<Note> {
    let p = note_path(ctx, id);
    p.exists().then(|| read_yaml(&p))
}

pub fn set_note(ctx: &Ctx, id: &str, n: &Note) -> BrResult<()> {
    write_yaml(ctx, &note_path(ctx, id), n)
}

pub fn parse_window(s: &str) -> Option<AdvisoryWindow> {
    let norm = s.replace(['\u{2013}', '\u{2014}'], "..").replace(" to ", "..");
    let (a, b) = norm.split_once("..")?;
    Some(AdvisoryWindow { from: super::util::norm_iso(a.trim()).ok()?, to: super::util::norm_iso(b.trim()).ok()? })
}

/// "your note 05-12 07:40Z" (or just "your note" for a note from before notes carried times).
fn note_label(at: &Option<String>) -> String {
    match at.as_deref().and_then(super::util::epoch) {
        Some(_) => format!("your note {}Z", super::util::fmt(at.as_deref().unwrap_or(""))),
        None => "your note".to_string(),
    }
}

/// The key a note uses for one package (`--fixed eco:name@V`): the ecosystem and the name as the matcher compares it.
pub fn fixed_key(eco: &str, name: &str) -> String {
    format!("{eco}:{}", crate::query::iocs::name_key(eco, name))
}

pub fn pkg_key(p: &AffectedPackage) -> String {
    fixed_key(&p.ecosystem, &p.name)
}

/// Add `versions`/`ranges` of `add` to the advisory's package of the same name, or the package itself.
fn merge_package(a: &mut Advisory, add: AffectedPackage, label: &str) {
    a.provenance.indicators.entry(pkg_key(&add)).or_insert_with(|| label.to_string());
    let key = pkg_key(&add);
    if let Some(p) = a.packages.iter_mut().find(|p| pkg_key(p) == key) {
        for v in add.versions {
            if !p.versions.contains(&v) {
                p.versions.push(v);
            }
        }
        for r in add.ranges {
            if !p.ranges.contains(&r) {
                p.ranges.push(r);
            }
        }
    } else {
        a.packages.push(add);
    }
}

/// A fixed version the operator states becomes a range `[v, fixed)` for each version the package lists, so
/// `version::fixed_for` finds it; a package whose ranges have no fix gets it on its open ranges. A package that already has
/// a fix from OSV keeps it unless `replace`.
pub fn apply_fixed(p: &mut AffectedPackage, fixed: &str, replace: bool) {
    let eco = p.ecosystem.clone();
    if replace {
        for r in p.ranges.iter_mut() {
            if r.fixed.is_some() {
                r.fixed = None;
                r.last_affected = None;
            }
        }
        p.ranges.retain(|r| r.introduced.is_some());
    } else if p.ranges.iter().any(|r| r.fixed.is_some()) {
        return;
    }
    let listed: Vec<String> = p.versions.clone();
    for v in listed {
        if crate::query::version::cmp(&eco, &v, fixed) == Some(std::cmp::Ordering::Less) {
            let r = crate::view::VersionRange { introduced: Some(v.clone()), fixed: Some(fixed.to_string()), last_affected: None };
            if !p.ranges.contains(&r) {
                p.ranges.push(r);
            }
        }
    }
    for r in p.ranges.iter_mut() {
        if r.fixed.is_none() && r.last_affected.is_none() {
            r.fixed = Some(fixed.to_string());
        }
    }
}

/// Merge a note into an advisory (OSV data or an empty stub). The note wins where both say something; the provenance
/// records which side each part came from.
pub fn merge_note(a: &mut Advisory, n: &Note) {
    if let Some(w) = n.window.as_deref().and_then(parse_window) {
        a.exposure_window = Some(w);
        a.provenance.window = Some(note_label(&n.window_at));
    }
    for (text, at) in &n.iocs {
        let Ok(i) = crate::query::iocs::parse_ioc(text, None) else { continue };
        let label = note_label(&Some(at.clone()).filter(|x| !x.is_empty()));
        if i.kind == crate::query::iocs::IocKind::Pkg {
            if let Some(set) = i.set.clone() {
                merge_package(a, set, &label);
            } else if let (Some(eco), Some(vs)) = (i.eco.clone(), i.versions.clone().filter(|v| !v.is_empty())) {
                merge_package(a, AffectedPackage { ecosystem: eco, name: i.name.clone(), versions: vs, ranges: vec![] }, &label);
            }
        } else if !a.affected.contains(&i.text) {
            a.provenance.indicators.insert(i.text.clone(), label);
            a.affected.push(i.text.clone());
        }
    }
    for (h, at) in &n.hashes {
        if !a.affected.contains(h) {
            a.affected.push(h.clone());
        }
        a.provenance.indicators.insert(h.clone(), note_label(&Some(at.clone()).filter(|x| !x.is_empty())));
    }
    for (h, name) in &n.hash_names {
        if !a.hash_names.iter().any(|t| &t.0 == h && &t.1 == name) {
            a.hash_names.push((h.clone(), name.clone()));
        }
    }
    if let Some(f) = n.fixed.as_deref().filter(|f| !f.is_empty()) {
        a.fixed = Some(f.to_string());
        a.provenance.fixed = Some(note_label(&n.fixed_at));
        for p in a.packages.iter_mut() {
            if !n.fixed_pkgs.contains_key(&pkg_key(p)) {
                apply_fixed(p, f, false);
            }
        }
    }
    for (k, nf) in &n.fixed_pkgs {
        if let Some(p) = a.packages.iter_mut().find(|p| pkg_key(p) == *k) {
            apply_fixed(p, &nf.version, true);
        }
        if a.fixed.is_none() {
            a.fixed = Some(nf.version.clone());
            a.provenance.fixed = Some(note_label(&nf.at));
        }
    }
    for b in &n.benign {
        if !a.benign.iter().any(|x| x.sha256 == b.sha256) {
            a.benign.push(b.clone());
        }
    }
}

/// Advisories the index knows: OSV records fetched earlier, merged with the operator's note for the same id; a note alone
/// gives an advisory of its own. Every reader takes advisories from here, so they all see the same packages, fixes and window.
pub fn advisories(ctx: &Ctx, st: &Store) -> Vec<Advisory> {
    advisories_from(ctx, st.present("_osv", "advisory").into_iter().collect())
}

/// The same from OSV records already read (empty when there is no index): the notes still make advisories.
pub fn advisories_from(ctx: &Ctx, osv: Vec<(String, serde_json::Value)>) -> Vec<Advisory> {
    let mut out: BTreeMap<String, Advisory> = BTreeMap::new();
    for (k, v) in osv {
        if let Ok(mut a) = serde_json::from_value::<Advisory>(v) {
            label_osv(&mut a);
            out.insert(k, a);
        }
    }
    if let Ok(rd) = std::fs::read_dir(ctx.home.join("advisories")) {
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        for p in files {
            if p.extension().and_then(|x| x.to_str()) != Some("yaml") {
                continue;
            }
            let id = p.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
            let n: Note = read_yaml(&p);
            let a = out.entry(id.clone()).or_insert_with(|| Advisory { id, ..Default::default() });
            merge_note(a, &n);
        }
    }
    out.into_values().collect()
}

/// Mark what an OSV record contributed.
fn label_osv(a: &mut Advisory) {
    for p in a.packages.clone() {
        a.provenance.indicators.entry(pkg_key(&p)).or_insert_with(|| "OSV".to_string());
    }
    for t in a.affected.clone().into_iter().filter(|t| t.starts_with("sha256:") || t.starts_with("simhash:")) {
        a.provenance.indicators.entry(t).or_insert_with(|| "OSV".to_string());
    }
    if a.fixed.is_some() && a.provenance.fixed.is_none() {
        a.provenance.fixed = Some("OSV".to_string());
    }
}

// ---- config.yaml ----------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub hash_filter: Option<Vec<String>>,
    pub stale_after: Option<String>,
    pub operator: Option<Operator>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Operator {
    pub name: Option<String>,
    pub host: Option<String>,
}

pub fn config(ctx: &Ctx) -> Config {
    read_yaml(&ctx.home.join("config.yaml"))
}

pub fn hash_filter(ctx: &Ctx) -> Vec<String> {
    config(ctx).hash_filter.unwrap_or_else(|| super::util::DEFAULT_HASH_FILTER.iter().map(|s| s.to_string()).collect())
}
