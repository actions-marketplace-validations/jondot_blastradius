//! OSV advisories (BR_OSV_API) cached in the index as source `_osv`.

use serde_json::Value;

use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::store::{Row, Store};
use crate::view::{Advisory, AffectedPackage, VersionRange};

fn base() -> String {
    std::env::var("BR_OSV_API").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "https://api.osv.dev".into()).trim_end_matches('/').to_string()
}

fn eco(e: &str) -> Option<&'static str> {
    // OSV ecosystem names may carry a suffix after a colon
    Some(match e.split(':').next().unwrap_or(e).to_lowercase().as_str() {
        "npm" => "npm",
        "pypi" => "pypi",
        "crates.io" => "cargo",
        "go" => "go",
        "github actions" => "action",
        _ => return None,
    })
}

/// Package names as the matcher sees them: PyPI is PEP 503 normalised; npm, Go, cargo and actions keep their case.
fn norm_name(eco: &str, n: &str) -> String {
    if eco == "pypi" {
        let mut out = String::new();
        let mut sep = false;
        for c in n.chars() {
            if matches!(c, '-' | '_' | '.') {
                sep = true;
            } else {
                if sep && !out.is_empty() {
                    out.push('-');
                }
                sep = false;
                out.extend(c.to_lowercase());
            }
        }
        out
    } else {
        n.to_string()
    }
}

fn ranges_of(a: &Value) -> Vec<VersionRange> {
    let mut out = vec![];
    for r in a["ranges"].as_array().into_iter().flatten() {
        // GIT ranges hold commit ids; they cannot be matched against a package version
        if r["type"].as_str().map(|t| t.eq_ignore_ascii_case("git")).unwrap_or(false) {
            continue;
        }
        let mut cur: Option<VersionRange> = None;
        let zero = || VersionRange { introduced: Some("0".into()), fixed: None, last_affected: None };
        for ev in r["events"].as_array().into_iter().flatten() {
            if let Some(i) = ev["introduced"].as_str() {
                if let Some(c) = cur.take() {
                    out.push(c);
                }
                cur = Some(VersionRange { introduced: Some(i.to_string()), fixed: None, last_affected: None });
            } else if let Some(f) = ev["fixed"].as_str() {
                let mut c = cur.take().unwrap_or_else(zero);
                c.fixed = Some(f.to_string());
                out.push(c);
            } else if let Some(l) = ev["last_affected"].as_str() {
                let mut c = cur.take().unwrap_or_else(zero);
                c.last_affected = Some(l.to_string());
                out.push(c);
            }
        }
        if let Some(c) = cur.take() {
            out.push(c);
        }
    }
    out
}

/// Every sha256 the record states in prose: `details` and any string under `database_specific`.
pub fn hashes_in(v: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                for h in crate::query::iocs::text_hashes(s) {
                    if !out.contains(&h) {
                        out.push(h);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = vec![];
    if let Some(d) = v.get("details") {
        walk(d, &mut out);
    }
    if let Some(d) = v.get("database_specific") {
        walk(d, &mut out);
    }
    out
}

/// The file name the record ties to each hash: prose in `details` and under `database_specific` (the same sentence or
/// line), and an object that holds a hash beside a name (`{"name": ..., "sha256": ...}`).
pub fn hash_ties_in(v: &Value) -> Vec<(String, String)> {
    fn walk(v: &Value, out: &mut Vec<(String, String)>) {
        let mut add = |t: (String, String)| {
            if !out.contains(&t) {
                out.push(t);
            }
        };
        match v {
            Value::String(s) => crate::query::iocs::text_hash_ties(s).into_iter().for_each(&mut add),
            Value::Array(a) => {
                let mut inner = vec![];
                a.iter().for_each(|x| walk(x, &mut inner));
                inner.into_iter().for_each(&mut add);
            }
            Value::Object(o) => {
                const NAME_KEYS: &[&str] = &["name", "file", "filename", "file_name", "path", "binary", "artifact"];
                let name = NAME_KEYS.iter().find_map(|k| o.get(*k).and_then(|x| x.as_str()));
                let mut inner = vec![];
                for x in o.values() {
                    walk(x, &mut inner);
                }
                inner.into_iter().for_each(&mut add);
                if let Some(n) = name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string()).filter(|n| !n.is_empty()) {
                    for x in o.values().filter_map(|x| x.as_str()) {
                        for h in crate::query::iocs::text_hashes(x) {
                            add((h, n.clone()));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = vec![];
    for k in ["details", "database_specific"] {
        if let Some(d) = v.get(k) {
            walk(d, &mut out);
        }
    }
    out
}

/// Turn an OSV/GHSA record into an Advisory. Each affected entry becomes an `AffectedPackage` with its own explicit
/// versions and ranges (the fixed version belongs to its package and range). `affected` lists the explicit versions as
/// `eco:name@version` and `fixed` the first fixed version, for older readers.
pub fn to_advisory(v: &Value) -> Option<Advisory> {
    let id = v["id"].as_str()?.to_string();
    let mut affected = vec![];
    let mut fixed: Option<String> = None;
    let mut packages: Vec<AffectedPackage> = vec![];
    for a in v["affected"].as_array().into_iter().flatten() {
        let (Some(e), Some(n)) = (a["package"]["ecosystem"].as_str().and_then(eco), a["package"]["name"].as_str()) else { continue };
        let name = norm_name(e, n);
        let versions: Vec<String> = a["versions"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(str::to_string)).collect();
        let ranges = ranges_of(a);
        for ver in &versions {
            affected.push(format!("{e}:{name}@{ver}"));
        }
        if fixed.is_none() {
            fixed = ranges.iter().find_map(|r| r.fixed.clone());
        }
        if versions.is_empty() && ranges.is_empty() {
            continue;
        }
        if let Some(p) = packages.iter_mut().find(|p| p.ecosystem == e && p.name == name) {
            for x in versions {
                if !p.versions.contains(&x) {
                    p.versions.push(x);
                }
            }
            for r in ranges {
                if !p.ranges.contains(&r) {
                    p.ranges.push(r);
                }
            }
        } else {
            packages.push(AffectedPackage { ecosystem: e.to_string(), name, versions, ranges });
        }
    }
    // non-package indicators (hashes, simhashes) travel in database_specific.indicators, and hashes in prose: the same
    // 64-hex reading `--text` does, over `details` and every string under `database_specific`
    for e in v["database_specific"]["indicators"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(|s| s.trim().to_string())) {
        if !affected.contains(&e) {
            affected.push(e);
        }
    }
    for e in hashes_in(v) {
        if !affected.contains(&e) {
            affected.push(e);
        }
    }
    Some(Advisory {
        benign: vec![],
        id,
        aliases: v["aliases"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        title: v["summary"].as_str().map(str::to_string),
        affected,
        fixed,
        exposure_window: None,
        text: v["details"].as_str().map(str::to_string),
        packages,
        provenance: Default::default(),
        hash_names: hash_ties_in(v),
    })
}

/// Fetch one advisory and cache it in the index. None when OSV does not know the id.
pub fn resolve(ctx: &Ctx, id: &str) -> BrResult<Option<Advisory>> {
    resolve_within(ctx, id, 30)
}

/// `resolve`, giving up on the network after `secs`.
pub fn resolve_within(ctx: &Ctx, id: &str, secs: u64) -> BrResult<Option<Advisory>> {
    let url = format!("{}/v1/vulns/{id}", base());
    let v: Value = match ureq::get(&url).timeout(std::time::Duration::from_secs(secs)).call() {
        Ok(r) => r.into_json().map_err(|e| BrError::with_code(format!("cannot read OSV ({e})"), Some("check BR_OSV_API"), 3))?,
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(e) => return Err(BrError::with_code(format!("cannot reach OSV ({e})"), Some("check the network and BR_OSV_API"), 3)),
    };
    let Some(a) = to_advisory(&v) else { return Ok(None) };
    if let Some(w) = v["withdrawn"].as_str() {
        return Err(BrError::with_code(format!("{} was withdrawn by its publisher on {w}", a.id), Some("use the id that replaced it (see aliases on the OSV page)"), 2));
    }
    if a.packages.is_empty() && a.affected.is_empty() {
        let ecos: Vec<String> = v["affected"].as_array().into_iter().flatten().filter_map(|x| x["package"]["ecosystem"].as_str().map(str::to_string)).collect();
        return Err(BrError::with_code(
            format!("{} names no package br can match (ecosystems in the record: {})", a.id, if ecos.is_empty() { "none".into() } else { ecos.join(", ") }),
            Some("br matches npm, PyPI, crates.io, Go and GitHub Actions; pass indicators directly, e.g. br hunt npm:name@1.2.3"),
            2,
        ));
    }
    if let Ok(mut st) = Store::open(ctx, false) {
        let src = "_osv";
        let rows = vec![Row::new("advisory", a.id.clone(), &a)];
        let _ = st.replace(src, &[], rows, &ctx.now);
    }
    Ok(Some(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ghsa_ranges_become_packages_with_per_range_fixes() {
        let v = json!({"id":"GHSA-aaaa-bbbb-cccc","affected":[
            {"package":{"ecosystem":"npm","name":"left-pad"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.3.1"},{"introduced":"2.0.0"},{"fixed":"2.1.4"}]}]},
            {"package":{"ecosystem":"PyPI","name":"Net_Probe.Py"},"versions":["0.4.2"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0.4"},{"last_affected":"0.4.9"}]}]},
            {"package":{"ecosystem":"GitHub Actions","name":"acme/setup"},"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"deadbeef"}]}]}
        ]});
        let a = to_advisory(&v).unwrap();
        assert_eq!(a.packages.len(), 2);
        let n = &a.packages[0];
        assert_eq!((n.ecosystem.as_str(), n.name.as_str()), ("npm", "left-pad"));
        assert_eq!(n.ranges.len(), 2);
        assert_eq!(n.ranges[1], VersionRange { introduced: Some("2.0.0".into()), fixed: Some("2.1.4".into()), last_affected: None });
        let p = &a.packages[1];
        assert_eq!(p.name, "net-probe-py");
        assert_eq!(p.ranges[0].last_affected.as_deref(), Some("0.4.9"));
        assert_eq!(a.affected, vec!["pypi:net-probe-py@0.4.2".to_string()]);
        assert_eq!(a.fixed.as_deref(), Some("1.3.1"));
    }

    #[test]
    fn go_record_without_versions_still_has_ranges() {
        let v = json!({"id":"GO-2026-1","affected":[{"package":{"ecosystem":"Go","name":"example.com/Mod"},"ranges":[{"type":"SEMVER","events":[{"fixed":"1.2.0"}]}]}]});
        let a = to_advisory(&v).unwrap();
        assert_eq!(a.packages[0].name, "example.com/Mod");
        assert_eq!(a.packages[0].ranges[0].introduced.as_deref(), Some("0"));
    }

    #[test]
    fn hashes_in_details_and_database_specific_become_indicators() {
        let h1 = "ab".repeat(32);
        let h2 = "cd".repeat(32);
        let v = json!({"id":"MAL-1","details": format!("The dropper (sha256: {h1}) was served."),
            "database_specific": {"iocs": {"files": [format!("sha256:{h2}")]}, "indicators": []},
            "affected":[{"package":{"ecosystem":"npm","name":"x"},"versions":["1.0.0"]}]});
        let a = to_advisory(&v).unwrap();
        assert!(a.affected.contains(&format!("sha256:{h1}")), "{:?}", a.affected);
        assert!(a.affected.contains(&format!("sha256:{h2}")), "{:?}", a.affected);
    }

    #[test]
    fn unknown_ecosystem_yields_no_packages() {
        let v = json!({"id":"X-1","affected":[{"package":{"ecosystem":"Maven","name":"a:b"},"versions":["1"]}]});
        let a = to_advisory(&v).unwrap();
        assert!(a.packages.is_empty() && a.affected.is_empty());
    }
}
