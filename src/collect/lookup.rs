//! Advisories are looked up, not assumed. An id that is in neither the index nor a note is asked of OSV before br says
//! "not found", and the error names every place it looked. Advisory ids in pasted text are fetched the same way, and "fixed in X"
//! / "upgrade to X" in the text become the fixed version of the packages beside it, labelled "from the text".

use crate::collect::{config, osv};
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::query::iocs::{self as I, Extracted, Ioc, IocKind, ResolvedAdvisory};
use crate::view::{Advisory, AffectedPackage};

/// The place OSV is asked, as the error names it.
fn osv_where() -> String {
    std::env::var("BR_OSV_API").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "https://api.osv.dev".into()).trim_end_matches('/').to_string()
}

/// The spellings OSV may know an id by: as typed, and GHSA ids in the lowercase form GitHub writes them.
fn spellings(id: &str) -> Vec<String> {
    let mut v = vec![id.to_string()];
    if id.len() > 5 && id[..5].eq_ignore_ascii_case("GHSA-") {
        v.push(format!("GHSA-{}", id[5..].to_lowercase()));
    } else if let Some((fam, rest)) = id.split_once('-') {
        v.push(format!("{}-{rest}", fam.to_uppercase()));
    }
    v.dedup();
    v
}

/// What asking OSV for one id gave.
pub enum Fetched {
    Found(Box<Advisory>),
    /// OSV answered and has no record
    Missing,
    /// OSV could not be asked (no network, a bad BR_OSV_API): why
    Unreached(String),
}

/// Ask OSV for `id` (and its other spellings). The record is cached in the index when there is one, so the next hunt is offline.
pub fn fetch(ctx: &Ctx, id: &str) -> BrResult<Fetched> {
    let mut unreached: Option<String> = None;
    for s in spellings(id) {
        match osv::resolve_within(ctx, &s, 10) {
            Ok(Some(a)) => return Ok(Fetched::Found(Box::new(a))),
            Ok(None) => {}
            // code 3 is "could not reach OSV"; the other errors (withdrawn, names no package) are answers worth showing as they are
            Err(e) if e.code == 3 => unreached = Some(e.msg),
            Err(e) => return Err(e),
        }
    }
    Ok(match unreached {
        Some(why) => Fetched::Unreached(why),
        None => Fetched::Missing,
    })
}

/// The "not found" error, naming where br looked.
pub fn not_found(ctx: &Ctx, id: &str, outcome: &Fetched) -> BrError {
    let osv = match outcome {
        Fetched::Unreached(why) => format!("OSV at {} could not be asked ({why})", osv_where()),
        _ => format!("OSV at {} has no record of it", osv_where()),
    };
    let notes = ctx.home.join("advisories").join(format!("{id}.yaml"));
    BrError::new(
        format!("advisory {id} not found; looked in the advisories cached in the index, your notes ({}), and {osv}", notes.display()),
        Some(&format!("pass --text FILE or a local advisory JSON file, or say what you know: br advisory note {id} --ioc eco:name@version")),
    )
}

/// `--advisory ID`: the index and the notes first, then OSV (and its other spellings of the id).
pub fn resolve(ctx: &Ctx, advs: &[Advisory], id: &str) -> BrResult<ResolvedAdvisory> {
    match I::resolve_advisory(advs, id) {
        // a note that holds a window and nothing to match on (OSV was out of reach when it was written) is not the record: ask again
        Ok(r) if r.packages.is_empty() && r.affected.is_empty() && !std::path::Path::new(id).is_file() => {
            if let Ok(Fetched::Found(a)) = fetch(ctx, id) {
                let row = serde_json::to_value(&*a).map_err(|e| BrError::new(format!("cannot read the OSV record ({e})"), None))?;
                let merged = config::advisories_from(ctx, vec![(a.id.clone(), row)]);
                return I::resolve_advisory(&merged, id).or(Ok(r));
            }
            return Ok(r);
        }
        Ok(r) => return Ok(r),
        Err(e) if !e.msg.ends_with("not found") => return Err(e),
        Err(_) => {}
    }
    match fetch(ctx, id)? {
        Fetched::Found(a) => {
            // merged with the operator's note on it, as every other reader sees it
            let row = serde_json::to_value(&*a).map_err(|e| BrError::new(format!("cannot read the OSV record ({e})"), None))?;
            let merged = config::advisories_from(ctx, vec![(a.id.clone(), row)]);
            I::resolve_advisory(&merged, id).or_else(|_| I::resolve_advisory(&merged, &merged.first().map(|m| m.id.clone()).unwrap_or_default()))
        }
        other => Err(not_found(ctx, id, &other)),
    }
}

/// What reading `--text` gave: the extraction, the advisories its ids fetched, and the lines that say so.
pub struct TextRead {
    pub ex: Extracted,
    pub advisories: Vec<ResolvedAdvisory>,
    /// package indicators of the fetched advisories, with their own versions and ranges
    pub pkg_iocs: Vec<Ioc>,
    /// non-package indicators of the fetched advisories (hashes, simhashes, action commits), in indicator syntax
    pub strs: Vec<String>,
    /// lines to say what was fetched and which fixed versions came from the text
    pub notes: Vec<String>,
}

/// Read advisory prose; every advisory id in it is looked up (the index, the notes, then OSV).
pub fn read_text(ctx: &Ctx, advs: &[Advisory], text: &str) -> BrResult<TextRead> {
    let ex = I::extract_prose(text)?;
    let mut t = TextRead { ex, advisories: vec![], pkg_iocs: vec![], strs: vec![], notes: vec![] };
    let ids = t.ex.advisory_ids.clone();
    for id in &ids {
        match resolve(ctx, advs, id) {
            Ok(r) => {
                let mut n = 0;
                for p in &r.packages {
                    if let Some(i) = Ioc::from_package(p) {
                        if !t.pkg_iocs.iter().any(|x| x.text == i.text) {
                            t.pkg_iocs.push(i);
                            n += 1;
                        }
                    }
                }
                t.strs.extend(r.affected.iter().filter(|x| x.starts_with("sha256:") || x.starts_with("simhash:") || (x.starts_with("action:") && x.contains('#'))).cloned());
                if r.packages.is_empty() {
                    t.strs.extend(r.affected.iter().filter(|x| !x.starts_with("sha256:") && !x.starts_with("simhash:") && !x.starts_with("action:")).cloned());
                }
                t.notes.push(format!("the text names {id}: read its record ({})", crate::collect::util::plural(n, "package")));
                if t.ex.window.is_none() {
                    t.ex.window = r.window.clone();
                }
                t.advisories.push(r);
            }
            Err(e) => t.notes.push(format!("the text names {id}, but its record could not be read: {}", e.msg)),
        }
    }
    if t.ex.iocs.is_empty() && t.pkg_iocs.is_empty() && t.strs.is_empty() {
        return Err(BrError::new(
            "no indicators found in the text",
            Some(&format!(
                "{}write them as eco:name@version (npm:lodash@4.17.21), @scope/name or a 64-hex sha256, or pass --advisory ID",
                if t.notes.is_empty() { String::new() } else { format!("{}; ", t.notes.join("; ")) }
            )),
        ));
    }
    Ok(t)
}

/// Attach the fixed version the text states to the packages it names. Each version the indicator lists below the fix gets
/// a range `[v, fixed)`, the same convention a note's `--fixed` uses, so `fix`, `notify` and `purge` find it with `fixed_for`.
/// An indicator that already carries an advisory's own ranges is left alone. Returns the lines that say what was read.
pub fn apply_text_fixes(iocs: &mut [Ioc], fixes: &[(String, String, String)]) -> Vec<String> {
    let mut lines = vec![];
    for ioc in iocs.iter_mut() {
        if ioc.kind != IocKind::Pkg || ioc.set.is_some() {
            continue;
        }
        let (Some(eco), Some(vs)) = (ioc.eco.clone(), ioc.versions.clone().filter(|v| !v.is_empty())) else { continue };
        let key = config::fixed_key(&eco, &ioc.name);
        let Some((_, _, fixed)) = fixes.iter().find(|(e, n, _)| config::fixed_key(&I::br_eco(e), n) == key) else { continue };
        let mut p = AffectedPackage { ecosystem: eco.clone(), name: ioc.name.clone(), versions: vs, ranges: vec![] };
        config::apply_fixed(&mut p, fixed, false);
        if p.ranges.is_empty() {
            continue;
        }
        lines.push(format!("{}:{}: fixed in {fixed} (from the text)", eco, ioc.name));
        ioc.versions = None;
        ioc.set = Some(p);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg_ioc(s: &str) -> Ioc {
        I::parse_ioc(s, None).unwrap()
    }

    // "fixed in X" in the text is the fixed version of the package beside it, and the plan finds it
    #[test]
    fn a_fixed_version_in_the_text_reaches_the_packages_beside_it() {
        let ex = I::extract_prose("npm lodash 4.17.21 is trojaned. Fixed in 4.17.22.\n\nPyPI evil-py 1.0.0 is malicious, upgrade to 1.0.1 now.").unwrap();
        assert!(ex.fixed.contains(&("npm".into(), "lodash".into(), "4.17.22".into())), "{:?}", ex.fixed);
        assert!(ex.fixed.contains(&("pypi".into(), "evil-py".into(), "1.0.1".into())), "{:?}", ex.fixed);
        let mut iocs: Vec<Ioc> = ex.iocs.iter().map(|s| pkg_ioc(s)).collect();
        let lines = apply_text_fixes(&mut iocs, &ex.fixed);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines.iter().all(|l| l.contains("from the text")));
        let l = iocs.iter().find(|i| i.name == "lodash").unwrap();
        assert_eq!(crate::query::version::fixed_for(l.set.as_ref().unwrap(), "4.17.21").as_deref(), Some("4.17.22"));
        // the bad version is still the only one named: the plan's fix does not make 4.17.20 affected
        assert!(crate::query::iocs::match_pkg(l, "npm", "lodash", "4.17.21"));
        assert!(!crate::query::iocs::match_pkg(l, "npm", "lodash", "4.17.20"));
    }

    // a paragraph that names two different fixes gives none to a package whose own sentence names none
    #[test]
    fn two_fixed_versions_in_a_paragraph_are_not_guessed() {
        let ex = I::extract_prose("npm alpha 1.0.0 is bad. PyPI beta 2.0.0 is bad. Fixed in 1.0.1 for one, upgrade to 2.0.1 for the other.").unwrap();
        assert!(ex.fixed.is_empty(), "{:?}", ex.fixed);
    }

    #[test]
    fn advisory_ids_in_prose_are_found_in_osv_s_spelling() {
        let ids = I::advisory_ids_in("See GHSA-Q7VR-4xhc-M2JW and mal-2026-3187, also cve-2026-12345.");
        assert_eq!(ids, vec!["GHSA-q7vr-4xhc-m2jw", "MAL-2026-3187", "CVE-2026-12345"]);
        assert!(I::advisory_ids_in("GHSA-short and MAL-26-1").is_empty());
    }

    #[test]
    fn the_not_found_error_names_where_it_looked() {
        let ctx = Ctx { now: "2026-05-12T07:40:00Z".into(), home: std::path::PathBuf::from("/tmp/br-home-x"), user: None, host: None, color: false };
        let e = not_found(&ctx, "GHSA-aaaa-bbbb-cccc", &Fetched::Missing);
        assert!(e.msg.contains("index") && e.msg.contains("your notes") && e.msg.contains("OSV"), "{}", e.msg);
        let e = not_found(&ctx, "GHSA-aaaa-bbbb-cccc", &Fetched::Unreached("timed out".into()));
        assert!(e.msg.contains("could not be asked (timed out)"), "{}", e.msg);
    }

    #[test]
    fn spellings_cover_ghsa_case_and_family_case() {
        assert_eq!(spellings("GHSA-Q7VR-4XHC-M2JW"), vec!["GHSA-Q7VR-4XHC-M2JW", "GHSA-q7vr-4xhc-m2jw"]);
        assert_eq!(spellings("mal-2026-1"), vec!["mal-2026-1", "MAL-2026-1"]);
    }
}
