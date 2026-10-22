//! `br advisory`: list what br knows, show one advisory as every command reads it, and keep a note.
//!
//! A note is one record per advisory id (`BR_HOME/advisories/<ID>.yaml`). `collect::config::advisories` merges it with the OSV
//! record, so hunt, fix, notify, purge, evidence and diff all see the same packages, fixed versions, indicators and window.

use crate::cli::{AdvisoryArgs, AdvisorySub};
use crate::collect::config::{self, NoteFixed};
use crate::collect::util::fmt;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::query::iocs as I;
use crate::store::Store;
use crate::view::{Advisory, VersionRange};

pub fn run(a: &AdvisoryArgs, ctx: &Ctx) -> BrResult<i32> {
    // `br advisory ID` is `br advisory show ID`
    if let (None, Some(id)) = (&a.sub, &a.id) {
        if !id.contains('-') {
            return Err(crate::cli::invalid_subcommand("advisory", id));
        }
        return show(ctx, id);
    }
    match &a.sub {
        None | Some(AdvisorySub::List) => list(ctx),
        Some(AdvisorySub::Show { id }) => show(ctx, id),
        Some(AdvisorySub::Note { id, window, fixed, ioc, hash, benign, why }) => note(ctx, id, window.as_deref(), fixed, ioc, hash, benign.as_deref(), why.as_deref()),
    }
}

/// Every advisory the index and the notes know, merged.
fn known(ctx: &Ctx) -> Vec<Advisory> {
    match Store::open(ctx, false) {
        Ok(st) => config::advisories(ctx, &st),
        Err(_) => config::advisories_from(ctx, vec![]),
    }
}

fn win_text(a: &Advisory) -> String {
    match &a.exposure_window {
        Some(w) => format!("{}..{}", fmt(&w.from), fmt(&w.to)),
        None => "-".into(),
    }
}

fn range_text(r: &VersionRange) -> String {
    let mut p = vec![];
    if let Some(i) = r.introduced.as_deref().filter(|x| *x != "0" && !x.is_empty()) {
        p.push(format!(">={i}"));
    }
    if let Some(f) = &r.fixed {
        p.push(format!("<{f}"));
    } else if let Some(l) = &r.last_affected {
        p.push(format!("<={l}"));
    }
    if p.is_empty() {
        "all versions".into()
    } else {
        p.join(" ")
    }
}

fn from(label: Option<&String>) -> String {
    label.map(|l| format!("from {l}")).unwrap_or_default()
}

fn list(ctx: &Ctx) -> BrResult<i32> {
    let advs = known(ctx);
    if advs.is_empty() {
        println!("no advisories yet");
        println!("add what you know with: br advisory note ID --ioc eco:name@1.2.3 --window FROM..TO   (br hunt --advisory ID then works from the note)");
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = advs
        .iter()
        .map(|a| {
            let osv = a.provenance.indicators.values().any(|l| l == "OSV") || a.provenance.fixed.as_deref() == Some("OSV");
            let note = config::note(ctx, &a.id).is_some();
            let src = match (osv, note) {
                (true, true) => "OSV + your note",
                (true, false) => "OSV",
                (false, _) => "your note",
            };
            let hashes = a.affected.iter().filter(|x| x.starts_with("sha256:")).count();
            vec![a.id.clone(), a.packages.len().to_string(), hashes.to_string(), win_text(a), a.fixed.clone().unwrap_or_else(|| "-".into()), src.to_string()]
        })
        .collect();
    println!("{}", crate::collect::util::table(&["ADVISORY", "PACKAGES", "HASHES", "WINDOW", "FIXED", "FROM"], &rows, 0).join("\n"));
    println!();
    println!("br advisory show ID prints one in full, with where each part came from");
    Ok(0)
}

fn show(ctx: &Ctx, id: &str) -> BrResult<i32> {
    let mut advs = known(ctx);
    let lo = id.to_lowercase();
    let find = |advs: &[Advisory]| advs.iter().position(|a| a.id.to_lowercase() == lo || a.aliases.iter().any(|x| x.to_lowercase() == lo));
    if find(&advs).is_none() {
        // Ask OSV before saying it is unknown, and say where br looked
        match crate::collect::lookup::fetch(ctx, id)? {
            crate::collect::lookup::Fetched::Found(a) => {
                let row = serde_json::to_value(&*a).map_err(|e| BrError::new(format!("cannot read the OSV record ({e})"), None))?;
                advs = config::advisories_from(ctx, vec![(a.id.clone(), row)]);
            }
            other => return Err(crate::collect::lookup::not_found(ctx, id, &other)),
        }
    }
    let Some(i) = find(&advs) else {
        return Err(BrError::new(format!("no advisory {id} in the index or in your notes"), Some("br advisory lists what is known; br advisory note ID --ioc eco:name@1.2.3 starts one")));
    };
    let a = &advs[i];
    println!("{}{}", a.id, if a.aliases.is_empty() { String::new() } else { format!("  (also {})", a.aliases.join(", ")) });
    if let Some(t) = &a.title {
        println!("{t}");
    }
    println!();
    println!("window   {}  {}", win_text(a), from(a.provenance.window.as_ref()));
    println!("fixed    {}  {}", a.fixed.clone().unwrap_or_else(|| "none stated".into()), from(a.provenance.fixed.as_ref()));
    if !a.packages.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = a
            .packages
            .iter()
            .map(|p| {
                let mut what: Vec<String> = p.versions.clone();
                what.extend(p.ranges.iter().filter(|r| !(r.introduced.is_some() && r.fixed.is_some() && p.versions.iter().any(|v| Some(v) == r.introduced.as_ref()))).map(range_text));
                let fixes: Vec<String> = p.ranges.iter().filter_map(|r| r.fixed.clone()).collect();
                let key = format!("{}:{}", p.ecosystem, I::name_key(&p.ecosystem, &p.name));
                vec![
                    format!("{}:{}", p.ecosystem, p.name),
                    what.join(", "),
                    if fixes.is_empty() { "-".into() } else { fixes.join(", ") },
                    a.provenance.indicators.get(&key).map(|l| format!("from {l}")).unwrap_or_default(),
                ]
            })
            .collect();
        println!("{}", crate::collect::util::table(&["PACKAGE", "AFFECTED", "FIXED IN", "SOURCE"], &rows, 0).join("\n"));
    }
    let others: Vec<&String> = a
        .affected
        .iter()
        .filter(|x| !x.contains('@') || x.starts_with("sha256:") || x.starts_with("simhash:") || x.starts_with("action:"))
        .filter(|x| x.starts_with("sha256:") || x.starts_with("simhash:") || x.starts_with("action:"))
        .collect();
    if !others.is_empty() {
        println!();
        for h in others {
            println!("{h}  {}", from(a.provenance.indicators.get(h)));
        }
    }
    for b in &a.benign {
        println!("benign: {}  {}", b.sha256, b.why);
    }
    Ok(0)
}

fn bad_fixed(f: &str) -> BrError {
    BrError::new(format!("cannot read --fixed \"{f}\""), Some("write a version (0.4.3) for every package, or eco:name@0.4.3 for one package"))
}

#[allow(clippy::too_many_arguments)]
fn note(ctx: &Ctx, id: &str, window: Option<&str>, fixed: &[String], iocs: &[String], hashes: &[String], benign: Option<&str>, why: Option<&str>) -> BrResult<i32> {
    let mut n = config::note(ctx, id).unwrap_or_default();
    let at = ctx.now.clone();
    if let Some(w) = window {
        if config::parse_window(w).is_none() {
            return Err(BrError::new(format!("cannot read the window \"{w}\""), Some("write FROM..TO, e.g. 2026-05-11T19:20Z..2026-05-11T19:41Z")));
        }
        n.window = Some(w.to_string());
        n.window_at = Some(at.clone());
    }
    for f in fixed {
        let f = f.trim();
        if f.is_empty() {
            return Err(bad_fixed(f));
        }
        if f.contains(':') {
            let Some((spec, ver)) = f.rsplit_once('@').filter(|(s, v)| s.contains(':') && !v.is_empty()) else { return Err(bad_fixed(f)) };
            let (eco, name) = spec.split_once(':').unwrap();
            let eco = I::br_eco(eco);
            if !I::ECOS.contains(&eco.as_str()) || name.is_empty() {
                return Err(BrError::new(format!("cannot read --fixed \"{f}\""), Some(&format!("the ecosystem must be one of: {}", I::ECOS.join(", ")))));
            }
            n.fixed_pkgs.insert(config::fixed_key(&eco, name), NoteFixed { version: ver.to_string(), at: Some(at.clone()) });
        } else {
            n.fixed = Some(f.to_string());
            n.fixed_at = Some(at.clone());
        }
    }
    for t in iocs {
        let i = I::parse_ioc(t, None)?;
        let ok = i.kind == I::IocKind::Pkg && (i.set.is_some() || i.versions.as_ref().map(|v| !v.is_empty()).unwrap_or(false));
        if !ok {
            return Err(BrError::new(
                format!("\"{t}\" names no version"),
                Some("a note adds an affected version or range: --ioc npm:name@1.2.3, or --ioc \"pypi:name@>=1.0,<1.2\"; use --hash for a file hash"),
            ));
        }
        n.iocs.insert(i.text.clone(), at.clone());
    }
    for h in hashes {
        // `sha256:HEX` or `sha256:HEX=NAME`: the name ties the hash to a file, for the "not a match" hint
        let (hex, name) = match h.split_once('=') {
            Some((x, nm)) => (x, Some(nm.trim()).filter(|nm| !nm.is_empty())),
            None => (h.as_str(), None),
        };
        let i = I::parse_ioc(&format!("sha256:{}", hex.trim().trim_start_matches("sha256:")), None)?;
        n.hashes.insert(i.text.clone(), at.clone());
        if let Some(nm) = name {
            n.hash_names.insert(i.text.clone(), nm.to_string());
        }
    }
    if let Some(b) = benign {
        let h = b.trim().to_lowercase();
        let h = h.strip_prefix("sha256:").unwrap_or(&h).to_string();
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(BrError::new(format!("\"{b}\" is not a sha256"), Some("write --benign sha256: followed by 64 hex characters")));
        }
        n.benign.retain(|x| x.sha256 != format!("sha256:{h}"));
        n.benign.push(crate::view::BenignMark { sha256: format!("sha256:{h}"), why: why.unwrap_or_default().to_string() });
    }
    // With no flag there is nothing to change: show the note and write nothing
    let changes = window.is_some() || !fixed.is_empty() || !iocs.is_empty() || !hashes.is_empty() || benign.is_some();
    if changes {
        config::set_note(ctx, id, &n)?;
        println!("noted {id}{}", n.window.as_ref().map(|w| format!(" window {w}")).unwrap_or_default());
        println!("the note now holds:");
    } else {
        println!("{id}: nothing was written (no flag given); the note holds:");
    }
    println!("  window      {}", n.window.clone().unwrap_or_else(|| "-".into()));
    let mut fx: Vec<String> = n.fixed.iter().map(|f| format!("{f} (every package)")).collect();
    fx.extend(n.fixed_pkgs.iter().map(|(k, v)| format!("{k} {}", v.version)));
    println!("  fixed       {}", if fx.is_empty() { "-".to_string() } else { fx.join(", ") });
    println!("  indicators  {}", if n.iocs.is_empty() { "-".to_string() } else { n.iocs.keys().cloned().collect::<Vec<_>>().join(", ") });
    println!(
        "  hashes      {}",
        if n.hashes.is_empty() { "-".to_string() } else { n.hashes.keys().map(|h| n.hash_names.get(h).map_or(h.clone(), |nm| format!("{h} ({nm})"))).collect::<Vec<_>>().join(", ") }
    );
    if !n.benign.is_empty() {
        println!("  benign      {}", n.benign.iter().map(|b| b.sha256.clone()).collect::<Vec<_>>().join(", "));
    }
    if !changes {
        return Ok(0);
    }
    // the note stands alone, but OSV's record is fetched when it can be, so the merged advisory has both
    match crate::collect::osv::resolve_within(ctx, id, 10) {
        Ok(Some(_)) => println!("OSV knows {id}: its record is cached and merged with your note (br advisory show {id})"),
        Ok(None) => println!("OSV has no record of {id}: the note stands alone (br hunt --advisory {id} works from it)"),
        Err(e) => println!("OSV was not reached ({}): the note stands alone; br scan --stale or init fetches the record later", e.msg),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::config::Note;

    fn ctx() -> Ctx {
        let home = std::env::temp_dir().join(format!("br-adv-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        Ctx { now: "2026-05-12T07:40:00Z".into(), home, user: None, host: None, color: false }
    }

    #[test]
    fn a_note_alone_is_an_advisory_with_packages_fixes_hashes_and_provenance() {
        let c = ctx();
        let h = "ab".repeat(32);
        std::env::set_var("BR_OSV_API", "http://127.0.0.1:9");
        note(
            &c,
            "GHSA-aaaa-bbbb-cccc",
            Some("2026-05-11T14:00Z..2026-05-11T18:00Z"),
            &["0.4.3".into(), "go:example.com/m@v1.2.1".into()],
            &["npm:left-pad@1.0.0".into(), "go:example.com/m@v1.2.0".into()],
            std::slice::from_ref(&h),
            None,
            None,
        )
        .unwrap();
        let advs = config::advisories_from(&c, vec![]);
        assert_eq!(advs.len(), 1);
        let a = &advs[0];
        assert_eq!(a.packages.len(), 2);
        let np = a.packages.iter().find(|p| p.name == "left-pad").unwrap();
        // the global fix reaches the package that has no fix of its own, through a range version::fixed_for reads
        assert_eq!(crate::query::version::fixed_for(np, "1.0.0").as_deref(), None::<&str>);
        let gp = a.packages.iter().find(|p| p.name == "example.com/m").unwrap();
        assert_eq!(crate::query::version::fixed_for(gp, "v1.2.0").as_deref(), Some("v1.2.1"));
        assert!(a.affected.contains(&format!("sha256:{h}")));
        assert_eq!(a.fixed.as_deref(), Some("0.4.3"));
        assert!(a.provenance.window.as_deref().unwrap().starts_with("your note 05-12 07:40"), "{:?}", a.provenance);
        assert!(a.provenance.indicators.values().all(|l| l.starts_with("your note")));
        let _ = std::fs::remove_dir_all(&c.home);
    }

    #[test]
    fn a_note_fix_for_one_package_replaces_osv_s_and_leaves_matching_alone() {
        let mut a = Advisory { id: "X".into(), ..Default::default() };
        a.packages.push(crate::view::AffectedPackage { ecosystem: "npm".into(), name: "p".into(), versions: vec!["1.0.0".into()], ranges: vec![] });
        let mut n = Note::default();
        n.fixed_pkgs.insert(config::fixed_key("npm", "p"), NoteFixed { version: "1.0.5".into(), at: None });
        config::merge_note(&mut a, &n);
        let p = &a.packages[0];
        assert_eq!(crate::query::version::fixed_for(p, "1.0.0").as_deref(), Some("1.0.5"));
        assert!(crate::query::version::is_affected(p, "1.0.0"));
        assert!(!crate::query::version::is_affected(p, "0.9.0"));
        assert!(!crate::query::version::is_affected(p, "1.0.5"));
    }
}
