//! `br verify`.

use crate::cli::VerifyArgs;
use crate::collect::brx;
use crate::ctx::Ctx;
use crate::error::BrResult;

/// The key fingerprint an evidence JSON in this seal says it was signed with: the newest custody row of its own
/// issue (the last "evidence" row), so a file that names a signature cannot lose it by losing the `.sig`.
fn recorded_signature(file: &str, manifest: Option<&str>) -> Option<String> {
    let dir = std::path::Path::new(manifest.unwrap_or(file)).parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let mut names: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from(file)];
    if let Some(m) = manifest {
        names.extend(brx::read_manifest(m).unwrap_or_default().into_iter().map(|(_, n)| dir.join(n)));
    }
    for p in names {
        if p.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let Some(doc) = std::fs::read_to_string(&p).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()) else { continue };
        let last = doc["custody"].as_array().and_then(|rows| rows.iter().rev().find(|r| r["event"] == "evidence"));
        if let Some(k) = last.and_then(|r| r["signed_with"].as_str()).filter(|k| !k.is_empty()) {
            return Some(k.to_string());
        }
    }
    None
}

/// A signature, once made, is required. Returns the FAIL message when one is missing, or None.
fn missing_signature(a: &VerifyArgs, status: &str) -> Option<String> {
    let manifest = brx::find_seal(&a.file);
    let sig = manifest.as_ref().map(|m| format!("{m}.sig"));
    if status != "ok" && status != "internal" && status != "unverified" {
        return None;
    }
    if sig.as_ref().is_some_and(|s| std::path::Path::new(s).exists()) {
        return None;
    }
    let where_ = sig.clone().unwrap_or_else(|| format!("{}.sha256.sig", a.file));
    if let Some(key) = recorded_signature(&a.file, manifest.as_deref()) {
        return Some(format!("the file records that it was signed with key {key}, but its signature {where_} is missing; a signature that was made is required, so this file is not what was issued"));
    }
    if let Some(al) = &a.allowed_signers {
        return Some(format!("--allowed-signers {al} was given, but there is no signature to check: {where_} is missing; the file is unsigned or its signature was removed"));
    }
    None
}

pub fn run(a: &VerifyArgs, _ctx: &Ctx) -> BrResult<i32> {
    let (status, msg, sha) = brx::verify_with(&a.file, a.no_seal, a.allowed_signers.as_deref())?;
    let f = &a.file;
    let short = &sha[..16.min(sha.len())];
    if let Some(m) = missing_signature(a, status) {
        println!("FAIL: {m}");
        return Ok(1);
    }
    match status {
        "ok" => {
            println!("OK: {f} unmodified (sha256 {short}...; {msg})");
            Ok(0)
        }
        "internal" => {
            println!("OK: {f} internal manifest intact (sha256 {short}...; {msg})");
            Ok(0)
        }
        "unverified" => {
            println!("UNVERIFIED: {msg} for {f}; nothing proves it is the file that was issued");
            println!("hint: ask the sender for the seal file, or check only the file's own manifest with: br verify {f} --no-seal");
            Ok(1)
        }
        _ => {
            // the seal's own messages already name the file they are about; only the bare ones need the file added
            if msg.contains(" is not listed in ") {
                // a renamed file: say which names the seal holds, and which of them has this file's content
                let entries = brx::find_seal(f).and_then(|m| brx::read_manifest(&m).ok()).unwrap_or_default();
                let held: Vec<&str> = entries.iter().map(|(_, n)| n.as_str()).collect();
                println!("FAIL: {msg}{}", if held.is_empty() { String::new() } else { format!("; the seal holds {}", held.join(", ")) });
                if let Some((_, n)) = entries.iter().find(|(h, _)| *h == sha) {
                    println!("hint: the content of {f} matches {n} in the seal, so the file was renamed; check it under that name: br verify {}", std::path::Path::new(f).with_file_name(n).display());
                }
            } else if msg.contains(" for ") || msg.contains(" is ") || msg.contains(" in the seal") {
                println!("FAIL: {msg}");
            } else {
                println!("FAIL: {msg} for {f}");
            }
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_signature_is_read_from_the_newest_evidence_row() {
        let d = std::env::temp_dir().join(format!("br-r60-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("e.json");
        std::fs::write(&f, r#"{"custody":[{"event":"evidence","signed_with":"SHA256:old"},{"event":"evidence","signed_with":"SHA256:new"}]}"#).unwrap();
        assert_eq!(recorded_signature(f.to_str().unwrap(), None).as_deref(), Some("SHA256:new"));
        std::fs::write(&f, r#"{"custody":[{"event":"evidence","signed_with":"SHA256:old"},{"event":"evidence"}]}"#).unwrap();
        assert_eq!(recorded_signature(f.to_str().unwrap(), None), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
