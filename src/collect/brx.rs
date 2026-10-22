//! Portable scan file (.brx) and the seals shared with evidence files.

use std::io::Read;
use std::path::Path;

use rusqlite::types::Value as Sql;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::view::{HostFile, HostItem};

pub const SIG_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
pub const SIG_END: &str = "-----END SSH SIGNATURE-----";
pub const SIG_NAMESPACE: &str = "br-evidence";
pub const MD_TRAILER: &str = "<!-- br-integrity sha256:";

pub fn sha_file(path: &Path) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn sha_str(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Who performed an action, for the chain of custody: BR_USER, else the git user name, else "unknown".
pub fn who(ctx: &Ctx) -> String {
    ctx.user.clone().unwrap_or_else(|| "unknown".into())
}

pub fn requested_by_default(ctx: &Ctx) -> Option<String> {
    ctx.user.clone()
}

/// This machine's name: BR_HOST, else the system hostname.
pub fn local_host(ctx: &Ctx) -> BrResult<String> {
    if let Some(h) = &ctx.host {
        return Ok(h.clone());
    }
    // macOS: the name the user set (stable), not the DHCP-assigned `hostname`
    if cfg!(target_os = "macos") {
        let o = std::process::Command::new("scutil").args(["--get", "LocalHostName"]).stderr(std::process::Stdio::null()).output().ok();
        if let Some(n) = o.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty()) {
            return Ok(n);
        }
    }
    let out = std::process::Command::new("hostname").stderr(std::process::Stdio::null()).output().ok();
    let name = out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty());
    name.ok_or_else(|| BrError::new("cannot tell which machine this is", Some("set BR_HOST to the machine name")))
}

pub fn io_err(e: std::io::Error, path: &str) -> BrError {
    BrError::with_code(format!("{}: {}", path, io_msg(&e)), Some("check the path and its permissions"), 1)
}

pub fn io_msg(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => "No such file or directory".into(),
        PermissionDenied => "Permission denied".into(),
        _ => {
            let s = e.to_string();
            s.split(" (os error").next().unwrap_or(&s).to_string()
        }
    }
}

// ---- seals ----------------------------------------------------------------------------------------------------
fn no_keygen() -> BrError {
    BrError::with_code(
        "ssh-keygen is not installed, so signatures cannot be made or checked".to_string(),
        Some("install OpenSSH (it provides ssh-keygen), then re-run; the sha256 seal alone needs no ssh-keygen"),
        1,
    )
}

fn keygen() -> String {
    std::env::var("BR_SSH_KEYGEN").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "ssh-keygen".into())
}

fn run_keygen(args: &[&str], stdin: Option<&[u8]>) -> BrResult<std::process::Output> {
    use std::io::Write;
    let mut c = std::process::Command::new(keygen());
    c.args(args).stdin(if stdin.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() }).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { no_keygen() } else { BrError::new(format!("cannot run ssh-keygen ({e})"), None) })?;
    if let (Some(d), Some(mut si)) = (stdin, child.stdin.take()) {
        let _ = si.write_all(d);
    }
    child.wait_with_output().map_err(|e| BrError::new(format!("ssh-keygen failed ({e})"), None))
}

fn text_of(o: &std::process::Output) -> String {
    let e = String::from_utf8_lossy(&o.stderr).trim().to_string();
    if e.is_empty() {
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    } else {
        e
    }
}

/// Write MAIN.sha256 covering every file in `paths`; with `key`, also sign it (MAIN.sha256.sig) with
/// `ssh-keygen -Y sign -n br-evidence -f KEY`. Returns the written paths.
pub fn write_seal(main_path: &str, paths: &[String], key: Option<&str>) -> BrResult<Vec<String>> {
    let manifest = format!("{main_path}.sha256");
    let mut text = String::new();
    for p in paths {
        let base = Path::new(p).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        text.push_str(&format!("{}  {}\n", sha_file(Path::new(p)).map_err(|e| io_err(e, p))?, base));
    }
    // check the key first: a failed signature must not leave a seal that looks complete
    if let Some(k) = key {
        key_fingerprint(k)?;
    }
    std::fs::write(&manifest, &text).map_err(|e| io_err(e, &manifest))?;
    let mut written = vec![manifest.clone()];
    let sig = format!("{manifest}.sig");
    let _ = std::fs::remove_file(&sig);
    if let Some(k) = key {
        let o = run_keygen(&["-Y", "sign", "-n", SIG_NAMESPACE, "-f", k, &manifest], None)?;
        if !o.status.success() || !Path::new(&sig).exists() {
            let _ = std::fs::remove_file(&manifest);
            return Err(BrError::with_code(
                format!("ssh-keygen could not sign with {k}: {}", text_of(&o)),
                Some("use an ssh private key without a passphrase, or one loaded in ssh-agent (pass the .pub path)"),
                1,
            ));
        }
        written.push(sig);
    }
    Ok(written)
}

/// The key's fingerprint from `ssh-keygen -l -f KEY`. The key file is never hashed here.
pub fn key_fingerprint(keyfile: &str) -> BrResult<String> {
    if !Path::new(keyfile).is_file() {
        return Err(BrError::new(format!("cannot read signing key {keyfile}"), Some("pass the path of an ssh key, e.g. --sign ~/.ssh/id_ed25519")));
    }
    let o = run_keygen(&["-l", "-f", keyfile], None)?;
    if !o.status.success() {
        return Err(BrError::new(format!("{keyfile} is not an ssh key ssh-keygen can read: {}", text_of(&o)), Some("pass the path of an ssh key, e.g. --sign ~/.ssh/id_ed25519")));
    }
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    out.split_whitespace().nth(1).filter(|f| f.starts_with("SHA256:")).map(str::to_string).ok_or_else(|| BrError::new(format!("ssh-keygen gave no fingerprint for {keyfile}"), None))
}

/// How a signature was checked.
#[derive(Debug, Clone, PartialEq)]
pub enum SigCheck {
    /// valid, and the key belongs to a principal in the allowed-signers file
    Identity {
        principal: String,
        fingerprint: String,
    },
    /// valid for the key it names; nothing says whose key that is
    KeyOnly {
        fingerprint: String,
    },
    Bad(String),
}

/// Check MANIFEST.sig against the manifest text with `ssh-keygen -Y verify` (allowed signers) or `check-novalidate`.
pub fn check_signature(sig_path: &str, manifest_text: &str, allowed: Option<&str>) -> BrResult<SigCheck> {
    let fp_of = |t: &str| -> String { t.split_whitespace().find(|w| w.starts_with("SHA256:")).unwrap_or("").to_string() };
    match allowed {
        None => {
            let o = run_keygen(&["-Y", "check-novalidate", "-n", SIG_NAMESPACE, "-s", sig_path], Some(manifest_text.as_bytes()))?;
            if o.status.success() {
                Ok(SigCheck::KeyOnly { fingerprint: fp_of(&String::from_utf8_lossy(&o.stdout)) })
            } else {
                Ok(SigCheck::Bad(text_of(&o)))
            }
        }
        Some(a) => {
            if !Path::new(a).is_file() {
                return Err(BrError::new(format!("cannot read allowed signers file {a}"), Some("pass the file you keep your team's public keys in (ssh-keygen allowed_signers format)")));
            }
            let o = run_keygen(&["-Y", "find-principals", "-f", a, "-s", sig_path], None)?;
            let principals: Vec<String> = String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
            if !o.status.success() || principals.is_empty() {
                // the key is not in the file: say which key it is
                let k = run_keygen(&["-Y", "check-novalidate", "-n", SIG_NAMESPACE, "-s", sig_path], Some(manifest_text.as_bytes()))?;
                let fp = fp_of(&String::from_utf8_lossy(&k.stdout));
                return Ok(SigCheck::Bad(if k.status.success() { format!("the signing key {fp} is not in {a}") } else { text_of(&k) }));
            }
            let mut last = String::new();
            for pr in principals {
                let o = run_keygen(&["-Y", "verify", "-f", a, "-I", &pr, "-n", SIG_NAMESPACE, "-s", sig_path], Some(manifest_text.as_bytes()))?;
                if o.status.success() {
                    return Ok(SigCheck::Identity { fingerprint: fp_of(&String::from_utf8_lossy(&o.stdout)), principal: pr });
                }
                last = text_of(&o);
            }
            Ok(SigCheck::Bad(last))
        }
    }
}

/// Every seal path `find_seal` tries for PATH, in order.
pub fn seal_candidates(path: &str) -> Vec<String> {
    let mut cands = vec![format!("{path}.sha256")];
    let p = Path::new(path);
    if p.extension().is_some() {
        let stem = p.with_extension("");
        cands.push(format!("{}.sha256", stem.display()));
        cands.push(format!("{}.json.sha256", stem.display()));
    }
    cands.dedup();
    cands
}

/// The manifest that covers `path`: PATH.sha256, STEM.sha256 or STEM.json.sha256 beside it.
pub fn find_seal(path: &str) -> Option<String> {
    seal_candidates(path).into_iter().find(|c| Path::new(c).exists())
}

pub fn read_manifest(manifest: &str) -> Result<Vec<(String, String)>, ()> {
    let text = std::fs::read_to_string(manifest).map_err(|_| ())?;
    let mut out = vec![];
    for line in text.lines() {
        let mut parts = line.trim_start().splitn(2, char::is_whitespace);
        let Some(first) = parts.next().filter(|s| !s.is_empty()) else { continue };
        let Some(rest) = parts.next() else { return Err(()) };
        if first.len() != 64 {
            return Err(());
        }
        out.push((first.to_string(), rest.trim_start().trim_start_matches('*').trim().to_string()));
    }
    if out.is_empty() {
        return Err(());
    }
    Ok(out)
}

/// (status, message): status is "sealed", "none" or "bad". The sha256 seal is integrity (the file is what was
/// sealed); only a signature says who sealed it, and only an allowed-signers file says that signer is someone you know.
pub fn check_seal(path: &str, sha: &str, allowed: Option<&str>) -> BrResult<(&'static str, String)> {
    let Some(manifest) = find_seal(path) else { return Ok(("none", String::new())) };
    let Ok(entries) = read_manifest(&manifest) else { return Ok(("bad", format!("seal file {manifest} is not readable"))) };
    let base = Path::new(path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let here = std::fs::canonicalize(&manifest).ok().and_then(|p| p.parent().map(|p| p.to_path_buf())).unwrap_or_default();
    let names: Vec<&String> = entries.iter().map(|(_, n)| n).collect();
    let man_base = Path::new(&manifest).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if !names.iter().any(|n| **n == base) {
        return Ok(("bad", format!("{base} is not listed in {man_base}")));
    }
    for (want, name) in &entries {
        let p = here.join(name);
        if !p.exists() {
            return Ok(("bad", format!("{name} is listed in the seal but missing")));
        }
        let got = if *name == base { sha.to_string() } else { sha_file(&p).unwrap_or_default() };
        if &got != want {
            return Ok(("bad", format!("sha256 mismatch for {name}")));
        }
    }
    let covers = if entries.len() == 1 { String::new() } else { format!("; covers {}", names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")) };
    let sig = format!("{manifest}.sig");
    if Path::new(&sig).exists() {
        let text = std::fs::read_to_string(&manifest).unwrap_or_default();
        let m = match check_signature(&sig, &text, allowed)? {
            SigCheck::Identity { principal, fingerprint } => format!("sealed{covers}; integrity intact, and signed by {principal} ({fingerprint}), checked against the allowed signers in {}", allowed.unwrap_or("")),
            SigCheck::KeyOnly { fingerprint } => format!("sealed{covers}; integrity intact, signature valid for key {fingerprint} but checked with check-novalidate: it proves one key signed this, not whose key it is; pass --allowed-signers FILE to check identity"),
            SigCheck::Bad(why) => return Ok(("bad", format!("signature of {man_base} does not verify: {why}"))),
        };
        Ok(("sealed", m))
    } else {
        Ok((
            "sealed",
            format!("sealed (unsigned): the sha256 seal is integrity only, it detects edits but does not say who made the file; anyone with the files can re-seal; use --sign for a signature{covers}"),
        ))
    }
}

// ---- integrity inside the file itself ------------------------------------------------------------------------------
/// Python's json.dumps for a row of SQL values (", " separators, ensure_ascii).
fn py_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn py_row(row: &[Sql]) -> String {
    let mut out = String::from("[");
    for (i, v) in row.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match v {
            Sql::Null => out.push_str("null"),
            Sql::Integer(n) => out.push_str(&n.to_string()),
            Sql::Real(f) => out.push_str(&format!("{f:?}")),
            Sql::Text(s) => py_json_str(s, &mut out),
            Sql::Blob(_) => out.push_str("null"),
        }
    }
    out.push(']');
    out
}

fn has_table(db: &Connection, name: &str) -> bool {
    db.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", [name], |_| Ok(())).is_ok()
}

pub fn content_digest(db: &Connection) -> rusqlite::Result<String> {
    let mut h = Sha256::new();
    // files and packages as before; the tables a newer export adds are covered when the file has them (old files do not)
    for t in ["files", "packages", "yara_hits", "declared", "trust"] {
        if !matches!(t, "files" | "packages") && !has_table(db, t) {
            continue;
        }
        let order = match t {
            "yara_hits" => "1, 2, 3, 4",
            "declared" => "1, 2, 3, 4, 5, 6",
            "trust" => "1, 2, 7",
            _ => "1, 2",
        };
        let mut st = db.prepare(&format!("SELECT * FROM {t} ORDER BY {order}"))?;
        let n = st.column_count();
        let rows = st.query_map([], |r| (0..n).map(|i| r.get::<_, Sql>(i)).collect::<Result<Vec<_>, _>>())?;
        for r in rows {
            h.update(py_row(&r?).as_bytes());
        }
    }
    Ok(hex::encode(h.finalize()))
}

/// (ok, message) for the manifest a file carries inside itself.
pub fn check_internal(path: &str) -> (bool, String) {
    if path.ends_with(".brx") {
        let r = (|| -> rusqlite::Result<bool> {
            let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let want: Option<String> = db.query_row("SELECT v FROM manifest WHERE k='digest'", [], |r| r.get(0)).ok();
            Ok(Some(content_digest(&db)?) == want)
        })();
        return match r {
            Ok(true) => (true, "internal manifest intact".into()),
            Ok(false) => (false, "internal manifest mismatch".into()),
            Err(_) => (false, "not a readable scan file".into()),
        };
    }
    if path.ends_with(".json") {
        let doc: Option<serde_json::Value> = std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok());
        let want = doc.as_ref().and_then(|d| d["integrity"]["digest"].as_str().map(str::to_string));
        return match (doc, want) {
            (Some(d), Some(w)) => {
                let ok = json_digest(&d) == w;
                (ok, if ok { "internal manifest intact" } else { "internal manifest mismatch" }.into())
            }
            _ => (false, "no internal manifest in this file".into()),
        };
    }
    if path.ends_with(".md") {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let Some(i) = text.rfind(MD_TRAILER) else { return (false, "no internal manifest in this file".into()) };
        let want = text[i + MD_TRAILER.len()..].split_whitespace().next().unwrap_or("").to_string();
        // a file that crossed a Windows machine or a git autocrlf checkout has CRLF line ends
        let ok = sha_str(&text[..i]) == want || sha_str(&text[..i].replace("\r\n", "\n")) == want;
        return (ok, if ok { "internal manifest intact" } else { "internal manifest mismatch" }.into());
    }
    (false, "no internal manifest in this file".into())
}

/// sha256 of json.dumps(doc without "integrity", sort_keys=True) as Python prints it.
pub fn json_digest(doc: &serde_json::Value) -> String {
    let mut d = doc.clone();
    if let Some(o) = d.as_object_mut() {
        o.remove("integrity");
    }
    sha_str(&crate::collect::util::py_dumps(&d, None, true))
}

/// (status, message, sha): status is "ok" (sealed), "internal" (--no-seal), "fail" or "unverified".
pub fn verify(path: &str, no_seal: bool) -> BrResult<(&'static str, String, String)> {
    verify_with(path, no_seal, None)
}

/// Like `verify`, with an allowed-signers file to check who signed (otherwise the key alone is checked, and the message says so).
pub fn verify_with(path: &str, no_seal: bool, allowed_signers: Option<&str>) -> BrResult<(&'static str, String, String)> {
    if !Path::new(path).is_file() {
        return Err(BrError::with_code(format!("{path}: no such file"), Some("check the path"), 1));
    }
    let sha = sha_file(Path::new(path)).map_err(|e| io_err(e, path))?;
    let (status, msg) = check_seal(path, &sha, allowed_signers)?;
    if status == "bad" {
        return Ok(("fail", msg, sha));
    }
    if status == "sealed" {
        let (ok, imsg) = if path.ends_with(".brx") || path.ends_with(".json") || path.ends_with(".md") { check_internal(path) } else { (true, String::new()) };
        if !ok && (imsg == "internal manifest mismatch" || imsg == "not a readable scan file") {
            return Ok(("fail", imsg, sha));
        }
        return Ok(("ok", msg, sha));
    }
    if !no_seal {
        return Ok(("unverified", format!("no seal file; looked for {}", seal_candidates(path).join(", ")), sha));
    }
    let (ok, imsg) = check_internal(path);
    if !ok {
        return Ok(("fail", imsg, sha));
    }
    Ok(("internal", "NOT sealed, so this does not prove it is the file that was issued".into(), sha))
}

/// For import: (ok, message, sha). An unsealed file passes on its internal manifest alone.
pub fn check(path: &str) -> BrResult<(bool, String, String)> {
    let (status, msg, sha) = verify(path, true)?;
    let ok = status == "ok" || status == "internal";
    Ok((ok, if status == "ok" { msg } else { format!("not sealed; {msg}") }, sha))
}

// ---- export and load ------------------------------------------------------------------------------------------------
pub struct ScanInfo {
    pub host: String,
    pub roots: Vec<String>,
    /// The scanning user's home directory, so a narrow root can be told from the home on import
    pub home: Option<String>,
    pub items: Vec<HostItem>,
    pub stage1: u64,
    pub hashed: usize,
    pub simhashed: usize,
    pub secs: u64,
    pub os: Option<String>,
    /// runner when the machine shows it; None otherwise
    pub kind: Option<String>,
    pub gaps: Vec<(String, String)>,
    pub rules_sha256: Option<String>,
    /// What the rules matched (rule, path, sha256), and how many rules ran (None: YARA was not run)
    pub yara_hits: Vec<crate::collect::local::YaraHit>,
    pub yara_rules: Option<usize>,
    /// What the lockfiles under the roots declare
    pub declared: Vec<crate::view::DeclaredLock>,
    /// The trust stores the scan read
    pub trust: crate::view::TrustSet,
}

pub fn export(ctx: &Ctx, info: &ScanInfo, path: &str, case: Option<&str>, requested_by: Option<&str>) -> BrResult<String> {
    if Path::new(path).is_dir() {
        return Err(BrError::new(format!("{path} is a directory"), Some("give a file name, e.g. --export laptop.brx")));
    }
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    let sql = |e: rusqlite::Error| BrError::with_code(format!("not a readable scan file ({e})"), Some("ask for a fresh export"), 1);
    let db = Connection::open(path).map_err(sql)?;
    db.execute_batch(
        "CREATE TABLE manifest(k TEXT, v TEXT);
         CREATE TABLE files(path TEXT, size INT, mtime TEXT, sha256 TEXT, simhash TEXT, item_kind TEXT, loc TEXT, at TEXT, yara TEXT);
         CREATE TABLE packages(p TEXT, loc TEXT, item_kind TEXT, at TEXT);
         CREATE TABLE custody(event TEXT, at TEXT, by TEXT, case_id TEXT, file_sha256 TEXT, requested_by TEXT);
         CREATE TABLE yara_hits(rule TEXT, path TEXT, sha256 TEXT, rules_sha256 TEXT, at TEXT);
         CREATE TABLE declared(loc TEXT, p TEXT, direct INT, dev INT, via TEXT, lock_line INT, as_written TEXT);
         CREATE TABLE trust(path TEXT, fp TEXT, subject TEXT, issuer TEXT, not_after TEXT, root INT, gap TEXT);",
    )
    .map_err(sql)?;
    let mut seen = std::collections::HashSet::new();
    for it in &info.items {
        for f in &it.files {
            db.execute(
                "INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?)",
                params![
                    f.path,
                    f.size.map(|s| s as i64),
                    f.mtime,
                    if f.sha256.is_empty() { None } else { Some(&f.sha256) },
                    f.simhash,
                    it.kind,
                    it.loc,
                    it.at,
                    serde_json::to_string(&f.yara_hits).map(|s| s.replace("\",\"", "\", \"")).unwrap_or_default()
                ],
            )
            .map_err(sql)?;
        }
        for p in &it.pkgs {
            if seen.insert((p.clone(), it.loc.clone())) {
                db.execute("INSERT INTO packages VALUES(?,?,?,?)", params![p, it.loc, it.kind, it.at]).map_err(sql)?;
            }
        }
    }
    for h in &info.yara_hits {
        db.execute("INSERT INTO yara_hits VALUES(?,?,?,?,?)", params![h.rule, h.path, h.sha256, info.rules_sha256, ctx.now]).map_err(sql)?;
    }
    for d in &info.declared {
        for p in &d.packages {
            db.execute(
                "INSERT INTO declared VALUES(?,?,?,?,?,?,?)",
                params![d.loc, p.p, p.direct as i64, p.dev as i64, serde_json::to_string(&p.via).unwrap_or_default(), p.lock_line.map(|l| l as i64), p.as_written],
            )
            .map_err(sql)?;
        }
    }
    // One row per certificate, one per line about what could not be read (a file's own, or the place's with no path)
    for f in &info.trust.files {
        for c in &f.certs {
            db.execute("INSERT INTO trust VALUES(?,?,?,?,?,?,NULL)", params![f.path, c.fp, c.subject, c.issuer, c.not_after, c.root as i64]).map_err(sql)?;
        }
        for g in &f.gaps {
            db.execute("INSERT INTO trust VALUES(?,NULL,NULL,NULL,NULL,NULL,?)", params![f.path, g]).map_err(sql)?;
        }
    }
    for n in &info.trust.notes {
        db.execute("INSERT INTO trust VALUES(NULL,NULL,NULL,NULL,NULL,NULL,?)", params![n]).map_err(sql)?;
    }
    let digest = content_digest(&db).map_err(sql)?;
    let roots = crate::collect::util::py_dumps(&serde_json::json!(info.roots), None, false);
    let empty = crate::collect::fs::read_nothing(info.hashed, &info.items);
    let m: Vec<(&str, String)> = vec![
        ("host", info.host.clone()),
        ("scanned_at", ctx.now.clone()),
        ("roots", roots),
        ("home", info.home.clone().unwrap_or_default()),
        ("stage1", info.stage1.to_string()),
        ("hashed", info.hashed.to_string()),
        ("simhashed", info.simhashed.to_string()),
        ("digest", digest),
        ("case_id", case.unwrap_or("").to_string()),
        ("empty", if empty { "1" } else { "0" }.to_string()),
        ("format", "brx/1".to_string()),
        ("os", info.os.clone().unwrap_or_default()),
        ("kind", info.kind.clone().unwrap_or_default()),
        ("rules_sha256", info.rules_sha256.clone().unwrap_or_default()),
        // How many rules ran ("" when YARA was not run), so an empty yara_hits table is told from a scan without rules
        ("yara_rules", info.yara_rules.map(|n| n.to_string()).unwrap_or_default()),
        ("gaps", serde_json::to_string(&info.gaps).unwrap_or_default()),
    ];
    for (k, v) in m {
        db.execute("INSERT INTO manifest VALUES(?,?)", params![k, v]).map_err(sql)?;
    }
    let req = requested_by.map(str::to_string).or_else(|| requested_by_default(ctx));
    for ev in ["scanned", "exported"] {
        db.execute("INSERT INTO custody VALUES(?,?,?,?,NULL,?)", params![ev, ctx.now, who(ctx), case, req]).map_err(sql)?;
    }
    Ok(path.to_string())
}

/// What merging a second scan of a host into the one already indexed did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Merged {
    pub items: Vec<HostItem>,
    /// files at paths the index did not have
    pub added: usize,
    /// files at paths it had, where the newer scan's record replaced the older one
    pub replaced: usize,
    /// files at paths it had, where the file imported was the older scan and the indexed record stayed
    pub kept: usize,
    /// files in the merged result
    pub total: usize,
}

/// Merge the items of a host already in the index (`old`, scanned at `old_at`) with those of an imported scan (`new`,
/// scanned at `new_at`). Files are keyed by path and the newer scan wins per path; a path only one scan saw is kept. A package
/// list at a place (kind and location) comes from the newer scan, and a place only one scan saw is kept. Times are ISO strings.
pub fn merge_items(old: &[HostItem], old_at: &str, new: &[HostItem], new_at: &str) -> Merged {
    use std::collections::BTreeMap;
    let new_wins = new_at >= old_at;
    let (loser, winner) = if new_wins { (old, new) } else { (new, old) };
    let mut places: BTreeMap<(String, String), HostItem> = BTreeMap::new();
    for it in loser {
        places.insert((it.kind.clone(), it.loc.clone()), it.clone());
    }
    for it in winner {
        match places.get_mut(&(it.kind.clone(), it.loc.clone())) {
            Some(e) => {
                e.at = it.at.clone();
                e.pkgs = it.pkgs.clone();
                e.hidden = it.hidden;
                for f in &it.files {
                    match e.files.iter_mut().find(|x| x.path == f.path) {
                        Some(x) => *x = f.clone(),
                        None => e.files.push(f.clone()),
                    }
                }
            }
            None => {
                places.insert((it.kind.clone(), it.loc.clone()), it.clone());
            }
        }
    }
    let paths = |items: &[HostItem]| -> BTreeMap<String, HostFile> { items.iter().flat_map(|i| i.files.iter()).map(|f| (f.path.clone(), f.clone())).collect() };
    let (po, pn) = (paths(old), paths(new));
    let mut m = Merged::default();
    for (p, f) in &pn {
        match po.get(p) {
            None => m.added += 1,
            Some(o) if o == f => {}
            Some(_) if new_wins => m.replaced += 1,
            Some(_) => m.kept += 1,
        }
    }
    let mut items: Vec<HostItem> = places.into_values().collect();
    for it in items.iter_mut() {
        it.files.sort_by(|a, b| a.path.cmp(&b.path));
    }
    m.total = items.iter().map(|i| i.files.len()).sum();
    m.items = items;
    m
}

pub struct Loaded {
    /// The rules' matches this scan file carries (the yara_hits table; an older file's per-file column when it has no table)
    pub yara_hits: Vec<crate::collect::local::YaraHit>,
    /// What the lockfiles in the scan declare
    pub declared: Vec<crate::view::DeclaredLock>,
    /// The trust stores this scan file carries (none for a file written before they were read)
    pub trust: crate::view::TrustSet,
    pub manifest: std::collections::BTreeMap<String, String>,
    pub items: Vec<HostItem>,
    pub n_pkgs: usize,
    pub custody: Vec<(String, String, Option<String>, Option<String>, Option<String>, Option<String>)>,
}

pub fn load(path: &str) -> BrResult<Loaded> {
    let sql = |e: rusqlite::Error| BrError::with_code(format!("not a readable scan file ({e})"), Some("ask for a fresh export"), 1);
    let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(sql)?;
    let mut manifest = std::collections::BTreeMap::new();
    {
        let mut st = db.prepare("SELECT k, v FROM manifest").map_err(sql)?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default()))).map_err(sql)? {
            let (k, v) = r.map_err(sql)?;
            manifest.insert(k, v);
        }
    }
    let mut groups: std::collections::BTreeMap<(String, String, String), HostItem> = Default::default();
    {
        let mut st = db.prepare("SELECT path,size,mtime,sha256,simhash,item_kind,loc,at,yara FROM files").map_err(sql)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            })
            .map_err(sql)?;
        for r in rows {
            let (p, size, mtime, sha, sim, kind, loc, at, yara) = r.map_err(sql)?;
            let it = groups.entry((at.clone(), kind.clone(), loc.clone())).or_insert_with(|| HostItem { at, kind, loc, ..Default::default() });
            if let Some(sha) = sha {
                it.files.push(HostFile { path: p, sha256: sha, size: size.map(|s| s as u64), mtime, simhash: sim, yara_hits: yara.and_then(|y| serde_json::from_str(&y).ok()).unwrap_or_default() });
            }
        }
    }
    let mut n_pkgs = 0;
    {
        let mut st = db.prepare("SELECT p,loc,item_kind,at FROM packages").map_err(sql)?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))).map_err(sql)? {
            let (p, loc, kind, at) = r.map_err(sql)?;
            n_pkgs += 1;
            let it = groups.entry((at.clone(), kind.clone(), loc.clone())).or_insert_with(|| HostItem { at, kind, loc, ..Default::default() });
            if !it.pkgs.contains(&p) {
                it.pkgs.push(p);
            }
        }
    }
    let mut custody = vec![];
    {
        let mut st = db.prepare("SELECT event,at,by,case_id,file_sha256,requested_by FROM custody").map_err(sql)?;
        for r in st
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, Option<String>>(4)?, r.get::<_, Option<String>>(5)?))
            })
            .map_err(sql)?
        {
            custody.push(r.map_err(sql)?);
        }
    }
    // The rules' matches. Files written before the table existed carry the rule names in the files table's `yara` column.
    let mut yara_hits: Vec<crate::collect::local::YaraHit> = vec![];
    if has_table(&db, "yara_hits") {
        let mut st = db.prepare("SELECT rule,path,sha256 FROM yara_hits ORDER BY path, rule").map_err(sql)?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?.unwrap_or_default()))).map_err(sql)? {
            let (rule, path, sha256) = r.map_err(sql)?;
            yara_hits.push(crate::collect::local::YaraHit { rule, path, sha256 });
        }
    } else {
        for it in groups.values() {
            for f in &it.files {
                for rule in &f.yara_hits {
                    yara_hits.push(crate::collect::local::YaraHit { rule: rule.clone(), path: f.path.clone(), sha256: f.sha256.clone() });
                }
            }
        }
        yara_hits.sort_by(|a, b| (&a.path, &a.rule).cmp(&(&b.path, &b.rule)));
    }
    let mut declared: Vec<crate::view::DeclaredLock> = vec![];
    if has_table(&db, "declared") {
        let mut st = db.prepare("SELECT loc,p,direct,dev,via,lock_line,as_written FROM declared ORDER BY rowid").map_err(sql)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? != 0,
                    r.get::<_, i64>(3)? != 0,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(sql)?;
        for r in rows {
            let (loc, p, direct, dev, via, line, aw) = r.map_err(sql)?;
            let lp = crate::view::LockPackage { p, direct, dev, via: via.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default(), lock_line: line.map(|l| l as u32), as_written: aw };
            match declared.iter_mut().find(|d| d.loc == loc) {
                Some(d) => d.packages.push(lp),
                None => declared.push(crate::view::DeclaredLock { loc, packages: vec![lp] }),
            }
        }
    }
    let mut trust = crate::view::TrustSet::default();
    if has_table(&db, "trust") {
        trust.read = true;
        let mut st = db.prepare("SELECT path,fp,subject,issuer,not_after,root,gap FROM trust ORDER BY rowid").map_err(sql)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(sql)?;
        for r in rows {
            let (path, fp, subject, issuer, not_after, root, gap) = r.map_err(sql)?;
            let Some(path) = path else {
                if let Some(g) = gap {
                    trust.notes.push(g);
                }
                continue;
            };
            if !trust.files.iter().any(|f| f.path == path) {
                trust.files.push(crate::view::TrustFile { path: path.clone(), ..Default::default() });
            }
            let f = trust.files.iter_mut().find(|f| f.path == path).unwrap();
            match (fp, gap) {
                (Some(fp), _) => f.certs.push(crate::view::CertRec { fp, subject: subject.unwrap_or_default(), issuer: issuer.unwrap_or_default(), not_after, root: root.unwrap_or(0) != 0 }),
                (None, Some(g)) => f.gaps.push(g),
                _ => {}
            }
        }
    }
    let mut items: Vec<HostItem> = groups.into_values().collect();
    for it in &mut items {
        it.pkgs.sort();
    }
    Ok(Loaded { yara_hits, declared, trust, manifest, items, n_pkgs, custody })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn have_keygen() -> bool {
        std::process::Command::new("ssh-keygen").arg("-?").stderr(std::process::Stdio::null()).stdout(std::process::Stdio::null()).status().is_ok()
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("br-brx-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn real_ssh_signature_verifies_and_detects_tampering() {
        if !have_keygen() {
            return;
        }
        let d = scratch("sig");
        let key = d.join("id");
        let st = std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "dana@example.com", "-f"]).arg(&key).status().unwrap();
        assert!(st.success());
        let file = d.join("ev.json");
        std::fs::write(&file, "{\"a\":1}").unwrap();
        let f = file.to_str().unwrap().to_string();
        let w = write_seal(&f, std::slice::from_ref(&f), Some(key.to_str().unwrap())).unwrap();
        assert_eq!(w.len(), 2);
        let sig = std::fs::read_to_string(&w[1]).unwrap();
        assert!(sig.starts_with(SIG_BEGIN), "an ssh-keygen armored signature, not a homemade one");
        // no allowed signers: the key is checked, identity is not, and the message says so
        let (st, msg, _) = verify_with(&f, false, None).unwrap();
        assert_eq!(st, "ok", "{msg}");
        assert!(msg.contains("check-novalidate") && msg.contains("not whose key"), "{msg}");
        let fp = key_fingerprint(key.to_str().unwrap()).unwrap();
        assert!(msg.contains(&fp), "{msg} vs {fp}");
        // with allowed signers: identity
        let pubkey = std::fs::read_to_string(d.join("id.pub")).unwrap();
        let allowed = d.join("allowed");
        std::fs::write(&allowed, format!("dana@example.com {pubkey}")).unwrap();
        let (st, msg, _) = verify_with(&f, false, allowed.to_str()).unwrap();
        assert_eq!(st, "ok", "{msg}");
        assert!(msg.contains("signed by dana@example.com"), "{msg}");
        // a different signer file: the key is not allowed
        let other = d.join("other");
        let st2 = std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&other).status().unwrap();
        assert!(st2.success());
        std::fs::write(d.join("allowed2"), format!("eve@example.com {}", std::fs::read_to_string(d.join("other.pub")).unwrap())).unwrap();
        let (st, msg, _) = verify_with(&f, false, d.join("allowed2").to_str()).unwrap();
        assert_eq!(st, "fail", "{msg}");
        // edit the file: the seal fails
        std::fs::write(&file, "{\"a\":2}").unwrap();
        assert_eq!(verify_with(&f, false, None).unwrap().0, "fail");
        // edit the seal and keep the file: the signature fails
        std::fs::write(&file, "{\"a\":1}").unwrap();
        let man = format!("{f}.sha256");
        let t = std::fs::read_to_string(&man).unwrap();
        std::fs::write(&man, format!("{t}{}  ev.json\n", "0".repeat(64))).unwrap();
        assert_eq!(verify_with(&f, false, None).unwrap().0, "fail");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unsigned_seal_says_it_is_integrity_not_identity() {
        let d = scratch("unsigned");
        let file = d.join("x.md");
        std::fs::write(&file, "hello").unwrap();
        let f = file.to_str().unwrap().to_string();
        write_seal(&f, std::slice::from_ref(&f), None).unwrap();
        let (st, msg, _) = verify(&f, false).unwrap();
        assert_eq!(st, "ok");
        assert!(msg.contains("integrity only") && msg.contains("who made"), "{msg}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn seal_beside_the_stem_is_found_and_all_candidates_are_listed() {
        let d = scratch("stem");
        let file = d.join("case.md");
        std::fs::write(&file, "hello").unwrap();
        let f = file.to_str().unwrap().to_string();
        let c = seal_candidates(&f);
        assert_eq!(c.len(), 3);
        assert!(c[1].ends_with("case.sha256") && c[2].ends_with("case.json.sha256"));
        std::fs::write(&c[1], format!("{}  case.md\n", sha_file(&file).unwrap())).unwrap();
        assert_eq!(verify(&f, false).unwrap().0, "ok");
        // and a missing seal names every place it looked
        std::fs::remove_file(&c[1]).unwrap();
        let (st, msg, _) = verify(&f, false).unwrap();
        assert_eq!(st, "unverified");
        assert!(msg.contains("case.sha256") && msg.contains("case.json.sha256"), "{msg}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_keygen_is_an_error_with_a_hint() {
        let e = std::process::Command::new("/nonexistent-br-keygen").spawn().unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        assert!(no_keygen().hint.unwrap_or_default().contains("OpenSSH"));
    }

    fn file(path: &str, sha: &str) -> HostFile {
        HostFile { path: path.into(), sha256: sha.into(), ..Default::default() }
    }

    fn item(loc: &str, at: &str, files: Vec<HostFile>, pkgs: &[&str]) -> HostItem {
        HostItem { at: at.into(), kind: "loose-file".into(), loc: loc.into(), pkgs: pkgs.iter().map(|p| p.to_string()).collect(), files, hidden: false }
    }

    // A second scan of a host adds its new paths, the newer scan wins per path, and nothing is silently dropped
    #[test]
    fn a_second_scan_merges_by_path_and_the_newer_scan_wins() {
        let old = vec![item("/a", "2026-05-01T00:00:00Z", vec![file("/a/1.js", "aa"), file("/a/2.js", "bb")], &["npm:x@1.0.0"])];
        let new = vec![item("/a", "2026-05-02T00:00:00Z", vec![file("/a/2.js", "cc"), file("/a/3.js", "dd")], &["npm:x@1.0.1"]), item("/b", "2026-05-02T00:00:00Z", vec![file("/b/9.js", "ee")], &[])];
        let m = merge_items(&old, "2026-05-01T00:00:00Z", &new, "2026-05-02T00:00:00Z");
        assert_eq!((m.added, m.replaced, m.kept, m.total), (2, 1, 0, 4));
        let a = m.items.iter().find(|i| i.loc == "/a").unwrap();
        assert_eq!(a.files.iter().map(|f| (f.path.as_str(), f.sha256.as_str())).collect::<Vec<_>>(), vec![("/a/1.js", "aa"), ("/a/2.js", "cc"), ("/a/3.js", "dd")]);
        assert_eq!(a.pkgs, vec!["npm:x@1.0.1"]);
        // the other way round: the file imported is the older scan, so the indexed record stays at a shared path
        let m = merge_items(&new, "2026-05-02T00:00:00Z", &old, "2026-05-01T00:00:00Z");
        assert_eq!((m.added, m.replaced, m.kept), (1, 0, 1));
        let a = m.items.iter().find(|i| i.loc == "/a").unwrap();
        assert_eq!(a.files.iter().find(|f| f.path == "/a/2.js").unwrap().sha256, "cc");
        assert_eq!(a.pkgs, vec!["npm:x@1.0.1"]);
        // the same file twice changes nothing
        let m = merge_items(&old, "2026-05-01T00:00:00Z", &old, "2026-05-01T00:00:00Z");
        assert_eq!((m.added, m.replaced, m.kept, m.total), (0, 0, 0, 2));
    }

    #[test]
    fn crlf_markdown_trailer_still_verifies() {
        let d = scratch("crlf");
        let body = "# Evidence\nline\n";
        let file = d.join("e.md");
        std::fs::write(&file, format!("{body}{MD_TRAILER}{} -->\n", sha_str(body))).unwrap();
        assert!(check_internal(file.to_str().unwrap()).0);
        std::fs::write(&file, format!("{body}{MD_TRAILER}{} -->\n", sha_str(body)).replace('\n', "\r\n")).unwrap();
        assert!(check_internal(file.to_str().unwrap()).0);
        let _ = std::fs::remove_dir_all(&d);
    }
}
