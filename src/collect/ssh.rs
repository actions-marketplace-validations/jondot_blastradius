//! Agentless host scan over ssh (BR_SSH): a POSIX sh script lists files, a second call streams the ones that need reading.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

use crate::collect::fs::{Analyzer, FileMeta};
use crate::error::{BrError, BrResult};
use crate::view::HostItem;

pub struct HostScan {
    pub items: Vec<HostItem>,
    pub stage1: u64,
    pub hashed: usize,
    pub simhashed: usize,
    pub os: Option<String>,
    /// `runner` when the machine shows an actions-runner or gitlab-runner install; None when it shows nothing
    pub kind: Option<String>,
    /// What could not be read: (scope, reason). A host with gaps is never reported clear.
    pub gaps: Vec<(String, String)>,
    /// What the lockfiles under the roots declare
    pub declared: Vec<crate::view::DeclaredLock>,
    /// The trust stores read under the roots
    pub trust: crate::view::TrustSet,
    /// The remote user's `$HOME` as the machine reports it (None when it did not say)
    pub home: Option<String>,
}

fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn command(target: &str, script: &str) -> Command {
    let cmd = std::env::var("BR_SSH").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "ssh".into());
    let mut parts = cmd.split_whitespace();
    let prog = parts.next().unwrap_or("ssh");
    let mut c = Command::new(prog);
    c.args(parts);
    if prog == "ssh" || cmd.ends_with("ssh") {
        c.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30"]);
    }
    c.arg(target).arg(script);
    c
}

/// Run SCRIPT and return (stdout, stderr, exit ok). Only a failure to run at all is an error.
fn run(target: &str, script: &str, stdin: Option<&[u8]>) -> BrResult<(Vec<u8>, String, bool)> {
    let mut c = command(target, script);
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().map_err(|e| unreachable_host(target, &e.to_string()))?;
    if let Some(data) = stdin {
        if let Some(mut si) = ch.stdin.take() {
            let d = data.to_vec();
            std::thread::spawn(move || {
                let _ = si.write_all(&d);
            });
        }
    }
    let out = ch.wait_with_output().map_err(|e| unreachable_host(target, &e.to_string()))?;
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() && out.stdout.is_empty() {
        return Err(unreachable_host(target, &err));
    }
    Ok((out.stdout, err, out.status.success()))
}

/// Run SCRIPT and hand its stdout to `f` as a stream; returns (stderr, exit ok).
fn run_stream(target: &str, script: &str, stdin: &[u8], f: impl FnOnce(&mut dyn Read)) -> BrResult<(String, bool)> {
    let mut c = command(target, script);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().map_err(|e| unreachable_host(target, &e.to_string()))?;
    if let Some(mut si) = ch.stdin.take() {
        let d = stdin.to_vec();
        std::thread::spawn(move || {
            let _ = si.write_all(&d);
        });
    }
    let mut so = ch.stdout.take().ok_or_else(|| unreachable_host(target, "no output"))?;
    let mut se = ch.stderr.take();
    let err_t = std::thread::spawn(move || {
        let mut b = String::new();
        if let Some(e) = se.as_mut() {
            let _ = e.read_to_string(&mut b);
        }
        b
    });
    f(&mut so);
    // drain what the consumer left so the remote side can finish
    let _ = std::io::copy(&mut so, &mut std::io::sink());
    let st = ch.wait().map_err(|e| unreachable_host(target, &e.to_string()))?;
    Ok((err_t.join().unwrap_or_default().trim().to_string(), st.success()))
}

fn unreachable_host(target: &str, why: &str) -> BrError {
    BrError::with_code(
        format!("cannot reach {target} over ssh ({})", if why.is_empty() { "no reply" } else { why }),
        Some("check that ssh works from here, or import a scan: br scan --local --export FILE there, br import FILE here"),
        3,
    )
}

/// The remote listing: `F size mtime path` per file, `E message` per directory find could not read, `K kind` for what
/// the machine shows about itself, `OS name`, and a closing `END` so a cut connection is told from a finished listing.
fn list_script(roots: &[String]) -> String {
    let rl: Vec<String> = roots.iter().map(|r| q(r)).collect();
    format!(
        "R=\"${{BR_REMOTE_ROOT:-}}\"; for d in {}; do \
         if [ \"$d\" = / ]; then find \"$R/\" -xdev \\( -path \"$R/proc\" -o -path \"$R/sys\" -o -path \"$R/dev\" -o -path \"$R/run\" -o -path \"$R/snap\" -o -path \"$R/mnt\" -o -path \"$R/media\" \\) -prune -o -type f -print 2>&1; else find \"$R$d\" -xdev -type f -print 2>&1; fi \
         | while IFS= read -r f; do case \"$f\" in find:*) printf 'E %s\\n' \"$f\";; *) s=$(stat -c '%s %Y' \"$f\" 2>/dev/null || stat -f '%z %m' \"$f\" 2>/dev/null) || {{ printf 'E %s: cannot stat\\n' \"$f\"; continue; }}; printf 'F %s %s\\n' \"$s\" \"${{f#$R}}\";; esac; done; done; \
         for p in \"$R\"/home/runner/_work \"$R\"/opt/actions-runner/.runner \"$R\"/actions-runner/.runner \"$R\"/home/*/actions-runner/.runner \"$R\"/Users/*/actions-runner/.runner \"$R\"/home/*/_work/_PipelineMapping; do [ -e \"$p\" ] && {{ echo 'K runner'; break; }}; done; \
         [ -f \"$R/etc/gitlab-runner/config.toml\" ] && echo 'K runner'; \
         command -v systemctl >/dev/null 2>&1 && [ -z \"$R\" ] && systemctl show -p Environment 'actions.runner.*' 2>/dev/null | grep -q 'RUNNER_' && echo 'K runner'; \
         if [ -f \"$R/etc/os-release\" ]; then echo \"OS linux\"; elif [ -f \"$R/System/Library/CoreServices/SystemVersion.plist\" ]; then echo \"OS macos\"; else echo \"OS $(uname -s)\"; fi; printf 'H %s\\n' \"$HOME\"; echo END",
        rl.join(" ")
    )
}

pub fn scan(target: &str, roots: &[String], globs: &[String], now: &str) -> BrResult<HostScan> {
    let roots: Vec<String> = if roots.is_empty() { vec!["/".to_string()] } else { roots.to_vec() };
    let (out, serr, _ok) = run(target, &list_script(&roots), None)?;
    let text = String::from_utf8_lossy(&out).to_string();
    let mut metas: Vec<FileMeta> = vec![];
    let mut os = None;
    let mut kind = None;
    let mut home: Option<String> = None;
    let mut gaps: Vec<(String, String)> = vec![];
    let mut finished = false;
    let mut denied = 0usize;
    let mut first_denied = String::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        if line == "END" {
            finished = true;
        } else if let Some(o) = line.strip_prefix("OS ") {
            os = Some(match o.trim().to_lowercase().as_str() {
                "darwin" => "macos".to_string(),
                x => x.to_string(),
            });
        } else if let Some(h) = line.strip_prefix("H ") {
            home = Some(h.trim().to_string()).filter(|h| h.starts_with('/'));
        } else if line.starts_with("K ") {
            kind = Some("runner".to_string());
        } else if let Some(e) = line.strip_prefix("E ") {
            denied += 1;
            if first_denied.is_empty() {
                first_denied = e.to_string();
            }
        } else if let Some(rest) = line.strip_prefix("F ") {
            let mut it = rest.splitn(3, ' ');
            let (Some(sz), Some(mt), Some(p)) = (it.next(), it.next(), it.next()) else { continue };
            let (Ok(size), Ok(mtime)) = (sz.parse::<u64>(), mt.parse::<i64>()) else { continue };
            let mut p = p.to_string();
            while p.contains("//") {
                p = p.replace("//", "/");
            }
            if seen.insert(p.clone()) {
                metas.push(FileMeta { path: p, size, mtime });
            }
        }
    }
    if !finished {
        gaps.push(("file listing".into(), format!("the listing ended early, so files after that point were not seen{}", if serr.is_empty() { String::new() } else { format!(" ({serr})") })));
    }
    if denied > 0 {
        gaps.push(("unreadable directories".into(), format!("{denied} path(s) could not be read, e.g. {first_denied}; run the scan as a user that can read them")));
    }
    let mut an = Analyzer::new(globs, Some(now));
    {
        let mut by_dir: HashMap<&str, Vec<&str>> = HashMap::new();
        for m in &metas {
            if let Some((d, b)) = m.path.rsplit_once('/') {
                by_dir.entry(d).or_default().push(b);
            }
        }
        for (d, names) in by_dir {
            an.note_dir(d, names);
        }
    }
    let need: Vec<usize> = (0..metas.len()).filter(|i| !an.future(metas[*i].mtime) && an.needs_content(&metas[*i])).collect();
    let by_path: HashMap<String, usize> = metas.iter().enumerate().map(|(i, m)| (m.path.clone(), i)).collect();
    let mut got = vec![false; metas.len()];
    // files are streamed out of tar one at a time and handed to the analyzer; nothing is held whole
    let mut stream_err = None;
    if !need.is_empty() {
        let list_in: String = need.iter().map(|i| format!("{}\n", metas[*i].path.trim_start_matches('/'))).collect();
        let fetch = "R=\"${BR_REMOTE_ROOT:-}\"; cd \"${R:-/}\" && tar -cf - -T -";
        let (err, ok) = run_stream(target, fetch, list_in.as_bytes(), |rd| {
            let mut ar = tar::Archive::new(rd);
            let ents = match ar.entries() {
                Ok(e) => e,
                Err(e) => {
                    stream_err = Some(e.to_string());
                    return;
                }
            };
            for e in ents {
                let mut e = match e {
                    Ok(e) => e,
                    Err(er) => {
                        stream_err = Some(er.to_string());
                        break;
                    }
                };
                if !e.header().entry_type().is_file() {
                    continue;
                }
                let Ok(p) = e.path() else { continue };
                let path = format!("/{}", p.to_string_lossy().trim_start_matches("./").trim_start_matches('/'));
                let Some(i) = by_path.get(&path).copied() else { continue };
                got[i] = true;
                an.add(metas[i].clone(), Some(&mut e));
            }
        })?;
        if let Some(e) = stream_err {
            gaps.push(("file contents".into(), format!("the transfer of file contents broke off ({e}); files after that point were not hashed")));
        } else if !ok && !err.is_empty() {
            gaps.push(("file contents".into(), format!("tar on the host reported: {}", err.lines().next().unwrap_or(""))));
        }
    }
    let missing = need.iter().filter(|i| !got[**i]).count();
    if missing > 0 {
        let e = need.iter().find(|i| !got[**i]).map(|i| metas[*i].path.clone()).unwrap_or_default();
        gaps.push(("unhashed files".into(), format!("{missing} file(s) selected for hashing were not returned by the host (unreadable or removed during the scan), e.g. {e}")));
    }
    for (i, m) in metas.iter().enumerate() {
        if !need.contains(&i) || false {
            an.add(m.clone(), None);
        }
    }
    for (p, why) in &an.skipped {
        let _ = (p, why);
    }
    if !an.skipped.is_empty() {
        gaps.push(("skipped files".into(), format!("{} file(s) could not be read in full, e.g. {} ({})", an.skipped.len(), an.skipped[0].0, an.skipped[0].1)));
    }
    gaps.extend(an.lock_gaps());
    let trust = {
        let (files, notes) = an.trust_stores();
        crate::view::TrustSet { files, notes, api_calls: 0, read: true }
    };
    Ok(HostScan { home, items: an.items(), declared: an.declared(), trust, stage1: an.stage1, hashed: an.hashed(), simhashed: an.simhashed(), os, kind, gaps })
}

/// Read the content of the given absolute paths on a host (BR_REMOTE_ROOT honoured), for the YARA pass. Missing files are skipped.
pub fn fetch_files(target: &str, paths: &[String]) -> BrResult<Vec<(String, Vec<u8>)>> {
    if paths.is_empty() {
        return Ok(vec![]);
    }
    let list_in: String = paths.iter().map(|p| format!("{}\n", p.trim_start_matches('/'))).collect();
    let fetch = "R=\"${BR_REMOTE_ROOT:-}\"; cd \"${R:-/}\" && tar -cf - -T - 2>/dev/null";
    let mut out = vec![];
    run_stream(target, fetch, list_in.as_bytes(), |rd| {
        let mut ar = tar::Archive::new(rd);
        if let Ok(ents) = ar.entries() {
            for e in ents.flatten() {
                let mut e = e;
                if !e.header().entry_type().is_file() {
                    continue;
                }
                let Ok(p) = e.path() else { continue };
                let path = format!("/{}", p.to_string_lossy().trim_start_matches("./").trim_start_matches('/'));
                let mut b = vec![];
                let _ = (&mut e).take(64 * 1024 * 1024).read_to_end(&mut b);
                out.push((path, b));
            }
        }
    })?;
    Ok(out)
}
