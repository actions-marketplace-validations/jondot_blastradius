//! `br demo [COMMAND ...]`: run br against a small sample org that is embedded in the binary.
//!
//! The org is the `acme-tanstack` world of the test rig, seeded into a real index and stored
//! as `assets/demo/home.tar.gz` (a tarball of a BR_HOME). A run unpacks it to a temporary directory, points br at it with
//! a pinned clock, runs the command, and deletes the directory. The user's own index is never opened or changed.

use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Args;

use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};

/// The embedded sample org: a gzip tarball of a BR_HOME (index.db and config.yaml).
const HOME_TGZ: &[u8] = include_bytes!("../../assets/demo/home.tar.gz");

/// A few manifests of the sample org and a snapshot of what the public registries would say about their names, for
/// `br demo claimcheck`. It is a sample registry: every claimcheck line that states a registry fact says so.
const CLAIM_SAMPLE: &str = include_str!("../../assets/demo/claim-sample.json");

/// The clock of the sample org. Every demo run uses it, whatever the real date is.
pub const DEMO_NOW: &str = "2026-05-12T07:10:00Z";
const ORG: &str = "acme";
const ADVISORY: &str = "GHSA-q7vr-4xhc-m2jw";

#[derive(Args, Debug)]
pub struct DemoArgs {
    /// a br command to run against the sample org, for example: hunt --advisory GHSA-q7vr-4xhc-m2jw
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    pub args: Vec<String>,
}

/// What the sample org is, printed on every run (to stderr, so `--format json` on stdout stays clean).
pub fn banner() -> String {
    format!("demo org ({ORG}), clock pinned at {DEMO_NOW}, no network, nothing of yours is read or changed")
}

/// The guided tour, printed by a bare `br demo`.
pub fn tour() -> String {
    format!(
        "br demo: a sample org ({ORG}) built into this binary. No token, no network, nothing to set up.
The story: on 2026-05-12 at 07:10 UTC, three @tanstack packages published on 2026-05-11 turn out to be malicious.
Advisory {ADVISORY}. The sample org has 40 repos, 2 CI runners, 2 laptops and a container registry.

Six steps. Run them in order.

  1. How fresh is the index, and what can it not see?
       br demo status

  2. Are we hit? Every place, with the exposure window and the secrets the CI runs could reach.
       br demo hunt --advisory {ADVISORY}

  3. Only one team's part of it.
       br demo hunt --advisory {ADVISORY} --owner frontend

  4. How does each repo get to a fixed version?
       br demo fix --advisory {ADVISORY}

  5. What to delete (printed, never run), and who to tell.
       br demo purge --advisory {ADVISORY}
       br demo notify --advisory {ADVISORY} --format slack

  6. A sealed record for the auditor or a customer.
       br demo evidence --advisory {ADVISORY} --out evidence.json

One more question, with no advisory: could a stranger already own the names your repos resolve privately?
       br demo claimcheck
   It reads a few sample manifests and asks a sample registry snapshot built into the binary (every line that depends on it says sample registry).

Any br command that only reads works after 'br demo'. 'init', 'scan' and 'import' do not: the demo has no org to read.
Every run uses the pinned clock {DEMO_NOW}. To use br on your own org: br init --org ORG
"
    )
}

/// Commands that make no sense here: they read the outside world, or start another demo.
fn blocked(first: &str) -> Option<&'static str> {
    match first {
        "init" | "scan" => Some("the demo has no org to read and no network; it only answers questions about the sample org"),
        "import" => Some("the demo index is fixed; import a .brx into your own index instead"),
        "demo" => Some("you are already in the demo"),
        _ => None,
    }
}

pub fn run(a: &DemoArgs, outer: &Ctx) -> BrResult<i32> {
    if a.args.is_empty() {
        print!("{}", tour());
        eprintln!("{}", banner());
        return Ok(0);
    }
    if let Some(why) = blocked(&a.args[0]) {
        return Err(BrError::new(format!("br demo {}: {why}", a.args[0]), Some("run br demo with nothing after it for the tour")));
    }
    for flag in ["--now", "--live"] {
        if a.args.iter().any(|x| x == flag) {
            return Err(BrError::new(format!("br demo {flag}: the demo has no network, so it cannot read anything live"), Some("drop the flag; the demo answers from its index")));
        }
    }
    // claimcheck in the demo reads a few sample manifests and a sample registry snapshot, never the network
    let claim_sample = a.args.iter().any(|x| x == "claimcheck" || x == "--claimcheck");
    if claim_sample {
        let s: crate::collect::public::Sample = serde_json::from_str(CLAIM_SAMPLE).map_err(|e| BrError::new(format!("the demo's sample registry is unreadable ({e})"), None))?;
        crate::collect::public::use_sample(Some(s));
    }
    let dir = unpack_temp()?;
    // The demo has its own clock, operator and home, and no way to reach a real service.
    let mut ctx = demo_ctx(&dir, outer.color);
    for k in ["BR_GITHUB_API", "BR_OSV_API", "BR_NPM_REGISTRY"] {
        std::env::set_var(k, "http://127.0.0.1:1");
    }
    std::env::set_var("BR_HOME", &dir);
    std::env::set_var("BR_NOW", DEMO_NOW);
    eprintln!("{}", banner());
    let mut argv = vec!["br".to_string()];
    argv.extend(a.args.iter().cloned());
    let res = (|| -> BrResult<i32> {
        let cli = match <crate::cli::Cli as clap::Parser>::try_parse_from(&argv) {
            Ok(c) => c,
            Err(e) => {
                crate::cli::usage_error(e, &argv)?;
                return Ok(0);
            }
        };
        let Some(cmd) = cli.cmd else {
            return Err(BrError::new("no command given", Some("run br demo with nothing after it for the tour")));
        };
        ctx.set_color_mode(cli.color.as_deref());
        crate::cli::dispatch(cmd, &ctx)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    crate::collect::public::use_sample(None);
    res
}

/// The Ctx of the sample org: pinned clock, the operator from its config.yaml, the unpacked directory as home.
pub fn demo_ctx(dir: &Path, color: bool) -> Ctx {
    let cfg: serde_yaml::Value = std::fs::read_to_string(dir.join("config.yaml")).ok().and_then(|t| serde_yaml::from_str(&t).ok()).unwrap_or(serde_yaml::Value::Null);
    let get = |k: &str| cfg["operator"][k].as_str().map(str::to_string);
    let (user, host) = (get("name"), get("host"));
    if let Some(u) = &user {
        std::env::set_var("BR_USER", u);
    }
    if let Some(h) = &host {
        std::env::set_var("BR_HOST", h);
    }
    Ctx { now: DEMO_NOW.to_string(), home: dir.to_path_buf(), user, host, color }
}

/// Unpack the embedded BR_HOME into a fresh temporary directory.
pub fn unpack_temp() -> BrResult<PathBuf> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("br-demo-{}-{nanos}", std::process::id()));
    let fail = |e: &dyn std::fmt::Display| BrError::with_code(format!("cannot unpack the demo org into {}: {e}", dir.display()), Some("check that the temporary directory is writable (TMPDIR)"), 1);
    std::fs::create_dir_all(&dir).map_err(|e| fail(&e))?;
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(HOME_TGZ).read_to_end(&mut raw).map_err(|e| fail(&e))?;
    tar::Archive::new(raw.as_slice()).unpack(&dir).map_err(|e| fail(&e))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tour_has_six_steps_and_only_demo_commands() {
        let t = tour();
        for n in 1..=6 {
            assert!(t.contains(&format!("  {n}. ")), "step {n} missing");
        }
        assert!(t.contains(DEMO_NOW));
        for line in t.lines().filter(|l| l.trim_start().starts_with("br demo ")) {
            assert!(line.starts_with("       br demo "), "{line}");
        }
        assert!(!t.contains("--now") && !t.contains("--live"));
    }

    /// Split a documented command line into words, honouring single and double quotes.
    fn words(line: &str) -> Vec<String> {
        let (mut out, mut cur, mut q, mut has) = (Vec::new(), String::new(), None::<char>, false);
        for c in line.chars() {
            match (q, c) {
                (Some(x), c) if c == x => q = None,
                (Some(_), c) => cur.push(c),
                (None, '\'' | '"') => {
                    q = Some(c);
                    has = true;
                }
                (None, c) if c.is_whitespace() => {
                    if has || !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                        has = false;
                    }
                }
                (None, c) => cur.push(c),
            }
        }
        if has || !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    /// Every `br demo ...` command written in the README and the docs must parse and must not be one the demo refuses.
    #[test]
    fn documented_demo_commands_parse() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = vec![root.join("README.md"), root.join("docs/why.md"), root.join("docs/launch/response-kit.md")];
        if let Ok(rd) = std::fs::read_dir(root.join("docs/playbooks")) {
            files.extend(rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "md")));
        }
        if !files[0].exists() {
            return; // a source tree without the docs
        }
        let mut seen = 0;
        for f in files {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            for line in text.lines() {
                let l = line.trim_start().trim_start_matches("$ ");
                if !l.starts_with("br demo ") {
                    continue;
                }
                let l = l.split(" #").next().unwrap_or(l);
                let rest: Vec<String> = words(l)[2..].to_vec();
                if rest.is_empty() {
                    continue; // bare `br demo`: the tour
                }
                assert!(blocked(&rest[0]).is_none(), "{}: the demo refuses: {line}", f.display());
                assert!(!rest.iter().any(|x| x == "--now" || x == "--live"), "{}: {line}", f.display());
                let mut argv = vec!["br".to_string()];
                argv.extend(rest);
                if let Err(e) = <crate::cli::Cli as clap::Parser>::try_parse_from(&argv) {
                    panic!("{}: does not parse: {line}\n{e}", f.display());
                }
                seen += 1;
            }
        }
        assert!(seen > 5, "the docs should show the demo commands (saw {seen})");
    }

    #[test]
    fn the_sample_registry_is_small_and_parses() {
        assert!(CLAIM_SAMPLE.len() < 6000, "keep the sample small ({} bytes)", CLAIM_SAMPLE.len());
        let s: crate::collect::public::Sample = serde_json::from_str(CLAIM_SAMPLE).unwrap();
        assert_eq!(s.org, "acme");
        assert!(s.repos.len() <= 4 && !s.registry.npm.is_empty());
    }

    #[test]
    fn banner_names_the_clock() {
        assert!(banner().contains("2026-05-12T07:10:00Z") && banner().contains("no network"));
    }

    #[test]
    fn network_and_init_commands_are_refused() {
        let ctx = Ctx { now: "2030-01-01T00:00:00Z".into(), home: PathBuf::from("."), user: None, host: None, color: false };
        for argv in [vec!["init"], vec!["scan", "--stale"], vec!["import", "x.brx"], vec!["demo"], vec!["hunt", "npm:x@1", "--now"], vec!["hunt", "npm:x@1", "--live"]] {
            let e = run(&DemoArgs { args: argv.iter().map(|s| s.to_string()).collect() }, &ctx).unwrap_err();
            assert_eq!(e.code, 2, "{argv:?}");
        }
    }

    #[test]
    fn the_embedded_org_unpacks_and_loads_with_the_pinned_clock() {
        let dir = unpack_temp().unwrap();
        let ctx = demo_ctx(&dir, false);
        assert_eq!(ctx.now, DEMO_NOW);
        let v = ctx.view().unwrap();
        assert!(v.sources.len() > 10, "the demo org has many sources");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
