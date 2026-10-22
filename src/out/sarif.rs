//! `br hunt --format sarif`: the hunt answer as SARIF 2.1.0, for GitHub code scanning and every other SARIF consumer.
//!
//! One result per finding (present, past run, possible, and present-after-window), each with a physical location when
//! the finding names a file (a lockfile, a workflow) and logical locations for the rest (repo, image, host, cache). What
//! br could not check goes in as tool execution notifications, so a clear answer with gaps never reads as clean.

use sha2::{Digest, Sha256};

use crate::out::json::J;
use crate::query::hunt::{self as H, FKind, Finding, HuntResult};
use crate::query::index::Index;

pub const SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const INFO_URI: &str = "https://github.com/jondot/blastradius";
const POSSIBLE: &str = "br.possible";

/// One rule per place a bad package can sit, plus one for the "possible" rows (a lead br could not confirm).
const RULES: &[(&str, &str, &str, &str)] = &[
    ("br.repo", "PackageInRepo", "A listed package or version is in a repo's lockfile", "Move the repo to a fixed version, then rescan: br fix shows the plan."),
    ("br.ci-run", "PackageInCiRun", "A CI run installed a listed package", "Rotate the secrets the run could read, then clean up: br hunt lists them under the run."),
    ("br.cache", "PackageInCache", "A CI cache holds a listed package", "Delete the cache: br purge prints the command."),
    ("br.artifact", "PackageInArtifact", "A CI artifact holds a listed package", "Delete the artifact: br purge prints the command."),
    (
        "br.image",
        "PackageInImage",
        "A container image holds a listed package or file, possibly in a deleted layer",
        "Rebuild the image from a clean tree and remove the old tag and blob: br purge prints the plan.",
    ),
    ("br.host", "PackageOnHost", "A machine has a listed package or file", "Remove it from the machine and rotate what the machine could reach: br purge prints the plan."),
    ("br.release-asset", "AssetInRelease", "A release asset matches a listed hash", "Withdraw the release asset and publish a clean one."),
    ("br.workflow-ref", "ListedActionInWorkflow", "A workflow uses a listed action or ref", "Pin the action to a safe commit: br fix shows the plan."),
    (POSSIBLE, "PossibleMatch", "A lead br could not confirm", "Read the reason on the result; br names what to check."),
];

fn rule_for(f: &Finding) -> &'static str {
    if f.possible {
        return POSSIBLE;
    }
    match f.kind {
        FKind::Repo => "br.repo",
        FKind::CiRun => "br.ci-run",
        FKind::Cache => "br.cache",
        FKind::Artifact => "br.artifact",
        FKind::Image => "br.image",
        FKind::Host => "br.host",
        FKind::ReleaseAsset => "br.release-asset",
        FKind::WorkflowRef => "br.workflow-ref",
    }
}

/// error: present now. warning: it ran and is gone (a past run). note: a lead, not a finding.
fn level_of(f: &Finding, after_window: bool) -> &'static str {
    if f.possible {
        "note"
    } else if f.past_run && !after_window {
        "warning"
    } else {
        "error"
    }
}

/// Percent-encode a path for a SARIF `uri` (unreserved characters and `/` stay).
pub fn uri_encode(p: &str) -> String {
    let mut out = String::new();
    for b in p.replace('\\', "/").bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The 1-based line of the package in the lockfile, from the lockfile parser's own record (newest commit that has it).
fn lock_line(ix: &Index, f: &Finding) -> Option<u32> {
    // a runtime version is named on a line of a Dockerfile, version file or workflow, not in a lockfile
    if f.rt.is_some() {
        return f.manifest_line;
    }
    let p = f.p.as_ref()?;
    for c in ix.repo(&f.where_).commits.iter().rev() {
        let from_file = c.lock_packages.get(&f.file).and_then(|v| v.iter().find(|x| &x.p == p));
        let found = from_file.or_else(|| c.packages.as_ref().and_then(|v| v.iter().find(|x| &x.p == p)));
        if let Some(l) = found {
            return l.lock_line.filter(|n| *n > 0);
        }
    }
    None
}

struct Logical {
    name: String,
    fqn: String,
    kind: &'static str,
}

struct Placed {
    file: Option<String>,
    line: Option<u32>,
    logical: Vec<Logical>,
}

fn real_file(s: &str) -> Option<String> {
    (!s.is_empty() && s != "-").then(|| s.to_string())
}

fn placed(ix: &Index, f: &Finding) -> Placed {
    let lg = |name: &str, fqn: String, kind: &'static str| Logical { name: name.to_string(), fqn, kind };
    match f.kind {
        FKind::Repo => Placed { file: real_file(&f.file), line: lock_line(ix, f), logical: vec![lg(&f.where_, format!("repo:{}", f.where_), "repository")] },
        FKind::WorkflowRef => Placed { file: real_file(&f.file), line: None, logical: vec![lg(&f.where_, format!("repo:{}", f.where_), "repository")] },
        FKind::CiRun => {
            Placed { file: None, line: None, logical: vec![lg(&f.where_, format!("repo:{}", f.where_), "repository"), lg(&f.workflow, format!("repo:{}/run:{}", f.where_, f.id), "ci-run")] }
        }
        FKind::Cache => Placed { file: None, line: None, logical: vec![lg(&f.key, format!("repo:{}/cache:{}", f.where_, f.key), "cache")] },
        FKind::Artifact => Placed { file: None, line: None, logical: vec![lg(&f.name, format!("repo:{}/artifact:{}", f.where_, f.name), "artifact")] },
        FKind::Image => {
            let mut v = vec![lg(&f.image, format!("image:{}@{}", f.image, f.digest), "image")];
            if !f.path.is_empty() {
                v.push(lg(&f.path, format!("image:{}@{}:{}", f.image, f.digest, f.path), "image-path"));
            }
            Placed { file: None, line: None, logical: v }
        }
        FKind::Host => Placed { file: None, line: None, logical: vec![lg(&f.where_, format!("host:{}", f.where_), "host"), lg(&f.loc, format!("host:{}:{}", f.where_, f.loc), "host-path")] },
        FKind::ReleaseAsset => Placed { file: None, line: None, logical: vec![lg(&f.asset, format!("repo:{}/release:{}/{}", f.where_, f.tag, f.asset), "release-asset")] },
    }
}

fn message(f: &Finding, after_window: bool) -> String {
    if let Some(c) = &f.cert {
        let place = match f.kind {
            FKind::Image => format!("image {}@{}", f.image, f.digest),
            FKind::Host => format!("host {}", f.where_),
            _ => format!("repo {}", f.where_),
        };
        let mut m = format!("{} is a {} certificate (\"{}\") in the trust store file {} of {}", f.ioc, if c.root { "root" } else { "intermediate" }, c.subject, c.file, place);
        if c.deleted {
            m += ". It is in a deleted layer (still in the image's blobs)";
        }
        return m;
    }
    let what = match f.kind {
        FKind::Repo if f.state == "install-only" => {
            format!("was installed in {} (not in its lockfile)", f.where_)
        }
        FKind::Repo => {
            format!("is in {} ({}){}", f.where_, if f.file.is_empty() { "-" } else { f.file.as_str() }, if f.depth.is_empty() || f.depth == "-" { String::new() } else { format!(", {}", f.depth) })
        }
        FKind::CiRun => format!("was installed by CI run #{} of {} ({}) on {}", f.id, f.where_, f.workflow, if f.runner.is_empty() { "an unknown runner" } else { f.runner.as_str() }),
        FKind::Cache => format!("is in the CI cache {} of {}", f.key, f.where_),
        FKind::Artifact => format!("is in the CI artifact {} of {}", f.name, f.where_),
        FKind::Image => format!("is in image {}@{} ({}){}", f.image, f.digest, f.path, if f.where_in.is_empty() { String::new() } else { format!(": {}", crate::out::render::where_in_words(f)) }),
        FKind::Host => format!("is on host {} at {}", f.where_, f.loc),
        FKind::ReleaseAsset => format!("matches release asset {} of {} {}", f.asset, f.where_, f.tag),
        FKind::WorkflowRef => format!("is used by {} in {} ({})", f.uses, f.where_, f.file),
    };
    let mut m = format!("{} {}", f.ioc, what);
    if f.kind == FKind::Repo && !f.version.is_empty() && f.state != "install-only" {
        m += &format!(" at version {}", f.version);
    }
    if let Some(r) = &f.rt {
        m += &format!(". Runtime: {} (seen as {})", crate::out::render::rt_fix_words(r), r.seen_as);
    }
    if f.possible && !f.reason.is_empty() {
        m += &format!(". Possible only: {}", f.reason);
    } else if f.past_run {
        m += ". Past run: it ran and is no longer there.";
    } else if after_window {
        m += ". Present now, first seen after the exposure window ended.";
    } else if !f.state.is_empty() && !matches!(f.state.as_str(), "present" | "ran") {
        m += &format!(". State: {}.", f.state);
    }
    m
}

fn fingerprint(rule: &str, f: &Finding, file: &Option<String>) -> String {
    let mut h = Sha256::new();
    for part in [rule, f.ioc.as_str(), f.where_.as_str(), file.as_deref().unwrap_or(""), f.version.as_str(), f.key.as_str(), f.name.as_str(), f.digest.as_str(), f.loc.as_str(), f.path.as_str()] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    h.update(f.id.to_string().as_bytes());
    if let Some(r) = &f.rt {
        h.update(r.version.as_bytes());
        h.update(r.seen_as.as_bytes());
    }
    hex::encode(h.finalize())[..32].to_string()
}

fn result_json(ix: &Index, f: &Finding, after_window: bool, checkout: bool) -> J {
    let rule = rule_for(f);
    let rule_index = RULES.iter().position(|r| r.0 == rule).unwrap_or(0);
    let pl = placed(ix, f);
    let mut loc = J::obj(vec![]);
    if let Some(file) = &pl.file {
        let mut art = J::obj(vec![("uri", J::s(uri_encode(file)))]);
        if checkout {
            art.set("uriBaseId", J::s("%SRCROOT%"));
        }
        let mut phys = J::obj(vec![("artifactLocation", art)]);
        if let Some(n) = pl.line {
            phys.set("region", J::obj(vec![("startLine", J::Int(n as i64))]));
        }
        loc.set("physicalLocation", phys);
    }
    loc.set("logicalLocations", J::Arr(pl.logical.iter().map(|l| J::obj(vec![("name", J::s(&l.name)), ("fullyQualifiedName", J::s(&l.fqn)), ("kind", J::s(l.kind))])).collect()));
    let mut props = J::obj(vec![
        ("kind", J::s(f.kind.name())),
        (
            "state",
            J::s(if after_window {
                "present-after-window"
            } else if f.state.is_empty() {
                "present"
            } else {
                f.state.as_str()
            }),
        ),
        ("indicators", J::strs(&f.iocs_or_one())),
        ("owner", J::s(if f.owner_label.is_empty() { "unresolved" } else { f.owner_label.as_str() })),
    ]);
    // a checkout is read at this moment: its "seen" times are the clock, not a fact about the finding
    if !checkout {
        if let Some(t) = &f.first_seen {
            props.set("firstSeen", J::s(t));
        }
        if let Some(t) = &f.last_seen {
            props.set("lastSeen", J::s(t));
        }
    }
    if !f.secrets.is_empty() {
        props.set("secrets", J::strs(&f.secrets));
    }
    if f.possible {
        props.set("possible", J::Bool(true));
    }
    if let Some(r) = &f.rt {
        props.set(
            "runtime",
            J::obj(vec![("runtime", J::s(&r.runtime)), ("version", J::s(&r.version)), ("seenAs", J::s(&r.seen_as)), ("lineFixed", J::opt(r.line_fixed.as_deref())), ("eol", J::Bool(r.eol))]),
        );
    }
    J::obj(vec![
        ("ruleId", J::s(rule)),
        ("ruleIndex", J::Int(rule_index as i64)),
        ("kind", J::s("fail")),
        ("level", J::s(level_of(f, after_window))),
        ("message", J::obj(vec![("text", J::s(message(f, after_window)))])),
        ("locations", J::Arr(vec![loc])),
        ("partialFingerprints", J::obj(vec![("blastradius/v1", J::s(fingerprint(rule, f, &pl.file)))])),
        ("properties", props),
    ])
}

fn rules_json() -> J {
    J::Arr(
        RULES
            .iter()
            .map(|(id, name, short, help)| {
                J::obj(vec![
                    ("id", J::s(*id)),
                    ("name", J::s(*name)),
                    ("shortDescription", J::obj(vec![("text", J::s(*short))])),
                    ("help", J::obj(vec![("text", J::s(*help))])),
                    ("defaultConfiguration", J::obj(vec![("level", J::s(if *id == POSSIBLE { "note" } else { "error" }))])),
                ])
            })
            .collect(),
    )
}

pub fn render_sarif(res: &HuntResult, ix: &Index) -> String {
    let checkout = res.q.checkout;
    let rows = H::findings(res).into_iter().chain(H::past_runs(res)).chain(H::possible(res)).map(|f| (f, false)).chain(res.present_after.iter().map(|f| (f, true)));
    let results: Vec<J> = rows.map(|(f, after)| result_json(ix, f, after, checkout)).collect();
    // what br could not check: a notification each, so a consumer that reads only results still sees "not clean" in the run
    let notes: Vec<J> = res
        .not_checked
        .iter()
        .map(|r| {
            let mut text = format!("Not checked: {} ({}). {}", r.name, r.state, r.why);
            if !r.command.is_empty() {
                text += &format!(" To close it: {}", r.command);
            }
            let logical = J::Arr(vec![J::obj(vec![("name", J::s(&r.name)), ("fullyQualifiedName", J::s(format!("{}:{}", r.kind, r.name))), ("kind", J::s("source"))])]);
            J::obj(vec![
                ("level", J::s("warning")),
                ("message", J::obj(vec![("text", J::s(text))])),
                ("locations", J::Arr(vec![J::obj(vec![("logicalLocations", logical)])])),
                ("properties", J::obj(vec![("gap", J::Bool(true)), ("state", J::s(&r.state))])),
            ])
        })
        .collect();
    // floating references are not findings: a note each, so a consumer sees them and knows the answer is not plain clear
    let floats: Vec<J> = res
        .floating
        .iter()
        .map(|f| {
            let at = if f.line > 0 { format!("{}:{}", f.file, f.line) } else { f.file.clone() };
            J::obj(vec![
                ("level", J::s("note")),
                (
                    "message",
                    J::obj(vec![("text", J::s(format!("Floating, not counted as found: {} {} {} ({}) in {}. {}", f.runtime, f.spec, at, f.seen_as, f.repo, crate::out::render::FLOATING_WORDS)))]),
                ),
                ("properties", J::obj(vec![("floating", J::Bool(true))])),
            ])
        })
        .collect();
    let notes: Vec<J> = notes.into_iter().chain(floats).collect();
    let verdict = match H::verdict(res) {
        "FOUND" => "found",
        "CLEAR" => "clear",
        _ => "clear_with_gaps",
    };
    let driver = J::obj(vec![("name", J::s("blastradius")), ("semanticVersion", J::s(env!("CARGO_PKG_VERSION"))), ("informationUri", J::s(INFO_URI)), ("rules", rules_json())]);
    let invocation = J::obj(vec![("executionSuccessful", J::Bool(true)), ("toolExecutionNotifications", J::Arr(notes))]);
    let mut run = J::obj(vec![("tool", J::obj(vec![("driver", driver)])), ("invocations", J::Arr(vec![invocation]))]);
    run.set("results", J::Arr(results));
    let mut props = J::obj(vec![
        ("verdict", J::s(verdict)),
        ("indicators", J::Arr(res.q.iocs.iter().map(|i| J::s(&i.text)).collect())),
        ("when", J::s(if res.q.now_only { "now" } else { "ever" })),
        ("notChecked", J::Int(res.not_checked.len() as i64)),
    ]);
    if !checkout {
        props.set("indexAsOf", J::opt(res.as_of.as_deref()));
    }
    run.set("properties", props);
    J::obj(vec![("$schema", J::s(SCHEMA_URI)), ("version", J::s("2.1.0")), ("runs", J::Arr(vec![run]))]).dumps()
}

// ---- br claimcheck --------------------------------------------------------------------------------------------------

/// One rule per exposed class. The flags (higher version, bin match, scope held) ride on the result as properties and in
/// the message, since one name can carry several.
const CLAIM_RULES: &[(&str, &str, &str, &str)] = &[
    ("br.claim.free", "NameFreeOnPublicRegistry", "An internal package name is free on its public registry", "Pin the registry per scope or index, claim the scope, or publish a placeholder. br never publishes or claims anything."),
    ("br.claim.squatted", "NameHeldByOthersOnPublicRegistry", "An internal package name is public and not shown to be yours", "Pin the registry per scope or index so the public copy is never asked for, or rename the package; report the public package to its registry; and run br hunt NAME@THEIRVERSION to see whether anything installed it. The name is already taken, so a placeholder cannot claim it."),
    ("br.claim.scope-unclaimed", "NpmScopeNotShownAsYours", "An npm scope you use is not shown as yours on the public registry", "Claim the scope with an org you own, and pin it to your registry in .npmrc."),
];

fn claim_rule(s: crate::query::claims::Status) -> Option<&'static str> {
    use crate::query::claims::Status as S;
    match s {
        S::Free => Some("br.claim.free"),
        S::Squatted => Some("br.claim.squatted"),
        S::ScopeUnclaimed => Some("br.claim.scope-unclaimed"),
        S::Ours | S::NotChecked => None,
    }
}

fn claim_message(r: &crate::query::claims::Row) -> String {
    let what = if r.is_scope { "npm scope".to_string() } else { r.eco.word().to_string() };
    let mut m = format!("{what} {}: {}", r.name, r.status.word());
    match r.status {
        crate::query::claims::Status::Free => {
            let p = crate::query::claims::plain(r);
            let mut cs = p.chars();
            m += &format!(". {}{}.", cs.next().map(|c| c.to_uppercase().to_string()).unwrap_or_default(), cs.as_str());
        }
        crate::query::claims::Status::ScopeUnclaimed => m += ". The public registry does not show this scope as yours.",
        _ => {
            m += &format!(". Public: {}", r.public_max.as_deref().unwrap_or("no versions"));
            if let Some(t) = &r.published {
                m += &format!(", published {} (newest version)", t.chars().take(10).collect::<String>());
            }
            if let Some(t) = &r.first_published {
                m += &format!(", name first claimed {}", t.chars().take(10).collect::<String>());
            }
            m += &format!(
                ", install script: {}",
                match r.install_script {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "unknown",
                }
            );
            m += if r.publishers.is_empty() { "; owner not shown." } else { "." };
        }
    }
    for f in &r.flags {
        m += &format!(" Flag: {}.", f.text());
    }
    m
}

/// `br claimcheck --format sarif`. One result per name that is FREE, SQUATTED or SCOPE UNCLAIMED, and one per file where
/// it was seen, so each manifest, lockfile or config gets its own annotation. Names shown to be yours are not results.
/// What could not be checked goes in as tool execution notifications, so a clear list with gaps never reads as clean.
pub fn render_claims(rep: &crate::cmd::claimcheck::Report) -> String {
    let mut results: Vec<J> = vec![];
    for r in rep.rows.iter().filter(|r| r.status.exposed()) {
        let rule = claim_rule(r.status).unwrap_or("br.claim.free");
        let rule_index = CLAIM_RULES.iter().position(|x| x.0 == rule).unwrap_or(0);
        let msg = claim_message(r);
        // the same file seen twice (two kinds of sighting) is one location
        let mut seen: Vec<&crate::query::claims::Seen> = vec![];
        for s in &r.seen {
            if !seen.iter().any(|x| x.repo == s.repo && x.file == s.file) {
                seen.push(s);
            }
        }
        let places: Vec<Option<&crate::query::claims::Seen>> = if seen.is_empty() { vec![None] } else { seen.into_iter().map(Some).collect() };
        let pkg_fqn = format!("{}:{}", if r.is_scope { "npm-scope" } else { r.eco.word() }, r.name);
        for pl in places {
            let mut loc = J::obj(vec![]);
            let mut file = String::new();
            let mut logical = vec![J::obj(vec![("name", J::s(&r.name)), ("fullyQualifiedName", J::s(&pkg_fqn)), ("kind", J::s("package"))])];
            if let Some(s) = pl {
                logical.insert(0, J::obj(vec![("name", J::s(&s.repo)), ("fullyQualifiedName", J::s(format!("repo:{}", s.repo))), ("kind", J::s("repository"))]));
                if real_file(&s.file).is_some() {
                    file = s.file.clone();
                    // one --path checkout: files are relative to it, as the Action runs. Several: the label keeps them apart.
                    let uri = if rep.checkout_roots > 1 { format!("{}/{}", s.repo, s.file) } else { s.file.clone() };
                    let mut art = J::obj(vec![("uri", J::s(uri_encode(&uri)))]);
                    if rep.checkout_roots == 1 {
                        art.set("uriBaseId", J::s("%SRCROOT%"));
                    }
                    loc.set("physicalLocation", J::obj(vec![("artifactLocation", art)]));
                }
            }
            loc.set("logicalLocations", J::Arr(logical));
            let mut h = Sha256::new();
            for part in [rule, r.eco.word(), r.name.as_str(), pl.map(|s| s.repo.as_str()).unwrap_or(""), file.as_str()] {
                h.update(part.as_bytes());
                h.update([0u8]);
            }
            let mut props = J::obj(vec![
                ("name", J::s(&r.name)),
                ("ecosystem", J::s(if r.is_scope { "npm" } else { r.eco.word() })),
                ("status", J::s(r.status.word())),
                ("flags", J::Arr(r.flags.iter().map(|f| J::s(f.key())).collect())),
            ]);
            if let Some(v) = &r.public_max {
                props.set("publicMaxVersion", J::s(v));
            }
            results.push(J::obj(vec![
                ("ruleId", J::s(rule)),
                ("ruleIndex", J::Int(rule_index as i64)),
                ("kind", J::s("fail")),
                ("level", J::s("error")),
                ("message", J::obj(vec![("text", J::s(&msg))])),
                ("locations", J::Arr(vec![loc])),
                ("partialFingerprints", J::obj(vec![("blastradius/claim/v1", J::s(hex::encode(h.finalize())[..32].to_string()))])),
                ("properties", props),
            ]));
        }
    }
    let notes: Vec<J> = rep
        .gaps
        .iter()
        .map(|g| {
            let logical = J::Arr(vec![J::obj(vec![("name", J::s(&g.what)), ("fullyQualifiedName", J::s(format!("source:{}", g.what))), ("kind", J::s("source"))])]);
            J::obj(vec![
                ("level", J::s("warning")),
                ("message", J::obj(vec![("text", J::s(format!("Not checked: {} ({}). {}", g.what, g.why, g.to_close)))])),
                ("locations", J::Arr(vec![J::obj(vec![("logicalLocations", logical)])])),
                ("properties", J::obj(vec![("gap", J::Bool(true))])),
            ])
        })
        .collect();
    let rules = J::Arr(
        CLAIM_RULES
            .iter()
            .map(|(id, name, short, help)| {
                J::obj(vec![
                    ("id", J::s(*id)),
                    ("name", J::s(*name)),
                    ("shortDescription", J::obj(vec![("text", J::s(*short))])),
                    ("help", J::obj(vec![("text", J::s(*help))])),
                    ("defaultConfiguration", J::obj(vec![("level", J::s("error"))])),
                ])
            })
            .collect(),
    );
    let driver = J::obj(vec![("name", J::s("blastradius")), ("semanticVersion", J::s(env!("CARGO_PKG_VERSION"))), ("informationUri", J::s(INFO_URI)), ("rules", rules)]);
    let verdict = match rep.verdict() {
        "EXPOSED" => "exposed",
        "CLEAR" => "clear",
        _ => "clear_with_gaps",
    };
    let mut run =
        J::obj(vec![("tool", J::obj(vec![("driver", driver)])), ("invocations", J::Arr(vec![J::obj(vec![("executionSuccessful", J::Bool(true)), ("toolExecutionNotifications", J::Arr(notes))])]))]);
    run.set("results", J::Arr(results));
    run.set(
        "properties",
        J::obj(vec![
            ("command", J::s("claimcheck")),
            ("verdict", J::s(verdict)),
            ("notChecked", J::Int(rep.not_checked_names() as i64)),
            ("clock", J::s(&rep.now)),
            ("asOf", J::opt(rep.as_of.as_deref())),
            ("indexAge", J::s(crate::cmd::claimcheck::index_line(rep))),
        ]),
    );
    J::obj(vec![("$schema", J::s(SCHEMA_URI)), ("version", J::s("2.1.0")), ("runs", J::Arr(vec![run]))]).dumps()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::hunt::Query;
    use crate::query::iocs::parse_ioc;
    use crate::view::View;
    use serde_json::Value;

    // ---- a validator for the subset of JSON Schema that tests/schemas/sarif-2.1.0.json uses --------------------------
    // (type, enum, required, properties, additionalProperties, items, minItems, minimum, pattern, anyOf, $ref)

    fn resolve<'a>(root: &'a Value, r: &str) -> &'a Value {
        let mut cur = root;
        for part in r.trim_start_matches("#/").split('/') {
            cur = &cur[part];
        }
        cur
    }

    fn check(root: &Value, schema: &Value, v: &Value, at: &str, errs: &mut Vec<String>) {
        if let Some(r) = schema.get("$ref").and_then(|r| r.as_str()) {
            return check(root, resolve(root, r), v, at, errs);
        }
        if let Some(t) = schema.get("type").and_then(|t| t.as_str()) {
            let ok = match t {
                "object" => v.is_object(),
                "array" => v.is_array(),
                "string" => v.is_string(),
                "boolean" => v.is_boolean(),
                "integer" => v.is_i64() || v.is_u64(),
                "number" => v.is_number(),
                _ => true,
            };
            if !ok {
                errs.push(format!("{at}: expected {t}"));
                return;
            }
        }
        if let Some(e) = schema.get("enum").and_then(|e| e.as_array()) {
            if !e.contains(v) {
                errs.push(format!("{at}: {v} not in enum"));
            }
        }
        if let (Some(min), Some(n)) = (schema.get("minimum").and_then(|m| m.as_i64()), v.as_i64()) {
            if n < min {
                errs.push(format!("{at}: {n} < minimum {min}"));
            }
        }
        if let (Some(p), Some(s)) = (schema.get("pattern").and_then(|p| p.as_str()), v.as_str()) {
            if !regex::Regex::new(p).unwrap().is_match(s) {
                errs.push(format!("{at}: {s:?} does not match {p}"));
            }
        }
        if let Some(any) = schema.get("anyOf").and_then(|a| a.as_array()) {
            if !any.iter().any(|s| {
                let mut e = vec![];
                check(root, s, v, at, &mut e);
                e.is_empty()
            }) {
                errs.push(format!("{at}: matches none of anyOf"));
            }
        }
        if let Some(o) = v.as_object() {
            for r in schema.get("required").and_then(|r| r.as_array()).into_iter().flatten() {
                if !o.contains_key(r.as_str().unwrap()) {
                    errs.push(format!("{at}: missing required {r}"));
                }
            }
            let props = schema.get("properties").and_then(|p| p.as_object());
            for (k, val) in o {
                match props.and_then(|p| p.get(k)) {
                    Some(s) => check(root, s, val, &format!("{at}/{k}"), errs),
                    None => match schema.get("additionalProperties") {
                        Some(Value::Bool(false)) => errs.push(format!("{at}: unexpected property {k}")),
                        Some(s) if s.is_object() => check(root, s, val, &format!("{at}/{k}"), errs),
                        _ => {}
                    },
                }
            }
        }
        if let Some(a) = v.as_array() {
            if let Some(n) = schema.get("minItems").and_then(|n| n.as_u64()) {
                if (a.len() as u64) < n {
                    errs.push(format!("{at}: fewer than {n} items"));
                }
            }
            if let Some(s) = schema.get("items") {
                for (i, x) in a.iter().enumerate() {
                    check(root, s, x, &format!("{at}[{i}]"), errs);
                }
            }
        }
    }

    fn schema() -> Value {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/schemas/sarif-2.1.0.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn validate(doc: &Value) -> Vec<String> {
        let mut errs = vec![];
        let s = schema();
        check(&s, &s, doc, "#", &mut errs);
        errs
    }

    fn acme() -> View {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/views/view-acme-tanstack.json");
        View::from_json_file(&p).unwrap()
    }

    fn hunt_at(v: &View, now: &str, iocs: &[&str]) -> (H::HuntResult, String) {
        let ix = Index::new(v, now);
        let q = Query { iocs: iocs.iter().map(|s| parse_ioc(s, None).unwrap()).collect(), ..Default::default() };
        let res = H::hunt(&ix, &q).unwrap();
        let s = render_sarif(&res, &ix);
        (res, s)
    }

    const HOT: [&str; 2] = ["npm:@tanstack/react-router@1.120.3", "npm:@tanstack/router-core@1.120.3"];

    #[test]
    fn sarif_validates_against_the_vendored_schema() {
        let v = acme();
        let (res, s) = hunt_at(&v, &v.now, &HOT);
        assert!(!res.findings.is_empty());
        let doc: Value = serde_json::from_str(&s).expect("valid JSON");
        let errs = validate(&doc);
        assert!(errs.is_empty(), "{errs:#?}");
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["runs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn the_validator_rejects_a_broken_document() {
        let v = acme();
        let (_, s) = hunt_at(&v, &v.now, &HOT);
        let good: Value = serde_json::from_str(&s).unwrap();
        let mut bad = good.clone();
        bad["runs"][0]["results"][0]["level"] = Value::String("critical".into());
        assert!(!validate(&bad).is_empty(), "an unknown level must fail");
        let mut bad = good.clone();
        bad["runs"][0]["results"][0].as_object_mut().unwrap().remove("message");
        assert!(!validate(&bad).is_empty(), "a result without a message must fail");
        let mut bad = good.clone();
        bad["version"] = Value::String("2.0.0".into());
        assert!(!validate(&bad).is_empty());
        let mut bad = good;
        bad["runs"][0]["results"][0]["typo"] = Value::Bool(true);
        assert!(!validate(&bad).is_empty(), "an unknown property must fail");
    }

    #[test]
    fn one_result_per_finding_with_the_right_kind_of_location() {
        let v = acme();
        let (res, s) = hunt_at(&v, &v.now, &HOT);
        let doc: Value = serde_json::from_str(&s).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        let expect = H::findings(&res).len() + H::past_runs(&res).len() + H::possible(&res).len() + res.present_after.len();
        assert_eq!(results.len(), expect);
        let mut kinds = std::collections::BTreeSet::new();
        for r in results {
            let k = r["properties"]["kind"].as_str().unwrap();
            kinds.insert(k.to_string());
            let loc = &r["locations"][0];
            assert!(!loc["logicalLocations"].as_array().unwrap().is_empty(), "every result is also placed logically: {r}");
            let physical = loc.get("physicalLocation").is_some();
            match (k, r["ruleId"].as_str().unwrap()) {
                (_, "br.possible") => {}
                ("repo" | "workflow_ref", _) => {
                    // a repo hit names its lockfile; an install-only hit has none and stays logical
                    if physical {
                        let uri = loc["physicalLocation"]["artifactLocation"]["uri"].as_str().unwrap();
                        assert!(!uri.is_empty() && uri != "-" && !uri.starts_with('/'), "{uri}");
                    }
                }
                _ => assert!(!physical, "{k} has no file in the repo, so no physical location: {r}"),
            }
            let idx = r["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(doc["runs"][0]["tool"]["driver"]["rules"][idx]["id"], r["ruleId"]);
        }
        assert!(kinds.contains("repo") && kinds.contains("ci_run"), "{kinds:?}");
        assert!(results.iter().any(|r| r["locations"][0].get("physicalLocation").is_some()), "a lockfile hit has a file");
    }

    #[test]
    fn a_lockfile_hit_carries_the_line_the_parser_recorded() {
        let v = acme();
        let (res, s) = hunt_at(&v, &v.now, &HOT);
        let doc: Value = serde_json::from_str(&s).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        let lined = results.iter().filter(|r| r["locations"][0]["physicalLocation"].get("region").is_some()).count();
        assert!(lined > 0, "the world records lock lines");
        for r in results {
            if let Some(n) = r["locations"][0]["physicalLocation"]["region"].get("startLine") {
                assert!(n.as_u64().unwrap() >= 1);
            }
        }
        // a line is never invented: a region is there exactly when the parser recorded a line
        let ix = Index::new(&v, &v.now);
        let expect = H::findings(&res).into_iter().filter(|f| f.kind == FKind::Repo && real_file(&f.file).is_some() && lock_line(&ix, f).is_some()).count();
        assert_eq!(lined, expect);
    }

    #[test]
    fn what_was_not_checked_is_a_notification_never_a_clean_answer() {
        let v = acme();
        // a month later every source is stale; a package nobody has gives no result but the gaps stay in the run
        let (res, s) = hunt_at(&v, "2026-06-20T00:00:00Z", &["npm:no-such-package-anywhere@1.0.0"]);
        assert!(!res.not_checked.is_empty());
        let doc: Value = serde_json::from_str(&s).unwrap();
        assert!(validate(&doc).is_empty());
        let run = &doc["runs"][0];
        assert!(run["results"].as_array().unwrap().is_empty());
        let notes = run["invocations"][0]["toolExecutionNotifications"].as_array().unwrap();
        assert_eq!(notes.len(), res.not_checked.len());
        for n in notes {
            assert_eq!(n["level"], "warning");
            assert!(n["message"]["text"].as_str().unwrap().starts_with("Not checked: "));
        }
        assert_eq!(run["properties"]["verdict"], "clear_with_gaps");
    }

    #[test]
    fn an_answer_with_no_findings_is_valid_and_an_empty_index_is_no_answer() {
        let v = acme();
        let (res, s) = hunt_at(&v, &v.now, &["npm:no-such-package-anywhere@1.0.0"]);
        let doc: Value = serde_json::from_str(&s).unwrap();
        assert!(validate(&doc).is_empty());
        assert!(doc["runs"][0]["results"].as_array().unwrap().is_empty());
        assert_eq!(doc["runs"][0]["invocations"][0]["toolExecutionNotifications"].as_array().unwrap().len(), res.not_checked.len());
        // an index with no sources is not a clean answer: hunt refuses (exit 5) before any SARIF is written
        let empty = View { now: "2026-05-12T07:10:00Z".into(), ..Default::default() };
        let ix = Index::new(&empty, &empty.now);
        let q = Query { iocs: vec![parse_ioc("npm:left-pad@1.3.0", None).unwrap()], ..Default::default() };
        assert_eq!(H::hunt(&ix, &q).unwrap_err().code, 5);
    }

    #[test]
    fn levels_follow_whether_it_is_there_now() {
        let v = acme();
        let (res, s) = hunt_at(&v, &v.now, &HOT);
        let doc: Value = serde_json::from_str(&s).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        let (present, past) = (H::findings(&res).len(), H::past_runs(&res).len());
        assert_eq!(results.iter().filter(|r| r["level"] == "error").count(), present + res.present_after.len());
        assert_eq!(results.iter().filter(|r| r["level"] == "warning").count(), past);
        assert_eq!(results.iter().filter(|r| r["level"] == "note").count(), H::possible(&res).len());
    }

    #[test]
    fn checkout_paths_are_relative_to_the_source_root() {
        let v = acme();
        let (mut res, _) = hunt_at(&v, &v.now, &HOT);
        let ix = Index::new(&v, &v.now);
        let plain: Value = serde_json::from_str(&render_sarif(&res, &ix)).unwrap();
        assert!(!plain.to_string().contains("uriBaseId"));
        res.q.checkout = true;
        let co: Value = serde_json::from_str(&render_sarif(&res, &ix)).unwrap();
        assert!(validate(&co).is_empty());
        let with_file: Vec<&Value> = co["runs"][0]["results"].as_array().unwrap().iter().filter(|r| r["locations"][0].get("physicalLocation").is_some()).collect();
        assert!(!with_file.is_empty());
        for r in with_file {
            assert_eq!(r["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"], "%SRCROOT%");
        }
    }

    #[test]
    fn fingerprints_are_stable_and_tell_results_apart() {
        let v = acme();
        let (_, a) = hunt_at(&v, &v.now, &HOT);
        let (_, b) = hunt_at(&v, &v.now, &HOT);
        assert_eq!(a, b, "same input, same bytes");
        let doc: Value = serde_json::from_str(&a).unwrap();
        let fps: Vec<String> = doc["runs"][0]["results"].as_array().unwrap().iter().map(|r| r["partialFingerprints"]["blastradius/v1"].as_str().unwrap().to_string()).collect();
        let set: std::collections::BTreeSet<&String> = fps.iter().collect();
        assert_eq!(set.len(), fps.len(), "no two results share a fingerprint");
    }

    #[test]
    fn uris_are_percent_encoded() {
        assert_eq!(uri_encode("apps/web/package-lock.json"), "apps/web/package-lock.json");
        assert_eq!(uri_encode("my app/yarn lock#1.lock"), "my%20app/yarn%20lock%231.lock");
        assert_eq!(uri_encode("a\\b"), "a/b");
        assert_eq!(uri_encode("é"), "%C3%A9");
    }

    #[test]
    fn claimcheck_sarif_puts_results_on_files_and_gaps_in_notifications() {
        use crate::cmd::claimcheck::{GapRow, Report};
        use crate::collect::public::{Eco, Lookup};
        use crate::query::claims::{self, Claim, Facts, Flag, Kind, Seen, Status};
        let mut cl = Claim::default();
        cl.kinds.insert(Kind::Own);
        let f = Facts { orgs: vec![], members: Default::default(), bin_cmds: &Default::default() };
        let mut sq = claims::classify(Eco::Npm, "corp-core", &cl, &Lookup::Free, &f);
        sq.status = Status::Squatted;
        sq.public_max = Some("9999.0.0".into());
        sq.flags = vec![Flag::HigherVersion { public: "9999.0.0".into(), yours: "1.0.0".into() }];
        sq.seen = vec![Seen { repo: "web".into(), file: "pkgs/a/package.json".into() }, Seen { repo: "web".into(), file: "package-lock.json".into() }];
        let mut free = claims::classify(Eco::Pypi, "corp-lib", &cl, &Lookup::Free, &f);
        free.status = Status::Free;
        free.seen = vec![Seen { repo: "web".into(), file: "requirements.txt".into() }];
        let mut ours = claims::classify(Eco::Npm, "mine", &cl, &Lookup::Free, &f);
        ours.status = Status::Ours;
        let rep = Report {
            now: "2026-05-12T07:10:00Z".into(),
            orgs: vec![],
            rows: vec![sq, free, ours],
            gaps: vec![GapRow { what: "2 names on pypi.org".into(), why: "unreachable".into(), to_close: "retry".into(), names: 2 }],
            trees: 1,
            files_read: 3,
            maps_read: 0,
            unreferenced_private: 0,
            go_public_skipped: 0,
            public_expected: 0,
            indexes: vec![],
            registries_asked: vec![],
            calls: 2,
            checkout_roots: 1,
            ..Default::default()
        };
        let doc: Value = serde_json::from_str(&render_claims(&rep)).unwrap();
        let errs = validate(&doc);
        assert!(errs.is_empty(), "{errs:#?}");
        let res = doc["runs"][0]["results"].as_array().unwrap();
        // two files for the squatted name, one for the free name, none for OURS
        assert_eq!(res.len(), 3);
        let uris: Vec<&str> = res.iter().map(|r| r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str().unwrap()).collect();
        assert_eq!(uris, vec!["pkgs/a/package.json", "package-lock.json", "requirements.txt"]);
        assert_eq!(res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"], "%SRCROOT%");
        assert_eq!(res[0]["ruleId"], "br.claim.squatted");
        assert!(res[0]["message"]["text"].as_str().unwrap().contains("highest you use"));
        assert_eq!(res[2]["ruleId"], "br.claim.free");
        let notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"].as_array().unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0]["message"]["text"].as_str().unwrap().contains("unreachable"));
        assert_eq!(doc["runs"][0]["properties"]["verdict"], "exposed");
    }
}
