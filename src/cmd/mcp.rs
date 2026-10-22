//! `br mcp`: a read-only MCP server over stdio (docs/mcp.md).
//!
//! Protocol: JSON-RPC 2.0, one message per line (the MCP stdio transport). Targets MCP revision 2025-06-18 and also
//! answers 2025-03-26 and 2024-11-05 when the client asks for them. Tools: hunt, status, advisory_show, hosts,
//! evidence_summary. Each tool runs one fixed, read-only `br` command as a child process (this same binary) and returns
//! a short text summary plus the output br prints. Nothing here scans, writes, notifies or purges, and the child never
//! asks OSV (a lookup would cache the record in the index, which is a write).

use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::ctx::Ctx;
use crate::error::BrResult;

/// The revision this server speaks first.
pub const LATEST: &str = "2025-06-18";
const SUPPORTED: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

#[derive(Debug, Default, clap::Args)]
pub struct McpArgs {}

/// What a child `br` printed.
pub struct Ran {
    pub code: i32,
    pub out: String,
    pub err: String,
}

/// Runs `br ARGS` and returns what it printed; replaced by a stub in unit tests.
pub type Runner<'a> = &'a dyn Fn(&[String]) -> Ran;

pub fn run(_a: &McpArgs, _ctx: &Ctx) -> BrResult<i32> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let _ = serve(stdin.lock(), stdout.lock(), &spawn_br);
    Ok(0)
}

fn spawn_br(args: &[String]) -> Ran {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return Ran { code: 1, out: String::new(), err: format!("cannot find the br binary: {e}") },
    };
    let res = Command::new(exe)
        .args(args)
        .env("NO_COLOR", "1")
        // an OSV lookup caches the record in the index; this server never writes, so it never asks
        .env("BR_OSV_API", "http://127.0.0.1:9")
        .stdin(Stdio::null())
        .output();
    match res {
        Ok(o) => Ran { code: o.status.code().unwrap_or(1), out: String::from_utf8_lossy(&o.stdout).into_owned(), err: String::from_utf8_lossy(&o.stderr).into_owned() },
        Err(e) => Ran { code: 1, out: String::new(), err: format!("cannot run br: {e}") },
    }
}

/// Read newline-delimited JSON-RPC from `input`, write replies to `output`, until the input ends.
pub fn serve<R: BufRead, W: Write>(input: R, mut output: W, runner: Runner) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = handle_line(&line, runner) {
            writeln!(output, "{reply}")?;
            output.flush()?;
        }
    }
    Ok(())
}

fn err(id: Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

/// One line in, at most one line out (a batch answers with an array; notifications answer nothing).
pub fn handle_line(line: &str, runner: Runner) -> Option<String> {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return Some(err(Value::Null, -32700, &format!("parse error: {e}")).to_string()),
    };
    match v {
        Value::Array(items) => {
            if items.is_empty() {
                return Some(err(Value::Null, -32600, "invalid request: empty batch").to_string());
            }
            let replies: Vec<Value> = items.iter().filter_map(|m| handle(m, runner)).collect();
            if replies.is_empty() {
                None
            } else {
                Some(Value::Array(replies).to_string())
            }
        }
        other => handle(&other, runner).map(|r| r.to_string()),
    }
}

/// Answer one JSON-RPC message; None for a notification (no `id`).
pub fn handle(msg: &Value, runner: Runner) -> Option<Value> {
    let Some(obj) = msg.as_object() else {
        return Some(err(Value::Null, -32600, "invalid request: not an object"));
    };
    let method = obj.get("method").and_then(Value::as_str);
    let id = obj.get("id").cloned();
    let Some(method) = method else {
        // a response from the client (we send no requests) or junk
        return if obj.contains_key("result") || obj.contains_key("error") { None } else { Some(err(id.unwrap_or(Value::Null), -32600, "invalid request: no method")) };
    };
    let id = id?; // no id: a notification (notifications/initialized, notifications/cancelled, ...)
    if !(id.is_string() || id.is_number()) {
        return Some(err(Value::Null, -32600, "invalid request: id must be a string or a number"));
    }
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    Some(match method {
        "initialize" => {
            let Some(asked) = params.get("protocolVersion").and_then(Value::as_str) else {
                return Some(err(id, -32602, "initialize needs params.protocolVersion"));
            };
            let version = if SUPPORTED.contains(&asked) { asked } else { LATEST };
            json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "blastradius", "title": "blastradius (br)", "version": crate::cli::VERSION},
                "instructions": "Read-only access to a blastradius index: where a package, action or file landed, and what the answer did not cover. Always read the gaps: a hunt that found nothing is clear only for the sources it checked. This server never scans, writes, notifies or purges."
            }})
        }
        "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        "tools/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools()}}),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(err(id, -32602, "tools/call needs params.name"));
            };
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match call(name, &args, runner) {
                None => err(id, -32602, &format!("unknown tool: {name}")),
                Some(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            }
        }
        other => err(id, -32601, &format!("method not found: {other}")),
    })
}

fn tool(name: &str, title: &str, desc: &str, props: Value, required: &[&str]) -> Value {
    json!({
        "name": name, "title": title, "description": desc,
        "inputSchema": {"type": "object", "properties": props, "required": required, "additionalProperties": false},
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
    })
}

/// The tool list. Every description says what the tool does not do.
pub fn tools() -> Value {
    let mut all = tool_list();
    // claimcheck is the one tool that talks to the world outside: public registries, by read-only GET
    for t in all.as_array_mut().into_iter().flatten() {
        if t["name"] == "claimcheck" {
            t["annotations"]["openWorldHint"] = json!(true);
        }
    }
    all
}

fn tool_list() -> Value {
    let s = |d: &str| json!({"type": "string", "description": d});
    json!([
        tool("hunt", "Hunt for an indicator",
            "Find where a bad package, action or file landed (repos, CI runs, caches, artifacts, images, hosts) and what the answer did not cover (gaps). Give indicators such as npm:name@1.2.3, pypi:, cargo:, go:, action:, sha256:, or an advisory id already in the index or notes. Reads the index only; it does not scan, write, notify or purge, and it does not ask OSV. A result with no findings is clear only for the sources checked: read counts.gaps.",
            json!({
                "indicators": {"type": "array", "items": {"type": "string"}, "description": "indicators, e.g. npm:left-pad@1.3.0"},
                "advisory": s("an advisory id (GHSA, OSV, CVE) known to the index or notes, or a local advisory JSON file"),
                "path": s("hunt the checkout in this directory instead of the index (reads its lockfiles; no index, no network)"),
                "repo": s("only this repository, ORG/NAME"),
                "owner": s("only what this team or person owns"),
                "host": s("only this host"),
                "now": {"type": "boolean", "description": "only what is present now: drop removed packages and past CI runs"},
                "only": s("limit the sections, comma separated: repos, ci, caches, artifacts, images, hosts, releases"),
                "window": s("exposure window FROM..TO, e.g. 2026-05-11T14:00Z..2026-05-11T18:00Z")
            }), &[]),
        tool("status", "Index freshness",
            "Show how fresh each source in the index is and what is not covered. Reads the index; it does not rescan anything.",
            json!({
                "all": {"type": "boolean", "description": "list every source, not only the stale ones"},
                "owner": s("only the sources this team or person owns")
            }), &[]),
        tool("advisory_show", "Show an advisory",
            "Show one advisory the index or the operator's notes already hold: its packages, hashes, window and fixed versions, and where each part came from. It does not ask OSV and does not write a note.",
            json!({"id": s("the advisory id (GHSA, OSV, CVE)")}), &["id"]),
        tool("hosts", "List machines",
            "List the machines in the index and the org members with no laptop scan. It does not register, remove or scan a host.",
            json!({}), &[]),
        tool("evidence_summary", "Summarise an evidence file",
            "Summarise an evidence file br evidence already wrote (br-evidence/1): the question, the claim, the verdict, counts, what was not checked, and whether its seal verifies. It does not write evidence, sign or alter the file.",
            json!({"file": s("path to the evidence JSON")}), &["file"]),
        tool("claimcheck", "Dependency-confusion exposure",
            "Check which of the org's own package names (from manifests, lockfiles, registry settings and source maps) are FREE, SQUATTED or SCOPE UNCLAIMED on the public registries, with the flags (higher public version, bin match, scope held) and the places each name was seen. It makes read-only GETs to public registries (npmjs.org, pypi.org, crates.io, proxy.golang.org), and reads the repos of the index through the GitHub API when no path is given. It writes nothing (no index, no cache, no BR_HOME, and it never records a snapshot), and it never publishes or claims a name. An unreachable registry is a gap, never clear: read counts and gaps.",
            json!({
                "path": s("check the checkout in this directory instead of the index's repos (no GitHub token needed)"),
                "repo": s("only this repository of the index, ORG/NAME"),
                "org": s("the GitHub org whose packages count as yours (default: the org of the index)"),
                "max_names": {"type": "integer", "minimum": 0, "description": "most names to ask the public registries about (default 400, the same as the CLI; 0 asks none); the rest are counted and listed as not checked"},
                "as_of": s("judge each public package by the versions published on or before this date, e.g. 2026-06-09; a registry that gives no publish time is named per name")
            }), &[]),
    ])
}

fn text_result(summary: &str, body: &str, is_error: bool) -> Value {
    let mut content = vec![json!({"type": "text", "text": summary})];
    if !body.trim().is_empty() {
        content.push(json!({"type": "text", "text": body.trim_end()}));
    }
    json!({"content": content, "isError": is_error})
}

fn bad(msg: &str) -> Option<Value> {
    Some(text_result(&format!("invalid arguments: {msg}"), "", true))
}

/// A string argument: absent is None, a non-string or a value that starts with `-` (a flag in disguise) is an error.
fn opt_str(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) if s.starts_with('-') => Err(format!("{key} must not start with '-'")),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

fn opt_bool(args: &Value, key: &str) -> Result<bool, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

fn known_keys(args: &Value, ok: &[&str]) -> Result<(), String> {
    match args.as_object() {
        None => Err("arguments must be an object".into()),
        Some(o) => match o.keys().find(|k| !ok.contains(&k.as_str())) {
            Some(k) => Err(format!("unknown argument {k}")),
            None => Ok(()),
        },
    }
}

/// Run a tool. None when the tool does not exist.
pub fn call(name: &str, args: &Value, runner: Runner) -> Option<Value> {
    let args = if args.is_null() { json!({}) } else { args.clone() };
    match name {
        "hunt" => hunt(&args, runner),
        "status" => status(&args, runner),
        "advisory_show" => advisory_show(&args, runner),
        "hosts" => {
            if let Err(e) = known_keys(&args, &[]) {
                return bad(&e);
            }
            let r = runner(&["hosts".into(), "list".into()]);
            Some(finish("hosts", &r, &[0], first_line))
        }
        "evidence_summary" => evidence_summary(&args, runner),
        "claimcheck" => claimcheck(&args, runner),
        _ => None,
    }
}

fn first_line(o: &str) -> String {
    o.lines().next().unwrap_or("").to_string()
}

/// Exit codes in `ok` are answers; anything else is a tool error carrying br's own message.
fn finish(what: &str, r: &Ran, ok: &[i32], summarise: impl Fn(&str) -> String) -> Value {
    if ok.contains(&r.code) {
        text_result(&format!("br {what}: {}", summarise(&r.out)), &r.out, false)
    } else {
        let msg = if r.err.trim().is_empty() { r.out.clone() } else { r.err.clone() };
        text_result(&format!("br {what} failed (exit {}): {}", r.code, msg.trim().lines().next().unwrap_or("")), &msg, true)
    }
}

fn hunt(args: &Value, runner: Runner) -> Option<Value> {
    if let Err(e) = known_keys(args, &["indicators", "advisory", "path", "repo", "owner", "host", "now", "only", "window"]) {
        return bad(&e);
    }
    let mut argv: Vec<String> = vec!["hunt".into(), "--format".into(), "json".into(), "--fail-if".into(), "found".into()];
    for (key, flag) in [("advisory", "--advisory"), ("path", "--path"), ("repo", "--repo"), ("owner", "--owner"), ("host", "--host"), ("only", "--only"), ("window", "--window")] {
        match opt_str(args, key) {
            Ok(Some(v)) => argv.push(format!("{flag}={v}")),
            Ok(None) => {}
            Err(e) => return bad(&e),
        }
    }
    match opt_bool(args, "now") {
        Ok(true) => argv.push("--now".into()),
        Ok(false) => {}
        Err(e) => return bad(&e),
    }
    let mut n = 0;
    match args.get("indicators") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            argv.push("--".into());
            for i in items {
                match i.as_str() {
                    Some(s) if !s.is_empty() && !s.starts_with('-') => {
                        argv.push(s.to_string());
                        n += 1;
                    }
                    _ => return bad("indicators must be non-empty strings that do not start with '-'"),
                }
            }
        }
        Some(_) => return bad("indicators must be an array of strings"),
    }
    if n == 0 && args.get("advisory").and_then(Value::as_str).is_none_or(str::is_empty) {
        return bad("give indicators or an advisory");
    }
    let r = runner(&argv);
    // 0 clear and 10 found are answers; 3 and 11 are not asked for; anything else is br's own error
    Some(finish("hunt", &r, &[0, 10], hunt_summary))
}

/// One line from br's hunt JSON: the verdict and the counts a reader must not skip.
pub fn hunt_summary(out: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(out) else { return "answered (output is not JSON)".into() };
    let c = &v["counts"];
    let n = |k: &str| c[k].as_u64().unwrap_or(0);
    let gaps = n("gaps");
    let mut s = format!("{}: {} findings in {} places, {} secrets", v["verdict"].as_str().unwrap_or("unknown"), n("findings"), n("places"), n("secrets"));
    if gaps > 0 {
        s += &format!("; {gaps} sources NOT CHECKED (a clear answer does not cover them)");
    }
    if let Some(a) = v["query"]["index_as_of"].as_str() {
        s += &format!("; index as of {a}");
    }
    s
}

fn claimcheck(args: &Value, runner: Runner) -> Option<Value> {
    if let Err(e) = known_keys(args, &["path", "repo", "org", "max_names", "as_of"]) {
        return bad(&e);
    }
    let mut argv: Vec<String> = vec!["claimcheck".into(), "--format".into(), "json".into(), "--fail-if".into(), "exposed".into()];
    for (key, flag) in [("path", "--path"), ("repo", "--repo"), ("org", "--org"), ("as_of", "--as-of")] {
        match opt_str(args, key) {
            Ok(Some(v)) => argv.push(format!("{flag}={v}")),
            Ok(None) => {}
            Err(e) => return bad(&e),
        }
    }
    match args.get("max_names") {
        None | Some(Value::Null) => {}
        Some(v) => match v.as_u64() {
            Some(n) => argv.push(format!("--max-names={n}")),
            None => return bad("max_names must be a whole number, 0 or more"),
        },
    }
    let r = runner(&argv);
    // 0 clear, 3 nothing could be checked (--fail-if cannot say none is exposed) and 10 exposed are answers; anything else is br's own error
    Some(finish("claimcheck", &r, &[0, 3, 10], claimcheck_summary))
}

/// One line from br's claimcheck JSON: the verdict, the counts and the gaps a reader must not skip.
pub fn claimcheck_summary(out: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(out) else { return "answered (output is not JSON)".into() };
    let n = |k: &str| v["counts"][k].as_u64().unwrap_or(0);
    // the CLI's own headline carries the verdict and every count, in names
    let mut s = match v["headline"].as_str() {
        Some(h) => h.to_string(),
        None => format!(
            "{}: {} exposed ({} squatted, {} free, {} scope unclaimed), {} shown to be yours",
            v["verdict"].as_str().unwrap_or("unknown"),
            v["exposed"].as_u64().unwrap_or(0),
            n("squatted"),
            n("free"),
            n("scope_unclaimed"),
            n("ours")
        ),
    };
    let gaps = v["gaps"].as_array().map_or(0, |g| g.len());
    if gaps > 0 || n("not_checked") > 0 {
        s += &format!("; NOT CHECKED names are not clear ({} not checked; read counts and gaps)", n("not_checked"));
    }
    if n("ours_declared") > 0 {
        s += &format!("; {} name(s) are ours only by the publisher's word", n("ours_declared"));
    }
    s
}

fn status(args: &Value, runner: Runner) -> Option<Value> {
    if let Err(e) = known_keys(args, &["all", "owner"]) {
        return bad(&e);
    }
    let mut argv: Vec<String> = vec!["status".into()];
    match opt_bool(args, "all") {
        Ok(true) => argv.push("--all".into()),
        Ok(false) => {}
        Err(e) => return bad(&e),
    }
    match opt_str(args, "owner") {
        Ok(Some(o)) => argv.push(format!("--owner={o}")),
        Ok(None) => {}
        Err(e) => return bad(&e),
    }
    let r = runner(&argv);
    Some(finish("status", &r, &[0], first_line))
}

fn advisory_show(args: &Value, runner: Runner) -> Option<Value> {
    if let Err(e) = known_keys(args, &["id"]) {
        return bad(&e);
    }
    let id = match opt_str(args, "id") {
        Ok(Some(i)) => i,
        Ok(None) => return bad("id is required"),
        Err(e) => return bad(&e),
    };
    let r = runner(&["advisory".into(), "show".into(), "--".into(), id.clone()]);
    Some(finish(&format!("advisory show {id}"), &r, &[0], first_line))
}

fn evidence_summary(args: &Value, runner: Runner) -> Option<Value> {
    if let Err(e) = known_keys(args, &["file"]) {
        return bad(&e);
    }
    let file = match opt_str(args, "file") {
        Ok(Some(f)) => f,
        Ok(None) => return bad("file is required"),
        Err(e) => return bad(&e),
    };
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => return Some(text_result(&format!("cannot read {file}: {e}"), "", true)),
    };
    let doc: Value = match serde_json::from_str(&text) {
        Ok(d) => d,
        Err(e) => return Some(text_result(&format!("{file} is not JSON: {e}"), "", true)),
    };
    if doc["schema"].as_str() != Some("br-evidence/1") {
        return Some(text_result(&format!("{file} is not a br evidence file (schema is {})", doc["schema"]), "", true));
    }
    let v = runner(&["verify".into(), "--".into(), file.clone()]);
    let seal = format!("seal: {}", v.out.lines().chain(v.err.lines()).next().unwrap_or("no answer").trim());
    let claim = &doc["claim"];
    let nc = doc["not_checked"].as_array().map_or(0, Vec::len);
    let summary = format!(
        "evidence {}: {} ({} findings in {} places), {} not checked; {seal}",
        claim["result"].as_str().unwrap_or("unknown"),
        claim["verdict"].as_str().unwrap_or("unknown"),
        claim["findings"].as_u64().unwrap_or(0),
        claim["places"].as_u64().unwrap_or(0),
        nc
    );
    let body = json!({
        "file": file, "schema": doc["schema"], "generated_at": doc["generated_at"], "tool": doc["tool"], "case_id": doc["case_id"],
        "question": {"iocs": doc["question"]["iocs"], "window": doc["question"]["window"], "asked": doc["question"]["asked"]},
        "claim": {"result": claim["result"], "verdict": claim["verdict"], "statement": claim["statement"], "findings": claim["findings"], "places": claim["places"],
                  "possible_hosts": claim["possible_hosts"], "indicators_with_hits": claim["indicators_with_hits"]},
        "secrets_exposed": doc["secrets_exposed"], "not_checked": doc["not_checked"], "not_checked_count": nc, "gaps": doc["gaps"],
        "limits": doc["limits"], "index_as_of": doc["index_as_of"], "seal_check": seal, "seal_exit": v.code,
    });
    Some(text_result(&summary, &serde_json::to_string_pretty(&body).unwrap_or_default(), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub(args: &[String]) -> Ran {
        let a = args.join(" ");
        if a.starts_with("hunt ") {
            let found = a.contains("npm:bad");
            Ran {
                code: if found { 10 } else { 0 },
                out: json!({"query": {"index_as_of": "2026-05-12T00:00:00Z"}, "verdict": if found { "FOUND" } else { "CLEAR WITH GAPS" },
                    "counts": {"findings": if found { 2 } else { 0 }, "places": 1, "secrets": 0, "gaps": 3}, "argv": a})
                .to_string(),
                err: String::new(),
            }
        } else if a.starts_with("claimcheck ") {
            Ran {
                code: 10,
                out: json!({"verdict": "EXPOSED", "headline": "EXPOSED: 2 names (1 squatted, 1 free); 1 name not checked; 3 shown to be yours (3 verified by the registry)", "exposed": 2,
                    "counts": {"squatted": 1, "free": 1, "scope_unclaimed": 0, "ours": 3, "not_checked": 1}, "gaps": [{"what": "1 name on pypi.org"}], "argv": a})
                .to_string(),
                err: String::new(),
            }
        } else if a.starts_with("advisory show -- NOPE") {
            Ran { code: 1, out: String::new(), err: "error: advisory NOPE not found\nhint: x\n".into() }
        } else if a.starts_with("verify") {
            Ran { code: 0, out: "OK: f unmodified\n".into(), err: String::new() }
        } else {
            Ran { code: 0, out: format!("ran {a}\nmore\n"), err: String::new() }
        }
    }

    fn rpc(lines: &[&str]) -> Vec<Value> {
        let input = lines.join("\n") + "\n";
        let mut out = Vec::new();
        serve(std::io::Cursor::new(input), &mut out, &stub).unwrap();
        String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn a_scripted_session_initializes_lists_and_calls() {
        let r = rpc(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hunt","arguments":{"indicators":["npm:bad@1.0.0"],"now":true,"only":"repos"}}}"#,
            r#"{"jsonrpc":"2.0","id":"x","method":"ping"}"#,
        ]);
        assert_eq!(r.len(), 4, "the notification gets no reply: {r:?}");
        assert_eq!(r[0]["id"], 1);
        assert_eq!(r[0]["result"]["protocolVersion"], "2025-06-18");
        assert!(r[0]["result"]["capabilities"]["tools"].is_object());
        assert_eq!(r[0]["result"]["serverInfo"]["name"], "blastradius");
        let names: Vec<&str> = r[1]["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["hunt", "status", "advisory_show", "hosts", "evidence_summary", "claimcheck"]);
        let hunt = &r[2]["result"];
        assert_eq!(hunt["isError"], false);
        assert!(hunt["content"][0]["text"].as_str().unwrap().contains("FOUND: 2 findings in 1 places"));
        assert!(hunt["content"][0]["text"].as_str().unwrap().contains("3 sources NOT CHECKED"));
        let argv = hunt["content"][1]["text"].as_str().unwrap();
        assert!(argv.contains("--format json") && argv.contains("--now") && argv.contains("--only=repos") && argv.contains("-- npm:bad@1.0.0"), "{argv}");
        assert_eq!(r[3]["id"], "x");
        assert_eq!(r[3]["result"], json!({}));
    }

    #[test]
    fn the_claimcheck_tool_says_it_reads_public_registries_and_writes_nothing() {
        let t = tools().as_array().unwrap().iter().find(|t| t["name"] == "claimcheck").unwrap().clone();
        let d = t["description"].as_str().unwrap();
        assert!(d.contains("read-only GETs to public registries"), "{d}");
        assert!(d.contains("writes nothing") && d.contains("never publishes or claims"), "{d}");
        assert_eq!(t["annotations"]["readOnlyHint"], true);
        assert_eq!(t["annotations"]["openWorldHint"], true);
        let r = call("claimcheck", &json!({"path": "./co", "org": "acme", "max_names": 50, "as_of": "2026-06-09"}), &stub).unwrap();
        // exit 10 (exposed) is an answer, not an error; the gap is in the summary
        assert_eq!(r["isError"], false);
        let sum = r["content"][0]["text"].as_str().unwrap();
        assert!(sum.contains("EXPOSED: 2 names (1 squatted, 1 free); 1 name not checked") && sum.contains("NOT CHECKED names are not clear"), "{sum}");
        let argv = r["content"][1]["text"].as_str().unwrap();
        assert!(argv.contains("claimcheck --format json --fail-if exposed --path=./co --org=acme --as-of=2026-06-09 --max-names=50"), "{argv}");
        assert!(!argv.contains("--record"), "{argv}");
    }

    #[test]
    fn the_claimcheck_max_names_schema_is_the_clis_own() {
        let t = tools().as_array().unwrap().iter().find(|t| t["name"] == "claimcheck").unwrap().clone();
        // the CLI accepts 0 (ask nothing), so the schema's minimum is 0, not 1
        assert_eq!(t["inputSchema"]["properties"]["max_names"]["minimum"], 0);
        assert!(t["inputSchema"]["properties"]["max_names"]["description"].as_str().unwrap().contains("400"));
        let r = call("claimcheck", &json!({"max_names": 0}), &stub).unwrap();
        assert_eq!(r["isError"], false, "{r}");
        let argv = r["content"][1]["text"].as_str().unwrap();
        assert!(argv.contains("--max-names=0"), "{argv}");
        // exit 3 (nothing checked under --fail-if) is an answer too
        let r3 = call("claimcheck", &json!({}), &|_: &[String]| Ran {
            code: 3,
            out: json!({"verdict": "CLEAR WITH GAPS", "headline": "CLEAR WITH GAPS: no name is exposed; 4 names not checked", "counts": {"not_checked": 4}, "gaps": [{}]}).to_string(),
            err: "no name was checked".into(),
        })
        .unwrap();
        assert_eq!(r3["isError"], false, "{r3}");
        assert!(r3["content"][0]["text"].as_str().unwrap().contains("4 names not checked"));
    }

    #[test]
    fn every_tool_has_an_object_schema_and_says_it_is_read_only() {
        for t in tools().as_array().unwrap() {
            assert_eq!(t["inputSchema"]["type"], "object", "{t}");
            assert!(t["inputSchema"]["properties"].is_object());
            assert_eq!(t["annotations"]["readOnlyHint"], true);
            assert!(t["description"].as_str().unwrap().contains("not ") || t["description"].as_str().unwrap().contains("never"), "{t}");
        }
        let hunt = tools()[0].clone();
        assert!(hunt["description"].as_str().unwrap().contains("does not scan, write, notify or purge"));
    }

    #[test]
    fn the_version_is_negotiated() {
        let r = rpc(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2031-01-01"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}"#,
        ]);
        assert_eq!(r[0]["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(r[1]["result"]["protocolVersion"], LATEST);
        assert_eq!(r[2]["error"]["code"], -32602);
    }

    #[test]
    fn protocol_errors_have_the_json_rpc_codes() {
        let r = rpc(&[
            "not json",
            r#"{"jsonrpc":"2.0","id":1,"method":"nope/nothing"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}"#,
            r#"[]"#,
            r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#,
            r#"5"#,
        ]);
        assert_eq!(r[0]["error"]["code"], -32700);
        assert_eq!(r[0]["id"], Value::Null);
        assert_eq!(r[1]["error"]["code"], -32601);
        assert_eq!(r[2]["error"]["code"], -32602);
        assert!(r[2]["error"]["message"].as_str().unwrap().contains("unknown tool: scan"));
        assert_eq!(r[3]["error"]["code"], -32602);
        assert_eq!(r[4]["error"]["code"], -32600);
        assert_eq!(r[5]["error"]["code"], -32600);
        assert_eq!(r[6]["error"]["code"], -32600);
    }

    #[test]
    fn a_batch_answers_with_an_array_and_skips_notifications() {
        let r = rpc(&[r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"ping"}]"#]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].as_array().unwrap().len(), 2);
    }

    #[test]
    fn the_server_never_offers_a_write_or_a_scan() {
        let all: Vec<String> = tools().as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        for banned in ["scan", "init", "notify", "purge", "fix", "import", "evidence", "note", "sql"] {
            assert!(!all.iter().any(|n| n == banned), "{banned} must not be a tool");
        }
        // and the commands the tools build are fixed: a tool cannot reach another subcommand
        let seen = std::cell::RefCell::new(Vec::<String>::new());
        let spy = |a: &[String]| {
            seen.borrow_mut().push(a[0].clone());
            Ran { code: 0, out: "{}".into(), err: String::new() }
        };
        for (n, a) in [("hunt", json!({"indicators": ["npm:a@1"]})), ("status", json!({})), ("advisory_show", json!({"id": "GHSA-1"})), ("hosts", json!({})), ("claimcheck", json!({"path": "."}))] {
            call(n, &a, &spy).unwrap();
        }
        assert_eq!(*seen.borrow(), ["hunt", "status", "advisory", "hosts", "claimcheck"]);
    }

    #[test]
    fn arguments_cannot_smuggle_a_flag() {
        for (n, a) in [
            ("hunt", json!({"indicators": ["--live"]})),
            ("hunt", json!({"indicators": ["npm:a@1"], "path": "--yara"})),
            ("hunt", json!({"indicators": ["npm:a@1"], "live": true})),
            ("hunt", json!({})),
            ("hunt", json!({"indicators": "npm:a@1"})),
            ("hunt", json!({"indicators": [3]})),
            ("hunt", json!({"indicators": ["npm:a@1"], "now": "yes"})),
            ("status", json!({"owner": "-x"})),
            ("status", json!({"nope": 1})),
            ("advisory_show", json!({})),
            ("advisory_show", json!({"id": "--help"})),
            ("hosts", json!({"remove": "x"})),
            ("evidence_summary", json!({})),
            ("claimcheck", json!({"path": "--format"})),
            ("claimcheck", json!({"max_names": -1})),
            ("claimcheck", json!({"max_names": "all"})),
            ("claimcheck", json!({"fail_if": "exposed"})),
            ("claimcheck", json!({"record": true})),
            ("claimcheck", json!({"as_of": "--record"})),
        ] {
            let r = call(n, &a, &stub).unwrap();
            assert_eq!(r["isError"], true, "{n} {a}: {r}");
            assert!(r["content"][0]["text"].as_str().unwrap().starts_with("invalid arguments"), "{n} {a}: {r}");
        }
    }

    #[test]
    fn a_br_failure_is_a_tool_error_with_its_message() {
        let r = call("advisory_show", &json!({"id": "NOPE"}), &stub).unwrap();
        assert_eq!(r["isError"], true);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("advisory NOPE not found"));
        let r = call("hunt", &json!({"indicators": ["npm:a@1"]}), &|_: &[String]| Ran { code: 5, out: String::new(), err: "error: no index\nhint: br init\n".into() }).unwrap();
        assert_eq!(r["isError"], true);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("exit 5"));
    }

    #[test]
    fn found_and_clear_are_both_answers_not_errors() {
        assert_eq!(call("hunt", &json!({"indicators": ["npm:bad@1"]}), &stub).unwrap()["isError"], false);
        assert_eq!(call("hunt", &json!({"indicators": ["npm:fine@1"]}), &stub).unwrap()["isError"], false);
        let r = call("status", &json!({"all": true, "owner": "web"}), &stub).unwrap();
        assert!(r["content"][1]["text"].as_str().unwrap().contains("status --all --owner=web"));
    }

    #[test]
    fn evidence_summary_reads_the_file_and_asks_verify_about_the_seal() {
        let d = std::env::temp_dir().join(format!("br-mcp-ev-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("ev.json");
        std::fs::write(
            &f,
            json!({"schema": "br-evidence/1", "claim": {"result": "found", "verdict": "FOUND", "findings": 4, "places": 2},
                "not_checked": [{"scope": "a"}], "question": {"iocs": ["npm:x@1"]}, "gaps": "1 source"})
            .to_string(),
        )
        .unwrap();
        let r = call("evidence_summary", &json!({"file": f.to_str().unwrap()}), &stub).unwrap();
        assert_eq!(r["isError"], false);
        let t = r["content"][0]["text"].as_str().unwrap();
        assert!(t.contains("found: FOUND (4 findings in 2 places), 1 not checked; seal: OK: f unmodified"), "{t}");
        let body: Value = serde_json::from_str(r["content"][1]["text"].as_str().unwrap()).unwrap();
        assert_eq!(body["not_checked_count"], 1);
        std::fs::write(&f, r#"{"schema":"other"}"#).unwrap();
        assert_eq!(call("evidence_summary", &json!({"file": f.to_str().unwrap()}), &stub).unwrap()["isError"], true);
        std::fs::write(&f, "nope").unwrap();
        assert_eq!(call("evidence_summary", &json!({"file": f.to_str().unwrap()}), &stub).unwrap()["isError"], true);
        assert_eq!(call("evidence_summary", &json!({"file": d.join("missing").to_str().unwrap()}), &stub).unwrap()["isError"], true);
        let _ = std::fs::remove_dir_all(&d);
    }
}
