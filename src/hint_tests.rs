//! Every `br ...` command a hint prints must be one the CLI parser accepts. The hints are string literals in the
//! sources that print them; this reads them all, takes each `br SUBCOMMAND ...` up to the end of the command, and parses it.
//! A hint that names a flag that does not exist, or leaves out an argument a flag needs, fails here instead of in a user's shell.

use clap::{CommandFactory, Parser};
use regex::Regex;

use crate::cli::Cli;

/// Words that end a command inside a sentence ("br scan --stale to refresh ...").
const STOP: &[&str] = &[
    "without",
    "to",
    "then",
    "and",
    "or",
    "for",
    "first",
    "before",
    "after",
    "with",
    "on",
    "in",
    "is",
    "are",
    "if",
    "when",
    "so",
    "lists",
    "list",
    "shows",
    "show",
    "reads",
    "run",
    "from",
    "that",
    "which",
    "not",
    "can",
    "cannot",
    "plans",
    "covers",
    "writes",
    "needs",
    "does",
    "do",
    "only",
    "also",
    "by",
    "it",
    "this",
    "the",
    "a",
    "an",
    "as",
    "at",
    "has",
    "have",
    "uses",
    "use",
    "takes",
    "gives",
    "adds",
    "says",
    "names",
    "rescans",
    "refreshes",
    "ties",
    "see",
    "again",
];

fn sources(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name.contains("tests") || name == "scan_brx_tests.rs" {
                continue;
            }
            out.push((p.display().to_string(), std::fs::read_to_string(&p).unwrap()));
        }
    }
}

fn tokens_of(rest: &str) -> Vec<String> {
    let mut out = vec![];
    // a printed `\n` ends the line the command is on; a closing quote ends the string it is in
    let rest = rest.split("\\n").next().unwrap_or("");
    for raw in rest.split_whitespace() {
        let closes = raw.contains('"');
        let raw = raw.split('"').next().unwrap_or("");
        let mut t = raw.to_string();
        // a placeholder `{name}` is some value
        let ph = Regex::new(r"\{[^}]*\}").unwrap();
        t = ph.replace_all(&t, "X").to_string();
        if t.starts_with('(') || t.starts_with('"') || t == "|" || t == "&&" || t == "—" || t.starts_with("...") {
            break;
        }
        let end = t.ends_with([')', ';', ',', '.', ':', '"', '`']);
        let t = t.trim_end_matches([')', ';', ',', '.', ':', '"', '`']).trim_matches('\'').to_string();
        if t.is_empty() || STOP.contains(&t.as_str()) {
            break;
        }
        out.push(t);
        if end || closes {
            break;
        }
    }
    out
}

#[test]
fn every_printed_br_command_parses() {
    let subs: Vec<String> = Cli::command().get_subcommands().map(|s| s.get_name().to_string()).collect();
    let re = Regex::new(&format!(r"\bbr ({})\b([^\n]*)", subs.join("|"))).unwrap();
    let mut files = vec![];
    sources(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    let mut bad: Vec<String> = vec![];
    let mut seen = 0;
    for (name, text) in &files {
        for line in text.lines() {
            let l = line.trim_start();
            // only text a user can read: string literals (not comments, which are not printed)
            if l.starts_with("//") || !l.contains('"') {
                continue;
            }
            for m in re.captures_iter(line) {
                let sub = &m[1];
                // a command in a sentence ends at the first word that is not part of it
                let toks = tokens_of(&m[2]);
                let mut argv: Vec<String> = vec!["br".into(), sub.to_string()];
                argv.extend(toks.iter().cloned());
                let flags: Vec<&String> = toks.iter().filter(|t| t.starts_with('-')).collect();
                let mut ok = false;
                for k in (0..=toks.len()).rev() {
                    let mut a: Vec<String> = vec!["br".into(), sub.to_string()];
                    a.extend(toks[..k].iter().cloned());
                    if Cli::try_parse_from(&a).is_ok() {
                        // every flag the hint wrote is inside what parsed
                        ok = flags.iter().all(|f| toks[..k].contains(f));
                        break;
                    }
                }
                seen += 1;
                if !ok {
                    bad.push(format!("{name}: br {sub} {}", toks.join(" ")));
                }
            }
        }
    }
    assert!(seen > 100, "the scan found only {seen} commands: the extraction is broken");
    assert!(bad.is_empty(), "{} printed commands do not parse:\n{}", bad.len(), bad.join("\n"));
}
