//! Small helpers shared by the collectors and the index-writing commands: times, tables, globs.

use regex::Regex;

use crate::error::{BrError, BrResult};

// ---- times -------------------------------------------------------------------------------------
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Epoch seconds -> `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso(t: i64) -> String {
    let days = t.div_euclid(86400);
    let rem = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `YYYY-MM-DDTHH:MM[:SS](Z|+00:00)` or a bare date -> epoch seconds.
pub fn epoch(s: &str) -> Option<i64> {
    let re = Regex::new(r"^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d))?(?:\.\d+)?)?\s*(Z|[+-]\d\d:?\d\d)?$").unwrap();
    let c = re.captures(s.trim())?;
    let g = |i: usize| c.get(i).map(|m| m.as_str().parse::<i64>().unwrap_or(0)).unwrap_or(0);
    let mut t = days_from_civil(g(1), g(2), g(3)) * 86400 + g(4) * 3600 + g(5) * 60 + g(6);
    if let Some(z) = c.get(7) {
        let z = z.as_str();
        if z != "Z" {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits: String = z[1..].chars().filter(|c| c.is_ascii_digit()).collect();
            let (h, m) = (digits[..2].parse::<i64>().unwrap_or(0), digits[2..].parse::<i64>().unwrap_or(0));
            t -= sign * (h * 3600 + m * 60);
        }
    }
    Some(t)
}

/// Any time an API gives (`2026-05-11T14:00:00Z`, `...+00:00`, fractional seconds) as the long UTC form.
pub fn norm_api_time(s: &str) -> Option<String> {
    epoch(s).map(iso)
}

/// Accepts `2026-05-11T14:00Z`, `2026-05-11T14:00:00Z`, `2026-05-11 14:00 UTC`, `2026-05-11T16:00+02:00` and a bare
/// `2026-05-11`; returns the long UTC form. A date without a year is a usage error (no year is ever guessed), and a
/// time of day needs `Z`, `UTC` or an offset because a wall clock reading means different instants in different places.
pub fn norm_iso(s: &str) -> BrResult<String> {
    let raw = s.trim();
    let full = "write the full form 2026-05-11T14:00:00Z";
    if Regex::new(r"^\d\d-\d\d([T ]|$)").unwrap().is_match(raw) {
        return Err(BrError::new(format!("\"{raw}\" has no year"), Some(full)));
    }
    let re = Regex::new(r"^(\d{4}-\d\d-\d\d)(?:[T ](\d\d:\d\d)(:\d\d)?(?:\.\d+)?\s*(Z|UTC|[+-]\d\d:?\d\d)?)?$").unwrap();
    let Some(c) = re.captures(raw) else {
        return Err(BrError::new(format!("\"{raw}\" is not a time"), Some(full)));
    };
    if c.get(2).is_some() && c.get(4).is_none() {
        return Err(BrError::new(format!("\"{raw}\" has a time of day but no zone"), Some("add Z for UTC or an offset such as +02:00: 2026-05-11T14:00:00Z")));
    }
    let zone = c.get(4).map(|m| m.as_str()).unwrap_or("Z");
    let zone = if zone == "UTC" { "Z" } else { zone };
    let text = format!("{}T{}{}{}", &c[1], c.get(2).map(|m| m.as_str()).unwrap_or("00:00"), c.get(3).map(|m| m.as_str()).unwrap_or(":00"), zone);
    match epoch(&text) {
        Some(t) => {
            // an impossible date (month 13, day 40) is not a time either
            let out = iso(t);
            if zone == "Z" && out[..10] != c[1] {
                return Err(BrError::new(format!("\"{raw}\" is not a real date"), Some(full)));
            }
            Ok(out)
        }
        None => Err(BrError::new(format!("\"{raw}\" is not a time"), Some(full))),
    }
}

pub fn system_now() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    iso(t)
}

/// Table time: `MM-DD HH:MM` (UTC).
pub fn fmt(s: &str) -> String {
    match epoch(s) {
        None => "-".into(),
        Some(t) => {
            let i = iso(t);
            format!("{} {}", &i[5..10], &i[11..16])
        }
    }
}

pub fn age_str(later: &str, earlier: &str) -> String {
    let secs = epoch(later).unwrap_or(0) - epoch(earlier).unwrap_or(0);
    if secs < 90 {
        return if secs < 60 { "just now".into() } else { "1m".into() };
    }
    let m = secs / 60;
    if m < 120 {
        return format!("{m}m");
    }
    let h = m / 60;
    if h < 48 {
        return if m % 60 != 0 { format!("{h}h{:02}m", m % 60) } else { format!("{h}h") };
    }
    if h % 24 != 0 {
        format!("{}d{:02}h", h / 24, h % 24)
    } else {
        format!("{}d", h / 24)
    }
}

pub fn parse_dur(s: &str) -> BrResult<i64> {
    let re = Regex::new(r"^(\d+)\s*([smhd])$").unwrap();
    match re.captures(s.trim()) {
        None => Err(BrError::new(format!("\"{s}\" is not a duration"), Some("write a number and a unit, e.g. 24h, 90m, 2d"))),
        Some(c) => {
            let n: i64 = c[1].parse().unwrap_or(0);
            Ok(n * match &c[2] {
                "s" => 1,
                "m" => 60,
                "h" => 3600,
                _ => 86400,
            })
        }
    }
}

/// The stale threshold as written: BR_STALE_AFTER, else `stale_after` in config.yaml, else 24h.
pub fn stale_label() -> String {
    if let Some(v) = std::env::var("BR_STALE_AFTER").ok().filter(|s| !s.is_empty()) {
        return v;
    }
    crate::collect::config::stale_after_setting().unwrap_or_else(|| "24h".into())
}

pub fn stale_threshold() -> BrResult<i64> {
    let raw = stale_label();
    parse_dur(&raw).map_err(|_| BrError::new(format!("BR_STALE_AFTER=\"{raw}\" is not a duration"), Some("write a number and a unit, e.g. 24h or 2d")))
}

pub fn is_stale(now: &str, indexed_at: &str) -> BrResult<bool> {
    Ok(epoch(now).unwrap_or(0) - epoch(indexed_at).unwrap_or(0) > stale_threshold()?)
}

// ---- text ---------------------------------------------------------------------------------------
pub fn plural(n: usize, one: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {one}s")
    }
}

/// "9 repos and 1 CI artifact": counts with their nouns, zero counts left out. The one way claimcheck and status name their sources.
pub fn count_words(parts: &[(usize, &str, &str)]) -> String {
    let v: Vec<String> = parts.iter().filter(|(n, _, _)| *n > 0).map(|(n, one, many)| format!("{n} {}", if *n == 1 { one } else { many })).collect();
    match v.len() {
        0 => "no sources".to_string(),
        1 => v[0].clone(),
        _ => format!("{} and {}", v[..v.len() - 1].join(", "), v[v.len() - 1]),
    }
}

pub fn plural2(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn secs(n: u64) -> String {
    if n < 60 {
        format!("{n}s")
    } else {
        format!("{}m{:02}s", n / 60, n % 60)
    }
}

/// Left-aligned columns separated by two spaces; trailing spaces trimmed.
pub fn table(headers: &[&str], rows: &[Vec<String>], indent: usize) -> Vec<String> {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let pad = " ".repeat(indent);
    let line = |cells: Vec<&str>| -> String {
        let s = cells.iter().enumerate().map(|(i, c)| format!("{c}{}", " ".repeat(widths[i] - c.chars().count()))).collect::<Vec<_>>().join("  ");
        format!("{pad}{}", s.trim_end())
    };
    let mut out = vec![line(headers.to_vec())];
    for r in rows {
        out.push(line(r.iter().map(|s| s.as_str()).collect()));
    }
    out
}

// ---- globs and paths ------------------------------------------------------------------------------
pub fn glob_re(g: &str) -> Regex {
    let b = g.as_bytes();
    let mut out = String::from("^");
    let mut i = 0;
    while i < b.len() {
        if g[i..].starts_with("**/") {
            out.push_str("(?:.*/)?");
            i += 3;
        } else if g[i..].starts_with("**") {
            out.push_str(".*");
            i += 2;
        } else if b[i] == b'*' {
            out.push_str("[^/]*");
            i += 1;
        } else if b[i] == b'?' {
            out.push_str("[^/]");
            i += 1;
        } else {
            let ch = g[i..].chars().next().unwrap();
            out.push_str(&regex::escape(&ch.to_string()));
            i += ch.len_utf8();
        }
    }
    out.push('$');
    Regex::new(&out).unwrap()
}

pub struct Globs {
    items: Vec<Option<Regex>>, // None = "executables"
}

impl Globs {
    pub fn new<S: AsRef<str>>(globs: &[S]) -> Globs {
        Globs { items: globs.iter().map(|g| if g.as_ref() == "executables" { None } else { Some(glob_re(g.as_ref())) }).collect() }
    }
    /// `exec` is whether the file's mode has an execute bit.
    pub fn matches(&self, path: &str) -> bool {
        let base = path.rsplit('/').next().unwrap_or(path);
        self.items.iter().any(|r| match r {
            None => !base.contains('.') && !NOT_EXECUTABLE.contains(&base),
            Some(r) => r.is_match(path),
        })
    }
}

pub fn under(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    path == root || path.starts_with(&format!("{root}/"))
}

/// Extension-less names that are text, not programs.
const NOT_EXECUTABLE: &[&str] = &[
    "LICENSE",
    "LICENCE",
    "README",
    "NOTICE",
    "AUTHORS",
    "CHANGELOG",
    "CONTRIBUTING",
    "Makefile",
    "Dockerfile",
    "Gemfile",
    "Rakefile",
    "Procfile",
    "OWNERS",
    "CODEOWNERS",
    "VERSION",
    "COPYING",
    "PATENTS",
];

pub const DEFAULT_HASH_FILTER: &[&str] = &[
    "**/*.js",
    "**/*.py",
    "**/*.sh",
    "**/*.class",
    "**/*.jar",
    "**/*.so",
    "**/*.dll",
    "**/bin/*",
    "**/node_modules/**",
    "**/site-packages/**",
    "**/dist-packages/**",
    "**/go/pkg/mod/**",
    "**/_actions/**",
    "**/hostedtoolcache/**",
    "**/_work/_tool/**",
    "**/*.exe",
    "**/*.dylib",
    "**/*.so.*",
    "**/*.node",
    "**/*.mjs",
    "**/*.cjs",
    "**/*.ps1",
    "**/*.bat",
    "**/*.cmd",
    "**/*.whl",
    "**/*.pyc",
    "**/*.pyd",
    "**/*.msi",
    "**/*.vbs",
    "executables",
];

/// Python's json.dumps(v, indent=indent, sort_keys=sort) with default separators and ensure_ascii.
pub fn py_dumps(v: &serde_json::Value, indent: Option<usize>, sort: bool) -> String {
    let mut out = String::new();
    py_val(v, indent, sort, 0, &mut out);
    out
}

fn py_str(s: &str, out: &mut String) {
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

fn py_val(v: &serde_json::Value, indent: Option<usize>, sort: bool, level: usize, out: &mut String) {
    use serde_json::Value::*;
    let nl = |lvl: usize, out: &mut std::string::String| {
        if let Some(n) = indent {
            out.push('\n');
            out.push_str(&" ".repeat(n * lvl));
        }
    };
    let (item_sep, key_sep) = if indent.is_some() { (",", ": ") } else { (", ", ": ") };
    match v {
        Null => out.push_str("null"),
        Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Number(n) => out.push_str(&n.to_string()),
        String(s) => py_str(s, out),
        Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                nl(level + 1, out);
                py_val(x, indent, sort, level + 1, out);
            }
            nl(level, out);
            out.push(']');
        }
        Object(m) => {
            if m.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            let mut keys: Vec<&std::string::String> = m.keys().collect();
            if sort {
                keys.sort();
            }
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                nl(level + 1, out);
                py_str(k, out);
                out.push_str(key_sep);
                py_val(&m[*k], indent, sort, level + 1, out);
            }
            nl(level, out);
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_dates_are_refused_and_offsets_become_utc() {
        assert!(norm_iso("05-11T14:00:00Z").is_err());
        assert_eq!(norm_iso("2026-05-11T16:00:00+02:00").unwrap(), "2026-05-11T14:00:00Z");
        assert_eq!(norm_iso("2026-05-11 14:00:00 UTC").unwrap(), "2026-05-11T14:00:00Z");
        assert!(norm_iso("2026-05-11T14:00:00").is_err());
        assert!(norm_iso("2026-02-30T00:00:00Z").is_err());
    }

    use super::*;
    #[test]
    fn times_round_trip() {
        assert_eq!(iso(epoch("2026-05-11T14:00:00Z").unwrap()), "2026-05-11T14:00:00Z");
        assert_eq!(norm_api_time("2026-05-11T16:00:00+02:00").unwrap(), "2026-05-11T14:00:00Z");
        assert_eq!(age_str("2026-08-21T09:00:00Z", "2026-08-14T10:00:00Z"), "6d23h");
        assert_eq!(fmt("2026-08-19T16:20:00Z"), "08-19 16:20");
    }
    #[test]
    fn globs() {
        let g = Globs::new(DEFAULT_HASH_FILTER);
        assert!(g.matches("/Users/a/x/node_modules/a/b.json"));
        assert!(g.matches("/a/b.js"));
        assert!(!g.matches("/a/b.txt"));
        assert!(g.matches("/a/run"));
    }
    #[test]
    fn nums() {
        assert_eq!(num(1234567), "1,234,567");
        assert_eq!(secs(125), "2m05s");
    }
}
