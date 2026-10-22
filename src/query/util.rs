//! Small helpers: times, tables, globs, durations.

use regex::Regex;

use crate::error::{BrError, BrResult};

/// Seconds since the epoch for `YYYY-MM-DDTHH:MM:SSZ` (after `norm_iso`).
pub fn parse_t(s: &str) -> i64 {
    let n = norm_iso(s).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let b = |a: usize, z: usize| n[a..z].parse::<i64>().unwrap_or(0);
    let (y, m, d) = (b(0, 4), b(5, 7), b(8, 10));
    let (hh, mm, ss) = (b(11, 13), b(14, 16), b(17, 19));
    days_from_civil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
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

pub fn iso_from_secs(t: i64) -> String {
    let days = t.div_euclid(86400);
    let rem = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// A compiled pattern, built once per distinct text (clones share the program).
pub fn re(p: &str) -> Regex {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, Regex>>> = OnceLock::new();
    let mut c = CACHE.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|e| e.into_inner());
    c.entry(p.to_string()).or_insert_with(|| Regex::new(p).unwrap()).clone()
}

/// Accept 2026-05-11T14:00Z, 2026-05-11T14:00:00Z, fractional seconds, a +HH:MM offset, or 2026-05-11; return the long UTC form.
/// A date without a year is not accepted: the year is never guessed.
pub fn norm_iso(s: &str) -> Result<String, ()> {
    let s = s.trim();
    if re(r"^\d{4}-\d\d-\d\d$").is_match(s) {
        return Ok(format!("{s}T00:00:00Z"));
    }
    let Some(m) = re(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d)(:\d\d)?(\.\d+)?(Z|z|[+-]\d\d:?\d\d)?$").captures(s) else { return Err(()) };
    let base = format!("{}T{}{}Z", &m[1], &m[2], m.get(3).map_or(":00", |x| x.as_str()));
    let off = match m.get(5).map(|x| x.as_str()) {
        None | Some("Z") | Some("z") => 0,
        Some(o) => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let d: String = o[1..].chars().filter(|c| c.is_ascii_digit()).collect();
            let (h, mi): (i64, i64) = (d[..2].parse().unwrap_or(0), d[2..].parse().unwrap_or(0));
            sign * (h * 3600 + mi * 60)
        }
    };
    if off == 0 {
        return Ok(base);
    }
    let b = |a: usize, z: usize| base[a..z].parse::<i64>().unwrap_or(0);
    let t = days_from_civil(b(0, 4), b(5, 7), b(8, 10)) * 86400 + b(11, 13) * 3600 + b(14, 16) * 60 + b(17, 19);
    Ok(iso_from_secs(t - off))
}

/// A date or time written without its year (05-11, 05-11T14:00Z): a usage error, never a guess.
pub fn is_short_date(s: &str) -> bool {
    re(r"^\d\d-\d\d(T\d\d:\d\d(:\d\d)?Z?)?$").is_match(s.trim())
}

fn is_date_only(s: &str) -> bool {
    re(r"^\d{4}-\d\d-\d\d$").is_match(s.trim())
}

/// One point in time. A bare date is a whole day: its start, or with end=true its last second.
pub fn parse_when(s: &str, end: bool) -> Result<String, ()> {
    let t = norm_iso(s)?;
    if end && is_date_only(s) {
        return Ok(format!("{}23:59:59Z", &t[..11]));
    }
    Ok(t)
}

pub fn parse_window(s: &str) -> BrResult<(String, String)> {
    let ex = "e.g. 2026-05-11T14:00Z..2026-05-11T18:00Z, or 2026-05-11..2026-05-12 for whole days";
    let s = s.trim();
    let (a, b) = match s.split_once("..") {
        Some((a, b)) => (a, b),
        None => (s, s),
    };
    for part in s.split("..") {
        if is_short_date(part) {
            return Err(BrError::new(
                format!("\"{}\" has no year, so br will not guess one", part.trim()),
                Some("write the full form: YYYY-MM-DD or YYYY-MM-DDTHH:MMZ, e.g. 2026-05-11T14:00Z..2026-05-11T18:00Z"),
            ));
        }
    }
    let bad = || BrError::new(format!("\"{s}\" is not a window"), Some(&format!("write FROM..TO, {ex}")));
    let a = parse_when(a, false).map_err(|_| bad())?;
    let b = parse_when(b, true).map_err(|_| bad())?;
    if b < a {
        return Err(BrError::new("window ends before it starts", Some("swap the two times")));
    }
    Ok((a, b))
}

/// --text value: '-' reads stdin, an existing file is read, anything with spaces or newlines is the text itself.
pub fn read_text_arg(arg: &str) -> BrResult<String> {
    use std::io::Read;
    let hint = "pass a readable file, - for stdin, or the advisory text in quotes";
    if arg == "-" {
        let mut s = String::new();
        let _ = std::io::stdin().read_to_string(&mut s);
        return Ok(s);
    }
    if std::path::Path::new(arg).is_file() {
        return std::fs::read_to_string(arg).map_err(|_| BrError::new(format!("cannot read {arg}"), Some(hint)));
    }
    if arg.chars().any(|c| c.is_whitespace()) {
        return Ok(arg.to_string());
    }
    Err(BrError::new(format!("cannot read {arg}"), Some(hint)))
}

// ---- staleness ---------------------------------------------------------------------------------
pub fn stale_threshold() -> BrResult<i64> {
    let raw = stale_label();
    parse_dur(&raw).map_err(|_| BrError::new(format!("BR_STALE_AFTER=\"{raw}\" is not a duration"), Some("write a number and a unit, e.g. 24h or 2d")))
}

pub fn stale_label() -> String {
    std::env::var("BR_STALE_AFTER").ok().filter(|x| !x.is_empty()).unwrap_or_else(|| "24h".to_string())
}

pub fn is_stale(now: &str, indexed_at: &str) -> bool {
    parse_t(now) - parse_t(indexed_at) > stale_threshold().unwrap_or(86400)
}

/// '40m old', or 'fresh' when the index was written this minute.
pub fn age_label(later: &str, earlier: &str) -> String {
    let a = age_str(later, earlier);
    if a == "just now" {
        "fresh".to_string()
    } else {
        format!("{a} old")
    }
}

pub fn add_days(s: &str, days: i64) -> String {
    iso_from_secs(parse_t(s) + days * 86400)
}

/// Table time: MM-DD HH:MM (UTC). "-" for empty.
pub fn fmt(s: &str) -> String {
    if s.is_empty() {
        return "-".to_string();
    }
    match norm_iso(s) {
        Ok(n) => format!("{} {}", &n[5..10], &n[11..16]),
        Err(_) => s.to_string(),
    }
}

pub fn fmt_opt(s: Option<&str>) -> String {
    s.map_or("-".to_string(), fmt)
}

pub fn fmtz(s: &str) -> String {
    format!("{}Z", fmt(s))
}

/// 05-11 14:00Z..18:00Z when both on the same day, else full.
pub fn fmt_range_end(a: &str, b: &str) -> String {
    let (na, nb) = (norm_iso(a).unwrap_or_default(), norm_iso(b).unwrap_or_default());
    if na.len() < 16 || nb.len() < 16 {
        return format!("{a}..{b}");
    }
    if na[..10] == nb[..10] {
        format!("{} {}Z..{}Z", &na[5..10], &na[11..16], &nb[11..16])
    } else {
        format!("{} {}Z..{} {}Z", &na[5..10], &na[11..16], &nb[5..10], &nb[11..16])
    }
}

pub fn age_str(later: &str, earlier: &str) -> String {
    let secs = parse_t(later) - parse_t(earlier);
    if secs < 90 {
        return if secs < 60 { "just now".to_string() } else { "1m".to_string() };
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
    match re(r"^(\d+)\s*([smhd])$").captures(s.trim()) {
        Some(m) => {
            let n: i64 = m[1].parse().unwrap_or(0);
            let u = match &m[2] {
                "s" => 1,
                "m" => 60,
                "h" => 3600,
                _ => 86400,
            };
            Ok(n * u)
        }
        None => Err(BrError::new(format!("\"{s}\" is not a duration"), Some("write a number and a unit, e.g. 24h, 90m, 2d"))),
    }
}

/// Left-aligned columns separated by two spaces.
pub fn table(headers: &[&str], rows: &[Vec<String>], indent: usize) -> Vec<String> {
    let w = |s: &str| s.chars().count();
    let mut widths: Vec<usize> = headers.iter().map(|h| w(h)).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(w(c));
        }
    }
    let pad = " ".repeat(indent);
    let line = |cells: Vec<&str>| {
        let parts: Vec<String> = cells.iter().enumerate().map(|(i, c)| format!("{c}{}", " ".repeat(widths[i].saturating_sub(w(c))))).collect();
        format!("{pad}{}", parts.join("  ")).trim_end().to_string()
    };
    let mut out = vec![line(headers.to_vec())];
    for r in rows {
        out.push(line(r.iter().map(|s| s.as_str()).collect()));
    }
    out
}

pub fn plural(n: usize, one: &str) -> String {
    plural_with(n, one, None)
}

pub fn plural_with(n: usize, one: &str, many: Option<&str>) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {}", many.map_or_else(|| format!("{one}s"), |m| m.to_string()))
    }
}

/// The one phrase for people and machines: "2 people and 1 machine", "3 machines", "1 person". Zero of either is left
/// out; zero of both is the empty string. Every view and evidence call this, so a person is never counted as a machine.
pub fn people_and_machines(people: usize, machines: usize) -> String {
    let mut bits = vec![];
    if people > 0 {
        bits.push(plural_with(people, "person", Some("people")));
    }
    if machines > 0 {
        bits.push(plural(machines, "machine"));
    }
    bits.join(" and ")
}

/// The one way to show a window: `FROM..TO`, and `(examined to T)` when the index stops before the window's end.
/// `examined_to` is the clipped end (see `coverage::examined_end`); it is shown only when it is earlier than `to`.
pub fn window_words(from: &str, to: &str, examined_to: Option<&str>) -> String {
    let base = fmt_range_end(from, to);
    match examined_to {
        Some(t) if !t.is_empty() && t < to => format!("{base} (examined to {})", fmtz(t)),
        _ => base,
    }
}

pub fn join_and(parts: &[String]) -> String {
    match parts.len() {
        0 => String::new(),
        1 => parts[0].clone(),
        n => format!("{} and {}", parts[..n - 1].join(", "), parts[n - 1]),
    }
}

pub fn short_digest(d: &str, wide: bool) -> String {
    let d = if d.starts_with("sha256:") { d.to_string() } else { format!("sha256:{d}") };
    if wide {
        d
    } else {
        d.chars().take(19).collect()
    }
}

pub fn err(msg: &str) {
    eprintln!("{msg}");
}

/// Python's `fnmatch` pattern as a regex that must match the whole string.
pub fn fnmatch_re(pat: &str) -> Regex {
    let cs: Vec<char> = pat.chars().collect();
    let mut out = String::from("(?s)^");
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        i += 1;
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '[' => {
                let mut j = i;
                if j < cs.len() && cs[j] == '!' {
                    j += 1;
                }
                if j < cs.len() && cs[j] == ']' {
                    j += 1;
                }
                while j < cs.len() && cs[j] != ']' {
                    j += 1;
                }
                if j >= cs.len() {
                    out.push_str("\\[");
                } else {
                    let mut stuff: String = cs[i..j].iter().collect::<String>().replace('\\', "\\\\");
                    i = j + 1;
                    if stuff.starts_with('!') {
                        stuff = format!("^{}", &stuff[1..]);
                    } else if stuff.starts_with('^') {
                        stuff = format!("\\{stuff}");
                    }
                    out.push_str(&format!("[{stuff}]"));
                }
            }
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out.push('$');
    Regex::new(&out).unwrap_or_else(|_| Regex::new("^$").unwrap())
}

pub fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

pub fn dirname(p: &str) -> &str {
    match p.rfind('/') {
        Some(0) => "/",
        Some(i) => &p[..i],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_end_same_day_and_across_days() {
        assert_eq!(fmt_range_end("2026-05-11T14:00:00Z", "2026-05-11T18:00:00Z"), "05-11 14:00Z..18:00Z");
        assert_eq!(fmt_range_end("2026-05-11T14:00:00Z", "2026-05-12T01:00:00Z"), "05-11 14:00Z..05-12 01:00Z");
        assert_eq!(fmt_range_end("", ""), "..");
    }

    #[test]
    fn people_and_machines_never_calls_a_person_a_machine() {
        assert_eq!(people_and_machines(2, 1), "2 people and 1 machine");
        assert_eq!(people_and_machines(1, 0), "1 person");
        assert_eq!(people_and_machines(0, 3), "3 machines");
        assert_eq!(people_and_machines(0, 0), "");
    }

    #[test]
    fn window_words_shows_the_clip_one_way() {
        let (a, b) = ("2026-05-11T14:00:00Z", "2026-05-12T23:59:59Z");
        assert_eq!(window_words(a, b, None), "05-11 14:00Z..05-12 23:59Z");
        assert_eq!(window_words(a, b, Some("2026-05-12T09:30:00Z")), "05-11 14:00Z..05-12 23:59Z (examined to 05-12 09:30Z)");
        assert_eq!(window_words(a, b, Some(b)), "05-11 14:00Z..05-12 23:59Z");
    }

    #[test]
    fn table_pads_columns() {
        let t = table(&["A", "BB"], &[vec!["xxx".into(), "1".into()]], 2).join("\n");
        assert!(t.starts_with("  A    BB"), "{t}");
    }

    #[test]
    fn short_dates_are_a_usage_error_naming_the_full_form() {
        let e = parse_window("05-11T14:00Z..05-12").unwrap_err();
        assert!(e.to_string().contains("no year"), "{e}");
        assert!(parse_window("2026-05-11..2026-05-12").is_ok());
        assert!(norm_iso("05-11").is_err());
    }

    #[test]
    fn fractions_and_offsets_parse_and_fmt_never_panics() {
        assert_eq!(norm_iso("2026-05-11T14:00:00.123Z").unwrap(), "2026-05-11T14:00:00Z");
        assert_eq!(norm_iso("2026-05-11T16:00:00+02:00").unwrap(), "2026-05-11T14:00:00Z");
        assert_eq!(norm_iso("2026-05-11T14:00:00-0530").unwrap(), "2026-05-11T19:30:00Z");
        assert_eq!(parse_t("2026-05-11T14:00:00.5Z"), parse_t("2026-05-11T14:00:00Z"));
        assert_eq!(fmt("garbage"), "garbage");
        assert_eq!(fmt("x"), "x");
    }
}
