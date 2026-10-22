//! One-pass line indexes for lockfiles and manifests, so that finding "the line a package is written on" costs one scan of
//! the file instead of one scan per package, plus the small helpers every parser shares.
use std::collections::HashMap;
use std::sync::LazyLock;

/// Separator inside a joined JSON path.
pub const SEP: &str = "\u{1f}";

pub fn join_path(parts: &[&str]) -> String {
    parts.join(SEP)
}

static PEP503: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[-_.]+").unwrap());

/// PEP 503 normalised project name.
pub fn pep503(name: &str) -> String {
    PEP503.replace_all(&name.to_lowercase(), "-").to_string()
}

/// `"key": ...` at the start of a (trimmed) line: the unescaped key and whether a `:` follows.
fn json_key(t: &str) -> Option<String> {
    let b = t.as_bytes();
    if b.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    let mut esc = false;
    while i < b.len() {
        match b[i] {
            b'\\' if !esc => esc = true,
            b'"' if !esc => break,
            _ => esc = false,
        }
        i += 1;
    }
    if i >= b.len() {
        return None;
    }
    if !t[i + 1..].trim_start().starts_with(':') {
        return None;
    }
    let raw = &t[1..i];
    if raw.contains('\\') {
        serde_json::from_str::<String>(&t[..=i]).ok()
    } else {
        Some(raw.to_string())
    }
}

/// Line (1-based) of every JSON key, addressed by its path of keys joined with [`SEP`]. It follows the file's own
/// indentation, so it works on pretty-printed files (what npm, pipenv and bun write) and finds nothing in minified ones.
pub fn json_paths(text: &str) -> HashMap<String, u32> {
    let mut out = HashMap::new();
    let mut stack: Vec<(usize, String)> = vec![];
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim_start();
        let Some(key) = json_key(t) else { continue };
        let indent = raw.len() - t.len();
        while stack.last().map(|(n, _)| *n >= indent).unwrap_or(false) {
            stack.pop();
        }
        let mut path = String::new();
        for (_, k) in &stack {
            path.push_str(k);
            path.push_str(SEP);
        }
        path.push_str(&key);
        out.entry(path).or_insert(i as u32 + 1);
        stack.push((indent, key));
    }
    out
}

/// Split a dotted TOML key or table name on its dots, honouring quotes.
pub fn toml_split(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut q: Option<char> = None;
    for c in s.chars() {
        match (q, c) {
            (Some(x), c) if c == x => q = None,
            (Some(_), c) => cur.push(c),
            (None, '"') | (None, '\'') => q = Some(c),
            (None, '.') => out.push(std::mem::take(&mut cur).trim().to_string()),
            (None, c) if c.is_whitespace() => {}
            (None, c) => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    out
}

#[derive(Default)]
pub struct TomlIndex {
    keys: HashMap<(String, String), u32>,
    tables: HashMap<String, u32>,
}

impl TomlIndex {
    /// Line of `key` in `table`, or of a `[table.key]` header.
    pub fn line(&self, table: &str, key: &str) -> Option<u32> {
        self.keys.get(&(table.to_string(), key.to_string())).or_else(|| self.tables.get(&format!("{table}.{key}"))).copied()
    }
    pub fn table(&self, table: &str) -> Option<u32> {
        self.tables.get(table).copied()
    }
}

/// Line numbers of TOML tables and of the first key of each dotted key line (`serde.workspace = true` indexes `serde`).
pub fn toml_index(text: &str) -> TomlIndex {
    let mut ix = TomlIndex::default();
    let mut table = String::new();
    let mut depth: i32 = 0; // open brackets of a multi-line value
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        if depth > 0 {
            depth += bracket_delta(t);
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            let h = t.trim_start_matches('[');
            let h = h.split(']').next().unwrap_or(h);
            table = toml_split(h).join(".");
            ix.tables.entry(table.clone()).or_insert(i as u32 + 1);
            continue;
        }
        // key = value
        let mut q: Option<char> = None;
        let mut eq = None;
        for (j, c) in t.char_indices() {
            match (q, c) {
                (Some(x), c) if c == x => q = None,
                (None, '"') | (None, '\'') => q = Some(c),
                (None, '=') => {
                    eq = Some(j);
                    break;
                }
                _ => {}
            }
        }
        let Some(eq) = eq else { continue };
        let parts = toml_split(&t[..eq]);
        if let Some(first) = parts.first() {
            ix.keys.entry((table.clone(), first.clone())).or_insert(i as u32 + 1);
            if parts.len() > 1 {
                ix.keys.entry((table.clone(), parts.join("."))).or_insert(i as u32 + 1);
            }
        }
        depth = bracket_delta(&t[eq + 1..]).max(0);
    }
    ix
}

/// Net `[`/`{` minus `]`/`}` outside strings and comments.
fn bracket_delta(s: &str) -> i32 {
    let mut d = 0;
    let mut q: Option<char> = None;
    for c in s.chars() {
        match (q, c) {
            (Some(x), c) if c == x => q = None,
            (Some(_), _) => {}
            (None, '"') | (None, '\'') => q = Some(c),
            (None, '#') => break,
            (None, '[') | (None, '{') => d += 1,
            (None, ']') | (None, '}') => d -= 1,
            _ => {}
        }
    }
    d
}

/// `name[extras] spec ; marker` of a PEP 508 requirement string: (name, spec without markers or spaces).
pub fn pep508(s: &str) -> Option<(String, String)> {
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$").unwrap());
    let body = s.split(';').next().unwrap_or(s).trim();
    let c = RE.captures(body)?;
    let spec = c[2].trim().trim_start_matches('(').trim_end_matches(')').replace(' ', "");
    Some((c[1].to_string(), spec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_paths_nest_by_indent() {
        let t = "{\n  \"packages\": {\n    \"\": {\n      \"dependencies\": {\n        \"a\": \"^1\"\n      }\n    },\n    \"node_modules/a\": {\n      \"version\": \"1.0.0\"\n    }\n  },\n  \"dependencies\": {\n    \"a\": {\"version\": \"1.0.0\"}\n  }\n}\n";
        let p = json_paths(t);
        assert_eq!(p[&join_path(&["packages", "node_modules/a"])], 8);
        assert_eq!(p[&join_path(&["packages", "", "dependencies", "a"])], 5);
        assert_eq!(p[&join_path(&["dependencies", "a"])], 13);
    }

    #[test]
    fn toml_index_lines() {
        let t = "[package]\nname = \"x\"\n\n[dependencies]\nserde.workspace = true\ntokio = { version = \"1\",\n  features = [\"rt\"] }\n# c = 1\nfoo = [\n  \"a\",\n]\n\n[dependencies.bar]\nversion = \"2\"\n\n[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n";
        let ix = toml_index(t);
        assert_eq!(ix.line("dependencies", "serde"), Some(5));
        assert_eq!(ix.line("dependencies", "tokio"), Some(6));
        assert_eq!(ix.line("dependencies", "c"), None);
        assert_eq!(ix.line("dependencies", "bar"), Some(13));
        assert_eq!(ix.line("target.cfg(windows).dependencies", "winapi"), Some(17));
    }

    #[test]
    fn pep508_strips_markers() {
        assert_eq!(pep508("requests[security]>=2.0,<3 ; python_version < '3.9'"), Some(("requests".into(), ">=2.0,<3".into())));
        assert_eq!(pep508("Flask"), Some(("Flask".into(), String::new())));
    }
}
