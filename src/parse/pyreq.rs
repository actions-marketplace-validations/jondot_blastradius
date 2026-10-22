//! pip requirements files (`requirements.txt`, `requirements/*.txt`, `*-requirements.txt`, `constraints*.txt`, pip-tools output).
//!
//! Handles `\` continuations (pip-compile's `--hash=` lines), comments, markers, extras, `-r`/`-c` includes, `-e` editables,
//! `name @ url` direct references, and tells an exact pin (`==1.2.3`) from an unpinned spec (`>=2`, `==2.*`).
use std::sync::LazyLock;

use super::idx::pep503;
use super::lock::{Entry, Lock, Unpinned};

#[derive(Debug, Clone, PartialEq)]
pub struct Req {
    pub name: String,
    /// The version specifier as written, spaces removed (`==1.2.3`, `>=2,<3`, `@https://...`), empty when none.
    pub spec: String,
    /// The exact version when the spec is a single `==`/`===` pin without a wildcard.
    pub pinned: Option<String>,
    pub line: u32,
    /// First whitespace-separated token as written.
    pub written: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Include {
    pub path: String,
    /// `-c`: constrains versions but installs nothing.
    pub constraint: bool,
    pub line: u32,
}

/// Logical lines (continuations joined, comments removed) with the physical line each starts on.
fn logical_lines(text: &str) -> Vec<(u32, String)> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = vec![];
    let mut cur = String::new();
    let mut start = 0u32;
    for (i, raw) in text.lines().enumerate() {
        let l = raw.trim_end_matches('\r');
        if cur.is_empty() {
            start = i as u32 + 1;
        }
        if let Some(c) = l.strip_suffix('\\') {
            cur.push_str(c);
            cur.push(' ');
            continue;
        }
        cur.push_str(l);
        out.push((start, std::mem::take(&mut cur)));
    }
    if !cur.is_empty() {
        out.push((start, cur));
    }
    out.into_iter()
        .map(|(n, l)| {
            // a comment starts at the line start or after whitespace
            let mut end = l.len();
            let b = l.as_bytes();
            for (i, c) in l.char_indices() {
                if c == '#' && (i == 0 || b[i - 1].is_ascii_whitespace()) {
                    end = i;
                    break;
                }
            }
            (n, l[..end].trim().to_string())
        })
        .filter(|(_, l)| !l.is_empty())
        .collect()
}

/// Version out of an archive file name: `pkg-1.2.3.tar.gz`, `pkg-1.2.3-py3-none-any.whl`.
fn version_from_url(url: &str) -> Option<String> {
    let file = url.split(['#', '?']).next()?.rsplit('/').next()?;
    if let Some(w) = file.strip_suffix(".whl") {
        return w.split('-').nth(1).map(str::to_string).filter(|v| v.starts_with(|c: char| c.is_ascii_digit()));
    }
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"] {
        if let Some(s) = file.strip_suffix(ext) {
            return s.rsplit_once('-').map(|x| x.1.to_string()).filter(|v| v.starts_with(|c: char| c.is_ascii_digit()));
        }
    }
    None
}

static NAME: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$").unwrap());
static PIN: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$").unwrap());

/// Everything a requirements file says: requirements and includes.
pub fn parse_lines(text: &str) -> (Vec<Req>, Vec<Include>) {
    let mut reqs = vec![];
    let mut incs = vec![];
    for (line, l) in logical_lines(text) {
        if l.starts_with('-') {
            // `--requirement=x`, `--requirement x`, `-r x`, `-rx`
            let (flag, rest) = if l.starts_with("--") {
                match l.split_once(|c: char| c.is_whitespace() || c == '=') {
                    Some((f, r)) => (f.to_string(), r.trim().to_string()),
                    None => (l.clone(), String::new()),
                }
            } else {
                (l.get(..2).unwrap_or(&l).to_string(), l.get(2..).unwrap_or("").trim_start_matches('=').trim().to_string())
            };
            match flag.as_str() {
                "-r" | "--requirement" if !rest.is_empty() => incs.push(Include { path: first_word(&rest), constraint: false, line }),
                "-c" | "--constraint" if !rest.is_empty() => incs.push(Include { path: first_word(&rest), constraint: true, line }),
                "-e" | "--editable" => {
                    // `-e git+https://github.com/x/y@sha#egg=name` is a direct reference without a version we can use
                    if let Some(egg) = rest.split("#egg=").nth(1) {
                        let name = egg.split(['&', ' ']).next().unwrap_or(egg).to_string();
                        reqs.push(Req { name, spec: format!("@{}", rest.split('#').next().unwrap_or("")), pinned: None, line, written: format!("-e {rest}") });
                    }
                }
                _ => {}
            }
            continue;
        }
        // drop trailing per-requirement options: --hash=..., --global-option ...
        let body = match l.find(" --") {
            Some(i) => l[..i].trim(),
            None => l.as_str(),
        };
        let body = body.split(';').next().unwrap_or(body).trim();
        if body.is_empty() {
            continue;
        }
        let written = body.split_whitespace().next().unwrap_or("").to_string();
        // a bare URL: `https://host/pkg-1.0.tar.gz`, `git+https://...#egg=name`
        if body.starts_with("git+") || body.starts_with("http://") || body.starts_with("https://") {
            if let Some(egg) = body.split("#egg=").nth(1) {
                reqs.push(Req {
                    name: egg.split(['&', ' ']).next().unwrap_or(egg).to_string(),
                    spec: format!("@{}", body.split('#').next().unwrap_or("")),
                    pinned: version_from_url(body.split('#').next().unwrap_or("")),
                    line,
                    written,
                });
            }
            continue;
        }
        let Some(c) = NAME.captures(body) else { continue };
        let name = c[1].to_string();
        let rest = c[2].trim();
        if let Some(url) = rest.strip_prefix('@') {
            let url = url.trim();
            reqs.push(Req { name, spec: format!("@{url}"), pinned: version_from_url(url), line, written });
            continue;
        }
        let rest = rest.trim_start_matches('(').trim_end_matches(')');
        let spec = rest.replace(' ', "");
        let pinned = if spec.is_empty() || spec.contains('*') || spec.contains(',') { None } else { PIN.captures(&spec).map(|m| m[1].to_string()) };
        reqs.push(Req { name, spec, pinned, line, written });
    }
    (reqs, incs)
}

fn first_word(s: &str) -> String {
    s.split_whitespace().next().unwrap_or("").trim_matches(|c| c == '"' || c == '\'').to_string()
}

/// Repo-relative path of an include named in the file at `from`; None for URLs and absolute paths.
pub fn resolve_include(from: &str, inc: &str) -> Option<String> {
    if inc.contains("://") || inc.starts_with('/') || inc.contains("${") || inc.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = from.split('/').collect();
    parts.pop();
    let norm = inc.replace('\\', "/");
    for seg in norm.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// Repo-relative paths of the `-r` includes (not `-c`) of the requirements file at `path`.
pub fn includes(path: &str, text: &str) -> Vec<String> {
    parse_lines(text).1.iter().filter(|i| !i.constraint).filter_map(|i| resolve_include(path, &i.path)).collect()
}

fn push_reqs(lock: &mut Lock, reqs: &[Req], line_override: Option<u32>, seen: &mut std::collections::HashSet<String>) {
    for r in reqs {
        let line = line_override.unwrap_or(r.line);
        match &r.pinned {
            Some(v) => {
                let id = format!("pypi:{}@{v}", pep503(&r.name));
                if !seen.insert(id.clone()) {
                    continue;
                }
                let norm = format!("{}=={v}", pep503(&r.name));
                lock.entries.push(Entry { id, line, deps: vec![], dev: false, as_written: (!r.written.is_empty() && r.written != norm).then(|| r.written.clone()) });
            }
            None => lock.unpinned.push(Unpinned { name: r.name.clone(), spec: r.spec.clone(), line }),
        }
    }
}

fn finish(lock: &mut Lock) {
    if !lock.unpinned.is_empty() {
        let names: Vec<String> = lock.unpinned.iter().take(5).map(|u| format!("{}{}", u.name, u.spec)).collect();
        lock.gaps.push(format!(
            "{} requirement{} without an exact version pin, so what is installed cannot be told from this file: {}{}",
            lock.unpinned.len(),
            if lock.unpinned.len() == 1 { "" } else { "s" },
            names.join(", "),
            if lock.unpinned.len() > 5 { ", ..." } else { "" }
        ));
    }
}

/// Parse one requirements file on its own.
pub fn parse(text: &str) -> Lock {
    let mut lock = Lock { all_direct: true, ..Default::default() };
    let (reqs, _) = parse_lines(text);
    push_reqs(&mut lock, &reqs, None, &mut Default::default());
    finish(&mut lock);
    lock
}

/// Parse a requirements file and the files it includes with `-r`. `fetch` returns the text of a repo-relative path. The
/// packages of an included file are attributed to the line of the `-r` that pulled them in. An include that cannot be read
/// is a gap.
pub fn parse_following(path: &str, text: &str, fetch: &mut dyn FnMut(&str) -> Option<String>) -> Lock {
    let mut lock = Lock { all_direct: true, ..Default::default() };
    let mut seen_ids = std::collections::HashSet::new();
    let mut visited = std::collections::HashSet::new();
    visited.insert(path.to_string());
    // (file path, text, line of the -r in the root file, depth)
    let mut stack: Vec<(String, String, Option<u32>, usize)> = vec![(path.to_string(), text.to_string(), None, 0)];
    while let Some((p, t, via, depth)) = stack.pop() {
        let (reqs, incs) = parse_lines(&t);
        push_reqs(&mut lock, &reqs, via, &mut seen_ids);
        for inc in incs.iter().filter(|i| !i.constraint).rev() {
            let Some(rp) = resolve_include(&p, &inc.path) else {
                lock.gaps.push(format!("{p}:{}: include {} is not a repo path and was not followed", inc.line, inc.path));
                continue;
            };
            if depth >= 8 || !visited.insert(rp.clone()) {
                continue;
            }
            match fetch(&rp) {
                Some(it) => stack.push((rp, it, Some(via.unwrap_or(inc.line)), depth + 1)),
                None => lock.gaps.push(format!("{p}:{}: included file {rp} could not be read", inc.line)),
            }
        }
    }
    finish(&mut lock);
    lock
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pip-compile output (hash mode), as written by pip-tools 7.
    const COMPILED: &str = "#\n# This file is autogenerated by pip-compile with Python 3.11\n# by the following command:\n#\n#    pip-compile --generate-hashes requirements.in\n#\ncertifi==2024.2.2 \\\n    --hash=sha256:0569859f95fc761b18b45ef421b1290a0f65f147e92a1e3e5e7d1cbc2a4d71ec \\\n    --hash=sha256:dc383c07b76109f368f6106eee2b593b04a011ea4d55f652c6ca24a754d1cdd1\n    # via requests\nrequests==2.31.0 ; python_version >= \"3.7\" \\\n    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003eb\n    # via -r requirements.in\nurllib3==2.2.1\n";

    #[test]
    fn pip_compile_hash_continuations() {
        let l = parse(COMPILED);
        let ids: Vec<_> = l.entries.iter().map(|e| (e.id.as_str(), e.line)).collect();
        assert_eq!(ids, vec![("pypi:certifi@2024.2.2", 7), ("pypi:requests@2.31.0", 11), ("pypi:urllib3@2.2.1", 14)]);
        assert!(l.unpinned.is_empty() && l.gaps.is_empty());
    }

    #[test]
    fn unpinned_and_direct_refs_are_reported_not_dropped() {
        let t = "flask>=2.0\ndjango==4.2.*\nnumpy>=1.20,<2\nrich @ https://files.pythonhosted.org/packages/ab/cd/rich-13.7.0-py3-none-any.whl\nmylib @ git+https://github.com/acme/mylib.git@abc123\n-e git+https://github.com/acme/other.git@v1#egg=other\nclick==8.1.7\n";
        let l = parse(t);
        assert_eq!(l.entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec!["pypi:rich@13.7.0", "pypi:click@8.1.7"]);
        let un: Vec<_> = l.unpinned.iter().map(|u| (u.name.as_str(), u.line)).collect();
        assert_eq!(un, vec![("flask", 1), ("django", 2), ("numpy", 3), ("mylib", 5), ("other", 6)]);
        assert!(l.gaps[0].starts_with("5 requirements without an exact version pin"), "{:?}", l.gaps);
    }

    #[test]
    fn includes_and_constraints() {
        let t = "-r base.txt\n-c ../constraints.txt\n--requirement=extra/dev.txt\n-rshort.txt\n--index-url https://pypi.example/simple\npytest==8.1.1\n";
        let (_, incs) = parse_lines(t);
        assert_eq!(incs.iter().map(|i| (i.path.as_str(), i.constraint)).collect::<Vec<_>>(), vec![("base.txt", false), ("../constraints.txt", true), ("extra/dev.txt", false), ("short.txt", false)]);
        assert_eq!(includes("requirements/prod.txt", t), vec!["requirements/base.txt", "requirements/extra/dev.txt", "requirements/short.txt"]);
    }

    #[test]
    fn django_layout_follows_includes() {
        let files: std::collections::HashMap<&str, &str> =
            [("requirements/base.txt", "django==4.2.11\npsycopg2-binary==2.9.9\n"), ("requirements/common.txt", "-r base.txt\nCelery==5.3.6\n")].into_iter().collect();
        let mut fetch = |p: &str| files.get(p).map(|s| s.to_string());
        let l = parse_following("requirements/prod.txt", "-r common.txt\ngunicorn==21.2.0\n-r missing.txt\n", &mut fetch);
        let mut ids: Vec<_> = l.entries.iter().map(|e| (e.id.clone(), e.line)).collect();
        ids.sort();
        assert_eq!(ids, vec![("pypi:celery@5.3.6".to_string(), 1), ("pypi:django@4.2.11".to_string(), 1), ("pypi:gunicorn@21.2.0".to_string(), 2), ("pypi:psycopg2-binary@2.9.9".to_string(), 1)]);
        assert_eq!(l.gaps.len(), 1);
        assert!(l.gaps[0].contains("requirements/missing.txt"), "{:?}", l.gaps);
    }

    #[test]
    fn as_written_keeps_original_spelling() {
        let l = parse("Netprobe_Py==0.4.2\nrequests==2.31.0  # x\n");
        assert_eq!(l.entries[0].as_written.as_deref(), Some("Netprobe_Py==0.4.2"));
        assert!(l.entries[1].as_written.is_none());
    }
}
