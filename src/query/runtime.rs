//! Language runtimes as indicators: `runtime:NAME@SPEC` (php, node, python, ruby, go, java).
//!
//! One table says how each runtime shows up (image names, env var, setup actions, version files, install
//! directory names, distro packages). Everything here reads text and path names; no binary is ever run.

use regex::Regex;
use std::cmp::Ordering;
use std::sync::OnceLock;

macro_rules! re {
    ($p:expr) => {{
        static R: OnceLock<Regex> = OnceLock::new();
        R.get_or_init(|| Regex::new($p).unwrap())
    }};
}

/// The pseudo ecosystem runtime sightings are stored under (`runtime:node@22.22.9` in a package list).
pub const ECO: &str = "runtime";
/// Distro package sightings (`distro:php8.3@8.3.6-0ubuntu0.24.04.2`): possible, never found, never clear.
pub const DISTRO: &str = "distro";

pub struct Rt {
    pub name: &'static str,
    /// Official image names (last path segment).
    pub images: &'static [&'static str],
    /// Env vars that carry the version in an official image.
    pub env: &'static [&'static str],
    /// Names the runtime goes by in setup actions, `.tool-versions`, mise, Homebrew and install directories.
    pub aliases: &'static [&'static str],
    /// Version files, by file name.
    pub version_files: &'static [&'static str],
    /// How many leading components name a release line (php 8.3, node 22).
    pub line_depth: usize,
}

pub const TABLE: &[Rt] = &[
    Rt { name: "php", images: &["php"], env: &["PHP_VERSION"], aliases: &["php"], version_files: &[".php-version"], line_depth: 2 },
    Rt { name: "node", images: &["node"], env: &["NODE_VERSION"], aliases: &["node", "nodejs"], version_files: &[".nvmrc", ".node-version"], line_depth: 1 },
    Rt { name: "python", images: &["python"], env: &["PYTHON_VERSION"], aliases: &["python", "cpython", "python3"], version_files: &[".python-version"], line_depth: 2 },
    Rt { name: "ruby", images: &["ruby"], env: &["RUBY_VERSION"], aliases: &["ruby"], version_files: &[".ruby-version"], line_depth: 2 },
    Rt { name: "go", images: &["golang"], env: &["GOLANG_VERSION", "GO_VERSION"], aliases: &["go", "golang"], version_files: &[".go-version"], line_depth: 2 },
    Rt { name: "java", images: &["eclipse-temurin", "openjdk"], env: &["JAVA_VERSION"], aliases: &["java", "openjdk", "temurin", "jdk"], version_files: &[".java-version"], line_depth: 1 },
];

pub fn lookup(name: &str) -> Option<&'static Rt> {
    let n = name.trim().to_lowercase();
    TABLE.iter().find(|r| r.name == n || r.aliases.contains(&n.as_str()))
}

pub fn names() -> String {
    TABLE.iter().map(|r| r.name).collect::<Vec<_>>().join(", ")
}

// ---- versions ---------------------------------------------------------------------------------------------

/// Leading numeric components: "v22.22.9-alpine" -> [22,22,9]; "20.x" -> [20]; "lts/*" -> None.
pub fn comps(s: &str) -> Option<Vec<u32>> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let mut out = vec![];
    for part in s.split('.') {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        out.push(digits.parse().ok()?);
        if digits.len() != part.len() {
            break;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn cmp_c(a: &[u32], b: &[u32]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let o = a.get(i).copied().unwrap_or(0).cmp(&b.get(i).copied().unwrap_or(0));
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

fn join(c: &[u32]) -> String {
    c.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".")
}

/// An exact release: three or more numeric components, then nothing or a build suffix ("8.3.20-apache",
/// "17.0.9_9", "jdk-21.0.2+13", "v22.22.9"). Anything shorter ("8.3", "22", "lts/*") is floating.
pub fn exact(s: &str) -> Option<String> {
    let t = s.trim().trim_start_matches(['v', 'V']);
    let t = re!(r"^(?:[A-Za-z]+(?:-[A-Za-z]+)*-)(\d)").replace(t, "$1").to_string();
    let c = re!(r"^(\d+(?:\.\d+){2,})(?:$|[-_+])").captures(&t)?;
    Some(c[1].to_string())
}

/// The numeric prefix a floating spec names ("8.3-apache" -> [8,3], "22" -> [22], "lts/*" -> None).
pub fn floating_prefix(s: &str) -> Option<Vec<u32>> {
    let t = s.trim().trim_start_matches(['v', 'V']);
    let c = re!(r"^(\d+(?:\.\d+)*)(?:$|[-_+.x*~^]|[a-z])").captures(t)?;
    comps(&c[1])
}

// ---- spec -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum RtSpec {
    Any,
    /// Exact versions or lines ("20.x" is the line [20]).
    Versions(Vec<(Vec<u32>, bool)>),
    Range {
        lo: Option<(Vec<u32>, bool)>,
        hi: Option<(Vec<u32>, bool)>,
    },
    /// One fixed release per line.
    Fixed(Vec<Vec<u32>>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// The release that fixes this version's line (None: end of life, or no fix named).
    pub line_fixed: Option<String>,
    pub eol: bool,
    /// For end of life: the lowest listed fix above the version.
    pub move_to: Option<String>,
}

pub fn parse_spec(s: &str) -> Result<RtSpec, String> {
    let s = s.trim().trim_matches(['"', '\'']);
    if s.is_empty() || s == "*" {
        return Ok(RtSpec::Any);
    }
    if let Some(rest) = s.strip_prefix("fixed:") {
        let mut v: Vec<Vec<u32>> = vec![];
        for x in rest.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            let c = comps(x).ok_or_else(|| format!("\"{x}\" is not a version"))?;
            if !v.contains(&c) {
                v.push(c);
            }
        }
        if v.is_empty() {
            return Err("fixed: needs at least one fixed release, e.g. fixed:8.5.12,8.4.27".into());
        }
        return Ok(RtSpec::Fixed(v));
    }
    let parts: Vec<&str> = s.split(',').map(str::trim).filter(|x| !x.is_empty()).collect();
    if parts.iter().any(|p| p.starts_with(['<', '>'])) {
        let (mut lo, mut hi) = (None, None);
        for p in parts {
            let (op, v) = if let Some(v) = p.strip_prefix(">=") {
                (">=", v)
            } else if let Some(v) = p.strip_prefix("<=") {
                ("<=", v)
            } else if let Some(v) = p.strip_prefix('>') {
                (">", v)
            } else if let Some(v) = p.strip_prefix('<') {
                ("<", v)
            } else {
                return Err(format!("\"{p}\" mixes a version with a range; write one or the other"));
            };
            let c = comps(v).ok_or_else(|| format!("\"{}\" is not a version", v.trim()))?;
            match op {
                ">=" => lo = Some((c, true)),
                ">" => lo = Some((c, false)),
                "<=" => hi = Some((c, true)),
                _ => hi = Some((c, false)),
            }
        }
        return Ok(RtSpec::Range { lo, hi });
    }
    let mut v = vec![];
    for p in parts {
        let c = comps(p).ok_or_else(|| format!("\"{p}\" is not a version"))?;
        let line = re!(r"(?i)(?:\.x|\.\*)$").is_match(p) || c.len() < 3 && !re!(r"^v?\d+(\.\d+){2,}").is_match(p);
        v.push((c, line));
    }
    Ok(RtSpec::Versions(v))
}

/// Smallest leading depth at which the listed fixes are told apart, never below `floor`.
fn line_depth(fixes: &[Vec<u32>], floor: usize) -> usize {
    let max = fixes.iter().map(Vec::len).max().unwrap_or(1);
    let mut d = floor.max(1);
    while d < max {
        let pre: Vec<Vec<u32>> = fixes.iter().map(|f| f.iter().take(d).copied().collect()).collect();
        if (0..pre.len()).all(|i| (i + 1..pre.len()).all(|j| cmp_c(&pre[i], &pre[j]) != Ordering::Equal)) {
            break;
        }
        d += 1;
    }
    d
}

impl RtSpec {
    /// Whether `version` is affected, and how it is fixed.
    pub fn eval(&self, version: &str, floor: usize) -> Option<Hit> {
        let v = comps(version)?;
        match self {
            RtSpec::Any => Some(Hit { line_fixed: None, eol: false, move_to: None }),
            RtSpec::Versions(list) => {
                let hit = list.iter().any(|(c, line)| if *line { v.len() >= c.len() && v[..c.len()] == c[..] } else { cmp_c(&v, c) == Ordering::Equal });
                hit.then_some(Hit { line_fixed: None, eol: false, move_to: None })
            }
            RtSpec::Range { lo, hi } => {
                if let Some((l, inc)) = lo {
                    let o = cmp_c(&v, l);
                    if o == Ordering::Less || (o == Ordering::Equal && !inc) {
                        return None;
                    }
                }
                if let Some((h, inc)) = hi {
                    let o = cmp_c(&v, h);
                    if o == Ordering::Greater || (o == Ordering::Equal && !inc) {
                        return None;
                    }
                }
                let fixed = match hi {
                    Some((h, false)) => Some(join(h)),
                    _ => None,
                };
                Some(Hit { line_fixed: fixed, eol: false, move_to: None })
            }
            RtSpec::Fixed(fixes) => {
                let d = line_depth(fixes, floor);
                let pre = |c: &[u32]| -> Vec<u32> { (0..d).map(|i| c.get(i).copied().unwrap_or(0)).collect() };
                let mine = pre(&v);
                if let Some(f) = fixes.iter().find(|f| pre(f) == mine) {
                    return (cmp_c(&v, f) == Ordering::Less).then(|| Hit { line_fixed: Some(join(f)), eol: false, move_to: None });
                }
                // No listed fix on this line: older than some fix means end of life, above every fix means unaffected.
                let mut above: Vec<&Vec<u32>> = fixes.iter().filter(|f| cmp_c(f, &v) == Ordering::Greater).collect();
                above.sort_by(|a, b| cmp_c(a, b));
                above.first().map(|f| Hit { line_fixed: None, eol: true, move_to: Some(join(f)) })
            }
        }
    }

    /// Could a floating spec ("8.3", "22", "lts/*") resolve to an affected release? Unknown shapes say yes.
    pub fn floating_may_hit(&self, floating: &str, floor: usize) -> bool {
        match floating_prefix(floating) {
            None => true,
            Some(p) => {
                let mut probe = p;
                while probe.len() < 3 {
                    probe.push(0);
                }
                self.eval(&join(&probe), floor).is_some()
            }
        }
    }
}

// ---- file scanning ----------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Ref {
    pub runtime: &'static str,
    /// As written ("8.3.20-apache", "22", "lts/*").
    pub spec: String,
    /// Exact release when the text names one.
    pub version: Option<String>,
    pub floating: bool,
    pub line: usize,
    /// What the line is ("FROM php:8.3.20-apache", "setup-node node-version", ".nvmrc").
    pub seen_as: String,
}

fn mk(rt: &'static Rt, spec: &str, line: usize, seen_as: String) -> Ref {
    let spec = spec.trim().to_string();
    let version = exact(&spec);
    Ref { runtime: rt.name, floating: version.is_none(), version, spec, line, seen_as }
}

/// The runtime an image reference names, with its tag: "php:8.3.20-apache" -> (php, "8.3.20-apache").
pub fn image_ref(image: &str) -> Option<(&'static Rt, String)> {
    let image = image.split('@').next().unwrap_or(image);
    let (path, tag) = match image.rsplit_once(':') {
        Some((p, t)) if !t.contains('/') => (p, t),
        _ => (image, "latest"),
    };
    let mut segs: Vec<&str> = path.split('/').collect();
    if segs.len() > 1 && (segs[0].contains('.') || segs[0].contains(':') || segs[0] == "localhost") {
        segs.remove(0);
    }
    if segs.len() == 2 && segs[0] == "library" {
        segs.remove(0);
    }
    if segs.len() != 1 {
        return None;
    }
    let name = segs[0].to_lowercase();
    let rt = TABLE.iter().find(|r| r.images.contains(&name.as_str()))?;
    Some((rt, tag.to_string()))
}

fn subst(s: &str, args: &std::collections::HashMap<String, String>) -> (String, bool) {
    let mut ok = true;
    let out = re!(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)").replace_all(s, |c: &regex::Captures| {
        let k = c.get(1).or(c.get(3)).map(|m| m.as_str()).unwrap_or("");
        if let Some(v) = args.get(k).filter(|v| !v.is_empty()) {
            return v.clone();
        }
        if let Some(d) = c.get(2) {
            return d.as_str().to_string();
        }
        ok = false;
        c[0].to_string()
    });
    (out.to_string(), ok)
}

fn from_image(img: &str, line: usize, label: &str, args: &std::collections::HashMap<String, String>, out: &mut Vec<Ref>) {
    let (img, ok) = subst(img.trim().trim_matches(['"', '\'']), args);
    if img.is_empty() || img == "scratch" {
        return;
    }
    if !ok {
        // An unresolved build argument: the image name is still visible, the tag is not.
        let head = img.split(['$', ':']).next().unwrap_or("");
        if let Some((rt, _)) = image_ref(head) {
            out.push(Ref { runtime: rt.name, spec: img.clone(), version: None, floating: true, line, seen_as: format!("{label} {img}") });
        }
        return;
    }
    if !img.contains(':') && img.contains("@sha256:") {
        return; // digest only: the version is not in the text
    }
    if let Some((rt, tag)) = image_ref(&img) {
        let r = mk(rt, &tag, line, format!("{label} {}", img.split('@').next().unwrap_or(&img)));
        out.push(r);
    }
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_dockerfile(b: &str) -> bool {
    let l = b.to_lowercase();
    l.starts_with("dockerfile") || l.starts_with("containerfile") || l.ends_with(".dockerfile") || l.ends_with(".containerfile")
}

fn is_compose(b: &str) -> bool {
    let l = b.to_lowercase();
    (l.starts_with("docker-compose") || l.starts_with("compose")) && (l.ends_with(".yml") || l.ends_with(".yaml"))
}

fn is_workflow(p: &str) -> bool {
    let l = p.to_lowercase();
    (l.contains(".github/workflows/") || l.contains(".github/actions/") || l.starts_with(".gitea/") || l.starts_with(".forgejo/")) && (l.ends_with(".yml") || l.ends_with(".yaml"))
}

/// Files that can name a runtime, by path. Used to pick which files to read.
pub fn candidate(path: &str) -> bool {
    let b = base_name(path);
    let l = b.to_lowercase();
    is_dockerfile(b) || is_compose(b) || is_workflow(path) || l == ".tool-versions" || l == "mise.toml" || l == ".mise.toml" || TABLE.iter().any(|r| r.version_files.contains(&l.as_str()))
}

/// Every runtime reference in one file's text.
pub fn scan_file(path: &str, text: &str) -> Vec<Ref> {
    let b = base_name(path);
    let l = b.to_lowercase();
    let mut out = vec![];
    if is_dockerfile(b) {
        scan_dockerfile(text, &mut out);
    } else if is_workflow(path) {
        scan_yaml_images(text, &mut out);
        scan_setup_steps(text, &mut out);
    } else if is_compose(b) {
        scan_yaml_images(text, &mut out);
    } else if l == ".tool-versions" {
        scan_tool_versions(text, &mut out);
    } else if l == "mise.toml" || l == ".mise.toml" {
        scan_mise(text, &mut out);
    } else if let Some(rt) = TABLE.iter().find(|r| r.version_files.contains(&l.as_str())) {
        scan_version_file(rt, &l, text, &mut out);
    }
    out
}

fn scan_dockerfile(text: &str, out: &mut Vec<Ref>) {
    let mut args = std::collections::HashMap::new();
    let mut stages: Vec<String> = vec![];
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let up = line.to_uppercase();
        if up.starts_with("ARG ") {
            for kv in line[4..].split_whitespace() {
                if let Some((k, v)) = kv.split_once('=') {
                    args.insert(k.to_string(), v.trim_matches(['"', '\'']).to_string());
                }
            }
        } else if up.starts_with("ENV ") {
            let rest = line[4..].trim();
            let pairs: Vec<(String, String)> = if rest.contains('=') {
                re!(r#"([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S*)"#).captures_iter(rest).map(|c| (c[1].to_string(), c[2].trim_matches(['"', '\'']).to_string())).collect()
            } else {
                rest.split_once(char::is_whitespace).map(|(k, v)| vec![(k.to_string(), v.trim().to_string())]).unwrap_or_default()
            };
            for (k, v) in pairs {
                if let Some(rt) = TABLE.iter().find(|r| r.env.contains(&k.as_str())) {
                    if !v.contains('$') {
                        out.push(mk(rt, &v, i + 1, format!("ENV {k}")));
                    }
                }
                args.insert(k, v);
            }
        } else if up.starts_with("FROM ") {
            let mut toks: Vec<&str> = line[5..].split_whitespace().collect();
            while toks.first().is_some_and(|t| t.starts_with("--")) {
                toks.remove(0);
            }
            let Some(img) = toks.first().copied() else { continue };
            let alias = toks.iter().position(|t| t.eq_ignore_ascii_case("as")).and_then(|p| toks.get(p + 1)).map(|a| a.to_lowercase());
            if !stages.contains(&img.to_lowercase()) {
                from_image(img, i + 1, "FROM", &args, out);
            }
            if let Some(a) = alias {
                stages.push(a);
            }
        }
    }
}

fn scan_yaml_images(text: &str, out: &mut Vec<Ref>) {
    let args = std::collections::HashMap::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_start().trim_start_matches("- ");
        if line.starts_with('#') {
            continue;
        }
        let v = if let Some(v) = line.strip_prefix("image:") {
            v
        } else if let Some(v) = line.strip_prefix("container:") {
            v
        } else {
            continue;
        };
        let v = v.split(" #").next().unwrap_or(v).trim();
        if v.is_empty() || v.starts_with('{') {
            continue;
        }
        if v.contains("${{") {
            let head = v.split("${{").next().unwrap_or("").trim_matches(['"', '\'']);
            if let Some((rt, _)) = image_ref(head.trim_end_matches(':')) {
                out.push(Ref { runtime: rt.name, spec: v.to_string(), version: None, floating: true, line: i + 1, seen_as: format!("image {v}") });
            }
            continue;
        }
        from_image(v, i + 1, "image", &args, out);
    }
}

fn matrix_values(text: &str, key: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut vals = vec![];
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        let Some(rest) = t.strip_prefix(&format!("{key}:")) else { continue };
        let rest = rest.trim();
        if let Some(inner) = rest.strip_prefix('[') {
            let inner = inner.split(']').next().unwrap_or("");
            vals.extend(inner.split(',').map(|x| x.trim().trim_matches(['"', '\'']).to_string()).filter(|x| !x.is_empty()));
        } else if rest.is_empty() || rest.starts_with('#') {
            let ind = l.len() - t.len();
            for n in &lines[i + 1..] {
                let nt = n.trim_start();
                if nt.is_empty() || nt.starts_with('#') {
                    continue;
                }
                if !nt.starts_with("- ") || n.len() - nt.len() < ind {
                    break;
                }
                vals.push(nt[2..].split(" #").next().unwrap_or("").trim().trim_matches(['"', '\'']).to_string());
            }
        }
    }
    vals
}

fn scan_setup_steps(text: &str, out: &mut Vec<Ref>) {
    let lines: Vec<&str> = text.lines().collect();
    for (i, raw) in lines.iter().enumerate() {
        let t = raw.trim_start().trim_start_matches("- ");
        let Some(u) = t.strip_prefix("uses:") else { continue };
        let u = u.trim().trim_matches(['"', '\'']);
        let Some(c) = re!(r"^[\w.-]+/setup-([\w-]+?)(?:@|/|$)").captures(u) else { continue };
        let Some(rt) = lookup(&c[1]) else { continue };
        let input = format!("{}-version", c[1].to_lowercase());
        let ind = raw.len() - raw.trim_start().len();
        let mut j = i + 1;
        while j < lines.len() {
            let n = lines[j];
            let nt = n.trim_start();
            let nind = n.len() - nt.len();
            if !nt.is_empty() && !nt.starts_with('#') && (nt.starts_with("- ") && nind <= ind || nind < ind) {
                break;
            }
            // the `uses:` line may itself follow a "- name:" line; only look downward
            if let Some(v) = nt.strip_prefix(&format!("{input}:")) {
                let v = v.split(" #").next().unwrap_or("").trim().trim_matches(['"', '\'']);
                let label = format!("{} {input}", u.split('@').next().unwrap_or(u).rsplit('/').next().unwrap_or(u));
                if let Some(m) = re!(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}").captures(v) {
                    let vals = matrix_values(text, &m[1]);
                    if vals.is_empty() {
                        out.push(Ref { runtime: rt.name, spec: v.to_string(), version: None, floating: true, line: j + 1, seen_as: label.clone() });
                    }
                    for x in vals {
                        out.push(mk(rt, &x, j + 1, label.clone()));
                    }
                } else if v.contains("${{") {
                    out.push(Ref { runtime: rt.name, spec: v.to_string(), version: None, floating: true, line: j + 1, seen_as: label });
                } else if !v.is_empty() {
                    out.push(mk(rt, v, j + 1, label));
                }
                break;
            }
            j += 1;
        }
    }
}

fn scan_version_file(rt: &'static Rt, file: &str, text: &str, out: &mut Vec<Ref>) {
    for (i, raw) in text.lines().enumerate() {
        let l = raw.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let ok = l.trim_start_matches(['v', 'V']).starts_with(|c: char| c.is_ascii_digit()) || l.starts_with("lts") || l == "latest" || l == "stable" || l == "node";
        if ok {
            out.push(mk(rt, l, i + 1, file.to_string()));
        }
    }
}

fn scan_tool_versions(text: &str, out: &mut Vec<Ref>) {
    for (i, raw) in text.lines().enumerate() {
        let l = raw.split('#').next().unwrap_or("").trim();
        let mut it = l.split_whitespace();
        let Some(name) = it.next() else { continue };
        let Some(rt) = lookup(name) else { continue };
        for v in it {
            if v == "system" || v.starts_with("ref:") || v.starts_with("path:") {
                continue;
            }
            out.push(mk(rt, v, i + 1, ".tool-versions".into()));
        }
    }
}

fn scan_mise(text: &str, out: &mut Vec<Ref>) {
    let Ok(v) = text.parse::<toml::Value>() else { return };
    let Some(tools) = v.get("tools").and_then(|t| t.as_table()) else { return };
    for (k, val) in tools {
        let Some(rt) = lookup(k.trim_matches('"')) else { continue };
        let mut specs = vec![];
        match val {
            toml::Value::String(s) => specs.push(s.clone()),
            toml::Value::Array(a) => specs.extend(a.iter().filter_map(|x| x.as_str().map(str::to_string))),
            toml::Value::Table(t) => {
                if let Some(s) = t.get("version").and_then(|x| x.as_str()) {
                    specs.push(s.to_string());
                }
            }
            _ => {}
        }
        let line = text.lines().position(|l| l.trim_start().starts_with(k.as_str()) || l.trim_start().starts_with(&format!("\"{k}\""))).map(|p| p + 1).unwrap_or(0);
        for s in specs {
            out.push(mk(rt, &s, line, "mise.toml".into()));
        }
    }
}

// ---- installed runtimes -----------------------------------------------------------------------------------

/// An install directory name on a host, in a layer or in a CI log: tool cache, Homebrew Cellar, nvm, asdf, mise,
/// volta, fnm and the *env managers. Returns the runtime and its exact version.
pub fn install_dir(path: &str) -> Option<(&'static str, String)> {
    install_root(path).map(|(n, v, _)| (n, v))
}

/// Like `install_dir`, with the version directory itself (the root a whiteout would have to remove).
pub fn install_root(path: &str) -> Option<(&'static str, String, String)> {
    let p = path.replace('\\', "/");
    let pats: [&Regex; 8] = [
        re!(r"(?i)(?:^|/)(?:hostedtoolcache|_work/_tool|_tool)/([^/\s]+)/(\d[^/\s]*)/"),
        re!(r"(?:^|/)Cellar/([A-Za-z0-9._+-]+?)(?:@[0-9.]+)?/(\d[^/\s]*)/"),
        re!(r"(?:^|/)\.?nvm/versions/(node)/v?(\d[^/\s]*)/"),
        re!(r"(?:^|/)\.asdf/installs/([^/\s]+)/(\d[^/\s]*)/"),
        re!(r"(?:^|/)mise/installs/([^/\s]+)/(\d[^/\s]*)/"),
        re!(r"(?:^|/)\.volta/tools/image/(node)/(\d[^/\s]*)/"),
        re!(r"(?:^|/)fnm/(node)-versions/v?(\d[^/\s]*)/"),
        re!(r"(?:^|/)\.(rbenv|pyenv|goenv|phpenv|nodenv|sdkman/candidates/java)/(?:versions/)?(\d[^/\s]*)/"),
    ];
    for (i, r) in pats.iter().enumerate() {
        let Some(c) = r.captures(&p) else { continue };
        let mut name = c[1].to_string();
        if i == 7 {
            // these layouts have no runtime-name directory: the manager names the runtime
            name = match name.as_str() {
                "rbenv" => "ruby",
                "pyenv" => "python",
                "goenv" => "go",
                "phpenv" => "php",
                "nodenv" => "node",
                _ => "java",
            }
            .into();
        }
        let ver = c[2].to_string();
        let low = name.to_lowercase();
        if low.starts_with("java_") || low.starts_with("jdk") {
            name = "java".into();
        }
        let Some(rt) = lookup(&name) else { continue };
        if let Some(v) = exact(&ver) {
            let end = c.get(0).map(|m| m.end()).unwrap_or(p.len());
            return Some((rt.name, v, p[..end - 1].to_string()));
        }
    }
    None
}

pub fn is_version_var(name: &str) -> bool {
    TABLE.iter().any(|r| r.env.contains(&name))
}

/// A runtime variable in an image config's Env: only the table's version variables are read for their value.
pub fn env_version(name: &str, value: &str) -> Option<(&'static str, String)> {
    let rt = TABLE.iter().find(|r| r.env.contains(&name))?;
    exact(value).map(|v| (rt.name, v))
}

/// Runtime versions a CI log line states (tool cache paths, setup action output).
pub fn log_versions(line: &str) -> Vec<(&'static str, String)> {
    let mut out = vec![];
    if let Some(x) = install_dir(line) {
        out.push(x);
    }
    if let Some(c) = re!(r"Successfully set up (CPython|PyPy) \((\d+\.\d+\.\d+)").captures(line) {
        out.push(("python", c[2].to_string()));
    }
    if let Some(c) = re!(r"go version go(\d+\.\d+\.\d+)").captures(line) {
        out.push(("go", c[1].to_string()));
    }
    if let Some(c) = re!(r"(?i)^\W*(php|node|ruby)(?:js)?(?: version)?[: ]+v?(\d+\.\d+\.\d+)\b").captures(line) {
        if let Some(rt) = lookup(&c[1]) {
            out.push((rt.name, c[2].to_string()));
        }
    }
    out.dedup();
    out
}

// ---- distro packages --------------------------------------------------------------------------------------

/// The runtime a distro package name belongs to (core packages only), for packages the index never treats as found.
pub fn distro_runtime(pkg: &str) -> Option<&'static str> {
    let pats: [(&str, &Regex); 6] = [
        ("php", re!(r"^php[0-9]*(\.[0-9]+)?(-cli|-fpm|-cgi|-common)?$")),
        ("node", re!(r"^nodejs$|^libnode[0-9]*$")),
        ("python", re!(r"^python3(\.[0-9]+)?(-minimal)?$|^libpython3\.[0-9]+(-minimal|-stdlib)?$")),
        ("ruby", re!(r"^ruby[0-9.]*$|^libruby[0-9.]*$")),
        ("go", re!(r"^golang-go$|^golang-[0-9.]+-go$|^golang$")),
        ("java", re!(r"^openjdk-[0-9]+-(jre|jdk)(-headless)?$|^openjdk[0-9]+(-jre|-jdk)?(-headless)?$|^java-[0-9]+-openjdk(-headless|-devel)?$|^temurin-[0-9]+-(jre|jdk)$")),
    ];
    pats.iter().find(|(_, r)| r.is_match(pkg)).map(|(n, _)| *n)
}

pub fn is_distro_db(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    p == "var/lib/dpkg/status" || p == "lib/apk/db/installed" || p.ends_with("/var/lib/dpkg/status") || p.ends_with("/lib/apk/db/installed")
}

/// (name, version) of every runtime-related package in a dpkg status or apk installed database.
pub fn distro_packages(text: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let (mut name, mut ver, mut installed) = (String::new(), String::new(), true);
    let mut flush = |name: &mut String, ver: &mut String, installed: &mut bool| {
        if !name.is_empty() && !ver.is_empty() && *installed && distro_runtime(name).is_some() {
            out.push((name.clone(), ver.clone()));
        }
        name.clear();
        ver.clear();
        *installed = true;
    };
    for l in text.lines() {
        if l.trim().is_empty() {
            flush(&mut name, &mut ver, &mut installed);
        } else if let Some(v) = l.strip_prefix("Package: ").or_else(|| l.strip_prefix("P:")) {
            name = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("Version: ").or_else(|| l.strip_prefix("V:")) {
            ver = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("Status: ") {
            installed = v.trim().ends_with("installed") && !v.contains("not-installed");
        }
    }
    flush(&mut name, &mut ver, &mut installed);
    out
}

/// Pseudo package strings as stored in package lists.
pub fn pseudo(runtime: &str, version: &str) -> String {
    format!("{ECO}:{runtime}@{version}")
}

pub fn pseudo_distro(pkg: &str, version: &str) -> String {
    format!("{DISTRO}:{pkg}@{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn php() -> RtSpec {
        parse_spec("fixed:8.5.12,8.4.27,8.3.36,8.2.35").unwrap()
    }
    fn node() -> RtSpec {
        parse_spec("fixed:22.23.4,24.22.1,26.12.1").unwrap()
    }

    #[test]
    fn fixed_php_on_its_own_line() {
        let h = php().eval("8.3.20", 2).unwrap();
        assert_eq!(h.line_fixed.as_deref(), Some("8.3.36"));
        assert!(!h.eol);
        assert!(php().eval("8.3.36", 2).is_none());
        assert!(php().eval("8.3.40", 2).is_none());
    }

    #[test]
    fn fixed_older_than_every_line_is_end_of_life() {
        let h = php().eval("8.1.30", 2).unwrap();
        assert!(h.eol);
        assert_eq!(h.line_fixed, None);
        assert_eq!(h.move_to.as_deref(), Some("8.2.35"));
    }

    #[test]
    fn fixed_above_the_line_fix_and_above_all() {
        assert!(php().eval("8.5.13", 2).is_none());
        assert!(php().eval("8.6.0", 2).is_none());
        assert!(node().eval("26.13.0", 1).is_none());
    }

    #[test]
    fn fixed_node_major_lines() {
        let h = node().eval("22.22.9", 1).unwrap();
        assert_eq!(h.line_fixed.as_deref(), Some("22.23.4"));
        assert!(!h.eol);
        assert!(node().eval("22.23.4", 1).is_none());
    }

    #[test]
    fn fixed_wildcard_line_is_end_of_life() {
        let h = node().eval("20.x", 1).unwrap();
        assert!(h.eol);
        assert_eq!(h.move_to.as_deref(), Some("22.23.4"));
    }

    #[test]
    fn fixed_between_lines_is_end_of_life() {
        assert!(node().eval("23.1.0", 1).unwrap().eol);
    }

    #[test]
    fn single_fix_does_not_swallow_older_minor_lines() {
        let s = parse_spec("fixed:8.3.36").unwrap();
        assert!(s.eval("8.1.30", 2).unwrap().eol);
        assert_eq!(s.eval("8.3.1", 2).unwrap().line_fixed.as_deref(), Some("8.3.36"));
    }

    #[test]
    fn ranges_and_versions() {
        let r = parse_spec(">=22.0.0,<22.23.4").unwrap();
        assert_eq!(r.eval("22.5.0", 1).unwrap().line_fixed.as_deref(), Some("22.23.4"));
        assert!(r.eval("22.23.4", 1).is_none());
        assert!(r.eval("21.9.0", 1).is_none());
        let v = parse_spec("8.3.20,8.3.21").unwrap();
        assert!(v.eval("8.3.21", 2).is_some());
        assert!(v.eval("8.3.22", 2).is_none());
        assert!(parse_spec("fixed:").is_err());
        assert!(parse_spec("lts").is_err());
    }

    #[test]
    fn exact_and_floating() {
        assert_eq!(exact("8.3.20-apache").as_deref(), Some("8.3.20"));
        assert_eq!(exact("17.0.9_9-jdk").as_deref(), Some("17.0.9"));
        assert_eq!(exact("jdk-21.0.2+13").as_deref(), Some("21.0.2"));
        assert_eq!(exact("v22.22.9").as_deref(), Some("22.22.9"));
        assert_eq!(exact("8.3-apache"), None);
        assert_eq!(exact("22"), None);
        assert_eq!(exact("lts/*"), None);
        assert!(php().floating_may_hit("8.3-apache", 2));
        assert!(!php().floating_may_hit("8.6", 2));
        assert!(php().floating_may_hit("latest", 2));
    }

    #[test]
    fn dockerfile_refs() {
        let t = "ARG V=22.22.9\nFROM node:${V} AS build\nFROM php:8.3-apache\nFROM build\nFROM docker.io/library/php:8.3.20-fpm@sha256:abcd\nFROM node:$MISSING\nENV PHP_VERSION=8.3.20\n";
        let r = scan_file("Dockerfile", t);
        let got: Vec<(&str, bool, usize)> = r.iter().map(|x| (x.runtime, x.floating, x.line)).collect();
        assert_eq!(got, vec![("node", false, 2), ("php", true, 3), ("php", false, 5), ("node", true, 6), ("php", false, 7)]);
        assert_eq!(r[0].version.as_deref(), Some("22.22.9"));
    }

    #[test]
    fn workflow_setup_steps_and_matrix() {
        let t = "jobs:\n  t:\n    strategy:\n      matrix:\n        node: [18, 22.22.9]\n    container: node:20.11.0\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.node }}\n      - uses: shivammathur/setup-php@v2\n        with:\n          php-version: '8.3'\n      - uses: actions/setup-go@v5\n        with:\n          go-version: 1.22.3\n";
        let r = scan_file(".github/workflows/ci.yml", t);
        let got: Vec<(&str, &str, bool)> = r.iter().map(|x| (x.runtime, x.spec.as_str(), x.floating)).collect();
        assert!(got.contains(&("node", "20.11.0", false)));
        assert!(got.contains(&("node", "18", true)));
        assert!(got.contains(&("node", "22.22.9", false)));
        assert!(got.contains(&("php", "8.3", true)));
        assert!(got.contains(&("go", "1.22.3", false)));
    }

    #[test]
    fn version_files() {
        assert_eq!(scan_file(".nvmrc", "v22.22.9\n")[0].version.as_deref(), Some("22.22.9"));
        assert!(scan_file(".nvmrc", "lts/*\n")[0].floating);
        let r = scan_file(".tool-versions", "nodejs 22.22.9 20.11.0\npython 3.12\nrust 1.80.0\n");
        assert_eq!(r.len(), 3);
        let m = scan_file("mise.toml", "[tools]\nnode = \"22.22.9\"\njava = \"temurin-21.0.2+13\"\n");
        assert_eq!(m.len(), 2);
        assert!(m.iter().any(|x| x.runtime == "java" && x.version.as_deref() == Some("21.0.2")));
    }

    #[test]
    fn install_dirs() {
        assert_eq!(install_dir("/opt/hostedtoolcache/node/22.22.9/x64/bin/node"), Some(("node", "22.22.9".into())));
        assert_eq!(install_dir("/home/runner/_work/_tool/Python/3.12.1/x64/bin/python"), Some(("python", "3.12.1".into())));
        assert_eq!(install_dir("/opt/homebrew/Cellar/php/8.3.20/bin/php"), Some(("php", "8.3.20".into())));
        assert_eq!(install_dir("/opt/homebrew/Cellar/node@22/22.22.9/bin/node"), Some(("node", "22.22.9".into())));
        assert_eq!(install_dir("/Users/a/.nvm/versions/node/v20.11.0/bin/node"), Some(("node", "20.11.0".into())));
        assert_eq!(install_dir("/Users/a/.asdf/installs/nodejs/22.22.9/bin/node"), Some(("node", "22.22.9".into())));
        assert_eq!(install_dir("/Users/a/.local/share/mise/installs/php/8.3.20/bin/php"), Some(("php", "8.3.20".into())));
        assert_eq!(install_dir("/Users/a/.volta/tools/image/node/22.22.9/bin/node"), Some(("node", "22.22.9".into())));
        assert_eq!(install_dir("/opt/hostedtoolcache/Java_Temurin-Hotspot_jdk/21.0.2-13.0.LTS/x64/bin/java"), Some(("java", "21.0.2".into())));
        assert_eq!(install_dir("/usr/bin/node"), None);
    }

    #[test]
    fn env_and_distro() {
        assert_eq!(env_version("PHP_VERSION", "8.3.20"), Some(("php", "8.3.20".into())));
        assert_eq!(env_version("API_TOKEN", "8.3.20"), None);
        let db = "Package: php8.3-cli\nStatus: install ok installed\nVersion: 8.3.6-0ubuntu0.24.04.2\n\nPackage: curl\nStatus: install ok installed\nVersion: 8.5.0\n\nPackage: php8.2-cli\nStatus: deinstall ok config-files\nVersion: 8.2.1\n";
        assert_eq!(distro_packages(db), vec![("php8.3-cli".to_string(), "8.3.6-0ubuntu0.24.04.2".to_string())]);
        let apk = "P:nodejs\nV:20.11.1-r0\n\nP:busybox\nV:1.36\n";
        assert_eq!(distro_packages(apk), vec![("nodejs".to_string(), "20.11.1-r0".to_string())]);
        assert_eq!(distro_runtime("openjdk-17-jre-headless"), Some("java"));
        assert_eq!(distro_runtime("php-curl"), None);
    }

    #[test]
    fn log_lines() {
        assert_eq!(log_versions("Found in cache @ /opt/hostedtoolcache/node/22.22.9/x64"), vec![("node", "22.22.9".to_string())]);
        assert_eq!(log_versions("Successfully set up CPython (3.12.1)"), vec![("python", "3.12.1".to_string())]);
    }
}
