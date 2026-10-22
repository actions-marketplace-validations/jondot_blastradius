//! Manifests: the direct dependencies, each with its spec and the line it is written on.
//!
//! `ManifestDep::section` is None for a production dependency. A development or group dependency carries a section name
//! that contains `dev` (`devDependencies`, `dev-dependencies`, `dev-dependencies (group test)`), because callers decide
//! "dev" from that word. Extras and optional dependencies carry `optional-dependencies.<extra>` and are not dev.
use std::collections::BTreeMap;

use serde_json::Value;

use super::idx::{join_path, json_paths, pep508, toml_index, TomlIndex};
use crate::view::{Manifest, ManifestDep};

pub const MANIFESTS: &[&str] = &["package.json", "pyproject.toml", "Pipfile", "Cargo.toml", "go.mod", "requirements.txt"];

type Deps = BTreeMap<String, ManifestDep>;

/// The manifest, or why it could not be read. A file that does not parse is an error here, never "no dependencies".
pub fn try_parse(path: &str, text: &str) -> Result<Manifest, String> {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let deps = match base {
        "package.json" => package_json(text)?,
        "go.mod" => go_mod(text),
        "Cargo.toml" => cargo_toml(text)?,
        "Pipfile" => pipfile(text)?,
        "pyproject.toml" => pyproject(text)?,
        _ if super::lock::is_requirements(path) || super::lock::is_requirements_in(path) => requirements(text),
        _ => Deps::new(),
    };
    Ok(Manifest { path: path.to_string(), deps })
}

/// Like [`try_parse`] for callers that only want what could be read (an unreadable file gives no dependencies).
pub fn parse(path: &str, text: &str) -> Manifest {
    try_parse(path, text).unwrap_or_else(|_| Manifest { path: path.to_string(), deps: Deps::new() })
}

fn add(out: &mut Deps, name: &str, spec: Option<String>, line: Option<u32>, section: Option<String>) {
    out.entry(name.to_string()).or_insert(ManifestDep { spec, line, section });
}

fn package_json(text: &str) -> Result<Deps, String> {
    let mut out = Deps::new();
    let v = serde_json::from_str::<Value>(text).map_err(|e| e.to_string())?;
    let paths = json_paths(text);
    for sec in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
        let Some(o) = v[sec].as_object() else { continue };
        for (k, s) in o {
            let line = paths.get(&join_path(&[sec, k])).copied();
            add(&mut out, k, s.as_str().map(str::to_string), line, (sec != "dependencies").then(|| sec.to_string()));
        }
    }
    Ok(out)
}

fn go_mod(text: &str) -> Deps {
    let g = super::golang::parse_go_mod(text);
    let mut out = Deps::new();
    for r in &g.requires {
        add(&mut out, &r.path, Some(r.version.clone()), Some(r.line), None);
    }
    out
}

fn requirements(text: &str) -> Deps {
    let mut out = Deps::new();
    for r in super::pyreq::parse_lines(text).0 {
        add(&mut out, &r.name, (!r.spec.is_empty()).then(|| r.spec.clone()), Some(r.line), None);
    }
    out
}

/// The version of a Cargo/Poetry/Pipfile dependency value: a string, or a table with `version` (or a git/path source).
fn spec_of(v: &toml::Value) -> Option<String> {
    match v {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Table(t) => {
            if let Some(s) = t.get("version").and_then(|x| x.as_str()) {
                return Some(s.to_string());
            }
            if t.get("workspace").and_then(|x| x.as_bool()) == Some(true) {
                return Some("workspace".to_string());
            }
            for k in ["git", "path", "url", "file"] {
                if let Some(s) = t.get(k).and_then(|x| x.as_str()) {
                    return Some(format!("{k}:{s}"));
                }
            }
            None
        }
        _ => None,
    }
}

fn table_deps(out: &mut Deps, ix: &TomlIndex, table_path: &str, t: &toml::Value, section: Option<String>, rename: bool) {
    let Some(t) = t.as_table() else { return };
    for (k, v) in t {
        let name = if rename { v.get("package").and_then(|p| p.as_str()).unwrap_or(k) } else { k.as_str() };
        add(out, name, spec_of(v), ix.line(table_path, k), section.clone());
    }
}

fn cargo_toml(text: &str) -> Result<Deps, String> {
    let mut out = Deps::new();
    let v = toml::from_str::<toml::Value>(text).map_err(|e| e.message().to_string())?;
    let ix = toml_index(text);
    let secs = [("dependencies", None), ("build-dependencies", Some("build-dependencies")), ("dev-dependencies", Some("dev-dependencies"))];
    for (s, label) in secs {
        if let Some(t) = v.get(s) {
            table_deps(&mut out, &ix, s, t, label.map(str::to_string), true);
        }
    }
    if let Some(t) = v.get("workspace").and_then(|w| w.get("dependencies")) {
        table_deps(&mut out, &ix, "workspace.dependencies", t, Some("workspace.dependencies".into()), true);
    }
    if let Some(targets) = v.get("target").and_then(|t| t.as_table()) {
        for (cfg, tv) in targets {
            for (s, label) in secs {
                if let Some(t) = tv.get(s) {
                    // `[target.'cfg(windows)'.dependencies]`: the index names the table with the quotes removed
                    let path = format!("target.{cfg}.{s}");
                    table_deps(
                        &mut out,
                        &ix,
                        &path,
                        t,
                        Some(match label {
                            Some(l) => l.to_string(),
                            None => format!("target.{cfg}"),
                        }),
                        true,
                    );
                }
            }
        }
    }
    Ok(out)
}

fn pipfile(text: &str) -> Result<Deps, String> {
    let mut out = Deps::new();
    let v = toml::from_str::<toml::Value>(text).map_err(|e| e.message().to_string())?;
    let ix = toml_index(text);
    for (s, label) in [("packages", None), ("dev-packages", Some("dev-packages"))] {
        if let Some(t) = v.get(s) {
            table_deps(&mut out, &ix, s, t, label.map(str::to_string), false);
        }
    }
    Ok(out)
}

/// Lines on which each lowercase package name appears as the start of a quoted string, in file order.
fn quoted_names(text: &str) -> BTreeMap<String, Vec<u32>> {
    let re = regex::Regex::new(r#"["']([A-Za-z0-9][A-Za-z0-9._-]*)"#).unwrap();
    let mut m: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for (i, l) in text.lines().enumerate() {
        for c in re.captures_iter(l) {
            m.entry(super::idx::pep503(&c[1])).or_default().push(i as u32 + 1);
        }
    }
    m
}

fn pyproject(text: &str) -> Result<Deps, String> {
    let mut out = Deps::new();
    let v = toml::from_str::<toml::Value>(text).map_err(|e| e.message().to_string())?;
    let ix = toml_index(text);
    let occ = quoted_names(text);
    // a requirement array: each string is a PEP 508 requirement; the line is the first mention at or after the array's key
    let arr = |out: &mut Deps, a: &toml::Value, table: &str, key: &str, section: Option<String>| {
        let start = ix.line(table, key).unwrap_or(0);
        let Some(a) = a.as_array() else { return };
        for x in a {
            let Some(s) = x.as_str() else { continue }; // `{ include-group = "x" }` adds no package
            let Some((n, spec)) = pep508(s) else { continue };
            let line = occ.get(&super::idx::pep503(&n)).and_then(|ls| ls.iter().copied().find(|l| *l >= start).or(ls.first().copied()));
            add(out, &n, (!spec.is_empty()).then_some(spec), line, section.clone());
        }
    };
    if let Some(p) = v.get("project") {
        if let Some(a) = p.get("dependencies") {
            arr(&mut out, a, "project", "dependencies", None);
        }
        if let Some(t) = p.get("optional-dependencies").and_then(|t| t.as_table()) {
            for (extra, a) in t {
                arr(&mut out, a, "project.optional-dependencies", extra, Some(format!("optional-dependencies.{extra}")));
            }
        }
    }
    // PEP 735 groups: none of them is installed for users of the package
    if let Some(t) = v.get("dependency-groups").and_then(|t| t.as_table()) {
        for (g, a) in t {
            arr(&mut out, a, "dependency-groups", g, Some(format!("dev-dependencies (group {g})")));
        }
    }
    if let Some(a) = v.get("tool").and_then(|t| t.get("uv")).and_then(|u| u.get("dev-dependencies")) {
        arr(&mut out, a, "tool.uv", "dev-dependencies", Some("dev-dependencies".into()));
    }
    if let Some(t) = v.get("tool").and_then(|t| t.get("pdm")).and_then(|u| u.get("dev-dependencies")).and_then(|t| t.as_table()) {
        for (g, a) in t {
            arr(&mut out, a, "tool.pdm.dev-dependencies", g, Some(format!("dev-dependencies (group {g})")));
        }
    }
    if let Some(po) = v.get("tool").and_then(|t| t.get("poetry")) {
        let mut main = Deps::new();
        if let Some(t) = po.get("dependencies") {
            table_deps(&mut main, &ix, "tool.poetry.dependencies", t, None, false);
        }
        main.remove("python");
        for (k, d) in main {
            out.entry(k).or_insert(d);
        }
        if let Some(t) = po.get("dev-dependencies") {
            table_deps(&mut out, &ix, "tool.poetry.dev-dependencies", t, Some("dev-dependencies".into()), false);
        }
        if let Some(gs) = po.get("group").and_then(|g| g.as_table()) {
            for (g, gv) in gs {
                if let Some(t) = gv.get("dependencies") {
                    let section = if g == "main" { None } else { Some(format!("dev-dependencies (group {g})")) };
                    table_deps(&mut out, &ix, &format!("tool.poetry.group.{g}.dependencies"), t, section, false);
                }
            }
        }
        if let Some(t) = po.get("extras").and_then(|t| t.as_table()) {
            let _ = t; // extras name dependencies already listed above
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_unparseable_manifest_is_an_error_not_no_dependencies() {
        assert!(try_parse("package.json", "{ not json").is_err());
        assert!(try_parse("Cargo.toml", "[dependencies]\nx = = 1\n").is_err());
        assert!(try_parse("pyproject.toml", "[project\n").is_err());
        assert!(try_parse("Pipfile", "[packages\n").is_err());
        assert_eq!(try_parse("Cargo.toml", "[dependencies]\n").unwrap().deps.len(), 0);
        // TOML 1.1 multi-line inline tables are not read by toml 0.8: that is an error naming the file, never an empty list
        let t = "[dependencies]\ntokio = {\n  version = \"1\",\n  features = [\"rt\"],\n}\n";
        if toml::from_str::<toml::Value>(t).is_err() {
            assert!(try_parse("crates/a/Cargo.toml", t).is_err());
        }
    }

    #[test]
    fn pkg_json_lines() {
        let t = "{\n  \"name\": \"x\",\n  \"dependencies\": {\n    \"a\": \"^1.0.0\"\n  },\n  \"devDependencies\": {\n    \"b\": \"2\"\n  }\n}\n";
        let m = parse("package.json", t);
        assert_eq!(m.deps["a"].line, Some(4));
        assert_eq!(m.deps["b"].section.as_deref(), Some("devDependencies"));
        assert_eq!(m.deps["b"].line, Some(7));
    }
    #[test]
    fn pkg_json_same_name_in_two_sections() {
        let t = "{\n  \"dependencies\": {\n    \"left-pad\": \"1\"\n  },\n  \"peerDependencies\": {\n    \"left-pad\": \"*\",\n    \"react\": \"18\"\n  }\n}\n";
        let m = parse("package.json", t);
        assert_eq!(m.deps["left-pad"].line, Some(3));
        assert_eq!(m.deps["react"].line, Some(7));
    }
    #[test]
    fn gomod_and_req() {
        let m = parse("go.mod", "module x\n\nrequire (\n\tgithub.com/a/b v0.4.2\n)\n");
        assert_eq!(m.deps["github.com/a/b"].line, Some(4));
        let r = parse("requirements.txt", "# c\n\nNetprobe_Py==0.4.2\n");
        assert_eq!(r.deps["Netprobe_Py"].spec.as_deref(), Some("==0.4.2"));
        assert_eq!(r.deps["Netprobe_Py"].line, Some(3));
    }
    #[test]
    fn requirements_markers_and_layout() {
        let r = parse("requirements/base.txt", "-r common.txt\nDjango>=4.2,<5 ; python_version >= \"3.9\"\nrequests[security]==2.32.3 \\\n    --hash=sha256:abc\n");
        assert_eq!(r.deps["Django"].spec.as_deref(), Some(">=4.2,<5"));
        assert_eq!(r.deps["requests"].line, Some(3));
        assert_eq!(r.deps.len(), 2);
    }
    #[test]
    fn cargo_workspace_target_and_inherited() {
        let t = "[package]\nname = \"x\"\n\n[workspace.dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }\n\n[dependencies]\nserde.workspace = true\ntokio = { version = \"1\", features = [\"rt\"] }\n# old = \"1\"\nrenamed = { package = \"real-name\", version = \"2\" }\n\n[dev-dependencies.pretty_assertions]\nversion = \"1.4\"\n\n[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n";
        let m = parse("Cargo.toml", t);
        assert!(!m.deps.contains_key("serde.workspace"));
        assert_eq!(m.deps["serde"].spec.as_deref(), Some("workspace"));
        assert_eq!(m.deps["serde"].line, Some(8));
        assert_eq!(m.deps["tokio"].spec.as_deref(), Some("1"));
        assert_eq!(m.deps["tokio"].line, Some(9));
        assert!(!m.deps.contains_key("old"));
        assert_eq!(m.deps["real-name"].spec.as_deref(), Some("2"));
        assert_eq!(m.deps["pretty_assertions"].section.as_deref(), Some("dev-dependencies"));
        assert_eq!(m.deps["winapi"].section.as_deref(), Some("target.cfg(windows)"));
        assert_eq!(m.deps["winapi"].line, Some(17));
    }
    #[test]
    fn pipfile_quoted_keys() {
        let t = "[packages]\n\"requests\" = \"*\"\nflask = {version = \"==2.0.1\", extras = [\"async\"]}\n\n[dev-packages]\npytest = \"*\"\n";
        let m = parse("Pipfile", t);
        assert_eq!(m.deps["requests"].line, Some(2));
        assert_eq!(m.deps["flask"].spec.as_deref(), Some("==2.0.1"));
        assert_eq!(m.deps["pytest"].section.as_deref(), Some("dev-packages"));
    }
    #[test]
    fn pyproject_poetry_groups_pep621_and_pep735() {
        let t = "[project]\nname = \"x\"\ndependencies = [\n  \"httpx>=0.27 ; python_version >= '3.9'\",\n  \"rich\",\n]\n\n[project.optional-dependencies]\ncli = [\"click>=8\"]\n\n[dependency-groups]\ndev = [\"pytest>=8\", {include-group = \"lint\"}]\nlint = [\"ruff\"]\n\n[tool.poetry.dependencies]\npython = \"^3.10\"\nattrs = \"^23\"\n\n[tool.poetry.group.dev.dependencies]\nblack = \"^24\"\n\n[tool.poetry.group.docs.dependencies]\nmkdocs = { version = \"^1.5\" }\n\n[tool.uv]\ndev-dependencies = [\"mypy\"]\n";
        let m = parse("pyproject.toml", t);
        assert_eq!(m.deps["httpx"].spec.as_deref(), Some(">=0.27"));
        assert_eq!(m.deps["httpx"].line, Some(4));
        assert_eq!(m.deps["httpx"].section, None);
        assert_eq!(m.deps["click"].section.as_deref(), Some("optional-dependencies.cli"));
        assert_eq!(m.deps["pytest"].section.as_deref(), Some("dev-dependencies (group dev)"));
        assert_eq!(m.deps["pytest"].line, Some(12));
        assert_eq!(m.deps["ruff"].line, Some(13));
        assert!(!m.deps.contains_key("python"));
        assert_eq!(m.deps["attrs"].section, None);
        assert_eq!(m.deps["black"].section.as_deref(), Some("dev-dependencies (group dev)"));
        assert_eq!(m.deps["mkdocs"].spec.as_deref(), Some("^1.5"));
        assert_eq!(m.deps["mypy"].section.as_deref(), Some("dev-dependencies"));
    }
}
