//! The variable NAMES a config file mentions (`.env.example`, compose, deploy configs). Names and line numbers only:
//! this module never returns the text after the `=` or `:`, so a value cannot reach the index through it.

use std::sync::LazyLock;

use regex::Regex;

use crate::view::EnvRef;

/// Most files read per repo, most bytes read per file, most names kept per file.
pub const MAX_FILES: usize = 24;
pub const MAX_BYTES: usize = 128 * 1024;
pub const MAX_NAMES: usize = 300;

static ASSIGN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?:^|[\s\-"'#]|\$\{)([A-Za-z_][A-Za-z0-9_]{2,})\s*[=:}]"#).unwrap());
static DOLLAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$([A-Z][A-Z0-9_]{2,})\b").unwrap());

/// Config files that name environment variables: env templates, compose files. Deploy configs are matched by their shape
/// (a YAML or TOML file in a `deploy`, `k8s`, `kubernetes`, `helm` or `charts` directory), never by a vendor's file name.
pub fn is_config_path(p: &str) -> bool {
    let base = p.rsplit('/').next().unwrap_or(p).to_lowercase();
    let tail = |b: &str| ["example", "sample", "template", "dist", "defaults"].iter().any(|t| b.ends_with(&format!(".{t}")));
    let env_template = (base.starts_with(".env") || base.starts_with("env.")) && tail(&base);
    let compose = (base.starts_with("docker-compose") || base.starts_with("compose")) && (base.ends_with(".yml") || base.ends_with(".yaml"));
    let deploy = (base.ends_with(".yml") || base.ends_with(".yaml") || base.ends_with(".toml"))
        && p.split('/').rev().skip(1).any(|d| matches!(d.to_lowercase().as_str(), "deploy" | "deployment" | "k8s" | "kubernetes" | "helm" | "charts"));
    let skipped = p.split('/').any(|d| matches!(d, "node_modules" | "vendor" | "target" | ".git"));
    !skipped && (env_template || compose || deploy)
}

/// The names (upper-case, after the shape of an environment variable) a file mentions, with the line of each.
pub fn env_names(file: &str, text: &str) -> Vec<EnvRef> {
    let mut out: Vec<EnvRef> = vec![];
    for (i, l) in text.lines().enumerate() {
        let mut here: Vec<String> = ASSIGN.captures_iter(l).map(|c| c[1].to_string()).chain(DOLLAR.captures_iter(l).map(|c| c[1].to_string())).collect();
        here.retain(|n| n.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
        for n in here {
            let line = (i + 1) as u32;
            if !out.iter().any(|e| e.name == n && e.line == line) {
                out.push(EnvRef { file: file.to_string(), line, name: n });
            }
        }
        if out.len() >= MAX_NAMES {
            break;
        }
    }
    out.truncate(MAX_NAMES);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_files_are_picked_by_shape_not_vendor() {
        for p in [".env.example", "svc/.env.sample", "docker-compose.yml", "compose.prod.yaml", "deploy/app.yaml", "k8s/web/dep.yml"] {
            assert!(is_config_path(p), "{p}");
        }
        for p in [".env", "src/main.rs", "node_modules/x/.env.example", "docs/compose.md", ".github/workflows/ci.yml"] {
            assert!(!is_config_path(p), "{p}");
        }
    }

    #[test]
    fn names_and_lines_come_out_and_values_do_not() {
        let t = "# comment\nPLAT_TOKEN=hunter2-secret-value\nexport OTHER_KEY=\"abc123\"\nservices:\n  web:\n    environment:\n      - DB_PASS=${DB_PASS}\n      API_KEY: realvalue99\n    cmd: run $RUN_TOKEN\n";
        let refs = env_names(".env.example", t);
        let names: Vec<(&str, u32)> = refs.iter().map(|e| (e.name.as_str(), e.line)).collect();
        for want in [("PLAT_TOKEN", 2), ("OTHER_KEY", 3), ("DB_PASS", 7), ("API_KEY", 8), ("RUN_TOKEN", 9)] {
            assert!(names.contains(&want), "{want:?} in {names:?}");
        }
        let all = format!("{refs:?}");
        for v in ["hunter2-secret-value", "abc123", "realvalue99"] {
            assert!(!all.contains(v), "a value leaked: {v}");
        }
    }
}
