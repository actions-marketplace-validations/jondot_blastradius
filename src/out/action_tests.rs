//! The integration files (action.yml, the pre-commit hook, the docs) must agree with each other and with the code.
//! These read the real files in the repo; nothing here is a copy of them.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_yaml::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn yaml(rel: &str) -> Value {
    serde_yaml::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn hook_regex() -> regex::Regex {
    let y = yaml(".pre-commit-hooks.yaml");
    let pat = y[0]["files"].as_str().expect("the hook has a files: pattern").to_string();
    regex::Regex::new(&pat).expect("the files: pattern is a regex")
}

#[test]
fn the_hook_matches_every_lockfile_br_reads_and_nothing_else() {
    let re = hook_regex();
    // every name the lockfile reader knows, at the root and nested
    for name in crate::parse::lock::LOCKFILES {
        for path in [name.to_string(), format!("apps/web/{name}")] {
            assert!(crate::parse::lock::is_lockfile(&path), "{path} is a lockfile to br");
            assert!(re.is_match(&path), "the hook skips {path}, which br reads");
        }
    }
    for path in ["vendor/modules.txt", "requirements/base.txt", "dev-requirements.txt", "requirements-dev.txt", "constraints.txt", "svc/requirements.txt"] {
        assert!(crate::parse::lock::is_lockfile(path), "{path}");
        assert!(re.is_match(path), "the hook skips {path}, which br reads");
    }
    for path in ["src/main.rs", "README.md", "package.json", "Cargo.toml", "package-lock.json.bak", "notes/modules.txt", "docs/yarn.lock.md"] {
        assert!(!re.is_match(path), "the hook would run on {path}");
    }
}

#[test]
fn every_input_is_documented_and_every_input_used_is_declared() {
    let y = yaml("action.yml");
    let declared: BTreeSet<String> = y["inputs"].as_mapping().unwrap().keys().map(|k| k.as_str().unwrap().to_string()).collect();
    let docs = read("docs/action.md");
    for name in &declared {
        assert!(docs.contains(&format!("`{name}`")), "docs/action.md does not document the input {name}");
        assert!(y["inputs"][name.as_str()]["description"].as_str().is_some_and(|d| !d.is_empty()), "input {name} has no description");
        assert!(y["inputs"][name.as_str()].get("default").is_some(), "input {name} has no default");
    }
    let text = read("action.yml");
    let used: BTreeSet<String> = regex::Regex::new(r"inputs\.([A-Za-z0-9_-]+)").unwrap().captures_iter(&text).map(|c| c[1].to_string()).collect();
    for u in &used {
        assert!(declared.contains(u), "action.yml uses inputs.{u}, which it does not declare");
    }
    for d in &declared {
        assert!(used.contains(d), "input {d} is declared and never used");
    }
}

#[test]
fn every_variable_the_scripts_read_is_set_by_the_action() {
    let y = yaml("action.yml");
    let mut set: BTreeSet<String> = BTreeSet::new();
    for step in y["runs"]["steps"].as_sequence().unwrap() {
        if let Some(env) = step["env"].as_mapping() {
            set.extend(env.keys().map(|k| k.as_str().unwrap().to_string()));
        }
    }
    let re = regex::Regex::new(r"\$\{?(BR_[A-Z0-9_]+)").unwrap();
    // BR_BIN, BR_OUT_DIR, BR_RELEASE_BASE and BR_INSTALL_DIR are optional knobs for local use and mirrors
    let optional: BTreeSet<&str> = ["BR_BIN", "BR_OUT_DIR", "BR_RELEASE_BASE", "BR_INSTALL_DIR", "BR_HOME"].into_iter().collect();
    for script in ["action/run.sh", "action/install.sh", "action/enforce.sh"] {
        for c in re.captures_iter(&read(script)) {
            let v = &c[1];
            assert!(set.contains(v) || optional.contains(v), "{script} reads {v}, which action.yml never sets");
        }
    }
}

#[test]
fn the_pinned_release_is_a_version_number() {
    let v = read("action/VERSION");
    assert!(regex::Regex::new(r"^\d+\.\d+\.\d+\n?$").unwrap().is_match(&v), "action/VERSION is {v:?}");
}

#[test]
fn the_action_is_a_composite_that_never_asks_for_a_token() {
    let y = yaml("action.yml");
    assert_eq!(y["runs"]["using"].as_str(), Some("composite"));
    let text = read("action.yml");
    assert!(!text.contains("GITHUB_TOKEN") && !text.contains("secrets."), "checkout mode must not need a token");
    // the upload is the only step that may fail without ending the job's answer, and enforcement comes last
    let steps = y["runs"]["steps"].as_sequence().unwrap();
    let names: Vec<&str> = steps.iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Install br", "Hunt", "Upload SARIF", "Enforce"]);
    assert!(steps[2]["uses"].as_str().unwrap().starts_with("github/codeql-action/upload-sarif@"));
}

#[test]
fn inputs_reach_the_scripts_as_environment_never_as_script_text() {
    let y = yaml("action.yml");
    for step in y["runs"]["steps"].as_sequence().unwrap() {
        if let Some(run) = step["run"].as_str() {
            assert!(!run.contains("inputs."), "step {:?} splices an input into shell text", step["name"]);
            assert!(!run.contains("steps.") || run.contains("github.action_path"), "{run}");
            for line in run.lines() {
                // only the script path may be interpolated
                let stripped = line.replace("${{ github.action_path }}", "");
                assert!(!stripped.contains("${{"), "step {:?} interpolates into shell text: {line}", step["name"]);
            }
        }
    }
}

#[test]
fn the_selftest_workflow_runs_this_action_on_a_bad_and_a_clean_fixture() {
    let w = yaml(".github/workflows/action-selftest.yml");
    let jobs = w["jobs"].as_mapping().unwrap();
    assert!(jobs.len() >= 3);
    let text = read(".github/workflows/action-selftest.yml");
    assert!(text.contains("uses: ./"));
    for fixture in ["tests/action/bad", "tests/action/clean"] {
        assert!(text.contains(fixture), "{fixture} is not used");
        assert!(root().join(fixture).join("package-lock.json").is_file(), "{fixture} has no lockfile");
    }
}

#[test]
fn the_hook_script_is_the_entry_the_hook_file_names() {
    let y = yaml(".pre-commit-hooks.yaml");
    let entry = y[0]["entry"].as_str().unwrap();
    assert!(root().join(entry).is_file(), "{entry}");
    assert_eq!(y[0]["language"].as_str(), Some("script"));
    assert_eq!(y[0]["pass_filenames"].as_bool(), Some(true));
    assert_eq!(y[0]["id"].as_str(), Some("blastradius"));
}

#[test]
fn the_action_metadata_fits_the_marketplace_limits() {
    let y = yaml("action.yml");
    let name = y["name"].as_str().expect("action.yml has a name");
    let desc = y["description"].as_str().expect("action.yml has a description");
    assert!(!name.trim().is_empty());
    // the Marketplace refuses to list an action whose description is 125 characters or longer
    assert!(desc.chars().count() < 125, "description is {} characters: {desc}", desc.chars().count());
    assert!(y["branding"]["icon"].as_str().is_some() && y["branding"]["color"].as_str().is_some(), "the Marketplace needs branding");
}
