//! The npm packages are cut from the release archives, so npm/, the release workflow and Cargo.toml must agree.
//! These read the real files in the repo; nothing here is a copy of them.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_yaml::Value;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn release() -> Value {
    serde_yaml::from_str(&read(".github/workflows/release.yml")).expect("release.yml is yaml")
}

fn release_targets() -> BTreeSet<String> {
    release()["jobs"]["build"]["strategy"]["matrix"]["include"]
        .as_sequence()
        .expect("the build job has a matrix include list")
        .iter()
        .map(|row| row["target"].as_str().expect("each row has a target").to_string())
        .collect()
}

fn npm_platforms() -> serde_json::Map<String, serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(&read("npm/platforms.json")).expect("platforms.json is json");
    v.as_object().expect("platforms.json is an object").clone()
}

#[test]
fn every_npm_platform_is_built_by_the_release() {
    let built = release_targets();
    for (key, target) in npm_platforms() {
        let target = target.as_str().expect("each platform maps to a target");
        assert!(built.contains(target), "npm platform {key} wants {target}, which release.yml does not build");
    }
}

#[test]
fn every_release_target_has_an_npm_package() {
    let mapped: BTreeSet<String> = npm_platforms().values().filter_map(|t| t.as_str().map(String::from)).collect();
    for target in release_targets() {
        assert!(mapped.contains(&target), "release.yml builds {target} but npm/platforms.json has no package for it");
    }
}

#[test]
fn npm_and_the_release_name_archives_the_same_way() {
    let wf = read(".github/workflows/release.yml");
    assert!(wf.contains(r#"name="br-${version}-${{ matrix.target }}""#), "release.yml archive name changed");
    let pack = read("npm/pack.mjs");
    assert!(pack.contains("`br-${version}-${target}.${windows ? \"zip\" : \"tar.gz\"}`"), "pack.mjs archive name changed");
}

#[test]
fn a_release_tag_must_match_the_crate_version() {
    let wf = read(".github/workflows/release.yml");
    assert!(wf.contains("Cargo.toml") && wf.contains("GITHUB_REF_NAME"), "release.yml no longer checks the tag against Cargo.toml");
}

#[test]
fn npm_publishes_only_when_enabled_and_with_provenance() {
    let npm = &release()["jobs"]["npm"];
    assert_eq!(npm["if"].as_str(), Some("vars.NPM_PUBLISH == '1'"));
    let runs: String = npm["steps"].as_sequence().unwrap().iter().filter_map(|s| s["run"].as_str()).collect();
    assert!(runs.contains("--provenance"), "npm publish lost --provenance");
}

#[test]
fn the_skill_names_itself_and_says_when_to_use_it() {
    let skill = read("skills/blastradius/SKILL.md");
    let front = skill.strip_prefix("---\n").and_then(|s| s.split("\n---\n").next()).expect("SKILL.md starts with frontmatter");
    let y: Value = serde_yaml::from_str(front).expect("frontmatter is yaml");
    assert_eq!(y["name"].as_str(), Some("blastradius"));
    assert!(y["description"].as_str().is_some_and(|d| d.len() > 40), "the skill needs a real description");
}
