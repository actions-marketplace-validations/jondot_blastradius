//! What an advisory says about running code at install time. The answer comes from the advisory itself: the OSV
//! id prefix for malicious-package reports, and the advisory's own words. Never from a package name.

use crate::view::Advisory;

/// OSV id prefixes that mean "malicious package" (the OpenSSF malicious-packages feed uses `MAL-`).
const MALICIOUS_ID_PREFIXES: &[&str] = &["MAL-"];

/// Phrases advisories use for code that runs when a package is installed, one row per ecosystem habit.
/// npm lifecycle scripts, Python build/setup hooks, Ruby extensions, Rust build scripts, and the plain words.
const INSTALL_TIME_WORDS: &[&str] = &[
    "install script",
    "install-time",
    "install time",
    "at install",
    "during install",
    "on install",
    "postinstall",
    "preinstall",
    "post-install",
    "pre-install",
    "install hook",
    "lifecycle script",
    "setup.py",
    "build script",
    "build.rs",
    "native extension",
];

/// Words that turn a phrase around when they come just before it ("no install script", "does not run a postinstall").
const NEGATIONS: &[&str] = &["no ", "not ", "without ", "n't ", "never ", "lacks ", "free of "];

fn says_install_time(text: &str) -> bool {
    let low = text.to_lowercase();
    for w in INSTALL_TIME_WORDS {
        let mut from = 0;
        while let Some(i) = low[from..].find(w) {
            let at = from + i;
            let mut start = at.saturating_sub(24);
            while !low.is_char_boundary(start) {
                start -= 1;
            }
            let before = &low[start..at];
            if !NEGATIONS.iter().any(|n| before.contains(n)) {
                return true;
            }
            from = at + w.len();
        }
    }
    false
}

/// Does installing a package named by this advisory run the attacker's code? True for OSV malicious-package ids and
/// for advisories whose own title or text says an install script, postinstall or the like does it.
pub fn runs_at_install_parts(id: &str, aliases: &[String], title: &str, text: &str) -> bool {
    let up = |s: &str| s.trim().to_uppercase();
    std::iter::once(id).chain(aliases.iter().map(|a| a.as_str())).any(|i| MALICIOUS_ID_PREFIXES.iter().any(|p| up(i).starts_with(p))) || says_install_time(title) || says_install_time(text)
}

pub fn runs_at_install(adv: &Advisory) -> bool {
    runs_at_install_parts(&adv.id, &adv.aliases, adv.title.as_deref().unwrap_or(""), adv.text.as_deref().unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adv(id: &str, title: &str, text: &str) -> Advisory {
        Advisory { id: id.into(), title: Some(title.into()), text: Some(text.into()), ..Default::default() }
    }

    #[test]
    fn osv_malicious_package_id_is_an_install_time_run() {
        assert!(runs_at_install(&adv("MAL-2026-1234", "Malicious code in a package", "")));
    }

    #[test]
    fn the_advisorys_own_words_decide() {
        assert!(runs_at_install(&adv("GHSA-aaaa-bbbb-cccc", "worm", "The package adds a postinstall script that reads ~/.npmrc.")));
        assert!(runs_at_install(&adv("GHSA-aaaa-bbbb-cccc", "x", "A setup.py hook downloads a payload when pip installs it.")));
        assert!(runs_at_install(&adv("CVE-2026-1", "Backdoor", "Runs code during install via an install script.")));
    }

    #[test]
    fn an_ordinary_vulnerability_is_not() {
        assert!(!runs_at_install(&adv("GHSA-aaaa-bbbb-cccc", "Prototype pollution", "A crafted object pollutes Object.prototype.")));
        assert!(!runs_at_install(&adv("GHSA-aaaa-bbbb-cccc", "x", "The package has no install script; the flaw is in the parser.")));
    }
}
