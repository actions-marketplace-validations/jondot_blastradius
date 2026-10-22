//! Shared words and small helpers for hints.

/// How the GitHub token is found, as help and hints say it.
pub const TOKEN_WORDS: &str = "GITHUB_TOKEN or GH_TOKEN, or a gh login";

/// A host registered with `br hosts add` that no scan has read yet.
pub fn never_scanned(s: &crate::view::Source) -> bool {
    s.gaps.iter().any(|g| g.scope == "registered")
}

/// Edit distance between two names (case-insensitive).
pub fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.to_lowercase().chars().collect(), b.to_lowercase().chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i];
        for j in 1..=b.len() {
            cur.push((prev[j - 1] + usize::from(a[i - 1] != b[j - 1])).min(prev[j] + 1).min(cur[j - 1] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// The candidate closest to `name`, when it is close enough to be a typo (about a third of the name may differ).
pub fn nearest<'a>(name: &str, candidates: impl IntoIterator<Item = &'a String>) -> Option<String> {
    let limit = (name.chars().count() / 3).max(2);
    candidates.into_iter().map(|c| (edit_distance(name, c), c)).filter(|(d, _)| *d <= limit).min_by_key(|(d, _)| *d).map(|(_, c)| c.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_suggests_a_typo_and_nothing_far() {
        let names = vec!["ci-ubuntu-07".to_string(), "laptop-priya".to_string()];
        assert_eq!(nearest("ci-ubuntu-7", &names).as_deref(), Some("ci-ubuntu-07"));
        assert_eq!(nearest("build-box", &names), None);
    }

    #[test]
    fn a_registered_host_is_never_scanned_until_a_scan_replaces_its_gap() {
        let mut s = crate::view::Source::default();
        assert!(!never_scanned(&s));
        s.gaps.push(crate::view::Gap { scope: "registered".into(), reason: "x".into(), at: String::new() });
        assert!(never_scanned(&s));
    }
}
