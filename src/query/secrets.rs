//! The one table of secrets a hunt answer puts at risk: secret -> scope -> runs -> repos -> owners.
//! Hunt's SECRETS TO ROTATE, the slack post, and (phase 2) fix and notify all read this function, so a secret that
//! several teams use is listed with all of them, and a count of secrets is the same number everywhere.

use std::collections::BTreeSet;

use super::hunt::{self as H, FKind, HuntResult};
use super::index::Index;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretUse {
    pub name: String,
    /// Where GitHub says it lives: `repo`, `org (all repos)`, `org (selected repos)`, `environment NAME`, or
    /// `not readable with this token`. br does not guess a scope.
    pub scope: String,
    /// CI runs in the answer (counted or past) that could read it
    pub runs: usize,
    pub repos: Vec<String>,
    /// every owner of those repos: resolved teams by id, people by `@login`. For an org secret these are the teams whose
    /// runs read it (see `used_by`); who can rotate it is `owner_label`.
    pub owners: Vec<String>,
    /// Who owns the secret. An org secret (all or selected repos) is owned by the org admins, `org admins (NAMES)`;
    /// any other secret by the owners of the repos that use it, joined, or `unresolved`.
    pub owner_label: String,
    /// The org admins' logins, for an org secret (empty otherwise)
    pub admins: Vec<String>,
    /// The teams and people whose runs read an org secret (empty for other scopes: the owners already are them)
    pub used_by: Vec<String>,
    /// How many separate secrets the name is. An org secret is one however many repos read it; a repo or environment secret
    /// is stored once per repo, so a name set in 3 repos is 3 secrets to rotate.
    pub separate: usize,
}

impl SecretUse {
    /// The owner as a table cell: who owns it, and for an org secret which teams' runs read it.
    pub fn owner_cell(&self) -> String {
        if self.used_by.is_empty() {
            self.owner_label.clone()
        } else {
            format!("{}; used by {}", self.owner_label, self.used_by.join(", "))
        }
    }
}

/// A scope label that names the org (`org (all repos)`, `org (selected repos)`).
pub fn is_org_scope(scope: &str) -> bool {
    scope.split(", ").any(|l| l.starts_with("org"))
}

/// What the scope column says when GitHub would not tell this token: never "unknown".
pub const UNREADABLE: &str = "not readable with this token";

/// Where a secret lives, as GitHub said: `repo`, `org (all repos)`, `org (selected repos)` or `environment NAME`, per
/// repo that uses it (several are joined). A list the token could not read is `not readable with this token`; a secret
/// that no readable list holds is `not listed by GitHub now` (deleted since the run, or renamed).
pub fn secret_scope(ix: &Index, name: &str, repos: &[String]) -> String {
    let mut labels: Vec<String> = vec![];
    let mut add = |l: String| {
        if !labels.contains(&l) {
            labels.push(l);
        }
    };
    let org = ix.v.secret_scopes.iter().find(|s| s.name == name);
    let org_unreadable = ix.v.secrets_unreadable.iter().any(|x| x == "org");
    let mut repos: Vec<&String> = repos.iter().collect();
    repos.sort();
    for r in repos {
        let own: Vec<&crate::view::SecretScope> = ix.v.repos.get(r.as_str()).map(|rp| rp.secret_scopes.iter().filter(|s| s.name == name).collect()).unwrap_or_default();
        if !own.is_empty() {
            own.iter().for_each(|s| add(s.scope.clone()));
        } else if let Some(o) = org {
            add(o.scope.clone());
        } else if org_unreadable || repo_secrets_unreadable(ix, r) {
            add(UNREADABLE.to_string());
        } else {
            add("not listed by GitHub now".to_string());
        }
    }
    if labels.is_empty() {
        labels.push(match org {
            Some(o) => o.scope.clone(),
            None if org_unreadable || (ix.v.secret_scopes.is_empty() && ix.v.org_secrets.is_empty()) => UNREADABLE.to_string(),
            None => "not listed by GitHub now".to_string(),
        });
    }
    labels.join(", ")
}

/// The repo's own secret lists were refused (a gap on its source).
fn repo_secrets_unreadable(ix: &Index, repo: &str) -> bool {
    ix.v.sources.get(repo).is_some_and(|s| s.gaps.iter().any(|g| g.scope == "repo secrets" || g.scope.starts_with("environment secrets")))
}

/// One row per secret name, in the order the runs list them first.
pub fn secret_uses(ix: &Index, res: &HuntResult) -> Vec<SecretUse> {
    let mut out: Vec<SecretUse> = vec![];
    for f in H::findings(res).into_iter().chain(H::past_runs(res)) {
        if f.kind != FKind::CiRun {
            continue;
        }
        for s in &f.secrets {
            let i = match out.iter().position(|u| &u.name == s) {
                Some(i) => i,
                None => {
                    out.push(SecretUse { name: s.clone(), ..Default::default() });
                    out.len() - 1
                }
            };
            let u = &mut out[i];
            u.runs += 1;
            if !u.repos.contains(&f.where_) {
                u.repos.push(f.where_.clone());
            }
            for o in H::owner_names(ix, &f.owner) {
                if !u.owners.contains(&o) {
                    u.owners.push(o);
                }
            }
        }
    }
    for u in out.iter_mut() {
        u.repos.sort();
        u.owners.sort();
        u.scope = secret_scope(ix, &u.name, &u.repos);
        let (mut org, mut per_repo) = (false, 0usize);
        for r in &u.repos {
            if is_org_scope(&secret_scope(ix, &u.name, std::slice::from_ref(r))) {
                org = true;
            } else {
                per_repo += 1;
            }
        }
        u.separate = (per_repo + usize::from(org)).max(1);
        if is_org_scope(&u.scope) {
            u.admins = ix.v.org_admins.iter().map(|a| a.trim_start_matches('@').to_string()).collect();
            let names: Vec<String> = u.admins.iter().map(|a| ix.person_name(a)).collect();
            u.owner_label = if names.is_empty() { "org admins (not on record)".to_string() } else { format!("org admins ({})", names.join(", ")) };
            u.used_by = u.owners.clone();
        } else {
            u.owner_label = if u.owners.is_empty() { "unresolved".to_string() } else { u.owners.join(", ") };
        }
    }
    out
}

/// The words for a count of secrets when names and separate secrets differ: "9 secrets", or "9 secret names, 11 secrets".
pub fn secret_words(names: usize, separate: usize) -> String {
    if separate <= names || separate == 0 {
        crate::query::util::plural(names, "secret")
    } else {
        format!("{} secret names, {} secrets", names, separate)
    }
}

/// The line that says a table of secret names holds more secrets than names, and which names are several: None when every
/// name is one secret.
pub fn separate_note(uses: &[SecretUse]) -> Option<String> {
    let total: usize = uses.iter().map(|u| u.separate).sum();
    if total <= uses.len() {
        return None;
    }
    let several: Vec<String> = uses.iter().filter(|u| u.separate > 1).map(|u| format!("{} ({} repos)", u.name, u.separate)).collect();
    Some(format!(
        "{}, {total} secrets: {} {} stored separately in each repo that uses {}",
        crate::query::util::plural(uses.len(), "secret name"),
        several.join(", "),
        if several.len() == 1 { "is" } else { "are" },
        if several.len() == 1 { "it" } else { "them" }
    ))
}

/// The names only, de-duplicated: for callers that need a count.
pub fn secret_names(ix: &Index, res: &HuntResult) -> BTreeSet<String> {
    secret_uses(ix, res).into_iter().map(|u| u.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::hunt::{Finding, Owner};
    use crate::view::View;

    fn run(repo: &str, id: u64, secrets: &[&str], team: &str) -> Finding {
        Finding {
            kind: FKind::CiRun,
            where_: repo.into(),
            id,
            secrets: secrets.iter().map(|s| s.to_string()).collect(),
            owner: Owner { team: Some(team.into()), ..Default::default() },
            ..Default::default()
        }
    }

    // A secret several teams use lists them all, with one run count and the scope GitHub gave
    #[test]
    fn a_secret_used_by_two_teams_lists_both_owners_and_its_scope() {
        let mut v = View::default();
        v.org_secrets = vec!["NPM_TOKEN".into()];
        v.secret_scopes = vec![crate::view::SecretScope { name: "NPM_TOKEN".into(), scope: "org (all repos)".into(), repos: vec![], ..Default::default() }];
        v.repos.insert(
            "acme/a".into(),
            crate::view::Repo {
                secret_scopes: vec![crate::view::SecretScope { name: "DEPLOY_KEY".into(), scope: "environment prod".into(), repos: vec![], ..Default::default() }],
                ..Default::default()
            },
        );
        v.teams = vec![crate::view::Team { id: "@acme/web".into(), ..Default::default() }, crate::view::Team { id: "@acme/growth".into(), ..Default::default() }];
        let ix = Index::new(&v, "2026-05-12T00:00:00Z");
        let res = HuntResult {
            findings: vec![run("acme/a", 1, &["NPM_TOKEN", "DEPLOY_KEY"], "@acme/web"), run("acme/b", 2, &["NPM_TOKEN"], "@acme/growth"), run("acme/a", 3, &["NPM_TOKEN"], "@acme/web")],
            ..Default::default()
        };
        let u = secret_uses(&ix, &res);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].name, "NPM_TOKEN");
        assert_eq!((u[0].scope.as_str(), u[0].runs), ("org (all repos)", 3));
        assert_eq!(u[0].repos, vec!["acme/a", "acme/b"]);
        assert_eq!(u[0].owners, vec!["@acme/growth", "@acme/web"]);
        assert_eq!(u[1].scope, "environment prod");
    }

    // An org secret is the org admins', whichever team's runs read it
    #[test]
    fn an_org_secret_is_owned_by_the_org_admins_and_lists_who_uses_it() {
        let mut v = View::default();
        v.org_admins = vec!["dokafor".into(), "lena".into()];
        v.people = vec![crate::view::Person { login: "dokafor".into(), name: Some("Dana Okafor".into()), ..Default::default() }];
        v.secret_scopes = vec![crate::view::SecretScope { name: "NPM_TOKEN".into(), scope: "org (selected repos)".into(), repos: vec![], ..Default::default() }];
        v.repos.insert(
            "acme/a".into(),
            crate::view::Repo { secret_scopes: vec![crate::view::SecretScope { name: "DEPLOY".into(), scope: "repo".into(), repos: vec![], ..Default::default() }], ..Default::default() },
        );
        v.teams = vec![crate::view::Team { id: "@acme/web".into(), ..Default::default() }];
        let ix = Index::new(&v, "2026-05-12T00:00:00Z");
        let res = HuntResult { findings: vec![run("acme/a", 1, &["NPM_TOKEN", "DEPLOY"], "@acme/web")], ..Default::default() };
        let u = secret_uses(&ix, &res);
        assert_eq!(u[0].owner_label, "org admins (Dana Okafor, lena)");
        assert_eq!((u[0].admins.clone(), u[0].used_by.clone()), (vec!["dokafor".to_string(), "lena".to_string()], vec!["@acme/web".to_string()]));
        // a repo-scoped secret stays with the owners of the repos that use it
        assert_eq!((u[1].owner_label.as_str(), u[1].used_by.len()), ("@acme/web", 0));
    }

    // A list the token could not read is said so, never "unknown"; a repo's own record wins over the org's
    #[test]
    fn an_unreadable_list_is_not_readable_with_this_token_never_unknown() {
        let mut v = View::default();
        v.secrets_unreadable = vec!["org".into()];
        let ix = Index::new(&v, "2026-05-12T00:00:00Z");
        assert_eq!(secret_scope(&ix, "X", &["o/r".to_string()]), UNREADABLE);
        assert_eq!(secret_scope(&ix, "X", &[]), UNREADABLE);
        let mut v = View::default();
        v.org_secrets = vec!["Y".into()];
        v.repos.insert(
            "o/r".into(),
            crate::view::Repo { secret_scopes: vec![crate::view::SecretScope { name: "X".into(), scope: "repo".into(), repos: vec![], ..Default::default() }], ..Default::default() },
        );
        let ix = Index::new(&v, "2026-05-12T00:00:00Z");
        assert_eq!(secret_scope(&ix, "X", &["o/r".to_string()]), "repo");
        assert_eq!(secret_scope(&ix, "Z", &["o/r".to_string()]), "not listed by GitHub now");
    }
}
