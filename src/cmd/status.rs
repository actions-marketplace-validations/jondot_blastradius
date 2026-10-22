//! `br status`.

use std::collections::BTreeSet;

use crate::collect::words::never_scanned;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::query::index::Index;
use crate::query::util::*;

#[derive(Debug, Clone, Default, clap::Args)]
pub struct StatusArgs {
    /// list every source, not only the stale ones
    #[arg(long)]
    pub all: bool,
    /// exit 5 if any source is older than this (e.g. 12h, 2d)
    #[arg(long = "max-age", value_name = "DUR")]
    pub max_age: Option<String>,
    /// show the index path, staleness threshold and file hash filter
    #[arg(long)]
    pub config: bool,
    /// only the sources this team or person owns (frontend, @acme/frontend, dana): their freshness, not the whole index's
    #[arg(long, value_name = "TEAM")]
    pub owner: Option<String>,
}

/// runner | laptop | server, or "host" when nobody said and the machine could not tell. A name or a reach never decides.
fn host_kind(ix: &Index, name: &str) -> &'static str {
    crate::store::view_kind(ix.host_def(name).and_then(|h| h.kind.as_deref()).unwrap_or(""))
}

struct Pop {
    hosts: usize,
    runners: usize,
    laptops: usize,
    servers: usize,
    others: usize,
    members: usize,
    missing: usize,
    source_label: String,
    stale_laptops: Vec<String>,
    empty: Vec<String>,
}

fn population(_ctx: &Ctx, ix: &Index) -> Pop {
    let hosts = ix.names("host");
    let runners = hosts.iter().filter(|n| host_kind(ix, n) == "runner").count();
    let laptops: Vec<&String> = hosts.iter().filter(|n| host_kind(ix, n) == "laptop").collect();
    let servers = hosts.iter().filter(|n| host_kind(ix, n) == "server").count();
    let others = hosts.iter().filter(|n| host_kind(ix, n) == "host").count();
    // The one laptop-coverage truth (hosts, hunt, notify and evidence use it too)
    let mc = crate::query::coverage::members_covered(ix, &crate::query::hunt::Query::default());
    let (members, missing) = (mc.members, mc.members - mc.covered);
    Pop {
        hosts: hosts.len(),
        runners,
        laptops: laptops.len(),
        servers,
        others,
        members,
        missing,
        source_label: mc.source_label,
        stale_laptops: laptops.iter().filter(|n| is_stale(&ix.now, &ix.srcs[**n].indexed_at)).map(|n| n.to_string()).collect(),
        empty: hosts.iter().filter(|n| ix.srcs[*n].empty && !never_scanned(&ix.srcs[*n])).cloned().collect(),
    }
}

fn population_line(ix: &Index, p: &Pop) -> String {
    let mut parts = vec![];
    if p.runners > 0 {
        parts.push(plural(p.runners, "runner"));
    }
    if p.laptops > 0 {
        parts.push(plural(p.laptops, "laptop"));
    }
    if p.servers > 0 {
        parts.push(plural(p.servers, "server"));
    }
    if p.others > 0 {
        parts.push(format!("{} of unknown kind", p.others));
    }
    let mut line = format!("hosts: {} indexed{}", p.hosts, if parts.is_empty() { String::new() } else { format!(" ({})", parts.join(", ")) });
    if p.members > 0 {
        let org = ix.v.org.github.clone().filter(|o| !o.is_empty()).unwrap_or_else(|| "the org".into());
        line += &format!("; {org} has {} {}, {} with no laptop scan here{}", plural(p.members, "member"), p.source_label, p.missing, if p.missing > 0 { ": run br hosts to list them" } else { "" });
    }
    line
}

/// `br teams NAME`: one team, from the one record `br teams` lists: where it is told, its lead, its members, and the repos
/// and machines it owns. NAME is `@org/team` or the short name; an unknown name lists the teams there are.
pub fn team_show(ctx: &Ctx, name: &str) -> BrResult<i32> {
    let view = ctx.view().ok();
    let cfg = crate::collect::config::teams(ctx);
    let empty = crate::view::View::default();
    let v = view.as_ref().unwrap_or(&empty);
    let ix = Index::new(v, &ctx.now);
    let mut ids: Vec<String> = v.teams.iter().map(|t| t.id.clone()).collect();
    for id in cfg.keys() {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    ids.sort();
    let low = name.trim().to_lowercase();
    let short = |id: &str| id.rsplit('/').next().unwrap_or(id).to_lowercase();
    let hits: Vec<&String> = ids.iter().filter(|id| id.to_lowercase() == low || id.to_lowercase() == format!("@{low}") || short(id) == low.trim_start_matches('@')).collect();
    let id = match hits.as_slice() {
        [one] => (*one).clone(),
        [] => {
            // the word may be a mistyped subcommand as well as a team that is not there: name both
            let shorts: Vec<String> = ids.iter().map(|id| id.rsplit('/').next().unwrap_or(id).to_string()).collect();
            let near = crate::collect::words::nearest(low.trim_start_matches('@'), shorts.iter()).map(|n| format!("did you mean {n}? ")).unwrap_or_default();
            let hint = near
                + &if ids.is_empty() { "br init --org ORG reads GitHub's teams; subcommands: 'list', 'set'".to_string() } else { format!("teams: {}; subcommands: 'list', 'set'", ids.join(", ")) };
            return Err(BrError::with_code(format!("no team called \"{name}\""), Some(&hint), 2));
        }
        many => {
            return Err(BrError::new(format!("\"{name}\" is ambiguous: it could be {}", many.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), Some("write the full team (@org/team)")));
        }
    };
    let gh = v.teams.iter().find(|t| t.id == id);
    let c = cfg.get(&id);
    let pick = |a: Option<&Option<String>>, b: Option<&Option<String>>| {
        a.and_then(|x| x.clone()).filter(|x| !x.is_empty()).or_else(|| b.and_then(|x| x.clone()).filter(|x| !x.is_empty())).unwrap_or_else(|| "-".into())
    };
    let slack = pick(gh.map(|t| &t.slack), c.map(|t| &t.slack));
    let jira = pick(gh.map(|t| &t.jira), c.map(|t| &t.jira));
    let lead = gh.and_then(|t| t.lead.clone()).map(|l| format!("{} (@{l})", ix.person_name(&l))).unwrap_or_else(|| "-".into());
    println!("{id}");
    println!("  slack: {slack}   jira: {jira}   lead: {lead}");
    println!("  {}", if gh.is_some() { "GitHub knows this team" } else { "not in GitHub: only teams.yaml knows it" });
    let members: Vec<String> =
        v.people.iter().filter(|p| !p.login.ends_with("[bot]") && ix.person_team_ids(&p.login).contains(&id)).map(|p| format!("{} (@{})", ix.person_name(&p.login), p.login)).collect();
    println!("  members ({}): {}", members.len(), if members.is_empty() { "none on record".to_string() } else { members.join(", ") });
    // The same owner every screen shows: the CODEOWNERS team when GitHub resolves it, else the suggested person
    let mut repos: Vec<String> = vec![];
    let mut suggested: Vec<String> = vec![];
    let member_ids: Vec<String> = v.people.iter().filter(|p| ix.person_team_ids(&p.login).contains(&id)).map(|p| p.login.to_lowercase()).collect();
    for r in ix.names("repo") {
        let owners: Vec<crate::query::hunt::Owner> =
            ix.lock_paths(&r).iter().map(|p| Some(p.as_str())).chain(std::iter::once(None)).map(|p| crate::query::hunt::repo_owner_suggested(&ix, &r, p)).collect();
        if owners.iter().any(|o| o.suggested.is_none() && o.teams().any(|t| *t == id)) {
            repos.push(r);
        } else if owners.iter().any(|o| o.suggested.is_some() && o.people.iter().any(|p| member_ids.contains(&p.to_lowercase()))) {
            suggested.push(r);
        }
    }
    println!("  repos it owns ({}): {}", repos.len(), if repos.is_empty() { "none by CODEOWNERS".to_string() } else { repos.join(", ") });
    if !suggested.is_empty() {
        println!(
            "  repos suggested to its members ({}): {} (CODEOWNERS names no team GitHub resolves there; br suggests the person who archived it or last committed)",
            suggested.len(),
            suggested.join(", ")
        );
    }
    let hosts: Vec<String> = ix.names("host").into_iter().filter(|h| crate::query::hunt::host_owner(&ix, h).teams().any(|t| *t == id)).collect();
    if !hosts.is_empty() {
        println!("  machines it owns ({}): {}", hosts.len(), hosts.join(", "));
    }
    if slack == "-" && jira == "-" {
        println!();
        println!("no Slack channel or Jira project yet: br teams set {id} --slack '#channel' --jira KEY");
    }
    Ok(0)
}

pub fn run(a: &StatusArgs, ctx: &Ctx) -> BrResult<i32> {
    if a.config {
        println!("index: {}", crate::store::index_path(ctx).display());
        println!("staleness threshold: {}", stale_label());
        println!("stage 1: metadata walk (path, size, mtime, mode) of every file under the scan roots");
        println!("stage 2 hash filter:");
        for g in crate::collect::config::hash_filter(ctx) {
            println!("  {g}");
        }
        println!("stage 2 simhash: text files <= 1 MB selected by the filter");
        return Ok(0);
    }
    let view = ctx.view()?;
    let ix = Index::new(&view, &ctx.now);
    // --owner narrows freshness to what that owner owns (the same sources a hunt with --owner would look at)
    let scope: Option<BTreeSet<String>> = match a.owner.as_ref().filter(|o| !o.is_empty()) {
        Some(o) => {
            let q = crate::query::hunt::Query { owner: Some(o.clone()), ..Default::default() };
            Some(crate::query::hunt::scope_sources(&ix, &q)?.into_iter().collect())
        }
        None => None,
    };
    let mut order: Vec<(&String, &crate::view::Source)> = ix.srcs.iter().filter(|(n, _)| scope.as_ref().map(|sc| sc.contains(*n)).unwrap_or(true)).collect();
    order.sort_by(|a, b| a.1.indexed_at.cmp(&b.1.indexed_at));
    let (mut rows, mut stale, mut empty_n) = (vec![], 0, 0usize);
    let mut stale_names: Vec<(String, String)> = vec![]; // (name, reach)
    let mut never: Vec<(String, String)> = vec![];
    for (n, s) in order.iter().copied() {
        let is_never = never_scanned(s);
        let old = !is_never && is_stale(&ix.now, &s.indexed_at);
        if s.empty && !old {
            empty_n += 1;
        }
        if old {
            stale += 1;
            stale_names.push((n.clone(), s.reach.clone()));
        }
        if is_never {
            never.push((n.clone(), s.reach.clone()));
        }
        if old || is_never || a.all {
            let (at, age) = if is_never { ("registered, never scanned".to_string(), "-".to_string()) } else { (fmt(&s.indexed_at), age_str(&ix.now, &s.indexed_at)) };
            rows.push(vec![n.clone(), s.kind.clone(), at, age, if s.reach.is_empty() { "-".into() } else { s.reach.clone() }]);
        }
    }
    let total = order.len();
    if let Some(m) = &a.max_age {
        let limit = parse_dur(m)?;
        let over: Vec<(String, String, String)> =
            order.iter().filter(|(_, s)| !never_scanned(s) && parse_t(&ix.now) - parse_t(&s.indexed_at) > limit).map(|(n, s)| ((*n).clone(), s.reach.clone(), s.indexed_at.clone())).collect();
        let old: Vec<String> =
            order.iter().filter(|(_, s)| !never_scanned(s) && parse_t(&ix.now) - parse_t(&s.indexed_at) > limit).map(|(n, s)| format!("{n} ({})", age_str(&ix.now, &s.indexed_at))).collect();
        if !old.is_empty() {
            return Err(BrError::with_code(format!("index is stale: {} older than {m}: {}", plural(old.len(), "source"), name_list(&old)), Some(&max_age_hint(&ix.now, &over)), 5));
        }
    }
    if let Some(o) = &a.owner {
        println!("scoped to {o}: {} of {} sources", total, ix.srcs.len());
    }
    if empty_n > 0 {
        println!("{total} sources: {} fresh, {stale} stale, {empty_n} not checked (threshold {})", total - stale - empty_n, stale_label());
    } else {
        println!("{total} sources: {} fresh, {stale} stale (threshold {})", total - stale, stale_label());
    }
    {
        // the sources named the way claimcheck names them: "9 repos and 1 CI artifact"
        let n_kind = |k: &str| order.iter().filter(|(_, s)| s.kind == k).count();
        let artifacts: usize = order.iter().filter(|(_, s)| s.kind == "repo").filter_map(|(n, _)| view.repos.get(*n)).map(|r| crate::cmd::claimcheck::readable_artifacts(r, &ix.now, 8).len()).sum();
        println!(
            "by kind: {}",
            crate::collect::util::count_words(&[
                (n_kind("repo"), "repo", "repos"),
                (artifacts, "CI artifact", "CI artifacts"),
                (n_kind("host"), "host", "hosts"),
                (n_kind("registry"), "container registry", "container registries")
            ])
        );
    }
    {
        // How many trust store files (certificate bundles, keystores) the scans read
        let n_files = |t: &crate::view::TrustSet| t.files.len();
        let in_repos: usize = view.repos.values().map(|r| n_files(&r.trust)).sum();
        let on_hosts: usize = view.hosts.values().map(|h| n_files(&h.trust)).sum();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for b in &view.images {
            for l in &b.layers {
                for t in &l.trust {
                    seen.insert((b.digest.clone(), t.path.clone()));
                }
            }
        }
        let calls: u32 = view.repos.values().map(|r| r.trust.api_calls).sum();
        if in_repos + on_hosts + seen.len() > 0 {
            let mut line = format!("trust stores read: {} ({} in repos, {} in images, {} on hosts)", in_repos + on_hosts + seen.len(), in_repos, seen.len(), on_hosts);
            if calls > 0 {
                line += &format!("; {calls} extra GitHub calls to read repo files");
            }
            println!("{line}");
        }
    }
    let pop = population(ctx, &ix);
    if pop.hosts > 0 || pop.members > 0 {
        println!("{}", population_line(&ix, &pop));
        if !pop.stale_laptops.is_empty() {
            println!("stale laptops: {} (a laptop is only as fresh as its last import)", pop.stale_laptops.join(", "));
        }
        if !pop.empty.is_empty() {
            println!("empty scans: {} hashed 0 files, so they count as not checked", pop.empty.join(", "));
        }
    }
    // A repo whose lockfiles gave no package is named here, with the file and the reason one hunt away
    let no_pkgs: Vec<&String> = ix.srcs.iter().filter(|(n, s)| scope.as_ref().map(|sc| sc.contains(*n)).unwrap_or(true) && s.kind == "repo" && no_packages_gap(s)).map(|(n, _)| n).collect();
    if !no_pkgs.is_empty() {
        println!("{}: lockfiles read but no packages ({}); br hunt lists the files and why", plural(no_pkgs.len(), "repo"), name_list(&no_pkgs.iter().map(|n| n.to_string()).collect::<Vec<_>>()));
    }
    let with_gaps: Vec<&String> = ix.srcs.iter().filter(|(_, s)| !s.gaps.is_empty()).map(|(n, _)| n).collect();
    if !with_gaps.is_empty() {
        println!("{} could not be fully checked at their last scan; br hunt lists what", plural(with_gaps.len(), "source"));
    }
    if !rows.is_empty() {
        println!();
        println!("{}", table(&["SOURCE", "KIND", "INDEXED", "AGE", "REACH"], &rows, 0).join("\n"));
    }
    if !never.is_empty() {
        println!();
        println!("registered, never scanned: {} (every hunt lists them as not checked)", never.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", "));
    }
    if stale > 0 {
        println!();
        println!("{}", refresh_hint(&stale_names));
    }
    Ok(0)
}

/// Did the last scan read a lockfile of this source and get no packages from it?
fn no_packages_gap(s: &crate::view::Source) -> bool {
    s.gaps.iter().any(|g| g.scope.starts_with("lockfile ") && g.reason.starts_with(crate::collect::github::NO_PACKAGES))
}

/// "a (3d), b (5d) and 2 more": a list in a sentence shows the first few.
pub fn name_list(items: &[String]) -> String {
    if items.len() <= 5 {
        items.join(", ")
    } else {
        format!("{} and {} more", items[..5].join(", "), items.len() - 5)
    }
}

/// What to do about sources older than `--max-age`. They need not be stale by the staleness threshold, so `br scan --stale`
/// would rescan none of them; `br scan --all` rescans every source br can reach. An import-only machine is refreshed on it.
pub fn max_age_hint(now: &str, over: &[(String, String, String)]) -> String {
    // every source over the limit is also stale by the threshold: `br scan --stale` reaches exactly those
    if over.iter().all(|(_, _, at)| is_stale(now, at)) {
        let pairs: Vec<(String, String)> = over.iter().map(|(n, r, _)| (n.clone(), r.clone())).collect();
        return refresh_hint(&pairs);
    }
    let over: Vec<(String, String)> = over.iter().map(|(n, r, _)| (n.clone(), r.clone())).collect();
    let over = &over[..];
    let import_only = |r: &str| r == "import-only" || r == "local";
    let (theirs, mine): (Vec<&(String, String)>, Vec<&(String, String)>) = over.iter().partition(|(_, r)| import_only(r));
    let names = |v: &[&(String, String)]| v.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ");
    let tail = "(br scan --local --export NAME.brx --seal there, then br import NAME.brx here)";
    match (mine.is_empty(), theirs.is_empty()) {
        (_, true) => "run br scan --all to refresh every source br can reach from here".to_string(),
        (true, false) => format!("br scan cannot help: {} can only be refreshed on that machine {tail}", names(&theirs)),
        (false, false) => format!("run br scan --all to refresh every source br can reach from here; {} can only be refreshed on that machine {tail}", names(&theirs)),
    }
}

/// What to do about stale sources, told by who can do it: br scan --stale reaches repos, registries and ssh machines, never an
/// import-only or local machine, whose owner has to export again.
pub fn refresh_hint(stale: &[(String, String)]) -> String {
    let import_only = |r: &str| r == "import-only" || r == "local";
    let (theirs, mine): (Vec<&(String, String)>, Vec<&(String, String)>) = stale.iter().partition(|(_, r)| import_only(r));
    let names = |v: &[&(String, String)]| v.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ");
    match (mine.is_empty(), theirs.is_empty()) {
        (_, true) => "run br scan --stale to refresh the stale sources that can be reached from here".to_string(),
        (true, false) => {
            format!("br scan --stale cannot help: {} can only be refreshed on that machine (br scan --local --export NAME.brx --seal there, then br import NAME.brx here)", names(&theirs))
        }
        (false, false) => format!(
            "run br scan --stale to refresh {}; {} can only be refreshed on that machine (br scan --local --export NAME.brx --seal there, then br import NAME.brx here)",
            names(&mine),
            names(&theirs)
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn config_shows_the_collectors_real_hash_filter() {
        let home = std::env::temp_dir().join(format!("br-status-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let ctx = crate::ctx::Ctx { now: "2026-05-12T07:10:00Z".into(), home: home.clone(), user: None, host: None, color: false };
        let real = crate::collect::config::hash_filter(&ctx);
        assert_eq!(real.len(), crate::collect::util::DEFAULT_HASH_FILTER.len());
        assert!(real.iter().any(|g| g == "**/*.ps1"), "the default list has entries the old copy lacked");
        std::fs::write(home.join("config.yaml"), "hash_filter: ['**/*.rb']\n").unwrap();
        assert_eq!(crate::collect::config::hash_filter(&ctx), vec!["**/*.rb".to_string()]);
        let _ = std::fs::remove_dir_all(&home);
    }
}
