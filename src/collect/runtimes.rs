//! Language runtimes a repo names: Dockerfile `FROM`, compose images, workflow setup steps, version files.
//! Read from file text at HEAD and, within a fixed budget, back through the history of each file. Nothing is run.

use std::collections::BTreeMap;

use crate::collect::github::{enc, enc_ref, s, skipped_dir, Gh};
use crate::collect::util::norm_api_time;
use crate::error::BrResult;
use crate::query::runtime::{self, Ref};
use crate::view::RuntimeRef;

/// Files whose history is read, newest commits per file, and the total number of file reads for history.
const MAX_FILES: usize = 60;
const COMMITS_PER_FILE: usize = 40;
const HISTORY_READS: usize = 400;

struct At {
    sha: String,
    time: String,
    author: Option<String>,
}

fn key(r: &Ref) -> (String, String, String) {
    (r.runtime.to_string(), r.spec.clone(), r.seen_as.clone())
}

pub fn collect(gh: &Gh, repo: &str, branch: &str, now: &str, tree: &[String]) -> BrResult<Vec<RuntimeRef>> {
    let mut files: Vec<&String> = tree.iter().filter(|p| !skipped_dir(p) && runtime::candidate(p)).collect();
    files.sort_by(|a, b| (a.matches('/').count(), a.as_str()).cmp(&(b.matches('/').count(), b.as_str())));
    if files.len() > MAX_FILES {
        gh.note("runtime files", format!("{} files can name a runtime; only the {MAX_FILES} nearest the repo root were read", files.len()));
        files.truncate(MAX_FILES);
    }
    let mut out: Vec<RuntimeRef> = vec![];
    let mut reads = 0usize;
    let mut budget_note = false;
    for path in files {
        let list = gh.list_max(&format!("/repos/{repo}/commits?sha={}&path={}&until={now}", enc_ref(branch), enc_ref(path)), None, COMMITS_PER_FILE)?;
        let (commits, cut) = (list.0.unwrap_or_default(), list.1);
        let Some(head_text) = gh.text(&format!("/repos/{repo}/contents/{}?ref={}", enc(path), enc_ref(branch)))? else { continue };
        let head = runtime::scan_file(path, &head_text);
        let ats: Vec<At> = commits
            .iter()
            .filter_map(|c| {
                let time = c["commit"]["committer"]["date"].as_str().and_then(norm_api_time).or_else(|| c["commit"]["author"]["date"].as_str().and_then(norm_api_time))?;
                Some(At { sha: s(c, "sha")?, time, author: c["author"]["login"].as_str().map(str::to_string).or_else(|| c["commit"]["author"]["name"].as_str().map(str::to_string)) })
            })
            .filter(|a| a.time.as_str() <= now)
            .collect();
        // newest first: refs[0] is HEAD's own text, the rest are read at each older commit while the budget lasts
        let mut per: Vec<Vec<Ref>> = vec![head.clone()];
        for a in ats.iter().skip(1) {
            if reads >= HISTORY_READS {
                if !budget_note {
                    gh.note("runtime history", format!("history of runtime files was read for {HISTORY_READS} file versions; older versions of the remaining files were not read"));
                    budget_note = true;
                }
                break;
            }
            reads += 1;
            let t = gh.text(&format!("/repos/{repo}/contents/{}?ref={}", enc(path), enc_ref(&a.sha)))?;
            per.push(t.map(|t| runtime::scan_file(path, &t)).unwrap_or_default());
        }
        if cut {
            gh.note(format!("history of {path}"), format!("only the newest {COMMITS_PER_FILE} commits of this file were read for runtimes"));
        }
        let mut seen: BTreeMap<(String, String, String), (usize, usize, Option<usize>)> = BTreeMap::new(); // first idx(oldest), line, removed-by idx
                                                                                                           // walk oldest -> newest over the commits that were read
        let n = per.len();
        for i in (0..n).rev() {
            let here: Vec<(String, String, String)> = per[i].iter().map(key).collect();
            for r in &per[i] {
                let e = seen.entry(key(r)).or_insert((i, r.line, None));
                if e.2.is_some() {
                    // came back after a removal: a new sighting
                    *e = (i, r.line, None);
                }
                if i == 0 {
                    e.1 = r.line;
                }
            }
            if i + 1 < n {
                // refs present one commit older but gone here were removed by commit i
                for k in per[i + 1].iter().map(key) {
                    if !here.contains(&k) {
                        if let Some(e) = seen.get_mut(&k) {
                            if e.2.is_none() {
                                e.2 = Some(i);
                            }
                        }
                    }
                }
            }
        }
        let history_complete = n == ats.len() && !cut;
        // sightings still present at HEAD, then ones removed in history
        let mut done: Vec<(String, String, String)> = vec![];
        for r in per.iter().flatten() {
            let k = key(r);
            if done.contains(&k) {
                continue;
            }
            done.push(k.clone());
            let (first, line, removed) = seen[&k];
            let at = ats.get(first);
            let rm = removed.and_then(|j| ats.get(j));
            let present_at_head = per[0].iter().any(|x| key(x) == k);
            if !present_at_head && rm.is_none() {
                continue;
            }
            // when the oldest commit read is not the file's first, the sighting may be older than we know
            let first_seen = if first + 1 == n && !history_complete { None } else { at.map(|a| a.time.clone()) };
            out.push(RuntimeRef {
                runtime: r.runtime.to_string(),
                spec: r.spec.clone(),
                version: r.version.clone(),
                floating: r.floating,
                file: path.clone(),
                line,
                seen_as: r.seen_as.clone(),
                first_seen,
                removed_at: if present_at_head { None } else { rm.map(|a| a.time.clone()) },
                commit: if first + 1 == n && !history_complete { None } else { at.map(|a| a.sha.clone()) },
                author: if first + 1 == n && !history_complete { None } else { at.and_then(|a| a.author.clone()) },
            });
        }
    }
    Ok(out)
}
