//! `br diff`.

use crate::cli::{DiffArgs, QueryArgs};
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::out::actions as A;
use crate::query::index::Index;

pub fn run(a: &DiffArgs, ctx: &Ctx) -> BrResult<i32> {
    if a.cc.claimcheck {
        return crate::cmd::claimhand::diff(a, ctx);
    }
    if a.last && a.since.is_some() {
        return Err(BrError::new("--last and --since together", Some("choose one: --last compares with before the last scan")));
    }
    let n = &a.q;
    let qa = QueryArgs { iocs: n.iocs.clone(), advisory: n.advisory.clone(), text: n.text.clone(), repo: n.repo.clone(), owner: n.owner.clone(), now: false, window: n.window.clone(), since: None };
    let view = ctx.view();
    let inputs = crate::cmd::hunt::QueryInputs { q: &qa, only: None, host: None, near: false, no_secrets: false, history: false, similar: None };
    let q = crate::cmd::hunt::build_query(ctx, view.as_ref().ok(), &inputs, false)?;
    let view = view?;
    let ix = Index::new(&view, &ctx.now);
    let text = A::diff(ctx, &ix, &q, &a.since, a.verbose, &a.format)?;
    print!("{text}");
    Ok(0)
}
