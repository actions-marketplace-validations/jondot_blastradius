//! `br purge`.

use crate::cli::PurgeArgs;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::out::actions as A;
use crate::query::index::Index;

pub fn run(a: &PurgeArgs, ctx: &Ctx) -> BrResult<i32> {
    if a.no_preserve && !a.commands {
        return Err(BrError::new("--no-preserve changes the script and has no effect on the plan", Some("add --commands, or drop --no-preserve")));
    }
    let path = A::prepare_out(&a.out, false)?;
    let (view, mut q) = A::load(ctx, &a.q)?;
    q.similar_related = a.similar_related;
    if !q.benign.is_empty() {
        println!("{}", crate::cmd::hunt::benign_lines(&q).join("\n"));
        if q.iocs.is_empty() {
            return Ok(0);
        }
        println!();
    }
    A::prepare_probe(ctx, a.offline);
    A::load_team_routes(ctx);
    let ix = Index::new(&view, &ctx.now);
    let mut res = crate::query::hunt::hunt(&ix, &q)?;
    A::add_similar(&ix, &q, &mut res);
    A::merge_findings(&mut res);
    let text = A::purge(&ix, &a.q, &q, &res, a.commands, &a.format, a.no_preserve);
    A::emit(&path, text)?;
    Ok(0)
}
