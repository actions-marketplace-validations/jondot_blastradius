//! `br fix`.

use crate::cli::FixArgs;
use crate::ctx::Ctx;
use crate::error::BrResult;
use crate::out::actions as A;
use crate::query::index::Index;

pub fn run(a: &FixArgs, ctx: &Ctx) -> BrResult<i32> {
    let path = A::prepare_out(&a.out, false)?;
    let (view, q) = A::load(ctx, &a.q)?;
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
    A::merge_findings(&mut res);
    let text = A::fix(&ix, &a.q, &q, &res, &a.to)?;
    A::emit(&path, text)?;
    Ok(0)
}
