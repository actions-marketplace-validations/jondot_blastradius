//! `br notify`.

use crate::cli::NotifyArgs;
use crate::ctx::Ctx;
use crate::error::BrResult;
use crate::out::actions as A;
use crate::query::index::Index;

pub fn run(a: &NotifyArgs, ctx: &Ctx) -> BrResult<i32> {
    if a.cc.claimcheck {
        return crate::cmd::claimhand::notify(a, ctx);
    }
    let path = A::prepare_out(&a.out, true)?;
    A::check_to(&a.to)?;
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
    if crate::query::secret_hunt::any_secret(&q) {
        if !crate::query::secret_hunt::is_secret_query(&a.q.iocs) {
            return Err(crate::error::BrError::new("secret:NAME cannot be mixed with package indicators", Some("notify one question at a time")));
        }
        let rep = crate::query::secret_hunt::build(&ix, &q)?;
        let fm = a.format.as_deref().unwrap_or("slack");
        let text = crate::out::secretq::notify_text(&rep, &|to: &str| format!("To {to}"), fm);
        A::emit(&path, text)?;
        return Ok(0);
    }
    let mut res = crate::query::hunt::hunt(&ix, &q)?;
    A::add_similar(&ix, &q, &mut res);
    A::merge_findings(&mut res);
    let text = A::notify_to(&ix, &q, &res, a.format.as_deref().unwrap_or("slack"), &a.to)?;
    A::emit(&path, text)?;
    Ok(0)
}
