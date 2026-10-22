//! Command entry points. Each exposes `#[derive(clap::Args)] XArgs` and
//! `run(&XArgs, &Ctx) -> BrResult<i32>` (the exit code); `src/cli.rs` dispatches to them.

pub mod advisory;
pub mod claimcheck;
pub mod claimhand;
pub mod demo;
pub mod diff;
pub mod evidence;
pub mod fix;
pub mod hunt;
pub mod mcp;
pub mod notify;
pub mod purge;
pub mod similar;
pub mod sql;
pub mod status;
pub mod verify;
pub mod yara;
