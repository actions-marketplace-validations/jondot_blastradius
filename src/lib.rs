//! blastradius: find where a bad package, action or file landed, what it could reach, and who to tell.
// Style lints that fight how this crate is written: wide record types, Default-then-fill builders, long argument lists.
#![allow(
    clippy::type_complexity,
    clippy::field_reassign_with_default,
    clippy::too_many_arguments,
    clippy::large_enum_variant,
    clippy::result_unit_err,
    clippy::needless_range_loop,
    clippy::if_same_then_else,
    // the re! macro compiles once into a OnceLock; clippy cannot see through it
    clippy::regex_creation_in_loops
)]

pub mod cli;
pub mod cmd;
pub mod collect;
pub mod ctx;
pub mod error;
pub mod out;
pub mod parse;
pub mod query;
pub mod store;
pub mod view;

#[cfg(test)]
mod hint_tests;
