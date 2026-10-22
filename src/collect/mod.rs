//! Collectors.
pub mod brx;
pub mod checkout;
pub mod cmds;
pub mod config;
pub mod fs;
pub mod github;
pub mod local;
pub mod lookup;
pub mod npm;
pub mod osv;
pub mod progress;
pub mod public;
pub mod registry;
pub mod runtimes;
#[cfg(test)]
mod scan_brx_tests;
pub mod ssh;
pub mod util;
pub mod words;
