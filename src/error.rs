//! The user-facing error: printed as `error: MSG` plus an optional `hint: HINT`, with its exit code.

#[derive(Debug, thiserror::Error)]
#[error("{msg}")]
pub struct BrError {
    pub msg: String,
    pub hint: Option<String>,
    pub code: i32,
    /// True when the index file does not exist (callers must not match on the message).
    pub no_index: bool,
}

impl BrError {
    /// A usage error (exit 2).
    pub fn new(msg: impl Into<String>, hint: Option<&str>) -> Self {
        Self::with_code(msg, hint, 2)
    }

    /// The index file is missing.
    pub fn no_index(path: &std::path::Path) -> Self {
        BrError { no_index: true, ..Self::with_code(format!("no index at {}", path.display()), Some("run br init"), 5) }
    }

    pub fn with_code(msg: impl Into<String>, hint: Option<&str>, code: i32) -> Self {
        BrError { msg: msg.into(), hint: hint.map(str::to_string), code, no_index: false }
    }
}

pub type BrResult<T> = Result<T, BrError>;
