use thiserror::Error;

/// Every fallible operation in the core returns this error.
///
/// Messages never include secret material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("invalid json: {0}")]
    Json(String),
    #[error("signature verification failed: {0}")]
    Signature(&'static str),
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid {what}: {why}")]
    Invalid { what: &'static str, why: String },
    #[error("policy violation: {0}")]
    Policy(String),
    #[error("zip rejected: {0}")]
    Zip(String),
    #[error("image rejected: {0}")]
    Image(String),
    #[error("io error: {0}")]
    Io(String),
}

impl Error {
    pub(crate) fn invalid(what: &'static str, why: impl Into<String>) -> Self {
        Error::Invalid { what, why: why.into() }
    }
    pub(crate) fn policy(why: impl Into<String>) -> Self {
        Error::Policy(why.into())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
