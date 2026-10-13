//! Group module error types.
//!
//! Only errors callers must distinguish live here; everything else propagates via `anyhow`.

use thiserror::Error;

/// Errors from the MLS adapter layer (the only layer touching openmls).
#[derive(Debug, Error)]
pub enum MlsError {
    #[error("MLS state not initialized: {0}")]
    NotInitialized(String),

    #[error("MLS state deserialization failed: {0}")]
    StateCorrupted(String),

    #[error("Group creation failed: {0}")]
    CreateGroup(String),

    #[error("Joining group failed: {0}")]
    JoinGroup(String),

    #[error("Membership change failed: {0}")]
    Membership(String),

    #[error("Message processing failed: {0}")]
    ProcessMessage(String),

    #[error("Malformed message: expected {expected}, got {actual}")]
    UnexpectedMessage { expected: &'static str, actual: String },

    #[error("MLS internal error: {0}")]
    Internal(String),
}

pub type MlsResult<T> = std::result::Result<T, MlsError>;
