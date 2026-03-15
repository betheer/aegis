use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("nftables command failed: {0}")]
    NftablesFailed(String),

    #[error("ruleset is empty")]
    EmptyRuleset,

    #[error("rule {id} is invalid: {reason}")]
    InvalidRule { id: String, reason: String },

    #[error("backend is not available: {0}")]
    BackendUnavailable(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
