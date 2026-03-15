use thiserror::Error;

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("failed to parse rules TOML: {0}")]
    ParseError(String),

    #[error("rule '{id}' is invalid: {reason}")]
    ValidationError { id: String, reason: String },

    #[error("rule '{id}' conflicts with rule '{other_id}': {detail}")]
    ConflictError {
        id: String,
        other_id: String,
        detail: String,
    },

    #[error("rules file not found: {0}")]
    FileNotFound(String),

    #[error("watcher error: {0}")]
    WatcherError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Core(#[from] aegis_core::CoreError),
}

pub type Result<T> = std::result::Result<T, RulesError>;
