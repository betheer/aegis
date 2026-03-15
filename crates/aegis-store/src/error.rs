use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("migration failed: {0}")]
    Migration(String),

    #[error("audit chain integrity violation at entry {entry_id}: {detail}")]
    AuditChainViolation { entry_id: i64, detail: String },

    #[error("database file is corrupt: {0}")]
    Corruption(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;
