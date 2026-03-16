use crate::error::{Result, StoreError};
use argon2::{Argon2, Params, Version};
use rusqlite::Connection;
use std::path::Path;

const ARGON2_MEM_KIB: u32 = 65536; // 64MB
const ARGON2_TIME: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const KEY_LEN: usize = 32;

/// A 32-byte database encryption key.
#[derive(Clone)]
pub struct DbKey(pub [u8; KEY_LEN]);

impl DbKey {
    /// Derive from machine secret using Argon2id.
    /// `domain_salt` distinguishes the SQLite key from the HMAC key derived
    /// from the same machine secret (e.g., "aegis-db-key" vs "aegis-hmac-key").
    pub fn derive(machine_secret: &[u8], domain_salt: &str) -> Result<Self> {
        let mut key = [0u8; KEY_LEN];
        let params = Params::new(
            ARGON2_MEM_KIB,
            ARGON2_TIME,
            ARGON2_PARALLELISM,
            Some(KEY_LEN),
        )
        .map_err(|e| StoreError::KeyDerivation(e.to_string()))?;
        Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(machine_secret, domain_salt.as_bytes(), &mut key)
            .map_err(|e| StoreError::KeyDerivation(e.to_string()))?;
        Ok(Self(key))
    }

    /// Generate a random key (for testing only).
    pub fn random() -> Self {
        use rand::RngCore;
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Open a SQLite database, applying all required PRAGMAs.
///
/// # SQLCipher note
/// On production Linux builds (bundled-sqlcipher feature), `PRAGMA key` encrypts
/// the database with AES-256-CBC. On Windows dev builds (bundled feature), the
/// PRAGMA is silently ignored — no encryption is applied, but all other PRAGMAs
/// and the rest of the API are identical.
pub fn open_database(path: &Path, key: &DbKey) -> Result<Connection> {
    let conn = Connection::open(path)?;

    // Apply SQLCipher key (no-op on plain SQLite, effective with bundled-sqlcipher)
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.hex()))?;

    // Performance + correctness PRAGMAs
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA cache_size = -65536;
        PRAGMA mmap_size = 268435456;
        PRAGMA temp_store = MEMORY;
        PRAGMA wal_autocheckpoint = 1000;
        PRAGMA foreign_keys = ON;
        PRAGMA page_size = 4096;
    ",
    )?;

    // Verify we can read the schema (fails on wrong key with SQLCipher)
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| {
            StoreError::Corruption(
                "failed to read schema — wrong key or corrupt database".to_string(),
            )
        })?;

    Ok(conn)
}
