use crate::error::{Result, StoreError};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Manages the tamper-evident audit log.
///
/// The audit log forms a HMAC-SHA256 chain where each entry includes the HMAC
/// of the previous entry. Tampering with any entry breaks the chain — this is
/// detected by `verify_chain()`.
///
/// HMAC input format: `"{prev_hash}|{ts}|{actor}|{action}|{detail}"`
pub struct AuditLog {
    hmac_key: Vec<u8>,
    genesis_hash: String,
}

impl AuditLog {
    pub fn new(hmac_key: &[u8], genesis_hash: &str) -> Self {
        Self {
            hmac_key: hmac_key.to_vec(),
            genesis_hash: genesis_hash.to_string(),
        }
    }

    /// Append a new audit entry. Reads the last entry's HMAC to form the chain.
    pub fn append(
        &self,
        conn: &mut Connection,
        actor: &str,
        action: &str,
        target_id: Option<&str>,
        detail: Option<&str>,
    ) -> Result<()> {
        let prev_hash = self.last_hmac(conn)?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let entry_hmac = self.compute_hmac(&prev_hash, ts, actor, action, detail.unwrap_or(""));

        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, target_id, detail, prev_hash, entry_hmac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![ts, actor, action, target_id, detail, prev_hash, entry_hmac],
        )?;
        Ok(())
    }

    /// Verify the HMAC chain from beginning to end. Returns error on first violation.
    pub fn verify_chain(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, action, detail, prev_hash, entry_hmac FROM audit_log ORDER BY id ASC",
        )?;

        let mut expected_prev_hash = self.genesis_hash.clone();

        let entries: Vec<_> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,            // id
                    r.get::<_, i64>(1)?,            // ts
                    r.get::<_, String>(2)?,         // actor
                    r.get::<_, String>(3)?,         // action
                    r.get::<_, Option<String>>(4)?, // detail
                    r.get::<_, String>(5)?,         // prev_hash
                    r.get::<_, String>(6)?,         // entry_hmac
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        for (id, ts, actor, action, detail, prev_hash, entry_hmac) in entries {
            // Verify prev_hash matches expected
            if prev_hash != expected_prev_hash {
                return Err(StoreError::AuditChainViolation {
                    entry_id: id,
                    detail: format!(
                        "prev_hash mismatch: expected {}, got {}",
                        expected_prev_hash, prev_hash
                    ),
                });
            }

            // Recompute HMAC and verify
            let detail_str = detail.as_deref().unwrap_or("");
            let expected_hmac = self.compute_hmac(&prev_hash, ts, &actor, &action, detail_str);
            if entry_hmac != expected_hmac {
                return Err(StoreError::AuditChainViolation {
                    entry_id: id,
                    detail: "HMAC verification failed — entry may have been tampered".to_string(),
                });
            }

            expected_prev_hash = entry_hmac;
        }

        Ok(())
    }

    fn last_hmac(&self, conn: &Connection) -> Result<String> {
        let result: Option<String> = conn
            .query_row(
                "SELECT entry_hmac FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();
        Ok(result.unwrap_or_else(|| self.genesis_hash.clone()))
    }

    fn compute_hmac(
        &self,
        prev_hash: &str,
        ts: i64,
        actor: &str,
        action: &str,
        detail: &str,
    ) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC can take key of any size");
        let input = format!("{}|{}|{}|{}|{}", prev_hash, ts, actor, action, detail);
        mac.update(input.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}
