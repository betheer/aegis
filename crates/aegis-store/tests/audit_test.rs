use aegis_store::{
    audit::AuditLog,
    db::{open_database, DbKey},
    migrations::run_migrations,
    StoreError,
};
use tempfile::TempDir;

fn setup_db(dir: &TempDir) -> rusqlite::Connection {
    let path = dir.path().join("audit.db");
    let key = DbKey::random();
    let mut conn = open_database(&path, &key).unwrap();
    run_migrations(&mut conn).unwrap();
    conn
}

const GENESIS_HASH: &str = "genesis-install-uuid-placeholder";
const HMAC_KEY: &[u8] = b"test-hmac-key-32-bytes-padded!!!";

#[test]
fn append_audit_entry_persists() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let log = AuditLog::new(HMAC_KEY, GENESIS_HASH);

    log.append(&mut conn, "system", "daemon.start", None, None)
        .unwrap();

    let count: i64 = conn
        .query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn audit_chain_verifies_correctly() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let log = AuditLog::new(HMAC_KEY, GENESIS_HASH);

    log.append(
        &mut conn,
        "admin",
        "rule.create",
        Some("rule-1"),
        Some(r#"{"name":"Allow SSH"}"#),
    )
    .unwrap();
    log.append(&mut conn, "admin", "rule.apply", None, None)
        .unwrap();
    log.append(&mut conn, "system", "daemon.reload", None, None)
        .unwrap();

    // Verification should pass
    log.verify_chain(&conn).unwrap();
}

#[test]
fn tampered_audit_chain_fails_verification() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let log = AuditLog::new(HMAC_KEY, GENESIS_HASH);

    log.append(&mut conn, "admin", "rule.create", None, None)
        .unwrap();

    // Tamper with the entry
    conn.execute("UPDATE audit_log SET actor = 'attacker' WHERE id = 1", [])
        .unwrap();

    // Verification should fail
    let result = log.verify_chain(&conn);
    assert!(matches!(
        result.unwrap_err(),
        StoreError::AuditChainViolation { .. }
    ));
}
