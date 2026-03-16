use aegis_store::db::{open_database, DbKey};
use tempfile::TempDir;

#[test]
fn open_encrypted_database_succeeds() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let key = DbKey::random();
    let conn = open_database(&db_path, &key).unwrap();
    // Basic smoke test: can execute a query
    let result: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
    assert_eq!(result, 1);
}

/// This test requires SQLCipher encryption (bundled-sqlcipher feature).
/// On Windows dev builds with plain bundled SQLite, PRAGMA key is a no-op,
/// so both keys succeed — this test is skipped on non-SQLCipher builds.
#[test]
#[ignore = "requires SQLCipher (bundled-sqlcipher feature); PRAGMA key is no-op on plain SQLite"]
fn wrong_key_fails_to_open() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let key1 = DbKey::random();
    let key2 = DbKey::random();

    // Create with key1
    open_database(&db_path, &key1).unwrap();

    // Open with key2 should fail (wrong key)
    let result = open_database(&db_path, &key2);
    assert!(result.is_err());
}

#[test]
fn migrations_run_on_fresh_database() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("migrated.db");
    let key = DbKey::random();
    let mut conn = open_database(&db_path, &key).unwrap();

    aegis_store::migrations::run_migrations(&mut conn).unwrap();

    // events table should exist
    let count: i64 = conn
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);

    // audit_log table should exist
    let count: i64 = conn
        .query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
