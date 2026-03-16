use aegis_store::{
    db::{open_database, DbKey},
    events::EventWriter,
    migrations::run_migrations,
    model::*,
};
use tempfile::TempDir;

fn test_event(src_ip: &str) -> Event {
    Event {
        id: None,
        ts: 1000,
        severity: Severity::High,
        kind: EventKind::Block,
        src_ip: src_ip.to_string(),
        dst_ip: "10.0.0.1".to_string(),
        src_port: Some(12345),
        dst_port: Some(22),
        protocol: Some("tcp".to_string()),
        rule_id: None,
        detector: Some("port_scan".to_string()),
        score: Some(80),
        hit_count: 1,
        first_seen: 1000,
        last_seen: 1000,
        reason_code: Some("port_scan".to_string()),
        reason_desc: Some("Port scan detected from 1.2.3.4".to_string()),
        raw_meta: None,
    }
}

fn setup_db(dir: &TempDir) -> rusqlite::Connection {
    let path = dir.path().join("test.db");
    let key = DbKey::random();
    let mut conn = open_database(&path, &key).unwrap();
    run_migrations(&mut conn).unwrap();
    conn
}

#[test]
fn insert_event_stores_in_db() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    let evt = test_event("1.2.3.4");
    writer.insert(&mut conn, evt).unwrap();

    let count: i64 = conn
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn duplicate_event_increments_hit_count() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    let evt = test_event("1.2.3.4");
    writer.insert(&mut conn, evt.clone()).unwrap();
    writer
        .insert(
            &mut conn,
            Event {
                ts: 2000,
                last_seen: 2000,
                ..evt
            },
        )
        .unwrap();

    // Should be 1 row with hit_count = 2
    let (count, hit_count): (i64, i64) = conn
        .query_row("SELECT count(*), max(hit_count) FROM events", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(hit_count, 2);
}

#[test]
fn fts5_search_finds_event() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    writer.insert(&mut conn, test_event("9.9.9.9")).unwrap();

    let results: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT src_ip FROM events WHERE id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?1)"
        ).unwrap();
        stmt.query_map(["port scan"], |r| r.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    };
    assert_eq!(results, vec!["9.9.9.9"]);
}

#[test]
fn query_events_by_severity() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    writer.insert(&mut conn, test_event("1.1.1.1")).unwrap();
    writer
        .insert(
            &mut conn,
            Event {
                severity: Severity::Low,
                src_ip: "2.2.2.2".to_string(),
                ..test_event("2.2.2.2")
            },
        )
        .unwrap();

    let query = EventQuery {
        severity: Some(Severity::High),
        limit: Some(10),
        ..Default::default()
    };
    let results = writer.query(&conn, &query).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].src_ip, "1.1.1.1");
}

#[test]
fn event_kind_round_trips_through_db() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    // Insert an Allow event (not Block)
    let allow_evt = Event {
        kind: EventKind::Allow,
        ..test_event("7.7.7.7")
    };
    writer.insert(&mut conn, allow_evt).unwrap();

    let query = EventQuery {
        limit: Some(10),
        ..Default::default()
    };
    let results = writer.query(&conn, &query).unwrap();
    assert_eq!(results.len(), 1);
    // kind must round-trip correctly through the DB — not hardcoded to Block
    assert_eq!(results[0].kind, EventKind::Allow);
}
