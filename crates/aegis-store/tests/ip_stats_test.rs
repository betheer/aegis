use aegis_store::{
    db::{open_database, DbKey},
    ip_stats::IpStatsCache,
    migrations::run_migrations,
};
use std::net::IpAddr;
use tempfile::TempDir;

fn setup_db(dir: &TempDir) -> rusqlite::Connection {
    let path = dir.path().join("stats.db");
    let key = DbKey::random();
    let mut conn = open_database(&path, &key).unwrap();
    run_migrations(&mut conn).unwrap();
    conn
}

#[test]
fn record_packet_updates_in_memory_stats() {
    let cache = IpStatsCache::new();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();

    cache.record_packet(ip, false, 0);
    cache.record_packet(ip, true, 80); // blocked

    let stats = cache.get(ip).unwrap();
    assert_eq!(stats.total_packets, 2);
    assert_eq!(stats.blocked_count, 1);
}

#[test]
fn flush_writes_to_database() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let cache = IpStatsCache::new();

    let ip: IpAddr = "5.6.7.8".parse().unwrap();
    cache.record_packet(ip, false, 0);
    cache.record_packet(ip, false, 0);

    cache.flush(&mut conn).unwrap();

    let count: i64 = conn
        .query_row(
            "SELECT total_packets FROM ip_stats WHERE ip = '5.6.7.8'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn flush_twice_upserts_correctly() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let cache = IpStatsCache::new();
    let ip: IpAddr = "9.9.9.9".parse().unwrap();

    cache.record_packet(ip, false, 0);
    cache.flush(&mut conn).unwrap();

    cache.record_packet(ip, true, 85);
    cache.flush(&mut conn).unwrap();

    let (total, blocked, risk): (i64, i64, u8) = conn
        .query_row(
            "SELECT total_packets, blocked_count, risk_score FROM ip_stats WHERE ip = '9.9.9.9'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(total, 2);
    assert_eq!(blocked, 1);
    assert!(risk > 0, "risk_score should be persisted after flush");
}
