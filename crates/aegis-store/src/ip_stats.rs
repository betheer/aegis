use crate::{error::Result, model::IpStats};
use dashmap::DashMap;
use rusqlite::{params, Connection};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Thread-safe in-memory cache of per-IP statistics.
/// Flushed to SQLite every 30 seconds by the background task.
pub struct IpStatsCache {
    map: DashMap<IpAddr, IpStats>,
}

impl IpStatsCache {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    /// Record a packet from `ip`. `blocked` = true if this packet was blocked.
    /// `score` = risk score (0–100) from detection engine, 0 if no detection.
    pub fn record_packet(&self, ip: IpAddr, blocked: bool, score: u8) {
        let now = now_ms();
        let mut entry = self.map.entry(ip).or_insert_with(|| IpStats {
            first_seen: now,
            last_seen: now,
            ..Default::default()
        });
        entry.last_seen = now;
        entry.total_packets += 1;
        if blocked {
            entry.blocked_count += 1;
        }
        if score > 0 {
            entry.alert_count += 1;
            // Rolling average (simple exponential, alpha=0.1)
            entry.rolling_risk_score =
                (entry.rolling_risk_score as f32 * 0.9 + score as f32 * 0.1) as u8;
        }
    }

    pub fn get(&self, ip: IpAddr) -> Option<IpStats> {
        self.map.get(&ip).map(|e| e.clone())
    }

    /// Flush all in-memory stats to SQLite via UPSERT.
    ///
    /// **Concurrency note:** The iter→reset sequence is not atomic. Events recorded
    /// between `self.map.iter()` and the counter reset will be silently lost.
    /// Acceptable for a 30-second periodic flush (tiny window, aggregate stats only).
    /// Production hardening: swap the DashMap atomically using `Arc::swap` or wrap
    /// the flush in a `tokio::sync::Mutex` if strict accuracy is needed.
    pub fn flush(&self, conn: &mut Connection) -> Result<()> {
        let tx = conn.transaction()?;
        for entry in self.map.iter() {
            let ip = entry.key().to_string();
            let stats = entry.value();
            tx.execute(
                "INSERT INTO ip_stats (ip, first_seen, last_seen, total_packets, blocked_count, alert_count, risk_score)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(ip) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   total_packets = total_packets + excluded.total_packets,
                   blocked_count = blocked_count + excluded.blocked_count,
                   alert_count = alert_count + excluded.alert_count,
                   risk_score = excluded.risk_score",
                params![
                    ip,
                    stats.first_seen,
                    stats.last_seen,
                    stats.total_packets,
                    stats.blocked_count,
                    stats.alert_count,
                    stats.rolling_risk_score
                ],
            )?;
        }
        tx.commit()?;
        // Reset counters after flush (they're now persisted)
        self.map.iter_mut().for_each(|mut e| {
            e.total_packets = 0;
            e.blocked_count = 0;
            e.alert_count = 0;
        });
        Ok(())
    }
}

impl Default for IpStatsCache {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
