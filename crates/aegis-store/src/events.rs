use crate::{error::Result, model::*};
use rusqlite::{params, Connection};

/// Handles event insertion, deduplication, querying, and FTS5 search.
pub struct EventWriter;

impl EventWriter {
    pub fn new() -> Self {
        Self
    }

    /// Insert an event, or increment `hit_count` if a matching recent event exists.
    /// Matching is on (src_ip, dst_ip, dst_port, reason_code) within 60 seconds.
    pub fn insert(&self, conn: &mut Connection, event: Event) -> Result<()> {
        let dedup_window_ms = 60_000i64;
        let cutoff = event.ts - dedup_window_ms;

        // Check for duplicate
        let existing_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM events
             WHERE src_ip = ?1 AND dst_ip = ?2 AND dst_port IS ?3
               AND reason_code IS ?4 AND last_seen > ?5
             LIMIT 1",
                params![
                    event.src_ip,
                    event.dst_ip,
                    event.dst_port,
                    event.reason_code,
                    cutoff
                ],
                |r| r.get(0),
            )
            .ok();

        if let Some(id) = existing_id {
            // Update existing: increment hit_count, update last_seen
            conn.execute(
                "UPDATE events SET hit_count = hit_count + 1, last_seen = ?1 WHERE id = ?2",
                params![event.ts, id],
            )?;
        } else {
            // Insert new event
            conn.execute(
                "INSERT INTO events
                 (ts, severity, kind, src_ip, dst_ip, src_port, dst_port, protocol,
                  rule_id, detector, score, hit_count, first_seen, last_seen,
                  reason_code, reason_desc, raw_meta)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    event.ts,
                    event.severity.as_str(),
                    event.kind.as_str(),
                    event.src_ip,
                    event.dst_ip,
                    event.src_port,
                    event.dst_port,
                    event.protocol,
                    event.rule_id,
                    event.detector,
                    event.score,
                    event.hit_count,
                    event.first_seen,
                    event.last_seen,
                    event.reason_code,
                    event.reason_desc,
                    event.raw_meta
                ],
            )?;
        }
        Ok(())
    }

    /// Batch insert a slice of events (in a single transaction for performance).
    pub fn insert_batch(&self, conn: &mut Connection, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let tx = conn.transaction()?;
        {
            for event in events {
                self.insert_in_tx(&tx, event)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn insert_in_tx(&self, conn: &Connection, event: &Event) -> Result<()> {
        let dedup_window_ms = 60_000i64;
        let cutoff = event.ts - dedup_window_ms;

        let existing_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM events
             WHERE src_ip = ?1 AND dst_ip = ?2 AND dst_port IS ?3
               AND reason_code IS ?4 AND last_seen > ?5
             LIMIT 1",
                params![
                    event.src_ip,
                    event.dst_ip,
                    event.dst_port,
                    event.reason_code,
                    cutoff
                ],
                |r| r.get(0),
            )
            .ok();

        if let Some(id) = existing_id {
            conn.execute(
                "UPDATE events SET hit_count = hit_count + 1, last_seen = ?1 WHERE id = ?2",
                params![event.ts, id],
            )?;
        } else {
            conn.execute(
                "INSERT INTO events
                 (ts, severity, kind, src_ip, dst_ip, src_port, dst_port, protocol,
                  rule_id, detector, score, hit_count, first_seen, last_seen,
                  reason_code, reason_desc, raw_meta)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    event.ts,
                    event.severity.as_str(),
                    event.kind.as_str(),
                    event.src_ip,
                    event.dst_ip,
                    event.src_port,
                    event.dst_port,
                    event.protocol,
                    event.rule_id,
                    event.detector,
                    event.score,
                    event.hit_count,
                    event.first_seen,
                    event.last_seen,
                    event.reason_code,
                    event.reason_desc,
                    event.raw_meta
                ],
            )?;
        }
        Ok(())
    }

    /// Query events with filtering. Returns results in descending timestamp order.
    pub fn query(&self, conn: &Connection, q: &EventQuery) -> Result<Vec<Event>> {
        use rusqlite::types::Value;

        let mut sql = String::from(
            "SELECT id,ts,severity,kind,src_ip,dst_ip,src_port,dst_port,protocol,
                    rule_id,detector,score,hit_count,first_seen,last_seen,
                    reason_code,reason_desc,raw_meta
             FROM events WHERE 1=1",
        );
        let mut param_values: Vec<Value> = vec![];

        if let Some(since) = q.since_ms {
            sql.push_str(" AND ts >= ?");
            param_values.push(Value::Integer(since));
        }
        if let Some(until) = q.until_ms {
            sql.push_str(" AND ts <= ?");
            param_values.push(Value::Integer(until));
        }
        if let Some(ref s) = q.severity {
            sql.push_str(" AND severity = ?");
            param_values.push(Value::Text(s.as_str().to_string()));
        }

        sql.push_str(" ORDER BY ts DESC");
        if let Some(limit) = q.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(param_values.iter()), |r| {
            Ok(Event {
                id: Some(r.get(0)?),
                ts: r.get(1)?,
                severity: Severity::from_str(&r.get::<_, String>(2)?).unwrap_or(Severity::Info),
                kind: EventKind::from_str(&r.get::<_, String>(3)?).unwrap_or(EventKind::Block),
                src_ip: r.get(4)?,
                dst_ip: r.get(5)?,
                src_port: r.get(6)?,
                dst_port: r.get(7)?,
                protocol: r.get(8)?,
                rule_id: r.get(9)?,
                detector: r.get(10)?,
                score: r.get(11)?,
                hit_count: r.get(12)?,
                first_seen: r.get(13)?,
                last_seen: r.get(14)?,
                reason_code: r.get(15)?,
                reason_desc: r.get(16)?,
                raw_meta: r.get(17)?,
            })
        })?;
        rows.map(|r| r.map_err(crate::error::StoreError::from))
            .collect()
    }
}

impl Default for EventWriter {
    fn default() -> Self {
        Self::new()
    }
}
