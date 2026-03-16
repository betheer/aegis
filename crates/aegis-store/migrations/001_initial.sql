CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    severity    TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
    kind        TEXT NOT NULL CHECK(kind IN ('block','allow','alert','anomaly')),
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    rule_id     TEXT,
    detector    TEXT,
    score       INTEGER CHECK(score BETWEEN 0 AND 100),
    hit_count   INTEGER NOT NULL DEFAULT 1,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    reason_code TEXT,
    reason_desc TEXT,
    raw_meta    TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_kind     ON events(kind);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    reason_desc, detector, src_ip, dst_ip,
    content='events',
    content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES (new.id, new.reason_desc, new.detector, new.src_ip, new.dst_ip);
END;

CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES ('delete', old.id, old.reason_desc, old.detector, old.src_ip, old.dst_ip);
END;

CREATE TRIGGER IF NOT EXISTS events_fts_update AFTER UPDATE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES ('delete', old.id, old.reason_desc, old.detector, old.src_ip, old.dst_ip);
    INSERT INTO events_fts(rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES (new.id, new.reason_desc, new.detector, new.src_ip, new.dst_ip);
END;

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_id   TEXT,
    detail      TEXT,
    prev_hash   TEXT NOT NULL,
    entry_hmac  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_stats (
    ip              TEXT PRIMARY KEY,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    total_packets   INTEGER NOT NULL DEFAULT 0,
    blocked_count   INTEGER NOT NULL DEFAULT 0,
    alert_count     INTEGER NOT NULL DEFAULT 0,
    risk_score      INTEGER NOT NULL DEFAULT 0
);
