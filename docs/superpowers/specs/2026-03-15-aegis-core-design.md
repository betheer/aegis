# Aegis — Core Firewall Engine & Backend Design Spec

**Date:** 2026-03-15
**Scope:** Core firewall engine, app backend, TUI, CLI
**Status:** Approved for implementation

---

## 1. Overview

Aegis is a Rust-based firewall for Linux (WSL-compatible) with commercial-grade network protection, anomaly detection, and multiple management interfaces. This spec covers the foundational layer: the firewall engine, detection pipeline, storage, gRPC API, TUI, and CLI.

**Out of scope for this phase:** Web GUI, Windows native support, anti-DDoS, zone-based rules, application-aware filtering, eBPF/XDP engine.

**Deferred to phase 2 (designed for but not built):** SIEM integration, per-flow PCAP capture.

**Guiding principles:**
- Ultra-stable, fast, and capable from day one
- Every abstraction designed for future extension without rewrite
- Security posture of the daemon matches the security posture it enforces

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                    User Layer                        │
│   aegis-tui (ratatui)    aegis-cli (clap)           │
└──────────────────┬──────────────────┬───────────────┘
                   │ gRPC (mTLS)      │ gRPC (mTLS)
┌──────────────────▼──────────────────▼───────────────┐
│                 aegis-daemon (unprivileged user)     │
│   gRPC server · orchestration · detection · storage │
└──────────────────────────┬──────────────────────────┘
                           │ Unix socket IPC (see §4.5)
┌──────────────────────────▼──────────────────────────┐
│           aegis-privileged (root)                    │
│   Minimal code: nftables JSON API + NFQUEUE fd mgmt │
└──────────────────────────┬──────────────────────────┘
                           │ nftables/NFQUEUE syscalls
┌──────────────────────────▼──────────────────────────┐
│                   Linux Kernel                       │
│   nftables (rules) · netfilter (NFQUEUE verdicts)   │
└─────────────────────────────────────────────────────┘
```

The daemon is split into two processes:
- **`aegis-privileged`** (root, `CAP_NET_ADMIN` + `CAP_NET_RAW`): minimal code surface, handles only kernel operations and fd passing
- **`aegis-daemon`** (unprivileged `aegis` system user): all business logic, gRPC, detection, storage

---

## 3. Cargo Workspace Structure

```
aegis/
├── Cargo.toml                    # workspace root
├── proto/
│   └── aegis.proto               # single source of truth for gRPC API
├── buf.yaml                      # buf toolchain config
├── buf.gen.yaml                  # code generation config
├── crates/
│   ├── aegis-core/               # FirewallBackend trait (interface only)
│   ├── aegis-detection/          # anomaly detection pipeline
│   ├── aegis-rules/              # rule model + TOML parser + hot reload
│   ├── aegis-store/              # tiered event storage (SQLite + ring buffer)
│   ├── aegis-proto/              # generated protobuf/gRPC code (tonic-build)
│   ├── aegis-daemon/             # main daemon binary (unprivileged)
│   ├── aegis-privileged/         # privileged binary (root, minimal code)
│   ├── aegis-tui/                # TUI client binary (ratatui + crossterm)
│   └── aegis-cli/                # CLI client binary (clap v4)
└── docs/
    └── superpowers/specs/
        └── 2026-03-15-aegis-core-design.md
```

**Crate boundaries (enforced):**
- `aegis-core` defines the `FirewallBackend` trait only — no implementation
- `aegis-privileged` implements `FirewallBackend` and owns all kernel fd handles
- `aegis-detection` never imports `aegis-core` or `aegis-privileged` directly
- Only `aegis-proto` is shared between daemon and clients; no business logic crosses the gRPC boundary
- `aegis-daemon` communicates with `aegis-privileged` exclusively via the IPC protocol in §4.5

---

## 4. `aegis-core` — Firewall Engine Abstraction

### 4.1 FirewallBackend Trait

```rust
// In aegis-core (trait definition only — no implementation here)
// Uses async-trait macro for dyn-safe async methods on stable Rust
#[async_trait::async_trait]
pub trait FirewallBackend: Send + Sync {
    async fn apply_ruleset(&self, ruleset: &Ruleset) -> Result<()>; // atomic batch
    async fn flush(&self) -> Result<()>;
    async fn list_active_rules(&self) -> Result<Vec<Rule>>;
}

// Implementation lives in aegis-privileged, not aegis-core:
// struct NftablesBackend { ... }
// impl FirewallBackend for NftablesBackend { ... }
```

**Note on async traits:** `async fn` in traits requires either `async-trait` (proc-macro, works with `dyn`) or AFIT + `#[trait_variant::make]`. Use `async-trait` for now; it supports `dyn FirewallBackend + Send + Sync` cleanly. AFIT has `dyn` limitations until Rust stabilizes return-position impl trait in traits.

The trait is the eBPF swap boundary. Future Aya/eBPF backend implements this trait; daemon code is unchanged.

### 4.2 Rule Application — Atomic via nftables

Rules are never applied one-by-one. Every apply is a single atomic nftables transaction:

```
nft -j -f <json_file>  →  atomic: all rules applied or none
Success → entire ruleset active. Failure → kernel rejects batch, old rules intact.
```

**Implementation:** Use `tokio::process::Command` to invoke `nft -j -f <tmpfile>` with a JSON ruleset file. Do not use any `nftables` crate from crates.io — existing crates have maintenance concerns. Generate nftables JSON directly from the `Ruleset` type using `serde_json`. The JSON schema is stable and documented in the nftables project.

### 4.3 NFQUEUE — Packet Interception

Uses `nfq` crate (pure Rust netlink-based NFQUEUE, no libnetfilter_queue C dependency).

**Critical:** `nfq` is a synchronous blocking library. It must NOT be called directly from a tokio async task (blocks executor thread). Use a dedicated OS thread:

```rust
// In aegis-privileged: dedicated NFQUEUE thread
let (packet_tx, packet_rx) = crossbeam_channel::bounded(4096);
let (verdict_tx, verdict_rx) = crossbeam_channel::bounded(4096);

std::thread::spawn(move || {
    let mut queue = nfq::Queue::open().unwrap();
    queue.bind(QUEUE_NUM).unwrap();
    loop {
        let msg = queue.recv().unwrap();         // blocking, safe in OS thread
        packet_tx.send(RawPacket::from(&msg)).unwrap();
        let verdict = verdict_rx.recv().unwrap();
        msg.set_verdict(verdict);
    }
});
// packet_rx forwarded to aegis-daemon via IPC (§4.5)
// verdict_tx receives verdicts from aegis-daemon via IPC (§4.5)
```

### 4.4 Packet Flow

```
Kernel (nftables) → NFQUEUE → OS thread (aegis-privileged)
  → IPC socket → aegis-daemon → Detection pipeline (rayon)
  → verdict → IPC socket → aegis-privileged OS thread → Kernel
```

### 4.5 IPC Protocol: aegis-privileged ↔ aegis-daemon

**Transport:** Unix domain socket at `/run/aegis/priv.sock` (created by `aegis-privileged`, permissions `0600`, owned by root, group `aegis`). `aegis-daemon` connects as the `aegis` user.

**Wire format:** Length-prefixed binary frames using `bincode` (deterministic, fast, no schema evolution needed for internal IPC). Each frame:

```
[u32 length LE][bincode-encoded IpcMessage]
```

**Message types:**

```rust
#[derive(Serialize, Deserialize)]
enum IpcMessage {
    // privileged → daemon
    Packet { id: u32, data: Vec<u8>, timestamp: u64 },
    RuleApplyAck { success: bool, error: Option<String> },

    // daemon → privileged
    Verdict { id: u32, verdict: NfqVerdict },           // ACCEPT | DROP | REJECT
    ApplyRuleset { json: String },                      // nftables JSON blob
    Flush,
}
```

**Authentication:** The socket is filesystem-permission-controlled. Only the `aegis` user and root can connect. No additional auth required for this internal channel.

**Crash recovery:** `aegis-daemon` monitors the IPC socket with a 1s keepalive ping. If `aegis-privileged` dies:
- `aegis-daemon` logs `CRIT: privileged process lost` to syslog and systemd journal
- Daemon **fails closed**: immediately flushes all NFQUEUE verdicts to `DROP`, nftables ruleset remains as-is (last applied state) — the kernel enforces existing rules even without the daemon
- Daemon emits a gRPC `SystemStatus` event so TUI/CLI can alert the operator
- Systemd `Restart=on-failure` restarts `aegis-privileged`; daemon reconnects automatically

**Hot reload vs. Apply race:** If a TOML hot reload fires while a gRPC `Apply` + rollback timer is active:
- Hot reload is rejected with `BUSY` status; the inotify handler re-queues and retries after the active Apply completes or rolls back
- Only one ruleset modification path is active at a time — enforced by a `tokio::sync::Mutex<RulesetState>`

---

## 5. `aegis-detection` — Threat Detection Pipeline

### 5.1 Architecture

Detection is **synchronous on rayon thread pool** (CPU-bound), bridged from async via crossbeam:

```
Packet (IPC from aegis-privileged → crossbeam channel, async bridge)
  → Decoder (rayon) — parse L2/L3/L4, zero-copy via bytes::Bytes
    → Stream reassembly (per-flow TCP buffer, keyed by FlowKey)
      → Detection engine (rayon) — all detectors, score aggregation
        → Verdict → crossbeam → IPC → aegis-privileged → Kernel
        → Alert → async channel → SQLite batch writer
        → Metrics → atomic counters (Prometheus)
```

### 5.2 Detector Trait (Sync)

```rust
#[derive(Debug)]
pub struct BlockReason {
    pub code: &'static str,      // stable machine-readable code e.g. "port_scan"
    pub description: String,     // human-readable detail
}

#[derive(Debug)]
pub struct DetectionEvent {
    pub detector: &'static str,
    pub severity: Severity,
    pub reason: BlockReason,
    pub metadata: serde_json::Value,
}

pub struct DetectorResult {
    pub score: u8,                       // 0–100 risk contribution
    pub reason: Option<BlockReason>,
    pub event: Option<DetectionEvent>,
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn weight(&self) -> f32;             // contribution weight for aggregation
    fn inspect(&self, packet: &DecodedPacket, flow: &FlowState, ctx: &DetectionContext) -> DetectorResult;
}
```

### 5.3 Confidence Scoring & Aggregation

Each detector returns a `score` (0–100) and a `weight`. Final risk score is a **weighted average**:

```
final_score = sum(score_i * weight_i) / sum(weight_i)
```

Scores are capped at 100. Default thresholds (configurable in TOML):

```
final_score >= 70  → Block
final_score 40–69  → Log + Monitor (allow but record)
final_score < 40   → Allow
```

Default detector weights:

| Detector | Weight |
|---|---|
| SynFloodDetector | 2.0 |
| PortScanDetector | 1.5 |
| IpReputationDetector | 1.5 |
| RateLimiter | 1.0 |
| GeoBlockDetector | 1.0 |
| ProtocolAnomalyDetector | 1.2 |
| DpiDetector | 1.8 |

### 5.4 Detectors at Launch

| Detector | Method |
|---|---|
| `PortScanDetector` | Sliding window (per src IP): tracks distinct dst ports contacted within time window; triggers on threshold |
| `SynFloodDetector` | Per-flow SYN/ACK ratio tracking; triggers when SYN count >> ACK count above threshold |
| `RateLimiter` | Token bucket algorithm per src IP; configurable rate + burst |
| `IpReputationDetector` | Checks src IP against local blocklists loaded into `HashSet<IpAddr>` at startup + background refresh |
| `GeoBlockDetector` | MaxMind GeoLite2 via `maxminddb` crate; country-level block list from TOML config |
| `ProtocolAnomalyDetector` | Validates packet structure and flags vs. declared protocol |
| `DpiDetector` | Aho-Corasick multi-pattern matching on reassembled TCP streams; patterns loaded from TOML config |

**Note:** Aho-Corasick (`aho-corasick` crate) is used only in `DpiDetector` for payload pattern matching. Port scan detection is purely statistical (sliding window counters), not string matching.

### 5.5 Flow Table

```rust
// FlowKey = (src_ip, dst_ip, src_port, dst_port, proto)
// FlowState = { tcp_state, syn_count, ack_count, last_seen, score_history, ... }
```

**LRU eviction:** Use `moka` crate (`moka::sync::Cache`) — thread-safe, concurrent, LRU-with-TTL, production-grade (used by Datafusion, TiKV). Wrap with `DashMap` is unnecessary; `moka` provides its own concurrent access.

```rust
let flow_table: Cache<FlowKey, FlowState> = Cache::builder()
    .max_capacity(config.flow_table_max_entries)  // configurable, default 500_000
    .time_to_idle(Duration::from_secs(120))
    .build();
```

Reads kernel `nf_conntrack` state via netlink on flow creation to initialize TCP state. Userspace flow state supplements (app-layer, scoring history), does not replace kernel conntrack.

### 5.6 DPI — Aho-Corasick Pattern Engine

Patterns defined in TOML config file (`/etc/aegis/dpi-patterns.toml`), compiled into an Aho-Corasick automaton at startup. Applied only to reassembled TCP streams after `pnet`/`etherparse` decoding. Zero-copy via `bytes::Bytes` throughout.

### 5.7 Threat Intelligence Updates

Background async task (tokio) on configurable schedule (default: every 6 hours):
- Pull updated IP blocklists (Emerging Threats, Spamhaus DROP list)
- Pull updated GeoLite2 database (requires license key — see §12.3)
- Atomically hot-swap loaded data via `Arc<RwLock<ThreatIntel>>`; no restart required

Manual trigger: `aegis update signatures` CLI command sends `UpdateSignatures` RPC → daemon triggers background task immediately → returns when update completes or fails with structured error.

Storage location: `/var/lib/aegis/threat-intel/` (created on install, owned by `aegis` user, permissions `0750`).

---

## 6. `aegis-rules` — Rule Model & Storage

### 6.1 Rule Types

```rust
pub struct Rule {
    pub id: RuleId,              // UUID string
    pub priority: u32,           // lower = evaluated first; range 0–65535
    pub name: String,
    pub enabled: bool,
    pub matches: Vec<Match>,     // all must match (AND semantics)
    pub action: Action,
    pub log: bool,
}

pub enum Direction {
    Inbound,    // traffic destined for this host
    Outbound,   // traffic originating from this host
    Forward,    // traffic routed through this host
}

pub enum Match {
    SrcIp(IpNet),
    DstIp(IpNet),
    SrcPort(PortRange),          // PortRange = single port or inclusive range
    DstPort(PortRange),
    Protocol(Protocol),          // Tcp | Udp | Icmp | Any
    Direction(Direction),
    // Future: Zone(ZoneId), Application(AppId) — added here without breaking existing rules
}

pub struct RateLimitPolicy {
    pub rate: u32,               // tokens per second (packets or bytes, see unit field)
    pub burst: u32,              // maximum burst size
    pub unit: RateLimitUnit,     // Packets | Bytes
    pub scope: RateLimitScope,   // PerSrcIp | PerConnection | Global
    pub on_exceed: ExceedAction, // Drop | Reject | Log
}

pub enum Action {
    Allow,
    Block,
    Reject,                      // Block + send RST (TCP) or ICMP unreachable (UDP)
    Log,                         // pass but record to event store
    RateLimit(RateLimitPolicy),
}
```

### 6.2 TOML Format

```toml
[[rules]]
id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
priority = 10
name = "Allow SSH from trusted subnet"
enabled = true
action = "allow"
log = false

  [[rules.matches]]
  type = "src_ip"
  value = "192.168.1.0/24"

  [[rules.matches]]
  type = "dst_port"
  value = "22"

  [[rules.matches]]
  type = "protocol"
  value = "tcp"

  [[rules.matches]]
  type = "direction"
  value = "inbound"

[[rules]]
id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
priority = 20
name = "Rate limit HTTP"
enabled = true
log = true

  [rules.action]
  type = "rate_limit"
  rate = 100
  burst = 200
  unit = "packets"
  scope = "per_src_ip"
  on_exceed = "drop"
```

### 6.3 Rule Engine Behaviours

- Rules sorted by priority at load, compiled to ordered `Vec<Rule>`
- **Hot reload:** `inotify` watch on `/etc/aegis/rules.toml`; hot reload is blocked while a gRPC `Apply` + rollback timer is active (enforced by `tokio::sync::Mutex<RulesetState>`)
- **Validation:** conflict detection, shadowed rules, invalid CIDRs, out-of-range priorities — errors returned via gRPC with structured `BadRequest` details
- **Rollback guard:**
  - `Apply` RPC acquires `RulesetState` lock, applies new ruleset, stores `previous_ruleset` snapshot, starts a `tokio::time::sleep(deadline)` task
  - Default deadline: 60 seconds (configurable in TOML and overridable per `Apply` call)
  - If `ConfirmApply` RPC received before deadline: cancels sleep task, releases lock, commits
  - If deadline expires (no confirm): auto-reverts to `previous_ruleset`, releases lock, logs `WARN: rollback triggered`
  - If daemon crashes during window: `aegis-privileged` retains last-applied nftables ruleset (kernel holds it); on restart, daemon reads active rules from nftables and marks state as unconfirmed
- **Dry-run:** translate rules to nftables JSON diff without IPC call to `aegis-privileged`; returns diff as structured response

---

## 7. `aegis-store` — Event Storage

### 7.1 Tiered Storage Architecture

```
Detection Engine (aegis-daemon)
      │
      ▼
┌─────────────────────────────┐
│  Hot tier: Memory ring      │  ringbuf crate (lock-free SPSC/MPSC)
│  buffer — last 50k events   │  TUI live feed reads from here directly
└──────────────┬──────────────┘
               │ Async batch flush (500 events OR 100ms, whichever first)
               ▼
┌─────────────────────────────┐
│  Warm tier: SQLite          │  sqlx + SQLCipher + WAL + FTS5
│  Days/weeks of history      │  1 writer conn + N reader conns
└──────────────┬──────────────┘
               │ Nightly rotation (configurable: age or size threshold)
               ▼
┌─────────────────────────────┐
│  Cold tier: .db.zst files   │  zstd-compressed SQLite snapshots
│  /var/lib/aegis/archive/    │  Read-only; decompressed to tmpfile on query
└─────────────────────────────┘
```

**Cold tier rotation trigger:** rotate when warm DB exceeds 1GB or 30 days old (configurable). Background task runs nightly at 02:00. Cold files are named `events-YYYY-MM-DD.db.zst`. Querying cold tier: daemon decompresses to `$TMPDIR/aegis-cold-<hash>.db`, opens read-only, closes + deletes tmpfile when query completes.

### 7.2 SQLite Configuration

**SQLCipher integration:** `sqlx` does not support SQLCipher natively. Use `rusqlite` (which has first-class SQLCipher support via the `bundled-sqlcipher` feature) wrapped in an async-compatible pool. Do NOT use `sqlx` with SQLCipher — the linker complexity is unacceptable. Use `rusqlite` + `tokio::task::spawn_blocking` for all DB calls, or `deadpool` for connection pooling.

```rust
// Cargo.toml
rusqlite = { version = "0.31", features = ["bundled-sqlcipher"] }
```

Key derivation: SQLCipher key derived via Argon2id from a machine secret (see §12.3). Applied as:
```sql
PRAGMA key = '<hex-encoded-key>';
PRAGMA cipher_page_size = 4096;
```

Additional PRAGMAs applied on every connection:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -65536;       -- 64MB page cache
PRAGMA mmap_size = 268435456;     -- 256MB memory-mapped I/O
PRAGMA temp_store = MEMORY;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA foreign_keys = ON;
```

**Connection model:** 1 dedicated writer thread (blocking, `spawn_blocking`) + read pool (configurable, default 4 reader threads). Writes are serialized via a channel to the writer thread.

**Schema migrations:** `rusqlite_migration` crate with versioned migration structs checked into `crates/aegis-store/migrations/`. Run on every daemon start before accepting connections.

**Startup integrity check:**
1. `PRAGMA integrity_check` — abort if not "ok"
2. HMAC chain verification on `audit_log` table (see §7.3)
3. If either fails: log to syslog + systemd journal with details; daemon refuses to start

### 7.3 Schema

```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,       -- Unix ms
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
    hit_count   INTEGER NOT NULL DEFAULT 1,   -- deduplication counter
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    reason_code TEXT,                         -- stable machine-readable code
    reason_desc TEXT,                         -- human-readable detail
    raw_meta    TEXT                          -- JSON for extensibility
);

CREATE INDEX idx_events_ts       ON events(ts DESC);
CREATE INDEX idx_events_src_ip   ON events(src_ip);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_kind     ON events(kind);

-- FTS5 with content table + sync triggers
CREATE VIRTUAL TABLE events_fts USING fts5(
    reason_desc, detector, src_ip, dst_ip,
    content='events',
    content_rowid='id'
);

CREATE TRIGGER events_fts_insert AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES (new.id, new.reason_desc, new.detector, new.src_ip, new.dst_ip);
END;
CREATE TRIGGER events_fts_delete AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES ('delete', old.id, old.reason_desc, old.detector, old.src_ip, old.dst_ip);
END;
CREATE TRIGGER events_fts_update AFTER UPDATE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES ('delete', old.id, old.reason_desc, old.detector, old.src_ip, old.dst_ip);
    INSERT INTO events_fts(rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES (new.id, new.reason_desc, new.detector, new.src_ip, new.dst_ip);
END;

-- Tamper-evident audit log (never deleted, append-only)
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    actor       TEXT NOT NULL,          -- cert CN of caller (or "system")
    action      TEXT NOT NULL,          -- e.g. "rule.create", "rule.apply", "daemon.start"
    target_id   TEXT,                   -- affected resource ID if applicable
    detail      TEXT,                   -- JSON blob of change details
    prev_hash   TEXT NOT NULL,          -- SHA-256 of previous row's entry_hmac
    entry_hmac  TEXT NOT NULL           -- HMAC-SHA256(prev_hash || ts || actor || action || detail)
);
-- audit_log has no DELETE trigger and no retention policy
```

**Audit HMAC specification:**
- Algorithm: HMAC-SHA256
- Key: audit HMAC key from key management (§12.3), distinct from SQLCipher key
- Input: `prev_hash || "|" || ts_string || "|" || actor || "|" || action || "|" || detail`
- First row `prev_hash`: SHA-256 of the daemon's installation UUID (set on first run)
- Chain verification: re-compute HMAC for every row on startup; abort if any mismatch

### 7.4 Additional Storage Features

**Event deduplication:** Before inserting, check for existing row with matching `(src_ip, dst_ip, dst_port, reason_code)` within the last 60 seconds (configurable). If found: `UPDATE SET hit_count = hit_count + 1, last_seen = ?` instead of insert.

**In-memory ip_stats:** `DashMap<IpAddr, IpStats>` (total packets, blocked count, alert count, rolling risk score) flushed to a separate `ip_stats` SQLite table every 30 seconds via `spawn_blocking`. Detectors read from memory only.

**PCAP capture (phase 2):** Designed for but not implemented in phase 1. When implemented: `.pcap` files stored in `/var/lib/aegis/pcap/` (permissions `0700`, owned by `aegis` user, never world-readable), rotated at 100MB per file, max 10GB total, cleaned by retention policy. SQLCipher-encrypted at rest using the same key derivation as the event DB.

**Retention policy:** Configurable `max_age_days` (default: 90) and `max_rows` (default: 10M). Background vacuum runs nightly; deletes oldest events first. Audit log is exempt from retention.

### 7.5 SIEM Integration (Phase 2)

Designed for but deferred to phase 2. Config stub reserved in TOML:
```toml
# [siem]  # Phase 2 — uncomment when implemented
# enabled = false
```

When implemented: syslog RFC 5424 + CEF/LEEF/Eve-JSON output over TCP+TLS to external SIEM (Splunk, QRadar, Graylog).

---

## 8. Daemon Security Architecture

### 8.1 Privilege Separation

```
aegis-privileged (root)          aegis-daemon (aegis user)
  CAP_NET_ADMIN                    No elevated capabilities
  CAP_NET_RAW                      All business logic
  ~200 lines of code               gRPC, detection, storage
  Only kernel ops + IPC            Communicates via /run/aegis/priv.sock
```

`aegis-privileged` is designed to be auditable by anyone in under 30 minutes. The small code surface is the point.

### 8.2 Linux Hardening

**Capabilities:** Both processes drop all capabilities except what is needed. `aegis-privileged` retains `CAP_NET_ADMIN` + `CAP_NET_RAW` via systemd `AmbientCapabilities`. Both processes call `prctl(PR_SET_NO_NEW_PRIVS, 1)` immediately on startup.

**Seccomp-BPF (`seccompiler` crate):**
- `aegis-privileged` whitelist: `read`, `write`, `sendmsg`, `recvmsg`, `socket`, `bind`, `accept`, `close`, netlink family only
- `aegis-daemon` whitelist: standard POSIX I/O, network (TCP only, no raw sockets), futex, mmap, clock — explicitly excludes `ptrace`, `kexec_load`, `perf_event_open`

**Systemd unit (`/lib/systemd/system/aegis.service`):**
```ini
[Service]
User=aegis
Group=aegis
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictSyscalls=@basic-io @network-io @system-service
AmbientCapabilities=              # aegis-daemon: none
# aegis-privileged has separate unit with CAP_NET_ADMIN CAP_NET_RAW
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete
Restart=on-failure
RestartSec=2s
```

### 8.3 gRPC Security

**Socket path and permissions:**
- gRPC Unix socket: `/run/aegis/mgmt.sock`
- Permissions: `0660`, owner `root`, group `aegis`
- TUI and CLI must run as `aegis` group or root to connect

**mTLS:**
- On first run: daemon generates local CA (`/etc/aegis/pki/ca.crt` + `ca.key`), admin client cert (`admin.crt` + `admin.key`)
- CA key: permissions `0600`, owned by root
- Client certs: permissions `0640`, group `aegis`
- Cert validity: 1 year for client certs, 10 years for CA cert
- Rotation: `aegis pki rotate-client --role <role>` generates new cert, old cert valid until expiry
- No CRL in phase 1 — cert expiry is the revocation mechanism; short validity period is intentional
- mTLS enforced by tonic; unauthenticated connections are rejected at TLS handshake

**RBAC via cert CN:**
```
CN=aegis-admin    → all RPCs
CN=aegis-operator → read + unblock + block; no CreateRule/DeleteRule/Apply
CN=aegis-monitor  → read-only RPCs only
CN=aegis-ci       → DryRun only
```
`AuthInterceptor` extracts CN from peer certificate, maps to role, checks against per-RPC permission table. Unknown CN → `PERMISSION_DENIED`.

**Interceptor chain:**
```
AuthInterceptor → RateLimitInterceptor → TracingInterceptor → AuditInterceptor → Handler
```

**Rate limits (per authenticated client, per minute):**
- Destructive mutations (DeleteRule, Apply, UnblockIp): 10/min
- Non-destructive mutations (CreateRule, UpdateRule): 60/min
- Reads (ListRules, QueryEvents): 600/min
- Streaming (ManageSession): 5 concurrent sessions per client
- Exceeded → `RESOURCE_EXHAUSTED` with `RetryInfo` delay hint

**Load shedding via `tower::load_shed` + semaphore:**
- P1 (never shed): `ConfirmApply`, `GetHealth`, `grpc.health.v1.Health/Check`
- P2 (shed under pressure): `CreateRule`, `Apply`, `UnblockIp`, `UpdateDetector`
- P3 (shed first): `QueryEvents`, `ExportEvents`, `ManageSession`

### 8.4 Secret & Key Management

All secrets stored at `/etc/aegis/secrets/` (permissions `0700`, owned by root):

| File | Contents | Permission |
|---|---|---|
| `machine.key` | 32-byte random machine secret (generated on install) | `0600` root |
| `pki/ca.key` | CA private key | `0600` root |
| `pki/ca.crt` | CA certificate | `0644` |
| `pki/<role>.key` | Client private key per role | `0640` root:aegis |
| `pki/<role>.crt` | Client certificate per role | `0644` |

**Key derivation:**
```
machine.key (32 bytes, random)
  → Argon2id(machine.key, salt="aegis-db-v1", m=65536, t=3, p=4) → SQLCipher key (32 bytes)
  → Argon2id(machine.key, salt="aegis-audit-v1", m=65536, t=3, p=4) → Audit HMAC key (32 bytes)
```

**GeoLite2 license key:** Stored in `/etc/aegis/secrets/geolite2.key` (plaintext, `0640` root:aegis). Configured during install via `aegis setup` command; never stored in TOML (which may be world-readable).

**No keyring integration in phase 1.** Phase 2: integrate with Linux kernel keyring (`keyctl`) or systemd credentials.

---

## 9. gRPC API (`aegis.v1`)

### 9.1 Toolchain

- **`buf`**: linting (`buf lint`), breaking change detection (`buf breaking` in CI), code generation (`buf generate`)
- **`protovalidate`**: field-level validation at request-handling time (NOT codegen only). Dependency: `protovalidate` Rust crate + CEL runtime. Added to Section 14 dependencies.
- **`tonic`**: Rust gRPC implementation
- **`tonic-web`**: added as a no-op stub (one line in server config, zero active functionality); activates only when web GUI is built in phase 2
- **`tonic_reflection`**: enabled for `grpcurl`, Postman, debugging

### 9.2 Services

```protobuf
syntax = "proto3";
package aegis.v1;

import "google/protobuf/field_mask.proto";
import "google/rpc/status.proto";
import "google/rpc/error_details.proto";
import "buf/validate/validate.proto";

// ── Rule Management ───────────────────────────────────────
service RuleService {
  rpc ListRules     (ListRulesRequest)   returns (ListRulesResponse);
  rpc GetRule       (GetRuleRequest)     returns (Rule);
  rpc CreateRule    (CreateRuleRequest)  returns (Rule);
  rpc UpdateRule    (UpdateRuleRequest)  returns (Rule);
  rpc DeleteRule    (DeleteRuleRequest)  returns (Empty);
  rpc ReorderRules  (ReorderRequest)     returns (Empty);
  rpc DryRun        (DryRunRequest)      returns (DryRunResponse);
  rpc Apply         (ApplyRequest)       returns (ApplyResponse);   // starts rollback timer
  rpc ConfirmApply  (ConfirmRequest)     returns (Empty);           // cancels rollback
}

message CreateRuleRequest {
  string idempotency_key = 1 [(buf.validate.field).string.min_len = 1];
  Rule rule = 2;
}
message UpdateRuleRequest {
  Rule rule = 1;
  google.protobuf.FieldMask update_mask = 2;
}
message ListRulesRequest {
  int32 page_size = 1 [(buf.validate.field).int32.lte = 1000];
  string page_token = 2;   // opaque cursor
}
message ListRulesResponse {
  repeated Rule rules = 1;
  string next_page_token = 2;
}
message ApplyResponse {
  int64 rollback_deadline_unix_ms = 1;  // when auto-revert fires if unconfirmed
  string changeset_id = 2;              // idempotency token for ConfirmApply
}
message DryRunResponse {
  repeated string nftables_diff = 1;   // human-readable nftables changes
  repeated string affected_traffic = 2; // description of traffic impact
  repeated string conflicts = 3;        // detected rule conflicts
}

// ── Event Log ─────────────────────────────────────────────
service EventService {
  rpc QueryEvents   (EventQuery)         returns (EventQueryResponse);
  rpc ManageSession (stream SessionReq)  returns (stream SessionEvent);  // bidi streaming
  rpc GetIpStats    (IpStatsRequest)     returns (IpStats);
  rpc ExportEvents  (ExportRequest)      returns (stream ExportChunk);
}

message SessionReq {
  oneof payload {
    SessionStart  start  = 1;
    FilterUpdate  filter = 2;
    Ping          ping   = 3;   // keepalive
    Pause         pause  = 4;
    Resume        resume = 5;
  }
}
message SessionStart {
  EventFilter initial_filter = 1;
}
message FilterUpdate {
  EventFilter filter = 1;   // replaces current filter mid-stream
}
message SessionEvent {
  oneof payload {
    Event       event  = 1;
    Pong        pong   = 2;
    StatusUpdate status = 3;
  }
}
message EventFilter {
  repeated string severity  = 1;   // filter by severity levels
  string src_ip_prefix      = 2;   // CIDR or prefix
  string fts_query          = 3;   // FTS5 query string
  int64  since_unix_ms      = 4;
}

// ── Detection ─────────────────────────────────────────────
service DetectionService {
  rpc GetDetectors      (Empty)              returns (DetectorList);
  rpc UpdateDetector    (DetectorConfig)     returns (Empty);
  rpc GetThreatSummary  (ThreatSummaryReq)   returns (ThreatSummary);
  rpc ListBlockedIps    (BlockedIpsRequest)  returns (BlockedIpsResponse);
  rpc UnblockIp         (UnblockRequest)     returns (Empty);
  rpc UpdateSignatures  (Empty)              returns (UpdateSignaturesResponse);
}

// ── System ────────────────────────────────────────────────
service SystemService {
  rpc GetStatus     (Empty)             returns (SystemStatus);
  rpc GetHealth     (Empty)             returns (HealthResponse);
  rpc GetMetrics    (Empty)             returns (MetricsSnapshot);
  rpc Reload        (Empty)             returns (Empty);
  rpc GetAuditLog   (AuditLogRequest)   returns (AuditLogResponse);
  rpc GenerateBundle(Empty)             returns (stream BundleChunk);
}
// Also implements grpc.health.v1.Health (Check + Watch)
```

### 9.3 API Design Decisions

**Error model:** All errors use `google.rpc.Status` with typed details:
- Input errors → `BadRequest` with per-field violations
- Auth errors → `ErrorInfo` with `domain="aegis"` and `reason` field (stable code)
- Not found → `ResourceInfo` naming the missing resource
- Quota exceeded → `QuotaFailure` + `RetryInfo`

**Stable error codes (application-level, in `ErrorInfo.reason`):**

| Code | Meaning |
|---|---|
| `RULE_NOT_FOUND` | Rule ID does not exist |
| `RULE_CONFLICT` | New rule conflicts with existing rule |
| `APPLY_IN_PROGRESS` | Another Apply is active; confirm or wait |
| `ROLLBACK_EXPIRED` | ConfirmApply called after deadline |
| `CERT_PERMISSION_DENIED` | Role insufficient for this RPC |
| `PRIVILEGED_UNAVAILABLE` | aegis-privileged process not reachable |
| `SIGNATURE_UPDATE_FAILED` | Threat intel download failed |

**Performance SLOs (pass/fail criteria for benchmarks):**

| Metric | Target |
|---|---|
| Detection pipeline throughput | ≥ 100k packets/sec on 4-core machine |
| Per-packet added latency (p99) | ≤ 500µs |
| Flow table capacity | ≥ 500k concurrent flows |
| gRPC RPC latency (p99, local) | ≤ 5ms for read RPCs |
| SQLite batch write throughput | ≥ 10k events/sec sustained |
| Daemon RSS memory under load | ≤ 512MB |

These are benchmarked via `criterion` in CI; regressions block merge.

---

## 10. TUI (`aegis-tui`)

### 10.1 Screens

| Screen | Purpose |
|---|---|
| Dashboard | Live event stream, sparkline charts, top threats, pipeline stats |
| Rules | List/create/edit/delete, drag-to-reorder, dry-run preview |
| Events | Filterable/searchable log, FTS5 queries, export |
| Threats | Active threats, blocked IPs, per-IP history, one-key unblock |
| Detectors | Per-detector config, thresholds, hit counters |
| System | Daemon health, metrics, audit log, rollback countdown banner |

### 10.2 Architecture

**Panic recovery hook** (first thing set, before terminal init):
```rust
let hook = std::panic::take_hook();
std::panic::set_hook(Box::new(move |info| {
    disable_raw_mode().ok();
    execute!(stdout(), LeaveAlternateScreen, Show).ok();
    hook(info);
}));
```

**Event loop** (single `tokio::select!`):
```rust
loop {
    terminal.draw(|f| app.render(f))?;
    tokio::select! {
        Some(key) = crossterm_events.next() => app.dispatch(Action::from(key)),
        Some(evt) = grpc_stream.next()      => app.dispatch(Action::ServerEvent(evt)),
        _ = render_ticker.tick()            => {}  // 60fps cap
    }
}
```

**State management** (Redux-style, pure update function):
```rust
enum Action {
    NavigateTo(Screen),
    ServerEvent(SessionEvent),
    FilterChanged(EventFilter),
    RuleToggled(RuleId),
    ConfirmDialog(bool),
}
fn update(state: &mut AppState, action: Action) { /* pure, unit-testable without terminal */ }
```

### 10.3 UX Details

- Rollback countdown: persistent top banner `[ROLLBACK IN 47s — press 'c' to confirm]` when Apply in progress
- All destructive actions: confirmation dialog `Are you sure? [y/N]`
- `?`: contextual keybinding help overlay on any screen
- Mouse: `EnableMouseCapture` — click to select rows, scroll event lists
- Color: `NO_COLOR` env var + `--color` flag; high-contrast theme option in config
- Minimum 80×24; `terminal_size()` check on startup with clear error if too small
- Preferences persisted: `~/.config/aegis/tui.toml` (last screen, column widths, active filters)
- gRPC connection: `ManageSession` bidirectional stream; exponential backoff reconnect (100ms base, 30s max)

---

## 11. CLI (`aegis-cli`)

### 11.1 Commands

```bash
# Rules
aegis rules list [--json|--yaml]
aegis rules get <id>
aegis rules add --name <n> --src <cidr> --dst-port <p> --proto <p> --action <a>
aegis rules edit <id> [--enabled true|false] [--priority <n>]
aegis rules delete <id>
aegis rules reorder <id> --priority <n>
aegis rules dry-run
aegis rules apply [--timeout <seconds>]
aegis rules confirm

# Events
aegis events list [--since 1h] [--severity high] [--src 45.33.0.0/16]
aegis events stream
aegis events export --since 24h --format cef > events.cef

# Threats
aegis threats list [--active]
aegis threats unblock <ip>
aegis threats block <ip> [--reason "manual"]

# System
aegis system status
aegis system reload
aegis config validate
aegis config show
aegis update signatures
aegis diagnose
aegis doctor
aegis pki rotate-client --role <admin|operator|monitor|ci>

# Meta
aegis completions <bash|zsh|fish|powershell>
aegis --version    # semver + git hash + build date + rustc version
```

### 11.2 CLI Design Decisions

- **Output**: human table via `comfy-table` (default), `--json`, `--yaml`, `--quiet` (exit codes only, nothing to stdout)
- **Errors**: `miette` crate — actionable errors with context, hints, suggestions printed to stderr
- **Paging**: long output auto-pipes through `$PAGER` (respects `--no-pager` flag and non-TTY detection)
- **Progress**: `indicatif` progress bars for long ops; suppressed when `--json` or non-TTY (pipe-safe)
- **Shell completions**: `clap_complete` (bash/zsh/fish/powershell)
- **Man pages**: `clap_mangen` generates `aegis.1` and sub-command pages at build time
- **Retry**: if daemon socket not yet accepting connections, retry with 100ms backoff up to 5s before failing
- **Idempotency**: all mutation commands generate a UUID `idempotency_key` per invocation

**Exit codes:**
```
0 → success
1 → general error
2 → connection error (daemon not running or socket missing)
3 → auth error (cert rejected or insufficient role)
4 → partial success (e.g., some rules applied, some rejected)
5 → timeout (e.g., Apply rollback expired before confirm)
```

### 11.3 `aegis doctor` Output

```
aegis doctor
✓ nftables available (v1.0.7)
✓ kernel modules: nf_tables, nfnetlink_queue loaded
✓ CAP_NET_ADMIN available to aegis-privileged
✗ GeoIP database missing → run 'aegis update signatures'
✓ daemon socket /run/aegis/mgmt.sock accessible
✓ mTLS cert valid (CN=aegis-admin, expires 2027-03-15)
✓ aegis-privileged process running (pid 1234)
✓ SQLite integrity: ok
✓ Audit log chain: ok (1,423 entries)
```

---

## 12. Observability

### 12.1 Metrics (Prometheus)
Exposed from daemon's internal HTTP server on `127.0.0.1:9100/metrics` (not gRPC). Key metrics:
- `aegis_packets_total{verdict}` — packets by verdict
- `aegis_detection_score_histogram` — risk score distribution
- `aegis_flow_table_size` — current flow table entries
- `aegis_events_written_total` — event store throughput
- `aegis_ruleset_version` — current ruleset apply counter

### 12.2 Tracing (OpenTelemetry)
`opentelemetry` + `tracing-opentelemetry` + `opentelemetry-otlp`. Exports to OTLP endpoint (configurable, default disabled). Every packet through detection gets a span. Every gRPC call instrumented via tower middleware.

### 12.3 Structured Logging
`tracing` crate with `tracing-subscriber` JSON formatter. Correlation IDs on all gRPC calls and packet traces. Output: systemd journal (via `tracing-journald`) + optional JSON log file.

---

## 13. Testing Strategy

| Layer | Approach | Tooling |
|---|---|---|
| Unit | Pure functions, state reducers, rule validation, score aggregation | `#[test]` |
| Property-based | Rule engine, score aggregation, packet decoder — random inputs | `proptest` |
| Integration | Real nftables on Linux CI runner; apply + verify kernel state | `#[tokio::test]` |
| Fuzz | Packet decoder, TOML rule parser, gRPC messages, nftables JSON responses | `cargo-fuzz` |
| Benchmark | Detection pipeline throughput, packet decoder latency; SLOs from §9.3 | `criterion` |
| End-to-end | Daemon + TUI headless + CLI against real nftables environment | `assert_cmd` |

Benchmarks run in CI; any regression against SLOs in §9.3 blocks merge.

---

## 14. Key Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `rayon` | Detection thread pool |
| `crossbeam-channel` | Lock-free channels for packet pipeline |
| `async-trait` | Async fn in dyn-safe traits |
| `tonic` | gRPC |
| `tonic-web` | gRPC-Web stub (phase 2 activation) |
| `prost` | Protobuf |
| `nfq` | Pure Rust NFQUEUE |
| `etherparse` | Packet parsing (more ergonomic than pnet) |
| `bytes` | Zero-copy packet buffers |
| `moka` | Concurrent LRU-TTL cache for flow table |
| `dashmap` | Concurrent hashmap for ip_stats |
| `aho-corasick` | Multi-pattern DPI matching |
| `maxminddb` | GeoIP lookups |
| `rusqlite` | SQLite with bundled SQLCipher |
| `rusqlite_migration` | Schema migrations |
| `ringbuf` | Lock-free ring buffer (hot event tier) |
| `zstd` | Cold storage compression |
| `ratatui` | TUI framework |
| `crossterm` | Terminal backend |
| `clap` v4 | CLI argument parsing |
| `clap_complete` | Shell completions |
| `clap_mangen` | Man page generation |
| `miette` | Actionable CLI error reporting |
| `indicatif` | Progress bars |
| `comfy-table` | CLI table output |
| `opentelemetry` | Distributed tracing |
| `tracing` | Structured logging |
| `tracing-opentelemetry` | OTLP trace export |
| `tracing-journald` | Systemd journal integration |
| `seccompiler` | Seccomp-BPF syscall filtering |
| `tower` | Middleware / interceptor chain |
| `bincode` | IPC wire format |
| `serde_json` | nftables JSON generation |
| `argon2` | Key derivation for SQLCipher + audit HMAC |
| `protovalidate` | Proto field validation at runtime |
| `thiserror` | Library error types |
| `anyhow` | Application error handling |
| `proptest` | Property-based testing |
| `criterion` | Benchmarking |
| `cargo-fuzz` | Fuzz testing |
