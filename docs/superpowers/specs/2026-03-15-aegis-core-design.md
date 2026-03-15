# Aegis — Core Firewall Engine & Backend Design Spec

**Date:** 2026-03-15
**Scope:** Core firewall engine, app backend, TUI, CLI
**Status:** Approved for implementation

---

## 1. Overview

Aegis is a Rust-based firewall for Linux (WSL-compatible) with commercial-grade network protection, anomaly detection, and multiple management interfaces. This spec covers the foundational layer: the firewall engine, detection pipeline, storage, gRPC API, TUI, and CLI.

**Out of scope for this phase:** Web GUI, Windows native support, anti-DDoS, zone-based rules, application-aware filtering, eBPF/XDP engine.

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
                           │ Restricted IPC
┌──────────────────────────▼──────────────────────────┐
│           aegis-privileged (root)                    │
│   Minimal code: nftables JSON API + NFQUEUE only    │
└──────────────────────────┬──────────────────────────┘
                           │ nftables/NFQUEUE syscalls
┌──────────────────────────▼──────────────────────────┐
│                   Linux Kernel                       │
│   nftables (rules) · netfilter (NFQUEUE verdicts)   │
└─────────────────────────────────────────────────────┘
```

The daemon is split into two processes:
- **`aegis-privileged`** (root): minimal code surface, handles only kernel operations
- **`aegis-daemon`** (unprivileged `aegis` system user): all business logic, gRPC, detection, storage

Clients never touch the kernel directly.

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
│   ├── aegis-core/               # FirewallBackend trait + nftables/NFQUEUE impl
│   ├── aegis-detection/          # anomaly detection pipeline
│   ├── aegis-rules/              # rule model + TOML parser + hot reload
│   ├── aegis-store/              # tiered event storage (SQLite + ring buffer)
│   ├── aegis-proto/              # generated protobuf/gRPC code (tonic-build)
│   ├── aegis-daemon/             # main daemon binary (unprivileged)
│   ├── aegis-privileged/         # privileged binary (root, minimal)
│   ├── aegis-tui/                # TUI client binary (ratatui + crossterm)
│   └── aegis-cli/                # CLI client binary (clap v4)
└── docs/
    └── superpowers/specs/
        └── 2026-03-15-aegis-core-design.md
```

**Crate boundaries (enforced):**
- Only `aegis-privileged` calls nftables/NFQUEUE
- Only `aegis-proto` is shared between daemon and clients
- `aegis-detection` never imports `aegis-core` directly
- `aegis-daemon` and `aegis-privileged` communicate via a restricted IPC protocol (not gRPC)

---

## 4. `aegis-core` — Firewall Engine Abstraction

### 4.1 FirewallBackend Trait

```rust
pub trait FirewallBackend: Send + Sync {
    async fn apply_ruleset(&self, ruleset: &Ruleset) -> Result<()>; // atomic batch
    async fn flush(&self) -> Result<()>;
    async fn list_active_rules(&self) -> Result<Vec<Rule>>;
}
```

The trait is the eBPF swap boundary. The nftables implementation lives entirely inside `aegis-privileged`. Future Aya/eBPF implementation replaces only this crate's internals.

### 4.2 Rule Application — Atomic via nftables JSON API

Rules are never applied one-by-one. Every apply is a single atomic nftables transaction:

```
nft flush ruleset + add all rules = single atomic batch via nft -j -f <json_file>
Success → all rules applied. Failure → kernel rejects entire batch, old rules intact.
```

Uses the `nftables` crate (JSON API mode) — no raw subprocess string building, no C FFI.

### 4.3 NFQUEUE — Pure Rust

Uses `nfq` crate (pure Rust netlink-based NFQUEUE, no libnetfilter_queue C dependency).

NFQUEUE listener runs as an async task, pushes `RawPacket` via crossbeam channel to the detection pipeline. Verdicts (ACCEPT/DROP/REJECT) are returned via a separate verdict channel.

### 4.4 Packet Flow

```
Kernel (nftables) → NFQUEUE → crossbeam channel → Detection pipeline → verdict → Kernel
```

---

## 5. `aegis-detection` — Threat Detection Pipeline

### 5.1 Architecture

The detection pipeline is **synchronous on rayon thread pool** (CPU-bound), decoupled from the async I/O layer via crossbeam channels:

```
Packet (NFQUEUE, tokio async)
  → crossbeam channel
    → Decoder (rayon) — parse L2/L3/L4, zero-copy via bytes::Bytes
      → Stream reassembly (per-flow TCP buffer)
        → Detection engine (rayon) — runs all detectors, aggregates score
          → Verdict → NFQUEUE (async)
          → Alert → SQLite writer (async, batched)
          → Metrics → Prometheus atomics
```

### 5.2 Detector Trait (Sync)

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn inspect(&self, packet: &DecodedPacket, flow: &FlowState, ctx: &DetectionContext) -> DetectorResult;
}

pub struct DetectorResult {
    pub score: u8,              // 0–100 risk contribution
    pub reason: Option<BlockReason>,
    pub event: Option<DetectionEvent>,
}
```

### 5.3 Confidence Scoring

Detectors run in order, each contributing a weighted risk score (0–100). Final verdict is based on configurable thresholds:

```
score >= 70  → Block
score 40–69  → Log + Monitor
score < 40   → Allow
```

Thresholds are configurable per-deployment in TOML.

### 5.4 Detectors at Launch

| Detector | Method |
|---|---|
| `PortScanDetector` | Sliding window counter per src IP, Aho-Corasick pattern match |
| `SynFloodDetector` | SYN/ACK ratio tracking via flow table |
| `RateLimiter` | Token bucket algorithm per src IP |
| `IpReputationDetector` | Local blocklists, auto-updated via background task |
| `GeoBlockDetector` | MaxMind GeoLite2 via `maxminddb` crate, auto-updated |
| `ProtocolAnomalyDetector` | Validates packet structure vs. declared protocol |
| `DpiDetector` | Aho-Corasick multi-pattern matching on reassembled TCP streams |

### 5.5 Flow Table

```rust
// DashMap<FlowKey, FlowState> with LRU eviction
// FlowKey = (src_ip, dst_ip, src_port, dst_port, proto)
// FlowState = SynSent | Established | FinWait | Closed + metadata + score history
```

- Integrates with kernel `nf_conntrack` via netlink (reads existing state, supplements with app-layer data)
- Memory-bounded: configurable max entries with LRU eviction — prevents OOM under adversarial traffic
- Per-IP state in separate `DashMap<IpAddr, IpState>` — also LRU-bounded

### 5.6 DPI — Aho-Corasick Pattern Engine

Patterns defined in TOML, compiled into an Aho-Corasick automaton at startup (`aho-corasick` crate). Same algorithm as Snort/Suricata. Applied only to reassembled TCP streams (not raw packets).

### 5.7 Threat Intelligence Updates

Background async task runs on configurable schedule (default: every 6 hours):
- Pull updated IP blocklists (Emerging Threats, Spamhaus)
- Pull updated GeoLite2 database
- Hot-reload into running detectors without restart

---

## 6. `aegis-rules` — Rule Model & Storage

### 6.1 Rule Type

```rust
pub struct Rule {
    pub id: RuleId,
    pub priority: u32,
    pub name: String,
    pub enabled: bool,
    pub matches: Vec<Match>,    // all must match (AND)
    pub action: Action,
    pub log: bool,
}

pub enum Match {
    SrcIp(IpNet),
    DstIp(IpNet),
    SrcPort(PortRange),
    DstPort(PortRange),
    Protocol(Protocol),
    Direction(Direction),       // extensible for future zone/app-aware modes
}

pub enum Action {
    Allow,
    Block,
    Reject,
    Log,
    RateLimit(RateLimitPolicy),
}
```

### 6.2 TOML Format

```toml
[[rules]]
id = "allow-ssh"
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
```

### 6.3 Rule Engine Behaviours

- Rules sorted by priority at load, compiled to ordered vec
- **Hot reload**: `inotify` watch on TOML file, atomic reload without restart
- **Validation**: conflict detection, shadowed rules, invalid CIDRs — errors surfaced to TUI/CLI
- **Rollback guard**: `Apply` starts a countdown timer; if `Confirm` not received within deadline, auto-revert to previous ruleset
- **Dry-run**: translate rules to nftables JSON diff without calling `aegis-core`

---

## 7. `aegis-store` — Event Storage

### 7.1 Tiered Storage Architecture

```
Detection Engine
      │
      ▼
┌─────────────────────────────┐
│  Hot tier: Memory ring      │  Lock-free ring buffer (ringbuf crate)
│  buffer                     │  Last 50k events — instant TUI live feed
└──────────────┬──────────────┘
               │ Batch flush (500 events or 100ms, whichever first)
               ▼
┌─────────────────────────────┐
│  Warm tier: SQLite          │  Days/weeks of queryable history
│  (SQLCipher + WAL + FTS5)   │
└──────────────┬──────────────┘
               │ Nightly rotation + zstd compression
               ▼
┌─────────────────────────────┐
│  Cold tier: .db.zst files   │  Months of history, forensics
└─────────────────────────────┘
```

### 7.2 SQLite Configuration

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -65536;       -- 64MB page cache
PRAGMA mmap_size = 268435456;     -- 256MB memory-mapped I/O
PRAGMA temp_store = MEMORY;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA page_size = 4096;
```

- **Encryption at rest**: SQLCipher with AES-256, key derived via Argon2 from machine secret
- **Connection pool**: 1 dedicated writer + N readers via `sqlx::SqlitePool`
- **Schema migrations**: `sqlx migrate` with versioned migration files
- **Integrity check**: `PRAGMA integrity_check` + HMAC chain verification on every daemon start

### 7.3 Schema

```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    severity    TEXT NOT NULL,     -- info|low|medium|high|critical
    kind        TEXT NOT NULL,     -- block|allow|alert|anomaly
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    rule_id     TEXT,
    detector    TEXT,
    score       INTEGER,
    reason      TEXT,
    hit_count   INTEGER DEFAULT 1, -- deduplication
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    raw_meta    TEXT               -- JSON for extensibility
);

CREATE INDEX idx_events_ts     ON events(ts);
CREATE INDEX idx_events_src_ip ON events(src_ip);
CREATE INDEX idx_events_kind   ON events(kind);

CREATE VIRTUAL TABLE events_fts USING fts5(
    reason, detector, src_ip, dst_ip,
    content='events', content_rowid='id'
);

-- Tamper-evident audit log (never deleted, HMAC-chained)
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    actor       TEXT NOT NULL,     -- cert CN of caller
    action      TEXT NOT NULL,
    detail      TEXT,
    prev_hash   TEXT NOT NULL,
    entry_hmac  TEXT NOT NULL
);
```

### 7.4 Additional Storage Features

- **Event deduplication**: same `(src_ip, dst_ip, dst_port, reason)` within time window → increment `hit_count`, update `last_seen`
- **In-memory `ip_stats`**: `DashMap<IpAddr, IpStats>` flushed to SQLite every 30s — detectors read from memory
- **PCAP capture on critical alerts**: ring buffer of last N packets per flow stored as `.pcap` for forensics
- **Retention policy**: configurable max age + max rows, background vacuum nightly
- **Startup integrity check**: verify HMAC chain, refuse to start if tampered

### 7.5 SIEM Integration

```toml
[siem]
enabled = true
protocol = "tcp+tls"
host = "siem.internal:6514"
format = "cef"                 # cef | leef | json-eve | syslog-rfc5424
min_severity = "medium"
```

Syslog RFC 5424 + CEF/LEEF/Eve-JSON output. Background async task forwards events matching `min_severity`.

---

## 8. Daemon Security Architecture

### 8.1 Privilege Separation

```
aegis-privileged (root)          aegis-daemon (aegis user)
  CAP_NET_ADMIN                    No elevated capabilities
  CAP_NET_RAW                      All business logic
  Minimal code surface             gRPC, detection, storage
  Only kernel ops                  Communicates up via IPC
```

### 8.2 Linux Hardening

- **Capabilities**: `CAP_NET_ADMIN` + `CAP_NET_RAW` only, dropped via `capctl`/`prctl` at startup
- **Seccomp-BPF**: whitelist of allowed syscalls via `seccompiler` crate; anything else → `SIGSYS`
- **Systemd unit hardening**: `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`, `RestrictSyscalls`, `AmbientCapabilities`

### 8.3 gRPC Security

- **mTLS**: daemon generates local CA + client certs on first run; all clients must present valid cert
- **RBAC via cert CN**: roles encoded in certificate CN
  - `admin` — full access
  - `operator` — read + unblock, no rule changes
  - `monitor` — read-only
  - `ci` — dry-run only
- **Interceptor chain**: `AuthInterceptor → RateLimitInterceptor → TracingInterceptor → AuditInterceptor → Handler`
- **Load shedding**: priority tiers via `tower::load_shed()` + semaphore
  - P1 (never shed): `ConfirmApply`, `GetHealth`
  - P2: `CreateRule`, `Apply`, `UnblockIp`
  - P3 (shed first): `QueryEvents`, `ExportEvents`, `StreamEvents`

### 8.4 Startup Integrity

On every start:
1. Verify SQLite HMAC chain continuity
2. Verify config TOML checksum
3. `PRAGMA integrity_check` on database
4. Refuse to start if tampered, log to system journal

---

## 9. gRPC API (`aegis.v1`)

### 9.1 Toolchain

- **`buf`**: linting (`buf lint`), breaking change detection (`buf breaking` in CI), code generation (`buf generate`)
- **`protovalidate`**: field-level validation in proto definitions
- **`tonic`**: Rust gRPC implementation
- **`tonic-web`**: enabled from day one for future web GUI (browser gRPC-Web compatibility)
- **`tonic_reflection`**: enabled for `grpcurl`, Postman, debugging

### 9.2 Services

```protobuf
syntax = "proto3";
package aegis.v1;

service RuleService {
  rpc ListRules     (ListRulesRequest)   returns (ListRulesResponse);
  rpc GetRule       (GetRuleRequest)     returns (Rule);
  rpc CreateRule    (CreateRuleRequest)  returns (Rule);
  rpc UpdateRule    (UpdateRuleRequest)  returns (Rule);  // uses FieldMask
  rpc DeleteRule    (DeleteRuleRequest)  returns (Empty);
  rpc ReorderRules  (ReorderRequest)     returns (Empty);
  rpc DryRun        (DryRunRequest)      returns (DryRunResponse);
  rpc Apply         (ApplyRequest)       returns (ApplyResponse);  // starts rollback timer
  rpc ConfirmApply  (ConfirmRequest)     returns (Empty);
}

service EventService {
  rpc QueryEvents   (EventQuery)         returns (EventQueryResponse);
  rpc ManageSession (stream SessionReq)  returns (stream SessionEvent);  // bidi streaming
  rpc GetIpStats    (IpStatsRequest)     returns (IpStats);
  rpc ExportEvents  (ExportRequest)      returns (stream ExportChunk);
}

service DetectionService {
  rpc GetDetectors      (Empty)              returns (DetectorList);
  rpc UpdateDetector    (DetectorConfig)     returns (Empty);
  rpc GetThreatSummary  (ThreatSummaryReq)   returns (ThreatSummary);
  rpc ListBlockedIps    (BlockedIpsRequest)  returns (BlockedIpsResponse);
  rpc UnblockIp         (UnblockRequest)     returns (Empty);
}

service SystemService {
  rpc GetStatus     (Empty)             returns (SystemStatus);
  rpc GetHealth     (Empty)             returns (HealthResponse);
  rpc GetMetrics    (Empty)             returns (MetricsSnapshot);
  rpc Reload        (Empty)             returns (Empty);
  rpc GetAuditLog   (AuditLogRequest)   returns (AuditLogResponse);
}
```

Also implements `grpc.health.v1.Health` (standard health check protocol).

### 9.3 API Design Decisions

- **Error model**: `google.rpc.Status` with `BadRequest`, `ErrorInfo` details — not raw status codes
- **Pagination**: cursor-based page tokens (not offset) on all list RPCs
- **Field masks**: `google.protobuf.FieldMask` on all update RPCs
- **Idempotency keys**: all mutation RPCs accept `idempotency_key` field
- **Versioning**: `package aegis.v1` from day one; daemon serves v1 and future v2 simultaneously during transitions
- **Compression**: gzip on all RPCs, critical for streaming
- **Bidirectional streaming**: `ManageSession` allows TUI to send filter changes while receiving events

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

**Panic recovery hook** (set before terminal initialization):
```rust
let hook = std::panic::take_hook();
std::panic::set_hook(Box::new(move |info| {
    disable_raw_mode().ok();
    execute!(stdout(), LeaveAlternateScreen, Show).ok();
    hook(info);
}));
```

**Event loop** (single `tokio::select!` multiplexing all inputs):
```rust
loop {
    terminal.draw(|f| app.render(f))?;
    tokio::select! {
        Some(key) = crossterm_events.next() => app.dispatch(Action::from(key)),
        Some(evt) = grpc_stream.next()      => app.dispatch(Action::EventReceived(evt)),
        _ = render_ticker.tick()            => {}  // capped at 60fps
    }
}
```

**State management** (unidirectional, Redux-style):
```rust
enum Action { NavigateTo(Screen), EventReceived(Event), RuleToggled(RuleId), FilterChanged(String) }
fn update(state: &mut AppState, action: Action) { /* pure function, unit-testable */ }
```

### 10.3 UX Details

- Rollback countdown shown as persistent top banner when `Apply` is in-progress
- All destructive actions require confirmation dialog (`y/N`)
- `?` opens contextual keybinding help on any screen
- Mouse support (`EnableMouseCapture`): click to select, scroll
- `NO_COLOR` env var + `--color` flag respected
- High-contrast theme option
- Minimum 80×24 with graceful degradation check on startup
- Session preferences persisted in `~/.config/aegis/tui.toml`
- Connects to `ManageSession` bidirectional stream on start; graceful reconnect with backoff

---

## 11. CLI (`aegis-cli`)

### 11.1 Commands

```bash
# Rules
aegis rules list [--json|--yaml]
aegis rules get <id>
aegis rules add --name <n> --src <cidr> --dst-port <p> --proto <p> --action <a>
aegis rules edit <id> --enabled false
aegis rules delete <id>
aegis rules reorder <id> --priority 5
aegis rules dry-run
aegis rules apply [--timeout 60s]
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
aegis completions <bash|zsh|fish|powershell>
aegis --version
```

### 11.2 CLI Design Decisions

- **Output**: human table (default), `--json`, `--yaml`, `--quiet` (exit codes only)
- **Errors**: `miette` crate — actionable errors with context, hints, suggestions
- **Paging**: long output auto-pipes through `$PAGER` (respects `--no-pager`)
- **Progress**: `indicatif` progress bars for long ops; suppressed when `--json` or non-TTY
- **Shell completions**: `clap_complete` (bash/zsh/fish/powershell)
- **Man pages**: `clap_mangen` at build time
- **Retry**: reconnect with exponential backoff if daemon is starting up
- **Exit codes**: `0` success · `1` error · `2` connection error · `3` auth error · `4` partial success

### 11.3 `aegis doctor` Output

```
aegis doctor
✓ nftables available (v1.0.7)
✓ kernel modules: nf_tables, nfnetlink_queue
✓ CAP_NET_ADMIN available
✗ GeoIP database missing → run 'aegis update signatures'
✓ daemon socket accessible
✓ mTLS cert valid (expires 2027-03-15)
```

---

## 12. Observability

- **Metrics**: Prometheus-compatible endpoint (`/metrics`) from daemon
- **Tracing**: OpenTelemetry via `opentelemetry` + `tracing-opentelemetry`; OTLP export (Jaeger, Datadog, Grafana Tempo)
- **Logging**: structured JSON logs with correlation IDs; all gRPC calls instrumented
- **Every packet** through detection pipeline gets a trace span

---

## 13. Testing Strategy

- **Unit tests**: pure functions, state reducers, rule validation, detection scoring
- **Property-based tests**: `proptest` on rule engine (random rule sets, expect no panics/invalid state)
- **Integration tests**: against real nftables in CI (Linux runner)
- **Fuzz tests**: `cargo-fuzz` targets for packet decoder, TOML rule parser, gRPC message handling, nftables JSON response parser
- **Performance benchmarks**: `criterion` on detection pipeline throughput, packet decoder latency
- **End-to-end tests**: daemon + TUI + CLI against a real nftables environment

---

## 14. Key Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `rayon` | Detection thread pool |
| `crossbeam` | Lock-free channels for packet pipeline |
| `tonic` | gRPC |
| `tonic-web` | gRPC-Web for future browser client |
| `prost` | Protobuf |
| `nftables` | nftables JSON API |
| `nfq` | Pure Rust NFQUEUE |
| `pnet` / `etherparse` | Packet parsing |
| `bytes` | Zero-copy packet buffers |
| `dashmap` | Concurrent hashmaps (flow table, ip_stats) |
| `aho-corasick` | Multi-pattern DPI matching |
| `maxminddb` | GeoIP lookups |
| `sqlx` | SQLite async (compile-time verified queries) |
| `ringbuf` | Lock-free ring buffer (hot event tier) |
| `zstd` | Cold storage compression |
| `ratatui` | TUI framework |
| `crossterm` | Terminal backend |
| `clap` v4 | CLI argument parsing |
| `clap_complete` | Shell completions |
| `clap_mangen` | Man page generation |
| `miette` | Actionable CLI error reporting |
| `indicatif` | Progress bars |
| `opentelemetry` | Distributed tracing |
| `seccompiler` | Seccomp-BPF syscall filtering |
| `tower` | Middleware / interceptor chain |
| `thiserror` | Library error types |
| `anyhow` | Application error handling |
| `proptest` | Property-based testing |
| `criterion` | Benchmarking |
