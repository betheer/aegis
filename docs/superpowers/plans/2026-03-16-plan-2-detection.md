# Aegis — Plan 2: Detection Engine (`aegis-detection`)

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `aegis-detection` crate — packet decoder, flow table, TCP stream reassembly, weighted detection engine (rayon), and all 7 threat detectors (PortScan, SynFlood, RateLimiter, IpReputation, GeoBlock, ProtocolAnomaly, DPI).

**Architecture:** `aegis-detection` is a pure library crate with no async runtime. It receives already-decoded `DecodedPacket` structs, maintains per-flow state in a `moka` LRU+TTL cache, runs detectors synchronously in parallel via `rayon`, aggregates scores with a weighted average, and returns a `DetectionVerdict`. Detectors are stateless structs implementing the `Detector` trait; per-IP/per-flow counters live in `DashMap`s inside each detector. The crate depends on `aegis-rules` (for `BlockReason`, `Protocol`, `Direction`, `PacketInfo`) and `aegis-store` (for `Severity`).

**Tech Stack:** Rust stable, `etherparse 0.15` (packet decoding), `bytes 1` (zero-copy payload), `rayon 1` (parallel detectors), `moka 0.12` (flow table LRU+TTI), `dashmap 6` (per-IP counters), `aho-corasick 1` (DPI), `maxminddb 0.23` (geo lookup), `serde`/`toml`/`serde_json` (config parsing)

**Spec:** `docs/superpowers/specs/2026-03-15-aegis-core-design.md` §5

**Deferred (not in Plan 2):** HTTP threat intel downloads, netlink conntrack reads, Prometheus metrics, IPC bridge to aegis-daemon.

---

## File Map

| File | Responsibility |
|---|---|
| `Cargo.toml` | Add `crates/aegis-detection` to workspace members; add new workspace deps |
| `crates/aegis-detection/Cargo.toml` | Crate manifest |
| `crates/aegis-detection/src/lib.rs` | Public re-exports |
| `crates/aegis-detection/src/model.rs` | All shared types: `TcpFlags`, `DecodedPacket`, `FlowKey`, `FlowState`, `DetectionContext`, `DetectorResult`, `DetectionEvent`, `DetectionVerdict`, `VerdictAction`, `Detector` trait |
| `crates/aegis-detection/src/decoder.rs` | `decode_ip_packet()` — etherparse L3/L4 → DecodedPacket |
| `crates/aegis-detection/src/flow_table.rs` | `FlowTable` — moka Cache wrapper, `get_or_create`, `invalidate` |
| `crates/aegis-detection/src/engine.rs` | `DetectionEngine` — orchestrates rayon parallel detection + score aggregation |
| `crates/aegis-detection/src/detectors/mod.rs` | Re-exports all detectors |
| `crates/aegis-detection/src/detectors/port_scan.rs` | `PortScanDetector` — sliding window per src IP |
| `crates/aegis-detection/src/detectors/syn_flood.rs` | `SynFloodDetector` — per-flow SYN/ACK ratio |
| `crates/aegis-detection/src/detectors/rate_limiter.rs` | `RateLimiter` — token bucket per src IP |
| `crates/aegis-detection/src/detectors/ip_reputation.rs` | `IpReputationDetector` — blocklist HashSet, hot-swap |
| `crates/aegis-detection/src/detectors/geo_block.rs` | `GeoBlockDetector` — maxminddb country lookup |
| `crates/aegis-detection/src/detectors/protocol_anomaly.rs` | `ProtocolAnomalyDetector` — TCP flag validation |
| `crates/aegis-detection/src/detectors/dpi.rs` | `DpiDetector` — Aho-Corasick multi-pattern |
| `crates/aegis-detection/tests/decoder_test.rs` | Decoder tests |
| `crates/aegis-detection/tests/flow_table_test.rs` | Flow table tests |
| `crates/aegis-detection/tests/engine_test.rs` | Engine harness tests |
| `crates/aegis-detection/tests/detectors_test.rs` | All detector unit tests |

---

## Chunk 1: Workspace Scaffold + Core Types

### Task 1: Add aegis-detection to Workspace

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/aegis-detection/Cargo.toml`
- Create: `crates/aegis-detection/src/lib.rs`

- [ ] **Step 1: Add new workspace deps and member**

Edit `Cargo.toml` — add `crates/aegis-detection` to `members` and add new deps to `[workspace.dependencies]`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/aegis-core",
    "crates/aegis-rules",
    "crates/aegis-store",
    "crates/aegis-detection",
]

[workspace.dependencies]
# Async
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"

# Error handling
thiserror = "2"
anyhow = "1"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Networking / IP types
ipnet = { version = "2", features = ["serde"] }

# Storage
rusqlite = { version = "0.31", features = ["bundled", "modern_sqlite"] }
rusqlite_migration = "1"
crossbeam-queue = "0.3"
dashmap = "6"
moka = { version = "0.12", features = ["sync"] }

# Crypto
argon2 = "0.5"
sha2 = "0.10"
hmac = "0.12"
hex = "0.4"
rand = "0.8"

# File watching
notify = "6"

# Detection — new in Plan 2
etherparse = "0.15"
bytes = "1"
rayon = "1"
aho-corasick = "1"
maxminddb = "0.23"

# Utilities
uuid = { version = "1", features = ["v4", "serde"] }
tempfile = "3"

# Testing
proptest = "1"
criterion = { version = "0.5", features = ["html_reports"] }
```

- [ ] **Step 2: Create crate manifest**

Create `crates/aegis-detection/Cargo.toml`:

```toml
[package]
name = "aegis-detection"
version = "0.1.0"
edition = "2021"

[dependencies]
aegis-rules = { path = "../aegis-rules" }
aegis-store = { path = "../aegis-store" }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
toml = { workspace = true }
bytes = { workspace = true }
rayon = { workspace = true }
dashmap = { workspace = true }
moka = { workspace = true }
etherparse = { workspace = true }
aho-corasick = { workspace = true }
maxminddb = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 3: Create stub lib.rs**

Create `crates/aegis-detection/src/lib.rs`:

```rust
pub mod decoder;
pub mod detectors;
pub mod engine;
pub mod flow_table;
pub mod model;

pub use model::{
    DecodedPacket, DetectionContext, DetectionEvent, DetectionVerdict, Detector,
    DetectorResult, FlowKey, FlowState, TcpFlags, VerdictAction,
};
```

- [ ] **Step 4: Verify workspace compiles**

```bash
cargo check --workspace 2>&1
```

Expected: `Finished` with no errors. The new crate will have empty module errors — that's OK, we'll fill them in Task 2.

Actually, create empty placeholder files so `cargo check` passes:

```bash
mkdir -p crates/aegis-detection/src/detectors
touch crates/aegis-detection/src/decoder.rs
touch crates/aegis-detection/src/flow_table.rs
touch crates/aegis-detection/src/engine.rs
echo "// detectors" > crates/aegis-detection/src/detectors/mod.rs
```

Then run:

```bash
cargo check --workspace 2>&1
```

Expected output contains: `Finished`

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aegis-detection/
git commit -m "feat(aegis-detection): add crate to workspace with empty scaffold"
```

---

### Task 2: Core Model Types

**Files:**
- Create: `crates/aegis-detection/src/model.rs`
- Create: `crates/aegis-detection/tests/model_test.rs`

- [ ] **Step 1: Write failing test**

Create `crates/aegis-detection/tests/model_test.rs`:

```rust
use aegis_detection::{
    DecodedPacket, DetectionContext, DetectorResult, FlowKey, FlowState, TcpFlags, VerdictAction,
};
use aegis_rules::model::{Direction, Protocol};
use bytes::Bytes;
use std::net::IpAddr;

fn test_packet() -> DecodedPacket {
    DecodedPacket {
        src_ip: "1.2.3.4".parse().unwrap(),
        dst_ip: "5.6.7.8".parse().unwrap(),
        src_port: Some(12345),
        dst_port: Some(80),
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
        payload: Bytes::from_static(b"hello"),
        packet_len: 60,
    }
}

#[test]
fn flow_state_update_tcp_flags() {
    let mut state = FlowState::new();
    let flags = TcpFlags { syn: true, ..Default::default() };
    state.update_tcp_flags(&flags);
    state.update_tcp_flags(&flags);
    assert_eq!(state.syn_count, 2);
    assert_eq!(state.ack_count, 0);
}

#[test]
fn flow_state_append_payload_caps_at_64k() {
    let mut state = FlowState::new();
    // Fill buffer to 64KB
    let chunk = vec![0u8; 1024];
    for _ in 0..64 {
        state.append_payload(&chunk);
    }
    assert_eq!(state.payload_buf.len(), 65536);
    // Additional data is silently dropped
    state.append_payload(&chunk);
    assert_eq!(state.payload_buf.len(), 65536);
}

#[test]
fn flow_state_is_closed_after_rst() {
    let mut state = FlowState::new();
    state.update_tcp_flags(&TcpFlags { rst: true, ..Default::default() });
    assert!(state.is_closed());
}

#[test]
fn detector_result_pass_has_zero_score() {
    let r = DetectorResult::pass();
    assert_eq!(r.score, 0);
    assert!(r.reason.is_none());
    assert!(r.event.is_none());
}

#[test]
fn detection_context_defaults() {
    let ctx = DetectionContext::default();
    assert_eq!(ctx.threshold_block, 70);
    assert_eq!(ctx.threshold_monitor, 40);
}

#[test]
fn flow_key_is_hashable() {
    use std::collections::HashMap;
    let key = FlowKey {
        src_ip: "1.2.3.4".parse().unwrap(),
        dst_ip: "5.6.7.8".parse().unwrap(),
        src_port: 1234,
        dst_port: 80,
        proto: 6,
    };
    let mut map = HashMap::new();
    map.insert(key.clone(), 42u32);
    assert_eq!(*map.get(&key).unwrap(), 42);
}

#[test]
fn decoded_packet_can_be_cloned() {
    let p = test_packet();
    let q = p.clone();
    assert_eq!(p.src_ip, q.src_ip);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test model_test 2>&1
```

Expected: compile error — `model.rs` is empty, types not defined.

- [ ] **Step 3: Implement `model.rs`**

Write `crates/aegis-detection/src/model.rs`:

```rust
use aegis_rules::model::{BlockReason, Direction, Protocol};
use aegis_store::model::Severity;
use bytes::{Bytes, BytesMut};
use serde_json::Value;
use std::net::IpAddr;
use std::time::Instant;

/// TCP control flags parsed from a packet header.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

/// Fully decoded L3/L4 packet, ready for rule matching and detection.
#[derive(Debug, Clone)]
pub struct DecodedPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub direction: Direction,
    /// TCP flags, present only for TCP packets.
    pub tcp_flags: Option<TcpFlags>,
    /// Raw payload bytes (zero-copy via Bytes).
    pub payload: Bytes,
    pub packet_len: u32,
}

/// Five-tuple flow identifier. Used as moka cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// IANA protocol number: 6=TCP, 17=UDP, 1=ICMP, 0=Any.
    pub proto: u8,
}

/// Per-flow mutable detection state. Stored behind `Arc<Mutex<FlowState>>` in the flow table.
#[derive(Clone)]
pub struct FlowState {
    pub syn_count: u32,
    pub ack_count: u32,
    pub rst_count: u32,
    pub fin_count: u32,
    /// Reassembled TCP payload, capped at 64 KB.
    pub payload_buf: BytesMut,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl FlowState {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            syn_count: 0,
            ack_count: 0,
            rst_count: 0,
            fin_count: 0,
            payload_buf: BytesMut::new(),
            first_seen: now,
            last_seen: now,
        }
    }

    /// Update TCP counters from packet flags.
    pub fn update_tcp_flags(&mut self, flags: &TcpFlags) {
        self.last_seen = Instant::now();
        if flags.syn { self.syn_count += 1; }
        if flags.ack { self.ack_count += 1; }
        if flags.rst { self.rst_count += 1; }
        if flags.fin { self.fin_count += 1; }
    }

    /// Append TCP payload bytes. Silently drops bytes beyond 64 KB.
    pub fn append_payload(&mut self, data: &[u8]) {
        const MAX_BUF: usize = 65536;
        let remaining = MAX_BUF.saturating_sub(self.payload_buf.len());
        let n = data.len().min(remaining);
        self.payload_buf.extend_from_slice(&data[..n]);
    }

    /// True once the flow is terminated (RST or bidirectional FIN).
    pub fn is_closed(&self) -> bool {
        self.rst_count > 0 || self.fin_count >= 2
    }
}

impl Default for FlowState {
    fn default() -> Self { Self::new() }
}

/// Per-packet evaluation thresholds (configurable).
pub struct DetectionContext {
    pub threshold_block: u8,   // default 70
    pub threshold_monitor: u8, // default 40
}

impl Default for DetectionContext {
    fn default() -> Self {
        Self { threshold_block: 70, threshold_monitor: 40 }
    }
}

/// A detection event emitted when a detector fires above zero.
#[derive(Debug)]
pub struct DetectionEvent {
    pub detector: &'static str,
    pub severity: Severity,
    pub reason: BlockReason,
    pub metadata: Value,
}

/// Result from a single detector's `inspect()` call.
#[derive(Debug)]
pub struct DetectorResult {
    /// Risk contribution score 0–100.
    pub score: u8,
    pub reason: Option<BlockReason>,
    pub event: Option<DetectionEvent>,
}

impl DetectorResult {
    /// Convenience: detector found nothing suspicious.
    pub fn pass() -> Self {
        Self { score: 0, reason: None, event: None }
    }
}

/// The action the engine decided for this packet after aggregation.
#[derive(Debug, PartialEq, Eq)]
pub enum VerdictAction {
    /// final_score >= threshold_block → drop the packet.
    Block,
    /// threshold_monitor <= final_score < threshold_block → allow but log.
    Monitor,
    /// final_score < threshold_monitor → allow silently.
    Allow,
}

/// The detection engine's combined verdict for one packet.
#[derive(Debug)]
pub struct DetectionVerdict {
    pub action: VerdictAction,
    pub final_score: u8,
    pub events: Vec<DetectionEvent>,
}

/// Synchronous detector interface. All detectors are `Send + Sync`.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    /// Weight used in the weighted-average score aggregation.
    fn weight(&self) -> f32;
    fn inspect(&self, packet: &DecodedPacket, flow: &FlowState, ctx: &DetectionContext) -> DetectorResult;
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p aegis-detection --test model_test 2>&1
```

Expected: `test result: ok. 7 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/model.rs crates/aegis-detection/tests/model_test.rs
git commit -m "feat(aegis-detection): core model types — DecodedPacket, FlowState, Detector trait"
```

---

## Chunk 2: Packet Decoder + Flow Table + Detection Engine

### Task 3: Packet Decoder

**Files:**
- Create: `crates/aegis-detection/src/decoder.rs`
- Create: `crates/aegis-detection/tests/decoder_test.rs`

- [ ] **Step 1: Write failing test**

Create `crates/aegis-detection/tests/decoder_test.rs`:

```rust
use aegis_detection::decoder::decode_ip_packet;
use aegis_rules::model::{Direction, Protocol};

/// Build a minimal IPv4+TCP SYN packet in raw bytes.
/// Structure: IPv4 header (20 bytes) + TCP header (20 bytes), no payload.
fn make_tcp_syn_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    // IPv4 header
    buf[0] = 0x45; // version=4, IHL=5
    buf[1] = 0x00; // DSCP/ECN
    buf[2] = 0x00; buf[3] = 0x28; // total length = 40
    buf[4] = 0x00; buf[5] = 0x01; // identification
    buf[6] = 0x40; buf[7] = 0x00; // flags (DF), fragment offset=0
    buf[8] = 0x40; // TTL=64
    buf[9] = 0x06; // protocol = TCP
    // checksum bytes 10-11 left as 0 (etherparse doesn't validate)
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    // TCP header
    buf[20] = (src_port >> 8) as u8; buf[21] = (src_port & 0xff) as u8;
    buf[22] = (dst_port >> 8) as u8; buf[23] = (dst_port & 0xff) as u8;
    // seq, ack = 0
    buf[32] = 0x50; // data offset = 5 (20 bytes), reserved=0
    buf[33] = 0x02; // SYN flag
    buf[34] = 0xff; buf[35] = 0xff; // window size
    // checksum, urgent = 0
    buf
}

/// Build a minimal IPv4+UDP packet.
fn make_udp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 28];
    buf[0] = 0x45;
    buf[1] = 0x00;
    buf[2] = 0x00; buf[3] = 0x1c; // total length = 28
    buf[4] = 0x00; buf[5] = 0x02;
    buf[6] = 0x40; buf[7] = 0x00;
    buf[8] = 0x40;
    buf[9] = 0x11; // protocol = UDP
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    // UDP header
    buf[20] = (src_port >> 8) as u8; buf[21] = (src_port & 0xff) as u8;
    buf[22] = (dst_port >> 8) as u8; buf[23] = (dst_port & 0xff) as u8;
    buf[24] = 0x00; buf[25] = 0x08; // length = 8 (header only)
    buf
}

#[test]
fn decode_tcp_syn_extracts_ips_and_ports() {
    let raw = make_tcp_syn_packet([1, 2, 3, 4], [5, 6, 7, 8], 12345, 80);
    let pkt = decode_ip_packet(&raw, Direction::Inbound).unwrap();
    assert_eq!(pkt.src_ip.to_string(), "1.2.3.4");
    assert_eq!(pkt.dst_ip.to_string(), "5.6.7.8");
    assert_eq!(pkt.src_port, Some(12345));
    assert_eq!(pkt.dst_port, Some(80));
    assert!(matches!(pkt.protocol, Protocol::Tcp));
}

#[test]
fn decode_tcp_syn_flag_set() {
    let raw = make_tcp_syn_packet([1, 2, 3, 4], [5, 6, 7, 8], 1024, 443);
    let pkt = decode_ip_packet(&raw, Direction::Inbound).unwrap();
    let flags = pkt.tcp_flags.expect("TCP packet must have flags");
    assert!(flags.syn);
    assert!(!flags.ack);
    assert!(!flags.rst);
    assert!(!flags.fin);
}

#[test]
fn decode_udp_extracts_ports() {
    let raw = make_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53);
    let pkt = decode_ip_packet(&raw, Direction::Outbound).unwrap();
    assert_eq!(pkt.src_port, Some(5000));
    assert_eq!(pkt.dst_port, Some(53));
    assert!(matches!(pkt.protocol, Protocol::Udp));
    assert!(pkt.tcp_flags.is_none());
}

#[test]
fn decode_invalid_bytes_returns_error() {
    let bad = vec![0xffu8; 4];
    assert!(decode_ip_packet(&bad, Direction::Inbound).is_err());
}

#[test]
fn decode_direction_preserved() {
    let raw = make_tcp_syn_packet([1, 2, 3, 4], [5, 6, 7, 8], 100, 200);
    let pkt = decode_ip_packet(&raw, Direction::Outbound).unwrap();
    assert!(matches!(pkt.direction, aegis_rules::model::Direction::Outbound));
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test decoder_test 2>&1
```

Expected: compile error — `decoder.rs` is empty.

- [ ] **Step 3: Implement `decoder.rs`**

Write `crates/aegis-detection/src/decoder.rs`:

```rust
use crate::model::{DecodedPacket, TcpFlags};
use aegis_rules::model::{Direction, Protocol};
use bytes::Bytes;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("failed to parse IP packet: {0}")]
    Parse(String),
    #[error("unsupported IP version or packet structure")]
    Unsupported,
}

/// Decode a raw IP-layer packet (no Ethernet header) into a `DecodedPacket`.
/// `direction` must be determined by the caller (e.g., from NFQUEUE hook point).
pub fn decode_ip_packet(raw: &[u8], direction: Direction) -> Result<DecodedPacket, DecodeError> {
    // PacketHeaders::from_ip_slice is the correct etherparse 0.15 API for raw IP packets.
    let pkt = PacketHeaders::from_ip_slice(raw)
        .map_err(|e| DecodeError::Parse(e.to_string()))?;

    let (src_ip, dst_ip) = match &pkt.net {
        Some(NetHeaders::Ipv4(h, _)) => (
            IpAddr::V4(h.source.into()),
            IpAddr::V4(h.destination.into()),
        ),
        Some(NetHeaders::Ipv6(h, _)) => (
            IpAddr::V6(h.source.into()),
            IpAddr::V6(h.destination.into()),
        ),
        _ => return Err(DecodeError::Unsupported),
    };

    let packet_len = raw.len() as u32;
    let payload_bytes = Bytes::copy_from_slice(pkt.payload.payload);

    match &pkt.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            let flags = TcpFlags {
                syn: tcp.syn,
                ack: tcp.ack,
                fin: tcp.fin,
                rst: tcp.rst,
                psh: tcp.psh,
                urg: tcp.urg,
            };
            Ok(DecodedPacket {
                src_ip,
                dst_ip,
                src_port: Some(tcp.source_port),
                dst_port: Some(tcp.destination_port),
                protocol: Protocol::Tcp,
                direction,
                tcp_flags: Some(flags),
                payload: payload_bytes,
                packet_len,
            })
        }
        Some(TransportHeader::Udp(udp)) => Ok(DecodedPacket {
            src_ip,
            dst_ip,
            src_port: Some(udp.source_port),
            dst_port: Some(udp.destination_port),
            protocol: Protocol::Udp,
            direction,
            tcp_flags: None,
            payload: payload_bytes,
            packet_len,
        }),
        Some(TransportHeader::Icmpv4(_)) | Some(TransportHeader::Icmpv6(_)) => Ok(DecodedPacket {
            src_ip,
            dst_ip,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Icmp,
            direction,
            tcp_flags: None,
            payload: payload_bytes,
            packet_len,
        }),
        None => Err(DecodeError::Unsupported),
        _ => Err(DecodeError::Unsupported),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p aegis-detection --test decoder_test 2>&1
```

Expected: `test result: ok. 5 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/decoder.rs crates/aegis-detection/tests/decoder_test.rs
git commit -m "feat(aegis-detection): IP packet decoder via etherparse"
```

---

### Task 4: Flow Table

**Files:**
- Create: `crates/aegis-detection/src/flow_table.rs`
- Create: `crates/aegis-detection/tests/flow_table_test.rs`

- [ ] **Step 1: Write failing test**

Create `crates/aegis-detection/tests/flow_table_test.rs`:

```rust
use aegis_detection::flow_table::FlowTable;
use aegis_detection::FlowKey;

fn key(src_port: u16, dst_port: u16) -> FlowKey {
    FlowKey {
        src_ip: "1.2.3.4".parse().unwrap(),
        dst_ip: "5.6.7.8".parse().unwrap(),
        src_port,
        dst_port,
        proto: 6,
    }
}

#[test]
fn get_or_create_same_key_returns_same_arc() {
    let table = FlowTable::new(1000);
    let k = key(1234, 80);
    let a = table.get_or_create(k.clone());
    let b = table.get_or_create(k.clone());
    assert!(std::sync::Arc::ptr_eq(&a, &b), "same key must return same Arc");
}

#[test]
fn different_keys_return_different_arcs() {
    let table = FlowTable::new(1000);
    let a = table.get_or_create(key(1, 80));
    let b = table.get_or_create(key(2, 80));
    assert!(!std::sync::Arc::ptr_eq(&a, &b));
}

#[test]
fn entry_count_increments() {
    let table = FlowTable::new(1000);
    table.get_or_create(key(1, 80));
    table.get_or_create(key(2, 80));
    // moka entry_count may be slightly delayed — give it a moment
    // (moka uses background maintenance) — just assert >= 1
    assert!(table.entry_count() >= 1);
}

#[test]
fn flow_state_mutations_visible_across_handles() {
    let table = FlowTable::new(1000);
    let k = key(9000, 443);
    let arc1 = table.get_or_create(k.clone());
    let arc2 = table.get_or_create(k.clone());

    arc1.lock().unwrap().syn_count = 42;
    assert_eq!(arc2.lock().unwrap().syn_count, 42);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test flow_table_test 2>&1
```

Expected: compile error — `flow_table.rs` is empty.

- [ ] **Step 3: Implement `flow_table.rs`**

Write `crates/aegis-detection/src/flow_table.rs`:

```rust
use crate::model::{FlowKey, FlowState};
use moka::sync::Cache;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Thread-safe, LRU+TTI flow table backed by moka.
/// Stores `Arc<Mutex<FlowState>>` so callers can mutate flow state in-place.
pub struct FlowTable {
    cache: Cache<FlowKey, Arc<Mutex<FlowState>>>,
}

impl FlowTable {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_idle(Duration::from_secs(120))
                .build(),
        }
    }

    /// Get or atomically create a FlowState for the given key.
    /// moka guarantees the initializer runs at most once per key.
    pub fn get_or_create(&self, key: FlowKey) -> Arc<Mutex<FlowState>> {
        self.cache
            .get_with(key, || Arc::new(Mutex::new(FlowState::new())))
    }

    /// Remove a flow (e.g., after it is confirmed closed).
    pub fn invalidate(&self, key: &FlowKey) {
        self.cache.invalidate(key);
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p aegis-detection --test flow_table_test 2>&1
```

Expected: `test result: ok. 4 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/flow_table.rs crates/aegis-detection/tests/flow_table_test.rs
git commit -m "feat(aegis-detection): moka flow table with LRU+TTI eviction"
```

---

### Task 5: Detection Engine Harness

**Files:**
- Create: `crates/aegis-detection/src/engine.rs`
- Create: `crates/aegis-detection/tests/engine_test.rs`
- Modify: `crates/aegis-detection/src/detectors/mod.rs` (add stub to satisfy compile)

- [ ] **Step 1: Write failing test**

Create `crates/aegis-detection/tests/engine_test.rs`:

```rust
use aegis_detection::{
    engine::{DetectionEngine, EngineConfig},
    model::{
        DecodedPacket, DetectionContext, DetectionEvent, DetectorResult, FlowState, VerdictAction,
        Detector,
    },
};
use aegis_rules::model::{Direction, Protocol};
use bytes::Bytes;
use std::net::IpAddr;

fn test_packet() -> DecodedPacket {
    DecodedPacket {
        src_ip: "1.2.3.4".parse().unwrap(),
        dst_ip: "5.6.7.8".parse().unwrap(),
        src_port: Some(12345),
        dst_port: Some(80),
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        tcp_flags: None,
        payload: Bytes::new(),
        packet_len: 40,
    }
}

struct AlwaysScore(u8);

impl Detector for AlwaysScore {
    fn name(&self) -> &'static str { "always" }
    fn weight(&self) -> f32 { 1.0 }
    fn inspect(&self, _p: &DecodedPacket, _f: &FlowState, _c: &DetectionContext) -> DetectorResult {
        DetectorResult { score: self.0, reason: None, event: None }
    }
}

#[test]
fn high_score_detector_causes_block() {
    let engine = DetectionEngine::new(
        vec![Box::new(AlwaysScore(90))],
        EngineConfig::default(),
    );
    let verdict = engine.process_packet(&test_packet());
    assert_eq!(verdict.action, VerdictAction::Block);
    assert_eq!(verdict.final_score, 90);
}

#[test]
fn zero_score_detector_causes_allow() {
    let engine = DetectionEngine::new(
        vec![Box::new(AlwaysScore(0))],
        EngineConfig::default(),
    );
    let verdict = engine.process_packet(&test_packet());
    assert_eq!(verdict.action, VerdictAction::Allow);
}

#[test]
fn score_50_causes_monitor() {
    let engine = DetectionEngine::new(
        vec![Box::new(AlwaysScore(50))],
        EngineConfig::default(),
    );
    let verdict = engine.process_packet(&test_packet());
    assert_eq!(verdict.action, VerdictAction::Monitor);
}

#[test]
fn weighted_average_aggregation() {
    // Two detectors: weight 1 score 100, weight 1 score 0 → avg = 50 → Monitor
    struct ScoreN(u8, f32);
    impl Detector for ScoreN {
        fn name(&self) -> &'static str { "n" }
        fn weight(&self) -> f32 { self.1 }
        fn inspect(&self, _p: &DecodedPacket, _f: &FlowState, _c: &DetectionContext) -> DetectorResult {
            DetectorResult { score: self.0, reason: None, event: None }
        }
    }
    let engine = DetectionEngine::new(
        vec![Box::new(ScoreN(100, 1.0)), Box::new(ScoreN(0, 1.0))],
        EngineConfig::default(),
    );
    let verdict = engine.process_packet(&test_packet());
    assert_eq!(verdict.final_score, 50);
    assert_eq!(verdict.action, VerdictAction::Monitor);
}

#[test]
fn same_flow_accumulates_syn_count() {
    struct ReadSynCount;
    use std::sync::atomic::{AtomicU32, Ordering};
    static CAPTURED: AtomicU32 = AtomicU32::new(0);
    impl Detector for ReadSynCount {
        fn name(&self) -> &'static str { "syn_reader" }
        fn weight(&self) -> f32 { 0.0 }
        fn inspect(&self, _p: &DecodedPacket, f: &FlowState, _c: &DetectionContext) -> DetectorResult {
            CAPTURED.store(f.syn_count, Ordering::Relaxed);
            DetectorResult::pass()
        }
    }
    use aegis_detection::TcpFlags;
    let engine = DetectionEngine::new(
        vec![Box::new(ReadSynCount)],
        EngineConfig::default(),
    );
    let mut pkt = test_packet();
    pkt.tcp_flags = Some(TcpFlags { syn: true, ..Default::default() });
    engine.process_packet(&pkt);
    engine.process_packet(&pkt);
    assert_eq!(CAPTURED.load(Ordering::Relaxed), 2);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test engine_test 2>&1
```

Expected: compile error — `engine.rs` is empty.

- [ ] **Step 3: Implement `engine.rs`**

Write `crates/aegis-detection/src/engine.rs`:

```rust
use crate::{
    flow_table::FlowTable,
    model::{
        DecodedPacket, DetectionContext, DetectionVerdict, Detector, FlowKey, VerdictAction,
    },
};
use aegis_rules::model::Protocol;
use rayon::prelude::*;

/// Engine configuration (thresholds + flow table sizing).
pub struct EngineConfig {
    /// Score >= this → Block. Default: 70.
    pub threshold_block: u8,
    /// Score >= this → Monitor. Default: 40.
    pub threshold_monitor: u8,
    /// Maximum concurrent flows in the flow table. Default: 500_000.
    pub flow_table_capacity: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            threshold_block: 70,
            threshold_monitor: 40,
            flow_table_capacity: 500_000,
        }
    }
}

/// The detection engine. Owns the flow table and the list of detectors.
/// `process_packet` is the only public entry point.
pub struct DetectionEngine {
    detectors: Vec<Box<dyn Detector>>,
    flow_table: FlowTable,
    threshold_block: u8,
    threshold_monitor: u8,
}

impl DetectionEngine {
    pub fn new(detectors: Vec<Box<dyn Detector>>, config: EngineConfig) -> Self {
        Self {
            flow_table: FlowTable::new(config.flow_table_capacity),
            detectors,
            threshold_block: config.threshold_block,
            threshold_monitor: config.threshold_monitor,
        }
    }

    /// Process one packet: update flow state, run all detectors in parallel,
    /// aggregate scores, return verdict.
    pub fn process_packet(&self, packet: &DecodedPacket) -> DetectionVerdict {
        let flow_key = FlowKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port.unwrap_or(0),
            dst_port: packet.dst_port.unwrap_or(0),
            proto: match packet.protocol {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
                Protocol::Icmp => 1,
                Protocol::Any => 0,
            },
        };

        let flow_arc = self.flow_table.get_or_create(flow_key);

        // Update flow state and capture a snapshot for detectors.
        let flow_snapshot = {
            let mut flow = flow_arc.lock().unwrap();
            if let Some(flags) = &packet.tcp_flags {
                flow.update_tcp_flags(flags);
            }
            if !packet.payload.is_empty() {
                flow.append_payload(&packet.payload);
            }
            flow.clone()
        };

        let ctx = DetectionContext {
            threshold_block: self.threshold_block,
            threshold_monitor: self.threshold_monitor,
        };

        // Run all detectors in parallel via rayon.
        let results: Vec<_> = self
            .detectors
            .par_iter()
            .map(|d| d.inspect(packet, &flow_snapshot, &ctx))
            .collect();

        // Weighted average score aggregation.
        let (weighted_sum, weight_sum) = results
            .iter()
            .zip(self.detectors.iter())
            .fold((0.0_f32, 0.0_f32), |(ws, wt), (r, d)| {
                (ws + r.score as f32 * d.weight(), wt + d.weight())
            });

        let final_score = if weight_sum > 0.0 {
            (weighted_sum / weight_sum).min(100.0) as u8
        } else {
            0
        };

        let action = if final_score >= self.threshold_block {
            VerdictAction::Block
        } else if final_score >= self.threshold_monitor {
            VerdictAction::Monitor
        } else {
            VerdictAction::Allow
        };

        let events = results.into_iter().filter_map(|r| r.event).collect();
        DetectionVerdict { action, final_score, events }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p aegis-detection --test engine_test 2>&1
```

Expected: `test result: ok. 5 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/engine.rs crates/aegis-detection/tests/engine_test.rs
git commit -m "feat(aegis-detection): detection engine harness — rayon parallel, weighted score aggregation"
```

---

## Chunk 3: Detectors (PortScan, SynFlood, RateLimiter, IpReputation)

### Task 6: PortScanDetector

**Files:**
- Create: `crates/aegis-detection/src/detectors/port_scan.rs`
- Modify: `crates/aegis-detection/src/detectors/mod.rs`
- Create: `crates/aegis-detection/tests/detectors_test.rs` (start the shared test file)

- [ ] **Step 1: Write failing test**

Create `crates/aegis-detection/tests/detectors_test.rs`:

```rust
// Shared detector tests — new tests and imports are added as each detector is implemented.
// Each task that adds a new detector appends both the import and the test functions.
use aegis_detection::{
    model::{DecodedPacket, DetectionContext, FlowState, TcpFlags},
    detectors::port_scan::PortScanDetector,
};
use aegis_rules::model::{Direction, Protocol};
use bytes::Bytes;
use std::net::IpAddr;

fn make_packet(src_ip: &str, dst_port: u16) -> DecodedPacket {
    DecodedPacket {
        src_ip: src_ip.parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: Some(50000),
        dst_port: Some(dst_port),
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        tcp_flags: Some(TcpFlags::default()),
        payload: Bytes::new(),
        packet_len: 40,
    }
}

fn default_flow() -> FlowState { FlowState::new() }
fn default_ctx() -> DetectionContext { DetectionContext::default() }

// ── PortScanDetector ─────────────────────────────────────────────────────────

#[test]
fn port_scan_triggers_above_threshold() {
    let detector = PortScanDetector::new(60, 5);
    let flow = default_flow();
    let ctx = default_ctx();
    // Contact 6 distinct ports — exceeds threshold of 5
    for port in 80u16..86 {
        detector.inspect(&make_packet("1.2.3.4", port), &flow, &ctx);
    }
    let result = detector.inspect(&make_packet("1.2.3.4", 99), &flow, &ctx);
    assert_eq!(result.score, 80, "expected port scan detection");
}

#[test]
fn port_scan_does_not_trigger_below_threshold() {
    let detector = PortScanDetector::new(60, 20);
    let flow = default_flow();
    let ctx = default_ctx();
    for port in 80u16..85 {
        detector.inspect(&make_packet("2.3.4.5", port), &flow, &ctx);
    }
    let result = detector.inspect(&make_packet("2.3.4.5", 85), &flow, &ctx);
    assert_eq!(result.score, 0);
}

#[test]
fn port_scan_different_ips_tracked_separately() {
    let detector = PortScanDetector::new(60, 3);
    let flow = default_flow();
    let ctx = default_ctx();
    // IP A contacts 2 ports
    for port in [80u16, 443] {
        detector.inspect(&make_packet("10.0.0.1", port), &flow, &ctx);
    }
    // IP B contacts 4 ports — should trigger
    for port in [80u16, 81, 82, 83] {
        detector.inspect(&make_packet("10.0.0.2", port), &flow, &ctx);
    }
    let result_a = detector.inspect(&make_packet("10.0.0.1", 8080), &flow, &ctx);
    let result_b = detector.inspect(&make_packet("10.0.0.2", 8080), &flow, &ctx);
    assert_eq!(result_a.score, 0, "IP A should not trigger yet");
    assert_eq!(result_b.score, 80, "IP B should trigger");
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test detectors_test 2>&1
```

Expected: compile error — detectors not yet implemented.

- [ ] **Step 3: Implement `port_scan.rs`**

Create `crates/aegis-detection/src/detectors/port_scan.rs`:

```rust
use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, DetectorResult, FlowState, Detector};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct PortScanDetector {
    windows: DashMap<IpAddr, VecDeque<(Instant, u16)>>,
    window: Duration,
    threshold: usize,
}

impl PortScanDetector {
    pub fn new(window_secs: u64, threshold: usize) -> Self {
        Self {
            windows: DashMap::new(),
            window: Duration::from_secs(window_secs),
            threshold,
        }
    }
}

impl Default for PortScanDetector {
    fn default() -> Self { Self::new(60, 20) }
}

impl Detector for PortScanDetector {
    fn name(&self) -> &'static str { "port_scan" }
    fn weight(&self) -> f32 { 1.5 }

    fn inspect(&self, packet: &DecodedPacket, _flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        let Some(dst_port) = packet.dst_port else {
            return DetectorResult::pass();
        };
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut entry = self.windows.entry(packet.src_ip).or_default();
        while entry.front().map_or(false, |(t, _)| *t < cutoff) {
            entry.pop_front();
        }
        entry.push_back((now, dst_port));

        let distinct: HashSet<u16> = entry.iter().map(|(_, p)| *p).collect();
        if distinct.len() >= self.threshold {
            let reason = BlockReason {
                code: "port_scan".to_string(),
                description: format!(
                    "{} distinct ports contacted within {}s",
                    distinct.len(),
                    self.window.as_secs()
                ),
            };
            return DetectorResult {
                score: 80,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "port_scan",
                    severity: Severity::High,
                    reason,
                    metadata: serde_json::json!({ "distinct_ports": distinct.len() }),
                }),
            };
        }
        DetectorResult::pass()
    }
}
```

Update `crates/aegis-detection/src/detectors/mod.rs`:

```rust
pub mod dpi;
pub mod geo_block;
pub mod ip_reputation;
pub mod port_scan;
pub mod protocol_anomaly;
pub mod rate_limiter;
pub mod syn_flood;
```

Create placeholder files for the remaining detectors (so the crate compiles):

```bash
touch crates/aegis-detection/src/detectors/dpi.rs
touch crates/aegis-detection/src/detectors/geo_block.rs
touch crates/aegis-detection/src/detectors/ip_reputation.rs
touch crates/aegis-detection/src/detectors/protocol_anomaly.rs
touch crates/aegis-detection/src/detectors/rate_limiter.rs
touch crates/aegis-detection/src/detectors/syn_flood.rs
```

- [ ] **Step 4: Run port scan tests only**

```bash
cargo test -p aegis-detection --test detectors_test port_scan 2>&1
```

Expected: `test result: ok. 3 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/detectors/
git commit -m "feat(aegis-detection): PortScanDetector — sliding window distinct port tracking"
```

---

### Task 7: SynFloodDetector

**Files:**
- Create: `crates/aegis-detection/src/detectors/syn_flood.rs`

- [ ] **Step 1: Add failing tests to `detectors_test.rs`**

Append to `crates/aegis-detection/tests/detectors_test.rs`:

```rust
// Add import at the top of the file (after existing imports):
use aegis_detection::detectors::syn_flood::SynFloodDetector;

// ── SynFloodDetector ─────────────────────────────────────────────────────────

fn make_flow_with_counts(syn: u32, ack: u32) -> FlowState {
    let mut state = FlowState::new();
    for _ in 0..syn {
        state.update_tcp_flags(&TcpFlags { syn: true, ..Default::default() });
    }
    for _ in 0..ack {
        state.update_tcp_flags(&TcpFlags { ack: true, ..Default::default() });
    }
    state
}

#[test]
fn syn_flood_triggers_above_ratio() {
    let detector = SynFloodDetector { syn_ratio_threshold: 3.0, min_syn_count: 10 };
    let flow = make_flow_with_counts(50, 2); // ratio = 50/3 ≈ 16.7
    let result = detector.inspect(&make_packet("3.4.5.6", 80), &flow, &default_ctx());
    assert_eq!(result.score, 90);
}

#[test]
fn syn_flood_below_min_count_does_not_trigger() {
    let detector = SynFloodDetector { syn_ratio_threshold: 3.0, min_syn_count: 10 };
    let flow = make_flow_with_counts(5, 0); // below min_syn_count
    let result = detector.inspect(&make_packet("3.4.5.6", 80), &flow, &default_ctx());
    assert_eq!(result.score, 0);
}

#[test]
fn syn_flood_normal_ratio_does_not_trigger() {
    let detector = SynFloodDetector { syn_ratio_threshold: 3.0, min_syn_count: 10 };
    let flow = make_flow_with_counts(15, 12); // ratio ≈ 1.15
    let result = detector.inspect(&make_packet("3.4.5.6", 80), &flow, &default_ctx());
    assert_eq!(result.score, 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test detectors_test syn_flood 2>&1
```

Expected: compile error or panic — `syn_flood.rs` is empty.

- [ ] **Step 3: Implement `syn_flood.rs`**

Write `crates/aegis-detection/src/detectors/syn_flood.rs`:

```rust
use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, DetectorResult, FlowState, Detector};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;

pub struct SynFloodDetector {
    pub syn_ratio_threshold: f32,
    pub min_syn_count: u32,
}

impl Default for SynFloodDetector {
    fn default() -> Self {
        Self { syn_ratio_threshold: 3.0, min_syn_count: 10 }
    }
}

impl Detector for SynFloodDetector {
    fn name(&self) -> &'static str { "syn_flood" }
    fn weight(&self) -> f32 { 2.0 }

    fn inspect(&self, _packet: &DecodedPacket, flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        if flow.syn_count < self.min_syn_count {
            return DetectorResult::pass();
        }
        let ratio = flow.syn_count as f32 / (flow.ack_count + 1) as f32;
        if ratio >= self.syn_ratio_threshold {
            let reason = BlockReason {
                code: "syn_flood".to_string(),
                description: format!(
                    "SYN/ACK ratio {:.1} ({}:{}) exceeds threshold {:.1}",
                    ratio, flow.syn_count, flow.ack_count, self.syn_ratio_threshold
                ),
            };
            DetectorResult {
                score: 90,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "syn_flood",
                    severity: Severity::Critical,
                    reason,
                    metadata: serde_json::json!({
                        "syn_count": flow.syn_count,
                        "ack_count": flow.ack_count,
                        "ratio": ratio
                    }),
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p aegis-detection --test detectors_test syn_flood 2>&1
```

Expected: `test result: ok. 3 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/detectors/syn_flood.rs crates/aegis-detection/tests/detectors_test.rs
git commit -m "feat(aegis-detection): SynFloodDetector — per-flow SYN/ACK ratio tracking"
```

---

### Task 8: RateLimiter

**Files:**
- Create: `crates/aegis-detection/src/detectors/rate_limiter.rs`

- [ ] **Step 1: Add failing tests to `detectors_test.rs`**

Append to `crates/aegis-detection/tests/detectors_test.rs`:

```rust
// Add import at the top of the file (after existing imports):
use aegis_detection::detectors::rate_limiter::RateLimiter;

// ── RateLimiter ──────────────────────────────────────────────────────────────

#[test]
fn rate_limiter_allows_within_capacity() {
    // capacity=5, rate=100/s — first 5 immediate packets should pass
    let detector = RateLimiter::new(100.0, 5.0);
    let flow = default_flow();
    let ctx = default_ctx();
    let pkt = make_packet("4.5.6.7", 80);
    for _ in 0..5 {
        let r = detector.inspect(&pkt, &flow, &ctx);
        assert_eq!(r.score, 0, "should be within capacity");
    }
}

#[test]
fn rate_limiter_blocks_when_tokens_exhausted() {
    // capacity=2, rate=0.001/s (negligible refill)
    let detector = RateLimiter::new(0.001, 2.0);
    let flow = default_flow();
    let ctx = default_ctx();
    let pkt = make_packet("5.6.7.8", 80);
    // consume 2 tokens
    detector.inspect(&pkt, &flow, &ctx);
    detector.inspect(&pkt, &flow, &ctx);
    // 3rd packet: no tokens, should be rate-limited
    let r = detector.inspect(&pkt, &flow, &ctx);
    assert_eq!(r.score, 60);
    assert!(r.reason.is_some());
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test detectors_test rate_limiter 2>&1
```

Expected: compile error — `rate_limiter.rs` is empty.

- [ ] **Step 3: Implement `rate_limiter.rs`**

Write `crates/aegis-detection/src/detectors/rate_limiter.rs`:

```rust
use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, DetectorResult, FlowState, Detector};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rate: f64,
    capacity: f64,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self { tokens: capacity, last_refill: Instant::now(), rate, capacity }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    buckets: DashMap<IpAddr, Mutex<TokenBucket>>,
    rate: f64,
    capacity: f64,
}

impl RateLimiter {
    pub fn new(rate: f64, capacity: f64) -> Self {
        Self { buckets: DashMap::new(), rate, capacity }
    }
}

impl Default for RateLimiter {
    fn default() -> Self { Self::new(1000.0, 2000.0) }
}

impl Detector for RateLimiter {
    fn name(&self) -> &'static str { "rate_limiter" }
    fn weight(&self) -> f32 { 1.0 }

    fn inspect(&self, packet: &DecodedPacket, _flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        let mut entry = self.buckets
            .entry(packet.src_ip)
            .or_insert_with(|| Mutex::new(TokenBucket::new(self.rate, self.capacity)));
        let allowed = entry.lock().unwrap().try_consume();
        if !allowed {
            let reason = BlockReason {
                code: "rate_exceeded".to_string(),
                description: format!(
                    "Source IP {} exceeded rate limit of {:.0} pkt/s",
                    packet.src_ip, self.rate
                ),
            };
            DetectorResult {
                score: 60,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "rate_limiter",
                    severity: Severity::Medium,
                    reason,
                    metadata: serde_json::json!({ "rate_per_sec": self.rate }),
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p aegis-detection --test detectors_test rate_limiter 2>&1
```

Expected: `test result: ok. 2 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/detectors/rate_limiter.rs crates/aegis-detection/tests/detectors_test.rs
git commit -m "feat(aegis-detection): RateLimiter — token bucket per src IP"
```

---

### Task 9: IpReputationDetector

**Files:**
- Create: `crates/aegis-detection/src/detectors/ip_reputation.rs`

- [ ] **Step 1: Add failing tests to `detectors_test.rs`**

Append to `crates/aegis-detection/tests/detectors_test.rs`:

```rust
// Add import at the top of the file (after existing imports):
use aegis_detection::detectors::ip_reputation::IpReputationDetector;

// ── IpReputationDetector ─────────────────────────────────────────────────────

#[test]
fn ip_reputation_blocks_listed_ip() {
    let detector = IpReputationDetector::new();
    detector.load_from_str("1.2.3.4\n5.6.7.8\n");
    let result = detector.inspect(&make_packet("1.2.3.4", 80), &default_flow(), &default_ctx());
    assert_eq!(result.score, 100);
}

#[test]
fn ip_reputation_allows_unlisted_ip() {
    let detector = IpReputationDetector::new();
    detector.load_from_str("1.2.3.4\n");
    let result = detector.inspect(&make_packet("9.9.9.9", 80), &default_flow(), &default_ctx());
    assert_eq!(result.score, 0);
}

#[test]
fn ip_reputation_hot_swap_clears_old_list() {
    use std::collections::HashSet;
    let detector = IpReputationDetector::new();
    detector.load_from_str("1.2.3.4\n");
    // hot-swap with empty set
    detector.swap_blocklist(HashSet::new());
    let result = detector.inspect(&make_packet("1.2.3.4", 80), &default_flow(), &default_ctx());
    assert_eq!(result.score, 0, "IP should be cleared after hot-swap");
}

#[test]
fn ip_reputation_skips_invalid_lines() {
    let detector = IpReputationDetector::new();
    detector.load_from_str("1.2.3.4\nnot-an-ip\n5.6.7.8\n");
    assert_eq!(
        detector.inspect(&make_packet("5.6.7.8", 80), &default_flow(), &default_ctx()).score,
        100
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test detectors_test ip_reputation 2>&1
```

Expected: compile error — `ip_reputation.rs` is empty.

- [ ] **Step 3: Implement `ip_reputation.rs`**

Write `crates/aegis-detection/src/detectors/ip_reputation.rs`:

```rust
use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, DetectorResult, FlowState, Detector};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

pub struct IpReputationDetector {
    blocklist: Arc<RwLock<HashSet<IpAddr>>>,
}

impl IpReputationDetector {
    pub fn new() -> Self {
        Self { blocklist: Arc::new(RwLock::new(HashSet::new())) }
    }

    /// Atomically replace the blocklist (for hot-swap on threat intel refresh).
    pub fn swap_blocklist(&self, ips: HashSet<IpAddr>) {
        *self.blocklist.write().unwrap() = ips;
    }

    /// Load IPs from a newline-separated string. Non-parseable lines are skipped silently.
    pub fn load_from_str(&self, content: &str) {
        let ips: HashSet<IpAddr> = content
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        self.swap_blocklist(ips);
    }
}

impl Default for IpReputationDetector {
    fn default() -> Self { Self::new() }
}

impl Detector for IpReputationDetector {
    fn name(&self) -> &'static str { "ip_reputation" }
    fn weight(&self) -> f32 { 1.5 }

    fn inspect(&self, packet: &DecodedPacket, _flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        if self.blocklist.read().unwrap().contains(&packet.src_ip) {
            let reason = BlockReason {
                code: "ip_reputation".to_string(),
                description: format!("Source IP {} is on the reputation block list", packet.src_ip),
            };
            DetectorResult {
                score: 100,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "ip_reputation",
                    severity: Severity::Critical,
                    reason,
                    metadata: serde_json::json!({ "src_ip": packet.src_ip.to_string() }),
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p aegis-detection --test detectors_test ip_reputation 2>&1
```

Expected: `test result: ok. 4 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/detectors/ip_reputation.rs crates/aegis-detection/tests/detectors_test.rs
git commit -m "feat(aegis-detection): IpReputationDetector — hot-swappable RwLock blocklist"
```

---

## Chunk 4: Detectors (GeoBlock, ProtocolAnomaly, DPI) + Final Verification

### Task 10: GeoBlockDetector

**Files:**
- Create: `crates/aegis-detection/src/detectors/geo_block.rs`

- [ ] **Step 1: Add failing tests to `detectors_test.rs`**

Append to `crates/aegis-detection/tests/detectors_test.rs`:

```rust
// Add import at the top of the file (after existing imports):
use aegis_detection::detectors::geo_block::GeoBlockDetector;

// ── GeoBlockDetector ─────────────────────────────────────────────────────────

#[test]
fn geo_block_no_db_always_passes() {
    // Without a MaxMind DB file, geo lookup is disabled — all packets pass.
    let detector = GeoBlockDetector::new(None, vec!["CN".to_string(), "RU".to_string()]);
    let result = detector.inspect(&make_packet("1.2.3.4", 80), &default_flow(), &default_ctx());
    assert_eq!(result.score, 0, "no DB → always pass");
}

#[test]
fn geo_block_no_countries_always_passes() {
    // Even with a DB path (non-existent file), no blocked countries → pass.
    let detector = GeoBlockDetector::new(
        Some(std::path::Path::new("/nonexistent/GeoLite2.mmdb")),
        vec![],
    );
    let result = detector.inspect(&make_packet("1.2.3.4", 80), &default_flow(), &default_ctx());
    assert_eq!(result.score, 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test detectors_test geo_block 2>&1
```

Expected: compile error — `geo_block.rs` is empty.

- [ ] **Step 3: Implement `geo_block.rs`**

Write `crates/aegis-detection/src/detectors/geo_block.rs`:

```rust
use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, DetectorResult, FlowState, Detector};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use std::collections::HashSet;
use std::path::Path;

pub struct GeoBlockDetector {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    blocked_countries: HashSet<String>,
}

impl GeoBlockDetector {
    /// Create with optional MaxMind GeoLite2-Country DB path and list of blocked
    /// ISO 3166-1 alpha-2 country codes (e.g. "CN", "RU").
    ///
    /// If `db_path` is `None` or the file does not exist, geo lookup is silently
    /// disabled and `inspect` always returns score=0.
    pub fn new(db_path: Option<&Path>, countries: Vec<String>) -> Self {
        let reader = db_path
            .filter(|p| p.exists())
            .and_then(|p| maxminddb::Reader::open_readfile(p).ok());
        Self {
            reader,
            blocked_countries: countries.into_iter().collect(),
        }
    }
}

impl Detector for GeoBlockDetector {
    fn name(&self) -> &'static str { "geo_block" }
    fn weight(&self) -> f32 { 1.0 }

    fn inspect(&self, packet: &DecodedPacket, _flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        let Some(ref reader) = self.reader else {
            return DetectorResult::pass();
        };

        let country_code: Option<String> = reader
            .lookup::<maxminddb::geoip2::Country>(packet.src_ip)
            .ok()
            .and_then(|c| c.country)
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string());

        if let Some(code) = country_code {
            if self.blocked_countries.contains(&code) {
                let reason = BlockReason {
                    code: "geo_block".to_string(),
                    description: format!(
                        "Source IP {} from blocked country {}",
                        packet.src_ip, code
                    ),
                };
                return DetectorResult {
                    score: 75,
                    reason: Some(reason.clone()),
                    event: Some(DetectionEvent {
                        detector: "geo_block",
                        severity: Severity::High,
                        reason,
                        metadata: serde_json::json!({ "country": code }),
                    }),
                };
            }
        }
        DetectorResult::pass()
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p aegis-detection --test detectors_test geo_block 2>&1
```

Expected: `test result: ok. 2 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/detectors/geo_block.rs crates/aegis-detection/tests/detectors_test.rs
git commit -m "feat(aegis-detection): GeoBlockDetector — maxminddb country lookup, disabled gracefully without DB"
```

---

### Task 11: ProtocolAnomalyDetector

**Files:**
- Create: `crates/aegis-detection/src/detectors/protocol_anomaly.rs`

- [ ] **Step 1: Add failing tests to `detectors_test.rs`**

Append to `crates/aegis-detection/tests/detectors_test.rs`:

```rust
// Add import at the top of the file (after existing imports):
use aegis_detection::detectors::protocol_anomaly::ProtocolAnomalyDetector;

// ── ProtocolAnomalyDetector ──────────────────────────────────────────────────

fn make_tcp_packet_with_flags(flags: TcpFlags) -> DecodedPacket {
    DecodedPacket {
        src_ip: "1.2.3.4".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: Some(50000),
        dst_port: Some(80),
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        tcp_flags: Some(flags),
        payload: Bytes::new(),
        packet_len: 40,
    }
}

#[test]
fn protocol_anomaly_syn_rst_triggers() {
    let detector = ProtocolAnomalyDetector;
    let flags = TcpFlags { syn: true, rst: true, ..Default::default() };
    let result = detector.inspect(&make_tcp_packet_with_flags(flags), &default_flow(), &default_ctx());
    assert_eq!(result.score, 70);
    assert_eq!(result.reason.unwrap().code, "syn_rst");
}

#[test]
fn protocol_anomaly_syn_fin_triggers() {
    let detector = ProtocolAnomalyDetector;
    let flags = TcpFlags { syn: true, fin: true, ..Default::default() };
    let result = detector.inspect(&make_tcp_packet_with_flags(flags), &default_flow(), &default_ctx());
    assert_eq!(result.score, 70);
    assert_eq!(result.reason.unwrap().code, "syn_fin");
}

#[test]
fn protocol_anomaly_null_scan_triggers() {
    let detector = ProtocolAnomalyDetector;
    let flags = TcpFlags::default(); // all false
    let result = detector.inspect(&make_tcp_packet_with_flags(flags), &default_flow(), &default_ctx());
    assert_eq!(result.score, 60);
    assert_eq!(result.reason.unwrap().code, "null_scan");
}

#[test]
fn protocol_anomaly_xmas_scan_triggers() {
    let detector = ProtocolAnomalyDetector;
    let flags = TcpFlags { syn: true, ack: true, fin: true, rst: true, psh: true, urg: true };
    let result = detector.inspect(&make_tcp_packet_with_flags(flags), &default_flow(), &default_ctx());
    assert_eq!(result.score, 75);
    assert_eq!(result.reason.unwrap().code, "xmas_scan");
}

#[test]
fn protocol_anomaly_normal_syn_passes() {
    let detector = ProtocolAnomalyDetector;
    let flags = TcpFlags { syn: true, ..Default::default() };
    let result = detector.inspect(&make_tcp_packet_with_flags(flags), &default_flow(), &default_ctx());
    assert_eq!(result.score, 0);
}

#[test]
fn protocol_anomaly_udp_always_passes() {
    let detector = ProtocolAnomalyDetector;
    let mut pkt = make_packet("1.2.3.4", 53);
    pkt.protocol = Protocol::Udp;
    pkt.tcp_flags = None;
    let result = detector.inspect(&pkt, &default_flow(), &default_ctx());
    assert_eq!(result.score, 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test detectors_test protocol_anomaly 2>&1
```

Expected: compile error — `protocol_anomaly.rs` is empty.

- [ ] **Step 3: Implement `protocol_anomaly.rs`**

Write `crates/aegis-detection/src/detectors/protocol_anomaly.rs`:

```rust
use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, DetectorResult, FlowState, Detector};
use aegis_rules::model::{BlockReason, Protocol};
use aegis_store::model::Severity;

pub struct ProtocolAnomalyDetector;

impl Default for ProtocolAnomalyDetector {
    fn default() -> Self { Self }
}

impl Detector for ProtocolAnomalyDetector {
    fn name(&self) -> &'static str { "protocol_anomaly" }
    fn weight(&self) -> f32 { 1.2 }

    fn inspect(&self, packet: &DecodedPacket, _flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        if !matches!(packet.protocol, Protocol::Tcp) {
            return DetectorResult::pass();
        }
        let Some(flags) = &packet.tcp_flags else {
            return DetectorResult::pass();
        };

        // Check anomaly patterns in priority order.
        // Xmas scan (all flags set) must be checked before syn+rst/syn+fin,
        // because all-flags-set also satisfies those narrower conditions.
        let anomaly: Option<(&'static str, &'static str, u8)> = if flags.syn && flags.ack && flags.fin && flags.rst && flags.psh && flags.urg {
            Some(("xmas_scan", "All TCP flags set (Xmas scan)", 75))
        } else if flags.syn && flags.rst {
            Some(("syn_rst", "SYN+RST combination is invalid", 70))
        } else if flags.syn && flags.fin {
            Some(("syn_fin", "SYN+FIN combination is invalid", 70))
        } else if !flags.syn && !flags.ack && !flags.fin && !flags.rst && !flags.psh && !flags.urg {
            Some(("null_scan", "All TCP flags clear (null scan)", 60))
        } else {
            None
        };

        if let Some((code, desc, score)) = anomaly {
            let reason = BlockReason {
                code: code.to_string(),
                description: desc.to_string(),
            };
            DetectorResult {
                score,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "protocol_anomaly",
                    severity: Severity::Medium,
                    reason,
                    metadata: serde_json::Value::Null,
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p aegis-detection --test detectors_test protocol_anomaly 2>&1
```

Expected: `test result: ok. 6 passed; 0 failed`

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-detection/src/detectors/protocol_anomaly.rs crates/aegis-detection/tests/detectors_test.rs
git commit -m "feat(aegis-detection): ProtocolAnomalyDetector — SYN+RST, SYN+FIN, null scan, Xmas scan"
```

---

### Task 12: DpiDetector

**Files:**
- Create: `crates/aegis-detection/src/detectors/dpi.rs`

- [ ] **Step 1: Add failing tests to `detectors_test.rs`**

Append to `crates/aegis-detection/tests/detectors_test.rs`:

```rust
// Add import at the top of the file (after existing imports):
use aegis_detection::detectors::dpi::DpiDetector;

// ── DpiDetector ──────────────────────────────────────────────────────────────

fn make_flow_with_payload(data: &[u8]) -> FlowState {
    let mut state = FlowState::new();
    state.append_payload(data);
    state
}

#[test]
fn dpi_matches_pattern_in_payload() {
    let detector = DpiDetector::from_patterns(vec![
        ("malware-c2".to_string(), "POST /beacon".to_string()),
    ]).unwrap();
    let flow = make_flow_with_payload(b"GET / HTTP/1.1\r\nHost: example.com\r\nPOST /beacon HTTP/1.1");
    let result = detector.inspect(&make_packet("1.2.3.4", 80), &flow, &default_ctx());
    assert_eq!(result.score, 85);
    assert_eq!(result.reason.unwrap().code, "dpi_match");
}

#[test]
fn dpi_no_match_returns_pass() {
    let detector = DpiDetector::from_patterns(vec![
        ("bad-agent".to_string(), "evil-bot/1.0".to_string()),
    ]).unwrap();
    let flow = make_flow_with_payload(b"GET / HTTP/1.1\r\nUser-Agent: curl/7.68\r\n");
    let result = detector.inspect(&make_packet("1.2.3.4", 80), &flow, &default_ctx());
    assert_eq!(result.score, 0);
}

#[test]
fn dpi_empty_payload_returns_pass() {
    let detector = DpiDetector::from_patterns(vec![
        ("test".to_string(), "anything".to_string()),
    ]).unwrap();
    let flow = default_flow();
    let result = detector.inspect(&make_packet("1.2.3.4", 80), &flow, &default_ctx());
    assert_eq!(result.score, 0);
}

#[test]
fn dpi_from_toml_parses_patterns() {
    let toml = r#"
[[patterns]]
label = "sql-injection"
pattern = "' OR '1'='1"

[[patterns]]
label = "shell-cmd"
pattern = "/bin/sh"
"#;
    let detector = DpiDetector::from_toml(toml).unwrap();
    assert_eq!(detector.pattern_count(), 2);
    let flow = make_flow_with_payload(b"SELECT * FROM users WHERE id=1' OR '1'='1");
    let result = detector.inspect(&make_packet("1.2.3.4", 3306), &flow, &default_ctx());
    assert_eq!(result.score, 85);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p aegis-detection --test detectors_test dpi 2>&1
```

Expected: compile error — `dpi.rs` is empty.

- [ ] **Step 3: Implement `dpi.rs`**

Write `crates/aegis-detection/src/detectors/dpi.rs`:

```rust
use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, DetectorResult, FlowState, Detector};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use aho_corasick::AhoCorasick;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct DpiPatternFile {
    pub patterns: Vec<DpiPatternEntry>,
}

#[derive(Deserialize)]
pub struct DpiPatternEntry {
    pub label: String,
    pub pattern: String,
}

pub struct DpiDetector {
    automaton: Arc<AhoCorasick>,
    labels: Vec<String>,
}

impl DpiDetector {
    /// Build from (label, pattern) pairs. Returns error if automaton construction fails.
    pub fn from_patterns(
        patterns: Vec<(String, String)>,
    ) -> Result<Self, aho_corasick::BuildError> {
        let (labels, pats): (Vec<_>, Vec<_>) = patterns.into_iter().unzip();
        let automaton = AhoCorasick::new(&pats)?;
        Ok(Self {
            automaton: Arc::new(automaton),
            labels,
        })
    }

    /// Parse patterns from TOML string (format: `[[patterns]]\nlabel = "..."\npattern = "..."`).
    pub fn from_toml(toml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file: DpiPatternFile = toml::from_str(toml_str)?;
        let pairs: Vec<(String, String)> = file
            .patterns
            .into_iter()
            .map(|p| (p.label, p.pattern))
            .collect();
        Ok(Self::from_patterns(pairs)?)
    }

    pub fn pattern_count(&self) -> usize {
        self.labels.len()
    }
}

impl Detector for DpiDetector {
    fn name(&self) -> &'static str { "dpi" }
    fn weight(&self) -> f32 { 1.8 }

    fn inspect(&self, _packet: &DecodedPacket, flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        if flow.payload_buf.is_empty() {
            return DetectorResult::pass();
        }
        if let Some(m) = self.automaton.find(&flow.payload_buf[..]) {
            let label = &self.labels[m.pattern().as_usize()];
            let reason = BlockReason {
                code: "dpi_match".to_string(),
                description: format!("DPI pattern match: {}", label),
            };
            DetectorResult {
                score: 85,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "dpi",
                    severity: Severity::High,
                    reason,
                    metadata: serde_json::json!({ "matched_pattern": label }),
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p aegis-detection --test detectors_test dpi 2>&1
```

Expected: `test result: ok. 4 passed; 0 failed`

- [ ] **Step 5: Run all detector tests to confirm no regressions**

```bash
cargo test -p aegis-detection --test detectors_test 2>&1
```

Expected: all detector tests pass (≥22 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/aegis-detection/src/detectors/dpi.rs crates/aegis-detection/tests/detectors_test.rs
git commit -m "feat(aegis-detection): DpiDetector — Aho-Corasick multi-pattern matching on reassembled TCP payload"
```

---

### Task 13: Final Verification

**Files:** No new files.

- [ ] **Step 1: Run full workspace test suite**

```bash
cargo test --workspace 2>&1
```

Expected: all tests pass, 0 failures. (1 `#[ignore]` for SQLCipher test in aegis-store is expected.)

- [ ] **Step 2: Format and clippy**

```bash
cargo fmt --all && cargo clippy --workspace -- -D warnings 2>&1
```

Expected: no warnings, no errors.

Common clippy fixes needed:
- If `AhoCorasick::new(&pats)` is flagged, ensure pats is `Vec<String>` (not `Vec<&String>`)
- If `entry.lock().unwrap()` inside `DashMap::entry` is flagged, it's fine — ignore if needed with `#[allow(clippy::...)]`
- Check for `needless_pass_by_value`, `redundant_closure`, `map_clone` warnings

- [ ] **Step 3: Release build**

```bash
cargo build --workspace --release 2>&1
```

Expected: `Finished release [optimized]` with no errors.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete Plan 2 — aegis-detection engine, 7 detectors, flow table, DPI"
```

- [ ] **Step 5: Push to origin**

```bash
git push origin main 2>&1
```

Expected: `main -> main` pushed successfully.
