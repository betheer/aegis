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
        if flags.syn {
            self.syn_count += 1;
        }
        if flags.ack {
            self.ack_count += 1;
        }
        if flags.rst {
            self.rst_count += 1;
        }
        if flags.fin {
            self.fin_count += 1;
        }
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
    fn default() -> Self {
        Self::new()
    }
}

/// Per-packet evaluation thresholds (configurable).
pub struct DetectionContext {
    pub threshold_block: u8,   // default 70
    pub threshold_monitor: u8, // default 40
}

impl Default for DetectionContext {
    fn default() -> Self {
        Self {
            threshold_block: 70,
            threshold_monitor: 40,
        }
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
        Self {
            score: 0,
            reason: None,
            event: None,
        }
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
    fn inspect(
        &self,
        packet: &DecodedPacket,
        flow: &FlowState,
        ctx: &DetectionContext,
    ) -> DetectorResult;
}
