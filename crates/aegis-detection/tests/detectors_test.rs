// Shared detector tests — new tests and imports are added as each detector is implemented.
// Each task that adds a new detector appends both the import and the test functions.
use aegis_detection::{
    model::{DecodedPacket, DetectionContext, FlowState, TcpFlags},
    detectors::port_scan::PortScanDetector,
    detectors::syn_flood::SynFloodDetector,
    detectors::rate_limiter::RateLimiter,
    detectors::ip_reputation::IpReputationDetector,
    Detector,
};
use aegis_rules::model::{Direction, Protocol};
use bytes::Bytes;

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
