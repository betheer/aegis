// Shared detector tests — new tests and imports are added as each detector is implemented.
// Each task that adds a new detector appends both the import and the test functions.
use aegis_detection::{
    model::{DecodedPacket, DetectionContext, FlowState, TcpFlags},
    detectors::port_scan::PortScanDetector,
    detectors::syn_flood::SynFloodDetector,
    detectors::rate_limiter::RateLimiter,
    detectors::ip_reputation::IpReputationDetector,
    detectors::geo_block::GeoBlockDetector,
    detectors::protocol_anomaly::ProtocolAnomalyDetector,
    detectors::dpi::DpiDetector,
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
    // threshold=4: IP A reaches 3 distinct ports (below threshold), IP B reaches 5 (at/above)
    let detector = PortScanDetector::new(60, 4);
    let flow = default_flow();
    let ctx = default_ctx();
    // IP A contacts 2 ports
    for port in [80u16, 443] {
        detector.inspect(&make_packet("10.0.0.1", port), &flow, &ctx);
    }
    // IP B contacts 4 ports — meets threshold, should trigger
    for port in [80u16, 81, 82, 83] {
        detector.inspect(&make_packet("10.0.0.2", port), &flow, &ctx);
    }
    let result_a = detector.inspect(&make_packet("10.0.0.1", 8080), &flow, &ctx); // IP A: 3 distinct, below 4
    let result_b = detector.inspect(&make_packet("10.0.0.2", 8080), &flow, &ctx); // IP B: 5 distinct, >= 4
    assert_eq!(result_a.score, 0, "IP A should not trigger yet");
    assert_eq!(result_b.score, 80, "IP B should trigger");
}

#[test]
fn port_scan_triggers_at_exact_threshold() {
    let detector = PortScanDetector::new(60, 3);
    let flow = default_flow();
    let ctx = default_ctx();
    // Contact exactly 3 distinct ports — equals threshold, should trigger
    for port in [80u16, 443, 8080] {
        detector.inspect(&make_packet("7.8.9.0", port), &flow, &ctx);
    }
    let result = detector.inspect(&make_packet("7.8.9.0", 8080), &flow, &ctx); // repeat port, still 3 distinct
    assert_eq!(result.score, 80, "exactly threshold distinct ports should trigger");
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
