#[allow(unused_imports)]
use aegis_detection::{
    DecodedPacket, DetectionContext, DetectorResult, FlowKey, FlowState, TcpFlags, VerdictAction,
};
use aegis_rules::model::{Direction, Protocol};
use bytes::Bytes;
#[allow(unused_imports)]
use std::net::IpAddr;

fn test_packet() -> DecodedPacket {
    DecodedPacket {
        src_ip: "1.2.3.4".parse().unwrap(),
        dst_ip: "5.6.7.8".parse().unwrap(),
        src_port: Some(12345),
        dst_port: Some(80),
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        tcp_flags: Some(TcpFlags {
            syn: true,
            ..Default::default()
        }),
        payload: Bytes::from_static(b"hello"),
        packet_len: 60,
    }
}

#[test]
fn flow_state_update_tcp_flags() {
    let mut state = FlowState::new();
    let flags = TcpFlags {
        syn: true,
        ..Default::default()
    };
    state.update_tcp_flags(&flags);
    state.update_tcp_flags(&flags);
    assert_eq!(state.syn_count, 2);
    assert_eq!(state.ack_count, 0);
}

#[test]
fn flow_state_append_payload_caps_at_64k() {
    let mut state = FlowState::new();
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
    state.update_tcp_flags(&TcpFlags {
        rst: true,
        ..Default::default()
    });
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
