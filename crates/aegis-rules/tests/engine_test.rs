use aegis_rules::{engine::RuleEngine, model::*};

fn make_packet(src: &str, dst: &str, dst_port: u16, proto: Protocol) -> PacketInfo {
    PacketInfo {
        src_ip: src.parse().unwrap(),
        dst_ip: dst.parse().unwrap(),
        src_port: Some(12345),
        dst_port: Some(dst_port),
        protocol: proto,
        direction: Direction::Inbound,
    }
}

fn ssh_allow_rule() -> Rule {
    Rule {
        id: "ssh-allow".to_string(),
        priority: 10,
        name: "Allow SSH".to_string(),
        enabled: true,
        matches: vec![
            Match::DstPort(PortRange::Single(22)),
            Match::Protocol(Protocol::Tcp),
        ],
        action: Action::Allow,
        log: false,
    }
}

fn default_block_rule() -> Rule {
    Rule {
        id: "default-block".to_string(),
        priority: 1000,
        name: "Default block".to_string(),
        enabled: true,
        matches: vec![],
        action: Action::Block,
        log: true,
    }
}

#[test]
fn matching_rule_returns_its_action() {
    let engine = RuleEngine::new(vec![ssh_allow_rule(), default_block_rule()]);
    let pkt = make_packet("10.0.0.1", "10.0.0.2", 22, Protocol::Tcp);
    let verdict = engine.evaluate(&pkt).unwrap();
    assert!(matches!(verdict.action, Action::Allow));
    assert_eq!(verdict.rule_id.as_deref(), Some("ssh-allow"));
}

#[test]
fn no_matching_rule_returns_default_block() {
    let engine = RuleEngine::new(vec![ssh_allow_rule(), default_block_rule()]);
    let pkt = make_packet("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp);
    let verdict = engine.evaluate(&pkt).unwrap();
    assert!(matches!(verdict.action, Action::Block));
    assert_eq!(verdict.rule_id.as_deref(), Some("default-block"));
}

#[test]
fn disabled_rule_is_skipped() {
    let mut rule = ssh_allow_rule();
    rule.enabled = false;
    let engine = RuleEngine::new(vec![rule, default_block_rule()]);
    let pkt = make_packet("10.0.0.1", "10.0.0.2", 22, Protocol::Tcp);
    let verdict = engine.evaluate(&pkt).unwrap();
    // disabled ssh rule skipped → hits default block
    assert!(matches!(verdict.action, Action::Block));
}

#[test]
fn src_ip_cidr_match() {
    let rule = Rule {
        id: "cidr-rule".to_string(),
        priority: 5,
        name: "Allow trusted subnet".to_string(),
        enabled: true,
        matches: vec![Match::SrcIp("192.168.1.0/24".parse().unwrap())],
        action: Action::Allow,
        log: false,
    };
    let engine = RuleEngine::new(vec![rule]);

    let pkt_in = make_packet("192.168.1.100", "10.0.0.1", 80, Protocol::Tcp);
    assert!(matches!(
        engine.evaluate(&pkt_in).unwrap().action,
        Action::Allow
    ));

    let pkt_out = make_packet("192.168.2.1", "10.0.0.1", 80, Protocol::Tcp);
    // No match → None
    assert!(engine.evaluate(&pkt_out).is_none());
}

#[test]
fn empty_engine_returns_none() {
    let engine = RuleEngine::new(vec![]);
    let pkt = make_packet("1.2.3.4", "5.6.7.8", 80, Protocol::Tcp);
    assert!(engine.evaluate(&pkt).is_none());
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn engine_never_panics_on_any_packet(
        src_a in 0u8..=255, src_b in 0u8..=255,
        dst_port in 0u16..=65535,
        proto_idx in 0usize..4,
        dir_idx in 0usize..3,
    ) {
        let engine = RuleEngine::new(vec![ssh_allow_rule(), default_block_rule()]);
        let proto = match proto_idx {
            0 => Protocol::Tcp,
            1 => Protocol::Udp,
            2 => Protocol::Icmp,
            _ => Protocol::Any,
        };
        let direction = match dir_idx {
            0 => Direction::Inbound,
            1 => Direction::Outbound,
            _ => Direction::Forward,
        };
        let pkt = PacketInfo {
            src_ip: format!("{}.{}.1.1", src_a, src_b).parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: Some(12345),
            dst_port: Some(dst_port),
            protocol: proto,
            direction,
        };
        // Should never panic regardless of input
        let _ = engine.evaluate(&pkt);
    }
}
