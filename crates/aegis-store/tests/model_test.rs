use aegis_store::model::*;

#[test]
fn severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn event_display() {
    let e = Event {
        id: None,
        ts: 0,
        severity: Severity::High,
        kind: EventKind::Block,
        src_ip: "1.2.3.4".to_string(),
        dst_ip: "5.6.7.8".to_string(),
        src_port: Some(12345),
        dst_port: Some(80),
        protocol: Some("tcp".to_string()),
        rule_id: None,
        detector: None,
        score: Some(85),
        hit_count: 1,
        first_seen: 0,
        last_seen: 0,
        reason_code: Some("port_scan".to_string()),
        reason_desc: Some("Port scan detected".to_string()),
        raw_meta: None,
    };
    assert_eq!(e.severity, Severity::High);
    assert_eq!(e.kind, EventKind::Block);
}
