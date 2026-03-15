use aegis_rules::model::*;

#[test]
fn rule_priority_ordering() {
    let r1 = Rule {
        priority: 10,
        ..Rule::default_allow()
    };
    let r2 = Rule {
        priority: 5,
        ..Rule::default_allow()
    };
    let mut rules = vec![r1, r2];
    rules.sort_by_key(|r| r.priority);
    assert_eq!(rules[0].priority, 5);
    assert_eq!(rules[1].priority, 10);
}

#[test]
fn port_range_contains() {
    let range = PortRange::Single(80);
    assert!(range.contains(80));
    assert!(!range.contains(81));

    let range = PortRange::Range {
        start: 8000,
        end: 8999,
    };
    assert!(range.contains(8080));
    assert!(!range.contains(9000));
}

#[test]
fn rate_limit_policy_default() {
    let policy = RateLimitPolicy::default();
    assert_eq!(policy.scope, RateLimitScope::PerSrcIp);
    assert_eq!(policy.on_exceed, ExceedAction::Drop);
}
