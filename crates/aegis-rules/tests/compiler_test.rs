use aegis_rules::{compiler::compile_rules, model::*};

#[test]
fn compile_empty_rules_produces_valid_json() {
    let ruleset = compile_rules(&[], "v0.0.1");
    let parsed: serde_json::Value = serde_json::from_str(&ruleset.nftables_json).unwrap();
    assert!(parsed.get("nftables").is_some());
}

#[test]
fn compile_allow_rule_contains_accept_verdict() {
    let rule = Rule {
        id: "test".to_string(),
        priority: 10,
        name: "Allow SSH".to_string(),
        enabled: true,
        matches: vec![Match::DstPort(PortRange::Single(22))],
        action: Action::Allow,
        log: false,
    };
    let ruleset = compile_rules(&[rule], "v0.0.2");
    assert!(ruleset.nftables_json.contains("accept"));
    assert_eq!(ruleset.version, "v0.0.2");
}

#[test]
fn compile_block_rule_contains_drop_verdict() {
    let rule = Rule {
        id: "block-all".to_string(),
        priority: 1000,
        name: "Block all".to_string(),
        enabled: true,
        matches: vec![],
        action: Action::Block,
        log: false,
    };
    let ruleset = compile_rules(&[rule], "v0.0.3");
    assert!(ruleset.nftables_json.contains("drop"));
}

#[test]
fn disabled_rules_not_compiled() {
    let rule = Rule {
        id: "disabled".to_string(),
        priority: 10,
        name: "Disabled rule".to_string(),
        enabled: false,
        matches: vec![],
        action: Action::Allow,
        log: false,
    };
    let ruleset = compile_rules(&[rule], "v1");
    // Disabled rule should not appear
    let parsed: serde_json::Value = serde_json::from_str(&ruleset.nftables_json).unwrap();
    let rules_arr = parsed["nftables"].as_array().unwrap();
    // Only the table/chain setup entries, no user rules with comment "disabled"
    for entry in rules_arr {
        if let Some(rule_obj) = entry.get("rule") {
            let comment = rule_obj
                .get("comment")
                .and_then(|c| c.as_str())
                .unwrap_or("");
            assert!(!comment.contains("disabled"));
        }
    }
}
