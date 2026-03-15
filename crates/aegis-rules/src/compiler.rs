//! Compiles Vec<Rule> into a nftables JSON Ruleset for atomic application.
//! Output format follows nftables JSON schema (nft -j).
use crate::model::*;
use aegis_core::Ruleset;
use serde_json::{json, Value};

pub fn compile_rules(rules: &[Rule], version: &str) -> Ruleset {
    let active: Vec<&Rule> = rules.iter().filter(|r| r.enabled).collect();

    let mut statements: Vec<Value> = vec![
        // Clear + recreate the aegis table
        json!({ "flush": { "ruleset": null } }),
        json!({ "add": { "table": { "family": "inet", "name": "aegis" } } }),
        json!({ "add": { "chain": {
            "family": "inet",
            "table": "aegis",
            "name": "input",
            "type": "filter",
            "hook": "input",
            "prio": 0,
            "policy": "accept"
        }}}),
    ];

    for rule in &active {
        statements.push(compile_rule(rule));
    }

    let nftables_json = json!({ "nftables": statements }).to_string();

    Ruleset {
        nftables_json,
        version: version.to_string(),
    }
}

fn compile_rule(rule: &Rule) -> Value {
    let mut exprs: Vec<Value> = vec![];

    for m in &rule.matches {
        match m {
            Match::DstPort(PortRange::Single(port)) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "payload": { "protocol": "tcp", "field": "dport" } }, "right": port } }));
            }
            Match::DstPort(PortRange::Range { start, end }) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "payload": { "protocol": "tcp", "field": "dport" } }, "right": { "range": [start, end] } } }));
            }
            Match::SrcIp(net) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "saddr" } }, "right": { "prefix": { "addr": net.network().to_string(), "len": net.prefix_len() } } } }));
            }
            Match::DstIp(net) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "daddr" } }, "right": { "prefix": { "addr": net.network().to_string(), "len": net.prefix_len() } } } }));
            }
            Match::Protocol(Protocol::Tcp) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "tcp" } }));
            }
            Match::Protocol(Protocol::Udp) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "udp" } }));
            }
            _ => {} // Direction, Protocol::Any, SrcPort handled in future iterations
        }
    }

    let verdict = match &rule.action {
        Action::Allow => json!({ "accept": null }),
        Action::Block => json!({ "drop": null }),
        Action::Reject => json!({ "reject": { "type": "tcp reset" } }),
        Action::Log | Action::RateLimit(_) => json!({ "accept": null }), // simplified; full impl in phase 2
    };

    exprs.push(verdict);

    if rule.log {
        let log_idx = exprs.len() - 1;
        exprs.insert(
            log_idx,
            json!({ "log": { "prefix": format!("[aegis:{}] ", rule.id) } }),
        );
    }

    json!({
        "add": {
            "rule": {
                "family": "inet",
                "table": "aegis",
                "chain": "input",
                "comment": rule.id,
                "expr": exprs
            }
        }
    })
}
