use crate::model::*;

/// Result of evaluating a packet against the rule set.
#[derive(Debug)]
pub struct Verdict {
    pub action: Action,
    pub rule_id: Option<String>,
    pub log: bool,
}

/// Ordered, compiled rule set for O(n) packet evaluation.
/// Rules are pre-sorted by priority (ascending) at construction.
pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    /// Create from a list of rules. Always sorts by priority ascending.
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut sorted = rules;
        sorted.sort_by_key(|r| r.priority);
        Self { rules: sorted }
    }

    /// Evaluate a packet against all rules. Returns the first matching rule's verdict.
    /// Returns `None` if no rule matches (caller decides default action).
    pub fn evaluate(&self, packet: &PacketInfo) -> Option<Verdict> {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if self.rule_matches(rule, packet) {
                return Some(Verdict {
                    action: rule.action.clone(),
                    rule_id: Some(rule.id.clone()),
                    log: rule.log,
                });
            }
        }
        None
    }

    fn rule_matches(&self, rule: &Rule, packet: &PacketInfo) -> bool {
        // All match conditions must hold (AND semantics)
        rule.matches
            .iter()
            .all(|m| self.condition_matches(m, packet))
    }

    fn condition_matches(&self, condition: &Match, packet: &PacketInfo) -> bool {
        match condition {
            Match::SrcIp(net) => net.contains(&packet.src_ip),
            Match::DstIp(net) => net.contains(&packet.dst_ip),
            Match::SrcPort(range) => packet.src_port.is_some_and(|p| range.contains(p)),
            Match::DstPort(range) => packet.dst_port.is_some_and(|p| range.contains(p)),
            Match::Protocol(proto) => match proto {
                Protocol::Any => true,
                _ => std::mem::discriminant(proto) == std::mem::discriminant(&packet.protocol),
            },
            Match::Direction(dir) => {
                std::mem::discriminant(dir) == std::mem::discriminant(&packet.direction)
            }
        }
    }
}
