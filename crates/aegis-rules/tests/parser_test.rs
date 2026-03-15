use aegis_rules::{model::*, parser::parse_rules_toml, RulesError};

const VALID_TOML: &str = r#"
[[rules]]
id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
priority = 10
name = "Allow SSH"
enabled = true
action = { type = "allow" }
log = false

  [[rules.matches]]
  type = "src_ip"
  value = "192.168.1.0/24"

  [[rules.matches]]
  type = "dst_port"
  value = 22

  [[rules.matches]]
  type = "protocol"
  value = "tcp"
"#;

#[test]
fn parse_valid_toml() {
    let rules = parse_rules_toml(VALID_TOML).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "Allow SSH");
    assert_eq!(rules[0].priority, 10);
    assert!(rules[0].enabled);
    assert_eq!(rules[0].matches.len(), 3);
}

#[test]
fn parse_invalid_toml_returns_error() {
    let result = parse_rules_toml("this is not toml ][");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), RulesError::ParseError(_)));
}

#[test]
fn parse_rule_with_out_of_range_priority_fails() {
    let toml = r#"
[[rules]]
id = "a1b2c3d4-e5f6-7890-abcd-ef1234567891"
priority = 99999
name = "Bad priority"
action = { type = "allow" }
"#;
    let result = parse_rules_toml(toml);
    assert!(matches!(
        result.unwrap_err(),
        RulesError::ValidationError { .. }
    ));
}

#[test]
fn parse_duplicate_ids_fails() {
    let toml = r#"
[[rules]]
id = "same-id"
priority = 1
name = "Rule 1"
action = { type = "allow" }

[[rules]]
id = "same-id"
priority = 2
name = "Rule 2"
action = { type = "block" }
"#;
    let result = parse_rules_toml(toml);
    assert!(matches!(
        result.unwrap_err(),
        RulesError::ConflictError { .. }
    ));
}

#[test]
fn parse_rate_limit_action() {
    let toml = r#"
[[rules]]
id = "rl-rule"
priority = 50
name = "Rate limit HTTP"
log = true

  [rules.action]
  type = "rate_limit"
  rate = 100
  burst = 200
  unit = "packets"
  scope = "per_src_ip"
  on_exceed = "drop"
"#;
    let rules = parse_rules_toml(toml).unwrap();
    assert_eq!(rules.len(), 1);
    assert!(matches!(rules[0].action, Action::RateLimit(_)));
}
