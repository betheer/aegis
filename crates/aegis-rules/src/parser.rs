use crate::{
    error::{Result, RulesError},
    model::Rule,
};

/// Parse and validate a TOML string into an ordered list of rules.
/// Returns error on invalid TOML, invalid field values, or duplicate IDs.
pub fn parse_rules_toml(toml_str: &str) -> Result<Vec<Rule>> {
    #[derive(serde::Deserialize)]
    struct RulesFile {
        #[serde(default)]
        rules: Vec<Rule>,
    }

    let file: RulesFile =
        toml::from_str(toml_str).map_err(|e| RulesError::ParseError(e.to_string()))?;

    validate_rules(file.rules)
}

/// Parse a TOML file from disk.
pub fn parse_rules_file(path: &std::path::Path) -> Result<Vec<Rule>> {
    let content = std::fs::read_to_string(path)
        .map_err(|_| RulesError::FileNotFound(path.display().to_string()))?;
    parse_rules_toml(&content)
}

fn validate_rules(mut rules: Vec<Rule>) -> Result<Vec<Rule>> {
    use std::collections::HashMap;
    let mut seen_ids: HashMap<String, usize> = HashMap::new();

    for (idx, rule) in rules.iter().enumerate() {
        // Priority range check (u32 field but spec says max 65535)
        if rule.priority > 65535 {
            return Err(RulesError::ValidationError {
                id: rule.id.clone(),
                reason: format!("priority {} exceeds maximum 65535", rule.priority),
            });
        }

        // Duplicate ID check — track first occurrence index
        if let Some(&first_idx) = seen_ids.get(&rule.id) {
            return Err(RulesError::ConflictError {
                id: rule.id.clone(),
                other_id: rules[first_idx].id.clone(),
                detail: format!(
                    "duplicate rule ID (first seen at position {}, repeated at position {})",
                    first_idx, idx
                ),
            });
        }
        seen_ids.insert(rule.id.clone(), idx);

        // Name must not be empty
        if rule.name.trim().is_empty() {
            return Err(RulesError::ValidationError {
                id: rule.id.clone(),
                reason: "rule name must not be empty".to_string(),
            });
        }
    }

    // Sort by priority ascending (lower = evaluated first)
    rules.sort_by_key(|r| r.priority);
    Ok(rules)
}
