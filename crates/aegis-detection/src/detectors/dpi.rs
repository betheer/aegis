use crate::model::{
    DecodedPacket, DetectionContext, DetectionEvent, Detector, DetectorResult, FlowState,
};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use aho_corasick::AhoCorasick;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct DpiPatternFile {
    pub patterns: Vec<DpiPatternEntry>,
}

#[derive(Deserialize)]
pub struct DpiPatternEntry {
    pub label: String,
    pub pattern: String,
}

pub struct DpiDetector {
    automaton: Arc<AhoCorasick>,
    labels: Vec<String>,
}

impl DpiDetector {
    /// Build from (label, pattern) pairs. Returns error if automaton construction fails.
    pub fn from_patterns(
        patterns: Vec<(String, String)>,
    ) -> Result<Self, aho_corasick::BuildError> {
        let (labels, pats): (Vec<_>, Vec<_>) = patterns.into_iter().unzip();
        let automaton = AhoCorasick::new(&pats)?;
        Ok(Self {
            automaton: Arc::new(automaton),
            labels,
        })
    }

    /// Parse patterns from TOML string (format: `[[patterns]]\nlabel = "..."\npattern = "..."`).
    pub fn from_toml(toml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file: DpiPatternFile = toml::from_str(toml_str)?;
        let pairs: Vec<(String, String)> = file
            .patterns
            .into_iter()
            .map(|p| (p.label, p.pattern))
            .collect();
        Ok(Self::from_patterns(pairs)?)
    }

    pub fn pattern_count(&self) -> usize {
        self.labels.len()
    }
}

impl Detector for DpiDetector {
    fn name(&self) -> &'static str {
        "dpi"
    }
    fn weight(&self) -> f32 {
        1.8
    }

    fn inspect(
        &self,
        _packet: &DecodedPacket,
        flow: &FlowState,
        _ctx: &DetectionContext,
    ) -> DetectorResult {
        if flow.payload_buf.is_empty() {
            return DetectorResult::pass();
        }
        if let Some(m) = self.automaton.find(&flow.payload_buf[..]) {
            let label = &self.labels[m.pattern().as_usize()];
            let reason = BlockReason {
                code: "dpi_match".to_string(),
                description: format!("DPI pattern match: {}", label),
            };
            DetectorResult {
                score: 85,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "dpi",
                    severity: Severity::High,
                    reason,
                    metadata: serde_json::json!({ "matched_pattern": label }),
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
