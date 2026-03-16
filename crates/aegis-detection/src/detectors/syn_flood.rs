use crate::model::{
    DecodedPacket, DetectionContext, DetectionEvent, Detector, DetectorResult, FlowState,
};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;

pub struct SynFloodDetector {
    pub syn_ratio_threshold: f32,
    pub min_syn_count: u32,
}

impl Default for SynFloodDetector {
    fn default() -> Self {
        Self {
            syn_ratio_threshold: 3.0,
            min_syn_count: 10,
        }
    }
}

impl Detector for SynFloodDetector {
    fn name(&self) -> &'static str {
        "syn_flood"
    }
    fn weight(&self) -> f32 {
        2.0
    }

    fn inspect(
        &self,
        _packet: &DecodedPacket,
        flow: &FlowState,
        _ctx: &DetectionContext,
    ) -> DetectorResult {
        if flow.syn_count < self.min_syn_count {
            return DetectorResult::pass();
        }
        let ratio = flow.syn_count as f32 / (flow.ack_count + 1) as f32;
        if ratio >= self.syn_ratio_threshold {
            let reason = BlockReason {
                code: "syn_flood".to_string(),
                description: format!(
                    "SYN/ACK ratio {:.1} ({}:{}) exceeds threshold {:.1}",
                    ratio, flow.syn_count, flow.ack_count, self.syn_ratio_threshold
                ),
            };
            DetectorResult {
                score: 90,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "syn_flood",
                    severity: Severity::Critical,
                    reason,
                    metadata: serde_json::json!({
                        "syn_count": flow.syn_count,
                        "ack_count": flow.ack_count,
                        "ratio": ratio
                    }),
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
