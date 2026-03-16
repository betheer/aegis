use crate::model::{
    DecodedPacket, DetectionContext, DetectionEvent, Detector, DetectorResult, FlowState,
};
use aegis_rules::model::{BlockReason, Protocol};
use aegis_store::model::Severity;

pub struct ProtocolAnomalyDetector;

impl Default for ProtocolAnomalyDetector {
    fn default() -> Self {
        Self
    }
}

impl Detector for ProtocolAnomalyDetector {
    fn name(&self) -> &'static str {
        "protocol_anomaly"
    }
    fn weight(&self) -> f32 {
        1.2
    }

    fn inspect(
        &self,
        packet: &DecodedPacket,
        _flow: &FlowState,
        _ctx: &DetectionContext,
    ) -> DetectorResult {
        if !matches!(packet.protocol, Protocol::Tcp) {
            return DetectorResult::pass();
        }
        let Some(flags) = &packet.tcp_flags else {
            return DetectorResult::pass();
        };

        // Check anomaly patterns in priority order.
        // Xmas scan (all flags set) must be checked before syn+rst/syn+fin,
        // because all-flags-set also satisfies those narrower conditions.
        let anomaly: Option<(&'static str, &'static str, u8)> = if flags.syn
            && flags.ack
            && flags.fin
            && flags.rst
            && flags.psh
            && flags.urg
        {
            Some(("xmas_scan", "All TCP flags set (Xmas scan)", 75))
        } else if flags.syn && flags.rst {
            Some(("syn_rst", "SYN+RST combination is invalid", 70))
        } else if flags.syn && flags.fin {
            Some(("syn_fin", "SYN+FIN combination is invalid", 70))
        } else if !flags.syn && !flags.ack && !flags.fin && !flags.rst && !flags.psh && !flags.urg {
            Some(("null_scan", "All TCP flags clear (null scan)", 60))
        } else {
            None
        };

        if let Some((code, desc, score)) = anomaly {
            let reason = BlockReason {
                code: code.to_string(),
                description: desc.to_string(),
            };
            DetectorResult {
                score,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "protocol_anomaly",
                    severity: Severity::Medium,
                    reason,
                    metadata: serde_json::Value::Null,
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
