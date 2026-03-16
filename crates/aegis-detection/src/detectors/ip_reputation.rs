use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, Detector, DetectorResult, FlowState};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

pub struct IpReputationDetector {
    blocklist: Arc<RwLock<HashSet<IpAddr>>>,
}

impl IpReputationDetector {
    pub fn new() -> Self {
        Self { blocklist: Arc::new(RwLock::new(HashSet::new())) }
    }

    /// Atomically replace the blocklist (for hot-swap on threat intel refresh).
    pub fn swap_blocklist(&self, ips: HashSet<IpAddr>) {
        *self.blocklist.write().unwrap() = ips;
    }

    /// Load IPs from a newline-separated string. Non-parseable lines are skipped silently.
    pub fn load_from_str(&self, content: &str) {
        let ips: HashSet<IpAddr> = content
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        self.swap_blocklist(ips);
    }
}

impl Default for IpReputationDetector {
    fn default() -> Self { Self::new() }
}

impl Detector for IpReputationDetector {
    fn name(&self) -> &'static str { "ip_reputation" }
    fn weight(&self) -> f32 { 1.5 }

    fn inspect(&self, packet: &DecodedPacket, _flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        if self.blocklist.read().unwrap().contains(&packet.src_ip) {
            let reason = BlockReason {
                code: "ip_reputation".to_string(),
                description: format!("Source IP {} is on the reputation block list", packet.src_ip),
            };
            DetectorResult {
                score: 100,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "ip_reputation",
                    severity: Severity::Critical,
                    reason,
                    metadata: serde_json::json!({ "src_ip": packet.src_ip.to_string() }),
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
