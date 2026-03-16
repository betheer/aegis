use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, Detector, DetectorResult, FlowState};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct PortScanDetector {
    windows: DashMap<IpAddr, VecDeque<(Instant, u16)>>,
    window: Duration,
    threshold: usize,
}

impl PortScanDetector {
    pub fn new(window_secs: u64, threshold: usize) -> Self {
        Self {
            windows: DashMap::new(),
            window: Duration::from_secs(window_secs),
            threshold,
        }
    }
}

impl Default for PortScanDetector {
    fn default() -> Self { Self::new(60, 20) }
}

impl Detector for PortScanDetector {
    fn name(&self) -> &'static str { "port_scan" }
    fn weight(&self) -> f32 { 1.5 }

    fn inspect(&self, packet: &DecodedPacket, _flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        let Some(dst_port) = packet.dst_port else {
            return DetectorResult::pass();
        };
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut entry = self.windows.entry(packet.src_ip).or_default();
        while entry.front().map_or(false, |(t, _)| *t < cutoff) {
            entry.pop_front();
        }
        entry.push_back((now, dst_port));

        let distinct: HashSet<u16> = entry.iter().map(|(_, p)| *p).collect();
        if distinct.len() > self.threshold {
            let reason = BlockReason {
                code: "port_scan".to_string(),
                description: format!(
                    "{} distinct ports contacted within {}s",
                    distinct.len(),
                    self.window.as_secs()
                ),
            };
            return DetectorResult {
                score: 80,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "port_scan",
                    severity: Severity::High,
                    reason,
                    metadata: serde_json::json!({ "distinct_ports": distinct.len() }),
                }),
            };
        }
        DetectorResult::pass()
    }
}
