use crate::{
    flow_table::FlowTable,
    model::{DecodedPacket, DetectionContext, DetectionVerdict, Detector, FlowKey, VerdictAction},
};
use aegis_rules::model::Protocol;
use rayon::prelude::*;

/// Engine configuration (thresholds + flow table sizing).
pub struct EngineConfig {
    /// Score >= this → Block. Default: 70.
    pub threshold_block: u8,
    /// Score >= this → Monitor. Default: 40.
    pub threshold_monitor: u8,
    /// Maximum concurrent flows in the flow table. Default: 500_000.
    pub flow_table_capacity: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            threshold_block: 70,
            threshold_monitor: 40,
            flow_table_capacity: 500_000,
        }
    }
}

/// The detection engine. Owns the flow table and the list of detectors.
/// `process_packet` is the only public entry point.
pub struct DetectionEngine {
    detectors: Vec<Box<dyn Detector>>,
    flow_table: FlowTable,
    threshold_block: u8,
    threshold_monitor: u8,
}

impl DetectionEngine {
    pub fn new(detectors: Vec<Box<dyn Detector>>, config: EngineConfig) -> Self {
        Self {
            flow_table: FlowTable::new(config.flow_table_capacity),
            detectors,
            threshold_block: config.threshold_block,
            threshold_monitor: config.threshold_monitor,
        }
    }

    /// Process one packet: update flow state, run all detectors in parallel,
    /// aggregate scores, return verdict.
    pub fn process_packet(&self, packet: &DecodedPacket) -> DetectionVerdict {
        let flow_key = FlowKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port.unwrap_or(0),
            dst_port: packet.dst_port.unwrap_or(0),
            proto: match packet.protocol {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
                Protocol::Icmp => 1,
                Protocol::Any => 0,
            },
        };

        let flow_arc = self.flow_table.get_or_create(flow_key);

        // Update flow state and capture a snapshot for detectors.
        let flow_snapshot = {
            let mut flow = flow_arc.lock().unwrap();
            if let Some(flags) = &packet.tcp_flags {
                flow.update_tcp_flags(flags);
            }
            if !packet.payload.is_empty() {
                flow.append_payload(&packet.payload);
            }
            flow.clone()
        };

        let ctx = DetectionContext {
            threshold_block: self.threshold_block,
            threshold_monitor: self.threshold_monitor,
        };

        // Run all detectors in parallel via rayon.
        let results: Vec<_> = self
            .detectors
            .par_iter()
            .map(|d| d.inspect(packet, &flow_snapshot, &ctx))
            .collect();

        // Weighted average score aggregation.
        let (weighted_sum, weight_sum) = results
            .iter()
            .zip(self.detectors.iter())
            .fold((0.0_f32, 0.0_f32), |(ws, wt), (r, d)| {
                (ws + r.score as f32 * d.weight(), wt + d.weight())
            });

        let final_score = if weight_sum > 0.0 {
            (weighted_sum / weight_sum).min(100.0) as u8
        } else {
            0
        };

        let action = if final_score >= self.threshold_block {
            VerdictAction::Block
        } else if final_score >= self.threshold_monitor {
            VerdictAction::Monitor
        } else {
            VerdictAction::Allow
        };

        let events = results.into_iter().filter_map(|r| r.event).collect();
        DetectionVerdict {
            action,
            final_score,
            events,
        }
    }
}
