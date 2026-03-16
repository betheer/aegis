use aegis_detection::{
    engine::{DetectionEngine, EngineConfig},
    model::{DecodedPacket, DetectionContext, Detector, DetectorResult, FlowState, VerdictAction},
};
use aegis_rules::model::{Direction, Protocol};
use bytes::Bytes;

fn test_packet() -> DecodedPacket {
    DecodedPacket {
        src_ip: "1.2.3.4".parse().unwrap(),
        dst_ip: "5.6.7.8".parse().unwrap(),
        src_port: Some(12345),
        dst_port: Some(80),
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        tcp_flags: None,
        payload: Bytes::new(),
        packet_len: 40,
    }
}

struct AlwaysScore(u8);

impl Detector for AlwaysScore {
    fn name(&self) -> &'static str {
        "always"
    }
    fn weight(&self) -> f32 {
        1.0
    }
    fn inspect(&self, _p: &DecodedPacket, _f: &FlowState, _c: &DetectionContext) -> DetectorResult {
        DetectorResult {
            score: self.0,
            reason: None,
            event: None,
        }
    }
}

#[test]
fn high_score_detector_causes_block() {
    let engine = DetectionEngine::new(vec![Box::new(AlwaysScore(90))], EngineConfig::default());
    let verdict = engine.process_packet(&test_packet());
    assert_eq!(verdict.action, VerdictAction::Block);
    assert_eq!(verdict.final_score, 90);
}

#[test]
fn zero_score_detector_causes_allow() {
    let engine = DetectionEngine::new(vec![Box::new(AlwaysScore(0))], EngineConfig::default());
    let verdict = engine.process_packet(&test_packet());
    assert_eq!(verdict.action, VerdictAction::Allow);
}

#[test]
fn score_50_causes_monitor() {
    let engine = DetectionEngine::new(vec![Box::new(AlwaysScore(50))], EngineConfig::default());
    let verdict = engine.process_packet(&test_packet());
    assert_eq!(verdict.action, VerdictAction::Monitor);
}

#[test]
fn weighted_average_aggregation() {
    // Two detectors: weight 1 score 100, weight 1 score 0 → avg = 50 → Monitor
    struct ScoreN(u8, f32);
    impl Detector for ScoreN {
        fn name(&self) -> &'static str {
            "n"
        }
        fn weight(&self) -> f32 {
            self.1
        }
        fn inspect(
            &self,
            _p: &DecodedPacket,
            _f: &FlowState,
            _c: &DetectionContext,
        ) -> DetectorResult {
            DetectorResult {
                score: self.0,
                reason: None,
                event: None,
            }
        }
    }
    let engine = DetectionEngine::new(
        vec![Box::new(ScoreN(100, 1.0)), Box::new(ScoreN(0, 1.0))],
        EngineConfig::default(),
    );
    let verdict = engine.process_packet(&test_packet());
    assert_eq!(verdict.final_score, 50);
    assert_eq!(verdict.action, VerdictAction::Monitor);
}

#[test]
fn same_flow_accumulates_syn_count() {
    struct ReadSynCount;
    use std::sync::atomic::{AtomicU32, Ordering};
    static CAPTURED: AtomicU32 = AtomicU32::new(0);
    impl Detector for ReadSynCount {
        fn name(&self) -> &'static str {
            "syn_reader"
        }
        fn weight(&self) -> f32 {
            0.0
        }
        fn inspect(
            &self,
            _p: &DecodedPacket,
            f: &FlowState,
            _c: &DetectionContext,
        ) -> DetectorResult {
            CAPTURED.store(f.syn_count, Ordering::Relaxed);
            DetectorResult::pass()
        }
    }
    use aegis_detection::TcpFlags;
    let engine = DetectionEngine::new(vec![Box::new(ReadSynCount)], EngineConfig::default());
    let mut pkt = test_packet();
    pkt.tcp_flags = Some(TcpFlags {
        syn: true,
        ..Default::default()
    });
    engine.process_packet(&pkt);
    engine.process_packet(&pkt);
    assert_eq!(CAPTURED.load(Ordering::Relaxed), 2);
}
