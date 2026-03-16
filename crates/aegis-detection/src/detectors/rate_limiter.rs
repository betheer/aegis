use crate::model::{DecodedPacket, DetectionContext, DetectionEvent, Detector, DetectorResult, FlowState};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rate: f64,
    capacity: f64,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self { tokens: capacity, last_refill: Instant::now(), rate, capacity }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    buckets: DashMap<IpAddr, Arc<Mutex<TokenBucket>>>,
    rate: f64,
    capacity: f64,
}

impl RateLimiter {
    pub fn new(rate: f64, capacity: f64) -> Self {
        Self { buckets: DashMap::new(), rate, capacity }
    }
}

impl Default for RateLimiter {
    fn default() -> Self { Self::new(1000.0, 2000.0) }
}

impl Detector for RateLimiter {
    fn name(&self) -> &'static str { "rate_limiter" }
    fn weight(&self) -> f32 { 1.0 }

    fn inspect(&self, packet: &DecodedPacket, _flow: &FlowState, _ctx: &DetectionContext) -> DetectorResult {
        // Clone the Arc out of the DashMap immediately, releasing the shard lock
        // before acquiring the TokenBucket Mutex. This prevents holding two locks simultaneously.
        let bucket = self.buckets
            .entry(packet.src_ip)
            .or_insert_with(|| Arc::new(Mutex::new(TokenBucket::new(self.rate, self.capacity))))
            .clone();
        let allowed = bucket.lock().unwrap().try_consume();
        if !allowed {
            let reason = BlockReason {
                code: "rate_exceeded".to_string(),
                description: format!(
                    "Source IP {} exceeded rate limit of {:.0} pkt/s",
                    packet.src_ip, self.rate
                ),
            };
            DetectorResult {
                score: 60,
                reason: Some(reason.clone()),
                event: Some(DetectionEvent {
                    detector: "rate_limiter",
                    severity: Severity::Medium,
                    reason,
                    metadata: serde_json::json!({ "rate_per_sec": self.rate }),
                }),
            }
        } else {
            DetectorResult::pass()
        }
    }
}
