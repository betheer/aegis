use crate::model::{
    DecodedPacket, DetectionContext, DetectionEvent, Detector, DetectorResult, FlowState,
};
use aegis_rules::model::BlockReason;
use aegis_store::model::Severity;
use std::collections::HashSet;
use std::path::Path;

pub struct GeoBlockDetector {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    blocked_countries: HashSet<String>,
}

impl GeoBlockDetector {
    /// Create with optional MaxMind GeoLite2-Country DB path and list of blocked
    /// ISO 3166-1 alpha-2 country codes (e.g. "CN", "RU").
    ///
    /// If `db_path` is `None` or the file does not exist, geo lookup is silently
    /// disabled and `inspect` always returns score=0.
    pub fn new(db_path: Option<&Path>, countries: Vec<String>) -> Self {
        let reader = db_path
            .filter(|p| p.exists())
            .and_then(|p| maxminddb::Reader::open_readfile(p).ok());
        Self {
            reader,
            blocked_countries: countries.into_iter().collect(),
        }
    }
}

impl Default for GeoBlockDetector {
    fn default() -> Self {
        Self::new(None, vec![])
    }
}

impl Detector for GeoBlockDetector {
    fn name(&self) -> &'static str {
        "geo_block"
    }
    fn weight(&self) -> f32 {
        1.0
    }

    fn inspect(
        &self,
        packet: &DecodedPacket,
        _flow: &FlowState,
        _ctx: &DetectionContext,
    ) -> DetectorResult {
        let Some(ref reader) = self.reader else {
            return DetectorResult::pass();
        };

        let country_code: Option<String> = reader
            .lookup(packet.src_ip)
            .ok()
            .map(|r: maxminddb::LookupResult<Vec<u8>>| r.decode::<maxminddb::geoip2::Country>().ok()).flatten().flatten().map(|c: maxminddb::geoip2::Country| c.country)
            .and_then(|c| c.iso_code)
            .map(|s: &str| s.to_string());

        if let Some(code) = country_code {
            if self.blocked_countries.contains(&code) {
                let reason = BlockReason {
                    code: "geo_block".to_string(),
                    description: format!(
                        "Source IP {} from blocked country {}",
                        packet.src_ip, code
                    ),
                };
                return DetectorResult {
                    score: 75,
                    reason: Some(reason.clone()),
                    event: Some(DetectionEvent {
                        detector: "geo_block",
                        severity: Severity::High,
                        reason,
                        metadata: serde_json::json!({ "country": code }),
                    }),
                };
            }
        }
        DetectorResult::pass()
    }
}
