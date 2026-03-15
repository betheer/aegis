use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Block,
    Allow,
    Alert,
    Anomaly,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
            Self::Alert => "alert",
            Self::Anomaly => "anomaly",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "block" => Some(Self::Block),
            "allow" => Some(Self::Allow),
            "alert" => Some(Self::Alert),
            "anomaly" => Some(Self::Anomaly),
            _ => None,
        }
    }
}

/// A firewall event record. `id` is None before insertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Option<i64>,
    pub ts: i64, // Unix ms
    pub severity: Severity,
    pub kind: EventKind,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub rule_id: Option<String>,
    pub detector: Option<String>,
    pub score: Option<u8>,
    pub hit_count: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub reason_code: Option<String>,
    pub reason_desc: Option<String>,
    pub raw_meta: Option<String>, // JSON blob
}

/// Per-IP aggregate statistics (in-memory).
#[derive(Debug, Clone, Default)]
pub struct IpStats {
    pub first_seen: i64,
    pub last_seen: i64,
    pub total_packets: u64,
    pub blocked_count: u64,
    pub alert_count: u64,
    pub rolling_risk_score: u8,
}

/// An entry in the tamper-evident audit log.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: Option<i64>,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub target_id: Option<String>,
    pub detail: Option<String>,
    pub prev_hash: String,
    pub entry_hmac: String,
}

/// Query parameters for event retrieval.
#[derive(Debug, Default)]
pub struct EventQuery {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub severity: Option<Severity>,
    pub src_ip_prefix: Option<String>,
    pub fts_query: Option<String>,
    pub limit: Option<usize>,
    pub page_token: Option<String>, // opaque cursor (last seen id)
}
