use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Human-readable reason for a block action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockReason {
    /// Stable machine-readable code, e.g. "port_scan", "syn_flood".
    pub code: String,
    /// Human-readable detail for display.
    pub description: String,
}

/// Traffic direction relative to the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
    Forward,
}

/// Supported network protocols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// A port number or inclusive range.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PortRange {
    Single(u16),
    Range { start: u16, end: u16 },
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortRange::Single(p) => *p == port,
            PortRange::Range { start, end } => port >= *start && port <= *end,
        }
    }
}

/// What unit rate limiting counts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitUnit {
    #[default]
    Packets,
    Bytes,
}

/// Scope of rate limit enforcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    #[default]
    PerSrcIp,
    PerConnection,
    Global,
}

/// What happens when rate limit is exceeded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExceedAction {
    #[default]
    Drop,
    Reject,
    Log,
}

/// Token-bucket rate limit policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitPolicy {
    /// Tokens replenished per second.
    pub rate: u32,
    /// Maximum burst size.
    pub burst: u32,
    #[serde(default)]
    pub unit: RateLimitUnit,
    #[serde(default)]
    pub scope: RateLimitScope,
    #[serde(default)]
    pub on_exceed: ExceedAction,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            rate: 100,
            burst: 200,
            unit: RateLimitUnit::Packets,
            scope: RateLimitScope::PerSrcIp,
            on_exceed: ExceedAction::Drop,
        }
    }
}

/// What action to take when a rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
    /// Block and send RST (TCP) or ICMP unreachable (UDP).
    Reject,
    /// Pass but record to event store.
    Log,
    RateLimit(RateLimitPolicy),
}

/// A single matching condition. All conditions in a Rule must match (AND).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Match {
    SrcIp(IpNet),
    DstIp(IpNet),
    SrcPort(PortRange),
    DstPort(PortRange),
    Protocol(Protocol),
    Direction(Direction),
}

/// A complete firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    /// Lower priority value = evaluated first. Range 0–65535.
    pub priority: u32,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub matches: Vec<Match>,
    pub action: Action,
    #[serde(default)]
    pub log: bool,
}

fn default_true() -> bool {
    true
}

impl Rule {
    /// Create an allow-all rule for testing.
    pub fn default_allow() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            priority: 100,
            name: "default-allow".to_string(),
            enabled: true,
            matches: vec![],
            action: Action::Allow,
            log: false,
        }
    }
}

/// A decoded packet for rule matching (simplified for the rule engine).
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub direction: Direction,
}
