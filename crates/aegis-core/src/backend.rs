use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A compiled, ordered set of rules ready to be applied to a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ruleset {
    /// nftables JSON blob, pre-serialized
    pub nftables_json: String,
    /// Human-readable version tag (e.g. git hash of rules file)
    pub version: String,
}

/// The core abstraction over the kernel firewall backend.
/// Current implementation: nftables JSON API (§4.2 of spec).
/// Future implementation: Aya/eBPF — same trait, zero changes to callers.
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Apply a complete ruleset atomically. Either all rules apply or none.
    async fn apply_ruleset(&self, ruleset: &Ruleset) -> Result<()>;

    /// Flush all rules. Fails closed — no traffic allowed after flush.
    async fn flush(&self) -> Result<()>;

    /// Return the currently active ruleset as nftables JSON, as reported by the backend.
    ///
    /// NOTE: Returns raw nftables JSON string rather than Vec<Rule> to avoid a circular
    /// dependency — Rule lives in aegis-rules which already depends on aegis-core.
    /// The daemon layer (aegis-daemon) translates JSON → Rule when needed.
    async fn list_active(&self) -> Result<String>;
}
