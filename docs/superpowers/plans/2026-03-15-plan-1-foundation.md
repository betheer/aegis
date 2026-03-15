# Aegis — Plan 1: Foundation Layer

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three foundational crates — `aegis-core` (trait abstraction), `aegis-rules` (rule model + TOML + hot reload), and `aegis-store` (tiered event storage) — with full test coverage, as a Cargo workspace.

**Architecture:** Cargo workspace with three library crates sharing no state. `aegis-core` defines the `FirewallBackend` trait only (no implementation). `aegis-rules` parses TOML rules, validates them, matches packets. `aegis-store` manages a lock-free ring buffer hot tier feeding a SQLCipher-encrypted SQLite warm tier with FTS5 search and a HMAC-chained audit log.

**Tech Stack:** Rust stable, `rusqlite` + `bundled-sqlcipher`, `ringbuf`, `moka`, `dashmap`, `async-trait`, `thiserror`, `serde`/`serde_json`, `toml`, `notify` (inotify), `argon2`, `sha2`, `hmac`, `proptest`, `criterion`

**Spec:** `docs/superpowers/specs/2026-03-15-aegis-core-design.md` §3–7

**Prerequisites (Linux / WSL):**
```bash
sudo apt-get install -y libssl-dev pkg-config build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh  # if not installed
rustup component add clippy rustfmt
```

---

## Chunk 1: Workspace Scaffold + `aegis-core`

### File Map

| File | Responsibility |
|---|---|
| `Cargo.toml` | Workspace root — lists all member crates, shared profile settings |
| `crates/aegis-core/Cargo.toml` | Crate manifest |
| `crates/aegis-core/src/lib.rs` | Public re-exports |
| `crates/aegis-core/src/backend.rs` | `FirewallBackend` trait + `Ruleset` type |
| `crates/aegis-core/src/error.rs` | `CoreError` type |
| `crates/aegis-core/tests/backend_trait.rs` | Integration test: mock backend satisfies trait |

---

### Task 1: Initialize Cargo Workspace

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `.cargo/config.toml`
- Create: `.gitignore`

- [ ] **Step 1: Create workspace Cargo.toml**

```toml
# Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/aegis-core",
    "crates/aegis-rules",
    "crates/aegis-store",
]

[workspace.dependencies]
# Async
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"

# Error handling
thiserror = "2"
anyhow = "1"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Networking / IP types
ipnet = { version = "2", features = ["serde"] }

# Storage
rusqlite = { version = "0.31", features = ["bundled-sqlcipher", "modern_sqlite"] }
rusqlite_migration = "1"
ringbuf = "0.4"
dashmap = "6"
moka = { version = "0.12", features = ["sync"] }

# Crypto
argon2 = "0.5"
sha2 = "0.10"
hmac = "0.12"
hex = "0.4"
rand = "0.8"

# File watching
notify = "6"

# Utilities
uuid = { version = "1", features = ["v4", "serde"] }
tempfile = "3"

# Testing
proptest = "1"
criterion = { version = "0.5", features = ["html_reports"] }

[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = "debuginfo"

[profile.dev]
opt-level = 0
debug = true
```

- [ ] **Step 2: Create `.cargo/config.toml`**

```toml
# .cargo/config.toml
[build]
rustflags = ["-D", "warnings"]
```

- [ ] **Step 3: Create `.gitignore`**

```
/target/
# NOTE: Cargo.lock is intentionally committed for binary workspaces
# (reproducible builds, security auditing of exact dep versions)
*.db
*.db-wal
*.db-shm
*.db.zst
/etc/
/run/
/var/
```

- [ ] **Step 4: Create stub crate directories so workspace is valid**

```bash
mkdir -p crates/aegis-core/src crates/aegis-rules/src crates/aegis-store/src
```

Create minimal stub manifests so Cargo can parse the workspace:
```toml
# crates/aegis-core/Cargo.toml (temporary stub)
[package]
name = "aegis-core"
version = "0.1.0"
edition = "2021"
```
```toml
# crates/aegis-rules/Cargo.toml (temporary stub)
[package]
name = "aegis-rules"
version = "0.1.0"
edition = "2021"
```
```toml
# crates/aegis-store/Cargo.toml (temporary stub)
[package]
name = "aegis-store"
version = "0.1.0"
edition = "2021"
```

Create empty lib files:
```bash
touch crates/aegis-core/src/lib.rs crates/aegis-rules/src/lib.rs crates/aegis-store/src/lib.rs
```

- [ ] **Step 5: Verify workspace parses correctly**

```bash
cargo check --workspace
```
Expected: `Finished` — all three empty crates compile.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml .cargo/config.toml .gitignore
git commit -m "feat: initialize cargo workspace"
```

---

### Task 2: Create `aegis-core` Crate

**Files:**
- Create: `crates/aegis-core/Cargo.toml`
- Create: `crates/aegis-core/src/lib.rs`
- Create: `crates/aegis-core/src/error.rs`
- Create: `crates/aegis-core/src/backend.rs`

- [ ] **Step 1: Create crate manifest**

```toml
# crates/aegis-core/Cargo.toml
[package]
name = "aegis-core"
version = "0.1.0"
edition = "2021"

[dependencies]
async-trait = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
ipnet = { workspace = true }
tokio = { workspace = true }
```

- [ ] **Step 2: Write `error.rs`**

```rust
// crates/aegis-core/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("nftables command failed: {0}")]
    NftablesFailed(String),

    #[error("ruleset is empty")]
    EmptyRuleset,

    #[error("rule {id} is invalid: {reason}")]
    InvalidRule { id: String, reason: String },

    #[error("backend is not available: {0}")]
    BackendUnavailable(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
```

- [ ] **Step 3: Write failing test for error types**

```rust
// crates/aegis-core/tests/backend_trait.rs
#[test]
fn core_error_display() {
    let e = aegis_core::CoreError::NftablesFailed("exit 1".to_string());
    assert!(e.to_string().contains("nftables command failed"));

    let e = aegis_core::CoreError::InvalidRule {
        id: "test-rule".to_string(),
        reason: "bad port".to_string(),
    };
    assert!(e.to_string().contains("test-rule"));
    assert!(e.to_string().contains("bad port"));
}
```

- [ ] **Step 4: Run test (expect compile failure — types not exported yet)**

```bash
cargo test -p aegis-core 2>&1 | head -20
```
Expected: compile error about `aegis_core::CoreError` not found.

- [ ] **Step 5: Write `backend.rs`**

```rust
// crates/aegis-core/src/backend.rs
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::error::Result;

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
    /// NOTE: The spec (§4.1) declares `list_active_rules() -> Result<Vec<Rule>>` but
    /// `Rule` lives in `aegis-rules` which already depends on `aegis-core` — a circular
    /// dependency. The backend only knows nftables JSON (not Rust Rule structs), so
    /// returning the raw JSON string is both correct and avoids the cycle. The daemon
    /// layer (aegis-daemon) translates JSON → Rule when needed.
    async fn list_active(&self) -> Result<String>;
}
```

- [ ] **Step 6: Write `lib.rs`**

```rust
// crates/aegis-core/src/lib.rs
pub mod backend;
pub mod error;

pub use backend::{FirewallBackend, Ruleset};
pub use error::{CoreError, Result};
```

- [ ] **Step 7: Add mock backend to test file and write trait test**

```rust
// crates/aegis-core/tests/backend_trait.rs
use aegis_core::{CoreError, FirewallBackend, Ruleset};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

struct MockBackend {
    applied: Arc<Mutex<Vec<String>>>,
    flushed: Arc<Mutex<bool>>,
}

#[async_trait]
impl FirewallBackend for MockBackend {
    async fn apply_ruleset(&self, ruleset: &Ruleset) -> aegis_core::Result<()> {
        self.applied.lock().unwrap().push(ruleset.version.clone());
        Ok(())
    }

    async fn flush(&self) -> aegis_core::Result<()> {
        *self.flushed.lock().unwrap() = true;
        Ok(())
    }

    async fn list_active(&self) -> aegis_core::Result<String> {
        Ok("{}".to_string())
    }
}

#[tokio::test]
async fn mock_backend_apply_ruleset() {
    let applied = Arc::new(Mutex::new(vec![]));
    let backend = MockBackend {
        applied: Arc::clone(&applied),
        flushed: Arc::new(Mutex::new(false)),
    };

    let ruleset = Ruleset {
        nftables_json: r#"{"nftables": []}"#.to_string(),
        version: "v1.0".to_string(),
    };

    backend.apply_ruleset(&ruleset).await.unwrap();
    assert_eq!(*applied.lock().unwrap(), vec!["v1.0"]);
}

#[tokio::test]
async fn mock_backend_flush() {
    let flushed = Arc::new(Mutex::new(false));
    let backend = MockBackend {
        applied: Arc::new(Mutex::new(vec![])),
        flushed: Arc::clone(&flushed),
    };

    backend.flush().await.unwrap();
    assert!(*flushed.lock().unwrap());
}

#[test]
fn core_error_display() {
    let e = CoreError::NftablesFailed("exit 1".to_string());
    assert!(e.to_string().contains("nftables command failed"));

    let e = CoreError::InvalidRule {
        id: "test-rule".to_string(),
        reason: "bad port".to_string(),
    };
    assert!(e.to_string().contains("test-rule"));
    assert!(e.to_string().contains("bad port"));
}
```

- [ ] **Step 8: Add tokio dev dependency and run tests**

Add to `crates/aegis-core/Cargo.toml`:
```toml
[dev-dependencies]
tokio = { workspace = true }
```

```bash
cargo test -p aegis-core -- --nocapture
```
Expected: all 3 tests pass.

- [ ] **Step 9: Lint**

```bash
cargo fmt -p aegis-core
cargo clippy -p aegis-core -- -D warnings
```
Expected: no warnings.

- [ ] **Step 10: Commit**

```bash
git add crates/aegis-core/
git commit -m "feat(aegis-core): add FirewallBackend trait and CoreError types"
```

---

## Chunk 2: `aegis-rules`

### File Map

| File | Responsibility |
|---|---|
| `crates/aegis-rules/Cargo.toml` | Crate manifest |
| `crates/aegis-rules/src/lib.rs` | Public re-exports |
| `crates/aegis-rules/src/model.rs` | All rule data types: `Rule`, `Match`, `Action`, `Direction`, `Protocol`, `PortRange`, `RateLimitPolicy`, `BlockReason` |
| `crates/aegis-rules/src/parser.rs` | TOML → `Vec<Rule>` with validation |
| `crates/aegis-rules/src/engine.rs` | Priority sorting + `matches_packet()` logic |
| `crates/aegis-rules/src/compiler.rs` | `Vec<Rule>` → nftables JSON `Ruleset` |
| `crates/aegis-rules/src/watcher.rs` | inotify hot-reload via `notify` crate |
| `crates/aegis-rules/src/error.rs` | `RulesError` type |
| `crates/aegis-rules/tests/` | Integration tests for parser, engine, compiler |

---

### Task 3: Rule Model Types

**Files:**
- Create: `crates/aegis-rules/Cargo.toml`
- Create: `crates/aegis-rules/src/model.rs`
- Create: `crates/aegis-rules/src/error.rs`
- Create: `crates/aegis-rules/src/lib.rs`

- [ ] **Step 1: Create crate manifest**

```toml
# crates/aegis-rules/Cargo.toml
[package]
name = "aegis-rules"
version = "0.1.0"
edition = "2021"

[dependencies]
aegis-core = { path = "../aegis-core" }
async-trait = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
toml = { workspace = true }
ipnet = { workspace = true }
tokio = { workspace = true }
notify = { workspace = true }
uuid = { version = "1", features = ["v4", "serde"] }

[dev-dependencies]
tokio = { workspace = true }
proptest = { workspace = true }
tempfile = "3"
```

Also add `uuid = "1"` and `notify = "6"` and `tempfile = "3"` to `[workspace.dependencies]` in root `Cargo.toml`.

- [ ] **Step 2: Write failing test for model types**

```rust
// crates/aegis-rules/tests/model_test.rs
use aegis_rules::model::*;

#[test]
fn rule_priority_ordering() {
    let r1 = Rule { priority: 10, ..Rule::default_allow() };
    let r2 = Rule { priority: 5,  ..Rule::default_allow() };
    let mut rules = vec![r1, r2];
    rules.sort_by_key(|r| r.priority);
    assert_eq!(rules[0].priority, 5);
    assert_eq!(rules[1].priority, 10);
}

#[test]
fn port_range_contains() {
    let range = PortRange::Single(80);
    assert!(range.contains(80));
    assert!(!range.contains(81));

    let range = PortRange::Range { start: 8000, end: 8999 };
    assert!(range.contains(8080));
    assert!(!range.contains(9000));
}

#[test]
fn rate_limit_policy_default() {
    let policy = RateLimitPolicy::default();
    assert_eq!(policy.scope, RateLimitScope::PerSrcIp);
    assert_eq!(policy.on_exceed, ExceedAction::Drop);
}
```

- [ ] **Step 3: Run test to confirm compile failure**

```bash
cargo test -p aegis-rules 2>&1 | head -20
```
Expected: cannot find module `aegis_rules::model`.

- [ ] **Step 4: Write `error.rs`**

```rust
// crates/aegis-rules/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("failed to parse rules TOML: {0}")]
    ParseError(String),

    #[error("rule '{id}' is invalid: {reason}")]
    ValidationError { id: String, reason: String },

    #[error("rule '{id}' conflicts with rule '{other_id}': {detail}")]
    ConflictError { id: String, other_id: String, detail: String },

    #[error("rules file not found: {0}")]
    FileNotFound(String),

    #[error("watcher error: {0}")]
    WatcherError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Core(#[from] aegis_core::CoreError),
}

pub type Result<T> = std::result::Result<T, RulesError>;
```

- [ ] **Step 5: Write `model.rs`**

```rust
// crates/aegis-rules/src/model.rs
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

fn default_true() -> bool { true }

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
```

- [ ] **Step 6: Write `lib.rs`**

```rust
// crates/aegis-rules/src/lib.rs
pub mod error;
pub mod model;
pub mod parser;
pub mod engine;
pub mod compiler;
pub mod watcher;

pub use error::{Result, RulesError};
pub use model::{Action, BlockReason, Direction, Match, PacketInfo, PortRange, Protocol, RateLimitPolicy, Rule};
```

- [ ] **Step 7: Create stub files so tests compile**

```rust
// crates/aegis-rules/src/parser.rs
// stub — implemented in Task 4
```
```rust
// crates/aegis-rules/src/engine.rs
// stub — implemented in Task 5
```
```rust
// crates/aegis-rules/src/compiler.rs
// stub — implemented in Task 6
```
```rust
// crates/aegis-rules/src/watcher.rs
// stub — implemented in Task 7
```

- [ ] **Step 8: Run tests**

```bash
cargo test -p aegis-rules -- --nocapture
```
Expected: all 3 model tests pass.

- [ ] **Step 9: Lint and commit**

```bash
cargo fmt -p aegis-rules && cargo clippy -p aegis-rules -- -D warnings
git add crates/aegis-rules/
git commit -m "feat(aegis-rules): add rule model types (Rule, Match, Action, etc.)"
```

---

### Task 4: TOML Parser + Validation

**Files:**
- Modify: `crates/aegis-rules/src/parser.rs`
- Create: `crates/aegis-rules/tests/parser_test.rs`

- [ ] **Step 1: Write failing parser tests**

```rust
// crates/aegis-rules/tests/parser_test.rs
use aegis_rules::{parser::parse_rules_toml, model::*, RulesError};

const VALID_TOML: &str = r#"
[[rules]]
id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
priority = 10
name = "Allow SSH"
enabled = true
action = { type = "allow" }
log = false

  [[rules.matches]]
  type = "src_ip"
  value = "192.168.1.0/24"

  [[rules.matches]]
  type = "dst_port"
  value = 22

  [[rules.matches]]
  type = "protocol"
  value = "tcp"
"#;

#[test]
fn parse_valid_toml() {
    let rules = parse_rules_toml(VALID_TOML).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "Allow SSH");
    assert_eq!(rules[0].priority, 10);
    assert!(rules[0].enabled);
    assert_eq!(rules[0].matches.len(), 3);
}

#[test]
fn parse_invalid_toml_returns_error() {
    let result = parse_rules_toml("this is not toml ][");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), RulesError::ParseError(_)));
}

#[test]
fn parse_rule_with_out_of_range_priority_fails() {
    let toml = r#"
[[rules]]
id = "a1b2c3d4-e5f6-7890-abcd-ef1234567891"
priority = 99999
name = "Bad priority"
action = { type = "allow" }
"#;
    let result = parse_rules_toml(toml);
    assert!(matches!(result.unwrap_err(), RulesError::ValidationError { .. }));
}

#[test]
fn parse_duplicate_ids_fails() {
    let toml = r#"
[[rules]]
id = "same-id"
priority = 1
name = "Rule 1"
action = { type = "allow" }

[[rules]]
id = "same-id"
priority = 2
name = "Rule 2"
action = { type = "block" }
"#;
    let result = parse_rules_toml(toml);
    assert!(matches!(result.unwrap_err(), RulesError::ConflictError { .. }));
}

#[test]
fn parse_rate_limit_action() {
    let toml = r#"
[[rules]]
id = "rl-rule"
priority = 50
name = "Rate limit HTTP"
log = true

  [rules.action]
  type = "rate_limit"
  rate = 100
  burst = 200
  unit = "packets"
  scope = "per_src_ip"
  on_exceed = "drop"
"#;
    let rules = parse_rules_toml(toml).unwrap();
    assert_eq!(rules.len(), 1);
    assert!(matches!(rules[0].action, Action::RateLimit(_)));
}
```

- [ ] **Step 2: Run to confirm failures**

```bash
cargo test -p aegis-rules --test parser_test 2>&1 | head -30
```
Expected: compile error — `parse_rules_toml` not found.

- [ ] **Step 3: Implement `parser.rs`**

```rust
// crates/aegis-rules/src/parser.rs
use crate::{
    error::{Result, RulesError},
    model::Rule,
};
use std::collections::HashSet;

/// Parse and validate a TOML string into an ordered list of rules.
/// Returns error on invalid TOML, invalid field values, or duplicate IDs.
pub fn parse_rules_toml(toml_str: &str) -> Result<Vec<Rule>> {
    #[derive(serde::Deserialize)]
    struct RulesFile {
        #[serde(default)]
        rules: Vec<Rule>,
    }

    let file: RulesFile = toml::from_str(toml_str)
        .map_err(|e| RulesError::ParseError(e.to_string()))?;

    validate_rules(file.rules)
}

/// Parse a TOML file from disk.
pub fn parse_rules_file(path: &std::path::Path) -> Result<Vec<Rule>> {
    let content = std::fs::read_to_string(path)
        .map_err(|_| RulesError::FileNotFound(path.display().to_string()))?;
    parse_rules_toml(&content)
}

fn validate_rules(mut rules: Vec<Rule>) -> Result<Vec<Rule>> {
    let mut seen_ids = HashSet::new();

    for rule in &rules {
        // Priority range check
        if rule.priority > 65535 {
            return Err(RulesError::ValidationError {
                id: rule.id.clone(),
                reason: format!("priority {} exceeds maximum 65535", rule.priority),
            });
        }

        // Duplicate ID check
        if !seen_ids.insert(rule.id.clone()) {
            return Err(RulesError::ConflictError {
                id: rule.id.clone(),
                other_id: rule.id.clone(),
                detail: "duplicate rule ID".to_string(),
            });
        }

        // Name must not be empty
        if rule.name.trim().is_empty() {
            return Err(RulesError::ValidationError {
                id: rule.id.clone(),
                reason: "rule name must not be empty".to_string(),
            });
        }
    }

    // Sort by priority ascending (lower = evaluated first)
    rules.sort_by_key(|r| r.priority);
    Ok(rules)
}
```

- [ ] **Step 4: Run parser tests**

```bash
cargo test -p aegis-rules --test parser_test -- --nocapture
```
Expected: all 5 tests pass.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt -p aegis-rules && cargo clippy -p aegis-rules -- -D warnings
git add crates/aegis-rules/src/parser.rs crates/aegis-rules/tests/parser_test.rs
git commit -m "feat(aegis-rules): TOML parser with validation (priority, duplicate ID, name)"
```

---

### Task 5: Rule Engine (Packet Matching)

**Files:**
- Modify: `crates/aegis-rules/src/engine.rs`
- Create: `crates/aegis-rules/tests/engine_test.rs`

- [ ] **Step 1: Write failing engine tests**

```rust
// crates/aegis-rules/tests/engine_test.rs
use aegis_rules::{
    engine::RuleEngine,
    model::*,
};
use std::net::IpAddr;

fn make_packet(src: &str, dst: &str, dst_port: u16, proto: Protocol) -> PacketInfo {
    PacketInfo {
        src_ip: src.parse().unwrap(),
        dst_ip: dst.parse().unwrap(),
        src_port: Some(12345),
        dst_port: Some(dst_port),
        protocol: proto,
        direction: Direction::Inbound,
    }
}

fn ssh_allow_rule() -> Rule {
    Rule {
        id: "ssh-allow".to_string(),
        priority: 10,
        name: "Allow SSH".to_string(),
        enabled: true,
        matches: vec![
            Match::DstPort(PortRange::Single(22)),
            Match::Protocol(Protocol::Tcp),
        ],
        action: Action::Allow,
        log: false,
    }
}

fn default_block_rule() -> Rule {
    Rule {
        id: "default-block".to_string(),
        priority: 1000,
        name: "Default block".to_string(),
        enabled: true,
        matches: vec![],
        action: Action::Block,
        log: true,
    }
}

#[test]
fn matching_rule_returns_its_action() {
    let engine = RuleEngine::new(vec![ssh_allow_rule(), default_block_rule()]);
    let pkt = make_packet("10.0.0.1", "10.0.0.2", 22, Protocol::Tcp);
    let verdict = engine.evaluate(&pkt).unwrap();
    assert!(matches!(verdict.action, Action::Allow));
    assert_eq!(verdict.rule_id.as_deref(), Some("ssh-allow"));
}

#[test]
fn no_matching_rule_returns_default_block() {
    let engine = RuleEngine::new(vec![ssh_allow_rule(), default_block_rule()]);
    let pkt = make_packet("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp);
    let verdict = engine.evaluate(&pkt).unwrap();
    assert!(matches!(verdict.action, Action::Block));
    assert_eq!(verdict.rule_id.as_deref(), Some("default-block"));
}

#[test]
fn disabled_rule_is_skipped() {
    let mut rule = ssh_allow_rule();
    rule.enabled = false;
    let engine = RuleEngine::new(vec![rule, default_block_rule()]);
    let pkt = make_packet("10.0.0.1", "10.0.0.2", 22, Protocol::Tcp);
    let verdict = engine.evaluate(&pkt).unwrap();
    // disabled ssh rule skipped → hits default block
    assert!(matches!(verdict.action, Action::Block));
}

#[test]
fn src_ip_cidr_match() {
    let rule = Rule {
        id: "cidr-rule".to_string(),
        priority: 5,
        name: "Allow trusted subnet".to_string(),
        enabled: true,
        matches: vec![Match::SrcIp("192.168.1.0/24".parse().unwrap())],
        action: Action::Allow,
        log: false,
    };
    let engine = RuleEngine::new(vec![rule]);

    let pkt_in = make_packet("192.168.1.100", "10.0.0.1", 80, Protocol::Tcp);
    assert!(matches!(engine.evaluate(&pkt_in).unwrap().action, Action::Allow));

    let pkt_out = make_packet("192.168.2.1", "10.0.0.1", 80, Protocol::Tcp);
    // No match → None
    assert!(engine.evaluate(&pkt_out).is_none());
}

#[test]
fn empty_engine_returns_none() {
    let engine = RuleEngine::new(vec![]);
    let pkt = make_packet("1.2.3.4", "5.6.7.8", 80, Protocol::Tcp);
    assert!(engine.evaluate(&pkt).is_none());
}
```

- [ ] **Step 2: Run to confirm failures**

```bash
cargo test -p aegis-rules --test engine_test 2>&1 | head -20
```
Expected: `RuleEngine` not found.

- [ ] **Step 3: Implement `engine.rs`**

```rust
// crates/aegis-rules/src/engine.rs
use crate::model::*;

/// Result of evaluating a packet against the rule set.
#[derive(Debug)]
pub struct Verdict {
    pub action: Action,
    pub rule_id: Option<String>,
    pub log: bool,
}

/// Ordered, compiled rule set for O(n) packet evaluation.
/// Rules are pre-sorted by priority (ascending) at construction.
pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    /// Create from a list of rules (already sorted by `parse_rules_toml`).
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut sorted = rules;
        sorted.sort_by_key(|r| r.priority);
        Self { rules: sorted }
    }

    /// Evaluate a packet against all rules. Returns the first matching rule's verdict.
    /// Returns `None` if no rule matches (caller decides default action).
    pub fn evaluate(&self, packet: &PacketInfo) -> Option<Verdict> {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if self.rule_matches(rule, packet) {
                return Some(Verdict {
                    action: rule.action.clone(),
                    rule_id: Some(rule.id.clone()),
                    log: rule.log,
                });
            }
        }
        None
    }

    fn rule_matches(&self, rule: &Rule, packet: &PacketInfo) -> bool {
        // All match conditions must hold (AND semantics)
        rule.matches.iter().all(|m| self.condition_matches(m, packet))
    }

    fn condition_matches(&self, condition: &Match, packet: &PacketInfo) -> bool {
        match condition {
            Match::SrcIp(net) => net.contains(&packet.src_ip),
            Match::DstIp(net) => net.contains(&packet.dst_ip),
            Match::SrcPort(range) => packet.src_port.map_or(false, |p| range.contains(p)),
            Match::DstPort(range) => packet.dst_port.map_or(false, |p| range.contains(p)),
            Match::Protocol(proto) => match proto {
                Protocol::Any => true,
                _ => std::mem::discriminant(proto) == std::mem::discriminant(&packet.protocol),
            },
            Match::Direction(dir) => std::mem::discriminant(dir) == std::mem::discriminant(&packet.direction),
        }
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p aegis-rules --test engine_test -- --nocapture
```
Expected: all 5 tests pass.

- [ ] **Step 5: Add property-based test**

```rust
// Add to crates/aegis-rules/tests/engine_test.rs
use proptest::prelude::*;

proptest! {
    #[test]
    fn engine_never_panics_on_any_packet(
        src_a in 0u8..=255, src_b in 0u8..=255,
        dst_port in 0u16..=65535,
    ) {
        let engine = RuleEngine::new(vec![ssh_allow_rule(), default_block_rule()]);
        let pkt = PacketInfo {
            src_ip: format!("{}.{}.1.1", src_a, src_b).parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: Some(12345),
            dst_port: Some(dst_port),
            protocol: Protocol::Tcp,
            direction: Direction::Inbound,
        };
        // Should never panic
        let _ = engine.evaluate(&pkt);
    }
}
```

Also add to `Cargo.toml` dev-dependencies: `proptest = { workspace = true }`.

```bash
cargo test -p aegis-rules -- --nocapture
```
Expected: all tests including proptest pass.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt -p aegis-rules && cargo clippy -p aegis-rules -- -D warnings
git add crates/aegis-rules/src/engine.rs crates/aegis-rules/tests/engine_test.rs
git commit -m "feat(aegis-rules): rule engine with packet matching and proptest"
```

---

### Task 6: nftables JSON Compiler

**Files:**
- Modify: `crates/aegis-rules/src/compiler.rs`
- Create: `crates/aegis-rules/tests/compiler_test.rs`

- [ ] **Step 1: Write failing compiler tests**

```rust
// crates/aegis-rules/tests/compiler_test.rs
use aegis_rules::{compiler::compile_rules, model::*};

#[test]
fn compile_empty_rules_produces_valid_json() {
    let ruleset = compile_rules(&[], "v0.0.1");
    let parsed: serde_json::Value = serde_json::from_str(&ruleset.nftables_json).unwrap();
    assert!(parsed.get("nftables").is_some());
}

#[test]
fn compile_allow_rule_contains_accept_verdict() {
    let rule = Rule {
        id: "test".to_string(),
        priority: 10,
        name: "Allow SSH".to_string(),
        enabled: true,
        matches: vec![Match::DstPort(PortRange::Single(22))],
        action: Action::Allow,
        log: false,
    };
    let ruleset = compile_rules(&[rule], "v0.0.2");
    assert!(ruleset.nftables_json.contains("accept"));
    assert_eq!(ruleset.version, "v0.0.2");
}

#[test]
fn compile_block_rule_contains_drop_verdict() {
    let rule = Rule {
        id: "block-all".to_string(),
        priority: 1000,
        name = "Block all".to_string(),
        enabled: true,
        matches: vec![],
        action: Action::Block,
        log: false,
    };
    let ruleset = compile_rules(&[rule], "v0.0.3");
    assert!(ruleset.nftables_json.contains("drop"));
}

#[test]
fn disabled_rules_not_compiled() {
    let rule = Rule {
        id: "disabled".to_string(),
        priority: 10,
        name: "Disabled rule".to_string(),
        enabled: false,
        matches: vec![],
        action: Action::Allow,
        log: false,
    };
    let ruleset = compile_rules(&[rule], "v1");
    // Disabled rule should not appear
    let parsed: serde_json::Value = serde_json::from_str(&ruleset.nftables_json).unwrap();
    let rules = parsed["nftables"].as_array().unwrap();
    // Only the table/chain setup entries, no user rules
    for entry in rules {
        if let Some(rule_obj) = entry.get("rule") {
            let comment = rule_obj.get("comment").and_then(|c| c.as_str()).unwrap_or("");
            assert!(!comment.contains("disabled"));
        }
    }
}
```

- [ ] **Step 2: Run to confirm failures**

```bash
cargo test -p aegis-rules --test compiler_test 2>&1 | head -20
```

- [ ] **Step 3: Implement `compiler.rs`**

```rust
// crates/aegis-rules/src/compiler.rs
//! Compiles Vec<Rule> into a nftables JSON Ruleset for atomic application.
//! Output format follows nftables JSON schema (nft -j).
use aegis_core::Ruleset;
use crate::model::*;
use serde_json::{json, Value};

pub fn compile_rules(rules: &[Rule], version: &str) -> Ruleset {
    let active: Vec<&Rule> = rules.iter().filter(|r| r.enabled).collect();

    let mut statements: Vec<Value> = vec![
        // Clear + recreate the aegis table
        json!({ "flush": { "ruleset": null } }),
        json!({ "add": { "table": { "family": "inet", "name": "aegis" } } }),
        json!({ "add": { "chain": {
            "family": "inet",
            "table": "aegis",
            "name": "input",
            "type": "filter",
            "hook": "input",
            "prio": 0,
            "policy": "accept"
        }}}),
    ];

    for rule in &active {
        statements.push(compile_rule(rule));
    }

    let nftables_json = json!({ "nftables": statements }).to_string();

    Ruleset {
        nftables_json,
        version: version.to_string(),
    }
}

fn compile_rule(rule: &Rule) -> Value {
    let mut exprs: Vec<Value> = vec![];

    for m in &rule.matches {
        match m {
            Match::DstPort(PortRange::Single(port)) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "payload": { "protocol": "tcp", "field": "dport" } }, "right": port } }));
            }
            Match::DstPort(PortRange::Range { start, end }) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "payload": { "protocol": "tcp", "field": "dport" } }, "right": { "range": [start, end] } } }));
            }
            Match::SrcIp(net) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "saddr" } }, "right": { "prefix": { "addr": net.network().to_string(), "len": net.prefix_len() } } } }));
            }
            Match::DstIp(net) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "daddr" } }, "right": { "prefix": { "addr": net.network().to_string(), "len": net.prefix_len() } } } }));
            }
            Match::Protocol(Protocol::Tcp) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "tcp" } }));
            }
            Match::Protocol(Protocol::Udp) => {
                exprs.push(json!({ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "udp" } }));
            }
            _ => {} // Direction, Protocol::Any, SrcPort handled in future iterations
        }
    }

    let verdict = match &rule.action {
        Action::Allow => json!({ "accept": null }),
        Action::Block => json!({ "drop": null }),
        Action::Reject => json!({ "reject": { "type": "tcp reset" } }),
        Action::Log | Action::RateLimit(_) => json!({ "accept": null }), // simplified; full impl in phase 2
    };

    exprs.push(verdict);

    if rule.log {
        exprs.insert(exprs.len() - 1, json!({ "log": { "prefix": format!("[aegis:{}] ", rule.id) } }));
    }

    json!({
        "add": {
            "rule": {
                "family": "inet",
                "table": "aegis",
                "chain": "input",
                "comment": rule.id,
                "expr": exprs
            }
        }
    })
}
```

- [ ] **Step 4: Fix test syntax error (name = should be name:)**

In compiler_test.rs line `name = "Block all".to_string(),` → `name: "Block all".to_string(),`

- [ ] **Step 5: Run compiler tests**

```bash
cargo test -p aegis-rules --test compiler_test -- --nocapture
```
Expected: all 4 tests pass.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt -p aegis-rules && cargo clippy -p aegis-rules -- -D warnings
git add crates/aegis-rules/src/compiler.rs crates/aegis-rules/tests/compiler_test.rs
git commit -m "feat(aegis-rules): nftables JSON compiler for atomic rule application"
```

---

### Task 7: Hot Reload Watcher

**Files:**
- Modify: `crates/aegis-rules/src/watcher.rs`
- Create: `crates/aegis-rules/tests/watcher_test.rs`

- [ ] **Step 1: Write failing watcher test**

```rust
// crates/aegis-rules/tests/watcher_test.rs
use aegis_rules::watcher::RulesWatcher;
use std::time::Duration;
use tempfile::NamedTempFile;
use std::io::Write;

#[tokio::test]
async fn watcher_detects_file_change() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "# initial").unwrap();

    let (watcher, mut rx) = RulesWatcher::new(file.path()).unwrap();

    // Modify the file
    tokio::time::sleep(Duration::from_millis(100)).await;
    writeln!(file, "# changed").unwrap();
    file.flush().unwrap();

    // Should receive a reload signal within 1s
    let result = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
    assert!(result.is_ok(), "Expected reload signal within 1s");

    drop(watcher);
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
cargo test -p aegis-rules --test watcher_test 2>&1 | head -20
```

- [ ] **Step 3: Implement `watcher.rs`**

```rust
// crates/aegis-rules/src/watcher.rs
use crate::error::{Result, RulesError};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// Watches a rules file for changes and sends reload signals.
pub struct RulesWatcher {
    _watcher: RecommendedWatcher,
}

impl RulesWatcher {
    /// Start watching `path`. Returns the watcher handle (keep alive) and a receiver
    /// that yields `()` on every detected change.
    pub fn new(path: &Path) -> Result<(Self, mpsc::Receiver<()>)> {
        let (tx, rx) = mpsc::channel(1);
        let watched_path = path.to_path_buf();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    // Non-blocking send — if the receiver is busy, skip duplicate
                    let _ = tx.try_send(());
                }
            }
        }).map_err(|e| RulesError::WatcherError(e.to_string()))?;

        watcher
            .watch(&watched_path, RecursiveMode::NonRecursive)
            .map_err(|e| RulesError::WatcherError(e.to_string()))?;

        Ok((Self { _watcher: watcher }, rx))
    }
}
```

- [ ] **Step 4: Run watcher test**

```bash
cargo test -p aegis-rules --test watcher_test -- --nocapture
```
Expected: test passes.

- [ ] **Step 5: Run all aegis-rules tests**

```bash
cargo test -p aegis-rules -- --nocapture
```
Expected: all tests pass.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt -p aegis-rules && cargo clippy -p aegis-rules -- -D warnings
git add crates/aegis-rules/src/watcher.rs crates/aegis-rules/tests/watcher_test.rs
git commit -m "feat(aegis-rules): inotify hot-reload watcher via notify crate"
```

---

## Chunk 3: `aegis-store`

### File Map

| File | Responsibility |
|---|---|
| `crates/aegis-store/Cargo.toml` | Crate manifest |
| `crates/aegis-store/src/lib.rs` | Public re-exports |
| `crates/aegis-store/src/error.rs` | `StoreError` type |
| `crates/aegis-store/src/db.rs` | SQLite connection setup, PRAGMA config, key derivation |
| `crates/aegis-store/src/migrations.rs` | Schema migrations (rusqlite_migration) |
| `crates/aegis-store/src/model.rs` | `Event`, `Severity`, `EventKind`, `IpStats`, `AuditEntry` types |
| `crates/aegis-store/src/events.rs` | Event insert (with dedup), batch writer, query, FTS5 search |
| `crates/aegis-store/src/audit.rs` | Audit log append + HMAC chain verification |
| `crates/aegis-store/src/ip_stats.rs` | In-memory DashMap + periodic SQLite flush |
| `crates/aegis-store/src/ring.rs` | Lock-free ring buffer hot tier |
| `crates/aegis-store/src/retention.rs` | Vacuum, cold tier rotation |
| `crates/aegis-store/tests/` | Integration tests |

---

### Task 8: Crate Setup + Error Types + Storage Model

**Files:**
- Create: `crates/aegis-store/Cargo.toml`
- Create: `crates/aegis-store/src/error.rs`
- Create: `crates/aegis-store/src/model.rs`
- Create: `crates/aegis-store/src/lib.rs`

- [ ] **Step 1: Create crate manifest**

```toml
# crates/aegis-store/Cargo.toml
[package]
name = "aegis-store"
version = "0.1.0"
edition = "2021"

[dependencies]
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
rusqlite = { workspace = true }
rusqlite_migration = { workspace = true }
ringbuf = { workspace = true }
dashmap = { workspace = true }
argon2 = { workspace = true }
sha2 = { workspace = true }
hmac = { workspace = true }
hex = { workspace = true }
rand = { workspace = true }

[dev-dependencies]
tokio = { workspace = true }
tempfile = "3"
```

Add `rusqlite_migration = "1"` to workspace dependencies.

- [ ] **Step 2: Write failing model test**

```rust
// crates/aegis-store/tests/model_test.rs
use aegis_store::model::*;

#[test]
fn severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn event_display() {
    let e = Event {
        id: None,
        ts: 0,
        severity: Severity::High,
        kind: EventKind::Block,
        src_ip: "1.2.3.4".to_string(),
        dst_ip: "5.6.7.8".to_string(),
        src_port: Some(12345),
        dst_port: Some(80),
        protocol: Some("tcp".to_string()),
        rule_id: None,
        detector: None,
        score: Some(85),
        hit_count: 1,
        first_seen: 0,
        last_seen: 0,
        reason_code: Some("port_scan".to_string()),
        reason_desc: Some("Port scan detected".to_string()),
        raw_meta: None,
    };
    assert_eq!(e.severity, Severity::High);
    assert_eq!(e.kind, EventKind::Block);
}
```

- [ ] **Step 3: Run to confirm compile failure**

```bash
cargo test -p aegis-store 2>&1 | head -10
```

- [ ] **Step 4: Implement `error.rs`**

```rust
// crates/aegis-store/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("migration failed: {0}")]
    Migration(String),

    #[error("audit chain integrity violation at entry {entry_id}: {detail}")]
    AuditChainViolation { entry_id: i64, detail: String },

    #[error("database file is corrupt: {0}")]
    Corruption(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;
```

- [ ] **Step 5: Implement `model.rs`**

```rust
// crates/aegis-store/src/model.rs
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
}

/// A firewall event record. `id` is None before insertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Option<i64>,
    pub ts: i64,               // Unix ms
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
    pub raw_meta: Option<String>,  // JSON blob
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
    pub page_token: Option<String>,  // opaque cursor (last seen id)
}
```

- [ ] **Step 6: Write `lib.rs`**

```rust
// crates/aegis-store/src/lib.rs
pub mod audit;
pub mod db;
pub mod error;
pub mod events;
pub mod ip_stats;
pub mod migrations;
pub mod model;
pub mod retention;
pub mod ring;

pub use error::{Result, StoreError};
pub use model::{AuditEntry, Event, EventKind, EventQuery, IpStats, Severity};
```

Create stub files for remaining modules (so it compiles):
```rust
// crates/aegis-store/src/db.rs
// stub
// crates/aegis-store/src/migrations.rs
// stub
// crates/aegis-store/src/events.rs
// stub
// crates/aegis-store/src/audit.rs
// stub
// crates/aegis-store/src/ip_stats.rs
// stub
// crates/aegis-store/src/ring.rs
// stub
// crates/aegis-store/src/retention.rs
// stub
```

- [ ] **Step 7: Run model test**

```bash
cargo test -p aegis-store -- --nocapture
```
Expected: both model tests pass.

- [ ] **Step 8: Lint and commit**

```bash
cargo fmt -p aegis-store && cargo clippy -p aegis-store -- -D warnings
git add crates/aegis-store/
git commit -m "feat(aegis-store): storage model types (Event, Severity, AuditEntry, IpStats)"
```

---

### Task 9: Database Setup, Key Derivation, Migrations

**Files:**
- Modify: `crates/aegis-store/src/db.rs`
- Modify: `crates/aegis-store/src/migrations.rs`
- Create: `crates/aegis-store/tests/db_test.rs`

- [ ] **Step 1: Write failing DB test**

```rust
// crates/aegis-store/tests/db_test.rs
use aegis_store::db::{open_database, DbKey};
use tempfile::TempDir;

#[test]
fn open_encrypted_database_succeeds() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let key = DbKey::random();
    let conn = open_database(&db_path, &key).unwrap();
    // Basic smoke test: can execute a query
    let result: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
    assert_eq!(result, 1);
}

#[test]
fn wrong_key_fails_to_open() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let key1 = DbKey::random();
    let key2 = DbKey::random();

    // Create with key1
    open_database(&db_path, &key1).unwrap();

    // Open with key2 should fail (wrong key)
    let result = open_database(&db_path, &key2);
    assert!(result.is_err());
}

#[test]
fn migrations_run_on_fresh_database() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("migrated.db");
    let key = DbKey::random();
    let mut conn = open_database(&db_path, &key).unwrap();

    aegis_store::migrations::run_migrations(&mut conn).unwrap();

    // events table should exist
    let count: i64 = conn
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);

    // audit_log table should exist
    let count: i64 = conn
        .query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
```

- [ ] **Step 2: Run to confirm failures**

```bash
cargo test -p aegis-store --test db_test 2>&1 | head -20
```

- [ ] **Step 3: Implement `db.rs`**

```rust
// crates/aegis-store/src/db.rs
use crate::error::{Result, StoreError};
use argon2::{Argon2, Params, Version};
use rusqlite::Connection;
use std::path::Path;

const ARGON2_MEM_KIB: u32 = 65536;   // 64MB
const ARGON2_TIME: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const KEY_LEN: usize = 32;

/// A 32-byte database encryption key.
#[derive(Clone)]
pub struct DbKey(pub [u8; KEY_LEN]);

impl DbKey {
    /// Derive from machine secret using Argon2id.
    pub fn derive(machine_secret: &[u8], domain_salt: &str) -> Result<Self> {
        let mut key = [0u8; KEY_LEN];
        let params = Params::new(ARGON2_MEM_KIB, ARGON2_TIME, ARGON2_PARALLELISM, Some(KEY_LEN))
            .map_err(|e| StoreError::KeyDerivation(e.to_string()))?;
        Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(machine_secret, domain_salt.as_bytes(), &mut key)
            .map_err(|e| StoreError::KeyDerivation(e.to_string()))?;
        Ok(Self(key))
    }

    /// Generate a random key (for testing only).
    pub fn random() -> Self {
        use rand::RngCore;
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Open a SQLCipher-encrypted SQLite database, applying all required PRAGMAs.
pub fn open_database(path: &Path, key: &DbKey) -> Result<Connection> {
    let conn = Connection::open(path)?;

    // Apply SQLCipher key
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.hex()))?;

    // Performance + correctness PRAGMAs
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA cache_size = -65536;
        PRAGMA mmap_size = 268435456;
        PRAGMA temp_store = MEMORY;
        PRAGMA wal_autocheckpoint = 1000;
        PRAGMA foreign_keys = ON;
        PRAGMA page_size = 4096;
    ")?;

    // Verify encryption worked (will fail on wrong key)
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| StoreError::Corruption("failed to read schema — wrong key or corrupt database".to_string()))?;

    Ok(conn)
}
```

- [ ] **Step 4: Implement `migrations.rs`**

```rust
// crates/aegis-store/src/migrations.rs
use crate::error::{Result, StoreError};
use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    let migrations = Migrations::new(vec![
        M::up(include_str!("../migrations/001_initial.sql")),
    ]);
    migrations.to_latest(conn).map_err(|e| StoreError::Migration(e.to_string()))
}
```

Create migration file:
```sql
-- crates/aegis-store/migrations/001_initial.sql

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    severity    TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
    kind        TEXT NOT NULL CHECK(kind IN ('block','allow','alert','anomaly')),
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    rule_id     TEXT,
    detector    TEXT,
    score       INTEGER CHECK(score BETWEEN 0 AND 100),
    hit_count   INTEGER NOT NULL DEFAULT 1,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    reason_code TEXT,
    reason_desc TEXT,
    raw_meta    TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_kind     ON events(kind);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    reason_desc, detector, src_ip, dst_ip,
    content='events',
    content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES (new.id, new.reason_desc, new.detector, new.src_ip, new.dst_ip);
END;

CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES ('delete', old.id, old.reason_desc, old.detector, old.src_ip, old.dst_ip);
END;

CREATE TRIGGER IF NOT EXISTS events_fts_update AFTER UPDATE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES ('delete', old.id, old.reason_desc, old.detector, old.src_ip, old.dst_ip);
    INSERT INTO events_fts(rowid, reason_desc, detector, src_ip, dst_ip)
    VALUES (new.id, new.reason_desc, new.detector, new.src_ip, new.dst_ip);
END;

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_id   TEXT,
    detail      TEXT,
    prev_hash   TEXT NOT NULL,
    entry_hmac  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_stats (
    ip              TEXT PRIMARY KEY,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    total_packets   INTEGER NOT NULL DEFAULT 0,
    blocked_count   INTEGER NOT NULL DEFAULT 0,
    alert_count     INTEGER NOT NULL DEFAULT 0,
    risk_score      INTEGER NOT NULL DEFAULT 0
);
```

- [ ] **Step 5: Run DB tests**

```bash
cargo test -p aegis-store --test db_test -- --nocapture
```
Expected: all 3 tests pass.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt -p aegis-store && cargo clippy -p aegis-store -- -D warnings
git add crates/aegis-store/
git commit -m "feat(aegis-store): SQLCipher DB setup, Argon2id key derivation, migrations"
```

---

### Task 10: Event Writer + Ring Buffer + Deduplication

**Files:**
- Modify: `crates/aegis-store/src/ring.rs`
- Modify: `crates/aegis-store/src/events.rs`
- Create: `crates/aegis-store/tests/events_test.rs`

- [ ] **Step 1: Write failing events tests**

```rust
// crates/aegis-store/tests/events_test.rs
use aegis_store::{
    db::{open_database, DbKey},
    events::EventWriter,
    migrations::run_migrations,
    model::*,
};
use tempfile::TempDir;

fn test_event(src_ip: &str) -> Event {
    Event {
        id: None,
        ts: 1000,
        severity: Severity::High,
        kind: EventKind::Block,
        src_ip: src_ip.to_string(),
        dst_ip: "10.0.0.1".to_string(),
        src_port: Some(12345),
        dst_port: Some(22),
        protocol: Some("tcp".to_string()),
        rule_id: None,
        detector: Some("port_scan".to_string()),
        score: Some(80),
        hit_count: 1,
        first_seen: 1000,
        last_seen: 1000,
        reason_code: Some("port_scan".to_string()),
        reason_desc: Some("Port scan detected from 1.2.3.4".to_string()),
        raw_meta: None,
    }
}

fn setup_db(dir: &TempDir) -> rusqlite::Connection {
    let path = dir.path().join("test.db");
    let key = DbKey::random();
    let mut conn = open_database(&path, &key).unwrap();
    run_migrations(&mut conn).unwrap();
    conn
}

#[test]
fn insert_event_stores_in_db() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    let evt = test_event("1.2.3.4");
    writer.insert(&mut conn, evt).unwrap();

    let count: i64 = conn.query_row("SELECT count(*) FROM events", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn duplicate_event_increments_hit_count() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    let evt = test_event("1.2.3.4");
    writer.insert(&mut conn, evt.clone()).unwrap();
    writer.insert(&mut conn, Event { ts: 2000, last_seen: 2000, ..evt }).unwrap();

    // Should be 1 row with hit_count = 2
    let (count, hit_count): (i64, i64) = conn.query_row(
        "SELECT count(*), max(hit_count) FROM events",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    assert_eq!(count, 1);
    assert_eq!(hit_count, 2);
}

#[test]
fn fts5_search_finds_event() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    writer.insert(&mut conn, test_event("9.9.9.9")).unwrap();

    let results: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT src_ip FROM events WHERE id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?1)"
        ).unwrap();
        stmt.query_map(["port scan"], |r| r.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    };
    assert_eq!(results, vec!["9.9.9.9"]);
}

#[test]
fn query_events_by_severity() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let writer = EventWriter::new();

    writer.insert(&mut conn, test_event("1.1.1.1")).unwrap();
    writer.insert(&mut conn, Event { severity: Severity::Low, src_ip: "2.2.2.2".to_string(), ..test_event("2.2.2.2") }).unwrap();

    let query = EventQuery { severity: Some(Severity::High), limit: Some(10), ..Default::default() };
    let results = writer.query(&conn, &query).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].src_ip, "1.1.1.1");
}
```

- [ ] **Step 2: Implement `ring.rs`**

```rust
// crates/aegis-store/src/ring.rs
use crate::model::Event;
use ringbuf::{HeapRb, Prod, Cons};
use std::sync::{Arc, Mutex};

const DEFAULT_CAPACITY: usize = 50_000;

/// Lock-free ring buffer for recent events (hot tier).
/// Producer: detection pipeline. Consumer: TUI live feed + batch writer.
pub struct EventRing {
    producer: Arc<Mutex<Prod<Event, Arc<HeapRb<Event>>>>>,
    consumer: Arc<Mutex<Cons<Event, Arc<HeapRb<Event>>>>>,
}

impl EventRing {
    pub fn new() -> Self {
        let rb = Arc::new(HeapRb::<Event>::new(DEFAULT_CAPACITY));
        let (prod, cons) = rb.split();
        Self {
            producer: Arc::new(Mutex::new(prod)),
            consumer: Arc::new(Mutex::new(cons)),
        }
    }

    /// Push an event. If ring is full, oldest event is overwritten (circular).
    pub fn push(&self, event: Event) {
        let mut prod = self.producer.lock().unwrap();
        if prod.is_full() {
            // pop one to make room
            self.consumer.lock().unwrap().try_pop();
        }
        let _ = prod.try_push(event);
    }

    /// Drain up to `max` events for batch writing.
    pub fn drain(&self, max: usize) -> Vec<Event> {
        let mut cons = self.consumer.lock().unwrap();
        let mut out = Vec::with_capacity(max.min(cons.len()));
        for _ in 0..max {
            match cons.try_pop() {
                Some(e) => out.push(e),
                None => break,
            }
        }
        out
    }

    /// Peek last N events for TUI live feed (non-consuming).
    pub fn recent(&self, n: usize) -> Vec<Event> {
        let cons = self.consumer.lock().unwrap();
        cons.iter().rev().take(n).cloned().collect()
    }
}

impl Default for EventRing {
    fn default() -> Self { Self::new() }
}
```

- [ ] **Step 3: Implement `events.rs`**

```rust
// crates/aegis-store/src/events.rs
use crate::{error::Result, model::*};
use rusqlite::{params, Connection};

/// Handles event insertion, deduplication, querying, and FTS5 search.
pub struct EventWriter;

impl EventWriter {
    pub fn new() -> Self { Self }

    /// Insert an event, or increment `hit_count` if a matching recent event exists.
    /// Matching is on (src_ip, dst_ip, dst_port, reason_code) within 60 seconds.
    pub fn insert(&self, conn: &mut Connection, event: Event) -> Result<()> {
        let dedup_window_ms = 60_000i64;
        let cutoff = event.ts - dedup_window_ms;

        // Check for duplicate
        let existing_id: Option<i64> = conn.query_row(
            "SELECT id FROM events
             WHERE src_ip = ?1 AND dst_ip = ?2 AND dst_port IS ?3
               AND reason_code IS ?4 AND last_seen > ?5
             LIMIT 1",
            params![
                event.src_ip, event.dst_ip, event.dst_port,
                event.reason_code, cutoff
            ],
            |r| r.get(0),
        ).ok();

        if let Some(id) = existing_id {
            // Update existing: increment hit_count, update last_seen
            conn.execute(
                "UPDATE events SET hit_count = hit_count + 1, last_seen = ?1 WHERE id = ?2",
                params![event.ts, id],
            )?;
        } else {
            // Insert new event
            conn.execute(
                "INSERT INTO events
                 (ts, severity, kind, src_ip, dst_ip, src_port, dst_port, protocol,
                  rule_id, detector, score, hit_count, first_seen, last_seen,
                  reason_code, reason_desc, raw_meta)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    event.ts, event.severity.as_str(), event.kind.as_str(),
                    event.src_ip, event.dst_ip, event.src_port, event.dst_port,
                    event.protocol, event.rule_id, event.detector, event.score,
                    event.hit_count, event.first_seen, event.last_seen,
                    event.reason_code, event.reason_desc, event.raw_meta
                ],
            )?;
        }
        Ok(())
    }

    /// Batch insert a slice of events (in a single transaction for performance).
    pub fn insert_batch(&self, conn: &mut Connection, events: &[Event]) -> Result<()> {
        if events.is_empty() { return Ok(()); }
        let tx = conn.transaction()?;
        {
            let writer = EventWriter;
            // Each insert uses the same dedup logic within the transaction
            for event in events {
                writer.insert_in_tx(&tx, event)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn insert_in_tx(&self, conn: &Connection, event: &Event) -> Result<()> {
        let dedup_window_ms = 60_000i64;
        let cutoff = event.ts - dedup_window_ms;

        let existing_id: Option<i64> = conn.query_row(
            "SELECT id FROM events
             WHERE src_ip = ?1 AND dst_ip = ?2 AND dst_port IS ?3
               AND reason_code IS ?4 AND last_seen > ?5
             LIMIT 1",
            params![event.src_ip, event.dst_ip, event.dst_port, event.reason_code, cutoff],
            |r| r.get(0),
        ).ok();

        if let Some(id) = existing_id {
            conn.execute(
                "UPDATE events SET hit_count = hit_count + 1, last_seen = ?1 WHERE id = ?2",
                params![event.ts, id],
            )?;
        } else {
            conn.execute(
                "INSERT INTO events
                 (ts, severity, kind, src_ip, dst_ip, src_port, dst_port, protocol,
                  rule_id, detector, score, hit_count, first_seen, last_seen,
                  reason_code, reason_desc, raw_meta)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    event.ts, event.severity.as_str(), event.kind.as_str(),
                    event.src_ip, event.dst_ip, event.src_port, event.dst_port,
                    event.protocol, event.rule_id, event.detector, event.score,
                    event.hit_count, event.first_seen, event.last_seen,
                    event.reason_code, event.reason_desc, event.raw_meta
                ],
            )?;
        }
        Ok(())
    }

    /// Query events with filtering. Returns results in descending timestamp order.
    pub fn query(&self, conn: &Connection, q: &EventQuery) -> Result<Vec<Event>> {
        let mut sql = String::from(
            "SELECT id,ts,severity,kind,src_ip,dst_ip,src_port,dst_port,protocol,
                    rule_id,detector,score,hit_count,first_seen,last_seen,
                    reason_code,reason_desc,raw_meta
             FROM events WHERE 1=1"
        );
        let mut conditions: Vec<String> = vec![];

        if let Some(since) = q.since_ms { conditions.push(format!("ts >= {}", since)); }
        if let Some(until) = q.until_ms { conditions.push(format!("ts <= {}", until)); }
        if let Some(ref s) = q.severity { conditions.push(format!("severity = '{}'", s.as_str())); }

        for c in &conditions { sql.push_str(&format!(" AND {}", c)); }
        sql.push_str(" ORDER BY ts DESC");
        if let Some(limit) = q.limit { sql.push_str(&format!(" LIMIT {}", limit)); }

        let mut stmt = conn.prepare(&sql)?;
        let events = stmt.query_map([], |r| {
            Ok(Event {
                id: Some(r.get(0)?),
                ts: r.get(1)?,
                severity: Severity::from_str(&r.get::<_, String>(2)?).unwrap_or(Severity::Info),
                kind: EventKind::Block, // simplified; full mapping in production
                src_ip: r.get(4)?,
                dst_ip: r.get(5)?,
                src_port: r.get(6)?,
                dst_port: r.get(7)?,
                protocol: r.get(8)?,
                rule_id: r.get(9)?,
                detector: r.get(10)?,
                score: r.get(11)?,
                hit_count: r.get(12)?,
                first_seen: r.get(13)?,
                last_seen: r.get(14)?,
                reason_code: r.get(15)?,
                reason_desc: r.get(16)?,
                raw_meta: r.get(17)?,
            })
        })?.filter_map(|r| r.ok()).collect();

        Ok(events)
    }
}

impl Default for EventWriter {
    fn default() -> Self { Self::new() }
}
```

- [ ] **Step 4: Run events tests**

```bash
cargo test -p aegis-store --test events_test -- --nocapture
```
Expected: all 4 tests pass.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt -p aegis-store && cargo clippy -p aegis-store -- -D warnings
git add crates/aegis-store/src/ring.rs crates/aegis-store/src/events.rs crates/aegis-store/tests/events_test.rs
git commit -m "feat(aegis-store): event ring buffer, insert with dedup, batch write, FTS5 query"
```

---

### Task 11: Audit Log + HMAC Chain

**Files:**
- Modify: `crates/aegis-store/src/audit.rs`
- Create: `crates/aegis-store/tests/audit_test.rs`

- [ ] **Step 1: Write failing audit tests**

```rust
// crates/aegis-store/tests/audit_test.rs
use aegis_store::{
    audit::AuditLog,
    db::{open_database, DbKey},
    migrations::run_migrations,
    model::AuditEntry,
    StoreError,
};
use tempfile::TempDir;

fn setup_db(dir: &TempDir) -> rusqlite::Connection {
    let path = dir.path().join("audit.db");
    let key = DbKey::random();
    let mut conn = open_database(&path, &key).unwrap();
    run_migrations(&mut conn).unwrap();
    conn
}

const GENESIS_HASH: &str = "genesis-install-uuid-placeholder";
const HMAC_KEY: &[u8] = b"test-hmac-key-32-bytes-padded!!!";

#[test]
fn append_audit_entry_persists() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let log = AuditLog::new(HMAC_KEY, GENESIS_HASH);

    log.append(&mut conn, "system", "daemon.start", None, None).unwrap();

    let count: i64 = conn.query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn audit_chain_verifies_correctly() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let log = AuditLog::new(HMAC_KEY, GENESIS_HASH);

    log.append(&mut conn, "admin", "rule.create", Some("rule-1"), Some(r#"{"name":"Allow SSH"}"#)).unwrap();
    log.append(&mut conn, "admin", "rule.apply", None, None).unwrap();
    log.append(&mut conn, "system", "daemon.reload", None, None).unwrap();

    // Verification should pass
    log.verify_chain(&conn).unwrap();
}

#[test]
fn tampered_audit_chain_fails_verification() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let log = AuditLog::new(HMAC_KEY, GENESIS_HASH);

    log.append(&mut conn, "admin", "rule.create", None, None).unwrap();

    // Tamper with the entry
    conn.execute("UPDATE audit_log SET actor = 'attacker' WHERE id = 1", []).unwrap();

    // Verification should fail
    let result = log.verify_chain(&conn);
    assert!(matches!(result.unwrap_err(), StoreError::AuditChainViolation { .. }));
}
```

- [ ] **Step 2: Implement `audit.rs`**

```rust
// crates/aegis-store/src/audit.rs
use crate::{error::{Result, StoreError}, model::AuditEntry};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Manages the tamper-evident audit log.
pub struct AuditLog {
    hmac_key: Vec<u8>,
    genesis_hash: String,
}

impl AuditLog {
    pub fn new(hmac_key: &[u8], genesis_hash: &str) -> Self {
        Self {
            hmac_key: hmac_key.to_vec(),
            genesis_hash: genesis_hash.to_string(),
        }
    }

    /// Append a new audit entry. Reads the last entry's HMAC to form the chain.
    pub fn append(
        &self,
        conn: &mut Connection,
        actor: &str,
        action: &str,
        target_id: Option<&str>,
        detail: Option<&str>,
    ) -> Result<()> {
        let prev_hash = self.last_hmac(conn)?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let entry_hmac = self.compute_hmac(&prev_hash, ts, actor, action, detail.unwrap_or(""));

        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, target_id, detail, prev_hash, entry_hmac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![ts, actor, action, target_id, detail, prev_hash, entry_hmac],
        )?;
        Ok(())
    }

    /// Verify the HMAC chain from beginning to end. Returns error on first violation.
    pub fn verify_chain(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, action, detail, prev_hash, entry_hmac FROM audit_log ORDER BY id ASC"
        )?;

        let mut expected_prev_hash = self.genesis_hash.clone();

        let entries = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,    // id
                r.get::<_, i64>(1)?,    // ts
                r.get::<_, String>(2)?, // actor
                r.get::<_, String>(3)?, // action
                r.get::<_, Option<String>>(4)?, // detail
                r.get::<_, String>(5)?, // prev_hash
                r.get::<_, String>(6)?, // entry_hmac
            ))
        })?;

        for entry in entries {
            let (id, ts, actor, action, detail, prev_hash, entry_hmac) = entry?;

            // Verify prev_hash matches expected
            if prev_hash != expected_prev_hash {
                return Err(StoreError::AuditChainViolation {
                    entry_id: id,
                    detail: format!("prev_hash mismatch: expected {}, got {}", expected_prev_hash, prev_hash),
                });
            }

            // Recompute HMAC and verify
            let detail_str = detail.as_deref().unwrap_or("");
            let expected_hmac = self.compute_hmac(&prev_hash, ts, &actor, &action, detail_str);
            if entry_hmac != expected_hmac {
                return Err(StoreError::AuditChainViolation {
                    entry_id: id,
                    detail: "HMAC verification failed — entry may have been tampered".to_string(),
                });
            }

            expected_prev_hash = entry_hmac;
        }

        Ok(())
    }

    fn last_hmac(&self, conn: &Connection) -> Result<String> {
        let result: Option<String> = conn
            .query_row(
                "SELECT entry_hmac FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();
        Ok(result.unwrap_or_else(|| self.genesis_hash.clone()))
    }

    fn compute_hmac(&self, prev_hash: &str, ts: i64, actor: &str, action: &str, detail: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC can take key of any size");
        let input = format!("{}|{}|{}|{}|{}", prev_hash, ts, actor, action, detail);
        mac.update(input.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}
```

- [ ] **Step 3: Run audit tests**

```bash
cargo test -p aegis-store --test audit_test -- --nocapture
```
Expected: all 3 tests pass.

- [ ] **Step 4: Run all store tests**

```bash
cargo test -p aegis-store -- --nocapture
```
Expected: all tests pass.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt -p aegis-store && cargo clippy -p aegis-store -- -D warnings
git add crates/aegis-store/src/audit.rs crates/aegis-store/tests/audit_test.rs
git commit -m "feat(aegis-store): HMAC-SHA256 chained audit log with tamper detection"
```

---

### Task 12: ip_stats In-Memory Cache + Periodic Flush

**Files:**
- Modify: `crates/aegis-store/src/ip_stats.rs`
- Create: `crates/aegis-store/tests/ip_stats_test.rs`

- [ ] **Step 1: Write failing test**

```rust
// crates/aegis-store/tests/ip_stats_test.rs
use aegis_store::{
    db::{open_database, DbKey},
    ip_stats::IpStatsCache,
    migrations::run_migrations,
};
use std::net::IpAddr;
use tempfile::TempDir;

fn setup_db(dir: &TempDir) -> rusqlite::Connection {
    let path = dir.path().join("stats.db");
    let key = DbKey::random();
    let mut conn = open_database(&path, &key).unwrap();
    run_migrations(&mut conn).unwrap();
    conn
}

#[test]
fn record_packet_updates_in_memory_stats() {
    let cache = IpStatsCache::new();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();

    cache.record_packet(ip, false, 0);
    cache.record_packet(ip, true, 80);   // blocked

    let stats = cache.get(ip).unwrap();
    assert_eq!(stats.total_packets, 2);
    assert_eq!(stats.blocked_count, 1);
}

#[test]
fn flush_writes_to_database() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let cache = IpStatsCache::new();

    let ip: IpAddr = "5.6.7.8".parse().unwrap();
    cache.record_packet(ip, false, 0);
    cache.record_packet(ip, false, 0);

    cache.flush(&mut conn).unwrap();

    let count: i64 = conn
        .query_row("SELECT total_packets FROM ip_stats WHERE ip = '5.6.7.8'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn flush_twice_upserts_correctly() {
    let dir = TempDir::new().unwrap();
    let mut conn = setup_db(&dir);
    let cache = IpStatsCache::new();
    let ip: IpAddr = "9.9.9.9".parse().unwrap();

    cache.record_packet(ip, false, 0);
    cache.flush(&mut conn).unwrap();

    cache.record_packet(ip, true, 85);
    cache.flush(&mut conn).unwrap();

    let (total, blocked): (i64, i64) = conn.query_row(
        "SELECT total_packets, blocked_count FROM ip_stats WHERE ip = '9.9.9.9'",
        [],
        |r| Ok((r.get(0)?, r.get(1)?))
    ).unwrap();
    assert_eq!(total, 2);
    assert_eq!(blocked, 1);
}
```

- [ ] **Step 2: Implement `ip_stats.rs`**

```rust
// crates/aegis-store/src/ip_stats.rs
use crate::{error::Result, model::IpStats};
use dashmap::DashMap;
use rusqlite::{params, Connection};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Thread-safe in-memory cache of per-IP statistics.
/// Flushed to SQLite every 30 seconds by the background task.
pub struct IpStatsCache {
    map: DashMap<IpAddr, IpStats>,
}

impl IpStatsCache {
    pub fn new() -> Self {
        Self { map: DashMap::new() }
    }

    /// Record a packet from `ip`. `blocked` = true if this packet was blocked.
    /// `score` = risk score (0–100) from detection engine, 0 if no detection.
    pub fn record_packet(&self, ip: IpAddr, blocked: bool, score: u8) {
        let now = now_ms();
        let mut entry = self.map.entry(ip).or_insert_with(|| IpStats {
            first_seen: now,
            last_seen: now,
            ..Default::default()
        });
        entry.last_seen = now;
        entry.total_packets += 1;
        if blocked { entry.blocked_count += 1; }
        if score > 0 {
            entry.alert_count += 1;
            // Rolling average (simple exponential, alpha=0.1)
            entry.rolling_risk_score = ((entry.rolling_risk_score as f32 * 0.9 + score as f32 * 0.1) as u8);
        }
    }

    pub fn get(&self, ip: IpAddr) -> Option<IpStats> {
        self.map.get(&ip).map(|e| e.clone())
    }

    /// Flush all in-memory stats to SQLite via UPSERT.
    pub fn flush(&self, conn: &mut Connection) -> Result<()> {
        let tx = conn.transaction()?;
        for entry in self.map.iter() {
            let ip = entry.key().to_string();
            let stats = entry.value();
            tx.execute(
                "INSERT INTO ip_stats (ip, first_seen, last_seen, total_packets, blocked_count, alert_count, risk_score)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(ip) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   total_packets = total_packets + excluded.total_packets,
                   blocked_count = blocked_count + excluded.blocked_count,
                   alert_count = alert_count + excluded.alert_count,
                   risk_score = excluded.risk_score",
                params![ip, stats.first_seen, stats.last_seen, stats.total_packets,
                        stats.blocked_count, stats.alert_count, stats.rolling_risk_score],
            )?;
        }
        tx.commit()?;
        // Reset counters after flush (they're now persisted)
        self.map.iter_mut().for_each(|mut e| {
            e.total_packets = 0;
            e.blocked_count = 0;
            e.alert_count = 0;
        });
        Ok(())
    }
}

impl Default for IpStatsCache {
    fn default() -> Self { Self::new() }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p aegis-store --test ip_stats_test -- --nocapture
```
Expected: all 3 tests pass.

- [ ] **Step 4: Lint and commit**

```bash
cargo fmt -p aegis-store && cargo clippy -p aegis-store -- -D warnings
git add crates/aegis-store/src/ip_stats.rs crates/aegis-store/tests/ip_stats_test.rs
git commit -m "feat(aegis-store): ip_stats DashMap cache with UPSERT flush to SQLite"
```

---

### Task 13: Final Verification

- [ ] **Step 1: Run full workspace test suite**

```bash
cargo test --workspace -- --nocapture
```
Expected: all tests pass, zero failures.

- [ ] **Step 2: Run clippy across entire workspace**

```bash
cargo fmt --all && cargo clippy --workspace -- -D warnings
```
Expected: no warnings, no errors.

- [ ] **Step 3: Verify workspace builds in release**

```bash
cargo build --workspace --release
```
Expected: `Finished release` with no errors.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete Plan 1 — aegis-core, aegis-rules, aegis-store foundation layer"
```

---

## Plan 2 Preview

Plan 2 covers `aegis-detection`: the packet decoding pipeline, flow table (moka), TCP stream reassembly, all 7 detectors, Aho-Corasick DPI engine, and the sync/rayon detection harness. It depends on Plan 1's `aegis-rules` (for `BlockReason`, `PacketInfo`) and `aegis-store` (for event insertion).
