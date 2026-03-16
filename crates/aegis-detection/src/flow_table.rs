use crate::model::{FlowKey, FlowState};
use moka::sync::Cache;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Thread-safe, LRU+TTI flow table backed by moka.
/// Stores `Arc<Mutex<FlowState>>` so callers can mutate flow state in-place.
pub struct FlowTable {
    cache: Cache<FlowKey, Arc<Mutex<FlowState>>>,
}

impl FlowTable {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_idle(Duration::from_secs(120))
                .build(),
        }
    }

    /// Get or atomically create a FlowState for the given key.
    /// moka guarantees the initializer runs at most once per key.
    #[must_use]
    pub fn get_or_create(&self, key: FlowKey) -> Arc<Mutex<FlowState>> {
        self.cache
            .get_with(key, || Arc::new(Mutex::new(FlowState::new())))
    }

    /// Remove a flow (e.g., after it is confirmed closed).
    pub fn invalidate(&self, key: &FlowKey) {
        self.cache.invalidate(key);
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Flush moka's internal write queue so that `entry_count` reflects
    /// all inserts made so far. Useful in tests where the background
    /// maintenance thread has not yet had a chance to run.
    #[doc(hidden)]
    pub fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks();
    }
}
