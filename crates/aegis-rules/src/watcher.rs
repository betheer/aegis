use crate::error::{Result, RulesError};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
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
        })
        .map_err(|e| RulesError::WatcherError(e.to_string()))?;

        watcher
            .watch(&watched_path, RecursiveMode::NonRecursive)
            .map_err(|e| RulesError::WatcherError(e.to_string()))?;

        Ok((Self { _watcher: watcher }, rx))
    }
}
