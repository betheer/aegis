//! Lock-free bounded MPSC event ring buffer (hot tier).
//!
//! Uses `crossbeam_queue::ArrayQueue` — a true lock-free bounded MPSC queue.
//! `ringbuf`'s HeapRb is SPSC only; wrapping it in Mutex defeats lock-freedom.
//! The TUI live feed subscribes via the gRPC ManageSession stream (daemon layer),
//! not by reading this buffer directly — this buffer exists only to batch events
//! for SQLite writes.
use crate::model::Event;
use crossbeam_queue::ArrayQueue;
use std::sync::Arc;

const DEFAULT_CAPACITY: usize = 50_000;

/// Bounded lock-free event buffer. Push from detection threads; drain for SQLite writes.
/// Clone to share across threads — all clones share the same underlying queue.
#[derive(Clone)]
pub struct EventRing {
    queue: Arc<ArrayQueue<Event>>,
}

impl EventRing {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(ArrayQueue::new(DEFAULT_CAPACITY)),
        }
    }

    /// Push an event. If the queue is full, the oldest event is dropped to make room.
    /// Safe to call from multiple threads concurrently.
    pub fn push(&self, event: Event) {
        if self.queue.is_full() {
            // Drop oldest — ring buffer semantics
            let _ = self.queue.pop();
        }
        // If push fails (race: another thread filled it between is_full and push), drop silently.
        let _ = self.queue.push(event);
    }

    /// Drain up to `max` events for batch SQLite writing. Safe to call from one writer thread.
    pub fn drain(&self, max: usize) -> Vec<Event> {
        let mut out = Vec::with_capacity(max);
        for _ in 0..max {
            match self.queue.pop() {
                Some(e) => out.push(e),
                None => break,
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for EventRing {
    fn default() -> Self {
        Self::new()
    }
}
