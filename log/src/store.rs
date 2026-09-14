use std::collections::VecDeque;
use std::sync::Arc;

use nos_proto::LogEntry;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{trace, warn};

/// Live `Tail` subscribers each get their own receiver off this channel;
/// a slow/absent subscriber never blocks `record` — `broadcast::Sender::send`
/// only fails when there are zero receivers, which is the normal, expected
/// case whenever nothing is tailing.
const TAIL_CHANNEL_CAPACITY: usize = 1024;

/// Cheap-`Clone` handle (like `nos-config`'s `ConfigStore`) over the
/// in-memory ring buffer, a broadcast channel for live `Tail` subscribers,
/// and the channel feeding the background persistence task.
#[derive(Clone)]
pub struct LogStore {
    buffer: Arc<RwLock<VecDeque<LogEntry>>>,
    capacity: usize,
    tail_tx: broadcast::Sender<LogEntry>,
    persist_tx: mpsc::UnboundedSender<LogEntry>,
}

impl LogStore {
    /// `seed` (oldest-first) pre-populates the buffer from disk at startup —
    /// see `persistence::load_recent`. `persist_tx` feeds the background
    /// persistence task; entries are never re-persisted here.
    pub fn new(
        capacity: usize,
        seed: Vec<LogEntry>,
        persist_tx: mpsc::UnboundedSender<LogEntry>,
    ) -> Self {
        let mut buffer = VecDeque::with_capacity(capacity);
        for entry in seed.into_iter().rev().take(capacity).collect::<Vec<_>>() {
            buffer.push_front(entry);
        }
        let (tail_tx, _) = broadcast::channel(TAIL_CHANNEL_CAPACITY);
        Self {
            buffer: Arc::new(RwLock::new(buffer)),
            capacity,
            tail_tx,
            persist_tx,
        }
    }

    /// Records one entry: appends to the in-memory buffer (evicting the
    /// oldest if at capacity), notifies any live `Tail` subscribers, and
    /// forwards it to the persistence task. Never blocks on disk I/O.
    pub async fn record(&self, entry: LogEntry) {
        {
            let mut buffer = self.buffer.write().await;
            if buffer.len() >= self.capacity {
                buffer.pop_front();
                trace!(
                    capacity = self.capacity,
                    "log buffer full, evicted oldest entry"
                );
            }
            buffer.push_back(entry.clone());
        }
        // No subscribers is a normal, expected state, not an error.
        let _ = self.tail_tx.send(entry.clone());
        if self.persist_tx.send(entry).is_err() {
            warn!("persistence task not running, log entry not persisted to disk");
        }
    }

    /// A filtered, capped snapshot of the buffer, oldest-first — the most
    /// recent `limit` matching entries when `limit` is given.
    pub async fn snapshot(&self, source: Option<&str>, limit: Option<usize>) -> Vec<LogEntry> {
        let buffer = self.buffer.read().await;
        let filtered: Vec<LogEntry> = buffer
            .iter()
            .filter(|e| match source {
                Some(s) => e.source == s,
                None => true,
            })
            .cloned()
            .collect();
        match limit {
            Some(limit) if filtered.len() > limit => filtered[filtered.len() - limit..].to_vec(),
            _ => filtered,
        }
    }

    /// A fresh receiver for live-tailing new entries as they're recorded.
    /// Filtering by `source` is left to the caller (see `server::dispatch`)
    /// since a broadcast channel has one shared stream for every subscriber.
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.tail_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use nos_proto::LogLevel;

    use super::*;

    fn entry(source: &str, message: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: 0,
            level: LogLevel::Info,
            source: source.to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            fields: Vec::new(),
        }
    }

    fn store(capacity: usize) -> LogStore {
        let (tx, _rx) = mpsc::unbounded_channel();
        LogStore::new(capacity, Vec::new(), tx)
    }

    #[tokio::test]
    async fn snapshot_reflects_recorded_entries_in_order() {
        let store = store(10);
        store.record(entry("a", "one")).await;
        store.record(entry("a", "two")).await;
        let snap = store.snapshot(None, None).await;
        assert_eq!(
            snap.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(),
            vec!["one", "two"]
        );
    }

    #[tokio::test]
    async fn snapshot_filters_by_source() {
        let store = store(10);
        store.record(entry("a", "one")).await;
        store.record(entry("b", "two")).await;
        let snap = store.snapshot(Some("a"), None).await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].message, "one");
    }

    #[tokio::test]
    async fn snapshot_respects_limit_keeping_most_recent() {
        let store = store(10);
        for i in 0..5 {
            store.record(entry("a", &i.to_string())).await;
        }
        let snap = store.snapshot(None, Some(2)).await;
        assert_eq!(
            snap.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(),
            vec!["3", "4"]
        );
    }

    #[tokio::test]
    async fn buffer_evicts_oldest_beyond_capacity() {
        let store = store(2);
        for i in 0..3 {
            store.record(entry("a", &i.to_string())).await;
        }
        let snap = store.snapshot(None, None).await;
        assert_eq!(
            snap.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(),
            vec!["1", "2"]
        );
    }

    #[test]
    fn seed_is_truncated_to_capacity_keeping_most_recent() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let seed = (0..5).map(|i| entry("a", &i.to_string())).collect();
        let store = LogStore::new(2, seed, tx);
        // No async runtime needed just to inspect the seeded buffer length
        // via a blocking read — spin one up for the snapshot call instead.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let snap = rt.block_on(store.snapshot(None, None));
        assert_eq!(
            snap.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(),
            vec!["3", "4"]
        );
    }
}
