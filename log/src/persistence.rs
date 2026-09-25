use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use nos_proto::LogEntry;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::store::entry_size;

/// Once the store file grows past `capacity * COMPACT_FACTOR` lines, it's
/// rewritten down to the most recent `capacity` — bounds disk usage without
/// paying a full rewrite on every single append.
const COMPACT_FACTOR: usize = 2;

/// Loads up to `capacity` most-recent entries from `path`, oldest-first, for
/// seeding `LogStore` at startup. A missing file is not an error — the first
/// run has nothing to load yet, exactly like `nos-config`'s
/// `persistence::load_or_default`. A line that fails to parse (e.g. written
/// by a future, incompatible version) is skipped rather than failing the
/// whole load.
pub fn load_recent(path: &Path, capacity: usize) -> Vec<LogEntry> {
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    let mut lines: VecDeque<String> = VecDeque::with_capacity(capacity);
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if lines.len() >= capacity {
            lines.pop_front();
        }
        lines.push_back(line);
    }
    lines
        .into_iter()
        .filter_map(|line| match serde_json::from_str(&line) {
            Ok(entry) => Some(entry),
            Err(e) => {
                warn!(error = %e, "skipping malformed log store line");
                None
            }
        })
        .collect()
}

/// Runs until `rx` closes (its sender drops on shutdown): appends every
/// received entry as one JSON line to `path`, compacting back down to
/// `capacity` lines once the file grows past `capacity * COMPACT_FACTOR`.
///
/// A failure to open or write the file disables persistence for the rest of
/// this run (a warning is logged once) rather than crashing `nos-logd` —
/// the in-memory buffer keeps serving queries either way.
///
/// `queued` is `LogStore::persist_queue_bytes`: each received entry's bytes are
/// released from it, which is what lets the store bound the queue's memory.
pub async fn run(
    path: PathBuf,
    capacity: usize,
    mut rx: mpsc::UnboundedReceiver<LogEntry>,
    queued: Arc<AtomicUsize>,
) {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Err(e) = fs::create_dir_all(parent) {
            warn!(error = %e, path = %parent.display(), "failed to create log store directory");
        }
    }

    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .inspect_err(|e| {
            warn!(error = %e, path = %path.display(), "failed to open log store file, persistence disabled");
        })
    else {
        // Drain the channel so senders (LogStore::record) never block on a
        // full mpsc queue even though nothing is being persisted.
        while let Some(entry) = rx.recv().await {
            queued.fetch_sub(entry_size(&entry), Ordering::Relaxed);
        }
        return;
    };
    info!(path = %path.display(), "log persistence started");
    let mut lines_since_compact = count_lines(&path).unwrap_or(0);

    while let Some(entry) = rx.recv().await {
        queued.fetch_sub(entry_size(&entry), Ordering::Relaxed);
        match serde_json::to_string(&entry) {
            Ok(line) => match writeln!(file, "{line}") {
                Ok(()) => lines_since_compact += 1,
                Err(e) => warn!(error = %e, "failed to append to log store file"),
            },
            Err(e) => warn!(error = %e, "failed to serialize log entry for persistence"),
        }

        if lines_since_compact > capacity.saturating_mul(COMPACT_FACTOR) {
            match compact(&path, capacity) {
                Ok(new_file) => {
                    file = new_file;
                    lines_since_compact = capacity;
                    debug!(path = %path.display(), capacity, "compacted log store file");
                }
                Err(e) => warn!(error = %e, "failed to compact log store file"),
            }
        }
    }
}

fn count_lines(path: &Path) -> std::io::Result<usize> {
    let file = File::open(path)?;
    Ok(BufReader::new(file).lines().count())
}

/// Rewrites `path` keeping only its last `capacity` lines (via a temp file
/// in the same directory, renamed over `path` — the same atomic-write
/// pattern as `nos-config`'s `persistence::save_to_disk`), then reopens it
/// for appending.
fn compact(path: &Path, capacity: usize) -> std::io::Result<File> {
    let kept = load_recent(path, capacity);
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dir {
        Some(dir) => tempfile::NamedTempFile::new_in(dir),
        None => tempfile::NamedTempFile::new(),
    }?;
    for entry in &kept {
        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        writeln!(tmp, "{line}")?;
    }
    tmp.persist(path)
        .map_err(|e| std::io::Error::other(e.error))?;
    OpenOptions::new().append(true).open(path)
}

#[cfg(test)]
mod tests {
    use nos_proto::LogLevel;

    use super::*;

    fn entry(message: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: 0,
            level: LogLevel::Info,
            source: "test".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn load_recent_returns_empty_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.jsonl");
        assert_eq!(load_recent(&path, 10), Vec::new());
    }

    #[tokio::test]
    async fn run_persists_entries_and_load_recent_reads_them_back() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/entries.jsonl");
        let (tx, rx) = mpsc::unbounded_channel();

        tx.send(entry("one")).unwrap();
        tx.send(entry("two")).unwrap();
        drop(tx);
        run(path.clone(), 10, rx, Arc::default()).await;

        let loaded = load_recent(&path, 10);
        assert_eq!(
            loaded
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>(),
            vec!["one", "two"]
        );
    }

    #[tokio::test]
    async fn run_compacts_once_past_the_threshold() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("entries.jsonl");
        let (tx, rx) = mpsc::unbounded_channel();

        // capacity=1, factor=2 -> compacts once more than 2 lines exist.
        for i in 0..5 {
            tx.send(entry(&i.to_string())).unwrap();
        }
        drop(tx);
        run(path.clone(), 1, rx, Arc::default()).await;

        let loaded = load_recent(&path, 10);
        assert_eq!(
            loaded
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>(),
            vec!["4"]
        );
    }
}
