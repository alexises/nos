//! A router's logs, collected over its REST API.
//!
//! A background task holds `GET /v1/logs/follow` (Server-Sent Events) open and
//! appends every entry to a growing list, so assertions never depend on the
//! `nos-logd` ring buffer not wrapping. On a dropped stream it reconnects and
//! re-reads the buffered backlog, de-duplicating by entry.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use nos_proto::LogEntry;
use regex::Regex;
use tokio::task::JoinHandle;

use crate::rest::Rest;

#[derive(Default)]
struct Store {
    lines: Vec<String>,
    seen: HashSet<(u64, String)>,
}

pub struct Logs {
    store: Arc<Mutex<Store>>,
    task: JoinHandle<()>,
}

impl Drop for Logs {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One entry as `LEVEL target: message k=v k=v` — the shape `tracing`'s own fmt
/// layer prints (minus the timestamp and colors), so patterns written against
/// container stdout keep working.
pub fn render(e: &LogEntry) -> String {
    let mut s = format!("{:?} {}: {}", e.level, e.target, e.message);
    for (k, v) in &e.fields {
        let _ = write!(s, " {k}={v}");
    }
    s
}

/// Translates a POSIX basic regex (what the old script's `grep` patterns were)
/// into a `regex` crate pattern: `\|` is alternation, and `( ) + ? { } |` are
/// literals in BRE but operators here.
pub fn bre(pattern: &str) -> Regex {
    let mut out = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('|') => out.push('|'),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push_str("\\\\"),
            },
            '(' | ')' | '+' | '?' | '{' | '}' | '|' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    Regex::new(&out).unwrap_or_else(|e| panic!("bad log pattern {pattern:?}: {e}"))
}

impl Logs {
    /// Starts following a router's logs over its REST API.
    pub fn follow(rest: Rest) -> Self {
        let store = Arc::new(Mutex::new(Store::default()));
        let task = tokio::spawn(follow_forever(rest, store.clone()));
        Self { store, task }
    }

    /// Waits until the backlog has been read (the line count stops growing),
    /// so baselines taken right after attaching aren't racing the first fetch.
    pub async fn settle(&self) {
        let mut last = usize::MAX;
        for _ in 0..150 {
            let now = self.store.lock().unwrap().lines.len();
            if now > 0 && now == last {
                return;
            }
            last = now;
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }

    /// Number of collected lines matching the BRE `pattern`.
    pub fn count(&self, pattern: &str) -> usize {
        let re = bre(pattern);
        self.store
            .lock()
            .unwrap()
            .lines
            .iter()
            .filter(|l| re.is_match(l))
            .count()
    }

    /// The most recent line matching `pattern`.
    pub fn last(&self, pattern: &str) -> Option<String> {
        let re = bre(pattern);
        self.store
            .lock()
            .unwrap()
            .lines
            .iter()
            .rev()
            .find(|l| re.is_match(l))
            .cloned()
    }

    /// Waits until more than `baseline` lines match; `false` on timeout.
    pub async fn wait_over(&self, pattern: &str, baseline: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.count(pattern) > baseline {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

async fn follow_forever(rest: Rest, store: Arc<Mutex<Store>>) {
    // `limit` trims the backlog to the most recent N; ask for "everything".
    let url = format!("{}/v1/logs/follow?limit=100000000", rest.base());
    loop {
        // Not yet up (or being restarted) is just "try again": `client` logs in
        // for a certificate each time it needs one.
        if let Ok(client) = rest.client().await {
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().is_success() {
                    read_stream(resp, &store).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn read_stream(resp: reqwest::Response, store: &Mutex<Store>) {
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    while let Some(Ok(chunk)) = stream.next().await {
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = buf.find("\n\n") {
            let event: String = buf.drain(..end + 2).collect();
            if let Some(entry) = parse_event(&event) {
                push(store, &entry);
            }
        }
    }
}

fn push(store: &Mutex<Store>, entry: &LogEntry) {
    let line = render(entry);
    let mut s = store.lock().unwrap();
    if s.seen.insert((entry.timestamp_ms, line.clone())) {
        s.lines.push(line);
    }
}

/// The `LogEntry` of one SSE event block, if it is an `event: log`.
fn parse_event(block: &str) -> Option<LogEntry> {
    let mut is_log = false;
    let mut data = String::new();
    for line in block.lines() {
        if let Some(v) = line.strip_prefix("event:") {
            is_log = v.trim() == "log";
        } else if let Some(v) = line.strip_prefix("data:") {
            data.push_str(v.strip_prefix(' ').unwrap_or(v));
        }
    }
    if is_log {
        serde_json::from_str(&data).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bre_translates_grep_patterns() {
        assert!(bre("source=Some(Ospf)").is_match("added route source=Some(Ospf)"));
        assert!(bre("a\\|b").is_match("xb"));
        assert!(bre("addresses=\\[10.0.0.1\\]").is_match("addresses=[10.0.0.1]"));
        assert!(bre("lsa installed.*neighbor=1.1.1.1").is_match("lsa installed x neighbor=1.1.1.1"));
    }

    #[test]
    fn parses_a_log_event_and_ignores_others() {
        let block = "event: log\ndata: {\"timestamp_ms\":1,\"level\":\"Info\",\"source\":\"s\",\"target\":\"t\",\"message\":\"m\",\"fields\":[[\"k\",\"v\"]]}\n\n";
        let e = parse_event(block).unwrap();
        assert_eq!(render(&e), "Info t: m k=v");
        assert!(parse_event("event: error\ndata: boom\n\n").is_none());
    }
}
