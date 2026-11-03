//! Live-heap check for the ring (#757): a counting global allocator proves
//! that pushing many REST-shaped entries leaves the heap near the byte
//! budget, and reports the transient cost of one `snapshot()`.

#![allow(
    unsafe_code,
    reason = "a GlobalAlloc impl is unsafe by definition; it only forwards to System"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use nos_log::store::{entry_size, MAX_MEMORY_BYTES};
use nos_log::LogStore;
use nos_proto::{LogEntry, LogLevel};
use tokio::sync::mpsc;

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let now = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(now, Relaxed);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- counting GlobalAlloc delegating to System
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- counting GlobalAlloc delegating to System
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_sub(l.size(), Relaxed);
        let now = LIVE.fetch_add(new, Relaxed) + new;
        PEAK.fetch_max(now, Relaxed);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- counting GlobalAlloc delegating to System
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Shaped like `rest request` lines: one PUT per route.
fn rest_entry(i: usize) -> LogEntry {
    LogEntry {
        timestamp_ms: i as u64,
        level: LogLevel::Info,
        source: "nos-restd[rt1]".to_string(),
        target: "nos_rest::auth".to_string(),
        message: "rest request".to_string(),
        fields: vec![
            ("method".into(), "PUT".into()),
            (
                "path".into(),
                format!(
                    "/v1/transactions/tx1/static-routing-instance/s1/route/10.{}.{}.0%2F24",
                    i / 256 % 256,
                    i % 256
                ),
            ),
            ("user".into(), "\"admin\"".into()),
            ("status".into(), "200".into()),
        ],
    }
}

/// Pushes `pushes` entries; returns the store and the live bytes it holds.
async fn fill(capacity: usize, pushes: usize) -> (LogStore, usize) {
    let (tx, rx) = mpsc::unbounded_channel();
    // A dropped receiver makes the persistence send fail, so nothing queues.
    drop(rx);
    let before = LIVE.load(Relaxed);
    let store = LogStore::new(capacity, Vec::new(), tx);
    for i in 0..pushes {
        store.record(rest_entry(i)).await;
    }
    (store, LIVE.load(Relaxed) - before)
}

#[tokio::test]
async fn live_heap_stays_within_budget() {
    let per = entry_size(&rest_entry(0));
    // Byte cap binds (capacity unreachable); push 5x what fits.
    let pushes = (MAX_MEMORY_BYTES / per) * 5;
    let (store, live) = fill(usize::MAX / 2, pushes).await;
    eprintln!("entry_size={per} pushes={pushes} live={live} budget={MAX_MEMORY_BYTES}");
    // ponytail: 1.5x is the plan's bound; retune from the #756 report.
    assert!(
        live * 2 <= MAX_MEMORY_BYTES * 3,
        "live heap {live} > 1.5x budget"
    );

    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let snap = store.snapshot(None, Some(20_000)).await;
    eprintln!(
        "snapshot {} entries, transient peak +{}",
        snap.len(),
        PEAK.load(Relaxed) - base
    );
    assert_eq!(snap.len(), 20_000);
    drop((store, snap));

    // Same test fn: the counters are process-global, tests must not overlap.
    let (_store, live) = fill(10_000, 50_000).await;
    eprintln!("default capacity live={live}");
    assert!(live * 2 <= MAX_MEMORY_BYTES * 3);
}
