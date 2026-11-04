//! The `tracing` → `nos-logd` forwarding layer, shared by every NOS daemon.
//!
//! This is a leaf crate: it depends only on `nos-proto` (for `LogEntry`/
//! `LogRequest`), never on another component crate, so the star dependency
//! graph in the root `CLAUDE.md` still holds — no daemon gains a dependency
//! on another daemon by using it.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::SinkExt;
use nos_pki::{Identity, PeerId};
use nos_proto::{IpcCodec, LogEntry, LogLevel, LogRequest, Role};
use tokio::sync::{watch, Notify};
use tokio_util::codec::FramedWrite;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Bounded so a burst of events can never build unbounded memory while
/// `nos-logd` is unreachable; a full queue means "drop the oldest queued
/// entry, never block the caller emitting a `tracing` event."
const CHANNEL_CAPACITY: usize = 1024;

/// Bounded drop-oldest queue shared by the layer and the forwarding task.
#[derive(Default)]
struct Queue {
    entries: Mutex<VecDeque<LogEntry>>,
    notify: Notify,
}

impl Queue {
    /// Never blocks (the lock is held only for the push/pop); evicts the
    /// oldest entry when full so the newest (e.g. a panic line) survives.
    fn push(&self, entry: LogEntry) {
        let mut q = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if q.len() >= CHANNEL_CAPACITY {
            q.pop_front();
        }
        q.push_back(entry);
        drop(q);
        self.notify.notify_one();
    }

    fn pop(&self) -> Option<LogEntry> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
    }

    fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    async fn recv(&self) -> LogEntry {
        loop {
            if let Some(e) = self.pop() {
                return e;
            }
            self.notify.notified().await;
        }
    }
}

/// The installed layer's queue, so the panic hook can wait for it to drain.
static QUEUE: OnceLock<Arc<Queue>> = OnceLock::new();

/// Fixed reconnect delay, matching every other reconnect loop in this
/// codebase (`watchdog_client::RETRY_DELAY`, `reconcile::RECONNECT_DELAY`).
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// A `tracing_subscriber::Layer` that forwards every event to `nos-logd`,
/// installed alongside the process's existing `fmt` layer (see `main.rs`) —
/// this is purely additive, stdout logging is unaffected.
pub struct ForwardingLayer {
    source: String,
    queue: Arc<Queue>,
}

impl ForwardingLayer {
    /// Spawns the background task that owns the connection to `log_socket`
    /// and returns the `Layer` to add to this process's subscriber registry.
    /// `shutdown` stops the background task's connect/reconnect loop.
    pub fn install(
        source: impl Into<String>,
        log_socket: PathBuf,
        identity: Identity,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let queue = Arc::new(Queue::default());
        let _ = QUEUE.set(queue.clone());
        tokio::spawn(run(log_socket, identity, queue.clone(), shutdown));
        Self {
            source: source.into(),
            queue,
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for ForwardingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let entry = LogEntry {
            timestamp_ms: now_ms(),
            level: to_level(*event.metadata().level()),
            source: self.source.clone(),
            target: event.metadata().target().to_string(),
            message: visitor.message.unwrap_or_default(),
            fields: visitor.fields,
        };
        // Non-blocking: a full queue drops the oldest entry rather than
        // stalling whatever code just emitted a tracing event.
        self.queue.push(entry);
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let text = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(text);
        } else {
            self.fields.push((field.name().to_string(), text));
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn to_level(level: tracing::Level) -> LogLevel {
    match level {
        tracing::Level::TRACE => LogLevel::Trace,
        tracing::Level::DEBUG => LogLevel::Debug,
        tracing::Level::INFO => LogLevel::Info,
        tracing::Level::WARN => LogLevel::Warn,
        tracing::Level::ERROR => LogLevel::Error,
    }
}

/// Owns the connection to `nos-logd` for this process's whole lifetime:
/// connects (retrying on a fixed delay, like every other reconnect loop in
/// this codebase), then forwards every entry from `queue` as `LogRequest::Push`
/// until the connection breaks, at which point it reconnects. No reply is
/// ever read — `Push` gets none (see `nos_proto::log`).
async fn run(
    log_socket: PathBuf,
    identity: Identity,
    queue: Arc<Queue>,
    mut shutdown: watch::Receiver<bool>,
) {
    let logd = PeerId::new(Role::Logd.as_str(), "");
    while !*shutdown.borrow() {
        let Ok(stream) = identity.connect(&log_socket, &logd).await else {
            if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                return;
            }
            continue;
        };
        let mut writer = FramedWrite::new(stream, IpcCodec::<LogRequest>::default());
        loop {
            let entry = tokio::select! {
                entry = queue.recv() => entry,
                _ = shutdown.changed() => return,
            };
            if writer.send(LogRequest::Push(entry)).await.is_err() {
                break;
            }
        }
    }
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

/// Message for a panic: `file:line`, thread and payload text.
fn panic_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let text = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload");
    let at = info.location().map_or_else(
        || "unknown location".to_string(),
        |l| format!("{}:{}", l.file(), l.line()),
    );
    let thread = std::thread::current();
    format!(
        "panic at {at}: {text} (thread {})",
        thread.name().unwrap_or("<unnamed>")
    )
}

/// Replaces the default panic hook: log the panic through `tracing` (stderr
/// and `nos-logd`), give the forwarding task a bounded moment to push it,
/// then abort so the watchdog restarts the daemon. A panic in a spawned task
/// would otherwise only kill that task and leave the daemon half alive (#419).
/// Aborts in every profile; call it from daemon `main`s only, after the
/// subscriber is initialised.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        tracing::error!("{}", panic_message(info));
        // ponytail: wait (<=200 ms) for the queue to empty; empty does not
        // mean the bytes are on the wire, and on a current_thread runtime
        // this sleep blocks the forwarder itself. A synchronous flush API
        // if this proves lossy.
        if let Some(q) = QUEUE.get() {
            for _ in 0..40 {
                if q.is_empty() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        std::process::abort();
    }));
}

/// Spawns a task that must live as long as the process (an rtnetlink
/// connection). If it ever completes the daemon is useless: log and exit so
/// the watchdog restarts it. Shutdown drops the runtime, so it never trips.
pub fn spawn_critical<F>(name: &'static str, task: F)
where
    F: std::future::Future + Send + 'static,
{
    tokio::spawn(async move {
        task.await;
        tracing::error!(task = name, "long-lived task ended unexpectedly, exiting");
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::process::exit(1);
    });
}

#[cfg(test)]
mod panic_tests {
    #[test]
    fn message_formats_str_and_string_payloads() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |i| {
            s.lock().unwrap().push(super::panic_message(i));
        }));
        let _ = std::panic::catch_unwind(|| panic!("static"));
        let _ = std::panic::catch_unwind(|| panic!("owned {}", 1));
        std::panic::set_hook(prev);
        let seen = seen.lock().unwrap();
        assert!(seen[0].contains("panic at ") && seen[0].contains(": static"));
        assert!(seen[1].contains(": owned 1"));
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    fn entry(msg: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: 0,
            level: LogLevel::Info,
            source: "t".into(),
            target: "t".into(),
            message: msg.into(),
            fields: vec![],
        }
    }

    fn drain_last(q: &Queue) -> Option<LogEntry> {
        let mut last = None;
        while let Some(e) = q.pop() {
            last = Some(e);
        }
        last
    }

    #[test]
    fn overflow_evicts_oldest_and_keeps_newest() {
        let q = Queue::default();
        for i in 0..=CHANNEL_CAPACITY {
            q.push(entry(&i.to_string()));
        }
        assert_eq!(q.pop().unwrap().message, "1");
        assert_eq!(
            drain_last(&q).unwrap().message,
            CHANNEL_CAPACITY.to_string()
        );
        assert!(q.is_empty());
    }

    #[test]
    fn panic_line_survives_a_full_queue() {
        let q = Queue::default();
        for _ in 0..CHANNEL_CAPACITY {
            q.push(entry("noise"));
        }
        q.push(entry("panic at x"));
        assert_eq!(drain_last(&q).unwrap().message, "panic at x");
    }

    #[tokio::test]
    async fn recv_wakes_on_push() {
        let q = Arc::new(Queue::default());
        let q2 = q.clone();
        let h = tokio::spawn(async move { q2.recv().await.message });
        tokio::task::yield_now().await;
        q.push(entry("hi"));
        assert_eq!(h.await.unwrap(), "hi");
    }
}
