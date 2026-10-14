//! The `tracing` → `nos-logd` forwarding layer, shared by every NOS daemon.
//!
//! This is a leaf crate: it depends only on `nos-proto` (for `LogEntry`/
//! `LogRequest`), never on another component crate, so the star dependency
//! graph in the root `CLAUDE.md` still holds — no daemon gains a dependency
//! on another daemon by using it.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::SinkExt;
use nos_pki::{Identity, PeerId};
use nos_proto::{IpcCodec, LogEntry, LogLevel, LogRequest, Role};
use tokio::sync::{mpsc, watch};
use tokio_util::codec::FramedWrite;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Bounded so a burst of events can never build unbounded memory while
/// `nos-logd` is unreachable; a full channel means "drop the oldest queued
/// entry, never block the caller emitting a `tracing` event."
const CHANNEL_CAPACITY: usize = 1024;

/// Fixed reconnect delay, matching every other reconnect loop in this
/// codebase (`watchdog_client::RETRY_DELAY`, `reconcile::RECONNECT_DELAY`).
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// A `tracing_subscriber::Layer` that forwards every event to `nos-logd`,
/// installed alongside the process's existing `fmt` layer (see `main.rs`) —
/// this is purely additive, stdout logging is unaffected.
pub struct ForwardingLayer {
    source: String,
    tx: mpsc::Sender<LogEntry>,
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
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(run(log_socket, identity, rx, shutdown));
        Self {
            source: source.into(),
            tx,
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
        // Non-blocking: a full channel drops this entry rather than
        // stalling whatever code just emitted a tracing event.
        let _ = self.tx.try_send(entry);
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
/// this codebase), then forwards every entry from `rx` as `LogRequest::Push`
/// until the connection breaks, at which point it reconnects. No reply is
/// ever read — `Push` gets none (see `nos_proto::log`).
async fn run(
    log_socket: PathBuf,
    identity: Identity,
    mut rx: mpsc::Receiver<LogEntry>,
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
                entry = rx.recv() => entry,
                _ = shutdown.changed() => return,
            };
            // A dropped sender means the process is exiting.
            let Some(entry) = entry else { return };
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
        // ponytail: fixed sleep, the layer's channel is try_send so delivery
        // is best-effort; a synchronous flush API if this proves lossy.
        std::thread::sleep(Duration::from_millis(200));
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
