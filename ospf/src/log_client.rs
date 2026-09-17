use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::SinkExt;
use nos_proto::{IpcCodec, LogEntry, LogLevel, LogRequest};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};
use tokio_util::codec::FramedWrite;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Own forwarder to `nos-logd` — reimplemented rather than shared, per the
/// root `CLAUDE.md`'s star dependency graph (every component depends only on
/// `nos-proto`, never on another component crate).
///
/// Bounded so a burst of events can never build unbounded memory while
/// `nos-logd` is unreachable; a full channel means "drop the oldest queued
/// entry, never block the caller emitting a `tracing` event."
const CHANNEL_CAPACITY: usize = 1024;

/// Fixed reconnect delay, matching every other reconnect loop in this crate
/// (`watchdog_client::RETRY_DELAY`, `reconcile::RECONNECT_DELAY`).
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
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(run(log_socket, rx, shutdown));
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
    mut rx: mpsc::Receiver<LogEntry>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        match UnixStream::connect(&log_socket).await {
            Ok(stream) => {
                let mut writer = FramedWrite::new(stream, IpcCodec::<LogRequest>::default());
                loop {
                    tokio::select! {
                        entry = rx.recv() => match entry {
                            Some(entry) => {
                                if writer.send(LogRequest::Push(entry)).await.is_err() {
                                    break;
                                }
                            }
                            None => return, // sender dropped: process is exiting
                        },
                        _ = shutdown.changed() => return,
                    }
                }
            }
            Err(_) => {
                if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                    return;
                }
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
