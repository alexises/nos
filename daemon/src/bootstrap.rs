//! The start of every daemon's `main()`: IPC identity and tracing.

use std::path::PathBuf;

use anyhow::Context;
use nos_log_client::ForwardingLayer;
use nos_pki::Identity;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Reads this daemon's IPC identity from stdin, where `nos-watchdogd` hands
/// it over; there is no plaintext fallback.
pub fn identity() -> anyhow::Result<Identity> {
    Identity::from_stdin().context("reading this daemon's ipc identity")
}

/// Installs the global subscriber (`EnvFilter`, default `trace`; fmt;
/// forwarding to `nos-logd`) and the panic hook. Must run inside a tokio
/// runtime. `log_shutdown` stops the forwarding loop: the caller flips it
/// last, so shutdown-time log lines are still forwarded.
pub fn init_tracing(
    name: impl Into<String>,
    log_socket: PathBuf,
    identity: Identity,
    log_shutdown: watch::Receiver<bool>,
) {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            name,
            log_socket,
            identity,
            log_shutdown,
        ))
        .init();
    nos_log_client::install_panic_hook();
}
