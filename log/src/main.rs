use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_log::{persistence, server, LogStore};
use nos_proto::DEFAULT_LOG_SOCKET;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::info;

/// Default location for the persisted log store — under `/var/lib/nos` (the
/// `nos-data` volume) so recent history survives a `nos-logd` restart. Never
/// read by any other process; other daemons and `nos-cli` only ever see
/// entries over IPC.
const DEFAULT_LOG_STORE_PATH: &str = "/var/lib/nos/log/entries.jsonl";

#[derive(Parser)]
#[command(name = "nos-logd", about = "NOS log collection daemon")]
struct Args {
    /// Unix socket to listen on — every other component process pushes its
    /// log entries here over one long-lived connection, and `nos-cli`
    /// queries it for `show log`/`show log --follow`.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    listen_socket: PathBuf,

    /// Where the in-memory buffer is persisted, so recent history survives a
    /// restart. The file is compacted back down to `--capacity` lines once
    /// it grows past twice that.
    #[arg(long, default_value = DEFAULT_LOG_STORE_PATH)]
    log_store_path: PathBuf,

    /// Maximum number of log entries kept in memory (and, after compaction,
    /// on disk). Oldest entries are evicted first.
    #[arg(long, default_value_t = 10_000)]
    capacity: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!(
        listen_socket = %args.listen_socket.display(),
        capacity = args.capacity,
        "nos-logd starting"
    );

    let seed = persistence::load_recent(&args.log_store_path, args.capacity);
    info!(entries = seed.len(), path = %args.log_store_path.display(), "loaded persisted log store");

    let (persist_tx, persist_rx) = mpsc::unbounded_channel();
    let store = LogStore::new(args.capacity, seed, persist_tx);
    let persistence_task = tokio::spawn(persistence::run(
        args.log_store_path.clone(),
        args.capacity,
        persist_rx,
        store.persist_queue_bytes(),
    ));

    let server_task =
        server::start(&args.listen_socket, store).context("starting log IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");

    // Every live connection (including each other daemon's long-lived Push
    // connection) holds its own clone of `store`, so `persist_tx` never sees
    // its last sender drop on a clean path — abort both tasks directly
    // rather than trying to await a drain, matching `nos-ribd`/
    // `nos-interfaced`'s own `server_task.abort()` shutdown, which makes the
    // same no-perfect-drain tradeoff for their IPC servers.
    server_task.abort();
    persistence_task.abort();

    info!("shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-logd` still flushes its persistence queue
/// cleanly instead of relying on a forced kill.
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}
