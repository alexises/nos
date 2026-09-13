use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_rib::reconcile;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;

#[derive(Parser)]
#[command(name = "nos-ribd", about = "NOS RIB (routing information base) daemon")]
struct Args {
    /// Name of the routing table (from the running config's
    /// `routing_tables`) this process computes best routes for.
    #[arg(long)]
    table: String,

    /// Path to nos-configd's IPC Unix socket.
    #[arg(long, default_value = "/run/nos/config.sock")]
    config_socket: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!(table = %args.table, "nos-ribd starting");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(reconcile::run(
        args.config_socket,
        args.table.clone(),
        shutdown_rx,
    ));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(table = %args.table, "shutdown signal received");

    let _ = shutdown_tx.send(true);
    let _ = task.await;

    info!(table = %args.table, "shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-ribd` still shuts down its in-memory RIB
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
