use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use nos_interface::{reconcile, server, watchdog_client, Interfaces};
use nos_proto::{ServiceRef, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, RwLock};
use tracing::info;

/// Default listen socket. Unlike `nos-ribd` (one instance per routing
/// table), `nos-interfaced` is a single process managing every configured
/// interface, so there's exactly one fixed default rather than one derived
/// per instance name.
const DEFAULT_LISTEN_SOCKET: &str = "/run/nos/interface.sock";

#[derive(Parser)]
#[command(name = "nos-interfaced", about = "NOS interface reconciliation daemon")]
struct Args {
    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for interface queries (e.g. from `nos show
    /// interface`).
    #[arg(long, default_value = DEFAULT_LISTEN_SOCKET)]
    listen_socket: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!("nos-interfaced starting");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let Some(config_socket) = watchdog_client::resolve_with_retry(
        &args.watchdog_socket,
        ServiceRef::Config,
        &mut shutdown_rx.clone(),
    )
    .await
    else {
        info!("shutdown signal received while resolving nos-configd, exiting");
        return Ok(());
    };

    let interfaces = Arc::new(RwLock::new(Interfaces::new()));
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        interfaces.clone(),
        shutdown_rx,
    ));
    let server_task =
        server::start(&args.listen_socket, interfaces).context("starting interface IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");

    let _ = shutdown_tx.send(true);
    let _ = reconcile_task.await;
    server_task.abort();

    info!("shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-interfaced` still shuts down cleanly instead of
/// relying on a forced kill.
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}
