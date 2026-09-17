use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_ospf::log_client::ForwardingLayer;
use nos_ospf::{reconcile, watchdog_client};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "nos-ospfd", about = "NOS OSPF daemon")]
struct Args {
    /// Name of the OSPF instance (from the running config's
    /// `ospf_instances`) this process is responsible for.
    #[arg(long)]
    instance: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see root `CLAUDE.md`'s
    /// "Process supervision" section).
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            format!("nos-ospfd[{}]", args.instance),
            args.log_socket.clone(),
            shutdown_rx.clone(),
        ))
        .init();
    info!(instance = %args.instance, "nos-ospfd starting");

    let Some(config_socket) = watchdog_client::resolve_with_retry(
        &args.watchdog_socket,
        ServiceRef::Config,
        &mut shutdown_rx.clone(),
    )
    .await
    else {
        info!(instance = %args.instance, "shutdown signal received while resolving nos-configd, exiting");
        return Ok(());
    };

    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.instance.clone(),
        shutdown_rx,
    ));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(instance = %args.instance, "shutdown signal received");

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        tracing::warn!(instance = %args.instance, error = %e, "reconcile task ended abnormally");
    }

    info!(instance = %args.instance, "shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-ospfd` still shuts down cleanly instead of
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
