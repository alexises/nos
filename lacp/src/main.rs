use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_lacp::{interface_client, reconcile, server, watchdog_client};
use nos_log_client::ForwardingLayer;
use nos_proto::{LacpAggregateMembers, ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Default listen socket. Like `nos-interfaced`/`nos-logd`, `nos-lacpd` is
/// a single process handling every configured `Lacp`-mode `PortAggregate`,
/// so there's exactly one fixed default rather than one derived per
/// instance name.
const DEFAULT_LISTEN_SOCKET: &str = "/run/nos/lacp.sock";

#[derive(Parser)]
#[command(name = "nos-lacpd", about = "NOS LACP (IEEE 802.1AX) daemon")]
#[allow(clippy::struct_field_names)] // matches interface::main::Args's own *_socket naming
struct Args {
    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// and nos-interfaced's current addresses rather than assuming
    /// hardcoded defaults.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for LACP status queries (`nos show lacp`).
    #[arg(long, default_value = DEFAULT_LISTEN_SOCKET)]
    listen_socket: PathBuf,

    /// Unix socket to forward this process's log events to.
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
            "nos-lacpd",
            args.log_socket.clone(),
            shutdown_rx.clone(),
        ))
        .init();
    info!(listen_socket = %args.listen_socket.display(), "nos-lacpd starting");

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

    let (push_tx, push_rx) = mpsc::channel::<LacpAggregateMembers>(16);

    let aggregates = reconcile::SharedAggregates::default();
    let server_task = server::start(&args.listen_socket, aggregates.clone())
        .inspect_err(|e| tracing::error!(error = %e, "failed to start lacp IPC server"))
        .context("starting lacp IPC server")?;
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        aggregates,
        push_tx,
        shutdown_rx.clone(),
    ));
    let interface_client_task = tokio::spawn(interface_client::run(
        args.watchdog_socket.clone(),
        push_rx,
        shutdown_rx.clone(),
    ));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        warn!(error = %e, "reconcile task ended abnormally");
    }
    server_task.abort();
    if let Err(e) = interface_client_task.await {
        warn!(error = %e, "interface_client task ended abnormally");
    }

    info!("shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT — SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-lacpd` still shuts down cleanly.
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}
