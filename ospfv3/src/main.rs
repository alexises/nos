use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_log_client::ForwardingLayer;
use nos_ospfv3::exchange;
use nos_ospfv3::link::LinkManager;
use nos_ospfv3::{reconcile, rib_push_client, server, watchdog_client};
use nos_pki::Identity;
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "nos-ospfv3d", about = "NOS OSPFv3 (RFC 5340) daemon")]
struct Args {
    /// Name of the `OSPFv3` instance (from the running config's
    /// `ospfv3_instances`) this process is responsible for.
    #[arg(long)]
    instance: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket this instance's IPC query server (`Ospfv3Request::
    /// GetNeighbors`, backing `show ospfv3 neigh`) listens on. Assigned and
    /// passed by `nos-watchdogd` at spawn time, mirroring `nos-ospfd`'s own
    /// `--listen-socket`.
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Multiplies the per-second LSA-age-clock increment (default 1 = real
    /// time). Test/debug only — mirrors `nos-ospfd`'s identical flag,
    /// reachable only via `nos-watchdogd`'s opaque `--ospfv3d-arg`
    /// pass-through. Do not wire this into `Ospfv3Profile`/`nos-cli`.
    #[arg(long, default_value_t = 1)]
    lsa_age_multiplier: u16,

    /// RFC 2328 §10.8's per-DBD-packet LSA-header budget override
    /// (unchanged by RFC 5340). Phase 1 has no MTU-driven per-link
    /// derivation (see `exchange`'s own doc comment) — this always falls
    /// back to `exchange::DEFAULT_DBD_MAX_HEADERS` when unset.
    #[arg(long)]
    dbd_max_headers: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Handed over by nos-watchdogd on stdin; there is no plaintext fallback.
    let identity = Identity::from_stdin().context("reading this daemon's ipc identity")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            format!("nos-ospfv3d[{}]", args.instance),
            args.log_socket.clone(),
            identity.clone(),
            shutdown_rx.clone(),
        ))
        .init();
    info!(instance = %args.instance, "nos-ospfv3d starting");

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

    let listen_socket = args
        .listen_socket
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/ospfv3-{}.sock", args.instance)));

    let (routing_table_tx, routing_table_rx) = watch::channel(None::<String>);
    let dbd_max_headers = args
        .dbd_max_headers
        .unwrap_or(exchange::DEFAULT_DBD_MAX_HEADERS);
    let links = LinkManager::new(args.lsa_age_multiplier, dbd_max_headers);
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.watchdog_socket.clone(),
        args.instance.clone(),
        links.clone(),
        routing_table_tx,
        shutdown_rx.clone(),
    ));
    let rib_push_task = rib_push_client::spawn(
        args.watchdog_socket.clone(),
        links.clone(),
        routing_table_rx,
        shutdown_rx,
    );
    let server_task = server::start(&listen_socket, args.instance.clone(), links, &identity)
        .inspect_err(|e| {
            tracing::error!(instance = %args.instance, error = %e, "failed to start OSPFv3 IPC server");
        })
        .context("starting OSPFv3 IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(instance = %args.instance, "shutdown signal received");

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        tracing::warn!(instance = %args.instance, error = %e, "reconcile task ended abnormally");
    }
    rib_push_task.abort();
    server_task.abort();

    info!(instance = %args.instance, "shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT — mirrors `nos-ospfd`'s own identical
/// handler.
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}
