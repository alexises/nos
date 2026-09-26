use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_log_client::ForwardingLayer;
use nos_ospf::boot::BootCounter;
use nos_ospf::link::LinkManager;
use nos_ospf::{reconcile, rib_push_client, server, watchdog_client};
use nos_pki::Identity;
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

    /// Unix socket this instance's IPC query server (`OspfRequest::
    /// GetNeighbors`, backing `show ospf neigh`) listens on. Assigned and
    /// passed by `nos-watchdogd` at spawn time, mirroring `nos-bgpd`'s own
    /// `--listen-socket`.
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see root `CLAUDE.md`'s
    /// "Process supervision" section).
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Multiplies the per-second LSA-age-clock increment (default 1 = real
    /// time). Test/debug only — never set by nos-watchdogd's normal config-
    /// driven spawn path, only reachable via its opaque `--ospfd-arg` pass-
    /// through (see root `CLAUDE.md`'s "Memory profiling" for the identical
    /// pattern). Do not wire this into OspfProfile/nos-cli.
    #[arg(long, default_value_t = 1)]
    lsa_age_multiplier: u16,

    /// RFC 2328 §10.8's per-DBD-packet LSA-header budget override. Left
    /// unset (the real production default), each link derives its own
    /// budget from its effective MTU (`OspfProfile.mtu` if set, else the
    /// real resolved interface MTU) — see `exchange::mtu_based_max_headers`.
    /// Set only by `tools/verify-e2e.sh`'s `ospf-dbd-pagination` phase, via
    /// the same opaque `--ospfd-arg` pass-through, to force every link to a
    /// fixed value regardless of MTU, for deterministic multi-packet
    /// pagination over a small lab LSDB.
    #[arg(long)]
    dbd_max_headers: Option<usize>,

    /// Directory for this daemon's persisted state: the RFC 7474 boot count
    /// (`<instance>.boot`), which must survive restarts.
    #[arg(long, default_value = "/var/lib/nos/ospf")]
    state_dir: PathBuf,
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
            format!("nos-ospfd[{}]", args.instance),
            args.log_socket.clone(),
            identity.clone(),
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

    let listen_socket = args
        .listen_socket
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/ospf-{}.sock", args.instance)));

    let (routing_table_tx, routing_table_rx) = watch::channel(None::<String>);
    let links = LinkManager::new(
        args.lsa_age_multiplier,
        args.dbd_max_headers,
        BootCounter::persistent(args.state_dir.join(format!("{}.boot", args.instance))),
    );
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
            tracing::error!(instance = %args.instance, error = %e, "failed to start OSPF IPC server");
        })
        .context("starting OSPF IPC server")?;

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
