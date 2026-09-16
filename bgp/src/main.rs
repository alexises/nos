use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_bgp::log_client::ForwardingLayer;
use nos_bgp::session::SessionManager;
use nos_bgp::{reconcile, server, watchdog_client};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Parser)]
#[command(name = "nos-bgpd", about = "NOS BGP-4 daemon")]
struct Args {
    /// Name of the BGP instance (from the running config's `bgp_instances`)
    /// this process is responsible for.
    #[arg(long)]
    instance: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for session-summary queries (e.g. from `nos
    /// show bgp brief`). Defaults to a path derived from `--instance` for
    /// standalone/dev runs; nos-watchdog always passes this explicitly for
    /// supervised instances.
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see root `CLAUDE.md`'s
    /// "Process supervision" section).
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Only present when built with `--features dhat-heap`. Path to write
    /// the dhat heap-profile report to on exit — load it at
    /// <https://nnethercote.github.io/dh_view/dh_view.html>.
    #[cfg(feature = "dhat-heap")]
    #[arg(long, default_value = "dhat-heap.json")]
    profile_memory_out: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::builder()
        .file_name(args.profile_memory_out.clone())
        .build();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tracing_subscriber::registry()
        // Without this there's no way to turn the log volume down at all —
        // and `rib.rs` emits an `info!` per learned route, each costing a
        // `format!` plus a synchronous `ForwardingLayer::on_event` in the
        // peer's FSM task, which dominates any high-route-count run (see
        // `tools/bench-bgp.sh`). Defaults to `trace`, i.e. exactly the
        // unfiltered behavior this process had before, so an unset
        // `RUST_LOG` changes nothing.
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            format!("nos-bgpd[{}]", args.instance),
            args.log_socket.clone(),
            shutdown_rx.clone(),
        ))
        .init();
    info!(instance = %args.instance, "nos-bgpd starting");
    #[cfg(feature = "dhat-heap")]
    info!(out = %args.profile_memory_out.display(), "memory profiling enabled (dhat)");

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
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/bgp-{}.sock", args.instance)));

    let sessions = SessionManager::new(args.instance.clone());
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.watchdog_socket.clone(),
        args.instance.clone(),
        sessions.clone(),
        shutdown_rx,
    ));
    let server_task = server::start(&listen_socket, args.instance.clone(), sessions)
        .inspect_err(|e| {
            tracing::error!(instance = %args.instance, error = %e, "failed to start BGP IPC server");
        })
        .context("starting BGP IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(instance = %args.instance, "shutdown signal received");

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        warn!(instance = %args.instance, error = %e, "reconcile task ended abnormally");
    }
    server_task.abort();

    info!(instance = %args.instance, "shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-bgpd` still shuts down its sessions cleanly
/// instead of relying on a forced kill.
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}
