use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_proto::{DEFAULT_CONFIG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use nos_watchdog::{
    bgp_instances, broker, routing_tables, supervise_one, BackoffPolicy, EndpointRegistry,
    ProcessSpec,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;

#[derive(Parser)]
#[command(name = "nos-watchdogd", about = "NOS process supervisor")]
struct Args {
    /// Path to the nos-configd binary to supervise.
    #[arg(long, default_value = "/usr/local/bin/nos-configd")]
    configd_bin: PathBuf,

    /// Extra arguments forwarded to nos-configd (e.g. --listen, --config-file).
    #[arg(long = "configd-arg", allow_hyphen_values = true)]
    configd_flags: Vec<String>,

    /// Path to the nos-bgpd binary to supervise (one instance is spawned per
    /// BGP instance in the running config).
    #[arg(long, default_value = "/usr/local/bin/nos-bgpd")]
    bgpd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-bgpd instance.
    #[arg(long = "bgpd-arg", allow_hyphen_values = true)]
    bgpd_flags: Vec<String>,

    /// Path to the nos-ribd binary to supervise (one instance is spawned per
    /// routing table in the running config).
    #[arg(long, default_value = "/usr/local/bin/nos-ribd")]
    ribd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-ribd instance.
    #[arg(long = "ribd-arg", allow_hyphen_values = true)]
    ribd_flags: Vec<String>,

    /// Path to nos-configd's IPC Unix socket, used by the watchdog itself to
    /// subscribe to BGP instance and routing table changes. Independent of
    /// `--configd-arg`, which is an opaque pass-through to the child — if
    /// the child's actual listen address is overridden via `--configd-arg
    /// --listen=...`, this must be updated to match. Also served out as the
    /// resolved address for `ServiceRef::Config` broker queries, since the
    /// watchdog itself is the one process every other client asks instead of
    /// assuming this default.
    #[arg(long, default_value = DEFAULT_CONFIG_SOCKET)]
    config_socket: PathBuf,

    /// Unix socket the endpoint-resolution broker listens on. Every other
    /// daemon/CLI dials this first to learn where to reach nos-configd or a
    /// specific nos-ribd instance, instead of assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    listen_socket: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let policy = BackoffPolicy::default();
    let registry = EndpointRegistry::default();

    let configd_spec = ProcessSpec::new("nos-configd", args.configd_bin, args.configd_flags);
    let mut tasks = vec![tokio::spawn(supervise_one(
        configd_spec,
        policy,
        shutdown_rx.clone(),
    ))];
    tasks.push(tokio::spawn(bgp_instances::manage(
        args.config_socket.clone(),
        args.bgpd_bin,
        args.bgpd_flags,
        policy,
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(routing_tables::manage(
        args.config_socket.clone(),
        args.ribd_bin,
        args.ribd_flags,
        policy,
        registry.clone(),
        args.listen_socket.clone(),
        shutdown_rx.clone(),
    )));

    let broker_task = broker::start(&args.listen_socket, registry, args.config_socket)
        .context("starting broker IPC server")?;

    info!("nos-watchdogd supervising {} task(s)", tasks.len());

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received, stopping supervised processes");

    let _ = shutdown_tx.send(true);
    for task in tasks {
        let _ = task.await;
    }
    // The broker's accept loop has no shutdown signal of its own (it never
    // needs to drain in-flight state the way a supervised process does) —
    // aborting it directly avoids blocking shutdown on a loop that would
    // otherwise run forever.
    broker_task.abort();

    info!("shutting down");
    Ok(())
}

/// Waits for either SIGTERM (the signal `docker stop` sends) or SIGINT
/// (Ctrl-C, for interactive/local runs).
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;

    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}
