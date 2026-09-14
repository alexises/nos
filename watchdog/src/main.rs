use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_proto::{DEFAULT_CONFIG_SOCKET, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use nos_watchdog::log_client::ForwardingLayer;
use nos_watchdog::{
    bgp_instances, broker, routing_tables, supervise_one, BackoffPolicy, EndpointRegistry,
    ProcessSpec,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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

    /// Path to the nos-interfaced binary to supervise. Unlike nos-bgpd/
    /// nos-ribd, exactly one instance is always supervised regardless of how
    /// many interfaces are configured — see `interface/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-interfaced")]
    interfaced_bin: PathBuf,

    /// Extra arguments forwarded to nos-interfaced.
    #[arg(long = "interfaced-arg", allow_hyphen_values = true)]
    interfaced_flags: Vec<String>,

    /// Unix socket nos-interfaced listens on for interface queries (e.g.
    /// from `nos show interface`). Also served out as the resolved address
    /// for `ServiceRef::Interfaces` broker queries, the same way
    /// `--config-socket` is for `ServiceRef::Config`.
    #[arg(long, default_value = "/run/nos/interface.sock")]
    interfaced_listen_socket: PathBuf,

    /// Path to the nos-logd binary to supervise. Like nos-interfaced, exactly
    /// one instance is always supervised regardless of how many other
    /// daemons are running.
    #[arg(long, default_value = "/usr/local/bin/nos-logd")]
    logd_bin: PathBuf,

    /// Extra arguments forwarded to nos-logd.
    #[arg(long = "logd-arg", allow_hyphen_values = true)]
    logd_flags: Vec<String>,

    /// Unix socket nos-logd listens on for pushed log entries and queries
    /// (e.g. from `nos show log`). Also served out as the resolved address
    /// for `ServiceRef::Log` broker queries, the same way
    /// `--interfaced-listen-socket` is for `ServiceRef::Interfaces` — and
    /// passed via `--log-socket` to every other supervised process so it can
    /// forward its own logs here.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

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
    let args = Args::parse();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            "nos-watchdogd",
            args.log_socket.clone(),
            shutdown_rx.clone(),
        ))
        .init();

    let policy = BackoffPolicy::default();
    let registry = EndpointRegistry::default();

    // nos-logd is spawned first (still just one more supervised process,
    // with no ordering guarantee enforced) so the window in which every
    // other process's own forwarder has nothing to connect to is as short
    // as possible — a fixed 1s retry (see `log_client::run`) covers the
    // rest.
    let logd_args = std::iter::once("--listen-socket".to_string())
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(args.logd_flags)
        .collect();
    let logd_spec = ProcessSpec::new("nos-logd", args.logd_bin, logd_args);
    let mut tasks = vec![tokio::spawn(supervise_one(
        logd_spec,
        policy,
        shutdown_rx.clone(),
    ))];

    let configd_args = std::iter::once("--log-socket".to_string())
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(args.configd_flags)
        .collect();
    let configd_spec = ProcessSpec::new("nos-configd", args.configd_bin, configd_args);
    tasks.push(tokio::spawn(supervise_one(
        configd_spec,
        policy,
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(bgp_instances::manage(
        args.config_socket.clone(),
        args.bgpd_bin,
        args.bgpd_flags,
        args.log_socket.clone(),
        policy,
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(routing_tables::manage(
        args.config_socket.clone(),
        args.ribd_bin,
        args.ribd_flags,
        args.log_socket.clone(),
        policy,
        registry.clone(),
        args.listen_socket.clone(),
        shutdown_rx.clone(),
    )));

    let interfaced_args = std::iter::once("--listen-socket".to_string())
        .chain(std::iter::once(
            args.interfaced_listen_socket.display().to_string(),
        ))
        .chain(std::iter::once("--watchdog-socket".to_string()))
        .chain(std::iter::once(args.listen_socket.display().to_string()))
        .chain(std::iter::once("--log-socket".to_string()))
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(args.interfaced_flags)
        .collect();
    let interfaced_spec = ProcessSpec::new("nos-interfaced", args.interfaced_bin, interfaced_args);
    tasks.push(tokio::spawn(supervise_one(
        interfaced_spec,
        policy,
        shutdown_rx.clone(),
    )));

    let broker_task = broker::start(
        &args.listen_socket,
        registry,
        args.config_socket,
        args.interfaced_listen_socket,
        args.log_socket,
    )
    .inspect_err(|e| tracing::error!(error = %e, "failed to start broker IPC server"))
    .context("starting broker IPC server")?;

    info!(task_count = tasks.len(), "nos-watchdogd supervising tasks");

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received, stopping supervised processes");

    let _ = shutdown_tx.send(true);
    for task in tasks {
        if let Err(e) = task.await {
            error!(error = %e, "supervisor task panicked");
        }
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
