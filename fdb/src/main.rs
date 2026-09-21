use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use nos_fdb::{
    bgp_client, reconcile, server, watchdog_client, Fdb, FdbDriver, LinuxFdbDriver, NoopFdbDriver,
};
use nos_log_client::ForwardingLayer;
use nos_pki::Identity;
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone, Copy, clap::ValueEnum)]
enum DriverKind {
    Noop,
    Linux,
}

impl std::fmt::Display for DriverKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriverKind::Noop => write!(f, "noop"),
            DriverKind::Linux => write!(f, "linux"),
        }
    }
}

#[cfg(target_os = "linux")]
fn default_driver_kind() -> DriverKind {
    DriverKind::Linux
}
#[cfg(not(target_os = "linux"))]
fn default_driver_kind() -> DriverKind {
    DriverKind::Noop
}

#[derive(Parser)]
#[command(
    name = "nos-fdbd",
    about = "NOS forwarding-database (EVPN/VXLAN) daemon"
)]
struct Args {
    /// Name of the broadcast domain (from the running config's
    /// `broadcast_domains`) this process owns the VXLAN device and FDB of.
    #[arg(long)]
    domain: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd,
    /// nos-interfaced and nos-bgpd.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for `show fdb` and `nos-bgpd`'s route push.
    /// Defaults to a path derived from `--domain`; nos-watchdog always
    /// passes it explicitly.
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Which backend programs the kernel: `linux` (real `rtnetlink` calls,
    /// the default on Linux) or `noop` (log-only).
    #[arg(long, value_enum, default_value_t = default_driver_kind())]
    driver: DriverKind,

    /// Unix socket to forward this process's log events to.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,
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
            format!("nos-fdbd[{}]", args.domain),
            args.log_socket.clone(),
            identity.clone(),
            shutdown_rx.clone(),
        ))
        .init();
    info!(domain = %args.domain, peer = ?identity.peer(), driver = %args.driver, "nos-fdbd starting");

    let listen_socket = args
        .listen_socket
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/fdb-{}.sock", args.domain)));

    let Some(config_socket) = watchdog_client::resolve_with_retry(
        &args.watchdog_socket,
        ServiceRef::Config,
        &mut shutdown_rx.clone(),
    )
    .await
    else {
        info!(domain = %args.domain, "shutdown signal received while resolving nos-configd, exiting");
        return Ok(());
    };

    let driver: Arc<dyn FdbDriver> = match args.driver {
        DriverKind::Noop => Arc::new(NoopFdbDriver),
        DriverKind::Linux => Arc::new(
            LinuxFdbDriver::new()
                .inspect_err(|e| tracing::error!(domain = %args.domain, error = %e, "failed to initialize linux fdb driver"))
                .context("initializing linux fdb driver")?,
        ),
    };

    let fdb = Fdb::new(args.domain.clone(), driver);
    let bgp_task = bgp_client::spawn(
        args.watchdog_socket.clone(),
        fdb.subscribe(),
        shutdown_rx.clone(),
    );
    let local_task = tokio::spawn(fdb.clone().run_local(shutdown_rx.clone()));
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.watchdog_socket.clone(),
        args.domain.clone(),
        fdb.clone(),
        shutdown_rx,
    ));
    let server_task = server::start(&listen_socket, args.domain.clone(), fdb.clone(), &identity)
        .inspect_err(|e| tracing::error!(domain = %args.domain, error = %e, "failed to start FDB IPC server"))
        .context("starting FDB IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(domain = %args.domain, "shutdown signal received");

    let _ = shutdown_tx.send(true);
    for (name, task) in [
        ("reconcile", reconcile_task),
        ("local mac", local_task),
        ("bgp push", bgp_task),
    ] {
        if let Err(e) = task.await {
            warn!(domain = %args.domain, error = %e, task = name, "task ended abnormally");
        }
    }
    server_task.abort();
    // Like `nos-ribd` deleting its VRF: SIGINT is both "the watchdog is
    // stopping" and "this domain lost its vni", so the vxlan device goes.
    fdb.set_ready(None).await;

    info!(domain = %args.domain, "shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT (the latter is what `nos-watchdog` sends).
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}
