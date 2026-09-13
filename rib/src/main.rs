use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use nos_proto::{ServiceRef, DEFAULT_WATCHDOG_SOCKET};
use nos_rib::{reconcile, server, watchdog_client, LinuxRibDriver, NoopRibDriver, Rib, RibDriver};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, RwLock};
use tracing::info;

/// Default location for `nos-ribd`'s own private table-id↔VRF-name
/// registry (see `nos_rib::driver::table_registry`) — never read by any
/// other process; `nos-interfaced` learns the VRF name over IPC instead
/// (`RibRequest::GetVrfName`).
const DEFAULT_TABLE_REGISTRY_PATH: &str = "/var/lib/nos/linux-driver/table-ids.yaml";

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
#[command(name = "nos-ribd", about = "NOS RIB (routing information base) daemon")]
struct Args {
    /// Name of the routing table (from the running config's
    /// `routing_tables`) this process computes best routes for.
    #[arg(long)]
    table: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for route queries (e.g. from `nos show
    /// route`). Defaults to a path derived from `--table` for standalone/dev
    /// runs; nos-watchdog always passes this explicitly for supervised
    /// instances.
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Which backend actually applies routes to the OS: `linux` (real
    /// `rtnetlink` calls, the default on Linux) or `noop` (log-only, no OS
    /// effect — the default off-Linux, and useful for tests/dev).
    #[arg(long, value_enum, default_value_t = default_driver_kind())]
    driver: DriverKind,

    /// Only used by `--driver linux`: where this instance persists its own
    /// table-id↔VRF-name allocation, for restart survival.
    #[arg(long, default_value = DEFAULT_TABLE_REGISTRY_PATH)]
    table_registry_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!(table = %args.table, "nos-ribd starting");

    let listen_socket = args
        .listen_socket
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/rib-{}.sock", args.table)));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let Some(config_socket) = watchdog_client::resolve_with_retry(
        &args.watchdog_socket,
        ServiceRef::Config,
        &mut shutdown_rx.clone(),
    )
    .await
    else {
        info!(table = %args.table, "shutdown signal received while resolving nos-configd, exiting");
        return Ok(());
    };

    let driver: Arc<dyn RibDriver> = match args.driver {
        DriverKind::Noop => Arc::new(NoopRibDriver),
        DriverKind::Linux => Arc::new(
            LinuxRibDriver::new(args.table_registry_path.clone())
                .context("initializing linux rib driver")?,
        ),
    };

    let rib = Arc::new(RwLock::new(Rib::new()));
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.table.clone(),
        rib.clone(),
        driver.clone(),
        shutdown_rx,
    ));
    let server_task = server::start(&listen_socket, args.table.clone(), rib, driver)
        .context("starting RIB IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(table = %args.table, "shutdown signal received");

    let _ = shutdown_tx.send(true);
    let _ = reconcile_task.await;
    server_task.abort();

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
