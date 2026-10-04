use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use nos_log_client::ForwardingLayer;
use nos_pki::Identity;
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use nos_rib::{
    bgp_client, evpn_client, ospf_client, reconcile, server, watchdog_client, LinuxRibDriver,
    NoopRibDriver, Rib, RibDriver,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, RwLock};
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see root `CLAUDE.md`'s
    /// "Process supervision" section), the same way `--config-socket` is.
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
        // `RUST_LOG` support: defaults to `trace`, i.e. exactly the
        // unfiltered behavior this process had before, so an unset
        // `RUST_LOG` changes nothing. Added so `tools/bench-bgp.sh` can run
        // the stack quietly enough to measure BGP rather than logging.
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            format!("nos-ribd[{}]", args.table),
            args.log_socket.clone(),
            identity.clone(),
            shutdown_rx.clone(),
        ))
        .init();
    info!(table = %args.table, peer = ?identity.peer(), "nos-ribd starting");

    let listen_socket = args
        .listen_socket
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/rib-{}.sock", args.table)));

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
                .inspect_err(|e| {
                    tracing::error!(table = %args.table, error = %e, "failed to initialize linux rib driver");
                })
                .context("initializing linux rib driver")?,
        ),
    };

    let redistribute_tx = bgp_client::spawn(args.watchdog_socket.clone(), shutdown_rx.clone());
    let ospf_redistribute_tx = vec![
        (
            nos_proto::RedistributeTarget::Ospf,
            ospf_client::spawn(
                args.watchdog_socket.clone(),
                shutdown_rx.clone(),
                ospf_client::OSPFV2,
            ),
        ),
        (
            nos_proto::RedistributeTarget::Ospfv3,
            ospf_client::spawn(
                args.watchdog_socket.clone(),
                shutdown_rx.clone(),
                ospf_client::OSPFV3,
            ),
        ),
    ];
    let evpn_tx = evpn_client::spawn(
        args.watchdog_socket.clone(),
        args.table.clone(),
        shutdown_rx.clone(),
    );

    let rib = Arc::new(RwLock::new(Rib::new()));
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.watchdog_socket.clone(),
        args.table.clone(),
        rib.clone(),
        driver.clone(),
        redistribute_tx,
        ospf_redistribute_tx,
        evpn_tx,
        shutdown_rx,
    ));
    let server_task = server::start(&listen_socket, args.table.clone(), rib, driver, &identity)
        .inspect_err(|e| {
            tracing::error!(table = %args.table, error = %e, "failed to start RIB IPC server");
        })
        .context("starting RIB IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(table = %args.table, "shutdown signal received");

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        warn!(table = %args.table, error = %e, "reconcile task ended abnormally");
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
        let args = Args::try_parse_from(["nos-ribd", "--table", "rt1"]).unwrap();
        assert_eq!(args.table, "rt1");
    }
}
