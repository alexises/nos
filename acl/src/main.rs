use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_acl::driver::{Driver, LinuxDriver, NoopDriver};
use nos_acl::engine::{self, Engine};
use nos_acl::link_client::{self, LinkTable};
use nos_acl::reconcile;
use nos_daemon::{bootstrap, watchdog};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum DriverKind {
    Noop,
    Linux,
}

#[derive(Parser)]
#[command(name = "nos-acld", about = "NOS access-list (tc flower) daemon")]
#[allow(clippy::struct_field_names)] // matches the other daemons' *_socket naming
struct Args {
    /// Path to nos-watchdogd's broker socket.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to forward this process's log events to.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// `linux` programs tc; `noop` leaves the kernel alone.
    #[arg(long, value_enum, default_value_t = DriverKind::Linux)]
    driver: DriverKind,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let identity = bootstrap::identity()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        "nos-acld",
        args.log_socket.clone(),
        identity,
        shutdown_rx.clone(),
    );
    info!(driver = ?args.driver, "nos-acld starting");
    match args.driver {
        DriverKind::Linux => serve(args, LinuxDriver, shutdown_tx, shutdown_rx).await,
        DriverKind::Noop => serve(args, NoopDriver::default(), shutdown_tx, shutdown_rx).await,
    }
}

async fn serve<D: Driver>(
    args: Args,
    driver: D,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let Some(config_socket) = watchdog::resolve_with_retry(
        &args.watchdog_socket,
        ServiceRef::Config,
        &mut shutdown_rx.clone(),
    )
    .await
    else {
        info!("shutdown signal received while resolving nos-configd, exiting");
        return Ok(());
    };

    let (plan_tx, plan_rx) = watch::channel(None);
    let (links_tx, links_rx) = watch::channel(LinkTable::default());
    let reconcile_task = tokio::spawn(reconcile::run(config_socket, plan_tx, shutdown_rx.clone()));
    let link_task = tokio::spawn(link_client::run(
        args.watchdog_socket.clone(),
        links_tx,
        shutdown_rx.clone(),
    ));
    let engine_task = tokio::spawn(engine::run(
        Engine::new(driver),
        plan_rx,
        links_rx,
        shutdown_rx,
    ));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    for (name, task) in [("reconcile", reconcile_task), ("link_client", link_task)] {
        if let Err(e) = task.await {
            warn!(error = %e, task = name, "task ended abnormally");
        }
    }
    // It removes every filter before the process exits.
    if let Err(e) = engine_task.await {
        warn!(error = %e, task = "engine", "task ended abnormally");
    }
    info!("shutting down");
    Ok(())
}

/// SIGINT is what `nos-watchdog` sends; SIGTERM covers a container stop.
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
        let args = Args::try_parse_from(["nos-acld"]).unwrap();
        assert!(matches!(args.driver, DriverKind::Linux));
        let args = Args::try_parse_from(["nos-acld", "--driver", "noop"]).unwrap();
        assert!(matches!(args.driver, DriverKind::Noop));
    }
}
