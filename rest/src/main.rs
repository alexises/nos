use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_log_client::ForwardingLayer;
use nos_pki::Identity;
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use nos_rest::{api, ipc::Daemons, listen::Listener, watchdog_client};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "nos-restd", about = "NOS REST API daemon")]
struct Args {
    /// The routing table this API is pinned to — it listens inside that
    /// table's VRF, on the address its `rest-api` config names.
    #[arg(long)]
    table: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd
    /// and every other daemon this API queries.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

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
            format!("nos-restd[{}]", args.table),
            args.log_socket.clone(),
            identity.clone(),
            shutdown_rx.clone(),
        ))
        .init();
    info!(table = %args.table, "nos-restd starting");

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

    let daemons = Daemons::new(args.watchdog_socket, config_socket);
    let listener = Listener {
        table: args.table,
        router: api::router(daemons.clone()),
        daemons,
    };
    let task = tokio::spawn(listener.run(shutdown_rx.clone()));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    let _ = task.await;
    info!("shutting down");
    Ok(())
}

/// SIGINT is what `nos-watchdog` sends (`supervisor::shutdown_child`); SIGTERM
/// is handled too so a directly-run or container-stopped `nos-restd` exits cleanly.
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
        let args = Args::try_parse_from(["nos-restd", "--table", "rt1"]).unwrap();
        assert_eq!(args.table, "rt1");
    }
}
