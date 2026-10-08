use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_bfd::manager::{Demux, Manager};
use nos_bfd::{server, socket::UdpNet};
use nos_log_client::ForwardingLayer;
use nos_pki::Identity;
use nos_proto::{DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// One system-wide process, like `nos-lldpd`, so one fixed socket.
const DEFAULT_LISTEN_SOCKET: &str = "/run/nos/bfd.sock";

#[derive(Parser)]
#[command(name = "nos-bfdd", about = "NOS BFD (RFC 5880/5881) daemon")]
#[allow(clippy::struct_field_names)] // matches the other daemons' *_socket naming
struct Args {
    /// Path to nos-watchdogd's broker socket, used to find each table's
    /// nos-ribd (for its VRF device).
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for session registrations and queries.
    #[arg(long, default_value = DEFAULT_LISTEN_SOCKET)]
    listen_socket: PathBuf,

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
            "nos-bfdd",
            args.log_socket.clone(),
            identity.clone(),
            shutdown_rx,
        ))
        .init();
    info!(listen_socket = %args.listen_socket.display(), "nos-bfdd starting");

    let demux = Demux::default();
    let net = UdpNet::new(args.watchdog_socket, demux.clone());
    let manager = Manager::new(net, demux);
    let server_task = server::start(&args.listen_socket, manager, &identity)
        .inspect_err(|e| tracing::error!(error = %e, "failed to start bfd IPC server"))
        .context("starting bfd IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    server_task.abort();
    info!("shutting down");
    Ok(())
}

/// SIGINT is what `nos-watchdog` sends; SIGTERM too for a container stop.
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
        let args = Args::try_parse_from(["nos-bfdd"]).unwrap();
        assert_eq!(args.listen_socket, PathBuf::from(DEFAULT_LISTEN_SOCKET));
    }
}
