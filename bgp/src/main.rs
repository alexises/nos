use anyhow::Context;
use clap::Parser;
use nos_bgp::log_client::ForwardingLayer;
use nos_proto::DEFAULT_LOG_SOCKET;
use std::path::PathBuf;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "nos-bgpd", about = "NOS BGP-4 daemon (placeholder)")]
struct Args {
    /// Name of the BGP instance (from the running config's `bgp_instances`)
    /// this process is responsible for.
    #[arg(long)]
    instance: String,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see root `CLAUDE.md`'s
    /// "Process supervision" section).
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // No graceful-shutdown signal of its own (see the bare `ctrl_c()` wait
    // below) — this channel exists purely so the forwarder's reconnect loop
    // has something to stop on if it's ever given one; kept alive for the
    // whole process so the forwarder doesn't see it as closed immediately.
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            format!("nos-bgpd[{}]", args.instance),
            args.log_socket.clone(),
            shutdown_rx,
        ))
        .init();

    tracing::info!(
        instance = %args.instance,
        "nos-bgpd starting (placeholder — no BGP protocol logic yet)"
    );

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;

    tracing::info!(instance = %args.instance, "shutting down");
    Ok(())
}
