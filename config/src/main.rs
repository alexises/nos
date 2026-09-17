use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_config::{persistence, ConfigStore, ListenAddr};
use nos_log_client::ForwardingLayer;
use nos_proto::DEFAULT_LOG_SOCKET;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "nos-configd", about = "NOS configuration daemon")]
struct Args {
    /// Where to listen for IPC connections.
    /// Accepts a Unix socket path (/run/nos/config.sock, config.sock)
    /// or a TCP address (127.0.0.1:9000, `[::1]:9000`).
    #[arg(long, default_value = "/run/nos/config.sock")]
    listen: ListenAddr,

    /// Path to the persisted config file. Loaded at startup — falling back
    /// to an empty default config if it does not exist — and written to
    /// when a client sends the `save` command.
    #[arg(long, default_value = "/var/lib/nos/config.yaml")]
    config_file: PathBuf,

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
            "nos-configd",
            args.log_socket.clone(),
            shutdown_rx,
        ))
        .init();

    let initial = persistence::load_or_default(&args.config_file)
        .with_context(|| format!("failed to load config from {}", args.config_file.display()))?;

    let store = ConfigStore::new(initial, Some(args.config_file.clone()));
    let _handle = store
        .start_ipc_server(&args.listen)
        .inspect_err(|e| {
            tracing::error!(error = %e, listen = %args.listen, "failed to bind config IPC server");
        })
        .with_context(|| format!("failed to bind {}", args.listen))?;

    tracing::info!(config_file = %args.config_file.display(), "config file path");

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;

    tracing::info!("shutting down");
    Ok(())
}
