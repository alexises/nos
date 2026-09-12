use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_config::{persistence, ConfigStore, ListenAddr};

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let initial = persistence::load_or_default(&args.config_file)
        .with_context(|| format!("failed to load config from {}", args.config_file.display()))?;

    let store = ConfigStore::new(initial);
    let _handle = store
        .start_ipc_server(&args.listen, Some(args.config_file.clone()))
        .with_context(|| format!("failed to bind {}", args.listen))?;

    tracing::info!("nos-configd listening on {}", args.listen);
    tracing::info!("config file: {}", args.config_file.display());

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;

    tracing::info!("shutting down");
    Ok(())
}
