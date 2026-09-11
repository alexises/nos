use anyhow::Context;
use clap::Parser;
use nos_config::{Config, ConfigStore, ListenAddr};

#[derive(Parser)]
#[command(name = "nos-configd", about = "NOS configuration daemon")]
struct Args {
    /// Where to listen for IPC connections.
    /// Accepts a Unix socket path (/run/nos/config.sock, config.sock)
    /// or a TCP address (127.0.0.1:9000, `[::1]:9000`).
    #[arg(long, default_value = "/run/nos/config.sock")]
    listen: ListenAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let store = ConfigStore::new(Config::default());
    let _handle = store
        .start_ipc_server(&args.listen)
        .with_context(|| format!("failed to bind {}", args.listen))?;

    tracing::info!("nos-configd listening on {}", args.listen);

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;

    tracing::info!("shutting down");
    Ok(())
}
