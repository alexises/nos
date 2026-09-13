use anyhow::Context;
use clap::Parser;

#[derive(Parser)]
#[command(name = "nos-bgpd", about = "NOS BGP-4 daemon (placeholder)")]
struct Args {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _args = Args::parse();

    tracing::info!("nos-bgpd starting (placeholder — no BGP protocol logic yet)");

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;

    tracing::info!("shutting down");
    Ok(())
}
