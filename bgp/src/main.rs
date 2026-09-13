use anyhow::Context;
use clap::Parser;

#[derive(Parser)]
#[command(name = "nos-bgpd", about = "NOS BGP-4 daemon (placeholder)")]
struct Args {
    /// Name of the BGP instance (from the running config's `bgp_instances`)
    /// this process is responsible for.
    #[arg(long)]
    instance: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

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
