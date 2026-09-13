use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_watchdog::{supervise_one, BackoffPolicy, ProcessSpec};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;

#[derive(Parser)]
#[command(name = "nos-watchdogd", about = "NOS process supervisor")]
struct Args {
    /// Path to the nos-configd binary to supervise.
    #[arg(long, default_value = "/usr/local/bin/nos-configd")]
    configd_bin: PathBuf,

    /// Extra arguments forwarded to nos-configd (e.g. --listen, --config-file).
    #[arg(long = "configd-arg", allow_hyphen_values = true)]
    configd_flags: Vec<String>,

    /// Path to the nos-bgpd binary to supervise.
    #[arg(long, default_value = "/usr/local/bin/nos-bgpd")]
    bgpd_bin: PathBuf,

    /// Extra arguments forwarded to nos-bgpd.
    #[arg(long = "bgpd-arg", allow_hyphen_values = true)]
    bgpd_flags: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let policy = BackoffPolicy::default();

    let specs = [
        ProcessSpec::new("nos-configd", args.configd_bin, args.configd_flags),
        ProcessSpec::new("nos-bgpd", args.bgpd_bin, args.bgpd_flags),
    ];

    let tasks: Vec<_> = specs
        .into_iter()
        .map(|spec| tokio::spawn(supervise_one(spec, policy, shutdown_rx.clone())))
        .collect();

    info!("nos-watchdogd supervising {} process(es)", tasks.len());

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received, stopping supervised processes");

    let _ = shutdown_tx.send(true);
    for task in tasks {
        let _ = task.await;
    }

    info!("shutting down");
    Ok(())
}

/// Waits for either SIGTERM (the signal `docker stop` sends) or SIGINT
/// (Ctrl-C, for interactive/local runs).
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;

    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}
