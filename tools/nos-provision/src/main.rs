//! One-shot config provisioning tool: speaks nos-configd's IPC protocol
//! directly (nos-cli's interactive shell can't be driven over a plain pipe).
//! The op list itself lives in `nos_provision::build_ops`; this bin only
//! opens a transaction, applies it, commits, and (with `--save`) persists.
//! Still used by `tools/bench-bgp.sh`; `tools/e2e` reuses `build_ops` and
//! provisions over the REST API instead.
//!
//! Every daemon socket is mutually authenticated TLS, so like `nos-cli` this
//! logs in first: it trusts the watchdog's published `ca.crt`, trades a
//! username and password for a certificate on a key generated here, and only
//! then opens its transaction.

use anyhow::{bail, Context};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use nos_pki::Identity;
use nos_proto::{
    Event, IpcCodec, Request, Role, TransactionBase, WatchdogEvent, WatchdogRequest,
    DEFAULT_PKI_CA, DEFAULT_WATCHDOG_SOCKET,
};
use nos_provision::{build_ops, Args};
use std::path::PathBuf;
use tokio::io::{ReadHalf, WriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite};

type Stream = nos_pki::Stream;

/// `nos-provision`'s own flags, alongside the shared config-building ones.
#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    args: Args,

    /// User to log in as (a local NOS user; a fresh router has `admin`).
    #[arg(long)]
    login_user: String,

    /// That user's password. Falls back to `NOS_LOGIN_PASSWORD`, which keeps
    /// it out of the process list.
    #[arg(long)]
    login_password: Option<String>,

    /// `nos-watchdogd`'s broker socket, where login happens.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// The watchdog's published CA certificate.
    #[arg(long, default_value = DEFAULT_PKI_CA)]
    pki_ca: PathBuf,
}

/// Trades the password for a certificate and installs it as this process's
/// identity, so every later `nos_pki::connect` is authenticated.
async fn log_in(cli: &Cli) -> anyhow::Result<()> {
    let password = cli
        .login_password
        .clone()
        .or_else(|| std::env::var("NOS_LOGIN_PASSWORD").ok())
        .context("--login-password (or NOS_LOGIN_PASSWORD) is required")?;
    let ca = std::fs::read(&cli.pki_ca)
        .with_context(|| format!("reading the ipc trust anchor {}", cli.pki_ca.display()))?;
    let identity = Identity::anonymous_from_pem(&ca).context("the ipc trust anchor is unusable")?;
    nos_pki::install(identity.clone());

    let (csr, key) = nos_pki::generate_csr()?;
    let stream = nos_pki::connect(&cli.watchdog_socket, Role::Watchdog, "")
        .await
        .with_context(|| format!("connecting to {}", cli.watchdog_socket.display()))?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());
    writer
        .send(WatchdogRequest::Login {
            user: cli.login_user.clone(),
            password,
            csr_der: csr,
        })
        .await
        .context("sending login")?;
    match reader.next().await {
        Some(Ok(WatchdogEvent::Issued { cert_der, .. })) => {
            identity.set_certificate(cert_der, key)?;
            Ok(())
        }
        Some(Ok(WatchdogEvent::Denied(reason))) => bail!("login refused: {reason}"),
        other => bail!("unexpected reply to login: {other:?}"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let args = &cli.args;
    let config_socket = args
        .config_socket
        .clone()
        .context("--config-socket is required")?;
    let ops = build_ops(args)?;

    log_in(&cli).await?;
    let stream = nos_pki::connect(&config_socket, Role::Configd, "")
        .await
        .with_context(|| format!("connecting to {}", config_socket.display()))?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());

    let txn = "verify".to_string();

    send(
        &mut writer,
        &mut reader,
        Request::OpenTransaction {
            name: txn.clone(),
            base: TransactionBase::Current,
        },
    )
    .await?;

    for op in ops {
        send(
            &mut writer,
            &mut reader,
            Request::ApplyOp {
                name: txn.clone(),
                op,
            },
        )
        .await?;
    }

    send(
        &mut writer,
        &mut reader,
        Request::CommitTransaction {
            name: txn.clone(),
            if_match: None,
        },
    )
    .await?;

    if args.save {
        send(&mut writer, &mut reader, Request::Save).await?;
    }

    println!("provisioning complete");
    Ok(())
}

async fn send(
    writer: &mut FramedWrite<WriteHalf<Stream>, IpcCodec<Request>>,
    reader: &mut FramedRead<ReadHalf<Stream>, IpcCodec<Event>>,
    req: Request,
) -> anyhow::Result<()> {
    let label = format!("{req:?}");
    writer.send(req).await.context("sending request")?;
    match reader.next().await {
        Some(Ok(Event::Error(e))) => bail!("{label} -> error: {e}"),
        Some(Ok(event)) => {
            eprintln!("{label} -> {event:?}");
            Ok(())
        }
        Some(Err(e)) => bail!("{label} -> transport error: {e}"),
        None => bail!("{label} -> connection closed"),
    }
}
