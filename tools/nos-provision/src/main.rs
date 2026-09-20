//! One-shot config provisioning tool: speaks nos-configd's IPC protocol
//! directly (nos-cli's interactive shell can't be driven over a plain pipe).
//! The op list itself lives in `nos_provision::build_ops`; this bin only
//! opens a transaction, applies it, commits, and (with `--save`) persists.
//! Still used by `tools/bench-bgp.sh`; `tools/e2e` reuses `build_ops` and
//! provisions over the REST API instead.

use anyhow::{bail, Context};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use nos_proto::{Event, IpcCodec, Request, TransactionBase};
use nos_provision::{build_ops, Args};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config_socket = args
        .config_socket
        .clone()
        .context("--config-socket is required")?;
    let ops = build_ops(&args)?;

    let stream = UnixStream::connect(&config_socket)
        .await
        .with_context(|| format!("connecting to {}", config_socket.display()))?;
    let (r, w) = stream.into_split();
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
        Request::CommitTransaction { name: txn.clone() },
    )
    .await?;

    if args.save {
        send(&mut writer, &mut reader, Request::Save).await?;
    }

    println!("provisioning complete");
    Ok(())
}

async fn send(
    writer: &mut FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<Request>>,
    reader: &mut FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<Event>>,
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
