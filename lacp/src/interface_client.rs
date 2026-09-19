//! Owns the persistent push connection to `nos-interfaced`
//! (`InterfaceRequest::PushLacpMembers`) — the data-plane push counterpart
//! of `bgp::rib_push_client`, simplified to full-resend-only (see
//! `nos_proto::interface::LacpAggregateMembers`'s doc comment for why no
//! `Full`/`Add`/`Remove` split is needed here). Every currently-known
//! aggregate's active-member set is cached locally and resent in full on
//! every fresh connection (covers both "we just reconnected" and, since the
//! very first connection attempt starts from an empty cache, "there's
//! nothing to send yet") as well as on every individual change.

use std::collections::HashMap;
use std::path::PathBuf;

use futures::SinkExt;
use nos_proto::{InterfaceRequest, IpcCodec, LacpAggregateMembers, ServiceRef};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};
use tokio_util::codec::FramedWrite;
use tracing::{info, warn};

/// Fixed reconnect delay, matching every other reconnect loop in this
/// codebase.
const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Runs for the process's lifetime: connects to `nos-interfaced` (resolved
/// via `ServiceRef::Interfaces`), resending every cached aggregate's
/// current state on connect, and forwarding each further update from `rx`
/// as it arrives — reconnecting on a fixed 1s delay if the connection
/// drops.
pub async fn run(
    watchdog_socket: PathBuf,
    mut rx: mpsc::Receiver<LacpAggregateMembers>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut cache: HashMap<String, Vec<String>> = HashMap::new();
    let mut writer: Option<
        FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<InterfaceRequest>>,
    > = None;

    loop {
        if writer.is_none() {
            let Some(socket) = crate::watchdog_client::resolve_with_retry(
                &watchdog_socket,
                ServiceRef::Interfaces,
                &mut shutdown,
            )
            .await
            else {
                return;
            };
            match UnixStream::connect(&socket).await {
                Ok(stream) => {
                    let (_r, w) = stream.into_split();
                    let mut w = FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default());
                    let mut ok = true;
                    for (aggregate, active_members) in &cache {
                        if send_push(&mut w, aggregate.clone(), active_members.clone())
                            .await
                            .is_err()
                        {
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        info!("lacp connected to nos-interfaced, resent cached aggregate state");
                        writer = Some(w);
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to connect to nos-interfaced, retrying");
                }
            }
            if writer.is_none() {
                if wait_or_shutdown(RECONNECT_DELAY, &mut shutdown).await {
                    return;
                }
                continue;
            }
        }

        tokio::select! {
            msg = rx.recv() => {
                let Some(msg) = msg else { return };
                cache.insert(msg.aggregate.clone(), msg.active_members.clone());
                if let Some(w) = writer.as_mut() {
                    if send_push(w, msg.aggregate, msg.active_members).await.is_err() {
                        writer = None;
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

async fn send_push(
    writer: &mut FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<InterfaceRequest>>,
    aggregate: String,
    active_members: Vec<String>,
) -> std::io::Result<()> {
    writer
        .send(InterfaceRequest::PushLacpMembers(LacpAggregateMembers {
            aggregate,
            active_members,
        }))
        .await
}

async fn wait_or_shutdown(
    delay: std::time::Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}
