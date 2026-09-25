//! A dedicated, genuinely pipelined netlink client for route add/del.
//!
//! `rtnetlink::Handle`'s background `Connection` task sends exactly one
//! queued netlink message per poll of its own future, then sleeps until an
//! ACK arrives before sending the next (see `netlink-proto`'s
//! `Connection::poll_send_messages`) — so every request funnels through one
//! shared socket strictly one-at-a-time, no matter how many futures a
//! caller buffers concurrently. Measured against `tools/bench-bgp.sh`, that
//! made bounded client-side concurrency alone a no-op (see
//! `target/bench-bgp/kernel-install-bottleneck.md`). `RouteChannel` sends
//! each request directly from the caller's own task (no hop through a
//! shared dispatch task) and matches ACKs back by sequence number as they
//! arrive on one background reader task, so many adds/dels are genuinely
//! in flight over the socket at once.
//!
//! Scoped to `RTM_NEWROUTE`/`RTM_DELROUTE` only — the measured bottleneck.
//! Link/VRF management and route dumps stay on `rtnetlink::Handle`.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::route::RouteMessage;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{protocols::NETLINK_ROUTE, AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket};
use tokio::sync::oneshot;
use tracing::warn;

use super::DriverError;

type PendingMap = HashMap<u32, oneshot::Sender<Result<(), DriverError>>>;

pub struct RouteChannel {
    socket: Arc<TokioSocket>,
    next_seq: AtomicU32,
    /// `None` once the reader task has died (fatal socket error) — a
    /// request arriving after that fails immediately instead of hanging
    /// forever on a `oneshot` no one will ever complete.
    pending: Arc<Mutex<Option<PendingMap>>>,
}

impl RouteChannel {
    pub fn new() -> Result<Self, DriverError> {
        let socket = Arc::new(TokioSocket::new(NETLINK_ROUTE).map_err(DriverError::Registry)?);
        let pending: Arc<Mutex<Option<PendingMap>>> = Arc::new(Mutex::new(Some(HashMap::new())));
        tokio::spawn(read_loop(socket.clone(), pending.clone()));
        Ok(Self {
            socket,
            next_seq: AtomicU32::new(1),
            pending,
        })
    }

    pub async fn add(&self, message: RouteMessage) -> Result<(), DriverError> {
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        self.request(RouteNetlinkMessage::NewRoute(message), flags)
            .await
    }

    pub async fn del(&self, message: RouteMessage) -> Result<(), DriverError> {
        let flags = NLM_F_REQUEST | NLM_F_ACK;
        self.request(RouteNetlinkMessage::DelRoute(message), flags)
            .await
    }

    async fn request(&self, payload: RouteNetlinkMessage, flags: u16) -> Result<(), DriverError> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut msg = NetlinkMessage::from(payload);
        msg.header.sequence_number = seq;
        msg.header.flags = flags;
        msg.finalize();
        let mut buf = vec![0u8; msg.buffer_len()];
        msg.serialize(&mut buf);

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock().unwrap();
            let Some(map) = guard.as_mut() else {
                return Err(DriverError::Registry(io::Error::other(
                    "netlink route channel reader has stopped",
                )));
            };
            map.insert(seq, tx);
        }

        if let Err(e) = self.socket.send_to(&buf, &SocketAddr::new(0, 0)).await {
            if let Some(map) = self.pending.lock().unwrap().as_mut() {
                map.remove(&seq);
            }
            return Err(DriverError::Registry(e));
        }

        rx.await.unwrap_or_else(|_| {
            Err(DriverError::Registry(io::Error::other(
                "netlink route channel reader has stopped",
            )))
        })
    }
}

async fn read_loop(socket: Arc<TokioSocket>, pending: Arc<Mutex<Option<PendingMap>>>) {
    loop {
        let bytes = match socket.recv_from_full().await {
            Ok((bytes, _addr)) => bytes,
            Err(e) => {
                warn!(error = %e, "netlink route channel read failed, stopping");
                if let Some(map) = pending.lock().unwrap().take() {
                    for (_, tx) in map {
                        let _ = tx.send(Err(DriverError::Registry(io::Error::other(format!(
                            "netlink route socket read failed: {e}"
                        )))));
                    }
                }
                return;
            }
        };

        let mut offset = 0;
        while offset < bytes.len() {
            let msg = match NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes[offset..]) {
                Ok(msg) => msg,
                Err(e) => {
                    warn!(error = %e, "failed to parse netlink route ack, dropping rest of datagram");
                    break;
                }
            };
            offset += msg.header.length as usize;

            let seq = msg.header.sequence_number;
            let tx = {
                let mut guard = pending.lock().unwrap();
                guard.as_mut().and_then(|map| map.remove(&seq))
            };
            let Some(tx) = tx else { continue };

            let result = match msg.payload {
                NetlinkPayload::Error(err) if err.code.is_none() => Ok(()),
                NetlinkPayload::Error(err) => {
                    Err(DriverError::Netlink(rtnetlink::Error::NetlinkError(err)))
                }
                _ => Ok(()),
            };
            let _ = tx.send(result);
        }
    }
}
