//! `--listen-socket`: clients `Register` sessions on a persistent connection
//! and are streamed `BfdEvent::State` (the current state first, then every
//! change); `GetSessions` is answered once. A connection that goes away
//! releases everything it registered.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{BfdEvent, BfdRequest, IpcCodec, Role, SessionKey};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, warn};

use crate::authz::allowed;
use crate::manager::Manager;
use crate::session::Status;

pub fn start(
    listen_socket: &Path,
    manager: Arc<Manager>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "bfd IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, manager)))
}

async fn accept_loop(listener: Listener, manager: Arc<Manager>) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, manager.clone()));
            }
            Err(e) => {
                error!(error = %e, "bfd IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn serve(incoming: Incoming, manager: Arc<Manager>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, &name, manager).await,
        Err(e) => debug!(error = %e, "bfd IPC handshake refused"),
    }
}

/// Streams a session's state to the connection's writer: the current one
/// first, then every change of (state, diag).
async fn forward(key: SessionKey, mut rx: watch::Receiver<Status>, out: mpsc::Sender<BfdEvent>) {
    let mut last = None;
    loop {
        let s = *rx.borrow_and_update();
        let now = (s.state, s.diag, s.control_plane_independent);
        if last != Some(now) {
            last = Some(now);
            let ev = BfdEvent::State {
                key: key.clone(),
                state: s.state,
                diag: s.diag,
                control_plane_independent: s.control_plane_independent,
            };
            if out.send(ev).await.is_err() || rx.changed().await.is_err() {
                return;
            }
        } else if rx.changed().await.is_err() {
            return;
        }
    }
}

fn key_of(req: &BfdRequest) -> Option<SessionKey> {
    match req {
        BfdRequest::Register {
            table,
            peer,
            local,
            interface,
            multihop,
            ..
        } => Some(SessionKey {
            aggregate: None,
            table: table.clone(),
            peer: *peer,
            local: *local,
            interface: interface.clone(),
            multihop: *multihop,
        }),
        BfdRequest::Deregister { key } => Some(key.clone()),
        BfdRequest::GetSessions { .. } => None,
    }
}

async fn handle_connection(stream: Stream, role: Role, name: &str, manager: Arc<Manager>) {
    let client = manager.new_client();
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<BfdRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<BfdEvent>::default());
    let (out_tx, mut out_rx) = mpsc::channel::<BfdEvent>(64);
    let mut forwarders: HashMap<SessionKey, JoinHandle<()>> = HashMap::new();

    loop {
        tokio::select! {
            msg = reader.next() => {
                // ponytail: request-side EOF ends the connection (clients
                // keep their write half open, `rib/src/bfd_client.rs`);
                // a client that half-closes would need the config
                // subscribers' "keep until a write fails" rule instead.
                let Some(Ok(req)) = msg else { break };
                if !allowed(role, &req) {
                    warn!(role = role.as_str(), name, "bfd request refused: this role may not send it");
                    break;
                }
                match &req {
                    BfdRequest::Register { profile, .. } => {
                        let key = key_of(&req).expect("register has a key");
                        let rx = manager.register(client, &key, profile);
                        if let Some(old) = forwarders.insert(key.clone(), tokio::spawn(forward(key, rx, out_tx.clone()))) {
                            old.abort();
                        }
                    }
                    BfdRequest::Deregister { key } => {
                        if let Some(f) = forwarders.remove(key) {
                            f.abort();
                        }
                        manager.deregister(client, key);
                    }
                    BfdRequest::GetSessions { peer } => {
                        if writer.send(BfdEvent::Sessions(manager.sessions(*peer))).await.is_err() {
                            break;
                        }
                    }
                }
            }
            Some(ev) = out_rx.recv() => {
                if writer.send(ev).await.is_err() {
                    break;
                }
            }
        }
    }
    for f in forwarders.into_values() {
        f.abort();
    }
    manager.drop_client(client);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::tests::mgr;
    use nos_pki::PeerId;
    use nos_proto::schema::BfdProfile;
    use nos_proto::BfdState;
    use std::time::Duration;

    type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<BfdEvent>>;
    type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<BfdRequest>>;

    async fn connect(path: &Path, role: &str) -> (Reader, Writer) {
        let id = nos_pki::testing::shared().identity(role, "x");
        let s = id.connect(path, &PeerId::new("bfdd", "")).await.unwrap();
        let (r, w) = tokio::io::split(s);
        (
            FramedRead::new(r, IpcCodec::default()),
            FramedWrite::new(w, IpcCodec::default()),
        )
    }

    fn register(peer: &str) -> BfdRequest {
        BfdRequest::Register {
            table: "rt1".into(),
            peer: peer.parse().unwrap(),
            local: None,
            interface: None,
            profile: BfdProfile::default(),
            multihop: false,
        }
    }

    #[tokio::test]
    async fn register_streams_state_and_disconnect_releases() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bfd.sock");
        let (m, _, _) = mgr(false);
        let id = nos_pki::testing::shared().identity("bfdd", "");
        let _server = start(&path, m.clone(), &id).unwrap();

        let (mut r, mut w) = connect(&path, "ribd").await;
        w.send(register("192.0.2.1")).await.unwrap();
        let Some(Ok(BfdEvent::State { key, state, .. })) = r.next().await else {
            panic!("no initial state");
        };
        assert_eq!(
            (key.peer.to_string().as_str(), state),
            ("192.0.2.1", BfdState::Down)
        );
        assert_eq!(m.sessions(None).len(), 1);

        // A second client asks, then the first deregisters explicitly.
        let (mut r2, mut w2) = connect(&path, "user").await;
        w2.send(BfdRequest::GetSessions { peer: None })
            .await
            .unwrap();
        let Some(Ok(BfdEvent::Sessions(v))) = r2.next().await else {
            panic!("no sessions");
        };
        assert_eq!(v.len(), 1);

        w.send(BfdRequest::Deregister { key }).await.unwrap();
        w.send(register("192.0.2.2")).await.unwrap();
        let _ = r.next().await;
        drop((r, w));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !m.sessions(None).is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("connection drop released the sessions");
    }

    #[tokio::test]
    async fn refused_role_gets_the_connection_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bfd.sock");
        let (m, _, _) = mgr(false);
        let id = nos_pki::testing::shared().identity("bfdd", "");
        let _server = start(&path, m.clone(), &id).unwrap();

        // `user` may query, not register.
        let (mut r, mut w) = connect(&path, "user").await;
        w.send(register("192.0.2.1")).await.unwrap();
        assert!(r.next().await.is_none());
        assert_eq!(m.sessions(None).len(), 0);
    }
}
