//! Binds `--listen-socket` and serves `AclRequest::Show` from the engine's
//! live state: backs `show acl` and `GET /v1/acl`. Mirrors `nos-lldp`'s
//! `server.rs`.

use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{AclEvent, AclRequest, IpcCodec, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::driver::Driver;
use crate::engine::Shared;

pub fn start<D: Driver>(
    listen_socket: &Path,
    engine: Shared<D>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "acl IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, engine)))
}

/// Every request is a read-only query: for people, and `Restd` on their
/// behalf.
pub fn allowed(role: Role, request: &AclRequest) -> bool {
    match request {
        AclRequest::Show { .. } => matches!(role, Role::User | Role::Restd),
    }
}

async fn accept_loop<D: Driver>(listener: Listener, engine: Shared<D>) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, engine.clone()));
            }
            Err(e) => {
                error!(error = %e, "acl IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn serve<D: Driver>(incoming: Incoming, engine: Shared<D>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, &name, engine).await,
        Err(e) => debug!(error = %e, "acl IPC handshake refused"),
    }
}

async fn handle_connection<D: Driver>(stream: Stream, role: Role, peer: &str, engine: Shared<D>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<AclRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<AclEvent>::default());

    while let Some(msg) = reader.next().await {
        let request = match msg {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "acl IPC read error");
                break;
            }
        };
        if !allowed(role, &request) {
            warn!(role = role.as_str(), name = %peer, "acl query refused: this role may not send it");
            break;
        }
        let AclRequest::Show { name } = request;
        trace!(?name, "serving acl query");
        let engine = engine.clone();
        // Counters are a blocking netlink dump taken under the engine lock.
        let Ok(acls) =
            tokio::task::spawn_blocking(move || engine.lock().unwrap().show(name.as_deref())).await
        else {
            break;
        };
        if writer.send(AclEvent::Acls(acls)).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use nos_pki::PeerId;

    use super::*;
    use crate::driver::NoopDriver;
    use crate::engine::Engine;

    #[test]
    fn only_people_may_query() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &AclRequest::Show { name: None }),
                matches!(role, Role::User | Role::Restd),
                "{role:?}"
            );
        }
    }

    /// A refused role has the connection closed with no frame; an allowed
    /// one gets a (here empty) reply.
    #[tokio::test]
    async fn serves_people_and_closes_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("acl.sock");
        let engine = Arc::new(Mutex::new(Engine::new(NoopDriver::default())));
        let id = nos_pki::testing::shared().identity("acld", "");
        let _server = start(&path, engine, &id).unwrap();

        for role in Role::ALL {
            let id = nos_pki::testing::shared().identity(role.as_str(), "x");
            let s = id.connect(&path, &PeerId::new("acld", "")).await.unwrap();
            let (r, w) = tokio::io::split(s);
            let mut r = FramedRead::new(r, IpcCodec::<AclEvent>::default());
            let mut w = FramedWrite::new(w, IpcCodec::<AclRequest>::default());
            w.send(AclRequest::Show { name: None }).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(5), r.next())
                .await
                .unwrap_or_else(|_| panic!("{role:?}: connection left open"));
            if matches!(role, Role::User | Role::Restd) {
                let Some(Ok(AclEvent::Acls(a))) = reply else {
                    panic!("{role:?}: no reply");
                };
                assert_eq!(a.len(), 0);
            } else {
                assert!(reply.is_none(), "{role:?} must get no reply");
            }
        }
    }
}
