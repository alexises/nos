use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_proto::{
    BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec, Role,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::trace;

/// One-shot queries of `nos-interfaced` for the addresses it applied — the
/// input to `reconcile::connected_entries`. Best-effort like
/// `nos-bgp`'s `interface_client`: "no answer" (not up yet, refused, a
/// malformed reply) is a normal transient condition, and the caller keeps
/// its previous `Connected` set until the next resync.
async fn query(interface_socket: &Path, request: InterfaceRequest) -> Option<InterfaceEvent> {
    let Ok(stream) = nos_pki::connect(interface_socket, Role::Interfaced, "").await else {
        trace!(socket = %interface_socket.display(), "failed to connect to nos-interfaced");
        return None;
    };
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<InterfaceEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default());
    writer.send(request).await.ok()?;
    reader.next().await?.ok()
}

/// Every interface as `nos-interfaced` currently sees it.
pub async fn get_interfaces(interface_socket: &Path) -> Option<Vec<InterfaceStatus>> {
    match query(interface_socket, InterfaceRequest::GetInterfaces).await? {
        InterfaceEvent::Interfaces(list) => Some(list),
        _ => None,
    }
}

/// One broadcast domain's SVI addressing.
pub async fn get_broadcast_domain(
    interface_socket: &Path,
    name: &str,
) -> Option<BroadcastDomainStatus> {
    let request = InterfaceRequest::GetBroadcastDomain {
        name: name.to_string(),
    };
    match query(interface_socket, request).await? {
        InterfaceEvent::BroadcastDomain(status) => Some(status),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve_once(
        path: &Path,
        reply: impl Fn(InterfaceRequest) -> InterfaceEvent + Send + 'static,
    ) {
        let listener = nos_pki::testing::shared()
            .identity("interfaced", "")
            .listen(path)
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (r, w) = tokio::io::split(stream);
            let mut reader = FramedRead::new(r, IpcCodec::<InterfaceRequest>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceEvent>::default());
            if let Some(Ok(req)) = reader.next().await {
                let _ = writer.send(reply(req)).await;
            }
        });
    }

    #[tokio::test]
    async fn interfaces_and_domain_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_| InterfaceEvent::Interfaces(vec![]));
        assert_eq!(get_interfaces(&path).await, Some(vec![]));

        let path = tmp.path().join("interface2.sock");
        serve_once(&path, |req| match req {
            InterfaceRequest::GetBroadcastDomain { name } => {
                InterfaceEvent::BroadcastDomain(BroadcastDomainStatus {
                    name,
                    addresses: vec![],
                    routing_table: Some("rt1".into()),
                    link_local_address: None,
                    bridge_name: None,
                })
            }
            _ => InterfaceEvent::NotFound,
        });
        let domain = get_broadcast_domain(&path, "bd1").await.unwrap();
        assert_eq!(domain.name, "bd1");
    }

    #[tokio::test]
    async fn not_found_and_unreachable_are_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_| InterfaceEvent::NotFound);
        assert_eq!(get_broadcast_domain(&path, "bd1").await, None);
        assert_eq!(get_interfaces(&tmp.path().join("missing.sock")).await, None);
    }
}
