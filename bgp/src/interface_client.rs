use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_proto::{InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::trace;

/// One-shot query of `nos-interfaced` for one named interface's reconciled
/// addresses.
///
/// Best-effort by design, mirroring `crate::rib_client::get_vrf_name`: this
/// is polled on every reconcile pass (see
/// `crate::reconcile::resolve_source_address`), and "no answer yet"
/// (connection refused, the interface isn't configured yet, an unexpected or
/// malformed reply) is a normal, frequently-recurring condition — never
/// worth surfacing as an error to the caller, which just retries next tick.
/// Only a well-formed `InterfaceEvent::Interface` reply is distinguished
/// from that.
pub async fn get_interface(interface_socket: &Path, name: &str) -> Option<InterfaceStatus> {
    let Ok(stream) = UnixStream::connect(interface_socket).await else {
        trace!(socket = %interface_socket.display(), "failed to connect to nos-interfaced");
        return None;
    };
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<InterfaceEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default());
    writer
        .send(InterfaceRequest::GetInterface {
            name: name.to_string(),
        })
        .await
        .ok()?;
    if let Some(Ok(InterfaceEvent::Interface(status))) = reader.next().await {
        Some(status)
    } else {
        trace!(
            name,
            "nos-interfaced gave no well-formed GetInterface reply"
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::InterfaceAddress;
    use tokio::net::UnixListener;

    fn serve_once(
        path: &Path,
        reply: impl Fn(InterfaceRequest) -> Option<InterfaceEvent> + Send + 'static,
    ) {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (r, w) = stream.into_split();
            let mut reader = FramedRead::new(r, IpcCodec::<InterfaceRequest>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceEvent>::default());
            if let Some(Ok(req)) = reader.next().await {
                if let Some(event) = reply(req) {
                    let _ = writer.send(event).await;
                }
            }
        });
    }

    #[tokio::test]
    async fn returns_status_on_well_formed_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_req| {
            Some(InterfaceEvent::Interface(InterfaceStatus {
                name: "eth0".to_string(),
                addresses: vec![InterfaceAddress {
                    address: "10.0.0.1/24".parse().unwrap(),
                    label: None,
                }],
                routing_table: None,
                switching_profile: None,
                subinterfaces: vec![],
            }))
        });

        let status = get_interface(&path, "eth0").await.unwrap();
        assert_eq!(status.name, "eth0");
    }

    #[tokio::test]
    async fn returns_none_when_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_req| Some(InterfaceEvent::NotFound));

        assert_eq!(get_interface(&path, "eth0").await, None);
    }

    #[tokio::test]
    async fn returns_none_when_connection_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.sock");

        assert_eq!(get_interface(&path, "eth0").await, None);
    }
}
