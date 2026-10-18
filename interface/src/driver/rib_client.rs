use std::path::Path;

use nos_daemon::ipc::one_shot;
use nos_proto::{RibEvent, RibRequest, Role};
use tracing::trace;

/// One-shot query of a `nos-ribd` instance's Linux VRF interface name.
///
/// Best-effort by design: this is polled on every reconcile pass (see
/// `driver::linux::LinuxInterfaceDriver::resolve_vrf_name`), and "no answer
/// yet" (connection refused, the daemon hasn't created a VRF, an
/// unexpected/malformed reply) is a normal, frequently-recurring condition
/// during that table's `nos-ribd` startup or restart — never worth
/// surfacing as an error to the caller, which just retries next tick. Only
/// a well-formed `RibEvent::VrfName` reply is distinguished from that.
pub async fn get_vrf_name(rib_socket: &Path) -> Option<String> {
    if let RibEvent::VrfName(name) =
        one_shot(rib_socket, Role::Ribd, RibRequest::GetVrfName).await?
    {
        name
    } else {
        trace!("nos-ribd gave no well-formed GetVrfName reply");
        None
    }
}

/// One-shot query of a `nos-ribd` instance's allocated kernel table id.
/// Symmetric to `get_vrf_name` — same best-effort, "no answer yet is
/// normal" contract.
pub async fn get_table_id(rib_socket: &Path) -> Option<u32> {
    if let RibEvent::TableId(id) = one_shot(rib_socket, Role::Ribd, RibRequest::GetTableId).await? {
        id
    } else {
        trace!("nos-ribd gave no well-formed GetTableId reply");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use nos_proto::IpcCodec;
    use tokio_util::codec::{FramedRead, FramedWrite};

    fn serve_once(path: &Path, reply: impl Fn(RibRequest) -> Option<RibEvent> + Send + 'static) {
        let listener = nos_pki::testing::shared()
            .identity("ribd", "rt1")
            .listen(path)
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (r, w) = tokio::io::split(stream);
            let mut reader = FramedRead::new(r, IpcCodec::<RibRequest>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<RibEvent>::default());
            if let Some(Ok(req)) = reader.next().await
                && let Some(event) = reply(req)
            {
                let _ = writer.send(event).await;
            }
        });
        // Give the accept loop a chance to bind/register before the client
        // connects — bind() above already happened synchronously, so the
        // socket file exists by the time this function returns; no sleep
        // needed.
    }

    #[tokio::test]
    async fn returns_vrf_name_on_well_formed_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        serve_once(&path, |_req| {
            Some(RibEvent::VrfName(Some("vrf100".to_string())))
        });

        let name = get_vrf_name(&path).await;
        assert_eq!(name.as_deref(), Some("vrf100"));
    }

    #[tokio::test]
    async fn returns_none_when_rib_has_no_vrf_yet() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        serve_once(&path, |_req| Some(RibEvent::VrfName(None)));

        let name = get_vrf_name(&path).await;
        assert_eq!(name, None);
    }

    #[tokio::test]
    async fn returns_none_on_unexpected_variant() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        serve_once(&path, |_req| Some(RibEvent::NoMatch));

        let name = get_vrf_name(&path).await;
        assert_eq!(name, None);
    }

    #[tokio::test]
    async fn returns_none_when_connection_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.sock");

        let name = get_vrf_name(&path).await;
        assert_eq!(name, None);
    }

    #[tokio::test]
    async fn returns_none_when_server_closes_without_replying() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        let listener = nos_pki::testing::shared()
            .identity("ribd", "rt1")
            .listen(&path)
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            drop(stream);
        });

        let name = get_vrf_name(&path).await;
        assert_eq!(name, None);
    }

    #[tokio::test]
    async fn table_id_returns_id_on_well_formed_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        serve_once(&path, |_req| Some(RibEvent::TableId(Some(100))));

        let id = get_table_id(&path).await;
        assert_eq!(id, Some(100));
    }

    #[tokio::test]
    async fn table_id_returns_none_when_rib_has_no_id_yet() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        serve_once(&path, |_req| Some(RibEvent::TableId(None)));

        let id = get_table_id(&path).await;
        assert_eq!(id, None);
    }

    #[tokio::test]
    async fn table_id_returns_none_on_unexpected_variant() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        serve_once(&path, |_req| Some(RibEvent::NoMatch));

        let id = get_table_id(&path).await;
        assert_eq!(id, None);
    }

    #[tokio::test]
    async fn table_id_returns_none_when_connection_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.sock");

        let id = get_table_id(&path).await;
        assert_eq!(id, None);
    }

    #[tokio::test]
    async fn table_id_returns_none_when_server_closes_without_replying() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        let listener = nos_pki::testing::shared()
            .identity("ribd", "rt1")
            .listen(&path)
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            drop(stream);
        });

        let id = get_table_id(&path).await;
        assert_eq!(id, None);
    }
}
