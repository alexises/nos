use std::path::Path;

use nos_daemon::ipc::one_shot;
use nos_proto::{RibEvent, RibRequest, Role};

/// One-shot query of a `nos-ribd` instance's Linux VRF interface name.
///
/// Best-effort by design: this is polled on every reconcile pass (see
/// `crate::reconcile`), and "no answer yet" (connection refused, the daemon
/// hasn't created a VRF, an unexpected/malformed reply) is a normal,
/// frequently-recurring condition during that table's `nos-ribd` startup or
/// restart — never worth surfacing as an error to the caller, which just
/// retries next tick. Only a well-formed `RibEvent::VrfName` reply is
/// distinguished from that.
pub async fn get_vrf_name(rib_socket: &Path) -> Option<String> {
    match one_shot(rib_socket, Role::Ribd, RibRequest::GetVrfName).await {
        Some(RibEvent::VrfName(name)) => name,
        _ => None,
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
    async fn returns_none_when_connection_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.sock");

        let name = get_vrf_name(&path).await;
        assert_eq!(name, None);
    }
}
