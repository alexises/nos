//! Generic best-effort one-shot request/reply against another daemon.

use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, Role};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::trace;

/// Connects to `socket` as a client of `role`, sends `req`, reads one reply.
///
/// Best-effort by design: callers poll this every reconcile tick, and "no
/// answer yet" (refused, closed, malformed reply) is a normal, recurring
/// condition, so every failure is a `trace!` and `None`. Callers match the
/// reply variant they expect.
pub async fn one_shot<Req, Ev>(socket: &Path, role: Role, req: Req) -> Option<Ev>
where
    Req: Serialize,
    Ev: DeserializeOwned,
{
    let Ok(stream) = nos_pki::connect_role(socket, role).await else {
        trace!(socket = %socket.display(), ?role, "one-shot connect failed");
        return None;
    };
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<Ev>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Req>::default());
    if writer.send(req).await.is_err() {
        trace!(socket = %socket.display(), ?role, "one-shot send failed");
        return None;
    }
    if let Some(Ok(ev)) = reader.next().await {
        Some(ev)
    } else {
        trace!(socket = %socket.display(), ?role, "one-shot got no well-formed reply");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    type Reply = Box<
        dyn FnOnce(tokio::io::WriteHalf<nos_pki::Stream>) -> futures::future::BoxFuture<'static, ()>
            + Send,
    >;

    fn serve(path: &Path, reply: Reply) {
        let listener = nos_pki::testing::shared()
            .identity("ribd", "rt1")
            .listen(path)
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (mut r, w) = tokio::io::split(stream);
            let mut buf = [0u8; 64];
            let _ = tokio::io::AsyncReadExt::read(&mut r, &mut buf).await;
            reply(w).await;
        });
    }

    #[tokio::test]
    async fn returns_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("s.sock");
        serve(
            &p,
            Box::new(|w| {
                Box::pin(async move {
                    let mut wr = FramedWrite::new(w, IpcCodec::<u32>::default());
                    let _ = wr.send(7).await;
                })
            }),
        );
        assert_eq!(one_shot::<u32, u32>(&p, Role::Ribd, 1).await, Some(7));
    }

    #[tokio::test]
    async fn refused_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nope.sock");
        assert_eq!(one_shot::<u32, u32>(&p, Role::Ribd, 1).await, None);
    }

    #[tokio::test]
    async fn malformed_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("s.sock");
        serve(
            &p,
            Box::new(|mut w| {
                Box::pin(async move {
                    // Frame announcing 1 byte holding an invalid bool.
                    let _ = w.write_all(&[1, 0, 0, 0, 9]).await;
                    let _ = w.flush().await;
                    // Keep the stream open long enough to be read.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                })
            }),
        );
        assert_eq!(one_shot::<u32, bool>(&p, Role::Ribd, 1).await, None);
    }

    #[tokio::test]
    async fn closed_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("s.sock");
        serve(&p, Box::new(|_w| Box::pin(async {})));
        assert_eq!(one_shot::<u32, u32>(&p, Role::Ribd, 1).await, None);
    }
}
