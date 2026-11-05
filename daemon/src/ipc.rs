//! Generic best-effort one-shot request/reply against another daemon.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, Role};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::trace;

/// Why a [`request`] got no reply.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("could not connect to {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection closed before a reply")]
    Closed,
    #[error("no reply within {0:?}")]
    Timeout(Duration),
}

/// Bound on the send + reply exchange (the TLS handshake has its own).
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Connects to `socket` as a client of `role`, sends `req`, reads one reply.
/// Callers match the reply variant they expect.
pub async fn request<Req, Ev>(socket: &Path, role: Role, req: Req) -> Result<Ev, IpcError>
where
    Req: Serialize,
    Ev: DeserializeOwned,
{
    request_within(REPLY_TIMEOUT, socket, role, req).await
}

async fn request_within<Req, Ev>(
    limit: Duration,
    socket: &Path,
    role: Role,
    req: Req,
) -> Result<Ev, IpcError>
where
    Req: Serialize,
    Ev: DeserializeOwned,
{
    let stream = nos_pki::connect_role(socket, role)
        .await
        .map_err(|source| IpcError::Connect {
            path: socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<Ev>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Req>::default());
    let exchange = async {
        writer.send(req).await?;
        match reader.next().await {
            Some(Ok(ev)) => Ok(ev),
            Some(Err(e)) => Err(IpcError::Io(e)),
            None => Err(IpcError::Closed),
        }
    };
    tokio::time::timeout(limit, exchange)
        .await
        .unwrap_or(Err(IpcError::Timeout(limit)))
}

/// [`request`], best-effort: callers poll this every reconcile tick, and "no
/// answer yet" (refused, closed, malformed reply) is a normal, recurring
/// condition, so every failure is a `trace!` and `None`.
pub async fn one_shot<Req, Ev>(socket: &Path, role: Role, req: Req) -> Option<Ev>
where
    Req: Serialize,
    Ev: DeserializeOwned,
{
    match request(socket, role, req).await {
        Ok(ev) => Some(ev),
        Err(e) => {
            trace!(socket = %socket.display(), ?role, error = %e, "one-shot failed");
            None
        }
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

    #[tokio::test]
    async fn silent_server_times_out() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("t.sock");
        serve(
            &p,
            Box::new(|_w| {
                Box::pin(async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                })
            }),
        );
        assert!(matches!(
            request_within::<u32, u32>(Duration::from_millis(100), &p, Role::Ribd, 1).await,
            Err(IpcError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn request_errors_are_typed() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nope.sock");
        assert!(matches!(
            request::<u32, u32>(&p, Role::Ribd, 1).await,
            Err(IpcError::Connect { .. })
        ));
        let p = tmp.path().join("c.sock");
        serve(&p, Box::new(|_w| Box::pin(async {})));
        assert!(matches!(
            request::<u32, u32>(&p, Role::Ribd, 1).await,
            Err(IpcError::Closed)
        ));
        let p = tmp.path().join("m.sock");
        serve(
            &p,
            Box::new(|mut w| {
                Box::pin(async move {
                    let _ = w.write_all(&[1, 0, 0, 0, 9]).await;
                    let _ = w.flush().await;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                })
            }),
        );
        assert!(matches!(
            request::<u32, bool>(&p, Role::Ribd, 1).await,
            Err(IpcError::Io(_))
        ));
    }
}
