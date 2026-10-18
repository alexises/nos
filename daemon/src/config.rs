//! `nos-configd` clients: a one-shot config fetch and a diff subscription.

use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_proto::{Config, DiffScope, Event, IpcCodec, Request, Role};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum ConfigClientError {
    #[error("i/o error talking to nos-configd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-configd reported an error: {0}")]
    Daemon(String),
    #[error("connection to nos-configd closed unexpectedly")]
    ConnectionClosed,
}

/// Event stream of a [`subscribe_diff`] connection.
pub type Reader = FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<Event>>;

/// One-shot fetch of the current running config, its own connection closed
/// after use.
pub async fn fetch_config(socket_path: &Path) -> Result<Config, ConfigClientError> {
    let stream = nos_pki::connect(socket_path, Role::Configd, "").await?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
    writer.send(Request::Get).await?;
    match reader.next().await {
        Some(Ok(Event::Config(cfg))) => Ok(cfg),
        Some(Ok(Event::Error(msg))) => Err(ConfigClientError::Daemon(msg)),
        Some(Ok(_)) => Err(ConfigClientError::Daemon(
            "unexpected event in reply to Get".to_string(),
        )),
        Some(Err(e)) => Err(ConfigClientError::Io(e)),
        None => Err(ConfigClientError::ConnectionClosed),
    }
}

/// Subscribes to diff events for `scopes`. Used purely as a resync
/// **trigger**: the caller never inspects a diff's content, only the fact
/// that an event arrived; the config itself always comes from a fresh
/// [`fetch_config`].
pub async fn subscribe_diff(
    socket_path: &Path,
    scopes: Vec<DiffScope>,
) -> Result<Reader, ConfigClientError> {
    let stream = nos_pki::connect(socket_path, Role::Configd, "").await?;
    let (r, w) = tokio::io::split(stream);
    let reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
    writer.send(Request::SubscribeDiff { scopes }).await?;
    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve_once(path: &Path, reply: Option<Event>) {
        let listener = nos_pki::testing::shared()
            .identity("configd", "")
            .listen(path)
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (r, w) = tokio::io::split(stream);
            let mut reader = FramedRead::new(r, IpcCodec::<Request>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<Event>::default());
            let _ = reader.next().await;
            if let Some(e) = reply {
                let _ = writer.send(e).await;
            }
        });
    }

    #[tokio::test]
    async fn fetch_returns_config() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.sock");
        serve_once(&p, Some(Event::Config(Config::default())));
        assert!(fetch_config(&p).await.is_ok());
    }

    #[tokio::test]
    async fn fetch_maps_error_event() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.sock");
        serve_once(&p, Some(Event::Error("boom".into())));
        assert!(matches!(
            fetch_config(&p).await,
            Err(ConfigClientError::Daemon(m)) if m == "boom"
        ));
    }

    #[tokio::test]
    async fn fetch_maps_unexpected_event() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.sock");
        serve_once(&p, Some(Event::Saved));
        assert!(matches!(
            fetch_config(&p).await,
            Err(ConfigClientError::Daemon(_))
        ));
    }

    #[tokio::test]
    async fn fetch_maps_close() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.sock");
        serve_once(&p, None);
        assert!(matches!(
            fetch_config(&p).await,
            Err(ConfigClientError::ConnectionClosed)
        ));
    }

    #[tokio::test]
    async fn fetch_refused_is_io() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nope.sock");
        assert!(matches!(
            fetch_config(&p).await,
            Err(ConfigClientError::Io(_))
        ));
    }

    #[tokio::test]
    async fn subscribe_yields_events() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.sock");
        serve_once(&p, Some(Event::Saved));
        let mut r = subscribe_diff(&p, vec![DiffScope::OspfInstances])
            .await
            .unwrap();
        assert!(matches!(r.next().await, Some(Ok(Event::Saved))));
    }
}
