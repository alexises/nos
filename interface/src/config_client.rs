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

type Reader = FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<Event>>;

/// One-shot fetch of the current running config, its own connection closed
/// after use. Mirrors `nos-rib`'s `config_client::fetch_config`, but
/// reimplemented here rather than imported — component crates form a star
/// around `nos-proto`, never depending on each other.
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
/// **trigger** — the caller never inspects a diff's content, only the fact
/// that an event arrived; the actual config content always comes from a
/// fresh `fetch_config` call (see `crate::reconcile` for why).
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
