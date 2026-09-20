//! One generic request/reply call over a daemon's Unix socket, replacing a
//! per-daemon client module: every query here is "send one request, read one
//! event" framed by `IpcCodec`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{Config, Event, IpcCodec, Request, ServiceRef};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::error::{ApiError, ApiResult};
use crate::watchdog_client::resolve_once;

/// Shared by every handler: where to find `nos-configd` (resolved once at
/// startup) and the broker used to find everything else, per request.
#[derive(Clone)]
pub struct Daemons {
    pub watchdog_socket: Arc<PathBuf>,
    pub config_socket: Arc<PathBuf>,
}

/// Sends `req` to `socket` and returns the first event of the reply.
pub async fn call<Req, Ev>(socket: &Path, req: Req) -> ApiResult<Ev>
where
    Req: Serialize,
    Ev: DeserializeOwned,
{
    let stream = UnixStream::connect(socket).await.map_err(|e| {
        ApiError::Unavailable(format!("cannot reach daemon at {}: {e}", socket.display()))
    })?;
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<Ev>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Req>::default());
    writer
        .send(req)
        .await
        .map_err(|e| ApiError::Unavailable(format!("sending request failed: {e}")))?;
    match reader.next().await {
        Some(Ok(ev)) => Ok(ev),
        Some(Err(e)) => Err(ApiError::BadGateway(format!("bad reply: {e}"))),
        None => Err(ApiError::Unavailable(
            "daemon closed the connection without replying".to_string(),
        )),
    }
}

/// Sends `req` and hands back the still-open connection, for a daemon reply
/// that keeps streaming (`LogRequest::Tail`). The write half must be kept
/// alive for as long as the stream is read: the daemon treats a closed
/// connection as the client leaving.
pub async fn open_stream<Req, Ev>(
    socket: &Path,
    req: Req,
) -> ApiResult<(
    FramedRead<OwnedReadHalf, IpcCodec<Ev>>,
    FramedWrite<OwnedWriteHalf, IpcCodec<Req>>,
)>
where
    Req: Serialize,
    Ev: DeserializeOwned,
{
    let stream = UnixStream::connect(socket).await.map_err(|e| {
        ApiError::Unavailable(format!("cannot reach daemon at {}: {e}", socket.display()))
    })?;
    let (r, w) = stream.into_split();
    let reader = FramedRead::new(r, IpcCodec::<Ev>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Req>::default());
    writer
        .send(req)
        .await
        .map_err(|e| ApiError::Unavailable(format!("sending request failed: {e}")))?;
    Ok((reader, writer))
}

impl Daemons {
    /// Resolves `service` through the watchdog broker, then `call`s it.
    pub async fn service<Req, Ev>(&self, service: ServiceRef, req: Req) -> ApiResult<Ev>
    where
        Req: Serialize,
        Ev: DeserializeOwned,
    {
        let socket = resolve_once(&self.watchdog_socket, &service)
            .await
            .ok_or_else(|| ApiError::Unavailable(format!("{service:?} is not running")))?;
        call(&socket, req).await
    }

    /// Resolves `service` through the watchdog broker, then `open_stream`s it.
    pub async fn open_stream<Req, Ev>(
        &self,
        service: ServiceRef,
        req: Req,
    ) -> ApiResult<(
        FramedRead<OwnedReadHalf, IpcCodec<Ev>>,
        FramedWrite<OwnedWriteHalf, IpcCodec<Req>>,
    )>
    where
        Req: Serialize,
        Ev: DeserializeOwned,
    {
        let socket = resolve_once(&self.watchdog_socket, &service)
            .await
            .ok_or_else(|| ApiError::Unavailable(format!("{service:?} is not running")))?;
        open_stream(&socket, req).await
    }

    /// One request to `nos-configd`, with its `Event::Error` mapped to a status.
    pub async fn config(&self, req: Request) -> ApiResult<Event> {
        match call::<_, Event>(&self.config_socket, req).await? {
            Event::Error(msg) => Err(ApiError::from_config(msg)),
            ev => Ok(ev),
        }
    }

    /// The running config.
    pub async fn running_config(&self) -> ApiResult<Config> {
        match self.config(Request::Get).await? {
            Event::Config(cfg) => Ok(cfg),
            other => Err(unexpected("nos-configd", &other)),
        }
    }
}

pub fn unexpected(daemon: &str, ev: &impl std::fmt::Debug) -> ApiError {
    ApiError::BadGateway(format!("{daemon} sent an unexpected reply: {ev:?}"))
}
