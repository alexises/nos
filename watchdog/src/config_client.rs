use std::path::Path;

use futures::SinkExt;
use nos_proto::{DiffScope, Event, IpcCodec, Request};
use tokio::net::unix::OwnedReadHalf;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

type Reader = FramedRead<OwnedReadHalf, IpcCodec<Event>>;

/// Dials `nos-configd`, sends `Request::SubscribeDiff { scopes }`, and
/// returns the reader half for the caller to loop on indefinitely: an
/// initial diff (synthesized against an empty config, so every
/// currently-configured item in `scopes` shows up as `Added`), then one more
/// `Event::Diff` per future commit that touches a requested scope.
///
/// Mirrors `nos-cli`'s `client::subscribe`, but deliberately not shared with
/// it — `nos-watchdog` must not depend on `nos-cli`, a consumer binary, not
/// a shared library.
pub async fn subscribe_diff(socket_path: &Path, scopes: Vec<DiffScope>) -> std::io::Result<Reader> {
    let stream = UnixStream::connect(socket_path).await?;
    let (r, w) = stream.into_split();
    let reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
    writer.send(Request::SubscribeDiff { scopes }).await?;
    Ok(reader)
}
