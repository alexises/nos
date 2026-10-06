//! `nos-logd` as a client of other daemons, for the syslog export only: the
//! broker (to find `nos-configd`/`nos-ribd`), `nos-configd` (the collectors)
//! and `nos-ribd` (a routing table's VRF device). Reimplemented here rather
//! than shared, per the root `CLAUDE.md`'s star dependency graph.

use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{
    Config, DiffScope, Event, IpcCodec, Request, RibEvent, RibRequest, Role, ServiceRef,
    WatchdogEvent, WatchdogRequest,
};
use tokio_util::codec::{FramedRead, FramedWrite};

pub type Reader = FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<Event>>;

/// One-shot `ResolveEndpoint`; `None` on any failure.
pub async fn resolve(watchdog_socket: &Path, service: ServiceRef) -> Option<PathBuf> {
    let stream = nos_pki::connect(watchdog_socket, Role::Watchdog, "")
        .await
        .ok()?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());
    writer
        .send(WatchdogRequest::ResolveEndpoint { service })
        .await
        .ok()?;
    match reader.next().await {
        Some(Ok(WatchdogEvent::Endpoint(path))) => Some(path),
        _ => None,
    }
}

/// The running config, or why it could not be read.
pub async fn fetch_config(config_socket: &Path) -> Result<Config, String> {
    let stream = nos_pki::connect(config_socket, Role::Configd, "")
        .await
        .map_err(|e| e.to_string())?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
    writer.send(Request::Get).await.map_err(|e| e.to_string())?;
    match reader.next().await {
        Some(Ok(Event::Config(cfg))) => Ok(cfg),
        Some(Ok(Event::Error(msg))) => Err(msg),
        Some(Ok(_)) => Err("unexpected event in reply to Get".to_string()),
        Some(Err(e)) => Err(e.to_string()),
        None => Err("connection closed".to_string()),
    }
}

/// Diff events for `scopes`, used only as a "re-read the config" trigger.
pub async fn subscribe_diff(
    config_socket: &Path,
    scopes: Vec<DiffScope>,
) -> Result<Reader, String> {
    let stream = nos_pki::connect(config_socket, Role::Configd, "")
        .await
        .map_err(|e| e.to_string())?;
    let (r, w) = tokio::io::split(stream);
    let reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
    writer
        .send(Request::SubscribeDiff { scopes })
        .await
        .map_err(|e| e.to_string())?;
    Ok(reader)
}

/// The Linux VRF device of routing table `table`: `None` while its `nos-ribd`
/// is not up or has not created the VRF yet (transient, retried by the caller).
pub async fn vrf_name(watchdog_socket: &Path, table: &str) -> Option<String> {
    let path = resolve(watchdog_socket, ServiceRef::RibTable(table.to_string())).await?;
    let stream = nos_pki::connect(&path, Role::Ribd, table).await.ok()?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<RibEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<RibRequest>::default());
    writer.send(RibRequest::GetVrfName).await.ok()?;
    match reader.next().await {
        Some(Ok(RibEvent::VrfName(name))) => name,
        _ => None,
    }
}
