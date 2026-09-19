use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_proto::{
    BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec,
};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::trace;

/// One-shot query of `nos-interfaced` for one named interface's reconciled
/// addresses (including its kernel-assigned IPv6 link-local address, once
/// `InterfaceStatus.link_local_address` exists — see the `OSPFv3` Phase 1
/// plan's "closing gap #1").
///
/// Best-effort by design, mirroring `crate::rib_client::get_vrf_name`: this
/// is polled on every reconcile pass (see `crate::reconcile`), and "no
/// answer yet" (connection refused, the interface isn't configured yet, an
/// unexpected or malformed reply) is a normal, frequently-recurring
/// condition — never worth surfacing as an error to the caller, which just
/// retries next tick. Only a well-formed `InterfaceEvent::Interface` reply is
/// distinguished from that. Reimplemented rather than imported from
/// `nos-ospf`/`nos-bgp`, per the root `CLAUDE.md`'s star dependency graph.
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

/// One-shot query of `nos-interfaced` for one named broadcast domain's
/// reconciled SVI addresses. Best-effort, mirrors `get_interface` exactly.
pub async fn get_broadcast_domain(
    interface_socket: &Path,
    name: &str,
) -> Option<BroadcastDomainStatus> {
    let Ok(stream) = UnixStream::connect(interface_socket).await else {
        trace!(socket = %interface_socket.display(), "failed to connect to nos-interfaced");
        return None;
    };
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<InterfaceEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default());
    writer
        .send(InterfaceRequest::GetBroadcastDomain {
            name: name.to_string(),
        })
        .await
        .ok()?;
    if let Some(Ok(InterfaceEvent::BroadcastDomain(status))) = reader.next().await {
        Some(status)
    } else {
        trace!(
            name,
            "nos-interfaced gave no well-formed GetBroadcastDomain reply"
        );
        None
    }
}
