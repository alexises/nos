use std::path::Path;

use ipnet::IpNet;
use nos_daemon::ipc::one_shot;
use nos_proto::{ResolvedNextHop, RibEvent, RibRequest, Role};
use std::net::IpAddr;
use tracing::trace;

/// One-shot query of a `nos-ribd` instance's Linux VRF interface name.
///
/// Best-effort by design: this is polled on every reconcile pass (see
/// `crate::reconcile::resolve_vrf`), and "no answer yet" (connection
/// refused, the daemon hasn't created a VRF, an unexpected/malformed reply)
/// is a normal, frequently-recurring condition during that table's
/// `nos-ribd` startup or restart — never worth surfacing as an error to the
/// caller, which just retries next tick. Only a well-formed
/// `RibEvent::VrfName` reply is distinguished from that.
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

/// One-shot query of every prefix's IGP cost (`RibRequest::IgpCosts`), for
/// BGP decision step (d). `None` on any failure — the caller just polls again.
pub async fn get_igp_costs(rib_socket: &Path) -> Option<Vec<(IpNet, u32)>> {
    match one_shot(rib_socket, Role::Ribd, RibRequest::IgpCosts).await? {
        RibEvent::IgpCosts(costs) => Some(costs),
        _ => None,
    }
}

/// One-shot query of how many BGP routes the table still holds
/// (`RibRequest::BgpRouteCount`). `None` on any failure.
pub async fn get_bgp_route_count(rib_socket: &Path) -> Option<u32> {
    match one_shot(rib_socket, Role::Ribd, RibRequest::BgpRouteCount).await? {
        RibEvent::BgpRouteCount(n) => Some(n),
        _ => None,
    }
}

/// One-shot `RibRequest::ResolveNextHop`: one answer per address, in order.
/// `None` on any failure (or a reply of the wrong length).
pub async fn resolve_next_hops(
    rib_socket: &Path,
    addrs: Vec<IpAddr>,
) -> Option<Vec<Option<ResolvedNextHop>>> {
    let n = addrs.len();
    match one_shot(rib_socket, Role::Ribd, RibRequest::ResolveNextHop { addrs }).await? {
        RibEvent::NextHops(hops) if hops.len() == n => Some(hops),
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
    async fn returns_igp_costs_on_well_formed_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        let net: IpNet = "10.0.0.0/24".parse().unwrap();
        serve_once(&path, move |_req| Some(RibEvent::IgpCosts(vec![(net, 20)])));

        assert_eq!(get_igp_costs(&path).await, Some(vec![(net, 20)]));
    }

    #[tokio::test]
    async fn returns_bgp_route_count_on_well_formed_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        serve_once(&path, |req| {
            matches!(req, RibRequest::BgpRouteCount).then_some(RibEvent::BgpRouteCount(7))
        });
        assert_eq!(get_bgp_route_count(&path).await, Some(7));
    }

    #[tokio::test]
    async fn resolves_next_hops_in_order_and_rejects_a_short_reply() {
        let hop = ResolvedNextHop {
            gateway: "10.0.0.3".parse().unwrap(),
            interface_id: None,
            source: nos_proto::RouteSourceKind::Connected,
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rib.sock");
        let h = hop.clone();
        serve_once(&path, move |req| match req {
            RibRequest::ResolveNextHop { addrs } if addrs.len() == 2 => {
                Some(RibEvent::NextHops(vec![Some(h.clone()), None]))
            }
            _ => None,
        });
        let addrs = vec!["10.0.0.3".parse().unwrap(), "10.9.0.1".parse().unwrap()];
        assert_eq!(
            resolve_next_hops(&path, addrs.clone()).await,
            Some(vec![Some(hop), None])
        );
        let short = tmp.path().join("short.sock");
        serve_once(&short, |_| Some(RibEvent::NextHops(vec![])));
        assert_eq!(resolve_next_hops(&short, addrs).await, None);
    }
}
