//! Live role gate of the BGP IPC server over real mutual TLS (#364): a role
//! that may not send a request is disconnected with no reply, a role that may
//! gets a real answer. Complements the pure `allowed` tests in `server.rs`,
//! which cannot see the `handle_connection` glue.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_bgp::session::SessionManager;
use nos_pki::testing::shared;
use nos_pki::{PeerId, Stream};
use nos_proto::{BgpEvent, BgpRequest, EvpnUpdate, IpcCodec, RedistributeUpdate, Role};
use tokio_util::codec::{FramedRead, FramedWrite};

type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<BgpEvent>>;
type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<BgpRequest>>;

async fn connect_as(path: &std::path::Path, role: Role) -> (Reader, Writer) {
    let stream = shared()
        .identity(role.as_str(), "x")
        .connect(path, &PeerId::new("bgpd", "r1"))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::default()),
        FramedWrite::new(w, IpcCodec::default()),
    )
}

/// `true` while the server keeps the connection open and sends nothing.
async fn stays_open(reader: &mut Reader) -> bool {
    tokio::time::timeout(Duration::from_secs(1), reader.next())
        .await
        .is_err()
}

/// The next frame, or `None` when the server closed (or reset) instead.
async fn next_event(reader: &mut Reader) -> Option<BgpEvent> {
    tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("connection left open with no reply")
        .and_then(Result::ok)
}

fn start() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bgp.sock");
    // The default instance, no peers: `start` only binds the IPC socket.
    let server = nos_bgp::server::start(
        &path,
        "r1".to_string(),
        SessionManager::new("r1".to_string()),
        &shared().identity("bgpd", "r1"),
        tmp.path().join("no-watchdog.sock"),
    )
    .unwrap();
    (tmp, path, server)
}

fn is_person(role: Role) -> bool {
    matches!(role, Role::User | Role::Restd)
}

#[tokio::test]
async fn only_people_get_the_show_queries_answered() {
    let (_tmp, path, _server) = start();
    for role in Role::ALL {
        for query in 0..5 {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = match query {
                0 => BgpRequest::GetSummary,
                1 => BgpRequest::GetEvpnRoutes,
                3 => BgpRequest::GetFlowspecRoutes,
                4 => BgpRequest::GetVpnRoutes {
                    family: nos_proto::AddressFamily::Vpnv4Unicast,
                    rd: Some("65001:1".into()),
                },
                _ => BgpRequest::GetRpkiSummary,
            };
            w.send(req).await.unwrap();
            let reply = next_event(&mut r).await;
            if !is_person(role) {
                assert!(reply.is_none(), "{role:?} query {query} must get no reply");
                continue;
            }
            let empty = match reply {
                Some(BgpEvent::Summary(v)) if query == 0 => v.is_empty(),
                Some(BgpEvent::EvpnRoutes(v)) if query == 1 => v.is_empty(),
                Some(BgpEvent::RpkiSummary(v)) if query == 2 => v.is_empty(),
                Some(BgpEvent::FlowspecRoutes(v)) if query == 3 => v.is_empty(),
                Some(BgpEvent::VpnRoutes(v)) if query == 4 => v.is_empty(),
                other => panic!("{role:?} query {query}: unexpected {other:?}"),
            };
            assert!(empty, "{role:?} query {query}: nothing is configured");
        }
    }
}

#[tokio::test]
async fn only_people_may_clear_or_refresh_a_peer() {
    let (_tmp, path, _server) = start();
    let peer: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    for role in Role::ALL {
        for refresh in [false, true] {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = if refresh {
                BgpRequest::SendRouteRefresh { peer }
            } else {
                BgpRequest::ClearPeer { peer }
            };
            w.send(req).await.unwrap();
            let reply = next_event(&mut r).await;
            if is_person(role) {
                assert!(
                    matches!(reply, Some(BgpEvent::PeerNotFound)),
                    "{role:?} refresh={refresh}: {reply:?}"
                );
            } else {
                assert!(reply.is_none(), "{role:?} refresh={refresh}");
            }
        }
    }
}

/// The three feeds are fire-and-forget: the right role keeps its connection
/// open with no reply, any other role is disconnected.
#[tokio::test]
async fn each_feed_is_kept_for_its_one_role_and_refused_to_all_others() {
    let (_tmp, path, _server) = start();
    for (name, owner) in [
        ("routes", Role::Ribd),
        ("macs", Role::Fdbd),
        ("evpn prefixes", Role::Ribd),
    ] {
        for role in Role::ALL {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = match name {
                "routes" => BgpRequest::RedistributeRoutes(RedistributeUpdate::Full(vec![])),
                "macs" => BgpRequest::RedistributeMacs {
                    domain: "bd1".to_string(),
                    update: EvpnUpdate::Full(vec![]),
                },
                _ => BgpRequest::RedistributeEvpnPrefixes {
                    table: "tenant".to_string(),
                    update: EvpnUpdate::Full(vec![]),
                },
            };
            w.send(req).await.unwrap();
            if role == owner {
                assert!(stays_open(&mut r).await, "{name}: {role:?} was refused");
            } else {
                assert!(
                    next_event(&mut r).await.is_none(),
                    "{name}: {role:?} must be disconnected"
                );
            }
        }
    }
}

/// #722: `GetRoutesPage` over a real connection walks the redistributed
/// routes in order, a page on a fresh connection (no snapshot) continues from
/// the same cursor, a route removed mid-walk is skipped, and the removed
/// unpaged `GetRoutes` answers with an error.
#[tokio::test]
async fn routes_are_paged_over_a_connection_and_the_old_query_is_an_error() {
    use nos_proto::{BgpRouteCursor, RedistributedRoute};
    let (_tmp, path, _server) = start();
    let route = |n: u8| RedistributedRoute {
        prefix: format!("10.{n}.0.0/16").parse().unwrap(),
        gateway: "192.0.2.1".parse().unwrap(),
    };
    let (_ribd_r, mut ribd_w) = connect_as(&path, Role::Ribd).await;
    ribd_w
        .send(BgpRequest::RedistributeRoutes(RedistributeUpdate::Full(
            (1..=5).map(route).collect(),
        )))
        .await
        .unwrap();

    let page = |after: Option<BgpRouteCursor>| BgpRequest::GetRoutesPage { after, limit: 2 };
    let (mut r, mut w) = connect_as(&path, Role::Restd).await;
    let mut prefixes = Vec::new();
    // The feed is fire-and-forget: wait until all five are visible.
    for _ in 0..50 {
        w.send(BgpRequest::GetRoutesPage {
            after: None,
            limit: 100,
        })
        .await
        .unwrap();
        match next_event(&mut r).await {
            Some(BgpEvent::RoutesPage { routes, .. }) if routes.len() == 5 => break,
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    w.send(page(None)).await.unwrap();
    let Some(BgpEvent::RoutesPage { routes, next }) = next_event(&mut r).await else {
        panic!("no first page")
    };
    prefixes.extend(routes.iter().map(|r| r.prefix.clone()));
    assert_eq!(prefixes, ["10.1.0.0/16", "10.2.0.0/16"]);
    let mut after = next;
    assert!(after.is_some());

    // 10.3 disappears before its page is read; a new connection has no
    // snapshot and still continues after the cursor.
    ribd_w
        .send(BgpRequest::RedistributeRoutes(RedistributeUpdate::Remove(
            "10.3.0.0/16".parse().unwrap(),
        )))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (mut r2, mut w2) = connect_as(&path, Role::User).await;
    loop {
        w2.send(page(after)).await.unwrap();
        let Some(BgpEvent::RoutesPage { routes, next }) = next_event(&mut r2).await else {
            panic!("no page")
        };
        prefixes.extend(routes.iter().map(|r| r.prefix.clone()));
        match next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    assert_eq!(
        prefixes,
        ["10.1.0.0/16", "10.2.0.0/16", "10.4.0.0/16", "10.5.0.0/16"]
    );

    w.send(BgpRequest::GetRoutes).await.unwrap();
    assert!(matches!(
        next_event(&mut r).await,
        Some(BgpEvent::Error(m)) if m.contains("GetRoutesPage")
    ));
}
