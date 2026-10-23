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
        for query in 0..4 {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = match query {
                0 => BgpRequest::GetSummary,
                1 => BgpRequest::GetEvpnRoutes,
                3 => BgpRequest::GetFlowspecRoutes,
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
