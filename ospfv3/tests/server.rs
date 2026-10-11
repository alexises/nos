//! Live role gate of the `OSPFv3` IPC server over real mutual TLS (#364): a role
//! that may not send a request is disconnected with no reply, a role that may
//! gets a real answer. Complements the pure `allowed` tests in `server.rs`,
//! which cannot see the `handle_connection` glue.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_ospfv3::link::LinkManager;
use nos_pki::testing::shared;
use nos_pki::{PeerId, Stream};
use nos_proto::{IpcCodec, Ospfv3Event, Ospfv3Request, RedistributeUpdate, Role};
use tokio_util::codec::{FramedRead, FramedWrite};

type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<Ospfv3Event>>;
type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<Ospfv3Request>>;

async fn connect_as(path: &std::path::Path, role: Role) -> (Reader, Writer) {
    let stream = shared()
        .identity(role.as_str(), "x")
        .connect(path, &PeerId::new("ospfv3d", "r1"))
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
async fn next_event(reader: &mut Reader) -> Option<Ospfv3Event> {
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
    let path = tmp.path().join("ospfv3.sock");
    // Nothing configured: every query answers with an empty list.
    let links = LinkManager::new(1, None);
    let server = nos_ospfv3::server::start(
        &path,
        "r1".to_string(),
        links,
        &shared().identity("ospfv3d", "r1"),
    )
    .unwrap();
    (tmp, path, server)
}

#[tokio::test]
async fn only_people_get_the_show_queries_answered() {
    let (_tmp, path, _server) = start();
    for role in Role::ALL {
        for database in [false, true] {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = if database {
                Ospfv3Request::GetDatabase
            } else {
                Ospfv3Request::GetNeighbors
            };
            w.send(req).await.unwrap();
            let reply = next_event(&mut r).await;
            if !matches!(role, Role::User | Role::Restd) {
                assert!(reply.is_none(), "{role:?} database={database}: no reply");
                continue;
            }
            let empty = match reply {
                Some(Ospfv3Event::Neighbors(v)) if !database => v.is_empty(),
                Some(Ospfv3Event::Database(v)) if database => v.is_empty(),
                other => panic!("{role:?} database={database}: unexpected {other:?}"),
            };
            assert!(empty);
        }
    }
}

/// The redistribution feed is fire-and-forget: `ribd` keeps its connection
/// open with no reply, any other role is disconnected.
#[tokio::test]
async fn only_ribd_may_feed_redistribution() {
    let (_tmp, path, _server) = start();
    for role in Role::ALL {
        let (mut r, mut w) = connect_as(&path, role).await;
        w.send(Ospfv3Request::RedistributeRoutes(RedistributeUpdate::Full(
            vec![],
        )))
        .await
        .unwrap();
        if role == Role::Ribd {
            assert!(stays_open(&mut r).await, "ribd was refused");
        } else {
            assert!(
                next_event(&mut r).await.is_none(),
                "{role:?} must be disconnected"
            );
        }
    }
}
