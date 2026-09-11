use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_config::{BgpInstance, Config, ConfigStore, ListenAddr};
use nos_proto::{Event, IpcCodec, Request};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

fn instance(name: &str, asn: u32) -> BgpInstance {
    BgpInstance { name: name.to_string(), router_id: Ipv4Addr::new(1, 1, 1, 1), asn }
}

async fn connect(socket_path: &std::path::Path) -> (
    FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<Event>>,
    FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<Request>>,
) {
    let stream = UnixStream::connect(socket_path).await.unwrap();
    let (r, w) = stream.into_split();
    (
        FramedRead::new(r, IpcCodec::<Event>::default()),
        FramedWrite::new(w, IpcCodec::<Request>::default()),
    )
}

#[tokio::test]
async fn get_returns_current_config() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let mut store = ConfigStore::new(Config::default());
    store.edit_candidate().await.bgp_instances.push(instance("default", 65000));
    store.commit().await.unwrap();
    let _srv = store.start_ipc_server(&ListenAddr::Unix(path.clone())).unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Get).await.unwrap();

    let event = reader.next().await.unwrap().unwrap();
    match event {
        Event::Config(c) => {
            assert_eq!(c.bgp_instances.len(), 1);
            assert_eq!(c.bgp_instances[0].name, "default");
        }
        _ => panic!("expected Config event"),
    }
}

#[tokio::test]
async fn subscribe_receives_initial_snapshot_then_updates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let mut store = ConfigStore::new(Config::default());
    let _srv = store.start_ipc_server(&ListenAddr::Unix(path.clone())).unwrap();

    // Give the accept loop a moment to be ready.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Subscribe).await.unwrap();

    // Initial snapshot — empty config.
    let event = reader.next().await.unwrap().unwrap();
    assert!(matches!(event, Event::Config(c) if c.bgp_instances.is_empty()));

    // Commit a change.
    store.edit_candidate().await.bgp_instances.push(instance("vrf-a", 65001));
    store.commit().await.unwrap();

    // Receive the update.
    let event = reader.next().await.unwrap().unwrap();
    match event {
        Event::Config(c) => assert_eq!(c.bgp_instances[0].name, "vrf-a"),
        _ => panic!("expected Config event"),
    }
}

#[tokio::test]
async fn unsubscribe_stops_updates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let mut store = ConfigStore::new(Config::default());
    let _srv = store.start_ipc_server(&ListenAddr::Unix(path.clone())).unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Subscribe).await.unwrap();

    // Consume initial snapshot.
    reader.next().await.unwrap().unwrap();

    // Unsubscribe, then commit.
    writer.send(Request::Unsubscribe).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await; // let server process Unsubscribe

    store.edit_candidate().await.bgp_instances.push(instance("vrf-b", 65002));
    store.commit().await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    // No event should arrive within a short timeout.
    let result =
        tokio::time::timeout(Duration::from_millis(50), reader.next()).await;
    assert!(result.is_err(), "expected timeout, but received an event after Unsubscribe");
}
