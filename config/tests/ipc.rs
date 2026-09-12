use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_config::{BgpInstance, Config, ConfigStore, ListenAddr};
use nos_proto::{BgpInstanceOp, ConfigOp, Event, IpcCodec, Request, Topic, TransactionBase};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

fn instance(name: &str, asn: u32) -> BgpInstance {
    BgpInstance {
        name: name.to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        asn,
    }
}

fn ensure_op(name: &str) -> ConfigOp {
    ConfigOp::BgpInstance(BgpInstanceOp::Ensure {
        name: name.to_string(),
    })
}

fn set_asn_op(name: &str, asn: u32) -> ConfigOp {
    ConfigOp::BgpInstance(BgpInstanceOp::SetAsn {
        name: name.to_string(),
        asn,
    })
}

async fn connect(
    socket_path: &std::path::Path,
) -> (
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

    let store = ConfigStore::new(Config::default(), None);
    store.open_transaction("t1", TransactionBase::Blank).await;
    store.apply_op("t1", ensure_op("default")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("default", 65000))
        .await
        .unwrap();
    store.commit_transaction("t1").await.unwrap();
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Get).await.unwrap();

    let event = reader.next().await.unwrap().unwrap();
    match event {
        Event::Config(c) => {
            assert_eq!(c.bgp_instances.len(), 1);
            assert_eq!(c.bgp_instances[0].name, "default");
        }
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_receives_initial_snapshot_then_updates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()))
        .unwrap();

    // Give the accept loop a moment to be ready.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Subscribe).await.unwrap();

    // Initial snapshot — empty config.
    let event = reader.next().await.unwrap().unwrap();
    assert!(matches!(event, Event::Config(c) if c.bgp_instances.is_empty()));

    // Commit a change directly through the store (in-process, as a future
    // daemon-internal caller would).
    store.open_transaction("t1", TransactionBase::Blank).await;
    store.apply_op("t1", ensure_op("vrf-a")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("vrf-a", 65001))
        .await
        .unwrap();
    store.commit_transaction("t1").await.unwrap();

    // Receive the update.
    let event = reader.next().await.unwrap().unwrap();
    match event {
        Event::Config(c) => assert_eq!(c.bgp_instances[0].name, "vrf-a"),
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn unsubscribe_stops_updates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Subscribe).await.unwrap();

    // Consume initial snapshot.
    reader.next().await.unwrap().unwrap();

    // Unsubscribe, then commit.
    writer.send(Request::Unsubscribe).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await; // let server process Unsubscribe

    store.open_transaction("t1", TransactionBase::Blank).await;
    store.apply_op("t1", ensure_op("vrf-b")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("vrf-b", 65002))
        .await
        .unwrap();
    store.commit_transaction("t1").await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    // No event should arrive within a short timeout.
    let result = tokio::time::timeout(Duration::from_millis(50), reader.next()).await;
    assert!(
        result.is_err(),
        "expected timeout, but received an event after Unsubscribe"
    );
}

#[tokio::test]
async fn save_persists_running_config_to_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");
    let config_path = tmp.path().join("config.yaml");

    let store = ConfigStore::new(Config::default(), Some(config_path.clone()));
    store.open_transaction("t1", TransactionBase::Blank).await;
    store.apply_op("t1", ensure_op("default")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("default", 65000))
        .await
        .unwrap();
    store.commit_transaction("t1").await.unwrap();
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer.send(Request::Save).await.unwrap();

    let event = reader.next().await.unwrap().unwrap();
    assert!(matches!(event, Event::Saved));

    let saved = nos_config::persistence::load_or_default(&config_path).unwrap();
    assert_eq!(saved.bgp_instances.len(), 1);
    assert_eq!(saved.bgp_instances[0].name, "default");
}

#[tokio::test]
async fn save_without_configured_path_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer.send(Request::Save).await.unwrap();

    let event = reader.next().await.unwrap().unwrap();
    assert!(matches!(event, Event::Error(_)));
}

#[tokio::test]
async fn open_transaction_blank_and_current_over_ipc() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(
        Config {
            bgp_instances: vec![instance("default", 65000)],
            ..Default::default()
        },
        None,
    );
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            name: "blank1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    match reader.next().await.unwrap().unwrap() {
        Event::Transaction(snap) => {
            assert!(snap.config.bgp_instances.is_empty());
            assert!(!snap.resumed);
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            name: "current1".to_string(),
            base: TransactionBase::Current,
        })
        .await
        .unwrap();
    match reader.next().await.unwrap().unwrap() {
        Event::Transaction(snap) => {
            assert_eq!(snap.config.bgp_instances.len(), 1);
            assert!(!snap.resumed);
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn resume_by_reopening_over_new_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    // Connection A: open + edit, then drop.
    {
        let (mut reader, mut writer) = connect(&sock_path).await;
        writer
            .send(Request::OpenTransaction {
                name: "t1".to_string(),
                base: TransactionBase::Blank,
            })
            .await
            .unwrap();
        reader.next().await.unwrap().unwrap();

        writer
            .send(Request::ApplyOp {
                name: "t1".to_string(),
                op: ensure_op("r1"),
            })
            .await
            .unwrap();
        reader.next().await.unwrap().unwrap();
    }

    // Connection B: reopen the same name.
    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            name: "t1".to_string(),
            base: TransactionBase::Current,
        })
        .await
        .unwrap();
    match reader.next().await.unwrap().unwrap() {
        Event::Transaction(snap) => {
            assert!(snap.resumed);
            assert!(snap.dirty);
            assert_eq!(snap.config.bgp_instances.len(), 1);
            assert_eq!(snap.config.bgp_instances[0].name, "r1");
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn apply_op_over_ipc_reflects_in_get_transaction() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();

    writer
        .send(Request::ApplyOp {
            name: "t1".to_string(),
            op: ensure_op("r1"),
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();

    writer
        .send(Request::GetTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    match reader.next().await.unwrap().unwrap() {
        Event::Transaction(snap) => {
            assert_eq!(snap.config.bgp_instances.len(), 1);
            assert_eq!(snap.config.bgp_instances[0].name, "r1");
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_over_ipc_updates_running_visible_to_fresh_get() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();
    writer
        .send(Request::ApplyOp {
            name: "t1".to_string(),
            op: ensure_op("r1"),
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();
    writer
        .send(Request::ApplyOp {
            name: "t1".to_string(),
            op: set_asn_op("r1", 65001),
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();
    writer
        .send(Request::CommitTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        Event::Committed
    ));

    // Fresh connection, one-shot Get, matching the CLI's actual usage pattern.
    let (mut reader2, mut writer2) = connect(&sock_path).await;
    writer2.send(Request::Get).await.unwrap();
    match reader2.next().await.unwrap().unwrap() {
        Event::Config(c) => {
            assert_eq!(c.bgp_instances.len(), 1);
            assert_eq!(c.bgp_instances[0].name, "r1");
            assert_eq!(c.bgp_instances[0].asn, 65001);
        }
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_invalid_over_ipc_returns_error_and_transaction_still_resumable() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();
    // Ensure leaves asn at the invalid placeholder 0.
    writer
        .send(Request::ApplyOp {
            name: "t1".to_string(),
            op: ensure_op("bad"),
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();

    writer
        .send(Request::CommitTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        Event::Error(_)
    ));

    writer
        .send(Request::GetTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    match reader.next().await.unwrap().unwrap() {
        Event::Transaction(snap) => assert_eq!(snap.config.bgp_instances.len(), 1),
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_missing_transaction_over_ipc_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::CommitTransaction {
            name: "missing".to_string(),
        })
        .await
        .unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        Event::Error(_)
    ));
}

#[tokio::test]
async fn discard_over_ipc_removes_transaction_so_reopen_is_fresh() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();
    writer
        .send(Request::ApplyOp {
            name: "t1".to_string(),
            op: ensure_op("r1"),
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();

    writer
        .send(Request::DiscardTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        Event::Discarded
    ));

    writer
        .send(Request::OpenTransaction {
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    match reader.next().await.unwrap().unwrap() {
        Event::Transaction(snap) => {
            assert!(!snap.resumed);
            assert!(snap.config.bgp_instances.is_empty());
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribed_client_receives_broadcast_after_named_transaction_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Connection A: subscribes (stands in for a future daemon like nos-bgp).
    let (mut reader_a, mut writer_a) = connect(&sock_path).await;
    writer_a.send(Request::Subscribe).await.unwrap();
    let initial = reader_a.next().await.unwrap().unwrap();
    assert!(matches!(initial, Event::Config(c) if c.bgp_instances.is_empty()));

    // Connection B: opens, edits, and commits a named transaction.
    let (mut reader_b, mut writer_b) = connect(&sock_path).await;
    writer_b
        .send(Request::OpenTransaction {
            name: "demo".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    reader_b.next().await.unwrap().unwrap();
    writer_b
        .send(Request::ApplyOp {
            name: "demo".to_string(),
            op: ensure_op("r1"),
        })
        .await
        .unwrap();
    reader_b.next().await.unwrap().unwrap();
    writer_b
        .send(Request::ApplyOp {
            name: "demo".to_string(),
            op: set_asn_op("r1", 65001),
        })
        .await
        .unwrap();
    reader_b.next().await.unwrap().unwrap();
    writer_b
        .send(Request::CommitTransaction {
            name: "demo".to_string(),
        })
        .await
        .unwrap();
    assert!(matches!(
        reader_b.next().await.unwrap().unwrap(),
        Event::Committed
    ));

    // Connection A must receive the broadcast update.
    let update = tokio::time::timeout(Duration::from_millis(200), reader_a.next())
        .await
        .expect("subscribed connection did not receive a broadcast update")
        .unwrap()
        .unwrap();
    match update {
        Event::Config(c) => {
            assert_eq!(c.bgp_instances.len(), 1);
            assert_eq!(c.bgp_instances[0].name, "r1");
            assert_eq!(c.bgp_instances[0].asn, 65001);
        }
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn hostname_change_is_broadcast_to_all_subscribers() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Two independently-connected subscribers, standing in for two `nos`
    // shells watching the same daemon.
    let (mut reader_a, mut writer_a) = connect(&sock_path).await;
    writer_a.send(Request::Subscribe).await.unwrap();
    let initial_a = reader_a.next().await.unwrap().unwrap();
    assert!(matches!(initial_a, Event::Config(c) if c.hostname == "nos"));

    let (mut reader_b, mut writer_b) = connect(&sock_path).await;
    writer_b.send(Request::Subscribe).await.unwrap();
    let initial_b = reader_b.next().await.unwrap().unwrap();
    assert!(matches!(initial_b, Event::Config(c) if c.hostname == "nos"));

    // A third connection commits a hostname change.
    let (mut reader_c, mut writer_c) = connect(&sock_path).await;
    writer_c
        .send(Request::OpenTransaction {
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    reader_c.next().await.unwrap().unwrap();
    writer_c
        .send(Request::ApplyOp {
            name: "t1".to_string(),
            op: ConfigOp::SetHostname("router1".to_string()),
        })
        .await
        .unwrap();
    reader_c.next().await.unwrap().unwrap();
    writer_c
        .send(Request::CommitTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    assert!(matches!(
        reader_c.next().await.unwrap().unwrap(),
        Event::Committed
    ));

    // Both subscribers — every connected client — must see the new hostname.
    for reader in [&mut reader_a, &mut reader_b] {
        let update = tokio::time::timeout(Duration::from_millis(200), reader.next())
            .await
            .expect("subscribed connection did not receive the hostname broadcast")
            .unwrap()
            .unwrap();
        assert!(matches!(update, Event::Config(c) if c.hostname == "router1"));
    }
}

#[tokio::test]
async fn describe_returns_the_requested_topics_doc() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()))
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::Describe {
            topic: Topic::SetHostname,
        })
        .await
        .unwrap();

    let event = reader.next().await.unwrap().unwrap();
    match event {
        Event::Description(doc) => {
            assert_eq!(doc.topic, Topic::SetHostname);
            assert!(!doc.summary.is_empty());
            assert!(!doc.detail.is_empty());
        }
        other => panic!("expected Description event, got {other:?}"),
    }
}
