use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_config::{BgpInstance, Config, ConfigStore, ListenAddr};
use nos_pki::testing::TestPki;
use nos_pki::{Identity, PeerId, Stream};
use nos_proto::{
    BgpInstanceOp, ConfigOp, DiffScope, DiffStatus, Event, IpcCodec, Request, Topic,
    TransactionBase,
};
use tokio_util::codec::{FramedRead, FramedWrite};

fn instance(name: &str, asn: u32) -> BgpInstance {
    BgpInstance {
        name: name.to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        asn,
        peer_groups: Vec::new(),
        peers: Vec::new(),
        cluster_id: None,
        maximum_paths: None,
        confederation: nos_proto::BgpConfederation::default(),
        rpki_caches: Vec::new(),
        aggregates: Vec::new(),
        graceful_restart: nos_proto::BgpGracefulRestart::default(),
        routing_table: None,
        redistribute_policy: None,
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

fn ensure_routing_table_op(name: &str) -> ConfigOp {
    ConfigOp::RoutingTable(nos_proto::RoutingTableOp::Ensure {
        name: name.to_string(),
    })
}

fn set_routing_table_bgp_instance_op(name: &str, bgp_instance: &str) -> ConfigOp {
    ConfigOp::RoutingTable(nos_proto::RoutingTableOp::SetBgpInstance {
        name: name.to_string(),
        bgp_instance: bgp_instance.to_string(),
    })
}

fn ensure_static_routing_instance_op(name: &str) -> ConfigOp {
    ConfigOp::StaticRoutingInstance(nos_proto::StaticRoutingInstanceOp::Ensure {
        name: name.to_string(),
    })
}

/// One CA per test binary: the server identity `start_ipc_server` is given
/// and every client `connect`s with come from it.
static PKI: std::sync::LazyLock<TestPki> = std::sync::LazyLock::new(TestPki::new);

fn server_identity() -> Identity {
    PKI.identity("configd", "")
}

fn configd() -> PeerId {
    PeerId::new("configd", "")
}

type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<Event>>;
type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<Request>>;

/// Connects as a person: the role allowed to do everything.
async fn connect(socket_path: &std::path::Path) -> (Reader, Writer) {
    connect_as(socket_path, "user", "tester").await
}

async fn connect_as(socket_path: &std::path::Path, role: &str, name: &str) -> (Reader, Writer) {
    let stream = PKI
        .identity(role, name)
        .connect(socket_path, &configd())
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
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
    store.commit_transaction("t1", None).await.unwrap();
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
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
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
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
    store.commit_transaction("t1", None).await.unwrap();

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
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
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
    store.commit_transaction("t1", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    // No event should arrive within a short timeout.
    let result = tokio::time::timeout(Duration::from_millis(50), reader.next()).await;
    assert!(
        result.is_err(),
        "expected timeout, but received an event after Unsubscribe"
    );
}

/// Regression test: a `Subscribe` client is documented (`client::subscribe`)
/// to send its request then drop its write half — "the caller owns its
/// lifetime" — so the connection must keep delivering events after that
/// half-close, not just the initial snapshot. Over TLS the halves come from
/// `tokio::io::split`, so dropping `writer` must leave `reader` (and the
/// stream behind it) untouched, mirroring real client usage exactly.
#[tokio::test]
async fn subscribe_survives_client_dropping_its_write_half() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let mut reader = {
        let (mut reader, mut writer) = connect(&path).await;
        writer.send(Request::Subscribe).await.unwrap();
        reader.next().await.unwrap().unwrap(); // initial snapshot
        reader
        // `writer` dropped here — the connection's write-to-server half closes.
    };

    store.open_transaction("t1", TransactionBase::Blank).await;
    store.apply_op("t1", ensure_op("vrf-c")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("vrf-c", 65003))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();

    let event = tokio::time::timeout(Duration::from_millis(200), reader.next())
        .await
        .expect("expected a Config event after commit, connection closed instead")
        .unwrap()
        .unwrap();
    match event {
        Event::Config(c) => assert_eq!(c.bgp_instances[0].name, "vrf-c"),
        other => panic!("expected Config event, got {other:?}"),
    }
}

/// Same regression as `subscribe_survives_client_dropping_its_write_half`,
/// for the `SubscribeDiff` path.
#[tokio::test]
async fn subscribe_diff_survives_client_dropping_its_write_half() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let mut reader = {
        let (mut reader, mut writer) = connect(&path).await;
        writer
            .send(Request::SubscribeDiff {
                scopes: vec![DiffScope::BgpInstances],
            })
            .await
            .unwrap();
        reader.next().await.unwrap().unwrap(); // initial diff
        reader
        // `writer` dropped here — the connection's write-to-server half closes.
    };

    store.open_transaction("t1", TransactionBase::Blank).await;
    store.apply_op("t1", ensure_op("vrf-d")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("vrf-d", 65004))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();

    let event = tokio::time::timeout(Duration::from_millis(200), reader.next())
        .await
        .expect("expected a Diff event after commit, connection closed instead")
        .unwrap()
        .unwrap();
    match event {
        Event::Diff(diff) => {
            assert_eq!(diff.bgp_instances.len(), 1);
            assert_eq!(diff.bgp_instances[0].name, "vrf-d");
            assert_eq!(diff.bgp_instances[0].status, DiffStatus::Added);
        }
        other => panic!("expected Diff event, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_diff_reports_pre_existing_instance_as_added_then_incremental_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    store.open_transaction("t1", TransactionBase::Blank).await;
    store.apply_op("t1", ensure_op("r1")).await.unwrap();
    store.apply_op("t1", set_asn_op("r1", 65000)).await.unwrap();
    store.commit_transaction("t1", None).await.unwrap();

    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::SubscribeDiff {
            scopes: vec![DiffScope::BgpInstances],
        })
        .await
        .unwrap();

    // Initial diff: the pre-existing instance shows up as Added, since it's
    // synthesized against an empty config.
    let event = reader.next().await.unwrap().unwrap();
    match event {
        Event::Diff(diff) => {
            assert_eq!(diff.bgp_instances.len(), 1);
            assert_eq!(diff.bgp_instances[0].name, "r1");
            assert_eq!(diff.bgp_instances[0].status, DiffStatus::Added);
        }
        other => panic!("expected Diff event, got {other:?}"),
    }

    // Add a second instance and remove the first in one commit.
    store.open_transaction("t2", TransactionBase::Current).await;
    store.apply_op("t2", ensure_op("r2")).await.unwrap();
    store.apply_op("t2", set_asn_op("r2", 65001)).await.unwrap();
    store
        .apply_op(
            "t2",
            ConfigOp::BgpInstance(BgpInstanceOp::Delete {
                name: "r1".to_string(),
            }),
        )
        .await
        .unwrap();
    store.commit_transaction("t2", None).await.unwrap();

    let event = reader.next().await.unwrap().unwrap();
    match event {
        Event::Diff(diff) => {
            assert_eq!(diff.bgp_instances.len(), 2);
            let added = diff
                .bgp_instances
                .iter()
                .find(|s| s.status == DiffStatus::Added)
                .expect("added section");
            let removed = diff
                .bgp_instances
                .iter()
                .find(|s| s.status == DiffStatus::Removed)
                .expect("removed section");
            assert_eq!(added.name, "r2");
            assert_eq!(removed.name, "r1");
        }
        other => panic!("expected Diff event, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_diff_skips_commits_outside_requested_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::SubscribeDiff {
            scopes: vec![DiffScope::BgpInstances],
        })
        .await
        .unwrap();

    // Initial diff — nothing configured yet, so it's empty.
    let event = reader.next().await.unwrap().unwrap();
    assert!(matches!(event, Event::Diff(d) if d.is_empty()));

    // A hostname-only commit is out of scope and must never be forwarded.
    store.open_transaction("t1", TransactionBase::Blank).await;
    store
        .apply_op("t1", ConfigOp::SetHostname("router-b".to_string()))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    let result = tokio::time::timeout(Duration::from_millis(50), reader.next()).await;
    assert!(
        result.is_err(),
        "expected timeout, but received a Diff event for an out-of-scope commit"
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
    store.commit_transaction("t1", None).await.unwrap();
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
            assert_eq!(
                snap.config.bgp_instances,
                [] as [nos_config::BgpInstance; 0]
            );
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
            if_match: None,
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
            if_match: None,
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
async fn stale_if_match_over_ipc_returns_precondition_error_and_keeps_transaction() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
        .send(Request::SetTransactionPath {
            name: "t1".to_string(),
            path: vec!["hostname".to_string()],
            value: Some("\"h1\"".to_string()),
            if_match: Some(0),
        })
        .await
        .unwrap();
    match reader.next().await.unwrap().unwrap() {
        Event::Transaction(snap) => assert_eq!(snap.generation, 1),
        other => panic!("expected Transaction event, got {other:?}"),
    }

    for req in [
        Request::SetTransactionPath {
            name: "t1".to_string(),
            path: vec!["hostname".to_string()],
            value: Some("\"h2\"".to_string()),
            if_match: Some(0),
        },
        Request::CommitTransaction {
            name: "t1".to_string(),
            if_match: Some(0),
        },
    ] {
        writer.send(req).await.unwrap();
        match reader.next().await.unwrap().unwrap() {
            Event::Error(msg) => assert!(msg.starts_with("precondition failed"), "{msg}"),
            other => panic!("expected Error event, got {other:?}"),
        }
    }
    writer
        .send(Request::GetTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    match reader.next().await.unwrap().unwrap() {
        Event::Transaction(snap) => {
            assert_eq!((snap.generation, snap.config.hostname.as_str()), (1, "h1"));
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_missing_transaction_over_ipc_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::CommitTransaction {
            name: "missing".to_string(),
            if_match: None,
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
            if_match: None,
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
            assert_eq!(
                snap.config.bgp_instances,
                [] as [nos_config::BgpInstance; 0]
            );
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
            if_match: None,
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
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
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
            if_match: None,
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
async fn routing_table_and_static_routing_instance_round_trip_over_ipc() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::OpenTransaction {
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();

    for op in [
        ensure_op("r1"),
        set_asn_op("r1", 65000),
        ensure_static_routing_instance_op("sri1"),
        ConfigOp::StaticRoute(nos_proto::StaticRouteOp::Set {
            instance: "sri1".to_string(),
            subnet: "10.0.0.0/24".parse().unwrap(),
            gateway: "10.0.0.1".parse().unwrap(),
        }),
        ensure_routing_table_op("rt1"),
        set_routing_table_bgp_instance_op("rt1", "r1"),
        ConfigOp::RoutingTable(nos_proto::RoutingTableOp::SetStaticRoutingInstance {
            name: "rt1".to_string(),
            static_routing_instance: "sri1".to_string(),
        }),
    ] {
        writer
            .send(Request::ApplyOp {
                name: "t1".to_string(),
                op,
            })
            .await
            .unwrap();
        reader.next().await.unwrap().unwrap();
    }

    writer
        .send(Request::CommitTransaction {
            name: "t1".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        Event::Committed
    ));

    let (mut reader2, mut writer2) = connect(&path).await;
    writer2.send(Request::Get).await.unwrap();
    match reader2.next().await.unwrap().unwrap() {
        Event::Config(c) => {
            assert_eq!(c.routing_tables.len(), 1);
            assert_eq!(c.routing_tables[0].bgp_instance.as_deref(), Some("r1"));
            assert_eq!(
                c.routing_tables[0].static_routing_instance.as_deref(),
                Some("sri1")
            );
            assert_eq!(c.static_routing_instances.len(), 1);
            assert_eq!(c.static_routing_instances[0].routes.len(), 1);
        }
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_fails_when_static_routing_instance_referenced_table_is_missing_over_ipc() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
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
            op: ensure_routing_table_op("rt1"),
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();
    writer
        .send(Request::ApplyOp {
            name: "t1".to_string(),
            op: set_routing_table_bgp_instance_op("rt1", "does-not-exist"),
        })
        .await
        .unwrap();
    reader.next().await.unwrap().unwrap();

    writer
        .send(Request::CommitTransaction {
            name: "t1".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        Event::Error(_)
    ));
}

#[tokio::test]
async fn describe_returns_the_requested_topics_doc() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::Describe {
            topic: Topic::Hostname,
        })
        .await
        .unwrap();

    let event = reader.next().await.unwrap().unwrap();
    match event {
        Event::Description(doc) => {
            assert_eq!(doc.topic, Topic::Hostname);
            assert_ne!(doc.summary, "");
            assert_ne!(doc.detail, "");
        }
        other => panic!("expected Description event, got {other:?}"),
    }
}

/// A daemon may read the config but not edit it; the refusal is reported and
/// the connection closed, while the daemon's *read* on another connection is
/// unaffected.
#[tokio::test]
async fn a_daemon_role_can_read_but_not_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    writer.send(Request::Get).await.unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        Event::Config(_)
    ));

    writer
        .send(Request::OpenTransaction {
            name: "sneaky".into(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        Event::Error(m) if m == "permission denied"
    ));
    assert!(
        reader.next().await.is_none_or(|r| r.is_err()),
        "connection should close"
    );
    assert!(
        store.get_transaction("sneaky").await.is_err(),
        "the edit must not have happened"
    );
}

/// `Restd` edits on behalf of a user, so it must be let through.
#[tokio::test]
async fn restd_and_users_can_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    for (role, name) in [("restd", "rt1"), ("user", "alice")] {
        let (mut reader, mut writer) = connect_as(&path, role, name).await;
        writer
            .send(Request::OpenTransaction {
                name: format!("t-{role}"),
                base: TransactionBase::Blank,
            })
            .await
            .unwrap();
        assert!(
            matches!(reader.next().await.unwrap().unwrap(), Event::Transaction(_)),
            "{role} should be allowed to edit"
        );
    }
}

/// A certificate from some other CA never gets as far as a request.
#[tokio::test]
async fn a_peer_from_another_ca_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let outsider = TestPki::new().identity("user", "mallory");
    let outcome = async {
        let stream = outsider.connect(&path, &configd()).await?;
        let (r, w) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
        let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
        writer.send(Request::Get).await?;
        reader.next().await.transpose()
    }
    .await;
    assert!(
        !matches!(outcome, Ok(Some(_))),
        "an outsider must not get a config back"
    );
}
