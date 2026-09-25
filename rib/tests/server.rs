use std::net::IpAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::testing::shared;
use nos_pki::Stream;
use nos_proto::{IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteSourceKind};
use nos_rib::{server, NoopRibDriver, Rib, RibEntry, RouteSource};
use tokio::sync::RwLock;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_rib() -> Rib {
    let mut rib = Rib::new();
    let broad: nos_proto::IpNet = "10.0.0.0/16".parse().unwrap();
    let narrow: nos_proto::IpNet = "10.0.1.0/24".parse().unwrap();
    rib.insert(RibEntry {
        interface_id: None,
        prefix: broad,
        gateway: "10.0.0.1".parse().unwrap(),
        source: RouteSource::Static,
        backup: None,
    });
    // Two competing candidates for the same prefix, to prove ordering.
    rib.insert(RibEntry {
        interface_id: None,
        prefix: narrow,
        gateway: "10.0.1.9".parse().unwrap(),
        source: RouteSource::Bgp,
        backup: None,
    });
    rib.insert(RibEntry {
        interface_id: None,
        prefix: narrow,
        gateway: "10.0.1.1".parse().unwrap(),
        source: RouteSource::Static,
        backup: None,
    });
    rib
}

type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<RibEvent>>;
type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<RibRequest>>;

/// Connects as a person, who may query but never push routes.
async fn connect(path: &std::path::Path) -> (Reader, Writer) {
    connect_as(path, "user", "tester").await
}

async fn connect_as(path: &std::path::Path, role: &str, name: &str) -> (Reader, Writer) {
    let stream = shared()
        .identity(role, name)
        .connect(path, &nos_pki::PeerId::new("ribd", "rt1"))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::<RibEvent>::default()),
        FramedWrite::new(w, IpcCodec::<RibRequest>::default()),
    )
}

#[tokio::test]
async fn get_routes_returns_sorted_prefixes_with_ranked_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::new(NoopRibDriver),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(RibRequest::GetRoutes).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    let RibEvent::Routes(routes) = event else {
        panic!("expected Routes, got {event:?}");
    };
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].prefix, "10.0.0.0/16".parse().unwrap());
    assert_eq!(routes[1].prefix, "10.0.1.0/24".parse().unwrap());
    // Best (Static) candidate first, then worst (Bgp).
    assert_eq!(routes[1].candidates.len(), 2);
    assert_eq!(routes[1].candidates[0].source, RouteSourceKind::Static);
    assert_eq!(routes[1].candidates[1].source, RouteSourceKind::Bgp);
}

#[tokio::test]
async fn lookup_matches_longest_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::new(NoopRibDriver),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    let addr: IpAddr = "10.0.1.5".parse().unwrap();
    writer.send(RibRequest::Lookup { addr }).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    let RibEvent::Match(PrefixRoutes { prefix, candidates }) = event else {
        panic!("expected Match, got {event:?}");
    };
    assert_eq!(prefix, "10.0.1.0/24".parse().unwrap());
    assert_eq!(candidates[0].source, RouteSourceKind::Static);
}

#[tokio::test]
async fn lookup_with_no_covering_prefix_returns_no_match() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::new(NoopRibDriver),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    let addr: IpAddr = "192.168.0.1".parse().unwrap();
    writer.send(RibRequest::Lookup { addr }).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::NoMatch));
}

/// A driver that reports a canned VRF name, so `GetVrfName`'s dispatch can
/// be tested without any real kernel/netlink involvement.
#[derive(Debug)]
struct FakeVrfDriver(Option<String>);

/// A driver that reports a canned table id, so `GetTableId`'s dispatch can
/// be tested the same way.
#[derive(Debug)]
struct FakeTableIdDriver(Option<u32>);

#[async_trait::async_trait]
impl nos_rib::RibDriver for FakeTableIdDriver {
    async fn apply(
        &self,
        _table_name: &str,
        _best_routes: &std::collections::HashMap<nos_proto::IpNet, RibEntry>,
    ) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn apply_delta(
        &self,
        _table_name: &str,
        _changes: &std::collections::HashMap<nos_proto::IpNet, Option<RibEntry>>,
    ) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn teardown(&self, _table_name: &str) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn vrf_name(&self, _table_name: &str) -> Option<String> {
        None
    }

    async fn table_id(&self, _table_name: &str) -> Option<u32> {
        self.0
    }
}

#[async_trait::async_trait]
impl nos_rib::RibDriver for FakeVrfDriver {
    async fn apply(
        &self,
        _table_name: &str,
        _best_routes: &std::collections::HashMap<nos_proto::IpNet, RibEntry>,
    ) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn apply_delta(
        &self,
        _table_name: &str,
        _changes: &std::collections::HashMap<nos_proto::IpNet, Option<RibEntry>>,
    ) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn teardown(&self, _table_name: &str) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn vrf_name(&self, _table_name: &str) -> Option<String> {
        self.0.clone()
    }

    async fn table_id(&self, _table_name: &str) -> Option<u32> {
        None
    }
}

#[tokio::test]
async fn get_vrf_name_returns_the_drivers_answer() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let driver: Arc<dyn nos_rib::RibDriver> = Arc::new(FakeVrfDriver(Some("vrf100".to_string())));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        driver,
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(RibRequest::GetVrfName).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::VrfName(Some(name)) if name == "vrf100"));
}

#[tokio::test]
async fn get_vrf_name_is_none_when_the_driver_has_no_vrf_yet() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let driver: Arc<dyn nos_rib::RibDriver> = Arc::new(FakeVrfDriver(None));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        driver,
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(RibRequest::GetVrfName).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::VrfName(None)));
}

#[tokio::test]
async fn get_table_id_returns_the_drivers_answer() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let driver: Arc<dyn nos_rib::RibDriver> = Arc::new(FakeTableIdDriver(Some(100)));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        driver,
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(RibRequest::GetTableId).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::TableId(Some(100))));
}

#[tokio::test]
async fn get_table_id_is_none_when_the_driver_has_no_id_yet() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let driver: Arc<dyn nos_rib::RibDriver> = Arc::new(FakeTableIdDriver(None));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        driver,
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    writer.send(RibRequest::GetTableId).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::TableId(None)));
}

/// A driver that records every `apply`/`apply_delta` call and notifies a
/// waiter, so `PushBgpRoutes`'s fire-and-forget dispatch (no reply on the
/// wire) can still be observed synchronizing with the test.
#[derive(Debug, Default)]
struct RecordingDriver {
    applied: tokio::sync::Mutex<Vec<std::collections::HashMap<nos_proto::IpNet, RibEntry>>>,
    applied_delta:
        tokio::sync::Mutex<Vec<std::collections::HashMap<nos_proto::IpNet, Option<RibEntry>>>>,
    notify: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl nos_rib::RibDriver for RecordingDriver {
    async fn apply(
        &self,
        _table_name: &str,
        best_routes: &std::collections::HashMap<nos_proto::IpNet, RibEntry>,
    ) -> Result<(), nos_rib::DriverError> {
        self.applied.lock().await.push(best_routes.clone());
        self.notify.notify_one();
        Ok(())
    }

    async fn apply_delta(
        &self,
        _table_name: &str,
        changes: &std::collections::HashMap<nos_proto::IpNet, Option<RibEntry>>,
    ) -> Result<(), nos_rib::DriverError> {
        self.applied_delta.lock().await.push(changes.clone());
        self.notify.notify_one();
        Ok(())
    }

    async fn teardown(&self, _table_name: &str) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn vrf_name(&self, _table_name: &str) -> Option<String> {
        None
    }

    async fn table_id(&self, _table_name: &str) -> Option<u32> {
        None
    }
}

#[tokio::test]
async fn push_bgp_routes_full_inserts_into_shared_rib_and_applies_to_driver() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let driver = Arc::new(RecordingDriver::default());
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        driver.clone(),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (_reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    let prefix: nos_proto::IpNet = "203.0.113.0/24".parse().unwrap();
    let next_hop: IpAddr = "203.0.113.1".parse().unwrap();
    writer
        .send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Full(vec![nos_proto::BgpRoute {
                prefix,
                next_hop,
                backup_next_hop: None,
            }]),
        ]))
        .await
        .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
        .await
        .expect("driver.apply was not called");

    let guard = rib.read().await;
    let best = guard.best_route(&prefix).unwrap();
    assert_eq!(best.gateway, next_hop);
    assert_eq!(best.source, RouteSource::Bgp);
}

#[tokio::test]
async fn push_bgp_routes_add_only_calls_apply_delta_when_the_winner_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let driver = Arc::new(RecordingDriver::default());
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        driver.clone(),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (_reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    let prefix: nos_proto::IpNet = "203.0.113.0/24".parse().unwrap();
    let next_hop: IpAddr = "203.0.113.1".parse().unwrap();
    let route = nos_proto::BgpRoute {
        prefix,
        next_hop,
        backup_next_hop: None,
    };

    // A genuinely new prefix triggers apply_delta.
    writer
        .send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Add(route.clone()),
        ]))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
        .await
        .expect("driver.apply_delta was not called for a new route");
    assert_eq!(driver.applied_delta.lock().await.len(), 1);

    // The identical route re-sent doesn't change the winner, so this must
    // not trigger apply_delta at all.
    writer
        .send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Add(route),
        ]))
        .await
        .unwrap();

    // A different prefix's genuine change, on the same connection, proves
    // the server has already processed the no-op push sent just before it
    // (a single connection processes requests in order) — if that no-op had
    // wrongly triggered a call, it would show up as an extra entry below.
    let other_prefix: nos_proto::IpNet = "203.0.114.0/24".parse().unwrap();
    writer
        .send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Add(nos_proto::BgpRoute {
                prefix: other_prefix,
                next_hop,
                backup_next_hop: None,
            }),
        ]))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
        .await
        .expect("driver.apply_delta was not called for the second new route");

    let applied = driver.applied_delta.lock().await;
    assert_eq!(
        applied.len(),
        2,
        "the unchanged re-send must not have triggered apply_delta"
    );
}

/// The kernel-route write path is closed to everyone but the owning daemon
/// family: a person, or another family's daemon, is disconnected and no
/// route lands.
#[tokio::test]
async fn route_pushes_from_the_wrong_role_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        Arc::new(NoopRibDriver),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    for (role, name) in [("user", "alice"), ("ospfd", "o1"), ("restd", "rt1")] {
        let (mut reader, mut writer) = connect_as(&path, role, name).await;
        writer
            .send(RibRequest::PushBgpRoutes(vec![
                nos_proto::BgpRouteUpdate::Add(nos_proto::BgpRoute {
                    prefix: "10.9.0.0/24".parse().unwrap(),
                    next_hop: "10.0.0.1".parse().unwrap(),
                    backup_next_hop: None,
                }),
            ]))
            .await
            .unwrap();
        assert!(
            reader.next().await.is_none_or(|r| r.is_err()),
            "{role} should have been disconnected"
        );
    }
    assert!(
        rib.read().await.all_routes().is_empty(),
        "no refused push may land a route"
    );
}
