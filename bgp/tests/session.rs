//! `SessionManager` end to end over localhost (#131): two real instances,
//! each with its own listener (`with_listen`, no VRF, so no privileges),
//! peer, exchange a route, and go through the config changes `reconcile`
//! handles — restart, shutdown, removal, MD5.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nos_bgp::collision::FsmCommand;
use nos_bgp::session::{LocalIdentity, ResolvedAuth, ResolvedPeer, SessionManager, VrfRequirement};
use nos_proto::bgp::BgpSessionState;
use nos_proto::{AddressFamily, BgpShutdown, RedistributeUpdate, RedistributedRoute};
use tokio::io::AsyncReadExt;

const A: Ipv4Addr = Ipv4Addr::LOCALHOST;
const B: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn peer(remote: Ipv4Addr, source: Ipv4Addr, remote_as: u32) -> ResolvedPeer {
    let accept = Arc::new(nos_rpl::ACCEPT_ALL.clone());
    ResolvedPeer {
        remote_address: IpAddr::V4(remote),
        source_address: Some(IpAddr::V4(source)),
        remote_as,
        peer_group: "pg".to_string(),
        hold_time: 9,
        keepalive_interval: None,
        connect_retry_time: Duration::from_millis(300),
        mrai: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: accept.clone(),
        export_policy: accept,
        shutdown: None,
    }
}

struct Router {
    manager: Arc<SessionManager>,
    local: LocalIdentity,
}

impl Router {
    async fn apply(&self, peers: Vec<ResolvedPeer>) {
        self.manager
            .reconcile(
                VrfRequirement::Resolved("unscoped".to_string()),
                Some("rt1".to_string()),
                self.local,
                peers,
                Arc::new(nos_rpl::ACCEPT_ALL.clone()),
                Vec::new(),
            )
            .await;
    }

    async fn state(&self) -> Option<BgpSessionState> {
        self.manager.peer_summaries().await.first().map(|p| p.state)
    }

    async fn wait_for(&self, want: BgpSessionState) {
        for _ in 0..200 {
            if self.state().await == Some(want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "never reached {want:?}: {:?}",
            self.manager.peer_summaries().await
        );
    }
}

fn routers() -> (Router, Router, u16) {
    let (pa, pb) = (free_port(), free_port());
    let local = |id, asn| LocalIdentity {
        asn,
        router_id: id,
        cluster_id: id,
    };
    (
        Router {
            manager: SessionManager::with_listen("a".to_string(), pa, pb, false),
            local: local(Ipv4Addr::new(1, 1, 1, 1), 65001),
        },
        Router {
            manager: SessionManager::with_listen("b".to_string(), pb, pa, false),
            local: local(Ipv4Addr::new(2, 2, 2, 2), 65002),
        },
        pa,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_instances_peer_exchange_a_route_and_follow_config_changes() {
    let (a, b, a_port) = routers();
    a.apply(vec![peer(B, A, 65002)]).await;
    b.apply(vec![peer(A, B, 65001)]).await;
    a.wait_for(BgpSessionState::Established).await;
    b.wait_for(BgpSessionState::Established).await;

    // A redistributes a static route; B learns it and would push it to its RIB.
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix: "198.51.100.0/24".parse().unwrap(),
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    let mut learned = false;
    for _ in 0..100 {
        let (table, routes) = b.manager.bgp_push_snapshot().await;
        assert_eq!(table.as_deref(), Some("rt1"));
        if routes.contains_key(&"198.51.100.0/24".parse().unwrap()) {
            learned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(learned, "b never learned a's route");

    // Operator commands and the periodic hooks all run against a live session.
    assert!(
        b.manager
            .send_command(IpAddr::V4(A), FsmCommand::SendRouteRefresh)
            .await
    );
    assert!(
        !b.manager
            .send_command(IpAddr::V4(B), FsmCommand::SendRouteRefresh)
            .await
    );
    b.manager.damping_tick().await;
    b.manager.mac_mobility_tick().await;
    b.manager
        .set_igp(std::collections::HashMap::default())
        .await;
    assert!(b.manager.evpn_route_summaries().await.is_empty());
    assert!(b.manager.fdb_push_snapshot().await.0.is_empty());

    // An unconfigured source is turned away by the listener.
    let stranger = tokio::net::TcpSocket::new_v4().unwrap();
    stranger
        .bind(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 3).into(), 0))
        .unwrap();
    let mut s = stranger
        .connect(SocketAddr::new(A.into(), a_port))
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "connection from an unconfigured peer stays closed");

    // A changed peer restarts the session (Cease, other configuration change).
    let mut changed = peer(B, A, 65002);
    changed.hold_time = 12;
    a.apply(vec![changed.clone()]).await;
    a.wait_for(BgpSessionState::Established).await;

    // Administrative shutdown with an RFC 9003 message: no session until cleared.
    changed.shutdown = Some(BgpShutdown {
        message: Some("maintenance".to_string()),
    });
    a.apply(vec![changed.clone()]).await;
    assert!(a.manager.peer_summaries().await[0].shutdown);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(b.state().await, Some(BgpSessionState::Established));
    changed.shutdown = None;
    a.apply(vec![changed]).await;
    b.wait_for(BgpSessionState::Established).await;

    // Removing the peer (Cease, peer de-configured) leaves nothing behind.
    a.apply(Vec::new()).await;
    assert!(a.manager.peer_summaries().await.is_empty());
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(b.state().await, Some(BgpSessionState::Established));

    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn md5_on_both_ends_establishes_over_localhost() {
    let (a, b, _) = routers();
    let md5 = |remote, source, asn| ResolvedPeer {
        auth: Some(ResolvedAuth::Md5("secret".to_string())),
        ..peer(remote, source, asn)
    };
    // Listener keys are primed on bind, then kept in step by later changes.
    a.apply(vec![md5(B, A, 65002)]).await;
    b.apply(vec![md5(A, B, 65001)]).await;
    a.wait_for(BgpSessionState::Established).await;
    let mut other = md5(B, A, 65002);
    other.auth = Some(ResolvedAuth::Md5("rotated".to_string()));
    a.apply(vec![other]).await;
    b.apply(vec![ResolvedPeer {
        auth: Some(ResolvedAuth::Md5("rotated".to_string())),
        ..peer(A, B, 65001)
    }])
    .await;
    a.wait_for(BgpSessionState::Established).await;
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}
