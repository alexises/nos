//! `SessionManager` end to end over localhost (#131): two real instances,
//! each with its own listener (`with_listen`, no VRF, so no privileges),
//! peer, exchange a route, and go through the config changes `reconcile`
//! handles — restart, shutdown, removal, MD5.

use std::future::Future;
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
        hold_time: 30,
        keepalive_interval: None,
        connect_retry_time: Duration::from_millis(300),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: accept.clone(),
        export_policy: accept,
        evpn_import_policy: None,
        flowspec_import_policy: None,
        flowspec_export_policy: None,
        enforce_first_as: true,
        flowspec_relax_dest: false,
        shutdown: None,
        maximum_prefix: nos_proto::BgpMaximumPrefix::default(),
        announce_rpki_state: false,
        local_as: None,
        add_path: None,
        add_path_send_count: None,
        role: None,
        strict_mode: false,
        confed_id: None,
        confed_member: false,
        graceful_restart: Some(120),
    }
}

/// Polls `f` until it holds. The 30s bound is only a hang guard: a loaded
/// machine makes this slower, never a failure (#270).
async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !f().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct Router {
    manager: Arc<SessionManager>,
    local: LocalIdentity,
}

impl Router {
    async fn apply(&self, peers: Vec<ResolvedPeer>) {
        self.apply_with(peers, &[]).await;
    }

    async fn apply_with(&self, peers: Vec<ResolvedPeer>, rpki_caches: &[nos_proto::RpkiCache]) {
        self.manager
            .reconcile(
                VrfRequirement::Resolved("unscoped".to_string()),
                Some("rt1".to_string()),
                self.local,
                peers,
                Arc::new(nos_rpl::ACCEPT_ALL.clone()),
                Vec::new(),
                Vec::new(),
                rpki_caches,
                std::collections::HashMap::default(),
            )
            .await;
    }

    async fn state(&self) -> Option<BgpSessionState> {
        self.manager.peer_summaries().await.first().map(|p| p.state)
    }

    async fn wait_for(&self, want: BgpSessionState) {
        eventually(&format!("never reached {want:?}"), || async {
            self.state().await == Some(want)
        })
        .await;
    }
}

fn routers() -> (Router, Router, u16) {
    let (pa, pb) = (free_port(), free_port());
    let local = |id, asn| LocalIdentity {
        asn,
        router_id: id,
        cluster_id: id,
        confed_id: None,
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
    eventually("b learns a's route", || async {
        let (table, routes) = b.manager.bgp_push_snapshot().await;
        assert_eq!(table.as_deref(), Some("rt1"));
        routes.contains_key(&"198.51.100.0/24".parse().unwrap())
    })
    .await;

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
    assert_eq!(
        b.manager.evpn_route_summaries().await,
        [] as [nos_proto::EvpnRouteSummary; 0]
    );
    assert_eq!(
        b.manager.evpn_feed_snapshot(false).await.0,
        [] as [std::string::String; 0]
    );
    assert_eq!(
        b.manager.evpn_feed_snapshot(true).await.0,
        [] as [std::string::String; 0]
    );

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
    assert_eq!(
        a.manager.peer_summaries().await,
        [] as [nos_proto::PeerSummary; 0]
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(b.state().await, Some(BgpSessionState::Established));

    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// RFC 4724 / RFC 8538 (#12): with graceful restart on both sides, a config
/// change on A resets the session with Cease/Other Configuration Change, which
/// N makes graceful: B keeps A's route the whole time and shows A's
/// capability. With graceful restart off on B, the same reset withdraws it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_restart_keeps_routes_across_a_graceful_reset() {
    let prefix: ipnet::IpNet = "198.51.100.0/24".parse().unwrap();
    for gr_on_b in [true, false] {
        let (a, b, _) = routers();
        a.manager
            .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
            }]))
            .await;
        a.apply(vec![peer(B, A, 65002)]).await;
        b.apply(vec![ResolvedPeer {
            graceful_restart: gr_on_b.then_some(120),
            ..peer(A, B, 65001)
        }])
        .await;
        b.wait_for(BgpSessionState::Established).await;
        let has = || async { b.manager.bgp_push_snapshot().await.1.contains_key(&prefix) };
        eventually("b learns a's route", || async { has().await }).await;
        let gr = b.manager.peer_summaries().await[0].graceful_restart.clone();
        assert_eq!(
            gr.as_ref().map(|g| (g.restart_time, g.notification)),
            gr_on_b.then_some((120, true))
        );

        // Reset A with Cease/Other Configuration Change, and hold it down with
        // an MD5 key B lacks, so nothing reconnects until we say so: the state
        // B reaches is then stable, with no blip to catch (#270).
        let mut changed = peer(B, A, 65002);
        changed.hold_time = 12;
        let mut held_down = changed.clone();
        held_down.auth = Some(ResolvedAuth::Md5("secret".to_string()));
        a.apply(vec![held_down]).await;
        if gr_on_b {
            // Kept as stale, still handed to the RIB, for as long as A is gone.
            eventually("b keeps a's route as stale", || async {
                b.manager.peer_summaries().await[0].stale_prefixes == 1
            })
            .await;
            assert!(has().await, "graceful: the route stays while a is down");
        } else {
            eventually("b withdraws a's route", || async { !has().await }).await;
        }

        a.apply(vec![changed]).await;
        a.wait_for(BgpSessionState::Established).await;
        b.wait_for(BgpSessionState::Established).await;
        eventually("b has a's route again", || async { has().await }).await;
        eventually("no stale route left", || async {
            b.manager.peer_summaries().await[0].stale_prefixes == 0
        })
        .await;
        a.manager.shutdown().await;
        b.manager.shutdown().await;
    }
}

/// #12: `SessionManager::shutdown` (SIGINT) tells every Established peer
/// first — a Hard Reset with N exchanged — so B, which would keep A's routes
/// across a bare TCP close, drops them at once. Bounded by one `CEASE_GRACE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_sends_a_hard_reset_so_the_peer_keeps_nothing() {
    let prefix: ipnet::IpNet = "198.51.100.0/24".parse().unwrap();
    let (a, b, _) = routers();
    // A tight retry makes A's redial during the Cease grace near-certain on
    // unfixed code (#455): nothing may reconnect once shutdown began.
    let fast = |p: ResolvedPeer| ResolvedPeer {
        connect_retry_time: Duration::from_millis(20),
        ..p
    };
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    a.apply(vec![fast(peer(B, A, 65002))]).await;
    b.apply(vec![fast(peer(A, B, 65001))]).await;
    b.wait_for(BgpSessionState::Established).await;
    let has = || async { b.manager.bgp_push_snapshot().await.1.contains_key(&prefix) };
    eventually("b learns a's route", || async { has().await }).await;
    // The shutdown Cease goes only to a session A itself holds Established.
    a.wait_for(BgpSessionState::Established).await;

    a.manager.shutdown().await;
    eventually("b drops a's route after a's shutdown", || async {
        !has().await
    })
    .await;
    // Stays gone: A did not redial (three retry intervals).
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(!has().await);
    assert_ne!(b.state().await, Some(BgpSessionState::Established));
    assert_eq!(b.manager.peer_summaries().await[0].stale_prefixes, 0);
    b.manager.shutdown().await;
}

/// RFC 4486 §4 (#79): b allows one prefix from a, which sends two — b closes
/// the session and holds a down; a clear is accepted, a raised limit lets
/// both routes in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maximum_prefix_trips_holds_and_clears() {
    let (a, b, _) = routers();
    let limited = |limit| ResolvedPeer {
        maximum_prefix: nos_proto::BgpMaximumPrefix {
            ipv4: Some(nos_proto::BgpPrefixLimit {
                limit,
                ..Default::default()
            }),
            ..Default::default()
        },
        ..peer(A, B, 65001)
    };
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(
            ["198.51.100.0/24", "198.51.101.0/24"]
                .map(|p| RedistributedRoute {
                    prefix: p.parse().unwrap(),
                    gateway: "10.0.0.9".parse().unwrap(),
                })
                .to_vec(),
        ))
        .await;
    a.apply(vec![peer(B, A, 65002)]).await;
    b.apply(vec![limited(1)]).await;
    eventually("b trips", || async {
        b.manager.peer_summaries().await[0].max_prefix_held
    })
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(b.state().await, Some(BgpSessionState::Established));

    assert!(b.manager.clear_peer(IpAddr::V4(A)).await);
    assert!(!b.manager.clear_peer(IpAddr::V4(B)).await);

    b.apply(vec![limited(5)]).await;
    b.wait_for(BgpSessionState::Established).await;
    eventually("b counts both routes", || async {
        b.manager.peer_summaries().await[0].accepted_prefixes == Some([2, 0, 0])
    })
    .await;
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

/// #17 end to end over localhost: a scripted RTR cache makes A's route
/// invalid, B's import policy rejects it; a serial update makes it valid and
/// B gets it back through a route refresh, with no session reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpki_validation_follows_the_cache() {
    use futures::{SinkExt, StreamExt};
    use nos_bgp::rpki::rtr::{Intervals, Pdu, RtrCodec};
    use nos_bgp::rpki::Vrp;

    let prefix: ipnet::IpNet = "198.51.100.0/24".parse().unwrap();
    let vrp = move |asn| Vrp {
        prefix,
        max_len: 24,
        asn,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cache_addr = listener.local_addr().unwrap();
    let (proceed_tx, proceed_rx) = tokio::sync::oneshot::channel::<()>();
    let cache = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut f = tokio_util::codec::Framed::new(stream, RtrCodec { version: 1 });
        assert_eq!(f.next().await.unwrap().unwrap().pdu, Pdu::ResetQuery);
        for p in [
            Pdu::CacheResponse { session: 9 },
            Pdu::Prefix {
                announce: true,
                vrp: vrp(65999),
            },
            Pdu::EndOfData {
                session: 9,
                serial: 1,
                intervals: Some(Intervals::default()),
            },
        ] {
            f.send(p).await.unwrap();
        }
        proceed_rx.await.unwrap();
        f.send(Pdu::SerialNotify {
            session: 9,
            serial: 2,
        })
        .await
        .unwrap();
        assert_eq!(
            f.next().await.unwrap().unwrap().pdu,
            Pdu::SerialQuery {
                session: 9,
                serial: 1
            }
        );
        for p in [
            Pdu::CacheResponse { session: 9 },
            Pdu::Prefix {
                announce: false,
                vrp: vrp(65999),
            },
            Pdu::Prefix {
                announce: true,
                vrp: vrp(65001),
            },
            Pdu::EndOfData {
                session: 9,
                serial: 2,
                intervals: Some(Intervals::default()),
            },
        ] {
            f.send(p).await.unwrap();
        }
        f
    });

    let (a, b, _) = routers();
    let mut to_a = peer(A, B, 65001);
    to_a.import_policy = Arc::new(
        nos_rpl::compile(
            "if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n",
            &nos_rpl::Symbols::EMPTY,
        )
        .unwrap(),
    );
    let caches = [nos_proto::RpkiCache {
        address: cache_addr.ip(),
        port: cache_addr.port(),
        preference: 0,
        auth: None,
    }];
    a.apply(vec![peer(B, A, 65002)]).await;
    b.apply_with(vec![to_a], &caches).await;
    a.wait_for(BgpSessionState::Established).await;
    b.wait_for(BgpSessionState::Established).await;
    // Wait for the cache's first End of Data before A's route arrives.
    eventually("cache serial 1 and its VRP", || async {
        let s = &b.manager.rpki_summaries().await[0];
        s.serial == Some(1) && s.active && s.vrp_count == 1
    })
    .await;
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    let has = || async { b.manager.bgp_push_snapshot().await.1.contains_key(&prefix) };
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!has().await, "an invalid route was accepted");

    proceed_tx.send(()).unwrap();
    // B route-refreshes only RPKI_REFRESH_DELAY (5s) after the VRP change.
    eventually("the now-valid route comes back", || async { has().await }).await;
    assert_eq!(b.manager.rpki_summaries().await[0].serial, Some(2));
    b.wait_for(BgpSessionState::Established).await;
    let _cache = cache.await.unwrap();

    // Removing the caches empties the VRP set.
    b.apply_with(vec![peer(A, B, 65001)], &[]).await;
    assert_eq!(b.manager.rpki_summaries().await, []);
}
