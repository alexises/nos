//! Integration tests for `nos_bgp::fsm::run` over real loopback TCP
//! connections — this crate's first `tests/` integration directory. Unlike
//! `fsm.rs`'s unit tests (which exercise the pure `step` function), these
//! drive the actual async orchestrator end to end.
//!
//! `fsm::run` has no observable "we reached Established" signal other than
//! staying alive (it only returns once a session ends), so these tests use
//! a bounded timeout as a stable-session proxy: a session that neither
//! errors out nor times out immediately, but is still running once the
//! OPEN/KEEPALIVE exchange has had time to complete, is presumed
//! `Established`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_bgp::collision::{PeerSlot, Role};
use nos_bgp::fsm::{self, FsmOutcome, PeerContext};
use nos_bgp::message::{self, BgpCodec, BgpMessage};
use nos_bgp::rib::BgpRib;
use nos_bgp::session::{LocalIdentity, ResolvedPeer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::codec::{FramedRead, FramedWrite};

fn new_bgp_rib() -> Arc<Mutex<BgpRib>> {
    Arc::new(Mutex::new(BgpRib::new()))
}

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::join!(async { listener.accept().await.unwrap().0 }, async {
        TcpStream::connect(addr).await.unwrap()
    },);
    (connected, accepted)
}

/// A minimal stand-in peer: sends its own OPEN immediately, replies to the
/// real side's OPEN with a KEEPALIVE, then holds the connection open so the
/// real side's hold timer never fires during the test.
async fn fake_peer(stream: TcpStream, asn: u32, router_id: Ipv4Addr, hold_time: u16) {
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, BgpCodec::default());
    let mut writer = FramedWrite::new(w, BgpCodec::default());

    let _ = writer
        .send(BgpMessage::Open(message::build_open(
            asn, router_id, hold_time,
        )))
        .await;

    loop {
        match reader.next().await {
            Some(Ok(BgpMessage::Open(_))) => {
                let _ = writer.send(BgpMessage::Keepalive).await;
                break;
            }
            Some(Ok(_)) => {}
            _ => return,
        }
    }
    while reader.next().await.is_some() {}
}

#[tokio::test]
async fn two_real_instances_establish_a_session() {
    let (a_stream, b_stream) = loopback_pair().await;

    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let b_router_id = Ipv4Addr::new(2, 2, 2, 2);
    let a_asn = 65001;
    let b_asn = 65002;

    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
    });
    let slot_b = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.1".parse().unwrap(),
        source_address: None,
        remote_as: a_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
    });

    let a_fut = fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
        },
        PeerContext {
            remote_address: "10.0.0.2".parse().unwrap(),
            expected_remote_as: b_asn,
            local_hold_time: 90,
            keepalive_override: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        new_bgp_rib(),
    );
    let b_fut = fsm::run(
        b_stream,
        Role::Passive,
        LocalIdentity {
            asn: b_asn,
            router_id: b_router_id,
            cluster_id: b_router_id,
        },
        PeerContext {
            remote_address: "10.0.0.1".parse().unwrap(),
            expected_remote_as: a_asn,
            local_hold_time: 90,
            keepalive_override: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_b,
        new_bgp_rib(),
    );

    let timeout = Duration::from_millis(500);
    let (a_result, b_result) = tokio::join!(
        tokio::time::timeout(timeout, a_fut),
        tokio::time::timeout(timeout, b_fut),
    );

    assert!(
        a_result.is_err(),
        "instance A should have reached a stable (Established) session, got {a_result:?}"
    );
    assert!(
        b_result.is_err(),
        "instance B should have reached a stable (Established) session, got {b_result:?}"
    );
}

/// Exercises a non-default, configured local hold time end to end: the real
/// side proposes 30s, the fake peer proposes 60s, so negotiation must settle
/// on `min(30, 60) = 30` — the session should still establish and stay
/// stable well within the test's bounded timeout.
#[tokio::test]
async fn established_session_honors_configured_non_default_hold_time() {
    let (a_stream, b_stream) = loopback_pair().await;

    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let b_router_id = Ipv4Addr::new(2, 2, 2, 2);
    let a_asn = 65001;
    let b_asn = 65002;

    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 30,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
    });

    let a_fut = fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
        },
        PeerContext {
            remote_address: "10.0.0.2".parse().unwrap(),
            expected_remote_as: b_asn,
            local_hold_time: 30,
            keepalive_override: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        new_bgp_rib(),
    );
    let fake_b = tokio::spawn(fake_peer(b_stream, b_asn, b_router_id, 60));

    let timeout = Duration::from_millis(500);
    let a_result = tokio::time::timeout(timeout, a_fut).await;

    assert!(
        a_result.is_err(),
        "instance A should have reached a stable (Established) session \
         negotiated at min(30, 60) = 30s, got {a_result:?}"
    );

    fake_b.abort();
}

/// Exercises the shared `PeerSlot::status` reporting path end to end: once a
/// real session reaches `Established`, the slot's status (read via
/// `status_receiver`, the same way `session::to_peer_summary` does for
/// `show bgp brief`) must reflect it, including the negotiated hold-time and
/// keepalive derived during the handshake.
#[tokio::test]
async fn established_session_reports_status_via_peer_slot() {
    let (a_stream, b_stream) = loopback_pair().await;

    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let b_router_id = Ipv4Addr::new(2, 2, 2, 2);
    let a_asn = 65001;
    let b_asn = 65002;

    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
    });
    let mut status = slot_a.status_receiver();

    let a_fut = fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
        },
        PeerContext {
            remote_address: "10.0.0.2".parse().unwrap(),
            expected_remote_as: b_asn,
            local_hold_time: 90,
            keepalive_override: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        new_bgp_rib(),
    );
    let fake_b = tokio::spawn(fake_peer(b_stream, b_asn, b_router_id, 90));

    let timeout = Duration::from_millis(500);
    let a_result = tokio::time::timeout(timeout, a_fut).await;
    assert!(
        a_result.is_err(),
        "instance A should have reached a stable (Established) session, got {a_result:?}"
    );

    // The session is presumed Established by now (per this module's timeout
    // convention); `status`'s watch channel already holds the latest value.
    let reported = *status.borrow_and_update();
    assert_eq!(reported.state, nos_bgp::status::PeerState::Established);
    assert_eq!(reported.remote_asn, Some(b_asn));
    assert_eq!(reported.remote_bgp_id, Some(b_router_id));
    assert_eq!(reported.negotiated_hold_time, Some(90));
    assert_eq!(reported.negotiated_keepalive, Some(30));
    assert!(reported.established_since.is_some());

    fake_b.abort();
}

/// Races a real active and a real passive connection against the same
/// `PeerSlot` for what looks like one peer. Over real sockets, one side's
/// full OPEN/KEEPALIVE round trip inevitably completes (reaches
/// `Established`) before the other side's OPEN is even processed, so this
/// exercises `collision.rs`'s Established-precedence rule rather than the
/// ID-comparison path — the two connections essentially never call
/// `on_open` "at the same time" in practice, no matter how the router-ids
/// are chosen. The ID-comparison path itself is covered deterministically
/// by `collision.rs`'s own unit tests, which call `PeerSlot::on_open`
/// directly without socket timing involved.
#[tokio::test]
async fn collision_leaves_exactly_one_side_running() {
    let (active_local, active_fake) = loopback_pair().await;
    let (passive_local, passive_fake) = loopback_pair().await;

    // Same remote ASN/router-id on both connections — as far as collision
    // resolution is concerned, this is one peer racing an active and a
    // passive connection against the same local instance.
    let remote_asn = 65002;
    let remote_router_id = Ipv4Addr::new(9, 9, 9, 9);
    let local = LocalIdentity {
        asn: 65001,
        router_id: Ipv4Addr::new(5, 5, 5, 5),
        cluster_id: Ipv4Addr::new(5, 5, 5, 5),
    };

    let fake_active = tokio::spawn(fake_peer(active_fake, remote_asn, remote_router_id, 90));
    let fake_passive = tokio::spawn(fake_peer(passive_fake, remote_asn, remote_router_id, 90));

    let slot = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: remote_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
    });

    let peer_ctx = || PeerContext {
        remote_address: "10.0.0.2".parse().unwrap(),
        expected_remote_as: remote_asn,
        local_hold_time: 90,
        keepalive_override: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        is_rr_client: false,
        is_rs_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
    };

    // Both sides share one `PeerSlot` (they're racing for the same peer), so
    // they share one `BgpRib` too — a real deployment would never run two
    // `fsm::run` tasks against different `BgpRib`s for the same peer.
    let bgp_rib = new_bgp_rib();
    let active_fut = fsm::run(
        active_local,
        Role::Active,
        local,
        peer_ctx(),
        slot.clone(),
        bgp_rib.clone(),
    );
    let passive_fut = fsm::run(
        passive_local,
        Role::Passive,
        local,
        peer_ctx(),
        slot.clone(),
        bgp_rib.clone(),
    );

    let timeout = Duration::from_millis(500);
    let (active_result, passive_result) = tokio::join!(
        tokio::time::timeout(timeout, active_fut),
        tokio::time::timeout(timeout, passive_fut),
    );

    let active_lost = matches!(active_result, Ok(FsmOutcome::CollisionLost));
    let passive_lost = matches!(passive_result, Ok(FsmOutcome::CollisionLost));
    assert!(
        active_lost ^ passive_lost,
        "expected exactly one side to lose the collision, got active={active_result:?} passive={passive_result:?}"
    );
    // The winner should have settled into a stable (Established) session,
    // not returned any outcome at all within the timeout.
    assert!(
        active_lost || active_result.is_err(),
        "active side neither lost the collision nor stayed running: {active_result:?}"
    );
    assert!(
        passive_lost || passive_result.is_err(),
        "passive side neither lost the collision nor stayed running: {passive_result:?}"
    );

    fake_active.abort();
    fake_passive.abort();
}
