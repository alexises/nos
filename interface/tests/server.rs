use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_interface::driver::NoopInterfaceDriver;
use nos_interface::{server, Interfaces};
use nos_pki::testing::shared;
use nos_proto::{InterfaceAddress, InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec};
use tokio::sync::RwLock;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_address() -> InterfaceAddress {
    InterfaceAddress {
        address: "10.0.0.1/24".parse().unwrap(),
        label: None,
    }
}

async fn sample_interfaces() -> Interfaces {
    // `Interfaces` has no public constructor from a map, so build it through
    // the same path production code uses.
    let cfg = nos_proto::Config {
        interfaces: vec![
            nos_proto::Interface {
                ospfv3_profile: None,
                name: "eth0".to_string(),
                addresses: vec![],
                routing_table: None,
                ospf_profile: None,
                switching_profile: None,
                port_aggregate: None,
                lacp_port_priority: None,
                lacp_mode: nos_proto::LacpMode::default(),
                mtu: None,
                lldp_transmit: false,
                lldp_receive: false,
                lldp_destination: nos_proto::LldpDestination::default(),
                subinterfaces: vec![nos_proto::Subinterface {
                    ospfv3_profile: None,
                    bfd_unsolicited: None,
                    tag: 0,
                    addresses: vec![sample_address()],
                    routing_table: Some("rt1".to_string()),
                    ospf_profile: None,
                }],
                ..Default::default()
            },
            nos_proto::Interface {
                ospfv3_profile: None,
                name: "eth1".to_string(),
                addresses: vec![],
                routing_table: None,
                ospf_profile: None,
                switching_profile: None,
                port_aggregate: None,
                lacp_port_priority: None,
                lacp_mode: nos_proto::LacpMode::default(),
                mtu: None,
                lldp_transmit: false,
                lldp_receive: false,
                lldp_destination: nos_proto::LldpDestination::default(),
                subinterfaces: vec![],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    nos_interface::state::build_from_config(&cfg, &NoopInterfaceDriver, &Interfaces::new()).await
}

async fn connect(
    path: &std::path::Path,
) -> (
    FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<InterfaceEvent>>,
    FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<InterfaceRequest>>,
) {
    let stream = shared()
        .identity("user", "tester")
        .connect(path, &nos_pki::PeerId::new("interfaced", ""))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::<InterfaceEvent>::default()),
        FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default()),
    )
}

#[tokio::test]
async fn get_interfaces_returns_every_interface_sorted_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces().await));
    let _server = server::start(
        &path,
        interfaces,
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(InterfaceRequest::GetInterfaces).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    let InterfaceEvent::Interfaces(statuses) = event else {
        panic!("expected Interfaces, got {event:?}");
    };
    assert_eq!(statuses.len(), 2);
    assert_eq!(statuses[0].name, "eth0");
    assert_eq!(statuses[1].name, "eth1");
}

#[tokio::test]
async fn get_interface_returns_matching_status() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces().await));
    let _server = server::start(
        &path,
        interfaces,
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(InterfaceRequest::GetInterface {
            name: "eth0".to_string(),
        })
        .await
        .unwrap();
    let event = reader.next().await.unwrap().unwrap();

    let InterfaceEvent::Interface(InterfaceStatus {
        name,
        subinterfaces,
        ..
    }) = event
    else {
        panic!("expected Interface, got {event:?}");
    };
    assert_eq!(name, "eth0");
    let tag0 = subinterfaces.iter().find(|s| s.tag == 0).unwrap();
    assert_eq!(tag0.addresses, vec![sample_address()]);
    assert_eq!(tag0.routing_table.as_deref(), Some("rt1"));
}

#[tokio::test]
async fn get_interface_missing_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces().await));
    let _server = server::start(
        &path,
        interfaces,
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(InterfaceRequest::GetInterface {
            name: "eth9".to_string(),
        })
        .await
        .unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, InterfaceEvent::NotFound));
}

#[tokio::test]
async fn push_bfd_members_enslaves_the_up_member_immediately() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let cfg = nos_proto::Config {
        interfaces: vec![nos_proto::Interface {
            name: "eth0".to_string(),
            port_aggregate: Some("bond1".to_string()),
            ..Default::default()
        }],
        port_aggregates: vec![nos_proto::PortAggregate {
            name: "bond1".to_string(),
            bfd: Some("fast".to_string()),
            bfd_peer: Some("10.0.0.2".parse().unwrap()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let interfaces = Arc::new(RwLock::new(
        nos_interface::state::build_from_config(&cfg, &NoopInterfaceDriver, &Interfaces::new())
            .await,
    ));
    assert!(
        !interfaces
            .read()
            .await
            .get("eth0")
            .unwrap()
            .port_aggregate_active
    );
    let _server = server::start(
        &path,
        interfaces.clone(),
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let stream = shared()
        .identity("bfdd", "")
        .connect(&path, &nos_pki::PeerId::new("interfaced", ""))
        .await
        .unwrap();
    let mut writer = FramedWrite::new(stream, IpcCodec::<InterfaceRequest>::default());
    writer
        .send(InterfaceRequest::PushBfdMembers(
            nos_proto::BfdAggregateMembers {
                aggregate: "bond1".to_string(),
                up_members: vec!["eth0".to_string()],
            },
        ))
        .await
        .unwrap();

    for _ in 0..50 {
        if interfaces
            .read()
            .await
            .get("eth0")
            .unwrap()
            .port_aggregate_active
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("eth0 never became active");
}

// ---- live role gate (#364): refused roles are disconnected, others served ----

async fn connect_role(
    path: &std::path::Path,
    role: nos_proto::Role,
) -> (
    FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<InterfaceEvent>>,
    FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<InterfaceRequest>>,
) {
    let stream = shared()
        .identity(role.as_str(), "x")
        .connect(path, &nos_pki::PeerId::new("interfaced", ""))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::<InterfaceEvent>::default()),
        FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default()),
    )
}

#[tokio::test]
async fn queries_and_pushes_are_gated_by_role_over_the_live_server() {
    use nos_proto::Role;
    use std::time::Duration;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces().await));
    let _server = server::start(
        &path,
        interfaces,
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let queriers = [
        Role::User,
        Role::Restd,
        Role::Bgpd,
        Role::Ribd,
        Role::Ospfd,
        Role::Ospfv3d,
        Role::Fdbd,
    ];
    for role in Role::ALL {
        // A query: a real reply for the allow list, a closed connection else.
        let (mut r, mut w) = connect_role(&path, role).await;
        w.send(InterfaceRequest::GetInterfaces).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), r.next())
            .await
            .unwrap_or_else(|_| panic!("{role:?}: connection left open with no reply"));
        if queriers.contains(&role) {
            assert!(
                matches!(reply, Some(Ok(InterfaceEvent::Interfaces(ref v))) if v.len() == 2),
                "{role:?}: {reply:?}"
            );
        } else {
            assert!(
                reply.is_none_or(|e| e.is_err()),
                "{role:?} must get no reply"
            );
        }

        // The pushes are fire-and-forget: kept open for the one owner,
        // disconnected for everyone else.
        let pushes: [(Role, InterfaceRequest); 3] = [
            (
                Role::Lacpd,
                InterfaceRequest::PushLacpMembers(nos_proto::LacpAggregateMembers {
                    aggregate: "nope".to_string(),
                    active_members: vec![],
                }),
            ),
            (
                Role::Bfdd,
                InterfaceRequest::PushBfdMembers(nos_proto::BfdAggregateMembers {
                    aggregate: "nope".to_string(),
                    up_members: vec![],
                }),
            ),
            (Role::Stpd, InterfaceRequest::SetStpPortStates(Vec::new())),
        ];
        for (owner, req) in pushes {
            let (mut r, mut w) = connect_role(&path, role).await;
            w.send(req).await.unwrap();
            let next = tokio::time::timeout(
                Duration::from_secs(if role == owner { 1 } else { 5 }),
                r.next(),
            )
            .await;
            if role == owner {
                assert!(next.is_err(), "{role:?} owns this push but was refused");
            } else {
                let closed = next.unwrap_or_else(|_| {
                    panic!("{role:?}: a refused push left the connection open")
                });
                assert!(closed.is_none_or(|e| e.is_err()), "{role:?}");
            }
        }
    }
}
