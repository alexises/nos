use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_interface::{server, InterfaceState, Interfaces};
use nos_proto::{InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec};
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_interfaces() -> Interfaces {
    let mut by_name = std::collections::HashMap::new();
    by_name.insert(
        "eth0".to_string(),
        InterfaceState {
            name: "eth0".to_string(),
            addresses: vec!["10.0.0.1/24".parse().unwrap()],
            routing_table: Some("rt1".to_string()),
        },
    );
    by_name.insert(
        "eth1".to_string(),
        InterfaceState {
            name: "eth1".to_string(),
            addresses: vec![],
            routing_table: None,
        },
    );
    // `Interfaces` has no public constructor from a map, so build it through
    // the same path production code uses.
    let cfg = nos_proto::Config {
        interfaces: by_name
            .values()
            .cloned()
            .map(|s| nos_proto::Interface {
                name: s.name,
                addresses: s.addresses,
                routing_table: s.routing_table,
            })
            .collect(),
        ..Default::default()
    };
    nos_interface::state::build_from_config(&cfg)
}

async fn connect(
    path: &std::path::Path,
) -> (
    FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<InterfaceEvent>>,
    FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<InterfaceRequest>>,
) {
    let stream = UnixStream::connect(path).await.unwrap();
    let (r, w) = stream.into_split();
    (
        FramedRead::new(r, IpcCodec::<InterfaceEvent>::default()),
        FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default()),
    )
}

#[tokio::test]
async fn get_interfaces_returns_every_interface_sorted_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces()));
    let _server = server::start(&path, interfaces).unwrap();

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
    let interfaces = Arc::new(RwLock::new(sample_interfaces()));
    let _server = server::start(&path, interfaces).unwrap();

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
        addresses,
        routing_table,
    }) = event
    else {
        panic!("expected Interface, got {event:?}");
    };
    assert_eq!(name, "eth0");
    assert_eq!(addresses, vec!["10.0.0.1/24".parse().unwrap()]);
    assert_eq!(routing_table.as_deref(), Some("rt1"));
}

#[tokio::test]
async fn get_interface_missing_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces()));
    let _server = server::start(&path, interfaces).unwrap();

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
