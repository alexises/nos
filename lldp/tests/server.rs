use std::time::Instant;

use futures::{SinkExt, StreamExt};
use nos_lldp::link::SharedNeighbors;
use nos_lldp::neighbor::NeighborTable;
use nos_lldp::packet::{Id, Lldpdu, CHASSIS_SUBTYPE_MAC, PORT_SUBTYPE_IF_NAME};
use nos_lldp::server;
use nos_proto::{IpcCodec, LldpEvent, LldpNeighbor, LldpRequest};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

async fn query(path: &std::path::Path) -> Vec<LldpNeighbor> {
    let stream = UnixStream::connect(path).await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<LldpEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<LldpRequest>::default());
    writer.send(LldpRequest::GetNeighbors).await.unwrap();
    let LldpEvent::Neighbors(neighbors) = reader.next().await.unwrap().unwrap();
    neighbors
}

fn pdu(chassis: u8, port: &str, name: &str) -> Lldpdu {
    Lldpdu {
        chassis_id: Id {
            subtype: CHASSIS_SUBTYPE_MAC,
            value: vec![2, 0, 0, 0, 0, chassis],
        },
        port_id: Id {
            subtype: PORT_SUBTYPE_IF_NAME,
            value: port.as_bytes().to_vec(),
        },
        ttl: 120,
        port_description: Some(port.to_string()),
        system_name: Some(name.to_string()),
        system_description: None,
        capabilities: None,
        management_addresses: Vec::new(),
    }
}

#[tokio::test]
async fn get_neighbors_lists_every_interface_sorted() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lldp.sock");
    let neighbors = SharedNeighbors::default();
    let now = Instant::now();
    for (iface, chassis, name) in [("eth2", 3, "router-c"), ("eth1", 2, "router-b")] {
        let mut table = NeighborTable::default();
        table.apply(pdu(chassis, "eth0", name), now);
        neighbors.lock().unwrap().insert(iface.to_string(), table);
    }
    let _server = server::start(&path, neighbors).unwrap();

    let all = query(&path).await;
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].local_interface, "eth1");
    assert_eq!(all[0].system_name.as_deref(), Some("router-b"));
    assert_eq!(all[0].chassis_id, "02:00:00:00:00:02");
    assert_eq!(all[0].port_id, "eth0");
    assert!(all[0].ttl_remaining_secs > 100);
    assert_eq!(all[1].local_interface, "eth2");
}

#[tokio::test]
async fn get_neighbors_with_no_links_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lldp.sock");
    let _server = server::start(&path, SharedNeighbors::default()).unwrap();
    assert!(query(&path).await.is_empty());
}
