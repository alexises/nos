use futures::{SinkExt, StreamExt};
use nos_cli::lldp_client::get_neighbors;
use nos_pki::testing::shared;
use nos_proto::{IpcCodec, LldpEvent, LldpNeighbor, LldpRequest};
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample() -> LldpNeighbor {
    LldpNeighbor {
        local_interface: "eth1".to_string(),
        chassis_id: "02:00:00:00:00:02".to_string(),
        port_id: "eth1".to_string(),
        port_description: Some("eth1".to_string()),
        system_name: Some("router-b".to_string()),
        system_description: Some("nos 0.1.0".to_string()),
        capabilities: vec!["router".to_string()],
        management_addresses: vec!["10.0.0.2".to_string()],
        ttl_remaining_secs: 117,
    }
}

#[tokio::test]
async fn get_neighbors_returns_neighbors_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lldp.sock");
    let listener = shared().identity("lldpd", "").listen(&path).unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<LldpRequest>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<LldpEvent>::default());
        let got = reader.next().await.unwrap().unwrap();
        assert!(matches!(got, LldpRequest::GetNeighbors));
        writer
            .send(LldpEvent::Neighbors(vec![sample()]))
            .await
            .unwrap();
    });

    assert_eq!(get_neighbors(&path).await.unwrap(), vec![sample()]);
    server.await.unwrap();
}

#[tokio::test]
async fn get_neighbors_reports_a_connect_error_when_nothing_listens() {
    let tmp = tempfile::tempdir().unwrap();
    let err = get_neighbors(&tmp.path().join("missing.sock"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("could not connect to nos-lldpd"));
}
