use futures::{SinkExt, StreamExt};
use nos_cli::interface_client::{get_interface, get_interfaces};
use nos_proto::{InterfaceAddress, InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec};
use tokio::net::UnixListener;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_status() -> InterfaceStatus {
    InterfaceStatus {
        name: "eth0".to_string(),
        addresses: vec![InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        }],
        routing_table: Some("rt1".to_string()),
        switching_profile: None,
        subinterfaces: vec![],
    }
}

async fn serve_once(listener: UnixListener, expected: InterfaceRequest, reply: InterfaceEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<InterfaceRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceEvent>::default());

    let got = reader.next().await.unwrap().unwrap();
    assert_eq!(format!("{got:?}"), format!("{expected:?}"));
    writer.send(reply).await.unwrap();
}

#[tokio::test]
async fn get_interfaces_returns_statuses_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        InterfaceRequest::GetInterfaces,
        InterfaceEvent::Interfaces(vec![sample_status()]),
    ));

    let statuses = get_interfaces(&path).await.unwrap();
    assert_eq!(statuses, vec![sample_status()]);

    server.await.unwrap();
}

#[tokio::test]
async fn get_interface_returns_status_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        InterfaceRequest::GetInterface {
            name: "eth0".to_string(),
        },
        InterfaceEvent::Interface(sample_status()),
    ));

    let status = get_interface(&path, "eth0").await.unwrap();
    assert_eq!(status, Some(sample_status()));

    server.await.unwrap();
}

#[tokio::test]
async fn get_interface_returns_none_on_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        InterfaceRequest::GetInterface {
            name: "eth9".to_string(),
        },
        InterfaceEvent::NotFound,
    ));

    let status = get_interface(&path, "eth9").await.unwrap();
    assert_eq!(status, None);

    server.await.unwrap();
}
