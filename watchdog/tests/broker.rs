use std::path::PathBuf;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, ServiceRef, WatchdogEvent, WatchdogRequest};
use nos_watchdog::{broker, EndpointRegistry};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[tokio::test]
async fn resolves_config_and_registered_rib_table() {
    let tmp = tempfile::tempdir().unwrap();
    let broker_socket = tmp.path().join("watchdog.sock");
    let config_socket = PathBuf::from("/run/nos/config.sock");
    let interfaces_socket = PathBuf::from("/run/nos/interface.sock");

    let registry = EndpointRegistry::default();
    registry
        .set_rib_table("rt1", PathBuf::from("/run/nos/rib-rt1.sock"))
        .await;

    let _server = broker::start(
        &broker_socket,
        registry,
        config_socket.clone(),
        interfaces_socket.clone(),
    )
    .unwrap();

    let stream = UnixStream::connect(&broker_socket).await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());

    writer
        .send(WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::Config,
        })
        .await
        .unwrap();
    let event = reader.next().await.unwrap().unwrap();
    assert!(matches!(event, WatchdogEvent::Endpoint(p) if p == config_socket));

    writer
        .send(WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::RibTable("rt1".to_string()),
        })
        .await
        .unwrap();
    let event = reader.next().await.unwrap().unwrap();
    assert!(
        matches!(event, WatchdogEvent::Endpoint(p) if p == std::path::Path::new("/run/nos/rib-rt1.sock"))
    );

    writer
        .send(WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::RibTable("unknown".to_string()),
        })
        .await
        .unwrap();
    let event = reader.next().await.unwrap().unwrap();
    assert!(matches!(event, WatchdogEvent::NotAvailable));

    writer
        .send(WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::Interfaces,
        })
        .await
        .unwrap();
    let event = reader.next().await.unwrap().unwrap();
    assert!(matches!(event, WatchdogEvent::Endpoint(p) if p == interfaces_socket));
}
