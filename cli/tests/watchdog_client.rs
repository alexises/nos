use futures::{SinkExt, StreamExt};
use nos_cli::watchdog_client::resolve;
use nos_proto::{IpcCodec, ServiceRef, WatchdogEvent, WatchdogRequest};
use tokio::net::UnixListener;
use tokio_util::codec::{FramedRead, FramedWrite};

async fn serve_once(listener: UnixListener, expected: WatchdogRequest, reply: WatchdogEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogEvent>::default());

    let got = reader.next().await.unwrap().unwrap();
    assert_eq!(format!("{got:?}"), format!("{expected:?}"));
    writer.send(reply).await.unwrap();
}

#[tokio::test]
async fn resolves_to_endpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("watchdog.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::Config,
        },
        WatchdogEvent::Endpoint("/run/nos/config.sock".into()),
    ));

    let resolved = resolve(&path, ServiceRef::Config).await.unwrap();
    assert_eq!(resolved, Some("/run/nos/config.sock".into()));

    server.await.unwrap();
}

#[tokio::test]
async fn not_available_resolves_to_none() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("watchdog.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::RibTable("rt1".to_string()),
        },
        WatchdogEvent::NotAvailable,
    ));

    let resolved = resolve(&path, ServiceRef::RibTable("rt1".to_string()))
        .await
        .unwrap();
    assert_eq!(resolved, None);

    server.await.unwrap();
}

#[tokio::test]
async fn missing_socket_is_a_connect_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("does-not-exist.sock");
    assert!(resolve(&path, ServiceRef::Config).await.is_err());
}
