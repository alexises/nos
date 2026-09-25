use futures::{SinkExt, StreamExt};
use nos_cli::watchdog_client::{login, renew, resolve, WatchdogClientError};
use nos_pki::testing::shared;
use nos_proto::{IpcCodec, ServiceRef, WatchdogEvent, WatchdogRequest};
use tokio_util::codec::{FramedRead, FramedWrite};

async fn serve_once(listener: nos_pki::Listener, expected: WatchdogRequest, reply: WatchdogEvent) {
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let (r, w) = tokio::io::split(stream);
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
    let listener = shared().identity("watchdog", "").listen(&path).unwrap();

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
    let listener = shared().identity("watchdog", "").listen(&path).unwrap();

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

#[tokio::test]
async fn login_returns_the_issued_certificate_and_its_lifetime() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("watchdog.sock");
    let listener = shared().identity("watchdog", "").listen(&path).unwrap();
    let server = tokio::spawn(serve_once(
        listener,
        WatchdogRequest::Login {
            user: "alice".into(),
            password: "pw".into(),
            csr_der: vec![1],
        },
        WatchdogEvent::Issued {
            cert_der: vec![9, 9],
            lifetime_secs: 60,
        },
    ));

    let issued = login(&path, "alice", "pw", vec![1]).await.unwrap();
    assert_eq!(issued.cert_der, vec![9, 9]);
    assert_eq!(issued.lifetime, std::time::Duration::from_secs(60));
    server.await.unwrap();
}

#[tokio::test]
async fn a_refused_login_is_reported_as_denied_not_as_an_io_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("watchdog.sock");
    let listener = shared().identity("watchdog", "").listen(&path).unwrap();
    let server = tokio::spawn(serve_once(
        listener,
        WatchdogRequest::Login {
            user: "alice".into(),
            password: "wrong".into(),
            csr_der: vec![1],
        },
        WatchdogEvent::Denied("invalid credentials".into()),
    ));

    match login(&path, "alice", "wrong", vec![1]).await {
        Err(WatchdogClientError::Denied(reason)) => assert_eq!(reason, "invalid credentials"),
        other => panic!("expected Denied, got {other:?}"),
    }
    server.await.unwrap();
}

#[tokio::test]
async fn renew_returns_a_fresh_certificate() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("watchdog.sock");
    let listener = shared().identity("watchdog", "").listen(&path).unwrap();
    let server = tokio::spawn(serve_once(
        listener,
        WatchdogRequest::RenewCert { csr_der: vec![2] },
        WatchdogEvent::Issued {
            cert_der: vec![7],
            lifetime_secs: 30,
        },
    ));
    assert_eq!(renew(&path, vec![2]).await.unwrap().cert_der, vec![7]);
    server.await.unwrap();
}
