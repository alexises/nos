use std::net::Ipv4Addr;

use futures::{SinkExt, StreamExt};
use nos_cli::client::{fetch_running_config, ClientError};
use nos_proto::{BgpInstance, Config, Event, IpcCodec, Request};
use tokio::net::UnixListener;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_config() -> Config {
    Config {
        bgp_instances: vec![BgpInstance {
            name: "default".to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
        }],
    }
}

/// Accepts a single connection, reads one `Request`, and replies with the given `Event`.
async fn serve_once(listener: UnixListener, reply: Event) {
    let (stream, _) = listener.accept().await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<Request>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Event>::default());

    assert!(matches!(reader.next().await, Some(Ok(Request::Get))));
    writer.send(reply).await.unwrap();
}

#[tokio::test]
async fn returns_config_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(listener, Event::Config(sample_config())));

    let cfg = fetch_running_config(&path).await.unwrap();
    assert_eq!(cfg, sample_config());

    server.await.unwrap();
}

#[tokio::test]
async fn returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(listener, Event::Error("boom".to_string())));

    let err = fetch_running_config(&path).await.unwrap_err();
    assert!(matches!(err, ClientError::Daemon(msg) if msg == "boom"));

    server.await.unwrap();
}

#[tokio::test]
async fn returns_connect_error_for_missing_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("does-not-exist.sock");

    let err = fetch_running_config(&path).await.unwrap_err();
    assert!(matches!(err, ClientError::Connect { .. }));
}
