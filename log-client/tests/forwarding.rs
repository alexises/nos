use futures::StreamExt;
use nos_log_client::ForwardingLayer;
use nos_pki::testing::shared;
use nos_proto::{IpcCodec, LogLevel, LogRequest};
use tokio::sync::watch;
use tokio_util::codec::FramedRead;
use tracing_subscriber::layer::SubscriberExt;

/// The layer is installed before `nos-logd` listens: the first connect fails,
/// the entries wait in the channel, and the retry delivers them in order with
/// their level, target, message and fields.
#[tokio::test]
async fn queued_events_reach_logd_once_it_listens() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log.sock");
    let (shutdown_tx, shutdown) = watch::channel(false);
    let layer = ForwardingLayer::install(
        "bgpd/r1",
        path.clone(),
        shared().identity("bgpd", "r1"),
        shutdown,
    );
    tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
        tracing::info!(peer = 7, "hello");
        tracing::trace!("t");
        tracing::debug!("d");
        tracing::warn!("w");
        tracing::error!("e");
    });

    let listener = shared().identity("logd", "").listen(&path).unwrap();
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let mut reader = FramedRead::new(stream, IpcCodec::<LogRequest>::default());
    let mut got = Vec::new();
    for _ in 0..5 {
        let LogRequest::Push(entry) = reader.next().await.unwrap().unwrap() else {
            panic!("expected a push");
        };
        got.push(entry);
    }
    assert_eq!(got[0].source, "bgpd/r1");
    assert_eq!(got[0].target, "forwarding");
    assert_eq!(got[0].message, "hello");
    assert_eq!(got[0].fields, vec![("peer".to_string(), "7".to_string())]);
    assert!(got[0].timestamp_ms > 0);
    let levels: Vec<_> = got.iter().map(|e| e.level).collect();
    assert_eq!(
        levels,
        [
            LogLevel::Info,
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Warn,
            LogLevel::Error
        ]
    );
    // The subscriber (and so the layer's sender) is gone: the task has exited.
    shutdown_tx.closed().await;
}

/// Shutdown while `nos-logd` is unreachable ends the reconnect loop.
#[tokio::test]
async fn shutdown_stops_the_retry_loop() {
    let tmp = tempfile::tempdir().unwrap();
    let (shutdown_tx, shutdown) = watch::channel(false);
    let _layer = ForwardingLayer::install(
        "bgpd/r1",
        tmp.path().join("missing.sock"),
        shared().identity("bgpd", "r1"),
        shutdown,
    );
    tokio::task::yield_now().await;
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), shutdown_tx.closed())
        .await
        .expect("the forwarding task exits on shutdown");
}
