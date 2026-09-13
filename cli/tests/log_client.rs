use futures::{SinkExt, StreamExt};
use nos_cli::log_client::{get_logs, tail};
use nos_proto::{IpcCodec, LogEntry, LogEvent, LogLevel, LogRequest};
use tokio::net::UnixListener;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_entry() -> LogEntry {
    LogEntry {
        timestamp_ms: 1,
        level: LogLevel::Info,
        source: "nos-ribd[rt1]".to_string(),
        target: "nos_rib::reconcile".to_string(),
        message: "resynced".to_string(),
        fields: Vec::new(),
    }
}

async fn serve_once(listener: UnixListener, expected: LogRequest, reply: LogEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<LogRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<LogEvent>::default());

    let got = reader.next().await.unwrap().unwrap();
    assert_eq!(format!("{got:?}"), format!("{expected:?}"));
    writer.send(reply).await.unwrap();
}

#[tokio::test]
async fn get_logs_returns_entries_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        LogRequest::GetLogs {
            source: None,
            limit: None,
        },
        LogEvent::Logs(vec![sample_entry()]),
    ));

    let logs = get_logs(&path, None, None).await.unwrap();
    assert_eq!(logs, vec![sample_entry()]);

    server.await.unwrap();
}

#[tokio::test]
async fn get_logs_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        LogRequest::GetLogs {
            source: Some("nos-ribd[rt1]".to_string()),
            limit: None,
        },
        LogEvent::Error("boom".to_string()),
    ));

    let err = get_logs(&path, Some("nos-ribd[rt1]".to_string()), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("boom"));

    server.await.unwrap();
}

#[tokio::test]
async fn tail_streams_initial_snapshot_then_new_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = FramedRead::new(r, IpcCodec::<LogRequest>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<LogEvent>::default());

        let got = reader.next().await.unwrap().unwrap();
        assert_eq!(got, LogRequest::Tail { source: None });
        writer.send(LogEvent::Logs(vec![])).await.unwrap();
        writer.send(LogEvent::Line(sample_entry())).await.unwrap();
    });

    let mut reader = tail(&path, None).await.unwrap();
    assert_eq!(
        reader.next().await.unwrap().unwrap(),
        LogEvent::Logs(vec![])
    );
    assert_eq!(
        reader.next().await.unwrap().unwrap(),
        LogEvent::Line(sample_entry())
    );

    server.await.unwrap();
}
