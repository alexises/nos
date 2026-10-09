use futures::{SinkExt, StreamExt};
use nos_cli::stp_client::get_summary;
use nos_pki::testing::shared;
use nos_proto::{IpcCodec, StpEvent, StpRequest, StpSummary};
use tokio_util::codec::{FramedRead, FramedWrite};

#[tokio::test]
async fn get_summary_returns_the_summary_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("stp.sock");
    let listener = shared().identity("stpd", "").listen(&path).unwrap();
    let want = StpSummary {
        enabled: true,
        bridge_id: "8000.02:00:00:00:00:01".into(),
        ..StpSummary::default()
    };
    let sent = want.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<StpRequest>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<StpEvent>::default());
        assert!(matches!(
            reader.next().await.unwrap().unwrap(),
            StpRequest::GetSummary
        ));
        writer.send(StpEvent::Summary(sent)).await.unwrap();
    });

    assert_eq!(get_summary(&path).await.unwrap(), want);
    server.await.unwrap();
}

#[tokio::test]
async fn get_summary_reports_a_connect_error_when_nothing_listens() {
    let tmp = tempfile::tempdir().unwrap();
    let err = get_summary(&tmp.path().join("missing.sock"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("could not connect to nos-stpd"));
}

#[tokio::test]
async fn mcheck_returns_the_port_count() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("stp.sock");
    let listener = shared().identity("stpd", "").listen(&path).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<StpRequest>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<StpEvent>::default());
        let StpRequest::Mcheck { interface } = reader.next().await.unwrap().unwrap() else {
            panic!("want Mcheck");
        };
        assert_eq!(interface.as_deref(), Some("eth1"));
        writer.send(StpEvent::Mcheck { ports: 1 }).await.unwrap();
    });
    let n = nos_cli::stp_client::mcheck(&path, Some("eth1".into()))
        .await
        .unwrap();
    assert_eq!(n, 1);
    server.await.unwrap();
}
