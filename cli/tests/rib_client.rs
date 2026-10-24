use futures::{SinkExt, StreamExt};
use nos_cli::rib_client::{get_routes, get_vpn_label, lookup};
use nos_pki::testing::shared;
use nos_proto::{IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteEntry, RouteSourceKind};
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_prefix_routes() -> PrefixRoutes {
    PrefixRoutes {
        prefix: "10.0.0.0/24".parse().unwrap(),
        candidates: vec![RouteEntry {
            gateways: vec!["10.0.0.1".parse().unwrap()],
            source: RouteSourceKind::Static,
            backup: None,
            discard: false,
            evpn: None,
            backup_tunnel: false,
            mpls_labels: vec![],
            vpn: None,
        }],
    }
}

async fn serve_once(listener: nos_pki::Listener, expected: RibRequest, reply: RibEvent) {
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<RibRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<RibEvent>::default());

    let got = reader.next().await.unwrap().unwrap();
    assert_eq!(format!("{got:?}"), format!("{expected:?}"));
    writer.send(reply).await.unwrap();
}

#[tokio::test]
async fn get_routes_returns_routes_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        RibRequest::GetRoutes,
        RibEvent::Routes(vec![sample_prefix_routes()]),
    ));

    let routes = get_routes(&path).await.unwrap();
    assert_eq!(routes, vec![sample_prefix_routes()]);

    server.await.unwrap();
}

#[tokio::test]
async fn lookup_returns_none_on_no_match() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();
    let addr = "192.168.0.1".parse().unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        RibRequest::Lookup { addr },
        RibEvent::NoMatch,
    ));

    let matched = lookup(&path, addr).await.unwrap();
    assert_eq!(matched, None);

    server.await.unwrap();
}

#[tokio::test]
async fn get_routes_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        RibRequest::GetRoutes,
        RibEvent::Error("boom".to_string()),
    ));

    let err = get_routes(&path).await.unwrap_err();
    assert!(err.to_string().contains("boom"));

    server.await.unwrap();
}

#[tokio::test]
async fn get_vpn_label_returns_the_label_and_none_on_anything_else() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();
    let server = tokio::spawn(serve_once(
        listener,
        RibRequest::GetVpnLabel,
        RibEvent::VpnLabel(Some(1000)),
    ));
    assert_eq!(get_vpn_label(&path).await, Some(1000));
    server.await.unwrap();

    let path = tmp.path().join("rib2.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();
    let server = tokio::spawn(serve_once(
        listener,
        RibRequest::GetVpnLabel,
        RibEvent::NoMatch,
    ));
    assert_eq!(get_vpn_label(&path).await, None);
    server.await.unwrap();
}
