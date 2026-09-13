use std::net::IpAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteSourceKind};
use nos_rib::{server, Rib, RibEntry, RouteSource};
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_rib() -> Rib {
    let mut rib = Rib::new();
    let broad: nos_proto::IpNet = "10.0.0.0/16".parse().unwrap();
    let narrow: nos_proto::IpNet = "10.0.1.0/24".parse().unwrap();
    rib.insert(RibEntry {
        prefix: broad,
        gateway: "10.0.0.1".parse().unwrap(),
        source: RouteSource::Static,
    });
    // Two competing candidates for the same prefix, to prove ordering.
    rib.insert(RibEntry {
        prefix: narrow,
        gateway: "10.0.1.9".parse().unwrap(),
        source: RouteSource::Bgp,
    });
    rib.insert(RibEntry {
        prefix: narrow,
        gateway: "10.0.1.1".parse().unwrap(),
        source: RouteSource::Static,
    });
    rib
}

async fn connect(
    path: &std::path::Path,
) -> (
    FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<RibEvent>>,
    FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<RibRequest>>,
) {
    let stream = UnixStream::connect(path).await.unwrap();
    let (r, w) = stream.into_split();
    (
        FramedRead::new(r, IpcCodec::<RibEvent>::default()),
        FramedWrite::new(w, IpcCodec::<RibRequest>::default()),
    )
}

#[tokio::test]
async fn get_routes_returns_sorted_prefixes_with_ranked_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(&path, rib).unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(RibRequest::GetRoutes).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    let RibEvent::Routes(routes) = event else {
        panic!("expected Routes, got {event:?}");
    };
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].prefix, "10.0.0.0/16".parse().unwrap());
    assert_eq!(routes[1].prefix, "10.0.1.0/24".parse().unwrap());
    // Best (Static) candidate first, then worst (Bgp).
    assert_eq!(routes[1].candidates.len(), 2);
    assert_eq!(routes[1].candidates[0].source, RouteSourceKind::Static);
    assert_eq!(routes[1].candidates[1].source, RouteSourceKind::Bgp);
}

#[tokio::test]
async fn lookup_matches_longest_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(&path, rib).unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    let addr: IpAddr = "10.0.1.5".parse().unwrap();
    writer.send(RibRequest::Lookup { addr }).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    let RibEvent::Match(PrefixRoutes { prefix, candidates }) = event else {
        panic!("expected Match, got {event:?}");
    };
    assert_eq!(prefix, "10.0.1.0/24".parse().unwrap());
    assert_eq!(candidates[0].source, RouteSourceKind::Static);
}

#[tokio::test]
async fn lookup_with_no_covering_prefix_returns_no_match() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(&path, rib).unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    let addr: IpAddr = "192.168.0.1".parse().unwrap();
    writer.send(RibRequest::Lookup { addr }).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::NoMatch));
}
