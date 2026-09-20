//! The REST layer against a real `ConfigStore` behind `nos-configd`'s own IPC
//! server (so the path-set semantics tested here are the shipped ones), plus a
//! fake watchdog broker and fake daemons for the show endpoints.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request as HttpRequest, StatusCode};
use axum::Router;
use futures::{SinkExt, StreamExt};
use nos_config::{Config, ConfigStore, ListenAddr};
use nos_proto::{
    BgpInstance, IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteEntry, RouteSourceKind,
    ServiceRef, WatchdogEvent, WatchdogRequest,
};
use nos_rest::{api, ipc::Daemons};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::net::UnixListener;
use tokio_util::codec::{FramedRead, FramedWrite};
use tower::ServiceExt;

/// Serves `handler` on `path`, one reply per request, forever.
fn serve<Req, Ev>(path: &Path, handler: impl Fn(Req) -> Ev + Send + Sync + 'static)
where
    Req: DeserializeOwned + Send + 'static,
    Ev: Serialize + Send + 'static,
{
    let listener = UnixListener::bind(path).unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let handler = handler.clone();
            tokio::spawn(async move {
                let (r, w) = stream.into_split();
                let mut reader = FramedRead::new(r, IpcCodec::<Req>::default());
                let mut writer = FramedWrite::new(w, IpcCodec::<Ev>::default());
                while let Some(Ok(req)) = reader.next().await {
                    if writer.send(handler(req)).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

struct Fixture {
    app: Router,
    _dir: tempfile::TempDir,
}

/// `services` are the fake daemons the broker knows about. `async` only for the
/// tokio context the spawned servers need.
#[allow(clippy::unused_async)]
async fn fixture(services: Vec<(ServiceRef, PathBuf)>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let config_socket = dir.path().join("config.sock");
    ConfigStore::new(Config::default(), None)
        .start_ipc_server(&ListenAddr::Unix(config_socket.clone()))
        .unwrap();

    let watchdog_socket = dir.path().join("watchdog.sock");
    serve(&watchdog_socket, move |req: WatchdogRequest| {
        let WatchdogRequest::ResolveEndpoint { service } = req;
        services
            .iter()
            .find(|(s, _)| *s == service)
            .map_or(WatchdogEvent::NotAvailable, |(_, p)| {
                WatchdogEvent::Endpoint(p.clone())
            })
    });
    let app = api::router(Daemons {
        watchdog_socket: Arc::new(watchdog_socket),
        config_socket: Arc::new(config_socket),
    });
    Fixture { app, _dir: dir }
}

async fn send(app: &Router, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let req = HttpRequest::builder()
        .method(method)
        .uri(uri)
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()))
    };
    (status, json)
}

fn bgp_instance(name: &str, asn: u32) -> Value {
    serde_json::to_value(BgpInstance {
        name: name.to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        asn,
        peer_groups: Vec::new(),
        peers: Vec::new(),
        cluster_id: None,
        routing_table: None,
        redistribute_policy: None,
    })
    .unwrap()
}

#[tokio::test]
async fn transaction_lifecycle_over_the_config_tree() {
    let f = fixture(vec![]).await;
    let app = &f.app;

    let (s, snap) = send(app, Method::POST, "/v1/transactions/t1?base=blank", None).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(snap["dirty"], false);
    // Resuming reports 200, not 201.
    assert_eq!(
        send(app, Method::POST, "/v1/transactions/t1", None).await.0,
        StatusCode::OK
    );

    // Scalar, then a whole list element, then a subsection nested inside it.
    let (s, v) = send(
        app,
        Method::PUT,
        "/v1/transactions/t1/hostname",
        Some(json!("rest-host")),
    )
    .await;
    assert_eq!((s, v), (StatusCode::OK, json!("rest-host")));
    let (s, _) = send(
        app,
        Method::PUT,
        "/v1/transactions/t1/bgp-instance/r1",
        Some(bgp_instance("r1", 65000)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let mut r1 = bgp_instance("r1", 65001);
    r1["router_id"] = json!("2.2.2.2");
    let (s, v) = send(
        app,
        Method::PUT,
        "/v1/transactions/t1/bgp-instance/r1/",
        Some(r1),
    )
    .await;
    assert_eq!((s, v["asn"].clone()), (StatusCode::OK, json!(65001)));

    // Read a subsection back, by path and via the whole transaction.
    let (s, v) = send(
        app,
        Method::GET,
        "/v1/transactions/t1/bgp-instance/r1/asn",
        None,
    )
    .await;
    assert_eq!((s, v), (StatusCode::OK, json!(65001)));
    let (_, whole) = send(app, Method::GET, "/v1/transactions/t1", None).await;
    assert_eq!(whole["config"]["hostname"], "rest-host");
    assert_eq!(whole["dirty"], true);

    // Nothing reaches running until commit.
    assert_eq!(
        send(app, Method::GET, "/v1/config", None).await.1["hostname"],
        "nos"
    );
    let (s, d) = send(app, Method::GET, "/v1/transactions/t1/diff", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(d["bgp_instances"].is_array());

    let (s, v) = send(app, Method::POST, "/v1/transactions/t1/commit", None).await;
    assert_eq!((s, v), (StatusCode::OK, json!({ "committed": "t1" })));
    let (_, running) = send(app, Method::GET, "/v1/config", None).await;
    assert_eq!(running["hostname"], "rest-host");
    assert_eq!(running["bgp_instances"][0]["asn"], 65001);
    // A committed transaction is gone.
    assert_eq!(
        send(app, Method::GET, "/v1/transactions/t1", None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn whole_config_put_delete_path_and_discard() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/t2?base=blank", None).await;

    let mut whole = send(app, Method::GET, "/v1/transactions/t2", None).await.1["config"].clone();
    whole["hostname"] = json!("bulk");
    whole["bgp_instances"] = json!([bgp_instance("a", 1), bgp_instance("b", 2)]);
    assert_eq!(
        send(app, Method::PUT, "/v1/transactions/t2", Some(whole))
            .await
            .0,
        StatusCode::OK
    );

    assert_eq!(
        send(
            app,
            Method::DELETE,
            "/v1/transactions/t2/bgp-instance/a",
            None
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (_, list) = send(app, Method::GET, "/v1/transactions/t2/bgp-instance", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["name"], "b");

    assert_eq!(
        send(app, Method::DELETE, "/v1/transactions/t2", None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(app, Method::GET, "/v1/transactions/t2", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(app, Method::DELETE, "/v1/transactions/t2", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn errors_map_to_statuses_and_leave_the_transaction_intact() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/t3?base=blank", None).await;

    // Unknown path / unknown transaction: 404. Malformed or ill-typed body: 400.
    assert_eq!(
        send(app, Method::GET, "/v1/transactions/t3/nonsense", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(app, Method::GET, "/v1/transactions/nope/hostname", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            app,
            Method::PUT,
            "/v1/transactions/t3/hostname",
            Some(json!(42))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (s, e) = send(
        app,
        Method::PUT,
        "/v1/transactions/t3/bgp-instance/x",
        Some(bgp_instance("y", 1)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(e["error"].as_str().unwrap().contains("does not match"));
    assert_eq!(
        send(app, Method::POST, "/v1/transactions/t3?base=bogus", None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    // A commit that fails validation is 422 and keeps the transaction.
    send(
        app,
        Method::PUT,
        "/v1/transactions/t3/hostname",
        Some(json!("bad host name!")),
    )
    .await;
    assert_eq!(
        send(app, Method::POST, "/v1/transactions/t3/commit", None)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (_, v) = send(app, Method::GET, "/v1/transactions/t3/hostname", None).await;
    assert_eq!(v, json!("bad host name!"));
}

#[tokio::test]
async fn show_routes_via_the_broker_and_missing_daemons_are_503() {
    let dir = tempfile::tempdir().unwrap();
    let rib = dir.path().join("rib.sock");
    serve(&rib, |req: RibRequest| match req {
        RibRequest::GetRoutes => RibEvent::Routes(vec![PrefixRoutes {
            prefix: "10.0.0.0/8".parse().unwrap(),
            candidates: vec![RouteEntry {
                gateway: "192.0.2.1".parse().unwrap(),
                source: RouteSourceKind::Static,
            }],
        }]),
        RibRequest::Lookup { .. } => RibEvent::NoMatch,
        _ => RibEvent::Error("unsupported".into()),
    });
    let f = fixture(vec![(ServiceRef::RibTable("rt1".into()), rib)]).await;

    let (s, v) = send(&f.app, Method::GET, "/v1/routes/rt1", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v[0]["prefix"], "10.0.0.0/8");
    assert_eq!(
        send(&f.app, Method::GET, "/v1/routes/rt1/192.0.2.9", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&f.app, Method::GET, "/v1/routes/other", None).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        send(&f.app, Method::GET, "/v1/interfaces", None).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn router_wide_show_reports_each_instance_that_is_not_running() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/t4?base=blank", None).await;
    send(
        app,
        Method::PUT,
        "/v1/transactions/t4/bgp-instance/r1",
        Some(bgp_instance("r1", 1)),
    )
    .await;
    send(app, Method::POST, "/v1/transactions/t4/commit", None).await;

    let (s, v) = send(app, Method::GET, "/v1/bgp/summary", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, json!([{ "instance": "r1", "error": "not running" }]));
    assert_eq!(
        send(app, Method::GET, "/v1/ospf/neighbors", None).await.1,
        json!([])
    );
}

#[tokio::test]
async fn serves_its_openapi_document() {
    let f = fixture(vec![]).await;
    let (s, doc) = send(&f.app, Method::GET, "/openapi.json", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(doc["openapi"].as_str().unwrap().starts_with("3."));
    let paths = doc["paths"].as_object().unwrap();
    assert!(!paths.contains_key("/v1/transactions/{tx}/bgp-instance/{bgp_instance}/name"));
    assert!(paths
        .contains_key("/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}"));
    assert!(paths.contains_key("/v1/routes/{table}"));
}
