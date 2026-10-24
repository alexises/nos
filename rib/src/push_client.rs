//! The long-lived origination push shared by `evpn_client` (Type-5) and
//! `vpn_client` (VPN export): one connection to the target `nos-bgpd`, a
//! `Full` on every (re)connect, then the `Add`/`Remove`s each new published
//! `Target` differs by, and `Full([])` when the target instance changes or
//! goes away (withdrawing everything). The write-only connection is also
//! read for EOF, so a `nos-bgpd` restart gets a fresh `Full` at once.

use std::collections::HashMap;
use std::hash::Hash;
use std::path::PathBuf;
use std::time::Duration;

use futures::SinkExt;
use nos_proto::{BgpRequest, IpcCodec, Role, ServiceRef};
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use tokio_util::codec::FramedWrite;
use tracing::{debug, info, warn};

use nos_daemon::watchdog::resolve_once;

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// The routes to originate and where, published by `reconcile::resync`.
#[derive(Debug, Clone, PartialEq)]
pub struct Target<R> {
    /// `None`: nothing to originate — idle.
    pub bgp_instance: Option<String>,
    pub routes: Vec<R>,
}

impl<R> Default for Target<R> {
    fn default() -> Self {
        Self {
            bgp_instance: None,
            routes: Vec::new(),
        }
    }
}

/// One kind of origination feed.
pub trait Feed: Send + Sync + 'static {
    type Route: Clone + PartialEq + Send + Sync + 'static;
    type Key: Clone + Eq + Hash + Send + Sync;
    type Update: Send;
    /// What the log lines call it (`evpn type-5`, `vpn`).
    const WHAT: &'static str;
    fn key(r: &Self::Route) -> Self::Key;
    fn full(routes: Vec<Self::Route>) -> Self::Update;
    fn add(r: Self::Route) -> Self::Update;
    fn remove(k: Self::Key) -> Self::Update;
    fn request(table: String, update: Self::Update) -> BgpRequest;
}

fn keyed<F: Feed>(routes: &[F::Route]) -> HashMap<F::Key, F::Route> {
    routes.iter().map(|r| (F::key(r), r.clone())).collect()
}

/// The `Add`/`Remove`s that bring `last` up to `new`. Pure, unit-tested.
pub fn diff<F: Feed, S: std::hash::BuildHasher>(
    last: &HashMap<F::Key, F::Route, S>,
    new: &[F::Route],
) -> Vec<F::Update> {
    let new = keyed::<F>(new);
    let mut out: Vec<F::Update> = new
        .iter()
        .filter(|(k, r)| last.get(*k) != Some(*r))
        .map(|(_, r)| F::add(r.clone()))
        .collect();
    out.extend(
        last.keys()
            .filter(|k| !new.contains_key(*k))
            .map(|k| F::remove(k.clone())),
    );
    out
}

pub fn spawn<F: Feed>(
    watchdog_socket: PathBuf,
    table: String,
    shutdown: watch::Receiver<bool>,
) -> watch::Sender<Target<F::Route>> {
    let (tx, rx) = watch::channel(Target::default());
    tokio::spawn(run::<F>(watchdog_socket, table, rx, shutdown));
    tx
}

async fn run<F: Feed>(
    watchdog_socket: PathBuf,
    table: String,
    mut rx: watch::Receiver<Target<F::Route>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let what = F::WHAT;
    let retry = |rx: &mut watch::Receiver<Target<F::Route>>,
                 shutdown: &mut watch::Receiver<bool>| {
        let (mut rx, mut shutdown) = (rx.clone(), shutdown.clone());
        async move {
            tokio::select! {
                () = tokio::time::sleep(RETRY_DELAY) => false,
                c = rx.changed() => c.is_err(),
                _ = shutdown.changed() => true,
            }
        }
    };
    while !*shutdown.borrow() {
        let target = rx.borrow_and_update().clone();
        let Some(name) = target.bgp_instance.clone() else {
            tokio::select! {
                c = rx.changed() => if c.is_err() { return },
                _ = shutdown.changed() => return,
            }
            continue;
        };
        let socket = resolve_once(&watchdog_socket, &ServiceRef::BgpInstance(name.clone())).await;
        let stream = match socket {
            Some(s) => nos_pki::connect(&s, Role::Bgpd, &name).await.ok(),
            None => None,
        };
        let Some(stream) = stream else {
            debug!(table = %table, bgp_instance = %name, "nos-bgpd not reachable yet, retrying");
            if retry(&mut rx, &mut shutdown).await {
                return;
            }
            continue;
        };
        let (mut reader, w) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<BgpRequest>::default());
        let send = |update| F::request(table.clone(), update);
        let current = rx.borrow_and_update().clone();
        if current.bgp_instance != target.bgp_instance {
            continue;
        }
        if writer
            .send(send(F::full(current.routes.clone())))
            .await
            .is_err()
        {
            warn!(table = %table, bgp_instance = %name, "failed to send the {what} snapshot to nos-bgpd, retrying");
            continue;
        }
        info!(table = %table, bgp_instance = %name, routes = current.routes.len(), "sent initial {what} snapshot to nos-bgpd");
        let mut last = keyed::<F>(&current.routes);
        let mut buf = [0u8; 64];
        loop {
            tokio::select! {
                c = rx.changed() => {
                    if c.is_err() {
                        return;
                    }
                    let new = rx.borrow_and_update().clone();
                    if new.bgp_instance.as_deref() != Some(name.as_str()) {
                        let _ = writer.send(send(F::full(Vec::new()))).await;
                        break;
                    }
                    let mut failed = false;
                    for u in diff::<F, _>(&last, &new.routes) {
                        if writer.send(send(u)).await.is_err() {
                            failed = true;
                            break;
                        }
                    }
                    if failed {
                        warn!(table = %table, bgp_instance = %name, "write failure sending {what} routes, reconnecting");
                        break;
                    }
                    last = keyed::<F>(&new.routes);
                }
                n = reader.read(&mut buf) => {
                    if matches!(n, Ok(0) | Err(_)) {
                        warn!(table = %table, bgp_instance = %name, "nos-bgpd closed the {what} connection, reconnecting");
                        break;
                    }
                }
                _ = shutdown.changed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nos_proto::{BgpEvent, VpnPrefix, VpnPrefixUpdate};
    use nos_test_support::{serve, Fake, Fakes, Reply, Server};

    use super::*;
    use crate::vpn_client::Vpn;

    fn route(label: u32) -> VpnPrefix {
        VpnPrefix {
            rd: [0; 8],
            prefix: "10.1.0.0/24".parse().unwrap(),
            labels: vec![label],
            ext_communities: vec![],
        }
    }

    fn target(instance: Option<&str>, routes: Vec<VpnPrefix>) -> Target<VpnPrefix> {
        Target {
            bgp_instance: instance.map(Into::into),
            routes,
        }
    }

    /// Waits until the fake has seen `n` more requests; returns them.
    async fn seen(bgpd: &Server<BgpRequest>, n: usize) -> Vec<VpnPrefixUpdate> {
        let mut got = Vec::new();
        for _ in 0..200 {
            got.extend(bgpd.take_seen().into_iter().map(|r| match r {
                BgpRequest::RedistributeVpnPrefixes { table, update } if table == "red" => update,
                other => panic!("unexpected {other:?}"),
            }));
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("saw only {got:?}");
    }

    /// The whole loop against a fake `nos-bgpd`: a retry while it is not
    /// registered, `Full` on connect, a diffed `Add`, a fresh `Full` after
    /// the peer closes, and `Full([])` when the target goes idle.
    #[tokio::test]
    async fn full_then_deltas_reconnect_and_an_empty_full_when_idle() {
        let fakes = Fakes::start(&[Fake::Watchdog]);
        let path = fakes.dir().join("bgp-core.sock");
        let bgpd = serve::<BgpRequest, BgpEvent, _>(&path, "bgpd", "core", |_| Reply::None);
        let (_stop, shutdown) = watch::channel(false);
        let tx = spawn::<Vpn>(fakes.watchdog_socket(), "red".into(), shutdown);

        tx.send(target(Some("core"), vec![route(1000)])).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        fakes
            .watchdog
            .as_ref()
            .unwrap()
            .set(ServiceRef::BgpInstance("core".into()), path.clone());
        assert_eq!(
            seen(&bgpd, 1).await,
            [VpnPrefixUpdate::Full(vec![route(1000)])]
        );

        tx.send(target(Some("core"), vec![route(1001)])).unwrap();
        assert_eq!(seen(&bgpd, 1).await, [VpnPrefixUpdate::Add(route(1001))]);

        bgpd.close_connections();
        assert_eq!(
            seen(&bgpd, 1).await,
            [VpnPrefixUpdate::Full(vec![route(1001)])]
        );

        tx.send(target(None, vec![])).unwrap();
        assert_eq!(seen(&bgpd, 1).await, [VpnPrefixUpdate::Full(vec![])]);
    }
}
