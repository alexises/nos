//! Pushes the VPN routes this (underlay) instance imports into each VRF
//! (`rib::vpn_import`) to that VRF table's `nos-ribd`
//! (`RibRequest::PushVpnRoutes`, the `Vpn` route source), with each PE next
//! hop resolved in this instance's own table (`RibRequest::ResolveNextHop`).
//! A next hop whose PE does not resolve there is withheld until it does
//! (the route goes once none resolves); the rest of its multipath set stays.
//!
//! The loop is `fdb_push_client`'s `Feed::Tables` one: a persistent
//! connection per VRF, `Full` on connect then diffed `Add`/`Remove`, woken
//! by `SessionManager::push_changed` (plus `FALLBACK_TICK`, which also
//! re-resolves), EOF-watched so a restarted `nos-ribd` gets a fresh `Full`.
// ponytail: copied from `fdb_push_client` rather than generalized; merge the
// two when a third table feed appears.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use ipnet::IpNet;
use nos_proto::{
    IpcCodec, ResolvedNextHop, RibRequest, Role, ServiceRef, VpnPath, VpnRoute, VpnRouteUpdate,
};
use tokio::io::WriteHalf;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::FramedWrite;
use tracing::{debug, info, warn};

use crate::push_conn::{any_eof, split, PushReader};
use crate::rib::{SooSkip, VpnImports};
use crate::rib_client::resolve_next_hops;
use crate::session::SessionManager;
use crate::vpn::{format_rd, format_soo};
use nos_daemon::watchdog::resolve_once;

const FALLBACK_TICK: Duration = Duration::from_secs(10);
const HOLD_DOWN: Duration = Duration::from_millis(50);
const RETRY_DELAY: Duration = Duration::from_secs(1);

type Routes = HashMap<IpNet, VpnRoute>;
type Resolved = HashMap<IpAddr, ResolvedNextHop>;

pub fn spawn(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, sessions, shutdown))
}

struct Conn {
    writer: FramedWrite<WriteHalf<nos_pki::Stream>, IpcCodec<RibRequest>>,
    reader: PushReader,
    last_sent: Routes,
}

async fn run(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut conns: HashMap<String, Conn> = HashMap::new();
    let mut shown: HashMap<String, Routes> = HashMap::new();
    let mut resolved = Resolved::new();
    let mut skipped = HashSet::new();
    let mut changed = sessions.push_changed();
    while !*shutdown.borrow() {
        let mut unconnected = false;
        // `None`: deferring (graceful restart), every VRF keeps what it has.
        if let (underlay, Some(imports)) = sessions.vpn_import_snapshot().await {
            // A failed query keeps the last answers: dropping them would
            // withdraw every VPN route on a transient error.
            if let Some(r) = resolve(&watchdog_socket, underlay, &imports).await {
                resolved = r;
            }
            log_soo_skips(&mut skipped, sessions.vpn_soo_skipped().await);
            let tables = build(&imports, &resolved);
            log_changes(&shown, &tables);
            shown.clone_from(&tables);
            conns.retain(|t, c| tables.contains_key(t) && !c.reader.closed());
            for (table, routes) in tables {
                if let Some(conn) = conns.get_mut(&table) {
                    let updates = diff(&conn.last_sent, &routes);
                    if updates.is_empty() {
                        continue;
                    }
                    if conn
                        .writer
                        .send(RibRequest::PushVpnRoutes(updates))
                        .await
                        .is_ok()
                    {
                        conn.last_sent = routes;
                    } else {
                        warn!(table = %table, "write failure pushing vpn routes, reconnecting");
                        conns.remove(&table);
                    }
                } else if let Some(conn) = connect(&watchdog_socket, &table, routes).await {
                    conns.insert(table, conn);
                } else {
                    unconnected = true;
                }
            }
        }
        let tick = if unconnected {
            RETRY_DELAY
        } else {
            FALLBACK_TICK
        };
        let eof = any_eof(conns.values_mut().map(|c| &mut c.reader));
        tokio::select! {
            () = tokio::time::sleep(tick) => {}
            r = changed.changed() => {
                if r.is_ok() {
                    tokio::time::sleep(HOLD_DOWN).await;
                    changed.borrow_and_update();
                }
            }
            () = eof => {}
            _ = shutdown.changed() => {}
        }
    }
}

/// Resolves every distinct PE of `imports` in the `underlay` table; `None`
/// when the query failed (no table yet, `nos-ribd` down).
async fn resolve(
    watchdog_socket: &Path,
    underlay: Option<String>,
    imports: &VpnImports,
) -> Option<Resolved> {
    let mut pes: Vec<IpAddr> = imports
        .values()
        .flat_map(HashMap::values)
        .flat_map(|i| i.paths.iter().map(|p| p.pe))
        .collect();
    pes.sort_unstable();
    pes.dedup();
    if pes.is_empty() {
        return Some(Resolved::new());
    }
    let socket = resolve_once(watchdog_socket, &ServiceRef::RibTable(underlay?)).await?;
    let hops = resolve_next_hops(&socket, pes.clone()).await?;
    Some(
        pes.into_iter()
            .zip(hops)
            .filter_map(|(pe, h)| Some((pe, h?)))
            .collect(),
    )
}

/// Each VRF's routes as pushed: an import's paths whose PE resolved, their
/// gateway the resolution (a route with none is withheld). Pure, unit-tested.
fn build(imports: &VpnImports, resolved: &Resolved) -> HashMap<String, Routes> {
    imports
        .iter()
        .map(|(table, routes)| {
            let routes = routes
                .iter()
                .filter_map(|(prefix, imp)| {
                    let paths: Vec<VpnPath> = imp
                        .paths
                        .iter()
                        .filter_map(|p| {
                            let Some(hop) = resolved.get(&p.pe) else {
                                debug!(table = %table, prefix = %prefix, next_hop = %p.pe, "vpn route withheld, pe next hop unresolved in the underlay");
                                return None;
                            };
                            Some(VpnPath {
                                pe_next_hop: p.pe,
                                rd: format_rd(&p.rd),
                                gateway: hop.gateway,
                                interface_id: hop.interface_id,
                                labels: p.labels.clone(),
                            })
                        })
                        .collect();
                    (!paths.is_empty()).then_some((
                        *prefix,
                        VpnRoute {
                            prefix: *prefix,
                            paths,
                        },
                    ))
                })
                .collect();
            (table.clone(), routes)
        })
        .collect()
}

/// Logs each path newly refused by Site of Origin, once; `held` becomes `now`.
fn log_soo_skips(held: &mut HashSet<SooSkip>, now: HashSet<SooSkip>) {
    for (table, rd, prefix, soo) in now.difference(held) {
        info!(table = %table, rd = %format_rd(rd), prefix = %prefix, soo = %format_soo(*soo), "vpn route skipped by site of origin");
    }
    *held = now;
}

/// The imported/unimported log lines between two pushes.
fn log_changes(old: &HashMap<String, Routes>, new: &HashMap<String, Routes>) {
    let empty = Routes::new();
    for (table, routes) in new {
        let before = old.get(table).unwrap_or(&empty);
        for (prefix, r) in routes {
            // One line per next hop, the single-path format unchanged.
            for p in &r.paths {
                match before.get(prefix) {
                    None => {
                        info!(table = %table, prefix = %prefix, labels = ?p.labels, rd = %p.rd, next_hop = %p.pe_next_hop, "vpn route imported");
                    }
                    Some(b) if b != r => {
                        debug!(table = %table, prefix = %prefix, labels = ?p.labels, rd = %p.rd, next_hop = %p.pe_next_hop, "vpn route import changed");
                    }
                    Some(_) => {}
                }
            }
        }
    }
    for (table, routes) in old {
        let after = new.get(table).unwrap_or(&empty);
        for prefix in routes.keys().filter(|p| !after.contains_key(p)) {
            info!(table = %table, prefix = %prefix, "vpn route unimported");
        }
    }
}

async fn connect(watchdog_socket: &Path, table: &str, routes: Routes) -> Option<Conn> {
    let socket = resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string())).await?;
    let stream = match nos_pki::connect(&socket, Role::Ribd, table).await {
        Ok(s) => s,
        Err(e) => {
            debug!(table = %table, error = %e, "vrf nos-ribd not reachable yet, retrying");
            return None;
        }
    };
    let (write_half, reader) = split(stream);
    let mut writer = FramedWrite::new(write_half, IpcCodec::default());
    let full = VpnRouteUpdate::Full(routes.values().cloned().collect());
    if writer
        .send(RibRequest::PushVpnRoutes(vec![full]))
        .await
        .is_err()
    {
        warn!(table = %table, "failed to send the initial vpn snapshot, retrying");
        return None;
    }
    info!(table = %table, routes = routes.len(), "sent initial vpn snapshot to nos-ribd");
    Some(Conn {
        writer,
        reader,
        last_sent: routes,
    })
}

/// The `Add`/`Remove`s that bring `last_sent` up to `new`. Pure, unit-tested.
fn diff(last_sent: &Routes, new: &Routes) -> Vec<VpnRouteUpdate> {
    let mut updates: Vec<VpnRouteUpdate> = new
        .iter()
        .filter(|(p, r)| last_sent.get(p) != Some(r))
        .map(|(_, r)| VpnRouteUpdate::Add(r.clone()))
        .collect();
    updates.extend(
        last_sent
            .keys()
            .filter(|p| !new.contains_key(p))
            .map(|p| VpnRouteUpdate::Remove(*p)),
    );
    updates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::{VpnImport, VpnImportPath};
    use nos_proto::RouteSourceKind;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn path(pe: &str, label: u32) -> VpnImportPath {
        VpnImportPath {
            pe: ip(pe),
            labels: vec![label],
            rd: [0, 0, 0xfd, 0xe9, 0, 0, 0, 1],
        }
    }

    fn multi(paths: Vec<VpnImportPath>) -> VpnImports {
        [(
            "red".to_string(),
            [("10.1.0.0/24".parse().unwrap(), VpnImport { paths })].into(),
        )]
        .into()
    }

    fn resolved2() -> Resolved {
        let mut r = resolved("10.0.0.1");
        r.insert(
            ip("192.0.2.2"),
            ResolvedNextHop {
                gateway: ip("10.0.0.2"),
                interface_id: Some(4),
                source: RouteSourceKind::Ospf,
            },
        );
        r
    }

    #[test]
    fn multipath_pushes_the_resolved_subset_and_withholds_when_none() {
        let both = multi(vec![path("192.0.2.1", 100), path("192.0.2.2", 200)]);
        let key = "10.1.0.0/24".parse().unwrap();
        let red = |t: &HashMap<String, Routes>| t["red"].clone();
        let full = build(&both, &resolved2());
        assert_eq!(full["red"][&key].paths.len(), 2);
        assert_eq!(full["red"][&key].paths[1].labels, vec![200]);
        // One PE unresolved: a subset, an Add with the smaller set, no Remove.
        let subset = build(&both, &resolved("10.0.0.1"));
        assert_eq!(subset["red"][&key].paths.len(), 1);
        let updates = diff(&red(&full), &red(&subset));
        assert!(
            matches!(&updates[..], [VpnRouteUpdate::Add(r)] if r.paths.len() == 1),
            "{updates:?}"
        );
        // A label-only change is an Add.
        let relabel = build(
            &multi(vec![path("192.0.2.1", 100), path("192.0.2.2", 201)]),
            &resolved2(),
        );
        assert!(matches!(
            &diff(&red(&full), &red(&relabel))[..],
            [VpnRouteUpdate::Add(_)]
        ));
        // None resolved: withheld.
        assert!(build(&both, &Resolved::new())["red"].is_empty());
        log_changes(&full, &subset);
    }

    fn imports(label: u32) -> VpnImports {
        let imp = |pe: &str| VpnImport {
            paths: vec![path(pe, label)],
        };
        [
            (
                "red".to_string(),
                [
                    ("10.1.0.0/24".parse().unwrap(), imp("192.0.2.1")),
                    ("10.2.0.0/24".parse().unwrap(), imp("192.0.2.9")),
                ]
                .into(),
            ),
            ("blue".to_string(), HashMap::new()),
        ]
        .into()
    }

    fn resolved(gw: &str) -> Resolved {
        [(
            ip("192.0.2.1"),
            ResolvedNextHop {
                gateway: ip(gw),
                interface_id: Some(3),
                source: RouteSourceKind::Ospf,
            },
        )]
        .into()
    }

    #[test]
    fn an_unresolved_pe_is_withheld_and_every_vrf_is_a_target() {
        let tables = build(&imports(100), &resolved("10.0.0.1"));
        assert!(tables["blue"].is_empty());
        let red = &tables["red"];
        assert_eq!(red.len(), 1, "192.0.2.9 does not resolve");
        let r = &red[&"10.1.0.0/24".parse().unwrap()];
        assert_eq!(
            r.paths,
            vec![VpnPath {
                pe_next_hop: ip("192.0.2.1"),
                rd: "65001:1".to_string(),
                gateway: ip("10.0.0.1"),
                interface_id: Some(3),
                labels: vec![100],
            }]
        );
    }

    #[test]
    fn a_label_or_resolution_change_is_an_add_and_a_loss_a_remove() {
        let base = build(&imports(100), &resolved("10.0.0.1"));
        let red = |t: &HashMap<String, Routes>| t["red"].clone();
        assert_eq!(
            diff(&red(&base), &red(&base)),
            [] as [nos_proto::VpnRouteUpdate; 0]
        );
        for changed in [
            build(&imports(200), &resolved("10.0.0.1")),
            build(&imports(100), &resolved("10.0.0.2")),
        ] {
            let updates = diff(&red(&base), &red(&changed));
            assert!(
                matches!(&updates[..], [VpnRouteUpdate::Add(_)]),
                "{updates:?}"
            );
        }
        let gone = build(&imports(100), &Resolved::new());
        assert_eq!(
            diff(&red(&base), &red(&gone)),
            vec![VpnRouteUpdate::Remove("10.1.0.0/24".parse().unwrap())]
        );
        // A Site of Origin skip is logged once, then again after it clears.
        let skip: SooSkip = ("red".into(), [0; 8], "10.1.0.0/24".parse().unwrap(), 7);
        let mut held = HashSet::new();
        log_soo_skips(&mut held, [skip.clone()].into());
        assert_eq!(held.len(), 1);
        log_soo_skips(&mut held, HashSet::new());
        assert!(held.is_empty());
        // Logging covers appear, change and disappear without panicking.
        log_changes(&HashMap::new(), &base);
        log_changes(&base, &build(&imports(200), &resolved("10.0.0.1")));
        log_changes(&base, &HashMap::new());
    }

    #[tokio::test]
    async fn resolution_without_pes_or_underlay() {
        let tmp = tempfile::tempdir().unwrap();
        let none: VpnImports = HashMap::new();
        assert_eq!(
            resolve(tmp.path(), None, &none).await,
            Some(Resolved::new())
        );
        assert_eq!(resolve(tmp.path(), None, &imports(1)).await, None);
    }

    /// Against a fake underlay `nos-ribd` (it resolves nothing) and a fake
    /// VRF `nos-ribd` behind a fake broker: every VRF gets a `Full` on
    /// connect, again after it drops the connection.
    #[tokio::test]
    async fn resolves_through_the_underlay_and_pushes_a_full_per_vrf() {
        use nos_test_support::{serve, FakeRibd, FakeWatchdog, Reply};
        let tmp = tempfile::tempdir().unwrap();
        let watchdog = FakeWatchdog::new(&tmp.path().join("wd.sock"));
        let underlay = FakeRibd::new(&tmp.path().join("rt1.sock"), "rt1");
        watchdog.set(ServiceRef::RibTable("rt1".into()), underlay.path().into());
        assert_eq!(
            resolve(watchdog.path(), Some("rt1".into()), &imports(1)).await,
            Some(Resolved::new())
        );

        let red_path = tmp.path().join("red.sock");
        let red = serve(&red_path, "ribd", "red", |_: &RibRequest| Reply::<()>::None);
        watchdog.set(ServiceRef::RibTable("red".into()), red_path);
        let sessions = SessionManager::new("r1".into());
        let vrf = crate::vpn::Vrf {
            table: "red".into(),
            rd: [0; 8],
            import: vec![],
            export: vec![],
            soo: None,
        };
        sessions.set_vpn_vrfs(crate::vpn::VrfSet(vec![vrf])).await;
        let (tx, rx) = watch::channel(false);
        let task = spawn(watchdog.path().to_path_buf(), sessions, rx);
        let full = || async {
            for _ in 0..100 {
                let seen = red.take_seen();
                if !seen.is_empty() {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("no push");
        };
        let is_empty_full = |s: &[RibRequest]| matches!(s, [RibRequest::PushVpnRoutes(u)] if u == &[VpnRouteUpdate::Full(vec![])]);
        assert!(is_empty_full(&full().await));
        red.close_connections();
        assert!(is_empty_full(&full().await));
        tx.send(true).unwrap();
        task.await.unwrap();
    }
}
