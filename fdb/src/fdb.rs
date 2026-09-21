//! One broadcast domain's MAC table: the local MACs the bridge learned, the
//! remote ones EVPN told us about, and the kernel state each implies. The
//! `nos-ribd` `Rib` counterpart — pure decisions here, kernel effects behind
//! `FdbDriver`.
//!
//! ponytail: a MAC learned from two VTEPs (or under two RDs) is last write
//! wins — no MAC-mobility sequence numbers, so it can flap between them.

use std::collections::{BTreeSet, HashMap};
use std::future::pending;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use nos_proto::evpn_id::ENCAP_VXLAN;
use nos_proto::{EvpnKey, EvpnRoute, EvpnUpdate, FdbTable, MacEntry, MacSource};
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{debug, info, warn};

use crate::driver::{vxlan_name, FdbDriver, Mac};

/// How often local MACs and kernel state are re-checked regardless of
/// notifications — the netlink feed can overflow, and readiness (bridge,
/// VTEP address) is an external condition no config diff signals.
pub const TICK: Duration = Duration::from_secs(10);
/// A burst of neighbour events is answered by one FDB dump.
const DEBOUNCE: Duration = Duration::from_millis(200);

/// This domain's config with everything resolved; absent while incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub vni: u32,
    pub bridge: String,
    pub vtep: IpAddr,
    /// The kernel device carrying `vtep`: the VXLAN device's underlay.
    pub underlay: String,
    pub rd: [u8; 8],
    pub rt_import: Vec<u64>,
    pub rt_export: Vec<u64>,
    pub bgp_instance: String,
}

/// What `bgp_client` keeps originated into the named BGP instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvpnTarget {
    pub domain: String,
    pub bgp_instance: Option<String>,
    pub routes: HashMap<EvpnKey, EvpnRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Installed {
    Mac { mac: Mac, vtep: IpAddr },
    Flood { vtep: IpAddr },
}

/// What a received route should become in the kernel, if anything: it must
/// carry one of our import Route Targets, name this VNI, and not be our own.
fn desired(r: &Ready, route: &EvpnRoute) -> Option<Installed> {
    if !route
        .ext_communities
        .iter()
        .any(|c| r.rt_import.contains(c))
    {
        return None;
    }
    match &route.key {
        EvpnKey::Mac { mac, .. } if route.vni == r.vni && route.next_hop != r.vtep => {
            Some(Installed::Mac {
                mac: *mac,
                vtep: route.next_hop,
            })
        }
        // A Type-3's VNI comes from its PMSI attribute (0 = absent).
        EvpnKey::Imet { origin, .. }
            if (route.vni == 0 || route.vni == r.vni) && *origin != r.vtep =>
        {
            Some(Installed::Flood { vtep: *origin })
        }
        _ => None,
    }
}

/// This domain's originated routes: one Type-3 for the domain, one Type-2
/// per local MAC.
fn local_routes(r: &Ready, macs: &BTreeSet<Mac>) -> HashMap<EvpnKey, EvpnRoute> {
    let mut ext = r.rt_export.clone();
    ext.push(ENCAP_VXLAN);
    let route = |key: EvpnKey| EvpnRoute {
        key: key.clone(),
        vni: r.vni,
        next_hop: r.vtep,
        ext_communities: ext.clone(),
    };
    let imet = EvpnKey::Imet {
        rd: r.rd,
        origin: r.vtep,
    };
    std::iter::once(imet)
        .chain(macs.iter().map(|m| EvpnKey::Mac { rd: r.rd, mac: *m }))
        .map(|k| (k.clone(), route(k)))
        .collect()
}

pub fn format_mac(mac: Mac) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Default)]
struct Inner {
    ready: Option<Ready>,
    received: HashMap<EvpnKey, EvpnRoute>,
    installed: HashMap<EvpnKey, Installed>,
    local: BTreeSet<Mac>,
}

pub struct Fdb {
    domain: String,
    driver: Arc<dyn FdbDriver>,
    inner: Mutex<Inner>,
    target: watch::Sender<EvpnTarget>,
}

impl Fdb {
    pub fn new(domain: String, driver: Arc<dyn FdbDriver>) -> Arc<Self> {
        let (target, _) = watch::channel(EvpnTarget {
            domain: domain.clone(),
            ..EvpnTarget::default()
        });
        Arc::new(Self {
            domain,
            driver,
            inner: Mutex::default(),
            target,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<EvpnTarget> {
        self.target.subscribe()
    }

    fn publish(&self, g: &Inner) {
        let target = EvpnTarget {
            domain: self.domain.clone(),
            bgp_instance: g.ready.as_ref().map(|r| r.bgp_instance.clone()),
            routes: g
                .ready
                .as_ref()
                .map(|r| local_routes(r, &g.local))
                .unwrap_or_default(),
        };
        self.target.send_if_modified(|t| {
            let changed = *t != target;
            *t = target;
            changed
        });
    }

    /// Called by `reconcile` on every resync with the fully resolved config
    /// (or `None` while incomplete): (re)builds the VXLAN device and
    /// everything on it when that changed, and heals drift when it didn't.
    pub async fn set_ready(&self, ready: Option<Ready>) {
        let mut g = self.inner.lock().await;
        if g.ready != ready {
            if let Some(old) = g.ready.take() {
                for (_, i) in std::mem::take(&mut g.installed) {
                    self.uninstall(&old, &i).await;
                }
                if ready.as_ref().map(|r| r.vni) != Some(old.vni) {
                    if let Err(e) = self.driver.remove_vxlan(old.vni).await {
                        warn!(domain = %self.domain, error = %e, "failed to remove the old vxlan device");
                    }
                }
                g.local.clear();
            }
            self.publish(&g);
        }
        let Some(want) = ready else { return };
        // Idempotent: also the tick's repair path for a deleted/changed link.
        if let Err(e) = self
            .driver
            .ensure_vxlan(want.vni, want.vtep, &want.underlay, &want.bridge)
            .await
        {
            debug!(domain = %self.domain, error = %e, "vxlan device not ready yet, retrying");
            g.ready = None;
            g.installed.clear();
            self.publish(&g);
            return;
        }
        if g.ready.is_none() {
            info!(
                domain = %self.domain, vni = want.vni, vxlan = %vxlan_name(want.vni),
                bridge = %want.bridge, vtep = %want.vtep, "vxlan device ready"
            );
            g.ready = Some(want);
            self.publish(&g);
        }
        let keys: Vec<EvpnKey> = g.received.keys().cloned().collect();
        for k in keys {
            self.sync_key(&mut g, &k).await;
        }
    }

    /// One `PushEvpnRoutes` from `nos-bgpd`.
    pub async fn apply_push(&self, update: EvpnUpdate) {
        let mut g = self.inner.lock().await;
        let keys: Vec<EvpnKey> = match update {
            EvpnUpdate::Full(routes) => {
                let new: HashMap<EvpnKey, EvpnRoute> =
                    routes.into_iter().map(|r| (r.key.clone(), r)).collect();
                let old = std::mem::replace(&mut g.received, new);
                old.into_keys().chain(g.received.keys().cloned()).collect()
            }
            EvpnUpdate::Add(r) => {
                let k = r.key.clone();
                g.received.insert(k.clone(), r);
                vec![k]
            }
            EvpnUpdate::Remove(k) => {
                g.received.remove(&k);
                vec![k]
            }
        };
        for k in keys {
            self.sync_key(&mut g, &k).await;
        }
    }

    /// Brings one route's kernel state in line with `received` + config.
    async fn sync_key(&self, g: &mut Inner, key: &EvpnKey) {
        let Some(ready) = g.ready.clone() else { return };
        let want = g.received.get(key).and_then(|r| desired(&ready, r));
        let have = g.installed.get(key).cloned();
        if want == have {
            return;
        }
        if let Some(h) = have {
            self.uninstall(&ready, &h).await;
            g.installed.remove(key);
        }
        if let Some(w) = want {
            if self.install(&ready, &w).await {
                g.installed.insert(key.clone(), w);
            }
        }
    }

    async fn install(&self, r: &Ready, i: &Installed) -> bool {
        let res = match i {
            Installed::Mac { mac, vtep } => self.driver.set_remote_mac(r.vni, *mac, *vtep).await,
            Installed::Flood { vtep } => self.driver.add_flood(r.vni, *vtep).await,
        };
        match (res, i) {
            (Ok(()), Installed::Mac { mac, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vtep = %vtep, "remote mac installed");
                true
            }
            (Ok(()), Installed::Flood { vtep }) => {
                info!(domain = %self.domain, vtep = %vtep, "flood entry installed");
                true
            }
            (Err(e), _) => {
                warn!(domain = %self.domain, error = %e, "failed to program the fdb, retrying");
                false
            }
        }
    }

    async fn uninstall(&self, r: &Ready, i: &Installed) {
        let res = match i {
            Installed::Mac { mac, vtep } => self.driver.del_remote_mac(r.vni, *mac, *vtep).await,
            Installed::Flood { vtep } => self.driver.del_flood(r.vni, *vtep).await,
        };
        match (res, i) {
            (Ok(()), Installed::Mac { mac, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vtep = %vtep, "remote mac removed");
            }
            (Ok(()), Installed::Flood { vtep }) => {
                info!(domain = %self.domain, vtep = %vtep, "flood entry removed");
            }
            // Deleting the device already dropped them; nothing left to do.
            (Err(e), _) => debug!(domain = %self.domain, error = %e, "fdb delete failed"),
        }
    }

    /// Re-reads the bridge's local MACs and publishes any change to the BGP
    /// instance.
    pub async fn refresh_local(&self) {
        let mut g = self.inner.lock().await;
        let Some(r) = g.ready.clone() else { return };
        let macs = match self.driver.local_macs(&r.bridge, r.vni).await {
            Ok(m) => m,
            Err(e) => {
                debug!(domain = %self.domain, error = %e, "could not read the bridge fdb");
                return;
            }
        };
        if macs == g.local {
            return;
        }
        for m in macs.difference(&g.local) {
            info!(domain = %self.domain, mac = %format_mac(*m), "local mac learned");
        }
        for m in g.local.difference(&macs) {
            info!(domain = %self.domain, mac = %format_mac(*m), "local mac removed");
        }
        g.local = macs;
        self.publish(&g);
    }

    /// The local-MAC loop: a kernel FDB notification (debounced) or the tick
    /// triggers a re-read. Runs until `shutdown`.
    pub async fn run_local(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut wake = self.driver.watch_neigh();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                ev = recv_opt(&mut wake) => {
                    if ev.is_none() {
                        wake = None; // feed died: the tick alone from here
                        continue;
                    }
                    tokio::time::sleep(DEBOUNCE).await;
                    if let Some(rx) = wake.as_mut() {
                        while rx.try_recv().is_ok() {}
                    }
                }
                _ = tick.tick() => {}
                _ = shutdown.changed() => break,
            }
            self.refresh_local().await;
        }
    }

    /// `GetMacs`: what this domain's FDB currently holds.
    pub async fn table(&self) -> FdbTable {
        let g = self.inner.lock().await;
        let mut macs: Vec<MacEntry> = g
            .local
            .iter()
            .map(|m| MacEntry {
                mac: format_mac(*m),
                source: MacSource::Local,
                vtep: None,
            })
            .collect();
        let mut flood = Vec::new();
        for i in g.installed.values() {
            match i {
                Installed::Mac { mac, vtep } => macs.push(MacEntry {
                    mac: format_mac(*mac),
                    source: MacSource::Remote,
                    vtep: Some(*vtep),
                }),
                Installed::Flood { vtep } => flood.push(*vtep),
            }
        }
        macs.sort_by(|a, b| a.mac.cmp(&b.mac));
        flood.sort();
        FdbTable {
            domain: self.domain.clone(),
            vni: g.ready.as_ref().map_or(0, |r| r.vni),
            bridge: g.ready.as_ref().map(|r| r.bridge.clone()),
            vxlan: g.ready.as_ref().map(|r| vxlan_name(r.vni)),
            macs,
            flood,
        }
    }
}

async fn recv_opt(rx: &mut Option<mpsc::UnboundedReceiver<()>>) -> Option<()> {
    match rx {
        Some(rx) => rx.recv().await,
        None => pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;

    use super::*;
    use crate::driver::DriverError;

    const RT: u64 = 0x0002_fde8_0000_2774;
    const VTEP: &str = "192.0.2.1";
    const REMOTE: &str = "192.0.2.9";

    fn ready() -> Ready {
        Ready {
            vni: 10100,
            bridge: "br1".to_string(),
            vtep: VTEP.parse().unwrap(),
            underlay: "eth0".to_string(),
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            rt_import: vec![RT],
            rt_export: vec![RT],
            bgp_instance: "r1".to_string(),
        }
    }

    fn mac_route(mac: u8, vni: u32, rt: u64, next_hop: &str) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::Mac {
                rd: [0; 8],
                mac: [0, 0, 0, 0, 0, mac],
            },
            vni,
            next_hop: next_hop.parse().unwrap(),
            ext_communities: vec![rt],
        }
    }

    fn imet_route(origin: &str, rt: u64) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::Imet {
                rd: [0; 8],
                origin: origin.parse().unwrap(),
            },
            vni: 0,
            next_hop: origin.parse().unwrap(),
            ext_communities: vec![rt],
        }
    }

    #[test]
    fn only_matching_foreign_routes_are_wanted() {
        let r = ready();
        assert!(desired(&r, &mac_route(1, 10100, RT, REMOTE)).is_some());
        assert!(
            desired(&r, &mac_route(1, 10100, 1, REMOTE)).is_none(),
            "wrong RT"
        );
        assert!(
            desired(&r, &mac_route(1, 999, RT, REMOTE)).is_none(),
            "wrong VNI"
        );
        assert!(
            desired(&r, &mac_route(1, 10100, RT, VTEP)).is_none(),
            "our own"
        );
        assert_eq!(
            desired(&r, &imet_route(REMOTE, RT)),
            Some(Installed::Flood {
                vtep: REMOTE.parse().unwrap()
            })
        );
        assert!(desired(&r, &imet_route(VTEP, RT)).is_none());
    }

    #[test]
    fn local_routes_are_a_type3_plus_a_type2_per_mac_with_rt_and_encap() {
        let macs = BTreeSet::from([[0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 2]]);
        let routes = local_routes(&ready(), &macs);
        assert_eq!(routes.len(), 3);
        let r = routes.values().next().unwrap();
        assert_eq!(r.next_hop, VTEP.parse::<IpAddr>().unwrap());
        assert_eq!(r.ext_communities, vec![RT, ENCAP_VXLAN]);
    }

    #[derive(Default)]
    struct Recorder(StdMutex<Vec<String>>);

    #[async_trait]
    impl FdbDriver for Recorder {
        async fn ensure_vxlan(
            &self,
            vni: u32,
            _: IpAddr,
            _: &str,
            _: &str,
        ) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("ensure {vni}"));
            Ok(())
        }
        async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("remove {vni}"));
            Ok(())
        }
        async fn set_remote_mac(&self, _: u32, m: Mac, v: IpAddr) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("set {} {v}", format_mac(m)));
            Ok(())
        }
        async fn del_remote_mac(&self, _: u32, m: Mac, v: IpAddr) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("del {} {v}", format_mac(m)));
            Ok(())
        }
        async fn add_flood(&self, _: u32, v: IpAddr) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("flood+ {v}"));
            Ok(())
        }
        async fn del_flood(&self, _: u32, v: IpAddr) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("flood- {v}"));
            Ok(())
        }
        async fn local_macs(&self, _: &str, _: u32) -> Result<BTreeSet<Mac>, DriverError> {
            Ok(BTreeSet::from([[0, 0, 0, 0, 0, 7]]))
        }
        fn watch_neigh(&self) -> Option<mpsc::UnboundedReceiver<()>> {
            None
        }
    }

    fn calls(d: &Recorder) -> Vec<String> {
        std::mem::take(&mut *d.0.lock().unwrap())
    }

    #[tokio::test]
    async fn pushes_program_the_kernel_by_delta_and_survive_reconfiguration() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone());
        fdb.set_ready(Some(ready())).await;
        assert_eq!(calls(&driver), ["ensure 10100"]);

        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        fdb.apply_push(EvpnUpdate::Add(imet_route(REMOTE, RT)))
            .await;
        fdb.apply_push(EvpnUpdate::Add(mac_route(2, 10100, 1, REMOTE)))
            .await; // wrong RT
        assert_eq!(
            calls(&driver),
            ["set 00:00:00:00:00:01 192.0.2.9", "flood+ 192.0.2.9"]
        );
        // An identical re-push is not reprogrammed; a moved MAC is.
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        assert!(calls(&driver).is_empty());
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, "192.0.2.10")))
            .await;
        assert_eq!(
            calls(&driver),
            [
                "del 00:00:00:00:00:01 192.0.2.9",
                "set 00:00:00:00:00:01 192.0.2.10"
            ]
        );
        let table = fdb.table().await;
        assert_eq!(table.macs.len(), 1);
        assert_eq!(table.flood, vec![REMOTE.parse::<IpAddr>().unwrap()]);

        // A `Full` that drops both withdraws both.
        fdb.apply_push(EvpnUpdate::Full(vec![])).await;
        let mut c = calls(&driver);
        c.sort();
        assert_eq!(c, ["del 00:00:00:00:00:01 192.0.2.10", "flood- 192.0.2.9"]);

        // Unconfiguring removes the device.
        fdb.set_ready(None).await;
        assert_eq!(calls(&driver), ["remove 10100"]);
    }

    #[tokio::test]
    async fn local_macs_are_published_for_bgp_with_the_type3() {
        let fdb = Fdb::new("bd1".to_string(), Arc::new(Recorder::default()));
        let mut rx = fdb.subscribe();
        fdb.set_ready(Some(ready())).await;
        assert_eq!(rx.borrow_and_update().routes.len(), 1, "just the Type-3");
        fdb.refresh_local().await;
        let t = rx.borrow_and_update().clone();
        assert_eq!(t.bgp_instance.as_deref(), Some("r1"));
        assert_eq!(t.routes.len(), 2);
        fdb.set_ready(None).await;
        assert!(rx.borrow().routes.is_empty() && rx.borrow().bgp_instance.is_none());
    }
}
