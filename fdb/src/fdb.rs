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
use nos_proto::{EvpnKey, EvpnRoute, EvpnUpdate, FdbTable, MacEntry, MacSource, NeighEntry};
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{debug, info, warn};

use crate::driver::{is_advertisable_ip, vxlan_name, FdbDriver, Mac};

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
    /// `redistribute from arp`: local ARP/ND bindings are originated too.
    pub arp: bool,
    /// `redistribute from connected`: these SVI addresses (already filtered
    /// to `is_advertisable_ip`) are originated with the bridge's MAC.
    pub connected: Vec<IpAddr>,
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
    Mac {
        mac: Mac,
        vtep: IpAddr,
    },
    /// An IP-to-MAC binding on the bridge; `vtep` is only for `show fdb`.
    Neigh {
        mac: Mac,
        ip: IpAddr,
        vtep: IpAddr,
    },
    Flood {
        vtep: IpAddr,
    },
}

/// What a received route should become in the kernel, if anything: it must
/// carry one of our import Route Targets, name this VNI, and not be our own.
/// A Type-2 with an IP is both an FDB entry (its MAC) and a neighbour (its IP).
fn desired(r: &Ready, route: &EvpnRoute) -> Vec<Installed> {
    if !route
        .ext_communities
        .iter()
        .any(|c| r.rt_import.contains(c))
    {
        return Vec::new();
    }
    let foreign_type2 = route.vni == r.vni && route.next_hop != r.vtep;
    let vtep = route.next_hop;
    match &route.key {
        EvpnKey::Mac { mac, .. } if foreign_type2 => vec![Installed::Mac { mac: *mac, vtep }],
        EvpnKey::MacIp { mac, ip, .. } if foreign_type2 => {
            let mut v = vec![Installed::Mac { mac: *mac, vtep }];
            if is_advertisable_ip(*ip) {
                v.push(Installed::Neigh {
                    mac: *mac,
                    ip: *ip,
                    vtep,
                });
            }
            v
        }
        // A Type-3's VNI comes from its PMSI attribute (0 = absent).
        EvpnKey::Imet { origin, .. }
            if (route.vni == 0 || route.vni == r.vni) && *origin != r.vtep =>
        {
            vec![Installed::Flood { vtep: *origin }]
        }
        _ => Vec::new(),
    }
}

/// This domain's originated routes: one Type-3 for the domain, one Type-2
/// per local MAC and one Type-2 (MAC+IP) per local neighbour / SVI address.
fn local_routes(
    r: &Ready,
    macs: &BTreeSet<Mac>,
    neighbours: &BTreeSet<(Mac, IpAddr)>,
) -> HashMap<EvpnKey, EvpnRoute> {
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
        .chain(neighbours.iter().map(|(m, ip)| EvpnKey::MacIp {
            rd: r.rd,
            mac: *m,
            ip: *ip,
        }))
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
    /// What each received route put in the kernel. Two routes can name the
    /// same entry (a MAC-only and a MAC+IP Type-2 for one MAC), so an item is
    /// only removed when no other key still holds it.
    installed: HashMap<EvpnKey, Vec<Installed>>,
    local: BTreeSet<Mac>,
    /// Local ARP/ND bindings and SVI addresses, as (MAC, IP).
    local_neigh: BTreeSet<(Mac, IpAddr)>,
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
                .map(|r| local_routes(r, &g.local, &g.local_neigh))
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
                let mut items: Vec<Installed> = Vec::new();
                for i in std::mem::take(&mut g.installed).into_values().flatten() {
                    if !items.contains(&i) {
                        items.push(i);
                    }
                }
                for i in &items {
                    self.uninstall(&old, i).await;
                }
                if ready.as_ref().map(|r| r.vni) != Some(old.vni) {
                    if let Err(e) = self.driver.remove_vxlan(old.vni).await {
                        warn!(domain = %self.domain, error = %e, "failed to remove the old vxlan device");
                    }
                }
                g.local.clear();
                g.local_neigh.clear();
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
        let want = g
            .received
            .get(key)
            .map(|r| desired(&ready, r))
            .unwrap_or_default();
        let have = g.installed.get(key).cloned().unwrap_or_default();
        if want == have {
            return;
        }
        let held_elsewhere =
            |g: &Inner, i: &Installed| g.installed.iter().any(|(k, v)| k != key && v.contains(i));
        for h in &have {
            if !want.contains(h) && !held_elsewhere(g, h) {
                self.uninstall(&ready, h).await;
            }
        }
        let mut now = Vec::new();
        for w in want {
            if have.contains(&w) || held_elsewhere(g, &w) || self.install(&ready, &w).await {
                now.push(w);
            }
        }
        if now.is_empty() {
            g.installed.remove(key);
        } else {
            g.installed.insert(key.clone(), now);
        }
    }

    async fn install(&self, r: &Ready, i: &Installed) -> bool {
        let res = match i {
            Installed::Mac { mac, vtep } => self.driver.set_remote_mac(r.vni, *mac, *vtep).await,
            Installed::Neigh { mac, ip, .. } => self.driver.set_neigh(&r.bridge, *mac, *ip).await,
            Installed::Flood { vtep } => self.driver.add_flood(r.vni, *vtep).await,
        };
        match (res, i) {
            (Ok(()), Installed::Mac { mac, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vtep = %vtep, "remote mac installed");
                true
            }
            (Ok(()), Installed::Neigh { mac, ip, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), ip = %ip, vtep = %vtep, "remote neighbour installed");
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
            Installed::Neigh { mac, ip, .. } => self.driver.del_neigh(&r.bridge, *mac, *ip).await,
            Installed::Flood { vtep } => self.driver.del_flood(r.vni, *vtep).await,
        };
        match (res, i) {
            (Ok(()), Installed::Mac { mac, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vtep = %vtep, "remote mac removed");
            }
            (Ok(()), Installed::Neigh { mac, ip, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), ip = %ip, vtep = %vtep, "remote neighbour removed");
            }
            (Ok(()), Installed::Flood { vtep }) => {
                info!(domain = %self.domain, vtep = %vtep, "flood entry removed");
            }
            // Deleting the device already dropped them; nothing left to do.
            (Err(e), _) => debug!(domain = %self.domain, error = %e, "fdb delete failed"),
        }
    }

    /// Re-reads the bridge's local MACs (and, when redistributing arp or
    /// connected, its IP bindings) and publishes any change to the BGP
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
        let mut neighbours = BTreeSet::new();
        if r.arp {
            match self.driver.local_neighbours(&r.bridge).await {
                // Only hosts behind a local port: a binding the SVI learned
                // over the VXLAN port belongs to the remote VTEP that
                // originated it, and re-originating it would be wrong.
                Ok(n) => neighbours.extend(n.into_iter().filter(|(m, _)| macs.contains(m))),
                Err(e) => {
                    debug!(domain = %self.domain, error = %e, "could not read the bridge neighbours");
                    return;
                }
            }
        }
        if !r.connected.is_empty() {
            match self.driver.bridge_mac(&r.bridge).await {
                Ok(m) => neighbours.extend(r.connected.iter().map(|ip| (m, *ip))),
                Err(e) => {
                    debug!(domain = %self.domain, error = %e, "could not read the bridge mac");
                    return;
                }
            }
        }
        if macs == g.local && neighbours == g.local_neigh {
            return;
        }
        for (m, ip) in neighbours.difference(&g.local_neigh) {
            info!(domain = %self.domain, mac = %format_mac(*m), ip = %ip, "local neighbour learned");
        }
        for (m, ip) in g.local_neigh.difference(&neighbours) {
            info!(domain = %self.domain, mac = %format_mac(*m), ip = %ip, "local neighbour removed");
        }
        g.local_neigh = neighbours;
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
        let mut neighbours: Vec<NeighEntry> = g
            .local_neigh
            .iter()
            .map(|(m, ip)| NeighEntry {
                ip: *ip,
                mac: format_mac(*m),
                source: MacSource::Local,
                vtep: None,
            })
            .collect();
        let mut flood = Vec::new();
        // Several routes can hold one entry; list it once.
        let mut items: Vec<&Installed> = Vec::new();
        for i in g.installed.values().flatten() {
            if !items.contains(&i) {
                items.push(i);
            }
        }
        for i in items {
            match i {
                Installed::Mac { mac, vtep } => macs.push(MacEntry {
                    mac: format_mac(*mac),
                    source: MacSource::Remote,
                    vtep: Some(*vtep),
                }),
                Installed::Neigh { mac, ip, vtep } => neighbours.push(NeighEntry {
                    ip: *ip,
                    mac: format_mac(*mac),
                    source: MacSource::Remote,
                    vtep: Some(*vtep),
                }),
                Installed::Flood { vtep } => flood.push(*vtep),
            }
        }
        macs.sort_by(|a, b| a.mac.cmp(&b.mac));
        neighbours.sort_by(|a, b| (a.ip, &a.mac).cmp(&(b.ip, &b.mac)));
        flood.sort();
        FdbTable {
            domain: self.domain.clone(),
            vni: g.ready.as_ref().map_or(0, |r| r.vni),
            bridge: g.ready.as_ref().map(|r| r.bridge.clone()),
            vxlan: g.ready.as_ref().map(|r| vxlan_name(r.vni)),
            macs,
            neighbours,
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
            arp: false,
            connected: Vec::new(),
        }
    }

    fn macip_route(mac: u8, ip: &str, vni: u32, rt: u64, next_hop: &str) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::MacIp {
                rd: [0; 8],
                mac: [0, 0, 0, 0, 0, mac],
                ip: ip.parse().unwrap(),
            },
            vni,
            next_hop: next_hop.parse().unwrap(),
            ext_communities: vec![rt],
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
        assert!(!desired(&r, &mac_route(1, 10100, RT, REMOTE)).is_empty());
        assert!(
            desired(&r, &mac_route(1, 10100, 1, REMOTE)).is_empty(),
            "wrong RT"
        );
        assert!(
            desired(&r, &mac_route(1, 999, RT, REMOTE)).is_empty(),
            "wrong VNI"
        );
        assert!(
            desired(&r, &mac_route(1, 10100, RT, VTEP)).is_empty(),
            "our own"
        );
        assert_eq!(
            desired(&r, &imet_route(REMOTE, RT)),
            vec![Installed::Flood {
                vtep: REMOTE.parse().unwrap()
            }]
        );
        assert!(desired(&r, &imet_route(VTEP, RT)).is_empty());
    }

    #[test]
    fn a_type2_with_an_ip_is_an_fdb_entry_and_a_neighbour() {
        let r = ready();
        let vtep: IpAddr = REMOTE.parse().unwrap();
        assert_eq!(
            desired(&r, &macip_route(1, "198.51.100.7", 10100, RT, REMOTE)),
            vec![
                Installed::Mac {
                    mac: [0, 0, 0, 0, 0, 1],
                    vtep
                },
                Installed::Neigh {
                    mac: [0, 0, 0, 0, 0, 1],
                    ip: "198.51.100.7".parse().unwrap(),
                    vtep
                }
            ]
        );
        // The same filters as a MAC-only route, and no link-local neighbour.
        assert!(desired(&r, &macip_route(1, "198.51.100.7", 10100, 1, REMOTE)).is_empty());
        assert!(desired(&r, &macip_route(1, "198.51.100.7", 10100, RT, VTEP)).is_empty());
        assert_eq!(
            desired(&r, &macip_route(1, "fe80::1", 10100, RT, REMOTE)).len(),
            1
        );
    }

    #[test]
    fn local_routes_are_a_type3_plus_a_type2_per_mac_with_rt_and_encap() {
        let macs = BTreeSet::from([[0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 2]]);
        let routes = local_routes(&ready(), &macs, &BTreeSet::new());
        assert_eq!(routes.len(), 3);
        let r = routes.values().next().unwrap();
        assert_eq!(r.next_hop, VTEP.parse::<IpAddr>().unwrap());
        assert_eq!(r.ext_communities, vec![RT, ENCAP_VXLAN]);
    }

    #[test]
    fn neighbours_add_one_type2_with_the_ip_each() {
        let neighbours = BTreeSet::from([([0, 0, 0, 0, 0, 1], "198.51.100.7".parse().unwrap())]);
        let routes = local_routes(&ready(), &BTreeSet::new(), &neighbours);
        assert_eq!(routes.len(), 2, "the Type-3 and the MAC+IP");
        assert!(routes
            .keys()
            .any(|k| matches!(k, EvpnKey::MacIp { ip, .. } if ip.to_string() == "198.51.100.7")));
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
        async fn local_neighbours(&self, _: &str) -> Result<BTreeSet<(Mac, IpAddr)>, DriverError> {
            // One host behind a local port, one only reachable over VXLAN.
            Ok(BTreeSet::from([
                ([0, 0, 0, 0, 0, 7], "198.51.100.7".parse().unwrap()),
                ([0, 0, 0, 0, 0, 8], "198.51.100.8".parse().unwrap()),
            ]))
        }
        async fn bridge_mac(&self, _: &str) -> Result<Mac, DriverError> {
            Ok([0, 0, 0, 0, 0, 0xfe])
        }
        async fn set_neigh(&self, _: &str, m: Mac, ip: IpAddr) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("neigh+ {} {ip}", format_mac(m)));
            Ok(())
        }
        async fn del_neigh(&self, _: &str, m: Mac, ip: IpAddr) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("neigh- {} {ip}", format_mac(m)));
            Ok(())
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
    async fn a_mac_shared_by_two_routes_is_removed_only_with_the_last() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone());
        fdb.set_ready(Some(ready())).await;
        calls(&driver);

        // MAC-only first, then the MAC+IP route for the same MAC.
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        fdb.apply_push(EvpnUpdate::Add(macip_route(
            1,
            "198.51.100.7",
            10100,
            RT,
            REMOTE,
        )))
        .await;
        assert_eq!(
            calls(&driver),
            [
                "set 00:00:00:00:00:01 192.0.2.9",
                "neigh+ 00:00:00:00:00:01 198.51.100.7"
            ],
            "the MAC is programmed once"
        );
        let t = fdb.table().await;
        assert_eq!((t.macs.len(), t.neighbours.len()), (1, 1));

        // Withdrawing the MAC-only route keeps the MAC (the other still names it).
        let k = mac_route(1, 10100, RT, REMOTE).key;
        fdb.apply_push(EvpnUpdate::Remove(k)).await;
        assert!(calls(&driver).is_empty());
        // Withdrawing the last one removes both.
        let k = macip_route(1, "198.51.100.7", 10100, RT, REMOTE).key;
        fdb.apply_push(EvpnUpdate::Remove(k)).await;
        let mut c = calls(&driver);
        c.sort();
        assert_eq!(
            c,
            [
                "del 00:00:00:00:00:01 192.0.2.9",
                "neigh- 00:00:00:00:00:01 198.51.100.7"
            ]
        );
    }

    #[tokio::test]
    async fn arp_and_connected_originate_type2_with_ip() {
        let fdb = Fdb::new("bd1".to_string(), Arc::new(Recorder::default()));
        let mut rx = fdb.subscribe();
        let mut r = ready();
        r.arp = true;
        r.connected = vec!["203.0.113.1".parse().unwrap()];
        fdb.set_ready(Some(r)).await;
        fdb.refresh_local().await;
        let t = rx.borrow_and_update().clone();
        // Type-3, the local MAC 7, MAC+IP for host 7 (host 8 is not behind a
        // local port) and MAC+IP for the SVI with the bridge's own MAC.
        assert_eq!(t.routes.len(), 4);
        assert!(t.routes.keys().any(|k| matches!(k,
            EvpnKey::MacIp { mac, ip, .. }
                if *mac == [0, 0, 0, 0, 0, 0xfe] && ip.to_string() == "203.0.113.1")));
        assert!(!t.routes.keys().any(|k| matches!(k,
            EvpnKey::MacIp { ip, .. } if ip.to_string() == "198.51.100.8")));
        let table = fdb.table().await;
        assert_eq!(table.neighbours.len(), 2);
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
