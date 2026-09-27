//! One broadcast domain's MAC table: the local MACs the bridge learned, the
//! remote ones EVPN told us about, and the kernel state each implies. The
//! `nos-ribd` `Rib` counterpart — pure decisions here, kernel effects behind
//! `FdbDriver`.
//!
//! ponytail: a MAC learned from two VTEPs (or under two RDs) is last write
//! wins — no MAC-mobility sequence numbers, so it can flap between them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::pending;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use nos_proto::evpn_id::{
    es_import_rt, esi_label_ext, format_esi, parse_esi_label, Esi, DEFAULT_GATEWAY, ENCAP_VXLAN,
};
use nos_proto::fdb::AD_TAG_ES;
use nos_proto::{
    EsEntry, EvpnKey, EvpnRoute, EvpnUpdate, FdbTable, MacEntry, MacSource, NeighEntry,
};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{sleep_until, Instant};
use tracing::{debug, info, warn};

use crate::df;
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
    /// The bridge ports of this domain that attach an Ethernet Segment (a
    /// port aggregate with an `esi`, member of this domain).
    pub es_ports: Vec<EsPort>,
}

/// A bridge port attached to an Ethernet Segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsPort {
    /// The kernel bridge-port device: the bond, or its `<bond>.<tag>` VLAN
    /// sub-link.
    pub port: String,
    pub esi: Esi,
    /// `redundancy-mode single-active` on the aggregate.
    pub single_active: bool,
}

/// One attached segment's election outcome for this domain. The four bools
/// are independent facts (elected, still waiting, carrier, mode).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
struct Segment {
    esi: Esi,
    port: String,
    /// Every PE on the segment, ranked (see `df::candidates`).
    pes: Vec<IpAddr>,
    df: bool,
    /// Inside the DF wait timer: treated as non-DF whatever the election says
    /// (set by `sync_df`; `plan_df` itself stays pure).
    waiting: bool,
    /// The port has carrier. A down segment is neither DF nor advertised.
    up: bool,
    /// The other PEs whose per-ES Ethernet A-D route for this segment we hold.
    ad_pes: Vec<IpAddr>,
    /// Single-active: a non-DF is blocked outright, not just refused BUM.
    single_active: bool,
}

impl Segment {
    /// Whether two plans elect the same way — `ad_pes` changing alone is not
    /// a new election (it would only repeat the `df elected` log).
    fn same_election(&self, o: &Self) -> bool {
        (
            &self.esi,
            &self.port,
            &self.pes,
            self.df,
            self.waiting,
            self.up,
            self.single_active,
        ) == (
            &o.esi,
            &o.port,
            &o.pes,
            o.df,
            o.waiting,
            o.up,
            o.single_active,
        )
    }
}

/// What the Ethernet A-D routes we hold say about one segment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SegmentAds {
    /// The PEs whose per-ES Ethernet A-D route we hold (RFC 7432 §8.2): a
    /// remote MAC on the segment is only usable while its PE is in here, and
    /// withdrawing the route is the mass withdrawal that takes every such MAC
    /// away at once.
    pes: BTreeSet<IpAddr>,
    /// The PEs whose per-EVI A-D route for this domain's VNI we hold: the
    /// backup paths of a single-active segment (§8.4.1.2).
    evi: BTreeSet<IpAddr>,
    /// A per-ES route carried the Single-Active flag in its ESI Label.
    single_active: bool,
}

type Ads = HashMap<Esi, SegmentAds>;

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
    /// A MAC on an all-active segment, balanced over these PEs (sorted).
    MacGroup {
        mac: Mac,
        vteps: Vec<IpAddr>,
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

/// The A-D index of `received`: only routes carrying one of our import Route
/// Targets count (a per-ES route carries the RTs of the EVIs on the segment),
/// and never our own. A per-EVI route also has to name this domain's VNI.
fn ad_index(r: &Ready, received: &HashMap<EvpnKey, EvpnRoute>) -> Ads {
    let mut out = Ads::new();
    for route in received.values() {
        let EvpnKey::EthernetAd {
            esi, tag, origin, ..
        } = &route.key
        else {
            continue;
        };
        if *origin == r.vtep
            || !route
                .ext_communities
                .iter()
                .any(|c| r.rt_import.contains(c))
        {
            continue;
        }
        let ads = out.entry(*esi).or_default();
        if *tag == AD_TAG_ES {
            ads.pes.insert(*origin);
            ads.single_active |= route
                .ext_communities
                .iter()
                .any(|c| parse_esi_label(*c) == Some(true));
        } else if route.vni == r.vni {
            ads.evi.insert(*origin);
        }
    }
    out
}

/// The PEs a MAC on an all-active segment is load-balanced over (aliasing,
/// RFC 7432 §8.4.1.1): those that advertise both the segment (per-ES A-D) and
/// the EVI (per-EVI A-D). Only when there are several, the MAC's own PE is one
/// of them, and they are all IPv4 (an FDB nexthop's gateway).
fn alias_group(a: &SegmentAds, owner: IpAddr) -> Option<Vec<IpAddr>> {
    if a.single_active {
        return None;
    }
    let members: Vec<IpAddr> = a.pes.intersection(&a.evi).copied().collect();
    (members.len() > 1 && members.contains(&owner) && members.iter().all(IpAddr::is_ipv4))
        .then_some(members)
}

/// What a received route should become in the kernel, if anything: it must
/// carry one of our import Route Targets, name this VNI, and not be our own.
/// A Type-2 with an IP is both an FDB entry (its MAC) and a neighbour (its IP).
/// A Type-2 on a segment is only usable while its PE's per-ES A-D route for
/// that segment is held (`ads`).
fn desired(r: &Ready, route: &EvpnRoute, ads: &Ads) -> Vec<Installed> {
    if !route
        .ext_communities
        .iter()
        .any(|c| r.rt_import.contains(c))
    {
        return Vec::new();
    }
    // A MAC on a segment we are attached to is reachable through our own
    // bond; a VXLAN entry to the peer PE that also learned it would win.
    let on_local_segment = route.esi != [0; 10] && r.es_ports.iter().any(|p| p.esi == route.esi);
    // The PE a MAC on a segment is reached through: the one that advertised it
    // while its per-ES A-D is held; on a single-active segment whose PE lost it,
    // a backup (a PE that advertised a per-EVI A-D for this VNI).
    let via = if route.esi == [0; 10] {
        Some(route.next_hop)
    } else {
        ads.get(&route.esi).and_then(|a| {
            if a.pes.contains(&route.next_hop) {
                Some(route.next_hop)
            } else if a.single_active {
                a.pes.intersection(&a.evi).next().copied()
            } else {
                None
            }
        })
    };
    let foreign_type2 =
        route.vni == r.vni && route.next_hop != r.vtep && !on_local_segment && via.is_some();
    let vtep = via.unwrap_or(route.next_hop);
    // A MAC whose own PE's per-ES A-D is held is aliased over the segment's PEs.
    let group = (via == Some(route.next_hop))
        .then(|| {
            ads.get(&route.esi)
                .and_then(|a| alias_group(a, route.next_hop))
        })
        .flatten();
    let mac_item = |mac: Mac| match &group {
        Some(vteps) => Installed::MacGroup {
            mac,
            vteps: vteps.clone(),
        },
        None => Installed::Mac { mac, vtep },
    };
    match &route.key {
        EvpnKey::Mac { mac, .. } if foreign_type2 => vec![mac_item(*mac)],
        EvpnKey::MacIp { mac, ip, .. } if foreign_type2 => {
            let mut v = vec![mac_item(*mac)];
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

/// The ESI a MAC learned behind `port` is advertised with (all-zero when the
/// port isn't a segment's).
fn esi_of(r: &Ready, port: Option<&String>) -> Esi {
    port.and_then(|port| r.es_ports.iter().find(|p| &p.port == port))
        .map_or([0; 10], |p| p.esi)
}

/// This domain's originated routes: one Type-3 for the domain, one Type-2
/// per local MAC and one Type-2 (MAC+IP) per local neighbour / SVI address
/// (carrying the ESI of the port the MAC sits behind, and — for an SVI
/// address, RFC 7432 §7.8 — the Default Gateway extended community), and,
/// per attached Ethernet Segment whose port has carrier (not in `down`), one
/// Type-4 and the two Type-1 Ethernet A-D routes (per-ES and per-EVI). A
/// segment going down withdraws all three — that is what tells the other PEs
/// to stop sending its MACs here.
fn local_routes(
    r: &Ready,
    macs: &BTreeMap<Mac, String>,
    neighbours: &BTreeSet<(Mac, IpAddr)>,
    down: &BTreeSet<String>,
) -> HashMap<EvpnKey, EvpnRoute> {
    let mut ext = r.rt_export.clone();
    ext.push(ENCAP_VXLAN);
    let route = |key: EvpnKey, esi: Esi| EvpnRoute {
        key,
        vni: r.vni,
        next_hop: r.vtep,
        ext_communities: ext.clone(),
        esi,
    };
    let mut out = HashMap::new();
    let imet = EvpnKey::Imet {
        rd: r.rd,
        origin: r.vtep,
    };
    out.insert(imet.clone(), route(imet, [0; 10]));
    for (m, port) in macs {
        let key = EvpnKey::Mac { rd: r.rd, mac: *m };
        out.insert(key.clone(), route(key, esi_of(r, Some(port))));
    }
    for (m, ip) in neighbours {
        let key = EvpnKey::MacIp {
            rd: r.rd,
            mac: *m,
            ip: *ip,
        };
        let mut evpn_route = route(key.clone(), esi_of(r, macs.get(m)));
        // RFC 7432 §7.8: mark the SVI's own address as the anycast gateway,
        // never a real ARP/ND-learned host behind a local port.
        if r.connected.contains(ip) {
            evpn_route.ext_communities.push(DEFAULT_GATEWAY);
        }
        out.insert(key, evpn_route);
    }
    let mut esis: BTreeMap<Esi, bool> = BTreeMap::new();
    for p in r.es_ports.iter().filter(|p| !down.contains(&p.port)) {
        *esis.entry(p.esi).or_default() |= p.single_active;
    }
    for (esi, single_active) in esis {
        let key = EvpnKey::EthernetSegment {
            rd: r.rd,
            esi,
            origin: r.vtep,
        };
        // A Type-4 carries only its ES-Import Route Target (RFC 7432 §7.6):
        // it is for the PEs on the segment, not for a MAC-VRF's import.
        out.insert(
            key.clone(),
            EvpnRoute {
                key,
                vni: 0,
                next_hop: r.vtep,
                ext_communities: vec![es_import_rt(&esi)],
                esi,
            },
        );
        // Per-ES A-D (RFC 7432 §8.2.1): MAX-ET, the export RTs of the EVIs on
        // the segment, and the ESI Label community (RFC 8365 §8.3.1: no label
        // with VXLAN, only its flags octet).
        let key = EvpnKey::EthernetAd {
            rd: r.rd,
            esi,
            tag: AD_TAG_ES,
            origin: r.vtep,
        };
        let mut es_ext = ext.clone();
        es_ext.push(esi_label_ext(single_active));
        out.insert(
            key.clone(),
            EvpnRoute {
                key,
                vni: 0,
                next_hop: r.vtep,
                ext_communities: es_ext,
                esi,
            },
        );
        // Per-EVI A-D (§8.4): tag 0, the VNI in the label, this domain's RTs.
        let key = EvpnKey::EthernetAd {
            rd: r.rd,
            esi,
            tag: 0,
            origin: r.vtep,
        };
        out.insert(key.clone(), route(key, esi));
    }
    out
}

/// Elects the Designated Forwarder of every segment this domain attaches to,
/// from the Type-4 routes received so far, restricted to PEs also attached to
/// this domain's own EVI (a held per-EVI Ethernet A-D for our VNI, RFC 7432
/// §8.5 / RFC 8584 §2.1) — a PE on the segment that never joined this EVI is
/// not a candidate for it. Other PEs are recognised by their Type-4's
/// originating address; our own is `r.vtep`. A segment whose port is in
/// `down` is never the DF.
fn plan_df(
    r: &Ready,
    received: &HashMap<EvpnKey, EvpnRoute>,
    ads: &Ads,
    down: &BTreeSet<String>,
) -> Vec<Segment> {
    r.es_ports
        .iter()
        .map(|p| {
            let peers: BTreeSet<IpAddr> = received
                .keys()
                .filter_map(|k| match k {
                    EvpnKey::EthernetSegment { esi, origin, .. } if *esi == p.esi => Some(*origin),
                    _ => None,
                })
                .filter(|o| *o != r.vtep)
                .filter(|o| ads.get(&p.esi).is_some_and(|a| a.evi.contains(o)))
                .collect();
            let up = !down.contains(&p.port);
            Segment {
                esi: p.esi,
                port: p.port.clone(),
                pes: df::candidates(r.vtep, &peers),
                df: up && df::elect(r.vtep, &peers, r.vni) == r.vtep,
                waiting: false,
                up,
                ad_pes: ads
                    .get(&p.esi)
                    .map(|a| a.pes.iter().copied().collect())
                    .unwrap_or_default(),
                single_active: p.single_active,
            }
        })
        .collect()
}

fn join_ips(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
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
    /// Each MAC with the bridge port it sits behind.
    local: BTreeMap<Mac, String>,
    /// The last election result per attached segment.
    segments: Vec<Segment>,
    /// The flood setting last applied to each segment port.
    es_flood: BTreeMap<String, bool>,
    /// The forwarding state last applied to each segment port (only recorded
    /// once it left the kernel default, forwarding).
    es_fwd: BTreeMap<String, bool>,
    /// When each attached segment port's DF wait timer ends (RFC 7432 §8.5
    /// step 3). Set the first time the port is planned, dropped when it leaves.
    df_wait_until: BTreeMap<String, Instant>,
    /// Local ARP/ND bindings and SVI addresses, as (MAC, IP).
    local_neigh: BTreeSet<(Mac, IpAddr)>,
    /// The per-ES A-D routes held, see `Ads`. Kept current by `refresh_ads`.
    ads: Ads,
    /// Attached segment ports with no carrier (unknown counts as up).
    es_down: BTreeSet<String>,
}

/// Recomputes `g.ads` and returns the segments whose PE set changed.
fn refresh_ads(g: &mut Inner) -> Vec<Esi> {
    let new = g
        .ready
        .as_ref()
        .map(|r| ad_index(r, &g.received))
        .unwrap_or_default();
    let stale = new
        .keys()
        .chain(g.ads.keys())
        .filter(|e| new.get(*e) != g.ads.get(*e))
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    g.ads = new;
    stale
}

pub struct Fdb {
    domain: String,
    driver: Arc<dyn FdbDriver>,
    inner: Mutex<Inner>,
    target: watch::Sender<EvpnTarget>,
    df_wait: Duration,
    /// The earliest running DF wait timer, for `run_local` to sleep until.
    df_deadline: watch::Sender<Option<Instant>>,
}

impl Fdb {
    pub fn new(domain: String, driver: Arc<dyn FdbDriver>, df_wait: Duration) -> Arc<Self> {
        let (target, _) = watch::channel(EvpnTarget {
            domain: domain.clone(),
            ..EvpnTarget::default()
        });
        Arc::new(Self {
            domain,
            driver,
            inner: Mutex::default(),
            target,
            df_wait,
            df_deadline: watch::channel(None).0,
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
                .map(|r| local_routes(r, &g.local, &g.local_neigh, &g.es_down))
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
        let Some(want) = ready else {
            self.sync_df(&mut g).await;
            return;
        };
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
            self.sync_df(&mut g).await;
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
        refresh_ads(&mut g);
        let keys: Vec<EvpnKey> = g.received.keys().cloned().collect();
        for k in keys {
            self.sync_key(&mut g, &k).await;
        }
        self.sync_df(&mut g).await;
    }

    /// Re-elects the Designated Forwarder of every attached segment and
    /// applies it: a non-DF stops flooding BUM to the segment's port, a DF
    /// (and a port no longer on any segment) floods normally. A port is held
    /// blocked for `df_wait` after it first appears (RFC 7432 §8.5 step 3), so
    /// a PE that has just come up doesn't deliver BUM the DF already does. The
    /// block is re-asserted every call, so a port the kernel recreated is
    /// healed by the tick.
    async fn sync_df(&self, g: &mut Inner) {
        let mut plan = g
            .ready
            .as_ref()
            .map(|r| plan_df(r, &g.received, &g.ads, &g.es_down))
            .unwrap_or_default();
        let now = Instant::now();
        for s in &mut plan {
            if !s.up {
                // No carrier: the wait starts over when it comes back.
                g.df_wait_until.remove(&s.port);
                s.waiting = true;
                continue;
            }
            let until = *g.df_wait_until.entry(s.port.clone()).or_insert_with(|| {
                info!(
                    domain = %self.domain, esi = %format_esi(&s.esi), port = %s.port,
                    seconds = self.df_wait.as_secs(), "df wait started"
                );
                now + self.df_wait
            });
            s.waiting = now < until;
        }
        g.df_wait_until
            .retain(|p, _| plan.iter().any(|s| &s.port == p));
        let next = g
            .df_wait_until
            .values()
            .filter(|u| **u > now)
            .min()
            .copied();
        self.df_deadline.send_if_modified(|d| {
            let changed = *d != next;
            *d = next;
            changed
        });
        for s in &plan {
            if !s.waiting
                && !g
                    .segments
                    .iter()
                    .find(|o| o.port == s.port)
                    .is_some_and(|o| o.same_election(s))
            {
                // `%`, not a bare str: a plain str field renders quoted.
                let role = if s.df { "df" } else { "non-df" };
                info!(
                    domain = %self.domain, esi = %format_esi(&s.esi), port = %s.port,
                    role = %role,
                    pes = %s.pes.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
                    "df elected"
                );
            }
            // All-active: only the DF floods BUM to the port. Single-active: the
            // port floods normally but only the DF's forwards anything.
            let active = s.df && !s.waiting;
            let (flood, forwarding) = if s.single_active {
                (true, active)
            } else {
                (active, true)
            };
            self.apply_port_flood(g, &s.port, flood).await;
            self.apply_port_forwarding(g, &s.port, forwarding).await;
        }
        let gone: Vec<String> = g
            .es_flood
            .keys()
            .chain(g.es_fwd.keys())
            .filter(|p| !plan.iter().any(|s| &s.port == *p))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for port in gone {
            // Best effort: if the port is gone too there is nothing to restore.
            if g.es_flood.remove(&port).is_some()
                && self.driver.set_port_flood(&port, true).await.is_ok()
            {
                info!(domain = %self.domain, port = %port, flood = true, "segment port flooding set");
            }
            if g.es_fwd.remove(&port) == Some(false)
                && self.driver.set_port_forwarding(&port, true).await.is_ok()
            {
                info!(domain = %self.domain, port = %port, forwarding = true, "segment port forwarding set");
            }
        }
        g.segments = plan;
    }

    /// Applies the BUM-flood setting of one segment port; a block is
    /// re-asserted on every call (a recreated port is healed by the tick).
    async fn apply_port_flood(&self, g: &mut Inner, port: &str, flood: bool) {
        let prev = g.es_flood.get(port).copied();
        if prev == Some(flood) && flood {
            return;
        }
        match self.driver.set_port_flood(port, flood).await {
            Ok(()) => {
                if prev != Some(flood) {
                    info!(domain = %self.domain, port = %port, flood, "segment port flooding set");
                }
                g.es_flood.insert(port.to_string(), flood);
            }
            Err(e) => {
                debug!(domain = %self.domain, port = %port, error = %e, "could not set port flooding yet, retrying");
                g.es_flood.remove(port);
            }
        }
    }

    /// Applies the forwarding state of one segment port (single-active blocks
    /// a non-DF outright). Forwarding is the kernel default, so it is only
    /// asserted when the port was blocked before.
    async fn apply_port_forwarding(&self, g: &mut Inner, port: &str, forwarding: bool) {
        let prev = g.es_fwd.get(port).copied();
        if forwarding && prev != Some(false) {
            return;
        }
        match self.driver.set_port_forwarding(port, forwarding).await {
            Ok(()) => {
                if prev != Some(forwarding) {
                    info!(domain = %self.domain, port = %port, forwarding, "segment port forwarding set");
                }
                g.es_fwd.insert(port.to_string(), forwarding);
            }
            Err(e) => {
                debug!(domain = %self.domain, port = %port, error = %e, "could not set port forwarding yet, retrying");
                g.es_fwd.remove(port);
            }
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
        let segments_changed = keys.iter().any(|k| {
            matches!(
                k,
                EvpnKey::EthernetSegment { .. } | EvpnKey::EthernetAd { .. }
            )
        });
        let mut keys = keys;
        if keys.iter().any(|k| matches!(k, EvpnKey::EthernetAd { .. })) {
            // A PE's per-ES A-D coming or going re-decides every MAC on that
            // segment at once (mass withdrawal, RFC 7432 §8.2.1).
            let stale = refresh_ads(&mut g);
            for esi in &stale {
                info!(
                    domain = %self.domain, esi = %format_esi(esi),
                    pes = %g.ads.get(esi).map(|a| a.pes.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")).unwrap_or_default(),
                    "segment per-es a-d changed"
                );
            }
            keys.extend(
                g.received
                    .iter()
                    .filter(|(_, r)| {
                        stale.contains(&r.esi)
                            && matches!(r.key, EvpnKey::Mac { .. } | EvpnKey::MacIp { .. })
                    })
                    .map(|(k, _)| k.clone()),
            );
        }
        for k in keys {
            self.sync_key(&mut g, &k).await;
        }
        if segments_changed {
            self.sync_df(&mut g).await;
        }
    }

    /// Brings one route's kernel state in line with `received` + config.
    async fn sync_key(&self, g: &mut Inner, key: &EvpnKey) {
        let Some(ready) = g.ready.clone() else { return };
        let want = g
            .received
            .get(key)
            .map(|r| desired(&ready, r, &g.ads))
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
            Installed::MacGroup { mac, vteps } => {
                self.driver.set_remote_mac_group(r.vni, *mac, vteps).await
            }
            Installed::Neigh { mac, ip, .. } => self.driver.set_neigh(&r.bridge, *mac, *ip).await,
            Installed::Flood { vtep } => self.driver.add_flood(r.vni, *vtep).await,
        };
        match (res, i) {
            (Ok(()), Installed::Mac { mac, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vtep = %vtep, "remote mac installed");
                true
            }
            (Ok(()), Installed::MacGroup { mac, vteps }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vteps = %join_ips(vteps), "remote mac group installed");
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
            Installed::MacGroup { mac, .. } => self.driver.del_remote_mac_group(r.vni, *mac).await,
            Installed::Neigh { mac, ip, .. } => self.driver.del_neigh(&r.bridge, *mac, *ip).await,
            Installed::Flood { vtep } => self.driver.del_flood(r.vni, *vtep).await,
        };
        match (res, i) {
            (Ok(()), Installed::Mac { mac, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vtep = %vtep, "remote mac removed");
            }
            (Ok(()), Installed::MacGroup { mac, vteps }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vteps = %join_ips(vteps), "remote mac group removed");
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
        // Segment carrier first: a down segment withdraws its routes. A failed
        // read counts as up, so a transient netlink error withdraws nothing.
        let mut down = BTreeSet::new();
        for p in &r.es_ports {
            if !self.driver.port_up(&p.port).await.unwrap_or(true) {
                down.insert(p.port.clone());
            }
        }
        if down != g.es_down {
            for p in down.symmetric_difference(&g.es_down) {
                info!(domain = %self.domain, port = %p, up = !down.contains(p), "segment port carrier changed");
            }
            g.es_down = down;
            self.sync_df(&mut g).await;
            self.publish(&g);
        }
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
                Ok(n) => neighbours.extend(n.into_iter().filter(|(m, _)| macs.contains_key(m))),
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
        for (m, port) in &macs {
            if g.local.get(m) != Some(port) {
                info!(domain = %self.domain, mac = %format_mac(*m), port = %port, "local mac learned");
            }
        }
        for m in g.local.keys().filter(|m| !macs.contains_key(*m)) {
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
        let mut df_deadline = self.df_deadline.subscribe();
        loop {
            let df_at = *df_deadline.borrow_and_update();
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
                // A DF wait timer ended: elect now rather than at the tick.
                () = sleep_until_opt(df_at) => {
                    let mut g = self.inner.lock().await;
                    self.sync_df(&mut g).await;
                    continue;
                }
                _ = df_deadline.changed() => continue,
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
            .map(|(m, port)| MacEntry {
                mac: format_mac(*m),
                source: MacSource::Local,
                vtep: None,
                vteps: Vec::new(),
                esi: g
                    .ready
                    .as_ref()
                    .map(|r| esi_of(r, Some(port)))
                    .filter(|e| *e != [0; 10])
                    .map(|e| format_esi(&e)),
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
                    vteps: vec![*vtep],
                    esi: None,
                }),
                Installed::MacGroup { mac, vteps } => macs.push(MacEntry {
                    mac: format_mac(*mac),
                    source: MacSource::Remote,
                    vtep: vteps.first().copied(),
                    vteps: vteps.clone(),
                    esi: None,
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
            segments: g
                .segments
                .iter()
                .map(|s| EsEntry {
                    esi: format_esi(&s.esi),
                    port: s.port.clone(),
                    designated_forwarder: s.df && !s.waiting,
                    pes: s.pes.clone(),
                    ad_pes: s.ad_pes.clone(),
                    up: s.up,
                    single_active: s.single_active,
                })
                .collect(),
        }
    }
}

async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => pending().await,
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
            es_ports: Vec::new(),
        }
    }

    const ESI: Esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    fn ready_with_segment() -> Ready {
        Ready {
            es_ports: vec![EsPort {
                // The `Recorder` driver puts every local MAC behind `eth1`.
                port: "eth1".to_string(),
                esi: ESI,
                single_active: false,
            }],
            ..ready()
        }
    }

    fn ready_single_active() -> Ready {
        let mut r = ready_with_segment();
        r.es_ports[0].single_active = true;
        r
    }

    /// The A-D index entry for a segment whose PEs' per-ES routes are held.
    fn ads_of(esi: Esi, pes: &[&str]) -> Ads {
        Ads::from([(
            esi,
            SegmentAds {
                pes: pes.iter().map(|p| p.parse().unwrap()).collect(),
                ..SegmentAds::default()
            },
        )])
    }

    /// `desired` with no per-ES A-D held.
    fn want(r: &Ready, route: &EvpnRoute) -> Vec<Installed> {
        desired(r, route, &Ads::new())
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
            esi: [0; 10],
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
            esi: [0; 10],
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
            esi: [0; 10],
        }
    }

    #[test]
    fn only_matching_foreign_routes_are_wanted() {
        let r = ready();
        assert!(!want(&r, &mac_route(1, 10100, RT, REMOTE)).is_empty());
        assert!(
            want(&r, &mac_route(1, 10100, 1, REMOTE)).is_empty(),
            "wrong RT"
        );
        assert!(
            want(&r, &mac_route(1, 999, RT, REMOTE)).is_empty(),
            "wrong VNI"
        );
        assert!(
            want(&r, &mac_route(1, 10100, RT, VTEP)).is_empty(),
            "our own"
        );
        assert_eq!(
            want(&r, &imet_route(REMOTE, RT)),
            vec![Installed::Flood {
                vtep: REMOTE.parse().unwrap()
            }]
        );
        assert!(want(&r, &imet_route(VTEP, RT)).is_empty());
    }

    #[test]
    fn a_type2_with_an_ip_is_an_fdb_entry_and_a_neighbour() {
        let r = ready();
        let vtep: IpAddr = REMOTE.parse().unwrap();
        assert_eq!(
            want(&r, &macip_route(1, "198.51.100.7", 10100, RT, REMOTE)),
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
        assert!(want(&r, &macip_route(1, "198.51.100.7", 10100, 1, REMOTE)).is_empty());
        assert!(want(&r, &macip_route(1, "198.51.100.7", 10100, RT, VTEP)).is_empty());
        assert_eq!(
            want(&r, &macip_route(1, "fe80::1", 10100, RT, REMOTE)).len(),
            1
        );
    }

    #[test]
    fn local_routes_are_a_type3_plus_a_type2_per_mac_with_rt_and_encap() {
        let macs = BTreeMap::from([
            ([0, 0, 0, 0, 0, 1], "eth1".to_string()),
            ([0, 0, 0, 0, 0, 2], "eth1".to_string()),
        ]);
        let routes = local_routes(&ready(), &macs, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(routes.len(), 3);
        let r = routes.values().next().unwrap();
        assert_eq!(r.next_hop, VTEP.parse::<IpAddr>().unwrap());
        assert_eq!(r.ext_communities, vec![RT, ENCAP_VXLAN]);
    }

    #[test]
    fn neighbours_add_one_type2_with_the_ip_each() {
        let neighbours = BTreeSet::from([([0, 0, 0, 0, 0, 1], "198.51.100.7".parse().unwrap())]);
        let routes = local_routes(&ready(), &BTreeMap::new(), &neighbours, &BTreeSet::new());
        assert_eq!(routes.len(), 2, "the Type-3 and the MAC+IP");
        assert!(routes
            .keys()
            .any(|k| matches!(k, EvpnKey::MacIp { ip, .. } if ip.to_string() == "198.51.100.7")));
    }

    /// Records every driver call; the second field is the ports with no carrier.
    #[derive(Default)]
    struct Recorder(StdMutex<Vec<String>>, StdMutex<BTreeSet<String>>);

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
        async fn set_remote_mac_group(
            &self,
            _: u32,
            m: Mac,
            v: &[IpAddr],
        ) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("group {} {}", format_mac(m), join_ips(v)));
            Ok(())
        }
        async fn del_remote_mac_group(&self, _: u32, m: Mac) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("group- {}", format_mac(m)));
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
        async fn local_macs(&self, _: &str, _: u32) -> Result<BTreeMap<Mac, String>, DriverError> {
            Ok(BTreeMap::from([([0, 0, 0, 0, 0, 7], "eth1".to_string())]))
        }
        async fn set_port_flood(&self, port: &str, flood: bool) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("flood {port} {flood}"));
            Ok(())
        }
        async fn set_port_forwarding(&self, port: &str, fwd: bool) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("fwd {port} {fwd}"));
            Ok(())
        }
        async fn port_up(&self, port: &str) -> Result<bool, DriverError> {
            Ok(!self.1.lock().unwrap().contains(port))
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
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
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
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
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
        let fdb = Fdb::new(
            "bd1".to_string(),
            Arc::new(Recorder::default()),
            Duration::ZERO,
        );
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
        let svi = t
            .routes
            .iter()
            .find(|(k, _)| {
                matches!(k, EvpnKey::MacIp { mac, ip, .. }
                    if *mac == [0, 0, 0, 0, 0, 0xfe] && ip.to_string() == "203.0.113.1")
            })
            .expect("svi route");
        // RFC 7432 §7.8: only the SVI's own address is the anycast gateway.
        assert!(svi.1.ext_communities.contains(&DEFAULT_GATEWAY));
        let host = t
            .routes
            .iter()
            .find(
                |(k, _)| matches!(k, EvpnKey::MacIp { ip, .. } if ip.to_string() == "198.51.100.7"),
            )
            .expect("arp-learned host route");
        assert!(!host.1.ext_communities.contains(&DEFAULT_GATEWAY));
        assert!(!t.routes.keys().any(|k| matches!(k,
            EvpnKey::MacIp { ip, .. } if ip.to_string() == "198.51.100.8")));
        let table = fdb.table().await;
        assert_eq!(table.neighbours.len(), 2);
    }

    #[tokio::test]
    async fn local_macs_are_published_for_bgp_with_the_type3() {
        let fdb = Fdb::new(
            "bd1".to_string(),
            Arc::new(Recorder::default()),
            Duration::ZERO,
        );
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

    fn es_route(esi: Esi, origin: &str) -> EvpnRoute {
        let origin: IpAddr = origin.parse().unwrap();
        EvpnRoute {
            key: EvpnKey::EthernetSegment {
                rd: [0; 8],
                esi,
                origin,
            },
            vni: 0,
            next_hop: origin,
            ext_communities: vec![es_import_rt(&esi)],
            esi,
        }
    }

    fn ad_route(esi: Esi, tag: u32, vni: u32, origin: &str) -> EvpnRoute {
        let origin: IpAddr = origin.parse().unwrap();
        EvpnRoute {
            key: EvpnKey::EthernetAd {
                rd: [0; 8],
                esi,
                tag,
                origin,
            },
            vni,
            next_hop: origin,
            ext_communities: vec![RT, esi_label_ext(false)],
            esi,
        }
    }

    fn es_ad(esi: Esi, origin: &str) -> EvpnRoute {
        ad_route(esi, AD_TAG_ES, 0, origin)
    }

    #[test]
    fn a_remote_mac_on_a_segment_needs_its_pes_per_es_ad_and_never_on_our_own() {
        let mut route = mac_route(1, 10100, RT, REMOTE);
        route.esi = ESI;
        let ads = ads_of(ESI, &[REMOTE]);
        // Not usable until the PE that advertised it has advertised the segment.
        assert!(want(&ready(), &route).is_empty(), "no per-es a-d yet");
        assert!(!desired(&ready(), &route, &ads).is_empty());
        // A different PE's A-D for the segment doesn't count.
        let other = ads_of(ESI, &["192.0.2.77"]);
        assert!(desired(&ready(), &route, &other).is_empty());
        // ... and on a segment we are attached to it is reachable via our own bond.
        assert!(desired(&ready_with_segment(), &route, &ads).is_empty());
        // A different segment's MAC is just as gated.
        route.esi = [9; 10];
        assert!(desired(&ready_with_segment(), &route, &ads).is_empty());
        let ads9 = ads_of([9; 10], &[REMOTE]);
        assert!(!desired(&ready_with_segment(), &route, &ads9).is_empty());
    }

    #[test]
    fn the_per_es_ad_index_counts_only_our_route_targets_and_never_our_own_pe() {
        let r = ready();
        let mut received = HashMap::new();
        for route in [
            es_ad(ESI, REMOTE),
            es_ad(ESI, VTEP),
            // A per-EVI route, and one for another domain (other RT).
            ad_route(ESI, 0, 10100, "192.0.2.10"),
            EvpnRoute {
                ext_communities: vec![1],
                ..es_ad(ESI, "192.0.2.11")
            },
        ] {
            received.insert(route.key.clone(), route);
        }
        // The per-EVI route counts as a backup path only for this domain's VNI.
        let mut expected = ads_of(ESI, &[REMOTE]);
        expected
            .get_mut(&ESI)
            .unwrap()
            .evi
            .insert("192.0.2.10".parse().unwrap());
        assert_eq!(ad_index(&r, &received), expected);
    }

    #[tokio::test]
    async fn withdrawing_a_pes_per_es_ad_takes_all_its_macs_at_once_and_readvertising_restores_them(
    ) {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        calls(&driver);
        let mut m1 = mac_route(1, 10100, RT, REMOTE);
        m1.esi = ESI;
        let mut m2 = mac_route(2, 10100, RT, REMOTE);
        m2.esi = ESI;
        // A MAC with no ESI is not affected by any of this.
        let plain = mac_route(3, 10100, RT, REMOTE);
        for r in [&m1, &m2, &plain] {
            fdb.apply_push(EvpnUpdate::Add(r.clone())).await;
        }
        assert_eq!(calls(&driver), ["set 00:00:00:00:00:03 192.0.2.9"]);

        fdb.apply_push(EvpnUpdate::Add(es_ad(ESI, REMOTE))).await;
        let mut c = calls(&driver);
        c.sort();
        assert_eq!(
            c,
            [
                "set 00:00:00:00:00:01 192.0.2.9",
                "set 00:00:00:00:00:02 192.0.2.9"
            ]
        );
        assert_eq!(fdb.table().await.macs.len(), 3);

        // Mass withdrawal: one route goes, both MACs go, the plain one stays.
        fdb.apply_push(EvpnUpdate::Remove(es_ad(ESI, REMOTE).key))
            .await;
        let mut c = calls(&driver);
        c.sort();
        assert_eq!(
            c,
            [
                "del 00:00:00:00:00:01 192.0.2.9",
                "del 00:00:00:00:00:02 192.0.2.9"
            ]
        );
        assert_eq!(fdb.table().await.macs.len(), 1);

        // A `Full` that brings it back reinstalls them.
        fdb.apply_push(EvpnUpdate::Full(vec![
            m1.clone(),
            m2.clone(),
            plain,
            es_ad(ESI, REMOTE),
        ]))
        .await;
        assert_eq!(fdb.table().await.macs.len(), 3);
    }

    #[tokio::test]
    async fn macs_behind_a_segment_port_carry_its_esi_and_a_type4_is_originated() {
        let fdb = Fdb::new(
            "bd1".to_string(),
            Arc::new(Recorder::default()),
            Duration::ZERO,
        );
        let mut rx = fdb.subscribe();
        fdb.set_ready(Some(ready_with_segment())).await;
        fdb.refresh_local().await;
        let t = rx.borrow_and_update().clone();
        // Type-3, Type-2 for MAC 7, Type-4, and the two Type-1.
        assert_eq!(t.routes.len(), 5);
        let mac = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::Mac { .. }))
            .unwrap();
        assert_eq!(mac.esi, ESI);
        let imet = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::Imet { .. }))
            .unwrap();
        assert_eq!(imet.esi, [0; 10]);
        let es = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::EthernetSegment { .. }))
            .unwrap();
        assert_eq!(es.ext_communities, vec![es_import_rt(&ESI)]);
        // Per-ES A-D: MAX-ET, the RTs, encapsulation and an all-active ESI Label.
        let per_es = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::EthernetAd { tag, .. } if tag == AD_TAG_ES))
            .unwrap();
        assert_eq!(
            per_es.ext_communities,
            vec![RT, ENCAP_VXLAN, esi_label_ext(false)]
        );
        // Per-EVI A-D: tag 0, the VNI, the domain's RTs.
        let per_evi = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::EthernetAd { tag: 0, .. }))
            .unwrap();
        assert_eq!(per_evi.vni, 10100);
        assert_eq!(per_evi.ext_communities, vec![RT, ENCAP_VXLAN]);
        assert_eq!(
            fdb.table().await.macs[0].esi.as_deref(),
            Some("00:01:02:03:04:05:06:07:08:09")
        );
    }

    #[tokio::test]
    async fn the_non_df_stops_flooding_to_the_segment_and_gets_it_back() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_with_segment())).await;
        // Alone on the segment: the DF, flooding explicitly enabled.
        assert_eq!(calls(&driver), ["ensure 10100", "flood eth1 true"]);
        assert!(fdb.table().await.segments[0].designated_forwarder);

        // A PE with a lower address, attached to this EVI too (a per-EVI A-D
        // for our VNI): [192.0.1.9, 192.0.2.1], 10100 % 2 == 0, so it is the
        // DF and we are not.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        assert_eq!(calls(&driver), ["flood eth1 false"]);
        let t = fdb.table().await;
        assert!(!t.segments[0].designated_forwarder);
        assert_eq!(t.segments[0].pes.len(), 2);

        // The block is re-asserted on every resync, then lifted when the peer goes.
        fdb.set_ready(Some(ready_with_segment())).await;
        assert!(calls(&driver).contains(&"flood eth1 false".to_string()));
        fdb.apply_push(EvpnUpdate::Remove(es_route(ESI, "192.0.1.9").key))
            .await;
        assert_eq!(calls(&driver), ["flood eth1 true"]);

        // A Type-4 for another segment is none of our business.
        fdb.apply_push(EvpnUpdate::Add(es_route([7; 10], "192.0.1.9")))
            .await;
        assert!(calls(&driver).is_empty());

        // Unconfiguring while blocked restores flooding.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        calls(&driver);
        fdb.set_ready(None).await;
        assert_eq!(calls(&driver), ["remove 10100", "flood eth1 true"]);
    }

    #[tokio::test]
    async fn a_peer_with_no_per_evi_ad_is_not_a_df_candidate() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_with_segment())).await;
        calls(&driver);

        // A lower-addressed PE's bare Type-4, with no per-EVI A-D for our
        // VNI, does not make it a candidate (RFC 7432 §8.5 / RFC 8584 §2.1):
        // it is on the segment but never joined this EVI, so we stay DF.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        assert!(calls(&driver).is_empty());
        let t = fdb.table().await;
        assert!(t.segments[0].designated_forwarder);
        assert_eq!(t.segments[0].pes, vec![VTEP.parse::<IpAddr>().unwrap()]);

        // Its per-EVI A-D arriving makes it a real candidate: we lose the election.
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        assert_eq!(calls(&driver), ["flood eth1 false"]);
        assert!(!fdb.table().await.segments[0].designated_forwarder);
    }

    #[tokio::test]
    async fn a_new_segment_port_stays_blocked_until_the_df_wait_ends() {
        let driver = Arc::new(Recorder::default());
        let wait = Duration::from_millis(150);
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), wait);
        let (stop, shutdown) = watch::channel(false);
        let local = tokio::spawn(fdb.clone().run_local(shutdown));

        // Alone on the segment, so the DF — but not until the timer ends.
        fdb.set_ready(Some(ready_with_segment())).await;
        assert!(calls(&driver).ends_with(&["flood eth1 false".to_string()]));
        assert!(!fdb.table().await.segments[0].designated_forwarder);

        // `run_local` wakes at the deadline by itself (the tick is 10s).
        tokio::time::sleep(wait * 3).await;
        assert!(calls(&driver).contains(&"flood eth1 true".to_string()));
        assert!(fdb.table().await.segments[0].designated_forwarder);

        // A PE joining an already-elected port does not restart the wait.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, REMOTE))).await;
        assert!(calls(&driver).is_empty(), "still the DF, still flooding");
        assert!(fdb.table().await.segments[0].designated_forwarder);

        // Leaving the segment clears the timer: coming back waits again.
        fdb.set_ready(None).await;
        calls(&driver);
        fdb.set_ready(Some(ready_with_segment())).await;
        assert!(calls(&driver).ends_with(&["flood eth1 false".to_string()]));

        stop.send(true).unwrap();
        local.await.unwrap();
    }

    #[tokio::test]
    async fn a_segment_without_carrier_withdraws_its_routes_and_is_never_the_df() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        let mut rx = fdb.subscribe();
        fdb.set_ready(Some(ready_with_segment())).await;
        fdb.refresh_local().await;
        assert_eq!(rx.borrow_and_update().routes.len(), 5);
        assert!(fdb.table().await.segments[0].up);

        // The bond loses its last member: Type-4 and both Type-1 go.
        driver.1.lock().unwrap().insert("eth1".to_string());
        fdb.refresh_local().await;
        let routes = rx.borrow_and_update().routes.clone();
        assert_eq!(routes.len(), 2, "the Type-3 and the MAC: {routes:?}");
        assert!(!routes.keys().any(|k| matches!(
            k,
            EvpnKey::EthernetSegment { .. } | EvpnKey::EthernetAd { .. }
        )));
        let t = fdb.table().await;
        assert!(!t.segments[0].up);
        assert!(!t.segments[0].designated_forwarder);

        // Carrier back: everything is advertised again.
        driver.1.lock().unwrap().clear();
        fdb.refresh_local().await;
        assert_eq!(rx.borrow_and_update().routes.len(), 5);
        assert!(fdb.table().await.segments[0].up);
    }

    #[tokio::test]
    async fn a_single_active_non_df_is_blocked_outright_and_the_df_forwards() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_single_active())).await;
        // Alone: the DF. It floods, and forwarding is the kernel default, so
        // it is never asserted.
        assert_eq!(calls(&driver), ["ensure 10100", "flood eth1 true"]);
        assert!(fdb.table().await.segments[0].single_active);

        // A PE with a lower address, also attached to this EVI, is the DF:
        // the port is blocked, but it still floods (only forwarding decides).
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        assert_eq!(calls(&driver), ["fwd eth1 false"]);
        assert!(!fdb.table().await.segments[0].designated_forwarder);

        // The block is re-asserted on every resync, then lifted when it goes.
        fdb.set_ready(Some(ready_single_active())).await;
        assert!(calls(&driver).contains(&"fwd eth1 false".to_string()));
        fdb.apply_push(EvpnUpdate::Remove(es_route(ESI, "192.0.1.9").key))
            .await;
        assert_eq!(calls(&driver), ["fwd eth1 true"]);

        // Unconfiguring while blocked restores both.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        calls(&driver);
        fdb.set_ready(None).await;
        assert_eq!(
            calls(&driver),
            ["remove 10100", "flood eth1 true", "fwd eth1 true"]
        );
    }

    #[tokio::test]
    async fn switching_the_mode_swaps_the_mechanism_and_undoes_the_old_one() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_with_segment())).await;
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        calls(&driver);
        // All-active non-DF: BUM flooding off, forwarding untouched.
        fdb.set_ready(Some(ready_with_segment())).await;
        let c = calls(&driver);
        assert!(c.contains(&"flood eth1 false".to_string()), "{c:?}");
        assert!(!c.iter().any(|x| x.starts_with("fwd")), "{c:?}");

        fdb.set_ready(Some(ready_single_active())).await;
        let c = calls(&driver);
        assert!(c.contains(&"flood eth1 true".to_string()), "{c:?}");
        assert!(c.contains(&"fwd eth1 false".to_string()), "{c:?}");

        fdb.set_ready(Some(ready_with_segment())).await;
        let c = calls(&driver);
        assert!(c.contains(&"flood eth1 false".to_string()), "{c:?}");
        assert!(c.contains(&"fwd eth1 true".to_string()), "{c:?}");
    }

    #[test]
    fn the_per_es_ad_announces_the_redundancy_mode_in_its_esi_label() {
        let label = |r: &Ready| {
            local_routes(r, &BTreeMap::new(), &BTreeSet::new(), &BTreeSet::new())
                .values()
                .find(|x| matches!(x.key, EvpnKey::EthernetAd { tag, .. } if tag == AD_TAG_ES))
                .unwrap()
                .ext_communities
                .iter()
                .find_map(|c| parse_esi_label(*c))
        };
        assert_eq!(label(&ready_with_segment()), Some(false));
        assert_eq!(label(&ready_single_active()), Some(true));
    }

    #[test]
    fn a_single_active_segments_macs_fall_back_to_a_pe_with_a_per_evi_ad() {
        let backup = "192.0.2.77";
        let mut route = mac_route(1, 10100, RT, REMOTE);
        route.esi = [9; 10];
        let ads = |single_active: bool, evi: &[&str]| {
            Ads::from([(
                [9; 10],
                SegmentAds {
                    pes: BTreeSet::from([backup.parse().unwrap()]),
                    evi: evi.iter().map(|p| p.parse().unwrap()).collect(),
                    single_active,
                },
            )])
        };
        let mac = |vtep: &str| {
            vec![Installed::Mac {
                mac: [0, 0, 0, 0, 0, 1],
                vtep: vtep.parse().unwrap(),
            }]
        };
        // REMOTE's per-ES A-D is gone: the MAC moves to the backup PE...
        assert_eq!(
            desired(&ready(), &route, &ads(true, &[backup])),
            mac(backup)
        );
        // ... unless the segment is all-active (mass withdrawal), or the
        // backup never advertised the EVI.
        assert!(desired(&ready(), &route, &ads(false, &[backup])).is_empty());
        assert!(desired(&ready(), &route, &ads(true, &[])).is_empty());
        // While REMOTE's own per-ES A-D is held the MAC stays where it is.
        let mut held = ads(true, &[backup]);
        held.get_mut(&[9; 10])
            .unwrap()
            .pes
            .insert(REMOTE.parse().unwrap());
        assert_eq!(desired(&ready(), &route, &held), mac(REMOTE));
    }

    fn evi_ad(esi: Esi, origin: &str) -> EvpnRoute {
        ad_route(esi, 0, 10100, origin)
    }

    #[test]
    fn a_mac_is_aliased_only_over_pes_with_both_a_per_es_and_a_per_evi_ad() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let ads = |pes: &[&str], evi: &[&str], single_active: bool| SegmentAds {
            pes: pes.iter().map(|p| ip(p)).collect(),
            evi: evi.iter().map(|p| ip(p)).collect(),
            single_active,
        };
        let (a, b) = ("192.0.2.9", "192.0.2.20");
        // Both PEs serve the segment and the EVI: balanced over both, sorted.
        assert_eq!(
            alias_group(&ads(&[b, a], &[a, b], false), ip(a)),
            Some(vec![ip(a), ip(b)])
        );
        // One PE is no group; a PE without the EVI's A-D is left out.
        assert_eq!(alias_group(&ads(&[a], &[a], false), ip(a)), None);
        assert_eq!(alias_group(&ads(&[a, b], &[a], false), ip(a)), None);
        // The MAC's own PE has to be one of them.
        assert_eq!(
            alias_group(&ads(&[a, b], &[b, "192.0.2.30"], false), ip(a)),
            None
        );
        // Single-active has a backup path, not aliasing.
        assert_eq!(alias_group(&ads(&[a, b], &[a, b], true), ip(a)), None);
        // An FDB nexthop's gateway is IPv4.
        assert_eq!(
            alias_group(&ads(&[a, "2001:db8::1"], &[a, "2001:db8::1"], false), ip(a)),
            None
        );
    }

    #[tokio::test]
    async fn a_segments_macs_move_between_one_pe_and_a_group_as_the_a_d_routes_come_and_go() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        let (a, b, esi) = (REMOTE, "192.0.2.20", [9; 10]);
        let mut mac = mac_route(1, 10100, RT, a);
        mac.esi = esi;
        fdb.apply_push(EvpnUpdate::Add(mac)).await;
        calls(&driver);

        // One PE serving the segment: the plain entry.
        fdb.apply_push(EvpnUpdate::Add(es_ad(esi, a))).await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(esi, a))).await;
        assert_eq!(calls(&driver), ["set 00:00:00:00:00:01 192.0.2.9"]);

        // A second PE that serves the segment and the EVI: aliased.
        fdb.apply_push(EvpnUpdate::Add(es_ad(esi, b))).await;
        assert!(calls(&driver).is_empty(), "no per-EVI A-D from it yet");
        fdb.apply_push(EvpnUpdate::Add(evi_ad(esi, b))).await;
        assert_eq!(
            calls(&driver),
            [
                "del 00:00:00:00:00:01 192.0.2.9",
                "group 00:00:00:00:00:01 192.0.2.9,192.0.2.20"
            ]
        );
        let table = fdb.table().await;
        assert_eq!(table.macs.len(), 1);
        assert_eq!(table.macs[0].vteps.len(), 2);

        // It stops serving the EVI: back to the plain entry.
        fdb.apply_push(EvpnUpdate::Remove(evi_ad(esi, b).key)).await;
        assert_eq!(
            calls(&driver),
            [
                "group- 00:00:00:00:00:01",
                "set 00:00:00:00:00:01 192.0.2.9"
            ]
        );
        assert_eq!(fdb.table().await.macs[0].vteps.len(), 1);

        // Its own per-ES A-D going is still a mass withdrawal.
        fdb.apply_push(EvpnUpdate::Remove(es_ad(esi, a).key)).await;
        assert_eq!(calls(&driver), ["del 00:00:00:00:00:01 192.0.2.9"]);
        assert!(fdb.table().await.macs.is_empty());
    }

    #[test]
    fn two_routes_for_one_aliased_mac_want_one_and_the_same_group() {
        let (a, b) = (REMOTE, "192.0.2.20");
        let esi = [9; 10];
        let ads = Ads::from([(
            esi,
            SegmentAds {
                pes: [a, b].iter().map(|p| p.parse().unwrap()).collect(),
                evi: [a, b].iter().map(|p| p.parse().unwrap()).collect(),
                single_active: false,
            },
        )]);
        // The MAC advertised by each PE (each under its own RD): the same item,
        // so the second route neither reinstalls nor flaps the first.
        let mut from_a = mac_route(1, 10100, RT, a);
        from_a.esi = esi;
        let mut from_b = mac_route(1, 10100, RT, b);
        from_b.esi = esi;
        assert_eq!(
            desired(&ready(), &from_a, &ads),
            desired(&ready(), &from_b, &ads)
        );
        assert!(matches!(
            desired(&ready(), &from_a, &ads)[..],
            [Installed::MacGroup { .. }]
        ));
    }
}
