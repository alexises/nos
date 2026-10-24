//! EVPN IP-VRF (RFC 9136 Type-5, RFC 9135 §4.4.1 "interface-less"): this
//! table's L3 VNI config, which received Type-5 routes become `Evpn`
//! candidates (`desired`), and which of the table's own best routes are
//! originated (`originated`). Pure — the devices are `RibDriver::sync_l3vni`'s,
//! the IPC is `server.rs`'s (received) and `evpn_client.rs`'s (originated).

use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;
use std::net::IpAddr;

use nos_proto::evpn_id::{parse_router_mac, router_mac_ext, ENCAP_VXLAN};
use nos_proto::rib::EvpnIrb;
use nos_proto::{EvpnKey, EvpnRoute, IpNet};
use tracing::debug;

use crate::rib::{RibEntry, RouteSource};

pub type Mac = [u8; 6];

/// One table's resolved `RoutingTable.evpn`: parsed RD/RTs plus the VTEP
/// address and the device carrying it (the VXLAN device's underlay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L3Vni {
    pub vni: u32,
    pub rd: [u8; 8],
    pub import: Vec<u64>,
    pub export: Vec<u64>,
    pub bgp_instance: String,
    pub vtep: IpAddr,
    pub underlay: String,
}

/// The EVPN side of a table's `Rib`.
#[derive(Debug, Clone, Default)]
pub struct EvpnState {
    /// `None` when the table has no `evpn` (or its VTEP never resolved yet).
    pub local: Option<L3Vni>,
    /// Our Router's MAC: the L3 bridge's own address, once the driver built it.
    pub rmac: Option<Mac>,
    /// Every Type-5 route `nos-bgpd` pushed, unfiltered.
    pub received: HashMap<EvpnKey, EvpnRoute>,
    /// Remote VTEP -> its Router's MAC, for every installed `Evpn` route: the
    /// neighbour and FDB entry each one needs.
    pub remotes: BTreeMap<IpAddr, Mac>,
}

/// The `Evpn` candidates `received` gives `l3`, and the remote VTEPs they
/// use: every Type-5, and every RFC 9135 symmetric IRB MAC+IP (its Label2,
/// `l3_vni`, set) as a host route. A route is kept only if it carries one of
/// our import Route Targets, names our L3 VNI, carries a Router's MAC, isn't
/// our own VTEP's, and its prefix and next hop share our VTEP's family.
// ponytail: same-family only (an IPv6 prefix over an IPv4 underlay needs the
// RFC 5549-style `RTA_VIA` route), and one PE per prefix — the lowest VTEP —
// rather than ECMP over every PE advertising it (a multi-homed host's ESI is
// ignored here: no aliasing for host routes).
pub fn desired<S: BuildHasher>(
    received: &HashMap<EvpnKey, EvpnRoute, S>,
    l3: &L3Vni,
) -> (Vec<RibEntry>, BTreeMap<IpAddr, Mac>) {
    let mut best: BTreeMap<IpNet, (IpAddr, Mac)> = BTreeMap::new();
    for r in received.values() {
        let (prefix, vni, route_type) = match r.key {
            EvpnKey::IpPrefix { prefix, .. } => (prefix, Some(r.vni), 5),
            EvpnKey::MacIp { ip, .. } => (IpNet::from(ip), r.l3_vni, 2),
            _ => continue,
        };
        if !r.ext_communities.iter().any(|c| l3.import.contains(c))
            || vni != Some(l3.vni)
            || r.next_hop == l3.vtep
            || prefix.addr().is_ipv4() != l3.vtep.is_ipv4()
            || r.next_hop.is_ipv4() != l3.vtep.is_ipv4()
        {
            continue;
        }
        let Some(rmac) = r.ext_communities.iter().find_map(|c| parse_router_mac(*c)) else {
            debug!(%prefix, vtep = %r.next_hop, route_type, "evpn route without a router's mac skipped");
            continue;
        };
        let e = best.entry(prefix).or_insert((r.next_hop, rmac));
        if r.next_hop < e.0 {
            *e = (r.next_hop, rmac);
        }
    }
    let entries = best
        .iter()
        .map(|(prefix, (vtep, _))| RibEntry {
            prefix: *prefix,
            next_hops: vec![(*vtep, None)],
            source: RouteSource::Evpn,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            mpls_labels: Vec::new(),
        })
        .collect();
    (entries, best.into_values().collect())
}

impl EvpnState {
    /// What `nos-fdbd` needs to make a domain's MAC+IP routes symmetric
    /// (`RibRequest::GetEvpnIrb`): `None` until the IP-VRF is up.
    #[must_use]
    pub fn irb(&self) -> Option<EvpnIrb> {
        let l3 = self.local.as_ref()?;
        Some(EvpnIrb {
            l3_vni: l3.vni,
            router_mac: self.rmac?,
            route_targets_export: l3.export.clone(),
        })
    }
}

/// One Type-5 per best route of the table that isn't itself `Evpn`-sourced
/// (the loop guard), connected subnets included.
// ponytail: no RPL policy on origination; every best route goes.
pub fn originated<S: BuildHasher>(
    best: &HashMap<IpNet, RibEntry, S>,
    l3: &L3Vni,
    rmac: Mac,
) -> Vec<EvpnRoute> {
    let mut ext: Vec<u64> = l3.export.clone();
    ext.extend([ENCAP_VXLAN, router_mac_ext(rmac)]);
    best.values()
        .filter(|e| e.source != RouteSource::Evpn)
        .map(|e| EvpnRoute {
            key: EvpnKey::IpPrefix {
                rd: l3.rd,
                prefix: e.prefix,
            },
            vni: l3.vni,
            next_hop: l3.vtep,
            ext_communities: ext.clone(),
            esi: [0; 10],
            l3_vni: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RT: u64 = 0x0002_fde8_0000_1388; // 65000:5000

    fn l3() -> L3Vni {
        L3Vni {
            vni: 5000,
            rd: [0; 8],
            import: vec![RT],
            export: vec![RT],
            bgp_instance: "r1".into(),
            vtep: "10.50.0.2".parse().unwrap(),
            underlay: "eth0".into(),
        }
    }

    fn route(prefix: &str, vtep: &str, ext: Vec<u64>, vni: u32) -> (EvpnKey, EvpnRoute) {
        let key = EvpnKey::IpPrefix {
            rd: [0, 0, 0, 0, 0, 0, 0, u8::try_from(vtep.len()).unwrap()],
            prefix: prefix.parse().unwrap(),
        };
        let r = EvpnRoute {
            key: key.clone(),
            vni,
            next_hop: vtep.parse().unwrap(),
            ext_communities: ext,
            esi: [0; 10],
            l3_vni: None,
        };
        (key, r)
    }

    #[test]
    fn desired_filters_on_rt_vni_rmac_own_vtep_and_family() {
        let rmac = router_mac_ext([2, 0, 0, 0, 0, 3]);
        let received: HashMap<_, _> = [
            route("10.2.0.0/24", "10.50.0.3", vec![RT, rmac], 5000),
            // Another RT, another VNI, no Router's MAC, our own VTEP, v6.
            route("10.3.0.0/24", "10.50.0.3", vec![1, rmac], 5000),
            route("10.4.0.0/24", "10.50.0.3", vec![RT, rmac], 5001),
            route("10.5.0.0/24", "10.50.0.3", vec![RT], 5000),
            route("10.6.0.0/24", "10.50.0.2", vec![RT, rmac], 5000),
            route("2001:db8::/64", "10.50.0.3", vec![RT, rmac], 5000),
            // The same prefix from a second PE: the lower VTEP wins.
            route("10.2.0.0/24", "10.50.0.33", vec![RT, rmac], 5000),
        ]
        .into_iter()
        .collect();
        let (entries, remotes) = desired(&received, &l3());
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].prefix, "10.2.0.0/24".parse::<IpNet>().unwrap());
        assert_eq!(entries[0].source, RouteSource::Evpn);
        assert_eq!(
            entries[0].next_hops,
            vec![("10.50.0.3".parse().unwrap(), None)]
        );
        assert_eq!(
            remotes,
            BTreeMap::from([("10.50.0.3".parse().unwrap(), [2, 0, 0, 0, 0, 3])])
        );
    }

    /// RFC 9135 symmetric IRB: a MAC+IP with our L3 VNI as Label2 is a host
    /// route; the same filters apply.
    #[test]
    fn desired_installs_symmetric_mac_ip_as_host_routes() {
        let rmac = router_mac_ext([2, 0, 0, 0, 0, 3]);
        let mac_ip = |ip: &str, vtep: &str, ext: Vec<u64>, l3_vni: Option<u32>| {
            let key = EvpnKey::MacIp {
                rd: [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    u8::try_from(ip.len() + vtep.len()).unwrap(),
                ],
                mac: [2, 0, 0, 0, 0, 9],
                ip: ip.parse().unwrap(),
            };
            let r = EvpnRoute {
                key: key.clone(),
                vni: 10_300,
                next_hop: vtep.parse().unwrap(),
                ext_communities: ext,
                esi: [0; 10],
                l3_vni,
            };
            (key, r)
        };
        let received: HashMap<_, _> = [
            mac_ip("10.72.0.20", "10.50.0.3", vec![RT, rmac], Some(5000)),
            // Wrong L3 VNI, asymmetric, no IP-VRF RT, no rmac, our own VTEP.
            mac_ip("10.72.0.21", "10.50.0.3", vec![RT, rmac], Some(5001)),
            mac_ip("10.72.0.22", "10.50.0.3", vec![RT, rmac], None),
            mac_ip("10.72.0.23", "10.50.0.3", vec![1, rmac], Some(5000)),
            mac_ip("10.72.0.24", "10.50.0.3", vec![RT], Some(5000)),
            mac_ip("10.72.0.25", "10.50.0.2", vec![RT, rmac], Some(5000)),
            // A Type-5 /32 for the same host collapses with it.
            route("10.72.0.20/32", "10.50.0.4", vec![RT, rmac], 5000),
        ]
        .into_iter()
        .collect();
        let (entries, remotes) = desired(&received, &l3());
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].prefix, "10.72.0.20/32".parse::<IpNet>().unwrap());
        assert_eq!(
            entries[0].next_hops,
            vec![("10.50.0.3".parse().unwrap(), None)]
        );
        assert_eq!(remotes.len(), 1);
    }

    #[test]
    fn originated_skips_evpn_routes_and_carries_rt_encap_and_rmac() {
        let entry = |p: &str, source| RibEntry {
            prefix: p.parse().unwrap(),
            next_hops: vec![("10.1.0.1".parse().unwrap(), None)],
            source,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            mpls_labels: Vec::new(),
        };
        let best: HashMap<IpNet, RibEntry> = [
            entry("10.1.0.0/24", RouteSource::Connected),
            entry("10.2.0.0/24", RouteSource::Evpn),
        ]
        .into_iter()
        .map(|e| (e.prefix, e))
        .collect();
        let out = originated(&best, &l3(), [2, 0, 0, 0, 0, 2]);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].key,
            EvpnKey::IpPrefix {
                rd: [0; 8],
                prefix: "10.1.0.0/24".parse().unwrap()
            }
        );
        assert_eq!((out[0].vni, out[0].next_hop), (5000, l3().vtep));
        assert_eq!(
            out[0].ext_communities,
            vec![RT, ENCAP_VXLAN, router_mac_ext([2, 0, 0, 0, 0, 2])]
        );
    }
}
