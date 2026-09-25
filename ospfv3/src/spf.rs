//! RFC 5340 §4.8 SPF: pure Dijkstra over Router-LSA/Network-LSA vertices —
//! same graph algorithm/heap as `ospf::spf` (RFC 2328's §16.1/§16.2
//! counterpart), but next-hop derivation and destination-prefix collection
//! are both structurally different, since v3 restructures where addresses
//! and prefixes live on the wire. No I/O; `crate::link::LinkManager::
//! compute_routes` is the only caller, feeding it one area's `Lsdb::all()`
//! snapshot at a time.
//!
//! # Next-hop derivation (RFC 5340 §4.8.1 — the fiddly part)
//! v3's Router-LSA carries no addresses at all — only topology (Interface
//! ID / Neighbor Interface ID / Neighbor Router ID per link). A neighbor
//! `w`'s IPv6 next-hop address is instead learned from *`w`'s own* Link-LSA
//! for that specific link, keyed by `(w, w's own interface id on that
//! link)`. For a direct point-to-point edge, `w`'s interface id on the link
//! is handed to us directly as the root's own link entry's `Neighbor
//! Interface ID` field — no search needed. For a transit-network edge
//! (`Network(network_id) -> Router(w)`), there's no such shortcut: we must
//! search `w`'s *own* Router-LSA for the transit-network link entry
//! pointing back at this same network (matched by `neighbor_interface_id ==
//! network_id`) and read *that* entry's own `interface_id` field. Every
//! vertex beyond the first hop simply inherits its parent's next-hop
//! unchanged, exactly like v2.
//!
//! # Destination prefixes (structurally new, not a port)
//! v2 folds a stub prefix into the Router-LSA link list directly. v3 has
//! nowhere to put a prefix in a Router-LSA at all — destinations come
//! entirely from Intra-Area-Prefix-LSAs, each referencing either a router
//! (`LSA_TYPE_ROUTER`, that router's own stub/loopback prefixes) or a
//! transit network (`LSA_TYPE_NETWORK`, that network's own prefix). `root`'s
//! own referenced prefixes are always filtered out (directly connected,
//! already a real kernel route via interface addressing) — both when `root`
//! is the referenced router directly, and via a key-based mirrored-prefix
//! filter for a point-to-point link's shared prefix (both ends indepenently
//! advertise the identical prefix via their own router reference, mirroring
//! `ospf::spf`'s own `root_advertises_stub` filter).

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;

use crate::lsa::{
    self, IntraAreaPrefixLsaBody, Lsa, LsaBody, NetworkLsaBody, RouterLsaBody,
    LINK_TYPE_POINT_TO_POINT, LINK_TYPE_TRANSIT_NETWORK, LSA_TYPE_E_NETWORK, LSA_TYPE_E_ROUTER,
    LSA_TYPE_NETWORK, LSA_TYPE_ROUTER,
};

/// One SPF vertex — a router (keyed by its router-id) or a transit network
/// (keyed by its Network-LSA's `link_state_id`, the DR's own interface id
/// on that link — see `link.rs`'s origination convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Vertex {
    Router(Ipv4Addr),
    Network(Ipv4Addr),
}

/// A vertex's derived next-hop. `Network` is a sentinel for a root-adjacent
/// transit network, mirroring `ospf::spf::NextHop`'s shape — but unlike v2,
/// both variants also carry root's own local interface id for that first
/// hop (`u32`, always root's own kernel ifindex — see `LinkConfig.
/// interface_id`'s doc comment in `reconcile.rs`): a link-local IPv6
/// next-hop is only meaningful relative to the specific local link it was
/// learned on, and Linux's netlink route install needs that outgoing
/// interface explicitly (see `RouteEntry::interface_id`'s doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextHop {
    Network(u32),
    Router(Ipv6Addr, u32),
}

/// One computed destination, ready to push to `nos-ribd`.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteEntry {
    pub prefix: Ipv6Net,
    pub next_hop: Ipv6Addr,
    /// Root's own local kernel interface (ifindex) `next_hop` is reachable
    /// over — required by Linux's netlink `RTM_NEWROUTE` for a link-local
    /// IPv6 gateway (`EINVAL` without it, since the kernel can't otherwise
    /// resolve which link a link-local address belongs to). Mirrors
    /// `nos_proto::OspfRoute::interface_id`, which this is pushed into
    /// verbatim by `rib_push_client`.
    pub interface_id: u32,
    pub metric: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapEntry {
    dist: u32,
    vertex: Vertex,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.dist.cmp(&self.dist)
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Every installed Link-LSA's own link-local address, keyed by
/// `(advertising_router, link_state_id)` — `link_state_id` here is that
/// link's own Interface ID, encoded via `lsa::interface_id_key`.
type LinkLocalAddresses = HashMap<(Ipv4Addr, Ipv4Addr), Ipv6Addr>;

/// Builds the lookup maps every pass needs: routers/networks by id (as
/// `ospf::spf`'s own `routers_and_networks` does), plus every installed
/// Link-LSA's own link-local address.
fn routers_networks_links(
    lsas: &[std::sync::Arc<Lsa>],
) -> (
    HashMap<Ipv4Addr, &RouterLsaBody>,
    HashMap<Ipv4Addr, &NetworkLsaBody>,
    LinkLocalAddresses,
) {
    let mut routers = HashMap::new();
    let mut networks = HashMap::new();
    let mut links = HashMap::new();
    for l in lsas {
        match &l.body {
            LsaBody::Router(r) => {
                routers.insert(l.header.advertising_router, r);
            }
            LsaBody::Network(n) => {
                networks.insert(l.header.link_state_id, n);
            }
            LsaBody::Link(link) => {
                links.insert(
                    (l.header.advertising_router, l.header.link_state_id),
                    link.link_local_address,
                );
            }
            LsaBody::IntraAreaPrefix(_) => {}
        }
    }
    (routers, networks, links)
}

/// Runs RFC 5340 §4.8 SPF from `root` over `lsas` (one area's worth),
/// returning every non-directly-connected destination reachable via
/// Intra-Area-Prefix-LSAs.
pub fn compute(root: Ipv4Addr, lsas: &[std::sync::Arc<Lsa>]) -> Vec<RouteEntry> {
    let (routers, networks, links) = routers_networks_links(lsas);
    let prefix_lsas: Vec<&IntraAreaPrefixLsaBody> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::IntraAreaPrefix(p) => Some(p),
            LsaBody::Router(_) | LsaBody::Network(_) | LsaBody::Link(_) => None,
        })
        .collect();

    let (dist, next_hop) = run_dijkstra(root, &routers, &networks, &links);
    let mut out: HashMap<(Ipv6Addr, u8), RouteEntry> = HashMap::new();
    collect_prefix_routes(root, &routers, &prefix_lsas, &dist, &next_hop, &mut out);
    out.into_values().collect()
}

fn run_dijkstra(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    links: &LinkLocalAddresses,
) -> (HashMap<Vertex, u32>, HashMap<Vertex, NextHop>) {
    let root_vertex = Vertex::Router(root);
    let mut dist: HashMap<Vertex, u32> = HashMap::new();
    let mut next_hop: HashMap<Vertex, NextHop> = HashMap::new();
    let mut visited: HashSet<Vertex> = HashSet::new();
    let mut heap = BinaryHeap::new();

    dist.insert(root_vertex, 0);
    heap.push(HeapEntry {
        dist: 0,
        vertex: root_vertex,
    });

    while let Some(HeapEntry { dist: d, vertex }) = heap.pop() {
        if !visited.insert(vertex) {
            continue;
        }
        if d > *dist.get(&vertex).unwrap_or(&u32::MAX) {
            continue;
        }

        for (next_vertex, edge_cost) in neighbors(vertex, routers, networks) {
            if visited.contains(&next_vertex) {
                continue;
            }
            let candidate = d.saturating_add(edge_cost);
            if candidate < *dist.get(&next_vertex).unwrap_or(&u32::MAX) {
                let Some(nh) =
                    derive_next_hop(vertex, next_vertex, root, routers, links, &next_hop)
                else {
                    continue;
                };
                dist.insert(next_vertex, candidate);
                next_hop.insert(next_vertex, nh);
                heap.push(HeapEntry {
                    dist: candidate,
                    vertex: next_vertex,
                });
            }
        }
    }

    (dist, next_hop)
}

/// Every graph edge out of `vertex`. A transit-network `RouterLsaLink`'s own
/// `neighbor_interface_id` is the network's vertex key directly — see the
/// module doc comment.
fn neighbors(
    vertex: Vertex,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
) -> Vec<(Vertex, u32)> {
    match vertex {
        Vertex::Router(id) => {
            let Some(body) = routers.get(&id) else {
                return Vec::new();
            };
            body.links
                .iter()
                .filter_map(|l| match l.link_type {
                    LINK_TYPE_POINT_TO_POINT => {
                        Some((Vertex::Router(l.neighbor_router_id), u32::from(l.metric)))
                    }
                    LINK_TYPE_TRANSIT_NETWORK => Some((
                        Vertex::Network(lsa::interface_id_key(l.neighbor_interface_id)),
                        u32::from(l.metric),
                    )),
                    _ => None,
                })
                .collect()
        }
        Vertex::Network(id) => {
            let Some(net) = networks.get(&id) else {
                return Vec::new();
            };
            net.attached_routers
                .iter()
                .map(|&r| (Vertex::Router(r), 0))
                .collect()
        }
    }
}

fn derive_next_hop(
    parent: Vertex,
    child: Vertex,
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    links: &LinkLocalAddresses,
    next_hop: &HashMap<Vertex, NextHop>,
) -> Option<NextHop> {
    if parent == Vertex::Router(root) {
        return match child {
            Vertex::Router(w) => p2p_next_hop(routers, links, root, w)
                .map(|(addr, interface_id)| NextHop::Router(addr, interface_id)),
            Vertex::Network(network_id) => {
                root_network_interface_id(root, routers, network_id).map(NextHop::Network)
            }
        };
    }
    match next_hop.get(&parent).copied()? {
        NextHop::Router(addr, interface_id) => Some(NextHop::Router(addr, interface_id)),
        NextHop::Network(interface_id) => match (parent, child) {
            (Vertex::Network(network_id), Vertex::Router(w)) => {
                network_next_hop(routers, links, network_id, w)
                    .map(|addr| NextHop::Router(addr, interface_id))
            }
            _ => None,
        },
    }
}

/// Direct point-to-point edge: `parent_router`'s own link entry to
/// `child_router` carries the child's interface id on that link directly
/// (`neighbor_interface_id`) — no search of the child's own LSA needed.
/// Also returns `parent_router`'s own `interface_id` on that same link
/// entry — meaningful only when `parent_router == root` (see
/// `RouteEntry::interface_id`'s doc comment), but harmless to return
/// unconditionally since every non-first-hop call site only reads the
/// address half.
fn p2p_next_hop(
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    links: &LinkLocalAddresses,
    parent_router: Ipv4Addr,
    child_router: Ipv4Addr,
) -> Option<(Ipv6Addr, u32)> {
    let l = routers.get(&parent_router)?.links.iter().find(|l| {
        l.link_type == LINK_TYPE_POINT_TO_POINT && l.neighbor_router_id == child_router
    })?;
    let addr = links
        .get(&(child_router, lsa::interface_id_key(l.neighbor_interface_id)))
        .copied()?;
    Some((addr, l.interface_id))
}

/// Root's own local interface id for its transit-network link to
/// `network_id`, if root is attached to it at all — mirrors
/// `root_attached_to_network`'s own lookup, which now delegates here.
fn root_network_interface_id(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    network_id: Ipv4Addr,
) -> Option<u32> {
    let network_key = lsa::key_to_interface_id(network_id);
    routers.get(&root)?.links.iter().find_map(|l| {
        (l.link_type == LINK_TYPE_TRANSIT_NETWORK && l.neighbor_interface_id == network_key)
            .then_some(l.interface_id)
    })
}

/// Transit-network edge: unlike the point-to-point case, `network_id` alone
/// doesn't give us `child_router`'s own interface id on the link — we have
/// to search `child_router`'s *own* Router-LSA for its transit-network
/// entry pointing back at this network (matched by `neighbor_interface_id
/// == network_id`) and read that entry's own `interface_id`.
fn network_next_hop(
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    links: &LinkLocalAddresses,
    network_id: Ipv4Addr,
    child_router: Ipv4Addr,
) -> Option<Ipv6Addr> {
    let network_key = lsa::key_to_interface_id(network_id);
    let own_interface_id = routers.get(&child_router)?.links.iter().find_map(|l| {
        (l.link_type == LINK_TYPE_TRANSIT_NETWORK && l.neighbor_interface_id == network_key)
            .then_some(l.interface_id)
    })?;
    links
        .get(&(child_router, lsa::interface_id_key(own_interface_id)))
        .copied()
}

fn root_attached_to_network(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    network_id: Ipv4Addr,
) -> bool {
    root_network_interface_id(root, routers, network_id).is_some()
}

/// RFC 5340 §4.8: every Intra-Area-Prefix-LSA's prefixes, attached either to
/// a router or a transit network. `root`'s own referenced prefixes are
/// filtered twice over: directly (the referenced vertex is `root` itself)
/// and by key (a point-to-point link's shared prefix, independently
/// advertised by both ends via their own router reference — the mirrored
/// case `ospf::spf::root_advertises_stub` also guards).
fn collect_prefix_routes(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    prefix_lsas: &[&IntraAreaPrefixLsaBody],
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, NextHop>,
    out: &mut HashMap<(Ipv6Addr, u8), RouteEntry>,
) {
    let root_prefixes: HashSet<(Ipv6Addr, u8)> = prefix_lsas
        .iter()
        .filter(|p| {
            matches!(p.referenced_ls_type, LSA_TYPE_ROUTER | LSA_TYPE_E_ROUTER)
                && p.referenced_advertising_router == root
        })
        .flat_map(|p| p.prefixes.iter())
        .map(|entry| prefix_key(entry.prefix))
        .collect();

    for body in prefix_lsas {
        let vertex = match body.referenced_ls_type {
            LSA_TYPE_ROUTER | LSA_TYPE_E_ROUTER => {
                Vertex::Router(body.referenced_advertising_router)
            }
            LSA_TYPE_NETWORK | LSA_TYPE_E_NETWORK => Vertex::Network(body.referenced_link_state_id),
            _ => continue,
        };
        if vertex == Vertex::Router(root) {
            continue;
        }
        if let Vertex::Network(network_id) = vertex {
            if root_attached_to_network(root, routers, network_id) {
                continue;
            }
        }
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let Some(NextHop::Router(nh, interface_id)) = next_hop.get(&vertex).copied() else {
            continue;
        };
        for entry in &body.prefixes {
            let key = prefix_key(entry.prefix);
            if root_prefixes.contains(&key) {
                continue;
            }
            insert_best(
                out,
                key,
                RouteEntry {
                    prefix: entry.prefix.trunc(),
                    next_hop: nh,
                    interface_id,
                    metric: d.saturating_add(u32::from(entry.metric)),
                },
            );
        }
    }
}

fn prefix_key(prefix: Ipv6Net) -> (Ipv6Addr, u8) {
    let t = prefix.trunc();
    (t.addr(), t.prefix_len())
}

fn insert_best(
    out: &mut HashMap<(Ipv6Addr, u8), RouteEntry>,
    key: (Ipv6Addr, u8),
    candidate: RouteEntry,
) {
    if out
        .get(&key)
        .is_none_or(|existing| candidate.metric < existing.metric)
    {
        out.insert(key, candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{
        IntraAreaPrefixEntry, LinkLsaBody, Lsa, LsaBody, LsaHeader, RouterLsaLink, LSA_TYPE_LINK,
    };
    use std::sync::Arc;

    fn router_id(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(1, 1, 1, n)
    }

    fn header(lsa_type: u16, link_state_id: Ipv4Addr, advertising_router: Ipv4Addr) -> LsaHeader {
        LsaHeader {
            age: 0,
            lsa_type,
            link_state_id,
            advertising_router,
            sequence_number: 1,
            checksum: 0,
            length: 0,
        }
    }

    fn router_lsa(id: Ipv4Addr, links: Vec<RouterLsaLink>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(LSA_TYPE_ROUTER, id, id),
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
                links,
            }),
        })
    }

    fn p2p(neighbor: Ipv4Addr, own_if: u32, neighbor_if: u32, metric: u16) -> RouterLsaLink {
        RouterLsaLink {
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric,
            interface_id: own_if,
            neighbor_interface_id: neighbor_if,
            neighbor_router_id: neighbor,
        }
    }

    fn transit(network_if: u32, own_if: u32, dr: Ipv4Addr, metric: u16) -> RouterLsaLink {
        RouterLsaLink {
            link_type: LINK_TYPE_TRANSIT_NETWORK,
            metric,
            interface_id: own_if,
            neighbor_interface_id: network_if,
            neighbor_router_id: dr,
        }
    }

    fn link_lsa(router: Ipv4Addr, if_id: u32, addr: Ipv6Addr) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(LSA_TYPE_LINK, lsa::interface_id_key(if_id), router),
            body: LsaBody::Link(LinkLsaBody {
                priority: 1,
                options: 0,
                link_local_address: addr,
                prefixes: Vec::new(),
            }),
        })
    }

    fn network_lsa(if_id: u32, dr: Ipv4Addr, attached: Vec<Ipv4Addr>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(LSA_TYPE_NETWORK, lsa::interface_id_key(if_id), dr),
            body: LsaBody::Network(NetworkLsaBody {
                options: 0,
                attached_routers: attached,
            }),
        })
    }

    fn router_prefix_lsa(router: Ipv4Addr, prefixes: Vec<(Ipv6Net, u16)>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(
                lsa::LSA_TYPE_INTRA_AREA_PREFIX,
                Ipv4Addr::UNSPECIFIED,
                router,
            ),
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type: LSA_TYPE_ROUTER,
                referenced_link_state_id: router,
                referenced_advertising_router: router,
                prefixes: prefixes
                    .into_iter()
                    .map(|(prefix, metric)| IntraAreaPrefixEntry {
                        options: 0,
                        metric,
                        prefix,
                    })
                    .collect(),
            }),
        })
    }

    fn network_prefix_lsa(
        router: Ipv4Addr,
        network_if: u32,
        dr: Ipv4Addr,
        prefixes: Vec<(Ipv6Net, u16)>,
    ) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(
                lsa::LSA_TYPE_INTRA_AREA_PREFIX,
                lsa::interface_id_key(network_if),
                router,
            ),
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type: LSA_TYPE_NETWORK,
                referenced_link_state_id: lsa::interface_id_key(network_if),
                referenced_advertising_router: dr,
                prefixes: prefixes
                    .into_iter()
                    .map(|(prefix, metric)| IntraAreaPrefixEntry {
                        options: 0,
                        metric,
                        prefix,
                    })
                    .collect(),
            }),
        })
    }

    #[test]
    fn direct_p2p_neighbor_prefix_distance_and_next_hop() {
        let root = router_id(1);
        let w = router_id(2);
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        let stub: Ipv6Net = "2001:db8:1::/64".parse().unwrap();

        let root_lsa = router_lsa(root, vec![p2p(w, 1, 2, 5)]);
        let w_lsa = router_lsa(w, vec![p2p(root, 2, 1, 5)]);
        let w_link = link_lsa(w, 2, w_link_local);
        let w_prefix = router_prefix_lsa(w, vec![(stub, 10)]);

        let routes = compute(root, &[root_lsa, w_lsa, w_link, w_prefix]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, stub);
        assert_eq!(routes[0].next_hop, w_link_local);
        // Root's own interface id on the p2p link to w — `p2p(w, 1, 2, 5)`'s
        // own_if=1 — required as `RTA_OIF` to install this link-local
        // next-hop (see `RouteEntry::interface_id`'s doc comment).
        assert_eq!(routes[0].interface_id, 1);
        assert_eq!(routes[0].metric, 15);
    }

    #[test]
    fn extended_lsas_give_the_same_routes_as_legacy_ones() {
        let root = router_id(1);
        let w = router_id(2);
        let stub: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
        let as_extended = |l: Arc<Lsa>| {
            let mut l = (*l).clone();
            l.header.lsa_type = match l.header.lsa_type {
                LSA_TYPE_ROUTER => lsa::LSA_TYPE_E_ROUTER,
                LSA_TYPE_LINK => lsa::LSA_TYPE_E_LINK,
                _ => lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
            };
            if let LsaBody::IntraAreaPrefix(p) = &mut l.body {
                p.referenced_ls_type = lsa::LSA_TYPE_E_ROUTER;
            }
            Arc::new(l)
        };
        let legacy = [
            router_lsa(root, vec![p2p(w, 1, 2, 5)]),
            router_lsa(w, vec![p2p(root, 2, 1, 5)]),
            link_lsa(w, 2, "fe80::2".parse().unwrap()),
            router_prefix_lsa(w, vec![(stub, 10)]),
        ];
        let extended: Vec<_> = legacy.iter().cloned().map(as_extended).collect();

        let routes = compute(root, &extended);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, stub);
        assert_eq!(routes[0].metric, 15);
        assert_eq!(routes[0].next_hop, compute(root, &legacy)[0].next_hop);
    }

    #[test]
    fn two_hop_chain_inherits_first_hop_next_hop() {
        let root = router_id(1);
        let w = router_id(2);
        let x = router_id(3);
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        let stub: Ipv6Net = "2001:db8:2::/64".parse().unwrap();

        let root_lsa = router_lsa(root, vec![p2p(w, 1, 2, 1)]);
        let w_lsa = router_lsa(w, vec![p2p(root, 2, 1, 1), p2p(x, 3, 4, 1)]);
        let x_lsa = router_lsa(x, vec![p2p(w, 4, 3, 1)]);
        let w_link = link_lsa(w, 2, w_link_local);
        let x_link = link_lsa(x, 4, "fe80::4".parse().unwrap());
        let x_prefix = router_prefix_lsa(x, vec![(stub, 1)]);

        let routes = compute(root, &[root_lsa, w_lsa, x_lsa, w_link, x_link, x_prefix]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hop, w_link_local);
        // Inherited unchanged from the first hop (root's own p2p link to w,
        // `p2p(w, 1, 2, 1)`'s own_if=1) — never x's own interface id.
        assert_eq!(routes[0].interface_id, 1);
        assert_eq!(routes[0].metric, 3);
    }

    #[test]
    fn network_attached_router_next_hop_derived_from_its_own_transit_link() {
        let root = router_id(1);
        let w = router_id(2);
        let network_if_on_root = 10u32;
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        let stub: Ipv6Net = "2001:db8:3::/64".parse().unwrap();

        // root is DR: network vertex key = root's own interface id (10).
        let root_lsa = router_lsa(
            root,
            vec![transit(network_if_on_root, network_if_on_root, root, 1)],
        );
        let w_lsa = router_lsa(w, vec![transit(network_if_on_root, 20, root, 1)]);
        let net_lsa = network_lsa(network_if_on_root, root, vec![root, w]);
        let w_link = link_lsa(w, 20, w_link_local);
        let w_prefix = router_prefix_lsa(w, vec![(stub, 1)]);

        let routes = compute(root, &[root_lsa, w_lsa, net_lsa, w_link, w_prefix]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, stub);
        assert_eq!(routes[0].next_hop, w_link_local);
        // Root's own interface id on its transit-network link — the
        // network sentinel's stored id, inherited unchanged into the
        // resolved router next-hop.
        assert_eq!(routes[0].interface_id, network_if_on_root);
        assert_eq!(routes[0].metric, 2);
    }

    #[test]
    fn directly_connected_transit_network_prefix_is_filtered() {
        let root = router_id(1);
        let w = router_id(2);
        let network_if = 10u32;
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        let transit_prefix: Ipv6Net = "2001:db8:4::/64".parse().unwrap();

        // root is Backup, w is DR (network vertex key = w's own interface id).
        let root_lsa = router_lsa(root, vec![transit(network_if, 30, w, 1)]);
        let w_lsa = router_lsa(w, vec![transit(network_if, network_if, w, 1)]);
        let net_lsa = network_lsa(network_if, w, vec![root, w]);
        let w_link = link_lsa(w, network_if, w_link_local);
        // A second router "on the network" that isn't root, so the network
        // is reachable but not root-attached... actually root IS attached
        // here (transit link above), so instead prove the transit prefix
        // itself is filtered as directly-connected — see next test. This
        // test proves a *different* router's prefix reachable via the
        // network's own derived next-hop still works when root is not DR.
        let net_prefix = network_prefix_lsa(w, network_if, w, vec![(transit_prefix, 0)]);

        let routes = compute(root, &[root_lsa, w_lsa, net_lsa, w_link, net_prefix]);
        // root is directly attached to this network, so its own transit
        // prefix is filtered (directly connected) — zero routes expected.
        assert!(routes.is_empty());
    }

    #[test]
    fn directly_connected_router_prefix_is_filtered() {
        let root = router_id(1);
        let stub: Ipv6Net = "2001:db8:5::/64".parse().unwrap();
        let root_lsa = router_lsa(root, vec![]);
        let root_prefix = router_prefix_lsa(root, vec![(stub, 1)]);
        assert!(compute(root, &[root_lsa, root_prefix]).is_empty());
    }

    #[test]
    fn mirrored_p2p_prefix_via_neighbor_is_filtered() {
        let root = router_id(1);
        let w = router_id(2);
        let shared: Ipv6Net = "2001:db8:6::/64".parse().unwrap();

        let root_lsa = router_lsa(root, vec![p2p(w, 1, 2, 1)]);
        let w_lsa = router_lsa(w, vec![p2p(root, 2, 1, 1)]);
        let w_link = link_lsa(w, 2, "fe80::2".parse().unwrap());
        let root_prefix = router_prefix_lsa(root, vec![(shared, 1)]);
        let w_prefix = router_prefix_lsa(w, vec![(shared, 1)]);

        let routes = compute(root, &[root_lsa, w_lsa, w_link, root_prefix, w_prefix]);
        assert!(routes.is_empty());
    }

    #[test]
    fn no_link_lsa_for_neighbor_is_treated_as_unreachable() {
        let root = router_id(1);
        let w = router_id(2);
        let stub: Ipv6Net = "2001:db8:7::/64".parse().unwrap();
        let root_lsa = router_lsa(root, vec![p2p(w, 1, 2, 1)]);
        let w_lsa = router_lsa(w, vec![p2p(root, 2, 1, 1)]);
        // No Link-LSA installed for w at all — next-hop can't be derived.
        let w_prefix = router_prefix_lsa(w, vec![(stub, 1)]);
        assert!(compute(root, &[root_lsa, w_lsa, w_prefix]).is_empty());
    }

    #[test]
    fn duplicate_prefix_via_two_routers_keeps_minimum_distance() {
        let root = router_id(1);
        let w1 = router_id(2);
        let w2 = router_id(3);
        let net: Ipv6Net = "2001:db8:8::/64".parse().unwrap();

        let root_lsa = router_lsa(root, vec![p2p(w1, 1, 2, 1), p2p(w2, 3, 4, 1)]);
        let w1_lsa = router_lsa(w1, vec![p2p(root, 2, 1, 1)]);
        let w2_lsa = router_lsa(w2, vec![p2p(root, 4, 3, 1)]);
        let w1_link = link_lsa(w1, 2, "fe80::2".parse().unwrap());
        let w2_link = link_lsa(w2, 4, "fe80::4".parse().unwrap());
        let w1_prefix = router_prefix_lsa(w1, vec![(net, 10)]);
        let w2_prefix = router_prefix_lsa(w2, vec![(net, 1)]);

        let routes = compute(
            root,
            &[
                root_lsa, w1_lsa, w2_lsa, w1_link, w2_link, w1_prefix, w2_prefix,
            ],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 2);
        assert_eq!(routes[0].next_hop, "fe80::4".parse::<Ipv6Addr>().unwrap());
    }
}
