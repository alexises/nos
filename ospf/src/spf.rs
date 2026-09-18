//! RFC 2328 §16.1/§16.2 SPF: pure Dijkstra over Router-LSA/Network-LSA
//! vertices, next-hop derivation entirely from already-installed LSAs (no
//! live neighbor-table dependency), plus stub-network leaf processing and a
//! directly-connected filter. No I/O — `crate::link::LinkManager::
//! compute_routes` is the only caller, feeding it one area's `Lsdb::all()`
//! snapshot at a time (this NOS is single-area/intra-area only, see
//! `ospf/CLAUDE.md`; a multi-area router just runs this once per area and
//! merges the results).
//!
//! # Next-hop derivation (the fiddly part of real OSPF SPF)
//! A point-to-point or transit-network Router-LSA link's `link_data` is
//! always the *originating* router's own address on that link (RFC 2328
//! §12.4.1.1) — never the neighbor's. So the only LSDB-only way to learn a
//! neighbor `w`'s address is to read *`w`'s own* Router-LSA for its link
//! back to us, not our own LSA. `derive_next_hop` applies this once per
//! vertex directly adjacent to the root (or adjacent to a network the root
//! itself sits on); every other vertex simply inherits its parent's
//! next-hop unchanged, since packets to the whole subtree beyond a vertex
//! flow through the same first-hop neighbor.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::Ipv4Net;

use crate::lsa::{
    Lsa, LsaBody, NetworkLsaBody, RouterLsaBody, LINK_TYPE_POINT_TO_POINT, LINK_TYPE_STUB_NETWORK,
    LINK_TYPE_TRANSIT_NETWORK,
};

/// One SPF vertex — a router (keyed by its router-id) or a transit network
/// (keyed by the Network-LSA's `link_state_id`, the DR's own address on
/// that network).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Vertex {
    Router(Ipv4Addr),
    Network(Ipv4Addr),
}

/// A vertex's derived next-hop. `Network` is a sentinel for a root-adjacent
/// transit network — it has no address of its own, so its own children
/// (routers on that network) must derive their next-hop fresh rather than
/// inherit this; every other vertex stores a concrete `Router` address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextHop {
    Network,
    Router(Ipv4Addr),
}

/// One computed destination, ready to push to `nos-ribd`.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteEntry {
    pub prefix: Ipv4Net,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapEntry {
    dist: u32,
    vertex: Vertex,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed: `BinaryHeap` is a max-heap, Dijkstra wants the smallest
        // distance popped first.
        other.dist.cmp(&self.dist)
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Runs RFC 2328 §16.1/§16.2 SPF from `root` over `lsas` (one area's
/// worth), returning every non-directly-connected destination reachable —
/// stub-network leaves and transit-network prefixes alike.
pub fn compute(root: Ipv4Addr, lsas: &[Arc<Lsa>]) -> Vec<RouteEntry> {
    let routers: HashMap<Ipv4Addr, &RouterLsaBody> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Router(r) => Some((l.header.advertising_router, r)),
            LsaBody::Network(_) => None,
        })
        .collect();
    let networks: HashMap<Ipv4Addr, &NetworkLsaBody> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Network(n) => Some((l.header.link_state_id, n)),
            LsaBody::Router(_) => None,
        })
        .collect();

    let (dist, next_hop) = run_dijkstra(root, &routers, &networks);
    let mut out: HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry> = HashMap::new();

    collect_network_routes(root, &routers, &networks, &dist, &next_hop, &mut out);
    collect_stub_routes(root, &routers, &dist, &next_hop, &mut out);

    out.into_values().collect()
}

/// The Dijkstra core: standard lazy-deletion priority-queue shortest path,
/// tracking each finalized vertex's distance and derived next-hop.
fn run_dijkstra(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
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
                let Some(nh) = derive_next_hop(vertex, next_vertex, root, routers, &next_hop)
                else {
                    // No reciprocal link back — stale/asymmetric LSDB
                    // mid-convergence. Treat as unreachable via this edge,
                    // never panic.
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

/// Every graph edge out of `vertex`. Type-3 (stub) Router-LSA links are
/// never edges — they're leaves, handled by `collect_stub_routes`.
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
                        Some((Vertex::Router(l.link_id), u32::from(l.metric)))
                    }
                    LINK_TYPE_TRANSIT_NETWORK => {
                        Some((Vertex::Network(l.link_id), u32::from(l.metric)))
                    }
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

/// Computes the next-hop to store for `child`, given it's being reached via
/// `parent`. `None` means no next-hop could be derived at all — the caller
/// treats `child` as unreachable via this edge.
fn derive_next_hop(
    parent: Vertex,
    child: Vertex,
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    next_hop: &HashMap<Vertex, NextHop>,
) -> Option<NextHop> {
    if parent == Vertex::Router(root) {
        return match child {
            Vertex::Router(w) => {
                own_link_data(routers, w, LINK_TYPE_POINT_TO_POINT, root).map(NextHop::Router)
            }
            Vertex::Network(_) => Some(NextHop::Network),
        };
    }
    match next_hop.get(&parent).copied()? {
        NextHop::Router(addr) => Some(NextHop::Router(addr)),
        NextHop::Network => match (parent, child) {
            (Vertex::Network(network_id), Vertex::Router(w)) => {
                own_link_data(routers, w, LINK_TYPE_TRANSIT_NETWORK, network_id)
                    .map(NextHop::Router)
            }
            // Only a `Network` vertex ever stores this sentinel — a
            // `Router` parent always resolves to `NextHop::Router`. Not a
            // real path.
            _ => None,
        },
    }
}

/// Looks up `router`'s own Router-LSA for a link of `link_type` pointing
/// back to `target` (root's router-id for a p2p link, or a network's
/// vertex id for a transit-network link), returning that link's
/// `link_data` — see the module doc for why this is `router`'s own address
/// as seen from `target`, derived purely from the LSDB.
fn own_link_data(
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    router: Ipv4Addr,
    link_type: u8,
    target: Ipv4Addr,
) -> Option<Ipv4Addr> {
    routers
        .get(&router)?
        .links
        .iter()
        .find_map(|l| (l.link_type == link_type && l.link_id == target).then_some(l.link_data))
}

/// Transit-network destinations (Network-LSA vertices reached by SPF),
/// skipping any network root itself is directly attached to — already a
/// real kernel connected route via the interface's own address, per the
/// module doc's directly-connected filter.
fn collect_network_routes(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, NextHop>,
    out: &mut HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry>,
) {
    for (&network_id, network) in networks {
        let vertex = Vertex::Network(network_id);
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        if root_attached_to_network(root, routers, network_id) {
            continue;
        }
        let Some(NextHop::Router(nh)) = next_hop.get(&vertex).copied() else {
            continue;
        };
        let key = (network_id, network.network_mask);
        insert_best(
            out,
            key,
            RouteEntry {
                prefix: net_from(network_id, network.network_mask),
                next_hop: nh,
                metric: d,
            },
        );
    }
}

/// Stub-network leaves (RFC 2328 §16.2): attached to every non-root router
/// with a finite Dijkstra distance. Filters by `(link_id, link_data)` key,
/// not by reachability — the far end of root's own point-to-point link
/// independently advertises the identical subnet (see `crate::link`'s
/// unconditional stub-network origination), which Dijkstra *will* reach;
/// only a key-based filter catches that mirrored duplicate.
fn collect_stub_routes(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, NextHop>,
    out: &mut HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry>,
) {
    for (&router_id, body) in routers {
        if router_id == root {
            continue;
        }
        let vertex = Vertex::Router(router_id);
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let Some(NextHop::Router(nh)) = next_hop.get(&vertex).copied() else {
            continue;
        };
        for link in &body.links {
            if link.link_type != LINK_TYPE_STUB_NETWORK {
                continue;
            }
            let key = (link.link_id, link.link_data);
            if root_advertises_stub(root, routers, key) {
                continue;
            }
            insert_best(
                out,
                key,
                RouteEntry {
                    prefix: net_from(link.link_id, link.link_data),
                    next_hop: nh,
                    metric: d.saturating_add(u32::from(link.metric)),
                },
            );
        }
    }
}

fn root_attached_to_network(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    network_id: Ipv4Addr,
) -> bool {
    routers.get(&root).is_some_and(|body| {
        body.links
            .iter()
            .any(|l| l.link_type == LINK_TYPE_TRANSIT_NETWORK && l.link_id == network_id)
    })
}

fn root_advertises_stub(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    key: (Ipv4Addr, Ipv4Addr),
) -> bool {
    routers.get(&root).is_some_and(|body| {
        body.links
            .iter()
            .any(|l| l.link_type == LINK_TYPE_STUB_NETWORK && (l.link_id, l.link_data) == key)
    })
}

/// Keeps the minimum-metric candidate per destination key — a stub network
/// (or, in principle, a transit network) reachable via more than one
/// router/path keeps only its shortest.
fn insert_best(
    out: &mut HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry>,
    key: (Ipv4Addr, Ipv4Addr),
    candidate: RouteEntry,
) {
    if out
        .get(&key)
        .is_none_or(|existing| candidate.metric < existing.metric)
    {
        out.insert(key, candidate);
    }
}

/// Builds the `Ipv4Net` for a `(network address, subnet mask)` pair, as
/// carried on the wire by a stub-network `RouterLink`/`NetworkLsaBody` —
/// both always encode a contiguous mask (never fabricated elsewhere in this
/// crate), so `count_ones` recovers the prefix length exactly.
fn net_from(addr: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Net {
    #[allow(clippy::cast_possible_truncation)]
    let prefix_len = u32::from(mask).count_ones() as u8;
    Ipv4Net::new(addr, prefix_len).unwrap_or_else(|_| Ipv4Net::new(addr, 32).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LsaHeader, RouterLink, LSA_TYPE_NETWORK, LSA_TYPE_ROUTER};

    fn router_id(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(1, 1, 1, n)
    }

    fn addr(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn p2p(neighbor: Ipv4Addr, own_addr: Ipv4Addr, metric: u16) -> RouterLink {
        RouterLink {
            link_id: neighbor,
            link_data: own_addr,
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric,
        }
    }

    fn transit(network_id: Ipv4Addr, own_addr: Ipv4Addr, metric: u16) -> RouterLink {
        RouterLink {
            link_id: network_id,
            link_data: own_addr,
            link_type: LINK_TYPE_TRANSIT_NETWORK,
            metric,
        }
    }

    fn stub(net: Ipv4Addr, mask: Ipv4Addr, metric: u16) -> RouterLink {
        RouterLink {
            link_id: net,
            link_data: mask,
            link_type: LINK_TYPE_STUB_NETWORK,
            metric,
        }
    }

    fn router_lsa(id: Ipv4Addr, links: Vec<RouterLink>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: id,
                advertising_router: id,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody { flags: 0, links }),
        })
    }

    fn network_lsa(id: Ipv4Addr, mask: Ipv4Addr, attached: Vec<Ipv4Addr>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_NETWORK,
                link_state_id: id,
                advertising_router: attached[0],
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsaBody {
                network_mask: mask,
                attached_routers: attached,
            }),
        })
    }

    #[test]
    fn direct_p2p_neighbor_stub_network_distance_and_next_hop() {
        let root = router_id(1);
        let w = router_id(2);
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 5)]);
        let w_lsa = router_lsa(
            w,
            vec![
                p2p(root, addr(10, 0, 0, 2), 5),
                stub(addr(192, 168, 1, 0), addr(255, 255, 255, 0), 10),
            ],
        );

        let routes = compute(root, &[root_lsa, w_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "192.168.1.0/24".parse().unwrap());
        assert_eq!(routes[0].next_hop, addr(10, 0, 0, 2));
        assert_eq!(routes[0].metric, 15);
    }

    #[test]
    fn two_hop_chain_inherits_first_hop_next_hop() {
        let root = router_id(1);
        let w = router_id(2);
        let x = router_id(3);
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]);
        let w_lsa = router_lsa(
            w,
            vec![
                p2p(root, addr(10, 0, 0, 2), 1),
                p2p(x, addr(10, 0, 1, 1), 1),
            ],
        );
        let x_lsa = router_lsa(
            x,
            vec![
                p2p(w, addr(10, 0, 1, 2), 1),
                stub(addr(192, 168, 2, 0), addr(255, 255, 255, 0), 1),
            ],
        );

        let routes = compute(root, &[root_lsa, w_lsa, x_lsa]);
        assert_eq!(routes.len(), 1);
        // Next-hop is W's own derived address (10.0.0.2), inherited
        // unchanged from the first hop — never X's link_data toward W
        // (10.0.1.2), which would be wrong.
        assert_eq!(routes[0].next_hop, addr(10, 0, 0, 2));
        assert_eq!(routes[0].metric, 3);
    }

    #[test]
    fn network_attached_router_next_hop_derived_from_its_own_type2_link() {
        let root = router_id(1);
        let w = router_id(2);
        let network_id = addr(10, 0, 0, 1); // root is DR, so this is root's own address too
        let root_lsa = router_lsa(root, vec![transit(network_id, addr(10, 0, 0, 1), 1)]);
        let w_lsa = router_lsa(
            w,
            vec![
                transit(network_id, addr(10, 0, 0, 2), 1),
                stub(addr(192, 168, 3, 0), addr(255, 255, 255, 0), 1),
            ],
        );
        let net_lsa = network_lsa(network_id, addr(255, 255, 255, 0), vec![root, w]);

        let routes = compute(root, &[root_lsa, w_lsa, net_lsa]);
        // Only the stub behind W, never a route for the shared network
        // itself (root is directly attached to it).
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "192.168.3.0/24".parse().unwrap());
        assert_eq!(routes[0].next_hop, addr(10, 0, 0, 2));
        assert_eq!(routes[0].metric, 2);
    }

    #[test]
    fn stub_leaf_duplicate_network_keeps_minimum_distance() {
        let root = router_id(1);
        let w1 = router_id(2);
        let w2 = router_id(3);
        let net = addr(192, 168, 4, 0);
        let mask = addr(255, 255, 255, 0);
        let root_lsa = router_lsa(
            root,
            vec![p2p(w1, addr(10, 0, 0, 1), 1), p2p(w2, addr(10, 0, 1, 1), 1)],
        );
        let w1_lsa = router_lsa(
            w1,
            vec![p2p(root, addr(10, 0, 0, 2), 1), stub(net, mask, 10)],
        );
        let w2_lsa = router_lsa(
            w2,
            vec![p2p(root, addr(10, 0, 1, 2), 1), stub(net, mask, 1)],
        );

        let routes = compute(root, &[root_lsa, w1_lsa, w2_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 2);
        assert_eq!(routes[0].next_hop, addr(10, 0, 1, 2));
    }

    #[test]
    fn directly_connected_p2p_subnet_is_filtered() {
        let root = router_id(1);
        let root_lsa = router_lsa(
            root,
            vec![stub(addr(10, 0, 0, 0), addr(255, 255, 255, 252), 1)],
        );
        assert!(compute(root, &[root_lsa]).is_empty());
    }

    #[test]
    fn directly_connected_transit_network_is_filtered() {
        let root = router_id(1);
        let network_id = addr(10, 0, 0, 1);
        let root_lsa = router_lsa(root, vec![transit(network_id, addr(10, 0, 0, 1), 1)]);
        let net_lsa = network_lsa(network_id, addr(255, 255, 255, 0), vec![root]);
        assert!(compute(root, &[root_lsa, net_lsa]).is_empty());
    }

    #[test]
    fn mirrored_p2p_subnet_via_neighbor_is_filtered() {
        let root = router_id(1);
        let w = router_id(2);
        let net = addr(10, 0, 0, 0);
        let mask = addr(255, 255, 255, 252);
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1), stub(net, mask, 1)]);
        let w_lsa = router_lsa(w, vec![p2p(root, addr(10, 0, 0, 2), 1), stub(net, mask, 1)]);

        // Without the key-based filter, Dijkstra would happily reach W and
        // produce a spurious second route to root's own subnet via W.
        assert!(compute(root, &[root_lsa, w_lsa]).is_empty());
    }

    #[test]
    fn no_reciprocal_link_back_is_treated_as_unreachable() {
        let root = router_id(1);
        let w = router_id(2);
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]);
        // W's own LSA has no link back to root — asymmetric/stale LSDB.
        let w_lsa = router_lsa(
            w,
            vec![stub(addr(192, 168, 5, 0), addr(255, 255, 255, 0), 1)],
        );

        // Must not panic, and W's stub must never appear — no next-hop
        // could be derived for it.
        assert!(compute(root, &[root_lsa, w_lsa]).is_empty());
    }

    #[test]
    fn dangling_link_id_with_no_matching_lsa_is_skipped() {
        let root = router_id(1);
        let w = router_id(2);
        // W's Router-LSA was never flooded/installed at all.
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]);
        assert!(compute(root, &[root_lsa]).is_empty());
    }
}
