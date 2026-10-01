//! RFC 2328 §16.1/§16.2 SPF: pure Dijkstra over Router-LSA/Network-LSA
//! vertices, next-hop derivation entirely from already-installed LSAs (no
//! live neighbor-table dependency), plus stub-network leaf processing and a
//! directly-connected filter, extended with a real, 2-area-scoped ABR
//! mechanism (Type-3/Type-4 Summary-LSA collector passes — see
//! `ospf/CLAUDE.md`'s "ABR and Summary-LSA origination"). No I/O —
//! `crate::link::LinkManager::compute_routes` is the only caller of
//! `compute`, feeding it one area's `Lsdb::all()` snapshot at a time and
//! merging each area's own result (`RouteEntry`-per-prefix, cheaper wins on
//! a prefix computed by more than one area — see that function's own doc
//! comment). `intra_area_routes` is `crate::link::originate_summary_lsas`'s
//! own per-area input for deciding what to summarize into a router's *other*
//! areas.
//!
//! # Next-hop derivation (the fiddly part of real OSPF SPF)
//! A point-to-point or transit-network Router-LSA link's `link_data` is
//! always the *originating* router's own address on that link (RFC 2328
//! §12.4.1.1) — never the neighbor's. So the only LSDB-only way to learn a
//! neighbor `w`'s address is to read *`w`'s own* Router-LSA for its link
//! back to us, not our own LSA. `derive_next_hops` applies this once per
//! vertex directly adjacent to the root (or adjacent to a network the root
//! itself sits on); every other vertex simply inherits its parent's
//! next-hop set unchanged, since packets to the whole subtree beyond a
//! vertex flow through the same first-hop neighbors.
//!
//! # Equal-cost multipath (RFC 2328 §16.1 step 2(d))
//! A vertex reached at the same distance through more than one parent keeps
//! the union of every parent's next hops, and a destination collected at
//! the same metric from more than one vertex keeps the union too
//! (`merge_equal`). `RouteEntry.next_hops` is that set, sorted and deduped.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::Ipv4Net;

use crate::lsa::{
    AsExternalLsaBody, Lsa, LsaBody, NetworkLsaBody, RouterLsaBody, SummaryLsaBody,
    LINK_TYPE_POINT_TO_POINT, LINK_TYPE_STUB_NETWORK, LINK_TYPE_TRANSIT_NETWORK,
    LSA_TYPE_ASBR_SUMMARY, LSA_TYPE_AS_EXTERNAL, LSA_TYPE_NETWORK_SUMMARY, MAX_AGE,
};

/// `ponytail:` RFC 2328 §16.4's E1/E2 external-metric-type distinction is not
/// implemented — every AS-external route is treated as Type-1 (the ASBR's
/// own intra-area SPF distance plus this fixed constant, summed like a stub
/// route), always. There is no per-route metric-type selection and no
/// Type-1-beats-Type-2 tie-break, since this NOS never produces a Type-2
/// route in the first place (see `AsExternalLsaBody`'s own doc comment).
/// Upgrade path: thread an `e_type` through `RouteEntry` and compare per RFC
/// 2328 §16.4.1 if a second redistribution source with meaningfully
/// different cost semantics is ever added.
pub const EXTERNAL_METRIC_CONSTANT: u32 = 20;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NextHop {
    Network,
    Router(Ipv4Addr),
}

/// One computed destination, ready to push to `nos-ribd`.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteEntry {
    pub prefix: Ipv4Net,
    /// Every equal-cost first hop, sorted by address, deduped, never empty.
    pub next_hops: Vec<Ipv4Addr>,
    pub metric: u32,
    /// RFC 5286 loop-free alternate next hop (a first hop outside
    /// `next_hops` that provably won't loop the packet back through us), if
    /// one exists. Filled in by `compute` after every collector has run.
    pub backup_next_hop: Option<Ipv4Addr>,
    /// The vertex this destination hangs off (the router/network whose
    /// distance the metric was built from) — what the loop-free test is
    /// evaluated against, since the leaf metric cancels out of it.
    egress: Vertex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapEntry {
    dist: u32,
    vertex: Vertex,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed: `BinaryHeap` is a max-heap, Dijkstra wants the smallest
        // distance popped first. At equal distance a transit network pops
        // before a router (RFC 2328 §16.1 step 3): its edges to routers cost
        // 0, so a router it ties with must not be finalized before the
        // network adds its own next hops to it.
        other
            .dist
            .cmp(&self.dist)
            .then_with(|| is_network(self.vertex).cmp(&is_network(other.vertex)))
    }
}

fn is_network(v: Vertex) -> bool {
    matches!(v, Vertex::Network(_))
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// RFC 2328 §16.1 step 2: an LSA at `MaxAge` (being flushed, see `lsdb.rs`'s
/// hold) takes no part in the routing computation.
fn live_lsas(lsas: &[Arc<Lsa>]) -> Vec<Arc<Lsa>> {
    lsas.iter()
        .filter(|l| l.header.age < MAX_AGE)
        .cloned()
        .collect()
}

/// Builds the `routers`/`networks` lookup maps `run_dijkstra` and every
/// collector pass need — shared by `compute` and `intra_area_routes` so
/// neither duplicates the filter.
fn routers_and_networks(
    lsas: &[Arc<Lsa>],
) -> (
    HashMap<Ipv4Addr, &RouterLsaBody>,
    HashMap<Ipv4Addr, &NetworkLsaBody>,
) {
    let routers = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Router(r) => Some((l.header.advertising_router, r)),
            LsaBody::Network(_)
            | LsaBody::Summary(_)
            | LsaBody::AsExternal(_)
            | LsaBody::Grace(_) => None,
        })
        .collect();
    let networks = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Network(n) => Some((l.header.link_state_id, n)),
            LsaBody::Router(_)
            | LsaBody::Summary(_)
            | LsaBody::AsExternal(_)
            | LsaBody::Grace(_) => None,
        })
        .collect();
    (routers, networks)
}

/// Runs RFC 2328 §16.1/§16.2 SPF from `root` over `lsas` (one area's
/// worth), returning every non-directly-connected destination reachable —
/// stub-network leaves, transit-network prefixes, RFC 2328 §16.3 inter-area
/// routes (Type-3 Summary-LSA) and §16.4 AS-external routes alike.
pub fn compute(root: Ipv4Addr, lsas: &[Arc<Lsa>]) -> Vec<RouteEntry> {
    let live = live_lsas(lsas);
    let lsas = &live[..];
    let (routers, networks) = routers_and_networks(lsas);
    // Plain `Vec`s, not `HashMap`s keyed by advertising_router — one ASBR/ABR
    // can originate more than one Type-5/Type-3/Type-4 for different
    // prefixes/ASBRs.
    let externals: Vec<(Ipv4Addr, Ipv4Addr, &AsExternalLsaBody)> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::AsExternal(e) => {
                Some((l.header.advertising_router, l.header.link_state_id, e))
            }
            LsaBody::Router(_) | LsaBody::Network(_) | LsaBody::Summary(_) | LsaBody::Grace(_) => {
                None
            }
        })
        .collect();
    let network_summaries: Vec<(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Summary(s) if l.header.lsa_type == LSA_TYPE_NETWORK_SUMMARY => {
                Some((l.header.advertising_router, l.header.link_state_id, s))
            }
            _ => None,
        })
        .collect();
    let asbr_summaries: Vec<(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Summary(s) if l.header.lsa_type == LSA_TYPE_ASBR_SUMMARY => {
                Some((l.header.advertising_router, l.header.link_state_id, s))
            }
            _ => None,
        })
        .collect();

    let (dist, next_hop) = run_dijkstra(root, &routers, &networks);
    let mut out: HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry> = HashMap::new();

    collect_network_routes(root, &routers, &networks, &dist, &next_hop, &mut out);
    collect_stub_routes(root, &routers, &dist, &next_hop, &mut out);
    collect_summary_routes(root, &network_summaries, &dist, &next_hop, &mut out);
    collect_external_routes(
        root,
        &externals,
        &asbr_summaries,
        &dist,
        &next_hop,
        &mut out,
    );

    let alternates = alternates(root, &routers, &networks);
    for route in out.values_mut() {
        route.backup_next_hop = pick_backup(route, &alternates, &dist);
    }

    out.into_values().collect()
}

/// One candidate first hop for a loop-free alternate: a router adjacent to
/// root (over a p2p link, or sharing a transit network), reached at `addr`,
/// with the shortest-path distances *from that router* to every vertex.
struct Alternate {
    /// The neighbor's own address on the shared link — the next hop.
    addr: Ipv4Addr,
    /// Root's cost of the link to it.
    link_cost: u32,
    /// Its shortest distance back to root.
    to_root: u32,
    dist_from: HashMap<Vertex, u32>,
}

/// RFC 5286 basic loop-free alternates: every root-adjacent router other
/// than root itself, each with its own Dijkstra (over the same LSDB), so
/// `pick_backup` can evaluate the loop-free inequality per destination.
///
/// `ponytail:` one full Dijkstra per neighbor per area on every SPF run —
/// fine for the handful of neighbors this NOS has; an incremental/reverse-SPF
/// would be the upgrade if a router ever had hundreds. Link protection only
/// (RFC 5286 §3.1's inequality), no node-protecting or downstream-path
/// criteria, no remote LFA.
fn alternates(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
) -> Vec<Alternate> {
    let Some(root_lsa) = routers.get(&root) else {
        return Vec::new();
    };
    // (neighbor router-id, its address toward us, our cost to it)
    let mut candidates: Vec<(Ipv4Addr, Ipv4Addr, u32)> = Vec::new();
    for l in &root_lsa.links {
        match l.link_type {
            LINK_TYPE_POINT_TO_POINT => {
                if let Some(addr) =
                    own_link_data(routers, l.link_id, LINK_TYPE_POINT_TO_POINT, root)
                {
                    candidates.push((l.link_id, addr, u32::from(l.metric)));
                }
            }
            LINK_TYPE_TRANSIT_NETWORK => {
                let Some(net) = networks.get(&l.link_id) else {
                    continue;
                };
                for &r in net.attached_routers.iter().filter(|&&r| r != root) {
                    if let Some(addr) =
                        own_link_data(routers, r, LINK_TYPE_TRANSIT_NETWORK, l.link_id)
                    {
                        candidates.push((r, addr, u32::from(l.metric)));
                    }
                }
            }
            _ => {}
        }
    }
    candidates
        .into_iter()
        .filter_map(|(id, addr, link_cost)| {
            let dist_from = run_dijkstra(id, routers, networks).0;
            let to_root = *dist_from.get(&Vertex::Router(root))?;
            Some(Alternate {
                addr,
                link_cost,
                to_root,
                dist_from,
            })
        })
        .collect()
}

/// The best alternate for `route`: among candidates whose address is none of
/// the primary next hops and that satisfy RFC 5286 §3.1's loop-free
/// inequality `dist(N, E) < dist(N, root) + dist(root, E)` for the route's
/// egress vertex `E`, the one with the lowest total cost (ties: lowest
/// address, for determinism).
fn pick_backup(
    route: &RouteEntry,
    alternates: &[Alternate],
    dist: &HashMap<Vertex, u32>,
) -> Option<Ipv4Addr> {
    let root_to_egress = *dist.get(&route.egress)?;
    alternates
        .iter()
        .filter(|a| !route.next_hops.contains(&a.addr))
        .filter_map(|a| {
            let n_to_egress = *a.dist_from.get(&route.egress)?;
            (n_to_egress < a.to_root.saturating_add(root_to_egress))
                .then_some((a.link_cost.saturating_add(n_to_egress), a.addr))
        })
        .min()
        .map(|(_, addr)| addr)
}

/// One area's intra-area-only view — the subset of RFC 2328 §16.1 SPF fit
/// for re-summarization into another area (`crate::link::
/// originate_summary_lsas`). Deliberately skips the external/summary
/// collector passes: RFC 2328 forbids re-summarizing an already inter-area
/// or already-external route — the mechanism that prevents trivial two-area
/// routing loops. Only a genuinely intra-area prefix or a genuinely-in-this-
/// area ASBR ever qualifies.
///
/// `ponytail:` root's own directly-attached *transit network* (as opposed to
/// a stub network — see `collect_intra_area_stub_routes`) is not summarized
/// — a router won't advertise reachability to a broadcast segment it's
/// itself sitting on into its other areas. Real RFC 2328 ABRs do; this NOS's
/// concrete ABR scenarios (a loopback stub, a redistributed prefix) never
/// need it. Upgrade path: a root-attached-network variant mirroring
/// `collect_intra_area_stub_routes`'s own root-inclusion, keyed off the
/// root's own transit-network `RouterLink`s rather than `next_hop`, which
/// (unlike a stub) is never populated for a vertex root itself sits on.
pub struct IntraAreaRoutes {
    pub routes: Vec<RouteEntry>,
    /// Every router-id in this area that both originated at least one
    /// Type-5 AS-external-LSA and is actually reachable via this area's own
    /// Dijkstra (a real, in-this-area ASBR) — `(router_id, intra_area_distance)`.
    pub asbrs: Vec<(Ipv4Addr, u32)>,
}

pub fn intra_area_routes(root: Ipv4Addr, lsas: &[Arc<Lsa>]) -> IntraAreaRoutes {
    let live = live_lsas(lsas);
    let lsas = &live[..];
    let (routers, networks) = routers_and_networks(lsas);
    let (dist, next_hop) = run_dijkstra(root, &routers, &networks);

    let mut out: HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry> = HashMap::new();
    collect_network_routes(root, &routers, &networks, &dist, &next_hop, &mut out);
    collect_intra_area_stub_routes(root, &routers, &dist, &next_hop, &mut out);

    let asbr_ids: HashSet<Ipv4Addr> = lsas
        .iter()
        .filter(|l| l.header.lsa_type == LSA_TYPE_AS_EXTERNAL)
        .map(|l| l.header.advertising_router)
        .filter(|&id| id != root)
        .collect();
    let asbrs = asbr_ids
        .into_iter()
        .filter_map(|id| dist.get(&Vertex::Router(id)).map(|&d| (id, d)))
        .collect();

    IntraAreaRoutes {
        routes: out.into_values().collect(),
        asbrs,
    }
}

/// The Dijkstra core: standard lazy-deletion priority-queue shortest path,
/// tracking each finalized vertex's distance and derived next-hop set. An
/// equal-distance relaxation unions the new parent's hops in (RFC 2328
/// §16.1 step 2(d)); it can only hit a not-yet-popped vertex, since every
/// parent at a lower distance pops first and a zero-cost network parent is
/// ordered ahead of its routers (`HeapEntry::cmp`).
fn run_dijkstra(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
) -> (HashMap<Vertex, u32>, HashMap<Vertex, Vec<NextHop>>) {
    let root_vertex = Vertex::Router(root);
    let mut dist: HashMap<Vertex, u32> = HashMap::new();
    let mut next_hop: HashMap<Vertex, Vec<NextHop>> = HashMap::new();
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
            let current = *dist.get(&next_vertex).unwrap_or(&u32::MAX);
            if candidate > current {
                continue;
            }
            let hops = derive_next_hops(vertex, next_vertex, root, routers, &next_hop);
            if hops.is_empty() {
                // No reciprocal link back — stale/asymmetric LSDB
                // mid-convergence. Treat as unreachable via this edge,
                // never panic.
                continue;
            }
            if candidate < current {
                dist.insert(next_vertex, candidate);
                next_hop.insert(next_vertex, hops);
                heap.push(HeapEntry {
                    dist: candidate,
                    vertex: next_vertex,
                });
            } else {
                let set = next_hop.entry(next_vertex).or_default();
                set.extend(hops);
                set.sort_unstable();
                set.dedup();
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

/// Computes the next-hop set to contribute to `child`, given it's being
/// reached via `parent`: each of the parent's hops is inherited, except the
/// `Network` sentinel, resolved per child. Empty means no next-hop could be
/// derived at all — the caller treats `child` as unreachable via this edge.
fn derive_next_hops(
    parent: Vertex,
    child: Vertex,
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
) -> Vec<NextHop> {
    if parent == Vertex::Router(root) {
        return match child {
            Vertex::Router(w) => own_link_data(routers, w, LINK_TYPE_POINT_TO_POINT, root)
                .map(NextHop::Router)
                .into_iter()
                .collect(),
            Vertex::Network(_) => vec![NextHop::Network],
        };
    }
    let mut hops: Vec<NextHop> = next_hop
        .get(&parent)
        .into_iter()
        .flatten()
        .filter_map(|&nh| match nh {
            NextHop::Router(addr) => Some(NextHop::Router(addr)),
            NextHop::Network => match (parent, child) {
                (Vertex::Network(network_id), Vertex::Router(w)) => {
                    own_link_data(routers, w, LINK_TYPE_TRANSIT_NETWORK, network_id)
                        .map(NextHop::Router)
                }
                // Only a `Network` vertex ever stores this sentinel — a
                // `Router` parent always resolves to `NextHop::Router`. Not
                // a real path.
                _ => None,
            },
        })
        .collect();
    hops.sort_unstable();
    hops.dedup();
    hops
}

/// The concrete router addresses in a vertex's next-hop set (sorted, since
/// the set is) — empty if it has none, e.g. only the `Network` sentinel.
fn router_hops(next_hop: &HashMap<Vertex, Vec<NextHop>>, vertex: Vertex) -> Vec<Ipv4Addr> {
    next_hop
        .get(&vertex)
        .into_iter()
        .flatten()
        .filter_map(|&nh| match nh {
            NextHop::Router(addr) => Some(addr),
            NextHop::Network => None,
        })
        .collect()
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
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
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
        let next_hops = router_hops(next_hop, vertex);
        if next_hops.is_empty() {
            continue;
        }
        let key = (network_id, network.network_mask);
        insert_best(
            out,
            key,
            RouteEntry {
                prefix: net_from(network_id, network.network_mask),
                next_hops,
                metric: d,
                backup_next_hop: None,
                egress: vertex,
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
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
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
        let next_hops = router_hops(next_hop, vertex);
        if next_hops.is_empty() {
            continue;
        }
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
                    next_hops: next_hops.clone(),
                    metric: d.saturating_add(u32::from(link.metric)),
                    backup_next_hop: None,
                    egress: vertex,
                },
            );
        }
    }
}

/// `intra_area_routes`'s own stub-network collector — unlike
/// `collect_stub_routes` (used by `compute` for this router's own final
/// route set, where a directly-connected destination is deliberately
/// excluded since it's already a real kernel connected route), this
/// **includes** root's own directly-attached stub networks: what's "already
/// directly connected" from this area's own perspective is exactly what a
/// real ABR must summarize into its *other* areas (e.g. this router's own
/// loopback stub in area A becomes a Type-3 into area B). `next_hop` is
/// irrelevant to a caller that only reads `.metric`/`.prefix` (see
/// `LinkManager::originate_summary_lsas`), so root's own stubs use `root`
/// itself as a placeholder next-hop. No mirrored-duplicate key filter is
/// needed (unlike `collect_stub_routes`'s `root_advertises_stub` guard): a
/// p2p subnet's own copy (distance 0 + local cost) and a neighbor's mirrored
/// copy (link cost + neighbor's advertised cost) share the same
/// `(link_id, link_data)` key, so `insert_best` already keeps the cheaper —
/// always root's own — automatically.
fn collect_intra_area_stub_routes(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry>,
) {
    for (&router_id, body) in routers {
        let vertex = Vertex::Router(router_id);
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let next_hops = if router_id == root {
            vec![root]
        } else {
            router_hops(next_hop, vertex)
        };
        if next_hops.is_empty() {
            continue;
        }
        for link in &body.links {
            if link.link_type != LINK_TYPE_STUB_NETWORK {
                continue;
            }
            let key = (link.link_id, link.link_data);
            insert_best(
                out,
                key,
                RouteEntry {
                    prefix: net_from(link.link_id, link.link_data),
                    next_hops: next_hops.clone(),
                    metric: d.saturating_add(u32::from(link.metric)),
                    backup_next_hop: None,
                    egress: vertex,
                },
            );
        }
    }
}

/// RFC 2328 §16.3 inter-area routes from Type-3 Summary-LSAs. Mirrors
/// `collect_external_routes` exactly: the summary's advertising router (the
/// ABR that originated it, see `crate::link::originate_summary_lsas`) must
/// already have a computed intra-area distance/next-hop in this area; the
/// summary's own `metric` is simply added. `advertising_router == root` is
/// guarded the same way `collect_external_routes` guards `asbr == root` —
/// this router's own self-installed Type-3 must never produce a spurious
/// route to its own summarized prefix via itself.
fn collect_summary_routes(
    root: Ipv4Addr,
    summaries: &[(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)],
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry>,
) {
    for &(abr, link_state_id, s) in summaries {
        if abr == root {
            continue;
        }
        let vertex = Vertex::Router(abr);
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let next_hops = router_hops(next_hop, vertex);
        if next_hops.is_empty() {
            continue;
        }
        let key = (link_state_id, s.network_mask);
        insert_best(
            out,
            key,
            RouteEntry {
                prefix: net_from(link_state_id, s.network_mask),
                next_hops,
                metric: d.saturating_add(s.metric),
                backup_next_hop: None,
                egress: vertex,
            },
        );
    }
}

/// Distance+next-hop to `asbr`. Prefers a direct intra-area Router-LSA
/// vertex; if `asbr` has none (it's genuinely outside this area), falls back
/// to an installed Type-4 ASBR-summary LSA for it in this area — cost is
/// that summary's advertising ABR's own intra-area distance plus the
/// summary's metric, next-hop is the ABR's own next-hop (packets to a
/// foreign ASBR go via the ABR proxying reachability to it). Multiple
/// Type-4s for the same `asbr` (from different ABRs) take the cheapest;
/// equal-cost ones union their ABRs' next hops (egress: the first of them).
fn asbr_distance(
    asbr: Ipv4Addr,
    asbr_summaries: &[(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)],
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
) -> Option<(u32, Vec<Ipv4Addr>, Vertex)> {
    let direct = Vertex::Router(asbr);
    if let Some(&d) = dist.get(&direct) {
        let hops = router_hops(next_hop, direct);
        if !hops.is_empty() {
            return Some((d, hops, direct));
        }
    }
    let proxies: Vec<(u32, Vec<Ipv4Addr>, Vertex)> = asbr_summaries
        .iter()
        .filter(|&&(_, target, _)| target == asbr)
        .filter_map(|&(abr, _, s)| {
            let vertex = Vertex::Router(abr);
            let &d = dist.get(&vertex)?;
            let hops = router_hops(next_hop, vertex);
            (!hops.is_empty()).then_some((d.saturating_add(s.metric), hops, vertex))
        })
        .collect();
    let best = proxies.iter().map(|&(d, _, _)| d).min()?;
    let mut ties = proxies.into_iter().filter(|&(d, _, _)| d == best);
    let (_, mut hops, egress) = ties.next()?;
    for (_, more, _) in ties {
        hops.extend(more);
    }
    hops.sort_unstable();
    hops.dedup();
    Some((best, hops, egress))
}

/// RFC 2328 §16.4 AS-external routes, restricted to this NOS's Type-1-only
/// simplification (see `EXTERNAL_METRIC_CONSTANT`'s doc comment) and
/// forwarding-address-`0.0.0.0`-only simplification (see
/// `AsExternalLsaBody`'s doc comment): every external route's next-hop is
/// always the advertising ASBR's own next-hop, and its cost is always the
/// ASBR's distance (direct intra-area, or via a Type-4 proxy — see
/// `asbr_distance`) plus the fixed external metric.
///
/// **Explicit `asbr == root` guard**: this router's own Type-5 LSA, once
/// installed into its own area's LSDB (see `crate::link::
/// originate_as_external_lsas`), would otherwise compute a spurious route to
/// its own redistributed prefix via itself at `0 + EXTERNAL_METRIC_CONSTANT`
/// — `dist` is seeded with `root -> 0`, so this is a real, not hypothetical,
/// case skipped here the same way `collect_stub_routes` skips `router_id ==
/// root`.
fn collect_external_routes(
    root: Ipv4Addr,
    externals: &[(Ipv4Addr, Ipv4Addr, &AsExternalLsaBody)],
    asbr_summaries: &[(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)],
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry>,
) {
    for &(asbr, link_state_id, ext) in externals {
        if asbr == root {
            continue;
        }
        let Some((d, next_hops, egress)) = asbr_distance(asbr, asbr_summaries, dist, next_hop)
        else {
            continue;
        };
        // Same `(Ipv4Addr, Ipv4Addr)` key shape `collect_stub_routes` uses,
        // so a stub route and an external route to the same prefix collide
        // correctly and `insert_best` keeps whichever is cheaper.
        let key = (link_state_id, ext.network_mask);
        insert_best(
            out,
            key,
            RouteEntry {
                prefix: net_from(link_state_id, ext.network_mask),
                next_hops,
                metric: d.saturating_add(ext.metric),
                backup_next_hop: None,
                egress,
            },
        );
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
/// router/path keeps only its shortest, and equal-metric candidates merge
/// their next hops (`merge_equal`).
fn insert_best(
    out: &mut HashMap<(Ipv4Addr, Ipv4Addr), RouteEntry>,
    key: (Ipv4Addr, Ipv4Addr),
    candidate: RouteEntry,
) {
    match out.get_mut(&key) {
        None => {
            out.insert(key, candidate);
        }
        Some(existing) if candidate.metric < existing.metric => *existing = candidate,
        Some(existing) if candidate.metric == existing.metric => merge_equal(existing, candidate),
        Some(_) => {}
    }
}

/// Folds an equal-metric `other` route to the same prefix into `existing`:
/// unions `next_hops` (sorted, deduped) and keeps `existing`'s `egress` — the
/// LFA test only needs *a* shortest-path egress, and both are at the same
/// distance. A backup that became a primary hop is dropped. Shared by
/// `insert_best` and `LinkManager::compute_routes`' cross-area merge.
pub(crate) fn merge_equal(existing: &mut RouteEntry, other: RouteEntry) {
    existing.next_hops.extend(other.next_hops);
    existing.next_hops.sort_unstable();
    existing.next_hops.dedup();
    if existing
        .backup_next_hop
        .is_some_and(|b| existing.next_hops.contains(&b))
    {
        existing.backup_next_hop = None;
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
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
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
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
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
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
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
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 1, 2)]);
    }

    #[test]
    fn directly_connected_p2p_subnet_is_filtered() {
        let root = router_id(1);
        let root_lsa = router_lsa(
            root,
            vec![stub(addr(10, 0, 0, 0), addr(255, 255, 255, 252), 1)],
        );
        assert_eq!(compute(root, &[root_lsa]), []);
    }

    #[test]
    fn directly_connected_transit_network_is_filtered() {
        let root = router_id(1);
        let network_id = addr(10, 0, 0, 1);
        let root_lsa = router_lsa(root, vec![transit(network_id, addr(10, 0, 0, 1), 1)]);
        let net_lsa = network_lsa(network_id, addr(255, 255, 255, 0), vec![root]);
        assert_eq!(compute(root, &[root_lsa, net_lsa]), []);
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
        assert_eq!(compute(root, &[root_lsa, w_lsa]), []);
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
        assert_eq!(compute(root, &[root_lsa, w_lsa]), []);
    }

    #[test]
    fn dangling_link_id_with_no_matching_lsa_is_skipped() {
        let root = router_id(1);
        let w = router_id(2);
        // W's Router-LSA was never flooded/installed at all.
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]);
        assert_eq!(compute(root, &[root_lsa]), []);
    }

    fn as_external_lsa(prefix: Ipv4Addr, mask: Ipv4Addr, advertising_router: Ipv4Addr) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: crate::lsa::LSA_TYPE_AS_EXTERNAL,
                link_state_id: prefix,
                advertising_router,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsaBody {
                network_mask: mask,
                metric: EXTERNAL_METRIC_CONSTANT,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
            }),
        })
    }

    #[test]
    fn reachable_asbr_external_route_uses_asbr_distance_plus_constant() {
        let root = router_id(1);
        let asbr = router_id(2);
        let root_lsa = router_lsa(root, vec![p2p(asbr, addr(10, 0, 0, 1), 5)]);
        let asbr_lsa = router_lsa(asbr, vec![p2p(root, addr(10, 0, 0, 2), 5)]);
        let ext_lsa = as_external_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), asbr);

        let routes = compute(root, &[root_lsa, asbr_lsa, ext_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "192.0.2.0/24".parse().unwrap());
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 5 + EXTERNAL_METRIC_CONSTANT);
    }

    #[test]
    fn unreachable_asbr_external_route_is_skipped() {
        let root = router_id(1);
        let asbr = router_id(2);
        // ASBR's own Router-LSA was never flooded/installed at all.
        let root_lsa = router_lsa(root, vec![]);
        let ext_lsa = as_external_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), asbr);
        assert_eq!(compute(root, &[root_lsa, ext_lsa]), []);
    }

    #[test]
    fn external_route_tie_break_against_stub_route_keeps_cheaper() {
        let root = router_id(1);
        let stub_router = router_id(2);
        let asbr = router_id(3);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        // Via the stub-advertising router: cost 1 + 100 = 101.
        let root_lsa = router_lsa(
            root,
            vec![
                p2p(stub_router, addr(10, 0, 0, 1), 1),
                p2p(asbr, addr(10, 0, 1, 1), 1),
            ],
        );
        let stub_router_lsa = router_lsa(
            stub_router,
            vec![p2p(root, addr(10, 0, 0, 2), 1), stub(net, mask, 100)],
        );
        // Via the ASBR: cost 1 + EXTERNAL_METRIC_CONSTANT (20) = 21, cheaper.
        let asbr_lsa = router_lsa(asbr, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let ext_lsa = as_external_lsa(net, mask, asbr);

        let routes = compute(root, &[root_lsa, stub_router_lsa, asbr_lsa, ext_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 1, 2)]);
        assert_eq!(routes[0].metric, 1 + EXTERNAL_METRIC_CONSTANT);
    }

    #[test]
    fn own_as_external_lsa_is_never_treated_as_a_route_to_self() {
        let root = router_id(1);
        let root_lsa = router_lsa(root, vec![]);
        let ext_lsa = as_external_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), root);
        assert_eq!(compute(root, &[root_lsa, ext_lsa]), []);
    }

    fn network_summary_lsa(
        prefix: Ipv4Addr,
        mask: Ipv4Addr,
        advertising_router: Ipv4Addr,
        metric: u32,
    ) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_NETWORK_SUMMARY,
                link_state_id: prefix,
                advertising_router,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsaBody {
                network_mask: mask,
                metric,
            }),
        })
    }

    fn asbr_summary_lsa(target_asbr: Ipv4Addr, advertising_abr: Ipv4Addr, metric: u32) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_ASBR_SUMMARY,
                link_state_id: target_asbr,
                advertising_router: advertising_abr,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsaBody {
                network_mask: Ipv4Addr::UNSPECIFIED,
                metric,
            }),
        })
    }

    #[test]
    fn intra_area_routes_excludes_external_and_summary_derived_routes() {
        let root = router_id(1);
        let asbr = router_id(2);
        let border = router_id(3);
        let net = addr(192, 168, 6, 0);
        let mask = addr(255, 255, 255, 0);

        let root_lsa = router_lsa(
            root,
            vec![
                p2p(asbr, addr(10, 0, 0, 1), 1),
                p2p(border, addr(10, 0, 1, 1), 1),
                stub(net, mask, 5),
            ],
        );
        let asbr_lsa = router_lsa(asbr, vec![p2p(root, addr(10, 0, 0, 2), 1)]);
        let border_lsa = router_lsa(border, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let ext_lsa = as_external_lsa(addr(198, 51, 100, 0), addr(255, 255, 255, 0), asbr);
        let summary_lsa_ = network_summary_lsa(addr(203, 0, 113, 0), mask, border, 10);

        let view = intra_area_routes(
            root,
            &[root_lsa, asbr_lsa, border_lsa, ext_lsa, summary_lsa_],
        );
        // Only the genuine intra-area stub, never the external/summary route.
        assert_eq!(view.routes.len(), 1);
        assert_eq!(view.routes[0].prefix, "192.168.6.0/24".parse().unwrap());
        // Only the genuine in-area ASBR, never the border router (no Type-5 of its own).
        assert_eq!(view.asbrs, vec![(asbr, 1)]);
    }

    #[test]
    fn intra_area_routes_excludes_asbr_unreachable_in_this_area() {
        let root = router_id(1);
        let asbr = router_id(2);
        let root_lsa = router_lsa(root, vec![]);
        let ext_lsa = as_external_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), asbr);
        let view = intra_area_routes(root, &[root_lsa, ext_lsa]);
        assert_eq!(view.routes, []);
        assert_eq!(view.asbrs, []);
    }

    #[test]
    fn type3_summary_route_uses_abr_distance_plus_summary_metric() {
        let root = router_id(1);
        let abr = router_id(2);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);
        let root_lsa = router_lsa(root, vec![p2p(abr, addr(10, 0, 0, 1), 5)]);
        let abr_lsa = router_lsa(abr, vec![p2p(root, addr(10, 0, 0, 2), 5)]);
        let summary_lsa_ = network_summary_lsa(net, mask, abr, 10);

        let routes = compute(root, &[root_lsa, abr_lsa, summary_lsa_]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "192.0.2.0/24".parse().unwrap());
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 15);
    }

    #[test]
    fn own_type3_summary_is_never_treated_as_a_route_to_self() {
        let root = router_id(1);
        let root_lsa = router_lsa(root, vec![]);
        let summary_lsa_ =
            network_summary_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), root, 10);
        assert_eq!(compute(root, &[root_lsa, summary_lsa_]), []);
    }

    #[test]
    fn type3_summary_tie_break_against_stub_route_keeps_cheaper() {
        let root = router_id(1);
        let stub_router = router_id(2);
        let abr = router_id(3);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        // Via the stub-advertising router: cost 1 + 100 = 101.
        let root_lsa = router_lsa(
            root,
            vec![
                p2p(stub_router, addr(10, 0, 0, 1), 1),
                p2p(abr, addr(10, 0, 1, 1), 1),
            ],
        );
        let stub_router_lsa = router_lsa(
            stub_router,
            vec![p2p(root, addr(10, 0, 0, 2), 1), stub(net, mask, 100)],
        );
        // Via the ABR's summary: cost 1 + 10 = 11, cheaper.
        let abr_lsa = router_lsa(abr, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let summary_lsa_ = network_summary_lsa(net, mask, abr, 10);

        let routes = compute(root, &[root_lsa, stub_router_lsa, abr_lsa, summary_lsa_]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 1, 2)]);
        assert_eq!(routes[0].metric, 11);
    }

    #[test]
    fn type4_summary_lets_foreign_asbr_be_reached_via_abr_proxy() {
        let root = router_id(1);
        let border = router_id(2);
        let asbr = router_id(3); // genuinely in another area: no Router-LSA here at all
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        let root_lsa = router_lsa(root, vec![p2p(border, addr(10, 0, 0, 1), 5)]);
        let border_lsa = router_lsa(border, vec![p2p(root, addr(10, 0, 0, 2), 5)]);
        let asbr_summary = asbr_summary_lsa(asbr, border, 10);
        let ext_lsa = as_external_lsa(net, mask, asbr);

        let routes = compute(root, &[root_lsa, border_lsa, asbr_summary, ext_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 5 + 10 + EXTERNAL_METRIC_CONSTANT);
    }

    #[test]
    fn direct_intra_area_asbr_beats_type4_proxy() {
        let root = router_id(1);
        let border = router_id(2);
        let asbr = router_id(3);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        // Direct path to the ASBR: cost 1. Via the border router's (much
        // pricier) Type-4 proxy: cost 5 + 10 = 15. Direct must win.
        let root_lsa = router_lsa(
            root,
            vec![
                p2p(asbr, addr(10, 0, 2, 1), 1),
                p2p(border, addr(10, 0, 0, 1), 5),
            ],
        );
        let asbr_lsa = router_lsa(asbr, vec![p2p(root, addr(10, 0, 2, 2), 1)]);
        let border_lsa = router_lsa(border, vec![p2p(root, addr(10, 0, 0, 2), 5)]);
        let asbr_summary = asbr_summary_lsa(asbr, border, 10);
        let ext_lsa = as_external_lsa(net, mask, asbr);

        let routes = compute(
            root,
            &[root_lsa, asbr_lsa, border_lsa, asbr_summary, ext_lsa],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 2, 2)]);
        assert_eq!(routes[0].metric, 1 + EXTERNAL_METRIC_CONSTANT);
    }

    #[test]
    fn asbr_distance_prefers_cheapest_of_multiple_type4_proxies() {
        let root = router_id(1);
        let abr1 = router_id(2);
        let abr2 = router_id(3);
        let asbr = router_id(4);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        // Via abr1: 1 + 100 = 101. Via abr2: 1 + 1 = 2, cheaper.
        let root_lsa = router_lsa(
            root,
            vec![
                p2p(abr1, addr(10, 0, 0, 1), 1),
                p2p(abr2, addr(10, 0, 1, 1), 1),
            ],
        );
        let abr1_lsa = router_lsa(abr1, vec![p2p(root, addr(10, 0, 0, 2), 1)]);
        let abr2_lsa = router_lsa(abr2, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let summary1 = asbr_summary_lsa(asbr, abr1, 100);
        let summary2 = asbr_summary_lsa(asbr, abr2, 1);
        let ext_lsa = as_external_lsa(net, mask, asbr);

        let routes = compute(
            root,
            &[root_lsa, abr1_lsa, abr2_lsa, summary1, summary2, ext_lsa],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 1, 2)]);
        assert_eq!(routes[0].metric, 2 + EXTERNAL_METRIC_CONSTANT);
    }

    /// root(1) — 2, root — 3, 2 — 3 with the given 2–3 cost; 2 owns a stub.
    fn triangle(cost_23: u16) -> Vec<Arc<Lsa>> {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        vec![
            router_lsa(
                r1,
                vec![
                    p2p(r2, addr(10, 0, 12, 1), 1),
                    p2p(r3, addr(10, 0, 13, 1), 1),
                ],
            ),
            router_lsa(
                r2,
                vec![
                    p2p(r1, addr(10, 0, 12, 2), 1),
                    p2p(r3, addr(10, 0, 23, 2), cost_23),
                    stub(addr(192, 168, 2, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
            router_lsa(
                r3,
                vec![
                    p2p(r1, addr(10, 0, 13, 3), 1),
                    p2p(r2, addr(10, 0, 23, 3), cost_23),
                ],
            ),
        ]
    }

    fn route_to(routes: &[RouteEntry], prefix: &str) -> RouteEntry {
        routes
            .iter()
            .find(|r| r.prefix == prefix.parse().unwrap())
            .cloned()
            .unwrap()
    }

    #[test]
    fn triangle_gets_loop_free_alternate_via_the_other_neighbor() {
        let routes = compute(router_id(1), &triangle(1));
        let r = route_to(&routes, "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        // 3 reaches 2 directly (1) < 3→root (1) + root→2 (1).
        assert_eq!(r.backup_next_hop, Some(addr(10, 0, 13, 3)));
    }

    #[test]
    fn neighbor_whose_best_path_loops_through_root_is_not_an_alternate() {
        // 3's shortest way to 2 is back through root (1+1=2 < 10), so
        // 2 < 1 + 1 fails: it would loop.
        let routes = compute(router_id(1), &triangle(10));
        let r = route_to(&routes, "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        assert_eq!(r.backup_next_hop, None);
    }

    #[test]
    fn single_neighbor_has_no_alternate() {
        let root = router_id(1);
        let w = router_id(2);
        let lsas = [
            router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]),
            router_lsa(
                w,
                vec![
                    p2p(root, addr(10, 0, 0, 2), 1),
                    stub(addr(192, 168, 1, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
        ];
        let routes = compute(root, &lsas);
        assert_eq!(routes[0].backup_next_hop, None);
    }

    /// root(1) — 2 (cost 1) and root — 3 (cost 1), 2 — 4 (cost 1) and 3 — 4
    /// (the given cost), 4 — 5 (cost 1); 4 and 5 each own a stub.
    fn square(cost_34: u16) -> Vec<Arc<Lsa>> {
        let (r1, r2, r3, r4, r5) = (
            router_id(1),
            router_id(2),
            router_id(3),
            router_id(4),
            router_id(5),
        );
        vec![
            router_lsa(
                r1,
                vec![
                    p2p(r2, addr(10, 0, 12, 1), 1),
                    p2p(r3, addr(10, 0, 13, 1), 1),
                ],
            ),
            router_lsa(
                r2,
                vec![
                    p2p(r1, addr(10, 0, 12, 2), 1),
                    p2p(r4, addr(10, 0, 24, 2), 1),
                ],
            ),
            router_lsa(
                r3,
                vec![
                    p2p(r1, addr(10, 0, 13, 3), 1),
                    p2p(r4, addr(10, 0, 34, 3), cost_34),
                ],
            ),
            router_lsa(
                r4,
                vec![
                    p2p(r2, addr(10, 0, 24, 4), 1),
                    p2p(r3, addr(10, 0, 34, 4), cost_34),
                    p2p(r5, addr(10, 0, 45, 4), 1),
                    stub(addr(192, 168, 4, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
            router_lsa(
                r5,
                vec![
                    p2p(r4, addr(10, 0, 45, 5), 1),
                    stub(addr(192, 168, 5, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
        ]
    }

    #[test]
    fn equal_cost_square_keeps_both_next_hops() {
        let routes = compute(router_id(1), &square(1));
        let r = route_to(&routes, "192.168.4.0/24");
        assert_eq!(r.metric, 3);
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2), addr(10, 0, 13, 3)]);
        // Both neighbors are primaries, so neither is an alternate.
        assert_eq!(r.backup_next_hop, None);
    }

    #[test]
    fn destination_behind_ecmp_vertex_inherits_every_next_hop() {
        let routes = compute(router_id(1), &square(1));
        let r = route_to(&routes, "192.168.5.0/24");
        assert_eq!(r.metric, 4);
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2), addr(10, 0, 13, 3)]);
    }

    #[test]
    fn unequal_square_keeps_only_the_cheaper_next_hop() {
        let routes = compute(router_id(1), &square(2));
        let r = route_to(&routes, "192.168.4.0/24");
        assert_eq!(r.metric, 3);
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        // 3 reaches 4 in 2 < 3→root (1) + root→4 (2): loop-free.
        assert_eq!(r.backup_next_hop, Some(addr(10, 0, 13, 3)));
    }

    #[test]
    fn p2p_and_transit_network_to_same_neighbor_give_both_its_addresses() {
        // The e2e shape: root and w share a p2p link and a broadcast
        // segment, both cost 1 — w's own address on each is a next hop.
        let root = router_id(1);
        let w = router_id(2);
        let dr = addr(10, 0, 9, 2); // w is DR: the network's id is w's own address
        let lsas = [
            router_lsa(
                root,
                vec![
                    p2p(w, addr(10, 0, 0, 1), 1),
                    transit(dr, addr(10, 0, 9, 1), 1),
                ],
            ),
            router_lsa(
                w,
                vec![
                    p2p(root, addr(10, 0, 0, 2), 1),
                    transit(dr, dr, 1),
                    stub(addr(203, 0, 113, 80), addr(255, 255, 255, 255), 1),
                ],
            ),
            network_lsa(dr, addr(255, 255, 255, 0), vec![w, root]),
        ];
        let routes = compute(root, &lsas);
        let r = route_to(&routes, "203.0.113.80/32");
        assert_eq!(r.metric, 2);
        assert_eq!(r.next_hops, vec![addr(10, 0, 0, 2), dr]);
    }

    #[test]
    fn equal_metric_externals_from_two_asbrs_union_next_hops() {
        let root = router_id(1);
        let (a1, a2) = (router_id(2), router_id(3));
        let (net, mask) = (addr(192, 0, 2, 0), addr(255, 255, 255, 0));
        let routes = compute(
            root,
            &[
                router_lsa(
                    root,
                    vec![p2p(a1, addr(10, 0, 0, 1), 1), p2p(a2, addr(10, 0, 1, 1), 1)],
                ),
                router_lsa(a1, vec![p2p(root, addr(10, 0, 0, 2), 1)]),
                router_lsa(a2, vec![p2p(root, addr(10, 0, 1, 2), 1)]),
                as_external_lsa(net, mask, a1),
                as_external_lsa(net, mask, a2),
            ],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 1 + EXTERNAL_METRIC_CONSTANT);
        assert_eq!(
            routes[0].next_hops,
            vec![addr(10, 0, 0, 2), addr(10, 0, 1, 2)]
        );
    }

    #[test]
    fn equal_metric_summaries_and_type4_proxies_union_next_hops() {
        let root = router_id(1);
        let (abr1, abr2, asbr) = (router_id(2), router_id(3), router_id(4));
        let mask = addr(255, 255, 255, 0);
        let routes = compute(
            root,
            &[
                router_lsa(
                    root,
                    vec![
                        p2p(abr1, addr(10, 0, 0, 1), 1),
                        p2p(abr2, addr(10, 0, 1, 1), 1),
                    ],
                ),
                router_lsa(abr1, vec![p2p(root, addr(10, 0, 0, 2), 1)]),
                router_lsa(abr2, vec![p2p(root, addr(10, 0, 1, 2), 1)]),
                network_summary_lsa(addr(192, 0, 2, 0), mask, abr1, 10),
                network_summary_lsa(addr(192, 0, 2, 0), mask, abr2, 10),
                asbr_summary_lsa(asbr, abr1, 5),
                asbr_summary_lsa(asbr, abr2, 5),
                as_external_lsa(addr(198, 51, 100, 0), mask, asbr),
            ],
        );
        let both = vec![addr(10, 0, 0, 2), addr(10, 0, 1, 2)];
        let summary = route_to(&routes, "192.0.2.0/24");
        assert_eq!(summary.metric, 11);
        assert_eq!(summary.next_hops, both);
        let external = route_to(&routes, "198.51.100.0/24");
        assert_eq!(external.metric, 1 + 5 + EXTERNAL_METRIC_CONSTANT);
        assert_eq!(external.next_hops, both);
    }
}
