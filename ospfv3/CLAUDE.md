# nos-ospfv3 — OSPFv3 (RFC 5340) daemon

One `nos-ospfv3d --instance <name>` process per `Ospfv3Instance`, spawned by `nos-watchdogd` (same dynamic-spawn pattern as `nos-ospfd`; see root `CLAUDE.md`). It mirrors `ospf/`'s architecture over real IPv6 raw protocol-89 sockets; read `ospf/CLAUDE.md` first for everything not called out here.

## Scope (Phase 1)
- Hello / DBD / LSR / LSU / LSAck reaching `Full` over point-to-point and broadcast links (DR/BDR election and neighbor FSM come from `nos-ospf-common`).
- Single-area SPF (RFC 5340 §4.8/§16) with next hops from Link-LSAs (never a live neighbor table), pushed to `nos-ribd` (`rib_push_client`).
- RFC 8362 Full mode (`extended-lsa`, `--ospfv3-extended-lsa`): E-Router/E-Link/E-Intra-Area-Prefix LSAs instead of the legacy set. No Sparse mode.
- RFC 5286 basic loop-free alternates (`spf::alternates`/`pick_backup`, same inequality and `ponytail:` ceiling as `nos-ospfd`: link protection only, one distance-only Dijkstra per neighbor — `run_dijkstra(.., links: None)` skips next-hop derivation, which would otherwise drop vertices from a non-root viewpoint). Differs from v2: the backup is link-local too, so it carries its own `backup_interface_id` (`OspfRoute`/`RibEntry`) and can leave over a different link than the primary; and `nos-ribd` installs an IPv6 backup at 2000, not 1000 (an IPv6 primary is 1024). Verified by `nos-e2e ospfv3-lfa`.
- **Not yet** (OSPFv2-only for now): authentication, ABR, ASBR/redistribution, RFC 5838 multi-instance.

## Layout
`socket` (raw socket) · `packet` (wire codec) · `lsa`/`lsdb` (LSAs, per-area database, aging) · `exchange` (DBD/LSR/LSU state, pure) · `link` (per-link driver task + `LinkManager`) · `reconcile` (config → `LinkConfig`) · `server` (IPC queries) · `rib_push_client`.

**LSDB scope** (RFC 5340 §4.5.1, #46): `LinkManager` holds one `Lsdb` per *area* (`lsdbs`, Router/Network/Intra-Area-Prefix and their E- forms) and one per *link* (`link_local_lsdbs`, keyed by attach point: Link-LSA/E-Link-LSA only, `lsa::is_link_local_scope`). A link's DBD summary, LSR answer and periodic flood read its area store plus its *own* link store, so a Link-LSA is never offered on a link other than the one it was received/originated on — `nos-ospfd` doesn't need this since OSPFv2 has no link-local scope. SPF (`compute_routes`) and `show ospfv3 database` (`Ospfv3LsaSummary.link = Some(attach_point)`) merge every same-area link store back in. `Lsdb` itself is scope-oblivious; `exchange::on_lsu_received` routes each received LSA by its S2/S1 bits.

## Things that differ from `ospf/`
- **Checksum**: the IPv6 upper-layer checksum is done by the kernel via `IPV6_CHECKSUM` (offset 12), set in `socket::open` — `packet.rs` doesn't compute it.
- **No IP header strip**: Linux IPv6 raw sockets deliver only the payload.
- **Hop limit 1**: unicast and multicast hops are both set to 1 on the socket (link-local scope; there are no virtual links). `ospf/src/socket.rs` does the same for IPv4 TTL.
- **DBD pagination** (RFC 2328 §10.8): the per-packet header budget is `exchange::mtu_based_max_headers(LinkConfig.mtu)` — MTU minus IPv6 (40) + OSPFv3 header (16) + DBD body (12), over the 20-byte LSA header. `Ospfv3Profile.mtu` overrides the interface MTU (`reconcile::resolve_effective_mtu`); `--dbd-max-headers` is a test/debug override only. Verified by `nos-e2e ospfv3-mtu-pagination`.
- Timers (`--lsa-age-multiplier`) are test-only, like in `nos-ospfd`.

## Verification
`nos-e2e ospfv3`, `ospfv3-dr`, `ospfv3-lfa`, `ospfv3-mtu-pagination` (see root `CLAUDE.md`).
