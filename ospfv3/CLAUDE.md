# nos-ospfv3 — OSPFv3 (RFC 5340) daemon

One `nos-ospfv3d --instance <name>` process per `Ospfv3Instance`, spawned by `nos-watchdogd` (same dynamic-spawn pattern as `nos-ospfd`; see root `CLAUDE.md`). It mirrors `ospf/`'s architecture over real IPv6 raw protocol-89 sockets; read `ospf/CLAUDE.md` first for everything not called out here.

## Scope (Phase 1)
- Hello / DBD / LSR / LSU / LSAck reaching `Full` over point-to-point and broadcast links (DR/BDR election and neighbor FSM come from `nos-ospf-common`).
- Single-area SPF (RFC 5340 §4.8/§16) with next hops from Link-LSAs (never a live neighbor table), pushed to `nos-ribd` (`rib_push_client`).
- RFC 8362 Full mode (`extended-lsa`, `--ospfv3-extended-lsa`): E-Router/E-Link/E-Intra-Area-Prefix LSAs instead of the legacy set. No Sparse mode.
- **Not yet** (OSPFv2-only for now): authentication, ABR, ASBR/redistribution, RFC 5838 multi-instance.

## Layout
`socket` (raw socket) · `packet` (wire codec) · `lsa`/`lsdb` (LSAs, per-area database, aging) · `exchange` (DBD/LSR/LSU state, pure) · `link` (per-link driver task + `LinkManager`) · `reconcile` (config → `LinkConfig`) · `server` (IPC queries) · `rib_push_client`.

## Things that differ from `ospf/`
- **Checksum**: the IPv6 upper-layer checksum is done by the kernel via `IPV6_CHECKSUM` (offset 12), set in `socket::open` — `packet.rs` doesn't compute it.
- **No IP header strip**: Linux IPv6 raw sockets deliver only the payload.
- **Hop limit 1**: unicast and multicast hops are both set to 1 on the socket (link-local scope; there are no virtual links). `ospf/src/socket.rs` does the same for IPv4 TTL.
- **DBD pagination** (RFC 2328 §10.8): the per-packet header budget is `exchange::mtu_based_max_headers(LinkConfig.mtu)` — MTU minus IPv6 (40) + OSPFv3 header (16) + DBD body (12), over the 20-byte LSA header. `Ospfv3Profile.mtu` overrides the interface MTU (`reconcile::resolve_effective_mtu`); `--dbd-max-headers` is a test/debug override only. Verified by `nos-e2e ospfv3-mtu-pagination`.
- Timers (`--lsa-age-multiplier`) are test-only, like in `nos-ospfd`.

## Verification
`nos-e2e ospfv3`, `ospfv3-dr`, `ospfv3-mtu-pagination` (see root `CLAUDE.md`).
