# nos-ospfv3 — OSPFv3 (RFC 5340) daemon

One `nos-ospfv3d --instance <name>` process per `Ospfv3Instance`, spawned by `nos-watchdogd` (same dynamic-spawn pattern as `nos-ospfd`; see root `CLAUDE.md`). It mirrors `ospf/`'s architecture over real IPv6 raw protocol-89 sockets; read `ospf/CLAUDE.md` first for everything not called out here.

## Scope (Phase 1)
- Hello / DBD / LSR / LSU / LSAck reaching `Full` over point-to-point and broadcast links (DR/BDR election and neighbor FSM come from `nos-ospf-common`).
- Single-area SPF (RFC 5340 §4.8/§16) with next hops from Link-LSAs (never a live neighbor table), pushed to `nos-ribd` (`rib_push_client`).
- RFC 8362 Full mode (`extended-lsa`, `--ospfv3-extended-lsa`): E-Router/E-Link/E-Intra-Area-Prefix LSAs instead of the legacy set. No Sparse mode.
- RFC 5286 basic loop-free alternates (`spf::alternates`/`pick_backup`, same inequality and `ponytail:` ceiling as `nos-ospfd`: link protection only, one distance-only Dijkstra per neighbor — `run_dijkstra(.., links: None)` skips next-hop derivation, which would otherwise drop vertices from a non-root viewpoint). Differs from v2: the backup is link-local too, so it carries its own `backup_interface_id` (`OspfRoute`/`RibEntry`) and can leave over a different link than the primary; and `nos-ribd` installs an IPv6 backup at 2000, not 1000 (an IPv6 primary is 1024). Verified by `nos-e2e ospfv3-lfa`.
- RFC 7166 authentication trailer (`Ospfv3Profile.auth`) — see "Authentication" below. Verified by `nos-e2e ospfv3-auth`.
- RFC 5187 graceful restart — see "Graceful restart" below. Verified by `nos-e2e ospfv3-graceful-restart`.
- **Not yet** (OSPFv2-only for now): ABR, ASBR/redistribution, RFC 5838 multi-instance.

## Authentication (RFC 7166)

`Ospfv3Profile.auth: Option<Vec<OspfCryptoKey>>` — the same `nos_proto::OspfCryptoKey` as `OspfProfile`'s `OspfAuth::Crypto`, with no enum wrapper since RFC 7166 has exactly one mechanism (HMAC-SHA-1/256/384/512; `Md5` is rejected at commit, §4.3 defines none) and no simple password. Same CLI/ops/REST as `ospf profile` (`set … crypto-key <key-id> <algorithm> <key>`, `crypto-key <key-id> current`, `delete crypto-key <key-id>`, `delete auth`; `Ospfv3ProfileOp::{SetCryptoKey,RemoveCryptoKey,SetCryptoCurrentKey,ClearAuth}`; provision `--ospfv3-crypto-key <key-id>:<algorithm>:<key>`). `key_id` is the 16-bit Security Association ID — which is why `OspfCryptoKey.key_id` is `u16` for both protocols (see `ospf/CLAUDE.md`).

Wire mechanics, all in `packet.rs` (`TrailerAuth::sign`/`verify_trailer`, pinned by a test recomputing the HMAC independently):
- **AT-bit** `lsa::OPTION_AT` (`0x000400`, §2.1/§7) set in Hello/DBD Options by `link::link_options` when the link has keys; LSR/LSU/LSAck carry no Options and inherit the link's setting. A received Hello/DBD whose AT-bit disagrees with the link's config, or an authenticated link receiving a packet with no trailer, is `AuthTypeMismatch`.
- **Trailer** (§4.1, after the packet, outside its `Length`): Auth Type `1`, Auth Data Len (`16 + L`), Reserved, SA ID (= `key_id`), 64-bit sequence, then the digest. `decode_header` now bounds every body by `Length`, so trailing bytes never reach a body decoder.
- **Digest** (§4.4/§4.5): `Ks = key || 0x0001` (OSPFv3's Cryptographic Protocol ID — the one step with no `ospf::packet` precedent), `Ko = H(Ks)` if longer than `L` else zero-padded to `L`, then `HMAC(Ko, packet || trailer header || Apad)` with `Apad` = the 16-byte IPv6 source address followed by `0x878FE1F3` (`ospf::packet::apad`'s RFC 7474 shape with a 16-byte source). Compared in constant time (`hmac::Mac::verify_slice`).
- **Checksum** (§2.2/§4.2): an authenticated `OspfSocket` does **not** set `IPV6_CHECKSUM` — the field stays `0` and the kernel neither fills nor verifies it; the digest covers the packet instead.
- **Where it runs**: the socket signs every send (`socket::OspfSocket::open(.., auth)`, owning the sequence counter — wall-clock-seconds floor, `ospf::link`'s classic `AuType` 2 scheme, not RFC 7474's persisted boot count); `link::run` verifies every receive before `packet::decode` and keeps one `NeighborInfo.last_crypto_seq` per neighbor (`accept_crypto_sequence`, a non-increasing number is dropped and logged `"ospfv3 packet crypto sequence number not increasing, dropping"`). Failures log `"ospfv3 packet authentication failed"` with `link`/`source`, and a key change restarts the link like any other `LinkConfig` field.
- No LLS (RFC 5613) in either OSPF version, so the L-bit/LLS part of the digest scope never applies.

## Graceful restart (RFC 5187)

- **Grace-LSA** is a native type (`lsa::LSA_TYPE_GRACE` `0x000B`, link-local, `LsaBody::Grace`): RFC 3623's Grace Period and Restart Reason TLVs, no IP-address TLV (OSPFv3 identifies neighbors by router ID). SPF ignores it.
- **Restarting side**: `Ospfv3Instance.graceful_restart_grace_period` (`LinkManager::set_graceful_restart`). Only SIGTERM (`main::wait_for_shutdown_signal`) announces it — the watchdog's SIGINT means stop/removal, with no restart to wait for. `main` calls `LinkManager::announce_graceful_restart` before signalling shutdown (the log forwarder stops on that signal), which asks every link task (`LinkEntry.grace_tx`) to unicast one Grace-LSA to each `Full` neighbor, twice, 500ms apart (`GRACE_SEND_WINDOW`), then exits. Nothing is prematurely aged (v3 never did); the restarted process resyncs cold.
- **Helper side**, always on: `handle_lsu` acts on a newly installed Grace-LSA from a `Full` neighbor (`on_grace_lsa` sets `NeighborInfo.grace_deadline`) and removes it from the link store at once — held, it would be offered back to the restarted router and flooded to us again. While in grace: `apply_dead_timer`/`sweep_dead_neighbors` skip the neighbor, a Hello that doesn't list us keeps its state, and `Lsdb::age_and_evict` holds its LSAs below `MaxAge`. The restarted neighbor's Init DBD while we still hold it `Full` resynchronizes it through the general RFC 2328 §10.6 rule (see `ospf/CLAUDE.md`'s "DBDs in `Loading`/`Full`", shared by both daemons). Grace ends on reaching `Full` again, on a `MaxAge` Grace-LSA, or at the deadline (`expire_grace`, 1s tick).
- Routes need nothing: `nos-ribd` keeps OSPF routes of a disconnected push client, and the helper's SPF still sees the held LSAs.

## Layout
`socket` (raw socket) · `packet` (wire codec) · `lsa`/`lsdb` (LSAs, per-area database, aging) · `exchange` (DBD/LSR/LSU state, pure) · `link` (per-link driver task + `LinkManager`) · `reconcile` (config → `LinkConfig`) · `server` (IPC queries) · `rib_push_client`.

**LSDB scope** (RFC 5340 §4.5.1, #46): `LinkManager` holds one `Lsdb` per *area* (`lsdbs`, Router/Network/Intra-Area-Prefix and their E- forms) and one per *link* (`link_local_lsdbs`, keyed by attach point: Link-LSA/E-Link-LSA only, `lsa::is_link_local_scope`). A link's DBD summary, LSR answer and periodic flood read its area store plus its *own* link store, so a Link-LSA is never offered on a link other than the one it was received/originated on — `nos-ospfd` doesn't need this since OSPFv2 has no link-local scope. SPF (`compute_routes`) and `show ospfv3 database` (`Ospfv3LsaSummary.link = Some(attach_point)`) merge every same-area link store back in. `Lsdb` itself is scope-oblivious; `exchange::on_lsu_received` routes each received LSA by its S2/S1 bits.

## Things that differ from `ospf/`
- **Checksum**: the IPv6 upper-layer checksum is done by the kernel via `IPV6_CHECKSUM` (offset 12), set in `socket::open` — `packet.rs` doesn't compute it. Skipped on an authenticated link (RFC 7166 §2.2/§4.2, see "Authentication").
- **No IP header strip**: Linux IPv6 raw sockets deliver only the payload.
- **Hop limit 1**: unicast and multicast hops are both set to 1 on the socket (link-local scope; there are no virtual links). `ospf/src/socket.rs` does the same for IPv4 TTL.
- **DBD pagination** (RFC 2328 §10.8): the per-packet header budget is `exchange::mtu_based_max_headers(LinkConfig.mtu)` — MTU minus IPv6 (40) + OSPFv3 header (16) + DBD body (12), over the 20-byte LSA header. `Ospfv3Profile.mtu` overrides the interface MTU (`reconcile::resolve_effective_mtu`); `--dbd-max-headers` is a test/debug override only. Verified by `nos-e2e ospfv3-mtu-pagination`.
- Timers (`--lsa-age-multiplier`) are test-only, like in `nos-ospfd`.

## Verification
`link::LinkSocket`/`LinkManager::with_opener` are the same test seam as `nos-ospfd`'s (see `ospf/CLAUDE.md`'s "Testing without raw sockets"); the in-memory wire signs RFC 7166 trailers like `OspfSocket`, and `link::tests` covers p2p/broadcast adjacency, SPF, extended LSAs, graceful-restart helping and trailer auth.

`nos-e2e ospfv3`, `ospfv3-graceful-restart`, `ospfv3-auth`, `ospfv3-dr`, `ospfv3-lfa`, `ospfv3-mtu-pagination` (see root `CLAUDE.md`).
