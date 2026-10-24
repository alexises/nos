# nos-rib — RIB Component

Computes the best route per prefix for one routing table (binary `nos-ribd`, one process per `RoutingTable`, spawned by `nos-watchdog`).


## Rules that bite

- **Multi-source `Rib`** (`rib.rs`): `RouteSource::{Static, Bgp, Ospf, Connected, Evpn, Vpn}`, each with its own writer; `replace_source`/`upsert`/`remove` are scoped to one source, so no writer clobbers another's candidates. `Static` and `Connected` (preference 0, below `Static`) are rebuilt from config / `nos-interfaced` (`interface_client.rs`) on every resync; `Bgp`/`Ospf` arrive only via `PushBgpRoutes`/`PushOspfRoutes` (`table.bgp_instance` is never read from config). `Evpn` and `Vpn` (`PushVpnRoutes`, RT-imported L3VPN routes) have preference 200, below `Ospf`.
- **Only the best route per prefix is installed** (`best_routes_for_kernel`), except a prefix whose winner is `Connected`: left to the kernel whole (#139), so a connected prefix never appears in the kernel dump-diff (`extract_route` skips gateway-less routes). `Connected` exists for `igp_costs()` (cost 0; RFC 4271 §9.1.2 in `nos-bgpd`) and `show route`.
- **Driver.** `--driver linux` (default on Linux) creates the VRF device and kernel table and diffs live routes (idempotent dump-diff-converge, so `server.rs` may call `driver.apply` itself); `noop` only logs. `teardown` runs on every SIGINT and never touches `driver/table_registry.rs` (`--table-registry-path`, ids 100-252, locked with `fs2`, read by no other process), so a restart recreates the same VRF name.
- **Redistribution the other way:** `reconcile::compute_redistribute_target`/`_ospf` filter `Static` candidates against `RoutingTable.redistribute` (each of `Bgp`/`Ospf`/`Ospfv3` independent; `Ospfv3` IPv6 only) and `bgp_client.rs`/`ospf_client.rs` forward them (`RedistributeRoutes`), reading the connection for EOF so a restarted peer gets a fresh `Full`.
- **Authorization** (`allowed(role, &request)`, role-level only, `ponytail:` in `server.rs`): `PushBgpRoutes` and `BgpRouteCount` `bgpd`; `PushOspfRoutes` `ospfd`/`ospfv3d`; `PushEvpnRoutes`/`PushVpnRoutes` `bgpd`; `ResolveNextHop` `bgpd`/`user`/`restd`; `GetEvpnIrb` `fdbd`; queries (incl. `GetVpnLabel`) `user`/`restd`; `GetVrfName`/`GetTableId` the daemons that resolve a VRF through this instance.
- **Failed route ops:** `drain` runs every add/remove of a pass to completion and returns the first error; `installed` keeps the slot of each failed op.
- **Two kernel slots per prefix** `(prefix, false)` primary and `(prefix, true)` backup (`BACKUP_METRIC_V4` 1000, `BACKUP_METRIC_V6` 2000); `RibEntry.backup`, `next_hops` and the discard flag are part of entry equality, so a change re-installs the winner. Discard routes are `RTN_BLACKHOLE` with `RTPROT_STATIC` only; `igp_costs` skips them. ECMP is `RTA_MULTIPATH` for 2+ hops, read back by `extract_route`.
- **Dump hygiene:** `extract_route` skips `RTM_F_CLONED`; `reconcile_routes` clears `RTNH_F_ONLINK` before deleting a dumped route.
- **L3VPN export** (`RoutingTable.vpn`, #580): `vpn.rs`/`vpn_client.rs` push every best route except `Vpn` (loop guard) and `Evpn` ones to `vpn.bgp_instance` with RD, export RTs and the VRF label. An explicit `vpn.label` wins; otherwise `table_registry::ensure_label` (same file and lock as the table ids, from 1000, never freed, clear of every explicit label).
- **L3VPN data plane** (#581): `RibDriver::sync_mpls` (AF_MPLS pop route `<label> dev <vrf>`, `net.mpls` sysctls read before written, `driver/mpls.rs`) runs before the export push, which is withheld when it fails; a `Vpn` winner is installed `encap mpls <labels> via <pe> dev <underlay if> onlink`. Each `RibEntry.next_hops` hop (`nos_proto::NextHop`) carries its own labels; slots compare by sorted `(gateway, labels)` pairs, multipath is per-next-hop encap.
- **EVPN IP-VRF** (`RoutingTable.evpn.l3_vni`): this daemon owns `brv<vni>`/`vx<vni>` and originates Type-5 routes (`evpn.rs`, `evpn_client.rs`, `RibDriver::sync_l3vni`); loop guard: an `Evpn`-sourced route is never re-originated. Remote LFA tunnel device `rlfa<table-id>` (`RibDriver::sync_tunnel`).

## Modules

| Module | Role |
|---|---|
| `main.rs` | Args (`--table`, `--watchdog-socket`, `--listen-socket`, `--driver`, `--table-registry-path`); shared `Arc<RwLock<Rib>>` and driver |
| `rib.rs` | `RouteSource`, `RibEntry`, `Rib`, `build_from_config` |
| `evpn.rs`, `evpn_client.rs` | EVPN IP-VRF pure part and Type-5 push |
| `vpn.rs`, `vpn_client.rs` | L3VPN VRF export pure part and push |
| `push_client.rs` | Origination push loop shared by both clients (`Feed`) |
| `driver/` | `mod.rs` trait, `noop.rs`, `linux.rs`, `mpls.rs` (pure MPLS/sysctl parts), `table_registry.rs` |
| `reconcile.rs` | Diff-triggered resync, 10s tick, `driver.teardown` on exit; `reconcile_tests.rs` runs it against `nos-test-support`'s fakes and a recording `RibDriver` (#344) |
| `server.rs` | Route queries, `GetVrfName`/`GetTableId`, `BgpRouteCount`, route pushes |
| `bgp_client.rs`, `ospf_client.rs`, `interface_client.rs` | Redistribution pushes; `get_interfaces`/`get_port_aggregates`/`get_broadcast_domain` |
| (no `config_client`/`watchdog_client`) | config, watchdog, one-shot IPC and `main()` bootstrap come from `nos-daemon` (`daemon/CLAUDE.md`) |

Details: [internals](../docs/internals/rib.md) (scope, EVPN IP-VRF, backup/tunnel/discard/ECMP routes, per-module notes), [routing tables](../docs/protocols/routing-tables.md), [EVPN/VXLAN](../docs/protocols/evpn-vxlan.md).
