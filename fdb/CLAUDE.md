# nos-fdb — Forwarding-database (EVPN/VXLAN) component

`nos-fdbd` is the MAC counterpart of `nos-ribd`: one process per `BroadcastDomain` that has a `vni` (spawned by `nos-watchdogd` through `instances::manage`, `claim_label: "vni"` — the opt-in mechanism `nos-restd` uses on `rest-api`). It owns the kernel side of the domain's EVPN: a VXLAN device enslaved into the domain's bridge, and the bridge FDB behind it, in both directions.

| `nos-ribd` (per `RoutingTable`) | `nos-fdbd` (per `BroadcastDomain`) |
|---|---|
| owns the kernel VRF + routes, deletes them on shutdown | owns the kernel VXLAN device + FDB entries, deletes the device on shutdown |
| `nos-bgpd` pushes learned routes in (`PushBgpRoutes`) | `nos-bgpd` pushes received EVPN routes in (`FdbRequest::PushEvpnRoutes`) |
| pushes redistributed routes to `nos-bgpd` (`RedistributeRoutes`) | pushes local MACs to `nos-bgpd` (`BgpRequest::RedistributeMacs`) |
| `show route <table>` | `show fdb <domain>` (`GET /v1/fdb/{domain}`) |

## Config (`BroadcastDomain`, see `proto/CLAUDE.md`)

`vni`, `rd`, `route_targets_import`/`route_targets_export`, `vtep_source` (a `SourceAddress`: `interface <if> [label <l>]` or `loopback [label <l>]`) and `mac_redistribute` (`redistribute from mac to bgp <instance>` — the BGP instance is named on that command, not on the domain). Two optional siblings add Type-2 routes *with an IP*: `arp_redistribute` (`redistribute from arp to bgp <instance>` — local ARP/IPv6 ND bindings on the bridge) and `connected_redistribute` (`redistribute from connected to bgp <instance>` — the domain's own SVI `addresses`, originated with the bridge's MAC). Both must name the same instance as `mac_redistribute` (validated) — one EVPN target per domain. Link-local/loopback/multicast addresses are never advertised (`is_advertisable_ip`). The daemon is only *ready* (`fdb::Ready`) when all of `rd`, `vtep_source`, `mac_redistribute`, the domain's bridge (asked of `nos-interfaced`, `GetBroadcastDomain` → `bridge_name`) and the VTEP address (`GetInterface`) resolve; until then it idles and the 10s tick retries — a bridge or address that isn't there *yet* is the normal case.

## Kernel side (`driver/`)

`FdbDriver` (`--driver linux|noop`, like `RibDriver`). The Linux driver, over `rtnetlink`:
- `vx<vni>` (a VNI is unique per netns, so no registry file) with `local <vtep>`, dstport 4789, `nolearning`, **and `dev <underlay>`** — the device carrying the VTEP address (`eth0` for an interface source, `lo<table-id>` for a loopback, via `RibRequest::GetTableId`). This is not cosmetic: when the address lives inside a VRF the kernel can only bind the tunnel's UDP socket through that device. A device whose VNI/address/underlay drifted is recreated; VNI can't change in place.
- Remote MAC: `RTM_NEWNEIGH` AF_BRIDGE on the VXLAN device, `NTF_SELF|NTF_MASTER|NTF_EXT_LEARNED` (files it in the bridge table too; the bridge neither ages nor relearns it), `dst`=remote VTEP, `vni`, state permanent.
- Flood list: one all-zero-MAC entry per remote VTEP (head-end replication), which needs `NLM_F_APPEND` — `NeighbourAddRequest` hardcodes its flags, so every FDB write is a raw message via `Handle::request`.
- Remote IP: a Type-2 with an IP (`EvpnKey::MacIp`) is also an IP neighbour on the *bridge* (`RTM_NEWNEIGH` AF_INET/INET6, permanent + `NTF_EXT_LEARNED`, so the SVI resolves the host without ARP and the kernel neither ages nor probes it) next to its FDB entry. `desired` returns both; `installed` holds a list per route and an item is only removed when no other route still names it (a MAC-only and a MAC+IP route for one MAC share the FDB entry).
- Local MACs: `local_macs` dumps the bridge FDB and keeps entries that are *not* `permanent` (the ports' own addresses), not `extern_learn` (fdbd's own writes — this is the loop guard), not on the VXLAN port, and not group/all-zero addresses. An `RTNLGRP_NEIGH` subscription (`watch_neigh`, which also wakes on IPv4/IPv6 neighbour events) only signals "look again"; a debounced (200ms) dump is the source of truth, and the 10s tick covers a dropped notification. Note `bridge fdb add` defaults to *permanent* — pin a test MAC with `static`.

## IPC

- `--listen-socket` (`/run/nos/fdb-<domain>.sock`, `ServiceRef::FdbDomain`). `allowed`: `PushEvpnRoutes` is `bgpd`'s, `GetMacs` is `user`/`restd`.
- `bgp_client.rs` originates this domain's routes into `ServiceRef::BgpInstance(mac_redistribute)`: one Type-3 (inclusive multicast, origin = VTEP), one Type-2 per local MAC and, with `arp`/`connected`, one Type-2 (MAC+IP) per local neighbour (`local_neighbours`: the bridge's ARP/ND dump, not `extern_learn` — the loop guard — *and only for MACs behind a local port*, so a binding the SVI learned over the VXLAN port isn't re-originated) and per SVI address (`bridge_mac` from netlink), carrying the export Route Targets and the VXLAN encapsulation community, next-hop = VTEP. `Full` on every (re)connect; the otherwise write-only connection is also read for EOF so a `nos-bgpd` restart is answered at once (unlike `nos-bgpd`'s `rib_push_client`, which doesn't notice).
- `nos-bgpd`'s `fdb_push_client` pushes *every* received EVPN route to each domain that redistributes into it; **Route-Target filtering is fdbd's** (`fdb::desired`): a route is installed only if it carries an import RT, names this VNI (a Type-3's VNI comes from its PMSI attribute, absent = matches) and isn't our own VTEP.

## Explicit ceilings (`ponytail:` in the code)

MAC mobility / duplicate-MAC selection (a MAC from two VTEPs or two RDs is last-write-wins and can flap); ARP suppression itself (the entries are installed but `neigh_suppress` isn't set on the VXLAN port), the IP-VRF label / Type-5 / router-MAC extended community / default-gateway flag on an SVI Type-2; ESI (single-homed only); RPL policy on EVPN (bypassed in `nos-bgpd`); re-advertising received EVPN routes; a `Lookup` query. **Data plane is not verified**: `nos-e2e evpn-fdb` proves the control plane and the kernel FDB programming, not forwarding. With the underlay in a VRF, receiving VXLAN also needs `net.ipv4.udp_l3mdev_accept=1`, which nothing sets.

## Modules

| Module | Role |
|---|---|
| `main.rs` | flags, PKI identity from stdin, tracing + `ForwardingLayer`, spawns reconcile / local-MAC loop / bgp push / server; SIGINT deletes the VXLAN device |
| `fdb.rs` | `Fdb`: the MAC table (`received`, `installed`, `local`), `desired`/`local_routes` (pure), `set_ready`/`apply_push`/`refresh_local`/`run_local`/`table` |
| `reconcile.rs` | config diff + tick → `Ready` → `Fdb::set_ready` |
| `driver/` | `FdbDriver`, `linux.rs`, `noop.rs`, `is_local_mac` (pure) |
| `bgp_client.rs` | pushes local routes to `nos-bgpd` |
| `interface_client.rs` | bridge name, VTEP address + underlay device |
| `server.rs` | `GetMacs` / `PushEvpnRoutes` |
| `config_client.rs`, `watchdog_client.rs` | reimplemented per crate, per the star dependency graph |

`nos-e2e evpn-fdb` (GoBGP as the remote VTEP; a helper container pins a MAC and an `ip neigh ... nud permanent` on the bridge from inside router-a's netns) is the end-to-end proof, including Type-2-with-IP in both directions.
