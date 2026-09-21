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

## Ethernet Segments (ESI) and the Designated Forwarder

A `PortAggregate` with an `esi` (config: `set port-aggregate <n> esi <10 hex bytes>`) that is a member of this domain's bridge — through its switching profile, untagged (the bond is the bridge port) or `Dot1q(n)` (its `<bond>.<n>` sub-link is) — is an **Ethernet Segment port** (`Ready.es_ports`, resolved in `reconcile::es_ports`, the bond's real `bond<id>` name coming from `nos-interfaced`'s `GetPortAggregate`). What that does:

- **Type-2 ESI.** `FdbDriver::local_macs` now returns each MAC with the bridge port it sits behind; `local_routes` puts that port's ESI on the MAC's Type-2 (and on a MAC+IP for a neighbour behind it). `EvpnRoute.esi` is in the route *value*, not `EvpnKey`; the ESI is part of a Type-2's wire identity though, so `nos-bgpd`'s `apply_evpn_local` withdraws the old NLRI when a MAC moves onto/off a segment.
- **Type-4.** One `EvpnKey::EthernetSegment { rd, esi, origin = VTEP }` per distinct ESI, carrying only its ES-Import Route Target (`nos_proto::evpn_id::es_import_rt`). Originated by *every domain's* fdbd that attaches the segment, each with its own RD, so the same segment appears once per domain; receivers dedupe by origin.
- **DF election** (`df.rs`, pure): RFC 7432 §8.5 default carving — the segment's PEs (our VTEP plus every received Type-4 origin for that ESI, matched on the exact ESI, not the ES-Import RT) ordered by ascending address; the DF for the domain is `pes[vni % n]` (RFC 8365 §8.3.1: the VNI is the Ethernet tag), so two domains on one segment spread over the PEs. `Fdb::sync_df` re-runs it on every received Type-4 change and on each resync.
- **Applied to the kernel:** `FdbDriver::set_port_flood` (an `RTM_NEWLINK` with `IFLA_INFO_PORT_DATA` = `IFLA_BRPORT_{UNICAST,MCAST,BCAST}_FLOOD`, the same as `ip link set … type bridge_slave flood …`; via netlink, not sysfs, since fdbd is the unprivileged `nos` user) — off on the non-DF's segment port, on for the DF and for a port that left the segment (or on shutdown). The block is re-asserted every resync so a recreated port is healed. Log anchors: `df elected … role=df|non-df pes=…`, `segment port flooding set … flood=…`.
- **`desired`** skips a remote Type-2 whose ESI is one of our local segments: that MAC is reachable through our own bond, a VXLAN entry to the peer PE would win over it.
- `show fdb` lists each segment (`FdbTable.segments`: ESI, port, DF role, ranked PEs) and the ESI of a local MAC.

- **DF wait timer** (§8.5 step 3, `--df-wait`, default 3s): a segment port is held blocked (`segments[].waiting`, reported non-DF in `show fdb`) for the wait after it *first appears* in the plan — fdbd start, ESI newly set, port newly attached, fdbd back from not-ready — and only then is the election applied, so a PE that has just come up doesn't double-deliver BUM. A peer's Type-4 arriving later does not restart it (the joining PE waits, the incumbent doesn't). `run_local` sleeps to the earliest deadline (`df_deadline`) since the 10s tick is too coarse. Log anchors: `df wait started … seconds=`, then `df elected …` only once it ends. Tunable through `--fdbd-arg=--df-wait=N` (e2e `evpn-esi` uses 12s so the kernel state can be read while blocked).

Ceilings (`ponytail:`): no local bias / split horizon, so BUM the ingress PE floods to its peer on the same segment is still forwarded to the segment by the peer if that one is the DF; no Type-1 (per-ES/per-EVI A-D, aliasing, mass withdraw) — every PE on a segment is assumed to serve every domain; all-active only (no single-active); the non-DF also stops delivering *locally sourced* BUM to that port; no ES-Import filtering. `nos-e2e evpn-esi` proves the control plane and the kernel port flags; `evpn-dataplane` proves forwarding (below).

## Explicit ceilings (`ponytail:` in the code)

MAC mobility / duplicate-MAC selection (a MAC from two VTEPs or two RDs is last-write-wins and can flap); ARP suppression itself (the entries are installed but `neigh_suppress` isn't set on the VXLAN port), the IP-VRF label / Type-5 / router-MAC extended community / default-gateway flag on an SVI Type-2; RPL policy on EVPN (bypassed in `nos-bgpd`); re-advertising received EVPN routes; a `Lookup` query. `nos-e2e evpn-fdb` proves the control plane and the kernel FDB programming against GoBGP; `nos-e2e evpn-dataplane` proves **forwarding** between two nos PEs and a dual-homed CE (unicast across the VXLAN both ways, a broadcast delivered to the segment once through the DF and never through the non-DF, local bridging on the non-DF) — the run that found every remote FDB entry must name its underlay (`via`/`NDA_IFINDEX`, the driver's `underlay` map), else with the underlay in a VRF the kernel looks the remote VTEP up in the main table and drops every frame (`tx_carrier_errors`). **Operator prerequisite nothing in nos sets:** with the underlay in a VRF, receiving VXLAN needs `net.ipv4.udp_l3mdev_accept=1` (the daemons are unprivileged and `/proc/sys` is read-only in the container); the e2e phase sets it through its privileged helper. Not observed by the e2e: a remote MAC behind a segment we share is *skipped* (`desired`) rather than pinned to our own segment port, so a PE that hasn't learned it locally has no FDB entry for it and would flood its unicast (the phase's pings pass either way).

## Modules

| Module | Role |
|---|---|
| `main.rs` | flags, PKI identity from stdin, tracing + `ForwardingLayer`, spawns reconcile / local-MAC loop / bgp push / server; SIGINT deletes the VXLAN device |
| `fdb.rs` | `Fdb`: the MAC table (`received`, `installed`, `local` with each MAC's port), `desired`/`local_routes`/`plan_df` (pure), `set_ready`/`apply_push`/`sync_df`/`refresh_local`/`run_local`/`table` |
| `df.rs` | pure DF election (`candidates`/`elect`) |
| `reconcile.rs` | config diff + tick → `Ready` → `Fdb::set_ready` |
| `driver/` | `FdbDriver`, `linux.rs`, `noop.rs`, `is_local_mac` (pure) |
| `bgp_client.rs` | pushes local routes to `nos-bgpd` |
| `interface_client.rs` | bridge name, VTEP address + underlay device, a port aggregate's `bond<id>` name |
| `server.rs` | `GetMacs` / `PushEvpnRoutes` |
| `config_client.rs`, `watchdog_client.rs` | reimplemented per crate, per the star dependency graph |

`nos-e2e evpn-fdb` (GoBGP as the remote VTEP; a helper container pins a MAC and an `ip neigh ... nud permanent` on the bridge from inside router-a's netns) is the end-to-end proof, including Type-2-with-IP in both directions.
