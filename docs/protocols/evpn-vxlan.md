# EVPN and VXLAN

EVPN (RFC 7432) extends a layer-2 broadcast domain across a routed network. Each router (a PE, or VTEP) carries the domain's Ethernet frames inside VXLAN tunnels (RFC 7348) to the other routers that have the same domain, and uses BGP to tell them which MAC addresses sit behind it. NOS implements EVPN over VXLAN as described in RFC 8365, including multi-homing: one customer device attached to two routers at once.

- [What it is for](#what-it-is-for)
- [Before you start](#before-you-start)
- [Common operations](#common-operations)
  - [Enable EVPN on a BGP session](#enable-evpn-on-a-bgp-session)
  - [Stretch a broadcast domain over VXLAN](#stretch-a-broadcast-domain-over-vxlan)
  - [Also advertise IP addresses](#also-advertise-ip-addresses)
  - [Check what was learned](#check-what-was-learned)
  - [Multi-home a customer device (Ethernet Segments)](#multi-home-a-customer-device-ethernet-segments)
  - [Route between subnets over EVPN (IP-VRF, Type 5)](#route-between-subnets-over-evpn-ip-vrf-type-5)
  - [Turn EVPN off](#turn-evpn-off)
- [How EVPN behaves](#how-evpn-behaves)
- [Configuration reference](#configuration-reference)

The examples use the `$B`/`$C` variables from [The REST API](../api.md#a-complete-session-with-curl) and the two-router lab from the [README](../README.md#conventions-used-in-these-pages): router-a (`10.50.0.2`, AS 65001, BGP instance `r1` in routing table `rt1`) peers with router-b (`10.50.0.3`, AS 65002) through peer-group `pg1`.

## What it is for

Without EVPN, a broadcast domain in NOS is a bridge local to one router: the interfaces trunked into it can talk to each other and nothing else. With EVPN, the same domain exists on several routers and behaves as one LAN:

- Hosts in the domain on router-a reach hosts in the domain on router-b at layer 2, over an IP network between the routers (the **underlay**). The underlay only needs to route between the routers' tunnel addresses.
- Each router learns MAC addresses on its own ports as a normal switch does, and advertises them in BGP. The other routers install them directly, so unicast frames go straight to the right router instead of being flooded.
- Broadcast, unknown-unicast and multicast frames (BUM) are copied to every router that has the domain (ingress replication). There is no multicast in the underlay.
- A customer device can be connected to two routers with one bond. Both routers know they share it, and they make sure it receives each flooded frame only once.

A **VNI** (VXLAN Network Identifier, 1 to 16777215) names the domain on the wire. Routers that should share a domain use the same VNI. **Route targets** decide which routers accept whose MAC addresses, and a **route distinguisher** keeps each router's routes apart in BGP.

## Before you start

EVPN builds on three things configured elsewhere:

- **A broadcast domain with ports.** Interfaces, VLAN tags and port aggregates join a domain through a switching profile; see the L2 switching guide. The examples below use a domain `bd100`. EVPN works on a domain that has no local ports yet, but it then has nothing to advertise except itself.
- **A BGP session between the routers.** Any BGP instance and peer-group will do, eBGP or iBGP; the examples reuse `r1` and `pg1`. EVPN routes are not passed through routing policies, so the peer-group's `import-policy` and `export-policy` do not affect them.
- **A tunnel address** on each router, reachable from the others through the underlay: an interface address, or the routing table's loopback. The examples use each router's `eth0` address.

When the tunnel address is in a routing table (it always is in NOS: there is no default VRF), Linux only delivers incoming VXLAN packets to the tunnel if the system setting `net.ipv4.udp_l3mdev_accept` is `1`. NOS does not change system settings, so set it yourself on the router's network namespace. With Docker Compose:

```yaml
services:
  watchdog:
    sysctls:
      - net.ipv4.udp_l3mdev_accept=1
```

Without it, the control plane works (routes are exchanged and `show fdb` fills in), but frames arriving from other routers are dropped.

## Common operations

### Enable EVPN on a BGP session

Add the `l2vpn-evpn` address family to the peer-group on both routers. The session restarts to negotiate it:

```
lab-1> configure evpn
lab-1(evpn)> set bgp instance r1 peer-group pg1 address-family l2vpn-evpn
lab-1(evpn)> commit
transaction 'evpn' committed
```

The family is added to the ones already there, so the session keeps carrying unicast routes. Over REST, `PUT` the new element of the peer-group's `address-family` list:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"L2vpnEvpn"' \
   $B/v1/transactions/evpn/bgp-instance/r1/peer-group/pg1/address-family/L2vpnEvpn
```

`show config` then shows `address-family [ipv4, l2vpn-evpn]` on the peer-group.

### Stretch a broadcast domain over VXLAN

Give the domain a VNI, a route distinguisher, import and export route targets, a tunnel source, and name the BGP instance to advertise into. Do it on every router that has the domain, with the same VNI and matching route targets, and a route distinguisher unique to each router. On router-a:

```
lab-1> configure bd
lab-1(bd)> edit broadcast domain bd100
lab-1(bd/broadcast-domain:bd100)> set vni 10100
lab-1(bd/broadcast-domain:bd100)> set rd 65001:100
lab-1(bd/broadcast-domain:bd100)> set route-target import 65000:10100
lab-1(bd/broadcast-domain:bd100)> set route-target export 65000:10100
lab-1(bd/broadcast-domain:bd100)> set vtep-source interface eth0
lab-1(bd/broadcast-domain:bd100)> set redistribute from mac to bgp r1
lab-1(bd/broadcast-domain:bd100)> commit
transaction 'bd' committed
```

On router-b, the same with `rd 65002:100`. Each command also has an absolute form that works from anywhere in the transaction, for example `set broadcast domain bd100 vni 10100`.

Over REST, the EVPN fields are fields of the broadcast domain. Here the whole domain is written in one `PUT`:

```sh
$C -X POST "$B/v1/transactions/bd?base=current"
$C -X PUT -H 'Content-Type: application/json' -d '{
  "name": "bd100", "addresses": [], "routing_table": null,
  "ospf_profile": null, "ospfv3_profile": null,
  "vni": 10100, "rd": "65001:100",
  "route_targets_import": ["65000:10100"], "route_targets_export": ["65000:10100"],
  "vtep_source": {"Interface": {"interface": "eth0", "label": null}},
  "mac_redistribute": "r1", "arp_redistribute": null, "connected_redistribute": null
}' $B/v1/transactions/bd/broadcast-domain/bd100
$C -X POST $B/v1/transactions/bd/commit
```

Each field also has its own path, for example `PUT …/broadcast-domain/bd100/vni` with body `10100`, or `PUT …/broadcast-domain/bd100/route-targets-import/65000:10100` with body `"65000:10100"` to add one route target.

What each setting does:

- `vni` turns EVPN on for the domain: the router creates the VXLAN tunnel in the domain's bridge. Every other EVPN setting requires it.
- `rd` is written `<asn>:<n>` or `<ipv4>:<n>`. It is attached to every route the domain advertises.
- `route-target import <rt>` (repeatable): a route received for this domain is used only if it carries at least one of these. `route-target export <rt>` (repeatable): attached to every route the domain advertises. Using one route target per domain, identical on all routers, is the simplest scheme.
- `vtep-source interface <name>` sources the tunnels from that interface's address; add `label <label>` to pick one address when the interface has several. `vtep-source loopback` uses the loopback of the routing table that owns the BGP instance (`loopback-rt1` for `r1`). This address is also the BGP next hop of every route the domain advertises, so the other routers must be able to reach it.
- `redistribute from mac to bgp <instance>` advertises the domain into that BGP instance, and installs the EVPN routes that instance receives. It needs `rd` and `vtep-source`.

Once committed, the domain advertises itself to the other routers (an Inclusive Multicast route, Type 3), and each router adds the others to its flood list:

```
lab-1> show fdb bd100
broadcast-domain bd100: vni 10100, bridge br1, vxlan vx10100
  no MAC addresses
  flood list: 10.50.0.3
```

`bridge` and `vxlan` are the Linux devices of the domain; the bridge number is allocated by the router.

From then on, every MAC address the bridge learns on a local port is advertised as a MAC route (Type 2), and withdrawn when the bridge forgets it.

### Also advertise IP addresses

Two optional rules add IP addresses to the MAC routes. Both must name the same BGP instance as `redistribute from mac`:

- `redistribute from arp to bgp <instance>` advertises the IPv4 ARP and IPv6 neighbour entries the router holds for hosts on the domain's local ports, as MAC+IP routes. Receiving routers install them as neighbour entries on their own bridge, so they can reach those hosts without resolving them first.
- `redistribute from connected to bgp <instance>` advertises the domain's own addresses (its SVI), with the bridge's MAC address, marked as a default gateway.

```
lab-1(bd)> set broadcast domain bd100 address 203.0.113.1/24
lab-1(bd)> set broadcast domain bd100 routing-table rt1
lab-1(bd)> set broadcast domain bd100 redistribute from arp to bgp r1
lab-1(bd)> set broadcast domain bd100 redistribute from connected to bgp r1
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"r1"' $B/v1/transactions/bd/broadcast-domain/bd100/arp-redistribute
$C -X PUT -H 'Content-Type: application/json' -d '"r1"' $B/v1/transactions/bd/broadcast-domain/bd100/connected-redistribute
```

Link-local, loopback and multicast addresses are never advertised.

### Check what was learned

`show bgp evpn` lists every EVPN route each BGP instance has received, with the peer it came from, its next hop, the route itself and its extended communities:

```
lab-1> show bgp evpn
bgp instance r1:
  from 10.50.0.3 next-hop 10.50.0.3 [3]:[65002:100]:[0]:[10.50.0.3] [RT:65000:10100 encap:8]
```

The route is shown in the usual bracketed EVPN notation, starting with its type:

- `[2]:[<rd>]:[<esi>]:[<tag>]:[48]:[<mac>]:[<ip>]:[<vni>]`: a MAC address (and, with `arp`/`connected`, its IP) behind the sending router. The ESI is all zeros unless the MAC sits behind a multi-homed bond.
- `[3]:[<rd>]:[<tag>]:[<address>]`: the sending router has the domain; the address is its tunnel address.
- `[4]:…`: the sending router is attached to an Ethernet Segment.
- `[1]:…`: an Ethernet A-D route, per segment or per domain, used for multi-homing (below).

The communities in brackets: `RT:<rt>` is a route target, `encap:8` means VXLAN, `default-gw` marks an SVI address, `esi-label:all-active|single-active` gives a segment's redundancy mode, and `0x06…` is the MAC Mobility community.

`show fdb <domain>` shows what the domain actually uses: its bridge and tunnel device, every MAC address with where it is (`local`, or `remote via <router>`), the IP neighbours, the flood list, and each Ethernet Segment:

```
lab-2> show fdb bd100
broadcast-domain bd100: vni 10100, bridge br1, vxlan vx10100
  ea:f3:14:7e:69:3f remote via 10.50.0.2
  203.0.113.1 is at ea:f3:14:7e:69:3f remote via 10.50.0.2
  203.0.113.2 is at ee:59:ae:e9:f1:74 local
  flood list: 10.50.0.2
lab-2> show bgp evpn
bgp instance r1:
  from 10.50.0.2 next-hop 10.50.0.2 [2]:[65001:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[48]:[ea:f3:14:7e:69:3f]:[203.0.113.1]:[10100] [RT:65000:10100 encap:8 default-gw 0x0600000000000000]
  from 10.50.0.2 next-hop 10.50.0.2 [3]:[65001:100]:[0]:[10.50.0.2] [RT:65000:10100 encap:8]
```

Here router-b (with `address 203.0.113.2/24` and both rules on its own `bd100`) has learned router-a's SVI: its MAC, and its address as a neighbour entry.

A remote route is used only if it carries one of the domain's import route targets, names the domain's VNI and does not come from the router itself; the others appear in `show bgp evpn` but not in `show fdb`. Over REST these are `GET /v1/bgp/evpn` and `GET /v1/fdb/{domain}`:

```sh
$ $C $B/v1/fdb/bd100 | jq -c '{vni, flood, macs: [.macs[] | {mac, source, vtep}]}'
{"vni":10100,"flood":["10.50.0.2"],"macs":[{"mac":"ea:f3:14:7e:69:3f","source":"Remote","vtep":"10.50.0.2"}]}
```

### Multi-home a customer device (Ethernet Segments)

A customer device (CE) can be connected to two or more routers with one bond, for redundancy or capacity. On the NOS side, each router has a port aggregate towards the CE, trunked into the EVPN domain. Giving those port aggregates the same **ESI** (Ethernet Segment Identifier) tells the routers they are one Ethernet Segment. On router-a, with the CE on `eth1`:

```
lab-1> configure es
lab-1(es)> edit switching-profile sp-evpn
lab-1(es/switching-profile:sp-evpn)> set broadcast-domain bd100 tag untagged
lab-1(es/switching-profile:sp-evpn)> top
lab-1(es)> edit port-aggregate bond1
lab-1(es/port-aggregate:bond1)> set esi 00:11:22:33:44:55:66:77:88:99
lab-1(es/port-aggregate:bond1)> set switching-profile sp-evpn
lab-1(es/port-aggregate:bond1)> top
lab-1(es)> edit interface eth1
lab-1(es/interface:eth1)> set port-aggregate bond1
lab-1(es/interface:eth1)> top
lab-1(es)> commit
```

Over REST, the switching profile is the port aggregate's `switching-profile` field:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"sp-evpn"' \
   $B/v1/transactions/es/port-aggregate/bond1/switching-profile
```

Router-b gets the same configuration with the same ESI. The ESI is ten colon-separated hexadecimal bytes, not all zero, and unique per router: two port aggregates on one router cannot share it. The port aggregate can be static (`xor`) or LACP; with LACP, give both routers the same `lacp-system-id` so the CE sees one partner and bundles its links across them (see the port aggregation guide).

With the segment configured, `show fdb` lists it on each router, with its bond and its state:

```
lab-1> show fdb bd100
broadcast-domain bd100: vni 10100, bridge br1, vxlan vx10100
  ee:59:ae:e9:f1:74 remote via 10.50.0.3
  203.0.113.1 is at 42:46:27:6c:ba:fb local
  203.0.113.2 is at ee:59:ae:e9:f1:74 remote via 10.50.0.3
  flood list: 10.50.0.3
  ethernet-segment 00:11:22:33:44:55:66:77:88:99 on bond1: down, no carrier (PEs 10.50.0.2)
```

The state is one of:

- `down, no carrier`: the bond has no working link (as above, in a lab where `eth1` is not cabled). The router does not advertise the segment and is never its DF.
- `designated forwarder`: this router sends flooded traffic to the CE.
- `non-designated forwarder, BUM blocked`: another router is the DF; this one still forwards unicast.
- `non-designated forwarder, port blocked`: the same in a single-active segment, where nothing is forwarded.

`PEs` lists the routers attached to the segment, in election order, and `per-ES A-D from` the other routers whose segment route is held.

**All-active and single-active.** By default a segment is **all-active**: every router forwards unicast traffic to and from the CE, and only the designated forwarder (DF) sends it flooded traffic. The CE can then use a load-balancing bond (`balance-xor`, or LACP). Set **single-active** when only one router at a time may carry the CE's traffic:

```
lab-1(es)> set port-aggregate bond1 redundancy-mode single-active
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"SingleActive"' $B/v1/transactions/es/port-aggregate/bond1/redundancy-mode
```

Set the same mode on every router of the segment. The non-DF routers then block their port to the CE entirely, and the segment line in `show fdb` ends with `single-active`:

```
  ethernet-segment 00:11:22:33:44:55:66:77:88:99 on bond1: down, no carrier (PEs 10.50.0.2), single-active
```

`show config` shows the whole EVPN setup of a router:

```
broadcast-domain bd100: address [203.0.113.1/24], routing-table rt1, ospf-profile unset, vni 10100, rd 65001:100, rt-import [65000:10100], rt-export [65000:10100], vtep-source interface eth0, redistribute-mac r1, redistribute-arp r1, redistribute-connected r1
switching-profile sp-evpn: members [bd100: untagged]
port-aggregate bond1: mode Xor, switching-profile sp-evpn, mtu unset, esi 00:11:22:33:44:55:66:77:88:99, redundancy-mode single-active
``` The blocked port keeps its link up, so the CE cannot see which router to use from the link state: it needs a bond that checks the path end to end, such as a Linux `active-backup` bond with an ARP monitor.

### Route between subnets over EVPN (IP-VRF, Type 5)

A routing table can be an **IP-VRF** stretched over EVPN: each router advertises the table's routes as IP prefix routes (Type 5, RFC 9136) and installs the ones the others advertise, routing the traffic over one VXLAN tunnel per table, its **L3 VNI**. This is the "interface-less" symmetric model of RFC 9135 §4.4.1: no broadcast domain is needed, and the subnets behind each router can all differ.

Before you start:

- The routers already peer with `address-family l2vpn-evpn` (above), in the **underlay** routing table (`rt1`, BGP instance `r1`).
- The IP-VRF is another routing table (`tenant` below) with the interfaces of its subnets in it. Its own `bgp-instance`, if any, is not used for EVPN.
- `net.ipv4.udp_l3mdev_accept=1` is set (see [Before you start](#before-you-start)), and so is `net.ipv4.ip_forward=1`, since the router now routes the tenant's traffic.

On router-a, with the tenant subnet `198.18.1.0/24` on `eth1`:

```
lab-1> configure l3
lab-1(l3)> set interface eth1 address 198.18.1.2/24
lab-1(l3)> set interface eth1 routing-table tenant
lab-1(l3)> edit routing-table tenant
lab-1(l3/routing-table:tenant)> set evpn l3-vni 5000
lab-1(l3/routing-table:tenant)> set evpn rd 65001:5000
lab-1(l3/routing-table:tenant)> set evpn route-target import 65000:5000
lab-1(l3/routing-table:tenant)> set evpn route-target export 65000:5000
lab-1(l3/routing-table:tenant)> set evpn vtep-source interface eth0
lab-1(l3/routing-table:tenant)> set evpn bgp-instance r1
lab-1(l3/routing-table:tenant)> commit
```

On router-b, the same with its own subnet and `rd 65002:5000`. Over REST, write the table's `evpn` object in one `PUT`:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{
  "l3_vni": 5000, "rd": "65001:5000",
  "route_targets_import": ["65000:5000"], "route_targets_export": ["65000:5000"],
  "vtep_source": {"Interface": {"interface": "eth0", "label": null}},
  "bgp_instance": "r1"
}' $B/v1/transactions/l3/routing-table/tenant/evpn
```

What happens:

- The table's `nos-ribd` creates a bridge `brv<l3-vni>` in the table's VRF and a VXLAN device `vx<l3-vni>` on it. The bridge's MAC address is the router's **Router's MAC**.
- Every best route of the table (connected subnets included, EVPN-learned ones excluded) is advertised into `bgp-instance` as a Type 5 route carrying the RD, the export route targets, the VXLAN encapsulation and the Router's MAC (`rmac:` in `show bgp evpn`). The next hop is the `vtep-source` address.
- A received Type 5 route is installed when it carries an import route target, names the table's L3 VNI and carries a Router's MAC. It becomes a route `via <remote VTEP> dev brv<l3-vni> onlink`, with a neighbour entry for the VTEP at its Router's MAC and a forwarding entry sending that MAC into the tunnel.

Check it with `show route`:

```
lab-1> show route tenant
198.18.1.0/24
  * via 198.18.1.2 [connected]
198.18.2.0/24
  * via 10.50.0.3 rmac 0a:1b:2c:3d:4e:5f vni 5000 [evpn]
```

EVPN routes rank below static, BGP and OSPF routes for the same prefix. To remove the IP-VRF, delete its `evpn` fields in one transaction (validation happens at commit): `delete routing-table tenant evpn l3-vni`, `… evpn rd`, `… evpn vtep-source`, `… evpn bgp-instance` and `… evpn route-target import|export <rt>`, or `DELETE` the same paths over REST. Its routes are withdrawn and the two devices deleted.

The **asymmetric** model (RFC 9135 §4.1) needs nothing of this: give each router an address in the same broadcast domain (an SVI) and `redistribute from arp|connected`, and routing happens on the ingress router into the stretched domain.

### Turn EVPN off

- `delete broadcast domain <domain> vni` stops EVPN for the domain and removes its tunnel. The other EVPN settings must be removed first (or in the same transaction, since validation happens at commit): `delete broadcast domain <domain> redistribute from mac` (also `from arp`, `from connected`), `delete broadcast domain <domain> vtep-source`, `delete broadcast domain <domain> rd` and `delete broadcast domain <domain> route-target import|export <rt>`.
- `delete port-aggregate <name> esi` takes a bond out of its Ethernet Segment; flooding to it resumes at once.
- `delete bgp instance r1 peer-group pg1 address-family l2vpn-evpn` stops exchanging EVPN routes on that session.

Over REST, `DELETE` the same paths: `…/broadcast-domain/bd100/vni`, `…/mac-redistribute`, `…/vtep-source`, `…/rd`, `…/route-targets-import/65000:10100`, `…/port-aggregate/bond1/esi`.

## How EVPN behaves

### Routes a domain advertises

For each domain with `redistribute from mac`, a router advertises:

- one **Inclusive Multicast route (Type 3)** for the domain, from its tunnel address. Receiving routers add that address to the domain's flood list.
- one **MAC route (Type 2)** per MAC address its bridge has learned on a local port, and with `arp`/`connected` one MAC+IP route per neighbour entry or SVI address. MAC addresses the bridge learned from the tunnel are never re-advertised.
- for each Ethernet Segment attached to the domain whose bond has link: an **Ethernet Segment route (Type 4)**, and two **Ethernet A-D routes (Type 1)**, one for the segment and one for the domain.

All carry the domain's export route targets and the VXLAN encapsulation community, with the tunnel address as BGP next hop. They are advertised to every peer whose peer-group has `l2vpn-evpn`.

EVPN routes a router receives are used, never passed on to other peers. So EVPN does not go through a route reflector or route server built with NOS: each router must peer with every other router that has the domain, or with a reflector that is not NOS.

### MAC mobility

When a host moves from one router to another, both may briefly advertise its MAC address. NOS follows RFC 7432 §15: each advertisement carries a sequence number in a MAC Mobility community, the highest number wins (on a tie, the router with the lower tunnel address), and a router that learns the MAC locally again advertises it with a higher number than the one it saw, so a real move always wins over a stale copy. A MAC address that changes router more than 5 times within 3 minutes is treated as a duplicate: NOS keeps its last location and ignores further moves until it has been quiet for 3 minutes.

A MAC address behind a multi-homed Ethernet Segment is not a move: every router on the segment advertises it with the same ESI, and they all keep their advertisement and share one sequence number. Only an advertisement behind a different ESI (or a single-homed one, ESI 0) competes as above.

### The designated forwarder

Among the routers attached to one Ethernet Segment, one per domain is the designated forwarder: it alone delivers flooded traffic to the CE, so the CE never receives a copy through each router. The candidates are the routers that advertise the segment. When every one of them announces the AC-DF capability (RFC 8584; NOS always does), only those that also serve the domain are candidates; otherwise every router on the segment is, as in RFC 7432. By default (`df-algorithm modulo`, RFC 7432 §8.5) the candidates are ordered by tunnel address and the DF for a domain is candidate number `VNI mod <number of candidates>`. Two domains on the same segment can therefore have different DFs, which spreads the load.

`set port-aggregate <p> df-algorithm hrw` asks for RFC 8584's Highest Random Weight election instead: each candidate gets a pseudo-random weight from its tunnel address, the VNI and the ESI, and the highest weight wins, which spreads domains more evenly and moves fewer of them when a router joins or leaves. The choice is announced in the segment's Type 4 route (`df-election:hrw,ac-df` in `show bgp evpn` on the peer), and HRW is only used when every candidate asks for it; if any router asks for something else or announces nothing (most other implementations), every router falls back to modulo. `show fdb` ends the segment line with `df-algorithm hrw` while HRW is in effect. HRW needs IPv4 tunnel addresses. Changing the algorithm on a live segment re-elects at once, without the wait below.

A router that has just joined a segment, whether it just started, the ESI was just set or the bond just came up, waits 3 seconds before applying the election, blocked as a non-DF meanwhile. This gives it time to hear the other routers, so the CE never receives flooded traffic twice. The delay is a start-up option of the router (`--fdbd-arg=--df-wait=<seconds>` on `nos-watchdogd`), not configuration; see [System](system.md#start-up-options).

When a segment's bond loses its link, the router withdraws the segment's Type 4 and Type 1 routes, so the others re-elect without it. It rejoins, with the wait above, when the link returns.

### Traffic towards a segment this router is on

A CE's MAC address is often learned by only one of its routers: the CE sends on one link, the other router never sees it. Yet a remote router balances traffic over both (aliasing), so each must be able to deliver it:

- A MAC address another router advertises on one of this router's own segments is pinned to the segment's bond, as a static entry of the domain's bridge. `show fdb` lists it as `remote, on our esi <esi>`.
- It is pinned only while the bond can carry it: the bond has link, and in a single-active segment the router is the DF. Otherwise the MAC goes over the tunnel to the router that advertised it, like a MAC on a remote segment.
- A pinned MAC is not advertised until the CE sends through this router. From then on the router advertises it too, and stops when the CE has been silent for the bridge's ageing time (300 seconds).
- The bridge never learns MAC addresses from the tunnel: remote MACs come from EVPN routes only (RFC 7432 §9.2). A CE's broadcast that another router floods back here therefore cannot move the CE's MAC behind the tunnel.

### Failover and load sharing towards a remote segment

For a segment that is attached to other routers, not this one:

- A MAC address behind the segment is used only while the router that advertised it still advertises the segment's Type 1 route. When that router loses the segment, it withdraws one route and every one of its MAC addresses on the segment is dropped at once (mass withdrawal, RFC 7432 §8.2.1), instead of one by one.
- In an all-active segment served by several routers, traffic to a MAC address behind it is balanced across all of them, even those that did not advertise that MAC (aliasing, RFC 7432 §8.4). `show fdb` lists such a MAC as `remote via <router>, <router> (aliased)`. This applies to IPv4 tunnel addresses only.
- In a single-active segment, when the router that advertised a MAC address loses the segment, the MAC is moved to the next router that serves it (backup path).

### Limits

- There is no local bias (RFC 8365 §8.3.1). In an all-active segment, a non-DF router does not deliver flooded traffic to the CE even when it came from a host on the same router; it reaches the CE through the DF instead.
- A router only notices a segment failure when its own bond loses link. If a link fails only on the CE's side (a switch in between, say), the router keeps sending the CE's traffic into it. Run LACP between the CE and its routers so a dead link takes the bond down.
- Over VXLAN only, no MPLS. IP prefix routes (Type 5) work through a routing table's L3 VNI; symmetric IRB host routes (a MAC+IP route carrying the L3 VNI and Router's MAC) are not generated or installed.
- A Type 5 route is installed only in its interface-less form: one with a gateway IP or an ESI as overlay index (RFC 9136 §4.3) is ignored. Its prefix must be of the same family as the tunnel addresses, and when several routers advertise one prefix the one with the lowest tunnel address is used (no ECMP).
- Routing policies do not apply to EVPN routes.
- ARP suppression is not enabled: received MAC+IP routes are installed as neighbour entries, but ARP requests are still flooded.

How NOS programs VXLAN devices, forwarding entries and the DF on Linux is described in [`fdb/CLAUDE.md`](../../fdb/CLAUDE.md).

## Configuration reference

Broadcast domain EVPN fields. CLI forms are shown absolute; the relative form, valid after `edit broadcast domain <d>`, drops the `broadcast domain <d>` prefix (`set vni 10100`, `delete redistribute from mac`). REST paths are relative to `/v1/transactions/{tx}/broadcast-domain/{domain}/`. The domain's other fields (addresses, routing table, OSPF) are in the L2 switching guide.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| vni | `set broadcast domain <d> vni <n>` / `delete broadcast domain <d> vni` | `vni`, `10100` | 1-16777215, unset | none beyond the range; required by every field below | Creates the domain's VXLAN tunnel | `show fdb <d>` |
| rd | `set broadcast domain <d> rd <rd>` / `delete … rd` | `rd`, `"65001:100"` | `<asn>:<n>` or `<ipv4>:<n>`, unset | `<n>` fits 16 bits unless the ASN fits 16 bits; needs `vni` | Route distinguisher of every route the domain advertises | `show bgp evpn` on the peer |
| route-target import | `set broadcast domain <d> route-target import <rt>` / `delete … route-target import <rt>` | `route-targets-import/{rt}`, `"65000:10100"` (the list: `route-targets-import`, `["65000:10100"]`) | list of `<asn>:<n>` or `<ipv4>:<n>`, empty | valid format; needs `vni` | Received routes must carry one of these to be used | `show fdb <d>` |
| route-target export | `set broadcast domain <d> route-target export <rt>` / `delete … route-target export <rt>` | `route-targets-export/{rt}`, `"65000:10100"` | as above | as above | Attached to every route the domain advertises | `show bgp evpn` on the peer |
| vtep-source | `set broadcast domain <d> vtep-source interface <if> [label <l>]` or `… vtep-source loopback [label <l>]` / `delete … vtep-source` | `vtep-source`, `{"Interface":{"interface":"eth0","label":null}}` or `{"Loopback":{"label":null}}` | unset | needs `vni`; the address is resolved at run time, not checked at commit | Tunnel source address and BGP next hop | `show fdb <d>` on the peer (flood list) |
| redistribute from mac | `set broadcast domain <d> redistribute from mac to bgp <i>` / `delete … redistribute from mac` (or `delete … redistribute`) | `mac-redistribute`, `"r1"` | BGP instance, unset | instance exists; needs `vni`, `rd` and `vtep-source` | Advertises the domain and its MAC addresses into the instance, installs what it receives | `show bgp evpn` on the peer |
| redistribute from arp | `set broadcast domain <d> redistribute from arp to bgp <i>` / `delete … redistribute from arp` | `arp-redistribute`, `"r1"` | BGP instance, unset | same instance as `redistribute from mac`; needs `vni` | Adds MAC+IP routes for local neighbour entries | `show fdb <d>` on the peer |
| redistribute from connected | `set broadcast domain <d> redistribute from connected to bgp <i>` / `delete … redistribute from connected` | `connected-redistribute`, `"r1"` | BGP instance, unset | as above | Adds MAC+IP routes for the domain's own addresses | `show fdb <d>` on the peer |

Port aggregate Ethernet Segment fields. The relative forms (after `edit port-aggregate <name>`) drop the `port-aggregate <p>` prefix (`set esi <esi>`, `delete esi`, `set switching-profile <sp>`). REST paths are relative to `/v1/transactions/{tx}/port-aggregate/{name}/`. The other port aggregate fields are in the port aggregation guide.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| esi | `set port-aggregate <p> esi <esi>` / `delete port-aggregate <p> esi` | `esi`, `"00:11:22:33:44:55:66:77:88:99"` | ten hex bytes, colon-separated, unset | not all zero; not used by another port aggregate on the router | Makes the bond an Ethernet Segment: ESI on its MAC routes, Type 4 and Type 1 routes, DF election | `show fdb <d>` |
| redundancy-mode | `set port-aggregate <p> redundancy-mode all-active\|single-active` | `redundancy-mode`, `"AllActive"` or `"SingleActive"` | `all-active` | `single-active` needs an `esi` | Whether non-DF routers block only flooded traffic or the whole port | `show fdb <d>`, `show bgp evpn` on the peer |
| df-algorithm | `set port-aggregate <p> df-algorithm modulo\|hrw` | `df-algorithm`, `"Modulo"` or `"Hrw"` | `modulo` | `hrw` needs an `esi` | The DF election algorithm asked for; HRW only runs when every router on the segment asks for it | `show fdb <d>`, `show bgp evpn` on the peer |
| switching-profile | `set port-aggregate <p> switching-profile <sp>` / `delete port-aggregate <p> switching-profile` | `switching-profile`, `"sp-evpn"` | name, unset | profile exists | Trunks the bond into the profile's domains; a segment must be in the EVPN domain | `show port-aggregate <p>`, `show fdb <d>` |
| lacp-system-id | `set port-aggregate <p> lacp-system-id <mac>` / `delete … lacp-system-id` | `lacp-system-id`, `"02:00:00:00:00:01"` | unicast MAC, derived | unicast MAC | LACP actor system id; set it identically on every router of an LACP segment | `show lacp <p>` |

BGP peer-group address family:

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| address-family l2vpn-evpn | `set bgp instance <i> peer-group <g> address-family l2vpn-evpn` / `delete … address-family l2vpn-evpn` (relative: `set address-family l2vpn-evpn`) | `bgp-instance/{i}/peer-group/{g}/address-family/L2vpnEvpn`, `"L2vpnEvpn"` | list, `[ipv4]` | at least one family | Negotiates EVPN (AFI 25, SAFI 70) on the group's sessions | `show bgp evpn` |

Routing table EVPN (IP-VRF) fields. REST paths are relative to `/v1/transactions/{tx}/routing-table/{table}/evpn/`; the CLI forms are `set routing-table <t> evpn <field> …`, or `set evpn <field> …` after `edit routing-table <t>`.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| l3-vni | `set routing-table <t> evpn l3-vni <n>` / `delete … evpn l3-vni` | `l3-vni`, `5000` | 1-16777215, unset | not used by another table or broadcast domain; every field below needs it | Creates the L3 VNI devices and turns the table into an IP-VRF | `show route <t>` |
| rd | `set routing-table <t> evpn rd <rd>` | `rd`, `"65001:5000"` | `<asn>:<n>` or `<ipv4>:<n>`, unset | required with `l3-vni` | Route distinguisher of the table's Type 5 routes | `show bgp evpn` on the peer |
| route-target import | `set routing-table <t> evpn route-target import <rt>` | `route-targets-import/{rt}`, `"65000:5000"` | list, empty | valid format | Received Type 5 routes must carry one of these | `show route <t>` |
| route-target export | `set routing-table <t> evpn route-target export <rt>` | `route-targets-export/{rt}`, `"65000:5000"` | list, empty | at least one with `l3-vni` | Attached to every Type 5 route the table advertises | `show bgp evpn` on the peer |
| vtep-source | `set routing-table <t> evpn vtep-source interface <if> [label <l>]` or `… loopback [label <l>]` | `vtep-source`, `{"Interface":{"interface":"eth0","label":null}}` | unset | required with `l3-vni`; resolved at run time | Tunnel source and next hop; `loopback` is the loopback of the table owning `bgp-instance` | `show bgp evpn` on the peer |
| bgp-instance | `set routing-table <t> evpn bgp-instance <i>` | `bgp-instance`, `"r1"` | BGP instance, unset | exists; not the table's own `bgp-instance` | The underlay instance that carries the Type 5 routes | `show bgp evpn` |

The designated-forwarder wait (`--df-wait`, default 3 seconds) is a start-up option, described in [System](system.md#start-up-options).
