# OSPF (OSPFv2)

OSPF is the link-state interior gateway protocol for IPv4 (RFC 2328). NOS runs it per routing table: each OSPF instance discovers neighbours on the interfaces you attach it to, floods link-state advertisements (LSAs), computes shortest paths, and installs the resulting routes in its routing table. For IPv6, see [OSPFv3](ospfv3.md).

- [How OSPF is configured in NOS](#how-ospf-is-configured-in-nos)
- [Common operations](#common-operations)
  - [Run OSPF between two routers](#run-ospf-between-two-routers)
  - [Check neighbours, the LSDB and routes](#check-neighbours-the-lsdb-and-routes)
  - [Advertise a loopback](#advertise-a-loopback)
  - [Run OSPF on a LAN segment](#run-ospf-on-a-lan-segment)
  - [Authenticate a link, and change its key](#authenticate-a-link-and-change-its-key)
  - [Redistribute static routes (ASBR)](#redistribute-static-routes-asbr)
  - [Add a second area (ABR)](#add-a-second-area-abr)
  - [Restart without dropping routes (RFC 3623)](#restart-without-dropping-routes-rfc-3623)
  - [Stop running OSPF](#stop-running-ospf)
- [Features and behaviour](#features-and-behaviour)
- [Configuration reference](#configuration-reference)

The examples use the two-router lab described in the [README](../README.md#conventions-used-in-these-pages): router-a (10.50.0.2) and router-b (10.50.0.3) share `10.50.0.0/24` on `eth0`, which is in routing table `rt1`. The CLI sessions run on router-a. The REST calls make the same change on router-b, so that together the two blocks configure both ends of a link; for those calls `$B` points at router-b (`B=https://10.50.0.3:8080`) and `$C` uses a client certificate obtained from router-b, as shown in [The REST API](../api.md#getting-a-client-certificate).

Every CLI command and REST path on this page matches what the shell and the API accept, and each configuration follows one that the end-to-end test suite runs against real routers. The sample outputs are not reproduced here yet; see [The CLI](../cli.md#operational-commands) for the general shape of `show` output.

## How OSPF is configured in NOS

The configuration has three levels, plus the places you attach it:

- An **OSPF instance** (`ospf instance <name>`) has a router ID and belongs to one routing table: `set routing-table <table> ospf-instance <name>`. Until a routing table refers to it, the instance does nothing. A routing table has at most one OSPF instance, and an instance belongs to at most one table.
- An **area** (`area <area-id>`, dotted quad, `0.0.0.0` for the backbone) lives inside an instance.
- A **profile** (`profile <name>`) lives inside an area and holds the per-link settings: hello and dead intervals, cost, priority, network type, authentication and an MTU override. Profile names are unique across the whole configuration, not just within their area.
- You run OSPF on a link by **attaching a profile** to it by name. The link then joins the instance and area the profile is declared in. Three kinds of link take a profile:
  - a subinterface, such as `eth0.0` or `eth0.100`: `set interface eth0 ospf <profile>`. It runs as point-to-point by default.
  - a broadcast domain's own address (its SVI): `set ospf <profile>` inside `edit broadcast domain <name>`. It runs as a broadcast network, with a DR and BDR, by default.
  - a loopback, `loopback-<table>`: `set interface loopback-<table> ospf <profile>`. Its addresses are advertised as stub networks; no neighbour is ever formed on it.

  Each of these must also have `routing-table` set, to the table the instance belongs to.

OSPF routes appear in `show route` with the source `ospf`. When the same prefix is also known from another source, the other source wins: connected, then static, then BGP, then OSPF.

How the OSPF implementation works internally is described in [`ospf/CLAUDE.md`](../../ospf/CLAUDE.md).

## Common operations

### Run OSPF between two routers

This creates instance `o1` with router ID 1.1.1.1, a backbone area with profile `p1`, links the instance to `rt1`, and runs OSPF on `eth0.0`:

```
configure ospf1
edit ospf instance o1
set router-id 1.1.1.1
edit area 0.0.0.0
edit profile p1
set hello-interval 10
set dead-interval 40
top
set routing-table rt1 ospf-instance o1
set interface eth0 ospf p1
diff
commit
```

`edit` creates the instance, area and profile as it moves into them. The hello and dead intervals shown are the defaults and can be left out; they are set here to show where they go. `set interface eth0 ospf p1` means the untagged subinterface, `eth0.0`, which already has an address and `routing-table rt1`.

Over REST, the instance is created whole, then linked and attached. This configures router-b, with router ID 2.2.2.2 and the same profile:

```sh
$C -X POST $B/v1/transactions/ospf1
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"o1","router_id":"2.2.2.2","areas":[{"area_id":"0.0.0.0","profiles":[{"name":"p1","hello_interval":10,"dead_interval":40}]}]}' \
  $B/v1/transactions/ospf1/ospf-instance/o1
$C -X PUT -H 'Content-Type: application/json' -d '"o1"' $B/v1/transactions/ospf1/routing-table/rt1/ospf-instance
$C -X PUT -H 'Content-Type: application/json' -d '"p1"' $B/v1/transactions/ospf1/interface/eth0/subinterface/0/ospf-profile
$C -X POST $B/v1/transactions/ospf1/commit
```

Within a few seconds both routers reach `Full`.

### Check neighbours, the LSDB and routes

```
show ospf neigh
show ospf database
show route rt1
```

- `show ospf neigh` prints one line per link and neighbour: the link, its area, the link's state (`point-to-point`, or `dr`/`backup`/`dr-other`/`waiting` on a LAN), the neighbour's router ID and state (`Init`, `2-Way`, `ExStart`, `Exchange`, `Loading`, `Full`), when its last Hello arrived, the timers and priorities, and the DR and BDR.
- `show ospf database` lists the header of every LSA held, per area: its type (1 router, 2 network, 3 summary, 4 ASBR summary, 5 AS-external), link-state ID, advertising router, sequence number, age and checksum.
- Both cover every OSPF instance on the router.

Over REST, `GET /v1/ospf/neighbors` and `GET /v1/ospf/database` return the same data as JSON, one entry per instance:

```sh
$C $B/v1/ospf/neighbors | jq .
$C $B/v1/ospf/database | jq .
$C $B/v1/routes/rt1
```

### Advertise a loopback

A loopback is named after its routing table, `loopback-<table>`. Give it an address, put it in the table, and attach a profile; its address is then advertised to the whole area.

```
configure lo
edit interface loopback-rt1
set routing-table rt1
set address 192.0.2.1/32
set ospf p1
commit
```

The same on router-b, with 192.0.2.2/32, over REST:

```sh
$C -X POST $B/v1/transactions/lo
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"loopback-rt1","addresses":[{"address":"192.0.2.2/32","label":null}],"routing_table":"rt1","ospf_profile":"p1","subinterfaces":[]}' \
  $B/v1/transactions/lo/interface/loopback-rt1
$C -X POST $B/v1/transactions/lo/commit
```

Each router now reaches the other's loopback through OSPF, with source `ospf`:

```
show route rt1 192.0.2.2            (on router-a)
$C $B/v1/routes/rt1/192.0.2.1       (on router-b)
```

### Run OSPF on a LAN segment

On a multi-access segment, OSPF elects a designated router (DR) and a backup (BDR), and every router forms a full adjacency only with those two. In NOS a LAN segment is a broadcast domain, and OSPF runs on the broadcast domain's own address (its SVI; see [L2 switching](../README.md#per-protocol-guides)). Here `eth0` carries broadcast domain `bd1` tagged with VLAN 400, the domain's SVI gets an address in `rt1`, and profile `p-lan` gives router-a priority 10 so it becomes the DR:

```
configure lan
edit ospf instance o1 area 0.0.0.0 profile p-lan
set priority 10
top
edit broadcast domain bd1
set address 203.0.113.1/24
set routing-table rt1
set ospf p-lan
top
edit switching-profile sp1
top
set switching-profile sp1 broadcast-domain bd1 tag dot1q 400
set interface eth0 switching-profile sp1
commit
```

Router-b does the same with the default priority of 1 and SVI address 203.0.113.2/24:

```sh
$C -X POST $B/v1/transactions/lan
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"p-lan"}' \
  $B/v1/transactions/lan/ospf-instance/o1/area/0.0.0.0/profile/p-lan
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"bd1","addresses":[{"address":"203.0.113.2/24","label":null}],"routing_table":"rt1","ospf_profile":"p-lan"}' \
  $B/v1/transactions/lan/broadcast-domain/bd1
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"sp1","members":[{"broadcast_domain":"bd1","tag":{"Dot1q":400}}]}' \
  $B/v1/transactions/lan/switching-profile/sp1
$C -X PUT -H 'Content-Type: application/json' -d '"sp1"' $B/v1/transactions/lan/interface/eth0/switching-profile
$C -X POST $B/v1/transactions/lan/commit
```

After the wait interval (the dead interval, 40 seconds by default), the election settles. `show ospf neigh` then shows `bd1` with link state `dr` on router-a and `backup` on router-b, and both neighbours `Full`:

```
show ospf neigh
```

A profile's network type follows the link by default: point-to-point on a subinterface, broadcast on a broadcast domain. `set network-type point-to-point|broadcast` in the profile forces either one on every link that uses it.

### Authenticate a link, and change its key

Authentication is set on the profile, so it applies to every link using that profile, and both ends must match. HMAC-SHA keys (RFC 5709) are the usual choice:

```
configure auth
edit ospf instance o1 area 0.0.0.0 profile p1
set crypto-key 1 hmac-sha256 s3cret-one
set crypto-key 1 current
show this
commit
```

A key has a key ID (0 to 255), an algorithm (`md5`, `hmac-sha1`, `hmac-sha256`, `hmac-sha384` or `hmac-sha512`) and a secret of 1 to 80 bytes. Exactly one key must be `current`: it signs what the router sends. Every configured key is accepted on receive. The same on router-b over REST, where `auth` is replaced whole:

```sh
$C -X POST $B/v1/transactions/auth
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"Crypto":{"keys":[{"key_id":1,"algorithm":"HmacSha256","key":"s3cret-one","is_current":true}]}}' \
  $B/v1/transactions/auth/ospf-instance/o1/area/0.0.0.0/profile/p1/auth
$C -X POST $B/v1/transactions/auth/commit
```

To change the key without dropping the adjacency, do it in three commits, on both routers each time: add the new key; once both have it, make it current; once both use it, delete the old one.

```
configure roll1
set ospf instance o1 area 0.0.0.0 profile p1 crypto-key 2 hmac-sha256 s3cret-two
commit
configure roll2
set ospf instance o1 area 0.0.0.0 profile p1 crypto-key 2 current
commit
configure roll3
edit ospf instance o1 area 0.0.0.0 profile p1
delete crypto-key 1
commit
```

Over REST, the same three steps are three `PUT`s of the whole `auth` value (both keys with key 1 current, both keys with key 2 current, then key 2 alone).

**Replay protection across restarts (RFC 7474).** With ordinary crypto authentication, a packet captured before a router restarts could be replayed after it. `set extended-sequence-numbers enable` in the profile switches to RFC 7474 authentication: the sequence number includes a boot counter kept on disk, and the digest also covers the sender's address. It needs crypto keys that are all HMAC-SHA (not MD5), and both ends must enable it: a router using it and one not using it do not accept each other's packets. It also allows key IDs above 255 (up to 65535).

```
configure ext
set ospf instance o1 area 0.0.0.0 profile p1 extended-sequence-numbers enable
commit
```

```sh
$C -X POST $B/v1/transactions/ext
$C -X PUT -H 'Content-Type: application/json' -d 'true' \
  $B/v1/transactions/ext/ospf-instance/o1/area/0.0.0.0/profile/p1/extended-sequence-numbers
$C -X POST $B/v1/transactions/ext/commit
```

The other two authentication modes are a plain-text password of up to 8 bytes (`set simple-password <password>`), which only protects against misconfiguration, and none (`delete auth`), the default.

### Redistribute static routes (ASBR)

`redistribute from static to ospf` on a routing table advertises the table's static routes into its OSPF instance, which makes this router an AS boundary router (ASBR). The table needs both a static routing instance and an OSPF instance:

```
configure asbr
edit static-routing-instance s1
set route 198.51.100.0/24 gateway 10.50.0.98
top
set routing-table rt1 static-routing-instance s1
set routing-table rt1 redistribute from static to ospf
commit
```

Router-b receives an AS-external LSA (type 5) and installs the route, which you can check on router-b with:

```
show ospf database          (look for type 5, advertising-router 1.1.1.1)
show route rt1 198.51.100.1
```

The REST equivalent of the redistribute rule, in a transaction `asbr` opened and committed as in the earlier examples (the static routing instance is created the same way as in [The REST API](../api.md#changing-configuration-transactions)):

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"from":"Static","to":"Ospf","policy":null}' \
  $B/v1/transactions/asbr/routing-table/rt1/redistribute
```

Add `policy <name>` to the command (`"policy": "<name>"` in the JSON) to filter what is redistributed through a routing policy; without it, every static route is redistributed. See [Routing policy](../README.md#per-protocol-guides). Deleting the rule (`delete routing-table rt1 redistribute`) withdraws the routes from the other routers within about 15 seconds.

A routing table has only one `redistribute` rule, so it redistributes static routes into BGP or into OSPF, not both.

### Add a second area (ABR)

A router attached to two or more areas is an area border router (ABR): it advertises each area's prefixes into the others as summary LSAs (type 3). There is no switch to turn this on; declaring a second area and attaching a profile from it is enough. Here router-a's loopback moves into area 0.0.0.1, while `eth0.0` stays in the backbone:

```
configure abr
edit ospf instance o1 area 0.0.0.1 profile p-area1
top
set interface loopback-rt1 ospf p-area1
commit
```

Router-b, which is only in the backbone, now learns 192.0.2.1/32 from router-a's summary LSA. On router-b:

```
show ospf database          (look for type 3, link-state-id 192.0.2.1, advertising-router 1.1.1.1)
show route rt1 192.0.2.1
```

Over REST, in a transaction `abr`, the new area is one `PUT` and the loopback's profile another:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"area_id":"0.0.0.1","profiles":[{"name":"p-area1"}]}' \
  $B/v1/transactions/abr/ospf-instance/o1/area/0.0.0.1
$C -X PUT -H 'Content-Type: application/json' -d '"p-area1"' \
  $B/v1/transactions/abr/interface/loopback-rt1/ospf-profile
```

### Restart without dropping routes (RFC 3623)

Set a grace period on the instance so that its neighbours keep the adjacency and this router's routes while its OSPF daemon restarts:

```
configure gr
set ospf instance o1 graceful-restart grace-period 120
commit
```

```sh
$C -X POST $B/v1/transactions/gr
$C -X PUT -H 'Content-Type: application/json' -d '120' $B/v1/transactions/gr/ospf-instance/o1/graceful-restart-grace-period
$C -X POST $B/v1/transactions/gr/commit
```

How it behaves:

- **Restarting router.** Only a planned restart announces a grace period: `nos-ospfd` receiving SIGTERM sends a Grace-LSA to every Full neighbour on every link (log `ospf graceful restart: grace-lsa sent`), keeps the LSAs it originated instead of withdrawing them, then exits and is restarted by the watchdog. Stopping the router or removing the instance (SIGINT) announces nothing and withdraws the LSAs as usual. A crash announces nothing either.
- **Helping neighbour.** Every OSPF instance helps; there is nothing to enable. On a Grace-LSA from a Full neighbour it logs `ospf helper: grace period entered`, keeps that neighbour Full through missing Hellos and through Hellos that don't list it yet, keeps the neighbour's LSAs (and, as DR, keeps it in the network LSA), so its routes stay installed. The Grace-LSA is acknowledged but never stored or passed on.
- **End of the grace period.** When the restarted router's adjacency is Full again, the helper logs `ospf helper: neighbor reformed, exiting grace early`. If it never comes back, the helper logs `ospf helper: grace period expired` and the ordinary dead interval applies from then on.
- **Between NOS routers only, for now.** The Grace-LSA is an opaque LSA, and NOS does not yet advertise opaque-LSA support (the O bit), so other vendors' routers do not send or accept it.
- `delete ospf instance o1 graceful-restart grace-period` turns it off.

### Stop running OSPF

- On one link: `delete interface eth0 ospf` (or `delete ospf` inside the interface, subinterface or broadcast domain). Over REST, `DELETE …/interface/eth0/subinterface/0/ospf-profile`.
- For the whole routing table: `delete routing-table rt1 ospf-instance`. The instance stays configured but stops running.
- Entirely: `delete ospf instance o1`, after removing every reference to it and to its profiles, or the commit is refused.

When OSPF stops cleanly (and no [graceful restart](#restart-without-dropping-routes-rfc-3623) was announced), the router first withdraws the LSAs it originated, so its neighbours remove its routes within seconds instead of waiting for them to age out.

## Features and behaviour

**Neighbours and adjacencies (RFC 2328 §10).** Hellos are sent every hello interval to 224.0.0.5. A Hello whose hello interval or dead interval differs from the local profile's is dropped, so a timer mismatch shows up as a neighbour that never appears, and the log says `dropping ospf hello with mismatched hello-interval` (or `dead-interval`). A neighbour that sends no Hello for the dead interval is removed. On a point-to-point link the two routers always form a full adjacency. On a LAN, every router forms a full adjacency with the DR and the BDR only; two routers that are neither stay at `2-Way`, which is normal.

**DR/BDR election (RFC 2328 §9.4).** The highest priority wins, then the highest router ID. A router with priority 0 never becomes DR or BDR. An elected DR keeps its role when a router with a higher priority or router ID joins later; the newcomer takes over only if the DR goes away. Priority has no effect on point-to-point links.

**Shortest paths and costs (RFC 2328 §16).** Each link's cost is the `cost` of its profile (1 by default); a route's metric is the sum of the costs along the path. When the LSDB changes, routes are recomputed and the routing table is updated within a few seconds. Routes are installed with source `ospf`, and their metric is what BGP uses as the IGP cost to a next hop.

**Equal-cost multipath (RFC 2328 §16.1).** When a destination is reachable over several paths with the same lowest metric, NOS keeps all of their next hops and installs one multipath kernel route; the kernel spreads flows across them. It is automatic, with no configuration. `show route` lists every next hop: `* via 203.0.113.2, 203.0.113.6 [ospf]`. A next hop whose link goes down stays in the multipath route until OSPF reconverges (the kernel keeps it unless `ignore_routes_with_linkdown` is set).

**Loop-free alternates (RFC 5286).** For each OSPF route, NOS also looks for a backup next hop through another neighbour (not one of the route's own next hops) whose own shortest path to the destination does not come back through this router. If there is one, it is installed in the kernel alongside the primary, at a worse metric, so traffic moves to it as soon as the primary next hop is withdrawn. It is computed automatically, with no configuration. `show route` shows it after the primary: `* via 203.0.113.2 [ospf] backup 203.0.113.3`. Only link protection is provided (no node protection and no remote LFA).

**Authentication (RFC 2328 Appendix D, RFC 5709, RFC 7474).** Described [above](#authenticate-a-link-and-change-its-key). A packet that fails authentication is dropped and logged (`ospf packet authentication failed`). A replayed or out-of-order packet (a sequence number that does not increase) is dropped and logged too.

**AS-external routes (ASBR).** Each redistributed static route becomes one type-5 LSA, flooded to every area the router is in. Other routers compute the route's metric as their distance to the ASBR plus 20. Only static routes can be redistributed, and every external route is metric type 1; there is no metric-type or per-route metric setting, and the forwarding address is always 0.0.0.0.

**Inter-area routes (ABR).** Each prefix of an area is advertised into the router's other areas as its own type-3 LSA, and each ASBR as a type-4 LSA. There is no range summarisation, no stub or NSSA area, and no virtual link. This is designed and tested for one or more non-backbone areas each behind its own ABR; in topologies where several ABRs connect the same areas, check the result.

**LSA ageing and withdrawal (RFC 2328 §14).** Self-originated LSAs are refreshed every 30 minutes and others expire after an hour without refresh. An LSA that is no longer wanted (a removed link, redistribution rule or area) is withdrawn at once by flooding it at maximum age.

**MTU and database exchange (RFC 2328 §10.6–10.8).** During the database exchange, the list of LSAs is split over as many packets as the link's MTU requires. The MTU used is the link's real MTU, unless the profile sets `mtu`. The MTU that a neighbour advertises is not checked against the local one, so an MTU mismatch does not block an adjacency.

**Not supported:** NSSA and stub areas, virtual links, area range summarisation, metric-type 2 external routes, redistribution of anything other than static routes, graceful restart with routers other than NOS (opaque LSAs), the restarting router's own RFC 3623 restart mode (it resynchronises from scratch while its neighbours help) and strict LSA checking in the helper, BFD, and the non-broadcast network types (NBMA and point-to-multipoint).

## Configuration reference

All paths are relative to `/v1/transactions/{tx}/`. `delete` forms marked *relative only* exist only inside the object (after `edit`), not as an absolute command. The REST equivalent of a `delete` is `DELETE` on the same path, and of `set` a `PUT` on it.

### OSPF instance

| Field | CLI | Config-tree path | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit ospf instance <name>`; `delete ospf instance <name>` | `ospf-instance/<name>` | string, 1 to 64 characters | unique among OSPF instances | names the instance | `show config` |
| router ID | `set ospf instance <name> router-id <ip>`; relative `set router-id <ip>` | `ospf-instance/<name>/router-id` | IPv4 address; `0.0.0.0` when created by `edit` | set it: it identifies the router in every LSA | router ID in Hellos and LSAs | `show ospf neigh` on the neighbour |
| graceful restart | `set ospf instance <name> graceful-restart grace-period <seconds>`; `delete ospf instance <name> graceful-restart grace-period` | `ospf-instance/<name>/graceful-restart-grace-period` | seconds, 1 to 1800; unset by default | | on SIGTERM, ask Full neighbours to keep the adjacency and routes this long (RFC 3623) | `ospf helper: grace period entered` in the neighbour's log |
| areas | `edit ospf instance <name> area <area-id>`; relative `edit area <area-id>` | `ospf-instance/<name>/area/<area-id>` | list of areas | area IDs unique within the instance | see [Area](#area) | `show config` |
| routing table | set on the table: `set routing-table <table> ospf-instance <name>`; `delete routing-table <table> ospf-instance` | `routing-table/<table>/ospf-instance` | instance name; unset by default | the instance must exist; one table per instance | runs the instance in that table's VRF and installs its routes there | `show ospf neigh`, `show route <table>` |

The instance's JSON also carries `routing_table` and `redistribute_policy`. They are filled in by the router from the routing table's settings, are read-only, and any value you send is replaced at commit.

### Area

| Field | CLI | Config-tree path | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| area ID | `edit ospf instance <name> area <area-id>`; `delete ospf instance <name> area <area-id>`; relative `edit area <area-id>` / `delete area <area-id>` | `ospf-instance/<name>/area/<area-id>` | dotted quad; `0.0.0.0` is the backbone | unique within the instance | groups the profiles, and so the links, of one area; deleting an area deletes its profiles | `show ospf neigh` (area column) |
| profiles | `edit ospf instance <name> area <area-id> profile <profile>`; relative `edit profile <profile>` | `…/area/<area-id>/profile/<profile>` | list of profiles | see [Profile](#profile) | | |

### Profile

Absolute forms start with `set ospf instance <name> area <area-id> profile <profile>`, written `set … profile <p>` below. Relative forms work inside the profile.

| Field | CLI | Config-tree path (under `ospf-instance/<name>/area/<area-id>/profile/<p>/`) | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit … profile <p>`; `delete ospf instance <name> area <area-id> profile <p>`; relative `delete profile <p>` | (the profile itself) | string, 1 to 64 characters | unique across all OSPF profiles in the config; deleting a profile that a link still uses is refused at commit | the name links attach to | `show config` |
| hello interval | `set … profile <p> hello-interval <s>`; relative `set hello-interval <s>` / `delete hello-interval` *(relative only)* | `hello-interval` | integer seconds, 0 to 65535; default 10 | if both are set, dead interval must be greater | interval between Hellos; must match the neighbour's | `show ospf neigh` |
| dead interval | `set … profile <p> dead-interval <s>`; relative `set dead-interval <s>` / `delete dead-interval` *(relative only)* | `dead-interval` | integer seconds, 0 to 65535; default 40 | greater than the hello interval when both are set | how long a silent neighbour is kept; must match the neighbour's; also the LAN wait time before the first election | `show ospf neigh` |
| cost | `set … profile <p> cost <n>`; relative `set cost <n>` / `delete cost` *(relative only)* | `cost` | integer 1 to 65535; default 1 | 0 is refused | cost of the link in SPF | `show route <table>` on other routers, `GET /v1/routes/{table}` |
| priority | `set … profile <p> priority <n>`; relative `set priority <n>` / `delete priority` *(relative only)* | `priority` | integer 0 to 255; default 1 | | DR/BDR election; 0 never becomes DR or BDR; no effect on point-to-point | `show ospf neigh` |
| MTU | `set … profile <p> mtu <bytes>`; relative `set mtu <bytes>` / `delete mtu` *(relative only)* | `mtu` | integer 0 to 65535; default: the link's own MTU (1500 if unknown) | | MTU advertised in database-description packets and used to size them; the interface's real MTU is not changed | `GET …/profile/<p>/mtu` |
| network type | `set … profile <p> network-type point-to-point\|broadcast`; relative `set network-type …` / `delete network-type` *(relative only)* | `network-type`, `"PointToPoint"` or `"Broadcast"` | default: point-to-point on a subinterface or loopback, broadcast on a broadcast domain | | forces the network type on every link using the profile | `show ospf neigh` (link state) |
| simple password | `set … profile <p> simple-password <password>`; relative `set simple-password <password>` | `auth`, `{"Simple":{"password":"…"}}` | 1 to 8 bytes; replaces any crypto keys | | RFC 2328 plain-text authentication; stored and shown in clear | `show this` in the profile |
| crypto key | `set … profile <p> crypto-key <id> <algorithm> <key>`; relative `set crypto-key <id> <algorithm> <key>` / `delete crypto-key <id>` *(relative only)* | `auth`, `{"Crypto":{"keys":[{"key_id":1,"algorithm":"HmacSha256","key":"…","is_current":true}]}}` | ID 0 to 255 (up to 65535 with extended sequence numbers); algorithm `md5`, `hmac-sha1`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512` (`Md5`, `HmacSha1`, … in JSON); key 1 to 80 bytes | key IDs unique; at least one key; exactly one current | adds or replaces one key; a new key list replaces a simple password | `show this` in the profile |
| current key | `set … profile <p> crypto-key <id> current`; relative `set crypto-key <id> current` | `is_current` of each key | exactly one key | the key must exist | the key that signs sent packets; all keys verify | `show this` in the profile |
| no authentication | relative `delete auth` *(relative only)* | `DELETE …/auth` | default | | no authentication | `show this` in the profile |
| extended sequence numbers | `set … profile <p> extended-sequence-numbers enable\|disable`; relative the same | `extended-sequence-numbers` | boolean; default `false` | needs crypto authentication with HMAC-SHA keys only | RFC 7474 authentication, protecting against replay across restarts; both ends must agree | `show this` in the profile |

`show this` and `show config` show a profile's name and authentication only. To see its timers, cost, priority, MTU and network type, use `GET` on the profile path, or `diff` right after changing them.

### Where a profile is attached

| Attach point | CLI | Config-tree path | Validation | Effect |
|---|---|---|---|---|
| subinterface | `set interface <if>[.<tag>] ospf <profile>`; `delete interface <if>[.<tag>] ospf`; relative `set ospf <profile>` / `delete ospf` inside `edit interface <if>.<tag>` | `interface/<if>/subinterface/<tag>/ospf-profile` | the profile must exist; the subinterface must have `routing-table` set | runs OSPF on the subinterface, point-to-point by default |
| loopback | `set interface loopback-<table> ospf <profile>`; `delete interface loopback-<table> ospf` | `interface/loopback-<table>/ospf-profile` | as above, on the loopback | advertises the loopback's addresses as stub networks |
| broadcast domain | relative only: `set ospf <profile>` / `delete ospf` inside `edit broadcast domain <name>` | `broadcast-domain/<name>/ospf-profile` | as above, on the broadcast domain | runs OSPF on the domain's SVI, broadcast by default, with DR/BDR election |

A physical interface such as `eth0` never takes a profile itself; `set interface eth0 ospf …` means its subinterface `eth0.0`.

### Redistribution into OSPF

| Field | CLI | Config-tree path | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| redistribute | `set routing-table <table> redistribute from static to ospf [policy <policy>]`; `delete routing-table <table> redistribute`; relative `set redistribute from static to ospf [policy <policy>]` / `delete redistribute` | `routing-table/<table>/redistribute`, `{"from":"Static","to":"Ospf","policy":null}` | unset by default; without a policy, everything is redistributed | the table needs both `static-routing-instance` and `ospf-instance`; the policy must exist | advertises the table's static routes as AS-external LSAs | `show ospf database` (type 5) on other routers |
