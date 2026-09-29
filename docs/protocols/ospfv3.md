# OSPFv3

OSPFv3 (RFC 5340) is OSPF for IPv6. It works like [OSPFv2](ospf.md) and is configured the same way: an instance in a routing table, areas, profiles, and profiles attached to links. This page covers what is different and what is not supported yet; read the [OSPF page](ospf.md) first.

- [How OSPFv3 is configured](#how-ospfv3-is-configured)
- [Common operations](#common-operations)
  - [Run OSPFv3 between two routers](#run-ospfv3-between-two-routers)
  - [Check neighbours, the LSDB and routes](#check-neighbours-the-lsdb-and-routes)
  - [Advertise a loopback](#advertise-a-loopback)
  - [Authenticate a link (RFC 7166)](#authenticate-a-link-rfc-7166)
  - [Use extended LSAs (RFC 8362)](#use-extended-lsas-rfc-8362)
- [Features and behaviour](#features-and-behaviour)
- [Not supported yet](#not-supported-yet)
- [Configuration reference](#configuration-reference)

As on the OSPF page, the CLI sessions run on router-a and the REST calls make the same change on router-b (`B=https://10.50.0.3:8080`, with a certificate from router-b). As on that page, the commands and paths match what the router accepts and follow configurations the end-to-end tests run, but sample outputs are not reproduced here yet.

## How OSPFv3 is configured

The model is the same as OSPFv2's, with `ospfv3` in place of `ospf` in every command and path:

- an **instance**, `ospfv3 instance <name>`, with a router ID (a dotted quad, as in OSPFv2) and linked to one routing table with `set routing-table <table> ospfv3-instance <name>`;
- **areas**, `area <area-id>`, inside it;
- **profiles**, `profile <name>`, inside an area, holding the per-link settings;
- a profile **attached** to a subinterface (`set interface eth0 ospfv3 <profile>`), a loopback (`set interface loopback-<table> ospfv3 <profile>`) or a broadcast domain (`set ospfv3 <profile>` inside `edit broadcast domain <name>`). The attach point must have `routing-table` set.

OSPFv2 and OSPFv3 are independent. One routing table can have both an `ospf-instance` and an `ospfv3-instance`, and one link can carry both an `ospf` and an `ospfv3` profile. OSPFv3 profile names are unique among OSPFv3 profiles, separately from OSPFv2's.

A link needs an IPv6 address to be advertised. Neighbours talk over IPv6 link-local addresses, which the kernel creates for every interface, so the next hops of OSPFv3 routes are link-local addresses.

How the OSPFv3 implementation works internally is described in [`ospfv3/CLAUDE.md`](../../ospfv3/CLAUDE.md).

## Common operations

### Run OSPFv3 between two routers

This gives `eth0.0` an IPv6 address, creates instance `v3` with profile `p6` in the backbone, links it to `rt1` and attaches it to `eth0.0`:

```
configure v3
set interface eth0 address 2001:db8:1::1/64
edit ospfv3 instance v3
set router-id 1.1.1.1
edit area 0.0.0.0
edit profile p6
top
set routing-table rt1 ospfv3-instance v3
set interface eth0 ospfv3 p6
commit
```

The same on router-b over REST, with router ID 2.2.2.2 and address 2001:db8:1::2/64:

```sh
$C -X POST $B/v1/transactions/v3
$C -X PUT -H 'Content-Type: application/json' -d '{"address":"2001:db8:1::2/64","label":null}' \
  $B/v1/transactions/v3/interface/eth0/subinterface/0/address/2001:db8:1::2%2F64
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"v3","router_id":"2.2.2.2","areas":[{"area_id":"0.0.0.0","profiles":[{"name":"p6"}]}]}' \
  $B/v1/transactions/v3/ospfv3-instance/v3
$C -X PUT -H 'Content-Type: application/json' -d '"v3"' $B/v1/transactions/v3/routing-table/rt1/ospfv3-instance
$C -X PUT -H 'Content-Type: application/json' -d '"p6"' $B/v1/transactions/v3/interface/eth0/subinterface/0/ospfv3-profile
$C -X POST $B/v1/transactions/v3/commit
```

### Check neighbours, the LSDB and routes

`show ospfv3 neigh` and `show ospfv3 database` work like their OSPF counterparts (`GET /v1/ospfv3/neighbors` and `GET /v1/ospfv3/database` over REST):

```
show ospfv3 neigh
show ospfv3 database
```

The `type` column holds OSPFv3's LS type codes (RFC 5340 and RFC 8362): `0x2001` router, `0x2002` network, `0x2003` inter-area prefix, `0x0008` link, `0x2009` intra-area prefix, and, in extended mode, `0xa021` E-Router, `0x8028` E-Link and `0xa029` E-Intra-Area-Prefix. Link LSAs are only valid on their own link, so the database also shows which link each one belongs to.

### Advertise a loopback

```
configure v3lo
edit interface loopback-rt1
set routing-table rt1
set address 2001:db8:2::1/128
set ospfv3 p6
commit
```

Router-b learns the loopback with router-a's link-local address as the next hop:


```
$C $B/v1/routes/rt1/2001:db8:2::1     (on router-b)
```

The REST equivalent on router-b adds an address to its loopback and attaches the profile:

```sh
$C -X POST $B/v1/transactions/v3lo
$C -X PUT -H 'Content-Type: application/json' -d '{"address":"2001:db8:4::1/128","label":null}' \
  $B/v1/transactions/v3lo/interface/loopback-rt1/address/2001:db8:4::1%2F128
$C -X PUT -H 'Content-Type: application/json' -d '"p6"' $B/v1/transactions/v3lo/interface/loopback-rt1/ospfv3-profile
$C -X POST $B/v1/transactions/v3lo/commit
```

### Authenticate a link (RFC 7166)

OSPFv3 authenticates with an authentication trailer appended to each packet. The commands are the same as OSPFv2's crypto keys, with two differences: only the HMAC-SHA algorithms are accepted (no `md5`, and no simple password), and the key ID is the RFC 7166 security association ID, from 0 to 65535. Rolling to a new key works the same way as in OSPFv2: add it, make it current, delete the old one.

```
configure v3auth
edit ospfv3 instance v3 area 0.0.0.0 profile p6
set crypto-key 300 hmac-sha256 v3-secret
set crypto-key 300 current
commit
```

Over REST, `auth` is the list of keys itself, without the `Crypto` wrapper OSPFv2 uses:

```sh
$C -X POST $B/v1/transactions/v3auth
$C -X PUT -H 'Content-Type: application/json' \
  -d '[{"key_id":300,"algorithm":"HmacSha256","key":"v3-secret","is_current":true}]' \
  $B/v1/transactions/v3auth/ospfv3-instance/v3/area/0.0.0.0/profile/p6/auth
$C -X POST $B/v1/transactions/v3auth/commit
```

There is no equivalent of OSPFv2's `extended-sequence-numbers`.

### Use extended LSAs (RFC 8362)

`set ospfv3 instance <name> extended-lsa` makes the instance originate the TLV-based extended LSAs of RFC 8362 ("full" mode) instead of the RFC 5340 ones. It also understands extended LSAs from its neighbours either way. `delete ospfv3 instance <name> extended-lsa` goes back to the RFC 5340 LSAs.

```
configure v3ext
set ospfv3 instance v3 extended-lsa
commit
```

```sh
$C -X POST $B/v1/transactions/v3ext
$C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/v3ext/ospfv3-instance/v3/extended-lsa
$C -X POST $B/v1/transactions/v3ext/commit
```

RFC 8362 intends full mode to be enabled on every router of an area at once, and that is how it has been tested in NOS; running an area with some routers in each mode is not tested.

## Features and behaviour

Neighbour discovery, DR/BDR election, timers, costs, network types, the MTU override and database exchange, LSA ageing and withdrawal, and loop-free alternates behave as in [OSPF](ospf.md#features-and-behaviour). The differences:

- **IPv6 only.** Only IPv6 prefixes are advertised, and neighbours are reached through their link-local addresses. On a link with several IPv6 addresses, only the first one is advertised.
- **Loop-free alternates.** The backup next hop is a link-local address too, and may leave through a different interface from the primary; it is installed with its own interface, at a worse metric than the primary.
- **Authentication** is RFC 7166's authentication trailer, with HMAC-SHA-1, -256, -384 or -512 only. A packet that fails is dropped and logged (`ospfv3 packet authentication failed`).
- **Link-local flooding scope.** A link LSA is only ever sent on the link it belongs to (RFC 5340 §4.5.1).

## Not supported yet

These work in OSPFv2 but not yet in OSPFv3:

- **More than one area.** An OSPFv3 router does not act as an area border router, so there are no inter-area routes: keep each OSPFv3 instance in one area.
- **Redistribution.** `redistribute from static to ospf` targets OSPFv2 only; nothing can be redistributed into OSPFv3, and a router cannot be an OSPFv3 ASBR.
- **RFC 7474-style replay protection** (`extended-sequence-numbers`).

Also not supported: several OSPFv3 instances on one link (RFC 5838 instance IDs), RFC 8362's sparse mode, NSSA and stub areas, virtual links, graceful restart, BFD, and the non-broadcast network types.

## Configuration reference

Fields, types, defaults and validation are those of [OSPF](ospf.md#configuration-reference), with `ospfv3` for `ospf` in the commands and `ospfv3-instance` for `ospf-instance` in the paths. Only the differences are listed here. All paths are relative to `/v1/transactions/{tx}/`.

| Field | CLI | Config-tree path | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| instance | `edit ospfv3 instance <name>`; `delete ospfv3 instance <name>` | `ospfv3-instance/<name>` | string, 1 to 64 characters | unique among OSPFv3 instances | names the instance | `show config` |
| router ID | `set ospfv3 instance <name> router-id <ip>`; relative `set router-id <ip>` | `ospfv3-instance/<name>/router-id` | dotted quad | | router ID in Hellos and LSAs | `show ospfv3 neigh` on the neighbour |
| extended LSAs | `set ospfv3 instance <name> extended-lsa`; `delete ospfv3 instance <name> extended-lsa` (absolute only) | `ospfv3-instance/<name>/extended-lsa` | boolean; default `false` | | originate RFC 8362 extended LSAs | `show ospfv3 database` |
| routing table | `set routing-table <table> ospfv3-instance <name>`; `delete routing-table <table> ospfv3-instance` | `routing-table/<table>/ospfv3-instance` | instance name | the instance must exist; one table per instance | runs the instance in that table | `show ospfv3 neigh` |
| area | `edit ospfv3 instance <name> area <area-id>`; `delete ospfv3 instance <name> area <area-id>` | `ospfv3-instance/<name>/area/<area-id>` | dotted quad | unique within the instance; use one area only (see above) | | |
| profile | `edit ospfv3 instance <name> area <area-id> profile <p>`; `delete ospfv3 instance <name> area <area-id> profile <p>` | `…/area/<area-id>/profile/<p>` | string, 1 to 64 characters | unique among OSPFv3 profiles | | |
| hello interval, dead interval, cost, priority, MTU, network type | `set ospfv3 instance <name> area <area-id> profile <p> <field> <value>`; relative forms as in OSPF | `…/profile/<p>/hello-interval`, `dead-interval`, `cost`, `priority`, `mtu`, `network-type` | as in OSPF | as in OSPF | as in OSPF | `show ospfv3 neigh` |
| crypto key | `set ospfv3 instance <name> area <area-id> profile <p> crypto-key <id> <algorithm> <key>`; relative `set crypto-key …` / `delete crypto-key <id>` *(relative only)* | `…/profile/<p>/auth`, `[{"key_id":300,"algorithm":"HmacSha256","key":"…","is_current":true}]` | ID 0 to 65535; `hmac-sha1`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`; key 1 to 80 bytes; unset by default | at least one key, IDs unique, exactly one current, no `md5` | RFC 7166 authentication trailer | `show this` in the profile |
| current key | `set … profile <p> crypto-key <id> current`; relative `set crypto-key <id> current` | `is_current` of each key | | the key must exist | signs sent packets; all keys verify | `show this` in the profile |
| no authentication | relative `delete auth` *(relative only)* | `DELETE …/profile/<p>/auth` | default | | | |
| subinterface / loopback | `set interface <if>[.<tag>] ospfv3 <p>`, `set interface loopback-<table> ospfv3 <p>`; `delete interface <if> ospfv3` | `interface/<if>/subinterface/<tag>/ospfv3-profile`, `interface/loopback-<table>/ospfv3-profile` | | the attach point needs `routing-table` | runs OSPFv3 on the link | `show ospfv3 neigh` |
| broadcast domain | relative only: `set ospfv3 <p>` / `delete ospfv3` inside `edit broadcast domain <name>` | `broadcast-domain/<name>/ospfv3-profile` | | the domain needs `routing-table` | runs OSPFv3 on the domain's SVI | `show ospfv3 neigh` |

OSPFv3 profiles have no `simple-password` and no `extended-sequence-numbers`. The instance's `routing_table` JSON field is filled in by the router and is read-only.
