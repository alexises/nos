# BGP

NOS speaks BGP-4 (RFC 4271) over IPv4 and IPv6. Use it to peer with upstream providers and customers over eBGP, to carry routes between your own routers over iBGP (with or without route reflectors), to act as a route server at an exchange point, and to carry EVPN routes for VXLAN. Every BGP instance runs inside one routing table (a VRF): it opens its sessions from that VRF and installs its best routes into it.

This page covers sessions and their options. Which routes a session accepts and advertises is decided by routing policies, covered in [Routing policy](routing-policy.md). How NOS implements BGP internally is in [`bgp/CLAUDE.md`](../../bgp/CLAUDE.md).

- [How BGP is configured](#how-bgp-is-configured)
- [Bringing up a session](#bringing-up-a-session)
- [Checking sessions and routes](#checking-sessions-and-routes)
- [Advertising routes](#advertising-routes)
- [Timers](#timers)
- [Shutting a session down](#shutting-a-session-down)
- [Asking a peer to resend its routes](#asking-a-peer-to-resend-its-routes)
- [Removing peers and instances](#removing-peers-and-instances)
- [Features and how they behave](#features-and-how-they-behave)
- [Configuration reference](#configuration-reference)

## How BGP is configured

BGP configuration has three levels:

- A **BGP instance** (`bgp instance <name>`) is one BGP speaker: its AS number, its router ID and, for route reflection, its cluster ID. It does nothing until a routing table claims it with `set routing-table <table> bgp-instance <name>`. Each instance belongs to at most one routing table, and each routing table has at most one instance.
- A **peer-group** (`peer-group <name>`, inside an instance) holds every session setting: remote AS, address families, timers, authentication, next-hop handling, policies. There is no per-peer override other than shutdown, so peers that need different settings go in different peer-groups.
- A **peer** (`peer <address>`, inside an instance) is a neighbour's address and the peer-group it uses.

Three rules catch people out:

- **Both policies default to `deny-all`.** A peer-group with no `import-policy` accepts no routes, and one with no `export-policy` advertises none. The session still comes up, so nothing looks wrong until you check the routes. Set both, to `accept-all` or to one of your own policies (see [Routing policy](routing-policy.md)).
- **Changing a peer-group resets its sessions.** Any change to a peer-group, or to a policy it uses, closes its established sessions with a Cease NOTIFICATION (RFC 4486 subcode 6, Other Configuration Change) and opens them again with the new settings. Plan changes to production peer-groups accordingly.
- **Names are global.** Peer-group names and peer addresses must be unique across all BGP instances, not just within one.

## Bringing up a session

This session sets up an eBGP session from router-a (AS 65001, 10.50.0.2) to router-b (AS 65002, 10.50.0.3) in routing table `rt1`, whose interface `eth0` already has the address 10.50.0.2/24:

```
edge-1> configure bgp1
edge-1(bgp1)> edit bgp instance r1
edge-1(bgp1/bgp-instance:r1)> set asn 65001
edge-1(bgp1/bgp-instance:r1)> set router-id 1.1.1.1
edge-1(bgp1/bgp-instance:r1)> edit peer-group pg1
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set remote-as 65002
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set address-family ipv4
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set import-policy accept-all
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set export-policy accept-all
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set connect-retry-time 5
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> up
edge-1(bgp1/bgp-instance:r1)> set peer 10.50.0.3 peer-group pg1
edge-1(bgp1/bgp-instance:r1)> top
edge-1(bgp1)> set routing-table rt1 bgp-instance r1
edge-1(bgp1)> commit
transaction 'bgp1' committed
edge-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS 65002 peer-group pg1 Established uptime 00:00:04 hold-time 90
```

Router-b needs the mirror image (AS 65002, router ID 2.2.2.2, remote AS 65001, peer 10.50.0.3 replaced by 10.50.0.2). NOS both connects to the peer and accepts its connection on TCP port 179, in the routing table's VRF; whichever connection wins RFC 4271 collision resolution becomes the session.

`connect-retry-time 5` is optional. The default is 120 seconds, which is how long a session can stay down after a failed attempt, for instance while the other side is still being configured.

Over REST, create the whole instance in one `PUT`, then link it to the routing table. A peer-group's `route_reflector_client` and `route_server_client` must be present; every other field can be left out and takes its default:

```sh
$ $C -X POST "$B/v1/transactions/bgp1?base=current" -o /dev/null -w '%{http_code}\n'
201
$ $C -X PUT -H 'Content-Type: application/json' -d '{
    "name": "r1", "asn": 65001, "router_id": "1.1.1.1",
    "peer_groups": [{"name": "pg1", "remote_as": 65002, "address_families": ["Ipv4Unicast"],
                     "import_policy": "accept-all", "export_policy": "accept-all",
                     "connect_retry_time": 5,
                     "route_reflector_client": false, "route_server_client": false}],
    "peers": [{"remote_address": "10.50.0.3", "peer_group": "pg1"}]
  }' $B/v1/transactions/bgp1/bgp-instance/r1 -o /dev/null
$ $C -X PUT -H 'Content-Type: application/json' -d '"r1"' \
    $B/v1/transactions/bgp1/routing-table/rt1/bgp-instance
"r1"
$ $C -X POST $B/v1/transactions/bgp1/commit
{"committed":"bgp1"}
```

To add a peer-group or a peer to an existing instance, `PUT` just that element:

```sh
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"remote_address":"10.50.0.3","peer_group":"pg1"}' \
  $B/v1/transactions/bgp1/bgp-instance/r1/peer/10.50.0.3
```

## Checking sessions and routes

`show bgp brief` (REST: `GET /v1/bgp/summary`) lists every peer of every instance: its state, the AS it announced, how long it has been up, and the negotiated hold time. The states are `Idle` (no OPEN exchanged yet: not connected, or retrying), `OpenSent`, `OpenConfirm` and `Established`. A shut-down peer shows as `Idle (shutdown)`.

```
edge-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS 65002 peer-group pg1 Established uptime 00:02:21 hold-time 90
```

The JSON form has more detail: the peer's BGP identifier, the negotiated keepalive, and, for TCP-AO sessions, the key state (see [TCP-AO](#tcp-ao-rfc-5925)):

```sh
$ $C $B/v1/bgp/summary | jq '.[0].result[0]'
{
  "remote_address": "10.50.0.3",
  "peer_group": "pg1",
  "shutdown": false,
  "remote_as": 65002,
  "remote_bgp_id": "2.2.2.2",
  "state": "Established",
  "uptime_secs": 141,
  "negotiated_hold_time": 90,
  "negotiated_keepalive": 30,
  …
}
```

Routes learned over BGP and chosen as best appear in the routing table as `bgp`. `show route <table>` lists every candidate for each prefix, best first:

```
edge-2> show route rt1 198.51.100.1
198.51.100.0/24
  * via 10.50.0.2 [bgp]
```

There is no command yet that lists BGP routes with their attributes (AS path, communities and so on). The router's log records each route as it is learned and each change of best path; see `show log nos-bgpd[r1]` in the shell or `GET /v1/logs?source=nos-bgpd%5Br1%5D` (see [Concepts: Logs](../concepts.md#logs)).

## Advertising routes

NOS advertises two kinds of routes to BGP peers:

- routes learned from other BGP peers, subject to the usual iBGP rules (see [Route reflection](#route-reflection-rfc-4456));
- static routes of the same routing table, once you redistribute them with `set routing-table <table> redistribute from static to bgp`.

Every advertisement also has to pass the peer-group's export policy. This example advertises 198.51.100.0/24 from router-a:

```
edge-1> configure adv
edge-1(adv)> edit static-routing-instance s1
edge-1(adv/static-routing-instance:s1)> set route 198.51.100.0/24 gateway 10.50.0.1
edge-1(adv/static-routing-instance:s1)> top
edge-1(adv)> set routing-table rt1 static-routing-instance s1
edge-1(adv)> set routing-table rt1 redistribute from static to bgp
edge-1(adv)> commit
transaction 'adv' committed
```

```sh
$C -X POST "$B/v1/transactions/adv?base=current" -o /dev/null
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"s1","routes":[{"subnet":"198.51.100.0/24","gateway":"10.50.0.1"}]}' \
  $B/v1/transactions/adv/static-routing-instance/s1
$C -X PUT -H 'Content-Type: application/json' -d '"s1"' \
  $B/v1/transactions/adv/routing-table/rt1/static-routing-instance
$C -X PUT -H 'Content-Type: application/json' -d '{"from":"Static","to":"Bgp","policy":null}' \
  $B/v1/transactions/adv/routing-table/rt1/redistribute
$C -X POST $B/v1/transactions/adv/commit
```

Adding `policy <name>` to the redistribute command filters the static routes before they enter BGP; see [Routing policy: Where policies attach](routing-policy.md#where-policies-attach).

## Timers

Three timers are set per peer-group:

- `hold-time` (default 90 seconds) is the hold time this router proposes in its OPEN. The session uses the lower of the two sides' values. `0` turns off both the hold timer and keepalives; otherwise the minimum is 3.
- `keepalive-interval` (default: a third of the negotiated hold time) must be lower than `hold-time` when both are set.
- `connect-retry-time` (default 120 seconds) is how long NOS waits between two attempts to connect to a peer.

```
edge-1(t1/bgp-instance:r1/peer-group:pg1)> set hold-time 30
edge-1(t1/bgp-instance:r1/peer-group:pg1)> set keepalive-interval 10
edge-1(t1/bgp-instance:r1/peer-group:pg1)> set connect-retry-time 5
```

The absolute form works from anywhere in the transaction: `set bgp instance r1 peer-group pg1 hold-time 30`. To go back to a default, use `delete hold-time` (or `keepalive-interval`, `connect-retry-time`) inside the peer-group, or the absolute `delete bgp instance r1 peer-group pg1 hold-time`.

```sh
$C -X PUT -H 'Content-Type: application/json' -d '30' $B/v1/transactions/t1/bgp-instance/r1/peer-group/pg1/hold-time
$C -X PUT -H 'Content-Type: application/json' -d '10' $B/v1/transactions/t1/bgp-instance/r1/peer-group/pg1/keepalive-interval
$C -X DELETE $B/v1/transactions/t1/bgp-instance/r1/peer-group/pg1/hold-time      # back to the default
```

`show bgp brief` shows the negotiated hold time once the session is back up. A keepalive interval that no longer fits under the negotiated hold time (because the peer proposed a lower one) is replaced by a third of the negotiated value.

## Shutting a session down

`shutdown` closes a session and keeps it closed without removing its configuration (RFC 4486). You can shut a whole peer-group or one peer, with an optional message of up to 255 bytes that the peer receives in its Cease NOTIFICATION (RFC 9003) and can log:

```
edge-1(t2/bgp-instance:r1/peer-group:pg1)> set shutdown maintenance until 18:00, ticket 4711
edge-1(t2/bgp-instance:r1/peer-group:pg1)> commit
transaction 't2' committed
edge-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS - peer-group pg1 Idle (shutdown) uptime - hold-time -
```

The peer logs the message:

```
edge-2> show log nos-bgpd[r1]
…  INFO nos-bgpd[r1] nos_bgp::fsm: received notification (peer=10.50.0.2 code=6 subcode=2 shutdown_message="maintenance until 18:00, ticket 4711")
```

To shut one peer only, set it on the peer, inside the instance: `set peer 10.50.0.3 shutdown [<message>]`, or `set bgp instance r1 peer 10.50.0.3 shutdown [<message>]` from the top. A shutdown set on a peer takes precedence over its peer-group's. `delete shutdown` (in the peer-group) or `delete peer 10.50.0.3 shutdown` (in the instance) brings the session back up.

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"message":"maintenance until 18:00, ticket 4711"}' \
  $B/v1/transactions/t2/bgp-instance/r1/peer-group/pg1/shutdown
$C -X PUT -H 'Content-Type: application/json' -d '{"message":null}' \
  $B/v1/transactions/t2/bgp-instance/r1/peer/10.50.0.3/shutdown           # one peer, no message
$C -X DELETE $B/v1/transactions/t2/bgp-instance/r1/peer-group/pg1/shutdown # up again
```

## Asking a peer to resend its routes

`clear bgp <instance> <peer> soft-in` sends the peer a route refresh request (RFC 2918): it resends every route it advertises to you, without resetting the session. Use it after changing something that affects routes you already hold, for example a prefix list that an import policy uses. It works in both modes and changes no configuration:

```
edge-1> clear bgp r1 10.50.0.3 soft-in
route refresh requested for 10.50.0.3
```

```sh
$ $C -X POST $B/v1/bgp/r1/peer/10.50.0.3/soft-in
{"instance":"r1","peer":"10.50.0.3","route_refresh":"sent"}
```

The request fails with `404` over REST if the peer is not configured or its session is not Established.

## Removing peers and instances

- `delete peer 10.50.0.3` in the instance (or `delete bgp instance r1 peer 10.50.0.3`) removes a peer. Its session is closed with a Cease / Peer De-configured NOTIFICATION (RFC 4486 subcode 3).
- `delete peer-group pg1` in the instance (or `delete bgp instance r1 peer-group pg1`) removes a peer-group. Remove or move its peers first: a peer that names a missing peer-group is refused at commit.
- `delete bgp instance r1` removes the instance. Remove the routing table's reference to it in the same transaction (`delete routing-table rt1 bgp-instance`), or the commit is refused.

Over REST, `DELETE` the same paths: `…/bgp-instance/r1/peer/10.50.0.3`, `…/bgp-instance/r1/peer-group/pg1`, `…/bgp-instance/r1` and `…/routing-table/rt1/bgp-instance`.

## Features and how they behave

### Sessions and capabilities (RFC 4271)

NOS runs the full RFC 4271 session: OPEN, KEEPALIVE, UPDATE and NOTIFICATION, with the hold and keepalive timers described in [Timers](#timers) and real collision resolution (§6.8) when both sides connect at once. It checks the peer's OPEN: BGP version 4, the AS number against the peer-group's `remote-as`, a valid BGP identifier and a valid hold time. Any mismatch is answered with the matching NOTIFICATION and the session is closed.

Every OPEN advertises these capabilities, with no option to turn them off:

- four-octet AS numbers (RFC 6793), see below;
- route refresh (RFC 2918) and enhanced route refresh (RFC 7313);
- extended messages up to 65535 bytes (RFC 8654), used only when the peer also advertises it;
- multiprotocol extensions (RFC 4760) for each configured address family.

A malformed attribute in a received UPDATE does not reset the session: the routes in that UPDATE are treated as withdrawn and logged (RFC 7606). Only a message that cannot be parsed at all closes the session.

### Address families

`set address-family ipv4|ipv6|l2vpn-evpn` adds an address family to a peer-group, and `delete address-family <af>` removes one. A peer-group needs at least one. The address families are independent of whether the peer is reached over IPv4 or IPv6: an IPv6 peer can carry IPv4 routes and the reverse.

- `ipv4` and `ipv6` are unicast routes, installed in the routing table.
- `l2vpn-evpn` (RFC 7432) carries EVPN routes for VXLAN broadcast domains. It is described with the rest of EVPN.

Over REST the list is `address_families`, with the values `Ipv4Unicast`, `Ipv6Unicast` and `L2vpnEvpn`: `PUT …/peer-group/pg1/address-family/Ipv6Unicast` with body `"Ipv6Unicast"` adds one, and `DELETE` on the same path removes it.

### Four-octet AS numbers (RFC 6793)

AS numbers can be anywhere from 1 to 4294967294. With a peer that does not support four-octet AS numbers, NOS uses the RFC 6793 transition mechanism: its own AS appears as 23456 (`AS_TRANS`) in the OPEN, and AS paths are exchanged as two-octet paths plus an `AS4_PATH` attribute. You configure the real AS numbers on both sides in all cases.

### Source address

By default the session's source address is whatever the kernel picks to reach the peer. `source-address` makes the session use the address of a given interface instead:

- `set source-address interface <name> [label <label>]` uses the address of that interface. `<name>` is written as in interface commands (`eth0` is its untagged subinterface, `eth0.100` a VLAN subinterface). If the interface has several addresses, `label` picks the one with that label; without it the interface must have exactly one address.
- `set source-address loopback [label <label>]` uses the routing table's loopback, the interface named `loopback-<table>`, without spelling out its name.

The address is looked up each time the configuration changes, and again every few seconds while it cannot be found. The router logs `resolved peer-group source-address` with the address it found, or `peer-group source-address not resolvable yet` (at debug level) while the interface does not exist or has no usable address. `delete source-address` goes back to the default.

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"Loopback":{"label":null}}' \
  $B/v1/transactions/t3/bgp-instance/r1/peer-group/pg1/source-address
$C -X PUT -H 'Content-Type: application/json' -d '{"Interface":{"interface":"eth0","label":null}}' \
  $B/v1/transactions/t3/bgp-instance/r1/peer-group/pg1/source-address
```

### Next hop

`next-hop` controls the `NEXT_HOP` of routes advertised to a peer-group:

- `self` replaces it with this router's own address on the session. This is the default for eBGP peer-groups (`remote-as` different from the instance's `asn`).
- `unchanged` keeps the next hop the route already has. This is the default for iBGP peer-groups and for route-server peer-groups (`route-server-client`).

`set next-hop self|unchanged` overrides the default, and `delete next-hop` restores it. An export policy can also set the next hop of individual routes (see [Routing policy](routing-policy.md#statements)). Over REST the values are `"SelfAddress"` and `"Unchanged"`.

A received route is used only if its next hop is reachable through the routing table (RFC 4271 §9.1.2): through a connected subnet, a static route or an OSPF route. A route whose next hop is not reachable stays in the router's Adj-RIB-In but is left out of best-path selection, and the router logs `bgp: candidate excluded, next hop unresolvable`. It becomes a candidate again as soon as a route to its next hop appears.

### Best path

For each prefix NOS runs the RFC 4271 §9.1.2.2 decision process over the candidates that passed the import policy, damping and next-hop checks, in this order: highest `LOCAL_PREF`; a route redistributed on this router over a learned one; shortest AS path; lowest origin (IGP, then EGP, then incomplete); lowest `MED`, compared only between routes from the same neighbouring AS (a missing MED counts as 0); eBGP over iBGP; lowest IGP cost to the next hop; between two eBGP routes, the older one; lowest BGP identifier; lowest peer address. The best route is installed in the routing table. When a second-best route with a different next hop exists, it is installed as a backup at a higher metric, so traffic can fail over without waiting for BGP to reconverge.

### Communities

Standard (RFC 1997), extended (RFC 4360) and large (RFC 8092) communities are passed on unchanged to every peer. The well-known communities (`NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`) have no built-in effect: write an export policy that acts on them if you need it. Policies can match, add and remove communities; see [Routing policy](routing-policy.md).

### MD5 authentication (RFC 2385)

`set md5-password <password>` signs every TCP segment of the peer-group's sessions with a shared password. Both sides must use the same password; with a wrong or missing one, the kernel drops the segments and the session never comes up. The password is 1 to 80 bytes.

```
edge-1(t4/bgp-instance:r1/peer-group:pg1)> set md5-password s3cr3t-md5
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"Md5":{"password":"s3cr3t-md5"}}' \
  $B/v1/transactions/t4/bgp-instance/r1/peer-group/pg1/auth
```

`delete auth` removes authentication, whether MD5 or TCP-AO. Passwords and keys are stored in clear text and shown in clear by `show config`, like every other setting.

### TCP-AO (RFC 5925)

TCP-AO is the successor of MD5 authentication. A peer-group can have several keys, which lets you change keys without dropping the session. MD5 and TCP-AO are mutually exclusive: setting one replaces the other.

Each key has:

- a send ID and a receive ID (0 to 255): the key IDs this router puts in outgoing segments and expects in incoming ones. The peer configures the same key with the two IDs swapped (or the same values, if you use the same ID in both directions);
- an algorithm: `hmac-sha1` (HMAC-SHA-1-96) or `aes-cmac` (AES-128-CMAC-96);
- the secret, 1 to 80 bytes.

Exactly one key must be marked `current`: it signs the segments this router sends. At most one may be marked `rnext`: it asks the peer to switch to that key.

```
edge-1(t5/bgp-instance:r1/peer-group:pg1)> set ao-key 1 1 hmac-sha1 first-key
edge-1(t5/bgp-instance:r1/peer-group:pg1)> set ao-key 1 current
edge-1(t5/bgp-instance:r1/peer-group:pg1)> commit
```

`set ao-key <send-id> <recv-id> <algorithm> <secret>` adds a key, or replaces the key with that send ID. `set ao-key <send-id> current` and `set ao-key <send-id> rnext` move the flags, and `delete ao-key <send-id>` removes one key.

Once the session is up, `show bgp brief` adds the key state read from the kernel: the key ID this router is sending with, the key ID the peer asks for, and the counts of good segments, bad segments and segments for an unknown key:

```
  10.50.0.2 AS 65001 peer-group pg1 Established uptime 00:00:15 hold-time 90 ao-current 1 ao-rnext 1 ao-good 7 ao-bad 0 ao-no-key 0
```

(That line is from router-b, whose peer is router-a.) During the rollover below, `ao-current` moves to key 2 once both sides have made it current.

To roll over to a new key without dropping the session (RFC 5925 §7.5), on both routers:

1. Add the new key and mark it `rnext`: `set ao-key 2 2 hmac-sha1 second-key`, `set ao-key 2 rnext`. Commit.
2. When both sides have it, make it current: `set ao-key 2 current`. Commit.
3. Remove the old key: `delete ao-key 1`. Commit.

Each commit changes the peer-group, so it resets the session (see [How BGP is configured](#how-bgp-is-configured)); the session comes straight back up with the keys both sides have.

Over REST, `auth` holds the whole key list:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"Ao":{"keys":[
    {"send_id":1,"recv_id":1,"algorithm":"HmacSha1_96","key":"first-key","is_current":true,"is_rnext":false,"exclude_options":false}]}}' \
  $B/v1/transactions/t5/bgp-instance/r1/peer-group/pg1/auth
```

The algorithm values are `HmacSha1_96` and `AesCmac96`. `exclude_options: true` leaves TCP options out of the MAC (RFC 5925 §5.2); both sides must agree on it. In the shell, `set ao-key <send-id> exclude-options` sets it on an existing key and `delete ao-key <send-id> exclude-options` clears it.

### GTSM (RFC 5082)

`set max-hops <n>` turns on the Generalized TTL Security Mechanism: the router sends the session's packets with TTL (or IPv6 hop limit) 255, and the kernel drops incoming packets whose TTL is below `256 - n`. Use `1` for a directly connected peer, so that nobody further away can inject packets into the session. The range is 1 to 254; `delete max-hops` turns it off. Set it on both sides.

### Administrative shutdown (RFC 4486, RFC 9003)

See [Shutting a session down](#shutting-a-session-down). While a peer is shut down, NOS neither connects to it nor accepts its connections. When a session is closed for another configuration reason, the peer receives a Cease NOTIFICATION that says why: Peer De-configured (subcode 3) when you delete the peer, Other Configuration Change (subcode 6) when you change its peer-group.

### Route refresh (RFC 2918, RFC 7313)

When a peer asks for a route refresh, NOS resends its routes for that address family. If both sides support enhanced route refresh, the resent routes are framed by begin and end markers, and routes the peer no longer sends are removed at the end. `clear bgp … soft-in` asks the peer to do the same (see [Asking a peer to resend its routes](#asking-a-peer-to-resend-its-routes)).

### MRAI (RFC 4271 §9.2.1.1)

`set mrai <seconds>` sets the MinRouteAdvertisementInterval: the minimum time between two advertisements of the same prefix to the same peer. The first advertisement of a prefix is sent at once, and so is every withdrawal. A change within the interval is held back until the interval ends, and several changes collapse into the last one. Unset or `0` sends every change at once. EVPN routes are not paced.

```
edge-1(t6/bgp-instance:r1/peer-group:pg1)> set mrai 30
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '30' $B/v1/transactions/t6/bgp-instance/r1/peer-group/pg1/mrai
```

### Route flap damping (RFC 2439)

`set damping` suppresses routes that a peer withdraws and re-announces too often. It applies to routes received from the peer-group's peers, and only in eBGP peer-groups. Each prefix from each peer has a penalty:

- a withdrawal adds 1000, and so does a route that the import policy now rejects;
- a re-announcement with different attributes adds 500;
- the penalty halves every `half-life` seconds.

When the penalty reaches `suppress`, the route is set aside: the router keeps it but does not use or advertise it. It is released once the penalty decays below `reuse`. `max-suppress` caps the penalty, and so the time a route can stay suppressed.

`set damping` alone uses the RFC 7196 defaults: half-life 900, reuse 750, suppress 6000, max-suppress 3600. Give any of the four parameters, in any order, to change them; the others keep their defaults:

```
edge-1(t7/bgp-instance:r1/peer-group:pg1)> set damping half-life 20 reuse 750 suppress 2000
```

```sh
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"half_life":20,"reuse":750,"suppress":2000,"max_suppress":3600}' \
  $B/v1/transactions/t7/bgp-instance/r1/peer-group/pg1/damping
```

The commit requires half-life > 0, reuse > 0, suppress > reuse and max-suppress ≥ half-life. `delete damping` turns damping off.

There is no `show` command for damping state yet. The router logs `route suppressed by flap damping` and `route released from flap damping` with the peer and prefix. A session reset clears the peer's penalties.

### Route reflection (RFC 4456)

Normally a route learned from one iBGP peer is not advertised to another iBGP peer, so iBGP needs a full mesh. A route reflector removes that need: routes from its clients are reflected to all its iBGP peers, and routes from non-clients are reflected to its clients.

On the reflector, mark the peer-group of its clients with `set route-reflector-client`. The peer-group must be iBGP (`remote-as` equal to the instance's `asn`). The clients need no special configuration.

```
edge-1(t8/bgp-instance:r1)> edit peer-group clients
edge-1(t8/bgp-instance:r1/peer-group:clients)> set remote-as 65001
edge-1(t8/bgp-instance:r1/peer-group:clients)> set address-family ipv4
edge-1(t8/bgp-instance:r1/peer-group:clients)> set import-policy accept-all
edge-1(t8/bgp-instance:r1/peer-group:clients)> set export-policy accept-all
edge-1(t8/bgp-instance:r1/peer-group:clients)> set route-reflector-client
```

On an eBGP peer-group the commit is refused:

```
error: nos-configd reported an error: validation failed:
bgp_instances: route-reflector-client requires an iBGP peer-group (remote-as must equal this instance's asn)
```

Reflected routes carry an `ORIGINATOR_ID` and a `CLUSTER_LIST`. The cluster ID defaults to the instance's router ID; if several reflectors serve the same clients, give them the same cluster ID with `set cluster-id <a.b.c.d>` on the instance (`delete cluster-id` restores the default). A route that comes back with the reflector's own cluster ID or router ID is dropped, which prevents reflection loops.

Over REST, `route_reflector_client` is a boolean on the peer-group and `cluster_id` a string on the instance:

```sh
$C -X PUT -H 'Content-Type: application/json' -d 'true' \
  $B/v1/transactions/t8/bgp-instance/r1/peer-group/clients/route-reflector-client
$C -X PUT -H 'Content-Type: application/json' -d '"10.255.0.1"' \
  $B/v1/transactions/t8/bgp-instance/r1/cluster-id
```

### Route server (RFC 7947)

At an exchange point, a route server passes routes between its clients without appearing in their paths. Mark the clients' peer-group with `set route-server-client`; it must be eBGP. For such peers NOS:

- never adds its own AS to the AS path;
- if the client supports ADD-PATH (RFC 7911), sends it every other client's path for a prefix, not only the single best one. A client without ADD-PATH receives the best path only.

- leaves the next hop unchanged by default (RFC 7947 §2.2.1), so clients forward to each other directly. An explicit `set next-hop self` still overrides it.

A received `MED` is not passed on to route-server clients (they are eBGP peers); a `MED` set by the export policy is.

`route-reflector-client` and `route-server-client` cannot both be set on one peer-group.

### What is not supported yet

These are known gaps, so plan around them:

- A route's attributes cannot be displayed. `show route` shows the chosen next hop, and the log records each learned route.
- There is no route aggregation (`aggregate-address`), no maximum-prefix limit, and no soft reconfiguration: changing a peer-group or its policies resets its sessions.
- The well-known communities have no built-in effect (see [Communities](#communities)).

## Configuration reference

"Relative" is the form used inside the object (after `edit bgp instance <i>`, or `edit peer-group <g>` inside it). REST paths are relative to `/v1/transactions/{tx}/`. Everything is validated at commit.

### BGP instance

Created with `edit bgp instance <name>`; deleted with `delete bgp instance <name>` (or `delete` inside it). REST: `bgp-instance/<name>`.

| Field | CLI (absolute / relative) | REST path and JSON | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit bgp instance <name>` | `bgp-instance/<name>`, `"name"` | string, 1 to 64 characters | unique | Names the instance, as referenced by a routing table | `show config` |
| asn | `set bgp instance <i> asn <n>` / `set asn <n>` | `…/asn`, number | 1 to 4294967294; required | not 0 or 4294967295 | This router's AS number | `show config` |
| router-id | `set bgp instance <i> router-id <a.b.c.d>` / `set router-id <a.b.c.d>` | `…/router-id`, `"1.1.1.1"` | IPv4 address; required | must be set (`0.0.0.0` is refused by peers) | BGP identifier in the OPEN; best-path tie-breaker | `GET /v1/bgp/summary` on the peer (`remote_bgp_id`) |
| cluster-id | `set bgp instance <i> cluster-id <a.b.c.d>` / `set cluster-id <a.b.c.d>`; `delete bgp instance <i> cluster-id` / `delete cluster-id` | `…/cluster-id`, `"10.255.0.1"` or `null` | IPv4 address; default: the router ID | none | Cluster ID added to `CLUSTER_LIST` when reflecting | `show config` |
| routing table | `set routing-table <t> bgp-instance <i>`; `delete routing-table <t> bgp-instance` | `routing-table/<t>/bgp-instance`, `"r1"` | name; default: none | instance must exist; one table per instance | Runs the instance in that table's VRF. Without it, the instance opens no session | `show bgp brief` |

`bgp-instance/<name>/routing-table` and `bgp-instance/<name>/redistribute-policy` also appear in the REST tree. They are read-only copies of the routing table's settings, recomputed at every commit; set the routing table's fields instead.

### Peer-group

Created with `edit bgp instance <i> peer-group <g>` (or `edit peer-group <g>` inside the instance); deleted with `delete bgp instance <i> peer-group <g>` (or `delete peer-group <g>`, or `delete` inside it). REST: `bgp-instance/<i>/peer-group/<g>`. Every `delete` of a single field is relative only: run it inside the peer-group.

| Field | CLI (absolute / relative) | REST path and JSON | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit peer-group <g>` | `…/peer-group/<g>`, `"name"` | string, 1 to 64 characters | unique across all instances | Names the group, as referenced by peers | `show config` |
| remote-as | `set bgp instance <i> peer-group <g> remote-as <n>` / `set remote-as <n>` | `…/remote-as`, number | 1 to 4294967294; required | not 0 or 4294967295 | The AS its peers must announce; equal to `asn` makes it iBGP | `show bgp brief` |
| address-family | `… address-family ipv4\|ipv6\|l2vpn-evpn` / `set address-family <af>`; `delete address-family <af>` | `…/address-family/<af>`, `"Ipv4Unicast"`, `"Ipv6Unicast"`, `"L2vpnEvpn"` | list; at least one required | not empty, no duplicates | Address families negotiated with the peer | `show config` |
| source-address | `… source-address interface <if> [label <l>]` or `… source-address loopback [label <l>]` / `set source-address …`; `delete source-address` | `…/source-address`, `{"Interface":{"interface":"eth0","label":null}}` or `{"Loopback":{"label":null}}` | default: chosen by the kernel | none at commit; resolved when connecting | Local address of the session | `show log nos-bgpd[<i>]` |
| hold-time | `… hold-time <s>` / `set hold-time <s>`; `delete hold-time` | `…/hold-time`, number or `null` | 0 to 65535 seconds; default 90 | 0 or ≥ 3 | Proposed hold time; the lower of both sides is used; 0 disables keepalives | `show bgp brief` (`hold-time`) |
| keepalive-interval | `… keepalive-interval <s>` / `set keepalive-interval <s>`; `delete keepalive-interval` | `…/keepalive-interval`, number or `null` | seconds; default: negotiated hold time / 3 | < hold-time when both are set | Interval between KEEPALIVEs | `GET /v1/bgp/summary` (`negotiated_keepalive`) |
| connect-retry-time | `… connect-retry-time <s>` / `set connect-retry-time <s>`; `delete connect-retry-time` | `…/connect-retry-time`, number or `null` | 1 to 65535 seconds; default 120 | ≥ 1 | Wait between two connection attempts | `show config` |
| mrai | `… mrai <s>` / `set mrai <s>`; `delete mrai` | `…/mrai`, number or `null` | 0 to 65535 seconds; default: unset (no pacing) | none | Minimum interval between advertisements of one prefix to one peer | `show config` |
| damping | `… damping [half-life <s>] [reuse <n>] [suppress <n>] [max-suppress <s>]` / `set damping …`; `delete damping` | `…/damping`, `{"half_life":900,"reuse":750,"suppress":6000,"max_suppress":3600}` or `null` | default: off; parameters default to 900 / 750 / 6000 / 3600 | eBGP peer-group only; half-life > 0, reuse > 0, suppress > reuse, max-suppress ≥ half-life | Flap damping of received routes | `show log nos-bgpd[<i>]` |
| max-hops | `… max-hops <n>` / `set max-hops <n>`; `delete max-hops` | `…/max-hops`, number or `null` | 1 to 254; default: off | 1 to 254 | GTSM: TTL 255 out, minimum TTL `256 - n` in | `show config` |
| md5-password | `… md5-password <pw>` / `set md5-password <pw>`; `delete auth` | `…/auth`, `{"Md5":{"password":"…"}}` | 1 to 80 bytes; default: no authentication | 1 to 80 bytes | TCP MD5 signature; replaces any TCP-AO keys | `show bgp brief` (session up) |
| ao-key | `… ao-key <send-id> <recv-id> hmac-sha1\|aes-cmac <secret>` / `set ao-key …`; `delete ao-key <send-id>`; `delete auth` | `…/auth`, `{"Ao":{"keys":[{"send_id":1,"recv_id":1,"algorithm":"HmacSha1_96","key":"…","is_current":true,"is_rnext":false,"exclude_options":false}]}}` | IDs 0 to 255; secret 1 to 80 bytes | at least one key; send IDs unique; exactly one current; at most one rnext | TCP-AO; replaces an MD5 password | `show bgp brief` (`ao-current`, `ao-rnext`, counters) |
| ao-key current | `… ao-key <send-id> current` / `set ao-key <send-id> current` | `is_current` in the key | flag | exactly one key | Key used to sign outgoing segments | `show bgp brief` (`ao-current`) |
| ao-key rnext | `… ao-key <send-id> rnext` / `set ao-key <send-id> rnext` | `is_rnext` in the key | flag | at most one key | Key the peer is asked to switch to | `show bgp brief` (`ao-rnext`) on the peer |
| exclude-options | `… ao-key <send-id> exclude-options` / `set ao-key <send-id> exclude-options`; `delete ao-key <send-id> exclude-options` | `exclude_options` in the key | boolean; default `false` | the key must exist | Leaves TCP options out of the MAC; both sides must agree | `show bgp brief` (session up) |
| next-hop | `… next-hop self\|unchanged` / `set next-hop self\|unchanged`; `delete next-hop` | `…/next-hop`, `"SelfAddress"`, `"Unchanged"` or `null` | default: `self` for eBGP, `unchanged` for iBGP and route-server peer-groups | none | `NEXT_HOP` of advertised routes | `show config`; `show route` on the peer |
| route-reflector-client | `… route-reflector-client` / `set route-reflector-client`; `delete route-reflector-client` | `…/route-reflector-client`, boolean | default `false`; required in a whole-object `PUT` | iBGP peer-group only; not with route-server-client | Reflects iBGP routes to and from these peers | `show config` |
| route-server-client | `… route-server-client` / `set route-server-client`; `delete route-server-client` | `…/route-server-client`, boolean | default `false`; required in a whole-object `PUT` | eBGP peer-group only; not with route-reflector-client | Transparent AS path; ADD-PATH views | `show config` |
| import-policy | `… import-policy <policy>` / `set import-policy <policy>`; `delete import-policy` | `…/import-policy`, `"accept-all"` or `null` | policy name; default `deny-all` | `accept-all`, `deny-all` or an existing policy-definition | Filters and modifies received routes | `show config`; `show route` |
| export-policy | `… export-policy <policy>` / `set export-policy <policy>`; `delete export-policy` | `…/export-policy`, `"accept-all"` or `null` | policy name; default `deny-all` | as import-policy | Filters and modifies advertised routes | `show config`; `show route` on the peer |
| shutdown | `… shutdown [<message>]` / `set shutdown [<message>]`; `delete shutdown` | `…/shutdown`, `{"message":"…"}` or `{"message":null}` or `null` | message up to 255 bytes; default: not shut | message ≤ 255 bytes | Closes and keeps closed every session of the group | `show bgp brief` (`Idle (shutdown)`) |

`show config` and `show this` end each peer-group line with its `import-policy` and `export-policy` (`default (deny-all)` when unset). Over REST, `GET …/peer-group/<g>/import-policy`.

### Peer

Created with `set bgp instance <i> peer <address> peer-group <g>` (or `set peer <address> peer-group <g>` inside the instance); the same command moves an existing peer to another group. Deleted with `delete bgp instance <i> peer <address>` (or `delete peer <address>`). REST: `bgp-instance/<i>/peer/<address>`.

| Field | CLI (absolute / relative) | REST path and JSON | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| remote-address | `… peer <address> …` | `…/peer/<address>`, `"remote_address":"10.50.0.3"` | IPv4 or IPv6 address | unique across all instances | The neighbour's address | `show bgp brief` |
| peer-group | `set bgp instance <i> peer <a> peer-group <g>` / `set peer <a> peer-group <g>` | `…/peer/<a>/peer-group`, `"pg1"` | name; required | the peer-group must exist | Settings used for this peer | `show bgp brief` |
| shutdown | `set bgp instance <i> peer <a> shutdown [<message>]` / `set peer <a> shutdown [<message>]`; `delete bgp instance <i> peer <a> shutdown` / `delete peer <a> shutdown` | `…/peer/<a>/shutdown`, `{"message":"…"}` or `null` | message up to 255 bytes; default: follow the peer-group | message ≤ 255 bytes | Shuts this peer only; overrides the peer-group | `show bgp brief` |

### Operational commands

| CLI | REST | Effect |
|---|---|---|
| `show bgp brief` | `GET /v1/bgp/summary` | Every peer of every instance, with state, remote AS, uptime, hold time and TCP-AO state |
| `show bgp evpn` | `GET /v1/bgp/evpn` | EVPN routes received, per instance |
| `show route <table> [<address>]` | `GET /v1/routes/{table}[/{addr}]` | Installed routes, BGP ones marked `bgp` |
| `clear bgp <instance> <peer> soft-in` | `POST /v1/bgp/{instance}/peer/{peer}/soft-in` | Route refresh request to one peer |
| `show log nos-bgpd[<instance>]` | `GET /v1/logs?source=nos-bgpd%5B<instance>%5D` | The instance's log: sessions, NOTIFICATIONs, learned routes, damping |
