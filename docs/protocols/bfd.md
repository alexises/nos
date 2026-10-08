# BFD profiles

A BFD profile (RFC 5880) is a named set of session parameters that BGP, OSPF, OSPFv3 and static routes can reference by name.

- `nos-bfdd` runs the sessions (RFC 5880, single-hop RFC 5881 over UDP 3784, multihop RFC 5883 over UDP 4784, both inside the routing table's VRF).
- **Static routes, BGP peer-groups, OSPF and OSPFv3 profiles use it** (see [BGP](bgp.md#bfd-rfc-5882-rfc-9384) and [OSPF and OSPFv3](#ospf-and-ospfv3)).
- Profiles are checked at commit time; the shell and REST accept any edit in a transaction.

## Define a profile

```
edit bfd-profile fast
set min-tx-interval 100
set min-rx-interval 100
set detect-multiplier 3
```

- `edit bfd-profile <name>` creates the profile with its defaults if it does not exist, then moves into it.
- The REST equivalent is `PUT /v1/transactions/<tx>/bfd-profile/<name>` (see [CLI ↔ API mapping](../cli-api-mapping.md)).

## Reference it

Set `bfd <profile>` on the object that should run BFD:

| Object | Command |
|--------|---------|
| BGP peer-group | `set bgp instance <i> peer-group <g> bfd <profile>` |
| OSPF profile | `set ospf instance <i> area <a> profile <p> bfd <profile>` |
| OSPFv3 profile | `set ospfv3 instance <i> area <a> profile <p> bfd <profile>` |
| Static route | `set static-routing-instance <i> route <cidr> bfd <profile>` |

`delete bfd` (relative) removes the reference.

## Protect a static route

```
edit bfd-profile fast
set min-tx-interval 100
set min-rx-interval 100
edit static-routing-instance s1
set route 198.51.100.0/24 gateway 192.0.2.1
set route 198.51.100.0/24 bfd fast
```

- `nos-ribd` registers one session per route gateway, in the route's routing table; the peer must also run BFD (or be a BFD-capable system such as FRR `bfdd`).
- The route stays out of the RIB until the session is `up`. It fails closed: while `nos-bfdd` is unreachable nothing is up.
- The route is removed when the session goes `down` or `init`, and when the peer signals `admin-down` (a peer that is administratively down gives no data-plane assurance).
- Editing the profile applies through Poll/Final without a flap; `shutdown enable` puts the session in `admin-down`.
- One session is shared by every route with the same gateway in the same table; it is identified by (table, peer address), not by interface.

## OSPF and OSPFv3

RFC 5882 §4.1: OSPF is a BFD client; BFD only ever kills a neighbor, it never gates one coming up.

```
set ospf instance o1 area 0.0.0.0 profile p1 bfd fast
set ospfv3 instance o1 area 0.0.0.0 profile p1 bfd fast
```

- `nos-ospfd` and `nos-ospfv3d` register one single-hop session per neighbor, in the instance's routing table, once the neighbor is at 2-Way or later; on a broadcast link that is one per neighbor, not per link. Below 2-Way, or when the link or the `bfd` reference goes, the session is deregistered.
- OSPFv2 sessions run between the interface addresses; OSPFv3 sessions between link-local addresses, scoped by the link's interface (the peer must run BFD too, or be a BFD-capable system such as FRR `bfdd`).
- A session going `up` then `down` kills the neighbor like an expired dead interval (RFC 2328 §10.2 `KillNbr`): it goes `Down`, the adjacency is cleared and the Router-LSA is re-originated within the 2 s origination tick, so the SPF route is withdrawn at once instead of after the dead interval (40 s by default). The next Hello brings it back through Init.
- `admin-down` (a local `shutdown enable`), `init`, a session that was never `up` and a lost connection to `nos-bfdd` kill nothing (RFC 5882 §3.2): OSPF behaves as without BFD.
- Adding, changing or removing the `bfd` reference never resets an adjacency; only registrations change.
- Log anchors: `bfd session down, killing ospf neighbor link=... neighbor=...` (`ospfv3` for OSPFv3), preceded by `ospf: bfd session down peer=... diag=...`.
- `show bfd sessions` lists the sessions; they are keyed by (table, peer), so two links to one peer address in one table share a session.

## Authenticate sessions

RFC 5880 section 6.7: every packet of a session carries a password or a digest, and packets that fail are dropped.

```
edit bfd-profile fast
set auth key-id 1 method meticulous-sha1 key s3cret
```

- Set the same `auth` on both ends. `delete auth` turns it off.
- Methods: `simple-password` (clear text on the wire), `keyed-md5`, `keyed-sha1`, and the `meticulous-` variants, which sign every packet with a fresh sequence number (strongest replay protection, a little more work per packet). Prefer `meticulous-sha1`.
- Key length: 1 to 16 bytes (`simple-password`, MD5), 1 to 20 bytes (SHA1); `key-id` is 0 to 255 and must match on both ends.
- A packet is dropped, and does not refresh the detection timer, when:
  - the A bit is set but no auth is configured, or the reverse;
  - the method or key id differs;
  - the password or digest is wrong;
  - the sequence number is outside the window (3 x the packet's detect multiplier ahead; for `meticulous-` it must also be new).
- A wrong key therefore leaves the session `down`. The drop is logged as `bfd auth failed peer=... reason=...`, at most once per 10 s per session, and counted in `auth_failures`.
- Enabling or disabling auth on one side only drops the session after the detection time, as the RFC allows.

### Change the key without a flap

- Edit the profile on both routers. The new key signs from that moment, and the previous key is still accepted for 4 detection times.
- Apply the change on the second router within that time. A change of key id, secret or method keeps the session `up` (a method change resets the sequence tracking, as the spaces differ).
- The router that changes second is the one at risk: until it applies the change it rejects the first router's packets, so keep the gap below the detection time (use longer intervals for a planned rollover).
- Multiple concurrent keys and key lifetimes are not supported.

## Use the Echo function

RFC 5880 section 6.4 and RFC 5881 section 4: each end sends packets addressed to itself through the neighbour, which only forwards them back. A broken forwarding path is found in `echo-interval x detect-multiplier` instead of the control detection time.

```
edit bfd-profile fast
set echo-mode affiliated
set echo-interval 50
```

- `echo-mode` is `disabled` (default) or `affiliated`: Echo runs next to the Control session. `echo-interval` is in milliseconds (10 to 4294967, default 50).
- Every Control packet advertises `echo-interval` as Required Min Echo RX; `disabled` advertises 0, so the peer never loops echoes through you.
- Echo starts when the session is `up`, the profile asks for it and the peer advertises a nonzero Required Min Echo RX. The interval used is the larger of the two. `nos-bfdd` logs `bfd echo active peer=... interval_us=...`, and `bfd echo inactive` when it stops (session not `up`, `echo-mode` removed, peer advertises 0).
- While Echo runs, Control packets slow to one per second or less (a Poll sequence raises Desired Min TX to 1 s, and restores it when Echo stops).
- No echo returning for `echo-interval x detect-multiplier` takes the session `down` with `diag echo-function-failed` (diagnostic 2). Control keeps flowing, so the session comes back `up` and Echo restarts; a persistent fault shows as a flapping session.
- Single-hop sessions only. A session that cannot open its Echo transport (no interface or address towards the peer) logs `bfd echo unavailable` once and stays Control-only.
- The neighbour must forward IP between the two addresses of the link (`net.ipv4.ip_forward=1` / `net.ipv6.conf.all.forwarding=1`). It may send ICMP redirects for the looped packet; it still forwards, but set `send_redirects=0` on that interface to avoid the noise.
- The neighbour's MAC comes from the kernel neighbour table, read only: the Control session's ARP/ND creates the entry. Without one, echoes are not sent and the session goes `down` after the echo detection time.
- Echo packets carry no authentication (RFC 5880 has none for Echo); `auth` covers Control only.

## Check sessions

- `show bfd sessions` lists every session, `show bfd sessions <peer>` those to one address. Sample:

```
rt1: peer 192.0.2.1, up, diag no-diagnostic, tx 100ms, detect 300ms, discriminators 1/7
```

- `tx` is the negotiated transmit interval, `detect` the detection time, `discriminators` local/remote.
- With `auth` set the line ends with `auth <method> key <id> (<n> failures)`; the key is never shown.
- While Echo runs the line ends with `echo active <n>ms`.
- A `down` session shows why: `diag control-detection-time-expired`, `neighbor-signaled-session-down`, and so on (RFC 5880 section 4.1 names).
- The REST equivalent is `GET /v1/bfd/sessions` (optionally `?peer=192.0.2.1`); it returns the same fields as JSON (`state` is `Up`, `Down`, `Init` or `AdminDown`), plus `auth_method`, `auth_key_id`, `auth_failures`, `echo_active` and `echo_interval_us` (0 while Echo is off).
- "nos-bfdd is not running" (CLI) or `503` (REST) means the daemon is not up.

## Multi-hop sessions

- A client picks multi-hop for a peer that is not directly connected; you configure nothing extra beyond the profile.
  - BGP: the peer-group has `max-hops` above 1, or the peer address is on no subnet configured on an interface (or subinterface) of the instance's routing table. An iBGP session between loopbacks reached over OSPF is the typical case.
  - Static routes: the gateway is on no such subnet.
- A subnet that is not in the configuration (learned over DHCP) is not seen: the peer is then registered multi-hop, which still works.
- Multi-hop sessions use UDP 4784 and are not tied to an interface; `show bfd sessions` prints `multihop` and no interface.
- TX TTL is 255. A received packet is dropped when its TTL is below the profile's `minimum-ttl` (default 254). Single-hop sessions still require exactly 255.
- The local address is the peer-group's `source-address` for BGP; otherwise `nos-bfdd` uses the address the kernel would use towards the peer, fixed when the session opens.
- Changing a peer between single-hop and multi-hop (an address added or `max-hops` edited) replaces the session: the old one is deregistered and a new one starts `down`.

## Commit-time errors

- A `bfd` reference to a profile that does not exist is refused: `bfd profile '<name>' does not exist`.
- Deleting a profile that is still referenced is refused the same way, once per referencing object, each under its own path (for example `bgp_instances[0].peer_groups[0].bfd`). Remove the references first, or delete them in the same transaction.
- Duplicate profile names are refused.

## Configuration reference

| Field | CLI | Type | Default | Validation |
|-------|-----|------|---------|------------|
| `name` | `edit bfd-profile <name>` | string | | 1 to 64 characters, unique |
| `min_tx_interval` | `set min-tx-interval <ms>` | integer, ms | 300 | 10 to 4294967 |
| `min_rx_interval` | `set min-rx-interval <ms>` | integer, ms | 300 | 10 to 4294967 |
| `detect_multiplier` | `set detect-multiplier <n>` | integer | 3 | at least 1 |
| `passive` | `set passive enable` | bool | off | |
| `minimum_ttl` | `set minimum-ttl <n>` | integer | 254 | |
| `shutdown` | `set shutdown enable` | bool | off | |
| `auth` | `set auth key-id <n> method <m> key <k>` | key id, method, key | none | key length per method, below |

- Methods: `simple-password`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`, `meticulous-sha1`.
- Key length (RFC 5880 sections 4.2 and 4.3): 1 to 16 bytes for `simple-password` and the MD5 methods, 1 to 20 bytes for the SHA1 methods.
- Keys are stored in clear text, like BGP and OSPF keys.
- The interval ceiling keeps the later millisecond-to-microsecond conversion inside the RFC's 32-bit field.
