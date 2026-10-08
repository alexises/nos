# BFD profiles

A BFD profile (RFC 5880) is a named set of session parameters that BGP, OSPF, OSPFv3 and static routes can reference by name.

- `nos-bfdd` runs the sessions (RFC 5880, single-hop RFC 5881 over UDP 3784 inside the routing table's VRF).
- **Only static routes use it today.** A `bfd` reference on a BGP peer-group, OSPF profile or OSPFv3 profile is accepted, validated and stored, but starts no session and nothing reacts to it until their own sub-issues land.
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

## Check sessions

- `show bfd sessions` lists every session, `show bfd sessions <peer>` those to one address. Sample:

```
rt1: peer 192.0.2.1, up, diag no-diagnostic, tx 100ms, detect 300ms, discriminators 1/7
```

- `tx` is the negotiated transmit interval, `detect` the detection time, `discriminators` local/remote.
- A `down` session shows why: `diag control-detection-time-expired`, `neighbor-signaled-session-down`, and so on (RFC 5880 section 4.1 names).
- The REST equivalent is `GET /v1/bfd/sessions` (optionally `?peer=192.0.2.1`); it returns the same fields as JSON (`state` is `Up`, `Down`, `Init` or `AdminDown`).
- "nos-bfdd is not running" (CLI) or `503` (REST) means the daemon is not up.

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
