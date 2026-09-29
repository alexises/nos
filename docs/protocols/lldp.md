# LLDP

LLDP (IEEE 802.1AB) lets directly connected devices discover each other: each end periodically announces who it is and which port the frame left from, and records what its neighbours announce. This page covers turning it on per interface, tuning it, and reading the neighbour table.

- [What NOS sends and records](#what-nos-sends-and-records)
- [Common operations](#common-operations)
- [How LLDP behaves](#how-lldp-behaves)
- [Configuration reference](#configuration-reference)

## What NOS sends and records

LLDP is off by default. It is enabled per physical interface, separately for each direction:

- **transmit**: NOS sends an LLDP frame out of the interface every 30 seconds (by default).
- **receive**: NOS listens on the interface and records every neighbour it hears.

Each frame NOS sends carries:

- the chassis ID, a MAC address that identifies this router;
- the port ID and port description, both the interface name (`eth1`);
- the time to live: how long the neighbour should keep this information, 120 seconds by default;
- the system name, which is the router's `hostname`, and the system description `nos <version>`;
- the capabilities: supported "Router, Bridge"; enabled "Router", plus "Bridge" on an interface that has a switching profile;
- a management address, if one is configured.

Three settings apply to all interfaces at once: the transmit interval, the hold multiplier, and the management address. One more is per interface: the destination group.

## Common operations

The examples use router-a and router-b, with `eth1` a direct link between them (see [Verification notes](#verification-notes)).

### Enable LLDP on a link

```
router-a> configure lldp
router-a(lldp)> edit interface eth1
router-a(lldp/interface:eth1)> set lldp transmit
router-a(lldp/interface:eth1)> set lldp receive
router-a(lldp/interface:eth1)> commit
transaction 'lldp' committed
```

With the same on router-b, a few seconds later:

```
router-a> show lldp neighbors
eth1: neighbor router-b, chassis 02:e1:8b:33:6b:4c, port eth1, capabilities router, ttl 112s
```

Each line gives the local interface, the neighbour's system name, chassis ID and port ID, the capabilities it has enabled, its management address if it sends one, and how many seconds are left before the entry expires.

The absolute forms are `set interface eth1 lldp transmit` and `set interface eth1 lldp receive`. `delete interface eth1 lldp transmit` (or `receive`) turns one direction off again.

REST: the two directions are booleans on the interface.

```sh
$ $C -X POST $B/v1/transactions/lldp
$ $C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/lldp/interface/eth1/lldp-transmit
$ $C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/lldp/interface/eth1/lldp-receive
$ $C -X POST $B/v1/transactions/lldp/commit
{"committed":"lldp"}
$ $C $B/v1/lldp/neighbors | jq .
[
  {
    "local_interface": "eth1",
    "chassis_id": "02:e1:8b:33:6b:4c",
    "port_id": "eth1",
    "port_description": "eth1",
    "system_name": "router-b",
    "system_description": "nos 0.1.0",
    "capabilities": [
      "router"
    ],
    "management_addresses": [],
    "ttl_remaining_secs": 94
  }
]
```

This assumes `eth1` is already in the configuration. If it is not, create it whole: `PUT …/interface/eth1` with body `{"name":"eth1","addresses":[],"subinterfaces":[],"lldp_transmit":true,"lldp_receive":true}`.

### Tune the timers and advertise a management address

```
router-a> configure lldp2
router-a(lldp2)> set lldp tx-interval 5
router-a(lldp2)> set lldp tx-hold 3
router-a(lldp2)> set lldp management-address 10.50.0.2
router-a(lldp2)> commit
transaction 'lldp2' committed
```

Router-b now keeps router-a's entry for 5 × 3 = 15 seconds and shows its management address:

```
router-b> show lldp neighbors
eth1: neighbor router-a, chassis 02:47:33:45:65:f2, port eth1, capabilities router, management 10.50.0.2, ttl 10s
```

REST: the three settings are the `lldp` section of the configuration.

```sh
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"tx_interval_secs":5,"tx_hold":3,"management_address":"10.50.0.2"}' \
    $B/v1/transactions/lldp2/lldp
$ $C -X POST $B/v1/transactions/lldp2/commit
```

Each can also be set on its own, for example `PUT …/lldp/tx-interval-secs` with body `5`. `delete lldp tx-interval` (REST: `DELETE …/lldp/tx-interval-secs`) goes back to the default.

### Change the destination group

```
router-a> configure lldp3
router-a(lldp3)> set interface eth1 lldp destination customer-bridge
router-a(lldp3)> commit
transaction 'lldp3' committed
```

REST: `PUT …/interface/eth1/lldp-destination` with body `"CustomerBridge"`. Both ends of the link must use the same group; see below.

## How LLDP behaves

**Physical interfaces only.** LLDP describes a physical link, so it can be enabled on a physical interface, including a port-aggregate member, but not on a loopback (refused at commit) and not on a subinterface or on the aggregate itself.

**Neighbours.** A neighbour is identified by its chassis ID and port ID, so one device heard on two of our ports shows as two neighbours. Each entry is kept for the time to live its sender advertised, counting down in `show lldp neighbors` (`ttl`); every new frame from the neighbour restarts the count. NOS keeps at most 32 neighbours per interface. Frames that NOS itself sent, looped back by a cable or a mirror port, are ignored.

**Shutdown.** When transmit stops on an interface (you delete `lldp transmit`, remove the interface, or the router shuts down), NOS sends a last frame with a time to live of zero, so the neighbour removes this router at once instead of waiting for the entry to expire. Turning receive off forgets the neighbours heard on that interface.

**New neighbours are answered at once.** When NOS hears a neighbour it did not know, it sends its own frame straight away instead of waiting for the next interval, so two routers learn each other within seconds of the link coming up.

**Timers.** `tx-interval` is the time between frames (1-3600 seconds, default 30). `tx-hold` is how many intervals a neighbour keeps our information (1-100, default 4); the time to live we advertise is `tx-interval × tx-hold`, which must not exceed 65535 seconds. Changing either, or the management address, restarts LLDP on every enabled interface: a shutdown frame, then a fresh one, so neighbours briefly drop and relearn this router.

**Management address.** One IPv4 or IPv6 unicast address, advertised on every interface. NOS sends it as configured; it does not check that the address is on any interface.

**Destination groups.** LLDP frames go to one of three reserved multicast addresses, which decide how far a frame travels through intermediate bridges:

- `nearest-bridge` (`01:80:C2:00:00:0E`, the default): reaches only the device at the other end of the cable; no bridge forwards it. The usual choice.
- `non-tpmr` (`01:80:C2:00:00:03`, "nearest non-TPMR bridge"): passes through two-port MAC relays (TPMRs), and stops at the first real bridge.
- `customer-bridge` (`01:80:C2:00:00:00`, "nearest customer bridge"): also passes through provider (S-VLAN) bridges, and stops at the first customer bridge.

An interface sends and listens on one group only, so both ends must be configured with the same group or they will never see each other.

### Verification notes

The examples were run on the lab of the [README](../README.md#conventions-used-in-these-pages), with `eth1` added as a veth pair directly between router-a and router-b. LLDP frames are never forwarded by a bridge, including a Docker network, so two containers can only hear each other over a direct link.

## Configuration reference

Every REST path starts with `/v1/transactions/{tx}/`. The relative CLI forms are what you type after `edit interface <if>`.

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| transmit | `set interface <if> lldp transmit` / `set lldp transmit`; `delete interface <if> lldp transmit` / `delete lldp transmit` | `interface/<if>/lldp-transmit` | boolean, default off | physical interface only | sends LLDP frames on the interface | the neighbour's `show lldp neighbors` |
| receive | `set interface <if> lldp receive` / `set lldp receive`; `delete … lldp receive` | `interface/<if>/lldp-receive` | boolean, default off | physical interface only | records neighbours heard on the interface | `show lldp neighbors` |
| destination | `set interface <if> lldp destination nearest-bridge\|non-tpmr\|customer-bridge` / `set lldp destination …`; `delete … lldp destination` | `interface/<if>/lldp-destination`, body `"NearestBridge"`, `"NonTpmr"` or `"CustomerBridge"` | default `nearest-bridge` | physical interface only | the multicast group sent to and listened on | `show config` |
| tx-interval | `set lldp tx-interval <secs>`; `delete lldp tx-interval` | `lldp/tx-interval-secs` | 1-3600 seconds, default 30 | range; `tx-interval × tx-hold` ≤ 65535 | time between frames, on every interface | the neighbour's `show lldp neighbors` (`ttl`) |
| tx-hold | `set lldp tx-hold <n>`; `delete lldp tx-hold` | `lldp/tx-hold` | 1-100, default 4 | range; as above | advertised time to live = `tx-interval × tx-hold` | the neighbour's `show lldp neighbors` (`ttl`) |
| management-address | `set lldp management-address <ip>`; `delete lldp management-address` | `lldp/management-address` | IPv4 or IPv6 address, default none | unicast (not unspecified, not multicast) | advertised on every interface | the neighbour's `show lldp neighbors` (`management`) |

`tx-interval`, `tx-hold` and `management-address` are system-wide: they are typed the same way from anywhere in configuration mode.

Implementation notes for developers are in [`lldp/CLAUDE.md`](../../lldp/CLAUDE.md).
