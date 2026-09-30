# Port aggregation and LACP

A port aggregate bundles several physical links into one logical link (a bond, or LAG). This page covers static aggregates, LACP-negotiated ones, and how to check them. Addresses and VLANs on top of an aggregate work as on any interface: see [Interfaces](interfaces.md) and [L2 switching](l2-switching.md).

- [What a port aggregate is](#what-a-port-aggregate-is)
- [Common operations](#common-operations)
- [How aggregation behaves](#how-aggregation-behaves)
- [Configuration reference](#configuration-reference)

## What a port aggregate is

A `port-aggregate` is a named bond. Physical interfaces join it by pointing at it: `set interface eth1 port-aggregate bond1`. The aggregate itself is then used like a physical interface: it can be trunked into broadcast domains, carry routed subinterfaces, and have an MTU.

An aggregate runs in one of two modes:

- **`xor`** (static). Every member interface is put in the bond as soon as it is configured. There is no protocol with the other end, so both ends must be configured to match by hand. This is the default for a new aggregate.
- **`lacp`**. Members are negotiated with the other end using LACP (IEEE 802.1AX). A member only joins the bond once LACP on both ends agrees it should, and leaves it again when the partner stops answering. This protects against a miscabled or half-configured link, which a static bond would happily use.

In both modes, traffic is spread over the active members by a hash of each frame's source and destination MAC addresses, so traffic between two hosts always uses the same link.

## Common operations

The examples bundle `eth1` and `eth2` of router-a, which are cabled to `eth1` and `eth2` of router-b (see [Verification](#verification-notes) below for how this was set up in the lab).

### Create an LACP aggregate

```
router-a> configure lag
router-a(lag)> edit port-aggregate bond-lacp
router-a(lag/port-aggregate:bond-lacp)> set mode lacp
router-a(lag/port-aggregate:bond-lacp)> set lacp-rate fast
router-a(lag/port-aggregate:bond-lacp)> top
router-a(lag)> edit interface eth1
router-a(lag/interface:eth1)> set port-aggregate bond-lacp
router-a(lag/interface:eth1)> top
router-a(lag)> edit interface eth2
router-a(lag/interface:eth2)> set port-aggregate bond-lacp
router-a(lag/interface:eth2)> commit
transaction 'lag' committed
```

The same on router-b. Once both ends have negotiated:

```
router-a> show lacp
lacp bond-lacp: system 02:47:33:45:65:f2, key 1, rate fast
  eth1: port 17, receive current, mux distributing, partner 02:e1:8b:33:6b:4c key 1 port 4, selected yes, synchronized yes, churn none
  eth2: port 18, receive current, mux distributing, partner 02:e1:8b:33:6b:4c key 1 port 5, selected yes, synchronized yes, churn none
router-a> show port-aggregate
port-aggregate bond-lacp: mode Lacp, switching-profile unset, mtu 1500
```

Absolute forms: `edit port-aggregate bond-lacp`, `set port-aggregate bond-lacp mode lacp`, `set port-aggregate bond-lacp lacp-rate fast`, and `set interface eth1 port-aggregate bond-lacp`, which creates `eth1` in the configuration if it isn't there yet, like every `set`. A static aggregate is the same without `mode lacp` and `lacp-rate`.

REST:

```sh
$ $C -X POST $B/v1/transactions/lag
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"name":"bond-lacp","mode":"Lacp","lacp_rate":"Fast","subinterfaces":[]}' \
    $B/v1/transactions/lag/port-aggregate/bond-lacp
$ $C -X PUT -H 'Content-Type: application/json' -d '{"name":"eth1","addresses":[],"subinterfaces":[],"port_aggregate":"bond-lacp"}' \
    $B/v1/transactions/lag/interface/eth1
$ $C -X PUT -H 'Content-Type: application/json' -d '{"name":"eth2","addresses":[],"subinterfaces":[],"port_aggregate":"bond-lacp"}' \
    $B/v1/transactions/lag/interface/eth2
$ $C -X POST $B/v1/transactions/lag/commit
{"committed":"lag"}
$ $C $B/v1/lacp/bond-lacp | jq -c '{aggregate, actor_key, rate, ports: [.ports[] | {interface, receive_state, mux_state, partner_port_number, selected, synchronized}]}'
{"aggregate":"bond-lacp","actor_key":1,"rate":"Fast","ports":[{"interface":"eth1","receive_state":"Current","mux_state":"Distributing","partner_port_number":4,"selected":true,"synchronized":true},{"interface":"eth2","receive_state":"Current","mux_state":"Distributing","partner_port_number":5,"selected":true,"synchronized":true}]}
```

For an interface that is already in the configuration, set only the field: `PUT …/interface/eth1/port-aggregate` with body `"bond-lacp"`.

### Use the aggregate

Route the aggregate like an interface: its subinterface 0 is the bond itself. For example, to route `bond-lacp` in `rt1` with a 9000-byte MTU:

```
router-a> configure lag2
router-a(lag2)> edit port-aggregate bond-lacp
router-a(lag2/port-aggregate:bond-lacp)> set mtu 9000
router-a(lag2/port-aggregate:bond-lacp)> edit subinterface 0
router-a(lag2/port-aggregate:bond-lacp/subinterface:0)> set address 192.0.2.33/29
router-a(lag2/port-aggregate:bond-lacp/subinterface:0)> set routing-table rt1
router-a(lag2/port-aggregate:bond-lacp/subinterface:0)> commit
transaction 'lag2' committed
```

The same over REST:

```sh
$ $C -X POST $B/v1/transactions/lag2
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"tag":0,"addresses":[{"address":"192.0.2.33/29","label":null}],"routing_table":"rt1"}' \
    $B/v1/transactions/lag2/port-aggregate/bond-lacp/subinterface/0
$ $C -X PUT -H 'Content-Type: application/json' -d '9000' $B/v1/transactions/lag2/port-aggregate/bond-lacp/mtu
$ $C -X POST $B/v1/transactions/lag2/commit
{"committed":"lag2"}
```

Then, in the shell:

```
router-a> show port-aggregate
port-aggregate bond-lacp: mode Lacp, switching-profile unset, mtu 9000
  subinterface 0: address [192.0.2.33/29], routing-table rt1
```

To trunk the aggregate into broadcast domains instead, `set port-aggregate bond-lacp switching-profile sp1` (REST: `PUT …/port-aggregate/bond-lacp/switching-profile` with body `"sp1"`).

Known gap: addresses on an aggregate's subinterfaces are applied, but they are not listed as `connected` routes in `show route`, unlike those of an interface or an SVI.

### Take a member out, or remove the aggregate

`delete interface eth2 port-aggregate` releases `eth2` from the bond. To delete the aggregate, first release every member, since a member still pointing at a missing aggregate fails the commit:

```
router-a> configure nolag
router-a(nolag)> delete interface eth1 port-aggregate
router-a(nolag)> delete interface eth2 port-aggregate
router-a(nolag)> delete port-aggregate bond-lacp
router-a(nolag)> commit
transaction 'nolag' committed
```

REST: `DELETE …/interface/eth1/port-aggregate`, the same for `eth2`, then `DELETE …/port-aggregate/bond-lacp`, and commit.

## How aggregation behaves

**Members.** A member must be a physical interface, and it gives the whole link to the bond: the commit refuses a member that also has subinterfaces (including an untagged `.0`) or a switching profile. Put those on the aggregate instead. LLDP, which is per physical link, still runs on the members (see [LLDP](lldp.md)).

**LACP negotiation.** In `lacp` mode each member runs the LACP state machines. `show lacp` shows, per member, two of them:

- `receive` is whether the partner is heard: `current` when LACPDUs arrive in time, `expired` right after they stop, then `defaulted`.
- `mux` is how far the member is into the bond: `detached`, `waiting` (a two-second settling time), `attached`, `collecting`, and finally `distributing`. Only a `distributing` member carries traffic, and NOS adds a member to the bond only in that state.

`selected` and `synchronized` say whether the member is chosen for the aggregate and in sync with the partner. `churn` reports `actor` or `partner` when one side has stayed out of sync for too long, which usually means a misconfiguration at that end; the member is kept out of the bond until it clears.

**`lacp-rate`** is how often this end asks its partner to send LACPDUs, and so how quickly a dead partner is detected: `slow` (default) asks for one every 30 seconds and gives up after 90; `fast` asks for one every second and gives up after 3. Each end sends at the rate the *other* end asks for, so set `fast` on both ends for fast detection in both directions.

**LACP identity.** An LACP partner is identified by a system ID (a MAC address) and a key. NOS derives both from the router and the aggregate; `show lacp` shows them as `system` and `key`. `lacp-system-id` overrides the system ID. It is meant for EVPN multi-homing, where two routers present one LACP partner to a dual-homed device: set the same value on both.

**EVPN multi-homing.** `esi` attaches the aggregate to an EVPN Ethernet Segment, and `redundancy-mode` chooses all-active or single-active forwarding for it. They are documented with EVPN.

**`show port-aggregate`** shows each aggregate's mode, switching profile, MTU and subinterfaces, as applied; `show lacp` the LACP state of every `lacp` aggregate. Neither lists the members of an `xor` aggregate: check them in `show config`.

### Verification notes

The examples on this page were run on the lab of the [README](../README.md#conventions-used-in-these-pages), with two extra links: `eth1` and `eth2` are veth pairs directly between router-a and router-b. A direct link matters: LACP (and LLDP) frames use reserved multicast addresses that a bridge, including a Docker network, never forwards, so the two ends would never hear each other through one.

## Configuration reference

Every REST path starts with `/v1/transactions/{tx}/`. The relative CLI form is what you type after `edit port-aggregate <pa>`.

### `port-aggregate <pa>`

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit port-aggregate <pa>` (creates it in `xor` mode); `delete port-aggregate <pa>` | `port-aggregate/<pa>` | string, 1-64 characters | unique; no `.`; no member may still reference a deleted aggregate | creates or deletes the bond | `show port-aggregate` |
| mode | `set port-aggregate <pa> mode xor\|lacp` / `set mode xor\|lacp` | `port-aggregate/<pa>/mode`, body `"Xor"` or `"Lacp"` | `xor` (default) or `lacp` | | `xor`: members join unconditionally; `lacp`: members join once negotiated | `show port-aggregate`, `show lacp` |
| lacp-rate | `set port-aggregate <pa> lacp-rate fast\|slow` / `set lacp-rate fast\|slow` | `port-aggregate/<pa>/lacp-rate`, body `"Fast"` or `"Slow"` | `slow` (default) or `fast` | | asks the partner for LACPDUs every 1 s (`fast`) or 30 s (`slow`); `lacp` mode only | `show lacp` (`rate`) |
| lacp-system-id | `set port-aggregate <pa> lacp-system-id <mac>` / `set lacp-system-id <mac>`; `delete … lacp-system-id` | `port-aggregate/<pa>/lacp-system-id` | unicast MAC, `02:00:00:00:00:01`; default derived | a unicast MAC | the LACP system ID advertised to the partner | `show lacp` (`system`) |
| esi | `set port-aggregate <pa> esi <esi>` / `set esi <esi>`; `delete … esi` | `port-aggregate/<pa>/esi` | 10 hex bytes; default unset | not all zero; unique among aggregates | EVPN Ethernet Segment, see EVPN | `show bgp evpn` |
| redundancy-mode | `set port-aggregate <pa> redundancy-mode all-active\|single-active` / `set redundancy-mode …` | `port-aggregate/<pa>/redundancy-mode`, body `"AllActive"` or `"SingleActive"` | `all-active` (default) | `single-active` needs an `esi` | EVPN multi-homing mode, see EVPN | `show config` |
| switching-profile | `set port-aggregate <pa> switching-profile <sp>` / `set switching-profile <sp>`; `delete … switching-profile` | `port-aggregate/<pa>/switching-profile` | name; default unset | profile exists; tags don't collide with the aggregate's subinterfaces | trunks the bond into the profile's broadcast domains | `show port-aggregate <pa>` |
| mtu | `set port-aggregate <pa> mtu <n>` / `set mtu <n>`; `delete … mtu` | `port-aggregate/<pa>/mtu` | 68-65535; default unset | range | the bond's MTU | `show port-aggregate <pa>` |
| subinterface | `edit port-aggregate <pa> subinterface <tag>`, then `set address <cidr>` / `set routing-table <t>`; `delete port-aggregate <pa> subinterface <tag>` | `port-aggregate/<pa>/subinterface/<tag>`, body `{"tag":<n>,"addresses":[…],"routing_table":…}` | tag 0-4094, as on an interface | as on an interface | routed subinterfaces of the bond (tag 0 is the bond itself) | `show port-aggregate <pa>` |

`mode`, `lacp-rate` and `redundancy-mode` cannot be deleted; set them back to their default instead.

### On a member interface

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| port-aggregate | `set interface <if> port-aggregate <pa>` / `set port-aggregate <pa>`; `delete interface <if> port-aggregate` / `delete port-aggregate` | `interface/<if>/port-aggregate` | name; default unset | aggregate exists; the interface has no subinterfaces and no switching profile | makes the interface a member | `show lacp` |

Implementation notes for developers are in [`lacp/CLAUDE.md`](../../lacp/CLAUDE.md) and [`interface/CLAUDE.md`](../../interface/CLAUDE.md).
