# Spanning tree

Spanning tree (IEEE 802.1Q clause 13) keeps an L2 topology loop-free.

- **Only `mode rstp` runs today.** `nos-stpd` speaks RSTP on every physical interface or port aggregate that has a `switching-profile`. `mstp` and `rapid-pvst` are accepted and checked but the daemon stays idle for them (and for `disabled`).
- **Fail-safe:** with a mode other than `disabled`, a new bridge port starts blocked and BPDUs are trapped until `nos-stpd` pushes a state (see [STP internals](../internals/stp.md#kernel-side-nos-interfaced-326)). Set `spanning-tree mode disabled` to forward without spanning tree.
- Everything is checked at commit time.
- A port aggregate with an `esi` needs a guard profile (see [ESI port aggregates](#esi-port-aggregates)).

## Enable it and pick the root

```
set spanning-tree mode rstp
set spanning-tree priority 4096
```

- `rstp` is the default mode. Both switches need it; the lowest priority (then lowest bridge MAC) becomes the root.
- Set the priority on the bridge you want as root. Leave the rest at 32768.
- Without spanning tree, two parallel links between two switches in one broadcast domain are a loop: broadcasts circulate forever. With it, one link is blocked until the other fails.

## Read the state

```
show spanning-tree
```

- Prints the bridge id, the root id (and the root port and path cost, or "this bridge is the root"), the timers, then one row per port: `Name Role State Cost Prio Designated`.
- REST: `GET /v1/spanning-tree` (same data as JSON; `enabled: false` and no ports when the mode is not `rstp`).
- `nos-stpd is not running` means the daemon is down; `spanning-tree is disabled` means the mode is not `rstp`.

| Role | Meaning |
|------|---------|
| `root` | The port toward the root bridge; at most one per non-root bridge |
| `designated` | The port that sends the best BPDUs on its segment |
| `alternate` | A backup path to the root through another bridge; takes over within about a second on a point-to-point link |
| `backup` | A second port of this bridge on a segment it already serves |
| `disabled` | No carrier, or not usable |

| State | Meaning |
|-------|---------|
| `discarding` | No learning, no forwarding (the kernel's blocking) |
| `learning` | Learns source MACs, does not forward |
| `forwarding` | Normal operation |

- `Designated` is the bridge id and port id (`priority.number`) the segment is led by; `-` for a disabled port.
- A port is discarding right after start-up or a topology change, until the handshake with its neighbour finishes (about a second between RSTP switches, up to `2 * forward-delay` toward a legacy STP one).

## Configure the bridge

```
set spanning-tree mode rapid-pvst
set spanning-tree priority 4096
set spanning-tree hello-time 2
set spanning-tree max-age 20
set spanning-tree forward-delay 15
```

- `mode` is `rstp` (default), `mstp`, `rapid-pvst` or `disabled`.
- The REST equivalent of each line is `PUT /v1/transactions/<tx>/spanning-tree/<field>` (see [CLI ↔ API mapping](../cli-api-mapping.md)); enum bodies are the variant name, e.g. `"RapidPvst"`.
- An old `config.yaml` without a `spanning_tree` key loads with the defaults.

## Define a port profile

```
edit stp-port-profile edge
set edge-port admin
set bpdu-guard
```

- Attach it with `set interface <if> stp-port-profile edge` or `set port-aggregate <pa> stp-port-profile edge`.
- Only an interface with a `switching-profile` is a spanning-tree port. On another one the attachment is kept but unused, so the edit order stays free.
- An interface that is a member of a port aggregate cannot carry its own profile: the spanning-tree port is the aggregate.
- `delete stp-port-profile <name>` is refused at commit while an interface or aggregate still names it; each user fails under its own path.

## Use MSTP

```
set spanning-tree mode mstp
set spanning-tree region name lab
set spanning-tree region revision 1
set spanning-tree mst-instance 5 priority 8192
set broadcast domain bd5 stp-instance 5
set stp-port-profile edge mst-instance 5 cost 100
```

- An instance must exist under `spanning-tree mst-instance` before a broadcast domain or a port profile names it. At most 64 instances, ids 1-4094.
- A domain with no `stp-instance` stays in the CIST.

## Use Rapid PVST

```
set spanning-tree mode rapid-pvst
set broadcast domain bd5 stp-priority 4096
set broadcast domain bd5 stp-hello-time 1
```

- `stp-priority`, `stp-hello-time`, `stp-max-age` and `stp-forward-delay` on a domain override the global value for that VLAN; unset inherits.
- Per switching profile member, `set switching-profile <sp> broadcast-domain <bd> stp-cost <n>` and `stp-priority <n>` tune the port.

## ESI port aggregates

A multi-homed segment must never become a root or transit port of the spanning tree.

- While `spanning-tree mode` is not `disabled`, a port aggregate with an `esi` must name a profile with `edge-port admin` and `bpdu-guard`.
- `nos-provision --port-aggregate-esi` creates that profile (`esi-guard`) and attaches it for you.
- A saved config with an ESI aggregate and no such profile is refused at its next commit: add the profile, or set `spanning-tree mode disabled`.

## Settings

| Field | CLI | REST path | Type, range, default | Check |
|---|---|---|---|---|
| mode | `set spanning-tree mode <m>` | `spanning-tree/mode` | `rstp`, `mstp`, `rapid-pvst`, `disabled`; `rstp` | `mstp` and `rapid-pvst` need one VLAN per used domain (below) |
| priority | `set spanning-tree priority <n>` | `spanning-tree/priority` | 0-61440, multiple of 4096; 32768 | |
| hello-time | `set spanning-tree hello-time <s>` | `spanning-tree/hello-time` | 1-10; 2 | timer relation |
| max-age | `set spanning-tree max-age <s>` | `spanning-tree/max-age` | 6-40; 20 | timer relation |
| forward-delay | `set spanning-tree forward-delay <s>` | `spanning-tree/forward-delay` | 4-30; 15 | timer relation |
| tx-hold-count | `set spanning-tree tx-hold-count <n>` | `spanning-tree/tx-hold-count` | 1-10; 6 | |
| max-hops | `set spanning-tree max-hops <n>` | `spanning-tree/max-hops` | 6-40; 20 | |
| force-version | `set spanning-tree force-version stp\|rstp` | `spanning-tree/force-version` | unset | accepted with every mode |
| region | `set spanning-tree region name <s>` / `revision <n>` | `spanning-tree/region/name`, `…/revision` | name at most 32 bytes; revision 0-65535 | |
| mst-instance | `set spanning-tree mst-instance <1-4094> priority <n>` | `spanning-tree/mst-instance/<id>` | at most 64; priority as above | unique ids |
| edge-port | `set stp-port-profile <p> edge-port admin\|auto\|disabled` | `stp-port-profile/<p>/edge-port` | `auto` | |
| link-type | `set stp-port-profile <p> link-type auto\|point-to-point\|shared` | `stp-port-profile/<p>/link-type` | `auto` | |
| cost | `set stp-port-profile <p> cost <n>` | `stp-port-profile/<p>/cost` | 1-200000000; unset = from link speed | |
| priority | `set stp-port-profile <p> priority <n>` | `stp-port-profile/<p>/priority` | 0-240, multiple of 16; 128 | |
| bpdu-guard, bpdu-filter, root-guard, loop-guard, restricted-tcn | `set stp-port-profile <p> bpdu-guard` etc.; `delete …` | `stp-port-profile/<p>/bpdu-guard` etc. | bool; off | |
| bpdu-guard-recovery | `set stp-port-profile <p> bpdu-guard-recovery <s>` | `stp-port-profile/<p>/bpdu-guard-recovery` | at least 1; unset = never | |
| mst-instance (port) | `set stp-port-profile <p> mst-instance <id> cost\|priority <n>` | `stp-port-profile/<p>/mst-instance/<id>` | cost and priority as above | instance exists under `spanning-tree` |
| stp-port-profile (attach) | `set interface <if> stp-port-profile <p>`; `set port-aggregate <pa> stp-port-profile <p>` | `interface/<if>/stp-port-profile`, `port-aggregate/<pa>/stp-port-profile` | name; unset | profile exists; not on a bond member; ESI rule |
| stp-instance | `set broadcast domain <bd> stp-instance <id>` | `broadcast-domain/<bd>/stp-instance` | unset | instance exists |
| stp-priority, stp-hello-time, stp-max-age, stp-forward-delay | `set broadcast domain <bd> stp-priority <n>` etc. | `broadcast-domain/<bd>/stp-priority` etc. | unset = inherit | priority multiple of 4096; timer relation on the effective set |
| stp-cost, stp-priority (member) | `set switching-profile <sp> broadcast-domain <bd> stp-cost <n>` | `switching-profile/<sp>/member/<bd>/stp-cost` | cost 1-200000000; priority 0-240, multiple of 16 | |

## Commit checks

- **Timers** (802.1Q 13.25): `2 * (forward-delay - 1) >= max-age >= 2 * (hello-time + 1)`, checked on the global values and, for a domain that overrides any of them, on its effective set (its own value, else the global one).
- **Priorities:** bridge, MST instance and per-VLAN priorities are multiples of 4096 up to 61440; port priorities are multiples of 16 up to 240.
- **References:** an unknown profile, MST instance or deleted profile is refused.
- **Per-VLAN modes** (`mstp`, `rapid-pvst`): every domain used by an interface or aggregate switching profile must have one VLAN across all of them (an untagged-only membership is VLAN 1), and two domains may not share a VLAN. The error names the domain and both tags.
- **Bond members:** `stp-port-profile` on an interface with `port-aggregate` set is refused.
- **ESI:** see [above](#esi-port-aggregates).

## Verify

- `show config` prints what is set; the transaction diff shows what a commit would change.
- `show spanning-tree` shows what the daemon computed (above).
- The bounds come from the 802.1Q-2022 tables for the bridge and port parameters (Table 13-5 for the timers and counters); the standard is paywalled and was not available while writing this page, so re-check the ranges against it.

Related: [L2 switching](l2-switching.md), [Port aggregation and LACP](port-aggregation-lacp.md), [EVPN/VXLAN](evpn-vxlan.md).
