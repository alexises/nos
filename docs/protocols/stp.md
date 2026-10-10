# Spanning tree

Spanning tree (IEEE 802.1Q clause 13) keeps an L2 topology loop-free.

- **`mode rstp` and `mode mstp` run today.** `nos-stpd` speaks them on every physical interface or port aggregate that has a `switching-profile`. `rapid-pvst` is accepted and checked but the daemon stays idle for it (and for `disabled`).
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
- REST: `GET /v1/spanning-tree` (same data as JSON; `enabled: false` and no ports when the mode is neither `rstp` nor `mstp`).
- `nos-stpd is not running` means the daemon is down; `spanning-tree is disabled` means the mode is neither `rstp` nor `mstp`.

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

## Protect a port

Set the protections on the `stp-port-profile` of the port.

```
edit stp-port-profile edge
set edge-port admin
set bpdu-guard enable
set bpdu-guard-recovery 300
```

| Protection | Use it on | Effect |
|---|---|---|
| `bpdu-guard` | A port to a host (an edge port, `admin` or detected by `auto`) | The first BPDU received shuts the link down (err-disabled) |
| `bpdu-guard-recovery <s>` | With `bpdu-guard` | The link comes back after `s` seconds; unset means only `clear` or removing the guard brings it back |
| `root-guard` | A port toward a switch that must never become the root | A superior BPDU makes the port alternate and discarding (root-inconsistent) for as long as it keeps arriving |
| `loop-guard` | A root or alternate port on a point-to-point link | When BPDUs stop arriving the port stays discarding (loop-inconsistent) instead of turning designated |
| `bpdu-filter` | A port that must stay silent | No BPDU is sent and none is processed |
| `restricted-tcn` | A port toward a switch you do not trust | A topology change received on it is not propagated to the other ports |

- `bpdu-guard` fires on any port that is an edge port at that moment: `edge-port admin`, or `auto` once no BPDU was heard for a few seconds. A port with `edge-port disabled` is never guarded.
- `bpdu-filter` on a port that is not an edge port can create a loop: both sides stop hearing each other and forward. Use it on edge ports only.
- A commit is refused for `root-guard` with `loop-guard`, `bpdu-filter` with `bpdu-guard`, and `bpdu-guard-recovery` without `bpdu-guard`.
- Loop guard clears when a BPDU arrives again or when the link goes down and up.

### Read and recover

- `show spanning-tree` adds a `Flags` column when a port has any: `Edge`, `BpduGuard`, `BpduFilter`, `RootGuard`, `LoopGuard`, `RestrictedTcn`, then what holds the port now: `Root-inconsistent`, `Loop-inconsistent`, `Err-disabled (recovers in 12s)` or `Err-disabled (manual clear)`. `GET /v1/spanning-tree` has the same fields per port.
- Logs: `port err-disabled port=<if> reason=bpdu-guard`, `port err-disabled recovered`, `port root-inconsistent` / `port root-consistent`, `port loop-inconsistent` / `port loop-consistent`.
- Recover an err-disabled port at once with `clear spanning-tree err-disabled <if>` (REST: `POST /v1/spanning-tree/port/<if>/err-disabled/clear`). It answers an error if the port is not err-disabled. If the BPDU source is still there the port is shut again.
- Removing `bpdu-guard` from the profile also brings the port back. Other config changes restart the protocol but keep an err-disabled port down.
- An err-disabled link is administratively down: LLDP and LACP on it stop too. Never put the guard on the interface that carries management traffic.

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
- A domain with no `stp-instance` stays in the CIST (instance 0).
- Every switch of one region needs the same `region name`, `region revision` and VLAN to instance map, or its ports toward the others are boundary ports (below).

### Map domains to instances

- A domain's VLAN is the dot1q tag of its switching-profile membership; a domain that is only untagged is VLAN 1. The instance is its `stp-instance`.
- `nos-stpd` derives the 4096-entry VLAN to instance table from that and hashes it into the MST configuration digest (802.1Q 13.8). Two switches share instances only when name, revision and digest all match.
- Every VLAN no domain uses maps to the CIST. A peer that maps extra VLANs to an instance gets a different digest; there is no explicit VLAN-range override, so give such a peer the same domains.
- Changing a domain's tag or `stp-instance` changes the digest and restarts the protocol, which is a region change for the peers: change every switch of the region in the same maintenance window.

### Read it and compare with a peer

```
show spanning-tree mst-config
show spanning-tree instance 5
```

- `mst-config` prints the region name, revision, digest (32 hex digits) and, per instance, the VLANs and domains. Compare the digest with the peer's: equal digests and equal name and revision mean one region.
- `instance <n>` prints the instance's bridge id, root (and root port and cost) and one row per port with role and state; a `Boundary` mark means the peer is outside the region and the port follows the CIST. `instance 0` is the CIST.
- REST: `GET /v1/spanning-tree/instance/<n>` and `GET /v1/spanning-tree/mst-config` (`404` when the mode is not `mstp` or the instance does not exist). `GET /v1/spanning-tree` also carries the `mst` object.
- Logs: `mst configuration` (once per start), `mst region match port=<if>` and `mst boundary port port=<if> reason=<plain-bpdu|name|revision|digest>` (once per change), `msti port role changed` and `msti port state changed port=<if> msti=<n> state=<s> domains=<list>`.

### What the kernel gets

- The state of a domain's bridge port is the state of the tree its `stp-instance` names. Instance 5 blocking `eth1` blocks `eth1.<tag>` of the domains in instance 5 and leaves the other domains on `eth1` forwarding, so two parallel links can each carry different VLANs.
- Domains without an instance, and untagged-only domains in the CIST, follow the CIST state of the physical link or bond.
- A topology change in an instance flushes only that instance's domains.

### Boundary ports

- A port is a boundary port when its peer is an RSTP or STP bridge, or an MST bridge of another region (name, revision or digest differs). The instances do not run there: every instance takes the CIST state of the port.
- Toward an RSTP peer `nos-stpd` still sends a version 3 BPDU, which RSTP reads as its CIST part; toward a legacy 802.1D peer the port migrates to STP as in [Interoperate with an 802.1D switch](#interoperate-with-an-8021d-switch) and sends Config BPDUs.
- A port leaves the boundary state when a BPDU of the same region arrives, or when the link goes down.

### Limits

- The CIST is one flat tree across regions: the external and internal root path costs are summed and the regional root is not tracked. Two NOS bridges, or one region of NOS bridges behind an RSTP core, behave correctly; mixing with another vendor's MSTP regions can pick a different root port than a full 802.1Q implementation would.
- `restricted-tcn`, root guard, loop guard and BPDU guard act on the CIST only; BPDU filter silences all instances.
- A per-instance port cost defaults to the CIST cost of the port (profile `cost`, else the link speed); `mst-instance <n> cost` overrides it for that instance.
- `max-hops` (default 20) is the remaining-hops budget of an instance's information; an instance's information from a bridge `max-hops` away is discarded.

## Use Rapid PVST

```
set spanning-tree mode rapid-pvst
set broadcast domain bd5 stp-priority 4096
set broadcast domain bd5 stp-hello-time 1
```

- `stp-priority`, `stp-hello-time`, `stp-max-age` and `stp-forward-delay` on a domain override the global value for that VLAN; unset inherits.
- Per switching profile member, `set switching-profile <sp> broadcast-domain <bd> stp-cost <n>` and `stp-priority <n>` tune the port.

## Interoperate with an 802.1D switch

- By default (`force-version` unset or `rstp`) each port starts in RSTP and falls back to 802.1D on its own when it hears a Config or TCN BPDU. Log: `port migrated to STP port=<if>`.
- A port that fell back stays in STP: a peer that later turns to RSTP is noticed on its first RST BPDU and the port migrates back (`port migrated to RSTP`), but a peer that merely stops talking does not.
- `set spanning-tree force-version stp` makes every port send Config/TCN BPDUs only, whatever the peer does. The port states then use the legacy Listening and Learning delays (`forward-delay` each, 30 s by default); Listening is shown as `discarding`.
- `clear spanning-tree detected-protocols [interface <if>]` (REST: `POST /v1/spanning-tree/mcheck`, or `/v1/spanning-tree/port/<if>/mcheck`) is the standard's `mcheck`: ports go back to RSTP and migrate again after Migrate Time (3 s) if the peer still sends STP BPDUs. It answers with the number of ports it reached.
- A change of `force-version` restarts the protocol, like any spanning-tree setting.
- Expect convergence in tens of seconds, not sub-second, on a legacy segment. Lowering `forward-delay` (4 to 30 s) and `max-age` shortens it within the timer relation.

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
| bpdu-guard, bpdu-filter, root-guard, loop-guard, restricted-tcn | `set stp-port-profile <p> bpdu-guard enable` etc.; `delete …` | `stp-port-profile/<p>/bpdu-guard` etc. | bool; off | see [Protect a port](#protect-a-port) |
| bpdu-guard-recovery | `set stp-port-profile <p> bpdu-guard-recovery <s>` | `stp-port-profile/<p>/bpdu-guard-recovery` | at least 1; unset = never | needs `bpdu-guard` |
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
- **Protections:** `root-guard` with `loop-guard`, `bpdu-filter` with `bpdu-guard`, and `bpdu-guard-recovery` without `bpdu-guard` are refused.
- **Bond members:** `stp-port-profile` on an interface with `port-aggregate` set is refused.
- **ESI:** see [above](#esi-port-aggregates).

## Verify

- `show config` prints what is set; the transaction diff shows what a commit would change.
- `show spanning-tree` shows what the daemon computed (above).
- The bounds come from the 802.1Q-2022 tables for the bridge and port parameters (Table 13-5 for the timers and counters); the standard is paywalled and was not available while writing this page, so re-check the ranges against it.

Related: [L2 switching](l2-switching.md), [Port aggregation and LACP](port-aggregation-lacp.md), [EVPN/VXLAN](evpn-vxlan.md).
