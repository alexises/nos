# Spanning tree internals

Reference for `nos-stp` (IEEE 802.1Q-2022). User-facing configuration: [Spanning tree](../protocols/stp.md).

## BPDU frame

- 802.3 frame: destination `01:80:c2:00:00:00`, source MAC, a length field (not an ethertype, at most 1500), LLC `42 42 03`, then the BPDU body.
- A receiver trusts the length field, so NIC padding after it is ignored.

## BPDU body

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | Protocol identifier, always 0 |
| 2 | 1 | Version: 0 Config, 2 RST (3 is MSTP, decoded as RST) |
| 3 | 1 | Type: `0x00` Config, `0x02` RST, `0x80` TCN |
| 4 | 1 | Flags |
| 5 | 8 | Root bridge identifier |
| 13 | 4 | Root path cost |
| 17 | 8 | Designated bridge identifier |
| 25 | 2 | Designated port identifier |
| 27 | 2 each | Message age, max age, hello time, forward delay (1/256 s) |
| 35 | 1 | RST only: Version 1 Length, 0 |

- Lengths: Config 35, RST 36, TCN 4 (header only).
- Flags: bit 0 TC, 1 Proposal, 2-3 Port Role (0 unknown, 1 alternate/backup, 2 root, 3 designated), 4 Learning, 5 Forwarding, 6 Agreement, 7 TC Ack. A Config BPDU uses only TC and TC Ack.
- Bridge identifier: first u16 is priority (4 bits, steps of 4096) over system id extension (12 bits), then the MAC. Port identifier: priority (4 bits, steps of 16) over number (12 bits).

## Priority vector

- Order (13.10), lowest wins: root, root path cost, designated bridge, designated port, receiving port.
- Identifiers compare as the big-endian integers of their wire bytes.

## Path cost

- `cost = 20 000 000 / speed in Mb/s`, clamped to 1..=200 000 000 (Table 13-4 is exactly this: 1 Gb/s 20 000, 10 Gb/s 2 000, 100 Mb/s 200 000).
- A bond uses the same formula on the sum of its active members' speeds.
- Speed 0 (unknown) gives 200 000 000.

## Timers

| Timer | Default | Range |
|-------|---------|-------|
| Hello | 2 | 1-10 |
| Max age | 20 | 6-40 |
| Forward delay | 15 | 4-30 |
| Tx hold count | 6 | 1-10 |
| Migrate time | 3 | fixed |

- 13.25: `2 * (forward-delay - 1) >= max-age >= 2 * (hello + 1)`.

## Test vectors

- Config BPDUs in `bpdu.rs` are real: captured from two Linux bridges (`stp_state 1`, veth pair) in a user+net namespace. Reproduce with `unshare -rn`, `ip link add ... type bridge stp_state 1` and an `AF_PACKET` socket.
- The kernel never emits RST or TCN BPDUs (it runs legacy STP), so those vectors come from the layout above.

## Kernel side (`nos-interfaced`, #326)

How the bridge ports are made safe before `nos-stpd` exists. Spike results, on kernel 7.2.9:

- **BR_NO_STP floods the group MAC.** A Linux bridge with `stp_state 0` treats `01:80:c2:00:00:00` as ordinary traffic and forwards it. Every bridge port therefore gets an ingress `flower dst_mac <group> action drop` filter (the BPDU group, plus Cisco SSTP `01:00:0c:cc:cc:cd`) under a `clsact` qdisc: the BPDU never reaches the bridge.
- **The tap still sees it.** An `ETH_P_ALL` `AF_PACKET` socket taps before tc ingress and before the bridge `rx_handler`, so it receives the frames the filter drops. A protocol-bound socket (`ETH_P_802_2`) runs after them and gets nothing. `nos-stpd` (#327) must capture with `ETH_P_ALL`.
- **BLOCKING does not stick.** With STP off the kernel's `br_port_state_selection` turns a blocking port back into forwarding at once (every port is designated). Only DISABLED survives, written through `RTM_SETLINK` in the `AF_BRIDGE` family with `IFLA_PROTINFO` (`bridge link set dev <port> state 0`); the `RTM_NEWLINK` slave-data path ignores it. So `StpPortState::Blocking` is kernel DISABLED, which neither learns nor forwards. `Learning` is 2, `Forwarding` 3, both through the same path.
- **A down device refuses** a state write (`ENETDOWN`) but is already DISABLED. The kernel opens a port when its link goes up, so the driver reconciles again right after every `up`.

Fail-safe rules:

- While `spanning-tree mode` is not `disabled` (the default is `rstp`), a bridge port is blocked and trapped until `nos-stpd` pushes a state. Log: `bridge port enslaved blocking interface=<link>`, `bpdu trap installed interface=<link>`. Until #327 lands this blackholes bridge ports by design.
- Window: one netlink round trip between the kernel opening a freshly enslaved running port and the block; and, after a carrier flap, up to the 10s resync. `nos-stpd` shortens the second one by reacting to `SubscribeLinks`.
- Mode `disabled` restores forwarding and removes the trap, but only on ports this process blocked or trapped (`nos-fdbd` also disables ports, for single-active segments). Logs: `bridge port forwarding restored`, `bpdu trap removed`.
- The VXLAN port of a VNI domain is never touched.

How to check by hand, in a throwaway namespace (`unshare -Urn`): `ip link add br0 type bridge stp_state 0`, a veth pair with one end in `br0`, `bridge link show dev <port>` for the state, `tc filter show dev <port> ingress` for the trap. `cargo test -p nos-interface stp_kernel -- --ignored` runs the same against the driver.
