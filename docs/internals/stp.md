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
