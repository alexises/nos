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

## State machines (`nos-stp`, clause 13)

- The core is pure: `Bridge` holds the per-port variable set (13.27) and one state per machine; nothing reads a clock or touches a socket.
- One module per machine under `stp/src/machines/`, each with `step(&mut Bridge, port) -> bool` (one diagram edge per call) and `enter` (a state's entry actions). State names follow the standard (`DESIGNATED_PORT` is `prt::State::DesignatedPort`).

| Machine | Module | Clause | Job |
|---------|--------|--------|-----|
| Port Receive | `prx` | 13.28 | takes the delivered BPDU, sets `rcvdMsg`, `rcvdRSTP`/`rcvdSTP`, drops `operEdge` |
| Port Protocol Migration | `ppm` | 13.31 | `sendRSTP` per port: falls back to STP after a legacy BPDU, `mcheck` restarts the probe |
| Bridge Detection | `bdm` | 13.32 | `operEdge` from admin edge / auto-edge |
| Port Information | `pim` | 13.34 | judges a received vector against the port's (`rcvInfo`), ages info out |
| Port Role Selection | `prs` | 13.36 | per bridge: root port, designated vectors, every port's `selectedRole` |
| Port Role Transition | `prt` | 13.35 | roles, sync/agree/reRoot handshake, `learn`/`forward` |
| Port State Transition | `pst` | 13.38 | `learn`/`forward` become `learning`/`forwarding` |
| Topology Change | `tcm` | 13.37 | `tcWhile`, TC propagation, FDB flush |
| Port Transmit | `ptx` | 13.33 | builds and rate-limits (`txHoldCount`) Config/RST/TCN BPDUs |

## Host contract (what `nos-stpd` feeds and drains)

- Build with `Bridge::new(id, timers, &[PortParams])`; every port starts disabled.
- Inputs, each one call that also runs the machines to quiescence:
  - `set_port_enabled(port, up)` is `portEnabled` (carrier and admin state).
  - `set_oper_point_to_point(port, bool)` is `operPointToPoint` (full duplex or configured).
  - `receive(port, bpdu)` delivers a decoded BPDU.
  - `tick()` once per second; every 13.22 timer decrements here and the per-second `txCount` resets.
  - `set_path_cost`, `set_bridge_id` re-run role selection.
- Output: `take_actions()` returns, in order:
  - `Transmit { port, bpdu }`: encode with `bpdu::encode_frame` and send.
  - `SetPortState { port, Discarding | Learning | Forwarding }`: program the kernel port.
  - `FlushFdb { port }`: flush that port's learned MACs now (the core does not wait for completion).
  - `Log(Event)`: role and root changes, plain data for the host to log.
- Seams, present as variables at their default: `restrictedRole`/`restrictedTcn` false (#320), `mcheck` and `rstp_version` (#319), CIST only (#321).

## Deviations from the standard's text

- `setSyncTree` also clears `synced`. With `sync && synced` already true, a Designated port neither discards nor clears `sync` (both need `!synced`) and stalls forever; found by the random-graph test.
- `PIM` resets `agree` on superior info, so a new root port always runs a fresh sync/agreement cycle.
- DESIGNATED_DISCARD is tested before DESIGNATED_SYNCED: a forwarding port must stop forwarding before it counts as synced.
- A down port never transmits (`PTX` requires `portEnabled`).
- `rcvInfo` treats a Designated BPDU from the same bridge/port as the stored info but with different values (e.g. a larger cost) as superior, so upstream changes are accepted.
- A BPDU whose message age is already at max age is dropped in `PRX` (9.3.4).

## Run and read the simulator

- `cargo test -p nos-stp sim` runs `stp/src/sim.rs`: N bridges joined by in-memory links (two ends point-to-point, more a shared segment), BPDUs delivered instantly, time moves only on `Sim::tick`.
- A failing scenario prints `Sim::dump()`: root port, role and state of every port. `Sim::converged()` means one root everywhere, every port settled, and the forwarding links form a tree (a loop of stale root info otherwise looks settled).
- Property tests: `PROPTEST_CASES=3000 cargo test -p nos-stp random` stresses random 4-8 bridge graphs (also with a cut link).
- Expected timing with default timers: a point-to-point link converges within a few hello times; a shared segment waits `max-age + forward-delay` after start.
