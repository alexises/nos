# nos-stp — spanning-tree building blocks

Pure library (no NOS dependencies, no I/O, no tokio) for the STP series (#316). The `nos-stpd` daemon arrives in a later sub-issue; byte layouts, cost table, the 13.25 rule, the machine table, the host contract and the deviations from the standard: `docs/internals/stp.md`.

## Modules

- `bpdu.rs`: IEEE 802.1Q-2022 cl.14. `decode`/`encode` work on the BPDU body, `decode_frame`/`encode_frame` add the 802.3 header (group MAC, length field, LLC `42 42 03`). `Bpdu::{Config, Rst}` share one `Params` struct.
- `vector.rs`: `BridgeId`, `PortId` (private fields, constructors reject bad priority/extension/number) and `PriorityVector` (derived `Ord` = 13.10 order, lower is better). The `infoIs`/`designatedPriority` comparisons are state-machine business, not here.
- `cost.rs`: Table 13-4 as `20 000 000 / speed_mbps` clamped to `1..=200 000 000`; speed 0 means unknown and gives the maximum.
- `timers.rs`: `Timers` defaults, Table 13-5 ranges and the 13.25 relation. The relation is also in the config commit check (`nos-proto`); this crate cannot depend on it.

- `machines/`: the nine clause 13 machines (`prx ppm bdm pim prs prt pst tcm ptx`), `step(&mut Bridge, port) -> bool` = one diagram edge; shared variables and procedures in `machines/mod.rs`. CIST only; `restricted*`/`mcheck` are seams.
- `bridge.rs`: `Bridge` (host inputs: `set_port_enabled`, `set_oper_point_to_point`, `receive`, `tick`; `run()` loops all machines to quiescence, cap 1000 passes). `actions.rs`: what the host drains (`Transmit`, `SetPortState`, `FlushFdb`, `Log`).
- `sim.rs` (test-only): deterministic multi-bridge simulator plus proptest on random graphs.

## Invariants

- Time enters only through `Bridge::tick` (1 s); no clock reads. A change to a machine guard needs a sim scenario or proptest run (`PROPTEST_CASES=3000`), the unit tests alone do not catch stalls.
- Timers in a BPDU stay raw `u16` (1/256 s) so any peer value round-trips; use `secs`/`raw_secs` for whole seconds.
- Decode ignores trailing bytes and NIC padding past the length field; a type 0x02 BPDU of version >= 2 (MSTP's 3 too) decodes as RST.
- Linux's kernel STP only emits Config BPDUs: the Config test vectors are real captures, the RST and TCN vectors follow the clause 14 layout.
