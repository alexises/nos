# nos-stp — spanning-tree building blocks

Pure library (no NOS dependencies, no I/O, no tokio) for the STP series (#316). The `nos-stpd` daemon and the cl.13 state machines arrive in later sub-issues; byte layouts, cost table and 13.25 rule: `docs/internals/stp.md`.

## Modules

- `bpdu.rs`: IEEE 802.1Q-2022 cl.14. `decode`/`encode` work on the BPDU body, `decode_frame`/`encode_frame` add the 802.3 header (group MAC, length field, LLC `42 42 03`). `Bpdu::{Config, Rst}` share one `Params` struct.
- `vector.rs`: `BridgeId`, `PortId` (private fields, constructors reject bad priority/extension/number) and `PriorityVector` (derived `Ord` = 13.10 order, lower is better). The `infoIs`/`designatedPriority` comparisons are state-machine business, not here.
- `cost.rs`: Table 13-4 as `20 000 000 / speed_mbps` clamped to `1..=200 000 000`; speed 0 means unknown and gives the maximum.
- `timers.rs`: `Timers` defaults, Table 13-5 ranges and the 13.25 relation. The relation is also in the config commit check (`nos-proto`); this crate cannot depend on it.

## Invariants

- Timers in a BPDU stay raw `u16` (1/256 s) so any peer value round-trips; use `secs`/`raw_secs` for whole seconds.
- Decode ignores trailing bytes and NIC padding past the length field; a type 0x02 BPDU of version >= 2 (MSTP's 3 too) decodes as RST.
- Linux's kernel STP only emits Config BPDUs: the Config test vectors are real captures, the RST and TCN vectors follow the clause 14 layout.
