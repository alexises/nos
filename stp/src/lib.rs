// nos-stp: pure IEEE 802.1Q spanning-tree building blocks (BPDU codec, priority
// vectors, path costs, timers). No NOS dependencies, no I/O — see stp/CLAUDE.md.

pub mod bpdu;
pub mod cost;
pub mod timers;
pub mod vector;
