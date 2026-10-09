// nos-stp: pure IEEE 802.1Q spanning-tree logic (BPDU codec, priority vectors,
#![allow(clippy::many_single_char_names, clippy::similar_names)] // b/i/p/s: bridge/port/state, as in every machine
#![allow(clippy::match_same_arms)] // one arm per diagram edge, even when two edges do the same
                                   // path costs, timers, and the clause 13 RSTP state machines). No NOS
                                   // dependencies, no I/O, no clock — see stp/CLAUDE.md.

pub mod actions;
pub mod bpdu;
pub mod bridge;
pub mod cost;
pub mod machines;
pub mod timers;
pub mod vector;

#[cfg(test)]
mod sim;
