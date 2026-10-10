// nos-stp: IEEE 802.1Q spanning tree. The pure core (BPDU codec, priority
// vectors, path costs, timers, the clause 13 RSTP state machines) has no I/O
// and no clock; the `nos-stpd` daemon modules host it on real ports. See
// stp/CLAUDE.md.
#![allow(clippy::many_single_char_names, clippy::similar_names)] // b/i/p/s: bridge/port/state, as in every machine
#![allow(clippy::match_same_arms)] // one arm per diagram edge, even when two edges do the same

pub mod actions;
pub mod bpdu;
pub mod bridge;
pub mod cost;
pub mod machines;
pub mod mst;
pub mod pvst;
pub mod sstp;
pub mod timers;
pub mod vector;

// The daemon (#327).
pub mod authz;
pub mod config_client;
pub mod daemon;
pub mod engine;
pub mod identity;
pub mod interface_client;
pub mod link;
pub mod link_client;
pub mod ports;
pub mod reconcile;
pub mod server;
pub mod watchdog_client;

#[cfg(test)]
mod sim;
