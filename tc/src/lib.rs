//! Hand-encoded Linux tc over a plain `NETLINK_ROUTE` socket: the `clsact`
//! qdisc, `flower`/`fw` filters with `gact`/`skbedit` actions, chains and
//! per-action stats dumps. `netlink-packet-route` types `flower` but not
//! `gact`, `skbedit` or `fw`, hence this crate. A leaf with no NOS
//! dependencies, like `nos-l2-socket`, shared by `nos-fdbd`,
//! `nos-interfaced` and `nos-acld`.
//!
//! [`send`] and [`dump`] block: call them from `spawn_blocking`.

mod consts;
mod decode;
mod encode;
mod genl;
mod socket;

pub use decode::FilterStats;
pub use encode::{
    encode, Action, ActionKind, Filter, FlowerKeys, Hook, Kind, Protocol, Request, Verdict,
    FLAG_FRAG_IS_FIRST, FLAG_IS_FRAGMENT,
};
pub use genl::{Psample, Sample};
pub use socket::{dump, psample, send, SampleSocket};
