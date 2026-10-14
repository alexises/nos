//! IPC transport security for NOS: post-quantum mutual TLS over Unix sockets, with
//! `nos-watchdogd` as the certificate authority. No NOS dependencies, like
//! `nos-password`/`nos-tcp-auth` — callers name peers by `PeerId`
//! (`nos_proto::ServiceRef::peer_id` builds the expected one).
#![warn(missing_docs)]

mod ca;
mod identity;
mod peer;
mod policy;
pub mod rest;
pub mod syslog;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

pub use ca::{generate_csr, generate_csr_for, Bundle, Ca, KeyAlg, Serial};
pub use identity::{
    connect, connect_role, global, install, Identity, Incoming, Listener, Negotiated, Stream,
};
pub use peer::PeerId;
pub use policy::Policy;
