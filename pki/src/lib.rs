//! IPC transport security for NOS: mutual TLS over Unix sockets, with
//! `nos-watchdogd` as the certificate authority. No NOS dependencies, like
//! `nos-password`/`nos-tcp-auth` — callers name peers by `PeerId`
//! (`nos_proto::ServiceRef::peer_id` builds the expected one).

mod ca;
mod identity;
mod peer;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

pub use ca::{generate_csr, Bundle, Ca};
pub use identity::{connect, connect_role, global, install, Identity, Incoming, Listener, Stream};
pub use peer::PeerId;
