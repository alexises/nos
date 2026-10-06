//! Remote syslog export (RFC 5424 over RFC 5426 UDP / RFC 6587 TCP, #71).

pub mod client;
pub mod reconcile;
pub mod render;
pub mod sink;
