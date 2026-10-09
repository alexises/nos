// nos-bfd: RFC 5880 BFD (see bfd/CLAUDE.md). The pure core (codec, FSM,
// timers, authz) plus the `nos-bfdd` daemon built on it: sessions, the
// client-facing IPC server and the UDP sockets.

pub mod auth;
pub mod authz;
pub mod config_client;
pub mod echo;
pub mod fsm;
pub mod interface_client;
pub mod manager;
pub mod micro;
pub mod micro_sessions;
pub mod neigh;
pub mod packet;
pub mod reflector;
pub mod sbfd;
pub mod server;
pub mod session;
pub mod socket;
pub mod timers;
pub mod unsolicited;
pub mod watchdog_client;
