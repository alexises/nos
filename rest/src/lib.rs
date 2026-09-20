// nos-rest: the HTTP+JSON management API (`nos-restd`, see rest/CLAUDE.md).
// One process per `RoutingTable` that has `rest-api` pinned to it, listening
// on that table's configured address inside its VRF. A thin translation layer:
// every endpoint resolves a daemon through the watchdog broker (or talks to
// `nos-configd`) and forwards one existing nos-proto request.

pub mod api;
pub mod error;
pub mod ipc;
pub mod listen;
pub mod openapi;
pub mod show;
pub mod tx;
pub mod watchdog_client;
