// nos-ospf: OSPF daemon — Hello-protocol neighbor discovery up to 2-Way,
// point-to-point links only (see ospf/CLAUDE.md)

pub mod config_client;
pub mod interface_client;
pub mod link;
pub mod neighbor;
pub mod packet;
pub mod reconcile;
pub mod rib_client;
pub mod server;
pub mod socket;
pub mod watchdog_client;
