// nos-ospf: OSPF daemon — Hello-protocol neighbor discovery up to 2-Way,
// point-to-point and broadcast (RFC 2328 DR/BDR election) links (see
// ospf/CLAUDE.md)

pub mod config_client;
pub mod election;
pub mod exchange;
pub mod interface_client;
pub mod link;
pub mod lsa;
pub mod lsdb;
pub mod neighbor;
pub mod packet;
pub mod reconcile;
pub mod rib_client;
pub mod server;
pub mod socket;
pub mod watchdog_client;
