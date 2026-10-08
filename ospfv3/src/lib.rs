// nos-ospfv3: OSPFv3 (RFC 5340) daemon — Phase 1: single-area intra-area
// adjacency, SPF, and route installation over real IPv6 links. See root
// CLAUDE.md's "New features require an end-to-end Docker verification
// phase" and the OSPFv3 Phase 1 plan for scope.

// One client for both daemons (the star dependency graph has no shared crate
// with tokio + nos-pki that fits): the file lives in `ospf/src`.
#[path = "../../ospf/src/bfd_client.rs"]
pub mod bfd_client;
pub mod config_client;
pub mod exchange;
pub mod interface_client;
pub mod link;
pub mod link_client;
pub mod lsa;
pub mod lsdb;
pub mod packet;
pub mod reconcile;
pub mod rib_client;
pub mod rib_push_client;
pub mod server;
pub mod socket;
pub mod spf;
pub mod watchdog_client;

pub use nos_ospf_common::{bfd, election, neighbor};
