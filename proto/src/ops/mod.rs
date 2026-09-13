pub mod bgp_instance;
pub mod bgp_peer;
pub mod bgp_peer_group;

pub use bgp_instance::BgpInstanceOp;
pub use bgp_peer::BgpPeerOp;
pub use bgp_peer_group::BgpPeerGroupOp;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::schema::Config;

/// A single edit applied to a transaction's in-progress config tree.
///
/// One variant per config section, plus one variant per top-level scalar
/// field. Adding a new named/keyed section follows the convention in
/// `proto/CLAUDE.md`'s "Adding a new config section": add a sibling
/// `<Section>Op` enum in `ops/<section>.rs`, then a new `ConfigOp` variant
/// wrapping it. A scalar field with a single possible edit (like
/// `hostname`) skips that — it gets one `ConfigOp` variant directly here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigOp {
    BgpInstance(BgpInstanceOp),
    SetHostname(String),
    BgpPeerGroup(BgpPeerGroupOp),
    BgpPeer(BgpPeerOp),
}

impl ConfigOp {
    /// Applies the op to `config` in place. Never runs `garde` validation —
    /// validation happens only at commit time. Only reports structural
    /// errors (e.g. setting a field on a name that doesn't exist).
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            ConfigOp::BgpInstance(op) => op.apply(config),
            ConfigOp::SetHostname(hostname) => {
                config.hostname.clone_from(hostname);
                Ok(())
            }
            ConfigOp::BgpPeerGroup(op) => op.apply(config),
            ConfigOp::BgpPeer(op) => op.apply(config),
        }
    }
}

#[derive(Debug, Error)]
pub enum OpError {
    #[error("bgp instance '{0}' not found")]
    BgpInstanceNotFound(String),
    #[error("peer-group '{name}' not found in bgp instance '{instance}'")]
    BgpPeerGroupNotFound { instance: String, name: String },
    #[error("peer '{remote_address}' not found in bgp instance '{instance}'")]
    BgpPeerNotFound {
        instance: String,
        remote_address: IpAddr,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_hostname_updates_config() {
        let mut cfg = Config::default();
        ConfigOp::SetHostname("router1".to_string())
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.hostname, "router1");
    }
}
