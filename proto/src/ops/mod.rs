pub mod bgp_instance;

pub use bgp_instance::BgpInstanceOp;

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
        }
    }
}

#[derive(Debug, Error)]
pub enum OpError {
    #[error("bgp instance '{0}' not found")]
    BgpInstanceNotFound(String),
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
