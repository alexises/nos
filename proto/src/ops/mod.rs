pub mod bgp_instance;

pub use bgp_instance::BgpInstanceOp;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::schema::Config;

/// A single edit applied to a transaction's in-progress config tree.
///
/// One variant per config section. Adding a second section follows the same
/// convention as `proto/CLAUDE.md`'s "Adding a new config section": add a
/// sibling `<Section>Op` enum in `ops/<section>.rs`, then a new `ConfigOp`
/// variant wrapping it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigOp {
    BgpInstance(BgpInstanceOp),
}

impl ConfigOp {
    /// Applies the op to `config` in place. Never runs `garde` validation —
    /// validation happens only at commit time. Only reports structural
    /// errors (e.g. setting a field on a name that doesn't exist).
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            ConfigOp::BgpInstance(op) => op.apply(config),
        }
    }
}

#[derive(Debug, Error)]
pub enum OpError {
    #[error("bgp instance '{0}' not found")]
    BgpInstanceNotFound(String),
}
