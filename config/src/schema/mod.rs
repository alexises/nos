pub mod bgp_instance;

pub use bgp_instance::BgpInstance;

use garde::Validate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct Config {
    #[garde(dive)]
    pub bgp_instances: Vec<BgpInstance>,
}

impl Default for Config {
    fn default() -> Self {
        Self { bgp_instances: Vec::new() }
    }
}
