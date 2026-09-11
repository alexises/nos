pub mod bgp_instance;

pub use bgp_instance::BgpInstance;

use garde::Validate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct Config {
    #[garde(dive)]
    pub bgp_instances: Vec<BgpInstance>,
}
