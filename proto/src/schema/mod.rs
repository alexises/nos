pub mod bgp_instance;
pub mod bgp_peer;
pub mod bgp_peer_group;
pub mod interface;
pub mod routing_table;
pub mod static_route;
pub mod static_routing_instance;

pub use bgp_instance::BgpInstance;
pub use bgp_peer::BgpPeer;
pub use bgp_peer_group::{
    AddressFamily, BgpAoAlgorithm, BgpAoKey, BgpAuth, BgpPeerGroup, NextHopMode,
    CONNECT_RETRY_TIME_DEFAULT_SECS, HOLD_TIME_DEFAULT, HOLD_TIME_FLOOR,
};
pub use interface::Interface;
pub use routing_table::{Redistribute, RedistributeSource, RedistributeTarget, RoutingTable};
pub use static_route::StaticRoute;
pub use static_routing_instance::StaticRoutingInstance;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::hostname_charset;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct Config {
    #[garde(dive)]
    pub bgp_instances: Vec<BgpInstance>,

    #[garde(
        dive,
        custom(|tables, _ctx: &Config| routing_table::valid_redistribute_rules(tables))
    )]
    pub routing_tables: Vec<RoutingTable>,

    #[garde(dive)]
    pub static_routing_instances: Vec<StaticRoutingInstance>,

    #[garde(dive)]
    pub interfaces: Vec<Interface>,

    #[serde(default = "default_hostname")]
    #[garde(length(min = 1, max = 253), custom(|h, _ctx: &Config| hostname_charset(h)))]
    pub hostname: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bgp_instances: Vec::new(),
            routing_tables: Vec::new(),
            static_routing_instances: Vec::new(),
            interfaces: Vec::new(),
            hostname: default_hostname(),
        }
    }
}

fn default_hostname() -> String {
    "nos".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_hostname_is_nos() {
        assert_eq!(Config::default().hostname, "nos");
    }

    #[test]
    fn valid_hostname_passes() {
        let cfg = Config {
            hostname: "router-1".to_string(),
            ..Default::default()
        };
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn empty_hostname_fails_length() {
        let cfg = Config {
            hostname: String::new(),
            ..Default::default()
        };
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn hyphen_leading_hostname_fails_charset() {
        let cfg = Config {
            hostname: "-router".to_string(),
            ..Default::default()
        };
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
