use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;

/// A named L2 broadcast domain. Carries no fields beyond its name —
/// `SwitchingProfile` is the only thing that references it, never the other
/// way around.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct BroadcastDomain {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.broadcast_domains, |d| &d.name))
    )]
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(domains: Vec<BroadcastDomain>) -> Config {
        Config {
            broadcast_domains: domains,
            ..Default::default()
        }
    }

    #[test]
    fn valid_domain_passes() {
        let cfg = config_with(vec![BroadcastDomain {
            name: "bd1".to_string(),
        }]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![
            BroadcastDomain {
                name: "bd1".to_string(),
            },
            BroadcastDomain {
                name: "bd1".to_string(),
            },
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn empty_name_fails() {
        let cfg = config_with(vec![BroadcastDomain {
            name: String::new(),
        }]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
