use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;

/// A named RPL script (see root `CLAUDE.md`'s "Routing policy language
/// (RPL)"), referenced by name from a `BgpPeerGroup`'s `import_policy`/
/// `export_policy`. Only the source text crosses the wire/IPC — each
/// consumer (`nos-bgpd`) compiles and caches its own bytecode locally,
/// matching the existing "each daemon re-resolves its own state from config
/// diffs" idiom, rather than `nos-proto` carrying a bytecode wire format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct PolicyDefinition {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| valid_name(n, ctx))
    )]
    pub name: String,

    #[garde(custom(|src: &String, _ctx: &Config| valid_source(src)))]
    pub source: String,
}

/// `"accept-all"`/`"deny-all"` are reserved system policies (see
/// `nos_rpl::ACCEPT_ALL_NAME`/`DENY_ALL_NAME`) — never stored as a
/// `PolicyDefinition`, so a user can't shadow or redefine either name.
fn valid_name(name: &String, ctx: &Config) -> garde::Result {
    if name == nos_rpl::ACCEPT_ALL_NAME || name == nos_rpl::DENY_ALL_NAME {
        return Err(garde::Error::new(format!(
            "'{name}' is a reserved system policy name"
        )));
    }
    unique_in(name, &ctx.policy_definitions, |p| &p.name)
}

/// Runs the real RPL compiler at commit time, so a syntactically or
/// semantically invalid policy is rejected before it ever reaches a
/// `nos-bgpd` instance — see root `CLAUDE.md`'s "Config schema changes".
fn valid_source(source: &str) -> garde::Result {
    nos_rpl::compile(source)
        .map(|_| ())
        .map_err(|e| garde::Error::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(policies: Vec<PolicyDefinition>) -> Config {
        Config {
            policy_definitions: policies,
            ..Default::default()
        }
    }

    fn policy(name: &str, source: &str) -> PolicyDefinition {
        PolicyDefinition {
            name: name.to_string(),
            source: source.to_string(),
        }
    }

    #[test]
    fn valid_policy_passes() {
        let cfg = config_with(vec![policy("p1", "accept\n")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn invalid_source_fails() {
        let cfg = config_with(vec![policy("p1", "if this.prefix in :\n    accept\n")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn non_terminating_source_fails() {
        let cfg = config_with(vec![policy(
            "p1",
            "if this.bgp.local_pref < 100:\n    reject\n",
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![policy("p1", "accept\n"), policy("p1", "reject\n")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn reserved_name_accept_all_fails() {
        let cfg = config_with(vec![policy("accept-all", "accept\n")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn reserved_name_deny_all_fails() {
        let cfg = config_with(vec![policy("deny-all", "reject\n")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
