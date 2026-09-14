use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;

/// A named routing table, optionally associated with one BGP instance and
/// one static routing instance. The reference lives only on the table —
/// `BgpInstance`/`StaticRoutingInstance` have no notion of which table(s)
/// reference them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct RoutingTable {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.routing_tables, |t| &t.name))
    )]
    pub name: String,

    #[garde(custom(|bi: &Option<String>, ctx: &Config| bgp_instance_reference_valid(bi.as_ref(), ctx)))]
    pub bgp_instance: Option<String>,

    #[garde(custom(|sri: &Option<String>, ctx: &Config| static_routing_instance_reference_valid(sri.as_ref(), ctx)))]
    pub static_routing_instance: Option<String>,
}

/// If set, `bgp_instance` must name an existing `BgpInstance` (cf.
/// `bgp_peer::peer_group_exists`), and at most one routing table may claim a
/// given instance at a time. A second table naming the same instance makes
/// *both* references invalid — this mirrors `bgp_peer_group::unique_name`'s
/// approach of scoring every occurrence rather than privileging a "first"
/// owner, since garde's validation context is fixed to `&Config` for the
/// whole dive chain.
fn bgp_instance_reference_valid(bgp_instance: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = bgp_instance else {
        return Ok(());
    };
    if !ctx.bgp_instances.iter().any(|i| &i.name == name) {
        return Err(garde::Error::new("referenced bgp instance does not exist"));
    }
    let claims = ctx
        .routing_tables
        .iter()
        .filter(|t| t.bgp_instance.as_deref() == Some(name.as_str()))
        .count();
    if claims > 1 {
        return Err(garde::Error::new(
            "bgp instance is already associated with another routing table",
        ));
    }
    Ok(())
}

/// Same shape as `bgp_instance_reference_valid`, checked against
/// `ctx.static_routing_instances` instead.
fn static_routing_instance_reference_valid(
    static_routing_instance: Option<&String>,
    ctx: &Config,
) -> garde::Result {
    let Some(name) = static_routing_instance else {
        return Ok(());
    };
    if !ctx.static_routing_instances.iter().any(|i| &i.name == name) {
        return Err(garde::Error::new(
            "referenced static routing instance does not exist",
        ));
    }
    let claims = ctx
        .routing_tables
        .iter()
        .filter(|t| t.static_routing_instance.as_deref() == Some(name.as_str()))
        .count();
    if claims > 1 {
        return Err(garde::Error::new(
            "static routing instance is already associated with another routing table",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::schema::{BgpInstance, Config, StaticRoutingInstance};

    use super::*;

    fn table(name: &str, bgp_instance: Option<&str>, sri: Option<&str>) -> RoutingTable {
        RoutingTable {
            name: name.to_string(),
            bgp_instance: bgp_instance.map(str::to_string),
            static_routing_instance: sri.map(str::to_string),
        }
    }

    fn instance(name: &str) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            routing_table: None,
        }
    }

    fn static_instance(name: &str) -> StaticRoutingInstance {
        StaticRoutingInstance {
            name: name.to_string(),
            routes: Vec::new(),
        }
    }

    fn config_with(
        tables: Vec<RoutingTable>,
        instances: Vec<BgpInstance>,
        static_instances: Vec<StaticRoutingInstance>,
    ) -> Config {
        Config {
            routing_tables: tables,
            bgp_instances: instances,
            static_routing_instances: static_instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_table_with_no_associations_passes() {
        let cfg = config_with(vec![table("rt1", None, None)], vec![], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_table_with_both_associations_passes() {
        let cfg = config_with(
            vec![table("rt1", Some("r1"), Some("sri1"))],
            vec![instance("r1")],
            vec![static_instance("sri1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_table_name_fails() {
        let cfg = config_with(
            vec![table("rt1", None, None), table("rt1", None, None)],
            vec![],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dangling_bgp_instance_reference_fails() {
        let cfg = config_with(
            vec![table("rt1", Some("does-not-exist"), None)],
            vec![],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dangling_static_routing_instance_reference_fails() {
        let cfg = config_with(
            vec![table("rt1", None, Some("does-not-exist"))],
            vec![],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn two_tables_claiming_same_bgp_instance_fails() {
        let cfg = config_with(
            vec![
                table("rt1", Some("r1"), None),
                table("rt2", Some("r1"), None),
            ],
            vec![instance("r1")],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn two_tables_claiming_same_static_routing_instance_fails() {
        let cfg = config_with(
            vec![
                table("rt1", None, Some("sri1")),
                table("rt2", None, Some("sri1")),
            ],
            vec![],
            vec![static_instance("sri1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_tables_claiming_distinct_instances_pass() {
        let cfg = config_with(
            vec![
                table("rt1", Some("r1"), Some("sri1")),
                table("rt2", Some("r2"), Some("sri2")),
            ],
            vec![instance("r1"), instance("r2")],
            vec![static_instance("sri1"), static_instance("sri2")],
        );
        cfg.validate_with(&cfg).unwrap();
    }
}
