use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;

/// The source side of a `Redistribute` rule. Only `Static` exists today —
/// see `Redistribute`'s doc comment for why this is an enum rather than a
/// bare marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedistributeSource {
    Static,
}

impl RedistributeSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            RedistributeSource::Static => "static",
        }
    }
}

impl std::fmt::Display for RedistributeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The target side of a `Redistribute` rule — `Bgp` or `Ospf`. See
/// `Redistribute`'s doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedistributeTarget {
    Bgp,
    Ospf,
}

impl RedistributeTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            RedistributeTarget::Bgp => "bgp",
            RedistributeTarget::Ospf => "ospf",
        }
    }
}

impl std::fmt::Display for RedistributeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single route-redistribution rule on a `RoutingTable` (syntax:
/// `redistribute from static to bgp`). Modeled as `Option<Redistribute>` on
/// the table, not `Vec<Redistribute>`: at most one meaningful rule exists
/// today, and a future second source/target is an enum-variant addition on
/// `RedistributeSource`/`RedistributeTarget`, not a shape change here.
/// `Vec<Redistribute>` is the documented follow-up if multiple simultaneous
/// rules are ever needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redistribute {
    pub from: RedistributeSource,
    pub to: RedistributeTarget,
    /// Names a `PolicyDefinition` (or the built-in `accept-all`/`deny-all`)
    /// to filter redistributed routes through before they reach BGP.
    /// Unlike `BgpPeerGroup.import_policy`/`export_policy`, `None` here
    /// means **accept-all**, not `deny-all` — redistribution has no
    /// filtering today, and defaulting to deny-all would silently break
    /// every existing `redistribute from static to bgp` config.
    pub policy: Option<String>,
}

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

    #[garde(custom(|oi: &Option<String>, ctx: &Config| ospf_instance_reference_valid(oi.as_ref(), ctx)))]
    pub ospf_instance: Option<String>,

    /// Same shape as `ospf_instance`, associating this table with an
    /// `Ospfv3Instance` (RFC 5340) instead — a separate field, not a
    /// widened `ospf_instance`, since `nos-ospfd`/`nos-ospfv3d` are two
    /// independent daemons that can both legitimately claim the same table
    /// (dual-stack OSPF on one VRF).
    #[garde(custom(|oi: &Option<String>, ctx: &Config| ospfv3_instance_reference_valid(oi.as_ref(), ctx)))]
    pub ospfv3_instance: Option<String>,

    /// `#[garde(skip)]`: the cross-field constraint (the referenced
    /// `bgp_instance`/`static_routing_instance` must actually be set on this
    /// same table) can't live in a per-field closure — garde's per-field
    /// `custom` closures can't see a sibling field — so it's wired one level
    /// up, on `Config.routing_tables` (`valid_redistribute_rules`), the same
    /// reason `BgpPeerGroup`'s timer check is wired on `BgpInstance.peer_groups`.
    #[garde(skip)]
    pub redistribute: Option<Redistribute>,
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
/// `ctx.ospf_instances` instead.
fn ospf_instance_reference_valid(ospf_instance: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = ospf_instance else {
        return Ok(());
    };
    if !ctx.ospf_instances.iter().any(|i| &i.name == name) {
        return Err(garde::Error::new("referenced ospf instance does not exist"));
    }
    let claims = ctx
        .routing_tables
        .iter()
        .filter(|t| t.ospf_instance.as_deref() == Some(name.as_str()))
        .count();
    if claims > 1 {
        return Err(garde::Error::new(
            "ospf instance is already associated with another routing table",
        ));
    }
    Ok(())
}

/// Same shape as `ospf_instance_reference_valid`, checked against
/// `ctx.ospfv3_instances` instead.
fn ospfv3_instance_reference_valid(
    ospfv3_instance: Option<&String>,
    ctx: &Config,
) -> garde::Result {
    let Some(name) = ospfv3_instance else {
        return Ok(());
    };
    if !ctx.ospfv3_instances.iter().any(|i| &i.name == name) {
        return Err(garde::Error::new(
            "referenced ospfv3 instance does not exist",
        ));
    }
    let claims = ctx
        .routing_tables
        .iter()
        .filter(|t| t.ospfv3_instance.as_deref() == Some(name.as_str()))
        .count();
    if claims > 1 {
        return Err(garde::Error::new(
            "ospfv3 instance is already associated with another routing table",
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

/// Cross-field check for the whole `routing_tables` list — garde's per-field
/// `custom` closures only ever see `(field_value, &Config)`, never a sibling
/// field on the same struct, so `redistribute`'s constraint on
/// `bgp_instance`/`static_routing_instance` must be wired here instead of on
/// `RoutingTable.redistribute` itself (mirrors
/// `bgp_peer_group::valid_peer_group_timers`'s technique).
///
/// `from: Static` requires `static_routing_instance` to be set; `to: Bgp`
/// requires `bgp_instance` to be set. Checked only at commit time, never in
/// `RoutingTableOp::apply`.
pub(crate) fn valid_redistribute_rules(tables: &[RoutingTable], ctx: &Config) -> garde::Result {
    for table in tables {
        let Some(redistribute) = &table.redistribute else {
            continue;
        };
        if redistribute.from == RedistributeSource::Static
            && table.static_routing_instance.is_none()
        {
            return Err(garde::Error::new(
                "redistribute from static requires static-routing-instance to be set",
            ));
        }
        if redistribute.to == RedistributeTarget::Bgp && table.bgp_instance.is_none() {
            return Err(garde::Error::new(
                "redistribute to bgp requires bgp-instance to be set",
            ));
        }
        if redistribute.to == RedistributeTarget::Ospf && table.ospf_instance.is_none() {
            return Err(garde::Error::new(
                "redistribute to ospf requires ospf-instance to be set",
            ));
        }
        redistribute_policy_reference_valid(redistribute.policy.as_ref(), ctx)?;
    }
    Ok(())
}

/// Same shape as `bgp_peer_group::policy_reference_valid`: `None` or the
/// built-in `accept-all`/`deny-all` names are always valid, anything else
/// must match a real `PolicyDefinition`.
fn redistribute_policy_reference_valid(name: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = name else {
        return Ok(());
    };
    if name == nos_rpl::ACCEPT_ALL_NAME || name == nos_rpl::DENY_ALL_NAME {
        return Ok(());
    }
    if ctx.policy_definitions.iter().any(|p| &p.name == name) {
        Ok(())
    } else {
        Err(garde::Error::new("referenced policy does not exist"))
    }
}

#[cfg(test)]
mod tests {
    use crate::schema::{BgpInstance, Config, OspfInstance, StaticRoutingInstance};

    use super::*;

    fn table(name: &str, bgp_instance: Option<&str>, sri: Option<&str>) -> RoutingTable {
        RoutingTable {
            ospfv3_instance: None,
            name: name.to_string(),
            bgp_instance: bgp_instance.map(str::to_string),
            ospf_instance: None,
            static_routing_instance: sri.map(str::to_string),
            redistribute: None,
        }
    }

    fn ospf_instance(name: &str) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
        }
    }

    fn instance(name: &str) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            routing_table: None,
            redistribute_policy: None,
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

    #[test]
    fn valid_table_with_ospf_association_passes() {
        let mut cfg = config_with(vec![table("rt1", None, None)], vec![], vec![]);
        cfg.routing_tables[0].ospf_instance = Some("o1".to_string());
        cfg.ospf_instances = vec![ospf_instance("o1")];
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_ospf_instance_reference_fails() {
        let mut cfg = config_with(vec![table("rt1", None, None)], vec![], vec![]);
        cfg.routing_tables[0].ospf_instance = Some("does-not-exist".to_string());
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn two_tables_claiming_same_ospf_instance_fails() {
        let mut cfg = config_with(
            vec![table("rt1", None, None), table("rt2", None, None)],
            vec![],
            vec![],
        );
        cfg.routing_tables[0].ospf_instance = Some("o1".to_string());
        cfg.routing_tables[1].ospf_instance = Some("o1".to_string());
        cfg.ospf_instances = vec![ospf_instance("o1")];
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn redistribute() -> Redistribute {
        Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Bgp,
            policy: None,
        }
    }

    #[test]
    fn redistribute_with_both_associations_passes() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = Some(redistribute());
        let cfg = config_with(
            vec![rt],
            vec![instance("r1")],
            vec![static_instance("sri1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn redistribute_without_static_routing_instance_fails() {
        let mut rt = table("rt1", Some("r1"), None);
        rt.redistribute = Some(redistribute());
        let cfg = config_with(vec![rt], vec![instance("r1")], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_without_bgp_instance_fails() {
        let mut rt = table("rt1", None, Some("sri1"));
        rt.redistribute = Some(redistribute());
        let cfg = config_with(vec![rt], vec![], vec![static_instance("sri1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_without_ospf_instance_fails() {
        let mut rt = table("rt1", None, Some("sri1"));
        rt.redistribute = Some(Redistribute {
            to: RedistributeTarget::Ospf,
            ..redistribute()
        });
        let cfg = config_with(vec![rt], vec![], vec![static_instance("sri1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_to_ospf_with_ospf_instance_passes() {
        let mut rt = table("rt1", None, Some("sri1"));
        rt.ospf_instance = Some("o1".to_string());
        rt.redistribute = Some(Redistribute {
            to: RedistributeTarget::Ospf,
            ..redistribute()
        });
        let mut cfg = config_with(vec![rt], vec![], vec![static_instance("sri1")]);
        cfg.ospf_instances = vec![ospf_instance("o1")];
        cfg.validate_with(&cfg).unwrap();
    }

    fn config_with_policy(
        rt: RoutingTable,
        policies: Vec<crate::schema::PolicyDefinition>,
    ) -> Config {
        let mut cfg = config_with(
            vec![rt],
            vec![instance("r1")],
            vec![static_instance("sri1")],
        );
        cfg.policy_definitions = policies;
        cfg
    }

    #[test]
    fn redistribute_with_no_policy_passes() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = Some(redistribute());
        let cfg = config_with_policy(rt, vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn redistribute_with_existing_policy_passes() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = Some(Redistribute {
            policy: Some("p1".to_string()),
            ..redistribute()
        });
        let cfg = config_with_policy(
            rt,
            vec![crate::schema::PolicyDefinition {
                name: "p1".to_string(),
                source: "accept\n".to_string(),
            }],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn redistribute_with_dangling_policy_fails() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = Some(Redistribute {
            policy: Some("does-not-exist".to_string()),
            ..redistribute()
        });
        let cfg = config_with_policy(rt, vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_with_builtin_policy_names_passes() {
        for name in [nos_rpl::ACCEPT_ALL_NAME, nos_rpl::DENY_ALL_NAME] {
            let mut rt = table("rt1", Some("r1"), Some("sri1"));
            rt.redistribute = Some(Redistribute {
                policy: Some(name.to_string()),
                ..redistribute()
            });
            let cfg = config_with_policy(rt, vec![]);
            cfg.validate_with(&cfg).unwrap();
        }
    }
}
