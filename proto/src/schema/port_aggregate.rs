use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::interface::{switching_profile_reference_valid, valid_mtu, valid_subinterface_list};
use super::{Config, Subinterface, VlanTag};

/// A bonding mode with no LACP (802.3ad) negotiation — the switch side must
/// be statically configured to match. Only the one mode this phase needs is
/// modeled; add a variant here (`RoundRobin`/`ActiveBackup`/`Broadcast`/…)
/// when a real need for it shows up, per `PortAggregate`'s own doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortAggregateMode {
    /// Linux bonding's `BalanceXor` — outgoing traffic is hashed across
    /// members by a fixed policy (source/destination MAC by default).
    Xor,
}

/// A named Linux bonding device — static aggregation only, no LACP. Same
/// config surface as a *physical* `Interface` (never a loopback — bonding a
/// loopback makes no sense): `switching_profile`/`mtu`/`subinterfaces`, all
/// validated by the exact same helpers `Interface` uses, plus `mode`. All L3
/// config (addresses/routing-table/OSPF) lives under `subinterfaces` (tag 0
/// for the untagged/native case), exactly like a physical `Interface` — a
/// `PortAggregate` never gets the loopback-style flat `addresses`/
/// `routing_table` fields, since there's no "loopback bond" concept. An
/// `Interface` becomes a bonded member by setting its own `port_aggregate`
/// field to this aggregate's name — the same reference-by-name shape
/// `Interface.switching_profile` already uses for L2 trunk membership —
/// rather than this type holding a member list itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct PortAggregate {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| port_aggregate_name_valid(n, ctx))
    )]
    pub name: String,

    #[garde(skip)]
    pub mode: PortAggregateMode,

    /// Names a `SwitchingProfile` trunking this bond into one or more
    /// `BroadcastDomain`s — same field, same meaning, as
    /// `Interface.switching_profile`.
    #[garde(custom(|sp: &Option<String>, ctx: &Config| switching_profile_reference_valid(sp.as_ref(), ctx)))]
    pub switching_profile: Option<String>,

    #[garde(custom(|m: &Option<u32>, _ctx: &Config| valid_mtu(*m)))]
    pub mtu: Option<u32>,

    /// This bond's own per-tag L3 attachment points — same type and same
    /// tag-0-is-untagged/native convention as `Interface.subinterfaces`.
    #[garde(dive, custom(|subs, _ctx: &Config| valid_subinterface_list(subs)))]
    pub subinterfaces: Vec<Subinterface>,
}

fn port_aggregate_name_valid(name: &String, ctx: &Config) -> garde::Result {
    unique_in(name, &ctx.port_aggregates, |a| &a.name)?;
    if name.contains('.') {
        return Err(garde::Error::new(
            "port aggregate name must not contain '.' (reserved for subinterface addressing, e.g. bond1.100)",
        ));
    }
    Ok(())
}

/// `Config.port_aggregates`-level validator: the same subinterface/
/// switching-profile tag-collision rule
/// `interface::valid_subinterface_and_switching_profile_tags` enforces on an
/// `Interface` — Linux only allows one master device per link, whether that
/// link is a physical interface or a bond. (The other half of that
/// interface-level validator, `valid_addressing_split`, has no counterpart
/// here — `PortAggregate` has no loopback-style flat L3 fields to keep
/// disjoint from `subinterfaces` in the first place.)
pub(crate) fn valid_port_aggregates(aggregates: &[PortAggregate], ctx: &Config) -> garde::Result {
    for agg in aggregates {
        if agg.subinterfaces.is_empty() {
            continue;
        }
        let Some(profile_name) = &agg.switching_profile else {
            continue;
        };
        let Some(profile) = ctx
            .switching_profiles
            .iter()
            .find(|p| &p.name == profile_name)
        else {
            continue;
        };
        for sub in &agg.subinterfaces {
            let collides = profile.members.iter().any(|m| match m.tag {
                VlanTag::Untagged => sub.tag == 0,
                VlanTag::Dot1q(n) => sub.tag == n,
            });
            if collides {
                return Err(garde::Error::new(format!(
                    "subinterface tag {} conflicts with a switching-profile member using the same tag",
                    sub.tag
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::InterfaceAddress;

    fn aggregate(name: &str) -> PortAggregate {
        PortAggregate {
            name: name.to_string(),
            mode: PortAggregateMode::Xor,
            switching_profile: None,
            mtu: None,
            subinterfaces: Vec::new(),
        }
    }

    fn config_with(aggregates: Vec<PortAggregate>) -> Config {
        Config {
            port_aggregates: aggregates,
            ..Default::default()
        }
    }

    #[test]
    fn valid_aggregate_passes() {
        let cfg = config_with(vec![aggregate("bond1")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![aggregate("bond1"), aggregate("bond1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dotted_name_fails() {
        let cfg = config_with(vec![aggregate("bond1.100")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn invalid_mtu_fails() {
        let mut agg = aggregate("bond1");
        agg.mtu = Some(10);
        let cfg = config_with(vec![agg]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn valid_subinterface_with_routing_table_passes() {
        let mut agg = aggregate("bond1");
        agg.subinterfaces = vec![crate::schema::Subinterface {
            tag: 0,
            addresses: vec![InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            }],
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            ospfv3_profile: None,
        }];
        let mut cfg = config_with(vec![agg]);
        cfg.routing_tables = vec![crate::schema::RoutingTable {
            ospfv3_instance: None,
            name: "rt1".to_string(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: None,
        }];
        cfg.validate_with(&cfg).unwrap();
    }
}
