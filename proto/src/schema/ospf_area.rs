use std::net::Ipv4Addr;

use garde::Validate;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use super::ospf_profile;
use super::{Config, OspfProfile};
use nos_proto_derive::Cli;

/// One OSPF area within an `OspfInstance`, keyed by its dotted-quad area id
/// (e.g. `0.0.0.0` for the backbone). Unique only within its owning
/// instance — never referenced from outside `OspfInstance`, unlike
/// `OspfProfile.name` — so uniqueness is enforced on the parent's `areas`
/// field (`ospf_instance::unique_area_ids`), not here.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct OspfArea {
    // Ipv4Addr is structurally valid by construction; uniqueness lives on
    // the owning OspfInstance.areas field instead.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    pub area_id: Ipv4Addr,

    #[garde(
        dive,
        custom(|profiles, _ctx: &Config| ospf_profile::valid_profile_timers(profiles))
    )]
    #[cli(topic = OspfProfile)]
    pub profiles: Vec<OspfProfile>,

    /// RFC 2328 §3.6 stub area (no AS-external LSAs, E-bit clear) or
    /// totally stubby (an ABR also sends no Type-3 but its default), or an
    /// RFC 3101 NSSA (no Type-5, but its own ASBRs' Type-7s, translated into
    /// Type-5s by one ABR). Every router on the area's links must agree, or
    /// their Hellos are dropped. The backbone (`0.0.0.0`) can't be either.
    /// Checked with its siblings by `valid_area_settings`, one level up.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaType)]
    pub area_type: OspfAreaType,

    /// The cost of the default an ABR originates into this stub area or NSSA
    /// (RFC 2328 `StubDefaultCost`). `None` means 1; only allowed on a stub
    /// area or NSSA.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaStubDefaultCost)]
    pub stub_default_cost: Option<u16>,

    /// RFC 2328 §3.5 address ranges, applied by an ABR to this area's own
    /// intra-area prefixes when summarizing them into its other areas: every
    /// covered prefix is suppressed, and an advertised range with at least
    /// one active component is sent as one Type-3 (metric = the largest
    /// component cost) and installed as a discard route on the ABR.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaRange)]
    pub ranges: Vec<OspfAreaRange>,

    /// RFC 3101 `NSSATranslatorRole` `Always`: as an ABR of this NSSA, always
    /// translate its Type-7s into Type-5s (and set the Router-LSA Nt-bit),
    /// instead of only when elected (`Candidate`, the default). NSSA only.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaNssaTranslateAlways, words = "nssa-translate-always enable", alias = "nssa-translate-always")]
    pub nssa_translate_always: bool,

    /// RFC 3101 §2.7: as an ABR of this NSSA, originate a default Type-7
    /// (P-bit clear, so never translated) into it. NSSA only.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaNssaDefaultOriginate, words = "nssa-default-originate enable", alias = "nssa-default-originate")]
    pub nssa_default_originate: bool,
}

/// What kind of RFC 2328 area an `OspfArea` is.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum OspfAreaType {
    #[default]
    Normal,
    /// No AS-external LSAs; the ABR originates a default Type-3.
    Stub,
    /// A stub area whose ABR sends only the default Type-3 (RFC 2328
    /// Appendix C.2 `ImportSummaries` off).
    TotallyStubby,
    /// RFC 3101 not-so-stubby area: no Type-5, but its own ASBRs originate
    /// Type-7s, which an ABR translates into Type-5s for the other areas.
    Nssa,
    /// An NSSA whose ABR sends only a default Type-3 into it, no other.
    NssaNoSummary,
}

impl OspfAreaType {
    /// No Type-5 in the area: a stub area or an NSSA.
    pub fn is_stub(self) -> bool {
        self != OspfAreaType::Normal
    }

    pub fn is_nssa(self) -> bool {
        matches!(self, OspfAreaType::Nssa | OspfAreaType::NssaNoSummary)
    }

    /// RFC 2328 Appendix C.2 `ImportSummaries`: off when an ABR sends only a
    /// default Type-3 into the area.
    pub fn import_summaries(self) -> bool {
        !matches!(
            self,
            OspfAreaType::TotallyStubby | OspfAreaType::NssaNoSummary
        )
    }
}

/// One RFC 2328 §3.5 area address range, keyed by `cidr`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct OspfAreaRange {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    pub cidr: Ipv4Net,
    /// RFC 2328's `DoNotAdvertise`: the covered prefixes are hidden from the
    /// other areas entirely. `false` (the default) advertises the range.
    #[serde(default)]
    #[cli(topic = OspfAreaRangeAdvertise)]
    pub not_advertise: bool,
}

/// `area_type`/`stub_default_cost`/`ranges` checks, run from the owning
/// instance's `areas` validator since they need sibling fields.
pub(crate) fn valid_area_settings(area: &OspfArea) -> garde::Result {
    if area.area_type.is_stub() && area.area_id.is_unspecified() {
        return Err(garde::Error::new(
            "the backbone (0.0.0.0) can't be a stub area or an nssa",
        ));
    }
    if (area.nssa_translate_always || area.nssa_default_originate) && !area.area_type.is_nssa() {
        return Err(garde::Error::new(
            "nssa-translate-always and nssa-default-originate are only allowed on an nssa",
        ));
    }
    match area.stub_default_cost {
        Some(_) if !area.area_type.is_stub() => {
            return Err(garde::Error::new(
                "stub-default-cost is only allowed on a stub area or an nssa",
            ))
        }
        Some(0) => return Err(garde::Error::new("stub-default-cost must be 1 or more")),
        _ => {}
    }
    for (i, r) in area.ranges.iter().enumerate() {
        if area.ranges[..i]
            .iter()
            .any(|o| o.cidr.trunc() == r.cidr.trunc())
        {
            return Err(garde::Error::new(
                "range cidrs must be unique within an area",
            ));
        }
    }
    Ok(())
}

/// The placeholder a new `OspfArea` starts from (`edit` on a missing one).
impl Default for OspfArea {
    fn default() -> Self {
        OspfArea {
            area_id: Ipv4Addr::UNSPECIFIED,
            profiles: Vec::new(),
            area_type: OspfAreaType::Normal,
            stub_default_cost: None,
            ranges: Vec::new(),
            nssa_translate_always: false,
            nssa_default_originate: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use garde::Validate as _;

    use crate::schema::{Config, OspfInstance};

    use super::{OspfArea, OspfAreaRange, OspfAreaType};

    fn area(area_id: &str) -> OspfArea {
        OspfArea {
            area_id: area_id.parse().unwrap(),
            ..Default::default()
        }
    }

    fn validates(a: OspfArea) -> bool {
        let cfg = config_with(vec![instance("r1", vec![a])]);
        cfg.validate_with(&cfg).is_ok()
    }

    #[test]
    fn backbone_cannot_be_stub() {
        let mut a = area("0.0.0.0");
        a.area_type = OspfAreaType::Stub;
        assert!(!validates(a));
        let mut a = area("0.0.0.1");
        a.area_type = OspfAreaType::TotallyStubby;
        assert!(validates(a));
    }

    /// RFC 3101: the backbone can't be an NSSA, and the nssa-* options need
    /// one.
    #[test]
    fn nssa_settings_need_a_non_backbone_nssa() {
        let mut a = area("0.0.0.0");
        a.area_type = OspfAreaType::Nssa;
        assert!(!validates(a));
        let mut a = area("0.0.0.1");
        a.nssa_translate_always = true;
        assert!(!validates(a.clone()));
        a.area_type = OspfAreaType::Stub;
        assert!(!validates(a.clone()));
        a.area_type = OspfAreaType::NssaNoSummary;
        a.nssa_default_originate = true;
        a.stub_default_cost = Some(3);
        assert!(validates(a));
    }

    #[test]
    fn stub_default_cost_needs_a_stub_and_is_nonzero() {
        let mut a = area("0.0.0.1");
        a.stub_default_cost = Some(5);
        assert!(!validates(a.clone()));
        a.area_type = OspfAreaType::Stub;
        assert!(validates(a.clone()));
        a.stub_default_cost = Some(0);
        assert!(!validates(a));
    }

    #[test]
    fn duplicate_range_is_refused() {
        let range = |c: &str| OspfAreaRange {
            cidr: c.parse().unwrap(),
            not_advertise: false,
        };
        let mut a = area("0.0.0.1");
        a.ranges = vec![range("10.0.0.0/16"), range("10.1.0.0/16")];
        assert!(validates(a.clone()));
        a.ranges.push(range("10.0.0.0/16"));
        assert!(!validates(a));
    }

    /// An area saved before the stub/range fields existed still loads.
    #[test]
    fn old_area_without_new_fields_loads() {
        let a: OspfArea = serde_json::from_str(r#"{"area_id":"0.0.0.1","profiles":[]}"#).unwrap();
        assert_eq!(a.area_type, OspfAreaType::Normal);
        assert_eq!(a.ranges, vec![]);
        let r: OspfAreaRange = serde_json::from_str(r#"{"cidr":"10.0.0.0/8"}"#).unwrap();
        assert!(!r.not_advertise);
    }

    fn instance(name: &str, areas: Vec<OspfArea>) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: "1.1.1.1".parse().unwrap(),
            areas,
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            prefix_suppression: false,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
        }
    }

    fn config_with(instances: Vec<OspfInstance>) -> Config {
        Config {
            ospf_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_area_passes() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0")])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_area_id_within_instance_fails() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.0")])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_area_ids_within_instance_pass() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.1")])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn same_area_id_across_different_instances_passes() {
        let cfg = config_with(vec![
            instance("r1", vec![area("0.0.0.0")]),
            instance("r2", vec![area("0.0.0.0")]),
        ]);
        cfg.validate_with(&cfg).unwrap();
    }
}
