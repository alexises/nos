//! Named spanning-tree port settings (`stp-port-profile`), referenced by bare
//! name from an `Interface` or a `PortAggregate`. Declaration only until
//! `nos-stpd` (STP 2/7): attaching one is inert.

use garde::Validate;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::spanning_tree::valid_port_priority;
use super::Config;

pub const PORT_PRIORITY_DEFAULT: u8 = 128;
pub const PORT_COST_MAX: u32 = 200_000_000;

/// Edge-port (`PortFast`) behaviour (802.1Q 13.4 `AdminEdgePort`/`AutoEdge`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum EdgePort {
    /// Always an edge port, until a BPDU arrives.
    Admin,
    /// Becomes an edge port after `3 * hello-time` without a BPDU.
    #[default]
    Auto,
    Disabled,
}

/// The link type for the RSTP rapid transitions (`AdminPointToPointMAC`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum LinkType {
    #[default]
    Auto,
    PointToPoint,
    Shared,
}

/// This port's cost and priority in one MST instance, which must exist in
/// `spanning-tree mst-instance`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct StpPortMstInstance {
    #[cli(key)]
    pub id: u16,
    #[serde(default)]
    #[cli(topic = StpPortProfileMstInstanceCost)]
    pub cost: Option<u32>,
    #[serde(default = "priority_default")]
    #[cli(topic = StpPortProfileMstInstancePriority)]
    pub priority: u8,
}

impl Default for StpPortMstInstance {
    fn default() -> Self {
        Self {
            id: 0,
            cost: None,
            priority: PORT_PRIORITY_DEFAULT,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one independent on/off switch per STP guard feature, edited one by one"
)]
pub struct StpPortProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.stp_port_profiles, |p| &p.name))
    )]
    #[cli(key)]
    pub name: String,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = StpPortProfileEdgePort)]
    pub edge_port: EdgePort,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = StpPortProfileLinkType)]
    pub link_type: LinkType,

    /// `None`: automatic from the link speed (802.1Q Table 13-4).
    #[serde(default)]
    #[garde(inner(range(min = 1, max = PORT_COST_MAX)))]
    #[cli(topic = StpPortProfileCost)]
    pub cost: Option<u32>,

    /// A multiple of 16, 0..=240.
    #[serde(default = "priority_default")]
    #[garde(custom(|p: &u8, _ctx: &Config| valid_port_priority(*p)))]
    #[cli(topic = StpPortProfilePriority)]
    pub priority: u8,

    /// Shut the port (`err-disabled`) when a BPDU arrives on it.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = StpPortProfileBpduGuard, words = "bpdu-guard enable", alias = "bpdu-guard")]
    pub bpdu_guard: bool,

    /// Seconds before an `err-disabled` port comes back; `None`: never.
    #[serde(default)]
    #[garde(inner(range(min = 1)))]
    #[cli(topic = StpPortProfileBpduGuardRecovery)]
    pub bpdu_guard_recovery: Option<u32>,

    /// Neither send nor process BPDUs on this port.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = StpPortProfileBpduFilter, words = "bpdu-filter enable", alias = "bpdu-filter")]
    pub bpdu_filter: bool,

    /// Never let this port become the root port.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = StpPortProfileRootGuard, words = "root-guard enable", alias = "root-guard")]
    pub root_guard: bool,

    /// Block the port when BPDUs stop arriving instead of forwarding.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = StpPortProfileLoopGuard, words = "loop-guard enable", alias = "loop-guard")]
    pub loop_guard: bool,

    /// Do not propagate topology changes received on this port (802.1Q
    /// `restrictedTcn`).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = StpPortProfileRestrictedTcn, words = "restricted-tcn enable", alias = "restricted-tcn")]
    pub restricted_tcn: bool,

    #[serde(default)]
    #[garde(custom(|m: &Vec<StpPortMstInstance>, ctx: &Config| valid_mst_instances(m, ctx)))]
    #[cli(topic = StpPortProfileMstInstance, words = "mst-instance")]
    pub mst_instances: Vec<StpPortMstInstance>,
}

fn priority_default() -> u8 {
    PORT_PRIORITY_DEFAULT
}

/// The placeholder a new `StpPortProfile` starts from (`edit` on a missing one).
impl Default for StpPortProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            edge_port: EdgePort::default(),
            link_type: LinkType::default(),
            cost: None,
            priority: PORT_PRIORITY_DEFAULT,
            bpdu_guard: false,
            bpdu_guard_recovery: None,
            bpdu_filter: false,
            root_guard: false,
            loop_guard: false,
            restricted_tcn: false,
            mst_instances: Vec::new(),
        }
    }
}

fn valid_mst_instances(list: &[StpPortMstInstance], ctx: &Config) -> garde::Result {
    for (i, m) in list.iter().enumerate() {
        if !ctx.spanning_tree.mst_instances.iter().any(|g| g.id == m.id) {
            return Err(garde::Error::new(format!(
                "mst-instance {} is not defined under spanning-tree",
                m.id
            )));
        }
        if list[..i].iter().any(|o| o.id == m.id) {
            return Err(garde::Error::new(format!(
                "mst-instance {} is listed twice",
                m.id
            )));
        }
        if m.cost.is_some_and(|c| !(1..=PORT_COST_MAX).contains(&c)) {
            return Err(garde::Error::new("mst-instance cost must be 1..=200000000"));
        }
        valid_port_priority(m.priority)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Config, MstInstance};

    fn with(p: StpPortProfile, mst: &[u16]) -> Config {
        let mut c = Config {
            stp_port_profiles: vec![p],
            ..Default::default()
        };
        c.spanning_tree.mst_instances = mst
            .iter()
            .map(|&id| MstInstance {
                id,
                ..Default::default()
            })
            .collect();
        c
    }

    fn ok(f: impl FnOnce(&mut StpPortProfile)) -> bool {
        let mut p = StpPortProfile {
            name: "p".into(),
            ..Default::default()
        };
        f(&mut p);
        let c = with(p, &[1]);
        c.validate_with(&c).is_ok()
    }

    #[test]
    fn defaults_commit() {
        assert!(ok(|_| {}));
    }

    #[test]
    fn port_priority_is_a_multiple_of_16() {
        assert!(ok(|p| p.priority = 240));
        assert!(ok(|p| p.priority = 0));
        assert!(!ok(|p| p.priority = 100));
        assert!(!ok(|p| p.priority = 241));
    }

    #[test]
    fn cost_is_ranged() {
        assert!(ok(|p| p.cost = Some(200_000_000)));
        assert!(!ok(|p| p.cost = Some(0)));
        assert!(!ok(|p| p.cost = Some(200_000_001)));
    }

    #[test]
    fn recovery_is_positive() {
        assert!(ok(|p| p.bpdu_guard_recovery = Some(300)));
        assert!(!ok(|p| p.bpdu_guard_recovery = Some(0)));
    }

    #[test]
    fn mst_instance_must_exist_globally() {
        let inst = |id| StpPortMstInstance {
            id,
            ..Default::default()
        };
        assert!(ok(|p| p.mst_instances = vec![inst(1)]));
        assert!(!ok(|p| p.mst_instances = vec![inst(2)]));
        assert!(!ok(|p| p.mst_instances = vec![inst(1), inst(1)]));
        assert!(!ok(|p| p.mst_instances = vec![StpPortMstInstance {
            id: 1,
            priority: 7,
            ..Default::default()
        }]));
    }

    #[test]
    fn duplicate_names_are_refused() {
        let mut c = with(
            StpPortProfile {
                name: "p".into(),
                ..Default::default()
            },
            &[],
        );
        c.stp_port_profiles.push(c.stp_port_profiles[0].clone());
        assert!(c.validate_with(&c).is_err());
    }
}
