//! MSTP (IEEE 802.1Q-2022 clause 13, 14.6): one RSTP machine set per MSTI
//! next to the CIST's, and the glue between them and the version 3 BPDU.
//!
//! Model (the deviations are in `docs/internals/stp.md`):
//! - Each MSTI is an ordinary [`Bridge`] whose bridge id is the MSTI priority
//!   plus the MSTID as system id extension. Its BPDU "message age" is the
//!   hops used (`MaxHops - remainingHops`) and its `max_age` is `MaxHops`, so
//!   the core's aged-BPDU and `rcvdInfoWhile` rules are the remaining-hops
//!   rules of 13.26.
//! - Only the CIST's transmit timer paces the wire: every MSTI's Transmit
//!   action is a trigger, one MST BPDU per port carries the CIST and all
//!   MSTI messages.
//! - A port whose peer is not in the same region (RSTP/STP bridge, or a
//!   different name/revision/digest) is a boundary port: the MSTIs are
//!   disabled on it and follow the CIST state.

pub mod digest;
pub mod vidmap;

use crate::bpdu::{
    raw_secs, secs, Bpdu, Flags, MstBpdu, MstConfigId, MstiMsg, Params, MST_MAX_MSTIS,
};
use crate::bridge::{Bridge, PortParams};
use crate::machines::{build, Tx};
use crate::timers::Timers;
use crate::vector::{BridgeId, IdError, PortId};

/// What `spanning-tree` and the domains say about MSTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MstPlan {
    pub name: String,
    pub revision: u16,
    pub digest: [u8; 16],
    pub max_hops: u8,
    /// `(id, bridge priority)`, sorted by id.
    pub instances: Vec<(u16, u16)>,
    /// `(domain, vid, mstid)`, sorted by VID.
    pub domains: Vec<(String, u16, u16)>,
}

impl MstPlan {
    pub fn config_id(&self) -> MstConfigId {
        let mut name = [0; 32];
        let n = self.name.len().min(32);
        name[..n].copy_from_slice(&self.name.as_bytes()[..n]);
        MstConfigId {
            name,
            revision: self.revision,
            digest: self.digest,
        }
    }

    /// The tree a domain runs in: its instance, or the CIST.
    pub fn tree_of(&self, domain: &str) -> u16 {
        self.domains
            .iter()
            .find(|d| d.0 == domain)
            .map_or(0, |d| d.2)
    }
}

/// One port's settings in one MSTI (`stp-port-profile mst-instance`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMst {
    pub id: u16,
    pub cost: Option<u32>,
    pub priority: u8,
}

/// Why a port is not in the region, or that it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// Nothing heard yet: v3 is sent, the MSTIs run.
    Unknown,
    Internal,
    /// `reason`: `plain-bpdu`, `name`, `revision` or `digest`.
    Boundary(&'static str),
}

pub struct Msti {
    pub id: u16,
    pub bridge: Bridge,
}

pub struct Mst {
    pub plan: MstPlan,
    pub id: MstConfigId,
    pub instances: Vec<Msti>,
    pub edge: Vec<Edge>,
    /// `PortMst` per port, as planned.
    pub port_cfg: Vec<Vec<PortMst>>,
}

/// The first of name, revision, digest that differs.
pub fn mismatch(a: &MstConfigId, b: &MstConfigId) -> Option<&'static str> {
    if a.name != b.name {
        Some("name")
    } else if a.revision != b.revision {
        Some("revision")
    } else if a.digest != b.digest {
        Some("digest")
    } else {
        None
    }
}

/// The CIST view of a version 3 BPDU for the core. ponytail: flat CIST, the
/// external and internal root path costs are summed and the regional root is
/// not tracked, so costs across a region boundary do not stay hidden inside
/// the region as 13.10 wants; upgrade path is a 7-component CIST vector.
pub fn flat(m: &MstBpdu) -> Params {
    Params {
        root_path_cost: m.params.root_path_cost.saturating_add(m.internal_cost),
        bridge: m.bridge,
        ..m.params
    }
}

/// The core's view of MSTI message `msg` of `m`, received on a port whose CIST
/// port number is `port_number`.
pub fn msti_params(m: &MstBpdu, msg: &MstiMsg, max_hops: u8) -> Option<Params> {
    let id = msg.regional_root.ext();
    let bridge = BridgeId::new(
        u16::from(msg.bridge_priority & 0xf0) << 8,
        id,
        m.bridge.mac(),
    )
    .ok()?;
    let port =
        PortId::from_u16((u16::from(msg.port_priority & 0xf0) << 8) | m.params.port.number());
    Some(Params {
        flags: Flags(msg.flags.0 & !Flags::TC_ACK),
        root: msg.regional_root,
        root_path_cost: msg.internal_cost,
        bridge,
        port,
        message_age: raw_secs(max_hops.saturating_sub(msg.remaining_hops)),
        max_age: raw_secs(max_hops),
        ..m.params
    })
}

/// The MSTI Configuration Message `b` (an MSTI bridge) would send on `port`.
fn record(b: &Bridge, port: usize, max_hops: u8) -> Option<MstiMsg> {
    let Bpdu::Rst(p) = build(b, port, Tx::Rst) else {
        return None;
    };
    Some(MstiMsg {
        flags: p.flags,
        regional_root: p.root,
        internal_cost: p.root_path_cost,
        bridge_priority: (b.id.priority() >> 8) as u8,
        port_priority: b.ports[port].port_id.priority(),
        remaining_hops: max_hops.saturating_sub(secs(p.message_age)),
    })
}

impl Mst {
    /// `ports[i]` and `port_cfg[i]` describe the same port; `timers` are the
    /// CIST's (an MSTI's `max_age` is replaced by `MaxHops`).
    pub fn new(
        plan: &MstPlan,
        mac: [u8; 6],
        timers: Timers,
        ports: &[PortParams],
        port_cfg: Vec<Vec<PortMst>>,
    ) -> Result<Self, IdError> {
        let mut instances = Vec::new();
        for &(id, priority) in plan.instances.iter().take(MST_MAX_MSTIS) {
            let ps: Vec<PortParams> = ports
                .iter()
                .zip(&port_cfg)
                .map(|(p, cfg)| {
                    let m = cfg.iter().find(|m| m.id == id);
                    Ok(PortParams {
                        id: PortId::new(m.map_or(p.id.priority(), |m| m.priority), p.id.number())?,
                        path_cost: m.and_then(|m| m.cost).unwrap_or(p.path_cost),
                        ..*p
                    })
                })
                .collect::<Result<_, IdError>>()?;
            let t = Timers {
                max_age: plan.max_hops,
                ..timers
            };
            instances.push(Msti {
                id,
                bridge: Bridge::new(BridgeId::new(priority, id, mac)?, t, &ps),
            });
        }
        Ok(Mst {
            plan: plan.clone(),
            id: plan.config_id(),
            instances,
            edge: vec![Edge::Unknown; ports.len()],
            port_cfg,
        })
    }

    /// The MST BPDU to send for the CIST's `p` (its Transmit) on `port`.
    pub fn tx(&self, port: usize, p: &Params, cist_bridge: BridgeId) -> MstBpdu {
        let mut mstis = Vec::new();
        for m in &self.instances {
            if m.bridge.ports[port].port_enabled {
                mstis.extend(record(&m.bridge, port, self.plan.max_hops));
            }
        }
        MstBpdu {
            params: Params {
                bridge: p.root,
                ..*p
            },
            config: self.id,
            internal_cost: 0,
            bridge: cist_bridge,
            remaining_hops: self.plan.max_hops.saturating_sub(secs(p.message_age)),
            mstis,
        }
    }

    /// Feed the MSTI messages of `m` (same region) to the instances.
    pub fn receive(&mut self, port: usize, m: &MstBpdu) {
        let max_hops = self.plan.max_hops;
        for msg in &m.mstis {
            let Some(inst) = self
                .instances
                .iter_mut()
                .find(|i| i.id == msg.regional_root.ext())
            else {
                continue;
            };
            if let Some(p) = msti_params(m, msg, max_hops) {
                inst.bridge.receive(port, Bpdu::Rst(p));
            }
        }
    }
}

#[cfg(test)]
mod tests;
