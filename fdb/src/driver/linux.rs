//! The real backend: a VXLAN device per domain plus its bridge FDB, over
//! `rtnetlink`. Idempotent throughout — see `FdbDriver`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{
    DefaultNla, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE,
    NLM_F_REPLACE, NLM_F_REQUEST,
};
use rtnetlink::packet_route::link::{
    InfoBridgePort, InfoData, InfoPortData, InfoPortKind, InfoVxlan, LinkAttribute, LinkFlags,
    LinkInfo, LinkMessage, LinkProtoInfoBridge,
};
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{Handle, LinkUnspec, LinkVxlan, MulticastGroup};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::nexthop::{self, Nexthop};
use super::{is_local_mac, is_local_neigh, vxlan_name, DriverError, FdbDriver, Mac, VXLAN_PORT};

/// errno(3) values the kernel answers a missing object with.
const ENODEV: i32 = 19;
const ENOENT: i32 = 2;
/// `NDA_NH_ID`: the FDB entry points at a nexthop (group) instead of a `dst`.
const NDA_NH_ID: u16 = 13;
/// Nexthop ids are `vni << 8 | slot`, so the per-domain `nos-fdbd` processes
/// sharing a network namespace never collide (ids are namespace-wide).
/// `ponytail:` 255 nexthops + groups per domain, and they are only deleted
/// with the domain; a few dozen PEs and distinct PE sets are the ceiling.
const NH_SLOTS: u32 = 255;

/// The nexthop objects this process created for one VNI.
#[derive(Default)]
struct NhState {
    slots: u32,
    gateways: HashMap<Ipv4Addr, u32>,
    groups: HashMap<Vec<Ipv4Addr>, u32>,
}

/// `IFLA_BRPORT_STATE` and the two bridge-port states used (`BR_STATE_*`).
const IFLA_BRPORT_STATE: u16 = 1;
const BR_STATE_DISABLED: u8 = 0;
const BR_STATE_FORWARDING: u8 = 3;

pub struct LinuxFdbDriver {
    handle: Handle,
    /// `vni -> ifindex` of the vxlan devices `ensure_vxlan` last saw, so the
    /// per-MAC calls don't each pay a link lookup.
    ifindex: Mutex<HashMap<u32, u32>>,
    /// `vni -> ifindex` of each device's underlay, which every remote entry
    /// must name (`NDA_IFINDEX`, `bridge fdb ... via`): without it the kernel
    /// resolves the remote VTEP in the *main* table, and with the underlay in a
    /// VRF the route isn't there (`tx_carrier_errors`, nothing ever sent).
    underlay: Mutex<HashMap<u32, u32>>,
    /// `vni ->` the FDB nexthops and groups created for it (see `NhState`).
    nexthops: Mutex<HashMap<u32, NhState>>,
}

impl LinuxFdbDriver {
    pub fn new() -> Result<Self, DriverError> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| DriverError::Other(e.to_string()))?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            ifindex: Mutex::new(HashMap::new()),
            underlay: Mutex::new(HashMap::new()),
            nexthops: Mutex::new(HashMap::new()),
        })
    }

    /// `ip link set dev <port> type bridge_slave ..`: an `RTM_NEWLINK` (not
    /// SETLINK — only the newlink path reaches the master's
    /// `slave_changelink`) carrying the port data. Only the bridge's own ports
    /// accept it (EOPNOTSUPP otherwise), so a port that isn't enslaved yet is
    /// an error the tick retries.
    async fn set_bridge_port(
        &self,
        index: u32,
        attrs: Vec<InfoBridgePort>,
    ) -> Result<(), DriverError> {
        let mut msg = LinkMessage::default();
        msg.header.index = index;
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(InfoPortData::BridgePort(attrs)),
        ]));
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req)?;
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                if e.raw_code() != 0 {
                    return Err(rtnetlink::Error::NetlinkError(e).into());
                }
            }
        }
        Ok(())
    }

    async fn find_link(&self, name: &str) -> Result<Option<LinkMessage>, DriverError> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match links.try_next().await {
            Ok(link) => Ok(link),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -ENODEV => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The name of the link with `index` (`None` if it vanished meanwhile).
    async fn link_name(&self, index: u32) -> Result<Option<String>, DriverError> {
        let mut links = self.handle.link().get().match_index(index).execute();
        match links.try_next().await {
            Ok(link) => Ok(link.and_then(|l| {
                l.attributes.into_iter().find_map(|a| match a {
                    LinkAttribute::IfName(n) => Some(n),
                    _ => None,
                })
            })),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -ENODEV => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn bridge_index(&self, bridge: &str) -> Result<u32, DriverError> {
        Ok(self
            .find_link(bridge)
            .await?
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} does not exist yet")))?
            .header
            .index)
    }

    fn via(&self, vni: u32) -> u32 {
        self.underlay
            .lock()
            .unwrap()
            .get(&vni)
            .copied()
            .unwrap_or(0)
    }

    async fn vxlan_index(&self, vni: u32) -> Result<u32, DriverError> {
        if let Some(idx) = self.ifindex.lock().unwrap().get(&vni) {
            return Ok(*idx);
        }
        let link = self
            .find_link(&vxlan_name(vni))
            .await?
            .ok_or_else(|| DriverError::Other(format!("{} does not exist", vxlan_name(vni))))?;
        self.ifindex.lock().unwrap().insert(vni, link.header.index);
        Ok(link.header.index)
    }

    /// Runs one nexthop request on a blocking thread (see `nexthop`).
    async fn nexthop(&self, nh: Nexthop, tolerate: i32) -> Result<(), DriverError> {
        tokio::task::spawn_blocking(move || nexthop::send(&nh, tolerate))
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
            .map_err(|e| DriverError::Other(format!("nexthop request failed: {e}")))
    }

    /// The id the next nexthop of `vni` will get. Only committed once the
    /// kernel accepted it, so a failed request wastes no slot.
    fn next_nexthop_id(&self, vni: u32) -> Result<u32, DriverError> {
        let slot = self
            .nexthops
            .lock()
            .unwrap()
            .get(&vni)
            .map_or(0, |s| s.slots)
            + 1;
        if slot > NH_SLOTS {
            return Err(DriverError::Other(format!(
                "vni {vni} is out of nexthop ids ({NH_SLOTS})"
            )));
        }
        Ok(vni << 8 | slot)
    }

    fn commit_nexthop(&self, vni: u32, f: impl FnOnce(&mut NhState)) {
        let mut all = self.nexthops.lock().unwrap();
        let state = all.entry(vni).or_default();
        state.slots += 1;
        f(state);
    }

    /// The id of the FDB group over `vteps`, creating its member nexthops and
    /// the group itself first when this is a new set.
    async fn ensure_group(&self, vni: u32, vteps: &[Ipv4Addr]) -> Result<u32, DriverError> {
        let mut key = vteps.to_vec();
        key.sort();
        key.dedup();
        if let Some(id) = self
            .nexthops
            .lock()
            .unwrap()
            .get(&vni)
            .and_then(|s| s.groups.get(&key))
        {
            return Ok(*id);
        }
        let mut members = Vec::new();
        for vtep in &key {
            let known = self
                .nexthops
                .lock()
                .unwrap()
                .get(&vni)
                .and_then(|s| s.gateways.get(vtep))
                .copied();
            let id = if let Some(id) = known {
                id
            } else {
                let id = self.next_nexthop_id(vni)?;
                self.nexthop(Nexthop::Gateway { id, gateway: *vtep }, 0)
                    .await?;
                self.commit_nexthop(vni, |s| {
                    s.gateways.insert(*vtep, id);
                });
                id
            };
            members.push(id);
        }
        let id = self.next_nexthop_id(vni)?;
        self.nexthop(Nexthop::Group { id, members }, 0).await?;
        self.commit_nexthop(vni, |s| {
            s.groups.insert(key, id);
        });
        Ok(id)
    }

    /// Sends one raw `RTM_NEWNEIGH`/`RTM_DELNEIGH`. `tolerate` is an errno
    /// (negated, as the kernel reports it) that counts as success.
    async fn neigh(
        &self,
        msg: NeighbourMessage,
        delete: bool,
        flags: u16,
        tolerate: i32,
    ) -> Result<(), DriverError> {
        let payload = if delete {
            RouteNetlinkMessage::DelNeighbour(msg)
        } else {
            RouteNetlinkMessage::NewNeighbour(msg)
        };
        let mut req = NetlinkMessage::from(payload);
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        let mut response = self.handle.clone().request(req)?;
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                if e.raw_code() == -tolerate {
                    continue;
                }
                return Err(rtnetlink::Error::NetlinkError(e).into());
            }
        }
        Ok(())
    }
}

fn master_of(link: &LinkMessage) -> Option<u32> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Controller(i) => Some(*i),
        _ => None,
    })
}

/// `IFLA_BRPORT_NEIGH_SUPPRESS` as the link dump reports it (`false` when the
/// link isn't a bridge port yet — the kernel default).
fn neigh_suppressed(link: &LinkMessage) -> bool {
    link.attributes
        .iter()
        .filter_map(|a| match a {
            LinkAttribute::LinkInfo(infos) => Some(infos),
            _ => None,
        })
        .flatten()
        .filter_map(|i| match i {
            LinkInfo::PortData(InfoPortData::BridgePort(attrs)) => Some(attrs),
            _ => None,
        })
        .flatten()
        .any(|a| matches!(a, InfoBridgePort::NeighSupress(true)))
}

fn link_mac(link: &LinkMessage) -> Option<Mac> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Address(b) => Mac::try_from(b.as_slice()).ok(),
        _ => None,
    })
}

fn neigh_address(a: &NeighbourAddress) -> Option<IpAddr> {
    match a {
        NeighbourAddress::Inet(a) => Some(IpAddr::V4(*a)),
        NeighbourAddress::Inet6(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

/// One IP neighbour on the bridge `ifindex` (its SVI's ARP/ND table).
fn ip_neigh_msg(ifindex: u32, mac: Mac, ip: IpAddr) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = match ip {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    m.header.ifindex = ifindex;
    m.header.state = NeighbourState::Permanent;
    m.header.flags = NeighbourFlags::ExtLearned;
    m.attributes = vec![
        NeighbourAttribute::LinkLayerAddress(mac.to_vec()),
        NeighbourAttribute::Destination(NeighbourAddress::from(ip)),
    ];
    m
}

fn vxlan_matches(link: &LinkMessage, vni: u32, vtep: IpAddr, underlay: u32) -> bool {
    let local = match vtep {
        IpAddr::V4(a) => InfoVxlan::Local(a),
        IpAddr::V6(a) => InfoVxlan::Local6(a),
    };
    link.attributes.iter().any(|a| match a {
        LinkAttribute::LinkInfo(infos) => infos.iter().any(|i| match i {
            LinkInfo::Data(InfoData::Vxlan(v)) => {
                v.contains(&InfoVxlan::Id(vni))
                    && v.contains(&local)
                    && v.contains(&InfoVxlan::Link(underlay))
            }
            _ => false,
        }),
        _ => false,
    })
}

/// A remote MAC's FDB entry pointing at nexthop group `nhid`. `NDA_NH_ID` is
/// exclusive with a `dst`, `vni` and `via`: the nexthops carry the VTEPs.
fn fdb_group_msg(ifindex: u32, mac: Mac, nhid: u32) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = AddressFamily::Bridge;
    m.header.ifindex = ifindex;
    m.header.state = NeighbourState::Permanent;
    m.header.flags = REMOTE_MAC;
    m.attributes = vec![NeighbourAttribute::LinkLayerAddress(mac.to_vec())];
    if nhid != 0 {
        m.attributes.push(NeighbourAttribute::Other(DefaultNla::new(
            NDA_NH_ID,
            nhid.to_ne_bytes().to_vec(),
        )));
    }
    m
}

/// One FDB entry on the vxlan device `ifindex`. `master` also files it in the
/// bridge's own table (with `extern_learn`, so the bridge neither ages nor
/// relearns it); without it, it's a vxlan-only entry (the flood list). `via`
/// is the underlay's ifindex the remote VTEP is reached through.
fn fdb_msg(
    ifindex: u32,
    via: u32,
    mac: Mac,
    dst: IpAddr,
    vni: u32,
    flags: NeighbourFlags,
) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = AddressFamily::Bridge;
    m.header.ifindex = ifindex;
    m.header.state = NeighbourState::Permanent;
    m.header.flags = flags;
    m.attributes = vec![
        NeighbourAttribute::LinkLayerAddress(mac.to_vec()),
        NeighbourAttribute::Destination(NeighbourAddress::from(dst)),
        NeighbourAttribute::Vni(vni),
        NeighbourAttribute::IfIndex(via),
    ];
    m
}

const REMOTE_MAC: NeighbourFlags = NeighbourFlags::Own
    .union(NeighbourFlags::Controller)
    .union(NeighbourFlags::ExtLearned);

#[async_trait]
impl FdbDriver for LinuxFdbDriver {
    async fn ensure_vxlan(
        &self,
        vni: u32,
        vtep: IpAddr,
        underlay: &str,
        bridge: &str,
        neigh_suppress: bool,
    ) -> Result<(), DriverError> {
        let bridge_idx = self
            .find_link(bridge)
            .await?
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} does not exist yet")))?
            .header
            .index;
        let underlay_idx = self
            .find_link(underlay)
            .await?
            .ok_or_else(|| DriverError::Other(format!("underlay {underlay} does not exist yet")))?
            .header
            .index;
        let name = vxlan_name(vni);

        let mut link = self.find_link(&name).await?;
        if let Some(l) = &link {
            if !vxlan_matches(l, vni, vtep, underlay_idx) {
                info!(vxlan = %name, vni, vtep = %vtep, "vxlan device drifted, recreating");
                self.handle.link().del(l.header.index).execute().await?;
                link = None;
            }
        }
        let link = if let Some(l) = link {
            l
        } else {
            let b = LinkVxlan::new(&name, vni)
                .dev(underlay_idx)
                .port(VXLAN_PORT)
                .learning(false);
            let b = match vtep {
                IpAddr::V4(a) => b.local(a),
                IpAddr::V6(a) => b.local6(a),
            };
            self.handle.link().add(b.build()).execute().await?;
            info!(vxlan = %name, vni, vtep = %vtep, underlay = %underlay, "created vxlan device");
            self.find_link(&name).await?.ok_or_else(|| {
                DriverError::Other(format!("created {name} but could not find it"))
            })?
        };
        let idx = link.header.index;
        if master_of(&link) != Some(bridge_idx) {
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(idx)
                        .controller(bridge_idx)
                        .build(),
                )
                .execute()
                .await?;
            info!(vxlan = %name, bridge = %bridge, "enslaved vxlan device to bridge");
        }
        // Read back every tick, so a recreated port is healed and unsetting
        // works too. A just-enslaved link's dump carried no port data: off.
        // ponytail: the same flag suppresses IPv6 ND, untested end to end, and a
        // proxied NA's Router flag isn't signalled (no RFC 9047 community).
        if neigh_suppressed(&link) != neigh_suppress {
            self.set_bridge_port(idx, vec![InfoBridgePort::NeighSupress(neigh_suppress)])
                .await?;
            info!(vxlan = %name, suppress = neigh_suppress, "vxlan neigh suppression set");
        }
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await?;
        self.ifindex.lock().unwrap().insert(vni, idx);
        self.underlay.lock().unwrap().insert(vni, underlay_idx);
        Ok(())
    }

    async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError> {
        self.ifindex.lock().unwrap().remove(&vni);
        self.underlay.lock().unwrap().remove(&vni);
        if let Some(l) = self.find_link(&vxlan_name(vni)).await? {
            self.handle.link().del(l.header.index).execute().await?;
            info!(vxlan = %vxlan_name(vni), "deleted vxlan device");
        }
        // The nexthops outlive the device; groups first, then what they hold.
        let state = self.nexthops.lock().unwrap().remove(&vni);
        for id in state.into_iter().flat_map(|s| {
            let groups = s.groups.into_values().collect::<Vec<_>>();
            groups.into_iter().chain(s.gateways.into_values())
        }) {
            // Best effort: the kernel already dropped whatever went with them.
            let _ = self.nexthop(Nexthop::Delete { id }, ENOENT).await;
        }
        Ok(())
    }

    async fn set_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, self.via(vni), mac, vtep, vni, REMOTE_MAC);
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_REPLACE, 0)
            .await
    }

    async fn del_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, self.via(vni), mac, vtep, vni, REMOTE_MAC);
        self.neigh(msg, true, 0, ENOENT).await
    }

    async fn set_remote_mac_group(
        &self,
        vni: u32,
        mac: Mac,
        vteps: &[IpAddr],
    ) -> Result<(), DriverError> {
        let v4 = vteps
            .iter()
            .map(|v| match v {
                IpAddr::V4(a) => Ok(*a),
                IpAddr::V6(_) => Err(DriverError::Other(
                    "an aliased MAC needs IPv4 VTEPs".to_string(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let nhid = self.ensure_group(vni, &v4).await?;
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_group_msg(idx, mac, nhid);
        // A REPLACE does not turn a `dst` entry into a nexthop one (or the
        // reverse): the kernel keeps the old form. Delete first.
        self.neigh(msg.clone(), true, 0, ENOENT).await?;
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_REPLACE, 0)
            .await
    }

    async fn del_remote_mac_group(&self, vni: u32, mac: Mac) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        self.neigh(fdb_group_msg(idx, mac, 0), true, 0, ENOENT)
            .await
    }

    async fn add_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, self.via(vni), [0; 6], vtep, vni, NeighbourFlags::Own);
        // APPEND: the all-zero MAC carries one destination per remote VTEP,
        // and `NeighbourAddRequest` offers no way to set it. An identical
        // destination already present is left alone by the kernel.
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_APPEND, 0).await
    }

    async fn del_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, self.via(vni), [0; 6], vtep, vni, NeighbourFlags::Own);
        self.neigh(msg, true, 0, ENOENT).await
    }

    async fn set_port_flood(&self, port: &str, flood: bool) -> Result<(), DriverError> {
        let link = self
            .find_link(port)
            .await?
            .ok_or_else(|| DriverError::Other(format!("port {port} does not exist yet")))?;
        // `ip link set dev <port> type bridge_slave flood .. mcast_flood ..
        // bcast_flood ..`.
        self.set_bridge_port(
            link.header.index,
            vec![
                InfoBridgePort::UnicastFlood(flood),
                InfoBridgePort::MulticastFlood(flood),
                InfoBridgePort::BroadcastFlood(flood),
            ],
        )
        .await
    }

    async fn set_port_forwarding(&self, port: &str, forwarding: bool) -> Result<(), DriverError> {
        let link = self
            .find_link(port)
            .await?
            .ok_or_else(|| DriverError::Other(format!("port {port} does not exist yet")))?;
        // `bridge link set dev <port> state 0|3`: an RTM_SETLINK in the
        // AF_BRIDGE family carrying the port data under IFLA_PROTINFO. Not the
        // slave-data path `set_port_flood` uses — that one accepts
        // IFLA_BRPORT_STATE and silently ignores it. The block is DISABLED, not
        // BLOCKING: with the bridge's STP off the kernel's
        // `br_port_state_selection` turns every other port straight back to
        // forwarding (a BLOCKING write is undone at once), but skips disabled
        // ones. A disabled port drops frames in both directions.
        let state = if forwarding {
            BR_STATE_FORWARDING
        } else {
            BR_STATE_DISABLED
        };
        let mut msg = LinkMessage::default();
        msg.header.interface_family = AddressFamily::Bridge;
        msg.header.index = link.header.index;
        msg.attributes.push(LinkAttribute::ProtoInfoBridge(vec![
            LinkProtoInfoBridge::Other(DefaultNla::new(IFLA_BRPORT_STATE, vec![state])),
        ]));
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::SetLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req)?;
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                if e.raw_code() != 0 {
                    return Err(rtnetlink::Error::NetlinkError(e).into());
                }
            }
        }
        Ok(())
    }

    async fn port_up(&self, port: &str) -> Result<bool, DriverError> {
        Ok(self
            .find_link(port)
            .await?
            .is_some_and(|l| l.header.flags.contains(LinkFlags::LowerUp)))
    }

    async fn local_macs(
        &self,
        bridge: &str,
        vni: u32,
    ) -> Result<BTreeMap<Mac, String>, DriverError> {
        let bridge_idx = self
            .find_link(bridge)
            .await?
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} does not exist yet")))?
            .header
            .index;
        let vxlan_idx = self.ifindex.lock().unwrap().get(&vni).copied();
        let mut dump = self
            .handle
            .neighbours()
            .get()
            .set_address_family(AddressFamily::Bridge)
            .execute();
        let mut out = BTreeMap::new();
        let mut names: HashMap<u32, String> = HashMap::new();
        while let Some(m) = dump.try_next().await? {
            let mut mac = None;
            let mut master = None;
            for a in &m.attributes {
                match a {
                    NeighbourAttribute::LinkLayerAddress(b) => {
                        mac = Mac::try_from(b.as_slice()).ok();
                    }
                    NeighbourAttribute::Controller(i) => master = Some(*i),
                    _ => {}
                }
            }
            let Some(mac) = mac else { continue };
            if is_local_mac(
                mac,
                m.header.state == NeighbourState::Permanent,
                m.header.flags.contains(NeighbourFlags::ExtLearned),
                m.header.ifindex,
                master,
                bridge_idx,
                vxlan_idx,
            ) {
                let port = m.header.ifindex;
                if let std::collections::hash_map::Entry::Vacant(v) = names.entry(port) {
                    if let Some(name) = self.link_name(port).await? {
                        v.insert(name);
                    }
                }
                out.insert(mac, names.get(&port).cloned().unwrap_or_default());
            }
        }
        Ok(out)
    }

    async fn local_neighbours(&self, bridge: &str) -> Result<BTreeSet<(Mac, IpAddr)>, DriverError> {
        let bridge_idx = self.bridge_index(bridge).await?;
        let mut out = BTreeSet::new();
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut dump = self
                .handle
                .neighbours()
                .get()
                .set_address_family(family)
                .execute();
            while let Some(m) = dump.try_next().await? {
                let mut mac = None;
                let mut ip = None;
                for a in &m.attributes {
                    match a {
                        NeighbourAttribute::LinkLayerAddress(b) => {
                            mac = Mac::try_from(b.as_slice()).ok();
                        }
                        NeighbourAttribute::Destination(d) => ip = neigh_address(d),
                        _ => {}
                    }
                }
                let (Some(mac), Some(ip)) = (mac, ip) else {
                    continue;
                };
                let usable = matches!(
                    m.header.state,
                    NeighbourState::Reachable
                        | NeighbourState::Stale
                        | NeighbourState::Delay
                        | NeighbourState::Probe
                        | NeighbourState::Permanent
                );
                if is_local_neigh(
                    mac,
                    ip,
                    usable,
                    m.header.flags.contains(NeighbourFlags::ExtLearned),
                    m.header.ifindex,
                    bridge_idx,
                ) {
                    out.insert((mac, ip));
                }
            }
        }
        Ok(out)
    }

    async fn bridge_mac(&self, bridge: &str) -> Result<Mac, DriverError> {
        self.find_link(bridge)
            .await?
            .as_ref()
            .and_then(link_mac)
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} has no MAC yet")))
    }

    async fn set_neigh(&self, bridge: &str, mac: Mac, ip: IpAddr) -> Result<(), DriverError> {
        let msg = ip_neigh_msg(self.bridge_index(bridge).await?, mac, ip);
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_REPLACE, 0)
            .await
    }

    async fn del_neigh(&self, bridge: &str, mac: Mac, ip: IpAddr) -> Result<(), DriverError> {
        let msg = ip_neigh_msg(self.bridge_index(bridge).await?, mac, ip);
        self.neigh(msg, true, 0, ENOENT).await
    }

    fn watch_neigh(&self) -> Option<mpsc::UnboundedReceiver<()>> {
        let (conn, _handle, mut messages) =
            rtnetlink::new_multicast_connection(&[MulticastGroup::Neigh, MulticastGroup::Link])
                .ok()?;
        tokio::spawn(conn);
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some((msg, _)) = messages.next().await {
                // Bridge FDB (MACs) and ARP/ND (IP neighbours) alike, and a
                // link changing state (an Ethernet Segment's carrier).
                let relevant = match &msg.payload {
                    NetlinkPayload::InnerMessage(
                        RouteNetlinkMessage::NewNeighbour(n) | RouteNetlinkMessage::DelNeighbour(n),
                    ) => matches!(
                        n.header.family,
                        AddressFamily::Bridge | AddressFamily::Inet | AddressFamily::Inet6
                    ),
                    NetlinkPayload::InnerMessage(
                        RouteNetlinkMessage::NewLink(_) | RouteNetlinkMessage::DelLink(_),
                    ) => true,
                    _ => false,
                };
                if relevant && tx.send(()).is_err() {
                    break;
                }
            }
            debug!("neighbour notification stream ended");
        });
        Some(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neigh_suppressed_reads_the_bridge_port_flag() {
        let port = |attrs| {
            let mut l = LinkMessage::default();
            l.attributes.push(LinkAttribute::LinkInfo(vec![
                LinkInfo::PortKind(InfoPortKind::Bridge),
                LinkInfo::PortData(InfoPortData::BridgePort(attrs)),
            ]));
            l
        };
        assert!(!neigh_suppressed(&LinkMessage::default()));
        assert!(!neigh_suppressed(&port(vec![InfoBridgePort::Learning(
            false
        )])));
        assert!(!neigh_suppressed(&port(vec![
            InfoBridgePort::NeighSupress(false)
        ])));
        assert!(neigh_suppressed(&port(vec![
            InfoBridgePort::Learning(false),
            InfoBridgePort::NeighSupress(true),
        ])));
    }
}
