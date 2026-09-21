//! The real backend: a VXLAN device per domain plus its bridge FDB, over
//! `rtnetlink`. Idempotent throughout — see `FdbDriver`.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_REPLACE,
    NLM_F_REQUEST,
};
use rtnetlink::packet_route::link::{InfoData, InfoVxlan, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{Handle, LinkUnspec, LinkVxlan, MulticastGroup};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::{is_local_mac, is_local_neigh, vxlan_name, DriverError, FdbDriver, Mac, VXLAN_PORT};

/// errno(3) values the kernel answers a missing object with.
const ENODEV: i32 = 19;
const ENOENT: i32 = 2;

pub struct LinuxFdbDriver {
    handle: Handle,
    /// `vni -> ifindex` of the vxlan devices `ensure_vxlan` last saw, so the
    /// per-MAC calls don't each pay a link lookup.
    ifindex: Mutex<HashMap<u32, u32>>,
}

impl LinuxFdbDriver {
    pub fn new() -> Result<Self, DriverError> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| DriverError::Other(e.to_string()))?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            ifindex: Mutex::new(HashMap::new()),
        })
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

    async fn bridge_index(&self, bridge: &str) -> Result<u32, DriverError> {
        Ok(self
            .find_link(bridge)
            .await?
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} does not exist yet")))?
            .header
            .index)
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

/// One FDB entry on the vxlan device `ifindex`. `master` also files it in the
/// bridge's own table (with `extern_learn`, so the bridge neither ages nor
/// relearns it); without it, it's a vxlan-only entry (the flood list).
fn fdb_msg(
    ifindex: u32,
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
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await?;
        self.ifindex.lock().unwrap().insert(vni, idx);
        Ok(())
    }

    async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError> {
        self.ifindex.lock().unwrap().remove(&vni);
        if let Some(l) = self.find_link(&vxlan_name(vni)).await? {
            self.handle.link().del(l.header.index).execute().await?;
            info!(vxlan = %vxlan_name(vni), "deleted vxlan device");
        }
        Ok(())
    }

    async fn set_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, mac, vtep, vni, REMOTE_MAC);
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_REPLACE, 0)
            .await
    }

    async fn del_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, mac, vtep, vni, REMOTE_MAC);
        self.neigh(msg, true, 0, ENOENT).await
    }

    async fn add_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, [0; 6], vtep, vni, NeighbourFlags::Own);
        // APPEND: the all-zero MAC carries one destination per remote VTEP,
        // and `NeighbourAddRequest` offers no way to set it. An identical
        // destination already present is left alone by the kernel.
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_APPEND, 0).await
    }

    async fn del_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, [0; 6], vtep, vni, NeighbourFlags::Own);
        self.neigh(msg, true, 0, ENOENT).await
    }

    async fn local_macs(&self, bridge: &str, vni: u32) -> Result<BTreeSet<Mac>, DriverError> {
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
        let mut out = BTreeSet::new();
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
                out.insert(mac);
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
            rtnetlink::new_multicast_connection(&[MulticastGroup::Neigh]).ok()?;
        tokio::spawn(conn);
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some((msg, _)) = messages.next().await {
                // Bridge FDB (MACs) and ARP/ND (IP neighbours) alike.
                let relevant = matches!(
                    &msg.payload,
                    NetlinkPayload::InnerMessage(
                        RouteNetlinkMessage::NewNeighbour(n) | RouteNetlinkMessage::DelNeighbour(n)
                    ) if matches!(
                        n.header.family,
                        AddressFamily::Bridge | AddressFamily::Inet | AddressFamily::Inet6
                    )
                );
                if relevant && tx.send(()).is_err() {
                    break;
                }
            }
            debug!("neighbour notification stream ended");
        });
        Some(rx)
    }
}
