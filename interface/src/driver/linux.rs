use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use async_trait::async_trait;
use futures::TryStreamExt;
use nos_proto::{
    loopback_table_name, InterfaceAddress, IpNet, PortAggregateMode, ServiceRef, VlanTag,
};
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use rtnetlink::packet_route::link::{BondMode, LinkAttribute, LinkMessage};
use rtnetlink::{Handle, LinkBond, LinkBridge, LinkDummy, LinkUnspec, LinkVlan};
use tracing::{debug, info, trace};

use super::{
    bridge_registry, port_aggregate_registry, rib_client, DriverError, InterfaceDriver, DEFAULT_MTU,
};
use crate::state::{BroadcastDomainState, InterfaceState, PortAggregateState, SubinterfaceState};
use crate::watchdog_client;

/// Both `Xor` and `Lacp` create the kernel bond in the same
/// `BalanceXor` mode — **never** `BondMode::Ieee8023Ad`. The kernel's own
/// 802.3ad bonding mode intercepts slow-protocol (ethertype `0x8809`)
/// frames on every slave via its own `rx_handler` before userspace ever
/// sees them, which would silently starve `nos-lacpd`'s raw `AF_PACKET`
/// sockets of every LACPDU it needs to run its own real negotiation. The
/// `PortAggregateMode` distinction only changes which control plane
/// decides which members are actually enslaved (unconditionally here vs.
/// gated on `nos-lacpd`'s push, see `InterfaceState.port_aggregate_active`)
/// — never the kernel driver's own bonding algorithm.
fn bond_mode_of(mode: PortAggregateMode) -> BondMode {
    match mode {
        PortAggregateMode::Xor | PortAggregateMode::Lacp => BondMode::BalanceXor,
    }
}

/// errno(3) `ENODEV` — the kernel's reply to a targeted `RTM_GETLINK`
/// lookup (`match_name`/`match_index`) for a link that doesn't exist.
const ENODEV: i32 = 19;

/// Which kind of thing `reconcile_master` is enslaving a link into — picks
/// only the log wording, see its doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MasterKind {
    Vrf,
    Bridge,
    /// A `PortAggregate`'s bond device — enslavement is the same generic
    /// `IFLA_MASTER` operation as `Vrf`/`Bridge`, just a different kind of
    /// master link.
    Bond,
}

/// What a tag>0 `<interface>.<tag>` sub-link should be enslaved to — an L2
/// switching-profile `Dot1q` member (`Bridge`) or an L3 `Subinterface`
/// (`Vrf`). Commit-time validation
/// (`valid_subinterface_and_switching_profile_tags`) guarantees a given tag
/// is claimed by at most one of the two, so `reconcile_tagged_subinterfaces`
/// never has to choose between them for the same tag.
enum TaggedMaster {
    /// A domain name, resolved to its bridge the same way as an `Untagged`
    /// member on the physical link itself.
    Bridge(String),
    /// A routing table name (VRF assignment) and this subinterface's own
    /// addresses. `routing_table: None` still creates/addresses the
    /// sub-link, just with no master enslavement — mirrors the physical
    /// link's own "addresses with no VRF" case.
    Vrf {
        routing_table: Option<String>,
        addresses: Vec<InterfaceAddress>,
    },
}

/// Kernel device name for a loopback interface's routing table, mirroring
/// `nos-ribd`'s `vrf<table_id>` VRF naming — the loopback's own config name
/// (`loopback-<table>`) is never used as the kernel name, same reasoning.
fn loopback_ifname(table_id: u32) -> String {
    format!("lo{table_id}")
}

/// Extracts a link's kernel interface name, if it has one (every real link
/// does; this is just the `Option` `find_map` requires).
fn link_name(link: &LinkMessage) -> Option<&str> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::IfName(name) => Some(name.as_str()),
        _ => None,
    })
}

/// The MTU to set on `link` so it has `want`, or `None` if it already does
/// (so the set, and its log line, happen only on a real change).
fn mtu_change(link: &LinkMessage, want: u32) -> Option<u32> {
    let current = link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Mtu(mtu) => Some(*mtu),
        _ => None,
    });
    (current != Some(want)).then_some(want)
}

/// Real `rtnetlink`-backed driver. `nos-interfaced` never creates ordinary
/// interfaces (see `CLAUDE.md`'s scope section) — every operation here
/// configures an interface that must already exist in the netns. The one
/// deliberate, narrow exception is a loopback interface (an `Interface`
/// named `loopback-<table>`, see `nos_proto::loopback_table_name`): its
/// kernel device (a `dummy` link named `lo<table_id>`, since Linux only
/// ever has one real `lo` per netns) is created and destroyed by this
/// driver.
pub struct LinuxInterfaceDriver {
    handle: Handle,
    watchdog_socket: PathBuf,
    /// This driver's own private persisted domain-name -> bridge-id map —
    /// see `bridge_registry` module docs. Never read by any other process.
    bridge_registry_path: PathBuf,
    /// This driver's own private persisted aggregate-name -> bond-id map —
    /// see `port_aggregate_registry` module docs. Never read by any other
    /// process.
    port_aggregate_registry_path: PathBuf,
}

impl LinuxInterfaceDriver {
    pub fn new(
        watchdog_socket: PathBuf,
        bridge_registry_path: PathBuf,
        port_aggregate_registry_path: PathBuf,
    ) -> Result<Self, DriverError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            watchdog_socket,
            bridge_registry_path,
            port_aggregate_registry_path,
        })
    }

    /// `.match_name()` performs a targeted (non-dump) `RTM_GETLINK`
    /// lookup — for a name that doesn't exist, the kernel replies with an
    /// `ENODEV` netlink error rather than an empty result, so that specific
    /// error must be translated back to `Ok(None)` here; any other error is
    /// a real failure and propagates.
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

    /// Resolves `table_name`'s Linux VRF interface name by asking the
    /// owning `nos-ribd` instance directly over IPC (see
    /// `super::rib_client`) — never derived locally, since allocation is
    /// entirely internal to that daemon's driver. `None` covers every
    /// "not answerable yet" case uniformly (broker doesn't know that
    /// table, connect failure, rib hasn't created a VRF yet): all
    /// expected, transient conditions, retried automatically by the
    /// caller's periodic re-apply tick.
    async fn resolve_vrf_name(&self, table_name: &str) -> Option<String> {
        let socket = watchdog_client::resolve_once(
            &self.watchdog_socket,
            &ServiceRef::RibTable(table_name.to_string()),
        )
        .await;
        let Some(socket) = socket else {
            debug!(table = %table_name, "routing table's nos-ribd instance not resolvable yet");
            return None;
        };
        let name = rib_client::get_vrf_name(&socket).await;
        if name.is_none() {
            debug!(table = %table_name, "routing table's nos-ribd has no vrf allocated yet");
        }
        name
    }

    /// Resolves `table_name`'s allocated kernel table id, symmetric to
    /// `resolve_vrf_name` — same broker-resolve-then-query pattern, same
    /// "`None` is normal/transient" contract.
    async fn resolve_table_id(&self, table_name: &str) -> Option<u32> {
        let socket = watchdog_client::resolve_once(
            &self.watchdog_socket,
            &ServiceRef::RibTable(table_name.to_string()),
        )
        .await;
        let Some(socket) = socket else {
            debug!(table = %table_name, "routing table's nos-ribd instance not resolvable yet");
            return None;
        };
        let id = rib_client::get_table_id(&socket).await;
        if id.is_none() {
            debug!(table = %table_name, "routing table's nos-ribd has no table id allocated yet");
        }
        id
    }

    /// Ensures a `dummy` kernel device named `name` exists (creating it if
    /// missing) — the only place this driver ever creates a link, scoped
    /// strictly to loopback interfaces (see the struct doc comment).
    async fn ensure_loopback_link(&self, name: &str) -> Result<LinkMessage, DriverError> {
        if let Some(link) = self.find_link(name).await? {
            return Ok(link);
        }
        self.handle
            .link()
            .add(LinkDummy::new(name).build())
            .execute()
            .await?;
        info!(device = %name, "created loopback device");
        self.find_link(name)
            .await?
            .ok_or_else(|| DriverError::LoopbackNotFound(name.to_string()))
    }

    async fn reconcile_addresses(
        &self,
        interface: &str,
        index: u32,
        desired: &[InterfaceAddress],
    ) -> Result<(), DriverError> {
        // ponytail: label is stored in config but never applied to the
        // kernel (no `ip addr ... label` call) — upgrade when a consumer
        // needs it.
        let desired: Vec<IpNet> = desired.iter().map(|a| a.address).collect();
        let desired = &desired[..];
        let mut observed: Vec<(IpNet, AddressMessage)> = Vec::new();
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        while let Some(msg) = addrs.try_next().await? {
            // Never touch kernel-auto-assigned addresses (IPv6 link-local
            // and friends) — NOS only owns globally/host-scoped addresses
            // it put there itself.
            if msg.header.scope == AddressScope::Link {
                continue;
            }
            let Some(ip) = msg.attributes.iter().find_map(|a| match a {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            }) else {
                continue;
            };
            let Ok(net) = IpNet::new(ip, msg.header.prefix_len) else {
                continue;
            };
            observed.push((net, msg));
        }

        let observed_keys: Vec<IpNet> = observed.iter().map(|(net, _)| *net).collect();
        let (to_add, to_remove) = diff_addresses(&observed_keys, desired);

        for net in to_add {
            self.handle
                .address()
                .add(index, net.addr(), net.prefix_len())
                .execute()
                .await?;
            info!(interface = %interface, address = %net, "added interface address");
        }
        for net in to_remove {
            if let Some((_, msg)) = observed.iter().find(|(o, _)| *o == net) {
                self.handle.address().del(msg.clone()).execute().await?;
                info!(interface = %interface, address = %net, "removed interface address");
            }
        }
        Ok(())
    }

    /// `master_ifname` is looked up purely by name — never by any numeric id
    /// — matching the correction to this plan: nos-interfaced is only ever
    /// told a master interface (VRF or broadcast-domain bridge) *name* over
    /// IPC or local lookup, and links to it by finding a kernel link with
    /// that exact name. Shared by both VRF enslavement (`apply`) and
    /// broadcast-domain bridge enslavement (`apply`'s untagged case,
    /// `reconcile_vlan_members`'s tagged sub-interfaces) — the underlying
    /// Linux operation (`IFLA_MASTER`) is identical either way. `kind`
    /// picks the log wording only (`"vrf"` preserves
    /// `tools/verify-bgp.sh`'s existing "enslaved interface to vrf" grep
    /// exactly; `"bridge"` is the new broadcast-domain case).
    async fn reconcile_master(
        &self,
        interface: &str,
        link: &LinkMessage,
        master_ifname: Option<&str>,
        kind: MasterKind,
    ) -> Result<(), DriverError> {
        let index = link.header.index;
        let current_master = link.attributes.iter().find_map(|a| match a {
            LinkAttribute::Controller(idx) => Some(*idx),
            _ => None,
        });

        let desired_master = match master_ifname {
            Some(name) => {
                let Some(master_link) = self.find_link(name).await? else {
                    // Expected/transient: the target VRF/bridge hasn't been
                    // created yet (or it was just torn down). Leave
                    // enslavement untouched; the periodic re-apply tick
                    // retries.
                    debug!(master = %name, "master interface not present yet, leaving enslavement unchanged");
                    return Ok(());
                };
                Some(master_link.header.index)
            }
            None => None,
        };

        match (current_master, desired_master) {
            (Some(current), Some(want)) if current == want => {}
            (None, None) => {}
            (_, Some(want)) => {
                if kind == MasterKind::Bond {
                    // Unlike bridge/VRF enslavement, Linux bonding refuses to
                    // enslave a link that's administratively up ("Device can
                    // not be enslaved while up") — bring it down first; the
                    // caller's own trailing `up` (apply's final
                    // LinkUnspec::up()) brings it back.
                    self.handle
                        .link()
                        .set(LinkUnspec::new_with_index(index).down().build())
                        .execute()
                        .await?;
                }
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(index).controller(want).build())
                    .execute()
                    .await?;
                match kind {
                    MasterKind::Vrf => info!(
                        interface = %interface,
                        vrf = %master_ifname.unwrap_or_default(),
                        "enslaved interface to vrf"
                    ),
                    MasterKind::Bridge => info!(
                        interface = %interface,
                        bridge = %master_ifname.unwrap_or_default(),
                        "enslaved interface to bridge"
                    ),
                    MasterKind::Bond => info!(
                        interface = %interface,
                        bond = %master_ifname.unwrap_or_default(),
                        "enslaved interface to bond"
                    ),
                }
            }
            (Some(_), None) => {
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(index).nocontroller().build())
                    .execute()
                    .await?;
                info!(interface = %interface, "removed interface from master enslavement");
            }
        }
        Ok(())
    }

    /// Reconciles `interface`'s tag>0 sub-interfaces — one per `Dot1q`
    /// switching-profile member (`TaggedMaster::Bridge`) or per `tag > 0`
    /// `Subinterface` (`TaggedMaster::Vrf`) — against `desired`, keyed by
    /// tag. Creates missing ones, deletes stale ones (a tag no longer
    /// desired by either kind), and enslaves/addresses each per its
    /// `TaggedMaster`. Sub-interface naming: `<interface>.<tag>`, the
    /// standard Linux VLAN sub-interface convention — found on relist by
    /// matching that prefix rather than a targeted lookup, since there's no
    /// single kernel call for "every link whose name starts with X". A
    /// single scan over the *union* of both kinds' tags is required —
    /// scanning each kind separately would see the other kind's live
    /// sub-link as stale and delete it.
    async fn reconcile_tagged_subinterfaces(
        &self,
        interface: &str,
        physical_index: u32,
        desired: &[(u16, TaggedMaster)],
    ) -> Result<(), DriverError> {
        let prefix = format!("{interface}.");
        let desired_tags: Vec<u16> = desired.iter().map(|(tag, _)| *tag).collect();

        let mut links = self.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            let Some(name) = link_name(&link) else {
                continue;
            };
            let Some(tag) = name
                .strip_prefix(&prefix)
                .and_then(|t| t.parse::<u16>().ok())
            else {
                continue;
            };
            if !desired_tags.contains(&tag) {
                self.handle.link().del(link.header.index).execute().await?;
                info!(interface = %interface, sub_interface = %name, "deleted vlan sub-interface");
            }
        }

        for (tag, master) in desired {
            let subname = format!("{prefix}{tag}");
            let sub_link = if let Some(link) = self.find_link(&subname).await? {
                link
            } else {
                self.handle
                    .link()
                    .add(LinkVlan::new(&subname, physical_index, *tag).build())
                    .execute()
                    .await?;
                info!(interface = %interface, sub_interface = %subname, tag, "created vlan sub-interface");
                self.find_link(&subname)
                    .await?
                    .ok_or_else(|| DriverError::LinkNotFoundAfterCreate(subname.clone()))?
            };

            match master {
                TaggedMaster::Bridge(domain) => {
                    let bridge_ifname =
                        bridge_registry::lookup_bridge_id(&self.bridge_registry_path, domain)
                            .map(bridge_registry::bridge_ifname);
                    self.reconcile_master(
                        &subname,
                        &sub_link,
                        bridge_ifname.as_deref(),
                        MasterKind::Bridge,
                    )
                    .await?;
                }
                TaggedMaster::Vrf {
                    routing_table,
                    addresses,
                } => {
                    let vrf_ifname = match routing_table {
                        Some(table_name) => self.resolve_vrf_name(table_name).await,
                        None => None,
                    };
                    self.reconcile_master(
                        &subname,
                        &sub_link,
                        vrf_ifname.as_deref(),
                        MasterKind::Vrf,
                    )
                    .await?;
                    self.reconcile_addresses(&subname, sub_link.header.index, addresses)
                        .await?;
                }
            }

            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(sub_link.header.index)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
        }
        Ok(())
    }

    /// Reconciles a link's addresses, master enslavement (VRF, bridge, or
    /// bond — at most one applies, by construction), and tag>0 VLAN
    /// sub-interfaces from its `subinterfaces`/`switching_profile_members` —
    /// the shared body of `apply`'s physical-interface case and
    /// `ensure_port_aggregate`'s own reconciliation, since a `PortAggregate`
    /// has the identical (non-loopback) config surface as a physical
    /// `Interface`. `name` is the real kernel link name (an interface's own
    /// config name, or a bond's registry-allocated ifname).
    /// `port_aggregate`, if set, names the `PortAggregate` `name` should be
    /// enslaved into — only ever passed by `apply` for a member interface;
    /// `ensure_port_aggregate` always passes `None`, since a bond never
    /// nests into another bond. `port_aggregate_active` gates whether that
    /// enslavement actually happens right now (see
    /// `InterfaceState.port_aggregate_active`); ignored when
    /// `port_aggregate` is `None`.
    async fn reconcile_physical_link(
        &self,
        name: &str,
        link: &LinkMessage,
        switching_profile_members: &[(String, VlanTag)],
        port_aggregate: Option<&str>,
        port_aggregate_active: bool,
        subinterfaces: &[SubinterfaceState],
    ) -> Result<(), DriverError> {
        let index = link.header.index;

        // All (tag-0) L3 config lives in `subinterfaces` — see
        // `schema::valid_addressing_split`/`PortAggregate`'s own doc
        // comment.
        let tag0 = subinterfaces.iter().find(|s| s.tag == 0);
        let physical_addresses: &[InterfaceAddress] =
            tag0.map_or(&[][..], |s| s.addresses.as_slice());
        self.reconcile_addresses(name, index, physical_addresses)
            .await?;

        let vrf_ifname = match tag0.and_then(|s| s.routing_table.clone()) {
            Some(table_name) => self.resolve_vrf_name(&table_name).await,
            None => None,
        };
        // At most one of a VRF/bond/`Untagged`-bridge master can apply to
        // the same link — commit-time validation
        // (`valid_subinterface_and_switching_profile_tags`,
        // `valid_port_aggregate_membership`) rejects any of the three
        // colliding, since the link has only one master.
        let bond_ifname = port_aggregate
            .filter(|_| port_aggregate_active)
            .and_then(|name| {
                port_aggregate_registry::lookup_port_aggregate_id(
                    &self.port_aggregate_registry_path,
                    name,
                )
            })
            .map(port_aggregate_registry::port_aggregate_ifname);
        let untagged_bridge = switching_profile_members
            .iter()
            .find(|(_, tag)| *tag == VlanTag::Untagged)
            .and_then(|(domain, _)| {
                bridge_registry::lookup_bridge_id(&self.bridge_registry_path, domain)
            })
            .map(bridge_registry::bridge_ifname);
        let (master_ifname, master_kind) = match (vrf_ifname, bond_ifname, untagged_bridge) {
            (Some(name), _, _) => (Some(name), MasterKind::Vrf),
            (None, Some(name), _) => (Some(name), MasterKind::Bond),
            (None, None, bridge) => (bridge, MasterKind::Bridge),
        };
        self.reconcile_master(name, link, master_ifname.as_deref(), master_kind)
            .await?;

        // Union of L2 dot1q switching-profile members and L3 subinterfaces
        // (tag>0) — commit-time validation guarantees the two sets of tags
        // are disjoint, so each tag appears in at most one of the two.
        let mut tagged: Vec<(u16, TaggedMaster)> = switching_profile_members
            .iter()
            .filter_map(|(domain, tag)| match tag {
                VlanTag::Dot1q(id) => Some((*id, TaggedMaster::Bridge(domain.clone()))),
                VlanTag::Untagged => None,
            })
            .collect();
        tagged.extend(subinterfaces.iter().filter(|s| s.tag > 0).map(|s| {
            (
                s.tag,
                TaggedMaster::Vrf {
                    routing_table: s.routing_table.clone(),
                    addresses: s.addresses.clone(),
                },
            )
        }));
        self.reconcile_tagged_subinterfaces(name, index, &tagged)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl InterfaceDriver for LinuxInterfaceDriver {
    async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError> {
        let loopback_table = loopback_table_name(&desired.name);

        let link = if let Some(table_name) = loopback_table {
            let Some(table_id) = self.resolve_table_id(table_name).await else {
                debug!(interface = %desired.name, table = %table_name, "table id not resolvable yet");
                return Ok(());
            };
            self.ensure_loopback_link(&loopback_ifname(table_id))
                .await?
        } else {
            let Some(link) = self.find_link(&desired.name).await? else {
                // nos-interfaced never creates ordinary interfaces — this
                // is a normal, expected condition for a not-yet-present
                // interface, not an error.
                debug!(interface = %desired.name, "interface not present in netns yet");
                return Ok(());
            };
            link
        };
        let index = link.header.index;

        if let Some(table_name) = loopback_table {
            // A loopback interface carries its flat L3 config directly
            // (`desired.addresses`/`routing_table`) — it never has
            // `subinterfaces`/`switching_profile`/`port_aggregate`, so
            // there's nothing for `reconcile_physical_link` to share here.
            self.reconcile_addresses(&desired.name, index, &desired.addresses)
                .await?;
            let vrf_ifname = self.resolve_vrf_name(table_name).await;
            self.reconcile_master(&desired.name, &link, vrf_ifname.as_deref(), MasterKind::Vrf)
                .await?;
        } else {
            self.reconcile_physical_link(
                &desired.name,
                &link,
                &desired.switching_profile_members,
                desired.port_aggregate.as_deref(),
                desired.port_aggregate_active,
                &desired.subinterfaces,
            )
            .await?;
        }

        let mut link_set = LinkUnspec::new_with_index(index).up();
        // Unset means 1500, enforced — except on a bond member, whose MTU the
        // bonding driver sets from its bond's.
        let want = desired
            .mtu
            .or(desired.port_aggregate.is_none().then_some(DEFAULT_MTU));
        if let Some(mtu) = want.and_then(|want| mtu_change(&link, want)) {
            link_set = link_set.mtu(mtu);
            info!(interface = %desired.name, mtu, "applied interface mtu");
        }
        self.handle.link().set(link_set.build()).execute().await?;
        trace!(interface = %desired.name, "ensuring interface administratively up");
        Ok(())
    }

    async fn remove(&self, name: &str) -> Result<(), DriverError> {
        if let Some(table_name) = loopback_table_name(name) {
            let Some(table_id) = self.resolve_table_id(table_name).await else {
                debug!(interface = %name, table = %table_name, "table id not resolvable yet, nothing to remove");
                return Ok(());
            };
            let kernel_name = loopback_ifname(table_id);
            let Some(link) = self.find_link(&kernel_name).await? else {
                debug!(interface = %name, device = %kernel_name, "loopback device not present, nothing to remove");
                return Ok(());
            };
            self.reconcile_addresses(&kernel_name, link.header.index, &[])
                .await?;
            self.handle.link().del(link.header.index).execute().await?;
            info!(interface = %name, device = %kernel_name, "deleted loopback device");
            return Ok(());
        }

        let Some(link) = self.find_link(name).await? else {
            debug!(interface = %name, "interface not present in netns, nothing to remove");
            return Ok(());
        };
        self.reconcile_tagged_subinterfaces(name, link.header.index, &[])
            .await?;
        self.reconcile_addresses(name, link.header.index, &[])
            .await?;
        self.reconcile_master(name, &link, None, MasterKind::Vrf)
            .await?;
        Ok(())
    }

    /// Ensures a bridge device named from `desired.name`'s persisted bridge
    /// id (see `bridge_registry`) exists — find-or-create, same shape as
    /// `ensure_loopback_link`/`nos-ribd`'s `ensure_vrf` — then reconciles
    /// `desired.addresses`/`routing_table` directly onto that bridge device,
    /// the same two calls `apply` makes for a physical/loopback link's own
    /// L3 config, making the bridge an SVI.
    async fn ensure_broadcast_domain(
        &self,
        desired: &BroadcastDomainState,
    ) -> Result<String, DriverError> {
        let bridge_id =
            bridge_registry::ensure_bridge_id(&self.bridge_registry_path, &desired.name)?;
        let ifname = bridge_registry::bridge_ifname(bridge_id);
        let link = if let Some(link) = self.find_link(&ifname).await? {
            link
        } else {
            self.handle
                .link()
                .add(LinkBridge::new(&ifname).build())
                .execute()
                .await?;
            info!(domain = %desired.name, bridge = %ifname, "created broadcast domain bridge");
            self.find_link(&ifname)
                .await?
                .ok_or_else(|| DriverError::LinkNotFoundAfterCreate(ifname.clone()))?
        };

        self.reconcile_addresses(&ifname, link.header.index, &desired.addresses)
            .await?;
        let vrf_ifname = match &desired.routing_table {
            Some(table_name) => self.resolve_vrf_name(table_name).await,
            None => None,
        };
        self.reconcile_master(&ifname, &link, vrf_ifname.as_deref(), MasterKind::Vrf)
            .await?;

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(link.header.index).up().build())
            .execute()
            .await?;
        Ok(ifname)
    }

    /// Deletes `domain`'s bridge device, if one was ever created for it.
    /// Never touches the bridge-id registry entry — same reasoning as
    /// `nos-ribd`'s VRF teardown: a later restart (or the domain being
    /// re-added) recreates the identically-named bridge.
    async fn remove_broadcast_domain(&self, domain: &str) -> Result<(), DriverError> {
        let Some(bridge_id) = bridge_registry::lookup_bridge_id(&self.bridge_registry_path, domain)
        else {
            debug!(domain = %domain, "no bridge id allocated, nothing to tear down");
            return Ok(());
        };
        let ifname = bridge_registry::bridge_ifname(bridge_id);
        if let Some(link) = self.find_link(&ifname).await? {
            self.handle.link().del(link.header.index).execute().await?;
            info!(domain = %domain, bridge = %ifname, "deleted broadcast domain bridge");
        }
        Ok(())
    }

    /// Ensures a bond device named from `desired.name`'s persisted bond id
    /// (see `port_aggregate_registry`) exists — find-or-create, same shape
    /// as `ensure_broadcast_domain`'s bridge — then reconciles the bond's
    /// own `switching_profile`/`mtu`/`subinterfaces` via the same
    /// `reconcile_physical_link` helper `apply` uses for a physical
    /// interface, since the config surface is identical.
    async fn ensure_port_aggregate(
        &self,
        desired: &PortAggregateState,
    ) -> Result<String, DriverError> {
        let bond_id = port_aggregate_registry::ensure_port_aggregate_id(
            &self.port_aggregate_registry_path,
            &desired.name,
        )?;
        let ifname = port_aggregate_registry::port_aggregate_ifname(bond_id);
        let link = if let Some(link) = self.find_link(&ifname).await? {
            link
        } else {
            self.handle
                .link()
                .add(
                    LinkBond::new(&ifname)
                        .mode(bond_mode_of(desired.mode))
                        .build(),
                )
                .execute()
                .await?;
            info!(port_aggregate = %desired.name, bond = %ifname, mode = ?desired.mode, "created port aggregate bond");
            self.find_link(&ifname)
                .await?
                .ok_or_else(|| DriverError::LinkNotFoundAfterCreate(ifname.clone()))?
        };
        let index = link.header.index;

        self.reconcile_physical_link(
            &ifname,
            &link,
            &desired.switching_profile_members,
            None,
            true,
            &desired.subinterfaces,
        )
        .await?;

        let mut link_set = LinkUnspec::new_with_index(index).up();
        if let Some(mtu) = mtu_change(&link, desired.mtu.unwrap_or(DEFAULT_MTU)) {
            link_set = link_set.mtu(mtu);
            info!(port_aggregate = %desired.name, mtu, "applied port aggregate mtu");
        }
        self.handle.link().set(link_set.build()).execute().await?;
        Ok(ifname)
    }

    /// Deletes `name`'s bond device, if one was ever created for it. Never
    /// touches the port-aggregate-id registry entry — same reasoning as
    /// `remove_broadcast_domain`.
    async fn remove_port_aggregate(&self, name: &str) -> Result<(), DriverError> {
        let Some(bond_id) = port_aggregate_registry::lookup_port_aggregate_id(
            &self.port_aggregate_registry_path,
            name,
        ) else {
            debug!(port_aggregate = %name, "no port aggregate id allocated, nothing to tear down");
            return Ok(());
        };
        let ifname = port_aggregate_registry::port_aggregate_ifname(bond_id);
        if let Some(link) = self.find_link(&ifname).await? {
            self.handle.link().del(link.header.index).execute().await?;
            info!(port_aggregate = %name, bond = %ifname, "deleted port aggregate bond");
        }
        Ok(())
    }

    async fn link_local_address(&self, kernel_interface: &str) -> Option<Ipv6Addr> {
        let link = self.find_link(kernel_interface).await.ok()??;
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();
        while let Ok(Some(msg)) = addrs.try_next().await {
            if msg.header.scope != AddressScope::Link {
                continue;
            }
            if let Some(IpAddr::V6(addr)) = msg.attributes.iter().find_map(|a| match a {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            }) {
                return Some(addr);
            }
        }
        None
    }
}

/// Pure, netlink-free: `desired`/`observed` are both plain address lists —
/// no kernel involved, so this is directly unit-testable.
fn diff_addresses(observed: &[IpNet], desired: &[IpNet]) -> (Vec<IpNet>, Vec<IpNet>) {
    let to_add = desired
        .iter()
        .filter(|d| !observed.contains(d))
        .copied()
        .collect();
    let to_remove = observed
        .iter()
        .filter(|o| !desired.contains(o))
        .copied()
        .collect();
    (to_add, to_remove)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_change_only_when_the_link_differs() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkAttribute::Mtu(9000));
        assert_eq!(mtu_change(&link, 1500), Some(1500));
        assert_eq!(mtu_change(&link, 9000), None);
    }

    #[test]
    fn loopback_ifname_formats_from_id() {
        assert_eq!(loopback_ifname(100), "lo100");
    }

    #[test]
    fn diff_addresses_computes_add_and_remove() {
        let observed = vec![
            "10.0.0.1/24".parse().unwrap(),
            "10.0.0.9/24".parse().unwrap(),
        ];
        let desired = vec![
            "10.0.0.1/24".parse().unwrap(),
            "10.0.0.2/24".parse().unwrap(),
        ];
        let (to_add, to_remove) = diff_addresses(&observed, &desired);
        assert_eq!(to_add, vec!["10.0.0.2/24".parse().unwrap()]);
        assert_eq!(to_remove, vec!["10.0.0.9/24".parse().unwrap()]);
    }

    #[test]
    fn diff_addresses_no_change_when_equal() {
        let addrs = vec!["10.0.0.1/24".parse().unwrap()];
        let (to_add, to_remove) = diff_addresses(&addrs, &addrs);
        assert!(to_add.is_empty());
        assert!(to_remove.is_empty());
    }

    #[test]
    fn diff_addresses_empty_desired_removes_everything() {
        let observed = vec!["10.0.0.1/24".parse().unwrap()];
        let (to_add, to_remove) = diff_addresses(&observed, &[]);
        assert!(to_add.is_empty());
        assert_eq!(to_remove, observed);
    }

    #[test]
    fn diff_addresses_empty_observed_adds_everything() {
        let desired = vec!["10.0.0.1/24".parse().unwrap()];
        let (to_add, to_remove) = diff_addresses(&[], &desired);
        assert_eq!(to_add, desired);
        assert!(to_remove.is_empty());
    }
}
