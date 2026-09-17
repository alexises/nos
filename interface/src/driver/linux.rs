use std::path::PathBuf;

use async_trait::async_trait;
use futures::TryStreamExt;
use nos_proto::{loopback_table_name, InterfaceAddress, IpNet, ServiceRef, VlanTag};
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use rtnetlink::packet_route::link::{LinkAttribute, LinkMessage};
use rtnetlink::{Handle, LinkBridge, LinkDummy, LinkUnspec, LinkVlan};
use tracing::{debug, info, trace};

use super::{bridge_registry, rib_client, DriverError, InterfaceDriver};
use crate::state::InterfaceState;
use crate::watchdog_client;

/// errno(3) `ENODEV` — the kernel's reply to a targeted `RTM_GETLINK`
/// lookup (`match_name`/`match_index`) for a link that doesn't exist.
const ENODEV: i32 = 19;

/// Which kind of thing `reconcile_master` is enslaving a link into — picks
/// only the log wording, see its doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MasterKind {
    Vrf,
    Bridge,
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
}

impl LinuxInterfaceDriver {
    pub fn new(
        watchdog_socket: PathBuf,
        bridge_registry_path: PathBuf,
    ) -> Result<Self, DriverError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            watchdog_socket,
            bridge_registry_path,
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

    /// Reconciles `interface`'s 802.1q sub-interfaces (one per `Dot1q`
    /// switching-profile member) against `desired` — creates missing ones,
    /// deletes stale ones (a tag no longer desired, or the whole profile
    /// cleared away, in which case `desired` is empty), and enslaves each
    /// into its broadcast domain's bridge. Sub-interface naming:
    /// `<interface>.<tag>`, the standard Linux VLAN sub-interface
    /// convention — found on relist by matching that prefix rather than a
    /// targeted lookup, since there's no single kernel call for "every link
    /// whose name starts with X".
    async fn reconcile_vlan_members(
        &self,
        interface: &str,
        physical_index: u32,
        desired: &[(String, u16)],
    ) -> Result<(), DriverError> {
        let prefix = format!("{interface}.");
        let desired_tags: Vec<u16> = desired.iter().map(|(_, tag)| *tag).collect();

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

        for (domain, tag) in desired {
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

        self.reconcile_addresses(&desired.name, index, &desired.addresses)
            .await?;

        let vrf_table = loopback_table
            .map(str::to_string)
            .or_else(|| desired.routing_table.clone());
        let vrf_ifname = match vrf_table {
            Some(table_name) => self.resolve_vrf_name(&table_name).await,
            None => None,
        };
        // At most one of `vrf_ifname`/an `Untagged` member can apply to the
        // same interface — commit-time validation
        // (`valid_routing_table_and_switching_profile`) rejects the
        // combination of `routing_table` and an `Untagged` switching-profile
        // member, since the physical link has only one master.
        let untagged_bridge = desired
            .switching_profile_members
            .iter()
            .find(|(_, tag)| *tag == VlanTag::Untagged)
            .and_then(|(domain, _)| {
                bridge_registry::lookup_bridge_id(&self.bridge_registry_path, domain)
            })
            .map(bridge_registry::bridge_ifname);
        let (master_ifname, master_kind) = match vrf_ifname {
            Some(name) => (Some(name), MasterKind::Vrf),
            None => (untagged_bridge, MasterKind::Bridge),
        };
        self.reconcile_master(&desired.name, &link, master_ifname.as_deref(), master_kind)
            .await?;

        let dot1q_members: Vec<(String, u16)> = desired
            .switching_profile_members
            .iter()
            .filter_map(|(domain, tag)| match tag {
                VlanTag::Dot1q(id) => Some((domain.clone(), *id)),
                VlanTag::Untagged => None,
            })
            .collect();
        self.reconcile_vlan_members(&desired.name, index, &dot1q_members)
            .await?;

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await?;
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
        self.reconcile_vlan_members(name, link.header.index, &[])
            .await?;
        self.reconcile_addresses(name, link.header.index, &[])
            .await?;
        self.reconcile_master(name, &link, None, MasterKind::Vrf)
            .await?;
        Ok(())
    }

    /// Ensures a bridge device named from `domain`'s persisted bridge id
    /// (see `bridge_registry`) exists and is up — find-or-create, same
    /// shape as `ensure_loopback_link`/`nos-ribd`'s `ensure_vrf`.
    async fn ensure_broadcast_domain(&self, domain: &str) -> Result<(), DriverError> {
        let bridge_id = bridge_registry::ensure_bridge_id(&self.bridge_registry_path, domain)?;
        let ifname = bridge_registry::bridge_ifname(bridge_id);
        let link = if let Some(link) = self.find_link(&ifname).await? {
            link
        } else {
            self.handle
                .link()
                .add(LinkBridge::new(&ifname).build())
                .execute()
                .await?;
            info!(domain = %domain, bridge = %ifname, "created broadcast domain bridge");
            self.find_link(&ifname)
                .await?
                .ok_or_else(|| DriverError::LinkNotFoundAfterCreate(ifname.clone()))?
        };
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(link.header.index).up().build())
            .execute()
            .await?;
        Ok(())
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
