use std::path::PathBuf;

use async_trait::async_trait;
use futures::TryStreamExt;
use nos_proto::{loopback_table_name, InterfaceAddress, IpNet, ServiceRef};
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use rtnetlink::packet_route::link::{LinkAttribute, LinkMessage};
use rtnetlink::{Handle, LinkDummy, LinkUnspec};
use tracing::{debug, info, trace};

use super::{rib_client, DriverError, InterfaceDriver};
use crate::state::InterfaceState;
use crate::watchdog_client;

/// errno(3) `ENODEV` — the kernel's reply to a targeted `RTM_GETLINK`
/// lookup (`match_name`/`match_index`) for a link that doesn't exist.
const ENODEV: i32 = 19;

/// Kernel device name for a loopback interface's routing table, mirroring
/// `nos-ribd`'s `vrf<table_id>` VRF naming — the loopback's own config name
/// (`loopback-<table>`) is never used as the kernel name, same reasoning.
fn loopback_ifname(table_id: u32) -> String {
    format!("lo{table_id}")
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
}

impl LinuxInterfaceDriver {
    pub fn new(watchdog_socket: PathBuf) -> Result<Self, DriverError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            watchdog_socket,
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

    /// `vrf_ifname` is looked up purely by name — never by any numeric id
    /// — matching the correction to this plan: nos-interfaced is only ever
    /// told a VRF interface *name* over IPC, and links to it by finding a
    /// kernel link with that exact name.
    async fn reconcile_master(
        &self,
        interface: &str,
        link: &LinkMessage,
        vrf_ifname: Option<&str>,
    ) -> Result<(), DriverError> {
        let index = link.header.index;
        let current_master = link.attributes.iter().find_map(|a| match a {
            LinkAttribute::Controller(idx) => Some(*idx),
            _ => None,
        });

        let desired_master = match vrf_ifname {
            Some(name) => {
                let Some(vrf_link) = self.find_link(name).await? else {
                    // Expected/transient: the table's nos-ribd hasn't
                    // created its VRF yet (or it was just torn down).
                    // Leave enslavement untouched; the periodic re-apply
                    // tick retries.
                    debug!(vrf = %name, "vrf interface not present yet, leaving enslavement unchanged");
                    return Ok(());
                };
                Some(vrf_link.header.index)
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
                info!(
                    interface = %interface,
                    vrf = %vrf_ifname.unwrap_or_default(),
                    "enslaved interface to vrf"
                );
            }
            (Some(_), None) => {
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(index).nocontroller().build())
                    .execute()
                    .await?;
                info!(interface = %interface, "removed interface from vrf enslavement");
            }
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
        self.reconcile_master(&desired.name, &link, vrf_ifname.as_deref())
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
        self.reconcile_addresses(name, link.header.index, &[])
            .await?;
        self.reconcile_master(name, &link, None).await?;
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
