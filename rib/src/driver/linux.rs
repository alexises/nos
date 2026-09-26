use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use futures::{stream, StreamExt as _, TryStreamExt as _};
use nos_proto::IpNet;
use rtnetlink::packet_route::link::LinkMessage;
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::{Handle, LinkUnspec, LinkVrf, RouteMessageBuilder};
use tracing::{debug, info, trace, warn};

use super::route_channel::RouteChannel;
use super::{table_registry, DriverError, RibDriver};
use crate::rib::{RibEntry, RouteSource};

/// errno(3) `ENODEV` — the kernel's reply to a targeted `RTM_GETLINK`
/// lookup (`match_name`/`match_index`) for a link that doesn't exist.
const ENODEV: i32 = 19;

// ponytail: fixed fan-out bound rather than a `--driver` flag — nothing in
// the bench-bgp kernel-install report suggests 64 is the wrong number.
// Upgrade to real rtnetlink-level batching if concurrency alone stops
// closing the gap to BIRD/FRR/GoBGP.
const MAX_CONCURRENT_ROUTE_OPS: usize = 64;

/// Kernel route priority (metric) of a backup route. Primaries use the
/// default (0, which the kernel reports as 0 for IPv4 and 1024 for IPv6), so
/// the backup must sit above that per family (an IPv6 backup at 1000 would
/// beat its own primary); the kernel keeps both routes in the FIB and falls
/// to this one the moment the primary is withdrawn — no netlink round trip
/// needed at failover time.
const BACKUP_METRIC_V4: u32 = 1000;
const BACKUP_METRIC_V6: u32 = 2000;

/// One kernel route of a prefix: `false` is the primary, `true` its backup.
type Slot = (IpNet, bool);

/// The kernel routes one winning entry wants: its primary, plus its backup.
fn slots(prefix: IpNet, entry: &RibEntry) -> Vec<(Slot, GatewayAndInterface)> {
    let mut out = vec![((prefix, false), (entry.gateway, entry.interface_id))];
    if let Some(backup) = entry.backup {
        out.push(((prefix, true), (backup, entry.backup_interface_id)));
    }
    out
}

/// A gateway plus (when known) the local kernel interface it's reachable
/// over — see `RibEntry::interface_id`'s doc comment.
type GatewayAndInterface = (IpAddr, Option<u32>);

/// Real Linux backend: creates a VRF device + kernel routing table per
/// routing table name (via `table_registry`'s persisted id allocation) and
/// installs the winning route per prefix into it.
pub struct LinuxRibDriver {
    handle: Handle,
    /// Dedicated, genuinely pipelined channel for route add/del — see
    /// `route_channel` module docs for why `handle` above (an ordinary
    /// `rtnetlink::Handle`) isn't used for this. Link/VRF management and
    /// route dumps stay on `handle`.
    route_channel: RouteChannel,
    registry_path: PathBuf,
    /// This driver's own record of what it last installed per table id —
    /// lets `apply_delta` add/remove exactly what changed without a fresh
    /// kernel dump. Kept honest by `reconcile_routes` (used by `apply`/
    /// `teardown`), which always sets it to the just-converged desired
    /// state; `apply_delta` is the only other writer, and only for
    /// prefixes it just itself installed/removed. A `std::sync::Mutex`,
    /// since every critical section here is a quick synchronous map
    /// read/write, never held across an `.await`. The `Option<u32>`
    /// alongside each gateway is `RibEntry::interface_id`, needed to
    /// reconstruct a matching `RTM_DELROUTE` for a link-local IPv6 gateway
    /// on the `apply_delta` removal path (see `add_route`'s doc comment).
    installed: Mutex<HashMap<u32, HashMap<Slot, GatewayAndInterface>>>,
}

impl LinuxRibDriver {
    pub fn new(registry_path: PathBuf) -> Result<Self, DriverError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        let route_channel = RouteChannel::new()?;
        Ok(Self {
            handle,
            route_channel,
            registry_path,
            installed: Mutex::new(HashMap::new()),
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

    /// Ensures the VRF device for `table_id` exists and is up, returning
    /// its ifindex.
    async fn ensure_vrf(&self, vrf_ifname: &str, table_id: u32) -> Result<u32, DriverError> {
        let index = if let Some(link) = self.find_link(vrf_ifname).await? {
            link.header.index
        } else {
            self.handle
                .link()
                .add(LinkVrf::new(vrf_ifname, table_id).build())
                .execute()
                .await?;
            let index = self
                .find_link(vrf_ifname)
                .await?
                .map(|link| link.header.index)
                .ok_or_else(|| {
                    DriverError::Registry(std::io::Error::other(format!(
                        "created VRF {vrf_ifname} but could not find it afterwards"
                    )))
                })?;
            info!(vrf = %vrf_ifname, table_id, "created VRF device");
            index
        };
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await?;
        trace!(vrf = %vrf_ifname, index, "ensured VRF link is up");
        Ok(index)
    }

    /// Dumps every route currently installed in kernel table `table_id`,
    /// across both address families, keeping the raw `RouteMessage`
    /// alongside its extracted `(prefix, gateway)` so a later deletion can
    /// reuse the exact message the kernel gave us (the safest way to make
    /// sure `RTM_DELROUTE` matches the entry we mean).
    async fn dump_routes(
        &self,
        table_id: u32,
    ) -> Result<Vec<(Slot, IpAddr, RouteMessage)>, DriverError> {
        let mut out = Vec::new();
        let table_id_u8 =
            u8::try_from(table_id).expect("table ids are always <= MAX_TABLE_ID (252)");

        let v4_filter = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(table_id)
            .build();
        let mut v4 = self.handle.route().get(v4_filter).execute();
        while let Some(route) = v4.try_next().await? {
            if route.header.table == table_id_u8 {
                if let Some((slot, gateway)) = extract_route(&route) {
                    out.push((slot, gateway, route));
                }
            }
        }

        let v6_filter = RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(table_id)
            .build();
        let mut v6 = self.handle.route().get(v6_filter).execute();
        while let Some(route) = v6.try_next().await? {
            if route.header.table == table_id_u8 {
                if let Some((slot, gateway)) = extract_route(&route) {
                    out.push((slot, gateway, route));
                }
            }
        }

        Ok(out)
    }

    /// `interface_id`, when given, becomes `RTA_OIF` on the built route —
    /// **required**, not optional, for an IPv6 gateway that's link-local
    /// (`fe80::/10`): Linux's `RTM_NEWROUTE` rejects such a route with
    /// `EINVAL` unless an outgoing interface is given alongside the
    /// gateway, since a link-local address is only meaningful relative to
    /// a specific link and the kernel has no other way to resolve which
    /// one. `nos-ospfv3d`'s own SPF next-hops are always link-local (RFC
    /// 5340 §4.8) and always carry a `Some` here; every other route source
    /// passes `None` and needs none. `backup` installs it at
    /// the family's backup metric instead of the default priority.
    async fn add_route(
        &self,
        table_id: u32,
        prefix: IpNet,
        gateway: IpAddr,
        source: Option<RouteSource>,
        interface_id: Option<u32>,
        backup: bool,
    ) -> Result<(), DriverError> {
        let Some(route) = build_route(prefix, gateway, table_id, interface_id, backup) else {
            warn!(%prefix, %gateway, table_id, "route prefix/gateway address family mismatch, skipping");
            return Ok(());
        };
        self.route_channel.add(route).await.inspect_err(|e| {
            warn!(%prefix, %gateway, table_id, backup, error = %e, "failed to add route");
        })?;
        info!(%prefix, %gateway, table_id, source = ?source, backup, "added route");
        Ok(())
    }

    /// Deletes one route directly from `(prefix, gateway, table_id,
    /// priority)`, without a kernel dump — the standard, sufficient way to
    /// identify a route for `RTM_DELROUTE` (the same key fields `ip route
    /// del ... table ... metric ...` uses). Used by `apply_delta`'s
    /// shadow-state-driven fast path; `reconcile_routes`'s full dump-diff
    /// path still reuses the exact dumped `RouteMessage` instead, since it
    /// already has it on hand. `interface_id` has the same load-bearing role
    /// for a link-local IPv6 gateway as `add_route`'s own doc comment
    /// describes.
    async fn remove_route(
        &self,
        table_id: u32,
        prefix: IpNet,
        gateway: IpAddr,
        interface_id: Option<u32>,
        backup: bool,
    ) -> Result<(), DriverError> {
        let Some(route) = build_route(prefix, gateway, table_id, interface_id, backup) else {
            warn!(%prefix, %gateway, table_id, "route prefix/gateway address family mismatch, skipping");
            return Ok(());
        };
        self.route_channel.del(route).await.inspect_err(|e| {
            warn!(%prefix, %gateway, table_id, backup, error = %e, "failed to remove route");
        })?;
        info!(%prefix, %gateway, table_id, backup, "removed route");
        Ok(())
    }

    /// Applies only `changes` directly against the kernel, using
    /// `self.installed` (not a kernel dump) to know each prefix's previous
    /// gateway — the hot path for incremental per-prefix BGP pushes. See
    /// `RibDriver::apply_delta`'s doc comment.
    async fn apply_delta_impl(
        &self,
        table_id: u32,
        changes: &HashMap<IpNet, Option<RibEntry>>,
    ) -> Result<(), DriverError> {
        type Slots = HashMap<Slot, GatewayAndInterface>;
        let items: Vec<(IpNet, Slots, Slots, Option<RouteSource>)> = {
            let installed = self.installed.lock().unwrap();
            let table_installed = installed.get(&table_id);
            changes
                .iter()
                .map(|(prefix, new)| {
                    let old: Slots = [false, true]
                        .into_iter()
                        .filter_map(|b| {
                            let slot = (*prefix, b);
                            table_installed
                                .and_then(|m| m.get(&slot))
                                .map(|gi| (slot, *gi))
                        })
                        .collect();
                    let source = new.as_ref().map(|e| e.source);
                    let new: Slots = new
                        .as_ref()
                        .map(|e| slots(*prefix, e).into_iter().collect())
                        .unwrap_or_default();
                    (*prefix, old, new, source)
                })
                .collect()
        };

        stream::iter(items)
            .map(|(prefix, old, new, source)| async move {
                // Remove before add, per prefix (a changed gateway at the
                // same priority would otherwise hit EEXIST).
                for (slot, (gw, ifid)) in &old {
                    if new.get(slot).map(|(g, _)| g) != Some(gw) {
                        self.remove_route(table_id, prefix, *gw, *ifid, slot.1)
                            .await?;
                    }
                }
                for (slot, (gw, ifid)) in &new {
                    if old.get(slot).map(|(g, _)| g) != Some(gw) {
                        self.add_route(table_id, prefix, *gw, source, *ifid, slot.1)
                            .await?;
                    }
                }

                let mut installed = self.installed.lock().unwrap();
                let table_installed = installed.entry(table_id).or_default();
                for b in [false, true] {
                    table_installed.remove(&(prefix, b));
                }
                table_installed.extend(new);
                Ok::<(), DriverError>(())
            })
            .buffer_unordered(MAX_CONCURRENT_ROUTE_OPS)
            .try_for_each(|()| async { Ok(()) })
            .await
    }

    /// Diffs `best_routes` against what's actually installed in
    /// `table_id`'s kernel table and adds/removes to converge, reusing the
    /// exact dumped `RouteMessage` for any removal.
    async fn reconcile_routes(
        &self,
        table_id: u32,
        best_routes: &HashMap<IpNet, RibEntry>,
    ) -> Result<(), DriverError> {
        let observed = self.dump_routes(table_id).await?;
        let observed_map: HashMap<Slot, IpAddr> = observed
            .iter()
            .map(|(slot, gateway, _)| (*slot, *gateway))
            .collect();
        let desired_full: HashMap<Slot, GatewayAndInterface> = best_routes
            .iter()
            .flat_map(|(prefix, entry)| slots(*prefix, entry))
            .collect();
        let desired: HashMap<Slot, IpAddr> = desired_full
            .iter()
            .map(|(slot, (gw, _))| (*slot, *gw))
            .collect();

        let observed_by_slot: HashMap<Slot, RouteMessage> = observed
            .iter()
            .map(|(slot, _, message)| (*slot, message.clone()))
            .collect();

        let (to_add, to_remove) = diff_routes(&observed_map, &desired);
        debug!(
            table_id,
            to_add = to_add.len(),
            to_remove = to_remove.len(),
            "reconciling kernel routes"
        );

        // Remove before add: `to_add`/`to_remove` can share the same prefix
        // with a different gateway (an operator changed a static route's
        // next hop) — adding the new route while the kernel still has the
        // old one for that exact prefix fails with EEXIST (`rtnetlink`'s
        // route add uses NLM_F_CREATE | NLM_F_EXCL), so the stale entry
        // must be gone first. Within each phase, up to
        // MAX_CONCURRENT_ROUTE_OPS requests are in flight at once, sent
        // over the dedicated `route_channel` (see its module docs) — a
        // plain `rtnetlink::Handle` dispatches one request at a time
        // regardless of client-side concurrency, so it isn't used here.
        stream::iter(to_remove)
            .map(|((prefix, backup), gateway)| {
                let message = observed_by_slot.get(&(prefix, backup)).cloned();
                async move {
                    if let Some(message) = message {
                        self.route_channel.del(message).await.inspect_err(|e| {
                            warn!(%prefix, %gateway, table_id, error = %e, "failed to remove route");
                        })?;
                        info!(%prefix, %gateway, table_id, backup, "removed route");
                    }
                    Ok::<(), DriverError>(())
                }
            })
            .buffer_unordered(MAX_CONCURRENT_ROUTE_OPS)
            .try_for_each(|()| async { Ok(()) })
            .await?;

        stream::iter(to_add)
            .map(|((prefix, backup), gateway)| {
                let source = best_routes.get(&prefix).map(|e| e.source);
                let interface_id = desired_full
                    .get(&(prefix, backup))
                    .and_then(|(_, ifid)| *ifid);
                async move {
                    self.add_route(table_id, prefix, gateway, source, interface_id, backup)
                        .await
                }
            })
            .buffer_unordered(MAX_CONCURRENT_ROUTE_OPS)
            .try_for_each(|()| async { Ok(()) })
            .await?;

        // The kernel now matches `desired` exactly — seed/correct
        // `apply_delta`'s shadow state from this ground truth, including on
        // `teardown` (an empty `desired` correctly clears it).
        self.installed
            .lock()
            .unwrap()
            .insert(table_id, desired_full);
        Ok(())
    }
}

#[async_trait]
impl RibDriver for LinuxRibDriver {
    async fn apply(
        &self,
        table_name: &str,
        best_routes: &HashMap<IpNet, RibEntry>,
    ) -> Result<(), DriverError> {
        debug!(table = %table_name, routes = best_routes.len(), "applying routes to kernel");
        let table_id = table_registry::ensure_table_id(&self.registry_path, table_name)?;
        let vrf_ifname = table_registry::vrf_ifname(table_id);
        self.ensure_vrf(&vrf_ifname, table_id).await?;
        self.reconcile_routes(table_id, best_routes).await
    }

    async fn apply_delta(
        &self,
        table_name: &str,
        changes: &HashMap<IpNet, Option<RibEntry>>,
    ) -> Result<(), DriverError> {
        debug!(table = %table_name, changed = changes.len(), "applying route deltas to kernel");
        let table_id = table_registry::ensure_table_id(&self.registry_path, table_name)?;
        let vrf_ifname = table_registry::vrf_ifname(table_id);
        self.ensure_vrf(&vrf_ifname, table_id).await?;
        self.apply_delta_impl(table_id, changes).await
    }

    async fn teardown(&self, table_name: &str) -> Result<(), DriverError> {
        let Some(table_id) = table_registry::lookup_table_id(&self.registry_path, table_name)
        else {
            debug!(table = %table_name, "no table id allocated, nothing to tear down");
            return Ok(());
        };
        self.reconcile_routes(table_id, &HashMap::new()).await?;

        let vrf_ifname = table_registry::vrf_ifname(table_id);
        if let Some(link) = self.find_link(&vrf_ifname).await? {
            self.handle.link().del(link.header.index).execute().await?;
            info!(vrf = %vrf_ifname, table_id, "deleted VRF device");
        }
        Ok(())
    }

    async fn vrf_name(&self, table_name: &str) -> Option<String> {
        table_registry::lookup_table_id(&self.registry_path, table_name)
            .map(table_registry::vrf_ifname)
    }

    async fn table_id(&self, table_name: &str) -> Option<u32> {
        table_registry::lookup_table_id(&self.registry_path, table_name)
    }
}

/// Extracts `((prefix, is_backup), gateway)` from a dumped `RouteMessage`, or `None` for
/// a route we don't manage (no gateway — e.g. a kernel-internal entry a VRF
/// device creates on its own, or an unsupported address family like MPLS).
/// A missing `Destination` attribute means the default route (kernel omits
/// it for 0/0), so it falls back to the family's unspecified address.
fn extract_route(route: &RouteMessage) -> Option<(Slot, IpAddr)> {
    let gateway = route.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Gateway(addr) => route_address_to_ip(addr),
        _ => None,
    })?;

    let destination = route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Destination(addr) => route_address_to_ip(addr),
            _ => None,
        })
        .unwrap_or(match route.header.address_family {
            AddressFamily::Inet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            AddressFamily::Inet6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => return None,
        });

    let backup = route.attributes.iter().any(|attr| {
        matches!(
            attr,
            RouteAttribute::Priority(BACKUP_METRIC_V4 | BACKUP_METRIC_V6)
        )
    });

    IpNet::new(destination, route.header.destination_prefix_length)
        .ok()
        .map(|prefix| ((prefix, backup), gateway))
}

/// Builds the `RouteMessage` for one kernel route, `None` on a
/// prefix/gateway address-family mismatch. `backup` sets the family's backup metric.
fn build_route(
    prefix: IpNet,
    gateway: IpAddr,
    table_id: u32,
    interface_id: Option<u32>,
    backup: bool,
) -> Option<RouteMessage> {
    match (prefix, gateway) {
        (IpNet::V4(prefix), IpAddr::V4(gateway)) => {
            let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(prefix.addr(), prefix.prefix_len())
                .gateway(gateway)
                .table_id(table_id);
            if backup {
                builder = builder.priority(BACKUP_METRIC_V4);
            }
            Some(builder.build())
        }
        (IpNet::V6(prefix), IpAddr::V6(gateway)) => {
            let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(prefix.addr(), prefix.prefix_len())
                .gateway(gateway)
                .table_id(table_id);
            if let Some(interface_id) = interface_id {
                builder = builder.output_interface(interface_id);
            }
            if backup {
                builder = builder.priority(BACKUP_METRIC_V6);
            }
            Some(builder.build())
        }
        _ => None,
    }
}

fn route_address_to_ip(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(addr) => Some(IpAddr::V4(*addr)),
        RouteAddress::Inet6(addr) => Some(IpAddr::V6(*addr)),
        _ => None,
    }
}

/// A route key + the gateway it should have (or currently has).
type RouteChange<K> = (K, IpAddr);

/// Pure diff, no `rtnetlink` types in its signature: which prefixes need a
/// route added, and which need one removed, to bring `observed` in line
/// with `desired`. A prefix present in both with a *different* gateway is
/// reported in both lists (remove the stale one, add the correct one).
fn diff_routes<K: Copy + Eq + std::hash::Hash>(
    observed: &HashMap<K, IpAddr>,
    desired: &HashMap<K, IpAddr>,
) -> (Vec<RouteChange<K>>, Vec<RouteChange<K>>) {
    let mut to_add = Vec::new();
    let mut to_remove = Vec::new();

    for (prefix, gateway) in desired {
        if observed.get(prefix) != Some(gateway) {
            to_add.push((*prefix, *gateway));
        }
    }
    for (prefix, gateway) in observed {
        if desired.get(prefix) != Some(gateway) {
            to_remove.push((*prefix, *gateway));
        }
    }

    (to_add, to_remove)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn identical_state_has_nothing_to_do() {
        let mut m = HashMap::new();
        m.insert(net("10.0.0.0/24"), addr("10.0.0.1"));
        let (add, remove) = diff_routes(&m, &m);
        assert!(add.is_empty());
        assert!(remove.is_empty());
    }

    #[test]
    fn missing_route_is_added() {
        let observed = HashMap::new();
        let mut desired = HashMap::new();
        desired.insert(net("10.0.0.0/24"), addr("10.0.0.1"));

        let (add, remove) = diff_routes(&observed, &desired);
        assert_eq!(add, vec![(net("10.0.0.0/24"), addr("10.0.0.1"))]);
        assert!(remove.is_empty());
    }

    #[test]
    fn stale_route_is_removed() {
        let mut observed = HashMap::new();
        observed.insert(net("10.0.0.0/24"), addr("10.0.0.1"));
        let desired = HashMap::new();

        let (add, remove) = diff_routes(&observed, &desired);
        assert!(add.is_empty());
        assert_eq!(remove, vec![(net("10.0.0.0/24"), addr("10.0.0.1"))]);
    }

    #[test]
    fn backup_slot_is_independent_of_primary() {
        let p = net("10.0.0.0/24");
        let observed = HashMap::from([((p, false), addr("10.0.0.1"))]);
        let desired = HashMap::from([
            ((p, false), addr("10.0.0.1")),
            ((p, true), addr("10.0.0.2")),
        ]);
        let (add, remove) = diff_routes(&observed, &desired);
        assert_eq!(add, vec![((p, true), addr("10.0.0.2"))]);
        assert!(remove.is_empty());

        // Backup vanishing removes only the backup.
        let (add, remove) = diff_routes(&desired, &observed);
        assert!(add.is_empty());
        assert_eq!(remove, vec![((p, true), addr("10.0.0.2"))]);
    }

    #[test]
    fn slots_lists_backup_after_primary() {
        let p = net("10.0.0.0/24");
        let entry = RibEntry {
            prefix: p,
            gateway: addr("10.0.0.1"),
            source: RouteSource::Ospf,
            interface_id: None,
            backup: Some(addr("10.0.0.2")),
            backup_interface_id: None,
        };
        assert_eq!(
            slots(p, &entry),
            vec![
                ((p, false), (addr("10.0.0.1"), None)),
                ((p, true), (addr("10.0.0.2"), None)),
            ]
        );
    }

    #[test]
    fn changed_gateway_is_removed_and_readded() {
        let mut observed = HashMap::new();
        observed.insert(net("10.0.0.0/24"), addr("10.0.0.1"));
        let mut desired = HashMap::new();
        desired.insert(net("10.0.0.0/24"), addr("10.0.0.2"));

        let (add, remove) = diff_routes(&observed, &desired);
        assert_eq!(add, vec![(net("10.0.0.0/24"), addr("10.0.0.2"))]);
        assert_eq!(remove, vec![(net("10.0.0.0/24"), addr("10.0.0.1"))]);
    }
}
