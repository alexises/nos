use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use async_trait::async_trait;
use futures::TryStreamExt as _;
use nos_proto::IpNet;
use rtnetlink::packet_route::link::LinkMessage;
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::{Handle, LinkUnspec, LinkVrf, RouteMessageBuilder};
use tracing::{debug, info, trace, warn};

use super::{table_registry, DriverError, RibDriver};
use crate::rib::RibEntry;

/// errno(3) `ENODEV` — the kernel's reply to a targeted `RTM_GETLINK`
/// lookup (`match_name`/`match_index`) for a link that doesn't exist.
const ENODEV: i32 = 19;

/// Real Linux backend: creates a VRF device + kernel routing table per
/// routing table name (via `table_registry`'s persisted id allocation) and
/// installs the winning route per prefix into it.
pub struct LinuxRibDriver {
    handle: Handle,
    registry_path: PathBuf,
}

impl LinuxRibDriver {
    pub fn new(registry_path: PathBuf) -> Result<Self, DriverError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            registry_path,
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
    ) -> Result<Vec<(IpNet, IpAddr, RouteMessage)>, DriverError> {
        let mut out = Vec::new();
        let table_id_u8 =
            u8::try_from(table_id).expect("table ids are always <= MAX_TABLE_ID (252)");

        let v4_filter = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(table_id)
            .build();
        let mut v4 = self.handle.route().get(v4_filter).execute();
        while let Some(route) = v4.try_next().await? {
            if route.header.table == table_id_u8 {
                if let Some((prefix, gateway)) = extract_route(&route) {
                    out.push((prefix, gateway, route));
                }
            }
        }

        let v6_filter = RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(table_id)
            .build();
        let mut v6 = self.handle.route().get(v6_filter).execute();
        while let Some(route) = v6.try_next().await? {
            if route.header.table == table_id_u8 {
                if let Some((prefix, gateway)) = extract_route(&route) {
                    out.push((prefix, gateway, route));
                }
            }
        }

        Ok(out)
    }

    async fn add_route(
        &self,
        table_id: u32,
        prefix: IpNet,
        gateway: IpAddr,
    ) -> Result<(), DriverError> {
        match (prefix, gateway) {
            (IpNet::V4(prefix), IpAddr::V4(gateway)) => {
                let route = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(prefix.addr(), prefix.prefix_len())
                    .gateway(gateway)
                    .table_id(table_id)
                    .build();
                self.handle
                    .route()
                    .add(route)
                    .execute()
                    .await
                    .inspect_err(|e| {
                        warn!(%prefix, %gateway, table_id, error = %e, "failed to add route");
                    })?;
                info!(%prefix, %gateway, table_id, "added route");
            }
            (IpNet::V6(prefix), IpAddr::V6(gateway)) => {
                let route = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(prefix.addr(), prefix.prefix_len())
                    .gateway(gateway)
                    .table_id(table_id)
                    .build();
                self.handle
                    .route()
                    .add(route)
                    .execute()
                    .await
                    .inspect_err(|e| {
                        warn!(%prefix, %gateway, table_id, error = %e, "failed to add route");
                    })?;
                info!(%prefix, %gateway, table_id, "added route");
            }
            _ => {
                warn!(%prefix, %gateway, table_id, "route prefix/gateway address family mismatch, skipping");
            }
        }
        Ok(())
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
        let observed_map: HashMap<IpNet, IpAddr> = observed
            .iter()
            .map(|(prefix, gateway, _)| (*prefix, *gateway))
            .collect();
        let desired: HashMap<IpNet, IpAddr> = best_routes
            .iter()
            .map(|(prefix, entry)| (*prefix, entry.gateway))
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
        // must be gone first.
        for (prefix, gateway) in to_remove {
            if let Some((_, _, message)) = observed.iter().find(|(p, _, _)| *p == prefix) {
                self.handle
                    .route()
                    .del(message.clone())
                    .execute()
                    .await
                    .inspect_err(|e| {
                        warn!(%prefix, %gateway, table_id, error = %e, "failed to remove route");
                    })?;
                info!(%prefix, %gateway, table_id, "removed route");
            }
        }
        for (prefix, gateway) in to_add {
            self.add_route(table_id, prefix, gateway).await?;
        }
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

/// Extracts `(prefix, gateway)` from a dumped `RouteMessage`, or `None` for
/// a route we don't manage (no gateway — e.g. a kernel-internal entry a VRF
/// device creates on its own, or an unsupported address family like MPLS).
/// A missing `Destination` attribute means the default route (kernel omits
/// it for 0/0), so it falls back to the family's unspecified address.
fn extract_route(route: &RouteMessage) -> Option<(IpNet, IpAddr)> {
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

    IpNet::new(destination, route.header.destination_prefix_length)
        .ok()
        .map(|prefix| (prefix, gateway))
}

fn route_address_to_ip(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(addr) => Some(IpAddr::V4(*addr)),
        RouteAddress::Inet6(addr) => Some(IpAddr::V6(*addr)),
        _ => None,
    }
}

/// A prefix + the gateway it should have (or currently has).
type RouteChange = (IpNet, IpAddr);

/// Pure diff, no `rtnetlink` types in its signature: which prefixes need a
/// route added, and which need one removed, to bring `observed` in line
/// with `desired`. A prefix present in both with a *different* gateway is
/// reported in both lists (remove the stale one, add the correct one).
fn diff_routes(
    observed: &HashMap<IpNet, IpAddr>,
    desired: &HashMap<IpNet, IpAddr>,
) -> (Vec<RouteChange>, Vec<RouteChange>) {
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
