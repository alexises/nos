//! Exports this table's best routes as VPN routes into its
//! `vpn.bgp_instance` (the underlay `nos-bgpd`) over one long-lived
//! `BgpRequest::RedistributeVpnPrefixes` connection; `push_client`'s loop,
//! like `evpn_client`.

use std::path::PathBuf;

use nos_proto::{BgpRequest, IpNet, VpnPrefix, VpnPrefixUpdate};
use tokio::sync::watch;

use crate::push_client::{self, Feed, Target};

/// The VPN routes to export and where (`crate::vpn::originated`);
/// `bgp_instance: None` when the table has no `vpn` (or no label yet).
pub type VpnTarget = Target<VpnPrefix>;

pub struct Vpn;

impl Feed for Vpn {
    type Route = VpnPrefix;
    type Key = ([u8; 8], IpNet);
    type Update = VpnPrefixUpdate;
    const WHAT: &'static str = "vpn";
    fn key(r: &VpnPrefix) -> Self::Key {
        (r.rd, r.prefix)
    }
    fn full(routes: Vec<VpnPrefix>) -> VpnPrefixUpdate {
        VpnPrefixUpdate::Full(routes)
    }
    fn add(r: VpnPrefix) -> VpnPrefixUpdate {
        VpnPrefixUpdate::Add(r)
    }
    fn remove((rd, prefix): Self::Key) -> VpnPrefixUpdate {
        VpnPrefixUpdate::Remove(rd, prefix)
    }
    fn request(table: String, update: VpnPrefixUpdate) -> BgpRequest {
        BgpRequest::RedistributeVpnPrefixes { table, update }
    }
}

pub fn spawn(
    watchdog_socket: PathBuf,
    table: String,
    shutdown: watch::Receiver<bool>,
) -> watch::Sender<VpnTarget> {
    push_client::spawn::<Vpn>(watchdog_socket, table, shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push_client::diff;

    fn route(prefix: &str, label: u32) -> VpnPrefix {
        VpnPrefix {
            rd: [0, 0, 0, 0, 0, 0, 0, 1],
            prefix: prefix.parse().unwrap(),
            labels: vec![label],
            ext_communities: vec![1],
        }
    }

    #[test]
    fn a_label_change_is_an_add_and_a_lost_route_a_remove() {
        let last: std::collections::HashMap<_, _> =
            [route("10.1.0.0/24", 1000), route("10.2.0.0/24", 1000)]
                .into_iter()
                .map(|r| (Vpn::key(&r), r))
                .collect();
        let got = diff::<Vpn, _>(&last, &[route("10.1.0.0/24", 1001)]);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&VpnPrefixUpdate::Add(route("10.1.0.0/24", 1001))));
        assert!(got.contains(&VpnPrefixUpdate::Remove(
            [0, 0, 0, 0, 0, 0, 0, 1],
            "10.2.0.0/24".parse().unwrap()
        )));
        assert!(matches!(
            Vpn::request("red".into(), Vpn::full(vec![])),
            BgpRequest::RedistributeVpnPrefixes { table, update: VpnPrefixUpdate::Full(v) }
                if table == "red" && v.is_empty()
        ));
    }
}
