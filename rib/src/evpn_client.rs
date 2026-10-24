//! Originates this table's best routes as EVPN Type-5 routes into its
//! `evpn.bgp_instance` (the underlay `nos-bgpd`) over one long-lived
//! `BgpRequest::RedistributeEvpnPrefixes` connection — independent of
//! `bgp_client.rs` (the two may name different instances). The connection
//! loop is `push_client`'s, shared with `vpn_client`.

use std::path::PathBuf;

use nos_proto::{BgpRequest, EvpnKey, EvpnRoute, EvpnUpdate};
use tokio::sync::watch;

use crate::push_client::{self, Feed, Target};

/// The Type-5 routes to originate and where (`crate::evpn::originated`);
/// `bgp_instance: None` when the table has no `evpn` (or no Router's MAC yet).
pub type EvpnTarget = Target<EvpnRoute>;

pub struct Evpn;

impl Feed for Evpn {
    type Route = EvpnRoute;
    type Key = EvpnKey;
    type Update = EvpnUpdate;
    const WHAT: &'static str = "evpn type-5";
    fn key(r: &EvpnRoute) -> EvpnKey {
        r.key.clone()
    }
    fn full(routes: Vec<EvpnRoute>) -> EvpnUpdate {
        EvpnUpdate::Full(routes)
    }
    fn add(r: EvpnRoute) -> EvpnUpdate {
        EvpnUpdate::Add(r)
    }
    fn remove(k: EvpnKey) -> EvpnUpdate {
        EvpnUpdate::Remove(k)
    }
    fn request(table: String, update: EvpnUpdate) -> BgpRequest {
        BgpRequest::RedistributeEvpnPrefixes { table, update }
    }
}

pub fn spawn(
    watchdog_socket: PathBuf,
    table: String,
    shutdown: watch::Receiver<bool>,
) -> watch::Sender<EvpnTarget> {
    push_client::spawn::<Evpn>(watchdog_socket, table, shutdown)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::push_client::diff;

    fn route(prefix: &str, vni: u32) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::IpPrefix {
                rd: [0; 8],
                prefix: prefix.parse().unwrap(),
            },
            vni,
            next_hop: "10.50.0.2".parse().unwrap(),
            ext_communities: vec![],
            esi: [0; 10],
            l3_vni: None,
        }
    }

    fn keyed(routes: &[EvpnRoute]) -> HashMap<EvpnKey, EvpnRoute> {
        routes.iter().map(|r| (r.key.clone(), r.clone())).collect()
    }

    #[test]
    fn diff_adds_changed_and_new_and_removes_gone() {
        let last = keyed(&[route("10.1.0.0/24", 1), route("10.2.0.0/24", 1)]);
        let mut got = diff::<Evpn, _>(&last, &[route("10.1.0.0/24", 2), route("10.3.0.0/24", 1)]);
        got.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(
            got,
            vec![
                EvpnUpdate::Add(route("10.1.0.0/24", 2)),
                EvpnUpdate::Add(route("10.3.0.0/24", 1)),
                EvpnUpdate::Remove(route("10.2.0.0/24", 0).key),
            ]
        );
        assert_eq!(
            diff::<Evpn, _>(&last, &[route("10.1.0.0/24", 1), route("10.2.0.0/24", 1)]),
            [] as [EvpnUpdate; 0]
        );
        assert!(matches!(
            Evpn::request("t".into(), Evpn::full(vec![])),
            BgpRequest::RedistributeEvpnPrefixes { .. }
        ));
    }
}
