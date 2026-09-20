//! Every phase, by its command-line name, and the CI groups that chain them.

mod bgp;
mod drivers;
mod ospf;

use anyhow::bail;

use crate::router::log;
use crate::world::World;

/// Runs one phase (or `up`) by name.
pub async fn run(name: &str, w: &mut World) -> anyhow::Result<()> {
    log(format!("=== {name} ==="));
    match name {
        "up" => w.up(&[]).await,
        "established" => bgp::established(w).await,
        "reconnect" => bgp::reconnect(w).await,
        "collision" => bgp::collision(w).await,
        "redistribute" => bgp::redistribute_phase(w).await,
        "auth" => bgp::auth(w).await,
        "policy" => bgp::policy(w).await,
        "redistribute-policy" => bgp::redistribute_policy(w).await,
        "communities" => bgp::communities(w).await,
        "reflector" => bgp::reflector(w).await,
        "route-server" => bgp::route_server(w).await,
        "loopback" => drivers::loopback(w).await,
        "mtu" => drivers::mtu(w).await,
        "port-aggregate" => drivers::port_aggregate(w).await,
        "lacp" => drivers::lacp(w).await,
        "lldp" => drivers::lldp(w).await,
        "switching" => drivers::switching(w).await,
        "svi" => drivers::svi(w).await,
        "routed-subinterface" => drivers::routed_subinterface(w).await,
        "source-address" => drivers::source_address(w).await,
        "rest" => drivers::rest(w).await,
        "ospf" => ospf::ospf_phase(w).await,
        "asbr" => ospf::asbr_phase(w).await,
        "ospf-dr" => ospf::ospf_dr(w).await,
        "ospf-spf" => ospf::ospf_spf(w).await,
        "abr" => ospf::abr(w).await,
        "ospf-aging" => ospf::ospf_aging(w).await,
        "ospf-auth" => ospf::ospf_auth(w).await,
        "ospf-dbd-pagination" => ospf::ospf_dbd_pagination(w).await,
        "ospf-mtu-pagination" => ospf::ospf_mtu_pagination(w).await,
        "ospfv3" => ospf::ospfv3_phase(w).await,
        "ospfv3-dr" => ospf::ospfv3_dr(w).await,
        other => bail!("unknown phase '{other}'"),
    }
}

/// The self-contained CI groups: each starts its own routers and tears them
/// down on exit (unless `VERIFY_E2E_KEEP=1`).
pub fn group(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "base" => &[
            "up",
            "established",
            "reconnect",
            "collision",
            "redistribute",
            "auth",
        ],
        "drivers" => &[
            "up",
            "established",
            "loopback",
            "mtu",
            "port-aggregate",
            "lacp",
            "lldp",
            "switching",
            "svi",
            "routed-subinterface",
            "source-address",
            "rest",
        ],
        "rpl" => &[
            "up",
            "established",
            "redistribute",
            "policy",
            "redistribute-policy",
            "communities",
        ],
        "ospf-suite" => &[
            "up",
            "established",
            "ospf",
            "asbr",
            "ospf-dr",
            "ospf-spf",
            "abr",
            "ospf-auth",
            "ospf-aging",
            "ospf-dbd-pagination",
            "ospf-mtu-pagination",
            "ospfv3",
            "ospfv3-dr",
        ],
        "multi" => &["reflector", "route-server"],
        _ => return None,
    })
}

/// `all`: every phase in sequence, leaving the containers up for inspection.
pub const ALL: &[&str] = &[
    "up",
    "established",
    "reconnect",
    "collision",
    "redistribute",
    "auth",
    "loopback",
    "mtu",
    "port-aggregate",
    "lacp",
    "lldp",
    "switching",
    "svi",
    "routed-subinterface",
    "source-address",
    "rest",
    "policy",
    "redistribute-policy",
    "communities",
    "reflector",
    "route-server",
    "ospf",
    "asbr",
    "ospf-dr",
    "ospf-spf",
    "abr",
    "ospf-auth",
    "ospf-aging",
    "ospf-dbd-pagination",
    "ospf-mtu-pagination",
    "ospfv3",
    "ospfv3-dr",
];
