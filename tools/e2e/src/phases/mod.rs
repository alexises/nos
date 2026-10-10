//! Every phase, by its command-line name, and the CI groups that chain them.

mod bfd;
mod bfd_auth;
mod bfd_echo;
mod bgp;
mod drivers;
mod ospf;
mod pki;

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
        "bgp-graceful-restart" => bgp::bgp_graceful_restart(w).await,
        "bgp-gr-frr" => bgp::bgp_gr_frr(w).await,
        "bfd" => bfd::bfd(w).await,
        "bgp-bfd" => bfd::bgp_bfd(w).await,
        "bfd-auth" => bfd_auth::bfd_auth(w).await,
        "bfd-padded" => bfd::bfd_padded(w).await,
        "bfd-sbfd" => bfd::bfd_sbfd(w).await,
        "bfd-echo" => bfd_echo::bfd_echo(w).await,
        "bfd-echo-unaffiliated" => bfd_echo::bfd_echo_unaffiliated(w).await,
        "bfd-unsolicited" => bfd::bfd_unsolicited(w).await,
        "auth" => bgp::auth(w).await,
        "ao" => bgp::ao(w).await,
        "gtsm" => bgp::gtsm(w).await,
        "policy" => bgp::policy(w).await,
        "redistribute-policy" => bgp::redistribute_policy(w).await,
        "communities" => bgp::communities(w).await,
        "mrai" => bgp::mrai(w).await,
        "damping" => bgp::damping(w).await,
        "aggregate" => bgp::aggregate(w).await,
        "shutdown" => bgp::shutdown(w).await,
        "reflector" => bgp::reflector(w).await,
        "route-server" => bgp::route_server(w).await,
        "bgp-multipath" => bgp::bgp_multipath(w).await,
        "as4" => bgp::as4(w).await,
        "malformed-update" => bgp::malformed_update(w).await,
        "maximum-prefix" => bgp::maximum_prefix(w).await,
        "add-path" => bgp::add_path(w).await,
        "route-refresh-stale" => bgp::route_refresh_stale(w).await,
        "confederation" => bgp::confederation(w).await,
        "local-as" => bgp::local_as(w).await,
        "bgp-role" => bgp::bgp_role(w).await,
        "rpki" => bgp::rpki(w).await,
        "evpn" => bgp::evpn(w).await,
        "evpn-fdb" => bgp::evpn_fdb(w).await,
        "evpn-esi" => bgp::evpn_esi(w).await,
        "evpn-dataplane" => bgp::evpn_dataplane(w).await,
        "evpn-single-active" => bgp::evpn_single_active(w).await,
        "evpn-v6" => bgp::evpn_v6(w).await,
        "evpn-l3" => bgp::evpn_l3(w).await,
        "loopback" => drivers::loopback(w).await,
        "mtu" => drivers::mtu(w).await,
        "port-aggregate" => drivers::port_aggregate(w).await,
        "lacp" => drivers::lacp(w).await,
        "micro-bfd" => drivers::micro_bfd(w).await,
        "lldp" => drivers::lldp(w).await,
        "switching" => drivers::switching(w).await,
        "stp-failsafe" => drivers::stp_failsafe(w).await,
        "stp-legacy" => drivers::stp_legacy(w).await,
        "stp-protections" => drivers::stp_protections(w).await,
        "stp-mstp" => drivers::stp_mstp(w).await,
        "stp-pvst" => drivers::stp_pvst(w).await,
        "stp" => drivers::stp(w).await,
        "svi" => drivers::svi(w).await,
        "routed-subinterface" => drivers::routed_subinterface(w).await,
        "source-address" => drivers::source_address(w).await,
        "rest" => drivers::rest(w).await,
        "syslog" => drivers::syslog(w).await,
        "ospf" => ospf::ospf_phase(w).await,
        "ospf-p2mp" => ospf::ospf_p2mp(w).await,
        "asbr" => ospf::asbr_phase(w).await,
        "ospf-dr" => ospf::ospf_dr(w).await,
        "ospf-spf" => ospf::ospf_spf(w).await,
        "next-hop-reachability" => bgp::next_hop_reachability(w).await,
        "ospf-lfa" => ospf::ospf_lfa(w).await,
        "ospf-stub-router" => ospf::ospf_stub_router(w).await,
        "ospf-host-router" => ospf::ospf_host_router(w).await,
        "ospf-prefix-suppression" => ospf::ospf_prefix_suppression(w).await,
        "abr" => ospf::abr(w).await,
        "ospf-aging" => ospf::ospf_aging(w).await,
        "ospf-auth" => ospf::ospf_auth(w).await,
        "ospf-mtu-mismatch" => ospf::ospf_mtu_mismatch(w).await,
        "ospf-bfd" => ospf::ospf_bfd(w).await,
        "ospf-graceful-restart" => ospf::ospf_graceful_restart(w).await,
        "ospf-dbd-pagination" => ospf::ospf_dbd_pagination(w).await,
        "ospf-mtu-pagination" => ospf::ospf_mtu_pagination(w).await,
        "ospf-stub" => ospf::ospf_stub(w).await,
        "ospf-nssa" => ospf::ospf_nssa(w).await,
        "ospf-external-flood" => ospf::ospf_external_flood(w).await,
        "ospf-virtual-link" => ospf::ospf_virtual_link(w).await,
        "ospf-opaque" => ospf::ospf_opaque(w).await,
        "ospfv3" => ospf::ospfv3_phase(w).await,
        "ospfv3-asbr" => ospf::ospfv3_asbr(w).await,
        "ospfv3-abr" => ospf::ospfv3_abr(w).await,
        "ospfv3-graceful-restart" => ospf::ospfv3_graceful_restart(w).await,
        "ospfv3-auth" => ospf::ospfv3_auth(w).await,
        "ospfv3-mtu-mismatch" => ospf::ospfv3_mtu_mismatch(w).await,
        "ospfv3-instance-id" => ospf::ospfv3_instance_id(w).await,
        "ospfv3-bfd" => ospf::ospfv3_bfd(w).await,
        "ospfv3-dr" => ospf::ospfv3_dr(w).await,
        "ospfv3-lfa" => ospf::ospfv3_lfa(w).await,
        "ospfv3-flush" => ospf::ospfv3_flush(w).await,
        "ospfv3-mtu-pagination" => ospf::ospfv3_mtu_pagination(w).await,
        "ospf-remote-lfa" => ospf::ospf_remote_lfa(w).await,
        "pki" => pki::pki(w).await,
        "pki-rotation" => pki::pki_rotation(w).await,
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
            "shutdown",
            "redistribute",
            "bgp-graceful-restart",
            "auth",
            "ao",
            "gtsm",
        ],
        "drivers" => &[
            "up",
            "established",
            "loopback",
            "mtu",
            "port-aggregate",
            "lacp",
            "micro-bfd",
            "lldp",
            "switching",
            "stp-failsafe",
            "stp",
            "stp-legacy",
            "stp-protections",
            "stp-mstp",
            "stp-pvst",
            "svi",
            "routed-subinterface",
            "source-address",
            "rest",
            "syslog",
        ],
        "rpl" => &[
            "up",
            "established",
            "redistribute",
            "policy",
            "redistribute-policy",
            "communities",
            "mrai",
            "damping",
            "aggregate",
        ],
        "ospf-suite" => &[
            "up",
            "established",
            "ospf",
            "ospf-p2mp",
            "asbr",
            "ospf-dr",
            "ospf-spf",
            "next-hop-reachability",
            "ospf-lfa",
            "ospf-stub-router",
            "ospf-host-router",
            "ospf-prefix-suppression",
            "abr",
            "ospf-auth",
            "ospf-mtu-mismatch",
            "ospf-bfd",
            "ospf-graceful-restart",
            "ospf-aging",
            "ospf-dbd-pagination",
            "ospf-mtu-pagination",
            "ospf-stub",
            "ospf-nssa",
            "ospf-external-flood",
            "ospf-virtual-link",
            "ospf-opaque",
            "ospfv3",
            "ospfv3-asbr",
            "ospfv3-abr",
            "ospfv3-graceful-restart",
            "ospfv3-auth",
            "ospfv3-mtu-mismatch",
            "ospfv3-instance-id",
            "ospfv3-bfd",
            "ospfv3-dr",
            "ospfv3-lfa",
            "ospfv3-flush",
            "ospfv3-mtu-pagination",
            "ospf-remote-lfa",
        ],
        "multi" => &[
            "as4",
            "malformed-update",
            "maximum-prefix",
            "add-path",
            "route-refresh-stale",
            "confederation",
            "local-as",
            "bgp-role",
            "rpki",
            "evpn",
            "evpn-fdb",
            "evpn-esi",
            "evpn-dataplane",
            "evpn-single-active",
            "evpn-v6",
            "evpn-l3",
            "reflector",
            "route-server",
            "bgp-multipath",
            "bgp-gr-frr",
            "bfd",
            "bgp-bfd",
            "bfd-auth",
            "bfd-padded",
            "bfd-sbfd",
            "bfd-echo",
            "bfd-echo-unaffiliated",
            "bfd-unsolicited",
        ],
        // Self-contained like `ospf-aging`: it needs its own short-lived
        // certificates, so it restarts the routers with them.
        "pki-suite" => &["up", "established", "pki", "pki-rotation"],
        _ => return None,
    })
}

/// `all`: every phase in sequence, leaving the containers up for inspection.
pub const ALL: &[&str] = &[
    "up",
    "established",
    "reconnect",
    "collision",
    "shutdown",
    "redistribute",
    "bgp-graceful-restart",
    "auth",
    "ao",
    "gtsm",
    "loopback",
    "mtu",
    "port-aggregate",
    "lacp",
    "micro-bfd",
    "lldp",
    "switching",
    "stp-failsafe",
    "stp",
    "stp-legacy",
    "stp-protections",
    "stp-mstp",
    "stp-pvst",
    "svi",
    "routed-subinterface",
    "source-address",
    "rest",
    "syslog",
    "policy",
    "redistribute-policy",
    "communities",
    "mrai",
    "damping",
    "aggregate",
    "evpn",
    "evpn-fdb",
    "evpn-esi",
    "evpn-dataplane",
    "evpn-single-active",
    "evpn-v6",
    "evpn-l3",
    "reflector",
    "route-server",
    "bgp-multipath",
    "bgp-gr-frr",
    "bfd",
    "bgp-bfd",
    "bfd-auth",
    "bfd-padded",
    "bfd-sbfd",
    "bfd-echo",
    "bfd-echo-unaffiliated",
    "bfd-unsolicited",
    "as4",
    "malformed-update",
    "maximum-prefix",
    "add-path",
    "route-refresh-stale",
    "confederation",
    "local-as",
    "bgp-role",
    "rpki",
    "ospf",
    "ospf-p2mp",
    "asbr",
    "ospf-dr",
    "ospf-spf",
    "next-hop-reachability",
    "ospf-lfa",
    "ospf-stub-router",
    "ospf-host-router",
    "ospf-prefix-suppression",
    "abr",
    "ospf-auth",
    "ospf-mtu-mismatch",
    "ospf-bfd",
    "ospf-graceful-restart",
    "ospf-aging",
    "ospf-dbd-pagination",
    "ospf-mtu-pagination",
    "ospf-stub",
    "ospf-nssa",
    "ospf-external-flood",
    "ospf-virtual-link",
    "ospf-opaque",
    "ospfv3",
    "ospfv3-asbr",
    "ospfv3-abr",
    "ospfv3-graceful-restart",
    "ospfv3-auth",
    "ospfv3-mtu-mismatch",
    "ospfv3-instance-id",
    "ospfv3-bfd",
    "ospfv3-dr",
    "ospfv3-lfa",
    "ospfv3-flush",
    "ospfv3-mtu-pagination",
    "ospf-remote-lfa",
    "pki",
    "pki-rotation",
];

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = include_str!("../../../../docs/e2e-phases.md");

    /// Add new groups here. (`run`'s match is not introspectable, so a name in
    /// `ALL` that `run` does not dispatch only fails when run: "unknown phase".)
    const GROUPS: [&str; 6] = ["base", "drivers", "rpl", "ospf-suite", "multi", "pki-suite"];

    struct Row {
        phase: String,
        groups: Vec<String>,
        requires: Vec<String>,
    }

    /// The table rows of `docs/e2e-phases.md`: lines starting with ``| ` ``.
    fn rows() -> Vec<Row> {
        let list = |cell: &str| -> Vec<String> {
            cell.split(',')
                .map(|s| s.trim().trim_matches('`').to_owned())
                .filter(|s| !s.is_empty() && s != "-" && s != "self-contained")
                .collect()
        };
        DOC.lines()
            .filter(|l| l.starts_with("| `"))
            .map(|l| {
                let cells: Vec<&str> = l.trim_matches('|').split('|').map(str::trim).collect();
                assert_eq!(cells.len(), 5, "row needs 5 cells: {l}");
                Row {
                    phase: cells[0].trim_matches('`').to_owned(),
                    groups: list(cells[2]),
                    requires: list(cells[3]),
                }
            })
            .collect()
    }

    #[test]
    fn doc_table_matches_registry() {
        let rows = rows();
        let names: Vec<&str> = rows.iter().map(|r| r.phase.as_str()).collect();
        for p in ALL {
            assert!(names.contains(p), "docs/e2e-phases.md has no row for `{p}`");
        }
        for n in &names {
            assert!(
                ALL.contains(n),
                "docs/e2e-phases.md row `{n}` is not in phases::ALL"
            );
        }
        assert_eq!(
            names, ALL,
            "table order must equal phases::ALL order (or a row is duplicated)"
        );

        for g in GROUPS {
            let members = group(g).unwrap_or_else(|| panic!("group `{g}` missing"));
            for m in members {
                assert!(ALL.contains(m), "group `{g}` member `{m}` is not in ALL");
            }
        }
        for (i, r) in rows.iter().enumerate() {
            let mut want: Vec<&str> = GROUPS
                .into_iter()
                .filter(|g| group(g).is_some_and(|m| m.contains(&r.phase.as_str())))
                .collect();
            let mut have: Vec<&str> = r.groups.iter().map(String::as_str).collect();
            want.sort_unstable();
            have.sort_unstable();
            assert_eq!(have, want, "Groups cell of `{}`", r.phase);
            for q in &r.requires {
                let at = ALL.iter().position(|p| p == q);
                assert!(
                    at.is_some_and(|at| at < i),
                    "`{}` requires `{q}`, which must be in ALL before it",
                    r.phase
                );
            }
        }
    }
}
