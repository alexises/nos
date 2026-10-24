//! The VRFs one underlay instance imports VPN routes into (RFC 4364 section
//! 4.3.2) and the family-agnostic Route Target matching over them: a route
//! is imported into every VRF whose import set shares one of its Route
//! Targets; no RT, no import. Nothing here names an IP prefix, so VPN
//! Flowspec (#574) reuses `import_by_table` with `VpnKey<FlowSpec>`.

use std::collections::HashMap;

use nos_proto::evpn_id::{parse_rd, parse_rt, parse_soo};
use nos_proto::Config;

use super::{has_soo, route_targets, Rd, VpnKey};

/// One VRF: a routing table whose `vpn.bgp_instance` is this instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vrf {
    pub table: String,
    pub rd: Rd,
    /// Import Route Targets as extended communities.
    pub import: Vec<u64>,
    /// Export Route Targets (#580).
    pub export: Vec<u64>,
    /// The table's Site of Origin (RFC 4364 section 7): a route carrying it
    /// came from this VRF's own CE site and is not imported back.
    pub soo: Option<u64>,
}

/// Every VRF of one instance, in config order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VrfSet(pub Vec<Vrf>);

impl VrfSet {
    /// The tables whose `vpn` rides `instance` and has a valid RD (commit
    /// validation guarantees it; a malformed RT is skipped).
    #[must_use]
    pub fn from_config(cfg: &Config, instance: &str) -> Self {
        let rts = |v: &[String]| v.iter().filter_map(|r| parse_rt(r)).collect();
        Self(
            cfg.routing_tables
                .iter()
                .filter(|t| t.vpn.bgp_instance.as_deref() == Some(instance))
                .filter_map(|t| {
                    Some(Vrf {
                        table: t.name.clone(),
                        rd: parse_rd(t.vpn.rd.as_deref()?)?,
                        import: rts(&t.vpn.route_targets_import),
                        export: rts(&t.vpn.route_targets_export),
                        soo: t.vpn.site_of_origin.as_deref().and_then(parse_soo),
                    })
                })
                .collect(),
        )
    }

    /// Every VRF's table name.
    pub fn tables(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|v| v.table.as_str())
    }

    /// The tables a route carrying `ext_communities` is imported into: those
    /// whose import set holds one of its Route Targets, unless it carries
    /// the table's own Site of Origin (other extended communities are
    /// ignored; another table's Site of Origin does not block).
    #[must_use]
    pub fn import_targets(&self, ext_communities: &[u64]) -> Vec<&str> {
        self.matching(ext_communities)
            .filter(|v| !v.soo.is_some_and(|s| has_soo(ext_communities, s)))
            .map(|v| v.table.as_str())
            .collect()
    }

    /// The (table, Site of Origin) pairs whose import would take a route
    /// carrying `ext_communities` but for that table's own Site of Origin on it.
    #[must_use]
    pub fn soo_blocked(&self, ext_communities: &[u64]) -> Vec<(&str, u64)> {
        self.matching(ext_communities)
            .filter_map(|v| {
                Some((
                    v.table.as_str(),
                    v.soo.filter(|s| has_soo(ext_communities, *s))?,
                ))
            })
            .collect()
    }

    fn matching<'a>(&'a self, ext_communities: &[u64]) -> impl Iterator<Item = &'a Vrf> {
        let rts = route_targets(ext_communities);
        self.0
            .iter()
            .filter(move |v| v.import.iter().any(|i| rts.contains(i)))
    }

    /// Groups `routes` (key, extended communities, payload) by the tables
    /// each is imported into; a route lands in every matching table.
    pub fn import_by_table<'a, T: 'a, R: 'a>(
        &self,
        routes: impl IntoIterator<Item = (&'a VpnKey<T>, &'a [u64], &'a R)>,
    ) -> HashMap<&str, Vec<(&'a VpnKey<T>, &'a R)>> {
        let mut out: HashMap<&str, Vec<_>> = HashMap::new();
        for (key, ext, route) in routes {
            for table in self.import_targets(ext) {
                out.entry(table).or_default().push((key, route));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::rt;
    use nos_proto::{RoutingTable, RoutingTableVpn};

    fn table(name: &str, instance: &str, import: &[&str]) -> RoutingTable {
        RoutingTable {
            name: name.to_string(),
            vpn: RoutingTableVpn {
                rd: Some(format!("65000:{}", name.len())),
                route_targets_import: import.iter().map(ToString::to_string).collect(),
                route_targets_export: vec!["65000:9".to_string()],
                bgp_instance: Some(instance.to_string()),
                label: None,
                site_of_origin: None,
            },
            ..RoutingTable::default()
        }
    }

    fn set() -> VrfSet {
        let cfg = Config {
            routing_tables: vec![
                table("red", "core", &["65000:1"]),
                table("blue", "core", &["65000:2", "65000:1"]),
                table("other", "elsewhere", &["65000:1"]),
                RoutingTable {
                    name: "plain".to_string(),
                    ..RoutingTable::default()
                },
            ],
            ..Config::default()
        };
        VrfSet::from_config(&cfg, "core")
    }

    #[test]
    fn only_this_instances_vpn_tables_are_vrfs() {
        let s = set();
        assert_eq!(s.tables().collect::<Vec<_>>(), ["red", "blue"]);
        assert_eq!(s.0[0].rd, parse_rd("65000:3").unwrap());
        assert_eq!(s.0[0].export, vec![rt(0, 65000, 9).unwrap()]);
    }

    #[test]
    fn own_site_of_origin_blocks_the_import_and_a_foreign_one_does_not() {
        let mut s = set();
        let soo = |t: &str| parse_soo(t).unwrap();
        s.0[0].soo = Some(soo("65001:77"));
        let rt1 = rt(0, 65000, 1).unwrap();
        // Own SoO: red skipped, blue (no SoO) still takes it.
        assert_eq!(s.import_targets(&[rt1, soo("65001:77")]), ["blue"]);
        assert_eq!(
            s.soo_blocked(&[rt1, soo("65001:77")]),
            [("red", soo("65001:77"))]
        );
        // Foreign and absent SoO import into both; nothing is blocked.
        for ext in [vec![rt1, soo("65001:99")], vec![rt1]] {
            assert_eq!(s.import_targets(&ext), ["red", "blue"]);
            assert_eq!(s.soo_blocked(&ext), []);
        }
        // No import RT matches: nothing to block either.
        assert_eq!(s.soo_blocked(&[soo("65001:77")]), []);
        // The block is per-table: the SoO, not the RT, decides, so the route
        // returns the moment the table's SoO changes.
        s.0[0].soo = Some(soo("65001:78"));
        assert_eq!(s.import_targets(&[rt1, soo("65001:77")]), ["red", "blue"]);
    }

    #[test]
    fn import_is_any_of_and_needs_a_route_target() {
        let s = set();
        let (rt1, rt2) = (rt(0, 65000, 1).unwrap(), rt(0, 65000, 2).unwrap());
        let soo = 0x0003_fde8_0000_0001_u64; // same value bytes, not an RT
        assert_eq!(s.import_targets(&[soo, rt1]), ["red", "blue"]);
        assert_eq!(s.import_targets(&[rt2]), ["blue"]);
        assert_eq!(s.import_targets(&[soo]), [] as [&str; 0]);
        assert_eq!(s.import_targets(&[]), [] as [&str; 0]);
        assert_eq!(VrfSet::default().import_targets(&[rt1]), [] as [&str; 0]);
    }

    /// Two payload types pin the grouping as family-agnostic (#574).
    #[test]
    fn import_by_table_groups_any_key_and_payload() {
        let s = set();
        let ext = [rt(0, 65000, 1).unwrap()];
        let none: [u64; 0] = [];
        let rd = [0; 8];
        let (k1, k2): (VpnKey<&str>, VpnKey<&str>) = ((rd, "a"), (rd, "b"));
        let got = s.import_by_table([(&k1, &ext[..], &1u8), (&k2, &none[..], &2u8)]);
        assert_eq!(got["red"], vec![(&k1, &1u8)]);
        assert_eq!(got["blue"], vec![(&k1, &1u8)]);
        let k3: VpnKey<u32> = (rd, 7);
        let flow = s.import_by_table([(&k3, &ext[..], &"rule")]);
        assert_eq!(flow["red"], vec![(&k3, &"rule")]);
    }
}
