use std::net::IpAddr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;

/// Which NLRI (AFI/SAFI) is exchanged over a peer-group's session —
/// independent of the IP version of `source_address` or a peer's
/// `remote_address`. RFC 8950's extended next-hop encoding allows an
/// IPv6-transport session to carry IPv4 unicast NLRI, so this must never be
/// derived from, or cross-validated against, either address's IP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFamily {
    Ipv4Unicast,
    Ipv6Unicast,
}

impl AddressFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressFamily::Ipv4Unicast => "ipv4",
            AddressFamily::Ipv6Unicast => "ipv6",
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct BgpPeerGroup {
    #[garde(length(min = 1, max = 64), custom(|n, ctx: &Config| unique_name(n, ctx)))]
    pub name: String,

    // RFC 6793: ASN 0 and 4_294_967_295 are reserved.
    #[garde(range(min = 1, max = 4_294_967_294u32))]
    pub remote_as: u32,

    // Transport source address. Deliberately `#[garde(skip)]` and never
    // cross-validated against `address_families` or a peer's
    // `remote_address` — see `AddressFamily`'s doc comment.
    #[garde(skip)]
    pub source_address: Option<IpAddr>,

    #[garde(custom(|afs, _ctx: &Config| non_empty_no_duplicate_afs(afs)))]
    pub address_families: Vec<AddressFamily>,
}

/// Peer-group names are unique across the whole config, not just within the
/// owning instance — garde's validation context is fixed as `&Config` for
/// the whole dive chain, so this is the simplest correct scoping, and a
/// name collision is a real conflict regardless of which instance either
/// group belongs to.
fn unique_name(name: &str, ctx: &Config) -> garde::Result {
    let count = ctx
        .bgp_instances
        .iter()
        .flat_map(|i| &i.peer_groups)
        .filter(|g| g.name == name)
        .count();
    if count > 1 {
        return Err(garde::Error::new("must be unique"));
    }
    Ok(())
}

fn non_empty_no_duplicate_afs(afs: &[AddressFamily]) -> garde::Result {
    if afs.is_empty() {
        return Err(garde::Error::new(
            "must include at least one address family",
        ));
    }
    let mut seen: Vec<AddressFamily> = Vec::new();
    for af in afs {
        if seen.contains(af) {
            return Err(garde::Error::new("address families must not repeat"));
        }
        seen.push(*af);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::schema::{BgpInstance, Config};

    use super::*;

    fn instance_with_groups(name: &str, groups: Vec<BgpPeerGroup>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers: Vec::new(),
        }
    }

    fn group(name: &str, remote_as: u32, afs: Vec<AddressFamily>) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: afs,
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_group_passes() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn remote_as_zero_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 0, vec![AddressFamily::Ipv4Unicast])],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn remote_as_max_reserved_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group(
                "pg1",
                4_294_967_295,
                vec![AddressFamily::Ipv4Unicast],
            )],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn empty_address_families_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 65001, vec![])],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_address_family_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group(
                "pg1",
                65001,
                vec![AddressFamily::Ipv4Unicast, AddressFamily::Ipv4Unicast],
            )],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_fails_across_different_instances() {
        let cfg = config_with(vec![
            instance_with_groups(
                "r1",
                vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
            ),
            instance_with_groups(
                "r2",
                vec![group("pg1", 65002, vec![AddressFamily::Ipv4Unicast])],
            ),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_across_instances_pass() {
        let cfg = config_with(vec![
            instance_with_groups(
                "r1",
                vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
            ),
            instance_with_groups(
                "r2",
                vec![group("pg2", 65002, vec![AddressFamily::Ipv4Unicast])],
            ),
        ]);
        cfg.validate_with(&cfg).unwrap();
    }

    /// RFC 8950: an IPv6-transport session may carry IPv4 unicast NLRI.
    /// `source_address`'s IP version must never constrain `address_families`.
    #[test]
    fn ipv6_source_address_with_ipv4_address_family_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.source_address = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }
}
