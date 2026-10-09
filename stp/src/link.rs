//! Speed, duplex and the values derived from them (sysfs: no ethtool, no
//! process spawn).

use nos_proto::schema::LinkType;

use crate::cost;

/// Used when the kernel does not know the speed (veth on some kernels, a
/// down link): virtual lab links must not get the 200 000 000 "unknown" cost.
pub const FALLBACK_SPEED_MBPS: u32 = 1000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkInfo {
    pub speed_mbps: Option<u32>,
    pub full_duplex: Option<bool>,
}

pub fn read(dev: &str) -> LinkInfo {
    let get = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{dev}/{f}")).ok();
    LinkInfo {
        speed_mbps: get("speed").and_then(|s| parse_speed(&s)),
        full_duplex: get("duplex").and_then(|s| parse_duplex(&s)),
    }
}

/// `-1` (unknown) and `0` are `None`.
pub fn parse_speed(s: &str) -> Option<u32> {
    s.trim().parse::<u32>().ok().filter(|&v| v > 0)
}

pub fn parse_duplex(s: &str) -> Option<bool> {
    match s.trim() {
        "full" => Some(true),
        "half" => Some(false),
        _ => None,
    }
}

/// Configured cost, else Table 13-4 for the speed (fallback when unknown).
pub fn path_cost(configured: Option<u32>, info: LinkInfo) -> u32 {
    configured.unwrap_or_else(|| cost::path_cost(info.speed_mbps.unwrap_or(FALLBACK_SPEED_MBPS)))
}

/// `operPointToPoint`: configured, else full duplex (unknown duplex counts as
/// full, like unknown speed counts as 1 Gb/s).
pub fn point_to_point(link_type: LinkType, info: LinkInfo) -> bool {
    match link_type {
        LinkType::PointToPoint => true,
        LinkType::Shared => false,
        LinkType::Auto => info.full_duplex.unwrap_or(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sysfs_values() {
        assert_eq!(parse_speed("1000\n"), Some(1000));
        assert_eq!(parse_speed("-1\n"), None);
        assert_eq!(parse_speed("0"), None);
        assert_eq!(parse_speed("junk"), None);
        assert_eq!(parse_duplex("full\n"), Some(true));
        assert_eq!(parse_duplex("half"), Some(false));
        assert_eq!(parse_duplex("unknown"), None);
    }

    #[test]
    fn cost_from_speed_or_config() {
        let known = |s| LinkInfo {
            speed_mbps: Some(s),
            full_duplex: None,
        };
        assert_eq!(path_cost(None, known(10_000)), 2_000);
        assert_eq!(path_cost(None, LinkInfo::default()), 20_000);
        assert_eq!(path_cost(Some(5), known(10_000)), 5);
    }

    #[test]
    fn point_to_point_rules() {
        let half = LinkInfo {
            speed_mbps: None,
            full_duplex: Some(false),
        };
        assert!(!point_to_point(LinkType::Auto, half));
        assert!(point_to_point(LinkType::PointToPoint, half));
        assert!(point_to_point(LinkType::Auto, LinkInfo::default()));
        assert!(!point_to_point(LinkType::Shared, LinkInfo::default()));
    }
}
