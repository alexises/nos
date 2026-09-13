use nos_proto::{
    AddressFamily, BgpInstance, BgpPeer, BgpPeerGroup, Config, ConfigDiff, DiffStatus, FieldDiff,
    Interface, InterfaceStatus, PrefixRoutes, RouteSourceKind, RoutingTable, SectionDiff,
    StaticRoute, StaticRoutingInstance, TransactionSnapshot,
};

use crate::session::Path;

/// Render one peer-group as human-readable text.
pub fn render_bgp_peer_group(group: &BgpPeerGroup) -> String {
    let source_address = group
        .source_address
        .map_or_else(|| "unset".to_string(), |a| a.to_string());
    let address_families = if group.address_families.is_empty() {
        "none".to_string()
    } else {
        group
            .address_families
            .iter()
            .map(AddressFamily::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "peer-group {}: remote-as {}, source-address {source_address}, address-family [{address_families}]",
        group.name, group.remote_as
    )
}

/// Render one peer as human-readable text.
pub fn render_bgp_peer(peer: &BgpPeer) -> String {
    format!(
        "peer {}: peer-group {}",
        peer.remote_address, peer.peer_group
    )
}

/// Render one BGP instance as human-readable text, including any nested
/// peer-groups and peers, each indented one level under the instance line.
pub fn render_bgp_instance(instance: &BgpInstance) -> String {
    let mut lines = vec![format!(
        "bgp instance {}: router-id {}, asn {}",
        instance.name, instance.router_id, instance.asn
    )];
    for group in &instance.peer_groups {
        lines.push(format!("  {}", render_bgp_peer_group(group)));
    }
    for peer in &instance.peers {
        lines.push(format!("  {}", render_bgp_peer(peer)));
    }
    lines.join("\n")
}

/// Render one routing table as human-readable text.
pub fn render_routing_table(table: &RoutingTable) -> String {
    let bgp_instance = table.bgp_instance.as_deref().unwrap_or("unset");
    let static_routing_instance = table.static_routing_instance.as_deref().unwrap_or("unset");
    format!(
        "routing-table {}: bgp-instance {bgp_instance}, static-routing-instance {static_routing_instance}",
        table.name
    )
}

/// Render one static route as human-readable text.
pub fn render_static_route(route: &StaticRoute) -> String {
    format!("route {}: gateway {}", route.subnet, route.gateway)
}

/// Render one interface's config as human-readable text.
pub fn render_interface(iface: &Interface) -> String {
    let addresses = if iface.addresses.is_empty() {
        "none".to_string()
    } else {
        iface
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let routing_table = iface.routing_table.as_deref().unwrap_or("unset");
    format!(
        "interface {}: address [{addresses}], routing-table {routing_table}",
        iface.name
    )
}

/// Render one interface's daemon-reported status (from `nos-interfaced`'s
/// `InterfaceRequest::GetInterfaces`/`GetInterface`) as human-readable text
/// — for `show interface`, distinct from `render_interface`'s config-only
/// view since it reflects what the daemon has reconciled.
pub fn render_interface_status(status: &InterfaceStatus) -> String {
    let addresses = if status.addresses.is_empty() {
        "none".to_string()
    } else {
        status
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let routing_table = status.routing_table.as_deref().unwrap_or("unset");
    format!(
        "interface {}: address [{addresses}], routing-table {routing_table}",
        status.name
    )
}

/// Render every interface's daemon-reported status, one per line — used for
/// both `show interface` (many entries) and `show interface <name>` (one).
pub fn render_interface_statuses(statuses: &[InterfaceStatus]) -> String {
    if statuses.is_empty() {
        return "no interfaces".to_string();
    }
    statuses
        .iter()
        .map(render_interface_status)
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_route_source(source: RouteSourceKind) -> &'static str {
    match source {
        RouteSourceKind::Static => "static",
        RouteSourceKind::Bgp => "bgp",
    }
}

/// Render one prefix's candidate routes, best (winner, marked `*`) to worst,
/// one line per candidate. Used for both `show route <table>` (many entries)
/// and `show route <table> <address>` (one entry, wrapped in a slice).
pub fn render_prefix_routes(entries: &[PrefixRoutes]) -> String {
    if entries.is_empty() {
        return "no routes".to_string();
    }
    let mut lines = Vec::new();
    for entry in entries {
        lines.push(format!("{}", entry.prefix));
        for (i, candidate) in entry.candidates.iter().enumerate() {
            let marker = if i == 0 { "*" } else { " " };
            lines.push(format!(
                "  {marker} via {} [{}]",
                candidate.gateway,
                render_route_source(candidate.source)
            ));
        }
    }
    lines.join("\n")
}

/// Render one static routing instance as human-readable text, including any
/// nested routes, each indented one level under the instance line.
pub fn render_static_routing_instance(instance: &StaticRoutingInstance) -> String {
    let mut lines = vec![format!("static-routing-instance {}", instance.name)];
    for route in &instance.routes {
        lines.push(format!("  {}", render_static_route(route)));
    }
    lines.join("\n")
}

/// Render a full running-config snapshot as human-readable text.
pub fn render_config(config: &Config) -> String {
    let mut lines = vec![format!("hostname: {}", config.hostname)];
    if config.bgp_instances.is_empty() {
        lines.push("no BGP instances configured".to_string());
    } else {
        lines.extend(config.bgp_instances.iter().map(render_bgp_instance));
    }
    if config.routing_tables.is_empty() {
        lines.push("no routing tables configured".to_string());
    } else {
        lines.extend(config.routing_tables.iter().map(render_routing_table));
    }
    if config.static_routing_instances.is_empty() {
        lines.push("no static routing instances configured".to_string());
    } else {
        lines.extend(
            config
                .static_routing_instances
                .iter()
                .map(render_static_routing_instance),
        );
    }
    if config.interfaces.is_empty() {
        lines.push("no interfaces configured".to_string());
    } else {
        lines.extend(config.interfaces.iter().map(render_interface));
    }
    lines.join("\n")
}

/// Render a transaction's in-progress config, scoped to the current
/// navigation path: the whole config at `Path::Root`, or a single BGP
/// instance at `Path::BgpInstance(name)`.
pub fn render_transaction(snapshot: &TransactionSnapshot, path: &Path) -> String {
    match path {
        Path::Root => {
            let header = if snapshot.dirty {
                format!("transaction '{}' (uncommitted changes):", snapshot.name)
            } else {
                format!("transaction '{}':", snapshot.name)
            };
            format!("{header}\n{}", render_config(&snapshot.config))
        }
        Path::BgpInstance(name) => snapshot
            .config
            .bgp_instances
            .iter()
            .find(|i| &i.name == name)
            .map_or_else(
                || format!("bgp instance '{name}' not found"),
                render_bgp_instance,
            ),
        Path::BgpPeerGroup { instance, group } => {
            match snapshot
                .config
                .bgp_instances
                .iter()
                .find(|i| &i.name == instance)
            {
                None => format!("bgp instance '{instance}' not found"),
                Some(inst) => inst
                    .peer_groups
                    .iter()
                    .find(|g| &g.name == group)
                    .map_or_else(
                        || format!("peer-group '{group}' not found in bgp instance '{instance}'"),
                        render_bgp_peer_group,
                    ),
            }
        }
        Path::RoutingTable(name) => snapshot
            .config
            .routing_tables
            .iter()
            .find(|t| &t.name == name)
            .map_or_else(
                || format!("routing-table '{name}' not found"),
                render_routing_table,
            ),
        Path::StaticRoutingInstance(name) => snapshot
            .config
            .static_routing_instances
            .iter()
            .find(|i| &i.name == name)
            .map_or_else(
                || format!("static routing instance '{name}' not found"),
                render_static_routing_instance,
            ),
        Path::Interface(name) => snapshot
            .config
            .interfaces
            .iter()
            .find(|i| &i.name == name)
            .map_or_else(|| format!("interface '{name}' not found"), render_interface),
    }
}

// ANSI SGR codes for `render_diff`. Hand-rolled rather than pulling in a
// color crate — this is the only place in `nos-cli` that needs color, and
// keeping the base color active while toggling bold/underline (via `22;24`,
// which turns those off without a full reset) lets a diff line's word-level
// highlight nest inside its red/green without ever losing that color.
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const EMPH_ON: &str = "\x1b[1;4m";
const EMPH_OFF: &str = "\x1b[22;24m";
const RESET: &str = "\x1b[0m";

/// Renders the structural difference between the running config and a
/// transaction's in-progress config, computed server-side by `nos-config`
/// (see `nos_proto::diff_configs`). `nos-cli`'s only job here is turning
/// that structured diff into colored, highlighted terminal text — with just
/// enough unmodified context (an unstyled section header) that a changed
/// field can always be traced back to the section it lives in.
pub fn render_diff(diff: &ConfigDiff, color: bool) -> String {
    let mut lines = Vec::new();

    if let Some(field) = &diff.hostname {
        render_field_diff(&mut lines, field, "", color);
    }

    for section in &diff.bgp_instances {
        render_section(&mut lines, section, 0, color);
    }
    for section in &diff.routing_tables {
        render_section(&mut lines, section, 0, color);
    }
    for section in &diff.static_routing_instances {
        render_section(&mut lines, section, 0, color);
    }
    for section in &diff.interfaces {
        render_section(&mut lines, section, 0, color);
    }

    lines.join("\n")
}

/// Renders one `SectionDiff` at `depth` levels of nesting (2 spaces per
/// level, matching the existing single-level indent), then recurses into
/// its `subsections` one level deeper.
fn render_section(lines: &mut Vec<String>, section: &SectionDiff, depth: usize, color: bool) {
    let indent = "  ".repeat(depth);
    let header = format!("{indent}{}:", section.header);
    match section.status {
        // The section itself didn't change — only shown so a reader can
        // tell which section its changed fields (below) belong to.
        DiffStatus::Modified => lines.push(context_line(&header)),
        DiffStatus::Added => lines.push(added_line(&header, color)),
        DiffStatus::Removed => lines.push(removed_line(&header, color)),
    }
    let field_indent = "  ".repeat(depth + 1);
    for field in &section.fields {
        render_field_diff(lines, field, &field_indent, color);
    }
    for subsection in &section.subsections {
        render_section(lines, subsection, depth + 1, color);
    }
}

fn render_field_diff(lines: &mut Vec<String>, field: &FieldDiff, indent: &str, color: bool) {
    match (&field.old, &field.new) {
        (Some(old), Some(new)) => {
            let (old_h, new_h) = highlight(old, new, color);
            lines.push(removed_line(
                &format!("{indent}{}: {old_h}", field.label),
                color,
            ));
            lines.push(added_line(
                &format!("{indent}{}: {new_h}", field.label),
                color,
            ));
        }
        (None, Some(new)) => {
            lines.push(added_line(
                &format!("{indent}{}: {new}", field.label),
                color,
            ));
        }
        (Some(old), None) => {
            lines.push(removed_line(
                &format!("{indent}{}: {old}", field.label),
                color,
            ));
        }
        (None, None) => {}
    }
}

fn context_line(text: &str) -> String {
    format!("  {text}")
}

fn added_line(text: &str, color: bool) -> String {
    styled_line('+', GREEN, text, color)
}

fn removed_line(text: &str, color: bool) -> String {
    styled_line('-', RED, text, color)
}

fn styled_line(marker: char, code: &str, text: &str, color: bool) -> String {
    if color {
        format!("{marker} {code}{text}{RESET}")
    } else {
        format!("{marker} {text}")
    }
}

/// Highlights only the substring that actually differs between `old` and
/// `new` (a simple common-prefix/common-suffix split, not a full LCS/Myers
/// diff — config field values are short atomic strings like hostnames,
/// ASNs, and IPs, not prose). Returns plain, unmarked strings when `color`
/// is off.
fn highlight(old: &str, new: &str, color: bool) -> (String, String) {
    if !color {
        return (old.to_string(), new.to_string());
    }
    let old_chars: Vec<char> = old.chars().collect();
    let new_chars: Vec<char> = new.chars().collect();
    let (prefix, suffix) = common_affixes(&old_chars, &new_chars);
    (
        emphasize_middle(&old_chars, prefix, suffix),
        emphasize_middle(&new_chars, prefix, suffix),
    )
}

/// Common prefix/suffix character counts between `a` and `b`, capped so
/// they never overlap.
fn common_affixes(a: &[char], b: &[char]) -> (usize, usize) {
    let limit = a.len().min(b.len());
    let prefix = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    let max_suffix = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let suffix = max_suffix.min(limit - prefix);
    (prefix, suffix)
}

fn emphasize_middle(chars: &[char], prefix: usize, suffix: usize) -> String {
    let end = chars.len() - suffix;
    let head: String = chars[..prefix].iter().collect();
    let mid: String = chars[prefix..end].iter().collect();
    let tail: String = chars[end..].iter().collect();
    if mid.is_empty() {
        return format!("{head}{tail}");
    }
    format!("{head}{EMPH_ON}{mid}{EMPH_OFF}{tail}")
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::{BgpInstance, SectionDiff};

    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
            peer_groups: Vec::new(),
            peers: Vec::new(),
        }
    }

    #[test]
    fn empty_config() {
        let cfg = Config::default();
        assert_eq!(
            render_config(&cfg),
            "hostname: nos\nno BGP instances configured\nno routing tables configured\nno static routing instances configured\nno interfaces configured"
        );
    }

    #[test]
    fn single_instance() {
        let cfg = Config {
            bgp_instances: vec![instance("default", 65000)],
            ..Default::default()
        };
        assert_eq!(
            render_config(&cfg),
            "hostname: nos\nbgp instance default: router-id 1.1.1.1, asn 65000\n\
             no routing tables configured\nno static routing instances configured\n\
             no interfaces configured"
        );
    }

    #[test]
    fn multiple_instances() {
        let cfg = Config {
            bgp_instances: vec![instance("vrf-a", 65001), instance("vrf-b", 65002)],
            ..Default::default()
        };
        assert_eq!(
            render_config(&cfg),
            "hostname: nos\nbgp instance vrf-a: router-id 1.1.1.1, asn 65001\n\
             bgp instance vrf-b: router-id 1.1.1.1, asn 65002\n\
             no routing tables configured\nno static routing instances configured\n\
             no interfaces configured"
        );
    }

    fn snapshot(dirty: bool) -> TransactionSnapshot {
        TransactionSnapshot {
            name: "demo".to_string(),
            config: Config {
                bgp_instances: vec![instance("r1", 65001)],
                ..Default::default()
            },
            dirty,
            resumed: false,
        }
    }

    #[test]
    fn render_transaction_at_root_clean() {
        let rendered = render_transaction(&snapshot(false), &Path::Root);
        assert_eq!(
            rendered,
            "transaction 'demo':\nhostname: nos\nbgp instance r1: router-id 1.1.1.1, asn 65001\n\
             no routing tables configured\nno static routing instances configured\n\
             no interfaces configured"
        );
    }

    #[test]
    fn render_transaction_at_root_dirty() {
        let rendered = render_transaction(&snapshot(true), &Path::Root);
        assert!(rendered.starts_with("transaction 'demo' (uncommitted changes):"));
    }

    #[test]
    fn render_transaction_at_bgp_instance_found() {
        let rendered = render_transaction(&snapshot(false), &Path::BgpInstance("r1".to_string()));
        assert_eq!(rendered, "bgp instance r1: router-id 1.1.1.1, asn 65001");
    }

    #[test]
    fn render_transaction_at_bgp_instance_not_found() {
        let rendered = render_transaction(&snapshot(false), &Path::BgpInstance("r2".to_string()));
        assert_eq!(rendered, "bgp instance 'r2' not found");
    }

    fn field(label: &str, old: Option<&str>, new: Option<&str>) -> FieldDiff {
        FieldDiff {
            label: label.to_string(),
            old: old.map(str::to_string),
            new: new.map(str::to_string),
        }
    }

    #[test]
    fn render_diff_hostname_change_no_color() {
        let diff = ConfigDiff {
            hostname: Some(field("hostname", Some("router-a"), Some("router-b"))),
            bgp_instances: vec![],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "- hostname: router-a\n+ hostname: router-b"
        );
    }

    #[test]
    fn render_diff_modified_section_shows_unstyled_header_as_context() {
        let diff = ConfigDiff {
            hostname: None,
            bgp_instances: vec![SectionDiff {
                header: "bgp instance r1".to_string(),
                name: "r1".to_string(),
                status: DiffStatus::Modified,
                fields: vec![field("asn", Some("65000"), Some("65001"))],
                subsections: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "  bgp instance r1:\n-   asn: 65000\n+   asn: 65001"
        );
    }

    #[test]
    fn render_diff_added_section_marks_every_line() {
        let diff = ConfigDiff {
            hostname: None,
            bgp_instances: vec![SectionDiff {
                header: "bgp instance r1".to_string(),
                name: "r1".to_string(),
                status: DiffStatus::Added,
                fields: vec![
                    field("router-id", None, Some("1.1.1.1")),
                    field("asn", None, Some("65000")),
                ],
                subsections: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "+ bgp instance r1:\n+   router-id: 1.1.1.1\n+   asn: 65000"
        );
    }

    #[test]
    fn render_diff_removed_section_marks_every_line() {
        let diff = ConfigDiff {
            hostname: None,
            bgp_instances: vec![SectionDiff {
                header: "bgp instance r1".to_string(),
                name: "r1".to_string(),
                status: DiffStatus::Removed,
                fields: vec![field("asn", Some("65000"), None)],
                subsections: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "- bgp instance r1:\n-   asn: 65000"
        );
    }

    #[test]
    fn highlight_marks_only_differing_middle() {
        let (old, new) = highlight("65000", "65001", true);
        assert_eq!(old, format!("6500{EMPH_ON}0{EMPH_OFF}"));
        assert_eq!(new, format!("6500{EMPH_ON}1{EMPH_OFF}"));
    }

    #[test]
    fn highlight_handles_pure_suffix_addition() {
        let (old, new) = highlight("ab", "abc", true);
        assert_eq!(old, "ab");
        assert_eq!(new, format!("ab{EMPH_ON}c{EMPH_OFF}"));
    }

    #[test]
    fn highlight_without_color_is_plain() {
        let (old, new) = highlight("65000", "65001", false);
        assert_eq!(old, "65000");
        assert_eq!(new, "65001");
    }

    use nos_proto::{BgpPeer, BgpPeerGroup};
    use std::net::IpAddr;

    fn peer_group(name: &str) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.to_string(),
            remote_as: 65001,
            source_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            address_families: vec![AddressFamily::Ipv4Unicast],
        }
    }

    #[test]
    fn render_bgp_peer_group_line() {
        assert_eq!(
            render_bgp_peer_group(&peer_group("pg1")),
            "peer-group pg1: remote-as 65001, source-address 10.0.0.1, address-family [ipv4]"
        );
    }

    #[test]
    fn render_bgp_peer_group_with_unset_source_address() {
        let mut pg = peer_group("pg1");
        pg.source_address = None;
        assert_eq!(
            render_bgp_peer_group(&pg),
            "peer-group pg1: remote-as 65001, source-address unset, address-family [ipv4]"
        );
    }

    #[test]
    fn render_instance_with_peer_groups_and_peers() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![peer_group("pg1")];
        inst.peers = vec![BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "pg1".to_string(),
        }];
        assert_eq!(
            render_bgp_instance(&inst),
            "bgp instance r1: router-id 1.1.1.1, asn 65000\n  \
             peer-group pg1: remote-as 65001, source-address 10.0.0.1, address-family [ipv4]\n  \
             peer 192.0.2.1: peer-group pg1"
        );
    }

    #[test]
    fn render_transaction_at_peer_group_found() {
        let mut snap = snapshot(false);
        snap.config.bgp_instances[0].peer_groups = vec![peer_group("pg1")];
        let rendered = render_transaction(
            &snap,
            &Path::BgpPeerGroup {
                instance: "r1".to_string(),
                group: "pg1".to_string(),
            },
        );
        assert_eq!(
            rendered,
            "peer-group pg1: remote-as 65001, source-address 10.0.0.1, address-family [ipv4]"
        );
    }

    #[test]
    fn render_transaction_at_peer_group_not_found() {
        let rendered = render_transaction(
            &snapshot(false),
            &Path::BgpPeerGroup {
                instance: "r1".to_string(),
                group: "pg-missing".to_string(),
            },
        );
        assert_eq!(
            rendered,
            "peer-group 'pg-missing' not found in bgp instance 'r1'"
        );
    }

    #[test]
    fn render_diff_nested_subsection_indents_one_level_deeper() {
        let diff = ConfigDiff {
            hostname: None,
            bgp_instances: vec![SectionDiff {
                header: "bgp instance r1".to_string(),
                name: "r1".to_string(),
                status: DiffStatus::Modified,
                fields: vec![],
                subsections: vec![SectionDiff {
                    header: "peer-group pg1".to_string(),
                    name: "pg1".to_string(),
                    status: DiffStatus::Modified,
                    fields: vec![field("remote-as", Some("65001"), Some("65002"))],
                    subsections: vec![],
                }],
            }],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "  bgp instance r1:\n    peer-group pg1:\n-     remote-as: 65001\n+     remote-as: 65002"
        );
    }
}
