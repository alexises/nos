use chrono::{DateTime, SecondsFormat, Utc};
use nos_proto::{
    AddressFamily, BgpAoAlgorithm, BgpAuth, BgpInstance, BgpPeer, BgpPeerGroup, BgpSessionState,
    BroadcastDomain, CommunityAlias, CommunityGroup, Config, ConfigDiff, DiffStatus, FieldDiff,
    Interface, InterfaceAddress, InterfaceStatus, LogEntry, LogLevel, NextHopMode, PeerSummary,
    PolicyDefinition, PrefixList, PrefixListEntry, PrefixRoutes, RouteSourceKind, RoutingTable,
    SectionDiff, SourceAddress, StaticRoute, StaticRoutingInstance, Subinterface,
    SubinterfaceStatus, SwitchingProfile, TransactionSnapshot, VlanTag,
};

use crate::session::Path;

/// Render one peer-group as human-readable text. `local_asn` is the owning
/// BGP instance's own ASN, needed only to render `next_hop`'s default
/// (eBGP/iBGP-dependent) label when the field is unset.
pub fn render_bgp_peer_group(group: &BgpPeerGroup, local_asn: u32) -> String {
    let source_address = group
        .source_address
        .as_ref()
        .map_or_else(|| "unset".to_string(), SourceAddress::to_string);
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
    let hold_time = group
        .hold_time
        .map_or_else(|| "default (90s)".to_string(), |h| h.to_string());
    let keepalive_interval = group
        .keepalive_interval
        .map_or_else(|| "default (hold-time / 3)".to_string(), |k| k.to_string());
    let connect_retry_time = group
        .connect_retry_time
        .map_or_else(|| "default (120s)".to_string(), |c| c.to_string());
    let auth = render_bgp_auth(group.auth.as_ref());
    let next_hop = match group.next_hop {
        Some(NextHopMode::SelfAddress) => "self".to_string(),
        Some(NextHopMode::Unchanged) => "unchanged".to_string(),
        None if group.remote_as == local_asn => "default (unchanged, iBGP)".to_string(),
        None => "default (self, eBGP)".to_string(),
    };
    let mut line = format!(
        "peer-group {}: remote-as {}, source-address {source_address}, address-family [{address_families}], \
         hold-time {hold_time}, keepalive-interval {keepalive_interval}, connect-retry-time {connect_retry_time}, \
         auth {auth}, next-hop {next_hop}",
        group.name, group.remote_as
    );
    if group.route_reflector_client {
        line.push_str(", route-reflector-client");
    }
    if group.route_server_client {
        line.push_str(", route-server-client");
    }
    line
}

/// Rendered in clear text, like every other field — passwords/keys are
/// stored unencrypted in this config, so there is nothing to mask.
fn render_bgp_auth(auth: Option<&BgpAuth>) -> String {
    match auth {
        None => "none".to_string(),
        Some(BgpAuth::Md5 { password }) => format!("md5-password {password}"),
        Some(BgpAuth::Ao { keys }) => {
            let rendered = keys
                .iter()
                .map(|k| {
                    let algorithm = match k.algorithm {
                        BgpAoAlgorithm::HmacSha1_96 => "hmac-sha1",
                        BgpAoAlgorithm::AesCmac96 => "aes-cmac",
                    };
                    let flags = match (k.is_current, k.is_rnext) {
                        (true, true) => " (current, rnext)",
                        (true, false) => " (current)",
                        (false, true) => " (rnext)",
                        (false, false) => "",
                    };
                    format!("send-id {} {algorithm} {}{flags}", k.send_id, k.key)
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("ao-keys [{rendered}]")
        }
    }
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
    let cluster_id = instance
        .cluster_id
        .map_or_else(|| "default (= router-id)".to_string(), |c| c.to_string());
    let mut lines = vec![format!(
        "bgp instance {}: router-id {}, asn {}, cluster-id {cluster_id}",
        instance.name, instance.router_id, instance.asn
    )];
    for group in &instance.peer_groups {
        lines.push(format!("  {}", render_bgp_peer_group(group, instance.asn)));
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
    let redistribute_str = match &table.redistribute {
        Some(r) => format!(
            "from {} to {}, policy {}",
            r.from,
            r.to,
            r.policy.as_deref().unwrap_or("unset")
        ),
        None => "unset".to_string(),
    };
    format!(
        "routing-table {}: bgp-instance {bgp_instance}, static-routing-instance {static_routing_instance}, redistribute {redistribute_str}",
        table.name
    )
}

/// Render one static route as human-readable text.
pub fn render_static_route(route: &StaticRoute) -> String {
    format!("route {}: gateway {}", route.subnet, route.gateway)
}

fn format_address(addr: &InterfaceAddress) -> String {
    match &addr.label {
        Some(label) => format!("{} (label {label})", addr.address),
        None => addr.address.to_string(),
    }
}

/// Render one subinterface as human-readable text — `tag 0` is the
/// untagged/native case (what used to be a physical interface's own flat
/// `addresses`/`routing_table`).
pub fn render_subinterface(sub: &Subinterface) -> String {
    let addresses = if sub.addresses.is_empty() {
        "none".to_string()
    } else {
        sub.addresses
            .iter()
            .map(format_address)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let routing_table = sub.routing_table.as_deref().unwrap_or("unset");
    format!(
        "subinterface {}: address [{addresses}], routing-table {routing_table}",
        sub.tag
    )
}

/// Render one interface's config as human-readable text, including any
/// (physical-interface-only) subinterfaces, each indented one level under
/// the interface line — mirrors `render_bgp_instance`'s nested peer-groups.
/// `iface.addresses`/`routing_table` are meaningful only for a loopback
/// interface (unchanged flat rendering); every other interface's L3 config
/// lives entirely in the nested subinterface lines instead.
pub fn render_interface(iface: &Interface) -> String {
    let addresses = if iface.addresses.is_empty() {
        "none".to_string()
    } else {
        iface
            .addresses
            .iter()
            .map(format_address)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let routing_table = iface.routing_table.as_deref().unwrap_or("unset");
    let switching_profile = iface.switching_profile.as_deref().unwrap_or("unset");
    let mut lines = vec![format!(
        "interface {}: address [{addresses}], routing-table {routing_table}, switching-profile {switching_profile}",
        iface.name
    )];
    for sub in &iface.subinterfaces {
        lines.push(format!("  {}", render_subinterface(sub)));
    }
    lines.join("\n")
}

/// Render one subinterface's daemon-reported status — the wire twin of
/// `render_subinterface`.
pub fn render_subinterface_status(status: &SubinterfaceStatus) -> String {
    let addresses = if status.addresses.is_empty() {
        "none".to_string()
    } else {
        status
            .addresses
            .iter()
            .map(format_address)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let routing_table = status.routing_table.as_deref().unwrap_or("unset");
    format!(
        "subinterface {}: address [{addresses}], routing-table {routing_table}",
        status.tag
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
            .map(format_address)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let routing_table = status.routing_table.as_deref().unwrap_or("unset");
    let switching_profile = status.switching_profile.as_deref().unwrap_or("unset");
    let mut lines = vec![format!(
        "interface {}: address [{addresses}], routing-table {routing_table}, switching-profile {switching_profile}",
        status.name
    )];
    for sub in &status.subinterfaces {
        lines.push(format!("  {}", render_subinterface_status(sub)));
    }
    lines.join("\n")
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

fn render_log_level(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "TRACE",
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
    }
}

/// Render one log entry as one line: `<timestamp> <LEVEL> <source> <target>: <message> {fields}`.
pub fn render_log_entry(entry: &LogEntry) -> String {
    let timestamp = DateTime::<Utc>::from_timestamp_millis(
        i64::try_from(entry.timestamp_ms).unwrap_or(i64::MAX),
    )
    .map_or_else(
        || entry.timestamp_ms.to_string(),
        |dt| dt.to_rfc3339_opts(SecondsFormat::Millis, true),
    );
    let base = format!(
        "{timestamp} {:>5} {} {}: {}",
        render_log_level(entry.level),
        entry.source,
        entry.target,
        entry.message
    );
    if entry.fields.is_empty() {
        return base;
    }
    let fields = entry
        .fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{base} ({fields})")
}

/// Render a buffer of log entries, one per line, in the order given (already
/// oldest-first from `nos-logd`) — used for both `show log` (a snapshot) and
/// each streamed line of `show log --follow`.
pub fn render_log_entries(entries: &[LogEntry]) -> String {
    if entries.is_empty() {
        return "no log entries".to_string();
    }
    entries
        .iter()
        .map(render_log_entry)
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

fn render_bgp_session_state(state: BgpSessionState) -> &'static str {
    match state {
        BgpSessionState::Idle => "Idle",
        BgpSessionState::OpenSent => "OpenSent",
        BgpSessionState::OpenConfirm => "OpenConfirm",
        BgpSessionState::Established => "Established",
    }
}

fn format_uptime(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Render one BGP instance's peer summaries, one line per peer — used for
/// `show bgp brief`.
pub fn render_bgp_summary(instance: &str, peers: &[PeerSummary]) -> String {
    if peers.is_empty() {
        return format!("bgp instance {instance}: no peers configured");
    }
    let mut lines = vec![format!("bgp instance {instance}:")];
    for peer in peers {
        let remote_as = peer
            .remote_as
            .map_or_else(|| "-".to_string(), |asn| asn.to_string());
        let uptime = peer
            .uptime_secs
            .map_or_else(|| "-".to_string(), format_uptime);
        let hold_time = peer
            .negotiated_hold_time
            .map_or_else(|| "-".to_string(), |h| h.to_string());
        lines.push(format!(
            "  {} AS {remote_as} peer-group {} {} uptime {uptime} hold-time {hold_time}",
            peer.remote_address,
            peer.peer_group,
            render_bgp_session_state(peer.state),
        ));
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
    if config.community_aliases.is_empty() {
        lines.push("no community aliases configured".to_string());
    } else {
        lines.extend(config.community_aliases.iter().map(render_community_alias));
    }
    if config.community_groups.is_empty() {
        lines.push("no community groups configured".to_string());
    } else {
        lines.extend(config.community_groups.iter().map(render_community_group));
    }
    if config.prefix_lists.is_empty() {
        lines.push("no prefix lists configured".to_string());
    } else {
        lines.extend(config.prefix_lists.iter().map(render_prefix_list));
    }
    if config.broadcast_domains.is_empty() {
        lines.push("no broadcast domains configured".to_string());
    } else {
        lines.extend(config.broadcast_domains.iter().map(render_broadcast_domain));
    }
    if config.switching_profiles.is_empty() {
        lines.push("no switching profiles configured".to_string());
    } else {
        lines.extend(
            config
                .switching_profiles
                .iter()
                .map(render_switching_profile),
        );
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
                        |g| render_bgp_peer_group(g, inst.asn),
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
        Path::Subinterface { interface, tag } => snapshot
            .config
            .interfaces
            .iter()
            .find(|i| &i.name == interface)
            .and_then(|i| i.subinterfaces.iter().find(|s| s.tag == *tag))
            .map_or_else(
                || format!("subinterface '{interface}.{tag}' not found"),
                render_subinterface,
            ),
        Path::PolicyDefinition(name) => snapshot
            .config
            .policy_definitions
            .iter()
            .find(|p| &p.name == name)
            .map_or_else(
                || format!("policy-definition '{name}' not found"),
                render_policy_definition,
            ),
        Path::CommunityAlias(name) => snapshot
            .config
            .community_aliases
            .iter()
            .find(|a| &a.name == name)
            .map_or_else(
                || format!("community-alias '{name}' not found"),
                render_community_alias,
            ),
        Path::CommunityGroup(name) => snapshot
            .config
            .community_groups
            .iter()
            .find(|g| &g.name == name)
            .map_or_else(
                || format!("community-group '{name}' not found"),
                render_community_group,
            ),
        Path::PrefixList(name) => snapshot
            .config
            .prefix_lists
            .iter()
            .find(|p| &p.name == name)
            .map_or_else(
                || format!("prefix-list '{name}' not found"),
                render_prefix_list,
            ),
        Path::BroadcastDomain(name) => snapshot
            .config
            .broadcast_domains
            .iter()
            .find(|d| &d.name == name)
            .map_or_else(
                || format!("broadcast-domain '{name}' not found"),
                render_broadcast_domain,
            ),
        Path::SwitchingProfile(name) => snapshot
            .config
            .switching_profiles
            .iter()
            .find(|p| &p.name == name)
            .map_or_else(
                || format!("switching-profile '{name}' not found"),
                render_switching_profile,
            ),
    }
}

/// Render one policy-definition as human-readable text — the name plus its
/// line-numbered source (see `render_policy_source`), matching `show
/// source`'s own rendering so the two never drift apart.
pub fn render_policy_definition(policy: &PolicyDefinition) -> String {
    format!(
        "policy-definition {}:\n{}",
        policy.name,
        render_policy_source(&policy.source)
    )
}

/// Render policy source with `cat -n`-style line numbers, so `set source
/// line <n> ...`/`delete source line <n>` can be given without re-reading
/// the source in an editor first.
pub fn render_policy_source(source: &str) -> String {
    if source.is_empty() {
        return "(empty)".to_string();
    }
    source
        .lines()
        .enumerate()
        .map(|(i, line)| format!("{:4}  {line}", i + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render one community-alias as human-readable text.
pub fn render_community_alias(alias: &CommunityAlias) -> String {
    format!("community-alias {}: value {}", alias.name, alias.value)
}

/// Render one community-group as human-readable text.
pub fn render_community_group(group: &CommunityGroup) -> String {
    let members = if group.members.is_empty() {
        "none".to_string()
    } else {
        group.members.join(", ")
    };
    format!("community-group {}: members [{members}]", group.name)
}

/// Render one `PrefixListEntry` the same way for every caller — `<cidr>` for
/// an exact-match entry, `<cidr> range(<min>,<max>)` otherwise.
pub fn render_prefix_list_entry(entry: &PrefixListEntry) -> String {
    match entry.range {
        None => entry.cidr.to_string(),
        Some((min, max)) => format!("{} range({min},{max})", entry.cidr),
    }
}

/// Render one prefix-list as human-readable text.
pub fn render_prefix_list(list: &PrefixList) -> String {
    let entries = if list.entries.is_empty() {
        "none".to_string()
    } else {
        list.entries
            .iter()
            .map(render_prefix_list_entry)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("prefix-list {}: entries [{entries}]", list.name)
}

/// Render one broadcast domain as human-readable text, including its own
/// SVI (address/routing-table) config — mirrors `render_interface`'s flat
/// loopback rendering, since a domain's bridge has the same flat L3 shape.
pub fn render_broadcast_domain(domain: &BroadcastDomain) -> String {
    let addresses = if domain.addresses.is_empty() {
        "none".to_string()
    } else {
        domain
            .addresses
            .iter()
            .map(format_address)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let routing_table = domain.routing_table.as_deref().unwrap_or("unset");
    format!(
        "broadcast-domain {}: address [{addresses}], routing-table {routing_table}",
        domain.name
    )
}

/// Render one `VlanTag` the same way for every caller.
pub fn render_vlan_tag(tag: VlanTag) -> String {
    match tag {
        VlanTag::Untagged => "untagged".to_string(),
        VlanTag::Dot1q(id) => format!("dot1q {id}"),
    }
}

/// Render one switching profile as human-readable text.
pub fn render_switching_profile(profile: &SwitchingProfile) -> String {
    let members = if profile.members.is_empty() {
        "none".to_string()
    } else {
        profile
            .members
            .iter()
            .map(|m| format!("{}: {}", m.broadcast_domain, render_vlan_tag(m.tag)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("switching-profile {}: members [{members}]", profile.name)
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
            cluster_id: None,
            routing_table: None,
            redistribute_policy: None,
        }
    }

    #[test]
    fn empty_config() {
        let cfg = Config::default();
        assert_eq!(
            render_config(&cfg),
            "hostname: nos\nno BGP instances configured\nno routing tables configured\nno static routing instances configured\nno interfaces configured\n\
             no community aliases configured\nno community groups configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured"
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
            "hostname: nos\nbgp instance default: router-id 1.1.1.1, asn 65000, cluster-id default (= router-id)\n\
             no routing tables configured\nno static routing instances configured\n\
             no interfaces configured\n\
             no community aliases configured\nno community groups configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured"
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
            "hostname: nos\nbgp instance vrf-a: router-id 1.1.1.1, asn 65001, cluster-id default (= router-id)\n\
             bgp instance vrf-b: router-id 1.1.1.1, asn 65002, cluster-id default (= router-id)\n\
             no routing tables configured\nno static routing instances configured\n\
             no interfaces configured\n\
             no community aliases configured\nno community groups configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured"
        );
    }

    #[test]
    fn render_interface_with_subinterfaces() {
        let iface = Interface {
            name: "eth0".to_string(),
            addresses: Vec::new(),
            routing_table: None,
            switching_profile: None,
            subinterfaces: vec![
                Subinterface {
                    tag: 0,
                    addresses: vec![InterfaceAddress {
                        address: "10.0.0.1/24".parse().unwrap(),
                        label: None,
                    }],
                    routing_table: Some("rt1".to_string()),
                },
                Subinterface {
                    tag: 100,
                    addresses: Vec::new(),
                    routing_table: None,
                },
            ],
        };
        assert_eq!(
            render_interface(&iface),
            "interface eth0: address [none], routing-table unset, switching-profile unset\n\
             \x20 subinterface 0: address [10.0.0.1/24], routing-table rt1\n\
             \x20 subinterface 100: address [none], routing-table unset"
        );
    }

    /// A loopback interface's flat `addresses`/`routing_table` still render
    /// on the interface's own line, unaffected by the addressing split — it
    /// never has `subinterfaces`, so no nested lines are added.
    #[test]
    fn render_loopback_interface_stays_flat() {
        let iface = Interface {
            name: "loopback-rt1".to_string(),
            addresses: vec![InterfaceAddress {
                address: "10.0.0.1/32".parse().unwrap(),
                label: None,
            }],
            routing_table: Some("rt1".to_string()),
            switching_profile: None,
            subinterfaces: Vec::new(),
        };
        assert_eq!(
            render_interface(&iface),
            "interface loopback-rt1: address [10.0.0.1/32], routing-table rt1, switching-profile unset"
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
            "transaction 'demo':\nhostname: nos\nbgp instance r1: router-id 1.1.1.1, asn 65001, cluster-id default (= router-id)\n\
             no routing tables configured\nno static routing instances configured\n\
             no interfaces configured\n\
             no community aliases configured\nno community groups configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured"
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
        assert_eq!(
            rendered,
            "bgp instance r1: router-id 1.1.1.1, asn 65001, cluster-id default (= router-id)"
        );
    }

    #[test]
    fn render_transaction_at_bgp_instance_not_found() {
        let rendered = render_transaction(&snapshot(false), &Path::BgpInstance("r2".to_string()));
        assert_eq!(rendered, "bgp instance 'r2' not found");
    }

    #[test]
    fn render_transaction_at_subinterface_found() {
        let mut snap = snapshot(false);
        snap.config.interfaces = vec![Interface {
            name: "eth0".to_string(),
            addresses: Vec::new(),
            routing_table: None,
            switching_profile: None,
            subinterfaces: vec![Subinterface {
                tag: 100,
                addresses: Vec::new(),
                routing_table: Some("rt1".to_string()),
            }],
        }];
        let rendered = render_transaction(
            &snap,
            &Path::Subinterface {
                interface: "eth0".to_string(),
                tag: 100,
            },
        );
        assert_eq!(
            rendered,
            "subinterface 100: address [none], routing-table rt1"
        );
    }

    #[test]
    fn render_transaction_at_subinterface_not_found() {
        let rendered = render_transaction(
            &snapshot(false),
            &Path::Subinterface {
                interface: "eth0".to_string(),
                tag: 100,
            },
        );
        assert_eq!(rendered, "subinterface 'eth0.100' not found");
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
            source_address: Some(SourceAddress::Interface {
                interface: "eth0".to_string(),
                label: None,
            }),
            address_families: vec![AddressFamily::Ipv4Unicast],
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
        }
    }

    #[test]
    fn render_bgp_peer_group_line() {
        assert_eq!(
            render_bgp_peer_group(&peer_group("pg1"), 65000),
            "peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), auth none, next-hop default (self, eBGP)"
        );
    }

    #[test]
    fn render_bgp_peer_group_with_unset_source_address() {
        let mut pg = peer_group("pg1");
        pg.source_address = None;
        assert_eq!(
            render_bgp_peer_group(&pg, 65000),
            "peer-group pg1: remote-as 65001, source-address unset, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), auth none, next-hop default (self, eBGP)"
        );
    }

    #[test]
    fn render_bgp_peer_group_with_explicit_timers() {
        let mut pg = peer_group("pg1");
        pg.hold_time = Some(30);
        pg.keepalive_interval = Some(10);
        pg.connect_retry_time = Some(45);
        assert_eq!(
            render_bgp_peer_group(&pg, 65000),
            "peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time 30, keepalive-interval 10, connect-retry-time 45, auth none, \
             next-hop default (self, eBGP)"
        );
    }

    #[test]
    fn render_bgp_peer_group_with_md5_auth() {
        let mut pg = peer_group("pg1");
        pg.auth = Some(BgpAuth::Md5 {
            password: "secret".to_string(),
        });
        assert_eq!(
            render_bgp_peer_group(&pg, 65000),
            "peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), auth md5-password secret, \
             next-hop default (self, eBGP)"
        );
    }

    #[test]
    fn render_bgp_peer_group_with_ao_auth() {
        use nos_proto::BgpAoKey;

        let mut pg = peer_group("pg1");
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![BgpAoKey {
                send_id: 1,
                recv_id: 1,
                algorithm: BgpAoAlgorithm::HmacSha1_96,
                key: "secret".to_string(),
                is_current: true,
                is_rnext: false,
            }],
        });
        assert_eq!(
            render_bgp_peer_group(&pg, 65000),
            "peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), \
             auth ao-keys [send-id 1 hmac-sha1 secret (current)], \
             next-hop default (self, eBGP)"
        );
    }

    #[test]
    fn render_bgp_peer_group_next_hop_ibgp_default_and_explicit_override() {
        let mut pg = peer_group("pg1");
        pg.remote_as = 65000;
        assert!(render_bgp_peer_group(&pg, 65000).contains("next-hop default (unchanged, iBGP)"));

        pg.next_hop = Some(NextHopMode::SelfAddress);
        assert!(render_bgp_peer_group(&pg, 65000).contains("next-hop self"));

        pg.next_hop = Some(NextHopMode::Unchanged);
        assert!(render_bgp_peer_group(&pg, 65000).contains("next-hop unchanged"));
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
            "bgp instance r1: router-id 1.1.1.1, asn 65000, cluster-id default (= router-id)\n  \
             peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), auth none, next-hop default (self, eBGP)\n  \
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
            "peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), auth none, next-hop default (unchanged, iBGP)"
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

    fn log_entry(source: &str, message: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: 0,
            level: LogLevel::Info,
            source: source.to_string(),
            target: "nos_rib::reconcile".to_string(),
            message: message.to_string(),
            fields: vec![("table".to_string(), "rt1".to_string())],
        }
    }

    #[test]
    fn render_log_entries_empty_buffer() {
        assert_eq!(render_log_entries(&[]), "no log entries");
    }

    #[test]
    fn render_log_entry_includes_timestamp_level_source_and_fields() {
        let rendered = render_log_entry(&log_entry("nos-ribd[rt1]", "resynced"));
        assert_eq!(
            rendered,
            "1970-01-01T00:00:00.000Z  INFO nos-ribd[rt1] nos_rib::reconcile: resynced (table=rt1)"
        );
    }

    #[test]
    fn render_log_entries_joins_multiple_lines() {
        let entries = vec![log_entry("a", "one"), log_entry("b", "two")];
        let rendered = render_log_entries(&entries);
        assert_eq!(rendered.lines().count(), 2);
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

    fn idle_peer(addr: &str) -> PeerSummary {
        PeerSummary {
            remote_address: addr.parse().unwrap(),
            peer_group: "pg1".to_string(),
            remote_as: None,
            remote_bgp_id: None,
            state: BgpSessionState::Idle,
            uptime_secs: None,
            negotiated_hold_time: None,
            negotiated_keepalive: None,
        }
    }

    #[test]
    fn render_bgp_summary_empty_list() {
        assert_eq!(
            render_bgp_summary("r1", &[]),
            "bgp instance r1: no peers configured"
        );
    }

    #[test]
    fn render_bgp_summary_one_established_peer_shows_uptime_and_hold_time() {
        let mut peer = idle_peer("10.0.0.1");
        peer.remote_as = Some(65002);
        peer.state = BgpSessionState::Established;
        peer.uptime_secs = Some(3725);
        peer.negotiated_hold_time = Some(90);
        assert_eq!(
            render_bgp_summary("r1", &[peer]),
            "bgp instance r1:\n  10.0.0.1 AS 65002 peer-group pg1 Established uptime 01:02:05 hold-time 90"
        );
    }

    #[test]
    fn render_bgp_summary_idle_peer_shows_dashes() {
        assert_eq!(
            render_bgp_summary("r1", &[idle_peer("10.0.0.1")]),
            "bgp instance r1:\n  10.0.0.1 AS - peer-group pg1 Idle uptime - hold-time -"
        );
    }
}
