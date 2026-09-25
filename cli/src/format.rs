use std::fmt::Write as _;
use std::net::Ipv4Addr;

use chrono::{DateTime, SecondsFormat, Utc};
use nos_proto::{
    AddressFamily, BgpAoAlgorithm, BgpAuth, BgpInstance, BgpPeer, BgpPeerGroup, BgpSessionState,
    BroadcastDomain, CommunityAlias, CommunityGroup, Config, ConfigDiff, DiffStatus,
    EvpnRouteSummary, FieldDiff, Interface, InterfaceAddress, InterfaceStatus, LacpMuxState,
    LacpRate, LacpReceiveState, LinkInterfaceState, LogEntry, LogLevel, LsaSummary,
    NeighborSummary, NextHopMode, OspfArea, OspfAuth, OspfCryptoAlgorithm, OspfInstance,
    OspfNeighborState, OspfProfile, Ospfv3Area, Ospfv3Instance, Ospfv3LsaSummary,
    Ospfv3NeighborSummary, Ospfv3Profile, PeerSummary, PolicyDefinition, PortAggregate,
    PortAggregateLacpSummary, PortAggregateStatus, PrefixList, PrefixListEntry, PrefixRoutes,
    RouteSourceKind, RoutingTable, SectionDiff, SourceAddress, StaticRoute, StaticRoutingInstance,
    Subinterface, SubinterfaceStatus, SwitchingProfile, TransactionSnapshot, VlanTag,
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

/// Render one OSPF instance as human-readable text, including any nested
/// areas (and each area's nested profiles), indented one/two levels under
/// the instance line — mirrors `render_interface`'s nested subinterfaces.
pub fn render_ospf_instance(instance: &OspfInstance) -> String {
    let mut lines = vec![format!(
        "ospf instance {}: router-id {}",
        instance.name, instance.router_id
    )];
    for area in &instance.areas {
        for line in render_ospf_area(area).lines() {
            lines.push(format!("  {line}"));
        }
    }
    lines.join("\n")
}

/// Render one OSPF area as human-readable text, including any nested
/// profiles, each indented one level under the area line.
pub fn render_ospf_area(area: &OspfArea) -> String {
    let mut lines = vec![format!("area {}", area.area_id)];
    for profile in &area.profiles {
        lines.push(format!("  {}", render_ospf_profile(profile)));
    }
    lines.join("\n")
}

/// Render one OSPF profile as human-readable text.
pub fn render_ospf_profile(profile: &OspfProfile) -> String {
    format!(
        "profile {}: auth {}",
        profile.name,
        render_ospf_auth(profile.auth.as_ref())
    )
}

/// Rendered in clear text, like every other field — mirrors
/// `render_bgp_auth`'s exact rationale.
fn render_ospf_auth(auth: Option<&OspfAuth>) -> String {
    match auth {
        None => "none".to_string(),
        Some(OspfAuth::Simple { password }) => format!("simple-password {password}"),
        Some(OspfAuth::Crypto { keys }) => {
            let rendered = keys
                .iter()
                .map(|k| {
                    let algorithm = match k.algorithm {
                        OspfCryptoAlgorithm::Md5 => "md5",
                        OspfCryptoAlgorithm::HmacSha1 => "hmac-sha1",
                        OspfCryptoAlgorithm::HmacSha256 => "hmac-sha256",
                        OspfCryptoAlgorithm::HmacSha384 => "hmac-sha384",
                        OspfCryptoAlgorithm::HmacSha512 => "hmac-sha512",
                    };
                    let flags = if k.is_current { " (current)" } else { "" };
                    format!("key-id {} {algorithm} {}{flags}", k.key_id, k.key)
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("crypto-keys [{rendered}]")
        }
    }
}

/// Render one `Ospfv3Instance` as human-readable text — mirrors
/// `render_ospf_instance` exactly.
pub fn render_ospfv3_instance(instance: &Ospfv3Instance) -> String {
    let mut lines = vec![format!(
        "ospfv3 instance {}: router-id {}",
        instance.name, instance.router_id
    )];
    for area in &instance.areas {
        for line in render_ospfv3_area(area).lines() {
            lines.push(format!("  {line}"));
        }
    }
    lines.join("\n")
}

/// Render one `Ospfv3Area` as human-readable text — mirrors
/// `render_ospf_area` exactly.
pub fn render_ospfv3_area(area: &Ospfv3Area) -> String {
    let mut lines = vec![format!("area {}", area.area_id)];
    for profile in &area.profiles {
        lines.push(format!("  {}", render_ospfv3_profile(profile)));
    }
    lines.join("\n")
}

/// Render one `Ospfv3Profile` as human-readable text — no `auth` field to
/// render (no authentication in this NOS build's `OSPFv3` support), unlike
/// `render_ospf_profile`.
pub fn render_ospfv3_profile(profile: &Ospfv3Profile) -> String {
    format!("profile {}", profile.name)
}

/// Render one routing table as human-readable text.
pub fn render_routing_table(table: &RoutingTable) -> String {
    let bgp_instance = table.bgp_instance.as_deref().unwrap_or("unset");
    let ospf_instance = table.ospf_instance.as_deref().unwrap_or("unset");
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
    let rest_api = table
        .rest_api
        .as_ref()
        .map_or("unset".to_string(), |r| format!("{}:{}", r.address, r.port));
    format!(
        "routing-table {}: bgp-instance {bgp_instance}, ospf-instance {ospf_instance}, static-routing-instance {static_routing_instance}, redistribute {redistribute_str}, rest-api {rest_api}",
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
    let ospf_profile = sub.ospf_profile.as_deref().unwrap_or("unset");
    format!(
        "subinterface {}: address [{addresses}], routing-table {routing_table}, ospf-profile {ospf_profile}",
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
    let ospf_profile = iface.ospf_profile.as_deref().unwrap_or("unset");
    let switching_profile = iface.switching_profile.as_deref().unwrap_or("unset");
    let mtu = iface
        .mtu
        .map_or_else(|| "unset".to_string(), |m| m.to_string());
    let mut lines = vec![format!(
        "interface {}: address [{addresses}], routing-table {routing_table}, ospf-profile {ospf_profile}, switching-profile {switching_profile}, mtu {mtu}, lldp-transmit {}, lldp-receive {}",
        iface.name,
        on_off(iface.lldp_transmit),
        on_off(iface.lldp_receive),
    )];
    // Only when set, so an interface that doesn't use it renders unchanged.
    if iface.lldp_destination != nos_proto::LldpDestination::default() {
        write!(
            lines[0],
            ", lldp-destination {}",
            iface.lldp_destination.name()
        )
        .expect("writing to a String cannot fail");
    }
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
        "interface {}: address [{addresses}], routing-table {routing_table}, switching-profile {switching_profile}, mtu {}",
        status.name, status.mtu
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

/// Render one port aggregate's config-only view — the `PortAggregate`
/// counterpart of `render_interface`, minus the loopback-only flat
/// addresses/routing-table fields it has none of.
pub fn render_port_aggregate(agg: &PortAggregate) -> String {
    let switching_profile = agg.switching_profile.as_deref().unwrap_or("unset");
    let mtu = agg
        .mtu
        .map_or_else(|| "unset".to_string(), |m| m.to_string());
    let esi = agg
        .esi
        .as_ref()
        .map_or_else(String::new, |e| format!(", esi {e}"));
    let system_id = agg
        .lacp_system_id
        .as_ref()
        .map_or_else(String::new, |i| format!(", lacp-system-id {i}"));
    let redundancy = match agg.redundancy_mode {
        nos_proto::EsRedundancy::AllActive => "",
        nos_proto::EsRedundancy::SingleActive => ", redundancy-mode single-active",
    };
    let mut lines = vec![format!(
        "port-aggregate {}: mode {:?}, switching-profile {switching_profile}, mtu {mtu}{esi}{redundancy}{system_id}",
        agg.name, agg.mode
    )];
    for sub in &agg.subinterfaces {
        lines.push(format!("  {}", render_subinterface(sub)));
    }
    lines.join("\n")
}

/// Render one port aggregate's daemon-reported status — the `PortAggregate`
/// counterpart of `render_interface_status`.
pub fn render_port_aggregate_status(status: &PortAggregateStatus) -> String {
    let switching_profile = status.switching_profile.as_deref().unwrap_or("unset");
    let mut lines = vec![format!(
        "port-aggregate {}: mode {:?}, switching-profile {switching_profile}, mtu {}",
        status.name, status.mode, status.mtu
    )];
    for sub in &status.subinterfaces {
        lines.push(format!("  {}", render_subinterface_status(sub)));
    }
    lines.join("\n")
}

/// Render every port aggregate's daemon-reported status, one per line — used
/// for both `show port-aggregate` (many entries) and `show port-aggregate
/// <name>` (one).
pub fn render_port_aggregate_statuses(statuses: &[PortAggregateStatus]) -> String {
    if statuses.is_empty() {
        return "no port aggregates".to_string();
    }
    statuses
        .iter()
        .map(render_port_aggregate_status)
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.map(|b| format!("{b:02x}")).join(":")
}

fn render_lacp_port(port: &nos_proto::LacpPortStatus) -> String {
    let receive = match port.receive_state {
        LacpReceiveState::Initialize => "initialize",
        LacpReceiveState::PortDisabled => "port-disabled",
        LacpReceiveState::LacpDisabled => "lacp-disabled",
        LacpReceiveState::Expired => "expired",
        LacpReceiveState::Defaulted => "defaulted",
        LacpReceiveState::Current => "current",
    };
    let mux = match port.mux_state {
        LacpMuxState::Detached => "detached",
        LacpMuxState::Waiting => "waiting",
        LacpMuxState::Attached => "attached",
        LacpMuxState::Collecting => "collecting",
        LacpMuxState::Distributing => "distributing",
    };
    let partner = match (port.partner_system_id, port.partner_key) {
        (Some(system), Some(key)) => format!(
            "partner {} key {key} port {}",
            format_mac(system),
            port.partner_port_number.unwrap_or(0)
        ),
        _ => "partner none".to_string(),
    };
    format!(
        "  {}: port {}, receive {receive}, mux {mux}, {partner}, selected {}, synchronized {}",
        port.interface,
        port.actor_port_number,
        yes_no(port.selected),
        yes_no(port.synchronized),
    )
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

/// Render `nos-lldpd`'s neighbor table, for `show lldp neighbors`.
pub fn render_lldp_neighbors(neighbors: &[nos_proto::LldpNeighbor]) -> String {
    if neighbors.is_empty() {
        return "no lldp neighbors".to_string();
    }
    neighbors
        .iter()
        .map(|n| {
            let capabilities = if n.capabilities.is_empty() {
                "none".to_string()
            } else {
                n.capabilities.join(",")
            };
            let description = n
                .port_description
                .as_deref()
                .filter(|d| *d != n.port_id)
                .map_or_else(String::new, |d| format!(" ({d})"));
            let management = if n.management_addresses.is_empty() {
                String::new()
            } else {
                format!(", management {}", n.management_addresses.join(","))
            };
            format!(
                "{}: neighbor {}, chassis {}, port {}{description}, capabilities {capabilities}{management}, ttl {}s",
                n.local_interface,
                n.system_name.as_deref().unwrap_or("unnamed"),
                n.chassis_id,
                n.port_id,
                n.ttl_remaining_secs,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// Render `nos-lacpd`'s per-aggregate LACP state, for `show lacp`.
pub fn render_lacp_summaries(summaries: &[PortAggregateLacpSummary]) -> String {
    if summaries.is_empty() {
        return "no lacp port aggregates".to_string();
    }
    summaries
        .iter()
        .map(|s| {
            let rate = match s.rate {
                LacpRate::Slow => "slow",
                LacpRate::Fast => "fast",
            };
            let mut lines = vec![format!(
                "lacp {}: system {}, key {}, rate {rate}",
                s.aggregate,
                format_mac(s.actor_system_id),
                s.actor_key
            )];
            if s.ports.is_empty() {
                lines.push("  no member ports".to_string());
            }
            lines.extend(s.ports.iter().map(render_lacp_port));
            lines.join("\n")
        })
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
        RouteSourceKind::Ospf => "ospf",
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
            let backup = candidate
                .backup
                .map_or_else(String::new, |b| format!(" backup {b}"));
            lines.push(format!(
                "  {marker} via {} [{}]{backup}",
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

/// Render one BGP instance's received EVPN routes, one line per route — used
/// for `show bgp evpn`.
pub fn render_bgp_evpn(instance: &str, routes: &[EvpnRouteSummary]) -> String {
    if routes.is_empty() {
        return format!("bgp instance {instance}: no evpn routes");
    }
    let mut lines = vec![format!("bgp instance {instance}:")];
    for r in routes {
        lines.push(format!(
            "  from {} next-hop {} {} [{}]",
            r.peer,
            r.next_hop,
            r.route,
            r.extended_communities.join(" ")
        ));
    }
    lines.join("\n")
}

fn render_ospf_neighbor_state(state: OspfNeighborState) -> &'static str {
    match state {
        OspfNeighborState::Down => "Down",
        OspfNeighborState::Init => "Init",
        OspfNeighborState::TwoWay => "2-Way",
        OspfNeighborState::ExStart => "ExStart",
        OspfNeighborState::Exchange => "Exchange",
        OspfNeighborState::Loading => "Loading",
        OspfNeighborState::Full => "Full",
    }
}

fn render_ospf_interface_state(state: LinkInterfaceState) -> &'static str {
    match state {
        LinkInterfaceState::PointToPoint => "point-to-point",
        LinkInterfaceState::Waiting => "waiting",
        LinkInterfaceState::Dr => "dr",
        LinkInterfaceState::Backup => "backup",
        LinkInterfaceState::DrOther => "dr-other",
    }
}

fn render_ip_or_dash(addr: Option<Ipv4Addr>) -> String {
    addr.map_or_else(|| "-".to_string(), |a| a.to_string())
}

/// Render one OSPF instance's link/neighbor summaries, one line per
/// neighbor — used for `show ospf neigh`. Mirrors `render_bgp_summary`'s
/// shape.
pub fn render_ospf_neighbors(instance: &str, neighbors: &[NeighborSummary]) -> String {
    if neighbors.is_empty() {
        return format!("ospf instance {instance}: no ospf links configured");
    }
    let mut lines = vec![format!("ospf instance {instance}:")];
    for link in neighbors {
        let neighbor_router_id = render_ip_or_dash(link.neighbor_router_id);
        let last_hello = link
            .last_hello_secs
            .map_or_else(|| "-".to_string(), |s| format!("{s}s"));
        let neighbor_priority = link
            .neighbor_priority
            .map_or_else(|| "-".to_string(), |p| p.to_string());
        lines.push(format!(
            "  {} area {} if-state {} neighbor {neighbor_router_id} {} last-hello {last_hello} \
             hello-interval {} dead-interval {} priority {} neighbor-priority {neighbor_priority} \
             dr {} bdr {}",
            link.link,
            link.area_id,
            render_ospf_interface_state(link.interface_state),
            render_ospf_neighbor_state(link.state),
            link.hello_interval,
            link.dead_interval,
            link.priority,
            render_ip_or_dash(link.dr),
            render_ip_or_dash(link.bdr),
        ));
    }
    lines.join("\n")
}

/// Render one OSPF instance's installed-LSA headers, one line per LSA —
/// used for `show ospf database`. Mirrors `render_ospf_neighbors`' shape.
pub fn render_ospf_database(instance: &str, entries: &[LsaSummary]) -> String {
    if entries.is_empty() {
        return format!("ospf instance {instance}: no LSAs installed");
    }
    let mut lines = vec![format!("ospf instance {instance}:")];
    for lsa in entries {
        lines.push(format!(
            "  area {} type {} link-state-id {} advertising-router {} \
             sequence 0x{:08x} age {} checksum 0x{:04x}",
            lsa.area_id,
            lsa.lsa_type,
            lsa.link_state_id,
            lsa.advertising_router,
            lsa.sequence_number,
            lsa.age,
            lsa.checksum,
        ));
    }
    lines.join("\n")
}

/// Render one `Ospfv3Instance`'s link/neighbor summaries, one line per
/// neighbor — used for `show ospfv3 neigh`. Mirrors `render_ospf_neighbors`
/// exactly, reusing the same `OspfNeighborState`/`LinkInterfaceState`
/// renderers since `Ospfv3NeighborSummary` shares those types verbatim.
pub fn render_ospfv3_neighbors(instance: &str, neighbors: &[Ospfv3NeighborSummary]) -> String {
    if neighbors.is_empty() {
        return format!("ospfv3 instance {instance}: no ospfv3 links configured");
    }
    let mut lines = vec![format!("ospfv3 instance {instance}:")];
    for link in neighbors {
        let neighbor_router_id = render_ip_or_dash(link.neighbor_router_id);
        let last_hello = link
            .last_hello_secs
            .map_or_else(|| "-".to_string(), |s| format!("{s}s"));
        let neighbor_priority = link
            .neighbor_priority
            .map_or_else(|| "-".to_string(), |p| p.to_string());
        lines.push(format!(
            "  {} area {} if-state {} neighbor {neighbor_router_id} {} last-hello {last_hello} \
             hello-interval {} dead-interval {} priority {} neighbor-priority {neighbor_priority} \
             dr {} bdr {}",
            link.link,
            link.area_id,
            render_ospf_interface_state(link.interface_state),
            render_ospf_neighbor_state(link.state),
            link.hello_interval,
            link.dead_interval,
            link.priority,
            render_ip_or_dash(link.dr),
            render_ip_or_dash(link.bdr),
        ));
    }
    lines.join("\n")
}

/// Render one `Ospfv3Instance`'s installed-LSA headers, one line per LSA —
/// used for `show ospfv3 database`. Mirrors `render_ospf_database` exactly.
pub fn render_ospfv3_database(instance: &str, entries: &[Ospfv3LsaSummary]) -> String {
    if entries.is_empty() {
        return format!("ospfv3 instance {instance}: no LSAs installed");
    }
    let mut lines = vec![format!("ospfv3 instance {instance}:")];
    for lsa in entries {
        lines.push(format!(
            "  area {} type {} link-state-id {} advertising-router {} \
             sequence 0x{:08x} age {} checksum 0x{:04x}",
            lsa.area_id,
            lsa.lsa_type,
            lsa.link_state_id,
            lsa.advertising_router,
            lsa.sequence_number,
            lsa.age,
            lsa.checksum,
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

/// The system-wide `lldp` settings line; only shown when something is set.
fn render_lldp_settings(lldp: &nos_proto::LldpSettings) -> String {
    let secs = lldp
        .tx_interval_secs
        .map_or_else(|| "default".to_string(), |v| v.to_string());
    let hold = lldp
        .tx_hold
        .map_or_else(|| "default".to_string(), |v| v.to_string());
    let address = lldp
        .management_address
        .map_or_else(|| "unset".to_string(), |a| a.to_string());
    format!("lldp: tx-interval {secs}, tx-hold {hold}, management-address {address}")
}

/// Render a full running-config snapshot as human-readable text.
pub fn render_config(config: &Config) -> String {
    let mut lines = vec![format!("hostname: {}", config.hostname)];
    if config.lldp != nos_proto::LldpSettings::default() {
        lines.push(render_lldp_settings(&config.lldp));
    }
    // Names only — a user's password (hash) is never displayed.
    lines.extend(config.users.iter().map(|u| format!("user {}", u.name)));
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
    if config.ospf_instances.is_empty() {
        lines.push("no OSPF instances configured".to_string());
    } else {
        lines.extend(config.ospf_instances.iter().map(render_ospf_instance));
    }
    if config.ospfv3_instances.is_empty() {
        lines.push("no OSPFv3 instances configured".to_string());
    } else {
        lines.extend(config.ospfv3_instances.iter().map(render_ospfv3_instance));
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
    if config.port_aggregates.is_empty() {
        lines.push("no port aggregates configured".to_string());
    } else {
        lines.extend(config.port_aggregates.iter().map(render_port_aggregate));
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
        Path::OspfInstance(name) => snapshot
            .config
            .ospf_instances
            .iter()
            .find(|i| &i.name == name)
            .map_or_else(
                || format!("ospf instance '{name}' not found"),
                render_ospf_instance,
            ),
        Path::OspfArea { instance, area_id } => snapshot
            .config
            .ospf_instances
            .iter()
            .find(|i| &i.name == instance)
            .and_then(|i| i.areas.iter().find(|a| a.area_id == *area_id))
            .map_or_else(
                || format!("ospf area '{area_id}' not found in ospf instance '{instance}'"),
                render_ospf_area,
            ),
        Path::OspfProfile {
            instance,
            area_id,
            name,
        } => snapshot
            .config
            .ospf_instances
            .iter()
            .find(|i| &i.name == instance)
            .and_then(|i| i.areas.iter().find(|a| a.area_id == *area_id))
            .and_then(|a| a.profiles.iter().find(|p| &p.name == name))
            .map_or_else(
                || {
                    format!(
                        "ospf profile '{name}' not found in area '{area_id}' of ospf instance '{instance}'"
                    )
                },
                render_ospf_profile,
            ),
        Path::Ospfv3Instance(name) => snapshot
            .config
            .ospfv3_instances
            .iter()
            .find(|i| &i.name == name)
            .map_or_else(
                || format!("ospfv3 instance '{name}' not found"),
                render_ospfv3_instance,
            ),
        Path::Ospfv3Area { instance, area_id } => snapshot
            .config
            .ospfv3_instances
            .iter()
            .find(|i| &i.name == instance)
            .and_then(|i| i.areas.iter().find(|a| a.area_id == *area_id))
            .map_or_else(
                || format!("ospfv3 area '{area_id}' not found in ospfv3 instance '{instance}'"),
                render_ospfv3_area,
            ),
        Path::Ospfv3Profile {
            instance,
            area_id,
            name,
        } => snapshot
            .config
            .ospfv3_instances
            .iter()
            .find(|i| &i.name == instance)
            .and_then(|i| i.areas.iter().find(|a| a.area_id == *area_id))
            .and_then(|a| a.profiles.iter().find(|p| &p.name == name))
            .map_or_else(
                || {
                    format!(
                        "ospfv3 profile '{name}' not found in area '{area_id}' of ospfv3 instance '{instance}'"
                    )
                },
                render_ospfv3_profile,
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
        Path::PortAggregate(name) => snapshot
            .config
            .port_aggregates
            .iter()
            .find(|a| &a.name == name)
            .map_or_else(
                || format!("port-aggregate '{name}' not found"),
                render_port_aggregate,
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

/// Render one domain's forwarding database for `show fdb`.
pub fn render_fdb_table(t: &nos_proto::FdbTable) -> String {
    let dev = |d: &Option<String>| d.as_deref().unwrap_or("not created yet").to_string();
    let mut lines = vec![format!(
        "broadcast-domain {}: vni {}, bridge {}, vxlan {}",
        t.domain,
        t.vni,
        dev(&t.bridge),
        dev(&t.vxlan)
    )];
    if t.macs.is_empty() {
        lines.push("  no MAC addresses".to_string());
    }
    for m in &t.macs {
        lines.push(match (m.source, m.vtep) {
            // An aliased MAC (RFC 7432 §8.4.1.1) is balanced over several PEs.
            (nos_proto::MacSource::Remote, Some(_)) if m.vteps.len() > 1 => format!(
                "  {} remote via {} (aliased)",
                m.mac,
                m.vteps
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            (nos_proto::MacSource::Remote, Some(vtep)) => format!("  {} remote via {vtep}", m.mac),
            (nos_proto::MacSource::Remote, None) => format!("  {} remote", m.mac),
            (nos_proto::MacSource::Local, _) => match &m.esi {
                Some(esi) => format!("  {} local, esi {esi}", m.mac),
                None => format!("  {} local", m.mac),
            },
        });
    }
    for n in &t.neighbours {
        lines.push(match (n.source, n.vtep) {
            (nos_proto::MacSource::Remote, Some(vtep)) => {
                format!("  {} is at {} remote via {vtep}", n.ip, n.mac)
            }
            (nos_proto::MacSource::Remote, None) => format!("  {} is at {} remote", n.ip, n.mac),
            (nos_proto::MacSource::Local, _) => format!("  {} is at {} local", n.ip, n.mac),
        });
    }
    let flood: Vec<String> = t.flood.iter().map(ToString::to_string).collect();
    lines.push(if flood.is_empty() {
        "  flood list: none".to_string()
    } else {
        format!("  flood list: {}", flood.join(", "))
    });
    for e in &t.segments {
        let pes: Vec<String> = e.pes.iter().map(ToString::to_string).collect();
        let ads: Vec<String> = e.ad_pes.iter().map(ToString::to_string).collect();
        lines.push(format!(
            "  ethernet-segment {} on {}: {} (PEs {}){}{}",
            e.esi,
            e.port,
            if !e.up {
                "down, no carrier"
            } else if e.designated_forwarder {
                "designated forwarder"
            } else if e.single_active {
                "non-designated forwarder, port blocked"
            } else {
                "non-designated forwarder, BUM blocked"
            },
            pes.join(", "),
            if ads.is_empty() {
                String::new()
            } else {
                format!(", per-ES A-D from {}", ads.join(", "))
            },
            if e.single_active {
                ", single-active"
            } else {
                ""
            }
        ));
    }
    lines.join("\n")
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
    let ospf_profile = domain.ospf_profile.as_deref().unwrap_or("unset");
    let mut line = format!(
        "broadcast-domain {}: address [{addresses}], routing-table {routing_table}, ospf-profile {ospf_profile}",
        domain.name
    );
    if let Some(vni) = domain.vni {
        let list = |v: &[String]| v.join(",");
        let _ = write!(
            line,
            ", vni {vni}, rd {}, rt-import [{}], rt-export [{}], vtep-source {}, redistribute-mac {}, redistribute-arp {}, redistribute-connected {}",
            domain.rd.as_deref().unwrap_or("unset"),
            list(&domain.route_targets_import),
            list(&domain.route_targets_export),
            domain
                .vtep_source
                .as_ref()
                .map_or_else(|| "unset".to_string(), ToString::to_string),
            domain.mac_redistribute.as_deref().unwrap_or("unset"),
            domain.arp_redistribute.as_deref().unwrap_or("unset"),
            domain.connected_redistribute.as_deref().unwrap_or("unset"),
        );
    }
    line
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
    for field in &diff.lldp {
        render_field_diff(&mut lines, field, "", color);
    }

    for section in &diff.users {
        render_section(&mut lines, section, 0, color);
    }
    for section in &diff.bgp_instances {
        render_section(&mut lines, section, 0, color);
    }
    for section in &diff.routing_tables {
        render_section(&mut lines, section, 0, color);
    }
    for section in &diff.ospf_instances {
        render_section(&mut lines, section, 0, color);
    }
    for section in &diff.ospfv3_instances {
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
            "hostname: nos\nno BGP instances configured\nno routing tables configured\nno OSPF instances configured\nno OSPFv3 instances configured\nno static routing instances configured\nno interfaces configured\n\
             no community aliases configured\nno community groups configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured\n\
             no port aggregates configured"
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
             no routing tables configured\nno OSPF instances configured\nno OSPFv3 instances configured\nno static routing instances configured\n\
             no interfaces configured\n\
             no community aliases configured\nno community groups configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured\n\
             no port aggregates configured"
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
             no routing tables configured\nno OSPF instances configured\nno OSPFv3 instances configured\nno static routing instances configured\n\
             no interfaces configured\n\
             no community aliases configured\nno community groups configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured\n\
             no port aggregates configured"
        );
    }

    #[test]
    fn render_interface_with_subinterfaces() {
        let iface = Interface {
            ospfv3_profile: None,
            name: "eth0".to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: Some(9000),
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: vec![
                Subinterface {
                    ospfv3_profile: None,
                    tag: 0,
                    addresses: vec![InterfaceAddress {
                        address: "10.0.0.1/24".parse().unwrap(),
                        label: None,
                    }],
                    routing_table: Some("rt1".to_string()),
                    ospf_profile: None,
                },
                Subinterface {
                    ospfv3_profile: None,
                    tag: 100,
                    addresses: Vec::new(),
                    routing_table: None,
                    ospf_profile: None,
                },
            ],
        };
        assert_eq!(
            render_interface(&iface),
            "interface eth0: address [none], routing-table unset, ospf-profile unset, switching-profile unset, mtu 9000, lldp-transmit off, lldp-receive off\n\
             \x20 subinterface 0: address [10.0.0.1/24], routing-table rt1, ospf-profile unset\n\
             \x20 subinterface 100: address [none], routing-table unset, ospf-profile unset"
        );
    }

    /// A loopback interface's flat `addresses`/`routing_table` still render
    /// on the interface's own line, unaffected by the addressing split — it
    /// never has `subinterfaces`, so no nested lines are added.
    #[test]
    fn render_loopback_interface_stays_flat() {
        let iface = Interface {
            ospfv3_profile: None,
            name: "loopback-rt1".to_string(),
            addresses: vec![InterfaceAddress {
                address: "10.0.0.1/32".parse().unwrap(),
                label: None,
            }],
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: None,
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: Vec::new(),
        };
        assert_eq!(
            render_interface(&iface),
            "interface loopback-rt1: address [10.0.0.1/32], routing-table rt1, ospf-profile unset, switching-profile unset, mtu unset, lldp-transmit off, lldp-receive off"
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
             no routing tables configured\nno OSPF instances configured\nno OSPFv3 instances configured\nno static routing instances configured\n\
             no interfaces configured\n\
             no community aliases configured\nno community groups configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured\n\
             no port aggregates configured"
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
            ospfv3_profile: None,
            name: "eth0".to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: None,
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: vec![Subinterface {
                ospfv3_profile: None,
                tag: 100,
                addresses: Vec::new(),
                routing_table: Some("rt1".to_string()),
                ospf_profile: None,
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
            "subinterface 100: address [none], routing-table rt1, ospf-profile unset"
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

    fn ospf_profile(name: &str) -> OspfProfile {
        OspfProfile {
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            mtu: None,
            network_type: None,
            auth: None,
        }
    }

    #[test]
    fn render_ospf_profile_with_no_auth() {
        assert_eq!(
            render_ospf_profile(&ospf_profile("p1")),
            "profile p1: auth none"
        );
    }

    #[test]
    fn render_ospf_profile_with_simple_auth() {
        let mut p = ospf_profile("p1");
        p.auth = Some(OspfAuth::Simple {
            password: "secret".to_string(),
        });
        assert_eq!(
            render_ospf_profile(&p),
            "profile p1: auth simple-password secret"
        );
    }

    #[test]
    fn render_ospf_profile_with_crypto_auth() {
        use nos_proto::OspfCryptoKey;

        let mut p = ospf_profile("p1");
        p.auth = Some(OspfAuth::Crypto {
            keys: vec![OspfCryptoKey {
                key_id: 1,
                algorithm: OspfCryptoAlgorithm::HmacSha256,
                key: "secret".to_string(),
                is_current: true,
            }],
        });
        assert_eq!(
            render_ospf_profile(&p),
            "profile p1: auth crypto-keys [key-id 1 hmac-sha256 secret (current)]"
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
    fn render_bgp_evpn_lists_one_route_per_line() {
        assert_eq!(
            render_bgp_evpn("r1", &[]),
            "bgp instance r1: no evpn routes"
        );
        let route = EvpnRouteSummary {
            peer: "10.0.0.2".parse().unwrap(),
            route_type: 3,
            route: "[3]:[65000:1]:[0]:[192.0.2.1]".to_string(),
            next_hop: "192.0.2.1".parse().unwrap(),
            extended_communities: vec!["RT:65000:10000".to_string(), "encap:8".to_string()],
        };
        assert_eq!(
            render_bgp_evpn("r1", &[route]),
            "bgp instance r1:\n  from 10.0.0.2 next-hop 192.0.2.1 [3]:[65000:1]:[0]:[192.0.2.1] [RT:65000:10000 encap:8]"
        );
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

    fn down_link(link: &str) -> NeighborSummary {
        NeighborSummary {
            link: link.to_string(),
            area_id: "0.0.0.0".parse().unwrap(),
            interface_state: LinkInterfaceState::PointToPoint,
            neighbor_router_id: None,
            state: OspfNeighborState::Down,
            last_hello_secs: None,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            neighbor_priority: None,
            dr: None,
            bdr: None,
        }
    }

    #[test]
    fn render_ospf_neighbors_empty_list() {
        assert_eq!(
            render_ospf_neighbors("o1", &[]),
            "ospf instance o1: no ospf links configured"
        );
    }

    #[test]
    fn render_ospf_neighbors_down_link_shows_dash() {
        assert_eq!(
            render_ospf_neighbors("o1", &[down_link("eth0.0")]),
            "ospf instance o1:\n  eth0.0 area 0.0.0.0 if-state point-to-point neighbor - Down \
             last-hello - hello-interval 10 dead-interval 40 priority 1 neighbor-priority - \
             dr - bdr -"
        );
    }

    #[test]
    fn render_ospf_neighbors_two_way_link_shows_neighbor_and_last_hello() {
        let mut link = down_link("eth0.0");
        link.neighbor_router_id = Some("9.9.9.10".parse().unwrap());
        link.state = OspfNeighborState::TwoWay;
        link.last_hello_secs = Some(3);
        link.neighbor_priority = Some(1);
        assert_eq!(
            render_ospf_neighbors("o1", &[link]),
            "ospf instance o1:\n  eth0.0 area 0.0.0.0 if-state point-to-point neighbor 9.9.9.10 \
             2-Way last-hello 3s hello-interval 10 dead-interval 40 priority 1 \
             neighbor-priority 1 dr - bdr -"
        );
    }

    #[test]
    fn render_ospf_neighbors_broadcast_link_shows_interface_state_and_dr_bdr() {
        let mut link = down_link("broadcast-domain:bd1");
        link.interface_state = LinkInterfaceState::Backup;
        link.neighbor_router_id = Some("9.9.9.10".parse().unwrap());
        link.state = OspfNeighborState::TwoWay;
        link.neighbor_priority = Some(200);
        link.dr = Some("9.9.9.10".parse().unwrap());
        link.bdr = Some("1.1.1.1".parse().unwrap());
        assert_eq!(
            render_ospf_neighbors("o1", &[link]),
            "ospf instance o1:\n  broadcast-domain:bd1 area 0.0.0.0 if-state backup neighbor \
             9.9.9.10 2-Way last-hello - hello-interval 10 dead-interval 40 priority 1 \
             neighbor-priority 200 dr 9.9.9.10 bdr 1.1.1.1"
        );
    }

    #[test]
    fn render_ospf_database_empty_list() {
        assert_eq!(
            render_ospf_database("o1", &[]),
            "ospf instance o1: no LSAs installed"
        );
    }

    #[test]
    fn render_ospf_database_one_lsa() {
        let lsa = LsaSummary {
            area_id: "0.0.0.0".parse().unwrap(),
            lsa_type: 1,
            link_state_id: "1.1.1.1".parse().unwrap(),
            advertising_router: "1.1.1.1".parse().unwrap(),
            sequence_number: 0x8000_0001u32.cast_signed(),
            age: 42,
            checksum: 0xabcd,
        };
        assert_eq!(
            render_ospf_database("o1", &[lsa]),
            "ospf instance o1:\n  area 0.0.0.0 type 1 link-state-id 1.1.1.1 \
             advertising-router 1.1.1.1 sequence 0x80000001 age 42 checksum 0xabcd"
        );
    }

    #[test]
    fn render_interface_shows_lldp_flags() {
        let mut iface = Interface {
            name: "eth1".to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: None,
            lldp_transmit: true,
            lldp_receive: false,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: Vec::new(),
        };
        assert!(render_interface(&iface).ends_with("lldp-transmit on, lldp-receive off"));
        iface.lldp_receive = true;
        assert!(render_interface(&iface).ends_with("lldp-transmit on, lldp-receive on"));
    }

    #[test]
    fn render_lldp_neighbors_empty_and_populated() {
        assert_eq!(render_lldp_neighbors(&[]), "no lldp neighbors");
        let neighbor = nos_proto::LldpNeighbor {
            local_interface: "eth1".to_string(),
            chassis_id: "02:00:00:00:00:02".to_string(),
            port_id: "eth1".to_string(),
            port_description: Some("uplink".to_string()),
            system_name: Some("router-b".to_string()),
            system_description: None,
            capabilities: vec!["router".to_string()],
            management_addresses: Vec::new(),
            ttl_remaining_secs: 117,
        };
        assert_eq!(
            render_lldp_neighbors(std::slice::from_ref(&neighbor)),
            "eth1: neighbor router-b, chassis 02:00:00:00:00:02, port eth1 (uplink), capabilities router, ttl 117s"
        );
        let with_mgmt = nos_proto::LldpNeighbor {
            management_addresses: vec!["10.0.0.2".to_string(), "2001:db8::2".to_string()],
            ..neighbor
        };
        assert!(render_lldp_neighbors(&[with_mgmt])
            .contains("capabilities router, management 10.0.0.2,2001:db8::2, ttl 117s"));
    }

    #[test]
    fn lldp_settings_and_destination_render_only_when_set() {
        let mut cfg = Config::default();
        assert!(!render_config(&cfg).contains("lldp"));
        cfg.lldp.tx_interval_secs = Some(5);
        cfg.lldp.management_address = Some("10.0.0.1".parse().unwrap());
        assert!(render_config(&cfg)
            .contains("lldp: tx-interval 5, tx-hold default, management-address 10.0.0.1"));

        let mut iface = nos_proto::Interface {
            name: "eth1".to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: None,
            lldp_transmit: true,
            lldp_receive: true,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: Vec::new(),
        };
        assert!(!render_interface(&iface).contains("lldp-destination"));
        iface.lldp_destination = nos_proto::LldpDestination::NonTpmr;
        assert!(render_interface(&iface).ends_with("lldp-receive on, lldp-destination non-tpmr"));
    }

    #[test]
    fn render_lacp_summaries_empty() {
        assert_eq!(render_lacp_summaries(&[]), "no lacp port aggregates");
    }

    #[test]
    fn render_lacp_summaries_shows_identity_rate_and_each_port() {
        let summary = PortAggregateLacpSummary {
            aggregate: "bond1".to_string(),
            actor_system_id: [2, 0, 0, 0, 0, 0xab],
            actor_key: 7,
            rate: LacpRate::Fast,
            ports: vec![
                nos_proto::LacpPortStatus {
                    interface: "eth1".to_string(),
                    actor_port_number: 4,
                    receive_state: LacpReceiveState::Current,
                    mux_state: LacpMuxState::Distributing,
                    partner_system_id: Some([2, 0, 0, 0, 0, 1]),
                    partner_key: Some(3),
                    partner_port_number: Some(9),
                    selected: true,
                    synchronized: true,
                },
                nos_proto::LacpPortStatus {
                    interface: "eth2".to_string(),
                    actor_port_number: 5,
                    receive_state: LacpReceiveState::Defaulted,
                    mux_state: LacpMuxState::Detached,
                    partner_system_id: None,
                    partner_key: None,
                    partner_port_number: None,
                    selected: false,
                    synchronized: false,
                },
            ],
        };
        let out = render_lacp_summaries(&[summary]);
        assert!(out.contains("lacp bond1: system 02:00:00:00:00:ab, key 7, rate fast"));
        assert!(out.contains("eth1: port 4, receive current, mux distributing, partner 02:00:00:00:00:01 key 3 port 9, selected yes, synchronized yes"));
        assert!(out.contains("eth2: port 5, receive defaulted, mux detached, partner none, selected no, synchronized no"));
    }

    #[test]
    fn render_config_shows_user_names_but_never_the_password() {
        let config = Config {
            users: vec![nos_proto::User {
                name: "alice".to_string(),
                password: "$argon2id$secret-hash".to_string(),
            }],
            ..Config::default()
        };
        let text = render_config(&config);
        assert!(text.contains("user alice"));
        assert!(!text.contains("argon2id") && !text.contains("secret-hash"));
    }

    #[test]
    fn fdb_table_lists_local_remote_and_flood() {
        let t = nos_proto::FdbTable {
            domain: "bd1".to_string(),
            vni: 10100,
            bridge: Some("br1".to_string()),
            vxlan: Some("vx10100".to_string()),
            macs: vec![
                nos_proto::MacEntry {
                    mac: "02:00:00:00:00:01".to_string(),
                    source: nos_proto::MacSource::Local,
                    vtep: None,
                    vteps: Vec::new(),
                    esi: Some("00:11:22:33:44:55:66:77:88:99".to_string()),
                },
                nos_proto::MacEntry {
                    mac: "02:00:00:00:00:09".to_string(),
                    source: nos_proto::MacSource::Remote,
                    vtep: Some("192.0.2.9".parse().unwrap()),
                    vteps: vec!["192.0.2.9".parse().unwrap()],
                    esi: None,
                },
                nos_proto::MacEntry {
                    mac: "02:00:00:00:00:0a".to_string(),
                    source: nos_proto::MacSource::Remote,
                    vtep: Some("192.0.2.9".parse().unwrap()),
                    vteps: vec!["192.0.2.9".parse().unwrap(), "192.0.2.10".parse().unwrap()],
                    esi: None,
                },
            ],
            neighbours: vec![
                nos_proto::NeighEntry {
                    ip: "198.51.100.7".parse().unwrap(),
                    mac: "02:00:00:00:00:01".to_string(),
                    source: nos_proto::MacSource::Local,
                    vtep: None,
                },
                nos_proto::NeighEntry {
                    ip: "192.0.2.10".parse().unwrap(),
                    mac: "02:00:00:00:00:09".to_string(),
                    source: nos_proto::MacSource::Remote,
                    vtep: Some("192.0.2.9".parse().unwrap()),
                },
            ],
            flood: vec!["192.0.2.9".parse().unwrap()],
            segments: vec![nos_proto::EsEntry {
                esi: "00:11:22:33:44:55:66:77:88:99".to_string(),
                port: "bond1".to_string(),
                designated_forwarder: false,
                pes: vec!["192.0.2.1".parse().unwrap(), "192.0.2.9".parse().unwrap()],
                ad_pes: vec!["192.0.2.9".parse().unwrap()],
                up: true,
                single_active: false,
            }],
        };
        assert_eq!(
            render_fdb_table(&t),
            "broadcast-domain bd1: vni 10100, bridge br1, vxlan vx10100\n  \
             02:00:00:00:00:01 local, esi 00:11:22:33:44:55:66:77:88:99\n  \
             02:00:00:00:00:09 remote via 192.0.2.9\n  \
             02:00:00:00:00:0a remote via 192.0.2.9, 192.0.2.10 (aliased)\n  \
             198.51.100.7 is at 02:00:00:00:00:01 local\n  \
             192.0.2.10 is at 02:00:00:00:00:09 remote via 192.0.2.9\n  \
             flood list: 192.0.2.9\n  \
             ethernet-segment 00:11:22:33:44:55:66:77:88:99 on bond1: non-designated \
             forwarder, BUM blocked (PEs 192.0.2.1, 192.0.2.9), per-ES A-D from 192.0.2.9"
        );
        // Single-active says so, and a blocked non-DF is a blocked port.
        let mut sa = t.clone();
        sa.segments[0].single_active = true;
        assert!(render_fdb_table(&sa).ends_with(
            "non-designated forwarder, port blocked (PEs 192.0.2.1, 192.0.2.9), \
             per-ES A-D from 192.0.2.9, single-active"
        ));
        // A segment without carrier says so instead of naming a role.
        let mut down = t.clone();
        down.segments[0].up = false;
        down.segments[0].ad_pes.clear();
        assert!(render_fdb_table(&down).ends_with(
            "ethernet-segment 00:11:22:33:44:55:66:77:88:99 on bond1: down, no carrier \
             (PEs 192.0.2.1, 192.0.2.9)"
        ));
    }
}
