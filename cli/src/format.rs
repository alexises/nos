use std::fmt::Write as _;
use std::net::Ipv4Addr;

use chrono::{DateTime, SecondsFormat, Utc};
use nos_proto::{
    AddressFamily, AsPathList, BgpAoAlgorithm, BgpAuth, BgpInstance, BgpPeer, BgpPeerGroup,
    BgpSessionState, BgpShutdown, BroadcastDomain, CommunityAlias, CommunityGroup, Config,
    ConfigDiff, DiffStatus, EvpnRouteSummary, FieldDiff, Interface, InterfaceAddress,
    InterfaceStatus, LacpMuxState, LacpRate, LacpReceiveState, LinkInterfaceState, LogEntry,
    LogLevel, LsaSummary, NeighborSummary, NextHopMode, OspfArea, OspfAuth, OspfCryptoAlgorithm,
    OspfInstance, OspfNeighborState, OspfProfile, Ospfv3Area, Ospfv3Instance, Ospfv3LsaSummary,
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
        None if group.route_server_client => "default (unchanged, route-server)".to_string(),
        None => "default (self, eBGP)".to_string(),
    };
    let policy = |p: &Option<String>| p.clone().unwrap_or_else(|| "default (deny-all)".into());
    let mut line = format!(
        "peer-group {}: remote-as {}, source-address {source_address}, address-family [{address_families}], \
         hold-time {hold_time}, keepalive-interval {keepalive_interval}, connect-retry-time {connect_retry_time}, \
         auth {auth}, next-hop {next_hop}, import-policy {}, export-policy {}",
        group.name,
        group.remote_as,
        policy(&group.import_policy),
        policy(&group.export_policy),
    );
    line.push_str(
        &group
            .mrai
            .map_or_else(String::new, |m| format!(", mrai {m}")),
    );
    line.push_str(
        &group
            .max_hops
            .map_or_else(String::new, |h| format!(", max-hops {h}")),
    );
    line.push_str(&render_shutdown(group.shutdown.as_ref()));
    if let Some(d) = group.damping {
        let _ = write!(
            line,
            ", damping half-life {} reuse {} suppress {} max-suppress {}",
            d.half_life, d.reuse, d.suppress, d.max_suppress
        );
    }
    for af in nos_proto::AddressFamily::ALL {
        if let Some(l) = group.maximum_prefix.get(af) {
            let _ = write!(line, ", maximum-prefix {af} limit {}", l.limit);
            if l.warning_only {
                line.push_str(" warning-only");
            }
            if l.restart_interval > 0 {
                let _ = write!(line, " restart-interval {}", l.restart_interval);
            }
        }
    }
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
                    let mut tags = Vec::new();
                    if k.is_current {
                        tags.push("current");
                    }
                    if k.is_rnext {
                        tags.push("rnext");
                    }
                    if k.exclude_options {
                        tags.push("exclude-options");
                    }
                    let flags = if tags.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", tags.join(", "))
                    };
                    format!("send-id {} {algorithm} {}{flags}", k.send_id, k.key)
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("ao-keys [{rendered}]")
        }
    }
}

/// `, shutdown` / `, shutdown "<message>"`, or nothing when unset.
fn render_shutdown(shutdown: Option<&BgpShutdown>) -> String {
    match shutdown {
        None => String::new(),
        Some(BgpShutdown { message: None }) => ", shutdown".to_string(),
        Some(BgpShutdown { message: Some(m) }) => format!(", shutdown \"{m}\""),
    }
}

/// Render one peer as human-readable text.
pub fn render_bgp_peer(peer: &BgpPeer) -> String {
    format!(
        "peer {}: peer-group {}{}",
        peer.remote_address,
        peer.peer_group,
        render_shutdown(peer.shutdown.as_ref())
    )
}

/// Render one BGP instance as human-readable text, including any nested
/// peer-groups and peers, each indented one level under the instance line.
pub fn render_bgp_instance(instance: &BgpInstance) -> String {
    let cluster_id = instance
        .cluster_id
        .map_or_else(|| "default (= router-id)".to_string(), |c| c.to_string());
    let c = &instance.confederation;
    let confederation = c.identifier.map_or_else(String::new, |id| {
        let peers: Vec<String> = c.peers.iter().map(u32::to_string).collect();
        format!(", confederation {id} peers [{}]", peers.join(", "))
    });
    let mut lines = vec![format!(
        "bgp instance {}: router-id {}, asn {}, cluster-id {cluster_id}{confederation}",
        instance.name, instance.router_id, instance.asn
    )];
    for group in &instance.peer_groups {
        lines.push(format!("  {}", render_bgp_peer_group(group, instance.asn)));
    }
    for peer in &instance.peers {
        lines.push(format!("  {}", render_bgp_peer(peer)));
    }
    for c in &instance.rpki_caches {
        lines.push(format!(
            "  rpki-cache {} port {} preference {}",
            c.address, c.port, c.preference
        ));
    }
    lines.join("\n")
}

/// Render one OSPF instance as human-readable text, including any nested
/// areas (and each area's nested profiles), indented one/two levels under
/// the instance line — mirrors `render_interface`'s nested subinterfaces.
pub fn render_ospf_instance(instance: &OspfInstance) -> String {
    let mut lines = vec![format!(
        "ospf instance {}: router-id {}{}",
        instance.name,
        instance.router_id,
        instance
            .graceful_restart_grace_period
            .map_or(String::new(), |p| format!(
                ", graceful-restart grace-period {p}"
            ))
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
    let extended = if profile.extended_sequence_numbers {
        " extended-sequence-numbers"
    } else {
        ""
    };
    format!(
        "profile {}: auth {}{extended}",
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
        "ospfv3 instance {}: router-id {}{}{}",
        instance.name,
        instance.router_id,
        if instance.extended_lsa {
            ", extended-lsa"
        } else {
            ""
        },
        instance
            .graceful_restart_grace_period
            .map_or(String::new(), |p| format!(
                ", graceful-restart grace-period {p}"
            ))
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
    let auth = profile
        .auth
        .as_ref()
        .map(|keys| OspfAuth::Crypto { keys: keys.clone() });
    format!(
        "profile {}: auth {}",
        profile.name,
        render_ospf_auth(auth.as_ref())
    )
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
    let df_algorithm = match agg.df_algorithm {
        nos_proto::DfAlgorithm::Modulo => "",
        nos_proto::DfAlgorithm::Hrw => ", df-algorithm hrw",
    };
    let mut lines = vec![format!(
        "port-aggregate {}: mode {:?}, switching-profile {switching_profile}, mtu {mtu}{esi}{redundancy}{df_algorithm}{system_id}",
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
        "  {}: port {}, receive {receive}, mux {mux}, {partner}, selected {}, synchronized {}, churn {}",
        port.interface,
        port.actor_port_number,
        yes_no(port.selected),
        yes_no(port.synchronized),
        match (port.actor_churn, port.partner_churn) {
            (false, false) => "none",
            (true, false) => "actor",
            (false, true) => "partner",
            (true, true) => "actor+partner",
        },
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
        RouteSourceKind::Connected => "connected",
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
            let via = candidate
                .gateways
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!(
                "  {marker} via {via} [{}]{backup}",
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
        let ao = match (peer.ao_current_key, peer.ao_rnext_key) {
            (Some(current), Some(rnext)) => format!(
                " ao-current {current} ao-rnext {rnext} ao-good {} ao-bad {} ao-no-key {}",
                peer.ao_packets_good.unwrap_or(0),
                peer.ao_packets_bad.unwrap_or(0),
                peer.ao_packets_key_not_found.unwrap_or(0),
            ),
            _ => String::new(),
        };
        let mut counts = String::new();
        for (af, n) in ["v4", "v6", "evpn"]
            .iter()
            .zip(peer.accepted_prefixes.unwrap_or_default())
        {
            if n > 0 {
                let _ = write!(counts, " {af} {n}");
            }
        }
        let prefixes = if counts.is_empty() {
            String::new()
        } else {
            format!(" prefixes{counts}")
        };
        lines.push(format!(
            "  {} AS {remote_as} peer-group {} {} uptime {uptime} hold-time {hold_time}{ao}{}",
            peer.remote_address,
            peer.peer_group,
            if peer.shutdown {
                "Idle (shutdown)"
            } else if peer.max_prefix_held {
                "Idle (max-prefix)"
            } else {
                render_bgp_session_state(peer.state)
            },
            prefixes,
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

/// One BGP instance's RPKI caches, one line each — `show bgp rpki`.
pub fn render_bgp_rpki(instance: &str, caches: &[nos_proto::RpkiCacheStatus]) -> String {
    if caches.is_empty() {
        return format!("bgp instance {instance}: no rpki caches");
    }
    let opt = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());
    let mut lines = vec![format!("bgp instance {instance}:")];
    for c in caches {
        lines.push(format!(
            "  {} port {} preference {} {:?}{} version {} session {} serial {} vrps {} updated {}",
            c.address,
            c.port,
            c.preference,
            c.state,
            if c.active { " (in use)" } else { "" },
            opt(c.version.map(|v| v.to_string())),
            opt(c.session_id.map(|v| v.to_string())),
            opt(c.serial.map(|v| v.to_string())),
            c.vrp_count,
            opt(c.last_update_secs.map(|s| format!("{s}s ago"))),
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
             sequence 0x{:08x} age {} checksum 0x{:04x} link {}",
            lsa.area_id,
            lsa.lsa_type,
            lsa.link_state_id,
            lsa.advertising_router,
            lsa.sequence_number,
            lsa.age,
            lsa.checksum,
            lsa.link.as_deref().unwrap_or("-"),
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
    if config.policy_definitions.is_empty() {
        lines.push("no policy definitions configured".to_string());
    } else {
        lines.extend(
            config
                .policy_definitions
                .iter()
                .map(render_policy_definition),
        );
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
    if config.as_path_lists.is_empty() {
        lines.push("no as-path lists configured".to_string());
    } else {
        lines.extend(config.as_path_lists.iter().map(render_as_path_list));
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
/// navigation position: the whole config at the root, else the object the
/// position names.
pub fn render_transaction(snapshot: &TransactionSnapshot, path: &Path) -> String {
    fn show<T>(item: Option<&T>, render: impl Fn(&T) -> String) -> String {
        item.map_or_else(|| "nothing configured here".to_string(), render)
    }
    let cfg = &snapshot.config;
    let segs: Vec<&str> = path.segments().iter().map(String::as_str).collect();
    let find = |name: &str, n: &String| n == name;
    let ospf_area = |i: &str, a: &str| {
        cfg.ospf_instances
            .iter()
            .find(|x| x.name == i)
            .and_then(|x| x.areas.iter().find(|y| y.area_id.to_string() == a))
    };
    let ospfv3_area = |i: &str, a: &str| {
        cfg.ospfv3_instances
            .iter()
            .find(|x| x.name == i)
            .and_then(|x| x.areas.iter().find(|y| y.area_id.to_string() == a))
    };
    match segs.as_slice() {
        [] => {
            let header = if snapshot.dirty {
                format!("transaction '{}' (uncommitted changes):", snapshot.name)
            } else {
                format!("transaction '{}':", snapshot.name)
            };
            format!("{header}\n{}", render_config(cfg))
        }
        ["bgp-instance", i] => show(
            cfg.bgp_instances.iter().find(|x| find(i, &x.name)),
            render_bgp_instance,
        ),
        ["bgp-instance", i, "peer-group", g] => {
            let inst = cfg.bgp_instances.iter().find(|x| find(i, &x.name));
            inst.and_then(|x| {
                x.peer_groups
                    .iter()
                    .find(|y| find(g, &y.name))
                    .map(|y| (y, x.asn))
            })
            .map_or_else(
                || "nothing configured here".to_string(),
                |(y, asn)| render_bgp_peer_group(y, asn),
            )
        }
        ["routing-table", n] => show(
            cfg.routing_tables.iter().find(|x| find(n, &x.name)),
            render_routing_table,
        ),
        ["ospf-instance", n] => show(
            cfg.ospf_instances.iter().find(|x| find(n, &x.name)),
            render_ospf_instance,
        ),
        ["ospf-instance", i, "area", a] => show(ospf_area(i, a), render_ospf_area),
        ["ospf-instance", i, "area", a, "profile", p] => show(
            ospf_area(i, a).and_then(|x| x.profiles.iter().find(|y| find(p, &y.name))),
            render_ospf_profile,
        ),
        ["ospfv3-instance", n] => show(
            cfg.ospfv3_instances.iter().find(|x| find(n, &x.name)),
            render_ospfv3_instance,
        ),
        ["ospfv3-instance", i, "area", a] => show(ospfv3_area(i, a), render_ospfv3_area),
        ["ospfv3-instance", i, "area", a, "profile", p] => show(
            ospfv3_area(i, a).and_then(|x| x.profiles.iter().find(|y| find(p, &y.name))),
            render_ospfv3_profile,
        ),
        ["static-routing-instance", n] => show(
            cfg.static_routing_instances
                .iter()
                .find(|x| find(n, &x.name)),
            render_static_routing_instance,
        ),
        ["interface", n] => show(
            cfg.interfaces.iter().find(|x| find(n, &x.name)),
            render_interface,
        ),
        ["interface", n, "subinterface", t] => show(
            cfg.interfaces
                .iter()
                .find(|x| find(n, &x.name))
                .and_then(|x| x.subinterfaces.iter().find(|y| y.tag.to_string() == *t)),
            render_subinterface,
        ),
        ["policy-definition", n] => show(
            cfg.policy_definitions.iter().find(|x| find(n, &x.name)),
            render_policy_definition,
        ),
        ["community-alias", n] => show(
            cfg.community_aliases.iter().find(|x| find(n, &x.name)),
            render_community_alias,
        ),
        ["community-group", n] => show(
            cfg.community_groups.iter().find(|x| find(n, &x.name)),
            render_community_group,
        ),
        ["as-path-list", n] => show(
            cfg.as_path_lists.iter().find(|x| find(n, &x.name)),
            render_as_path_list,
        ),
        ["prefix-list", n] => show(
            cfg.prefix_lists.iter().find(|x| find(n, &x.name)),
            render_prefix_list,
        ),
        ["broadcast-domain", n] => show(
            cfg.broadcast_domains.iter().find(|x| find(n, &x.name)),
            render_broadcast_domain,
        ),
        ["switching-profile", n] => show(
            cfg.switching_profiles.iter().find(|x| find(n, &x.name)),
            render_switching_profile,
        ),
        ["port-aggregate", n] => show(
            cfg.port_aggregates.iter().find(|x| find(n, &x.name)),
            render_port_aggregate,
        ),
        // A position with no dedicated renderer (e.g. a user, a peer): its
        // own JSON, which is what `set` edits there anyway.
        _ => serde_json::to_value(cfg)
            .ok()
            .and_then(|doc| {
                nos_proto::config_path::get(&doc, path.segments())
                    .ok()
                    .cloned()
            })
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or_else(|| "nothing configured here".to_string()),
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

/// Render one as-path-list as human-readable text.
pub fn render_as_path_list(list: &AsPathList) -> String {
    let patterns = if list.patterns.is_empty() {
        "none".to_string()
    } else {
        list.patterns.join(", ")
    };
    format!("as-path-list {}: patterns [{patterns}]", list.name)
}

/// Render one `PrefixListEntry` the same way for every caller — `<cidr>` for
/// an exact-match entry, `<cidr> orlonger`/`<cidr> upto <max>` when the range starts at the
/// cidr's own length, `<cidr> range(<min>,<max>)` otherwise.
pub fn render_prefix_list_entry(entry: &PrefixListEntry) -> String {
    match entry.range {
        None => entry.cidr.to_string(),
        Some((min, max))
            if min == entry.cidr.prefix_len() && max == entry.cidr.max_prefix_len() =>
        {
            format!("{} orlonger", entry.cidr)
        }
        Some((min, max)) if min == entry.cidr.prefix_len() => {
            format!("{} upto {max}", entry.cidr)
        }
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
        "broadcast-domain {}: vni {}, bridge {}, vxlan {}, neigh-suppress {}",
        t.domain,
        t.vni,
        dev(&t.bridge),
        dev(&t.vxlan),
        if t.neigh_suppress { "on" } else { "off" }
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
            "  ethernet-segment {} on {}: {} (PEs {}){}{}{}",
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
            },
            match e.df_algorithm {
                nos_proto::DfAlgorithm::Modulo => "",
                nos_proto::DfAlgorithm::Hrw => ", df-algorithm hrw",
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
            ", vni {vni}, rd {}, rt-import [{}], rt-export [{}], vtep-source {}, redistribute-mac {}, redistribute-arp {}, redistribute-connected {}, neigh-suppress {}",
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
            if domain.neigh_suppress { "on" } else { "off" },
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
    // No `..`: a new `ConfigDiff` section is a compile error here, not a
    // silently missing part of `diff`.
    let ConfigDiff {
        hostname,
        bgp_instances,
        routing_tables,
        ospf_instances,
        ospfv3_instances,
        static_routing_instances,
        interfaces,
        policy_definitions,
        community_aliases,
        community_groups,
        as_path_lists,
        prefix_lists,
        broadcast_domains,
        switching_profiles,
        port_aggregates,
        lldp,
        users,
    } = diff;
    let mut lines = Vec::new();

    if let Some(field) = hostname {
        render_field_diff(&mut lines, field, "", color);
    }
    for field in lldp {
        render_field_diff(&mut lines, field, "", color);
    }

    for sections in [
        users,
        bgp_instances,
        routing_tables,
        ospf_instances,
        ospfv3_instances,
        static_routing_instances,
        interfaces,
        port_aggregates,
        broadcast_domains,
        switching_profiles,
        policy_definitions,
        community_aliases,
        community_groups,
        as_path_lists,
        prefix_lists,
    ] {
        for section in sections {
            render_section(&mut lines, section, 0, color);
        }
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

/// Marks every line of `text`, so a multi-line value (a policy's source)
/// stays readable as part of the diff.
fn styled_line(marker: char, code: &str, text: &str, color: bool) -> String {
    // Callers always pass at least a label, so `lines()` is never empty.
    text.lines()
        .map(|line| {
            if color {
                format!("{marker} {code}{line}{RESET}")
            } else {
                format!("{marker} {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
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

    #[test]
    fn ecmp_route_renders_every_gateway_on_one_line() {
        let routes = [PrefixRoutes {
            prefix: "203.0.113.80/32".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.0.0.2".parse().unwrap(), "10.0.1.2".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Ospf,
                backup: Some("10.0.1.3".parse().unwrap()),
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "203.0.113.80/32\n  * via 10.0.0.2, 10.0.1.2 [ospf] backup 10.0.1.3"
        );
    }

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            confederation: nos_proto::BgpConfederation::default(),
            rpki_caches: Vec::new(),
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
             no policy definitions configured\nno community aliases configured\nno community groups configured\nno as-path lists configured\nno prefix lists configured\n\
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
             no policy definitions configured\nno community aliases configured\nno community groups configured\nno as-path lists configured\nno prefix lists configured\n\
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
             no policy definitions configured\nno community aliases configured\nno community groups configured\nno as-path lists configured\nno prefix lists configured\n\
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
            generation: 0,
        }
    }

    #[test]
    fn render_transaction_at_root_clean() {
        let rendered = render_transaction(&snapshot(false), &Path::root());
        assert_eq!(
            rendered,
            "transaction 'demo':\nhostname: nos\nbgp instance r1: router-id 1.1.1.1, asn 65001, cluster-id default (= router-id)\n\
             no routing tables configured\nno OSPF instances configured\nno OSPFv3 instances configured\nno static routing instances configured\n\
             no interfaces configured\n\
             no policy definitions configured\nno community aliases configured\nno community groups configured\nno as-path lists configured\nno prefix lists configured\n\
             no broadcast domains configured\nno switching profiles configured\n\
             no port aggregates configured"
        );
    }

    #[test]
    fn render_transaction_at_root_dirty() {
        let rendered = render_transaction(&snapshot(true), &Path::root());
        assert!(rendered.starts_with("transaction 'demo' (uncommitted changes):"));
    }

    #[test]
    fn render_transaction_at_bgp_instance_found() {
        let rendered = render_transaction(
            &snapshot(false),
            &Path::from(vec!["bgp-instance".to_string(), "r1".to_string()]),
        );
        assert_eq!(
            rendered,
            "bgp instance r1: router-id 1.1.1.1, asn 65001, cluster-id default (= router-id)"
        );
    }

    #[test]
    fn render_transaction_at_bgp_instance_not_found() {
        let rendered = render_transaction(
            &snapshot(false),
            &Path::from(vec!["bgp-instance".to_string(), "r2".to_string()]),
        );
        assert_eq!(rendered, "nothing configured here");
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
            &Path::from(vec![
                "interface".to_string(),
                "eth0".to_string(),
                "subinterface".to_string(),
                "100".to_string(),
            ]),
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
            &Path::from(vec![
                "interface".to_string(),
                "eth0".to_string(),
                "subinterface".to_string(),
                "100".to_string(),
            ]),
        );
        assert_eq!(rendered, "nothing configured here");
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
    fn render_diff_shows_l2_and_policy_sections() {
        let base = nos_proto::Config::default();
        let mut candidate = base.clone();
        candidate
            .broadcast_domains
            .push(nos_proto::BroadcastDomain {
                name: "blue".into(),
                ..Default::default()
            });
        candidate
            .switching_profiles
            .push(nos_proto::SwitchingProfile {
                name: "trunk".into(),
                ..Default::default()
            });
        candidate
            .policy_definitions
            .push(nos_proto::PolicyDefinition {
                name: "p1".into(),
                source: "if this.prefix in 10.0.0.0/8:\n    reject\naccept\n".into(),
            });
        let out = render_diff(&nos_proto::diff_configs(&base, &candidate), false);
        for want in [
            "+ broadcast-domain blue:",
            "+ switching-profile trunk:",
            "+ policy-definition p1:",
            "+   source: if this.prefix in 10.0.0.0/8:\n+     reject\n+ accept",
        ] {
            assert!(out.contains(want), "{want:?} missing from:\n{out}");
        }
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
            mrai: None,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
            shutdown: None,
            maximum_prefix: nos_proto::BgpMaximumPrefix::default(),
        }
    }

    #[test]
    fn render_bgp_peer_group_line() {
        assert_eq!(
            render_bgp_peer_group(&peer_group("pg1"), 65000),
            "peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), auth none, next-hop default (self, eBGP), \
             import-policy default (deny-all), export-policy default (deny-all)"
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
             connect-retry-time default (120s), auth none, next-hop default (self, eBGP), \
             import-policy default (deny-all), export-policy default (deny-all)"
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
             next-hop default (self, eBGP), \
             import-policy default (deny-all), export-policy default (deny-all)"
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
             next-hop default (self, eBGP), \
             import-policy default (deny-all), export-policy default (deny-all)"
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
                exclude_options: true,
            }],
        });
        assert_eq!(
            render_bgp_peer_group(&pg, 65000),
            "peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), \
             auth ao-keys [send-id 1 hmac-sha1 secret (current, exclude-options)], \
             next-hop default (self, eBGP), \
             import-policy default (deny-all), export-policy default (deny-all)"
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
    fn render_bgp_peer_group_policies() {
        let mut pg = peer_group("pg1");
        pg.import_policy = Some("in".to_string());
        pg.export_policy = Some("out".to_string());
        assert!(render_bgp_peer_group(&pg, 65000).ends_with("import-policy in, export-policy out"));
    }

    #[test]
    fn render_bgp_peer_group_next_hop_route_server_default() {
        let mut pg = peer_group("pg1");
        pg.route_server_client = true;
        assert!(render_bgp_peer_group(&pg, 65000)
            .contains("next-hop default (unchanged, route-server)"));
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
            extended_sequence_numbers: false,
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
            shutdown: None,
        }];
        assert_eq!(
            render_bgp_instance(&inst),
            "bgp instance r1: router-id 1.1.1.1, asn 65000, cluster-id default (= router-id)\n  \
             peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), auth none, next-hop default (self, eBGP), \
             import-policy default (deny-all), export-policy default (deny-all)\n  \
             peer 192.0.2.1: peer-group pg1"
        );
    }

    #[test]
    fn render_transaction_at_peer_group_found() {
        let mut snap = snapshot(false);
        snap.config.bgp_instances[0].peer_groups = vec![peer_group("pg1")];
        let rendered = render_transaction(
            &snap,
            &Path::from(vec![
                "bgp-instance".to_string(),
                "r1".to_string(),
                "peer-group".to_string(),
                "pg1".to_string(),
            ]),
        );
        assert_eq!(
            rendered,
            "peer-group pg1: remote-as 65001, source-address interface eth0, address-family [ipv4], \
             hold-time default (90s), keepalive-interval default (hold-time / 3), \
             connect-retry-time default (120s), auth none, next-hop default (unchanged, iBGP), \
             import-policy default (deny-all), export-policy default (deny-all)"
        );
    }

    #[test]
    fn render_transaction_at_peer_group_not_found() {
        let rendered = render_transaction(
            &snapshot(false),
            &Path::from(vec![
                "bgp-instance".to_string(),
                "r1".to_string(),
                "peer-group".to_string(),
                "pg-missing".to_string(),
            ]),
        );
        assert_eq!(rendered, "nothing configured here");
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
            shutdown: false,
            ao_current_key: None,
            ao_rnext_key: None,
            ao_packets_good: None,
            ao_packets_bad: None,
            ao_packets_key_not_found: None,
            max_prefix_held: false,
            accepted_prefixes: None,
        }
    }

    #[test]
    fn render_bgp_summary_shows_max_prefix_hold_and_prefix_counts() {
        let mut held = idle_peer("10.0.0.1");
        held.max_prefix_held = true;
        let mut up = idle_peer("10.0.0.2");
        up.state = BgpSessionState::Established;
        up.accepted_prefixes = Some([3, 0, 2]);
        assert_eq!(
            render_bgp_summary("r1", &[held, up]),
            "bgp instance r1:\n  10.0.0.1 AS - peer-group pg1 Idle (max-prefix) uptime - hold-time -\n  \
             10.0.0.2 AS - peer-group pg1 Established uptime - hold-time - prefixes v4 3 evpn 2"
        );
    }

    #[test]
    fn render_bgp_rpki_lists_one_cache_per_line() {
        assert_eq!(
            render_bgp_rpki("r1", &[]),
            "bgp instance r1: no rpki caches"
        );
        let c = nos_proto::RpkiCacheStatus {
            address: "192.0.2.5".parse().unwrap(),
            port: 323,
            preference: 1,
            state: nos_proto::RpkiSessionState::Established,
            active: true,
            version: Some(1),
            session_id: Some(7),
            serial: Some(42),
            vrp_count: 3,
            last_update_secs: Some(5),
        };
        assert_eq!(
            render_bgp_rpki("r1", &[c]),
            "bgp instance r1:\n  192.0.2.5 port 323 preference 1 Established (in use) version 1 \
             session 7 serial 42 vrps 3 updated 5s ago"
        );
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

    #[test]
    fn render_bgp_summary_with_ao_info_appends_key_and_counters() {
        let mut peer = idle_peer("10.0.0.1");
        peer.remote_as = Some(65002);
        peer.state = BgpSessionState::Established;
        peer.uptime_secs = Some(5);
        peer.negotiated_hold_time = Some(90);
        peer.ao_current_key = Some(1);
        peer.ao_rnext_key = Some(2);
        peer.ao_packets_good = Some(42);
        peer.ao_packets_bad = Some(1);
        peer.ao_packets_key_not_found = Some(0);
        assert_eq!(
            render_bgp_summary("r1", &[peer]),
            "bgp instance r1:\n  10.0.0.1 AS 65002 peer-group pg1 Established uptime 00:00:05 \
             hold-time 90 ao-current 1 ao-rnext 2 ao-good 42 ao-bad 1 ao-no-key 0"
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
    fn render_config_shows_policy_definitions() {
        let cfg = Config {
            policy_definitions: vec![PolicyDefinition {
                name: "p1".to_string(),
                source: "accept\n".to_string(),
            }],
            ..Default::default()
        };
        assert!(render_config(&cfg).contains("policy-definition p1:\n   1  accept\n"));
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
                    actor_churn: false,
                    partner_churn: false,
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
                    actor_churn: false,
                    partner_churn: true,
                },
            ],
        };
        let out = render_lacp_summaries(&[summary]);
        assert!(out.contains("lacp bond1: system 02:00:00:00:00:ab, key 7, rate fast"));
        assert!(out.contains("eth1: port 4, receive current, mux distributing, partner 02:00:00:00:00:01 key 3 port 9, selected yes, synchronized yes"));
        assert!(out.contains("eth2: port 5, receive defaulted, mux detached, partner none, selected no, synchronized no, churn partner"));
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
                df_algorithm: nos_proto::DfAlgorithm::Modulo,
            }],
            neigh_suppress: true,
        };
        assert_eq!(
            render_fdb_table(&t),
            "broadcast-domain bd1: vni 10100, bridge br1, vxlan vx10100, neigh-suppress on\n  \
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
        // HRW in effect says so.
        let mut hrw = t.clone();
        hrw.segments[0].df_algorithm = nos_proto::DfAlgorithm::Hrw;
        assert!(render_fdb_table(&hrw).ends_with("192.0.2.9, df-algorithm hrw"));
        // A segment without carrier says so instead of naming a role.
        let mut down = t.clone();
        down.segments[0].up = false;
        down.segments[0].ad_pes.clear();
        assert!(render_fdb_table(&down).ends_with(
            "ethernet-segment 00:11:22:33:44:55:66:77:88:99 on bond1: down, no carrier \
             (PEs 192.0.2.1, 192.0.2.9)"
        ));
    }

    fn crypto_key(
        key_id: u16,
        algorithm: OspfCryptoAlgorithm,
        current: bool,
    ) -> nos_proto::OspfCryptoKey {
        nos_proto::OspfCryptoKey {
            key_id,
            algorithm,
            key: "k".to_string(),
            is_current: current,
        }
    }

    fn addr(a: &str, label: Option<&str>) -> InterfaceAddress {
        InterfaceAddress {
            address: a.parse().unwrap(),
            label: label.map(str::to_string),
        }
    }

    /// One of everything `render_config`/`render_transaction` have a line for.
    fn full_config() -> Config {
        let area = |id: &str| id.parse::<Ipv4Addr>().unwrap();
        Config {
            bgp_instances: vec![BgpInstance {
                peers: vec![BgpPeer {
                    remote_address: "192.0.2.2".parse().unwrap(),
                    peer_group: "pg".to_string(),
                    shutdown: Some(BgpShutdown { message: None }),
                }],
                peer_groups: vec![BgpPeerGroup {
                    name: "pg".to_string(),
                    remote_as: 65002,
                    ..Default::default()
                }],
                cluster_id: Some(Ipv4Addr::new(9, 9, 9, 9)),
                confederation: nos_proto::BgpConfederation::default(),
                rpki_caches: Vec::new(),
                ..instance("r1", 65001)
            }],
            routing_tables: vec![RoutingTable {
                name: "rt1".to_string(),
                bgp_instance: Some("r1".to_string()),
                redistribute: Some(nos_proto::Redistribute {
                    from: nos_proto::RedistributeSource::Static,
                    to: nos_proto::RedistributeTarget::Bgp,
                    policy: Some("p1".to_string()),
                }),
                rest_api: Some(nos_proto::RestApi {
                    address: "10.0.0.1".parse().unwrap(),
                    port: 443,
                }),
                ..Default::default()
            }],
            ospf_instances: vec![OspfInstance {
                name: "o1".to_string(),
                router_id: Ipv4Addr::new(1, 1, 1, 1),
                areas: vec![OspfArea {
                    area_id: area("0.0.0.0"),
                    profiles: vec![OspfProfile {
                        name: "op".to_string(),
                        extended_sequence_numbers: true,
                        auth: Some(OspfAuth::Crypto {
                            keys: vec![
                                crypto_key(1, OspfCryptoAlgorithm::Md5, false),
                                crypto_key(2, OspfCryptoAlgorithm::HmacSha1, false),
                                crypto_key(3, OspfCryptoAlgorithm::HmacSha384, false),
                                crypto_key(4, OspfCryptoAlgorithm::HmacSha512, true),
                            ],
                        }),
                        ..Default::default()
                    }],
                }],
                routing_table: None,
                redistribute_policy: None,
                graceful_restart_grace_period: None,
            }],
            ospfv3_instances: vec![Ospfv3Instance {
                name: "v3".to_string(),
                router_id: Ipv4Addr::new(2, 2, 2, 2),
                areas: vec![Ospfv3Area {
                    area_id: area("0.0.0.1"),
                    profiles: vec![Ospfv3Profile {
                        name: "p3".to_string(),
                        auth: Some(vec![crypto_key(300, OspfCryptoAlgorithm::HmacSha256, true)]),
                        ..Default::default()
                    }],
                }],
                routing_table: None,
                extended_lsa: true,
                graceful_restart_grace_period: Some(120),
            }],
            static_routing_instances: vec![StaticRoutingInstance {
                name: "s1".to_string(),
                routes: vec![StaticRoute {
                    subnet: "203.0.113.0/24".parse().unwrap(),
                    gateway: "10.0.0.2".parse().unwrap(),
                }],
            }],
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                subinterfaces: vec![Subinterface {
                    tag: 0,
                    addresses: vec![addr("10.0.0.1/24", Some("peering"))],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            community_aliases: vec![CommunityAlias {
                name: "blackhole".to_string(),
                value: "65535:666".to_string(),
            }],
            community_groups: vec![
                CommunityGroup {
                    name: "g".to_string(),
                    members: vec!["blackhole".to_string(), "65000:1".to_string()],
                },
                CommunityGroup {
                    name: "empty".to_string(),
                    members: Vec::new(),
                },
            ],
            as_path_lists: vec![
                AsPathList {
                    name: "a".to_string(),
                    patterns: vec!["^65001_".to_string()],
                },
                AsPathList {
                    name: "none".to_string(),
                    patterns: Vec::new(),
                },
            ],
            prefix_lists: vec![
                PrefixList {
                    name: "pl".to_string(),
                    entries: [None, Some((8, 32)), Some((8, 24)), Some((16, 24))]
                        .into_iter()
                        .map(|range| PrefixListEntry {
                            cidr: "10.0.0.0/8".parse().unwrap(),
                            range,
                        })
                        .collect(),
                },
                PrefixList {
                    name: "empty".to_string(),
                    entries: Vec::new(),
                },
            ],
            broadcast_domains: vec![
                BroadcastDomain {
                    name: "bd1".to_string(),
                    addresses: vec![addr("10.1.0.1/24", None)],
                    routing_table: Some("rt1".to_string()),
                    vni: Some(10100),
                    rd: Some("1.1.1.1:100".to_string()),
                    route_targets_import: vec!["65000:100".to_string()],
                    route_targets_export: vec!["65000:100".to_string(), "65000:101".to_string()],
                    vtep_source: Some(SourceAddress::Interface {
                        interface: "lo".to_string(),
                        label: None,
                    }),
                    mac_redistribute: Some("r1".to_string()),
                    ..Default::default()
                },
                BroadcastDomain {
                    name: "bd2".to_string(),
                    ..Default::default()
                },
            ],
            switching_profiles: vec![
                SwitchingProfile {
                    name: "trunk".to_string(),
                    members: vec![
                        nos_proto::SwitchingProfileMember {
                            broadcast_domain: "bd1".to_string(),
                            tag: VlanTag::Untagged,
                        },
                        nos_proto::SwitchingProfileMember {
                            broadcast_domain: "bd2".to_string(),
                            tag: VlanTag::Dot1q(200),
                        },
                    ],
                },
                SwitchingProfile {
                    name: "empty".to_string(),
                    members: Vec::new(),
                },
            ],
            port_aggregates: vec![PortAggregate {
                name: "bond1".to_string(),
                esi: Some("00:11:22:33:44:55:66:77:88:99".to_string()),
                redundancy_mode: nos_proto::EsRedundancy::SingleActive,
                df_algorithm: nos_proto::DfAlgorithm::default(),
                lacp_system_id: Some("02:00:00:00:00:01".to_string()),
                mtu: Some(9000),
                subinterfaces: vec![Subinterface {
                    tag: 10,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn render_config_covers_every_section() {
        let out = render_config(&full_config());
        for expected in [
            "bgp instance r1: router-id 1.1.1.1, asn 65001, cluster-id 9.9.9.9",
            "  peer 192.0.2.2: peer-group pg, shutdown",
            "routing-table rt1: bgp-instance r1, ospf-instance unset, static-routing-instance unset, \
             redistribute from static to bgp, policy p1, rest-api 10.0.0.1:443",
            "ospf instance o1: router-id 1.1.1.1\n  area 0.0.0.0\n    profile op: auth crypto-keys \
             [key-id 1 md5 k, key-id 2 hmac-sha1 k, key-id 3 hmac-sha384 k, key-id 4 hmac-sha512 k (current)] \
             extended-sequence-numbers",
            "ospfv3 instance v3: router-id 2.2.2.2, extended-lsa, graceful-restart grace-period 120\n  \
             area 0.0.0.1\n    profile p3: auth crypto-keys [key-id 300 hmac-sha256 k (current)]",
            "static-routing-instance s1\n  route 203.0.113.0/24: gateway 10.0.0.2",
            "  subinterface 0: address [10.0.0.1/24 (label peering)], routing-table unset, ospf-profile unset",
            "community-alias blackhole: value 65535:666",
            "community-group g: members [blackhole, 65000:1]",
            "community-group empty: members [none]",
            "as-path-list a: patterns [^65001_]",
            "as-path-list none: patterns [none]",
            "prefix-list pl: entries [10.0.0.0/8, 10.0.0.0/8 orlonger, 10.0.0.0/8 upto 24, 10.0.0.0/8 range(16,24)]",
            "prefix-list empty: entries [none]",
            "broadcast-domain bd1: address [10.1.0.1/24], routing-table rt1, ospf-profile unset, vni 10100, \
             rd 1.1.1.1:100, rt-import [65000:100], rt-export [65000:100,65000:101], vtep-source ",
            "redistribute-mac r1, redistribute-arp unset, redistribute-connected unset, neigh-suppress off",
            "broadcast-domain bd2: address [none], routing-table unset, ospf-profile unset\n",
            "switching-profile trunk: members [bd1: untagged, bd2: dot1q 200]",
            "switching-profile empty: members [none]",
            "port-aggregate bond1: mode Xor, switching-profile unset, mtu 9000, \
             esi 00:11:22:33:44:55:66:77:88:99, redundancy-mode single-active, lacp-system-id 02:00:00:00:00:01\n  \
             subinterface 10: address [none]",
        ] {
            assert!(out.contains(expected), "missing {expected:?} in:\n{out}");
        }
    }

    #[test]
    fn render_transaction_scopes_to_every_position() {
        let snap = TransactionSnapshot {
            name: "t".to_string(),
            config: full_config(),
            dirty: false,
            resumed: false,
            generation: 0,
        };
        for (segs, starts) in [
            (&["routing-table", "rt1"][..], "routing-table rt1:"),
            (&["ospf-instance", "o1"], "ospf instance o1:"),
            (&["ospf-instance", "o1", "area", "0.0.0.0"], "area 0.0.0.0"),
            (
                &["ospf-instance", "o1", "area", "0.0.0.0", "profile", "op"],
                "profile op:",
            ),
            (&["ospfv3-instance", "v3"], "ospfv3 instance v3:"),
            (
                &["ospfv3-instance", "v3", "area", "0.0.0.1"],
                "area 0.0.0.1",
            ),
            (
                &["ospfv3-instance", "v3", "area", "0.0.0.1", "profile", "p3"],
                "profile p3:",
            ),
            (
                &["static-routing-instance", "s1"],
                "static-routing-instance s1",
            ),
            (&["interface", "eth0"], "interface eth0:"),
            (
                &["community-alias", "blackhole"],
                "community-alias blackhole:",
            ),
            (&["community-group", "g"], "community-group g:"),
            (&["as-path-list", "a"], "as-path-list a:"),
            (&["prefix-list", "pl"], "prefix-list pl:"),
            (&["broadcast-domain", "bd1"], "broadcast-domain bd1:"),
            (&["switching-profile", "trunk"], "switching-profile trunk:"),
            (&["port-aggregate", "bond1"], "port-aggregate bond1:"),
            (&["policy-definition", "nope"], "nothing configured here"),
            (
                &["ospf-instance", "o1", "area", "9.9.9.9"],
                "nothing configured here",
            ),
            // No dedicated renderer: the object's own JSON.
            (&["bgp-instance", "r1", "peer", "192.0.2.2"], "{"),
            (
                &["bgp-instance", "r1", "peer", "192.0.2.99"],
                "nothing configured here",
            ),
        ] {
            let path = Path::from(segs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
            let out = render_transaction(&snap, &path);
            assert!(out.starts_with(starts), "{segs:?} rendered {out:?}");
        }
    }

    fn sub_status(tag: u16, addresses: Vec<InterfaceAddress>) -> SubinterfaceStatus {
        SubinterfaceStatus {
            tag,
            addresses,
            routing_table: (tag == 0).then(|| "rt1".to_string()),
            link_local_address: None,
        }
    }

    #[test]
    fn render_interface_and_port_aggregate_statuses() {
        assert_eq!(render_interface_statuses(&[]), "no interfaces");
        assert_eq!(render_port_aggregate_statuses(&[]), "no port aggregates");
        let iface = InterfaceStatus {
            name: "eth0".to_string(),
            addresses: vec![addr("10.9.0.1/32", None)],
            routing_table: None,
            switching_profile: Some("trunk".to_string()),
            port_aggregate: None,
            mtu: 1500,
            subinterfaces: vec![
                sub_status(0, vec![addr("10.0.0.1/24", None)]),
                sub_status(5, Vec::new()),
            ],
            link_local_address: None,
        };
        let out = render_interface_statuses(&[iface.clone(), iface]);
        assert_eq!(
            out.lines().take(3).collect::<Vec<_>>(),
            [
                "interface eth0: address [10.9.0.1/32], routing-table unset, switching-profile trunk, mtu 1500",
                "  subinterface 0: address [10.0.0.1/24], routing-table rt1",
                "  subinterface 5: address [none], routing-table unset",
            ]
        );
        let agg = PortAggregateStatus {
            name: "bond1".to_string(),
            mode: nos_proto::PortAggregateMode::Xor,
            switching_profile: None,
            mtu: 9000,
            subinterfaces: vec![sub_status(0, Vec::new())],
            link_local_address: None,
            bond_name: None,
        };
        assert_eq!(
            render_port_aggregate_statuses(&[agg]),
            "port-aggregate bond1: mode Xor, switching-profile unset, mtu 9000\n  \
             subinterface 0: address [none], routing-table rt1"
        );
    }

    #[test]
    fn render_lacp_port_names_every_state() {
        let port = |receive, mux, actor_churn, partner_churn| nos_proto::LacpPortStatus {
            interface: "eth1".to_string(),
            actor_port_number: 1,
            receive_state: receive,
            mux_state: mux,
            partner_system_id: Some([2, 0, 0, 0, 0, 1]),
            partner_key: None,
            partner_port_number: None,
            selected: false,
            synchronized: false,
            actor_churn,
            partner_churn,
        };
        for (p, want) in [
            (
                port(LacpReceiveState::Initialize, LacpMuxState::Waiting, true, false),
                "receive initialize, mux waiting, partner none, selected no, synchronized no, churn actor",
            ),
            (
                port(LacpReceiveState::PortDisabled, LacpMuxState::Attached, true, true),
                "receive port-disabled, mux attached, partner none, selected no, synchronized no, churn actor+partner",
            ),
            (
                port(LacpReceiveState::LacpDisabled, LacpMuxState::Collecting, false, false),
                "receive lacp-disabled, mux collecting,",
            ),
            (
                port(LacpReceiveState::Expired, LacpMuxState::Detached, false, false),
                "receive expired, mux detached,",
            ),
        ] {
            let out = render_lacp_port(&p);
            assert!(out.contains(want), "{out}");
        }
        let empty = PortAggregateLacpSummary {
            aggregate: "bond1".to_string(),
            actor_system_id: [0; 6],
            actor_key: 1,
            rate: LacpRate::Slow,
            ports: Vec::new(),
        };
        assert!(render_lacp_summaries(&[empty]).ends_with("rate slow\n  no member ports"));
    }

    #[test]
    fn render_ospfv3_neighbors_and_database() {
        assert_eq!(
            render_ospfv3_neighbors("v3", &[]),
            "ospfv3 instance v3: no ospfv3 links configured"
        );
        assert_eq!(
            render_ospfv3_database("v3", &[]),
            "ospfv3 instance v3: no LSAs installed"
        );
        let link = Ospfv3NeighborSummary {
            link: "eth0.0".to_string(),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_state: LinkInterfaceState::DrOther,
            neighbor_router_id: Some(Ipv4Addr::new(2, 2, 2, 2)),
            state: OspfNeighborState::Full,
            last_hello_secs: Some(1),
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            neighbor_priority: Some(1),
            dr: Some(Ipv4Addr::new(3, 3, 3, 3)),
            bdr: None,
        };
        assert_eq!(
            render_ospfv3_neighbors("v3", &[link]),
            "ospfv3 instance v3:\n  eth0.0 area 0.0.0.0 if-state dr-other neighbor 2.2.2.2 Full \
             last-hello 1s hello-interval 10 dead-interval 40 priority 1 neighbor-priority 1 \
             dr 3.3.3.3 bdr -"
        );
        let lsa = |link: Option<&str>| Ospfv3LsaSummary {
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_type: 0x2001,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: Ipv4Addr::new(2, 2, 2, 2),
            sequence_number: 1,
            age: 3,
            checksum: 0x1234,
            link: link.map(str::to_string),
        };
        assert_eq!(
            render_ospfv3_database("v3", &[lsa(Some("eth0.0")), lsa(None)]),
            "ospfv3 instance v3:\n  area 0.0.0.0 type 8193 link-state-id 0.0.0.0 advertising-router 2.2.2.2 \
             sequence 0x00000001 age 3 checksum 0x1234 link eth0.0\n  \
             area 0.0.0.0 type 8193 link-state-id 0.0.0.0 advertising-router 2.2.2.2 \
             sequence 0x00000001 age 3 checksum 0x1234 link -"
        );
    }

    #[test]
    fn render_small_enums_and_edge_cases() {
        for (s, want) in [
            (OspfNeighborState::Init, "Init"),
            (OspfNeighborState::ExStart, "ExStart"),
            (OspfNeighborState::Exchange, "Exchange"),
            (OspfNeighborState::Loading, "Loading"),
        ] {
            assert_eq!(render_ospf_neighbor_state(s), want);
        }
        assert_eq!(
            render_ospf_interface_state(LinkInterfaceState::Waiting),
            "waiting"
        );
        assert_eq!(render_ospf_interface_state(LinkInterfaceState::Dr), "dr");
        assert_eq!(
            render_bgp_session_state(BgpSessionState::OpenSent),
            "OpenSent"
        );
        assert_eq!(
            render_bgp_session_state(BgpSessionState::OpenConfirm),
            "OpenConfirm"
        );
        for (s, want) in [
            (RouteSourceKind::Static, "static"),
            (RouteSourceKind::Bgp, "bgp"),
            (RouteSourceKind::Connected, "connected"),
        ] {
            assert_eq!(render_route_source(s), want);
        }
        for (l, want) in [
            (LogLevel::Trace, "TRACE"),
            (LogLevel::Debug, "DEBUG"),
            (LogLevel::Warn, "WARN"),
            (LogLevel::Error, "ERROR"),
        ] {
            assert_eq!(render_log_level(l), want);
        }
        assert_eq!(render_prefix_routes(&[]), "no routes");
        assert_eq!(render_policy_source(""), "(empty)");
        // An out-of-range timestamp falls back to the raw milliseconds.
        let mut entry = log_entry("configd", "m");
        entry.timestamp_ms = u64::MAX;
        entry.fields.clear();
        assert!(render_log_entry(&entry).starts_with(&u64::MAX.to_string()));
        // A shutdown with an RFC 9003 message quotes it.
        assert_eq!(
            render_bgp_peer(&BgpPeer {
                remote_address: "192.0.2.2".parse().unwrap(),
                peer_group: "pg".to_string(),
                shutdown: Some(BgpShutdown {
                    message: Some("maintenance".to_string()),
                }),
            }),
            "peer 192.0.2.2: peer-group pg, shutdown \"maintenance\""
        );
        // A remote FDB entry with no VTEP, no devices yet, an empty flood list.
        let mut t = nos_proto::FdbTable {
            domain: "bd".to_string(),
            vni: 1,
            bridge: None,
            vxlan: None,
            macs: vec![nos_proto::MacEntry {
                mac: "02:00:00:00:00:01".to_string(),
                source: nos_proto::MacSource::Remote,
                vtep: None,
                vteps: Vec::new(),
                esi: None,
            }],
            neighbours: vec![nos_proto::NeighEntry {
                ip: "10.0.0.9".parse().unwrap(),
                mac: "02:00:00:00:00:01".to_string(),
                source: nos_proto::MacSource::Remote,
                vtep: None,
            }],
            flood: Vec::new(),
            segments: Vec::new(),
            neigh_suppress: false,
        };
        assert_eq!(
            render_fdb_table(&t),
            "broadcast-domain bd: vni 1, bridge not created yet, vxlan not created yet, neigh-suppress off\n  \
             02:00:00:00:00:01 remote\n  10.0.0.9 is at 02:00:00:00:00:01 remote\n  flood list: none"
        );
        t.macs.clear();
        t.neighbours.clear();
        t.segments.push(nos_proto::EsEntry {
            esi: "e".to_string(),
            port: "bond1".to_string(),
            designated_forwarder: true,
            pes: Vec::new(),
            ad_pes: Vec::new(),
            up: true,
            single_active: false,
            df_algorithm: nos_proto::DfAlgorithm::Modulo,
        });
        let out = render_fdb_table(&t);
        assert!(out.contains("  no MAC addresses\n"), "{out}");
        assert!(
            out.ends_with("on bond1: designated forwarder (PEs )"),
            "{out}"
        );
    }
}
