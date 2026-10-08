use std::fmt::Write as _;
use std::net::Ipv4Addr;

use chrono::{DateTime, SecondsFormat, Utc};
use nos_proto::{
    BgpSessionState, Config, ConfigDiff, DiffStatus, EvpnRouteSummary, FieldDiff, InterfaceAddress,
    InterfaceStatus, LacpMuxState, LacpRate, LacpReceiveState, LinkInterfaceState, LogEntry,
    LogLevel, LsaSummary, NeighborSummary, OspfNeighborState, Ospfv3LsaSummary,
    Ospfv3NeighborSummary, PeerSummary, PortAggregateLacpSummary, PortAggregateStatus,
    PrefixRoutes, RouteSourceKind, SectionDiff, SubinterfaceStatus, TransactionSnapshot,
};

use nos_proto::cli::render;

use crate::session::Path;

fn format_address(addr: &InterfaceAddress) -> String {
    match &addr.label {
        Some(label) => format!("{} (label {label})", addr.address),
        None => addr.address.to_string(),
    }
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
    let mode = match port.mode {
        nos_proto::LacpMode::Active => "active",
        nos_proto::LacpMode::Passive => "passive",
    };
    let partner_priority = match (port.partner_system_priority, port.partner_port_priority) {
        (Some(system), Some(port)) => format!(", partner priority {system}/{port}"),
        _ => String::new(),
    };
    let individual = if port.individual {
        ", individual (partner not aggregatable)"
    } else {
        ""
    };
    format!(
        "  {}: port {}, receive {receive}, mux {mux}, {partner}, selected {}, synchronized {}, churn {}, port priority {}{partner_priority}, mode {mode}{individual}",
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
        port.actor_port_priority,
    )
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

/// Render `nos-lldpd`'s neighbor table one block per neighbor, for `show lldp
/// neighbors detail`: every field, the optional ones only when sent.
pub fn render_lldp_neighbors_detail(neighbors: &[nos_proto::LldpNeighbor]) -> String {
    if neighbors.is_empty() {
        return "no lldp neighbors".to_string();
    }
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    neighbors
        .iter()
        .map(|n| {
            let mut lines = vec![
                format!(
                    "{}: neighbor {}",
                    n.local_interface,
                    n.system_name.as_deref().unwrap_or("unnamed")
                ),
                format!("  chassis {}", n.chassis_id),
                format!("  port {}", n.port_id),
            ];
            let mut opt = |label: &str, value: Option<String>| {
                if let Some(v) = value {
                    lines.push(format!("  {label} {v}"));
                }
            };
            opt("port-description", n.port_description.clone());
            opt("system-description", n.system_description.clone());
            opt(
                "capabilities",
                (!n.capabilities.is_empty()).then(|| n.capabilities.join(",")),
            );
            opt(
                "management",
                (!n.management_addresses.is_empty()).then(|| n.management_addresses.join(",")),
            );
            opt(
                "vlans",
                (!n.vlan_names.is_empty()).then(|| {
                    n.vlan_names
                        .iter()
                        .map(|v| format!("{} ({})", v.id, v.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                }),
            );
            opt("port-vlan-id", n.port_vlan_id.map(|v| v.to_string()));
            opt(
                "aggregation",
                n.link_aggregation.map(|a| match (a.enabled, a.capable) {
                    (true, _) => format!("aggregated, port id {}", a.port_id),
                    (false, true) => "capable, not aggregated".to_string(),
                    (false, false) => "not capable".to_string(),
                }),
            );
            opt("max-frame-size", n.max_frame_size.map(|s| s.to_string()));
            opt(
                "mac/phy",
                n.mac_phy.map(|m| {
                    format!(
                        "autoneg supported {}, enabled {}, advertised 0x{:04x}, mau-type {}",
                        yes_no(m.autoneg_supported),
                        yes_no(m.autoneg_enabled),
                        m.advertised,
                        m.mau_type
                    )
                }),
            );
            lines.push(format!("  ttl {}s", n.ttl_remaining_secs));
            lines.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render `nos-lldpd`'s per-interface counters, for `show lldp statistics`.
pub fn render_lldp_statistics(stats: &[nos_proto::LldpLinkStats]) -> String {
    if stats.is_empty() {
        return "no lldp links".to_string();
    }
    stats
        .iter()
        .map(|s| {
            format!(
                "{}: tx {}, rx {}, rx errors {}, rx discarded {}, tlvs discarded {}, \
                 tlvs unrecognized {}, ageouts {}, too many neighbors {}",
                s.interface,
                s.frames_out,
                s.frames_in,
                s.frames_in_errors,
                s.frames_discarded,
                s.tlvs_discarded,
                s.tlvs_unrecognized,
                s.ageouts,
                s.too_many_neighbors,
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
                "lacp {}: system {}, key {}, rate {rate}, system priority {}",
                s.aggregate,
                format_mac(s.actor_system_id),
                s.actor_key,
                s.actor_system_priority
            )];
            if s.min_links > 1 {
                lines.push(format!(
                    "  min-links {}: {}",
                    s.min_links,
                    if s.min_links_met {
                        "met"
                    } else {
                        "not met, bond emptied"
                    }
                ));
            }
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
        RouteSourceKind::Evpn => "evpn",
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
            let backup = candidate.backup.map_or_else(String::new, |b| {
                let tunnel = if candidate.backup_tunnel {
                    "tunnel "
                } else {
                    ""
                };
                format!(" backup {tunnel}{b}")
            });
            let via = if candidate.discard {
                "discard".to_string()
            } else {
                let gateways = candidate
                    .gateways
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let evpn = candidate.evpn.as_ref().map_or_else(String::new, |e| {
                    format!(" rmac {} vni {}", e.router_mac, e.vni)
                });
                format!("via {gateways}{evpn}")
            };
            lines.push(format!(
                "  {marker} {via} [{}]{backup}",
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
        // RFC 4724 / RFC 8538: the peer's restart time, N, and the families
        // it keeps forwarding state for (F).
        let gr = match &peer.graceful_restart {
            Some(g) if peer.state == BgpSessionState::Established => {
                let f: Vec<&str> = g
                    .families
                    .iter()
                    .filter(|(_, f)| *f)
                    .map(|(af, _)| af.as_str())
                    .collect();
                format!(
                    " gr {}s{}{}",
                    g.restart_time,
                    if g.notification { " N" } else { "" },
                    if f.is_empty() {
                        String::new()
                    } else {
                        format!(" F:{}", f.join(","))
                    }
                )
            }
            _ => String::new(),
        };
        lines.push(format!(
            "  {} AS {remote_as} peer-group {} {} uptime {uptime} hold-time {hold_time}{ao}{}{gr}",
            peer.remote_address,
            peer.peer_group,
            if peer.shutdown {
                "Idle (shutdown)".to_string()
            } else if peer.max_prefix_held {
                "Idle (max-prefix)".to_string()
            } else if peer.stale_prefixes > 0 && peer.state != BgpSessionState::Established {
                format!("Idle (gr-stale {})", peer.stale_prefixes)
            } else {
                render_bgp_session_state(peer.state).to_string()
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

/// Render a full running-config snapshot as human-readable text: the
/// generated `nos_proto::cli::render` hierarchy, only what is configured.
pub fn render_config(config: &Config) -> String {
    let doc = serde_json::to_value(config).unwrap_or_default();
    let text = render::indent(&render::render_root(&doc));
    if text.is_empty() {
        "nothing configured".to_string()
    } else {
        text
    }
}

/// Render a transaction's in-progress config, scoped to the current
/// navigation position: the whole config at the root, else the object the
/// position names (headed by its own words).
pub fn render_transaction(snapshot: &TransactionSnapshot, path: &Path) -> String {
    if path.segments().is_empty() {
        let header = if snapshot.dirty {
            format!("transaction '{}' (uncommitted changes):", snapshot.name)
        } else {
            format!("transaction '{}':", snapshot.name)
        };
        return format!("{header}\n{}", render_config(&snapshot.config));
    }
    serde_json::to_value(&snapshot.config)
        .ok()
        .and_then(|doc| render::render_at(&doc, path.segments()))
        .map_or_else(
            || "nothing configured here".to_string(),
            |lines| render::indent(&lines),
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
            // A remote MAC pinned to one of our own segments' ports.
            (nos_proto::MacSource::Remote, None) => match &m.esi {
                Some(esi) => format!("  {} remote, on our esi {esi}", m.mac),
                None => format!("  {} remote", m.mac),
            },
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
            "  ethernet-segment {} on {}: {} (PEs {}){}{}{}{}",
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
            },
            if e.local_bias { ", local-bias" } else { "" }
        ));
    }
    lines.join("\n")
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
        logging,
        bfd_profiles,
    } = diff;
    let mut lines = Vec::new();

    if let Some(field) = hostname {
        render_field_diff(&mut lines, field, "", color);
    }
    for field in lldp.iter().chain(logging) {
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
        bfd_profiles,
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

    use nos_proto::SectionDiff;

    use super::*;

    #[test]
    fn discard_route_renders_as_discard() {
        let routes = [PrefixRoutes {
            prefix: "203.0.113.120/29".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec![],
                source: nos_proto::RouteSourceKind::Ospf,
                backup: None,
                discard: true,
                evpn: None,
                backup_tunnel: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "203.0.113.120/29\n  * discard [ospf]"
        );
    }

    #[test]
    fn evpn_route_renders_its_router_mac_and_vni() {
        let routes = [PrefixRoutes {
            prefix: "10.2.0.0/24".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.50.0.3".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Evpn,
                backup: None,
                discard: false,
                evpn: Some(nos_proto::EvpnRouteInfo {
                    vtep: "10.50.0.3".parse().unwrap(),
                    router_mac: "02:00:00:00:00:03".to_string(),
                    vni: 5000,
                }),
                backup_tunnel: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "10.2.0.0/24\n  * via 10.50.0.3 rmac 02:00:00:00:00:03 vni 5000 [evpn]"
        );
    }

    #[test]
    fn ecmp_route_renders_every_gateway_on_one_line() {
        let routes = [PrefixRoutes {
            prefix: "203.0.113.80/32".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.0.0.2".parse().unwrap(), "10.0.1.2".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Ospf,
                backup: Some("10.0.1.3".parse().unwrap()),
                discard: false,
                evpn: None,
                backup_tunnel: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "203.0.113.80/32\n  * via 10.0.0.2, 10.0.1.2 [ospf] backup 10.0.1.3"
        );
    }

    #[test]
    fn remote_lfa_backup_renders_as_a_tunnel() {
        let routes = [PrefixRoutes {
            prefix: "203.0.113.80/32".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.0.0.2".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Ospf,
                backup: Some("203.0.113.84".parse().unwrap()),
                discard: false,
                evpn: None,
                backup_tunnel: true,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "203.0.113.80/32\n  * via 10.0.0.2 [ospf] backup tunnel 203.0.113.84"
        );
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
            "+ broadcast domain blue:",
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
            graceful_restart: None,
            stale_prefixes: 0,
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
    fn render_bgp_summary_shows_graceful_restart() {
        let mut stale = idle_peer("10.0.0.1");
        stale.stale_prefixes = 4;
        let mut up = idle_peer("10.0.0.2");
        up.state = BgpSessionState::Established;
        up.graceful_restart = Some(nos_proto::GrSummary {
            restart_time: 120,
            notification: true,
            restarting: false,
            families: vec![
                (nos_proto::AddressFamily::Ipv4Unicast, true),
                (nos_proto::AddressFamily::Ipv6Unicast, false),
            ],
        });
        assert_eq!(
            render_bgp_summary("r1", &[stale, up]),
            "bgp instance r1:\n  10.0.0.1 AS - peer-group pg1 Idle (gr-stale 4) uptime - hold-time -\n  \
             10.0.0.2 AS - peer-group pg1 Established uptime - hold-time - gr 120s N F:ipv4"
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
            external_metric: None,
            external_type2: false,
            checksum: 0xabcd,
            router_flags: Some(0),
            virtual_links: Vec::new(),
        };
        assert_eq!(
            render_ospf_database("o1", &[lsa]),
            "ospf instance o1:\n  area 0.0.0.0 type 1 link-state-id 1.1.1.1 \
             advertising-router 1.1.1.1 sequence 0x80000001 age 42 checksum 0xabcd"
        );
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
            ..Default::default()
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
    fn render_lldp_neighbors_detail_prints_only_what_was_sent() {
        assert_eq!(render_lldp_neighbors_detail(&[]), "no lldp neighbors");
        let bare = nos_proto::LldpNeighbor {
            local_interface: "eth1".to_string(),
            chassis_id: "02:00:00:00:00:02".to_string(),
            port_id: "eth1".to_string(),
            ttl_remaining_secs: 117,
            ..Default::default()
        };
        assert_eq!(
            render_lldp_neighbors_detail(std::slice::from_ref(&bare)),
            "eth1: neighbor unnamed\n  chassis 02:00:00:00:00:02\n  port eth1\n  ttl 117s"
        );
        let full = nos_proto::LldpNeighbor {
            system_name: Some("router-b".to_string()),
            capabilities: vec!["bridge".to_string(), "router".to_string()],
            vlan_names: vec![nos_proto::lldp::LldpVlanName {
                id: 100,
                name: "bd-x".to_string(),
            }],
            port_vlan_id: Some(1),
            link_aggregation: Some(nos_proto::lldp::LldpLinkAggregation {
                capable: true,
                enabled: true,
                port_id: 7,
            }),
            max_frame_size: Some(9018),
            mac_phy: Some(nos_proto::lldp::LldpMacPhy {
                autoneg_supported: true,
                autoneg_enabled: false,
                advertised: 0x6c01,
                mau_type: 30,
            }),
            ..bare
        };
        let out = render_lldp_neighbors_detail(&[full]);
        for line in [
            "eth1: neighbor router-b",
            "  capabilities bridge,router",
            "  vlans 100 (bd-x)",
            "  port-vlan-id 1",
            "  aggregation aggregated, port id 7",
            "  max-frame-size 9018",
            "  mac/phy autoneg supported yes, enabled no, advertised 0x6c01, mau-type 30",
        ] {
            assert!(
                out.lines().any(|l| l == line),
                "{line:?} missing from:\n{out}"
            );
        }
    }

    #[test]
    fn render_lldp_statistics_empty_and_populated() {
        assert_eq!(render_lldp_statistics(&[]), "no lldp links");
        let stats = nos_proto::LldpLinkStats {
            interface: "eth1".to_string(),
            frames_out: 1,
            frames_in: 2,
            frames_in_errors: 3,
            frames_discarded: 4,
            tlvs_discarded: 5,
            tlvs_unrecognized: 6,
            ageouts: 7,
            too_many_neighbors: 8,
        };
        assert_eq!(
            render_lldp_statistics(&[stats]),
            "eth1: tx 1, rx 2, rx errors 3, rx discarded 4, tlvs discarded 5, \
             tlvs unrecognized 6, ageouts 7, too many neighbors 8"
        );
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
            actor_system_priority: 100,
            rate: LacpRate::Fast,
            min_links: 2,
            min_links_met: false,
            ports: vec![
                nos_proto::LacpPortStatus {
                    interface: "eth1".to_string(),
                    actor_port_number: 4,
                    receive_state: LacpReceiveState::Current,
                    mux_state: LacpMuxState::Distributing,
                    partner_system_id: Some([2, 0, 0, 0, 0, 1]),
                    partner_key: Some(3),
                    partner_port_number: Some(9),
                    actor_port_priority: 50,
                    mode: nos_proto::LacpMode::Passive,
                    partner_system_priority: Some(200),
                    partner_port_priority: Some(60),
                    selected: true,
                    synchronized: true,
                    actor_churn: false,
                    partner_churn: false,
                    individual: false,
                },
                nos_proto::LacpPortStatus {
                    interface: "eth2".to_string(),
                    actor_port_number: 5,
                    receive_state: LacpReceiveState::Defaulted,
                    mux_state: LacpMuxState::Detached,
                    partner_system_id: None,
                    partner_key: None,
                    partner_port_number: None,
                    actor_port_priority: 32768,
                    mode: nos_proto::LacpMode::Active,
                    partner_system_priority: None,
                    partner_port_priority: None,
                    selected: false,
                    synchronized: false,
                    actor_churn: false,
                    partner_churn: true,
                    individual: true,
                },
            ],
        };
        let out = render_lacp_summaries(&[summary]);
        assert!(out.contains(
            "lacp bond1: system 02:00:00:00:00:ab, key 7, rate fast, system priority 100"
        ));
        assert!(out.contains("  min-links 2: not met, bond emptied"));
        assert!(out.contains("churn partner, port priority 32768, mode active, individual (partner not aggregatable)"), "{out}");
        assert!(out.contains("eth1: port 4, receive current, mux distributing, partner 02:00:00:00:00:01 key 3 port 9, selected yes, synchronized yes, churn none, port priority 50, partner priority 200/60, mode passive"));
        assert!(out.contains("eth2: port 5, receive defaulted, mux detached, partner none, selected no, synchronized no, churn partner"));
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
                local_bias: false,
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
        // Local bias in place says so (and the kernel fallback does not).
        let mut lb = t.clone();
        lb.segments[0].local_bias = true;
        assert!(render_fdb_table(&lb).ends_with("per-ES A-D from 192.0.2.9, local-bias"));
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

    fn addr(a: &str, label: Option<&str>) -> InterfaceAddress {
        InterfaceAddress {
            address: a.parse().unwrap(),
            label: label.map(str::to_string),
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
            actor_port_priority: 32768,
            mode: nos_proto::LacpMode::Active,
            partner_system_priority: None,
            partner_port_priority: None,
            selected: false,
            synchronized: false,
            actor_churn,
            partner_churn,
            individual: false,
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
            actor_system_priority: 32768,
            rate: LacpRate::Slow,
            min_links: 1,
            min_links_met: true,
            ports: Vec::new(),
        };
        assert!(
            render_lacp_summaries(&[empty]).ends_with("system priority 32768\n  no member ports")
        );
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
            (RouteSourceKind::Evpn, "evpn"),
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
            local_bias: false,
        });
        let out = render_fdb_table(&t);
        assert!(out.contains("  no MAC addresses\n"), "{out}");
        assert!(
            out.ends_with("on bond1: designated forwarder (PEs )"),
            "{out}"
        );
    }

    /// A config from the fields given, the rest default.
    fn config_from(json: &serde_json::Value) -> Config {
        let mut base = serde_json::to_value(Config::default()).unwrap();
        base.as_object_mut()
            .unwrap()
            .extend(json.as_object().unwrap().clone());
        serde_json::from_value(base).unwrap()
    }

    /// The fields #116 found missing from the hand-written renderer.
    fn ospf_config() -> Config {
        config_from(&serde_json::json!({
            "hostname": "r1",
            "ospf_instances": [{
                "name": "o1", "router_id": "1.1.1.1", "areas": [{
                    "area_id": "0.0.0.0", "profiles": [{
                        "name": "p1", "hello_interval": 5, "dead_interval": 20,
                        "cost": 10, "priority": 3, "mtu": 1400,
                        "network_type": "PointToPoint",
                        "auth": {"Crypto": {"keys": [
                            {"key_id": 1, "algorithm": "HmacSha256", "key": "k", "is_current": true}
                        ]}}
                    }]
                }]
            }],
            "routing_tables": [{
                "name": "rt1", "ospfv3_instance": "o3",
                "evpn": {"l3_vni": 5000, "rd": "1:1"}
            }],
            "users": [{"name": "admin", "password": "$argon2id$secret"}]
        }))
    }

    #[test]
    fn show_config_lists_every_configured_field() {
        let out = render_config(&ospf_config());
        for want in [
            "hostname r1",
            "ospf instance o1",
            "  area 0.0.0.0",
            "      hello-interval 5",
            "      dead-interval 20",
            "      cost 10",
            "      priority 3",
            "      mtu 1400",
            "      network-type point-to-point",
            "      crypto-key 1 hmac-sha256 k",
            "      crypto-key 1 current",
            "routing-table rt1",
            "  ospfv3-instance o3",
            "  evpn",
            "    l3-vni 5000",
            "    rd 1:1",
        ] {
            assert!(out.lines().any(|l| l == want), "missing `{want}` in\n{out}");
        }
    }

    #[test]
    fn show_config_never_prints_a_password() {
        let out = render_config(&ospf_config());
        assert!(out.contains("user admin\n  password <hidden>"), "{out}");
        assert!(!out.contains("argon2id"), "{out}");
    }

    #[test]
    fn show_config_of_nothing_says_so() {
        assert_eq!(
            render_config(&config_from(&serde_json::json!({"hostname": "nos"}))),
            "nothing configured"
        );
    }

    #[test]
    fn show_this_scopes_to_the_position() {
        let snap = TransactionSnapshot {
            name: "t".to_string(),
            config: ospf_config(),
            dirty: false,
            resumed: false,
            generation: 0,
        };
        let at = |segs: &[&str]| {
            let path = Path::from(segs.iter().map(ToString::to_string).collect::<Vec<_>>());
            render_transaction(&snap, &path)
        };
        let out = at(&["ospf-instance", "o1", "area", "0.0.0.0", "profile", "p1"]);
        assert!(out.starts_with("profile p1\n  hello-interval 5"), "{out}");
        assert_eq!(at(&["routing-table", "nope"]), "nothing configured here");
        assert!(at(&["routing-table", "rt1", "evpn"]).starts_with("evpn\n  l3-vni 5000"));
    }

    #[test]
    fn show_config_of_a_switching_profile() {
        let cfg = config_from(&serde_json::json!({
            "broadcast_domains": [{"name": "bd1", "addresses": []}],
            "switching_profiles": [{"name": "sp1", "members": [
                {"broadcast_domain": "bd1", "tag": {"Dot1q": 100}}
            ]}]
        }));
        assert_eq!(render_config(&cfg), "broadcast domain bd1\nswitching-profile sp1\n  broadcast-domain bd1\n    tag dot1q 100");
    }
}
