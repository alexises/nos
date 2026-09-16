use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use nos_proto::{
    AddressFamily, BgpAoAlgorithm, NextHopMode, Redistribute, RedistributeSource,
    RedistributeTarget, TransactionBase,
};

/// A single field edit targeting a BGP instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpInstanceField {
    Asn(u32),
    RouterId(Ipv4Addr),
    ClusterId(Ipv4Addr),
}

/// A single field edit targeting a BGP peer-group. Not `Copy` — the auth
/// variants carry owned `String` key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpPeerGroupField {
    RemoteAs(u32),
    SourceAddress(IpAddr),
    AddressFamily(AddressFamily),
    HoldTime(u16),
    KeepaliveInterval(u16),
    ConnectRetryTime(u16),
    Md5Password(String),
    /// A new (or replacement) TCP-AO key — `current`/`rnext` are set via the
    /// separate `AoCurrentKey`/`AoRnextKey` variants, not here.
    AoKey {
        send_id: u8,
        recv_id: u8,
        algorithm: BgpAoAlgorithm,
        key: String,
    },
    AoCurrentKey(u8),
    AoRnextKey(u8),
    NextHop(NextHopMode),
    /// `route-reflector-client` — always sets it to `true`; clearing goes
    /// through `DeleteTarget::RouteReflectorClient`.
    RouteReflectorClient,
    /// `route-server-client` — always sets it to `true`; clearing goes
    /// through `DeleteTarget::RouteServerClient`.
    RouteServerClient,
    /// `import-policy <name>` — `<name>` is any `PolicyDefinition`, or the
    /// reserved `accept-all`/`deny-all` names; not validated here, only at
    /// commit time.
    ImportPolicy(String),
    ExportPolicy(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditTarget {
    BgpInstance {
        name: String,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    BgpPeerGroup {
        instance: String,
        name: String,
    },
    /// Context-relative — only valid while navigated into a BGP instance.
    PeerGroupRelative {
        name: String,
    },
    RoutingTable {
        name: String,
    },
    StaticRoutingInstance {
        name: String,
    },
    Interface {
        name: String,
    },
    PolicyDefinition {
        name: String,
    },
    CommunityAlias {
        name: String,
    },
    CommunityGroup {
        name: String,
    },
    PrefixList {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetTarget {
    /// Fully-qualified — works from anywhere in configuration mode.
    BgpInstance {
        name: String,
        field: BgpInstanceField,
    },
    /// Context-relative — only valid while navigated into a BGP instance.
    Relative { field: BgpInstanceField },
    /// A top-level scalar with no navigation context — works from anywhere
    /// in configuration mode, regardless of the current path.
    Hostname(String),
    /// Fully-qualified peer-group field edit — works from anywhere in
    /// configuration mode.
    BgpPeerGroup {
        instance: String,
        group: String,
        field: BgpPeerGroupField,
    },
    /// Context-relative — only valid while navigated into a peer-group.
    PeerGroupRelative { field: BgpPeerGroupField },
    /// Fully-qualified peer upsert — works from anywhere in configuration
    /// mode.
    BgpPeer {
        instance: String,
        remote_address: IpAddr,
        peer_group: String,
    },
    /// Context-relative — only valid while navigated into a BGP instance
    /// (peers are siblings of peer-groups, not reachable from inside one).
    PeerRelative {
        remote_address: IpAddr,
        peer_group: String,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    RoutingTable { name: String, bgp_instance: String },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableRelative { bgp_instance: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    RoutingTableStaticRoutingInstance {
        name: String,
        static_routing_instance: String,
    },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableStaticRoutingInstanceRelative { static_routing_instance: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    RoutingTableRedistribute {
        name: String,
        redistribute: Redistribute,
    },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableRedistributeRelative { redistribute: Redistribute },
    /// Fully-qualified route upsert — works from anywhere in configuration
    /// mode.
    StaticRoute {
        instance: String,
        subnet: IpNet,
        gateway: IpAddr,
    },
    /// Context-relative — only valid while navigated into a static routing
    /// instance.
    StaticRouteRelative { subnet: IpNet, gateway: IpAddr },
    /// Fully-qualified — works from anywhere in configuration mode.
    InterfaceAddress { name: String, address: IpNet },
    /// Context-relative — only valid while navigated into an interface.
    InterfaceAddressRelative { address: IpNet },
    /// Fully-qualified — works from anywhere in configuration mode.
    InterfaceRoutingTable { name: String, routing_table: String },
    /// Context-relative — only valid while navigated into an interface.
    InterfaceRoutingTableRelative { routing_table: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    CommunityAliasValue { name: String, value: String },
    /// Context-relative — only valid while navigated into a community-alias.
    CommunityAliasValueRelative { value: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    CommunityGroupMember { name: String, member: String },
    /// Context-relative — only valid while navigated into a community-group.
    CommunityGroupMemberRelative { member: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    PrefixListEntry {
        name: String,
        cidr: IpNet,
        range: Option<(u8, u8)>,
    },
    /// Context-relative — only valid while navigated into a prefix-list.
    PrefixListEntryRelative {
        cidr: IpNet,
        range: Option<(u8, u8)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteTarget {
    /// Bare `delete` — deletes whatever the current navigation context is.
    Current,
    BgpInstance {
        name: String,
    },
    BgpPeerGroup {
        instance: String,
        name: String,
    },
    PeerGroupRelative {
        name: String,
    },
    BgpPeer {
        instance: String,
        remote_address: IpAddr,
    },
    PeerRelative {
        remote_address: IpAddr,
    },
    /// `delete source-address` — only valid while navigated into a
    /// peer-group.
    SourceAddress,
    /// `delete address-family ipv4|ipv6` — only valid while navigated into
    /// a peer-group.
    AddressFamily(AddressFamily),
    /// `delete hold-time` — only valid while navigated into a peer-group.
    HoldTime,
    /// `delete keepalive-interval` — only valid while navigated into a
    /// peer-group.
    KeepaliveInterval,
    /// `delete connect-retry-time` — only valid while navigated into a
    /// peer-group.
    ConnectRetryTime,
    /// `delete auth` — only valid while navigated into a peer-group.
    Auth,
    /// `delete ao-key <send-id>` — only valid while navigated into a
    /// peer-group.
    AoKey(u8),
    /// `delete next-hop` — only valid while navigated into a peer-group.
    NextHop,
    /// `delete route-reflector-client` — only valid while navigated into a
    /// peer-group.
    RouteReflectorClient,
    /// `delete route-server-client` — only valid while navigated into a
    /// peer-group.
    RouteServerClient,
    /// `delete import-policy` — only valid while navigated into a
    /// peer-group.
    ImportPolicy,
    /// `delete export-policy` — only valid while navigated into a
    /// peer-group.
    ExportPolicy,
    /// `delete bgp instance <name> cluster-id` — qualified clear.
    BgpInstanceClusterId {
        name: String,
    },
    /// `delete cluster-id` — relative clear, only valid while navigated into
    /// a BGP instance.
    BgpInstanceClusterIdRelative,
    RoutingTable {
        name: String,
    },
    /// `delete routing-table <name> bgp-instance` — qualified clear.
    RoutingTableBgpInstance {
        name: String,
    },
    /// `delete bgp-instance` — relative clear, only valid while navigated
    /// into a routing table.
    RoutingTableBgpInstanceRelative,
    /// `delete routing-table <name> static-routing-instance` — qualified
    /// clear.
    RoutingTableStaticRoutingInstance {
        name: String,
    },
    /// `delete static-routing-instance` — relative clear, only valid while
    /// navigated into a routing table.
    RoutingTableStaticRoutingInstanceRelative,
    /// `delete routing-table <name> redistribute` — qualified clear.
    RoutingTableRedistribute {
        name: String,
    },
    /// `delete redistribute` — relative clear, only valid while navigated
    /// into a routing table.
    RoutingTableRedistributeRelative,
    StaticRoutingInstance {
        name: String,
    },
    StaticRoute {
        instance: String,
        subnet: IpNet,
    },
    /// Only valid while navigated into a static routing instance.
    StaticRouteRelative {
        subnet: IpNet,
    },
    Interface {
        name: String,
    },
    /// `delete interface <name> address <cidr>` — qualified.
    InterfaceAddress {
        name: String,
        address: IpNet,
    },
    /// `delete address <cidr>` — relative, only valid while navigated into
    /// an interface.
    InterfaceAddressRelative {
        address: IpNet,
    },
    /// `delete interface <name> routing-table` — qualified clear.
    InterfaceRoutingTable {
        name: String,
    },
    /// `delete routing-table` — relative clear, only valid while navigated
    /// into an interface.
    InterfaceRoutingTableRelative,
    CommunityAlias {
        name: String,
    },
    CommunityGroup {
        name: String,
    },
    /// `delete community-group <name> member <m>` — qualified.
    CommunityGroupMember {
        name: String,
        member: String,
    },
    /// `delete member <m>` — relative, only valid while navigated into a
    /// community-group.
    CommunityGroupMemberRelative {
        member: String,
    },
    PrefixList {
        name: String,
    },
    /// `delete prefix-list <name> entry <cidr> [range <min> <max>]` —
    /// qualified.
    PrefixListEntry {
        name: String,
        cidr: IpNet,
        range: Option<(u8, u8)>,
    },
    /// `delete entry <cidr> [range <min> <max>]` — relative, only valid
    /// while navigated into a prefix-list.
    PrefixListEntryRelative {
        cidr: IpNet,
        range: Option<(u8, u8)>,
    },
}

/// A parsed REPL input line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ShowConfig,
    /// `show this` — only meaningful in configuration mode.
    Show,
    /// `show route <table>` (whole table) or `show route <table> <address>`
    /// (longest-prefix-match lookup).
    ShowRoute {
        table: String,
        address: Option<IpAddr>,
    },
    /// `show interface` (every interface) or `show interface <name>` (one).
    ShowInterface {
        name: Option<String>,
    },
    /// `show log [<source>] [--follow]` — a one-shot buffer snapshot,
    /// optionally filtered to one source, or a live tail with `--follow`.
    ShowLog {
        source: Option<String>,
        follow: bool,
    },
    /// `show bgp brief` — a one-line-per-peer session summary across every
    /// configured BGP instance.
    ShowBgpBrief,
    /// `clear bgp <instance> <peer> soft-in` — ask `<peer>`'s live session
    /// on `<instance>` to resend its routes (RFC 2918 route refresh).
    ClearBgpSoftIn {
        instance: String,
        peer: IpAddr,
    },
    Save,
    Help,
    /// `exit` | `quit` | `end`
    Exit,
    Configure {
        name: String,
        /// `None` when `from ...` was omitted (defaults to `Current`).
        base: Option<TransactionBase>,
    },
    Edit(EditTarget),
    Set(SetTarget),
    Delete(DeleteTarget),
    /// `edit source` — only valid while navigated into a policy-definition;
    /// opens `$EDITOR`/`$VISUAL`/`nano` on its current source. See root
    /// `CLAUDE.md`'s "nos-cli editing UX".
    EditSource,
    /// `show source` — only valid while navigated into a policy-definition.
    ShowSource,
    /// `set source line <n> <text>` — only valid while navigated into a
    /// policy-definition. `<text>` is the raw remainder of the line
    /// (leading whitespace preserved) since RPL's indentation is
    /// semantically meaningful — parsed outside the generic
    /// `split_whitespace()` matcher below, see `parse`'s doc comment.
    SetSourceLine {
        line: usize,
        text: String,
    },
    /// `delete source line <n>` — only valid while navigated into a
    /// policy-definition.
    DeleteSourceLine {
        line: usize,
    },
    Up,
    Top,
    Commit,
    /// `discard` | `abort`
    Discard,
    /// `diff` — only meaningful in configuration mode.
    Diff,
    Empty,
    Unknown(String),
}

impl Command {
    pub fn parse(line: &str) -> Self {
        let trimmed = line.trim();
        // `set source line <n> <text>` is the one command whose value must
        // preserve leading whitespace verbatim — RPL's indentation is
        // semantically meaningful — so it's parsed here, before the generic
        // `split_whitespace()` matcher below would otherwise collapse it.
        if let Some(rest) = trimmed.strip_prefix("set source line ") {
            return match rest.find(' ') {
                Some(space_idx) => match rest[..space_idx].parse::<usize>() {
                    Ok(line) => Command::SetSourceLine {
                        line,
                        text: rest[space_idx + 1..].to_string(),
                    },
                    Err(_) => Command::Unknown(trimmed.to_string()),
                },
                None => Command::Unknown(trimmed.to_string()),
            };
        }
        match trimmed.split_whitespace().collect::<Vec<_>>().as_slice() {
            [] => Command::Empty,
            ["show", "config"] => Command::ShowConfig,
            ["show", "this"] => Command::Show,
            ["show", "route", table] => Command::ShowRoute {
                table: (*table).to_string(),
                address: None,
            },
            ["show", "route", table, addr] => match addr.parse::<IpAddr>() {
                Ok(address) => Command::ShowRoute {
                    table: (*table).to_string(),
                    address: Some(address),
                },
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["show", "interface"] => Command::ShowInterface { name: None },
            ["show", "interface", name] => Command::ShowInterface {
                name: Some((*name).to_string()),
            },
            ["show", "log"] => Command::ShowLog {
                source: None,
                follow: false,
            },
            ["show", "log", "--follow"] => Command::ShowLog {
                source: None,
                follow: true,
            },
            ["show", "log", source] => Command::ShowLog {
                source: Some((*source).to_string()),
                follow: false,
            },
            ["show", "log", source, "--follow"] => Command::ShowLog {
                source: Some((*source).to_string()),
                follow: true,
            },
            ["show", "bgp", "brief"] => Command::ShowBgpBrief,
            ["clear", "bgp", instance, peer, "soft-in"] => match peer.parse::<IpAddr>() {
                Ok(peer) => Command::ClearBgpSoftIn {
                    instance: (*instance).to_string(),
                    peer,
                },
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["save"] => Command::Save,
            ["help"] => Command::Help,
            ["exit" | "quit" | "end"] => Command::Exit,
            ["commit"] => Command::Commit,
            ["discard" | "abort"] => Command::Discard,
            ["diff"] => Command::Diff,
            ["up"] => Command::Up,
            ["top"] => Command::Top,
            ["configure", name] => Command::Configure {
                name: (*name).to_string(),
                base: None,
            },
            ["configure", name, "from", "blank"] => Command::Configure {
                name: (*name).to_string(),
                base: Some(TransactionBase::Blank),
            },
            ["configure", name, "from", "current"] => Command::Configure {
                name: (*name).to_string(),
                base: Some(TransactionBase::Current),
            },
            ["edit", "bgp", "instance", name] => Command::Edit(EditTarget::BgpInstance {
                name: (*name).to_string(),
            }),
            ["edit", "bgp", "instance", instance, "peer-group", group] => {
                Command::Edit(EditTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    name: (*group).to_string(),
                })
            }
            ["edit", "peer-group", group] => Command::Edit(EditTarget::PeerGroupRelative {
                name: (*group).to_string(),
            }),
            ["edit", "routing-table", name] => Command::Edit(EditTarget::RoutingTable {
                name: (*name).to_string(),
            }),
            ["edit", "static-routing-instance", name] => {
                Command::Edit(EditTarget::StaticRoutingInstance {
                    name: (*name).to_string(),
                })
            }
            ["edit", "interface", name] => Command::Edit(EditTarget::Interface {
                name: (*name).to_string(),
            }),
            ["edit", "policy-definition", name] => Command::Edit(EditTarget::PolicyDefinition {
                name: (*name).to_string(),
            }),
            ["edit", "community-alias", name] => Command::Edit(EditTarget::CommunityAlias {
                name: (*name).to_string(),
            }),
            ["edit", "community-group", name] => Command::Edit(EditTarget::CommunityGroup {
                name: (*name).to_string(),
            }),
            ["edit", "prefix-list", name] => Command::Edit(EditTarget::PrefixList {
                name: (*name).to_string(),
            }),
            ["edit", "source"] => Command::EditSource,
            ["show", "source"] => Command::ShowSource,
            ["delete", "source", "line", n] => match n.parse::<usize>() {
                Ok(line) => Command::DeleteSourceLine { line },
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "bgp", "instance", name, "asn", n] => match n.parse::<u32>() {
                Ok(asn) => Command::Set(SetTarget::BgpInstance {
                    name: (*name).to_string(),
                    field: BgpInstanceField::Asn(asn),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "bgp", "instance", name, "router-id", ip] => match ip.parse::<Ipv4Addr>() {
                Ok(router_id) => Command::Set(SetTarget::BgpInstance {
                    name: (*name).to_string(),
                    field: BgpInstanceField::RouterId(router_id),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "bgp", "instance", name, "cluster-id", ip] => match ip.parse::<Ipv4Addr>() {
                Ok(cluster_id) => Command::Set(SetTarget::BgpInstance {
                    name: (*name).to_string(),
                    field: BgpInstanceField::ClusterId(cluster_id),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "asn", n] => match n.parse::<u32>() {
                Ok(asn) => Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::Asn(asn),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "router-id", ip] => match ip.parse::<Ipv4Addr>() {
                Ok(router_id) => Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::RouterId(router_id),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "cluster-id", ip] => match ip.parse::<Ipv4Addr>() {
                Ok(cluster_id) => Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::ClusterId(cluster_id),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "hostname", name] => Command::Set(SetTarget::Hostname((*name).to_string())),
            ["set", "bgp", "instance", instance, "peer-group", group, "remote-as", n] => {
                match n.parse::<u32>() {
                    Ok(remote_as) => Command::Set(SetTarget::BgpPeerGroup {
                        instance: (*instance).to_string(),
                        group: (*group).to_string(),
                        field: BgpPeerGroupField::RemoteAs(remote_as),
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "source-address", addr] => {
                match addr.parse::<IpAddr>() {
                    Ok(address) => Command::Set(SetTarget::BgpPeerGroup {
                        instance: (*instance).to_string(),
                        group: (*group).to_string(),
                        field: BgpPeerGroupField::SourceAddress(address),
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "address-family", "ipv4"] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv4Unicast),
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "address-family", "ipv6"] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv6Unicast),
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "hold-time", n] => {
                match n.parse::<u16>() {
                    Ok(hold_time) => Command::Set(SetTarget::BgpPeerGroup {
                        instance: (*instance).to_string(),
                        group: (*group).to_string(),
                        field: BgpPeerGroupField::HoldTime(hold_time),
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "keepalive-interval", n] => {
                match n.parse::<u16>() {
                    Ok(keepalive_interval) => Command::Set(SetTarget::BgpPeerGroup {
                        instance: (*instance).to_string(),
                        group: (*group).to_string(),
                        field: BgpPeerGroupField::KeepaliveInterval(keepalive_interval),
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "connect-retry-time", n] => {
                match n.parse::<u16>() {
                    Ok(connect_retry_time) => Command::Set(SetTarget::BgpPeerGroup {
                        instance: (*instance).to_string(),
                        group: (*group).to_string(),
                        field: BgpPeerGroupField::ConnectRetryTime(connect_retry_time),
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "next-hop", "self"] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "next-hop", "unchanged"] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "route-reflector-client"] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::RouteReflectorClient,
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "route-server-client"] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::RouteServerClient,
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "import-policy", name] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::ImportPolicy((*name).to_string()),
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "export-policy", name] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::ExportPolicy((*name).to_string()),
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "md5-password", password] => {
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    group: (*group).to_string(),
                    field: BgpPeerGroupField::Md5Password((*password).to_string()),
                })
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "ao-key", send_id, recv_id, algorithm, key] => {
                match (
                    send_id.parse::<u8>(),
                    recv_id.parse::<u8>(),
                    parse_ao_algorithm(algorithm),
                ) {
                    (Ok(send_id), Ok(recv_id), Some(algorithm)) => {
                        Command::Set(SetTarget::BgpPeerGroup {
                            instance: (*instance).to_string(),
                            group: (*group).to_string(),
                            field: BgpPeerGroupField::AoKey {
                                send_id,
                                recv_id,
                                algorithm,
                                key: (*key).to_string(),
                            },
                        })
                    }
                    _ => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "ao-key", send_id, "current"] => {
                match send_id.parse::<u8>() {
                    Ok(send_id) => Command::Set(SetTarget::BgpPeerGroup {
                        instance: (*instance).to_string(),
                        group: (*group).to_string(),
                        field: BgpPeerGroupField::AoCurrentKey(send_id),
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "bgp", "instance", instance, "peer-group", group, "ao-key", send_id, "rnext"] => {
                match send_id.parse::<u8>() {
                    Ok(send_id) => Command::Set(SetTarget::BgpPeerGroup {
                        instance: (*instance).to_string(),
                        group: (*group).to_string(),
                        field: BgpPeerGroupField::AoRnextKey(send_id),
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "remote-as", n] => match n.parse::<u32>() {
                Ok(remote_as) => Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::RemoteAs(remote_as),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "source-address", addr] => match addr.parse::<IpAddr>() {
                Ok(address) => Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::SourceAddress(address),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "address-family", "ipv4"] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv4Unicast),
            }),
            ["set", "address-family", "ipv6"] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv6Unicast),
            }),
            ["set", "next-hop", "self"] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
            }),
            ["set", "next-hop", "unchanged"] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
            }),
            ["set", "route-reflector-client"] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::RouteReflectorClient,
            }),
            ["set", "route-server-client"] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::RouteServerClient,
            }),
            ["set", "import-policy", name] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::ImportPolicy((*name).to_string()),
            }),
            ["set", "export-policy", name] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::ExportPolicy((*name).to_string()),
            }),
            ["set", "hold-time", n] => match n.parse::<u16>() {
                Ok(hold_time) => Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::HoldTime(hold_time),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "keepalive-interval", n] => match n.parse::<u16>() {
                Ok(keepalive_interval) => Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::KeepaliveInterval(keepalive_interval),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "connect-retry-time", n] => match n.parse::<u16>() {
                Ok(connect_retry_time) => Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::ConnectRetryTime(connect_retry_time),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "md5-password", password] => Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::Md5Password((*password).to_string()),
            }),
            ["set", "ao-key", send_id, recv_id, algorithm, key] => {
                match (
                    send_id.parse::<u8>(),
                    recv_id.parse::<u8>(),
                    parse_ao_algorithm(algorithm),
                ) {
                    (Ok(send_id), Ok(recv_id), Some(algorithm)) => {
                        Command::Set(SetTarget::PeerGroupRelative {
                            field: BgpPeerGroupField::AoKey {
                                send_id,
                                recv_id,
                                algorithm,
                                key: (*key).to_string(),
                            },
                        })
                    }
                    _ => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "ao-key", send_id, "current"] => match send_id.parse::<u8>() {
                Ok(send_id) => Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::AoCurrentKey(send_id),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "ao-key", send_id, "rnext"] => match send_id.parse::<u8>() {
                Ok(send_id) => Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::AoRnextKey(send_id),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "bgp", "instance", instance, "peer", ip, "peer-group", group] => {
                match ip.parse::<IpAddr>() {
                    Ok(remote_address) => Command::Set(SetTarget::BgpPeer {
                        instance: (*instance).to_string(),
                        remote_address,
                        peer_group: (*group).to_string(),
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "peer", ip, "peer-group", group] => match ip.parse::<IpAddr>() {
                Ok(remote_address) => Command::Set(SetTarget::PeerRelative {
                    remote_address,
                    peer_group: (*group).to_string(),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "routing-table", name, "bgp-instance", instance] => {
                Command::Set(SetTarget::RoutingTable {
                    name: (*name).to_string(),
                    bgp_instance: (*instance).to_string(),
                })
            }
            ["set", "bgp-instance", instance] => Command::Set(SetTarget::RoutingTableRelative {
                bgp_instance: (*instance).to_string(),
            }),
            ["set", "routing-table", name, "static-routing-instance", instance] => {
                Command::Set(SetTarget::RoutingTableStaticRoutingInstance {
                    name: (*name).to_string(),
                    static_routing_instance: (*instance).to_string(),
                })
            }
            ["set", "static-routing-instance", instance] => {
                Command::Set(SetTarget::RoutingTableStaticRoutingInstanceRelative {
                    static_routing_instance: (*instance).to_string(),
                })
            }
            ["set", "routing-table", name, "redistribute", "from", "static", "to", "bgp"] => {
                Command::Set(SetTarget::RoutingTableRedistribute {
                    name: (*name).to_string(),
                    redistribute: Redistribute {
                        from: RedistributeSource::Static,
                        to: RedistributeTarget::Bgp,
                    },
                })
            }
            ["set", "redistribute", "from", "static", "to", "bgp"] => {
                Command::Set(SetTarget::RoutingTableRedistributeRelative {
                    redistribute: Redistribute {
                        from: RedistributeSource::Static,
                        to: RedistributeTarget::Bgp,
                    },
                })
            }
            ["set", "static-routing-instance", name, "route", subnet, "gateway", addr] => {
                match (subnet.parse::<IpNet>(), addr.parse::<IpAddr>()) {
                    (Ok(subnet), Ok(gateway)) => Command::Set(SetTarget::StaticRoute {
                        instance: (*name).to_string(),
                        subnet,
                        gateway,
                    }),
                    _ => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "route", subnet, "gateway", addr] => {
                match (subnet.parse::<IpNet>(), addr.parse::<IpAddr>()) {
                    (Ok(subnet), Ok(gateway)) => {
                        Command::Set(SetTarget::StaticRouteRelative { subnet, gateway })
                    }
                    _ => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "interface", name, "address", addr] => match addr.parse::<IpNet>() {
                Ok(address) => Command::Set(SetTarget::InterfaceAddress {
                    name: (*name).to_string(),
                    address,
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "address", addr] => match addr.parse::<IpNet>() {
                Ok(address) => Command::Set(SetTarget::InterfaceAddressRelative { address }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "interface", name, "routing-table", table] => {
                Command::Set(SetTarget::InterfaceRoutingTable {
                    name: (*name).to_string(),
                    routing_table: (*table).to_string(),
                })
            }
            ["set", "routing-table", table] => {
                Command::Set(SetTarget::InterfaceRoutingTableRelative {
                    routing_table: (*table).to_string(),
                })
            }
            ["set", "community-alias", name, "value", value] => {
                Command::Set(SetTarget::CommunityAliasValue {
                    name: (*name).to_string(),
                    value: (*value).to_string(),
                })
            }
            ["set", "value", value] => Command::Set(SetTarget::CommunityAliasValueRelative {
                value: (*value).to_string(),
            }),
            ["set", "community-group", name, "member", member] => {
                Command::Set(SetTarget::CommunityGroupMember {
                    name: (*name).to_string(),
                    member: (*member).to_string(),
                })
            }
            ["set", "member", member] => Command::Set(SetTarget::CommunityGroupMemberRelative {
                member: (*member).to_string(),
            }),
            ["set", "prefix-list", name, "entry", cidr] => match cidr.parse::<IpNet>() {
                Ok(cidr) => Command::Set(SetTarget::PrefixListEntry {
                    name: (*name).to_string(),
                    cidr,
                    range: None,
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "prefix-list", name, "entry", cidr, "range", min, max] => {
                match (cidr.parse::<IpNet>(), min.parse::<u8>(), max.parse::<u8>()) {
                    (Ok(cidr), Ok(min), Ok(max)) => Command::Set(SetTarget::PrefixListEntry {
                        name: (*name).to_string(),
                        cidr,
                        range: Some((min, max)),
                    }),
                    _ => Command::Unknown(trimmed.to_string()),
                }
            }
            ["set", "entry", cidr] => match cidr.parse::<IpNet>() {
                Ok(cidr) => Command::Set(SetTarget::PrefixListEntryRelative { cidr, range: None }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "entry", cidr, "range", min, max] => {
                match (cidr.parse::<IpNet>(), min.parse::<u8>(), max.parse::<u8>()) {
                    (Ok(cidr), Ok(min), Ok(max)) => {
                        Command::Set(SetTarget::PrefixListEntryRelative {
                            cidr,
                            range: Some((min, max)),
                        })
                    }
                    _ => Command::Unknown(trimmed.to_string()),
                }
            }
            ["delete"] => Command::Delete(DeleteTarget::Current),
            ["delete", "bgp", "instance", name] => Command::Delete(DeleteTarget::BgpInstance {
                name: (*name).to_string(),
            }),
            ["delete", "bgp", "instance", instance, "peer-group", group] => {
                Command::Delete(DeleteTarget::BgpPeerGroup {
                    instance: (*instance).to_string(),
                    name: (*group).to_string(),
                })
            }
            ["delete", "peer-group", group] => Command::Delete(DeleteTarget::PeerGroupRelative {
                name: (*group).to_string(),
            }),
            ["delete", "bgp", "instance", name, "cluster-id"] => {
                Command::Delete(DeleteTarget::BgpInstanceClusterId {
                    name: (*name).to_string(),
                })
            }
            ["delete", "cluster-id"] => Command::Delete(DeleteTarget::BgpInstanceClusterIdRelative),
            ["delete", "bgp", "instance", instance, "peer", ip] => match ip.parse::<IpAddr>() {
                Ok(remote_address) => Command::Delete(DeleteTarget::BgpPeer {
                    instance: (*instance).to_string(),
                    remote_address,
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["delete", "peer", ip] => match ip.parse::<IpAddr>() {
                Ok(remote_address) => {
                    Command::Delete(DeleteTarget::PeerRelative { remote_address })
                }
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["delete", "source-address"] => Command::Delete(DeleteTarget::SourceAddress),
            ["delete", "address-family", "ipv4"] => {
                Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv4Unicast))
            }
            ["delete", "address-family", "ipv6"] => {
                Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv6Unicast))
            }
            ["delete", "next-hop"] => Command::Delete(DeleteTarget::NextHop),
            ["delete", "route-reflector-client"] => {
                Command::Delete(DeleteTarget::RouteReflectorClient)
            }
            ["delete", "route-server-client"] => Command::Delete(DeleteTarget::RouteServerClient),
            ["delete", "import-policy"] => Command::Delete(DeleteTarget::ImportPolicy),
            ["delete", "export-policy"] => Command::Delete(DeleteTarget::ExportPolicy),
            ["delete", "hold-time"] => Command::Delete(DeleteTarget::HoldTime),
            ["delete", "keepalive-interval"] => Command::Delete(DeleteTarget::KeepaliveInterval),
            ["delete", "connect-retry-time"] => Command::Delete(DeleteTarget::ConnectRetryTime),
            ["delete", "auth"] => Command::Delete(DeleteTarget::Auth),
            ["delete", "ao-key", send_id] => match send_id.parse::<u8>() {
                Ok(send_id) => Command::Delete(DeleteTarget::AoKey(send_id)),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["delete", "routing-table", name] => Command::Delete(DeleteTarget::RoutingTable {
                name: (*name).to_string(),
            }),
            ["delete", "routing-table", name, "bgp-instance"] => {
                Command::Delete(DeleteTarget::RoutingTableBgpInstance {
                    name: (*name).to_string(),
                })
            }
            ["delete", "bgp-instance"] => {
                Command::Delete(DeleteTarget::RoutingTableBgpInstanceRelative)
            }
            ["delete", "routing-table", name, "static-routing-instance"] => {
                Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstance {
                    name: (*name).to_string(),
                })
            }
            ["delete", "static-routing-instance"] => {
                Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstanceRelative)
            }
            ["delete", "routing-table", name, "redistribute"] => {
                Command::Delete(DeleteTarget::RoutingTableRedistribute {
                    name: (*name).to_string(),
                })
            }
            ["delete", "redistribute"] => {
                Command::Delete(DeleteTarget::RoutingTableRedistributeRelative)
            }
            ["delete", "static-routing-instance", name] => {
                Command::Delete(DeleteTarget::StaticRoutingInstance {
                    name: (*name).to_string(),
                })
            }
            ["delete", "static-routing-instance", name, "route", subnet] => {
                match subnet.parse::<IpNet>() {
                    Ok(subnet) => Command::Delete(DeleteTarget::StaticRoute {
                        instance: (*name).to_string(),
                        subnet,
                    }),
                    Err(_) => Command::Unknown(trimmed.to_string()),
                }
            }
            ["delete", "route", subnet] => match subnet.parse::<IpNet>() {
                Ok(subnet) => Command::Delete(DeleteTarget::StaticRouteRelative { subnet }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["delete", "interface", name] => Command::Delete(DeleteTarget::Interface {
                name: (*name).to_string(),
            }),
            ["delete", "interface", name, "address", addr] => match addr.parse::<IpNet>() {
                Ok(address) => Command::Delete(DeleteTarget::InterfaceAddress {
                    name: (*name).to_string(),
                    address,
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["delete", "address", addr] => match addr.parse::<IpNet>() {
                Ok(address) => Command::Delete(DeleteTarget::InterfaceAddressRelative { address }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["delete", "interface", name, "routing-table"] => {
                Command::Delete(DeleteTarget::InterfaceRoutingTable {
                    name: (*name).to_string(),
                })
            }
            ["delete", "routing-table"] => {
                Command::Delete(DeleteTarget::InterfaceRoutingTableRelative)
            }
            ["delete", "community-alias", name] => Command::Delete(DeleteTarget::CommunityAlias {
                name: (*name).to_string(),
            }),
            ["delete", "community-group", name] => Command::Delete(DeleteTarget::CommunityGroup {
                name: (*name).to_string(),
            }),
            ["delete", "community-group", name, "member", member] => {
                Command::Delete(DeleteTarget::CommunityGroupMember {
                    name: (*name).to_string(),
                    member: (*member).to_string(),
                })
            }
            ["delete", "member", member] => {
                Command::Delete(DeleteTarget::CommunityGroupMemberRelative {
                    member: (*member).to_string(),
                })
            }
            ["delete", "prefix-list", name] => Command::Delete(DeleteTarget::PrefixList {
                name: (*name).to_string(),
            }),
            ["delete", "prefix-list", name, "entry", cidr] => match cidr.parse::<IpNet>() {
                Ok(cidr) => Command::Delete(DeleteTarget::PrefixListEntry {
                    name: (*name).to_string(),
                    cidr,
                    range: None,
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["delete", "prefix-list", name, "entry", cidr, "range", min, max] => {
                match (cidr.parse::<IpNet>(), min.parse::<u8>(), max.parse::<u8>()) {
                    (Ok(cidr), Ok(min), Ok(max)) => {
                        Command::Delete(DeleteTarget::PrefixListEntry {
                            name: (*name).to_string(),
                            cidr,
                            range: Some((min, max)),
                        })
                    }
                    _ => Command::Unknown(trimmed.to_string()),
                }
            }
            ["delete", "entry", cidr] => match cidr.parse::<IpNet>() {
                Ok(cidr) => {
                    Command::Delete(DeleteTarget::PrefixListEntryRelative { cidr, range: None })
                }
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["delete", "entry", cidr, "range", min, max] => {
                match (cidr.parse::<IpNet>(), min.parse::<u8>(), max.parse::<u8>()) {
                    (Ok(cidr), Ok(min), Ok(max)) => {
                        Command::Delete(DeleteTarget::PrefixListEntryRelative {
                            cidr,
                            range: Some((min, max)),
                        })
                    }
                    _ => Command::Unknown(trimmed.to_string()),
                }
            }
            _ => Command::Unknown(trimmed.to_string()),
        }
    }
}

fn parse_ao_algorithm(token: &str) -> Option<BgpAoAlgorithm> {
    match token {
        "hmac-sha1" => Some(BgpAoAlgorithm::HmacSha1_96),
        "aes-cmac" => Some(BgpAoAlgorithm::AesCmac96),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_config() {
        assert_eq!(Command::parse("show config"), Command::ShowConfig);
    }

    #[test]
    fn show_config_extra_whitespace() {
        assert_eq!(Command::parse("  show   config  "), Command::ShowConfig);
    }

    #[test]
    fn show_this() {
        assert_eq!(Command::parse("show this"), Command::Show);
    }

    #[test]
    fn bare_show_is_unknown() {
        assert_eq!(Command::parse("show"), Command::Unknown("show".to_string()));
    }

    #[test]
    fn show_route_whole_table() {
        assert_eq!(
            Command::parse("show route rt1"),
            Command::ShowRoute {
                table: "rt1".to_string(),
                address: None,
            }
        );
    }

    #[test]
    fn show_route_with_address() {
        assert_eq!(
            Command::parse("show route rt1 10.0.0.5"),
            Command::ShowRoute {
                table: "rt1".to_string(),
                address: Some("10.0.0.5".parse().unwrap()),
            }
        );
    }

    #[test]
    fn show_route_with_invalid_address_is_unknown() {
        assert_eq!(
            Command::parse("show route rt1 not-an-address"),
            Command::Unknown("show route rt1 not-an-address".to_string())
        );
    }

    #[test]
    fn set_source_line_preserves_leading_whitespace() {
        assert_eq!(
            Command::parse("set source line 2     accept"),
            Command::SetSourceLine {
                line: 2,
                text: "    accept".to_string(),
            }
        );
    }

    #[test]
    fn set_source_line_preserves_deep_indentation() {
        // The generic split_whitespace() matcher used by every other
        // command would collapse this to a single space — this command's
        // whole reason for a dedicated pre-check is that RPL's indentation
        // is semantically meaningful and must survive verbatim.
        assert_eq!(
            Command::parse("set source line 5         set this.bgp.local_pref = 150"),
            Command::SetSourceLine {
                line: 5,
                text: "        set this.bgp.local_pref = 150".to_string(),
            }
        );
    }

    #[test]
    fn set_source_line_with_no_text_is_unknown() {
        assert_eq!(
            Command::parse("set source line 3"),
            Command::Unknown("set source line 3".to_string())
        );
    }

    #[test]
    fn set_source_line_with_non_numeric_line_is_unknown() {
        assert_eq!(
            Command::parse("set source line abc accept"),
            Command::Unknown("set source line abc accept".to_string())
        );
    }

    #[test]
    fn delete_source_line() {
        assert_eq!(
            Command::parse("delete source line 4"),
            Command::DeleteSourceLine { line: 4 }
        );
    }

    #[test]
    fn edit_policy_definition_and_source() {
        assert_eq!(
            Command::parse("edit policy-definition p1"),
            Command::Edit(EditTarget::PolicyDefinition {
                name: "p1".to_string()
            })
        );
        assert_eq!(Command::parse("edit source"), Command::EditSource);
        assert_eq!(Command::parse("show source"), Command::ShowSource);
    }

    #[test]
    fn set_and_delete_import_export_policy_relative() {
        assert_eq!(
            Command::parse("set import-policy accept-all"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::ImportPolicy("accept-all".to_string()),
            })
        );
        assert_eq!(
            Command::parse("set export-policy deny-all"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::ExportPolicy("deny-all".to_string()),
            })
        );
        assert_eq!(
            Command::parse("delete import-policy"),
            Command::Delete(DeleteTarget::ImportPolicy)
        );
        assert_eq!(
            Command::parse("delete export-policy"),
            Command::Delete(DeleteTarget::ExportPolicy)
        );
    }

    #[test]
    fn save() {
        assert_eq!(Command::parse("save"), Command::Save);
    }

    #[test]
    fn help() {
        assert_eq!(Command::parse("help"), Command::Help);
    }

    #[test]
    fn exit_quit_and_end() {
        assert_eq!(Command::parse("exit"), Command::Exit);
        assert_eq!(Command::parse("quit"), Command::Exit);
        assert_eq!(Command::parse("end"), Command::Exit);
    }

    #[test]
    fn commit() {
        assert_eq!(Command::parse("commit"), Command::Commit);
    }

    #[test]
    fn discard_and_abort() {
        assert_eq!(Command::parse("discard"), Command::Discard);
        assert_eq!(Command::parse("abort"), Command::Discard);
    }

    #[test]
    fn diff() {
        assert_eq!(Command::parse("diff"), Command::Diff);
    }

    #[test]
    fn up_and_top() {
        assert_eq!(Command::parse("up"), Command::Up);
        assert_eq!(Command::parse("top"), Command::Top);
    }

    #[test]
    fn empty_line() {
        assert_eq!(Command::parse(""), Command::Empty);
        assert_eq!(Command::parse("   "), Command::Empty);
    }

    #[test]
    fn unknown_command() {
        assert_eq!(
            Command::parse("show interfaces"),
            Command::Unknown("show interfaces".to_string())
        );
    }

    #[test]
    fn configure_default_base() {
        assert_eq!(
            Command::parse("configure my-txn"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: None,
            }
        );
    }

    #[test]
    fn configure_from_blank() {
        assert_eq!(
            Command::parse("configure my-txn from blank"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: Some(TransactionBase::Blank),
            }
        );
    }

    #[test]
    fn configure_from_current() {
        assert_eq!(
            Command::parse("configure my-txn from current"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: Some(TransactionBase::Current),
            }
        );
    }

    #[test]
    fn edit_bgp_instance() {
        assert_eq!(
            Command::parse("edit bgp instance R1"),
            Command::Edit(EditTarget::BgpInstance {
                name: "R1".to_string()
            })
        );
    }

    #[test]
    fn set_bgp_instance_asn_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 asn 65001"),
            Command::Set(SetTarget::BgpInstance {
                name: "R1".to_string(),
                field: BgpInstanceField::Asn(65001),
            })
        );
    }

    #[test]
    fn set_bgp_instance_router_id_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 router-id 10.0.0.1"),
            Command::Set(SetTarget::BgpInstance {
                name: "R1".to_string(),
                field: BgpInstanceField::RouterId(Ipv4Addr::new(10, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn set_asn_qualified_with_malformed_number_is_unknown() {
        assert_eq!(
            Command::parse("set bgp instance R1 asn abc"),
            Command::Unknown("set bgp instance R1 asn abc".to_string())
        );
    }

    #[test]
    fn set_asn_relative() {
        assert_eq!(
            Command::parse("set asn 65001"),
            Command::Set(SetTarget::Relative {
                field: BgpInstanceField::Asn(65001),
            })
        );
    }

    #[test]
    fn set_router_id_relative() {
        assert_eq!(
            Command::parse("set router-id 10.0.0.1"),
            Command::Set(SetTarget::Relative {
                field: BgpInstanceField::RouterId(Ipv4Addr::new(10, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn set_router_id_relative_malformed_ip_is_unknown() {
        assert_eq!(
            Command::parse("set router-id not-an-ip"),
            Command::Unknown("set router-id not-an-ip".to_string())
        );
    }

    #[test]
    fn set_hostname() {
        assert_eq!(
            Command::parse("set hostname router1"),
            Command::Set(SetTarget::Hostname("router1".to_string()))
        );
    }

    #[test]
    fn delete_bare() {
        assert_eq!(
            Command::parse("delete"),
            Command::Delete(DeleteTarget::Current)
        );
    }

    #[test]
    fn delete_bgp_instance_qualified() {
        assert_eq!(
            Command::parse("delete bgp instance R1"),
            Command::Delete(DeleteTarget::BgpInstance {
                name: "R1".to_string()
            })
        );
    }

    #[test]
    fn edit_bgp_peer_group_qualified() {
        assert_eq!(
            Command::parse("edit bgp instance R1 peer-group PG1"),
            Command::Edit(EditTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                name: "PG1".to_string(),
            })
        );
    }

    #[test]
    fn edit_peer_group_relative() {
        assert_eq!(
            Command::parse("edit peer-group PG1"),
            Command::Edit(EditTarget::PeerGroupRelative {
                name: "PG1".to_string()
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_remote_as_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 remote-as 65001"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::RemoteAs(65001),
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_source_address_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 source-address 2001:db8::1"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::SourceAddress("2001:db8::1".parse::<IpAddr>().unwrap()),
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_address_family_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 address-family ipv4"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv4Unicast),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 address-family ipv6"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv6Unicast),
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_timers_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 hold-time 30"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::HoldTime(30),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 keepalive-interval 10"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::KeepaliveInterval(10),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 connect-retry-time 45"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::ConnectRetryTime(45),
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_next_hop_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 next-hop self"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 next-hop unchanged"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
            })
        );
    }

    #[test]
    fn set_peer_group_next_hop_relative() {
        assert_eq!(
            Command::parse("set next-hop self"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
            })
        );
        assert_eq!(
            Command::parse("set next-hop unchanged"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
            })
        );
    }

    #[test]
    fn delete_peer_group_next_hop_relative() {
        assert_eq!(
            Command::parse("delete next-hop"),
            Command::Delete(DeleteTarget::NextHop)
        );
    }

    #[test]
    fn set_bgp_peer_group_route_reflector_and_server_client_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 route-reflector-client"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::RouteReflectorClient,
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 route-server-client"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::RouteServerClient,
            })
        );
    }

    #[test]
    fn set_peer_group_route_reflector_and_server_client_relative() {
        assert_eq!(
            Command::parse("set route-reflector-client"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::RouteReflectorClient,
            })
        );
        assert_eq!(
            Command::parse("set route-server-client"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::RouteServerClient,
            })
        );
    }

    #[test]
    fn delete_peer_group_route_reflector_and_server_client_relative() {
        assert_eq!(
            Command::parse("delete route-reflector-client"),
            Command::Delete(DeleteTarget::RouteReflectorClient)
        );
        assert_eq!(
            Command::parse("delete route-server-client"),
            Command::Delete(DeleteTarget::RouteServerClient)
        );
    }

    #[test]
    fn set_and_delete_bgp_instance_cluster_id_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 cluster-id 1.2.3.4"),
            Command::Set(SetTarget::BgpInstance {
                name: "R1".to_string(),
                field: BgpInstanceField::ClusterId(Ipv4Addr::new(1, 2, 3, 4)),
            })
        );
        assert_eq!(
            Command::parse("delete bgp instance R1 cluster-id"),
            Command::Delete(DeleteTarget::BgpInstanceClusterId {
                name: "R1".to_string(),
            })
        );
    }

    #[test]
    fn set_and_delete_bgp_instance_cluster_id_relative() {
        assert_eq!(
            Command::parse("set cluster-id 1.2.3.4"),
            Command::Set(SetTarget::Relative {
                field: BgpInstanceField::ClusterId(Ipv4Addr::new(1, 2, 3, 4)),
            })
        );
        assert_eq!(
            Command::parse("delete cluster-id"),
            Command::Delete(DeleteTarget::BgpInstanceClusterIdRelative)
        );
    }

    #[test]
    fn set_peer_group_timers_relative() {
        assert_eq!(
            Command::parse("set hold-time 30"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::HoldTime(30),
            })
        );
        assert_eq!(
            Command::parse("set keepalive-interval 10"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::KeepaliveInterval(10),
            })
        );
        assert_eq!(
            Command::parse("set connect-retry-time 45"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::ConnectRetryTime(45),
            })
        );
    }

    #[test]
    fn delete_peer_group_timers_relative() {
        assert_eq!(
            Command::parse("delete hold-time"),
            Command::Delete(DeleteTarget::HoldTime)
        );
        assert_eq!(
            Command::parse("delete keepalive-interval"),
            Command::Delete(DeleteTarget::KeepaliveInterval)
        );
        assert_eq!(
            Command::parse("delete connect-retry-time"),
            Command::Delete(DeleteTarget::ConnectRetryTime)
        );
    }

    #[test]
    fn set_md5_password_qualified_and_relative() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 md5-password hunter2"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::Md5Password("hunter2".to_string()),
            })
        );
        assert_eq!(
            Command::parse("set md5-password hunter2"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::Md5Password("hunter2".to_string()),
            })
        );
    }

    #[test]
    fn set_ao_key_qualified_and_relative() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 ao-key 1 2 hmac-sha1 secret"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AoKey {
                    send_id: 1,
                    recv_id: 2,
                    algorithm: BgpAoAlgorithm::HmacSha1_96,
                    key: "secret".to_string(),
                },
            })
        );
        assert_eq!(
            Command::parse("set ao-key 1 2 aes-cmac secret"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::AoKey {
                    send_id: 1,
                    recv_id: 2,
                    algorithm: BgpAoAlgorithm::AesCmac96,
                    key: "secret".to_string(),
                },
            })
        );
    }

    #[test]
    fn set_ao_key_bad_algorithm_is_unknown() {
        assert_eq!(
            Command::parse("set ao-key 1 2 rot13 secret"),
            Command::Unknown("set ao-key 1 2 rot13 secret".to_string())
        );
    }

    #[test]
    fn set_ao_key_current_and_rnext() {
        assert_eq!(
            Command::parse("set ao-key 1 current"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::AoCurrentKey(1),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 ao-key 1 rnext"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AoRnextKey(1),
            })
        );
    }

    #[test]
    fn delete_auth_and_ao_key() {
        assert_eq!(
            Command::parse("delete auth"),
            Command::Delete(DeleteTarget::Auth)
        );
        assert_eq!(
            Command::parse("delete ao-key 1"),
            Command::Delete(DeleteTarget::AoKey(1))
        );
    }

    #[test]
    fn set_remote_as_relative() {
        assert_eq!(
            Command::parse("set remote-as 65001"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::RemoteAs(65001),
            })
        );
    }

    #[test]
    fn set_peer_qualified_and_relative() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer 192.0.2.1 peer-group PG1"),
            Command::Set(SetTarget::BgpPeer {
                instance: "R1".to_string(),
                remote_address: "192.0.2.1".parse::<IpAddr>().unwrap(),
                peer_group: "PG1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set peer 192.0.2.1 peer-group PG1"),
            Command::Set(SetTarget::PeerRelative {
                remote_address: "192.0.2.1".parse::<IpAddr>().unwrap(),
                peer_group: "PG1".to_string(),
            })
        );
    }

    #[test]
    fn delete_bgp_peer_group_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete bgp instance R1 peer-group PG1"),
            Command::Delete(DeleteTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                name: "PG1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete peer-group PG1"),
            Command::Delete(DeleteTarget::PeerGroupRelative {
                name: "PG1".to_string()
            })
        );
    }

    #[test]
    fn delete_peer_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete bgp instance R1 peer 192.0.2.1"),
            Command::Delete(DeleteTarget::BgpPeer {
                instance: "R1".to_string(),
                remote_address: "192.0.2.1".parse::<IpAddr>().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("delete peer 192.0.2.1"),
            Command::Delete(DeleteTarget::PeerRelative {
                remote_address: "192.0.2.1".parse::<IpAddr>().unwrap(),
            })
        );
    }

    #[test]
    fn edit_routing_table() {
        assert_eq!(
            Command::parse("edit routing-table rt1"),
            Command::Edit(EditTarget::RoutingTable {
                name: "rt1".to_string()
            })
        );
    }

    #[test]
    fn edit_static_routing_instance() {
        assert_eq!(
            Command::parse("edit static-routing-instance sri1"),
            Command::Edit(EditTarget::StaticRoutingInstance {
                name: "sri1".to_string()
            })
        );
    }

    #[test]
    fn set_routing_table_bgp_instance_qualified_and_relative() {
        assert_eq!(
            Command::parse("set routing-table rt1 bgp-instance r1"),
            Command::Set(SetTarget::RoutingTable {
                name: "rt1".to_string(),
                bgp_instance: "r1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set bgp-instance r1"),
            Command::Set(SetTarget::RoutingTableRelative {
                bgp_instance: "r1".to_string(),
            })
        );
    }

    #[test]
    fn set_routing_table_static_routing_instance_qualified_and_relative() {
        assert_eq!(
            Command::parse("set routing-table rt1 static-routing-instance sri1"),
            Command::Set(SetTarget::RoutingTableStaticRoutingInstance {
                name: "rt1".to_string(),
                static_routing_instance: "sri1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set static-routing-instance sri1"),
            Command::Set(SetTarget::RoutingTableStaticRoutingInstanceRelative {
                static_routing_instance: "sri1".to_string(),
            })
        );
    }

    #[test]
    fn set_routing_table_redistribute_qualified_and_relative() {
        let redistribute = Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Bgp,
        };
        assert_eq!(
            Command::parse("set routing-table rt1 redistribute from static to bgp"),
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: "rt1".to_string(),
                redistribute,
            })
        );
        assert_eq!(
            Command::parse("set redistribute from static to bgp"),
            Command::Set(SetTarget::RoutingTableRedistributeRelative { redistribute })
        );
    }

    #[test]
    fn set_static_route_qualified_and_relative() {
        assert_eq!(
            Command::parse("set static-routing-instance sri1 route 10.0.0.0/24 gateway 10.0.0.1"),
            Command::Set(SetTarget::StaticRoute {
                instance: "sri1".to_string(),
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("set route 10.0.0.0/24 gateway 10.0.0.1"),
            Command::Set(SetTarget::StaticRouteRelative {
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
            })
        );
    }

    #[test]
    fn set_static_route_malformed_subnet_is_unknown() {
        assert_eq!(
            Command::parse("set route not-a-subnet gateway 10.0.0.1"),
            Command::Unknown("set route not-a-subnet gateway 10.0.0.1".to_string())
        );
    }

    #[test]
    fn delete_routing_table_and_its_associations() {
        assert_eq!(
            Command::parse("delete routing-table rt1"),
            Command::Delete(DeleteTarget::RoutingTable {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete routing-table rt1 bgp-instance"),
            Command::Delete(DeleteTarget::RoutingTableBgpInstance {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete bgp-instance"),
            Command::Delete(DeleteTarget::RoutingTableBgpInstanceRelative)
        );
        assert_eq!(
            Command::parse("delete routing-table rt1 static-routing-instance"),
            Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstance {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete static-routing-instance"),
            Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstanceRelative)
        );
        assert_eq!(
            Command::parse("delete routing-table rt1 redistribute"),
            Command::Delete(DeleteTarget::RoutingTableRedistribute {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete redistribute"),
            Command::Delete(DeleteTarget::RoutingTableRedistributeRelative)
        );
    }

    #[test]
    fn delete_static_routing_instance_and_its_routes() {
        assert_eq!(
            Command::parse("delete static-routing-instance sri1"),
            Command::Delete(DeleteTarget::StaticRoutingInstance {
                name: "sri1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete static-routing-instance sri1 route 10.0.0.0/24"),
            Command::Delete(DeleteTarget::StaticRoute {
                instance: "sri1".to_string(),
                subnet: "10.0.0.0/24".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("delete route 10.0.0.0/24"),
            Command::Delete(DeleteTarget::StaticRouteRelative {
                subnet: "10.0.0.0/24".parse().unwrap(),
            })
        );
    }

    #[test]
    fn delete_source_address_and_address_family() {
        assert_eq!(
            Command::parse("delete source-address"),
            Command::Delete(DeleteTarget::SourceAddress)
        );
        assert_eq!(
            Command::parse("delete address-family ipv4"),
            Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv4Unicast))
        );
        assert_eq!(
            Command::parse("delete address-family ipv6"),
            Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv6Unicast))
        );
    }

    #[test]
    fn show_log_variants() {
        assert_eq!(
            Command::parse("show log"),
            Command::ShowLog {
                source: None,
                follow: false,
            }
        );
        assert_eq!(
            Command::parse("show log --follow"),
            Command::ShowLog {
                source: None,
                follow: true,
            }
        );
        assert_eq!(
            Command::parse("show log nos-ribd[rt1]"),
            Command::ShowLog {
                source: Some("nos-ribd[rt1]".to_string()),
                follow: false,
            }
        );
        assert_eq!(
            Command::parse("show log nos-ribd[rt1] --follow"),
            Command::ShowLog {
                source: Some("nos-ribd[rt1]".to_string()),
                follow: true,
            }
        );
    }

    #[test]
    fn show_bgp_brief() {
        assert_eq!(Command::parse("show bgp brief"), Command::ShowBgpBrief);
    }

    #[test]
    fn clear_bgp_soft_in() {
        assert_eq!(
            Command::parse("clear bgp r1 10.0.0.1 soft-in"),
            Command::ClearBgpSoftIn {
                instance: "r1".to_string(),
                peer: "10.0.0.1".parse().unwrap(),
            }
        );
        assert_eq!(
            Command::parse("clear bgp r1 not-an-ip soft-in"),
            Command::Unknown("clear bgp r1 not-an-ip soft-in".to_string())
        );
    }

    #[test]
    fn show_interface_all_and_named() {
        assert_eq!(
            Command::parse("show interface"),
            Command::ShowInterface { name: None }
        );
        assert_eq!(
            Command::parse("show interface eth0"),
            Command::ShowInterface {
                name: Some("eth0".to_string())
            }
        );
    }

    #[test]
    fn edit_interface() {
        assert_eq!(
            Command::parse("edit interface eth0"),
            Command::Edit(EditTarget::Interface {
                name: "eth0".to_string()
            })
        );
    }

    #[test]
    fn set_interface_address_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth0 address 10.0.0.1/24"),
            Command::Set(SetTarget::InterfaceAddress {
                name: "eth0".to_string(),
                address: "10.0.0.1/24".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("set address 10.0.0.1/24"),
            Command::Set(SetTarget::InterfaceAddressRelative {
                address: "10.0.0.1/24".parse().unwrap(),
            })
        );
    }

    #[test]
    fn set_interface_address_malformed_is_unknown() {
        assert_eq!(
            Command::parse("set interface eth0 address not-a-cidr"),
            Command::Unknown("set interface eth0 address not-a-cidr".to_string())
        );
    }

    #[test]
    fn set_interface_routing_table_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth0 routing-table rt1"),
            Command::Set(SetTarget::InterfaceRoutingTable {
                name: "eth0".to_string(),
                routing_table: "rt1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set routing-table rt1"),
            Command::Set(SetTarget::InterfaceRoutingTableRelative {
                routing_table: "rt1".to_string(),
            })
        );
    }

    #[test]
    fn delete_interface_qualified() {
        assert_eq!(
            Command::parse("delete interface eth0"),
            Command::Delete(DeleteTarget::Interface {
                name: "eth0".to_string()
            })
        );
    }

    #[test]
    fn delete_interface_address_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete interface eth0 address 10.0.0.1/24"),
            Command::Delete(DeleteTarget::InterfaceAddress {
                name: "eth0".to_string(),
                address: "10.0.0.1/24".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("delete address 10.0.0.1/24"),
            Command::Delete(DeleteTarget::InterfaceAddressRelative {
                address: "10.0.0.1/24".parse().unwrap(),
            })
        );
    }

    #[test]
    fn delete_interface_routing_table_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete interface eth0 routing-table"),
            Command::Delete(DeleteTarget::InterfaceRoutingTable {
                name: "eth0".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete routing-table"),
            Command::Delete(DeleteTarget::InterfaceRoutingTableRelative)
        );
    }

    #[test]
    fn edit_community_alias_group_and_prefix_list() {
        assert_eq!(
            Command::parse("edit community-alias CUSTOMER_A"),
            Command::Edit(EditTarget::CommunityAlias {
                name: "CUSTOMER_A".to_string()
            })
        );
        assert_eq!(
            Command::parse("edit community-group CUSTOMERS"),
            Command::Edit(EditTarget::CommunityGroup {
                name: "CUSTOMERS".to_string()
            })
        );
        assert_eq!(
            Command::parse("edit prefix-list BLOCKS"),
            Command::Edit(EditTarget::PrefixList {
                name: "BLOCKS".to_string()
            })
        );
    }

    #[test]
    fn set_community_alias_value_qualified_and_relative() {
        assert_eq!(
            Command::parse("set community-alias CUSTOMER_A value 65000:100"),
            Command::Set(SetTarget::CommunityAliasValue {
                name: "CUSTOMER_A".to_string(),
                value: "65000:100".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set value 65000:100"),
            Command::Set(SetTarget::CommunityAliasValueRelative {
                value: "65000:100".to_string(),
            })
        );
    }

    #[test]
    fn set_community_group_member_qualified_and_relative() {
        assert_eq!(
            Command::parse("set community-group CUSTOMERS member CUSTOMER_A"),
            Command::Set(SetTarget::CommunityGroupMember {
                name: "CUSTOMERS".to_string(),
                member: "CUSTOMER_A".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set member 65000:200"),
            Command::Set(SetTarget::CommunityGroupMemberRelative {
                member: "65000:200".to_string(),
            })
        );
    }

    #[test]
    fn set_prefix_list_entry_with_and_without_range() {
        assert_eq!(
            Command::parse("set prefix-list BLOCKS entry 10.0.0.0/8"),
            Command::Set(SetTarget::PrefixListEntry {
                name: "BLOCKS".to_string(),
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: None,
            })
        );
        assert_eq!(
            Command::parse("set prefix-list BLOCKS entry 10.0.0.0/8 range 24 32"),
            Command::Set(SetTarget::PrefixListEntry {
                name: "BLOCKS".to_string(),
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((24, 32)),
            })
        );
        assert_eq!(
            Command::parse("set entry 10.0.0.0/8"),
            Command::Set(SetTarget::PrefixListEntryRelative {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: None,
            })
        );
        assert_eq!(
            Command::parse("set entry 10.0.0.0/8 range 24 32"),
            Command::Set(SetTarget::PrefixListEntryRelative {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((24, 32)),
            })
        );
    }

    #[test]
    fn set_prefix_list_entry_malformed_is_unknown() {
        assert_eq!(
            Command::parse("set prefix-list BLOCKS entry not-a-cidr"),
            Command::Unknown("set prefix-list BLOCKS entry not-a-cidr".to_string())
        );
        assert_eq!(
            Command::parse("set entry 10.0.0.0/8 range not-a-number 32"),
            Command::Unknown("set entry 10.0.0.0/8 range not-a-number 32".to_string())
        );
    }

    #[test]
    fn delete_community_alias_group_member_and_prefix_list_entry() {
        assert_eq!(
            Command::parse("delete community-alias CUSTOMER_A"),
            Command::Delete(DeleteTarget::CommunityAlias {
                name: "CUSTOMER_A".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete community-group CUSTOMERS member CUSTOMER_A"),
            Command::Delete(DeleteTarget::CommunityGroupMember {
                name: "CUSTOMERS".to_string(),
                member: "CUSTOMER_A".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete member CUSTOMER_A"),
            Command::Delete(DeleteTarget::CommunityGroupMemberRelative {
                member: "CUSTOMER_A".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete prefix-list BLOCKS"),
            Command::Delete(DeleteTarget::PrefixList {
                name: "BLOCKS".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete prefix-list BLOCKS entry 10.0.0.0/8 range 24 32"),
            Command::Delete(DeleteTarget::PrefixListEntry {
                name: "BLOCKS".to_string(),
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((24, 32)),
            })
        );
        assert_eq!(
            Command::parse("delete entry 10.0.0.0/8"),
            Command::Delete(DeleteTarget::PrefixListEntryRelative {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: None,
            })
        );
    }
}
