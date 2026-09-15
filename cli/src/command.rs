use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use nos_proto::{
    AddressFamily, BgpAoAlgorithm, Redistribute, RedistributeSource, RedistributeTarget,
    TransactionBase,
};

/// A single field edit targeting a BGP instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpInstanceField {
    Asn(u32),
    RouterId(Ipv4Addr),
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
}
