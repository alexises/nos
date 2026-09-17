//! The CLI's own command grammar: what can be typed, in what mode, and where
//! its documentation comes from. This is the single source of truth `help`,
//! Tab-completion, and the live `?` key all read from — but it only knows
//! about *syntax* (token order, which is inherently specific to this one
//! client) and *availability* (which `Mode`/`Path` a command is valid in).
//! The *semantic* explanation of what a command does comes from
//! `nos-config` (see `Doc::FromConfig`) — `spec.rs` stays pure and knows
//! nothing about caching or IPC; resolving a `Doc::FromConfig(topic)` into
//! actual text is the caller's job (see `main.rs`'s `doc_for`/`doc_for_blocking`).

use nos_proto::Topic;

use crate::session::{Mode, Path};

/// One piece of a command's token sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    Literal(&'static str),
    Arg(ArgKind),
}

/// What kind of value an argument slot accepts — `BgpInstanceName` and
/// `BgpPeerGroupName` are the slots Tab-completion can fill from live
/// daemon state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    Plain,
    BgpInstanceName,
    BgpPeerGroupName,
    RoutingTableName,
    OspfInstanceName,
    StaticRoutingInstanceName,
    InterfaceName,
    BroadcastDomainName,
    SwitchingProfileName,
}

/// Where a command's summary/detail text comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doc {
    /// Resolve via `nos-config`'s `Request::Describe { topic }` (cached).
    FromConfig(Topic),
    /// Purely local shell mechanics with no server-side meaning.
    Local {
        summary: &'static str,
        detail: &'static str,
    },
}

/// Which `Mode`/`Path` a command is valid in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Always,
    Operational,
    Configuration,
    ConfigurationInstance,
    ConfigurationPeerGroup,
    ConfigurationRoutingTable,
    ConfigurationOspfInstance,
    ConfigurationStaticRoutingInstance,
    ConfigurationInterface,
    /// `Path::Interface`, `Path::Subinterface`, or `Path::BroadcastDomain` —
    /// for address/routing-table commands, valid on a loopback interface
    /// (flat L3 config), a physical interface's subinterface (per-tag L3
    /// config), or a broadcast domain's own SVI (its bridge device's flat L3
    /// config). Distinct from `ConfigurationInterface`, which
    /// switching-profile commands still use since that field stays
    /// interface-only.
    ConfigurationInterfaceOrSubinterface,
    ConfigurationSwitchingProfile,
    /// Any non-root navigation position — `BgpInstance`, `BgpPeerGroup`,
    /// `RoutingTable`, `StaticRoutingInstance`, `Interface`, or
    /// `Subinterface`.
    ConfigurationNested,
}

/// Each `Configuration*` arm asks the same `Path` accessor
/// `session::resolve_table` uses to decide whether the command is valid here,
/// so "what counts as being navigated into an X" is defined once — a command
/// can never be offered by Tab/`?` in a position that would then reject it.
pub fn availability_matches(availability: Availability, mode: &Mode) -> bool {
    let path = match mode {
        Mode::Operational => {
            return matches!(
                availability,
                Availability::Always | Availability::Operational
            )
        }
        Mode::Configuration { path, .. } => path,
    };
    match availability {
        Availability::Always | Availability::Configuration => true,
        Availability::Operational => false,
        Availability::ConfigurationInstance => path.bgp_instance().is_ok(),
        Availability::ConfigurationPeerGroup => path.peer_group().is_ok(),
        Availability::ConfigurationRoutingTable => path.routing_table().is_ok(),
        Availability::ConfigurationOspfInstance => matches!(path, Path::OspfInstance(_)),
        Availability::ConfigurationStaticRoutingInstance => path.static_routing_instance().is_ok(),
        Availability::ConfigurationInterface => path.interface().is_ok(),
        Availability::ConfigurationInterfaceOrSubinterface => path.l3_target().is_ok(),
        Availability::ConfigurationSwitchingProfile => path.switching_profile().is_ok(),
        Availability::ConfigurationNested => matches!(
            path,
            Path::BgpInstance(_)
                | Path::BgpPeerGroup { .. }
                | Path::RoutingTable(_)
                | Path::OspfInstance(_)
                | Path::StaticRoutingInstance(_)
                | Path::Interface(_)
                | Path::Subinterface { .. }
        ),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CommandSpec {
    pub tokens: &'static [Token],
    /// CLI-owned invocation syntax, e.g. `"set bgp instance <name> asn <n>"`.
    pub usage: &'static str,
    pub doc: Doc,
    pub availability: Availability,
}

const EXIT_DOC: Doc = Doc::Local {
    summary: "Exit the shell (or leave configuration mode).",
    detail: "In operational mode, exits the shell entirely. In configuration mode, returns \
             to operational mode instead — prompting to commit, discard, or leave the \
             transaction open first if there are uncommitted changes. `quit` and `end` are \
             synonyms.",
};

/// One token of a command's syntax: a bare string literal is a keyword, a
/// parenthesised identifier is an argument slot naming its `ArgKind`.
macro_rules! tok {
    ($l:literal) => {
        Token::Literal($l)
    };
    (($k:ident)) => {
        Token::Arg(ArgKind::$k)
    };
}

/// One row of the grammar table: its token syntax, the usage string shown to
/// the user, where its prose comes from, and where it's valid.
///
/// ```ignore
/// spec!(["set" "bgp" "instance" (BgpInstanceName) "asn" (Plain)],
///     "set bgp instance <name> asn <n>",
///     Doc::FromConfig(Topic::SetBgpInstanceAsn),
///     Configuration),
/// ```
macro_rules! spec {
    ([$($t:tt)*], $usage:literal, $doc:expr, $avail:ident) => {
        CommandSpec {
            tokens: &[$(tok!($t)),*],
            usage: $usage,
            doc: $doc,
            availability: Availability::$avail,
        }
    };
}

pub const COMMAND_SPECS: &[CommandSpec] = &[
    spec!(["show" "config"],
        "show config",
        Doc::FromConfig(Topic::ShowRunningConfig),
        Always),
    spec!(["show" "this"],
        "show this",
        Doc::FromConfig(Topic::GetTransaction),
        Configuration),
    spec!(["show" "route" (RoutingTableName)],
        "show route <table>",
        Doc::Local {
            summary: "Show every route in a routing table, best to worst per prefix.",
            detail: "Queries the table's nos-ribd instance (resolved via nos-watchdogd) for \
                     every prefix it currently knows, each with its full list of candidate \
                     routes ordered from the winning route to the losing ones — since more \
                     than one source (e.g. static and BGP) can target the same prefix. \
                     Prefixes are listed in ascending CIDR order.",
        },
        Always),
    spec!(["show" "route" (RoutingTableName) (Plain)],
        "show route <table> <address>",
        Doc::Local {
            summary: "Look up the best route(s) for one destination address.",
            detail: "Performs a longest-prefix-match lookup against the table's nos-ribd \
                     instance for the given address, and shows every candidate route for the \
                     matched prefix, ordered from the winning route to the losing ones.",
        },
        Always),
    spec!(["save"], "save", Doc::FromConfig(Topic::Save), Operational),
    spec!(
        ["help"],
        "help",
        Doc::Local {
            summary: "Show available commands for the current mode.",
            detail: "Lists every command valid right now, given whether the shell is in \
                     operational mode or configuration mode (and, within configuration \
                     mode, the current navigation position). Equivalent to pressing `?` on \
                     an empty line.",
        },
        Always
    ),
    spec!(["exit"], "exit", EXIT_DOC, Always),
    spec!(["quit"], "quit", EXIT_DOC, Always),
    spec!(["end"], "end", EXIT_DOC, Always),
    spec!(
        ["configure"(Plain)],
        "configure <name> [from blank|current]",
        Doc::FromConfig(Topic::OpenTransaction),
        Operational
    ),
    spec!(["edit" "bgp" "instance" (BgpInstanceName)],
        "edit bgp instance <name>",
        Doc::FromConfig(Topic::EnsureBgpInstance),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "asn" (Plain)],
        "set bgp instance <name> asn <n>",
        Doc::FromConfig(Topic::SetBgpInstanceAsn),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "router-id" (Plain)],
        "set bgp instance <name> router-id <router-id>",
        Doc::FromConfig(Topic::SetBgpInstanceRouterId),
        Configuration),
    spec!(["set" "asn" (Plain)],
        "set asn <n>",
        Doc::FromConfig(Topic::SetBgpInstanceAsn),
        ConfigurationInstance),
    spec!(["set" "router-id" (Plain)],
        "set router-id <router-id>",
        Doc::FromConfig(Topic::SetBgpInstanceRouterId),
        ConfigurationInstance),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "cluster-id" (Plain)],
        "set bgp instance <name> cluster-id <ip>",
        Doc::FromConfig(Topic::SetBgpInstanceClusterId),
        Configuration),
    spec!(["set" "cluster-id" (Plain)],
        "set cluster-id <ip>",
        Doc::FromConfig(Topic::SetBgpInstanceClusterId),
        ConfigurationInstance),
    spec!(["delete" "bgp" "instance" (BgpInstanceName) "cluster-id"],
        "delete bgp instance <name> cluster-id",
        Doc::FromConfig(Topic::ClearBgpInstanceClusterId),
        Configuration),
    spec!(["delete" "cluster-id"],
        "delete cluster-id",
        Doc::FromConfig(Topic::ClearBgpInstanceClusterId),
        ConfigurationInstance),
    spec!(["set" "hostname" (Plain)],
        "set hostname <name>",
        Doc::FromConfig(Topic::SetHostname),
        Configuration),
    spec!(
        ["delete"],
        "delete",
        Doc::FromConfig(Topic::DeleteBgpInstance),
        ConfigurationNested
    ),
    spec!(["delete" "bgp" "instance" (BgpInstanceName)],
        "delete bgp instance <name>",
        Doc::FromConfig(Topic::DeleteBgpInstance),
        Configuration),
    spec!(["edit" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)],
        "edit bgp instance <name> peer-group <group>",
        Doc::FromConfig(Topic::EnsureBgpPeerGroup),
        Configuration),
    spec!(["edit" "peer-group" (BgpPeerGroupName)],
        "edit peer-group <group>",
        Doc::FromConfig(Topic::EnsureBgpPeerGroup),
        ConfigurationInstance),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "remote-as" (Plain)],
        "set bgp instance <name> peer-group <group> remote-as <n>",
        Doc::FromConfig(Topic::SetBgpPeerGroupRemoteAs),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "source-address" "interface" (InterfaceName)],
        "set bgp instance <name> peer-group <group> source-address interface <name>",
        Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "source-address" "interface" (InterfaceName) "label" (Plain)],
        "set bgp instance <name> peer-group <group> source-address interface <name> label <label>",
        Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "source-address" "loopback"],
        "set bgp instance <name> peer-group <group> source-address loopback",
        Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "source-address" "loopback" "label" (Plain)],
        "set bgp instance <name> peer-group <group> source-address loopback label <label>",
        Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "address-family" "ipv4"],
        "set bgp instance <name> peer-group <group> address-family ipv4",
        Doc::FromConfig(Topic::AddBgpPeerGroupAddressFamily),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "address-family" "ipv6"],
        "set bgp instance <name> peer-group <group> address-family ipv6",
        Doc::FromConfig(Topic::AddBgpPeerGroupAddressFamily),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "hold-time" (Plain)],
        "set bgp instance <name> peer-group <group> hold-time <n>",
        Doc::FromConfig(Topic::SetBgpPeerGroupHoldTime),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "next-hop" "self"],
        "set bgp instance <name> peer-group <group> next-hop self",
        Doc::FromConfig(Topic::SetBgpPeerGroupNextHop),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "next-hop" "unchanged"],
        "set bgp instance <name> peer-group <group> next-hop unchanged",
        Doc::FromConfig(Topic::SetBgpPeerGroupNextHop),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "route-reflector-client"],
        "set bgp instance <name> peer-group <group> route-reflector-client",
        Doc::FromConfig(Topic::SetBgpPeerGroupRouteReflectorClient),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "route-server-client"],
        "set bgp instance <name> peer-group <group> route-server-client",
        Doc::FromConfig(Topic::SetBgpPeerGroupRouteServerClient),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "keepalive-interval" (Plain)],
        "set bgp instance <name> peer-group <group> keepalive-interval <n>",
        Doc::FromConfig(Topic::SetBgpPeerGroupKeepaliveInterval),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "connect-retry-time" (Plain)],
        "set bgp instance <name> peer-group <group> connect-retry-time <n>",
        Doc::FromConfig(Topic::SetBgpPeerGroupConnectRetryTime),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "md5-password" (Plain)],
        "set bgp instance <name> peer-group <group> md5-password <password>",
        Doc::FromConfig(Topic::SetBgpPeerGroupMd5Auth),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "ao-key" (Plain) (Plain) (Plain) (Plain)],
        "set bgp instance <name> peer-group <group> ao-key <send-id> <recv-id> <hmac-sha1|aes-cmac> <key>",
        Doc::FromConfig(Topic::SetBgpPeerGroupAoKey),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "ao-key" (Plain) "current"],
        "set bgp instance <name> peer-group <group> ao-key <send-id> current",
        Doc::FromConfig(Topic::SetBgpPeerGroupAoCurrentKey),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "ao-key" (Plain) "rnext"],
        "set bgp instance <name> peer-group <group> ao-key <send-id> rnext",
        Doc::FromConfig(Topic::SetBgpPeerGroupAoRnextKey),
        Configuration),
    spec!(["set" "remote-as" (Plain)],
        "set remote-as <n>",
        Doc::FromConfig(Topic::SetBgpPeerGroupRemoteAs),
        ConfigurationPeerGroup),
    spec!(["set" "source-address" "interface" (InterfaceName)],
        "set source-address interface <name>",
        Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["set" "source-address" "interface" (InterfaceName) "label" (Plain)],
        "set source-address interface <name> label <label>",
        Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["set" "source-address" "loopback"],
        "set source-address loopback",
        Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["set" "source-address" "loopback" "label" (Plain)],
        "set source-address loopback label <label>",
        Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["set" "address-family" "ipv4"],
        "set address-family ipv4",
        Doc::FromConfig(Topic::AddBgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["set" "address-family" "ipv6"],
        "set address-family ipv6",
        Doc::FromConfig(Topic::AddBgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["set" "next-hop" "self"],
        "set next-hop self",
        Doc::FromConfig(Topic::SetBgpPeerGroupNextHop),
        ConfigurationPeerGroup),
    spec!(["set" "next-hop" "unchanged"],
        "set next-hop unchanged",
        Doc::FromConfig(Topic::SetBgpPeerGroupNextHop),
        ConfigurationPeerGroup),
    spec!(["set" "route-reflector-client"],
        "set route-reflector-client",
        Doc::FromConfig(Topic::SetBgpPeerGroupRouteReflectorClient),
        ConfigurationPeerGroup),
    spec!(["set" "route-server-client"],
        "set route-server-client",
        Doc::FromConfig(Topic::SetBgpPeerGroupRouteServerClient),
        ConfigurationPeerGroup),
    spec!(["set" "hold-time" (Plain)],
        "set hold-time <n>",
        Doc::FromConfig(Topic::SetBgpPeerGroupHoldTime),
        ConfigurationPeerGroup),
    spec!(["set" "keepalive-interval" (Plain)],
        "set keepalive-interval <n>",
        Doc::FromConfig(Topic::SetBgpPeerGroupKeepaliveInterval),
        ConfigurationPeerGroup),
    spec!(["set" "connect-retry-time" (Plain)],
        "set connect-retry-time <n>",
        Doc::FromConfig(Topic::SetBgpPeerGroupConnectRetryTime),
        ConfigurationPeerGroup),
    spec!(["set" "md5-password" (Plain)],
        "set md5-password <password>",
        Doc::FromConfig(Topic::SetBgpPeerGroupMd5Auth),
        ConfigurationPeerGroup),
    spec!(["set" "ao-key" (Plain) (Plain) (Plain) (Plain)],
        "set ao-key <send-id> <recv-id> <hmac-sha1|aes-cmac> <key>",
        Doc::FromConfig(Topic::SetBgpPeerGroupAoKey),
        ConfigurationPeerGroup),
    spec!(["set" "ao-key" (Plain) "current"],
        "set ao-key <send-id> current",
        Doc::FromConfig(Topic::SetBgpPeerGroupAoCurrentKey),
        ConfigurationPeerGroup),
    spec!(["set" "ao-key" (Plain) "rnext"],
        "set ao-key <send-id> rnext",
        Doc::FromConfig(Topic::SetBgpPeerGroupAoRnextKey),
        ConfigurationPeerGroup),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer" (Plain) "peer-group"
           (BgpPeerGroupName)],
        "set bgp instance <name> peer <address> peer-group <group>",
        Doc::FromConfig(Topic::SetBgpPeer),
        Configuration),
    spec!(["set" "peer" (Plain) "peer-group" (BgpPeerGroupName)],
        "set peer <address> peer-group <group>",
        Doc::FromConfig(Topic::SetBgpPeer),
        ConfigurationInstance),
    spec!(["delete" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)],
        "delete bgp instance <name> peer-group <group>",
        Doc::FromConfig(Topic::DeleteBgpPeerGroup),
        Configuration),
    spec!(["delete" "peer-group" (BgpPeerGroupName)],
        "delete peer-group <group>",
        Doc::FromConfig(Topic::DeleteBgpPeerGroup),
        ConfigurationInstance),
    spec!(["delete" "bgp" "instance" (BgpInstanceName) "peer" (Plain)],
        "delete bgp instance <name> peer <address>",
        Doc::FromConfig(Topic::DeleteBgpPeer),
        Configuration),
    spec!(["delete" "peer" (Plain)],
        "delete peer <address>",
        Doc::FromConfig(Topic::DeleteBgpPeer),
        ConfigurationInstance),
    spec!(["delete" "source-address"],
        "delete source-address",
        Doc::FromConfig(Topic::ClearBgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["delete" "address-family" "ipv4"],
        "delete address-family ipv4",
        Doc::FromConfig(Topic::RemoveBgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["delete" "address-family" "ipv6"],
        "delete address-family ipv6",
        Doc::FromConfig(Topic::RemoveBgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["delete" "next-hop"],
        "delete next-hop",
        Doc::FromConfig(Topic::ClearBgpPeerGroupNextHop),
        ConfigurationPeerGroup),
    spec!(["delete" "route-reflector-client"],
        "delete route-reflector-client",
        Doc::FromConfig(Topic::ClearBgpPeerGroupRouteReflectorClient),
        ConfigurationPeerGroup),
    spec!(["delete" "route-server-client"],
        "delete route-server-client",
        Doc::FromConfig(Topic::ClearBgpPeerGroupRouteServerClient),
        ConfigurationPeerGroup),
    spec!(["delete" "hold-time"],
        "delete hold-time",
        Doc::FromConfig(Topic::ClearBgpPeerGroupHoldTime),
        ConfigurationPeerGroup),
    spec!(["delete" "keepalive-interval"],
        "delete keepalive-interval",
        Doc::FromConfig(Topic::ClearBgpPeerGroupKeepaliveInterval),
        ConfigurationPeerGroup),
    spec!(["delete" "connect-retry-time"],
        "delete connect-retry-time",
        Doc::FromConfig(Topic::ClearBgpPeerGroupConnectRetryTime),
        ConfigurationPeerGroup),
    spec!(["delete" "auth"],
        "delete auth",
        Doc::FromConfig(Topic::ClearBgpPeerGroupAuth),
        ConfigurationPeerGroup),
    spec!(["delete" "ao-key" (Plain)],
        "delete ao-key <send-id>",
        Doc::FromConfig(Topic::RemoveBgpPeerGroupAoKey),
        ConfigurationPeerGroup),
    spec!(
        ["up"],
        "up",
        Doc::Local {
            summary: "Navigate up one level.",
            detail: "Moves the current navigation position up one level: from a peer-group, \
                     to its owning BGP instance; from a BGP instance, to the transaction \
                     root (same as `top`).",
        },
        ConfigurationNested
    ),
    spec!(
        ["top"],
        "top",
        Doc::Local {
            summary: "Navigate back to the transaction root.",
            detail: "Moves the current navigation position directly to the transaction \
                     root, regardless of how deep it is.",
        },
        ConfigurationNested
    ),
    spec!(
        ["commit"],
        "commit",
        Doc::FromConfig(Topic::CommitTransaction),
        Configuration
    ),
    spec!(
        ["discard"],
        "discard",
        Doc::FromConfig(Topic::DiscardTransaction),
        Configuration
    ),
    spec!(
        ["abort"],
        "abort",
        Doc::FromConfig(Topic::DiscardTransaction),
        Configuration
    ),
    spec!(
        ["diff"],
        "diff",
        Doc::FromConfig(Topic::DiffTransaction),
        Configuration
    ),
    spec!(["edit" "routing-table" (RoutingTableName)],
        "edit routing-table <name>",
        Doc::FromConfig(Topic::EnsureRoutingTable),
        Configuration),
    spec!(["edit" "ospf" "instance" (OspfInstanceName)],
        "edit ospf instance <name>",
        Doc::FromConfig(Topic::EnsureOspfInstance),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "router-id" (Plain)],
        "set ospf instance <name> router-id <router-id>",
        Doc::FromConfig(Topic::SetOspfInstanceRouterId),
        Configuration),
    spec!(["set" "router-id" (Plain)],
        "set router-id <router-id>",
        Doc::FromConfig(Topic::SetOspfInstanceRouterId),
        ConfigurationOspfInstance),
    spec!(["delete" "ospf" "instance" (OspfInstanceName)],
        "delete ospf instance <name>",
        Doc::FromConfig(Topic::DeleteOspfInstance),
        Configuration),
    spec!(["set" "routing-table" (RoutingTableName) "bgp-instance" (BgpInstanceName)],
        "set routing-table <name> bgp-instance <instance>",
        Doc::FromConfig(Topic::SetRoutingTableBgpInstance),
        Configuration),
    spec!(["set" "bgp-instance" (BgpInstanceName)],
        "set bgp-instance <instance>",
        Doc::FromConfig(Topic::SetRoutingTableBgpInstance),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "bgp-instance"],
        "delete routing-table <name> bgp-instance",
        Doc::FromConfig(Topic::ClearRoutingTableBgpInstance),
        Configuration),
    spec!(["delete" "bgp-instance"],
        "delete bgp-instance",
        Doc::FromConfig(Topic::ClearRoutingTableBgpInstance),
        ConfigurationRoutingTable),
    spec!(["set" "routing-table" (RoutingTableName) "ospf-instance" (OspfInstanceName)],
        "set routing-table <name> ospf-instance <instance>",
        Doc::FromConfig(Topic::SetRoutingTableOspfInstance),
        Configuration),
    spec!(["set" "ospf-instance" (OspfInstanceName)],
        "set ospf-instance <instance>",
        Doc::FromConfig(Topic::SetRoutingTableOspfInstance),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "ospf-instance"],
        "delete routing-table <name> ospf-instance",
        Doc::FromConfig(Topic::ClearRoutingTableOspfInstance),
        Configuration),
    spec!(["delete" "ospf-instance"],
        "delete ospf-instance",
        Doc::FromConfig(Topic::ClearRoutingTableOspfInstance),
        ConfigurationRoutingTable),
    spec!(["set" "routing-table" (RoutingTableName) "static-routing-instance"
           (StaticRoutingInstanceName)],
        "set routing-table <name> static-routing-instance <instance>",
        Doc::FromConfig(Topic::SetRoutingTableStaticRoutingInstance),
        Configuration),
    spec!(["set" "static-routing-instance" (StaticRoutingInstanceName)],
        "set static-routing-instance <instance>",
        Doc::FromConfig(Topic::SetRoutingTableStaticRoutingInstance),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "static-routing-instance"],
        "delete routing-table <name> static-routing-instance",
        Doc::FromConfig(Topic::ClearRoutingTableStaticRoutingInstance),
        Configuration),
    spec!(["delete" "static-routing-instance"],
        "delete static-routing-instance",
        Doc::FromConfig(Topic::ClearRoutingTableStaticRoutingInstance),
        ConfigurationRoutingTable),
    spec!(["set" "routing-table" (RoutingTableName) "redistribute" "from" "static" "to" "bgp"],
        "set routing-table <name> redistribute from static to bgp",
        Doc::FromConfig(Topic::SetRoutingTableRedistribute),
        Configuration),
    spec!(["set" "redistribute" "from" "static" "to" "bgp"],
        "set redistribute from static to bgp",
        Doc::FromConfig(Topic::SetRoutingTableRedistribute),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "redistribute"],
        "delete routing-table <name> redistribute",
        Doc::FromConfig(Topic::ClearRoutingTableRedistribute),
        Configuration),
    spec!(["delete" "redistribute"],
        "delete redistribute",
        Doc::FromConfig(Topic::ClearRoutingTableRedistribute),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName)],
        "delete routing-table <name>",
        Doc::FromConfig(Topic::DeleteRoutingTable),
        Configuration),
    spec!(["edit" "static-routing-instance" (StaticRoutingInstanceName)],
        "edit static-routing-instance <name>",
        Doc::FromConfig(Topic::EnsureStaticRoutingInstance),
        Configuration),
    spec!(["delete" "static-routing-instance" (StaticRoutingInstanceName)],
        "delete static-routing-instance <name>",
        Doc::FromConfig(Topic::DeleteStaticRoutingInstance),
        Configuration),
    spec!(["set" "static-routing-instance" (StaticRoutingInstanceName) "route" (Plain)
           "gateway" (Plain)],
        "set static-routing-instance <name> route <subnet> gateway <address>",
        Doc::FromConfig(Topic::SetStaticRoute),
        Configuration),
    spec!(["set" "route" (Plain) "gateway" (Plain)],
        "set route <subnet> gateway <address>",
        Doc::FromConfig(Topic::SetStaticRoute),
        ConfigurationStaticRoutingInstance),
    spec!(["delete" "static-routing-instance" (StaticRoutingInstanceName) "route" (Plain)],
        "delete static-routing-instance <name> route <subnet>",
        Doc::FromConfig(Topic::DeleteStaticRoute),
        Configuration),
    spec!(["delete" "route" (Plain)],
        "delete route <subnet>",
        Doc::FromConfig(Topic::DeleteStaticRoute),
        ConfigurationStaticRoutingInstance),
    spec!(["edit" "broadcast" "domain" (BroadcastDomainName)],
        "edit broadcast domain <name>",
        Doc::FromConfig(Topic::EnsureBroadcastDomain),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName)],
        "delete broadcast domain <name>",
        Doc::FromConfig(Topic::DeleteBroadcastDomain),
        Configuration),
    spec!(["edit" "switching-profile" (SwitchingProfileName)],
        "edit switching-profile <name>",
        Doc::FromConfig(Topic::EnsureSwitchingProfile),
        Configuration),
    spec!(["delete" "switching-profile" (SwitchingProfileName)],
        "delete switching-profile <name>",
        Doc::FromConfig(Topic::DeleteSwitchingProfile),
        Configuration),
    spec!(["set" "switching-profile" (SwitchingProfileName) "broadcast-domain"
           (BroadcastDomainName) "tag" "dot1q" (Plain)],
        "set switching-profile <name> broadcast-domain <domain> tag dot1q <n>",
        Doc::FromConfig(Topic::AddSwitchingProfileMember),
        Configuration),
    spec!(["set" "switching-profile" (SwitchingProfileName) "broadcast-domain"
           (BroadcastDomainName) "tag" "untagged"],
        "set switching-profile <name> broadcast-domain <domain> tag untagged",
        Doc::FromConfig(Topic::AddSwitchingProfileMember),
        Configuration),
    spec!(["set" "broadcast-domain" (BroadcastDomainName) "tag" "dot1q" (Plain)],
        "set broadcast-domain <domain> tag dot1q <n>",
        Doc::FromConfig(Topic::AddSwitchingProfileMember),
        ConfigurationSwitchingProfile),
    spec!(["set" "broadcast-domain" (BroadcastDomainName) "tag" "untagged"],
        "set broadcast-domain <domain> tag untagged",
        Doc::FromConfig(Topic::AddSwitchingProfileMember),
        ConfigurationSwitchingProfile),
    spec!(["delete" "switching-profile" (SwitchingProfileName) "broadcast-domain"
           (BroadcastDomainName)],
        "delete switching-profile <name> broadcast-domain <domain>",
        Doc::FromConfig(Topic::RemoveSwitchingProfileMember),
        Configuration),
    spec!(["delete" "broadcast-domain" (BroadcastDomainName)],
        "delete broadcast-domain <domain>",
        Doc::FromConfig(Topic::RemoveSwitchingProfileMember),
        ConfigurationSwitchingProfile),
    spec!(["show" "interface"],
        "show interface",
        Doc::Local {
            summary: "Show every interface's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every configured \
                     interface's addresses and routing-table assignment.",
        },
        Always),
    spec!(["show" "interface" (InterfaceName)],
        "show interface <name>",
        Doc::Local {
            summary: "Show one interface's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for the named \
                     interface's addresses and routing-table assignment.",
        },
        Always),
    spec!(["show" "log"],
        "show log",
        Doc::Local {
            summary: "Show the most recent collected log entries from every daemon.",
            detail: "Queries nos-logd (resolved via nos-watchdogd) for its current buffer of \
                     log entries pushed by every other component process.",
        },
        Always),
    spec!(["show" "log" "--follow"],
        "show log --follow",
        Doc::Local {
            summary: "Live-tail collected log entries from every daemon.",
            detail: "Prints the current buffer, then streams new entries as they're pushed to \
                     nos-logd until Ctrl-C is pressed or the connection is lost.",
        },
        Always),
    spec!(["show" "log" (Plain)],
        "show log <source>",
        Doc::Local {
            summary: "Show the most recent collected log entries from one source.",
            detail: "Same as `show log`, filtered to entries whose source exactly matches \
                     <source> (e.g. `nos-ribd[rt1]`, `nos-interfaced`, `nos-configd`).",
        },
        Always),
    spec!(["show" "log" (Plain) "--follow"],
        "show log <source> --follow",
        Doc::Local {
            summary: "Live-tail collected log entries from one source.",
            detail: "Same as `show log --follow`, filtered to entries whose source exactly \
                     matches <source>.",
        },
        Always),
    spec!(["show" "bgp" "brief"],
        "show bgp brief",
        Doc::Local {
            summary: "Show a one-line-per-peer BGP session summary across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for its peers' current session state, remote AS, uptime, \
                     and negotiated hold-time. An instance whose nos-bgpd isn't running is \
                     reported individually rather than aborting the whole command.",
        },
        Always),
    spec!(["clear" "bgp" (BgpInstanceName) (Plain) "soft-in"],
        "clear bgp <instance> <peer> soft-in",
        Doc::Local {
            summary: "Ask a peer to resend its routes (RFC 2918 route refresh).",
            detail: "Sends a BGP ROUTE_REFRESH message to <peer> over its current session on \
                     <instance>'s nos-bgpd, asking it to re-advertise its full Adj-RIB-Out for \
                     every address family this session negotiated. Reported as an error if \
                     <instance> has no established session with <peer> right now.",
        },
        Always),
    spec!(["edit" "interface" (InterfaceName)],
        "edit interface <name>",
        Doc::FromConfig(Topic::EnsureInterface),
        Configuration),
    spec!(["set" "interface" (InterfaceName) "address" (Plain)],
        "set interface <name> address <cidr>",
        Doc::FromConfig(Topic::AddInterfaceAddress),
        Configuration),
    spec!(["set" "address" (Plain)],
        "set address <cidr>",
        Doc::FromConfig(Topic::AddInterfaceAddress),
        ConfigurationInterfaceOrSubinterface),
    spec!(["set" "interface" (InterfaceName) "address" (Plain) "label" (Plain)],
        "set interface <name> address <cidr> label <label>",
        Doc::FromConfig(Topic::AddInterfaceAddress),
        Configuration),
    spec!(["set" "address" (Plain) "label" (Plain)],
        "set address <cidr> label <label>",
        Doc::FromConfig(Topic::AddInterfaceAddress),
        ConfigurationInterfaceOrSubinterface),
    spec!(["delete" "interface" (InterfaceName) "address" (Plain)],
        "delete interface <name> address <cidr>",
        Doc::FromConfig(Topic::RemoveInterfaceAddress),
        Configuration),
    spec!(["delete" "address" (Plain)],
        "delete address <cidr>",
        Doc::FromConfig(Topic::RemoveInterfaceAddress),
        ConfigurationInterfaceOrSubinterface),
    spec!(["set" "interface" (InterfaceName) "routing-table" (RoutingTableName)],
        "set interface <name> routing-table <table>",
        Doc::FromConfig(Topic::SetInterfaceRoutingTable),
        Configuration),
    spec!(["set" "routing-table" (RoutingTableName)],
        "set routing-table <table>",
        Doc::FromConfig(Topic::SetInterfaceRoutingTable),
        ConfigurationInterfaceOrSubinterface),
    spec!(["delete" "interface" (InterfaceName) "routing-table"],
        "delete interface <name> routing-table",
        Doc::FromConfig(Topic::ClearInterfaceRoutingTable),
        Configuration),
    spec!(["delete" "routing-table"],
        "delete routing-table",
        Doc::FromConfig(Topic::ClearInterfaceRoutingTable),
        ConfigurationInterfaceOrSubinterface),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "address" (Plain)],
        "set broadcast domain <name> address <cidr>",
        Doc::FromConfig(Topic::AddBroadcastDomainAddress),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "address" (Plain) "label" (Plain)],
        "set broadcast domain <name> address <cidr> label <label>",
        Doc::FromConfig(Topic::AddBroadcastDomainAddress),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "address" (Plain)],
        "delete broadcast domain <name> address <cidr>",
        Doc::FromConfig(Topic::RemoveBroadcastDomainAddress),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "routing-table" (RoutingTableName)],
        "set broadcast domain <name> routing-table <table>",
        Doc::FromConfig(Topic::SetBroadcastDomainRoutingTable),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "routing-table"],
        "delete broadcast domain <name> routing-table",
        Doc::FromConfig(Topic::ClearBroadcastDomainRoutingTable),
        Configuration),
    spec!(["set" "interface" (InterfaceName) "switching-profile" (SwitchingProfileName)],
        "set interface <name> switching-profile <profile>",
        Doc::FromConfig(Topic::SetInterfaceSwitchingProfile),
        Configuration),
    spec!(["set" "switching-profile" (SwitchingProfileName)],
        "set switching-profile <profile>",
        Doc::FromConfig(Topic::SetInterfaceSwitchingProfile),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "switching-profile"],
        "delete interface <name> switching-profile",
        Doc::FromConfig(Topic::ClearInterfaceSwitchingProfile),
        Configuration),
    spec!(["delete" "switching-profile"],
        "delete switching-profile",
        Doc::FromConfig(Topic::ClearInterfaceSwitchingProfile),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName)],
        "delete interface <name>",
        Doc::FromConfig(Topic::DeleteInterface),
        Configuration),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Command;

    fn config_mode(path: Path) -> Mode {
        Mode::Configuration {
            transaction: "t1".to_string(),
            path,
            dirty: false,
        }
    }

    #[test]
    fn always_matches_every_mode() {
        assert!(availability_matches(
            Availability::Always,
            &Mode::Operational
        ));
        assert!(availability_matches(
            Availability::Always,
            &config_mode(Path::Root)
        ));
        assert!(availability_matches(
            Availability::Always,
            &config_mode(Path::BgpInstance("r1".to_string()))
        ));
    }

    #[test]
    fn operational_only_matches_operational() {
        assert!(availability_matches(
            Availability::Operational,
            &Mode::Operational
        ));
        assert!(!availability_matches(
            Availability::Operational,
            &config_mode(Path::Root)
        ));
    }

    #[test]
    fn configuration_matches_any_path_but_not_operational() {
        assert!(!availability_matches(
            Availability::Configuration,
            &Mode::Operational
        ));
        assert!(availability_matches(
            Availability::Configuration,
            &config_mode(Path::Root)
        ));
        assert!(availability_matches(
            Availability::Configuration,
            &config_mode(Path::BgpInstance("r1".to_string()))
        ));
    }

    #[test]
    fn configuration_instance_only_matches_bgp_instance_path() {
        assert!(!availability_matches(
            Availability::ConfigurationInstance,
            &Mode::Operational
        ));
        assert!(!availability_matches(
            Availability::ConfigurationInstance,
            &config_mode(Path::Root)
        ));
        assert!(availability_matches(
            Availability::ConfigurationInstance,
            &config_mode(Path::BgpInstance("r1".to_string()))
        ));
        assert!(!availability_matches(
            Availability::ConfigurationInstance,
            &config_mode(peer_group_path())
        ));
    }

    fn peer_group_path() -> Path {
        Path::BgpPeerGroup {
            instance: "r1".to_string(),
            group: "pg1".to_string(),
        }
    }

    #[test]
    fn configuration_peer_group_only_matches_peer_group_path() {
        assert!(!availability_matches(
            Availability::ConfigurationPeerGroup,
            &Mode::Operational
        ));
        assert!(!availability_matches(
            Availability::ConfigurationPeerGroup,
            &config_mode(Path::Root)
        ));
        assert!(!availability_matches(
            Availability::ConfigurationPeerGroup,
            &config_mode(Path::BgpInstance("r1".to_string()))
        ));
        assert!(availability_matches(
            Availability::ConfigurationPeerGroup,
            &config_mode(peer_group_path())
        ));
    }

    #[test]
    fn configuration_nested_matches_instance_and_peer_group_but_not_root() {
        assert!(!availability_matches(
            Availability::ConfigurationNested,
            &config_mode(Path::Root)
        ));
        assert!(availability_matches(
            Availability::ConfigurationNested,
            &config_mode(Path::BgpInstance("r1".to_string()))
        ));
        assert!(availability_matches(
            Availability::ConfigurationNested,
            &config_mode(peer_group_path())
        ));
    }

    #[test]
    fn configuration_nested_matches_subinterface() {
        assert!(availability_matches(
            Availability::ConfigurationNested,
            &config_mode(Path::Subinterface {
                interface: "eth0".to_string(),
                tag: 100,
            })
        ));
    }

    #[test]
    fn configuration_interface_or_subinterface_matches_both_but_not_root() {
        assert!(!availability_matches(
            Availability::ConfigurationInterfaceOrSubinterface,
            &config_mode(Path::Root)
        ));
        assert!(availability_matches(
            Availability::ConfigurationInterfaceOrSubinterface,
            &config_mode(Path::Interface("eth0".to_string()))
        ));
        assert!(availability_matches(
            Availability::ConfigurationInterfaceOrSubinterface,
            &config_mode(Path::Subinterface {
                interface: "eth0".to_string(),
                tag: 100,
            })
        ));
    }

    #[test]
    fn operational_mode_hides_every_configuration_only_command() {
        for spec in COMMAND_SPECS {
            if matches!(
                spec.availability,
                Availability::Configuration
                    | Availability::ConfigurationInstance
                    | Availability::ConfigurationPeerGroup
                    | Availability::ConfigurationNested
            ) {
                assert!(
                    !availability_matches(spec.availability, &Mode::Operational),
                    "{} should not be available in Operational mode",
                    spec.usage
                );
            }
        }
    }

    /// Drift guard: every literal-only spec's usage string must actually
    /// parse to something other than `Command::Unknown`, keeping this
    /// grammar table honest against `command::Command::parse`.
    #[test]
    fn literal_only_specs_parse_successfully() {
        for spec in COMMAND_SPECS {
            let all_literal = spec.tokens.iter().all(|t| matches!(t, Token::Literal(_)));
            if !all_literal {
                continue;
            }
            let parsed = Command::parse(spec.usage);
            assert!(
                !matches!(parsed, Command::Unknown(_)),
                "spec usage {:?} parsed to Unknown",
                spec.usage
            );
        }
    }
}
