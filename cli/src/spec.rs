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
    OspfProfileName,
    Ospfv3InstanceName,
    Ospfv3ProfileName,
    StaticRoutingInstanceName,
    InterfaceName,
    BroadcastDomainName,
    SwitchingProfileName,
    PortAggregateName,
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
    ConfigurationOspfArea,
    ConfigurationOspfProfile,
    ConfigurationOspfv3Instance,
    ConfigurationOspfv3Area,
    ConfigurationOspfv3Profile,
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
    /// `Path::Interface` or `Path::OspfProfile` — `set`/`delete mtu`'s
    /// shared, path-disambiguated token (see `SetTarget::MtuRelative`).
    ConfigurationInterfaceOrOspfProfile,
    ConfigurationSwitchingProfile,
    ConfigurationPortAggregate,
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
        Availability::ConfigurationOspfInstance => path.ospf_instance().is_ok(),
        Availability::ConfigurationOspfArea => path.ospf_area().is_ok(),
        Availability::ConfigurationOspfProfile => path.ospf_profile().is_ok(),
        Availability::ConfigurationOspfv3Instance => path.ospfv3_instance().is_ok(),
        Availability::ConfigurationOspfv3Area => path.ospfv3_area().is_ok(),
        Availability::ConfigurationOspfv3Profile => path.ospfv3_profile().is_ok(),
        Availability::ConfigurationStaticRoutingInstance => path.static_routing_instance().is_ok(),
        Availability::ConfigurationInterface => path.interface().is_ok(),
        Availability::ConfigurationInterfaceOrSubinterface => path.l3_target().is_ok(),
        Availability::ConfigurationInterfaceOrOspfProfile => {
            path.interface().is_ok() || path.ospf_profile().is_ok() || path.ospfv3_profile().is_ok()
        }
        Availability::ConfigurationSwitchingProfile => path.switching_profile().is_ok(),
        Availability::ConfigurationPortAggregate => path.port_aggregate().is_ok(),
        Availability::ConfigurationNested => matches!(
            path,
            Path::BgpInstance(_)
                | Path::BgpPeerGroup { .. }
                | Path::RoutingTable(_)
                | Path::OspfInstance(_)
                | Path::OspfArea { .. }
                | Path::OspfProfile { .. }
                | Path::Ospfv3Instance(_)
                | Path::Ospfv3Area { .. }
                | Path::Ospfv3Profile { .. }
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
    spec!(["show" "fdb" (BroadcastDomainName)],
        "show fdb <domain>",
        Doc::Local {
            summary: "Show a broadcast domain's forwarding database.",
            detail: "Queries the domain's nos-fdbd instance (resolved via nos-watchdogd) for \
                     the MACs behind its VXLAN device — learned locally on the bridge, or \
                     from EVPN Type-2 routes with the VTEP they sit behind — and the remote \
                     VTEPs its flood list replicates broadcast/unknown/multicast traffic to.",
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
    spec!(["set" "user" (Plain) "password" (Plain)],
        "set user <name> password <clear>",
        Doc::Local {
            summary: "Create a user or change its password.",
            detail: "Users log in to the shell and authenticate every REST request. The password \
                     is stored as an argon2id hash; setting the same password again leaves the \
                     stored hash (and the diff) unchanged. Every user is a full administrator.",
        },
        Configuration),
    spec!(["delete" "user" (Plain)],
        "delete user <name>",
        Doc::Local {
            summary: "Delete a user.",
            detail: "Committing a config with no users left is refused, so you cannot lock yourself out.",
        },
        Configuration),
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
           "address-family" "l2vpn-evpn"],
        "set bgp instance <name> peer-group <group> address-family l2vpn-evpn",
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
    spec!(["set" "address-family" "l2vpn-evpn"],
        "set address-family l2vpn-evpn",
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
    spec!(["delete" "address-family" "l2vpn-evpn"],
        "delete address-family l2vpn-evpn",
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
    // Shares its token sequence with the peer-group `delete auth` above —
    // `Availability` disambiguates by path, mirroring `set router-id`'s
    // shared-tokens precedent.
    spec!(["delete" "auth"],
        "delete auth",
        Doc::FromConfig(Topic::ClearOspfProfileAuth),
        ConfigurationOspfProfile),
    spec!(["delete" "crypto-key" (Plain)],
        "delete crypto-key <key-id>",
        Doc::FromConfig(Topic::RemoveOspfProfileCryptoKey),
        ConfigurationOspfProfile),
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
    spec!(["edit" "ospf" "instance" (OspfInstanceName) "area" (Plain)],
        "edit ospf instance <name> area <area-id>",
        Doc::FromConfig(Topic::EnsureOspfArea),
        Configuration),
    spec!(["edit" "area" (Plain)],
        "edit area <area-id>",
        Doc::FromConfig(Topic::EnsureOspfArea),
        ConfigurationOspfInstance),
    spec!(["delete" "ospf" "instance" (OspfInstanceName) "area" (Plain)],
        "delete ospf instance <name> area <area-id>",
        Doc::FromConfig(Topic::DeleteOspfArea),
        Configuration),
    spec!(["delete" "area" (Plain)],
        "delete area <area-id>",
        Doc::FromConfig(Topic::DeleteOspfArea),
        ConfigurationOspfInstance),
    spec!(["edit" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)],
        "edit ospf instance <name> area <area-id> profile <profile-name>",
        Doc::FromConfig(Topic::EnsureOspfProfile),
        Configuration),
    spec!(["edit" "profile" (OspfProfileName)],
        "edit profile <profile-name>",
        Doc::FromConfig(Topic::EnsureOspfProfile),
        ConfigurationOspfArea),
    spec!(["delete" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)],
        "delete ospf instance <name> area <area-id> profile <profile-name>",
        Doc::FromConfig(Topic::DeleteOspfProfile),
        Configuration),
    spec!(["delete" "profile" (OspfProfileName)],
        "delete profile <profile-name>",
        Doc::FromConfig(Topic::DeleteOspfProfile),
        ConfigurationOspfArea),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "hello-interval" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> hello-interval <n>",
        Doc::FromConfig(Topic::SetOspfProfileHelloInterval),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "dead-interval" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> dead-interval <n>",
        Doc::FromConfig(Topic::SetOspfProfileDeadInterval),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "cost" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> cost <n>",
        Doc::FromConfig(Topic::SetOspfProfileCost),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "priority" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> priority <n>",
        Doc::FromConfig(Topic::SetOspfProfilePriority),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "mtu" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> mtu <n>",
        Doc::FromConfig(Topic::SetOspfProfileMtu),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "network-type" "point-to-point"],
        "set ospf instance <name> area <area-id> profile <profile-name> network-type point-to-point",
        Doc::FromConfig(Topic::SetOspfProfileNetworkType),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "network-type" "broadcast"],
        "set ospf instance <name> area <area-id> profile <profile-name> network-type broadcast",
        Doc::FromConfig(Topic::SetOspfProfileNetworkType),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "simple-password" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> simple-password <password>",
        Doc::FromConfig(Topic::SetOspfProfileSimpleAuth),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "crypto-key" (Plain) (Plain) (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> crypto-key <key-id> <md5|hmac-sha1|hmac-sha256|hmac-sha384|hmac-sha512> <key>",
        Doc::FromConfig(Topic::SetOspfProfileCryptoKey),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "crypto-key" (Plain) "current"],
        "set ospf instance <name> area <area-id> profile <profile-name> crypto-key <key-id> current",
        Doc::FromConfig(Topic::SetOspfProfileCryptoCurrentKey),
        Configuration),
    spec!(["set" "hello-interval" (Plain)],
        "set hello-interval <n>",
        Doc::FromConfig(Topic::SetOspfProfileHelloInterval),
        ConfigurationOspfProfile),
    spec!(["set" "dead-interval" (Plain)],
        "set dead-interval <n>",
        Doc::FromConfig(Topic::SetOspfProfileDeadInterval),
        ConfigurationOspfProfile),
    spec!(["set" "cost" (Plain)],
        "set cost <n>",
        Doc::FromConfig(Topic::SetOspfProfileCost),
        ConfigurationOspfProfile),
    spec!(["set" "priority" (Plain)],
        "set priority <n>",
        Doc::FromConfig(Topic::SetOspfProfilePriority),
        ConfigurationOspfProfile),
    spec!(["set" "network-type" "point-to-point"],
        "set network-type point-to-point",
        Doc::FromConfig(Topic::SetOspfProfileNetworkType),
        ConfigurationOspfProfile),
    spec!(["set" "network-type" "broadcast"],
        "set network-type broadcast",
        Doc::FromConfig(Topic::SetOspfProfileNetworkType),
        ConfigurationOspfProfile),
    spec!(["set" "simple-password" (Plain)],
        "set simple-password <password>",
        Doc::FromConfig(Topic::SetOspfProfileSimpleAuth),
        ConfigurationOspfProfile),
    spec!(["set" "crypto-key" (Plain) (Plain) (Plain)],
        "set crypto-key <key-id> <md5|hmac-sha1|hmac-sha256|hmac-sha384|hmac-sha512> <key>",
        Doc::FromConfig(Topic::SetOspfProfileCryptoKey),
        ConfigurationOspfProfile),
    spec!(["set" "crypto-key" (Plain) "current"],
        "set crypto-key <key-id> current",
        Doc::FromConfig(Topic::SetOspfProfileCryptoCurrentKey),
        ConfigurationOspfProfile),
    spec!(["delete" "hello-interval"],
        "delete hello-interval",
        Doc::FromConfig(Topic::ClearOspfProfileHelloInterval),
        ConfigurationOspfProfile),
    spec!(["delete" "dead-interval"],
        "delete dead-interval",
        Doc::FromConfig(Topic::ClearOspfProfileDeadInterval),
        ConfigurationOspfProfile),
    spec!(["delete" "cost"],
        "delete cost",
        Doc::FromConfig(Topic::ClearOspfProfileCost),
        ConfigurationOspfProfile),
    spec!(["delete" "priority"],
        "delete priority",
        Doc::FromConfig(Topic::ClearOspfProfilePriority),
        ConfigurationOspfProfile),
    spec!(["delete" "network-type"],
        "delete network-type",
        Doc::FromConfig(Topic::ClearOspfProfileNetworkType),
        ConfigurationOspfProfile),
    spec!(["edit" "ospfv3" "instance" (Ospfv3InstanceName)],
        "edit ospfv3 instance <name>",
        Doc::Local {
            summary: "Create (if missing) and navigate into an OSPFv3 (RFC 5340) instance.",
            detail: "Mirrors 'edit ospf instance <name>' for OSPFv3.",
        },
        Configuration),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "router-id" (Plain)],
        "set ospfv3 instance <name> router-id <router-id>",
        Doc::Local {
            summary: "Set an OSPFv3 instance's router-id.",
            detail: "Mirrors 'set ospf instance <name> router-id <router-id>' for OSPFv3.",
        },
        Configuration),
    spec!(["set" "router-id" (Plain)],
        "set router-id <router-id>",
        Doc::Local {
            summary: "Set the current OSPFv3 instance's router-id.",
            detail: "Shares its token sequence with the same relative command on a BGP \
                     instance or an OSPF instance; which one applies is resolved by the \
                     current navigation position.",
        },
        ConfigurationOspfv3Instance),
    spec!(["delete" "ospfv3" "instance" (Ospfv3InstanceName)],
        "delete ospfv3 instance <name>",
        Doc::Local {
            summary: "Delete an OSPFv3 instance.",
            detail: "Mirrors 'delete ospf instance <name>' for OSPFv3.",
        },
        Configuration),
    spec!(["edit" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain)],
        "edit ospfv3 instance <name> area <area-id>",
        Doc::Local {
            summary: "Create (if missing) and navigate into an OSPFv3 area.",
            detail: "Mirrors 'edit ospf instance <name> area <area-id>' for OSPFv3.",
        },
        Configuration),
    spec!(["edit" "area" (Plain)],
        "edit area <area-id>",
        Doc::Local {
            summary: "Create (if missing) and navigate into an area of the current instance.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     instance; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Instance),
    spec!(["delete" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain)],
        "delete ospfv3 instance <name> area <area-id>",
        Doc::Local {
            summary: "Delete an OSPFv3 area.",
            detail: "Mirrors 'delete ospf instance <name> area <area-id>' for OSPFv3.",
        },
        Configuration),
    spec!(["delete" "area" (Plain)],
        "delete area <area-id>",
        Doc::Local {
            summary: "Delete an area of the current instance.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     instance; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Instance),
    spec!(["edit" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)],
        "edit ospfv3 instance <name> area <area-id> profile <profile-name>",
        Doc::Local {
            summary: "Create (if missing) and navigate into an OSPFv3 profile.",
            detail: "Mirrors 'edit ospf instance <name> area <area-id> profile <profile-name>' \
                     for OSPFv3.",
        },
        Configuration),
    spec!(["edit" "profile" (Ospfv3ProfileName)],
        "edit profile <profile-name>",
        Doc::Local {
            summary: "Create (if missing) and navigate into a profile of the current area.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     area; which one applies is resolved by the current navigation position.",
        },
        ConfigurationOspfv3Area),
    spec!(["delete" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)],
        "delete ospfv3 instance <name> area <area-id> profile <profile-name>",
        Doc::Local {
            summary: "Delete an OSPFv3 profile.",
            detail: "Mirrors 'delete ospf instance <name> area <area-id> profile \
                     <profile-name>' for OSPFv3.",
        },
        Configuration),
    spec!(["delete" "profile" (Ospfv3ProfileName)],
        "delete profile <profile-name>",
        Doc::Local {
            summary: "Delete a profile of the current area.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     area; which one applies is resolved by the current navigation position.",
        },
        ConfigurationOspfv3Area),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "hello-interval" (Plain)],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> hello-interval <n>",
        Doc::Local {
            summary: "Set an OSPFv3 profile's hello-interval.",
            detail: "Mirrors the OSPF equivalent for OSPFv3.",
        },
        Configuration),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "dead-interval" (Plain)],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> dead-interval <n>",
        Doc::Local {
            summary: "Set an OSPFv3 profile's dead-interval.",
            detail: "Mirrors the OSPF equivalent for OSPFv3.",
        },
        Configuration),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "cost" (Plain)],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> cost <n>",
        Doc::Local {
            summary: "Set an OSPFv3 profile's cost.",
            detail: "Mirrors the OSPF equivalent for OSPFv3.",
        },
        Configuration),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "priority" (Plain)],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> priority <n>",
        Doc::Local {
            summary: "Set an OSPFv3 profile's priority.",
            detail: "Mirrors the OSPF equivalent for OSPFv3.",
        },
        Configuration),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "mtu" (Plain)],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> mtu <n>",
        Doc::Local {
            summary: "Override an OSPFv3 profile's mtu.",
            detail: "Mirrors the OSPF equivalent for OSPFv3.",
        },
        Configuration),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "network-type" "point-to-point"],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> network-type point-to-point",
        Doc::Local {
            summary: "Override an OSPFv3 profile's network type to point-to-point.",
            detail: "Mirrors the OSPF equivalent for OSPFv3.",
        },
        Configuration),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "network-type" "broadcast"],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> network-type broadcast",
        Doc::Local {
            summary: "Override an OSPFv3 profile's network type to broadcast.",
            detail: "Mirrors the OSPF equivalent for OSPFv3.",
        },
        Configuration),
    spec!(["set" "hello-interval" (Plain)],
        "set hello-interval <n>",
        Doc::Local {
            summary: "Set the current profile's hello-interval.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["set" "dead-interval" (Plain)],
        "set dead-interval <n>",
        Doc::Local {
            summary: "Set the current profile's dead-interval.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["set" "cost" (Plain)],
        "set cost <n>",
        Doc::Local {
            summary: "Set the current profile's cost.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["set" "priority" (Plain)],
        "set priority <n>",
        Doc::Local {
            summary: "Set the current profile's priority.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["set" "network-type" "point-to-point"],
        "set network-type point-to-point",
        Doc::Local {
            summary: "Override the current profile's network type to point-to-point.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["set" "network-type" "broadcast"],
        "set network-type broadcast",
        Doc::Local {
            summary: "Override the current profile's network type to broadcast.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["delete" "hello-interval"],
        "delete hello-interval",
        Doc::Local {
            summary: "Clear the current profile's hello-interval override.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["delete" "dead-interval"],
        "delete dead-interval",
        Doc::Local {
            summary: "Clear the current profile's dead-interval override.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["delete" "cost"],
        "delete cost",
        Doc::Local {
            summary: "Clear the current profile's cost override.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["delete" "priority"],
        "delete priority",
        Doc::Local {
            summary: "Clear the current profile's priority override.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["delete" "network-type"],
        "delete network-type",
        Doc::Local {
            summary: "Clear the current profile's network-type override.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["set" "interface" (InterfaceName) "ospfv3" (Ospfv3ProfileName)],
        "set interface <name> ospfv3 <profile-name>",
        Doc::Local {
            summary: "Join OSPFv3 (RFC 5340) under a profile on this attach point.",
            detail: "Mirrors 'set interface <name> ospf <profile-name>' for OSPFv3 — requires \
                     a routing-table already set on the same attach point, checked at commit \
                     time.",
        },
        Configuration),
    spec!(["set" "ospfv3" (Ospfv3ProfileName)],
        "set ospfv3 <profile-name>",
        Doc::Local {
            summary: "Join OSPFv3 under a profile on the current attach point.",
            detail: "Context-relative form of 'set interface <name> ospfv3 <profile-name>' — \
                     valid while navigated into a loopback interface, a subinterface, or a \
                     broadcast domain.",
        },
        ConfigurationInterfaceOrSubinterface),
    spec!(["delete" "interface" (InterfaceName) "ospfv3"],
        "delete interface <name> ospfv3",
        Doc::Local {
            summary: "Clear an interface's OSPFv3 profile association.",
            detail: "Mirrors 'delete interface <name> ospf' for OSPFv3.",
        },
        Configuration),
    spec!(["delete" "ospfv3"],
        "delete ospfv3",
        Doc::Local {
            summary: "Clear the current attach point's OSPFv3 profile association.",
            detail: "Context-relative form of 'delete interface <name> ospfv3'.",
        },
        ConfigurationInterfaceOrSubinterface),
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
    spec!(["set" "routing-table" (RoutingTableName) "ospfv3-instance" (Ospfv3InstanceName)],
        "set routing-table <name> ospfv3-instance <instance>",
        Doc::Local {
            summary: "Associate an OSPFv3 instance with a routing table.",
            detail: "Mirrors 'set routing-table <name> ospf-instance <instance>' for OSPFv3.",
        },
        Configuration),
    spec!(["set" "ospfv3-instance" (Ospfv3InstanceName)],
        "set ospfv3-instance <instance>",
        Doc::Local {
            summary: "Associate an OSPFv3 instance with the current routing table.",
            detail: "Context-relative form of 'set routing-table <name> ospfv3-instance \
                     <instance>'.",
        },
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "ospfv3-instance"],
        "delete routing-table <name> ospfv3-instance",
        Doc::Local {
            summary: "Clear a routing table's OSPFv3 instance association.",
            detail: "Mirrors 'delete routing-table <name> ospf-instance' for OSPFv3.",
        },
        Configuration),
    spec!(["delete" "ospfv3-instance"],
        "delete ospfv3-instance",
        Doc::Local {
            summary: "Clear the current routing table's OSPFv3 instance association.",
            detail: "Context-relative form of 'delete routing-table <name> ospfv3-instance'.",
        },
        ConfigurationRoutingTable),
    spec!(["set" "routing-table" (RoutingTableName) "rest-api" "address" (Plain)],
        "set routing-table <name> rest-api address <ip>",
        Doc::Local {
            summary: "Pin the REST API (nos-restd) to a routing table on the given address.",
            detail: "nos-restd listens on <ip> inside the table's VRF, port 8080. Every request \
                     needs HTTP Basic credentials of a configured user ('set user <name> \
                     password <clear>'). The address must be a specific unicast address already configured on an \
                     interface in that VRF; until it is, nos-restd keeps retrying the bind.",
        },
        Configuration),
    spec!(["set" "routing-table" (RoutingTableName) "rest-api" "address" (Plain) "port" (Plain)],
        "set routing-table <name> rest-api address <ip> port <port>",
        Doc::Local {
            summary: "Pin the REST API (nos-restd) to a routing table on the given address and port.",
            detail: "Same as 'set routing-table <name> rest-api address <ip>', with an explicit \
                     TCP port instead of the default 8080.",
        },
        Configuration),
    spec!(["set" "rest-api" "address" (Plain)],
        "set rest-api address <ip>",
        Doc::Local {
            summary: "Pin the REST API to the current routing table on the given address.",
            detail: "Context-relative form of 'set routing-table <name> rest-api address <ip>'.",
        },
        ConfigurationRoutingTable),
    spec!(["set" "rest-api" "address" (Plain) "port" (Plain)],
        "set rest-api address <ip> port <port>",
        Doc::Local {
            summary: "Pin the REST API to the current routing table on the given address and port.",
            detail: "Context-relative form of 'set routing-table <name> rest-api address <ip> \
                     port <port>'.",
        },
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "rest-api"],
        "delete routing-table <name> rest-api",
        Doc::Local {
            summary: "Unpin the REST API from a routing table (stops its nos-restd).",
            detail: "Clears the table's rest-api setting; nos-watchdogd stops the table's \
                     nos-restd process.",
        },
        Configuration),
    spec!(["delete" "rest-api"],
        "delete rest-api",
        Doc::Local {
            summary: "Unpin the REST API from the current routing table.",
            detail: "Context-relative form of 'delete routing-table <name> rest-api'.",
        },
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
    spec!(["set" "routing-table" (RoutingTableName) "redistribute" "from" "static" "to" "ospf"],
        "set routing-table <name> redistribute from static to ospf",
        Doc::FromConfig(Topic::SetRoutingTableRedistribute),
        Configuration),
    spec!(["set" "redistribute" "from" "static" "to" "ospf"],
        "set redistribute from static to ospf",
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
    spec!(["edit" "port-aggregate" (PortAggregateName)],
        "edit port-aggregate <name>",
        Doc::FromConfig(Topic::EnsurePortAggregate),
        Configuration),
    spec!(["delete" "port-aggregate" (PortAggregateName)],
        "delete port-aggregate <name>",
        Doc::FromConfig(Topic::DeletePortAggregate),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "mode" "xor"],
        "set port-aggregate <name> mode xor",
        Doc::FromConfig(Topic::SetPortAggregateMode),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "mode" "lacp"],
        "set port-aggregate <name> mode lacp",
        Doc::FromConfig(Topic::SetPortAggregateMode),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "lacp-rate" "fast"],
        "set port-aggregate <name> lacp-rate fast",
        Doc::FromConfig(Topic::SetPortAggregateLacpRate),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "lacp-rate" "slow"],
        "set port-aggregate <name> lacp-rate slow",
        Doc::FromConfig(Topic::SetPortAggregateLacpRate),
        Configuration),
    spec!(["set" "lacp-rate" "fast"],
        "set lacp-rate fast",
        Doc::FromConfig(Topic::SetPortAggregateLacpRate),
        ConfigurationPortAggregate),
    spec!(["set" "lacp-rate" "slow"],
        "set lacp-rate slow",
        Doc::FromConfig(Topic::SetPortAggregateLacpRate),
        ConfigurationPortAggregate),
    spec!(["set" "mode" "xor"],
        "set mode xor",
        Doc::FromConfig(Topic::SetPortAggregateMode),
        ConfigurationPortAggregate),
    spec!(["set" "mode" "lacp"],
        "set mode lacp",
        Doc::FromConfig(Topic::SetPortAggregateMode),
        ConfigurationPortAggregate),
    spec!(["set" "interface" (InterfaceName) "port-aggregate" (PortAggregateName)],
        "set interface <name> port-aggregate <aggregate>",
        Doc::FromConfig(Topic::SetInterfacePortAggregate),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName)],
        "set port-aggregate <aggregate>",
        Doc::FromConfig(Topic::SetInterfacePortAggregate),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "port-aggregate"],
        "delete interface <name> port-aggregate",
        Doc::FromConfig(Topic::ClearInterfacePortAggregate),
        Configuration),
    spec!(["delete" "port-aggregate"],
        "delete port-aggregate",
        Doc::FromConfig(Topic::ClearInterfacePortAggregate),
        ConfigurationInterface),
    spec!(["show" "port-aggregate"],
        "show port-aggregate",
        Doc::Local {
            summary: "Show every port aggregate's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every configured \
                     port aggregate's mode, switching-profile, mtu, and subinterfaces.",
        },
        Always),
    spec!(["show" "port-aggregate" (PortAggregateName)],
        "show port-aggregate <name>",
        Doc::Local {
            summary: "Show one port aggregate's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for the named port \
                     aggregate's mode, switching-profile, mtu, and subinterfaces.",
        },
        Always),
    spec!(["show" "lldp" "neighbors"],
        "show lldp neighbors",
        Doc::Local {
            summary: "Show every LLDP neighbor heard on any interface.",
            detail: "Queries nos-lldpd (resolved via nos-watchdogd) for every neighbor learned \
                     from received LLDPDUs (IEEE 802.1AB): the local interface it was heard on, \
                     its chassis id, port id, system name and enabled capabilities, and how long \
                     until its entry ages out.",
        },
        Always),
    spec!(["show" "lacp"],
        "show lacp",
        Doc::Local {
            summary: "Show every LACP port aggregate's negotiation state.",
            detail: "Queries nos-lacpd (resolved via nos-watchdogd) for every lacp-mode port \
                     aggregate's actor system id, key and rate, and each member port's \
                     receive/mux machine state, partner identity, and whether it is selected \
                     and synchronized.",
        },
        Always),
    spec!(["show" "lacp" (PortAggregateName)],
        "show lacp <name>",
        Doc::Local {
            summary: "Show one LACP port aggregate's negotiation state.",
            detail: "Queries nos-lacpd (resolved via nos-watchdogd) for the named lacp-mode \
                     port aggregate's actor identity and rate, and each member port's \
                     receive/mux machine state and partner identity.",
        },
        Always),
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
    spec!(["show" "bgp" "evpn"],
        "show bgp evpn",
        Doc::Local {
            summary: "Show every EVPN route received from BGP peers, across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for the EVPN (AFI 25 / SAFI 70) routes its peers sent: \
                     route type, NLRI, next-hop and extended communities (Route Targets, \
                     Encapsulation). Only peers whose peer-group has `address-family \
                     l2vpn-evpn` exchange them. An instance whose nos-bgpd isn't running is \
                     reported individually rather than aborting the whole command.",
        },
        Always),
    spec!(["show" "ospf" "neigh"],
        "show ospf neigh",
        Doc::Local {
            summary: "Show a one-line-per-neighbor OSPF adjacency summary across every instance.",
            detail: "Queries every configured OSPF instance's nos-ospfd (each resolved via \
                     nos-watchdogd) for its links' current neighbor state, interface state, \
                     last-hello age, and elected DR/BDR. An instance whose nos-ospfd isn't \
                     running is reported individually rather than aborting the whole command.",
        },
        Always),
    spec!(["show" "ospf" "database"],
        "show ospf database",
        Doc::Local {
            summary: "Show every installed LSA's header across every OSPF instance.",
            detail: "Queries every configured OSPF instance's nos-ospfd (each resolved via \
                     nos-watchdogd) for its per-area LSDB's installed LSA headers (type, \
                     link-state-id, advertising router, sequence number, age, checksum). An \
                     instance whose nos-ospfd isn't running is reported individually rather \
                     than aborting the whole command.",
        },
        Always),
    spec!(["show" "ospfv3" "neigh"],
        "show ospfv3 neigh",
        Doc::Local {
            summary: "Show a one-line-per-neighbor OSPFv3 adjacency summary across every instance.",
            detail: "Mirrors 'show ospf neigh' for OSPFv3 (RFC 5340): queries every configured \
                     Ospfv3Instance's nos-ospfv3d (each resolved via nos-watchdogd) for its \
                     links' current neighbor state, interface state, last-hello age, and \
                     elected DR/BDR.",
        },
        Always),
    spec!(["show" "ospfv3" "database"],
        "show ospfv3 database",
        Doc::Local {
            summary: "Show every installed LSA's header across every OSPFv3 instance.",
            detail: "Mirrors 'show ospf database' for OSPFv3 (RFC 5340).",
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
    spec!(["set" "interface" (InterfaceName) "ospf" (OspfProfileName)],
        "set interface <name> ospf <profile-name>",
        Doc::FromConfig(Topic::SetInterfaceOspfProfile),
        Configuration),
    spec!(["set" "ospf" (OspfProfileName)],
        "set ospf <profile-name>",
        Doc::FromConfig(Topic::SetInterfaceOspfProfile),
        ConfigurationInterfaceOrSubinterface),
    spec!(["delete" "interface" (InterfaceName) "ospf"],
        "delete interface <name> ospf",
        Doc::FromConfig(Topic::ClearInterfaceOspfProfile),
        Configuration),
    spec!(["delete" "ospf"],
        "delete ospf",
        Doc::FromConfig(Topic::ClearInterfaceOspfProfile),
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
    spec!(["set" "port-aggregate" (PortAggregateName) "esi" (Plain)],
        "set port-aggregate <name> esi <00:11:22:33:44:55:66:77:88:99>",
        Doc::FromConfig(Topic::SetPortAggregateEsi),
        Configuration),
    spec!(["delete" "port-aggregate" (PortAggregateName) "esi"],
        "delete port-aggregate <name> esi",
        Doc::FromConfig(Topic::SetPortAggregateEsi),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "lacp-system-id" (Plain)],
        "set port-aggregate <name> lacp-system-id <mac>",
        Doc::FromConfig(Topic::SetPortAggregateLacpSystemId),
        Configuration),
    spec!(["delete" "port-aggregate" (PortAggregateName) "lacp-system-id"],
        "delete port-aggregate <name> lacp-system-id",
        Doc::FromConfig(Topic::SetPortAggregateLacpSystemId),
        Configuration),
    spec!(["set" "esi" (Plain)],
        "set esi <00:11:22:33:44:55:66:77:88:99>",
        Doc::FromConfig(Topic::SetPortAggregateEsi),
        ConfigurationPortAggregate),
    spec!(["delete" "esi"],
        "delete esi",
        Doc::FromConfig(Topic::SetPortAggregateEsi),
        ConfigurationPortAggregate),
    spec!(["set" "lacp-system-id" (Plain)],
        "set lacp-system-id <mac>",
        Doc::FromConfig(Topic::SetPortAggregateLacpSystemId),
        ConfigurationPortAggregate),
    spec!(["delete" "lacp-system-id"],
        "delete lacp-system-id",
        Doc::FromConfig(Topic::SetPortAggregateLacpSystemId),
        ConfigurationPortAggregate),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vni" (Plain)],
        "set broadcast domain <name> vni <n>",
        Doc::FromConfig(Topic::SetBroadcastDomainVni),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "vni"],
        "delete broadcast domain <name> vni",
        Doc::FromConfig(Topic::SetBroadcastDomainVni),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "rd" (Plain)],
        "set broadcast domain <name> rd <asn:nn|a.b.c.d:nn>",
        Doc::FromConfig(Topic::SetBroadcastDomainRd),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "rd"],
        "delete broadcast domain <name> rd",
        Doc::FromConfig(Topic::SetBroadcastDomainRd),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "route-target" "import" (Plain)],
        "set broadcast domain <name> route-target import <asn:nn>",
        Doc::FromConfig(Topic::AddBroadcastDomainRouteTarget),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "route-target" "export" (Plain)],
        "set broadcast domain <name> route-target export <asn:nn>",
        Doc::FromConfig(Topic::AddBroadcastDomainRouteTarget),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "route-target" "import" (Plain)],
        "delete broadcast domain <name> route-target import <asn:nn>",
        Doc::FromConfig(Topic::AddBroadcastDomainRouteTarget),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "route-target" "export" (Plain)],
        "delete broadcast domain <name> route-target export <asn:nn>",
        Doc::FromConfig(Topic::AddBroadcastDomainRouteTarget),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vtep-source" "interface" (InterfaceName)],
        "set broadcast domain <name> vtep-source interface <name>",
        Doc::FromConfig(Topic::SetBroadcastDomainVtepSource),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vtep-source" "interface" (InterfaceName) "label" (Plain)],
        "set broadcast domain <name> vtep-source interface <name> label <label>",
        Doc::FromConfig(Topic::SetBroadcastDomainVtepSource),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vtep-source" "loopback"],
        "set broadcast domain <name> vtep-source loopback",
        Doc::FromConfig(Topic::SetBroadcastDomainVtepSource),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vtep-source" "loopback" "label" (Plain)],
        "set broadcast domain <name> vtep-source loopback label <label>",
        Doc::FromConfig(Topic::SetBroadcastDomainVtepSource),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "vtep-source"],
        "delete broadcast domain <name> vtep-source",
        Doc::FromConfig(Topic::SetBroadcastDomainVtepSource),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "mac" "to" "bgp" (BgpInstanceName)],
        "set broadcast domain <name> redistribute from mac to bgp <instance>",
        Doc::FromConfig(Topic::SetBroadcastDomainMacRedistribute),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "redistribute"],
        "delete broadcast domain <name> redistribute",
        Doc::FromConfig(Topic::SetBroadcastDomainMacRedistribute),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "mac"],
        "delete broadcast domain <name> redistribute from mac",
        Doc::FromConfig(Topic::SetBroadcastDomainMacRedistribute),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "arp" "to" "bgp" (BgpInstanceName)],
        "set broadcast domain <name> redistribute from arp to bgp <instance>",
        Doc::FromConfig(Topic::SetBroadcastDomainArpRedistribute),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "arp"],
        "delete broadcast domain <name> redistribute from arp",
        Doc::FromConfig(Topic::SetBroadcastDomainArpRedistribute),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "connected" "to" "bgp" (BgpInstanceName)],
        "set broadcast domain <name> redistribute from connected to bgp <instance>",
        Doc::FromConfig(Topic::SetBroadcastDomainConnectedRedistribute),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "connected"],
        "delete broadcast domain <name> redistribute from connected",
        Doc::FromConfig(Topic::SetBroadcastDomainConnectedRedistribute),
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
    spec!(["set" "interface" (InterfaceName) "mtu" (Plain)],
        "set interface <name> mtu <n>",
        Doc::FromConfig(Topic::SetInterfaceMtu),
        Configuration),
    spec!(["set" "mtu" (Plain)],
        "set mtu <n>",
        Doc::FromConfig(Topic::SetInterfaceMtu),
        ConfigurationInterfaceOrOspfProfile),
    spec!(["delete" "interface" (InterfaceName) "mtu"],
        "delete interface <name> mtu",
        Doc::FromConfig(Topic::ClearInterfaceMtu),
        Configuration),
    spec!(["delete" "mtu"],
        "delete mtu",
        Doc::FromConfig(Topic::ClearInterfaceMtu),
        ConfigurationInterfaceOrOspfProfile),
    spec!(["set" "interface" (InterfaceName) "lldp" "transmit"],
        "set interface <name> lldp transmit",
        Doc::FromConfig(Topic::SetInterfaceLldpTransmit),
        Configuration),
    spec!(["set" "lldp" "transmit"],
        "set lldp transmit",
        Doc::FromConfig(Topic::SetInterfaceLldpTransmit),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "lldp" "receive"],
        "set interface <name> lldp receive",
        Doc::FromConfig(Topic::SetInterfaceLldpReceive),
        Configuration),
    spec!(["set" "lldp" "receive"],
        "set lldp receive",
        Doc::FromConfig(Topic::SetInterfaceLldpReceive),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "lldp" "transmit"],
        "delete interface <name> lldp transmit",
        Doc::FromConfig(Topic::SetInterfaceLldpTransmit),
        Configuration),
    spec!(["delete" "lldp" "transmit"],
        "delete lldp transmit",
        Doc::FromConfig(Topic::SetInterfaceLldpTransmit),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "lldp" "receive"],
        "delete interface <name> lldp receive",
        Doc::FromConfig(Topic::SetInterfaceLldpReceive),
        Configuration),
    spec!(["delete" "lldp" "receive"],
        "delete lldp receive",
        Doc::FromConfig(Topic::SetInterfaceLldpReceive),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "lldp" "destination" "nearest-bridge"],
        "set interface <name> lldp destination nearest-bridge",
        Doc::FromConfig(Topic::SetInterfaceLldpDestination),
        Configuration),
    spec!(["set" "lldp" "destination" "nearest-bridge"],
        "set lldp destination nearest-bridge",
        Doc::FromConfig(Topic::SetInterfaceLldpDestination),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "lldp" "destination" "non-tpmr"],
        "set interface <name> lldp destination non-tpmr",
        Doc::FromConfig(Topic::SetInterfaceLldpDestination),
        Configuration),
    spec!(["set" "lldp" "destination" "non-tpmr"],
        "set lldp destination non-tpmr",
        Doc::FromConfig(Topic::SetInterfaceLldpDestination),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "lldp" "destination" "customer-bridge"],
        "set interface <name> lldp destination customer-bridge",
        Doc::FromConfig(Topic::SetInterfaceLldpDestination),
        Configuration),
    spec!(["set" "lldp" "destination" "customer-bridge"],
        "set lldp destination customer-bridge",
        Doc::FromConfig(Topic::SetInterfaceLldpDestination),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "lldp" "destination"],
        "delete interface <name> lldp destination",
        Doc::FromConfig(Topic::SetInterfaceLldpDestination),
        Configuration),
    spec!(["delete" "lldp" "destination"],
        "delete lldp destination",
        Doc::FromConfig(Topic::SetInterfaceLldpDestination),
        ConfigurationInterface),
    spec!(["set" "lldp" "tx-interval" (Plain)],
        "set lldp tx-interval <seconds>",
        Doc::FromConfig(Topic::SetLldpTxInterval),
        Configuration),
    spec!(["delete" "lldp" "tx-interval"],
        "delete lldp tx-interval",
        Doc::FromConfig(Topic::SetLldpTxInterval),
        Configuration),
    spec!(["set" "lldp" "tx-hold" (Plain)],
        "set lldp tx-hold <n>",
        Doc::FromConfig(Topic::SetLldpTxHold),
        Configuration),
    spec!(["delete" "lldp" "tx-hold"],
        "delete lldp tx-hold",
        Doc::FromConfig(Topic::SetLldpTxHold),
        Configuration),
    spec!(["set" "lldp" "management-address" (Plain)],
        "set lldp management-address <address>",
        Doc::FromConfig(Topic::SetLldpManagementAddress),
        Configuration),
    spec!(["delete" "lldp" "management-address"],
        "delete lldp management-address",
        Doc::FromConfig(Topic::SetLldpManagementAddress),
        Configuration),
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
