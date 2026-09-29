//! The CLI's own command grammar: what can be typed, in what mode, and where
//! its documentation comes from. This is the single source of truth `help`,
//! Tab-completion, and the live `?` key all read from — but it only knows
//! about *syntax* (token order, which is inherently specific to this one
//! client) and *availability* (which `Mode`/`Path` a command is valid in).
//! The *semantic* explanation of what a command does comes from
//! `nos-config` (see `Doc::FromConfig`) — `spec.rs` stays pure and knows
//! nothing about caching or IPC; resolving a `Doc::FromConfig(topic)` into
//! actual text is the caller's job (see `main.rs`'s `doc_for`/`doc_for_blocking`).

use nos_proto::{Topic, TransactionBase};

use crate::command::Command;
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
    /// An IPv4 or IPv6 address.
    IpAddr,
    /// A non-negative integer.
    Number,
    /// The rest of the line, verbatim (leading whitespace kept) — only ever
    /// a row's last token.
    Rest,
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
    ConfigurationPolicyDefinition,
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
        Availability::ConfigurationPolicyDefinition => path.policy_definition().is_ok(),
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
    /// Builds the `Command` from the row's argument words, in token order.
    /// `Some` makes the row part of the grammar [`parse`] walks, so a command
    /// can't be accepted without the `doc` it is declared with. `None` only
    /// for the config rows `command.rs` still parses by hand (#109).
    pub build: Option<Build>,
}

/// A `cmd!` row's constructor: its argument words in, the `Command` out.
pub type Build = fn(&[&str]) -> Option<Command>;

const EXIT_DOC: Doc = Doc::Local {
    summary: "Exit the shell (or leave configuration mode).",
    detail: "In operational mode, exits the shell entirely. In configuration mode, returns \
             to operational mode instead — prompting to commit, discard, or leave the \
             transaction open first if there are uncommitted changes. `quit` and `end` are \
             synonyms.",
};

/// One token of a command's syntax: a bare string literal is a keyword, a
/// parenthesised identifier is an argument slot naming its `ArgKind` —
/// optionally named, `(table: RoutingTableName)`, which `cmd!` needs for the
/// usage string.
macro_rules! tok {
    ($l:literal) => {
        Token::Literal($l)
    };
    (($k:ident)) => {
        Token::Arg(ArgKind::$k)
    };
    (($n:ident : $k:ident)) => {
        Token::Arg(ArgKind::$k)
    };
}

/// A token's text in a generated usage string: the keyword, or `<name>`.
macro_rules! usage_tok {
    ($l:literal) => {
        $l
    };
    (($n:ident : $k:ident)) => {
        concat!("<", stringify!($n), ">")
    };
}

/// One row of the command grammar: its token syntax (every argument named),
/// where its prose comes from, where it's valid, and the `Command` it
/// parses to — built from the argument words, bound in token order. The
/// usage string is generated from the tokens. A body that fails (`?`) makes
/// the whole line `Command::Unknown`; it never falls through to a later row.
///
/// ```ignore
/// cmd!(["show" "route" (table: RoutingTableName) (address: IpAddr)],
///     Doc::Local { summary: "…", detail: "…" },
///     Always,
///     |table, address| Command::ShowRoute {
///         table: table.to_string(),
///         address: Some(address.parse().ok()?),
///     }),
/// ```
macro_rules! cmd {
    ([$first:tt $($rest:tt)*], $doc:expr, $avail:ident, |$($arg:ident),+| $body:expr) => {
        cmd!(@row [$first $($rest)*], $doc, $avail, |args: &[&str]| {
            let &[$($arg),+] = args else { return None };
            Some($body)
        })
    };
    ([$first:tt $($rest:tt)*], $doc:expr, $avail:ident, $body:expr) => {
        cmd!(@row [$first $($rest)*], $doc, $avail, |_: &[&str]| Some($body))
    };
    (@row [$first:tt $($rest:tt)*], $doc:expr, $avail:ident, $build:expr) => {
        CommandSpec {
            tokens: &[tok!($first) $(, tok!($rest))*],
            usage: concat!(usage_tok!($first) $(, " ", usage_tok!($rest))*),
            doc: $doc,
            availability: Availability::$avail,
            build: Some($build),
        }
    };
}

/// One row of the grammar table: its token syntax, the usage string shown to
/// the user, where its prose comes from, and where it's valid.
///
/// ```ignore
/// spec!(["set" "bgp" "instance" (BgpInstanceName) "asn" (Plain)],
///     "set bgp instance <name> asn <n>",
///     Doc::FromConfig(Topic::BgpInstanceAsn),
///     Configuration),
/// ```
macro_rules! spec {
    ([$($t:tt)*], $usage:literal, $doc:expr, $avail:ident) => {
        CommandSpec {
            tokens: &[$(tok!($t)),*],
            usage: $usage,
            doc: $doc,
            availability: Availability::$avail,
            build: None,
        }
    };
}

#[rustfmt::skip]
pub const COMMAND_SPECS: &[CommandSpec] = &[
    cmd!(["show" "config"],
        Doc::FromConfig(Topic::ShowRunningConfig),
        Always,
        Command::ShowConfig),
    cmd!(["show" "this"],
        Doc::FromConfig(Topic::GetTransaction),
        Configuration,
        Command::Show),
    cmd!(["show" "route" (table: RoutingTableName)],
        Doc::Local {
            summary: "Show every route in a routing table, best to worst per prefix.",
            detail: "Queries the table's nos-ribd instance (resolved via nos-watchdogd) for \
                     every prefix it currently knows, each with its full list of candidate \
                     routes ordered from the winning route to the losing ones — since more \
                     than one source (e.g. static and BGP) can target the same prefix. \
                     Prefixes are listed in ascending CIDR order.",
        },
        Always,
        |table| Command::ShowRoute {
            table: table.to_string(),
            address: None,
        }),
    cmd!(["show" "route" (table: RoutingTableName) (address: IpAddr)],
        Doc::Local {
            summary: "Look up the best route(s) for one destination address.",
            detail: "Performs a longest-prefix-match lookup against the table's nos-ribd \
                     instance for the given address, and shows every candidate route for the \
                     matched prefix, ordered from the winning route to the losing ones.",
        },
        Always,
        |table, address| Command::ShowRoute {
            table: table.to_string(),
            address: Some(address.parse().ok()?),
        }),
    cmd!(["show" "fdb" (domain: BroadcastDomainName)],
        Doc::Local {
            summary: "Show a broadcast domain's forwarding database.",
            detail: "Queries the domain's nos-fdbd instance (resolved via nos-watchdogd) for \
                     the MACs behind its VXLAN device — learned locally on the bridge, or \
                     from EVPN Type-2 routes with the VTEP they sit behind — and the remote \
                     VTEPs its flood list replicates broadcast/unknown/multicast traffic to.",
        },
        Always,
        |domain| Command::ShowFdb {
            domain: domain.to_string(),
        }),
    cmd!(
        ["save"],
        Doc::FromConfig(Topic::Save),
        Operational,
        Command::Save
    ),
    cmd!(
        ["help"],
        Doc::Local {
            summary: "Show available commands for the current mode.",
            detail: "Lists every command valid right now, given whether the shell is in \
                     operational mode or configuration mode (and, within configuration \
                     mode, the current navigation position). Equivalent to pressing `?` on \
                     an empty line.",
        },
        Always,
        Command::Help
    ),
    cmd!(["exit"], EXIT_DOC, Always, Command::Exit),
    cmd!(["quit"], EXIT_DOC, Always, Command::Exit),
    cmd!(["end"], EXIT_DOC, Always, Command::Exit),
    cmd!(["configure" (name: Plain)],
        Doc::FromConfig(Topic::OpenTransaction),
        Operational,
        |name| Command::Configure {
            name: name.to_string(),
            base: None,
        }),
    cmd!(["configure" (name: Plain) "from" "blank"],
        Doc::FromConfig(Topic::OpenTransaction),
        Operational,
        |name| Command::Configure {
            name: name.to_string(),
            base: Some(TransactionBase::Blank),
        }),
    cmd!(["configure" (name: Plain) "from" "current"],
        Doc::FromConfig(Topic::OpenTransaction),
        Operational,
        |name| Command::Configure {
            name: name.to_string(),
            base: Some(TransactionBase::Current),
        }),
    spec!(["edit" "bgp" "instance" (BgpInstanceName)],
        "edit bgp instance <name>",
        Doc::FromConfig(Topic::BgpInstance),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "asn" (Plain)],
        "set bgp instance <name> asn <n>",
        Doc::FromConfig(Topic::BgpInstanceAsn),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "router-id" (Plain)],
        "set bgp instance <name> router-id <router-id>",
        Doc::FromConfig(Topic::BgpInstanceRouterId),
        Configuration),
    spec!(["set" "asn" (Plain)],
        "set asn <n>",
        Doc::FromConfig(Topic::BgpInstanceAsn),
        ConfigurationInstance),
    spec!(["set" "router-id" (Plain)],
        "set router-id <router-id>",
        Doc::FromConfig(Topic::BgpInstanceRouterId),
        ConfigurationInstance),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "cluster-id" (Plain)],
        "set bgp instance <name> cluster-id <ip>",
        Doc::FromConfig(Topic::BgpInstanceClusterId),
        Configuration),
    spec!(["set" "cluster-id" (Plain)],
        "set cluster-id <ip>",
        Doc::FromConfig(Topic::BgpInstanceClusterId),
        ConfigurationInstance),
    spec!(["delete" "bgp" "instance" (BgpInstanceName) "cluster-id"],
        "delete bgp instance <name> cluster-id",
        Doc::FromConfig(Topic::BgpInstanceClusterId),
        Configuration),
    spec!(["delete" "cluster-id"],
        "delete cluster-id",
        Doc::FromConfig(Topic::BgpInstanceClusterId),
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
        Doc::FromConfig(Topic::Hostname),
        Configuration),
    spec!(
        ["delete"],
        "delete",
        Doc::FromConfig(Topic::BgpInstance),
        ConfigurationNested
    ),
    spec!(["delete" "bgp" "instance" (BgpInstanceName)],
        "delete bgp instance <name>",
        Doc::FromConfig(Topic::BgpInstance),
        Configuration),
    spec!(["edit" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)],
        "edit bgp instance <name> peer-group <group>",
        Doc::FromConfig(Topic::BgpPeerGroup),
        Configuration),
    spec!(["edit" "peer-group" (BgpPeerGroupName)],
        "edit peer-group <group>",
        Doc::FromConfig(Topic::BgpPeerGroup),
        ConfigurationInstance),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "remote-as" (Plain)],
        "set bgp instance <name> peer-group <group> remote-as <n>",
        Doc::FromConfig(Topic::BgpPeerGroupRemoteAs),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "source-address" "interface" (InterfaceName)],
        "set bgp instance <name> peer-group <group> source-address interface <name>",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "source-address" "interface" (InterfaceName) "label" (Plain)],
        "set bgp instance <name> peer-group <group> source-address interface <name> label <label>",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "source-address" "loopback"],
        "set bgp instance <name> peer-group <group> source-address loopback",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "source-address" "loopback" "label" (Plain)],
        "set bgp instance <name> peer-group <group> source-address loopback label <label>",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "address-family" "ipv4"],
        "set bgp instance <name> peer-group <group> address-family ipv4",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "address-family" "ipv6"],
        "set bgp instance <name> peer-group <group> address-family ipv6",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "address-family" "l2vpn-evpn"],
        "set bgp instance <name> peer-group <group> address-family l2vpn-evpn",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "hold-time" (Plain)],
        "set bgp instance <name> peer-group <group> hold-time <n>",
        Doc::FromConfig(Topic::BgpPeerGroupHoldTime),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "next-hop" "self"],
        "set bgp instance <name> peer-group <group> next-hop self",
        Doc::FromConfig(Topic::BgpPeerGroupNextHop),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "next-hop" "unchanged"],
        "set bgp instance <name> peer-group <group> next-hop unchanged",
        Doc::FromConfig(Topic::BgpPeerGroupNextHop),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "route-reflector-client"],
        "set bgp instance <name> peer-group <group> route-reflector-client",
        Doc::FromConfig(Topic::BgpPeerGroupRouteReflectorClient),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "route-server-client"],
        "set bgp instance <name> peer-group <group> route-server-client",
        Doc::FromConfig(Topic::BgpPeerGroupRouteServerClient),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "keepalive-interval" (Plain)],
        "set bgp instance <name> peer-group <group> keepalive-interval <n>",
        Doc::FromConfig(Topic::BgpPeerGroupKeepaliveInterval),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "mrai" (Plain)],
        "set bgp instance <name> peer-group <group> mrai <seconds>",
        Doc::FromConfig(Topic::BgpPeerGroupMrai),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "max-hops" (Plain)],
        "set bgp instance <name> peer-group <group> max-hops <n>",
        Doc::FromConfig(Topic::BgpPeerGroupMaxHops),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "damping"],
        "set bgp instance <name> peer-group <group> damping",
        Doc::FromConfig(Topic::BgpPeerGroupDamping),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "connect-retry-time" (Plain)],
        "set bgp instance <name> peer-group <group> connect-retry-time <n>",
        Doc::FromConfig(Topic::BgpPeerGroupConnectRetryTime),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "md5-password" (Plain)],
        "set bgp instance <name> peer-group <group> md5-password <password>",
        Doc::FromConfig(Topic::BgpPeerGroupMd5Password),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "ao-key" (Plain) (Plain) (Plain) (Plain)],
        "set bgp instance <name> peer-group <group> ao-key <send-id> <recv-id> <hmac-sha1|aes-cmac> <key>",
        Doc::FromConfig(Topic::BgpPeerGroupAoKey),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "ao-key" (Plain) "current"],
        "set bgp instance <name> peer-group <group> ao-key <send-id> current",
        Doc::FromConfig(Topic::BgpPeerGroupAoKey),
        Configuration),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "ao-key" (Plain) "rnext"],
        "set bgp instance <name> peer-group <group> ao-key <send-id> rnext",
        Doc::FromConfig(Topic::BgpPeerGroupAoKey),
        Configuration),
    spec!(["set" "remote-as" (Plain)],
        "set remote-as <n>",
        Doc::FromConfig(Topic::BgpPeerGroupRemoteAs),
        ConfigurationPeerGroup),
    spec!(["set" "source-address" "interface" (InterfaceName)],
        "set source-address interface <name>",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["set" "source-address" "interface" (InterfaceName) "label" (Plain)],
        "set source-address interface <name> label <label>",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["set" "source-address" "loopback"],
        "set source-address loopback",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["set" "source-address" "loopback" "label" (Plain)],
        "set source-address loopback label <label>",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["set" "address-family" "ipv4"],
        "set address-family ipv4",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["set" "address-family" "ipv6"],
        "set address-family ipv6",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["set" "address-family" "l2vpn-evpn"],
        "set address-family l2vpn-evpn",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["set" "next-hop" "self"],
        "set next-hop self",
        Doc::FromConfig(Topic::BgpPeerGroupNextHop),
        ConfigurationPeerGroup),
    spec!(["set" "next-hop" "unchanged"],
        "set next-hop unchanged",
        Doc::FromConfig(Topic::BgpPeerGroupNextHop),
        ConfigurationPeerGroup),
    spec!(["set" "route-reflector-client"],
        "set route-reflector-client",
        Doc::FromConfig(Topic::BgpPeerGroupRouteReflectorClient),
        ConfigurationPeerGroup),
    spec!(["set" "route-server-client"],
        "set route-server-client",
        Doc::FromConfig(Topic::BgpPeerGroupRouteServerClient),
        ConfigurationPeerGroup),
    spec!(["set" "hold-time" (Plain)],
        "set hold-time <n>",
        Doc::FromConfig(Topic::BgpPeerGroupHoldTime),
        ConfigurationPeerGroup),
    spec!(["set" "keepalive-interval" (Plain)],
        "set keepalive-interval <n>",
        Doc::FromConfig(Topic::BgpPeerGroupKeepaliveInterval),
        ConfigurationPeerGroup),
    spec!(["set" "mrai" (Plain)],
        "set mrai <seconds>",
        Doc::FromConfig(Topic::BgpPeerGroupMrai),
        ConfigurationPeerGroup),
    spec!(["set" "max-hops" (Plain)],
        "set max-hops <n>",
        Doc::FromConfig(Topic::BgpPeerGroupMaxHops),
        ConfigurationPeerGroup),
    spec!(["set" "damping"],
        "set damping",
        Doc::FromConfig(Topic::BgpPeerGroupDamping),
        ConfigurationPeerGroup),
    spec!(["set" "connect-retry-time" (Plain)],
        "set connect-retry-time <n>",
        Doc::FromConfig(Topic::BgpPeerGroupConnectRetryTime),
        ConfigurationPeerGroup),
    spec!(["set" "md5-password" (Plain)],
        "set md5-password <password>",
        Doc::FromConfig(Topic::BgpPeerGroupMd5Password),
        ConfigurationPeerGroup),
    spec!(["set" "ao-key" (Plain) (Plain) (Plain) (Plain)],
        "set ao-key <send-id> <recv-id> <hmac-sha1|aes-cmac> <key>",
        Doc::FromConfig(Topic::BgpPeerGroupAoKey),
        ConfigurationPeerGroup),
    spec!(["set" "ao-key" (Plain) "current"],
        "set ao-key <send-id> current",
        Doc::FromConfig(Topic::BgpPeerGroupAoKey),
        ConfigurationPeerGroup),
    spec!(["set" "ao-key" (Plain) "rnext"],
        "set ao-key <send-id> rnext",
        Doc::FromConfig(Topic::BgpPeerGroupAoKey),
        ConfigurationPeerGroup),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)
           "shutdown"],
        "set bgp instance <name> peer-group <group> shutdown [<message>]",
        Doc::FromConfig(Topic::BgpPeerGroupShutdown),
        Configuration),
    spec!(["set" "shutdown"],
        "set shutdown [<message>]",
        Doc::FromConfig(Topic::BgpPeerGroupShutdown),
        ConfigurationPeerGroup),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer" (Plain) "shutdown"],
        "set bgp instance <name> peer <address> shutdown [<message>]",
        Doc::FromConfig(Topic::BgpPeerShutdown),
        Configuration),
    spec!(["set" "peer" (Plain) "shutdown"],
        "set peer <address> shutdown [<message>]",
        Doc::FromConfig(Topic::BgpPeerShutdown),
        ConfigurationInstance),
    spec!(["delete" "shutdown"],
        "delete shutdown",
        Doc::FromConfig(Topic::BgpPeerGroupShutdown),
        ConfigurationPeerGroup),
    spec!(["delete" "bgp" "instance" (BgpInstanceName) "peer" (Plain) "shutdown"],
        "delete bgp instance <name> peer <address> shutdown",
        Doc::FromConfig(Topic::BgpPeerShutdown),
        Configuration),
    spec!(["delete" "peer" (Plain) "shutdown"],
        "delete peer <address> shutdown",
        Doc::FromConfig(Topic::BgpPeerShutdown),
        ConfigurationInstance),
    spec!(["set" "bgp" "instance" (BgpInstanceName) "peer" (Plain) "peer-group"
           (BgpPeerGroupName)],
        "set bgp instance <name> peer <address> peer-group <group>",
        Doc::FromConfig(Topic::BgpPeer),
        Configuration),
    spec!(["set" "peer" (Plain) "peer-group" (BgpPeerGroupName)],
        "set peer <address> peer-group <group>",
        Doc::FromConfig(Topic::BgpPeer),
        ConfigurationInstance),
    spec!(["delete" "bgp" "instance" (BgpInstanceName) "peer-group" (BgpPeerGroupName)],
        "delete bgp instance <name> peer-group <group>",
        Doc::FromConfig(Topic::BgpPeerGroup),
        Configuration),
    spec!(["delete" "peer-group" (BgpPeerGroupName)],
        "delete peer-group <group>",
        Doc::FromConfig(Topic::BgpPeerGroup),
        ConfigurationInstance),
    spec!(["delete" "bgp" "instance" (BgpInstanceName) "peer" (Plain)],
        "delete bgp instance <name> peer <address>",
        Doc::FromConfig(Topic::BgpPeer),
        Configuration),
    spec!(["delete" "peer" (Plain)],
        "delete peer <address>",
        Doc::FromConfig(Topic::BgpPeer),
        ConfigurationInstance),
    spec!(["delete" "source-address"],
        "delete source-address",
        Doc::FromConfig(Topic::BgpPeerGroupSourceAddress),
        ConfigurationPeerGroup),
    spec!(["delete" "address-family" "ipv4"],
        "delete address-family ipv4",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["delete" "address-family" "ipv6"],
        "delete address-family ipv6",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["delete" "address-family" "l2vpn-evpn"],
        "delete address-family l2vpn-evpn",
        Doc::FromConfig(Topic::BgpPeerGroupAddressFamily),
        ConfigurationPeerGroup),
    spec!(["delete" "next-hop"],
        "delete next-hop",
        Doc::FromConfig(Topic::BgpPeerGroupNextHop),
        ConfigurationPeerGroup),
    spec!(["delete" "route-reflector-client"],
        "delete route-reflector-client",
        Doc::FromConfig(Topic::BgpPeerGroupRouteReflectorClient),
        ConfigurationPeerGroup),
    spec!(["delete" "route-server-client"],
        "delete route-server-client",
        Doc::FromConfig(Topic::BgpPeerGroupRouteServerClient),
        ConfigurationPeerGroup),
    spec!(["delete" "hold-time"],
        "delete hold-time",
        Doc::FromConfig(Topic::BgpPeerGroupHoldTime),
        ConfigurationPeerGroup),
    spec!(["delete" "keepalive-interval"],
        "delete keepalive-interval",
        Doc::FromConfig(Topic::BgpPeerGroupKeepaliveInterval),
        ConfigurationPeerGroup),
    spec!(["delete" "max-hops"],
        "delete max-hops",
        Doc::FromConfig(Topic::BgpPeerGroupMaxHops),
        ConfigurationPeerGroup),
    spec!(["delete" "damping"],
        "delete damping",
        Doc::FromConfig(Topic::BgpPeerGroupDamping),
        ConfigurationPeerGroup),
    spec!(["delete" "mrai"],
        "delete mrai",
        Doc::FromConfig(Topic::BgpPeerGroupMrai),
        ConfigurationPeerGroup),
    spec!(["delete" "connect-retry-time"],
        "delete connect-retry-time",
        Doc::FromConfig(Topic::BgpPeerGroupConnectRetryTime),
        ConfigurationPeerGroup),
    spec!(["delete" "auth"],
        "delete auth",
        Doc::FromConfig(Topic::BgpPeerGroupAuth),
        ConfigurationPeerGroup),
    spec!(["delete" "ao-key" (Plain)],
        "delete ao-key <send-id>",
        Doc::FromConfig(Topic::BgpPeerGroupAoKey),
        ConfigurationPeerGroup),
    // Shares its token sequence with the peer-group `delete auth` above —
    // `Availability` disambiguates by path, mirroring `set router-id`'s
    // shared-tokens precedent.
    spec!(["delete" "auth"],
        "delete auth",
        Doc::FromConfig(Topic::OspfProfileAuth),
        ConfigurationOspfProfile),
    spec!(["delete" "crypto-key" (Plain)],
        "delete crypto-key <key-id>",
        Doc::FromConfig(Topic::OspfProfileCryptoKey),
        ConfigurationOspfProfile),
    spec!(["delete" "auth"],
        "delete auth",
        Doc::Local {
            summary: "Clear the current OSPFv3 profile's RFC 7166 authentication.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile or peer-group; which one applies is resolved by the current \
                     navigation position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["delete" "crypto-key" (Plain)],
        "delete crypto-key <key-id>",
        Doc::Local {
            summary: "Remove one RFC 7166 key from the current OSPFv3 profile.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    cmd!(
        ["up"],
        Doc::Local {
            summary: "Navigate up one level.",
            detail: "Moves the current navigation position up one level: from a peer-group, \
                     to its owning BGP instance; from a BGP instance, to the transaction \
                     root (same as `top`).",
        },
        ConfigurationNested,
        Command::Up
    ),
    cmd!(
        ["top"],
        Doc::Local {
            summary: "Navigate back to the transaction root.",
            detail: "Moves the current navigation position directly to the transaction \
                     root, regardless of how deep it is.",
        },
        ConfigurationNested,
        Command::Top
    ),
    cmd!(
        ["commit"],
        Doc::FromConfig(Topic::CommitTransaction),
        Configuration,
        Command::Commit
    ),
    cmd!(
        ["discard"],
        Doc::FromConfig(Topic::DiscardTransaction),
        Configuration,
        Command::Discard
    ),
    cmd!(
        ["abort"],
        Doc::FromConfig(Topic::DiscardTransaction),
        Configuration,
        Command::Discard
    ),
    cmd!(
        ["diff"],
        Doc::FromConfig(Topic::DiffTransaction),
        Configuration,
        Command::Diff
    ),
    cmd!(["edit" "source"],
        Doc::Local {
            summary: "Edit the current policy's RPL source in $EDITOR.",
            detail: "Opens $EDITOR (else $VISUAL, else nano) on the current \
                     policy-definition's source. On save, the edited source is compiled against \
                     the transaction and applied only if it compiles; otherwise it is \
                     discarded.",
        },
        ConfigurationPolicyDefinition,
        Command::EditSource),
    cmd!(["show" "source"],
        Doc::Local {
            summary: "Show the current policy's RPL source with line numbers.",
            detail: "Prints the current policy-definition's source as held by the \
                     transaction, one numbered line at a time — the numbers `set source line` \
                     and `delete source line` take.",
        },
        ConfigurationPolicyDefinition,
        Command::ShowSource),
    cmd!(["set" "source" "line" (line: Number) (text: Rest)],
        Doc::Local {
            summary: "Replace (or append) one line of the current policy's RPL source.",
            detail: "Sets line <line> of the current policy-definition's source to <text>, \
                     taken verbatim — leading whitespace is kept, since RPL's indentation is \
                     meaningful. A line number one past the end appends.",
        },
        ConfigurationPolicyDefinition,
        |line, text| Command::SetSourceLine {
            line: line.parse().ok()?,
            text: text.to_string(),
        }),
    cmd!(["delete" "source" "line" (line: Number)],
        Doc::Local {
            summary: "Delete one line of the current policy's RPL source.",
            detail: "Removes line <line> from the current policy-definition's source; the \
                     lines after it move up by one.",
        },
        ConfigurationPolicyDefinition,
        |line| Command::DeleteSourceLine {
            line: line.parse().ok()?,
        }),
    spec!(["edit" "routing-table" (RoutingTableName)],
        "edit routing-table <name>",
        Doc::FromConfig(Topic::RoutingTable),
        Configuration),
    spec!(["edit" "ospf" "instance" (OspfInstanceName)],
        "edit ospf instance <name>",
        Doc::FromConfig(Topic::OspfInstance),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "router-id" (Plain)],
        "set ospf instance <name> router-id <router-id>",
        Doc::FromConfig(Topic::OspfInstanceRouterId),
        Configuration),
    spec!(["set" "router-id" (Plain)],
        "set router-id <router-id>",
        Doc::FromConfig(Topic::OspfInstanceRouterId),
        ConfigurationOspfInstance),
    spec!(["delete" "ospf" "instance" (OspfInstanceName)],
        "delete ospf instance <name>",
        Doc::FromConfig(Topic::OspfInstance),
        Configuration),
    spec!(["edit" "ospf" "instance" (OspfInstanceName) "area" (Plain)],
        "edit ospf instance <name> area <area-id>",
        Doc::FromConfig(Topic::OspfArea),
        Configuration),
    spec!(["edit" "area" (Plain)],
        "edit area <area-id>",
        Doc::FromConfig(Topic::OspfArea),
        ConfigurationOspfInstance),
    spec!(["delete" "ospf" "instance" (OspfInstanceName) "area" (Plain)],
        "delete ospf instance <name> area <area-id>",
        Doc::FromConfig(Topic::OspfArea),
        Configuration),
    spec!(["delete" "area" (Plain)],
        "delete area <area-id>",
        Doc::FromConfig(Topic::OspfArea),
        ConfigurationOspfInstance),
    spec!(["edit" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)],
        "edit ospf instance <name> area <area-id> profile <profile-name>",
        Doc::FromConfig(Topic::OspfProfile),
        Configuration),
    spec!(["edit" "profile" (OspfProfileName)],
        "edit profile <profile-name>",
        Doc::FromConfig(Topic::OspfProfile),
        ConfigurationOspfArea),
    spec!(["delete" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)],
        "delete ospf instance <name> area <area-id> profile <profile-name>",
        Doc::FromConfig(Topic::OspfProfile),
        Configuration),
    spec!(["delete" "profile" (OspfProfileName)],
        "delete profile <profile-name>",
        Doc::FromConfig(Topic::OspfProfile),
        ConfigurationOspfArea),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "hello-interval" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> hello-interval <n>",
        Doc::FromConfig(Topic::OspfProfileHelloInterval),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "dead-interval" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> dead-interval <n>",
        Doc::FromConfig(Topic::OspfProfileDeadInterval),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "cost" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> cost <n>",
        Doc::FromConfig(Topic::OspfProfileCost),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "priority" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> priority <n>",
        Doc::FromConfig(Topic::OspfProfilePriority),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "mtu" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> mtu <n>",
        Doc::FromConfig(Topic::OspfProfileMtu),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "extended-sequence-numbers" "enable"],
        "set ospf instance <name> area <area-id> profile <profile-name> extended-sequence-numbers enable",
        Doc::FromConfig(Topic::OspfProfileExtendedSequenceNumbers),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "extended-sequence-numbers" "disable"],
        "set ospf instance <name> area <area-id> profile <profile-name> extended-sequence-numbers disable",
        Doc::FromConfig(Topic::OspfProfileExtendedSequenceNumbers),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "network-type" "point-to-point"],
        "set ospf instance <name> area <area-id> profile <profile-name> network-type point-to-point",
        Doc::FromConfig(Topic::OspfProfileNetworkType),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "network-type" "broadcast"],
        "set ospf instance <name> area <area-id> profile <profile-name> network-type broadcast",
        Doc::FromConfig(Topic::OspfProfileNetworkType),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "simple-password" (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> simple-password <password>",
        Doc::FromConfig(Topic::OspfProfileSimplePassword),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "crypto-key" (Plain) (Plain) (Plain)],
        "set ospf instance <name> area <area-id> profile <profile-name> crypto-key <key-id> <md5|hmac-sha1|hmac-sha256|hmac-sha384|hmac-sha512> <key>",
        Doc::FromConfig(Topic::OspfProfileCryptoKey),
        Configuration),
    spec!(["set" "ospf" "instance" (OspfInstanceName) "area" (Plain) "profile" (OspfProfileName)
           "crypto-key" (Plain) "current"],
        "set ospf instance <name> area <area-id> profile <profile-name> crypto-key <key-id> current",
        Doc::FromConfig(Topic::OspfProfileCryptoKey),
        Configuration),
    spec!(["set" "hello-interval" (Plain)],
        "set hello-interval <n>",
        Doc::FromConfig(Topic::OspfProfileHelloInterval),
        ConfigurationOspfProfile),
    spec!(["set" "dead-interval" (Plain)],
        "set dead-interval <n>",
        Doc::FromConfig(Topic::OspfProfileDeadInterval),
        ConfigurationOspfProfile),
    spec!(["set" "cost" (Plain)],
        "set cost <n>",
        Doc::FromConfig(Topic::OspfProfileCost),
        ConfigurationOspfProfile),
    spec!(["set" "priority" (Plain)],
        "set priority <n>",
        Doc::FromConfig(Topic::OspfProfilePriority),
        ConfigurationOspfProfile),
    spec!(["set" "network-type" "point-to-point"],
        "set network-type point-to-point",
        Doc::FromConfig(Topic::OspfProfileNetworkType),
        ConfigurationOspfProfile),
    spec!(["set" "network-type" "broadcast"],
        "set network-type broadcast",
        Doc::FromConfig(Topic::OspfProfileNetworkType),
        ConfigurationOspfProfile),
    spec!(["set" "simple-password" (Plain)],
        "set simple-password <password>",
        Doc::FromConfig(Topic::OspfProfileSimplePassword),
        ConfigurationOspfProfile),
    spec!(["set" "crypto-key" (Plain) (Plain) (Plain)],
        "set crypto-key <key-id> <md5|hmac-sha1|hmac-sha256|hmac-sha384|hmac-sha512> <key>",
        Doc::FromConfig(Topic::OspfProfileCryptoKey),
        ConfigurationOspfProfile),
    spec!(["set" "crypto-key" (Plain) "current"],
        "set crypto-key <key-id> current",
        Doc::FromConfig(Topic::OspfProfileCryptoKey),
        ConfigurationOspfProfile),
    spec!(["delete" "hello-interval"],
        "delete hello-interval",
        Doc::FromConfig(Topic::OspfProfileHelloInterval),
        ConfigurationOspfProfile),
    spec!(["delete" "dead-interval"],
        "delete dead-interval",
        Doc::FromConfig(Topic::OspfProfileDeadInterval),
        ConfigurationOspfProfile),
    spec!(["delete" "cost"],
        "delete cost",
        Doc::FromConfig(Topic::OspfProfileCost),
        ConfigurationOspfProfile),
    spec!(["delete" "priority"],
        "delete priority",
        Doc::FromConfig(Topic::OspfProfilePriority),
        ConfigurationOspfProfile),
    spec!(["delete" "network-type"],
        "delete network-type",
        Doc::FromConfig(Topic::OspfProfileNetworkType),
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
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "extended-lsa"],
        "set ospfv3 instance <name> extended-lsa",
        Doc::Local {
            summary: "Originate RFC 8362 extended (TLV) LSAs instead of the legacy set.",
            detail: "Full mode: E-Router, E-Network, E-Link and E-Intra-Area-Prefix LSAs replace \
                     the RFC 5340 Router/Network/Link/Intra-Area-Prefix LSAs; extended LSAs \
                     from neighbors are always understood. Undo with 'delete ospfv3 instance \
                     <name> extended-lsa'.",
        },
        Configuration),
    spec!(["delete" "ospfv3" "instance" (Ospfv3InstanceName) "extended-lsa"],
        "delete ospfv3 instance <name> extended-lsa",
        Doc::Local {
            summary: "Go back to originating the legacy RFC 5340 LSAs.",
            detail: "Turns off RFC 8362 extended-LSA origination for the instance.",
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
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "crypto-key" (Plain) (Plain) (Plain)],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> crypto-key <key-id> <hmac-sha1|hmac-sha256|hmac-sha384|hmac-sha512> <key>",
        Doc::Local {
            summary: "Add or replace an RFC 7166 authentication-trailer key on an OSPFv3 profile.",
            detail: "<key-id> is the 16-bit Security Association ID (0-65535). Every configured \
                     key is accepted on receive; mark the one that signs with 'crypto-key \
                     <key-id> current'. HMAC-SHA only: RFC 7166 has no MD5.",
        },
        Configuration),
    spec!(["set" "ospfv3" "instance" (Ospfv3InstanceName) "area" (Plain) "profile" (Ospfv3ProfileName)
           "crypto-key" (Plain) "current"],
        "set ospfv3 instance <name> area <area-id> profile <profile-name> crypto-key <key-id> current",
        Doc::Local {
            summary: "Mark one RFC 7166 key as the one signing outgoing OSPFv3 packets.",
            detail: "Mirrors the OSPF equivalent for OSPFv3.",
        },
        Configuration),
    spec!(["set" "crypto-key" (Plain) (Plain) (Plain)],
        "set crypto-key <key-id> <hmac-sha1|hmac-sha256|hmac-sha384|hmac-sha512> <key>",
        Doc::Local {
            summary: "Add or replace an RFC 7166 key on the current OSPFv3 profile.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
    spec!(["set" "crypto-key" (Plain) "current"],
        "set crypto-key <key-id> current",
        Doc::Local {
            summary: "Mark one RFC 7166 key as current on the current OSPFv3 profile.",
            detail: "Shares its token sequence with the same relative command on an OSPF \
                     profile; which one applies is resolved by the current navigation \
                     position.",
        },
        ConfigurationOspfv3Profile),
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
        Doc::FromConfig(Topic::RoutingTableBgpInstance),
        Configuration),
    spec!(["set" "bgp-instance" (BgpInstanceName)],
        "set bgp-instance <instance>",
        Doc::FromConfig(Topic::RoutingTableBgpInstance),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "bgp-instance"],
        "delete routing-table <name> bgp-instance",
        Doc::FromConfig(Topic::RoutingTableBgpInstance),
        Configuration),
    spec!(["delete" "bgp-instance"],
        "delete bgp-instance",
        Doc::FromConfig(Topic::RoutingTableBgpInstance),
        ConfigurationRoutingTable),
    spec!(["set" "routing-table" (RoutingTableName) "ospf-instance" (OspfInstanceName)],
        "set routing-table <name> ospf-instance <instance>",
        Doc::FromConfig(Topic::RoutingTableOspfInstance),
        Configuration),
    spec!(["set" "ospf-instance" (OspfInstanceName)],
        "set ospf-instance <instance>",
        Doc::FromConfig(Topic::RoutingTableOspfInstance),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "ospf-instance"],
        "delete routing-table <name> ospf-instance",
        Doc::FromConfig(Topic::RoutingTableOspfInstance),
        Configuration),
    spec!(["delete" "ospf-instance"],
        "delete ospf-instance",
        Doc::FromConfig(Topic::RoutingTableOspfInstance),
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
        Doc::FromConfig(Topic::RoutingTableStaticRoutingInstance),
        Configuration),
    spec!(["set" "static-routing-instance" (StaticRoutingInstanceName)],
        "set static-routing-instance <instance>",
        Doc::FromConfig(Topic::RoutingTableStaticRoutingInstance),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "static-routing-instance"],
        "delete routing-table <name> static-routing-instance",
        Doc::FromConfig(Topic::RoutingTableStaticRoutingInstance),
        Configuration),
    spec!(["delete" "static-routing-instance"],
        "delete static-routing-instance",
        Doc::FromConfig(Topic::RoutingTableStaticRoutingInstance),
        ConfigurationRoutingTable),
    spec!(["set" "routing-table" (RoutingTableName) "redistribute" "from" "static" "to" "bgp"],
        "set routing-table <name> redistribute from static to bgp",
        Doc::FromConfig(Topic::RoutingTableRedistribute),
        Configuration),
    spec!(["set" "redistribute" "from" "static" "to" "bgp"],
        "set redistribute from static to bgp",
        Doc::FromConfig(Topic::RoutingTableRedistribute),
        ConfigurationRoutingTable),
    spec!(["set" "routing-table" (RoutingTableName) "redistribute" "from" "static" "to" "ospf"],
        "set routing-table <name> redistribute from static to ospf",
        Doc::FromConfig(Topic::RoutingTableRedistribute),
        Configuration),
    spec!(["set" "redistribute" "from" "static" "to" "ospf"],
        "set redistribute from static to ospf",
        Doc::FromConfig(Topic::RoutingTableRedistribute),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName) "redistribute"],
        "delete routing-table <name> redistribute",
        Doc::FromConfig(Topic::RoutingTableRedistribute),
        Configuration),
    spec!(["delete" "redistribute"],
        "delete redistribute",
        Doc::FromConfig(Topic::RoutingTableRedistribute),
        ConfigurationRoutingTable),
    spec!(["delete" "routing-table" (RoutingTableName)],
        "delete routing-table <name>",
        Doc::FromConfig(Topic::RoutingTable),
        Configuration),
    spec!(["edit" "static-routing-instance" (StaticRoutingInstanceName)],
        "edit static-routing-instance <name>",
        Doc::FromConfig(Topic::StaticRoutingInstance),
        Configuration),
    spec!(["delete" "static-routing-instance" (StaticRoutingInstanceName)],
        "delete static-routing-instance <name>",
        Doc::FromConfig(Topic::StaticRoutingInstance),
        Configuration),
    spec!(["set" "static-routing-instance" (StaticRoutingInstanceName) "route" (Plain)
           "gateway" (Plain)],
        "set static-routing-instance <name> route <subnet> gateway <address>",
        Doc::FromConfig(Topic::StaticRoute),
        Configuration),
    spec!(["set" "route" (Plain) "gateway" (Plain)],
        "set route <subnet> gateway <address>",
        Doc::FromConfig(Topic::StaticRoute),
        ConfigurationStaticRoutingInstance),
    spec!(["delete" "static-routing-instance" (StaticRoutingInstanceName) "route" (Plain)],
        "delete static-routing-instance <name> route <subnet>",
        Doc::FromConfig(Topic::StaticRoute),
        Configuration),
    spec!(["delete" "route" (Plain)],
        "delete route <subnet>",
        Doc::FromConfig(Topic::StaticRoute),
        ConfigurationStaticRoutingInstance),
    spec!(["edit" "broadcast" "domain" (BroadcastDomainName)],
        "edit broadcast domain <name>",
        Doc::FromConfig(Topic::BroadcastDomain),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName)],
        "delete broadcast domain <name>",
        Doc::FromConfig(Topic::BroadcastDomain),
        Configuration),
    spec!(["edit" "switching-profile" (SwitchingProfileName)],
        "edit switching-profile <name>",
        Doc::FromConfig(Topic::SwitchingProfile),
        Configuration),
    spec!(["delete" "switching-profile" (SwitchingProfileName)],
        "delete switching-profile <name>",
        Doc::FromConfig(Topic::SwitchingProfile),
        Configuration),
    spec!(["set" "switching-profile" (SwitchingProfileName) "broadcast-domain"
           (BroadcastDomainName) "tag" "dot1q" (Plain)],
        "set switching-profile <name> broadcast-domain <domain> tag dot1q <n>",
        Doc::FromConfig(Topic::SwitchingProfileMember),
        Configuration),
    spec!(["set" "switching-profile" (SwitchingProfileName) "broadcast-domain"
           (BroadcastDomainName) "tag" "untagged"],
        "set switching-profile <name> broadcast-domain <domain> tag untagged",
        Doc::FromConfig(Topic::SwitchingProfileMember),
        Configuration),
    spec!(["set" "broadcast-domain" (BroadcastDomainName) "tag" "dot1q" (Plain)],
        "set broadcast-domain <domain> tag dot1q <n>",
        Doc::FromConfig(Topic::SwitchingProfileMember),
        ConfigurationSwitchingProfile),
    spec!(["set" "broadcast-domain" (BroadcastDomainName) "tag" "untagged"],
        "set broadcast-domain <domain> tag untagged",
        Doc::FromConfig(Topic::SwitchingProfileMember),
        ConfigurationSwitchingProfile),
    spec!(["delete" "switching-profile" (SwitchingProfileName) "broadcast-domain"
           (BroadcastDomainName)],
        "delete switching-profile <name> broadcast-domain <domain>",
        Doc::FromConfig(Topic::SwitchingProfileMember),
        Configuration),
    spec!(["delete" "broadcast-domain" (BroadcastDomainName)],
        "delete broadcast-domain <domain>",
        Doc::FromConfig(Topic::SwitchingProfileMember),
        ConfigurationSwitchingProfile),
    spec!(["edit" "port-aggregate" (PortAggregateName)],
        "edit port-aggregate <name>",
        Doc::FromConfig(Topic::PortAggregate),
        Configuration),
    spec!(["delete" "port-aggregate" (PortAggregateName)],
        "delete port-aggregate <name>",
        Doc::FromConfig(Topic::PortAggregate),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "mode" "xor"],
        "set port-aggregate <name> mode xor",
        Doc::FromConfig(Topic::PortAggregateMode),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "mode" "lacp"],
        "set port-aggregate <name> mode lacp",
        Doc::FromConfig(Topic::PortAggregateMode),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "lacp-rate" "fast"],
        "set port-aggregate <name> lacp-rate fast",
        Doc::FromConfig(Topic::PortAggregateLacpRate),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "lacp-rate" "slow"],
        "set port-aggregate <name> lacp-rate slow",
        Doc::FromConfig(Topic::PortAggregateLacpRate),
        Configuration),
    spec!(["set" "lacp-rate" "fast"],
        "set lacp-rate fast",
        Doc::FromConfig(Topic::PortAggregateLacpRate),
        ConfigurationPortAggregate),
    spec!(["set" "lacp-rate" "slow"],
        "set lacp-rate slow",
        Doc::FromConfig(Topic::PortAggregateLacpRate),
        ConfigurationPortAggregate),
    spec!(["set" "port-aggregate" (PortAggregateName) "redundancy-mode" "all-active"],
        "set port-aggregate <name> redundancy-mode all-active",
        Doc::FromConfig(Topic::PortAggregateRedundancyMode),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "redundancy-mode" "single-active"],
        "set port-aggregate <name> redundancy-mode single-active",
        Doc::FromConfig(Topic::PortAggregateRedundancyMode),
        Configuration),
    spec!(["set" "redundancy-mode" "all-active"],
        "set redundancy-mode all-active",
        Doc::FromConfig(Topic::PortAggregateRedundancyMode),
        ConfigurationPortAggregate),
    spec!(["set" "redundancy-mode" "single-active"],
        "set redundancy-mode single-active",
        Doc::FromConfig(Topic::PortAggregateRedundancyMode),
        ConfigurationPortAggregate),
    spec!(["set" "mode" "xor"],
        "set mode xor",
        Doc::FromConfig(Topic::PortAggregateMode),
        ConfigurationPortAggregate),
    spec!(["set" "mode" "lacp"],
        "set mode lacp",
        Doc::FromConfig(Topic::PortAggregateMode),
        ConfigurationPortAggregate),
    spec!(["set" "interface" (InterfaceName) "port-aggregate" (PortAggregateName)],
        "set interface <name> port-aggregate <aggregate>",
        Doc::FromConfig(Topic::InterfacePortAggregate),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName)],
        "set port-aggregate <aggregate>",
        Doc::FromConfig(Topic::InterfacePortAggregate),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "port-aggregate"],
        "delete interface <name> port-aggregate",
        Doc::FromConfig(Topic::InterfacePortAggregate),
        Configuration),
    spec!(["delete" "port-aggregate"],
        "delete port-aggregate",
        Doc::FromConfig(Topic::InterfacePortAggregate),
        ConfigurationInterface),
    cmd!(["show" "port-aggregate"],
        Doc::Local {
            summary: "Show every port aggregate's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every configured \
                     port aggregate's mode, switching-profile, mtu, and subinterfaces.",
        },
        Always,
        Command::ShowPortAggregate { name: None }),
    cmd!(["show" "port-aggregate" (name: PortAggregateName)],
        Doc::Local {
            summary: "Show one port aggregate's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for the named port \
                     aggregate's mode, switching-profile, mtu, and subinterfaces.",
        },
        Always,
        |name| Command::ShowPortAggregate {
            name: Some(name.to_string()),
        }),
    cmd!(["show" "lldp" "neighbors"],
        Doc::Local {
            summary: "Show every LLDP neighbor heard on any interface.",
            detail: "Queries nos-lldpd (resolved via nos-watchdogd) for every neighbor learned \
                     from received LLDPDUs (IEEE 802.1AB): the local interface it was heard on, \
                     its chassis id, port id, system name and enabled capabilities, and how long \
                     until its entry ages out.",
        },
        Always,
        Command::ShowLldpNeighbors),
    cmd!(["show" "lacp"],
        Doc::Local {
            summary: "Show every LACP port aggregate's negotiation state.",
            detail: "Queries nos-lacpd (resolved via nos-watchdogd) for every lacp-mode port \
                     aggregate's actor system id, key and rate, and each member port's \
                     receive/mux machine state, partner identity, and whether it is selected \
                     and synchronized.",
        },
        Always,
        Command::ShowLacp { name: None }),
    cmd!(["show" "lacp" (name: PortAggregateName)],
        Doc::Local {
            summary: "Show one LACP port aggregate's negotiation state.",
            detail: "Queries nos-lacpd (resolved via nos-watchdogd) for the named lacp-mode \
                     port aggregate's actor identity and rate, and each member port's \
                     receive/mux machine state and partner identity.",
        },
        Always,
        |name| Command::ShowLacp {
            name: Some(name.to_string()),
        }),
    cmd!(["show" "interface"],
        Doc::Local {
            summary: "Show every interface's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every configured \
                     interface's addresses and routing-table assignment.",
        },
        Always,
        Command::ShowInterface { name: None }),
    cmd!(["show" "interface" (name: InterfaceName)],
        Doc::Local {
            summary: "Show one interface's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for the named \
                     interface's addresses and routing-table assignment.",
        },
        Always,
        |name| Command::ShowInterface {
            name: Some(name.to_string()),
        }),
    cmd!(["show" "log"],
        Doc::Local {
            summary: "Show the most recent collected log entries from every daemon.",
            detail: "Queries nos-logd (resolved via nos-watchdogd) for its current buffer of \
                     log entries pushed by every other component process.",
        },
        Always,
        Command::ShowLog {
            source: None,
            follow: false,
        }),
    cmd!(["show" "log" "--follow"],
        Doc::Local {
            summary: "Live-tail collected log entries from every daemon.",
            detail: "Prints the current buffer, then streams new entries as they're pushed to \
                     nos-logd until Ctrl-C is pressed or the connection is lost.",
        },
        Always,
        Command::ShowLog {
            source: None,
            follow: true,
        }),
    cmd!(["show" "log" (source: Plain)],
        Doc::Local {
            summary: "Show the most recent collected log entries from one source.",
            detail: "Same as `show log`, filtered to entries whose source exactly matches \
                     <source> (e.g. `nos-ribd[rt1]`, `nos-interfaced`, `nos-configd`).",
        },
        Always,
        |source| Command::ShowLog {
            source: Some(source.to_string()),
            follow: false,
        }),
    cmd!(["show" "log" (source: Plain) "--follow"],
        Doc::Local {
            summary: "Live-tail collected log entries from one source.",
            detail: "Same as `show log --follow`, filtered to entries whose source exactly \
                     matches <source>.",
        },
        Always,
        |source| Command::ShowLog {
            source: Some(source.to_string()),
            follow: true,
        }),
    cmd!(["show" "bgp" "brief"],
        Doc::Local {
            summary: "Show a one-line-per-peer BGP session summary across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for its peers' current session state, remote AS, uptime, \
                     and negotiated hold-time. An instance whose nos-bgpd isn't running is \
                     reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpBrief),
    cmd!(["show" "bgp" "evpn"],
        Doc::Local {
            summary: "Show every EVPN route received from BGP peers, across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for the EVPN (AFI 25 / SAFI 70) routes its peers sent: \
                     route type, NLRI, next-hop and extended communities (Route Targets, \
                     Encapsulation). Only peers whose peer-group has `address-family \
                     l2vpn-evpn` exchange them. An instance whose nos-bgpd isn't running is \
                     reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpEvpn),
    cmd!(["show" "ospf" "neigh"],
        Doc::Local {
            summary: "Show a one-line-per-neighbor OSPF adjacency summary across every instance.",
            detail: "Queries every configured OSPF instance's nos-ospfd (each resolved via \
                     nos-watchdogd) for its links' current neighbor state, interface state, \
                     last-hello age, and elected DR/BDR. An instance whose nos-ospfd isn't \
                     running is reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowOspfNeigh),
    cmd!(["show" "ospf" "database"],
        Doc::Local {
            summary: "Show every installed LSA's header across every OSPF instance.",
            detail: "Queries every configured OSPF instance's nos-ospfd (each resolved via \
                     nos-watchdogd) for its per-area LSDB's installed LSA headers (type, \
                     link-state-id, advertising router, sequence number, age, checksum). An \
                     instance whose nos-ospfd isn't running is reported individually rather \
                     than aborting the whole command.",
        },
        Always,
        Command::ShowOspfDatabase),
    cmd!(["show" "ospfv3" "neigh"],
        Doc::Local {
            summary: "Show a one-line-per-neighbor OSPFv3 adjacency summary across every instance.",
            detail: "Mirrors 'show ospf neigh' for OSPFv3 (RFC 5340): queries every configured \
                     Ospfv3Instance's nos-ospfv3d (each resolved via nos-watchdogd) for its \
                     links' current neighbor state, interface state, last-hello age, and \
                     elected DR/BDR.",
        },
        Always,
        Command::ShowOspfv3Neigh),
    cmd!(["show" "ospfv3" "database"],
        Doc::Local {
            summary: "Show every installed LSA's header across every OSPFv3 instance.",
            detail: "Mirrors 'show ospf database' for OSPFv3 (RFC 5340).",
        },
        Always,
        Command::ShowOspfv3Database),
    cmd!(["clear" "bgp" (instance: BgpInstanceName) (peer: IpAddr) "soft-in"],
        Doc::Local {
            summary: "Ask a peer to resend its routes (RFC 2918 route refresh).",
            detail: "Sends a BGP ROUTE_REFRESH message to <peer> over its current session on \
                     <instance>'s nos-bgpd, asking it to re-advertise its full Adj-RIB-Out for \
                     every address family this session negotiated. Reported as an error if \
                     <instance> has no established session with <peer> right now.",
        },
        Always,
        |instance, peer| Command::ClearBgpSoftIn {
            instance: instance.to_string(),
            peer: peer.parse().ok()?,
        }),
    spec!(["edit" "interface" (InterfaceName)],
        "edit interface <name>",
        Doc::FromConfig(Topic::Interface),
        Configuration),
    spec!(["set" "interface" (InterfaceName) "address" (Plain)],
        "set interface <name> address <cidr>",
        Doc::FromConfig(Topic::InterfaceAddress),
        Configuration),
    spec!(["set" "address" (Plain)],
        "set address <cidr>",
        Doc::FromConfig(Topic::InterfaceAddress),
        ConfigurationInterfaceOrSubinterface),
    spec!(["set" "interface" (InterfaceName) "address" (Plain) "label" (Plain)],
        "set interface <name> address <cidr> label <label>",
        Doc::FromConfig(Topic::InterfaceAddress),
        Configuration),
    spec!(["set" "address" (Plain) "label" (Plain)],
        "set address <cidr> label <label>",
        Doc::FromConfig(Topic::InterfaceAddress),
        ConfigurationInterfaceOrSubinterface),
    spec!(["delete" "interface" (InterfaceName) "address" (Plain)],
        "delete interface <name> address <cidr>",
        Doc::FromConfig(Topic::InterfaceAddress),
        Configuration),
    spec!(["delete" "address" (Plain)],
        "delete address <cidr>",
        Doc::FromConfig(Topic::InterfaceAddress),
        ConfigurationInterfaceOrSubinterface),
    spec!(["set" "interface" (InterfaceName) "routing-table" (RoutingTableName)],
        "set interface <name> routing-table <table>",
        Doc::FromConfig(Topic::InterfaceRoutingTable),
        Configuration),
    spec!(["set" "routing-table" (RoutingTableName)],
        "set routing-table <table>",
        Doc::FromConfig(Topic::InterfaceRoutingTable),
        ConfigurationInterfaceOrSubinterface),
    spec!(["delete" "interface" (InterfaceName) "routing-table"],
        "delete interface <name> routing-table",
        Doc::FromConfig(Topic::InterfaceRoutingTable),
        Configuration),
    spec!(["delete" "routing-table"],
        "delete routing-table",
        Doc::FromConfig(Topic::InterfaceRoutingTable),
        ConfigurationInterfaceOrSubinterface),
    spec!(["set" "interface" (InterfaceName) "ospf" (OspfProfileName)],
        "set interface <name> ospf <profile-name>",
        Doc::FromConfig(Topic::InterfaceOspfProfile),
        Configuration),
    spec!(["set" "ospf" (OspfProfileName)],
        "set ospf <profile-name>",
        Doc::FromConfig(Topic::InterfaceOspfProfile),
        ConfigurationInterfaceOrSubinterface),
    spec!(["delete" "interface" (InterfaceName) "ospf"],
        "delete interface <name> ospf",
        Doc::FromConfig(Topic::InterfaceOspfProfile),
        Configuration),
    spec!(["delete" "ospf"],
        "delete ospf",
        Doc::FromConfig(Topic::InterfaceOspfProfile),
        ConfigurationInterfaceOrSubinterface),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "address" (Plain)],
        "set broadcast domain <name> address <cidr>",
        Doc::FromConfig(Topic::BroadcastDomainAddress),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "address" (Plain) "label" (Plain)],
        "set broadcast domain <name> address <cidr> label <label>",
        Doc::FromConfig(Topic::BroadcastDomainAddress),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "address" (Plain)],
        "delete broadcast domain <name> address <cidr>",
        Doc::FromConfig(Topic::BroadcastDomainAddress),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "routing-table" (RoutingTableName)],
        "set broadcast domain <name> routing-table <table>",
        Doc::FromConfig(Topic::BroadcastDomainRoutingTable),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "routing-table"],
        "delete broadcast domain <name> routing-table",
        Doc::FromConfig(Topic::BroadcastDomainRoutingTable),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "esi" (Plain)],
        "set port-aggregate <name> esi <00:11:22:33:44:55:66:77:88:99>",
        Doc::FromConfig(Topic::PortAggregateEsi),
        Configuration),
    spec!(["delete" "port-aggregate" (PortAggregateName) "esi"],
        "delete port-aggregate <name> esi",
        Doc::FromConfig(Topic::PortAggregateEsi),
        Configuration),
    spec!(["set" "port-aggregate" (PortAggregateName) "lacp-system-id" (Plain)],
        "set port-aggregate <name> lacp-system-id <mac>",
        Doc::FromConfig(Topic::PortAggregateLacpSystemId),
        Configuration),
    spec!(["delete" "port-aggregate" (PortAggregateName) "lacp-system-id"],
        "delete port-aggregate <name> lacp-system-id",
        Doc::FromConfig(Topic::PortAggregateLacpSystemId),
        Configuration),
    spec!(["set" "esi" (Plain)],
        "set esi <00:11:22:33:44:55:66:77:88:99>",
        Doc::FromConfig(Topic::PortAggregateEsi),
        ConfigurationPortAggregate),
    spec!(["delete" "esi"],
        "delete esi",
        Doc::FromConfig(Topic::PortAggregateEsi),
        ConfigurationPortAggregate),
    spec!(["set" "lacp-system-id" (Plain)],
        "set lacp-system-id <mac>",
        Doc::FromConfig(Topic::PortAggregateLacpSystemId),
        ConfigurationPortAggregate),
    spec!(["delete" "lacp-system-id"],
        "delete lacp-system-id",
        Doc::FromConfig(Topic::PortAggregateLacpSystemId),
        ConfigurationPortAggregate),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vni" (Plain)],
        "set broadcast domain <name> vni <n>",
        Doc::FromConfig(Topic::BroadcastDomainVni),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "vni"],
        "delete broadcast domain <name> vni",
        Doc::FromConfig(Topic::BroadcastDomainVni),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "rd" (Plain)],
        "set broadcast domain <name> rd <asn:nn|a.b.c.d:nn>",
        Doc::FromConfig(Topic::BroadcastDomainRd),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "rd"],
        "delete broadcast domain <name> rd",
        Doc::FromConfig(Topic::BroadcastDomainRd),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "route-target" "import" (Plain)],
        "set broadcast domain <name> route-target import <asn:nn>",
        Doc::FromConfig(Topic::BroadcastDomainRouteTarget),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "route-target" "export" (Plain)],
        "set broadcast domain <name> route-target export <asn:nn>",
        Doc::FromConfig(Topic::BroadcastDomainRouteTarget),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "route-target" "import" (Plain)],
        "delete broadcast domain <name> route-target import <asn:nn>",
        Doc::FromConfig(Topic::BroadcastDomainRouteTarget),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "route-target" "export" (Plain)],
        "delete broadcast domain <name> route-target export <asn:nn>",
        Doc::FromConfig(Topic::BroadcastDomainRouteTarget),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vtep-source" "interface" (InterfaceName)],
        "set broadcast domain <name> vtep-source interface <name>",
        Doc::FromConfig(Topic::BroadcastDomainVtepSource),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vtep-source" "interface" (InterfaceName) "label" (Plain)],
        "set broadcast domain <name> vtep-source interface <name> label <label>",
        Doc::FromConfig(Topic::BroadcastDomainVtepSource),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vtep-source" "loopback"],
        "set broadcast domain <name> vtep-source loopback",
        Doc::FromConfig(Topic::BroadcastDomainVtepSource),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "vtep-source" "loopback" "label" (Plain)],
        "set broadcast domain <name> vtep-source loopback label <label>",
        Doc::FromConfig(Topic::BroadcastDomainVtepSource),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "vtep-source"],
        "delete broadcast domain <name> vtep-source",
        Doc::FromConfig(Topic::BroadcastDomainVtepSource),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "mac" "to" "bgp" (BgpInstanceName)],
        "set broadcast domain <name> redistribute from mac to bgp <instance>",
        Doc::FromConfig(Topic::BroadcastDomainMacRedistribute),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "redistribute"],
        "delete broadcast domain <name> redistribute",
        Doc::FromConfig(Topic::BroadcastDomainMacRedistribute),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "mac"],
        "delete broadcast domain <name> redistribute from mac",
        Doc::FromConfig(Topic::BroadcastDomainMacRedistribute),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "arp" "to" "bgp" (BgpInstanceName)],
        "set broadcast domain <name> redistribute from arp to bgp <instance>",
        Doc::FromConfig(Topic::BroadcastDomainArpRedistribute),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "arp"],
        "delete broadcast domain <name> redistribute from arp",
        Doc::FromConfig(Topic::BroadcastDomainArpRedistribute),
        Configuration),
    spec!(["set" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "connected" "to" "bgp" (BgpInstanceName)],
        "set broadcast domain <name> redistribute from connected to bgp <instance>",
        Doc::FromConfig(Topic::BroadcastDomainConnectedRedistribute),
        Configuration),
    spec!(["delete" "broadcast" "domain" (BroadcastDomainName) "redistribute" "from" "connected"],
        "delete broadcast domain <name> redistribute from connected",
        Doc::FromConfig(Topic::BroadcastDomainConnectedRedistribute),
        Configuration),
    spec!(["set" "interface" (InterfaceName) "switching-profile" (SwitchingProfileName)],
        "set interface <name> switching-profile <profile>",
        Doc::FromConfig(Topic::InterfaceSwitchingProfile),
        Configuration),
    spec!(["set" "switching-profile" (SwitchingProfileName)],
        "set switching-profile <profile>",
        Doc::FromConfig(Topic::InterfaceSwitchingProfile),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "switching-profile"],
        "delete interface <name> switching-profile",
        Doc::FromConfig(Topic::InterfaceSwitchingProfile),
        Configuration),
    spec!(["delete" "switching-profile"],
        "delete switching-profile",
        Doc::FromConfig(Topic::InterfaceSwitchingProfile),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "mtu" (Plain)],
        "set interface <name> mtu <n>",
        Doc::FromConfig(Topic::InterfaceMtu),
        Configuration),
    spec!(["set" "mtu" (Plain)],
        "set mtu <n>",
        Doc::FromConfig(Topic::InterfaceMtu),
        ConfigurationInterfaceOrOspfProfile),
    spec!(["delete" "interface" (InterfaceName) "mtu"],
        "delete interface <name> mtu",
        Doc::FromConfig(Topic::InterfaceMtu),
        Configuration),
    spec!(["delete" "mtu"],
        "delete mtu",
        Doc::FromConfig(Topic::InterfaceMtu),
        ConfigurationInterfaceOrOspfProfile),
    spec!(["set" "interface" (InterfaceName) "lldp" "transmit"],
        "set interface <name> lldp transmit",
        Doc::FromConfig(Topic::InterfaceLldpTransmit),
        Configuration),
    spec!(["set" "lldp" "transmit"],
        "set lldp transmit",
        Doc::FromConfig(Topic::InterfaceLldpTransmit),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "lldp" "receive"],
        "set interface <name> lldp receive",
        Doc::FromConfig(Topic::InterfaceLldpReceive),
        Configuration),
    spec!(["set" "lldp" "receive"],
        "set lldp receive",
        Doc::FromConfig(Topic::InterfaceLldpReceive),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "lldp" "transmit"],
        "delete interface <name> lldp transmit",
        Doc::FromConfig(Topic::InterfaceLldpTransmit),
        Configuration),
    spec!(["delete" "lldp" "transmit"],
        "delete lldp transmit",
        Doc::FromConfig(Topic::InterfaceLldpTransmit),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "lldp" "receive"],
        "delete interface <name> lldp receive",
        Doc::FromConfig(Topic::InterfaceLldpReceive),
        Configuration),
    spec!(["delete" "lldp" "receive"],
        "delete lldp receive",
        Doc::FromConfig(Topic::InterfaceLldpReceive),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "lldp" "destination" "nearest-bridge"],
        "set interface <name> lldp destination nearest-bridge",
        Doc::FromConfig(Topic::InterfaceLldpDestination),
        Configuration),
    spec!(["set" "lldp" "destination" "nearest-bridge"],
        "set lldp destination nearest-bridge",
        Doc::FromConfig(Topic::InterfaceLldpDestination),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "lldp" "destination" "non-tpmr"],
        "set interface <name> lldp destination non-tpmr",
        Doc::FromConfig(Topic::InterfaceLldpDestination),
        Configuration),
    spec!(["set" "lldp" "destination" "non-tpmr"],
        "set lldp destination non-tpmr",
        Doc::FromConfig(Topic::InterfaceLldpDestination),
        ConfigurationInterface),
    spec!(["set" "interface" (InterfaceName) "lldp" "destination" "customer-bridge"],
        "set interface <name> lldp destination customer-bridge",
        Doc::FromConfig(Topic::InterfaceLldpDestination),
        Configuration),
    spec!(["set" "lldp" "destination" "customer-bridge"],
        "set lldp destination customer-bridge",
        Doc::FromConfig(Topic::InterfaceLldpDestination),
        ConfigurationInterface),
    spec!(["delete" "interface" (InterfaceName) "lldp" "destination"],
        "delete interface <name> lldp destination",
        Doc::FromConfig(Topic::InterfaceLldpDestination),
        Configuration),
    spec!(["delete" "lldp" "destination"],
        "delete lldp destination",
        Doc::FromConfig(Topic::InterfaceLldpDestination),
        ConfigurationInterface),
    spec!(["set" "lldp" "tx-interval" (Plain)],
        "set lldp tx-interval <seconds>",
        Doc::FromConfig(Topic::LldpTxInterval),
        Configuration),
    spec!(["delete" "lldp" "tx-interval"],
        "delete lldp tx-interval",
        Doc::FromConfig(Topic::LldpTxInterval),
        Configuration),
    spec!(["set" "lldp" "tx-hold" (Plain)],
        "set lldp tx-hold <n>",
        Doc::FromConfig(Topic::LldpTxHold),
        Configuration),
    spec!(["delete" "lldp" "tx-hold"],
        "delete lldp tx-hold",
        Doc::FromConfig(Topic::LldpTxHold),
        Configuration),
    spec!(["set" "lldp" "management-address" (Plain)],
        "set lldp management-address <address>",
        Doc::FromConfig(Topic::LldpManagementAddress),
        Configuration),
    spec!(["delete" "lldp" "management-address"],
        "delete lldp management-address",
        Doc::FromConfig(Topic::LldpManagementAddress),
        Configuration),
    spec!(["delete" "interface" (InterfaceName)],
        "delete interface <name>",
        Doc::FromConfig(Topic::Interface),
        Configuration),
];

/// One whitespace-delimited token of `line`, with its start byte offset.
pub(crate) fn tokenize_with_offsets(line: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, ch) in line.char_indices() {
        if ch.is_whitespace() {
            if let Some(s) = start.take() {
                out.push((s, &line[s..i]));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push((s, &line[s..]));
    }
    out
}

/// Parses `line` against the `cmd!` rows: the index of the first row whose
/// token shape fits, and what its `build` made of the argument words
/// (`None` — an argument that doesn't parse — is final, never a reason to
/// try a later row). `None` when no row fits.
pub fn parse(line: &str) -> Option<(usize, Option<Command>)> {
    let words = tokenize_with_offsets(line);
    COMMAND_SPECS.iter().enumerate().find_map(|(i, spec)| {
        let build = spec.build?;
        let mut args = Vec::new();
        for (j, token) in spec.tokens.iter().enumerate() {
            let &(_, word) = words.get(j)?;
            match token {
                Token::Literal(lit) if *lit == word => {}
                Token::Literal(_) => return None,
                // Everything after the one separator that follows the
                // previous word, so leading whitespace survives.
                Token::Arg(ArgKind::Rest) => {
                    let (prev_start, prev) = words[j - 1];
                    let mut rest = line[prev_start + prev.len()..].chars();
                    rest.next();
                    args.push(rest.as_str());
                    return Some((i, build(&args)));
                }
                Token::Arg(_) => args.push(word),
            }
        }
        (words.len() == spec.tokens.len()).then(|| (i, build(&args)))
    })
}

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

    /// Every `cmd!` row, filled with a sample word per argument, parses back
    /// through `parse` to a command built by that same row — so no row is
    /// shadowed by an earlier one, and each `build` binds as many words as
    /// the row has argument slots.
    #[test]
    fn every_cmd_row_round_trips() {
        for (i, spec) in COMMAND_SPECS.iter().enumerate() {
            if spec.build.is_none() {
                continue;
            }
            let line = spec
                .tokens
                .iter()
                .map(|t| match t {
                    Token::Literal(lit) => *lit,
                    Token::Arg(ArgKind::IpAddr) => "192.0.2.1",
                    Token::Arg(ArgKind::Number) => "1",
                    Token::Arg(ArgKind::Rest) => "  some text",
                    Token::Arg(_) => "sample",
                })
                .collect::<Vec<_>>()
                .join(" ");
            match parse(&line) {
                Some((j, Some(_))) if j == i => {}
                other => panic!("{:?} ({line:?}) parsed to {other:?}", spec.usage),
            }
        }
    }

    #[test]
    fn cmd_usage_is_generated_from_tokens() {
        let usages: Vec<_> = COMMAND_SPECS.iter().map(|s| s.usage).collect();
        assert!(usages.contains(&"show route <table> <address>"));
        assert!(usages.contains(&"clear bgp <instance> <peer> soft-in"));
        assert!(usages.contains(&"set source line <line> <text>"));
    }

    #[test]
    fn rest_keeps_leading_whitespace() {
        assert_eq!(
            Command::parse("set source line 2     accept"),
            Command::SetSourceLine {
                line: 2,
                text: "    accept".to_string(),
            }
        );
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
