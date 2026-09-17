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
    ConfigurationStaticRoutingInstance,
    ConfigurationInterface,
    ConfigurationSwitchingProfile,
    /// Any non-root navigation position — `BgpInstance`, `BgpPeerGroup`,
    /// `RoutingTable`, `StaticRoutingInstance`, or `Interface`.
    ConfigurationNested,
}

pub fn availability_matches(availability: Availability, mode: &Mode) -> bool {
    match availability {
        Availability::Always => true,
        Availability::Operational => matches!(mode, Mode::Operational),
        Availability::Configuration => matches!(mode, Mode::Configuration { .. }),
        Availability::ConfigurationInstance => matches!(
            mode,
            Mode::Configuration {
                path: Path::BgpInstance(_),
                ..
            }
        ),
        Availability::ConfigurationPeerGroup => matches!(
            mode,
            Mode::Configuration {
                path: Path::BgpPeerGroup { .. },
                ..
            }
        ),
        Availability::ConfigurationRoutingTable => matches!(
            mode,
            Mode::Configuration {
                path: Path::RoutingTable(_),
                ..
            }
        ),
        Availability::ConfigurationStaticRoutingInstance => matches!(
            mode,
            Mode::Configuration {
                path: Path::StaticRoutingInstance(_),
                ..
            }
        ),
        Availability::ConfigurationInterface => matches!(
            mode,
            Mode::Configuration {
                path: Path::Interface(_),
                ..
            }
        ),
        Availability::ConfigurationSwitchingProfile => matches!(
            mode,
            Mode::Configuration {
                path: Path::SwitchingProfile(_),
                ..
            }
        ),
        Availability::ConfigurationNested => matches!(
            mode,
            Mode::Configuration {
                path: Path::BgpInstance(_)
                    | Path::BgpPeerGroup { .. }
                    | Path::RoutingTable(_)
                    | Path::StaticRoutingInstance(_)
                    | Path::Interface(_),
                ..
            }
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

pub const COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec {
        tokens: &[Token::Literal("show"), Token::Literal("config")],
        usage: "show config",
        doc: Doc::FromConfig(Topic::ShowRunningConfig),
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[Token::Literal("show"), Token::Literal("this")],
        usage: "show this",
        doc: Doc::FromConfig(Topic::GetTransaction),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("show"),
            Token::Literal("route"),
            Token::Arg(ArgKind::RoutingTableName),
        ],
        usage: "show route <table>",
        doc: Doc::Local {
            summary: "Show every route in a routing table, best to worst per prefix.",
            detail: "Queries the table's nos-ribd instance (resolved via nos-watchdogd) for \
                     every prefix it currently knows, each with its full list of candidate \
                     routes ordered from the winning route to the losing ones — since more \
                     than one source (e.g. static and BGP) can target the same prefix. \
                     Prefixes are listed in ascending CIDR order.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("show"),
            Token::Literal("route"),
            Token::Arg(ArgKind::RoutingTableName),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "show route <table> <address>",
        doc: Doc::Local {
            summary: "Look up the best route(s) for one destination address.",
            detail: "Performs a longest-prefix-match lookup against the table's nos-ribd \
                     instance for the given address, and shows every candidate route for the \
                     matched prefix, ordered from the winning route to the losing ones.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[Token::Literal("save")],
        usage: "save",
        doc: Doc::FromConfig(Topic::Save),
        availability: Availability::Operational,
    },
    CommandSpec {
        tokens: &[Token::Literal("help")],
        usage: "help",
        doc: Doc::Local {
            summary: "Show available commands for the current mode.",
            detail: "Lists every command valid right now, given whether the shell is in \
                     operational mode or configuration mode (and, within configuration \
                     mode, the current navigation position). Equivalent to pressing `?` on \
                     an empty line.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[Token::Literal("exit")],
        usage: "exit",
        doc: EXIT_DOC,
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[Token::Literal("quit")],
        usage: "quit",
        doc: EXIT_DOC,
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[Token::Literal("end")],
        usage: "end",
        doc: EXIT_DOC,
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[Token::Literal("configure"), Token::Arg(ArgKind::Plain)],
        usage: "configure <name> [from blank|current]",
        doc: Doc::FromConfig(Topic::OpenTransaction),
        availability: Availability::Operational,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("edit"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
        ],
        usage: "edit bgp instance <name>",
        doc: Doc::FromConfig(Topic::EnsureBgpInstance),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("asn"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> asn <n>",
        doc: Doc::FromConfig(Topic::SetBgpInstanceAsn),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("router-id"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> router-id <router-id>",
        doc: Doc::FromConfig(Topic::SetBgpInstanceRouterId),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("asn"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set asn <n>",
        doc: Doc::FromConfig(Topic::SetBgpInstanceAsn),
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("router-id"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set router-id <router-id>",
        doc: Doc::FromConfig(Topic::SetBgpInstanceRouterId),
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("cluster-id"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> cluster-id <ip>",
        doc: Doc::FromConfig(Topic::SetBgpInstanceClusterId),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("cluster-id"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set cluster-id <ip>",
        doc: Doc::FromConfig(Topic::SetBgpInstanceClusterId),
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("cluster-id"),
        ],
        usage: "delete bgp instance <name> cluster-id",
        doc: Doc::FromConfig(Topic::ClearBgpInstanceClusterId),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete"), Token::Literal("cluster-id")],
        usage: "delete cluster-id",
        doc: Doc::FromConfig(Topic::ClearBgpInstanceClusterId),
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("hostname"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set hostname <name>",
        doc: Doc::FromConfig(Topic::SetHostname),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete")],
        usage: "delete",
        doc: Doc::FromConfig(Topic::DeleteBgpInstance),
        availability: Availability::ConfigurationNested,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
        ],
        usage: "delete bgp instance <name>",
        doc: Doc::FromConfig(Topic::DeleteBgpInstance),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("edit"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
        ],
        usage: "edit bgp instance <name> peer-group <group>",
        doc: Doc::FromConfig(Topic::EnsureBgpPeerGroup),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("edit"),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
        ],
        usage: "edit peer-group <group>",
        doc: Doc::FromConfig(Topic::EnsureBgpPeerGroup),
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("remote-as"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> peer-group <group> remote-as <n>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupRemoteAs),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("source-address"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
        ],
        usage: "set bgp instance <name> peer-group <group> source-address interface <name>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("source-address"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
            Token::Literal("label"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> peer-group <group> source-address interface <name> label <label>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("source-address"),
            Token::Literal("loopback"),
        ],
        usage: "set bgp instance <name> peer-group <group> source-address loopback",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("source-address"),
            Token::Literal("loopback"),
            Token::Literal("label"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> peer-group <group> source-address loopback label <label>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("address-family"),
            Token::Literal("ipv4"),
        ],
        usage: "set bgp instance <name> peer-group <group> address-family ipv4",
        doc: Doc::FromConfig(Topic::AddBgpPeerGroupAddressFamily),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("address-family"),
            Token::Literal("ipv6"),
        ],
        usage: "set bgp instance <name> peer-group <group> address-family ipv6",
        doc: Doc::FromConfig(Topic::AddBgpPeerGroupAddressFamily),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("hold-time"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> peer-group <group> hold-time <n>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupHoldTime),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("next-hop"),
            Token::Literal("self"),
        ],
        usage: "set bgp instance <name> peer-group <group> next-hop self",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupNextHop),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("next-hop"),
            Token::Literal("unchanged"),
        ],
        usage: "set bgp instance <name> peer-group <group> next-hop unchanged",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupNextHop),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("route-reflector-client"),
        ],
        usage: "set bgp instance <name> peer-group <group> route-reflector-client",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupRouteReflectorClient),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("route-server-client"),
        ],
        usage: "set bgp instance <name> peer-group <group> route-server-client",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupRouteServerClient),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("keepalive-interval"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> peer-group <group> keepalive-interval <n>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupKeepaliveInterval),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("connect-retry-time"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> peer-group <group> connect-retry-time <n>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupConnectRetryTime),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("md5-password"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> peer-group <group> md5-password <password>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupMd5Auth),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("ao-key"),
            Token::Arg(ArgKind::Plain),
            Token::Arg(ArgKind::Plain),
            Token::Arg(ArgKind::Plain),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set bgp instance <name> peer-group <group> ao-key <send-id> <recv-id> <hmac-sha1|aes-cmac> <key>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupAoKey),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("ao-key"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("current"),
        ],
        usage: "set bgp instance <name> peer-group <group> ao-key <send-id> current",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupAoCurrentKey),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
            Token::Literal("ao-key"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("rnext"),
        ],
        usage: "set bgp instance <name> peer-group <group> ao-key <send-id> rnext",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupAoRnextKey),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("remote-as"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set remote-as <n>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupRemoteAs),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("source-address"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
        ],
        usage: "set source-address interface <name>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("source-address"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
            Token::Literal("label"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set source-address interface <name> label <label>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("source-address"),
            Token::Literal("loopback"),
        ],
        usage: "set source-address loopback",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("source-address"),
            Token::Literal("loopback"),
            Token::Literal("label"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set source-address loopback label <label>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupSourceAddress),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("address-family"),
            Token::Literal("ipv4"),
        ],
        usage: "set address-family ipv4",
        doc: Doc::FromConfig(Topic::AddBgpPeerGroupAddressFamily),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("address-family"),
            Token::Literal("ipv6"),
        ],
        usage: "set address-family ipv6",
        doc: Doc::FromConfig(Topic::AddBgpPeerGroupAddressFamily),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("next-hop"),
            Token::Literal("self"),
        ],
        usage: "set next-hop self",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupNextHop),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("next-hop"),
            Token::Literal("unchanged"),
        ],
        usage: "set next-hop unchanged",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupNextHop),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[Token::Literal("set"), Token::Literal("route-reflector-client")],
        usage: "set route-reflector-client",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupRouteReflectorClient),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[Token::Literal("set"), Token::Literal("route-server-client")],
        usage: "set route-server-client",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupRouteServerClient),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("hold-time"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set hold-time <n>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupHoldTime),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("keepalive-interval"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set keepalive-interval <n>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupKeepaliveInterval),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("connect-retry-time"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set connect-retry-time <n>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupConnectRetryTime),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("md5-password"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set md5-password <password>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupMd5Auth),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("ao-key"),
            Token::Arg(ArgKind::Plain),
            Token::Arg(ArgKind::Plain),
            Token::Arg(ArgKind::Plain),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set ao-key <send-id> <recv-id> <hmac-sha1|aes-cmac> <key>",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupAoKey),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("ao-key"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("current"),
        ],
        usage: "set ao-key <send-id> current",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupAoCurrentKey),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("ao-key"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("rnext"),
        ],
        usage: "set ao-key <send-id> rnext",
        doc: Doc::FromConfig(Topic::SetBgpPeerGroupAoRnextKey),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
        ],
        usage: "set bgp instance <name> peer <address> peer-group <group>",
        doc: Doc::FromConfig(Topic::SetBgpPeer),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("peer"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
        ],
        usage: "set peer <address> peer-group <group>",
        doc: Doc::FromConfig(Topic::SetBgpPeer),
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
        ],
        usage: "delete bgp instance <name> peer-group <group>",
        doc: Doc::FromConfig(Topic::DeleteBgpPeerGroup),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("peer-group"),
            Token::Arg(ArgKind::BgpPeerGroupName),
        ],
        usage: "delete peer-group <group>",
        doc: Doc::FromConfig(Topic::DeleteBgpPeerGroup),
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("bgp"),
            Token::Literal("instance"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Literal("peer"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "delete bgp instance <name> peer <address>",
        doc: Doc::FromConfig(Topic::DeleteBgpPeer),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("peer"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "delete peer <address>",
        doc: Doc::FromConfig(Topic::DeleteBgpPeer),
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete"), Token::Literal("source-address")],
        usage: "delete source-address",
        doc: Doc::FromConfig(Topic::ClearBgpPeerGroupSourceAddress),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("address-family"),
            Token::Literal("ipv4"),
        ],
        usage: "delete address-family ipv4",
        doc: Doc::FromConfig(Topic::RemoveBgpPeerGroupAddressFamily),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("address-family"),
            Token::Literal("ipv6"),
        ],
        usage: "delete address-family ipv6",
        doc: Doc::FromConfig(Topic::RemoveBgpPeerGroupAddressFamily),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete"), Token::Literal("next-hop")],
        usage: "delete next-hop",
        doc: Doc::FromConfig(Topic::ClearBgpPeerGroupNextHop),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("route-reflector-client"),
        ],
        usage: "delete route-reflector-client",
        doc: Doc::FromConfig(Topic::ClearBgpPeerGroupRouteReflectorClient),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("route-server-client"),
        ],
        usage: "delete route-server-client",
        doc: Doc::FromConfig(Topic::ClearBgpPeerGroupRouteServerClient),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete"), Token::Literal("hold-time")],
        usage: "delete hold-time",
        doc: Doc::FromConfig(Topic::ClearBgpPeerGroupHoldTime),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("keepalive-interval"),
        ],
        usage: "delete keepalive-interval",
        doc: Doc::FromConfig(Topic::ClearBgpPeerGroupKeepaliveInterval),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("connect-retry-time"),
        ],
        usage: "delete connect-retry-time",
        doc: Doc::FromConfig(Topic::ClearBgpPeerGroupConnectRetryTime),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete"), Token::Literal("auth")],
        usage: "delete auth",
        doc: Doc::FromConfig(Topic::ClearBgpPeerGroupAuth),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("ao-key"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "delete ao-key <send-id>",
        doc: Doc::FromConfig(Topic::RemoveBgpPeerGroupAoKey),
        availability: Availability::ConfigurationPeerGroup,
    },
    CommandSpec {
        tokens: &[Token::Literal("up")],
        usage: "up",
        doc: Doc::Local {
            summary: "Navigate up one level.",
            detail: "Moves the current navigation position up one level: from a peer-group, \
                     to its owning BGP instance; from a BGP instance, to the transaction \
                     root (same as `top`).",
        },
        availability: Availability::ConfigurationNested,
    },
    CommandSpec {
        tokens: &[Token::Literal("top")],
        usage: "top",
        doc: Doc::Local {
            summary: "Navigate back to the transaction root.",
            detail: "Moves the current navigation position directly to the transaction \
                     root, regardless of how deep it is.",
        },
        availability: Availability::ConfigurationNested,
    },
    CommandSpec {
        tokens: &[Token::Literal("commit")],
        usage: "commit",
        doc: Doc::FromConfig(Topic::CommitTransaction),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[Token::Literal("discard")],
        usage: "discard",
        doc: Doc::FromConfig(Topic::DiscardTransaction),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[Token::Literal("abort")],
        usage: "abort",
        doc: Doc::FromConfig(Topic::DiscardTransaction),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[Token::Literal("diff")],
        usage: "diff",
        doc: Doc::FromConfig(Topic::DiffTransaction),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("edit"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
        ],
        usage: "edit routing-table <name>",
        doc: Doc::FromConfig(Topic::EnsureRoutingTable),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
            Token::Literal("bgp-instance"),
            Token::Arg(ArgKind::BgpInstanceName),
        ],
        usage: "set routing-table <name> bgp-instance <instance>",
        doc: Doc::FromConfig(Topic::SetRoutingTableBgpInstance),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("bgp-instance"),
            Token::Arg(ArgKind::BgpInstanceName),
        ],
        usage: "set bgp-instance <instance>",
        doc: Doc::FromConfig(Topic::SetRoutingTableBgpInstance),
        availability: Availability::ConfigurationRoutingTable,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
            Token::Literal("bgp-instance"),
        ],
        usage: "delete routing-table <name> bgp-instance",
        doc: Doc::FromConfig(Topic::ClearRoutingTableBgpInstance),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete"), Token::Literal("bgp-instance")],
        usage: "delete bgp-instance",
        doc: Doc::FromConfig(Topic::ClearRoutingTableBgpInstance),
        availability: Availability::ConfigurationRoutingTable,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
            Token::Literal("static-routing-instance"),
            Token::Arg(ArgKind::StaticRoutingInstanceName),
        ],
        usage: "set routing-table <name> static-routing-instance <instance>",
        doc: Doc::FromConfig(Topic::SetRoutingTableStaticRoutingInstance),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("static-routing-instance"),
            Token::Arg(ArgKind::StaticRoutingInstanceName),
        ],
        usage: "set static-routing-instance <instance>",
        doc: Doc::FromConfig(Topic::SetRoutingTableStaticRoutingInstance),
        availability: Availability::ConfigurationRoutingTable,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
            Token::Literal("static-routing-instance"),
        ],
        usage: "delete routing-table <name> static-routing-instance",
        doc: Doc::FromConfig(Topic::ClearRoutingTableStaticRoutingInstance),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("static-routing-instance"),
        ],
        usage: "delete static-routing-instance",
        doc: Doc::FromConfig(Topic::ClearRoutingTableStaticRoutingInstance),
        availability: Availability::ConfigurationRoutingTable,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
            Token::Literal("redistribute"),
            Token::Literal("from"),
            Token::Literal("static"),
            Token::Literal("to"),
            Token::Literal("bgp"),
        ],
        usage: "set routing-table <name> redistribute from static to bgp",
        doc: Doc::FromConfig(Topic::SetRoutingTableRedistribute),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("redistribute"),
            Token::Literal("from"),
            Token::Literal("static"),
            Token::Literal("to"),
            Token::Literal("bgp"),
        ],
        usage: "set redistribute from static to bgp",
        doc: Doc::FromConfig(Topic::SetRoutingTableRedistribute),
        availability: Availability::ConfigurationRoutingTable,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
            Token::Literal("redistribute"),
        ],
        usage: "delete routing-table <name> redistribute",
        doc: Doc::FromConfig(Topic::ClearRoutingTableRedistribute),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete"), Token::Literal("redistribute")],
        usage: "delete redistribute",
        doc: Doc::FromConfig(Topic::ClearRoutingTableRedistribute),
        availability: Availability::ConfigurationRoutingTable,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
        ],
        usage: "delete routing-table <name>",
        doc: Doc::FromConfig(Topic::DeleteRoutingTable),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("edit"),
            Token::Literal("static-routing-instance"),
            Token::Arg(ArgKind::StaticRoutingInstanceName),
        ],
        usage: "edit static-routing-instance <name>",
        doc: Doc::FromConfig(Topic::EnsureStaticRoutingInstance),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("static-routing-instance"),
            Token::Arg(ArgKind::StaticRoutingInstanceName),
        ],
        usage: "delete static-routing-instance <name>",
        doc: Doc::FromConfig(Topic::DeleteStaticRoutingInstance),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("static-routing-instance"),
            Token::Arg(ArgKind::StaticRoutingInstanceName),
            Token::Literal("route"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("gateway"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set static-routing-instance <name> route <subnet> gateway <address>",
        doc: Doc::FromConfig(Topic::SetStaticRoute),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("route"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("gateway"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set route <subnet> gateway <address>",
        doc: Doc::FromConfig(Topic::SetStaticRoute),
        availability: Availability::ConfigurationStaticRoutingInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("static-routing-instance"),
            Token::Arg(ArgKind::StaticRoutingInstanceName),
            Token::Literal("route"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "delete static-routing-instance <name> route <subnet>",
        doc: Doc::FromConfig(Topic::DeleteStaticRoute),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("route"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "delete route <subnet>",
        doc: Doc::FromConfig(Topic::DeleteStaticRoute),
        availability: Availability::ConfigurationStaticRoutingInstance,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("edit"),
            Token::Literal("broadcast"),
            Token::Literal("domain"),
            Token::Arg(ArgKind::BroadcastDomainName),
        ],
        usage: "edit broadcast domain <name>",
        doc: Doc::FromConfig(Topic::EnsureBroadcastDomain),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("broadcast"),
            Token::Literal("domain"),
            Token::Arg(ArgKind::BroadcastDomainName),
        ],
        usage: "delete broadcast domain <name>",
        doc: Doc::FromConfig(Topic::DeleteBroadcastDomain),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("edit"),
            Token::Literal("switching-profile"),
            Token::Arg(ArgKind::SwitchingProfileName),
        ],
        usage: "edit switching-profile <name>",
        doc: Doc::FromConfig(Topic::EnsureSwitchingProfile),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("switching-profile"),
            Token::Arg(ArgKind::SwitchingProfileName),
        ],
        usage: "delete switching-profile <name>",
        doc: Doc::FromConfig(Topic::DeleteSwitchingProfile),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("switching-profile"),
            Token::Arg(ArgKind::SwitchingProfileName),
            Token::Literal("broadcast-domain"),
            Token::Arg(ArgKind::BroadcastDomainName),
            Token::Literal("tag"),
            Token::Literal("dot1q"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set switching-profile <name> broadcast-domain <domain> tag dot1q <n>",
        doc: Doc::FromConfig(Topic::AddSwitchingProfileMember),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("switching-profile"),
            Token::Arg(ArgKind::SwitchingProfileName),
            Token::Literal("broadcast-domain"),
            Token::Arg(ArgKind::BroadcastDomainName),
            Token::Literal("tag"),
            Token::Literal("untagged"),
        ],
        usage: "set switching-profile <name> broadcast-domain <domain> tag untagged",
        doc: Doc::FromConfig(Topic::AddSwitchingProfileMember),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("broadcast-domain"),
            Token::Arg(ArgKind::BroadcastDomainName),
            Token::Literal("tag"),
            Token::Literal("dot1q"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set broadcast-domain <domain> tag dot1q <n>",
        doc: Doc::FromConfig(Topic::AddSwitchingProfileMember),
        availability: Availability::ConfigurationSwitchingProfile,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("broadcast-domain"),
            Token::Arg(ArgKind::BroadcastDomainName),
            Token::Literal("tag"),
            Token::Literal("untagged"),
        ],
        usage: "set broadcast-domain <domain> tag untagged",
        doc: Doc::FromConfig(Topic::AddSwitchingProfileMember),
        availability: Availability::ConfigurationSwitchingProfile,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("switching-profile"),
            Token::Arg(ArgKind::SwitchingProfileName),
            Token::Literal("broadcast-domain"),
            Token::Arg(ArgKind::BroadcastDomainName),
        ],
        usage: "delete switching-profile <name> broadcast-domain <domain>",
        doc: Doc::FromConfig(Topic::RemoveSwitchingProfileMember),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("broadcast-domain"),
            Token::Arg(ArgKind::BroadcastDomainName),
        ],
        usage: "delete broadcast-domain <domain>",
        doc: Doc::FromConfig(Topic::RemoveSwitchingProfileMember),
        availability: Availability::ConfigurationSwitchingProfile,
    },
    CommandSpec {
        tokens: &[Token::Literal("show"), Token::Literal("interface")],
        usage: "show interface",
        doc: Doc::Local {
            summary: "Show every interface's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every configured \
                     interface's addresses and routing-table assignment.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("show"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
        ],
        usage: "show interface <name>",
        doc: Doc::Local {
            summary: "Show one interface's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for the named \
                     interface's addresses and routing-table assignment.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[Token::Literal("show"), Token::Literal("log")],
        usage: "show log",
        doc: Doc::Local {
            summary: "Show the most recent collected log entries from every daemon.",
            detail: "Queries nos-logd (resolved via nos-watchdogd) for its current buffer of \
                     log entries pushed by every other component process.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("show"),
            Token::Literal("log"),
            Token::Literal("--follow"),
        ],
        usage: "show log --follow",
        doc: Doc::Local {
            summary: "Live-tail collected log entries from every daemon.",
            detail: "Prints the current buffer, then streams new entries as they're pushed to \
                     nos-logd until Ctrl-C is pressed or the connection is lost.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("show"),
            Token::Literal("log"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "show log <source>",
        doc: Doc::Local {
            summary: "Show the most recent collected log entries from one source.",
            detail: "Same as `show log`, filtered to entries whose source exactly matches \
                     <source> (e.g. `nos-ribd[rt1]`, `nos-interfaced`, `nos-configd`).",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("show"),
            Token::Literal("log"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("--follow"),
        ],
        usage: "show log <source> --follow",
        doc: Doc::Local {
            summary: "Live-tail collected log entries from one source.",
            detail: "Same as `show log --follow`, filtered to entries whose source exactly \
                     matches <source>.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("show"),
            Token::Literal("bgp"),
            Token::Literal("brief"),
        ],
        usage: "show bgp brief",
        doc: Doc::Local {
            summary: "Show a one-line-per-peer BGP session summary across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for its peers' current session state, remote AS, uptime, \
                     and negotiated hold-time. An instance whose nos-bgpd isn't running is \
                     reported individually rather than aborting the whole command.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("clear"),
            Token::Literal("bgp"),
            Token::Arg(ArgKind::BgpInstanceName),
            Token::Arg(ArgKind::Plain),
            Token::Literal("soft-in"),
        ],
        usage: "clear bgp <instance> <peer> soft-in",
        doc: Doc::Local {
            summary: "Ask a peer to resend its routes (RFC 2918 route refresh).",
            detail: "Sends a BGP ROUTE_REFRESH message to <peer> over its current session on \
                     <instance>'s nos-bgpd, asking it to re-advertise its full Adj-RIB-Out for \
                     every address family this session negotiated. Reported as an error if \
                     <instance> has no established session with <peer> right now.",
        },
        availability: Availability::Always,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("edit"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
        ],
        usage: "edit interface <name>",
        doc: Doc::FromConfig(Topic::EnsureInterface),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
            Token::Literal("address"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set interface <name> address <cidr>",
        doc: Doc::FromConfig(Topic::AddInterfaceAddress),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("address"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set address <cidr>",
        doc: Doc::FromConfig(Topic::AddInterfaceAddress),
        availability: Availability::ConfigurationInterface,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
            Token::Literal("address"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("label"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set interface <name> address <cidr> label <label>",
        doc: Doc::FromConfig(Topic::AddInterfaceAddress),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("address"),
            Token::Arg(ArgKind::Plain),
            Token::Literal("label"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "set address <cidr> label <label>",
        doc: Doc::FromConfig(Topic::AddInterfaceAddress),
        availability: Availability::ConfigurationInterface,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
            Token::Literal("address"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "delete interface <name> address <cidr>",
        doc: Doc::FromConfig(Topic::RemoveInterfaceAddress),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("address"),
            Token::Arg(ArgKind::Plain),
        ],
        usage: "delete address <cidr>",
        doc: Doc::FromConfig(Topic::RemoveInterfaceAddress),
        availability: Availability::ConfigurationInterface,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
        ],
        usage: "set interface <name> routing-table <table>",
        doc: Doc::FromConfig(Topic::SetInterfaceRoutingTable),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("set"),
            Token::Literal("routing-table"),
            Token::Arg(ArgKind::RoutingTableName),
        ],
        usage: "set routing-table <table>",
        doc: Doc::FromConfig(Topic::SetInterfaceRoutingTable),
        availability: Availability::ConfigurationInterface,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
            Token::Literal("routing-table"),
        ],
        usage: "delete interface <name> routing-table",
        doc: Doc::FromConfig(Topic::ClearInterfaceRoutingTable),
        availability: Availability::Configuration,
    },
    CommandSpec {
        tokens: &[Token::Literal("delete"), Token::Literal("routing-table")],
        usage: "delete routing-table",
        doc: Doc::FromConfig(Topic::ClearInterfaceRoutingTable),
        availability: Availability::ConfigurationInterface,
    },
    CommandSpec {
        tokens: &[
            Token::Literal("delete"),
            Token::Literal("interface"),
            Token::Arg(ArgKind::InterfaceName),
        ],
        usage: "delete interface <name>",
        doc: Doc::FromConfig(Topic::DeleteInterface),
        availability: Availability::Configuration,
    },
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
