use std::net::{IpAddr, Ipv4Addr};

use nos_proto::{
    loopback_table_name, BgpAoKey, BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp, BroadcastDomainOp,
    CommunityAliasOp, CommunityGroupOp, ConfigOp, InterfaceOp, LldpOp, OspfAreaOp, OspfCryptoKey,
    OspfInstanceOp, OspfProfileOp, Ospfv3AreaOp, Ospfv3InstanceOp, Ospfv3ProfileOp,
    PolicyDefinitionOp, PortAggregateOp, PrefixListEntry, PrefixListOp, RoutingTableOp,
    StaticRouteOp, StaticRoutingInstanceOp, SubinterfaceOp, SwitchingProfileOp, TransactionBase,
    UserOp,
};

use crate::command::{
    BgpInstanceField, BgpPeerGroupField, Command, DeleteTarget, EditTarget, LldpDirection,
    LldpSetting, LldpSettingKind, OspfProfileField, SetTarget,
};

/// Navigation position within the transaction's config tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path {
    Root,
    BgpInstance(String),
    BgpPeerGroup {
        instance: String,
        group: String,
    },
    RoutingTable(String),
    OspfInstance(String),
    OspfArea {
        instance: String,
        area_id: Ipv4Addr,
    },
    OspfProfile {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    Ospfv3Instance(String),
    Ospfv3Area {
        instance: String,
        area_id: Ipv4Addr,
    },
    Ospfv3Profile {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    StaticRoutingInstance(String),
    Interface(String),
    /// A physical interface's tag-scoped L3 attachment point, navigated to
    /// by `edit interface <name>.<tag>` — see `split_subinterface`. Never
    /// reached for a loopback interface, which keeps its flat L3 config
    /// under plain `Path::Interface` navigation.
    Subinterface {
        interface: String,
        tag: u16,
    },
    PolicyDefinition(String),
    CommunityAlias(String),
    CommunityGroup(String),
    PrefixList(String),
    BroadcastDomain(String),
    SwitchingProfile(String),
    PortAggregate(String),
}

/// Splits `"eth0.100"` into `("eth0", 100)` when the suffix after the LAST
/// `.` parses as a valid subinterface tag (`0..=4094`); `None` otherwise, so
/// a loopback name or any interface name with no numeric dot-suffix parses
/// as a plain (non-dotted) interface reference. Mirrors
/// `nos_proto::schema::interface`'s own tag bound.
fn split_subinterface(name: &str) -> Option<(String, u16)> {
    let (base, suffix) = name.rsplit_once('.')?;
    let tag: u16 = suffix.parse().ok()?;
    (tag <= 4094).then(|| (base.to_string(), tag))
}

/// Builds the `ConfigOp` for adding/upserting an address on `name`: a
/// loopback interface keeps its flat `InterfaceOp::AddAddress`; a dotted
/// non-loopback name (`"eth0.100"`) targets that tag's subinterface; a bare
/// non-loopback name implicitly targets its tag-0 (untagged/native)
/// subinterface, preserving the pre-subinterface "just works" UX.
fn interface_add_address_op(name: &str, address: ipnet::IpNet, label: Option<String>) -> ConfigOp {
    if let Some((interface, tag)) = split_subinterface(name) {
        return ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
            interface,
            tag,
            address,
            label,
        });
    }
    match loopback_table_name(name) {
        Some(_) => ConfigOp::Interface(InterfaceOp::AddAddress {
            name: name.to_string(),
            address,
            label,
        }),
        None => ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
            interface: name.to_string(),
            tag: 0,
            address,
            label,
        }),
    }
}

fn interface_remove_address_op(name: &str, address: ipnet::IpNet) -> ConfigOp {
    if let Some((interface, tag)) = split_subinterface(name) {
        return ConfigOp::Subinterface(SubinterfaceOp::RemoveAddress {
            interface,
            tag,
            address,
        });
    }
    match loopback_table_name(name) {
        Some(_) => ConfigOp::Interface(InterfaceOp::RemoveAddress {
            name: name.to_string(),
            address,
        }),
        None => ConfigOp::Subinterface(SubinterfaceOp::RemoveAddress {
            interface: name.to_string(),
            tag: 0,
            address,
        }),
    }
}

fn interface_set_routing_table_op(name: &str, routing_table: String) -> ConfigOp {
    if let Some((interface, tag)) = split_subinterface(name) {
        return ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
            interface,
            tag,
            routing_table,
        });
    }
    match loopback_table_name(name) {
        Some(_) => ConfigOp::Interface(InterfaceOp::SetRoutingTable {
            name: name.to_string(),
            routing_table,
        }),
        None => ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
            interface: name.to_string(),
            tag: 0,
            routing_table,
        }),
    }
}

fn interface_clear_routing_table_op(name: &str) -> ConfigOp {
    if let Some((interface, tag)) = split_subinterface(name) {
        return ConfigOp::Subinterface(SubinterfaceOp::ClearRoutingTable { interface, tag });
    }
    match loopback_table_name(name) {
        Some(_) => ConfigOp::Interface(InterfaceOp::ClearRoutingTable {
            name: name.to_string(),
        }),
        None => ConfigOp::Subinterface(SubinterfaceOp::ClearRoutingTable {
            interface: name.to_string(),
            tag: 0,
        }),
    }
}

fn interface_set_ospf_profile_op(name: &str, ospf_profile: String) -> ConfigOp {
    if let Some((interface, tag)) = split_subinterface(name) {
        return ConfigOp::Subinterface(SubinterfaceOp::SetOspfProfile {
            interface,
            tag,
            ospf_profile,
        });
    }
    match loopback_table_name(name) {
        Some(_) => ConfigOp::Interface(InterfaceOp::SetOspfProfile {
            name: name.to_string(),
            ospf_profile,
        }),
        None => ConfigOp::Subinterface(SubinterfaceOp::SetOspfProfile {
            interface: name.to_string(),
            tag: 0,
            ospf_profile,
        }),
    }
}

fn interface_clear_ospf_profile_op(name: &str) -> ConfigOp {
    if let Some((interface, tag)) = split_subinterface(name) {
        return ConfigOp::Subinterface(SubinterfaceOp::ClearOspfProfile { interface, tag });
    }
    match loopback_table_name(name) {
        Some(_) => ConfigOp::Interface(InterfaceOp::ClearOspfProfile {
            name: name.to_string(),
        }),
        None => ConfigOp::Subinterface(SubinterfaceOp::ClearOspfProfile {
            interface: name.to_string(),
            tag: 0,
        }),
    }
}

/// Same shape as `interface_set_ospf_profile_op`, joining `OSPFv3` instead.
fn interface_set_ospfv3_profile_op(name: &str, ospfv3_profile: String) -> ConfigOp {
    if let Some((interface, tag)) = split_subinterface(name) {
        return ConfigOp::Subinterface(SubinterfaceOp::SetOspfv3Profile {
            interface,
            tag,
            ospfv3_profile,
        });
    }
    match loopback_table_name(name) {
        Some(_) => ConfigOp::Interface(InterfaceOp::SetOspfv3Profile {
            name: name.to_string(),
            ospfv3_profile,
        }),
        None => ConfigOp::Subinterface(SubinterfaceOp::SetOspfv3Profile {
            interface: name.to_string(),
            tag: 0,
            ospfv3_profile,
        }),
    }
}

fn interface_clear_ospfv3_profile_op(name: &str) -> ConfigOp {
    if let Some((interface, tag)) = split_subinterface(name) {
        return ConfigOp::Subinterface(SubinterfaceOp::ClearOspfv3Profile { interface, tag });
    }
    match loopback_table_name(name) {
        Some(_) => ConfigOp::Interface(InterfaceOp::ClearOspfv3Profile {
            name: name.to_string(),
        }),
        None => ConfigOp::Subinterface(SubinterfaceOp::ClearOspfv3Profile {
            interface: name.to_string(),
            tag: 0,
        }),
    }
}

/// The relative (`set address`, `set routing-table`, and their `delete`
/// counterparts) counterparts to the four `interface_*_op` builders above:
/// same ops, but targeting whichever L3 attachment point the path is
/// currently navigated into rather than a name given on the command line.
fn l3_add_address_op(
    target: L3Target<'_>,
    address: ipnet::IpNet,
    label: Option<String>,
) -> ConfigOp {
    match target {
        L3Target::Interface(name) => interface_add_address_op(name, address, label),
        L3Target::Subinterface { interface, tag } => {
            ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
                interface: interface.to_string(),
                tag,
                address,
                label,
            })
        }
        L3Target::BroadcastDomain(name) => {
            ConfigOp::BroadcastDomain(BroadcastDomainOp::AddAddress {
                name: name.to_string(),
                address,
                label,
            })
        }
    }
}

fn l3_remove_address_op(target: L3Target<'_>, address: ipnet::IpNet) -> ConfigOp {
    match target {
        L3Target::Interface(name) => interface_remove_address_op(name, address),
        L3Target::Subinterface { interface, tag } => {
            ConfigOp::Subinterface(SubinterfaceOp::RemoveAddress {
                interface: interface.to_string(),
                tag,
                address,
            })
        }
        L3Target::BroadcastDomain(name) => {
            ConfigOp::BroadcastDomain(BroadcastDomainOp::RemoveAddress {
                name: name.to_string(),
                address,
            })
        }
    }
}

fn l3_set_routing_table_op(target: L3Target<'_>, routing_table: String) -> ConfigOp {
    match target {
        L3Target::Interface(name) => interface_set_routing_table_op(name, routing_table),
        L3Target::Subinterface { interface, tag } => {
            ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
                interface: interface.to_string(),
                tag,
                routing_table,
            })
        }
        L3Target::BroadcastDomain(name) => {
            ConfigOp::BroadcastDomain(BroadcastDomainOp::SetRoutingTable {
                name: name.to_string(),
                routing_table,
            })
        }
    }
}

fn l3_clear_routing_table_op(target: L3Target<'_>) -> ConfigOp {
    match target {
        L3Target::Interface(name) => interface_clear_routing_table_op(name),
        L3Target::Subinterface { interface, tag } => {
            ConfigOp::Subinterface(SubinterfaceOp::ClearRoutingTable {
                interface: interface.to_string(),
                tag,
            })
        }
        L3Target::BroadcastDomain(name) => {
            ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearRoutingTable {
                name: name.to_string(),
            })
        }
    }
}

fn l3_set_ospf_profile_op(target: L3Target<'_>, ospf_profile: String) -> ConfigOp {
    match target {
        L3Target::Interface(name) => interface_set_ospf_profile_op(name, ospf_profile),
        L3Target::Subinterface { interface, tag } => {
            ConfigOp::Subinterface(SubinterfaceOp::SetOspfProfile {
                interface: interface.to_string(),
                tag,
                ospf_profile,
            })
        }
        L3Target::BroadcastDomain(name) => {
            ConfigOp::BroadcastDomain(BroadcastDomainOp::SetOspfProfile {
                name: name.to_string(),
                ospf_profile,
            })
        }
    }
}

fn l3_clear_ospf_profile_op(target: L3Target<'_>) -> ConfigOp {
    match target {
        L3Target::Interface(name) => interface_clear_ospf_profile_op(name),
        L3Target::Subinterface { interface, tag } => {
            ConfigOp::Subinterface(SubinterfaceOp::ClearOspfProfile {
                interface: interface.to_string(),
                tag,
            })
        }
        L3Target::BroadcastDomain(name) => {
            ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearOspfProfile {
                name: name.to_string(),
            })
        }
    }
}

/// Same shape as `l3_set_ospf_profile_op`, joining `OSPFv3` instead.
fn l3_set_ospfv3_profile_op(target: L3Target<'_>, ospfv3_profile: String) -> ConfigOp {
    match target {
        L3Target::Interface(name) => interface_set_ospfv3_profile_op(name, ospfv3_profile),
        L3Target::Subinterface { interface, tag } => {
            ConfigOp::Subinterface(SubinterfaceOp::SetOspfv3Profile {
                interface: interface.to_string(),
                tag,
                ospfv3_profile,
            })
        }
        L3Target::BroadcastDomain(name) => {
            ConfigOp::BroadcastDomain(BroadcastDomainOp::SetOspfv3Profile {
                name: name.to_string(),
                ospfv3_profile,
            })
        }
    }
}

fn l3_clear_ospfv3_profile_op(target: L3Target<'_>) -> ConfigOp {
    match target {
        L3Target::Interface(name) => interface_clear_ospfv3_profile_op(name),
        L3Target::Subinterface { interface, tag } => {
            ConfigOp::Subinterface(SubinterfaceOp::ClearOspfv3Profile {
                interface: interface.to_string(),
                tag,
            })
        }
        L3Target::BroadcastDomain(name) => {
            ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearOspfv3Profile {
                name: name.to_string(),
            })
        }
    }
}

/// Builds the `ConfigOp` (and its `Path`/error) for `edit interface <name>`:
/// a dotted non-loopback name ensures the subinterface (cascading its
/// parent interface); a bare name ensures the physical interface, unchanged.
fn interface_ensure_op_and_path(name: String) -> (ConfigOp, Path) {
    match split_subinterface(&name) {
        Some((interface, tag)) => (
            ConfigOp::Subinterface(SubinterfaceOp::Ensure {
                interface: interface.clone(),
                tag,
            }),
            Path::Subinterface { interface, tag },
        ),
        None => (
            ConfigOp::Interface(InterfaceOp::Ensure { name: name.clone() }),
            Path::Interface(name),
        ),
    }
}

/// Builds the `ConfigOp` for `delete interface <name>`: a dotted name
/// deletes just that subinterface; a bare name deletes the whole interface.
fn interface_delete_op(name: String) -> ConfigOp {
    match split_subinterface(&name) {
        Some((interface, tag)) => ConfigOp::Subinterface(SubinterfaceOp::Delete { interface, tag }),
        None => ConfigOp::Interface(InterfaceOp::Delete { name }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Operational,
    Configuration {
        transaction: String,
        path: Path,
        dirty: bool,
    },
}

/// Where a path transition should land after a successful op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAfter {
    Stay,
    ToRoot,
    To(Path),
}

/// The concrete next step for the REPL to execute, computed from `Mode` and
/// a parsed `Command`.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved {
    Nothing,
    Help,
    /// Operational `exit`/`quit`/`end` — exit the whole shell.
    ExitShell,
    /// Configuration-mode `exit`/`quit`/`end` with uncommitted changes — the
    /// REPL must interactively ask commit/discard/leave-open.
    LeaveConfigPrompt,
    NavigateTop,
    /// Navigate to a specific path with no op applied — used by `up` from a
    /// peer-group, which lands one level up (its owning instance) rather
    /// than at the root, unlike `NavigateTop`.
    Navigate(Path),
    ShowRunningConfig,
    /// `show this` in configuration mode — fetch the transaction and render
    /// it at the current path.
    ShowTransaction,
    /// `show route <table>` (whole table) or `show route <table> <address>`
    /// (longest-prefix-match lookup) — data-plane, valid in any mode.
    ShowRoute {
        table: String,
        address: Option<IpAddr>,
    },
    /// `show fdb <domain>` — data-plane, valid in any mode.
    ShowFdb {
        domain: String,
    },
    /// `show interface` (every interface) or `show interface <name>` (one)
    /// — data-plane, valid in any mode.
    ShowInterface {
        name: Option<String>,
    },
    /// `show port-aggregate` (every aggregate) or `show port-aggregate
    /// <name>` (one) — data-plane, valid in any mode.
    ShowPortAggregate {
        name: Option<String>,
    },
    ShowLacp {
        name: Option<String>,
    },
    /// `show lldp neighbors` — data-plane, valid in any mode.
    ShowLldpNeighbors,
    /// `show log [<source>] [--follow]` — data-plane, valid in any mode.
    ShowLog {
        source: Option<String>,
        follow: bool,
    },
    /// `show bgp brief` — data-plane, valid in any mode. Router-wide (no
    /// instance argument): the caller iterates every `BgpInstance` in the
    /// running config itself.
    ShowBgpBrief,
    /// `show bgp evpn` — data-plane, valid in any mode. Router-wide like
    /// `ShowBgpBrief`.
    ShowBgpEvpn,
    /// `show ospf neigh` — data-plane, valid in any mode. Router-wide (no
    /// instance argument), mirroring `ShowBgpBrief`: the caller iterates
    /// every `OspfInstance` in the running config itself.
    ShowOspfNeigh,
    /// `show ospf database` — data-plane, valid in any mode. Router-wide (no
    /// instance argument), mirroring `ShowOspfNeigh`.
    ShowOspfDatabase,
    /// `show ospfv3 neigh` — mirrors `ShowOspfNeigh`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Neigh,
    /// `show ospfv3 database` — mirrors `ShowOspfDatabase`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Database,
    /// `clear bgp <instance> <peer> soft-in` — data-plane action, valid in
    /// any mode.
    ClearBgpSoftIn {
        instance: String,
        peer: IpAddr,
    },
    SaveRunningConfig,
    OpenTransaction {
        name: String,
        base: TransactionBase,
        explicit_base: bool,
    },
    ApplyOp {
        op: ConfigOp,
        after: PathAfter,
    },
    Commit,
    Discard,
    /// `diff` — fetch and render the transaction's diff against running.
    Diff,
    /// `edit source` — only valid navigated into a policy-definition. Fetches
    /// the transaction, opens an external editor on the current source,
    /// compiles the result client-side, and (on success) stages `SetSource`
    /// — see root `CLAUDE.md`'s "nos-cli editing UX".
    EditPolicySource {
        name: String,
    },
    /// `show source` — only valid navigated into a policy-definition.
    ShowPolicySource {
        name: String,
    },
    /// `set source line <n> <text>` — only valid navigated into a
    /// policy-definition.
    SetPolicySourceLine {
        name: String,
        line: usize,
        text: String,
    },
    /// `delete source line <n>` — only valid navigated into a
    /// policy-definition.
    DeletePolicySourceLine {
        name: String,
        line: usize,
    },
    Error(String),
}

pub fn resolve(mode: &Mode, cmd: Command) -> Resolved {
    match cmd {
        Command::Empty => Resolved::Nothing,
        Command::Help => Resolved::Help,
        Command::ShowConfig => Resolved::ShowRunningConfig,
        Command::ShowRoute { table, address } => Resolved::ShowRoute { table, address },
        Command::ShowFdb { domain } => Resolved::ShowFdb { domain },
        Command::ShowInterface { name } => Resolved::ShowInterface { name },
        Command::ShowPortAggregate { name } => Resolved::ShowPortAggregate { name },
        Command::ShowLacp { name } => Resolved::ShowLacp { name },
        Command::ShowLldpNeighbors => Resolved::ShowLldpNeighbors,
        Command::ShowLog { source, follow } => Resolved::ShowLog { source, follow },
        Command::ShowBgpBrief => Resolved::ShowBgpBrief,
        Command::ShowBgpEvpn => Resolved::ShowBgpEvpn,
        Command::ShowOspfNeigh => Resolved::ShowOspfNeigh,
        Command::ShowOspfDatabase => Resolved::ShowOspfDatabase,
        Command::ShowOspfv3Neigh => Resolved::ShowOspfv3Neigh,
        Command::ShowOspfv3Database => Resolved::ShowOspfv3Database,
        Command::ClearBgpSoftIn { instance, peer } => Resolved::ClearBgpSoftIn { instance, peer },
        Command::Unknown(s) => {
            Resolved::Error(format!("unknown command: '{s}' (type 'help' for a list)"))
        }

        Command::Exit => match mode {
            Mode::Operational => Resolved::ExitShell,
            Mode::Configuration { .. } => Resolved::LeaveConfigPrompt,
        },

        Command::Save => match mode {
            Mode::Operational => Resolved::SaveRunningConfig,
            Mode::Configuration { .. } => Resolved::Error(
                "'save' persists the running config; commit first, or run it after leaving configuration mode".to_string(),
            ),
        },

        Command::Configure { name, base } => resolve_configure(mode, name, base),

        // Everything else only makes sense once a transaction is open.
        other => match mode {
            Mode::Operational => not_configuring(&other),
            Mode::Configuration { path, .. } => resolve_in_transaction(path, other),
        },
    }
}

fn resolve_configure(mode: &Mode, name: String, base: Option<TransactionBase>) -> Resolved {
    match mode {
        Mode::Operational => Resolved::OpenTransaction {
            name,
            base: base.unwrap_or(TransactionBase::Current),
            explicit_base: base.is_some(),
        },
        Mode::Configuration { transaction, .. } => Resolved::Error(format!(
            "already editing transaction '{transaction}' — use 'top' or 'exit' first"
        )),
    }
}

/// The error for a command that requires configuration mode, issued while
/// still `Operational`. `Commit`/`Discard` get a more specific message.
fn not_configuring(cmd: &Command) -> Resolved {
    let msg = match cmd {
        Command::Commit => "not in configuration mode — nothing to commit",
        Command::Discard => "not in configuration mode — nothing to discard",
        _ => "not in configuration mode — use 'configure <name>' first",
    };
    Resolved::Error(msg.to_string())
}

const NO_CURRENT_INSTANCE: &str = "no current instance — use 'edit bgp instance <name>' or the fully-qualified 'set bgp instance <name> ...' form";
const NO_CURRENT_POLICY_DEFINITION: &str =
    "no current policy-definition — use 'edit policy-definition <name>' first";
const NO_CURRENT_PEER_GROUP: &str =
    "no current peer-group — use 'edit peer-group <name>' or the fully-qualified 'set bgp instance <name> peer-group <group> ...' form";
const NO_CURRENT_ROUTING_TABLE: &str = "no current routing table — use 'edit routing-table <name>' or the fully-qualified 'set routing-table <name> ...' form";
const NO_CURRENT_STATIC_ROUTING_INSTANCE: &str = "no current static routing instance — use 'edit static-routing-instance <name>' or the fully-qualified 'set static-routing-instance <name> ...' form";
const NO_CURRENT_INTERFACE: &str = "no current interface — use 'edit interface <name>' or the fully-qualified 'set interface <name> ...' form";
const NO_CURRENT_COMMUNITY_ALIAS: &str = "no current community-alias — use 'edit community-alias <name>' or the fully-qualified 'set community-alias <name> ...' form";
const NO_CURRENT_COMMUNITY_GROUP: &str = "no current community-group — use 'edit community-group <name>' or the fully-qualified 'set community-group <name> ...' form";
const NO_CURRENT_PREFIX_LIST: &str = "no current prefix-list — use 'edit prefix-list <name>' or the fully-qualified 'set prefix-list <name> ...' form";
const NO_CURRENT_SWITCHING_PROFILE: &str = "no current switching-profile — use 'edit switching-profile <name>' or the fully-qualified 'set switching-profile <name> ...' form";
const NO_CURRENT_PORT_AGGREGATE: &str = "no current port-aggregate — use 'edit port-aggregate <name>' or the fully-qualified 'set port-aggregate <name> ...' form";
const NO_CURRENT_OSPF_INSTANCE: &str = "no current ospf instance — use 'edit ospf instance <name>' or the fully-qualified 'set ospf instance <name> ...' form";
const NO_CURRENT_OSPF_AREA: &str = "no current ospf area — use 'edit ospf instance <name> area <area-id>' or 'edit area <area-id>' while navigated into an ospf instance";
const NO_CURRENT_OSPF_PROFILE: &str = "no current ospf profile — use 'edit ospf instance <name> area <area-id> profile <name>' or 'edit profile <name>' while navigated into an ospf area";
const NO_CURRENT_OSPFV3_INSTANCE: &str = "no current ospfv3 instance — use 'edit ospfv3 instance <name>' or the fully-qualified 'set ospfv3 instance <name> ...' form";
const NO_CURRENT_OSPFV3_AREA: &str = "no current ospfv3 area — use 'edit ospfv3 instance <name> area <area-id>' or 'edit area <area-id>' while navigated into an ospfv3 instance";
const NO_CURRENT_OSPFV3_PROFILE: &str = "no current ospfv3 profile — use 'edit ospfv3 instance <name> area <area-id> profile <name>' or 'edit profile <name>' while navigated into an ospfv3 area";
const NO_CURRENT_OSPF_OR_OSPFV3_INSTANCE: &str = "'area <area-id>' is only valid while navigated into an ospf instance or an ospfv3 instance — use the fully-qualified 'edit ospf instance <name> area <area-id>' or 'edit ospfv3 instance <name> area <area-id>' form";
const NO_CURRENT_OSPF_OR_OSPFV3_AREA: &str = "'profile <name>' is only valid while navigated into an ospf area or an ospfv3 area — use the fully-qualified 'edit ospf instance <name> area <area-id> profile <name>' or 'edit ospfv3 instance <name> area <area-id> profile <name>' form";
const NO_CURRENT_OSPF_OR_OSPFV3_PROFILE: &str =
    "this field is only valid while navigated into an ospf profile or an ospfv3 profile";
const NO_CURRENT_INTERFACE_OR_OSPF_PROFILE: &str = "'mtu' is only valid while navigated into an interface, an ospf profile, or an ospfv3 profile — use the fully-qualified 'set interface <name> mtu <n>', 'set ospf instance <name> area <area-id> profile <name> mtu <n>', or 'set ospfv3 instance <name> area <area-id> profile <name> mtu <n>' form";
const ALREADY_AT_TOP: &str = "already at the top level";

/// The three L3 attachment points `set address` / `set routing-table` (and
/// their `delete` counterparts) accept relative to the current path. Each
/// maps to a different `ConfigOp` family, so unlike the single-name
/// accessors below this can't collapse to one `&str`.
#[derive(Clone, Copy)]
pub(crate) enum L3Target<'a> {
    Interface(&'a str),
    Subinterface { interface: &'a str, tag: u16 },
    BroadcastDomain(&'a str),
}

/// Accessors for "this command needs the current path to be an X".
///
/// Each returns, as its `Err`, the "you aren't navigated into an X" message —
/// so `resolve_table` can `?` on it and stay a flat one-arm-per-command table
/// instead of nesting a 13-variant `match path` inside every arm. The
/// wildcard arm is deliberate: a future `Path` variant genuinely is not a
/// peer-group/prefix-list/etc., and the one place that must stay exhaustive
/// over `Path` is `format::render_transaction`.
impl Path {
    pub(crate) fn bgp_instance(&self) -> Result<&str, &'static str> {
        match self {
            Path::BgpInstance(name) => Ok(name),
            _ => Err(NO_CURRENT_INSTANCE),
        }
    }

    pub(crate) fn peer_group(&self) -> Result<(&str, &str), &'static str> {
        match self {
            Path::BgpPeerGroup { instance, group } => Ok((instance, group)),
            _ => Err(NO_CURRENT_PEER_GROUP),
        }
    }

    pub(crate) fn routing_table(&self) -> Result<&str, &'static str> {
        match self {
            Path::RoutingTable(name) => Ok(name),
            _ => Err(NO_CURRENT_ROUTING_TABLE),
        }
    }

    pub(crate) fn static_routing_instance(&self) -> Result<&str, &'static str> {
        match self {
            Path::StaticRoutingInstance(name) => Ok(name),
            _ => Err(NO_CURRENT_STATIC_ROUTING_INSTANCE),
        }
    }

    /// The physical interface only — a subinterface has no switching profile
    /// of its own, so this deliberately does not accept `Path::Subinterface`.
    pub(crate) fn interface(&self) -> Result<&str, &'static str> {
        match self {
            Path::Interface(name) => Ok(name),
            _ => Err(NO_CURRENT_INTERFACE),
        }
    }

    fn policy_definition(&self) -> Result<&str, &'static str> {
        match self {
            Path::PolicyDefinition(name) => Ok(name),
            _ => Err(NO_CURRENT_POLICY_DEFINITION),
        }
    }

    fn community_alias(&self) -> Result<&str, &'static str> {
        match self {
            Path::CommunityAlias(name) => Ok(name),
            _ => Err(NO_CURRENT_COMMUNITY_ALIAS),
        }
    }

    fn community_group(&self) -> Result<&str, &'static str> {
        match self {
            Path::CommunityGroup(name) => Ok(name),
            _ => Err(NO_CURRENT_COMMUNITY_GROUP),
        }
    }

    fn prefix_list(&self) -> Result<&str, &'static str> {
        match self {
            Path::PrefixList(name) => Ok(name),
            _ => Err(NO_CURRENT_PREFIX_LIST),
        }
    }

    pub(crate) fn switching_profile(&self) -> Result<&str, &'static str> {
        match self {
            Path::SwitchingProfile(name) => Ok(name),
            _ => Err(NO_CURRENT_SWITCHING_PROFILE),
        }
    }

    pub(crate) fn port_aggregate(&self) -> Result<&str, &'static str> {
        match self {
            Path::PortAggregate(name) => Ok(name),
            _ => Err(NO_CURRENT_PORT_AGGREGATE),
        }
    }

    pub(crate) fn ospf_instance(&self) -> Result<&str, &'static str> {
        match self {
            Path::OspfInstance(name) => Ok(name),
            _ => Err(NO_CURRENT_OSPF_INSTANCE),
        }
    }

    pub(crate) fn ospf_area(&self) -> Result<(&str, Ipv4Addr), &'static str> {
        match self {
            Path::OspfArea { instance, area_id } => Ok((instance, *area_id)),
            _ => Err(NO_CURRENT_OSPF_AREA),
        }
    }

    pub(crate) fn ospf_profile(&self) -> Result<(&str, Ipv4Addr, &str), &'static str> {
        match self {
            Path::OspfProfile {
                instance,
                area_id,
                name,
            } => Ok((instance, *area_id, name)),
            _ => Err(NO_CURRENT_OSPF_PROFILE),
        }
    }

    pub(crate) fn ospfv3_instance(&self) -> Result<&str, &'static str> {
        match self {
            Path::Ospfv3Instance(name) => Ok(name),
            _ => Err(NO_CURRENT_OSPFV3_INSTANCE),
        }
    }

    pub(crate) fn ospfv3_area(&self) -> Result<(&str, Ipv4Addr), &'static str> {
        match self {
            Path::Ospfv3Area { instance, area_id } => Ok((instance, *area_id)),
            _ => Err(NO_CURRENT_OSPFV3_AREA),
        }
    }

    pub(crate) fn ospfv3_profile(&self) -> Result<(&str, Ipv4Addr, &str), &'static str> {
        match self {
            Path::Ospfv3Profile {
                instance,
                area_id,
                name,
            } => Ok((instance, *area_id, name)),
            _ => Err(NO_CURRENT_OSPFV3_PROFILE),
        }
    }

    pub(crate) fn l3_target(&self) -> Result<L3Target<'_>, &'static str> {
        match self {
            Path::Interface(name) => Ok(L3Target::Interface(name)),
            Path::Subinterface { interface, tag } => Ok(L3Target::Subinterface {
                interface,
                tag: *tag,
            }),
            Path::BroadcastDomain(name) => Ok(L3Target::BroadcastDomain(name)),
            _ => Err(NO_CURRENT_INTERFACE),
        }
    }
}

/// Resolves a command that requires configuration mode, given the current
/// navigation `path`. Never called with `Command::Configure`, `Empty`,
/// `Help`, `ShowConfig`, `Unknown`, `Exit`, or `Save` — `resolve` handles
/// those itself before delegating here.
fn resolve_in_transaction(path: &Path, cmd: Command) -> Resolved {
    resolve_table(path, cmd).unwrap_or_else(|err| Resolved::Error(err.to_string()))
}

/// The command table proper. `Err` is not a failure to resolve — it is the
/// message for a `Resolved::Error`, carried out-of-band purely so that every
/// "wrong navigation position" check can be one `?` (see `impl Path` above)
/// rather than a nested `match path`. `resolve_in_transaction` builds the
/// `Resolved::Error` from it at the boundary, so no arm here allocates one.
fn resolve_table(path: &Path, cmd: Command) -> Result<Resolved, &'static str> {
    Ok(match cmd {
        Command::Show => Resolved::ShowTransaction,

        Command::Edit(EditTarget::BgpInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpInstance(BgpInstanceOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::BgpInstance(name)),
        },
        Command::Edit(EditTarget::BgpPeerGroup { instance, name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Ensure {
                instance: instance.clone(),
                name: name.clone(),
            }),
            after: PathAfter::To(Path::BgpPeerGroup {
                instance,
                group: name,
            }),
        },
        Command::Edit(EditTarget::PeerGroupRelative { name }) => {
            let instance = path.bgp_instance()?;
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Ensure {
                    instance: instance.to_string(),
                    name: name.clone(),
                }),
                after: PathAfter::To(Path::BgpPeerGroup {
                    instance: instance.to_string(),
                    group: name,
                }),
            }
        }
        Command::Edit(EditTarget::RoutingTable { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::RoutingTable(name)),
        },
        Command::Edit(EditTarget::OspfInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::OspfInstance(OspfInstanceOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::OspfInstance(name)),
        },
        Command::Edit(EditTarget::OspfArea { instance, area_id }) => Resolved::ApplyOp {
            op: ConfigOp::OspfArea(OspfAreaOp::Ensure {
                instance: instance.clone(),
                area_id,
            }),
            after: PathAfter::To(Path::OspfArea { instance, area_id }),
        },
        // Shared, path-disambiguated token with `edit ospfv3 instance <name>
        // area <area-id>`'s own relative form — an `OspfArea`/`Ospfv3Area`
        // have no field enum of their own to carry two separate
        // `EditTarget` variants, mirroring `BgpInstanceField::RouterId`'s
        // precedent.
        Command::Edit(EditTarget::OspfAreaRelative { area_id }) => match path {
            Path::OspfInstance(instance) => {
                let instance = instance.clone();
                Resolved::ApplyOp {
                    op: ConfigOp::OspfArea(OspfAreaOp::Ensure {
                        instance: instance.clone(),
                        area_id,
                    }),
                    after: PathAfter::To(Path::OspfArea { instance, area_id }),
                }
            }
            Path::Ospfv3Instance(instance) => {
                let instance = instance.clone();
                Resolved::ApplyOp {
                    op: ConfigOp::Ospfv3Area(Ospfv3AreaOp::Ensure {
                        instance: instance.clone(),
                        area_id,
                    }),
                    after: PathAfter::To(Path::Ospfv3Area { instance, area_id }),
                }
            }
            _ => return Err(NO_CURRENT_OSPF_OR_OSPFV3_INSTANCE),
        },
        Command::Edit(EditTarget::OspfProfile {
            instance,
            area_id,
            name,
        }) => Resolved::ApplyOp {
            op: ConfigOp::OspfProfile(OspfProfileOp::Ensure {
                instance: instance.clone(),
                area_id,
                name: name.clone(),
            }),
            after: PathAfter::To(Path::OspfProfile {
                instance,
                area_id,
                name,
            }),
        },
        // Shared, path-disambiguated token — see `OspfAreaRelative`'s doc
        // comment above.
        Command::Edit(EditTarget::OspfProfileRelative { name }) => match path {
            Path::OspfArea { instance, area_id } => {
                let instance = instance.clone();
                let area_id = *area_id;
                Resolved::ApplyOp {
                    op: ConfigOp::OspfProfile(OspfProfileOp::Ensure {
                        instance: instance.clone(),
                        area_id,
                        name: name.clone(),
                    }),
                    after: PathAfter::To(Path::OspfProfile {
                        instance,
                        area_id,
                        name,
                    }),
                }
            }
            Path::Ospfv3Area { instance, area_id } => {
                let instance = instance.clone();
                let area_id = *area_id;
                Resolved::ApplyOp {
                    op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::Ensure {
                        instance: instance.clone(),
                        area_id,
                        name: name.clone(),
                    }),
                    after: PathAfter::To(Path::Ospfv3Profile {
                        instance,
                        area_id,
                        name,
                    }),
                }
            }
            _ => return Err(NO_CURRENT_OSPF_OR_OSPFV3_AREA),
        },
        Command::Edit(EditTarget::Ospfv3Instance { name }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::Ospfv3Instance(name)),
        },
        Command::Edit(EditTarget::Ospfv3Area { instance, area_id }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Area(Ospfv3AreaOp::Ensure {
                instance: instance.clone(),
                area_id,
            }),
            after: PathAfter::To(Path::Ospfv3Area { instance, area_id }),
        },
        Command::Edit(EditTarget::Ospfv3Profile {
            instance,
            area_id,
            name,
        }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::Ensure {
                instance: instance.clone(),
                area_id,
                name: name.clone(),
            }),
            after: PathAfter::To(Path::Ospfv3Profile {
                instance,
                area_id,
                name,
            }),
        },
        Command::Edit(EditTarget::StaticRoutingInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Ensure {
                name: name.clone(),
            }),
            after: PathAfter::To(Path::StaticRoutingInstance(name)),
        },
        Command::Edit(EditTarget::Interface { name }) => {
            let (op, path) = interface_ensure_op_and_path(name);
            Resolved::ApplyOp {
                op,
                after: PathAfter::To(path),
            }
        }
        Command::Edit(EditTarget::PolicyDefinition { name }) => Resolved::ApplyOp {
            op: ConfigOp::PolicyDefinition(PolicyDefinitionOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::PolicyDefinition(name)),
        },
        Command::Edit(EditTarget::CommunityAlias { name }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityAlias(CommunityAliasOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::CommunityAlias(name)),
        },
        Command::Edit(EditTarget::CommunityGroup { name }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityGroup(CommunityGroupOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::CommunityGroup(name)),
        },
        Command::Edit(EditTarget::PrefixList { name }) => Resolved::ApplyOp {
            op: ConfigOp::PrefixList(PrefixListOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::PrefixList(name)),
        },
        Command::Edit(EditTarget::BroadcastDomain { name }) => Resolved::ApplyOp {
            op: ConfigOp::BroadcastDomain(BroadcastDomainOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::BroadcastDomain(name)),
        },
        Command::Edit(EditTarget::SwitchingProfile { name }) => Resolved::ApplyOp {
            op: ConfigOp::SwitchingProfile(SwitchingProfileOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::SwitchingProfile(name)),
        },
        Command::Edit(EditTarget::PortAggregate { name }) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::Ensure {
                name: name.clone(),
                mode: nos_proto::PortAggregateMode::Xor,
            }),
            after: PathAfter::To(Path::PortAggregate(name)),
        },
        Command::EditSource => Resolved::EditPolicySource {
            name: path.policy_definition()?.to_string(),
        },
        Command::ShowSource => Resolved::ShowPolicySource {
            name: path.policy_definition()?.to_string(),
        },
        Command::SetSourceLine { line, text } => Resolved::SetPolicySourceLine {
            name: path.policy_definition()?.to_string(),
            line,
            text,
        },
        Command::DeleteSourceLine { line } => Resolved::DeletePolicySourceLine {
            name: path.policy_definition()?.to_string(),
            line,
        },

        Command::Set(SetTarget::BgpInstance { name, field }) => Resolved::ApplyOp {
            op: set_op(name, field),
            after: PathAfter::Stay,
        },
        // No navigation context to check — hostname is a top-level scalar,
        // valid from anywhere in configuration mode.
        Command::Set(SetTarget::Hostname(name)) => Resolved::ApplyOp {
            op: ConfigOp::SetHostname(name),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::UserPassword { name, password }) => Resolved::ApplyOp {
            op: ConfigOp::User(UserOp::SetPassword { name, password }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::User { name }) => Resolved::ApplyOp {
            op: ConfigOp::User(UserOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::Relative { field }) => match path {
            Path::BgpInstance(name) => Resolved::ApplyOp {
                op: set_op(name.clone(), field),
                after: PathAfter::Stay,
            },
            // `set router-id <ip>`'s literal token sequence is already
            // claimed by `BgpInstanceField::RouterId` at parse time (see its
            // doc comment) — an `OspfInstance` has no field enum of its own,
            // so this is where the shared relative command is retargeted by
            // `path` instead. Any other `BgpInstanceField` variant has no
            // meaning on an OSPF instance.
            Path::OspfInstance(name) => match field {
                BgpInstanceField::RouterId(router_id) => Resolved::ApplyOp {
                    op: ConfigOp::OspfInstance(OspfInstanceOp::SetRouterId {
                        name: name.clone(),
                        router_id,
                    }),
                    after: PathAfter::Stay,
                },
                BgpInstanceField::Asn(_) | BgpInstanceField::ClusterId(_) => Resolved::Error(
                    "only 'set router-id <ip>' is valid on an ospf instance".to_string(),
                ),
            },
            // Same sharing, for an `Ospfv3Instance`.
            Path::Ospfv3Instance(name) => match field {
                BgpInstanceField::RouterId(router_id) => Resolved::ApplyOp {
                    op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::SetRouterId {
                        name: name.clone(),
                        router_id,
                    }),
                    after: PathAfter::Stay,
                },
                BgpInstanceField::Asn(_) | BgpInstanceField::ClusterId(_) => Resolved::Error(
                    "only 'set router-id <ip>' is valid on an ospfv3 instance".to_string(),
                ),
            },
            _ => return Err(NO_CURRENT_INSTANCE),
        },
        Command::Set(SetTarget::BgpPeerGroup {
            instance,
            group,
            field,
        }) => Resolved::ApplyOp {
            op: peer_group_set_op(instance, group, field),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PeerGroupRelative { field }) => {
            let (instance, group) = path.peer_group()?;
            Resolved::ApplyOp {
                op: peer_group_set_op(instance.to_string(), group.to_string(), field),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::OspfProfile {
            instance,
            area_id,
            name,
            field,
        }) => Resolved::ApplyOp {
            op: ospf_profile_set_op(instance, area_id, name, field),
            after: PathAfter::Stay,
        },
        // Shared, path-disambiguated token with `Ospfv3Profile`'s own
        // relative fields — mirrors `OspfAreaRelative`'s precedent.
        // `OspfProfileField::SimplePassword`/`CryptoKey`/`CryptoCurrentKey`
        // have no `Ospfv3Profile` equivalent (no auth in this NOS build).
        Command::Set(SetTarget::OspfProfileRelative { field }) => match path {
            Path::OspfProfile {
                instance,
                area_id,
                name,
            } => Resolved::ApplyOp {
                op: ospf_profile_set_op(instance.clone(), *area_id, name.clone(), field),
                after: PathAfter::Stay,
            },
            Path::Ospfv3Profile {
                instance,
                area_id,
                name,
            } => match ospfv3_profile_set_op(instance.clone(), *area_id, name.clone(), &field) {
                Ok(op) => Resolved::ApplyOp {
                    op,
                    after: PathAfter::Stay,
                },
                Err(msg) => Resolved::Error(msg),
            },
            _ => return Err(NO_CURRENT_OSPF_OR_OSPFV3_PROFILE),
        },
        Command::Set(SetTarget::Ospfv3InstanceExtendedLsa { name }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::SetExtendedLsa {
                name,
                enabled: true,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::Ospfv3Instance { name, router_id }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::SetRouterId { name, router_id }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::Ospfv3Profile {
            instance,
            area_id,
            name,
            field,
        }) => match ospfv3_profile_set_op(instance, area_id, name, &field) {
            Ok(op) => Resolved::ApplyOp {
                op,
                after: PathAfter::Stay,
            },
            Err(msg) => Resolved::Error(msg),
        },
        Command::Set(SetTarget::BgpPeer {
            instance,
            remote_address,
            peer_group,
        }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeer(BgpPeerOp::Set {
                instance,
                remote_address,
                peer_group,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PeerRelative {
            remote_address,
            peer_group,
        }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeer(BgpPeerOp::Set {
                instance: path.bgp_instance()?.to_string(),
                remote_address,
                peer_group,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::BgpPeerShutdown {
            instance,
            remote_address,
            message,
        }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeer(BgpPeerOp::SetShutdown {
                instance,
                remote_address,
                message,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PeerShutdownRelative {
            remote_address,
            message,
        }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeer(BgpPeerOp::SetShutdown {
                instance: path.bgp_instance()?.to_string(),
                remote_address,
                message,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTable { name, bgp_instance }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance { name, bgp_instance }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableRelative { bgp_instance }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance {
                name: path.routing_table()?.to_string(),
                bgp_instance,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableStaticRoutingInstance {
            name,
            static_routing_instance,
        }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::SetStaticRoutingInstance {
                name,
                static_routing_instance,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableStaticRoutingInstanceRelative {
            static_routing_instance,
        }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::SetStaticRoutingInstance {
                name: path.routing_table()?.to_string(),
                static_routing_instance,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableOspfInstance {
            name,
            ospf_instance,
        }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::SetOspfInstance {
                name,
                ospf_instance,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableOspfInstanceRelative { ospf_instance }) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetOspfInstance {
                    name: path.routing_table()?.to_string(),
                    ospf_instance,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::RoutingTableOspfv3Instance {
            name,
            ospfv3_instance,
        }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::SetOspfv3Instance {
                name,
                ospfv3_instance,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableOspfv3InstanceRelative { ospfv3_instance }) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetOspfv3Instance {
                    name: path.routing_table()?.to_string(),
                    ospfv3_instance,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::RoutingTableRestApi {
            name,
            address,
            port,
        }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::SetRestApi {
                name,
                address,
                port,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableRestApiRelative { address, port }) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetRestApi {
                    name: path.routing_table()?.to_string(),
                    address,
                    port,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::OspfInstance { name, router_id }) => Resolved::ApplyOp {
            op: ConfigOp::OspfInstance(OspfInstanceOp::SetRouterId { name, router_id }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableRedistribute { name, redistribute }) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute { name, redistribute }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::RoutingTableRedistributeRelative { redistribute }) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
                    name: path.routing_table()?.to_string(),
                    redistribute,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::StaticRoute {
            instance,
            subnet,
            gateway,
        }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoute(StaticRouteOp::Set {
                instance,
                subnet,
                gateway,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::StaticRouteRelative { subnet, gateway }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoute(StaticRouteOp::Set {
                instance: path.static_routing_instance()?.to_string(),
                subnet,
                gateway,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceAddress {
            name,
            address,
            label,
        }) => Resolved::ApplyOp {
            op: interface_add_address_op(&name, address, label),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceAddressRelative { address, label }) => Resolved::ApplyOp {
            op: l3_add_address_op(path.l3_target()?, address, label),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceRoutingTable {
            name,
            routing_table,
        }) => Resolved::ApplyOp {
            op: interface_set_routing_table_op(&name, routing_table),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceRoutingTableRelative { routing_table }) => {
            Resolved::ApplyOp {
                op: l3_set_routing_table_op(path.l3_target()?, routing_table),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::InterfaceOspfProfile { name, ospf_profile }) => Resolved::ApplyOp {
            op: interface_set_ospf_profile_op(&name, ospf_profile),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceOspfProfileRelative { ospf_profile }) => {
            Resolved::ApplyOp {
                op: l3_set_ospf_profile_op(path.l3_target()?, ospf_profile),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::BroadcastDomainAddress {
            name,
            address,
            label,
        }) => Resolved::ApplyOp {
            op: ConfigOp::BroadcastDomain(BroadcastDomainOp::AddAddress {
                name,
                address,
                label,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::BroadcastDomainRoutingTable {
            name,
            routing_table,
        }) => Resolved::ApplyOp {
            op: ConfigOp::BroadcastDomain(BroadcastDomainOp::SetRoutingTable {
                name,
                routing_table,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::BroadcastDomainEvpn(op))
        | Command::Delete(DeleteTarget::BroadcastDomainEvpn(op)) => Resolved::ApplyOp {
            op: ConfigOp::BroadcastDomain(op),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PortAggregateField(op))
        | Command::Delete(DeleteTarget::PortAggregateField(op)) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(op),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceSwitchingProfile {
            name,
            switching_profile,
        }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::SetSwitchingProfile {
                name,
                switching_profile,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceSwitchingProfileRelative { switching_profile }) => {
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetSwitchingProfile {
                    name: path.interface()?.to_string(),
                    switching_profile,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::InterfaceLldp { name, direction }) => Resolved::ApplyOp {
            op: lldp_op(name, direction, true),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceLldpRelative { direction }) => Resolved::ApplyOp {
            op: lldp_op(path.interface()?.to_string(), direction, true),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceLldpDestination { name, destination }) => {
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetLldpDestination { name, destination }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::InterfaceLldpDestinationRelative { destination }) => {
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetLldpDestination {
                    name: path.interface()?.to_string(),
                    destination,
                }),
                after: PathAfter::Stay,
            }
        }
        // System-wide, like hostname: no navigation context to check.
        Command::Set(SetTarget::Lldp(setting)) => Resolved::ApplyOp {
            op: ConfigOp::Lldp(match setting {
                LldpSetting::TxInterval(secs) => LldpOp::SetTxInterval { secs },
                LldpSetting::TxHold(hold) => LldpOp::SetTxHold { hold },
                LldpSetting::ManagementAddress(address) => LldpOp::SetManagementAddress { address },
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceMtu { name, mtu }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::SetMtu { name, mtu }),
            after: PathAfter::Stay,
        },
        // `set mtu <n>`'s literal token sequence is shared between a
        // physical interface's own mtu and an `OspfProfile`'s mtu override —
        // see `SetTarget::MtuRelative`'s doc comment.
        Command::Set(SetTarget::MtuRelative(mtu)) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetMtu {
                    name: name.clone(),
                    mtu: u32::from(mtu),
                }),
                after: PathAfter::Stay,
            },
            Path::OspfProfile {
                instance,
                area_id,
                name,
            } => Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetMtu {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name: name.clone(),
                    mtu,
                }),
                after: PathAfter::Stay,
            },
            Path::Ospfv3Profile {
                instance,
                area_id,
                name,
            } => Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetMtu {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name: name.clone(),
                    mtu,
                }),
                after: PathAfter::Stay,
            },
            _ => return Err(NO_CURRENT_INTERFACE_OR_OSPF_PROFILE),
        },

        Command::Set(SetTarget::InterfaceOspfv3Profile {
            name,
            ospfv3_profile,
        }) => Resolved::ApplyOp {
            op: interface_set_ospfv3_profile_op(&name, ospfv3_profile),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceOspfv3ProfileRelative { ospfv3_profile }) => {
            Resolved::ApplyOp {
                op: l3_set_ospfv3_profile_op(path.l3_target()?, ospfv3_profile),
                after: PathAfter::Stay,
            }
        }

        Command::Set(SetTarget::CommunityAliasValue { name, value }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityAlias(CommunityAliasOp::SetValue { name, value }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::CommunityAliasValueRelative { value }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityAlias(CommunityAliasOp::SetValue {
                name: path.community_alias()?.to_string(),
                value,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::CommunityGroupMember { name, member }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityGroup(CommunityGroupOp::AddMember { name, member }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::CommunityGroupMemberRelative { member }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityGroup(CommunityGroupOp::AddMember {
                name: path.community_group()?.to_string(),
                member,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PrefixListEntry { name, cidr, range }) => Resolved::ApplyOp {
            op: ConfigOp::PrefixList(PrefixListOp::AddEntry {
                name,
                entry: PrefixListEntry { cidr, range },
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PrefixListEntryRelative { cidr, range }) => Resolved::ApplyOp {
            op: ConfigOp::PrefixList(PrefixListOp::AddEntry {
                name: path.prefix_list()?.to_string(),
                entry: PrefixListEntry { cidr, range },
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::SwitchingProfileMember {
            name,
            broadcast_domain,
            tag,
        }) => Resolved::ApplyOp {
            op: ConfigOp::SwitchingProfile(SwitchingProfileOp::AddMember {
                name,
                broadcast_domain,
                tag,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::SwitchingProfileMemberRelative {
            broadcast_domain,
            tag,
        }) => Resolved::ApplyOp {
            op: ConfigOp::SwitchingProfile(SwitchingProfileOp::AddMember {
                name: path.switching_profile()?.to_string(),
                broadcast_domain,
                tag,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PortAggregateMode { name, mode }) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::SetMode { name, mode }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PortAggregateModeRelative { mode }) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::SetMode {
                name: path.port_aggregate()?.to_string(),
                mode,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PortAggregateLacpRate { name, rate }) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::SetLacpRate { name, rate }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PortAggregateLacpRateRelative { rate }) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::SetLacpRate {
                name: path.port_aggregate()?.to_string(),
                rate,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PortAggregateRedundancyMode { name, mode }) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::SetRedundancyMode { name, mode }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PortAggregateRedundancyModeRelative { mode }) => {
            Resolved::ApplyOp {
                op: ConfigOp::PortAggregate(PortAggregateOp::SetRedundancyMode {
                    name: path.port_aggregate()?.to_string(),
                    mode,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::PortAggregateEsiRelative { esi }) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::SetEsi {
                name: path.port_aggregate()?.to_string(),
                esi,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PortAggregateLacpSystemIdRelative { system_id }) => {
            Resolved::ApplyOp {
                op: ConfigOp::PortAggregate(PortAggregateOp::SetLacpSystemId {
                    name: path.port_aggregate()?.to_string(),
                    system_id,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::PortAggregateEsiRelative) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::ClearEsi {
                name: path.port_aggregate()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::PortAggregateLacpSystemIdRelative) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::ClearLacpSystemId {
                name: path.port_aggregate()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfacePortAggregate {
            name,
            port_aggregate,
        }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::SetPortAggregate {
                name,
                port_aggregate,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfacePortAggregateRelative { port_aggregate }) => {
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetPortAggregate {
                    name: path.interface()?.to_string(),
                    port_aggregate,
                }),
                after: PathAfter::Stay,
            }
        }

        Command::Delete(DeleteTarget::BgpInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpInstance(BgpInstanceOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::OspfInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::OspfInstance(OspfInstanceOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::OspfArea { instance, area_id }) => Resolved::ApplyOp {
            op: ConfigOp::OspfArea(OspfAreaOp::Delete { instance, area_id }),
            after: PathAfter::Stay,
        },
        // Shared, path-disambiguated token — mirrors the `Edit` side above.
        Command::Delete(DeleteTarget::OspfAreaRelative { area_id }) => match path {
            Path::OspfInstance(instance) => Resolved::ApplyOp {
                op: ConfigOp::OspfArea(OspfAreaOp::Delete {
                    instance: instance.clone(),
                    area_id,
                }),
                after: PathAfter::Stay,
            },
            Path::Ospfv3Instance(instance) => Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Area(Ospfv3AreaOp::Delete {
                    instance: instance.clone(),
                    area_id,
                }),
                after: PathAfter::Stay,
            },
            _ => return Err(NO_CURRENT_OSPF_OR_OSPFV3_INSTANCE),
        },
        Command::Delete(DeleteTarget::OspfProfile {
            instance,
            area_id,
            name,
        }) => Resolved::ApplyOp {
            op: ConfigOp::OspfProfile(OspfProfileOp::Delete {
                instance,
                area_id,
                name,
            }),
            after: PathAfter::Stay,
        },
        // Shared, path-disambiguated token — mirrors the `Edit` side above.
        Command::Delete(DeleteTarget::OspfProfileRelative { name }) => match path {
            Path::OspfArea { instance, area_id } => Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::Delete {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name,
                }),
                after: PathAfter::Stay,
            },
            Path::Ospfv3Area { instance, area_id } => Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::Delete {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name,
                }),
                after: PathAfter::Stay,
            },
            _ => return Err(NO_CURRENT_OSPF_OR_OSPFV3_AREA),
        },
        Command::Delete(DeleteTarget::Ospfv3InstanceExtendedLsa { name }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::SetExtendedLsa {
                name,
                enabled: false,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::Ospfv3Instance { name }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::Ospfv3Area { instance, area_id }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Area(Ospfv3AreaOp::Delete { instance, area_id }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::Ospfv3Profile {
            instance,
            area_id,
            name,
        }) => Resolved::ApplyOp {
            op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::Delete {
                instance,
                area_id,
                name,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::Current) => match path {
            Path::BgpInstance(name) => Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Delete {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::To(Path::BgpInstance(instance.clone())),
            },
            Path::RoutingTable(name) => Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::OspfInstance(name) => Resolved::ApplyOp {
                op: ConfigOp::OspfInstance(OspfInstanceOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::OspfArea { instance, area_id } => Resolved::ApplyOp {
                op: ConfigOp::OspfArea(OspfAreaOp::Delete {
                    instance: instance.clone(),
                    area_id: *area_id,
                }),
                after: PathAfter::To(Path::OspfInstance(instance.clone())),
            },
            Path::OspfProfile {
                instance,
                area_id,
                name,
            } => Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::Delete {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name: name.clone(),
                }),
                after: PathAfter::To(Path::OspfArea {
                    instance: instance.clone(),
                    area_id: *area_id,
                }),
            },
            Path::Ospfv3Instance(name) => Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::Ospfv3Area { instance, area_id } => Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Area(Ospfv3AreaOp::Delete {
                    instance: instance.clone(),
                    area_id: *area_id,
                }),
                after: PathAfter::To(Path::Ospfv3Instance(instance.clone())),
            },
            Path::Ospfv3Profile {
                instance,
                area_id,
                name,
            } => Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::Delete {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name: name.clone(),
                }),
                after: PathAfter::To(Path::Ospfv3Area {
                    instance: instance.clone(),
                    area_id: *area_id,
                }),
            },
            Path::StaticRoutingInstance(name) => Resolved::ApplyOp {
                op: ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Delete {
                    name: name.clone(),
                }),
                after: PathAfter::ToRoot,
            },
            Path::Interface(name) => Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::Subinterface { interface, tag } => Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::Delete {
                    interface: interface.clone(),
                    tag: *tag,
                }),
                after: PathAfter::To(Path::Interface(interface.clone())),
            },
            Path::PolicyDefinition(name) => Resolved::ApplyOp {
                op: ConfigOp::PolicyDefinition(PolicyDefinitionOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::CommunityAlias(name) => Resolved::ApplyOp {
                op: ConfigOp::CommunityAlias(CommunityAliasOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::CommunityGroup(name) => Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::PrefixList(name) => Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::BroadcastDomain(name) => Resolved::ApplyOp {
                op: ConfigOp::BroadcastDomain(BroadcastDomainOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::SwitchingProfile(name) => Resolved::ApplyOp {
                op: ConfigOp::SwitchingProfile(SwitchingProfileOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::PortAggregate(name) => Resolved::ApplyOp {
                op: ConfigOp::PortAggregate(PortAggregateOp::Delete { name: name.clone() }),
                after: PathAfter::ToRoot,
            },
            Path::Root => Resolved::Error(
                "nothing to delete at the top level — use 'delete bgp instance <name>'".to_string(),
            ),
        },
        Command::Delete(DeleteTarget::RoutingTable { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableBgpInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearBgpInstance { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableBgpInstanceRelative) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearBgpInstance {
                name: path.routing_table()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableOspfInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearOspfInstance { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableOspfInstanceRelative) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearOspfInstance {
                name: path.routing_table()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableOspfv3Instance { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearOspfv3Instance { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableOspfv3InstanceRelative) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearOspfv3Instance {
                name: path.routing_table()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableRestApi { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearRestApi { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableRestApiRelative) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearRestApi {
                name: path.routing_table()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstance { name }) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearStaticRoutingInstance { name }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstanceRelative) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearStaticRoutingInstance {
                    name: path.routing_table()?.to_string(),
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::RoutingTableRedistribute { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableRedistributeRelative) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute {
                name: path.routing_table()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::StaticRoutingInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::StaticRoute { instance, subnet }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoute(StaticRouteOp::Delete { instance, subnet }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::StaticRouteRelative { subnet }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoute(StaticRouteOp::Delete {
                instance: path.static_routing_instance()?.to_string(),
                subnet,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::Interface { name }) => Resolved::ApplyOp {
            op: interface_delete_op(name),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceAddress { name, address }) => Resolved::ApplyOp {
            op: interface_remove_address_op(&name, address),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceAddressRelative { address }) => Resolved::ApplyOp {
            op: l3_remove_address_op(path.l3_target()?, address),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceRoutingTable { name }) => Resolved::ApplyOp {
            op: interface_clear_routing_table_op(&name),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceRoutingTableRelative) => Resolved::ApplyOp {
            op: l3_clear_routing_table_op(path.l3_target()?),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceOspfProfile { name }) => Resolved::ApplyOp {
            op: interface_clear_ospf_profile_op(&name),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceOspfProfileRelative) => Resolved::ApplyOp {
            op: l3_clear_ospf_profile_op(path.l3_target()?),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceOspfv3Profile { name }) => Resolved::ApplyOp {
            op: interface_clear_ospfv3_profile_op(&name),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceOspfv3ProfileRelative) => Resolved::ApplyOp {
            op: l3_clear_ospfv3_profile_op(path.l3_target()?),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::BroadcastDomainAddress { name, address }) => {
            Resolved::ApplyOp {
                op: ConfigOp::BroadcastDomain(BroadcastDomainOp::RemoveAddress { name, address }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::BroadcastDomainRoutingTable { name }) => Resolved::ApplyOp {
            op: ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearRoutingTable { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceSwitchingProfile { name }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceSwitchingProfileRelative) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile {
                name: path.interface()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceLldp { name, direction }) => Resolved::ApplyOp {
            op: lldp_op(name, direction, false),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceLldpRelative { direction }) => Resolved::ApplyOp {
            op: lldp_op(path.interface()?.to_string(), direction, false),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceLldpDestination { name }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::ClearLldpDestination { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceLldpDestinationRelative) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::ClearLldpDestination {
                name: path.interface()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::Lldp(kind)) => Resolved::ApplyOp {
            op: ConfigOp::Lldp(match kind {
                LldpSettingKind::TxInterval => LldpOp::ClearTxInterval,
                LldpSettingKind::TxHold => LldpOp::ClearTxHold,
                LldpSettingKind::ManagementAddress => LldpOp::ClearManagementAddress,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceMtu { name }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::ClearMtu { name }),
            after: PathAfter::Stay,
        },
        // See `SetTarget::MtuRelative`'s doc comment — `delete mtu` is the
        // same shared, path-disambiguated token.
        Command::Delete(DeleteTarget::MtuRelative) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::ClearMtu { name: name.clone() }),
                after: PathAfter::Stay,
            },
            Path::OspfProfile {
                instance,
                area_id,
                name,
            } => Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::ClearMtu {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name: name.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Ospfv3Profile {
                instance,
                area_id,
                name,
            } => Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::ClearMtu {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name: name.clone(),
                }),
                after: PathAfter::Stay,
            },
            _ => return Err(NO_CURRENT_INTERFACE_OR_OSPF_PROFILE),
        },
        Command::Delete(DeleteTarget::CommunityAlias { name }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityAlias(CommunityAliasOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::CommunityGroup { name }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityGroup(CommunityGroupOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::CommunityGroupMember { name, member }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityGroup(CommunityGroupOp::RemoveMember { name, member }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::CommunityGroupMemberRelative { member }) => {
            Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::RemoveMember {
                    name: path.community_group()?.to_string(),
                    member,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::PrefixList { name }) => Resolved::ApplyOp {
            op: ConfigOp::PrefixList(PrefixListOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::PrefixListEntry { name, cidr, range }) => Resolved::ApplyOp {
            op: ConfigOp::PrefixList(PrefixListOp::RemoveEntry {
                name,
                entry: PrefixListEntry { cidr, range },
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::PrefixListEntryRelative { cidr, range }) => {
            Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::RemoveEntry {
                    name: path.prefix_list()?.to_string(),
                    entry: PrefixListEntry { cidr, range },
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::BroadcastDomain { name }) => Resolved::ApplyOp {
            op: ConfigOp::BroadcastDomain(BroadcastDomainOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::SwitchingProfile { name }) => Resolved::ApplyOp {
            op: ConfigOp::SwitchingProfile(SwitchingProfileOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::SwitchingProfileMember {
            name,
            broadcast_domain,
        }) => Resolved::ApplyOp {
            op: ConfigOp::SwitchingProfile(SwitchingProfileOp::RemoveMember {
                name,
                broadcast_domain,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::SwitchingProfileMemberRelative { broadcast_domain }) => {
            Resolved::ApplyOp {
                op: ConfigOp::SwitchingProfile(SwitchingProfileOp::RemoveMember {
                    name: path.switching_profile()?.to_string(),
                    broadcast_domain,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::PortAggregate { name }) => Resolved::ApplyOp {
            op: ConfigOp::PortAggregate(PortAggregateOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfacePortAggregate { name }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::ClearPortAggregate { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfacePortAggregateRelative) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::ClearPortAggregate {
                name: path.interface()?.to_string(),
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::BgpPeerGroup { instance, name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Delete { instance, name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::PeerGroupRelative { name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Delete {
                instance: path.bgp_instance()?.to_string(),
                name,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::BgpPeer {
            instance,
            remote_address,
        }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeer(BgpPeerOp::Delete {
                instance,
                remote_address,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::PeerRelative { remote_address }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeer(BgpPeerOp::Delete {
                instance: path.bgp_instance()?.to_string(),
                remote_address,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::SourceAddress) => {
            peer_group_clear(path, |instance, name| BgpPeerGroupOp::ClearSourceAddress {
                instance,
                name,
            })?
        }
        Command::Delete(DeleteTarget::AddressFamily(af)) => {
            peer_group_clear(path, |instance, name| BgpPeerGroupOp::RemoveAddressFamily {
                instance,
                name,
                af,
            })?
        }
        Command::Delete(DeleteTarget::HoldTime) => peer_group_clear(path, |instance, name| {
            BgpPeerGroupOp::ClearHoldTime { instance, name }
        })?,
        Command::Delete(DeleteTarget::KeepaliveInterval) => {
            peer_group_clear(path, |instance, name| {
                BgpPeerGroupOp::ClearKeepaliveInterval { instance, name }
            })?
        }
        // Each of these five is a shared, path-disambiguated token with the
        // matching `Ospfv3ProfileOp::Clear*` — an `Ospfv3Profile` has the
        // same non-auth fields as an `OspfProfile`, so `_` (any path other
        // than `OspfProfile`) falls through to the `Ospfv3Profile` clear,
        // whose own `path.ospfv3_profile()?` check inside
        // `ospfv3_profile_clear` produces the right error otherwise —
        // mirrors `DeleteTarget::Auth`'s exact precedent below.
        Command::Delete(DeleteTarget::HelloInterval) => match path {
            Path::OspfProfile { .. } => ospf_profile_clear(path, |instance, area_id, name| {
                OspfProfileOp::ClearHelloInterval {
                    instance,
                    area_id,
                    name,
                }
            })?,
            _ => ospfv3_profile_clear(path, |instance, area_id, name| {
                Ospfv3ProfileOp::ClearHelloInterval {
                    instance,
                    area_id,
                    name,
                }
            })?,
        },
        Command::Delete(DeleteTarget::DeadInterval) => match path {
            Path::OspfProfile { .. } => ospf_profile_clear(path, |instance, area_id, name| {
                OspfProfileOp::ClearDeadInterval {
                    instance,
                    area_id,
                    name,
                }
            })?,
            _ => ospfv3_profile_clear(path, |instance, area_id, name| {
                Ospfv3ProfileOp::ClearDeadInterval {
                    instance,
                    area_id,
                    name,
                }
            })?,
        },
        Command::Delete(DeleteTarget::Cost) => match path {
            Path::OspfProfile { .. } => {
                ospf_profile_clear(path, |instance, area_id, name| OspfProfileOp::ClearCost {
                    instance,
                    area_id,
                    name,
                })?
            }
            _ => {
                ospfv3_profile_clear(path, |instance, area_id, name| Ospfv3ProfileOp::ClearCost {
                    instance,
                    area_id,
                    name,
                })?
            }
        },
        Command::Delete(DeleteTarget::Priority) => match path {
            Path::OspfProfile { .. } => ospf_profile_clear(path, |instance, area_id, name| {
                OspfProfileOp::ClearPriority {
                    instance,
                    area_id,
                    name,
                }
            })?,
            _ => ospfv3_profile_clear(path, |instance, area_id, name| {
                Ospfv3ProfileOp::ClearPriority {
                    instance,
                    area_id,
                    name,
                }
            })?,
        },
        Command::Delete(DeleteTarget::NetworkType) => match path {
            Path::OspfProfile { .. } => ospf_profile_clear(path, |instance, area_id, name| {
                OspfProfileOp::ClearNetworkType {
                    instance,
                    area_id,
                    name,
                }
            })?,
            _ => ospfv3_profile_clear(path, |instance, area_id, name| {
                Ospfv3ProfileOp::ClearNetworkType {
                    instance,
                    area_id,
                    name,
                }
            })?,
        },
        Command::Delete(DeleteTarget::Shutdown) => peer_group_clear(path, |instance, name| {
            BgpPeerGroupOp::ClearShutdown { instance, name }
        })?,
        Command::Delete(DeleteTarget::BgpPeerShutdown {
            instance,
            remote_address,
        }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeer(BgpPeerOp::ClearShutdown {
                instance,
                remote_address,
            }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::PeerShutdownRelative { remote_address }) => {
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeer(BgpPeerOp::ClearShutdown {
                    instance: path.bgp_instance()?.to_string(),
                    remote_address,
                }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::MaxHops) => peer_group_clear(path, |instance, name| {
            BgpPeerGroupOp::ClearMaxHops { instance, name }
        })?,
        Command::Delete(DeleteTarget::Mrai) => peer_group_clear(path, |instance, name| {
            BgpPeerGroupOp::ClearMrai { instance, name }
        })?,
        Command::Delete(DeleteTarget::Damping) => peer_group_clear(path, |instance, name| {
            BgpPeerGroupOp::ClearDamping { instance, name }
        })?,
        Command::Delete(DeleteTarget::ConnectRetryTime) => {
            peer_group_clear(path, |instance, name| {
                BgpPeerGroupOp::ClearConnectRetryTime { instance, name }
            })?
        }
        // `delete auth`'s literal token sequence is shared between a
        // peer-group and an OSPF profile (see `DeleteTarget::Auth`'s doc
        // comment) — resolved by path, mirroring `set router-id`'s
        // precedent above.
        Command::Delete(DeleteTarget::Auth) => match path {
            Path::OspfProfile { .. } => {
                ospf_profile_clear(path, |instance, area_id, name| OspfProfileOp::ClearAuth {
                    instance,
                    area_id,
                    name,
                })?
            }
            _ => peer_group_clear(path, |instance, name| BgpPeerGroupOp::ClearAuth {
                instance,
                name,
            })?,
        },
        Command::Delete(DeleteTarget::AoKey(send_id)) => {
            peer_group_clear(path, |instance, name| BgpPeerGroupOp::RemoveAoKey {
                instance,
                name,
                send_id,
            })?
        }
        Command::Delete(DeleteTarget::CryptoKey(key_id)) => {
            ospf_profile_clear(path, |instance, area_id, name| {
                OspfProfileOp::RemoveCryptoKey {
                    instance,
                    area_id,
                    name,
                    key_id,
                }
            })?
        }
        Command::Delete(DeleteTarget::NextHop) => peer_group_clear(path, |instance, name| {
            BgpPeerGroupOp::ClearNextHop { instance, name }
        })?,
        Command::Delete(DeleteTarget::RouteReflectorClient) => {
            peer_group_clear(path, |instance, name| {
                BgpPeerGroupOp::ClearRouteReflectorClient { instance, name }
            })?
        }
        Command::Delete(DeleteTarget::RouteServerClient) => {
            peer_group_clear(path, |instance, name| {
                BgpPeerGroupOp::ClearRouteServerClient { instance, name }
            })?
        }
        Command::Delete(DeleteTarget::ImportPolicy) => peer_group_clear(path, |instance, name| {
            BgpPeerGroupOp::ClearImportPolicy { instance, name }
        })?,
        Command::Delete(DeleteTarget::ExportPolicy) => peer_group_clear(path, |instance, name| {
            BgpPeerGroupOp::ClearExportPolicy { instance, name }
        })?,
        Command::Delete(DeleteTarget::BgpInstanceClusterId { name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpInstance(BgpInstanceOp::ClearClusterId { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::BgpInstanceClusterIdRelative) => Resolved::ApplyOp {
            op: ConfigOp::BgpInstance(BgpInstanceOp::ClearClusterId {
                name: path.bgp_instance()?.to_string(),
            }),
            after: PathAfter::Stay,
        },

        // `top` always lands at the root, however deep the current path is.
        Command::Top => match path {
            Path::Root => return Err(ALREADY_AT_TOP),
            _ => Resolved::NavigateTop,
        },
        // `up` moves exactly one level — from an instance that's the root
        // (coinciding with `top`), but from a peer-group it's the owning
        // instance, not the root. Routing tables, static routing instances,
        // interfaces, and policy-definitions have no navigable child (routes/
        // addresses/source aren't a `Path` position), so they behave like a
        // BGP instance here.
        Command::Up => match path {
            Path::Root => return Err(ALREADY_AT_TOP),
            Path::BgpPeerGroup { instance, .. } => {
                Resolved::Navigate(Path::BgpInstance(instance.clone()))
            }
            _ => Resolved::NavigateTop,
        },

        Command::Commit => Resolved::Commit,
        Command::Discard => Resolved::Discard,
        Command::Diff => Resolved::Diff,

        Command::Configure { .. }
        | Command::Empty
        | Command::Help
        | Command::ShowConfig
        | Command::ShowRoute { .. }
        | Command::ShowFdb { .. }
        | Command::ShowInterface { .. }
        | Command::ShowPortAggregate { .. }
        | Command::ShowLacp { .. }
        | Command::ShowLldpNeighbors
        | Command::ShowLog { .. }
        | Command::ShowBgpBrief
        | Command::ShowBgpEvpn
        | Command::ShowOspfNeigh
        | Command::ShowOspfDatabase
        | Command::ShowOspfv3Neigh
        | Command::ShowOspfv3Database
        | Command::ClearBgpSoftIn { .. }
        | Command::Unknown(_)
        | Command::Exit
        | Command::Save => {
            unreachable!("resolve() handles these before delegating to resolve_in_transaction")
        }
    })
}

/// `delete <field>` on the peer-group the path is currently navigated into.
/// Every such command runs the same navigation check and produces the same
/// `after`, differing only in which field its op clears — so each arm in the
/// table stays one line, naming just its `BgpPeerGroupOp`.
fn peer_group_clear(
    path: &Path,
    op: impl FnOnce(String, String) -> BgpPeerGroupOp,
) -> Result<Resolved, &'static str> {
    let (instance, group) = path.peer_group()?;
    Ok(Resolved::ApplyOp {
        op: ConfigOp::BgpPeerGroup(op(instance.to_string(), group.to_string())),
        after: PathAfter::Stay,
    })
}

fn set_op(name: String, field: BgpInstanceField) -> ConfigOp {
    ConfigOp::BgpInstance(match field {
        BgpInstanceField::Asn(asn) => BgpInstanceOp::SetAsn { name, asn },
        BgpInstanceField::RouterId(router_id) => BgpInstanceOp::SetRouterId { name, router_id },
        BgpInstanceField::ClusterId(cluster_id) => BgpInstanceOp::SetClusterId { name, cluster_id },
    })
}

fn peer_group_set_op(instance: String, group: String, field: BgpPeerGroupField) -> ConfigOp {
    ConfigOp::BgpPeerGroup(match field {
        BgpPeerGroupField::RemoteAs(remote_as) => BgpPeerGroupOp::SetRemoteAs {
            instance,
            name: group,
            remote_as,
        },
        BgpPeerGroupField::SourceAddress(source) => BgpPeerGroupOp::SetSourceAddress {
            instance,
            name: group,
            source,
        },
        BgpPeerGroupField::AddressFamily(af) => BgpPeerGroupOp::AddAddressFamily {
            instance,
            name: group,
            af,
        },
        BgpPeerGroupField::HoldTime(hold_time) => BgpPeerGroupOp::SetHoldTime {
            instance,
            name: group,
            hold_time,
        },
        BgpPeerGroupField::KeepaliveInterval(keepalive_interval) => {
            BgpPeerGroupOp::SetKeepaliveInterval {
                instance,
                name: group,
                keepalive_interval,
            }
        }
        BgpPeerGroupField::ConnectRetryTime(connect_retry_time) => {
            BgpPeerGroupOp::SetConnectRetryTime {
                instance,
                name: group,
                connect_retry_time,
            }
        }
        BgpPeerGroupField::Shutdown(message) => BgpPeerGroupOp::SetShutdown {
            instance,
            name: group,
            message,
        },
        BgpPeerGroupField::MaxHops(max_hops) => BgpPeerGroupOp::SetMaxHops {
            instance,
            name: group,
            max_hops,
        },
        BgpPeerGroupField::Damping(damping) => BgpPeerGroupOp::SetDamping {
            instance,
            name: group,
            damping,
        },
        BgpPeerGroupField::Mrai(mrai) => BgpPeerGroupOp::SetMrai {
            instance,
            name: group,
            mrai,
        },
        BgpPeerGroupField::Md5Password(password) => BgpPeerGroupOp::SetMd5Auth {
            instance,
            name: group,
            password,
        },
        BgpPeerGroupField::AoKey {
            send_id,
            recv_id,
            algorithm,
            key,
        } => BgpPeerGroupOp::SetAoKey {
            instance,
            name: group,
            key: BgpAoKey {
                send_id,
                recv_id,
                algorithm,
                key,
                is_current: false,
                is_rnext: false,
            },
        },
        BgpPeerGroupField::AoCurrentKey(send_id) => BgpPeerGroupOp::SetAoCurrentKey {
            instance,
            name: group,
            send_id,
        },
        BgpPeerGroupField::AoRnextKey(send_id) => BgpPeerGroupOp::SetAoRnextKey {
            instance,
            name: group,
            send_id,
        },
        BgpPeerGroupField::NextHop(mode) => BgpPeerGroupOp::SetNextHop {
            instance,
            name: group,
            mode,
        },
        BgpPeerGroupField::RouteReflectorClient => BgpPeerGroupOp::SetRouteReflectorClient {
            instance,
            name: group,
        },
        BgpPeerGroupField::RouteServerClient => BgpPeerGroupOp::SetRouteServerClient {
            instance,
            name: group,
        },
        BgpPeerGroupField::ImportPolicy(import_policy) => BgpPeerGroupOp::SetImportPolicy {
            instance,
            name: group,
            import_policy,
        },
        BgpPeerGroupField::ExportPolicy(export_policy) => BgpPeerGroupOp::SetExportPolicy {
            instance,
            name: group,
            export_policy,
        },
    })
}

/// `delete <field>` on the ospf profile the path is currently navigated
/// into — mirrors `peer_group_clear` exactly.
fn ospf_profile_clear(
    path: &Path,
    op: impl FnOnce(String, Ipv4Addr, String) -> OspfProfileOp,
) -> Result<Resolved, &'static str> {
    let (instance, area_id, name) = path.ospf_profile()?;
    Ok(Resolved::ApplyOp {
        op: ConfigOp::OspfProfile(op(instance.to_string(), area_id, name.to_string())),
        after: PathAfter::Stay,
    })
}

/// `set`/`delete ... lldp transmit|receive` — the two directions are the same
/// op on different fields, `enabled` being `true` for `set`, `false` for `delete`.
fn lldp_op(name: String, direction: LldpDirection, enabled: bool) -> ConfigOp {
    ConfigOp::Interface(match direction {
        LldpDirection::Transmit => InterfaceOp::SetLldpTransmit { name, enabled },
        LldpDirection::Receive => InterfaceOp::SetLldpReceive { name, enabled },
    })
}

fn ospf_profile_set_op(
    instance: String,
    area_id: Ipv4Addr,
    name: String,
    field: OspfProfileField,
) -> ConfigOp {
    ConfigOp::OspfProfile(match field {
        OspfProfileField::HelloInterval(hello_interval) => OspfProfileOp::SetHelloInterval {
            instance,
            area_id,
            name,
            hello_interval,
        },
        OspfProfileField::DeadInterval(dead_interval) => OspfProfileOp::SetDeadInterval {
            instance,
            area_id,
            name,
            dead_interval,
        },
        OspfProfileField::Cost(cost) => OspfProfileOp::SetCost {
            instance,
            area_id,
            name,
            cost,
        },
        OspfProfileField::Priority(priority) => OspfProfileOp::SetPriority {
            instance,
            area_id,
            name,
            priority,
        },
        OspfProfileField::Mtu(mtu) => OspfProfileOp::SetMtu {
            instance,
            area_id,
            name,
            mtu,
        },
        OspfProfileField::NetworkType(network_type) => OspfProfileOp::SetNetworkType {
            instance,
            area_id,
            name,
            network_type,
        },
        OspfProfileField::SimplePassword(password) => OspfProfileOp::SetSimpleAuth {
            instance,
            area_id,
            name,
            password,
        },
        OspfProfileField::CryptoKey {
            key_id,
            algorithm,
            key,
        } => OspfProfileOp::SetCryptoKey {
            instance,
            area_id,
            name,
            key: OspfCryptoKey {
                key_id,
                algorithm,
                key,
                is_current: false,
            },
        },
        OspfProfileField::CryptoCurrentKey(key_id) => OspfProfileOp::SetCryptoCurrentKey {
            instance,
            area_id,
            name,
            key_id,
        },
    })
}

/// `delete <field>` on the ospfv3 profile the path is currently navigated
/// into — mirrors `ospf_profile_clear` exactly.
fn ospfv3_profile_clear(
    path: &Path,
    op: impl FnOnce(String, Ipv4Addr, String) -> Ospfv3ProfileOp,
) -> Result<Resolved, &'static str> {
    let (instance, area_id, name) = path.ospfv3_profile()?;
    Ok(Resolved::ApplyOp {
        op: ConfigOp::Ospfv3Profile(op(instance.to_string(), area_id, name.to_string())),
        after: PathAfter::Stay,
    })
}

/// Mirrors `ospf_profile_set_op`, minus the auth fields — an `Ospfv3Profile`
/// has no `SimplePassword`/`CryptoKey`/`CryptoCurrentKey` equivalent (no
/// authentication in this NOS build's `OSPFv3` support), so those return an
/// error instead of a `ConfigOp`.
fn ospfv3_profile_set_op(
    instance: String,
    area_id: Ipv4Addr,
    name: String,
    field: &OspfProfileField,
) -> Result<ConfigOp, String> {
    Ok(ConfigOp::Ospfv3Profile(match *field {
        OspfProfileField::HelloInterval(hello_interval) => Ospfv3ProfileOp::SetHelloInterval {
            instance,
            area_id,
            name,
            hello_interval,
        },
        OspfProfileField::DeadInterval(dead_interval) => Ospfv3ProfileOp::SetDeadInterval {
            instance,
            area_id,
            name,
            dead_interval,
        },
        OspfProfileField::Cost(cost) => Ospfv3ProfileOp::SetCost {
            instance,
            area_id,
            name,
            cost,
        },
        OspfProfileField::Priority(priority) => Ospfv3ProfileOp::SetPriority {
            instance,
            area_id,
            name,
            priority,
        },
        OspfProfileField::Mtu(mtu) => Ospfv3ProfileOp::SetMtu {
            instance,
            area_id,
            name,
            mtu,
        },
        OspfProfileField::NetworkType(network_type) => Ospfv3ProfileOp::SetNetworkType {
            instance,
            area_id,
            name,
            network_type,
        },
        OspfProfileField::SimplePassword(_)
        | OspfProfileField::CryptoKey { .. }
        | OspfProfileField::CryptoCurrentKey(_) => {
            return Err("ospfv3 profiles support no authentication in this NOS build".to_string());
        }
    }))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::{
        NetworkType, NextHopMode, Redistribute, RedistributeSource, RedistributeTarget,
    };

    use super::*;

    fn config_mode(transaction: &str, path: Path, dirty: bool) -> Mode {
        Mode::Configuration {
            transaction: transaction.to_string(),
            path,
            dirty,
        }
    }

    #[test]
    fn empty_and_help_are_mode_independent() {
        assert_eq!(
            resolve(&Mode::Operational, Command::Empty),
            Resolved::Nothing
        );
        assert_eq!(resolve(&Mode::Operational, Command::Help), Resolved::Help);
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, false), Command::Help),
            Resolved::Help
        );
    }

    #[test]
    fn show_config_always_hits_running_config() {
        assert_eq!(
            resolve(&Mode::Operational, Command::ShowConfig),
            Resolved::ShowRunningConfig
        );
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, false), Command::ShowConfig),
            Resolved::ShowRunningConfig
        );
    }

    #[test]
    fn show_route_works_in_any_mode() {
        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            resolve(
                &Mode::Operational,
                Command::ShowRoute {
                    table: "rt1".to_string(),
                    address: Some(addr),
                }
            ),
            Resolved::ShowRoute {
                table: "rt1".to_string(),
                address: Some(addr),
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowRoute {
                    table: "rt1".to_string(),
                    address: None,
                }
            ),
            Resolved::ShowRoute {
                table: "rt1".to_string(),
                address: None,
            }
        );
    }

    #[test]
    fn show_fdb_works_in_any_mode() {
        let domain = || "bd1".to_string();
        for mode in [Mode::Operational, config_mode("t1", Path::Root, false)] {
            assert_eq!(
                resolve(&mode, Command::ShowFdb { domain: domain() }),
                Resolved::ShowFdb { domain: domain() }
            );
        }
    }

    #[test]
    fn operational_exit_exits_shell() {
        assert_eq!(
            resolve(&Mode::Operational, Command::Exit),
            Resolved::ExitShell
        );
    }

    #[test]
    fn configuration_exit_prompts() {
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, true), Command::Exit),
            Resolved::LeaveConfigPrompt
        );
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, false), Command::Exit),
            Resolved::LeaveConfigPrompt
        );
    }

    #[test]
    fn operational_save_saves() {
        assert_eq!(
            resolve(&Mode::Operational, Command::Save),
            Resolved::SaveRunningConfig
        );
    }

    #[test]
    fn configuration_save_errors() {
        assert!(matches!(
            resolve(&config_mode("t1", Path::Root, false), Command::Save),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn operational_configure_opens_transaction_default_current() {
        assert_eq!(
            resolve(
                &Mode::Operational,
                Command::Configure {
                    name: "t1".to_string(),
                    base: None
                }
            ),
            Resolved::OpenTransaction {
                name: "t1".to_string(),
                base: TransactionBase::Current,
                explicit_base: false,
            }
        );
    }

    #[test]
    fn operational_configure_explicit_blank() {
        assert_eq!(
            resolve(
                &Mode::Operational,
                Command::Configure {
                    name: "t1".to_string(),
                    base: Some(TransactionBase::Blank)
                }
            ),
            Resolved::OpenTransaction {
                name: "t1".to_string(),
                base: TransactionBase::Blank,
                explicit_base: true,
            }
        );
    }

    #[test]
    fn configure_while_already_configuring_errors() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Configure {
                    name: "t2".to_string(),
                    base: None
                }
            ),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn show_this_requires_configuration_mode() {
        assert!(matches!(
            resolve(&Mode::Operational, Command::Show),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, false), Command::Show),
            Resolved::ShowTransaction
        );
    }

    #[test]
    fn edit_requires_configuration_mode_and_navigates() {
        assert!(matches!(
            resolve(
                &Mode::Operational,
                Command::Edit(EditTarget::BgpInstance {
                    name: "r1".to_string()
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::BgpInstance {
                    name: "r1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::Ensure {
                    name: "r1".to_string()
                }),
                after: PathAfter::To(Path::BgpInstance("r1".to_string())),
            }
        );
    }

    #[test]
    fn set_qualified_works_from_root() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::BgpInstance {
                    name: "r1".to_string(),
                    field: BgpInstanceField::Asn(65001)
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::SetAsn {
                    name: "r1".to_string(),
                    asn: 65001
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_relative_requires_bgp_instance_context() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::Asn(65001)
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::RouterId(Ipv4Addr::new(10, 0, 0, 1))
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::SetRouterId {
                    name: "r1".to_string(),
                    router_id: Ipv4Addr::new(10, 0, 0, 1)
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_hostname_works_from_root() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::Hostname("router1".to_string()))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::SetHostname("router1".to_string()),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_user_password_works_from_anywhere() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Set(SetTarget::UserPassword {
                    name: "alice".to_string(),
                    password: "pw".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::User(UserOp::SetPassword {
                    name: "alice".to_string(),
                    password: "pw".to_string()
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_hostname_works_from_bgp_instance_context() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Set(SetTarget::Hostname("router1".to_string()))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::SetHostname("router1".to_string()),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_current_requires_bgp_instance_context_and_returns_to_root() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::Delete {
                    name: "r1".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
    }

    #[test]
    fn delete_qualified_stays_put() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::BgpInstance {
                    name: "r1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::Delete {
                    name: "r1".to_string()
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn up_and_top_from_root_error() {
        assert!(matches!(
            resolve(&config_mode("t1", Path::Root, false), Command::Up),
            Resolved::Error(_)
        ));
        assert!(matches!(
            resolve(&config_mode("t1", Path::Root, false), Command::Top),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn up_and_top_from_bgp_instance_navigate_to_root() {
        let mode = config_mode("t1", Path::BgpInstance("r1".to_string()), false);
        assert_eq!(resolve(&mode, Command::Up), Resolved::NavigateTop);
        assert_eq!(resolve(&mode, Command::Top), Resolved::NavigateTop);
    }

    #[test]
    fn commit_and_discard_require_configuration_mode() {
        assert!(matches!(
            resolve(&Mode::Operational, Command::Commit),
            Resolved::Error(_)
        ));
        assert!(matches!(
            resolve(&Mode::Operational, Command::Discard),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, true), Command::Commit),
            Resolved::Commit
        );
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, true), Command::Discard),
            Resolved::Discard
        );
    }

    #[test]
    fn diff_requires_configuration_mode() {
        assert!(matches!(
            resolve(&Mode::Operational, Command::Diff),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, false), Command::Diff),
            Resolved::Diff
        );
    }

    use nos_proto::AddressFamily;

    fn peer_group_path(instance: &str, group: &str) -> Path {
        Path::BgpPeerGroup {
            instance: instance.to_string(),
            group: group.to_string(),
        }
    }

    fn ospf_profile_path(instance: &str, area_id: &str, name: &str) -> Path {
        Path::OspfProfile {
            instance: instance.to_string(),
            area_id: area_id.parse().unwrap(),
            name: name.to_string(),
        }
    }

    #[test]
    fn edit_bgp_peer_group_qualified_navigates() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::BgpPeerGroup {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Ensure {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::To(peer_group_path("r1", "pg1")),
            }
        );
    }

    #[test]
    fn edit_peer_group_relative_requires_bgp_instance_context() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::PeerGroupRelative {
                    name: "pg1".to_string()
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Edit(EditTarget::PeerGroupRelative {
                    name: "pg1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Ensure {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::To(peer_group_path("r1", "pg1")),
            }
        );
    }

    #[test]
    fn set_peer_group_field_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: "r1".to_string(),
                    group: "pg1".to_string(),
                    field: BgpPeerGroupField::RemoteAs(65001),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRemoteAs {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    remote_as: 65001,
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::RemoteAs(65001)
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::RemoteAs(65001)
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRemoteAs {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    remote_as: 65001,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_peer_group_timer_fields_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: "r1".to_string(),
                    group: "pg1".to_string(),
                    field: BgpPeerGroupField::HoldTime(30),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetHoldTime {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    hold_time: 30,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::KeepaliveInterval(10),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetKeepaliveInterval {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    keepalive_interval: 10,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::ConnectRetryTime(45),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetConnectRetryTime {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    connect_retry_time: 45,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_ospf_profile_fields_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::OspfProfile {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    field: OspfProfileField::HelloInterval(5),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetHelloInterval {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    hello_interval: 5,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Set(SetTarget::OspfProfileRelative {
                    field: OspfProfileField::DeadInterval(20),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetDeadInterval {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    dead_interval: 20,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Set(SetTarget::OspfProfileRelative {
                    field: OspfProfileField::Cost(15),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetCost {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    cost: 15,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Set(SetTarget::OspfProfileRelative {
                    field: OspfProfileField::Priority(200),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetPriority {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    priority: 200,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Set(SetTarget::OspfProfileRelative {
                    field: OspfProfileField::NetworkType(NetworkType::Broadcast),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetNetworkType {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    network_type: NetworkType::Broadcast,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_ospf_profile_fields_require_ospf_profile_context() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::OspfInstance("o1".to_string()), false),
                Command::Delete(DeleteTarget::HelloInterval)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Delete(DeleteTarget::HelloInterval)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::ClearHelloInterval {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Delete(DeleteTarget::DeadInterval)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::ClearDeadInterval {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Delete(DeleteTarget::Cost)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::ClearCost {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Delete(DeleteTarget::Priority)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::ClearPriority {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Delete(DeleteTarget::NetworkType)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::ClearNetworkType {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_and_delete_peer_group_next_hop_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: "r1".to_string(),
                    group: "pg1".to_string(),
                    field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetNextHop {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    mode: NextHopMode::SelfAddress,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetNextHop {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    mode: NextHopMode::Unchanged,
                }),
                after: PathAfter::Stay,
            }
        );
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Delete(DeleteTarget::NextHop)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::NextHop)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearNextHop {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_and_delete_peer_group_route_reflector_and_server_client_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::BgpPeerGroup {
                    instance: "r1".to_string(),
                    group: "pg1".to_string(),
                    field: BgpPeerGroupField::RouteReflectorClient,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRouteReflectorClient {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::RouteServerClient,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRouteServerClient {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Delete(DeleteTarget::RouteReflectorClient)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::RouteReflectorClient)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearRouteReflectorClient {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::RouteServerClient)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearRouteServerClient {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_and_delete_bgp_instance_cluster_id_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::BgpInstance {
                    name: "r1".to_string(),
                    field: BgpInstanceField::ClusterId(Ipv4Addr::new(1, 2, 3, 4)),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::SetClusterId {
                    name: "r1".to_string(),
                    cluster_id: Ipv4Addr::new(1, 2, 3, 4),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::ClusterId(Ipv4Addr::new(1, 2, 3, 4)),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::SetClusterId {
                    name: "r1".to_string(),
                    cluster_id: Ipv4Addr::new(1, 2, 3, 4),
                }),
                after: PathAfter::Stay,
            }
        );
        assert!(matches!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::BgpInstanceClusterIdRelative)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Delete(DeleteTarget::BgpInstanceClusterIdRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::ClearClusterId {
                    name: "r1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::BgpInstanceClusterId {
                    name: "r1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::ClearClusterId {
                    name: "r1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_peer_group_timers_require_peer_group_context() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Delete(DeleteTarget::HoldTime)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::HoldTime)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearHoldTime {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::KeepaliveInterval)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearKeepaliveInterval {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::ConnectRetryTime)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearConnectRetryTime {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_peer_group_auth_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::Md5Password("secret".to_string()),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetMd5Auth {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    password: "secret".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::AoKey {
                        send_id: 1,
                        recv_id: 2,
                        algorithm: nos_proto::BgpAoAlgorithm::HmacSha1_96,
                        key: "secret".to_string(),
                    },
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAoKey {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    key: BgpAoKey {
                        send_id: 1,
                        recv_id: 2,
                        algorithm: nos_proto::BgpAoAlgorithm::HmacSha1_96,
                        key: "secret".to_string(),
                        is_current: false,
                        is_rnext: false,
                    },
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::AoCurrentKey(1),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAoCurrentKey {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    send_id: 1,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerGroupRelative {
                    field: BgpPeerGroupField::AoRnextKey(1),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAoRnextKey {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    send_id: 1,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_peer_group_auth_requires_peer_group_context() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Delete(DeleteTarget::Auth)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::Auth)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearAuth {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::AoKey(1))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::RemoveAoKey {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    send_id: 1,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    /// `delete auth` shares its token sequence with the peer-group one
    /// above — confirms it's routed to `OspfProfileOp::ClearAuth` when the
    /// path is navigated into an OSPF profile instead.
    #[test]
    fn delete_auth_routes_to_ospf_profile_when_navigated_into_one() {
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Delete(DeleteTarget::Auth)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::ClearAuth {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_ospf_profile_simple_password_and_crypto_key() {
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Set(SetTarget::OspfProfileRelative {
                    field: OspfProfileField::SimplePassword("hunter2".to_string()),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetSimpleAuth {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    password: "hunter2".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Set(SetTarget::OspfProfileRelative {
                    field: OspfProfileField::CryptoKey {
                        key_id: 1,
                        algorithm: nos_proto::OspfCryptoAlgorithm::HmacSha256,
                        key: "secret".to_string(),
                    },
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetCryptoKey {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    key: OspfCryptoKey {
                        key_id: 1,
                        algorithm: nos_proto::OspfCryptoAlgorithm::HmacSha256,
                        key: "secret".to_string(),
                        is_current: false,
                    },
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospf_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Delete(DeleteTarget::CryptoKey(1))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::RemoveCryptoKey {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    key_id: 1,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_peer_qualified_and_relative() {
        let addr: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::BgpPeer {
                    instance: "r1".to_string(),
                    remote_address: addr,
                    peer_group: "pg1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeer(BgpPeerOp::Set {
                    instance: "r1".to_string(),
                    remote_address: addr,
                    peer_group: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Set(SetTarget::PeerRelative {
                    remote_address: addr,
                    peer_group: "pg1".to_string(),
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Set(SetTarget::PeerRelative {
                    remote_address: addr,
                    peer_group: "pg1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeer(BgpPeerOp::Set {
                    instance: "r1".to_string(),
                    remote_address: addr,
                    peer_group: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_current_at_peer_group_deletes_group_and_lands_on_instance() {
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Delete {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::To(Path::BgpInstance("r1".to_string())),
            }
        );
    }

    #[test]
    fn delete_source_address_and_address_family_require_peer_group_context() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::BgpInstance("r1".to_string()), false),
                Command::Delete(DeleteTarget::SourceAddress)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::SourceAddress)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearSourceAddress {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", peer_group_path("r1", "pg1"), false),
                Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv4Unicast))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::RemoveAddressFamily {
                    instance: "r1".to_string(),
                    name: "pg1".to_string(),
                    af: AddressFamily::Ipv4Unicast,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    /// `up`/`top` finally diverge once a second nesting level exists: from a
    /// peer-group, `up` lands one level up (the owning instance), while
    /// `top` always lands at the root.
    #[test]
    fn up_and_top_diverge_from_peer_group() {
        let mode = config_mode("t1", peer_group_path("r1", "pg1"), false);
        assert_eq!(
            resolve(&mode, Command::Up),
            Resolved::Navigate(Path::BgpInstance("r1".to_string()))
        );
        assert_eq!(resolve(&mode, Command::Top), Resolved::NavigateTop);
    }

    #[test]
    fn unknown_command_errors() {
        assert!(matches!(
            resolve(
                &Mode::Operational,
                Command::Unknown("frobnicate".to_string())
            ),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn edit_routing_table_navigates() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::RoutingTable {
                    name: "rt1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::Ensure {
                    name: "rt1".to_string()
                }),
                after: PathAfter::To(Path::RoutingTable("rt1".to_string())),
            }
        );
    }

    #[test]
    fn edit_policy_definition_navigates() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::PolicyDefinition {
                    name: "p1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PolicyDefinition(PolicyDefinitionOp::Ensure {
                    name: "p1".to_string()
                }),
                after: PathAfter::To(Path::PolicyDefinition("p1".to_string())),
            }
        );
    }

    #[test]
    fn edit_and_show_source_require_policy_definition_context() {
        assert!(matches!(
            resolve(&config_mode("t1", Path::Root, false), Command::EditSource),
            Resolved::Error(_)
        ));
        assert!(matches!(
            resolve(&config_mode("t1", Path::Root, false), Command::ShowSource),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PolicyDefinition("p1".to_string()), false),
                Command::EditSource
            ),
            Resolved::EditPolicySource {
                name: "p1".to_string()
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PolicyDefinition("p1".to_string()), false),
                Command::ShowSource
            ),
            Resolved::ShowPolicySource {
                name: "p1".to_string()
            }
        );
    }

    #[test]
    fn set_and_delete_source_line_require_policy_definition_context() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PolicyDefinition("p1".to_string()), false),
                Command::SetSourceLine {
                    line: 2,
                    text: "    accept".to_string()
                }
            ),
            Resolved::SetPolicySourceLine {
                name: "p1".to_string(),
                line: 2,
                text: "    accept".to_string(),
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PolicyDefinition("p1".to_string()), false),
                Command::DeleteSourceLine { line: 2 }
            ),
            Resolved::DeletePolicySourceLine {
                name: "p1".to_string(),
                line: 2,
            }
        );
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::SetSourceLine {
                    line: 1,
                    text: "accept".to_string()
                }
            ),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn delete_current_at_policy_definition_returns_to_root() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PolicyDefinition("p1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PolicyDefinition(PolicyDefinitionOp::Delete {
                    name: "p1".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
    }

    #[test]
    fn up_and_top_from_policy_definition_navigate_to_root() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PolicyDefinition("p1".to_string()), false),
                Command::Up
            ),
            Resolved::NavigateTop
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PolicyDefinition("p1".to_string()), false),
                Command::Top
            ),
            Resolved::NavigateTop
        );
    }

    #[test]
    fn edit_static_routing_instance_navigates() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::StaticRoutingInstance {
                    name: "sri1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Ensure {
                    name: "sri1".to_string()
                }),
                after: PathAfter::To(Path::StaticRoutingInstance("sri1".to_string())),
            }
        );
    }

    #[test]
    fn set_routing_table_bgp_instance_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::RoutingTable {
                    name: "rt1".to_string(),
                    bgp_instance: "r1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance {
                    name: "rt1".to_string(),
                    bgp_instance: "r1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::RoutingTableRelative {
                    bgp_instance: "r1".to_string()
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::RoutingTable("rt1".to_string()), false),
                Command::Set(SetTarget::RoutingTableRelative {
                    bgp_instance: "r1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance {
                    name: "rt1".to_string(),
                    bgp_instance: "r1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_routing_table_redistribute_qualified_and_relative() {
        let redistribute = Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Bgp,
            policy: None,
        };
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::RoutingTableRedistribute {
                    name: "rt1".to_string(),
                    redistribute: redistribute.clone(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
                    name: "rt1".to_string(),
                    redistribute: redistribute.clone(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::RoutingTableRedistributeRelative {
                    redistribute: redistribute.clone()
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::RoutingTable("rt1".to_string()), false),
                Command::Set(SetTarget::RoutingTableRedistributeRelative { redistribute })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
                    name: "rt1".to_string(),
                    redistribute: Redistribute {
                        from: RedistributeSource::Static,
                        to: RedistributeTarget::Bgp,
                        policy: None,
                    },
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_routing_table_static_routing_instance_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::RoutingTableStaticRoutingInstance {
                    name: "rt1".to_string(),
                    static_routing_instance: "sri1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetStaticRoutingInstance {
                    name: "rt1".to_string(),
                    static_routing_instance: "sri1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert_eq!(
            resolve(
                &config_mode("t1", Path::RoutingTable("rt1".to_string()), false),
                Command::Set(SetTarget::RoutingTableStaticRoutingInstanceRelative {
                    static_routing_instance: "sri1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetStaticRoutingInstance {
                    name: "rt1".to_string(),
                    static_routing_instance: "sri1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_static_route_qualified_and_relative() {
        let subnet: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();
        let gateway: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::StaticRoute {
                    instance: "sri1".to_string(),
                    subnet,
                    gateway,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::StaticRoute(StaticRouteOp::Set {
                    instance: "sri1".to_string(),
                    subnet,
                    gateway,
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::StaticRouteRelative { subnet, gateway })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::StaticRoutingInstance("sri1".to_string()), false),
                Command::Set(SetTarget::StaticRouteRelative { subnet, gateway })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::StaticRoute(StaticRouteOp::Set {
                    instance: "sri1".to_string(),
                    subnet,
                    gateway,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_current_at_routing_table_and_static_routing_instance_returns_to_root() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::RoutingTable("rt1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::Delete {
                    name: "rt1".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::StaticRoutingInstance("sri1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Delete {
                    name: "sri1".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
    }

    #[test]
    fn delete_routing_table_bgp_instance_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::RoutingTableBgpInstance {
                    name: "rt1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearBgpInstance {
                    name: "rt1".to_string()
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::RoutingTableBgpInstanceRelative)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::RoutingTable("rt1".to_string()), false),
                Command::Delete(DeleteTarget::RoutingTableBgpInstanceRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearBgpInstance {
                    name: "rt1".to_string()
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_routing_table_redistribute_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::RoutingTableRedistribute {
                    name: "rt1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute {
                    name: "rt1".to_string()
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::RoutingTableRedistributeRelative)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::RoutingTable("rt1".to_string()), false),
                Command::Delete(DeleteTarget::RoutingTableRedistributeRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute {
                    name: "rt1".to_string()
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_static_route_qualified_and_relative() {
        let subnet: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();

        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::StaticRoute {
                    instance: "sri1".to_string(),
                    subnet,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::StaticRoute(StaticRouteOp::Delete {
                    instance: "sri1".to_string(),
                    subnet,
                }),
                after: PathAfter::Stay,
            }
        );

        assert_eq!(
            resolve(
                &config_mode("t1", Path::StaticRoutingInstance("sri1".to_string()), false),
                Command::Delete(DeleteTarget::StaticRouteRelative { subnet })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::StaticRoute(StaticRouteOp::Delete {
                    instance: "sri1".to_string(),
                    subnet,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn up_and_top_from_routing_table_and_static_routing_instance_navigate_to_root() {
        let rt_mode = config_mode("t1", Path::RoutingTable("rt1".to_string()), false);
        assert_eq!(resolve(&rt_mode, Command::Up), Resolved::NavigateTop);
        assert_eq!(resolve(&rt_mode, Command::Top), Resolved::NavigateTop);

        let sri_mode = config_mode("t1", Path::StaticRoutingInstance("sri1".to_string()), false);
        assert_eq!(resolve(&sri_mode, Command::Up), Resolved::NavigateTop);
        assert_eq!(resolve(&sri_mode, Command::Top), Resolved::NavigateTop);
    }

    #[test]
    fn show_interface_works_in_any_mode() {
        assert_eq!(
            resolve(&Mode::Operational, Command::ShowInterface { name: None }),
            Resolved::ShowInterface { name: None }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowInterface {
                    name: Some("eth0".to_string())
                }
            ),
            Resolved::ShowInterface {
                name: Some("eth0".to_string())
            }
        );
    }

    #[test]
    fn show_log_works_in_any_mode() {
        assert_eq!(
            resolve(
                &Mode::Operational,
                Command::ShowLog {
                    source: None,
                    follow: false,
                }
            ),
            Resolved::ShowLog {
                source: None,
                follow: false,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowLog {
                    source: Some("nos-ribd[rt1]".to_string()),
                    follow: true,
                }
            ),
            Resolved::ShowLog {
                source: Some("nos-ribd[rt1]".to_string()),
                follow: true,
            }
        );
    }

    #[test]
    fn show_bgp_brief_works_in_any_mode() {
        assert_eq!(
            resolve(&Mode::Operational, Command::ShowBgpBrief),
            Resolved::ShowBgpBrief
        );
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, false), Command::ShowBgpBrief),
            Resolved::ShowBgpBrief
        );
    }

    #[test]
    fn show_ospf_neigh_works_in_any_mode() {
        assert_eq!(
            resolve(&Mode::Operational, Command::ShowOspfNeigh),
            Resolved::ShowOspfNeigh
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowOspfNeigh
            ),
            Resolved::ShowOspfNeigh
        );
    }

    #[test]
    fn show_ospf_database_works_in_any_mode() {
        assert_eq!(
            resolve(&Mode::Operational, Command::ShowOspfDatabase),
            Resolved::ShowOspfDatabase
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowOspfDatabase
            ),
            Resolved::ShowOspfDatabase
        );
    }

    #[test]
    fn clear_bgp_soft_in_works_in_any_mode() {
        let cmd = Command::ClearBgpSoftIn {
            instance: "r1".to_string(),
            peer: "10.0.0.1".parse().unwrap(),
        };
        let expected = Resolved::ClearBgpSoftIn {
            instance: "r1".to_string(),
            peer: "10.0.0.1".parse().unwrap(),
        };
        assert_eq!(resolve(&Mode::Operational, cmd.clone()), expected);
        assert_eq!(
            resolve(&config_mode("t1", Path::Root, false), cmd),
            expected
        );
    }

    #[test]
    fn edit_interface_navigates() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::Interface {
                    name: "eth0".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::Ensure {
                    name: "eth0".to_string()
                }),
                after: PathAfter::To(Path::Interface("eth0".to_string())),
            }
        );
    }

    /// `edit interface eth0.100` ensures the subinterface (cascading its
    /// parent interface) and navigates into `Path::Subinterface`, rather
    /// than the plain `Path::Interface` a bare (undotted) name gets.
    #[test]
    fn edit_dotted_interface_navigates_to_subinterface() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::Interface {
                    name: "eth0.100".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::Ensure {
                    interface: "eth0".to_string(),
                    tag: 100,
                }),
                after: PathAfter::To(Path::Subinterface {
                    interface: "eth0".to_string(),
                    tag: 100,
                }),
            }
        );
    }

    /// `.0` is the explicit, canonical way to reach the untagged/native
    /// subinterface — same target a bare non-loopback name implicitly
    /// resolves to.
    #[test]
    fn edit_dot_zero_navigates_to_tag_zero_subinterface() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::Interface {
                    name: "eth0.0".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::Ensure {
                    interface: "eth0".to_string(),
                    tag: 0,
                }),
                after: PathAfter::To(Path::Subinterface {
                    interface: "eth0".to_string(),
                    tag: 0,
                }),
            }
        );
    }

    /// A loopback name is never split, even with a trailing numeric suffix
    /// that happens to look like a tag — loopback names are excluded from
    /// this feature entirely, so `loopback-rt1` (no dot at all) stays a
    /// plain interface reference. This test only guards the no-dot case;
    /// a dotted loopback name is rejected by commit-time validation
    /// (`interface_name_valid`'s '.'-rejection), not by CLI-side parsing.
    #[test]
    fn edit_loopback_interface_navigates_unsplit() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::Interface {
                    name: "loopback-rt1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::Ensure {
                    name: "loopback-rt1".to_string()
                }),
                after: PathAfter::To(Path::Interface("loopback-rt1".to_string())),
            }
        );
    }

    #[test]
    fn set_interface_address_qualified_and_relative() {
        let address: ipnet::IpNet = "10.0.0.1/24".parse().unwrap();
        // A bare (undotted) non-loopback interface name implicitly targets
        // its tag-0 (untagged/native) subinterface.
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceAddress {
                    name: "eth0".to_string(),
                    address,
                    label: None,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
                    interface: "eth0".to_string(),
                    tag: 0,
                    address,
                    label: None,
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceAddressRelative {
                    address,
                    label: None
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Set(SetTarget::InterfaceAddressRelative {
                    address,
                    label: None
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
                    interface: "eth0".to_string(),
                    tag: 0,
                    address,
                    label: None,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_interface_address_dotted_name_targets_subinterface() {
        let address: ipnet::IpNet = "10.0.0.1/24".parse().unwrap();
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceAddress {
                    name: "eth0.100".to_string(),
                    address,
                    label: None,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
                    interface: "eth0".to_string(),
                    tag: 100,
                    address,
                    label: None,
                }),
                after: PathAfter::Stay,
            }
        );

        assert_eq!(
            resolve(
                &config_mode(
                    "t1",
                    Path::Subinterface {
                        interface: "eth0".to_string(),
                        tag: 100
                    },
                    false
                ),
                Command::Set(SetTarget::InterfaceAddressRelative {
                    address,
                    label: None
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
                    interface: "eth0".to_string(),
                    tag: 100,
                    address,
                    label: None,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    /// A loopback interface name is unaffected by the addressing split —
    /// its L3 config stays on the flat `InterfaceOp`, regardless of the
    /// bare-name-implies-tag-0 rule that applies to every other interface.
    #[test]
    fn set_interface_address_loopback_stays_flat() {
        let address: ipnet::IpNet = "10.0.0.1/24".parse().unwrap();
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceAddress {
                    name: "loopback-rt1".to_string(),
                    address,
                    label: None,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::AddAddress {
                    name: "loopback-rt1".to_string(),
                    address,
                    label: None,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_interface_routing_table_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceRoutingTable {
                    name: "eth0".to_string(),
                    routing_table: "rt1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
                    interface: "eth0".to_string(),
                    tag: 0,
                    routing_table: "rt1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceRoutingTableRelative {
                    routing_table: "rt1".to_string()
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Set(SetTarget::InterfaceRoutingTableRelative {
                    routing_table: "rt1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
                    interface: "eth0".to_string(),
                    tag: 0,
                    routing_table: "rt1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert_eq!(
            resolve(
                &config_mode(
                    "t1",
                    Path::Subinterface {
                        interface: "eth0".to_string(),
                        tag: 300
                    },
                    false
                ),
                Command::Set(SetTarget::InterfaceRoutingTableRelative {
                    routing_table: "rt1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
                    interface: "eth0".to_string(),
                    tag: 300,
                    routing_table: "rt1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_interface_switching_profile_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceSwitchingProfile {
                    name: "eth0".to_string(),
                    switching_profile: "sp1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetSwitchingProfile {
                    name: "eth0".to_string(),
                    switching_profile: "sp1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceSwitchingProfileRelative {
                    switching_profile: "sp1".to_string()
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Set(SetTarget::InterfaceSwitchingProfileRelative {
                    switching_profile: "sp1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetSwitchingProfile {
                    name: "eth0".to_string(),
                    switching_profile: "sp1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_interface_mtu_qualified() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceMtu {
                    name: "eth0".to_string(),
                    mtu: 9000,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetMtu {
                    name: "eth0".to_string(),
                    mtu: 9000,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_mtu_relative_dispatches_by_path() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::MtuRelative(9000))
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Set(SetTarget::MtuRelative(9000))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetMtu {
                    name: "eth0".to_string(),
                    mtu: 9000,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode(
                    "t1",
                    Path::OspfProfile {
                        instance: "o1".to_string(),
                        area_id: "0.0.0.0".parse().unwrap(),
                        name: "p1".to_string(),
                    },
                    false
                ),
                Command::Set(SetTarget::MtuRelative(1400))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::SetMtu {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    mtu: 1400,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_mtu_relative_dispatches_by_path() {
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::MtuRelative)
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Delete(DeleteTarget::MtuRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::ClearMtu {
                    name: "eth0".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode(
                    "t1",
                    Path::OspfProfile {
                        instance: "o1".to_string(),
                        area_id: "0.0.0.0".parse().unwrap(),
                        name: "p1".to_string(),
                    },
                    false
                ),
                Command::Delete(DeleteTarget::MtuRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfProfile(OspfProfileOp::ClearMtu {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_current_at_interface_returns_to_root() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::Delete {
                    name: "eth0".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
    }

    #[test]
    fn delete_interface_qualified() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::Interface {
                    name: "eth0".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::Delete {
                    name: "eth0".to_string()
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_interface_address_qualified_and_relative() {
        let address: ipnet::IpNet = "10.0.0.1/24".parse().unwrap();
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::InterfaceAddress {
                    name: "eth0".to_string(),
                    address,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::RemoveAddress {
                    interface: "eth0".to_string(),
                    tag: 0,
                    address,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Delete(DeleteTarget::InterfaceAddressRelative { address })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::RemoveAddress {
                    interface: "eth0".to_string(),
                    tag: 0,
                    address,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode(
                    "t1",
                    Path::Subinterface {
                        interface: "eth0".to_string(),
                        tag: 100
                    },
                    false
                ),
                Command::Delete(DeleteTarget::InterfaceAddressRelative { address })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::RemoveAddress {
                    interface: "eth0".to_string(),
                    tag: 100,
                    address,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_interface_routing_table_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::InterfaceRoutingTable {
                    name: "eth0".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::ClearRoutingTable {
                    interface: "eth0".to_string(),
                    tag: 0,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Delete(DeleteTarget::InterfaceRoutingTableRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::ClearRoutingTable {
                    interface: "eth0".to_string(),
                    tag: 0,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    /// `delete interface <name>.<tag>` deletes just that subinterface;
    /// `DeleteTarget::Current` from inside `Path::Subinterface` does the
    /// same and returns to the owning physical interface's path (not root).
    #[test]
    fn delete_subinterface_qualified_and_current() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::Interface {
                    name: "eth0.100".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::Delete {
                    interface: "eth0".to_string(),
                    tag: 100,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode(
                    "t1",
                    Path::Subinterface {
                        interface: "eth0".to_string(),
                        tag: 100
                    },
                    false
                ),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::Delete {
                    interface: "eth0".to_string(),
                    tag: 100,
                }),
                after: PathAfter::To(Path::Interface("eth0".to_string())),
            }
        );
    }

    #[test]
    fn delete_interface_switching_profile_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::InterfaceSwitchingProfile {
                    name: "eth0".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile {
                    name: "eth0".to_string()
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Delete(DeleteTarget::InterfaceSwitchingProfileRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile {
                    name: "eth0".to_string()
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn up_and_top_from_interface_navigate_to_root() {
        let mode = config_mode("t1", Path::Interface("eth0".to_string()), false);
        assert_eq!(resolve(&mode, Command::Up), Resolved::NavigateTop);
        assert_eq!(resolve(&mode, Command::Top), Resolved::NavigateTop);
    }

    #[test]
    fn edit_community_alias_group_and_prefix_list_navigate() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::CommunityAlias {
                    name: "a1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityAlias(CommunityAliasOp::Ensure {
                    name: "a1".to_string()
                }),
                after: PathAfter::To(Path::CommunityAlias("a1".to_string())),
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::CommunityGroup {
                    name: "g1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::Ensure {
                    name: "g1".to_string()
                }),
                after: PathAfter::To(Path::CommunityGroup("g1".to_string())),
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::PrefixList {
                    name: "l1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::Ensure {
                    name: "l1".to_string()
                }),
                after: PathAfter::To(Path::PrefixList("l1".to_string())),
            }
        );
    }

    #[test]
    fn set_community_alias_value_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::CommunityAliasValue {
                    name: "a1".to_string(),
                    value: "65000:100".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityAlias(CommunityAliasOp::SetValue {
                    name: "a1".to_string(),
                    value: "65000:100".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::CommunityAliasValueRelative {
                    value: "65000:100".to_string()
                })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::CommunityAlias("a1".to_string()), false),
                Command::Set(SetTarget::CommunityAliasValueRelative {
                    value: "65000:100".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityAlias(CommunityAliasOp::SetValue {
                    name: "a1".to_string(),
                    value: "65000:100".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_community_group_member_qualified_and_relative() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::CommunityGroupMember {
                    name: "g1".to_string(),
                    member: "a1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::AddMember {
                    name: "g1".to_string(),
                    member: "a1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        assert_eq!(
            resolve(
                &config_mode("t1", Path::CommunityGroup("g1".to_string()), false),
                Command::Set(SetTarget::CommunityGroupMemberRelative {
                    member: "a1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::AddMember {
                    name: "g1".to_string(),
                    member: "a1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_prefix_list_entry_qualified_and_relative() {
        let cidr: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::PrefixListEntry {
                    name: "l1".to_string(),
                    cidr,
                    range: Some((24, 32)),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::AddEntry {
                    name: "l1".to_string(),
                    entry: PrefixListEntry {
                        cidr,
                        range: Some((24, 32)),
                    },
                }),
                after: PathAfter::Stay,
            }
        );

        assert_eq!(
            resolve(
                &config_mode("t1", Path::PrefixList("l1".to_string()), false),
                Command::Set(SetTarget::PrefixListEntryRelative { cidr, range: None })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::AddEntry {
                    name: "l1".to_string(),
                    entry: PrefixListEntry { cidr, range: None },
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn delete_current_from_community_alias_group_and_prefix_list_go_to_root() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::CommunityAlias("a1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityAlias(CommunityAliasOp::Delete {
                    name: "a1".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::CommunityGroup("g1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::Delete {
                    name: "g1".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PrefixList("l1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::Delete {
                    name: "l1".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
    }

    #[test]
    fn delete_community_group_member_and_prefix_list_entry() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Delete(DeleteTarget::CommunityGroupMember {
                    name: "g1".to_string(),
                    member: "a1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::RemoveMember {
                    name: "g1".to_string(),
                    member: "a1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );

        let cidr: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PrefixList("l1".to_string()), false),
                Command::Delete(DeleteTarget::PrefixListEntryRelative { cidr, range: None })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::RemoveEntry {
                    name: "l1".to_string(),
                    entry: PrefixListEntry { cidr, range: None },
                }),
                after: PathAfter::Stay,
            }
        );
    }

    fn ospfv3_profile_path(instance: &str, area_id: &str, name: &str) -> Path {
        Path::Ospfv3Profile {
            instance: instance.to_string(),
            area_id: area_id.parse().unwrap(),
            name: name.to_string(),
        }
    }

    #[test]
    fn edit_ospfv3_instance_area_profile_qualified_navigates() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::Ospfv3Instance {
                    name: "o1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::Ensure {
                    name: "o1".to_string()
                }),
                after: PathAfter::To(Path::Ospfv3Instance("o1".to_string())),
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::Ospfv3Profile {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::Ensure {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::To(ospfv3_profile_path("o1", "0.0.0.0", "p1")),
            }
        );
    }

    /// `edit area <area-id>` is the same `Command` regardless of whether the
    /// user is navigated into an OSPF or an `OSPFv3` instance — the
    /// riskiest part of the shared-token design, so it gets its own test.
    #[test]
    fn edit_area_relative_dispatches_between_ospf_and_ospfv3_instance() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::OspfInstance("o1".to_string()), false),
                Command::Edit(EditTarget::OspfAreaRelative {
                    area_id: "0.0.0.0".parse().unwrap(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::OspfArea(OspfAreaOp::Ensure {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                }),
                after: PathAfter::To(Path::OspfArea {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                }),
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Ospfv3Instance("o1".to_string()), false),
                Command::Edit(EditTarget::OspfAreaRelative {
                    area_id: "0.0.0.0".parse().unwrap(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Area(Ospfv3AreaOp::Ensure {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                }),
                after: PathAfter::To(Path::Ospfv3Area {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                }),
            }
        );
        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::OspfAreaRelative {
                    area_id: "0.0.0.0".parse().unwrap(),
                })
            ),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn set_router_id_relative_dispatches_to_ospfv3_instance() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Ospfv3Instance("o1".to_string()), false),
                Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::RouterId("2.2.2.2".parse().unwrap()),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::SetRouterId {
                    name: "o1".to_string(),
                    router_id: "2.2.2.2".parse().unwrap(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    /// `set ospfv3 instance <name> ... hello-interval <n>` (qualified) and
    /// its shared-token relative form both dispatch to `Ospfv3ProfileOp`;
    /// an auth field on the shared relative token is rejected instead of
    /// silently landing on the wrong daemon's op.
    #[test]
    fn set_ospfv3_profile_fields_qualified_relative_and_rejects_auth() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::Ospfv3Profile {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    field: OspfProfileField::HelloInterval(5),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetHelloInterval {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    hello_interval: 5,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospfv3_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Set(SetTarget::OspfProfileRelative {
                    field: OspfProfileField::Cost(20),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetCost {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                    cost: 20,
                }),
                after: PathAfter::Stay,
            }
        );
        assert!(matches!(
            resolve(
                &config_mode("t1", ospfv3_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Set(SetTarget::OspfProfileRelative {
                    field: OspfProfileField::SimplePassword("secret".to_string()),
                })
            ),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn delete_current_on_ospfv3_instance_area_and_profile() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Ospfv3Instance("o1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::Delete {
                    name: "o1".to_string()
                }),
                after: PathAfter::ToRoot,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", ospfv3_profile_path("o1", "0.0.0.0", "p1"), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::Delete {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                    name: "p1".to_string(),
                }),
                after: PathAfter::To(Path::Ospfv3Area {
                    instance: "o1".to_string(),
                    area_id: "0.0.0.0".parse().unwrap(),
                }),
            }
        );
    }

    #[test]
    fn set_and_delete_routing_table_ospfv3_instance() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::RoutingTable("rt1".to_string()), false),
                Command::Set(SetTarget::RoutingTableOspfv3InstanceRelative {
                    ospfv3_instance: "o1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetOspfv3Instance {
                    name: "rt1".to_string(),
                    ospfv3_instance: "o1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::RoutingTable("rt1".to_string()), false),
                Command::Delete(DeleteTarget::RoutingTableOspfv3InstanceRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearOspfv3Instance {
                    name: "rt1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn show_ospfv3_neigh_and_database_work_in_any_mode() {
        assert_eq!(
            resolve(&Mode::Operational, Command::ShowOspfv3Neigh),
            Resolved::ShowOspfv3Neigh
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowOspfv3Database
            ),
            Resolved::ShowOspfv3Database
        );
    }

    #[test]
    fn edit_port_aggregate_ensures_and_navigates() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Edit(EditTarget::PortAggregate {
                    name: "bond1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PortAggregate(nos_proto::PortAggregateOp::Ensure {
                    name: "bond1".to_string(),
                    mode: nos_proto::PortAggregateMode::Xor,
                }),
                after: PathAfter::To(Path::PortAggregate("bond1".to_string())),
            }
        );
    }

    #[test]
    fn set_port_aggregate_mode_relative_requires_navigation() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::PortAggregateModeRelative {
                    mode: nos_proto::PortAggregateMode::Xor,
                })
            ),
            Resolved::Error(NO_CURRENT_PORT_AGGREGATE.to_string())
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PortAggregate("bond1".to_string()), false),
                Command::Set(SetTarget::PortAggregateModeRelative {
                    mode: nos_proto::PortAggregateMode::Xor,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PortAggregate(nos_proto::PortAggregateOp::SetMode {
                    name: "bond1".to_string(),
                    mode: nos_proto::PortAggregateMode::Xor,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn set_and_clear_interface_port_aggregate() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Set(SetTarget::InterfacePortAggregateRelative {
                    port_aggregate: "bond1".to_string(),
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetPortAggregate {
                    name: "eth0".to_string(),
                    port_aggregate: "bond1".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Delete(DeleteTarget::InterfacePortAggregateRelative)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::ClearPortAggregate {
                    name: "eth0".to_string(),
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn bare_delete_on_port_aggregate_returns_to_root() {
        assert_eq!(
            resolve(
                &config_mode("t1", Path::PortAggregate("bond1".to_string()), false),
                Command::Delete(DeleteTarget::Current)
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PortAggregate(nos_proto::PortAggregateOp::Delete {
                    name: "bond1".to_string(),
                }),
                after: PathAfter::ToRoot,
            }
        );
    }

    #[test]
    fn show_lldp_neighbors_works_in_any_mode() {
        assert_eq!(
            resolve(&Mode::Operational, Command::ShowLldpNeighbors),
            Resolved::ShowLldpNeighbors
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowLldpNeighbors
            ),
            Resolved::ShowLldpNeighbors
        );
    }

    #[test]
    fn set_and_delete_lldp_resolve_to_interface_ops() {
        let root = config_mode("t1", Path::Root, false);
        assert_eq!(
            resolve(
                &root,
                Command::Set(SetTarget::InterfaceLldp {
                    name: "eth1".to_string(),
                    direction: LldpDirection::Transmit,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetLldpTransmit {
                    name: "eth1".to_string(),
                    enabled: true,
                }),
                after: PathAfter::Stay,
            }
        );
        let in_interface = config_mode("t1", Path::Interface("eth1".to_string()), false);
        assert_eq!(
            resolve(
                &in_interface,
                Command::Delete(DeleteTarget::InterfaceLldpRelative {
                    direction: LldpDirection::Receive,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetLldpReceive {
                    name: "eth1".to_string(),
                    enabled: false,
                }),
                after: PathAfter::Stay,
            }
        );
        // The relative form needs a current interface.
        assert!(matches!(
            resolve(
                &root,
                Command::Set(SetTarget::InterfaceLldpRelative {
                    direction: LldpDirection::Transmit,
                })
            ),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn lldp_destination_and_system_settings_resolve_to_ops() {
        let root = config_mode("t1", Path::Root, false);
        assert_eq!(
            resolve(
                &root,
                Command::Set(SetTarget::Lldp(LldpSetting::TxInterval(5)))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Lldp(LldpOp::SetTxInterval { secs: 5 }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &root,
                Command::Delete(DeleteTarget::Lldp(LldpSettingKind::ManagementAddress))
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Lldp(LldpOp::ClearManagementAddress),
                after: PathAfter::Stay,
            }
        );
        let in_interface = config_mode("t1", Path::Interface("eth1".to_string()), false);
        assert_eq!(
            resolve(
                &in_interface,
                Command::Set(SetTarget::InterfaceLldpDestinationRelative {
                    destination: nos_proto::LldpDestination::NonTpmr,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetLldpDestination {
                    name: "eth1".to_string(),
                    destination: nos_proto::LldpDestination::NonTpmr,
                }),
                after: PathAfter::Stay,
            }
        );
        assert_eq!(
            resolve(
                &root,
                Command::Delete(DeleteTarget::InterfaceLldpDestination {
                    name: "eth1".to_string()
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::ClearLldpDestination {
                    name: "eth1".to_string()
                }),
                after: PathAfter::Stay,
            }
        );
        assert!(matches!(
            resolve(
                &root,
                Command::Delete(DeleteTarget::InterfaceLldpDestinationRelative)
            ),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn show_lacp_works_in_any_mode() {
        assert_eq!(
            resolve(&Mode::Operational, Command::ShowLacp { name: None }),
            Resolved::ShowLacp { name: None }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowLacp {
                    name: Some("bond1".to_string()),
                }
            ),
            Resolved::ShowLacp {
                name: Some("bond1".to_string()),
            }
        );
    }

    #[test]
    fn set_lacp_rate_resolves_to_a_port_aggregate_op() {
        let mode = config_mode("t1", Path::PortAggregate("bond1".to_string()), false);
        assert_eq!(
            resolve(
                &mode,
                Command::Set(SetTarget::PortAggregateLacpRateRelative {
                    rate: nos_proto::LacpRate::Fast,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::PortAggregate(PortAggregateOp::SetLacpRate {
                    name: "bond1".to_string(),
                    rate: nos_proto::LacpRate::Fast,
                }),
                after: PathAfter::Stay,
            }
        );
    }

    #[test]
    fn redundancy_mode_resolves_relative_and_qualified() {
        let mode = config_mode("t1", Path::PortAggregate("bond1".to_string()), false);
        let op = ConfigOp::PortAggregate(PortAggregateOp::SetRedundancyMode {
            name: "bond1".to_string(),
            mode: nos_proto::EsRedundancy::SingleActive,
        });
        for cmd in [
            SetTarget::PortAggregateRedundancyModeRelative {
                mode: nos_proto::EsRedundancy::SingleActive,
            },
            SetTarget::PortAggregateRedundancyMode {
                name: "bond1".to_string(),
                mode: nos_proto::EsRedundancy::SingleActive,
            },
        ] {
            assert_eq!(
                resolve(&mode, Command::Set(cmd)),
                Resolved::ApplyOp {
                    op: op.clone(),
                    after: PathAfter::Stay,
                }
            );
        }
    }

    #[test]
    fn relative_esi_and_lacp_system_id_resolve_against_the_current_aggregate() {
        let mode = config_mode("t1", Path::PortAggregate("bond1".to_string()), false);
        let esi = "00:11:22:33:44:55:66:77:88:99".to_string();
        for (cmd, op) in [
            (
                Command::Set(SetTarget::PortAggregateEsiRelative { esi: esi.clone() }),
                PortAggregateOp::SetEsi {
                    name: "bond1".to_string(),
                    esi,
                },
            ),
            (
                Command::Delete(DeleteTarget::PortAggregateEsiRelative),
                PortAggregateOp::ClearEsi {
                    name: "bond1".to_string(),
                },
            ),
            (
                Command::Set(SetTarget::PortAggregateLacpSystemIdRelative {
                    system_id: "02:00:00:00:00:01".to_string(),
                }),
                PortAggregateOp::SetLacpSystemId {
                    name: "bond1".to_string(),
                    system_id: "02:00:00:00:00:01".to_string(),
                },
            ),
            (
                Command::Delete(DeleteTarget::PortAggregateLacpSystemIdRelative),
                PortAggregateOp::ClearLacpSystemId {
                    name: "bond1".to_string(),
                },
            ),
        ] {
            assert_eq!(
                resolve(&mode, cmd),
                Resolved::ApplyOp {
                    op: ConfigOp::PortAggregate(op),
                    after: PathAfter::Stay,
                }
            );
        }
    }

    #[test]
    fn show_port_aggregate_works_in_any_mode() {
        assert_eq!(
            resolve(
                &Mode::Operational,
                Command::ShowPortAggregate { name: None }
            ),
            Resolved::ShowPortAggregate { name: None }
        );
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::ShowPortAggregate {
                    name: Some("bond1".to_string()),
                }
            ),
            Resolved::ShowPortAggregate {
                name: Some("bond1".to_string()),
            }
        );
    }
}
