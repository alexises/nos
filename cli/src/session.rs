use std::net::IpAddr;

use nos_proto::{
    BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp, ConfigOp, InterfaceOp, RoutingTableOp, StaticRouteOp,
    StaticRoutingInstanceOp, TransactionBase,
};

use crate::command::{
    BgpInstanceField, BgpPeerGroupField, Command, DeleteTarget, EditTarget, SetTarget,
};

/// Navigation position within the transaction's config tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path {
    Root,
    BgpInstance(String),
    BgpPeerGroup { instance: String, group: String },
    RoutingTable(String),
    StaticRoutingInstance(String),
    Interface(String),
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
    /// `show interface` (every interface) or `show interface <name>` (one)
    /// — data-plane, valid in any mode.
    ShowInterface {
        name: Option<String>,
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
    Error(String),
}

pub fn resolve(mode: &Mode, cmd: Command) -> Resolved {
    match cmd {
        Command::Empty => Resolved::Nothing,
        Command::Help => Resolved::Help,
        Command::ShowConfig => Resolved::ShowRunningConfig,
        Command::ShowRoute { table, address } => Resolved::ShowRoute { table, address },
        Command::ShowInterface { name } => Resolved::ShowInterface { name },
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

/// Resolves a command that requires configuration mode, given the current
/// navigation `path`. Never called with `Command::Configure`, `Empty`,
/// `Help`, `ShowConfig`, `Unknown`, `Exit`, or `Save` — `resolve` handles
/// those itself before delegating here.
const NO_CURRENT_INSTANCE: &str = "no current instance — use 'edit bgp instance <name>' or the fully-qualified 'set bgp instance <name> ...' form";
const NO_CURRENT_PEER_GROUP: &str =
    "no current peer-group — use 'edit peer-group <name>' or the fully-qualified 'set bgp instance <name> peer-group <group> ...' form";
const NO_CURRENT_ROUTING_TABLE: &str = "no current routing table — use 'edit routing-table <name>' or the fully-qualified 'set routing-table <name> ...' form";
const NO_CURRENT_STATIC_ROUTING_INSTANCE: &str = "no current static routing instance — use 'edit static-routing-instance <name>' or the fully-qualified 'set static-routing-instance <name> ...' form";
const NO_CURRENT_INTERFACE: &str = "no current interface — use 'edit interface <name>' or the fully-qualified 'set interface <name> ...' form";

fn resolve_in_transaction(path: &Path, cmd: Command) -> Resolved {
    match cmd {
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
        Command::Edit(EditTarget::PeerGroupRelative { name }) => match path {
            Path::BgpInstance(instance) => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Ensure {
                    instance: instance.clone(),
                    name: name.clone(),
                }),
                after: PathAfter::To(Path::BgpPeerGroup {
                    instance: instance.clone(),
                    group: name,
                }),
            },
            Path::Root
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
        },
        Command::Edit(EditTarget::RoutingTable { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::RoutingTable(name)),
        },
        Command::Edit(EditTarget::StaticRoutingInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Ensure {
                name: name.clone(),
            }),
            after: PathAfter::To(Path::StaticRoutingInstance(name)),
        },
        Command::Edit(EditTarget::Interface { name }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::Interface(name)),
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
        Command::Set(SetTarget::Relative { field }) => match path {
            Path::BgpInstance(name) => Resolved::ApplyOp {
                op: set_op(name.clone(), field),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
        },
        Command::Set(SetTarget::BgpPeerGroup {
            instance,
            group,
            field,
        }) => Resolved::ApplyOp {
            op: peer_group_set_op(instance, group, field),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PeerGroupRelative { field }) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: peer_group_set_op(instance.clone(), group.clone(), field),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
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
        }) => match path {
            Path::BgpInstance(instance) => Resolved::ApplyOp {
                op: ConfigOp::BgpPeer(BgpPeerOp::Set {
                    instance: instance.clone(),
                    remote_address,
                    peer_group,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
        },
        Command::Set(SetTarget::RoutingTable { name, bgp_instance }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance { name, bgp_instance }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::RoutingTableRelative { bgp_instance }) => match path {
            Path::RoutingTable(name) => Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance {
                    name: name.clone(),
                    bgp_instance,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
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
        }) => match path {
            Path::RoutingTable(name) => Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetStaticRoutingInstance {
                    name: name.clone(),
                    static_routing_instance,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
        },
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
        Command::Set(SetTarget::StaticRouteRelative { subnet, gateway }) => match path {
            Path::StaticRoutingInstance(instance) => Resolved::ApplyOp {
                op: ConfigOp::StaticRoute(StaticRouteOp::Set {
                    instance: instance.clone(),
                    subnet,
                    gateway,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_STATIC_ROUTING_INSTANCE.to_string()),
        },
        Command::Set(SetTarget::InterfaceAddress { name, address }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::AddAddress { name, address }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceAddressRelative { address }) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::AddAddress {
                    name: name.clone(),
                    address,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
        },
        Command::Set(SetTarget::InterfaceRoutingTable {
            name,
            routing_table,
        }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::SetRoutingTable {
                name,
                routing_table,
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceRoutingTableRelative { routing_table }) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::SetRoutingTable {
                    name: name.clone(),
                    routing_table,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
        },

        Command::Delete(DeleteTarget::BgpInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpInstance(BgpInstanceOp::Delete { name }),
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
        Command::Delete(DeleteTarget::RoutingTableBgpInstanceRelative) => match path {
            Path::RoutingTable(name) => Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearBgpInstance { name: name.clone() }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
        },
        Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstance { name }) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearStaticRoutingInstance { name }),
                after: PathAfter::Stay,
            }
        }
        Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstanceRelative) => match path {
            Path::RoutingTable(name) => Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearStaticRoutingInstance {
                    name: name.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
        },
        Command::Delete(DeleteTarget::StaticRoutingInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::StaticRoute { instance, subnet }) => Resolved::ApplyOp {
            op: ConfigOp::StaticRoute(StaticRouteOp::Delete { instance, subnet }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::StaticRouteRelative { subnet }) => match path {
            Path::StaticRoutingInstance(instance) => Resolved::ApplyOp {
                op: ConfigOp::StaticRoute(StaticRouteOp::Delete {
                    instance: instance.clone(),
                    subnet,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_STATIC_ROUTING_INSTANCE.to_string()),
        },
        Command::Delete(DeleteTarget::Interface { name }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::Delete { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceAddress { name, address }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::RemoveAddress { name, address }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceAddressRelative { address }) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::RemoveAddress {
                    name: name.clone(),
                    address,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
        },
        Command::Delete(DeleteTarget::InterfaceRoutingTable { name }) => Resolved::ApplyOp {
            op: ConfigOp::Interface(InterfaceOp::ClearRoutingTable { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceRoutingTableRelative) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::ClearRoutingTable { name: name.clone() }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
        },
        Command::Delete(DeleteTarget::BgpPeerGroup { instance, name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Delete { instance, name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::PeerGroupRelative { name }) => match path {
            Path::BgpInstance(instance) => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Delete {
                    instance: instance.clone(),
                    name,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
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
        Command::Delete(DeleteTarget::PeerRelative { remote_address }) => match path {
            Path::BgpInstance(instance) => Resolved::ApplyOp {
                op: ConfigOp::BgpPeer(BgpPeerOp::Delete {
                    instance: instance.clone(),
                    remote_address,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
        },
        Command::Delete(DeleteTarget::SourceAddress) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearSourceAddress {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::AddressFamily(af)) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::RemoveAddressFamily {
                    instance: instance.clone(),
                    name: group.clone(),
                    af,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },

        // `top` always lands at the root, however deep the current path is.
        Command::Top => match path {
            Path::Root => Resolved::Error("already at the top level".to_string()),
            Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::NavigateTop,
        },
        // `up` moves exactly one level — from an instance that's the root
        // (coinciding with `top`), but from a peer-group it's the owning
        // instance, not the root. Routing tables, static routing instances,
        // and interfaces have no navigable child (routes/addresses aren't a
        // `Path` position), so they behave like a BGP instance here.
        Command::Up => match path {
            Path::Root => Resolved::Error("already at the top level".to_string()),
            Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_) => Resolved::NavigateTop,
            Path::BgpPeerGroup { instance, .. } => {
                Resolved::Navigate(Path::BgpInstance(instance.clone()))
            }
        },

        Command::Commit => Resolved::Commit,
        Command::Discard => Resolved::Discard,
        Command::Diff => Resolved::Diff,

        Command::Configure { .. }
        | Command::Empty
        | Command::Help
        | Command::ShowConfig
        | Command::ShowRoute { .. }
        | Command::ShowInterface { .. }
        | Command::Unknown(_)
        | Command::Exit
        | Command::Save => {
            unreachable!("resolve() handles these before delegating to resolve_in_transaction")
        }
    }
}

fn set_op(name: String, field: BgpInstanceField) -> ConfigOp {
    ConfigOp::BgpInstance(match field {
        BgpInstanceField::Asn(asn) => BgpInstanceOp::SetAsn { name, asn },
        BgpInstanceField::RouterId(router_id) => BgpInstanceOp::SetRouterId { name, router_id },
    })
}

fn peer_group_set_op(instance: String, group: String, field: BgpPeerGroupField) -> ConfigOp {
    ConfigOp::BgpPeerGroup(match field {
        BgpPeerGroupField::RemoteAs(remote_as) => BgpPeerGroupOp::SetRemoteAs {
            instance,
            name: group,
            remote_as,
        },
        BgpPeerGroupField::SourceAddress(address) => BgpPeerGroupOp::SetSourceAddress {
            instance,
            name: group,
            address,
        },
        BgpPeerGroupField::AddressFamily(af) => BgpPeerGroupOp::AddAddressFamily {
            instance,
            name: group,
            af,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

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

    #[test]
    fn set_interface_address_qualified_and_relative() {
        let address: ipnet::IpNet = "10.0.0.1/24".parse().unwrap();
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceAddress {
                    name: "eth0".to_string(),
                    address,
                })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::AddAddress {
                    name: "eth0".to_string(),
                    address,
                }),
                after: PathAfter::Stay,
            }
        );

        assert!(matches!(
            resolve(
                &config_mode("t1", Path::Root, false),
                Command::Set(SetTarget::InterfaceAddressRelative { address })
            ),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(
                &config_mode("t1", Path::Interface("eth0".to_string()), false),
                Command::Set(SetTarget::InterfaceAddressRelative { address })
            ),
            Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::AddAddress {
                    name: "eth0".to_string(),
                    address,
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
                op: ConfigOp::Interface(InterfaceOp::SetRoutingTable {
                    name: "eth0".to_string(),
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
                op: ConfigOp::Interface(InterfaceOp::SetRoutingTable {
                    name: "eth0".to_string(),
                    routing_table: "rt1".to_string(),
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
                op: ConfigOp::Interface(InterfaceOp::RemoveAddress {
                    name: "eth0".to_string(),
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
                op: ConfigOp::Interface(InterfaceOp::RemoveAddress {
                    name: "eth0".to_string(),
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
                op: ConfigOp::Interface(InterfaceOp::ClearRoutingTable {
                    name: "eth0".to_string()
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
                op: ConfigOp::Interface(InterfaceOp::ClearRoutingTable {
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
}
