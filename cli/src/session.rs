use std::net::IpAddr;

use nos_proto::{
    loopback_table_name, BgpAoKey, BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp, BroadcastDomainOp,
    CommunityAliasOp, CommunityGroupOp, ConfigOp, InterfaceOp, PolicyDefinitionOp, PrefixListEntry,
    PrefixListOp, RoutingTableOp, StaticRouteOp, StaticRoutingInstanceOp, SubinterfaceOp,
    SwitchingProfileOp, TransactionBase,
};

use crate::command::{
    BgpInstanceField, BgpPeerGroupField, Command, DeleteTarget, EditTarget, SetTarget,
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
    /// `show interface` (every interface) or `show interface <name>` (one)
    /// — data-plane, valid in any mode.
    ShowInterface {
        name: Option<String>,
    },
    /// `show log [<source>] [--follow]` — data-plane, valid in any mode.
    ShowLog {
        source: Option<String>,
        follow: bool,
    },
    /// `show bgp brief` — data-plane, valid in any mode. Router-wide (no
    /// instance argument): the caller iterates every `BgpInstance` in the
    /// running config itself.
    ShowBgpBrief,
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
        Command::ShowInterface { name } => Resolved::ShowInterface { name },
        Command::ShowLog { source, follow } => Resolved::ShowLog { source, follow },
        Command::ShowBgpBrief => Resolved::ShowBgpBrief,
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

/// Resolves a command that requires configuration mode, given the current
/// navigation `path`. Never called with `Command::Configure`, `Empty`,
/// `Help`, `ShowConfig`, `Unknown`, `Exit`, or `Save` — `resolve` handles
/// those itself before delegating here.
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
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
        Command::EditSource => match path {
            Path::PolicyDefinition(name) => Resolved::EditPolicySource { name: name.clone() },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => {
                Resolved::Error(NO_CURRENT_POLICY_DEFINITION.to_string())
            }
        },
        Command::ShowSource => match path {
            Path::PolicyDefinition(name) => Resolved::ShowPolicySource { name: name.clone() },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => {
                Resolved::Error(NO_CURRENT_POLICY_DEFINITION.to_string())
            }
        },
        Command::SetSourceLine { line, text } => match path {
            Path::PolicyDefinition(name) => Resolved::SetPolicySourceLine {
                name: name.clone(),
                line,
                text,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => {
                Resolved::Error(NO_CURRENT_POLICY_DEFINITION.to_string())
            }
        },
        Command::DeleteSourceLine { line } => match path {
            Path::PolicyDefinition(name) => Resolved::DeletePolicySourceLine {
                name: name.clone(),
                line,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => {
                Resolved::Error(NO_CURRENT_POLICY_DEFINITION.to_string())
            }
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
        },
        Command::Set(SetTarget::RoutingTableRedistribute { name, redistribute }) => {
            Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute { name, redistribute }),
                after: PathAfter::Stay,
            }
        }
        Command::Set(SetTarget::RoutingTableRedistributeRelative { redistribute }) => match path {
            Path::RoutingTable(name) => Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
                    name: name.clone(),
                    redistribute,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => {
                Resolved::Error(NO_CURRENT_STATIC_ROUTING_INSTANCE.to_string())
            }
        },
        Command::Set(SetTarget::InterfaceAddress {
            name,
            address,
            label,
        }) => Resolved::ApplyOp {
            op: interface_add_address_op(&name, address, label),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceAddressRelative { address, label }) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: interface_add_address_op(name, address, label),
                after: PathAfter::Stay,
            },
            Path::Subinterface { interface, tag } => Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
                    interface: interface.clone(),
                    tag: *tag,
                    address,
                    label,
                }),
                after: PathAfter::Stay,
            },
            Path::BroadcastDomain(name) => Resolved::ApplyOp {
                op: ConfigOp::BroadcastDomain(BroadcastDomainOp::AddAddress {
                    name: name.clone(),
                    address,
                    label,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
        },
        Command::Set(SetTarget::InterfaceRoutingTable {
            name,
            routing_table,
        }) => Resolved::ApplyOp {
            op: interface_set_routing_table_op(&name, routing_table),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::InterfaceRoutingTableRelative { routing_table }) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: interface_set_routing_table_op(name, routing_table),
                after: PathAfter::Stay,
            },
            Path::Subinterface { interface, tag } => Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
                    interface: interface.clone(),
                    tag: *tag,
                    routing_table,
                }),
                after: PathAfter::Stay,
            },
            Path::BroadcastDomain(name) => Resolved::ApplyOp {
                op: ConfigOp::BroadcastDomain(BroadcastDomainOp::SetRoutingTable {
                    name: name.clone(),
                    routing_table,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
        },
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
            match path {
                Path::Interface(name) => Resolved::ApplyOp {
                    op: ConfigOp::Interface(InterfaceOp::SetSwitchingProfile {
                        name: name.clone(),
                        switching_profile,
                    }),
                    after: PathAfter::Stay,
                },
                Path::Root
                | Path::BgpInstance(_)
                | Path::BgpPeerGroup { .. }
                | Path::RoutingTable(_)
                | Path::StaticRoutingInstance(_)
                | Path::Subinterface { .. }
                | Path::PolicyDefinition(_)
                | Path::CommunityAlias(_)
                | Path::CommunityGroup(_)
                | Path::PrefixList(_)
                | Path::BroadcastDomain(_)
                | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
            }
        }

        Command::Set(SetTarget::CommunityAliasValue { name, value }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityAlias(CommunityAliasOp::SetValue { name, value }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::CommunityAliasValueRelative { value }) => match path {
            Path::CommunityAlias(name) => Resolved::ApplyOp {
                op: ConfigOp::CommunityAlias(CommunityAliasOp::SetValue {
                    name: name.clone(),
                    value,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_COMMUNITY_ALIAS.to_string()),
        },
        Command::Set(SetTarget::CommunityGroupMember { name, member }) => Resolved::ApplyOp {
            op: ConfigOp::CommunityGroup(CommunityGroupOp::AddMember { name, member }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::CommunityGroupMemberRelative { member }) => match path {
            Path::CommunityGroup(name) => Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::AddMember {
                    name: name.clone(),
                    member,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_COMMUNITY_GROUP.to_string()),
        },
        Command::Set(SetTarget::PrefixListEntry { name, cidr, range }) => Resolved::ApplyOp {
            op: ConfigOp::PrefixList(PrefixListOp::AddEntry {
                name,
                entry: PrefixListEntry { cidr, range },
            }),
            after: PathAfter::Stay,
        },
        Command::Set(SetTarget::PrefixListEntryRelative { cidr, range }) => match path {
            Path::PrefixList(name) => Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::AddEntry {
                    name: name.clone(),
                    entry: PrefixListEntry { cidr, range },
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PREFIX_LIST.to_string()),
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
        }) => match path {
            Path::SwitchingProfile(name) => Resolved::ApplyOp {
                op: ConfigOp::SwitchingProfile(SwitchingProfileOp::AddMember {
                    name: name.clone(),
                    broadcast_domain,
                    tag,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_) => Resolved::Error(NO_CURRENT_SWITCHING_PROFILE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
        },
        Command::Delete(DeleteTarget::RoutingTableRedistribute { name }) => Resolved::ApplyOp {
            op: ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::RoutingTableRedistributeRelative) => match path {
            Path::RoutingTable(name) => Resolved::ApplyOp {
                op: ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute {
                    name: name.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_ROUTING_TABLE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => {
                Resolved::Error(NO_CURRENT_STATIC_ROUTING_INSTANCE.to_string())
            }
        },
        Command::Delete(DeleteTarget::Interface { name }) => Resolved::ApplyOp {
            op: interface_delete_op(name),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceAddress { name, address }) => Resolved::ApplyOp {
            op: interface_remove_address_op(&name, address),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceAddressRelative { address }) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: interface_remove_address_op(name, address),
                after: PathAfter::Stay,
            },
            Path::Subinterface { interface, tag } => Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::RemoveAddress {
                    interface: interface.clone(),
                    tag: *tag,
                    address,
                }),
                after: PathAfter::Stay,
            },
            Path::BroadcastDomain(name) => Resolved::ApplyOp {
                op: ConfigOp::BroadcastDomain(BroadcastDomainOp::RemoveAddress {
                    name: name.clone(),
                    address,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
        },
        Command::Delete(DeleteTarget::InterfaceRoutingTable { name }) => Resolved::ApplyOp {
            op: interface_clear_routing_table_op(&name),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::InterfaceRoutingTableRelative) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: interface_clear_routing_table_op(name),
                after: PathAfter::Stay,
            },
            Path::Subinterface { interface, tag } => Resolved::ApplyOp {
                op: ConfigOp::Subinterface(SubinterfaceOp::ClearRoutingTable {
                    interface: interface.clone(),
                    tag: *tag,
                }),
                after: PathAfter::Stay,
            },
            Path::BroadcastDomain(name) => Resolved::ApplyOp {
                op: ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearRoutingTable {
                    name: name.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
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
        Command::Delete(DeleteTarget::InterfaceSwitchingProfileRelative) => match path {
            Path::Interface(name) => Resolved::ApplyOp {
                op: ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile { name: name.clone() }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INTERFACE.to_string()),
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
        Command::Delete(DeleteTarget::CommunityGroupMemberRelative { member }) => match path {
            Path::CommunityGroup(name) => Resolved::ApplyOp {
                op: ConfigOp::CommunityGroup(CommunityGroupOp::RemoveMember {
                    name: name.clone(),
                    member,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_COMMUNITY_GROUP.to_string()),
        },
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
        Command::Delete(DeleteTarget::PrefixListEntryRelative { cidr, range }) => match path {
            Path::PrefixList(name) => Resolved::ApplyOp {
                op: ConfigOp::PrefixList(PrefixListOp::RemoveEntry {
                    name: name.clone(),
                    entry: PrefixListEntry { cidr, range },
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PREFIX_LIST.to_string()),
        },
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
            match path {
                Path::SwitchingProfile(name) => Resolved::ApplyOp {
                    op: ConfigOp::SwitchingProfile(SwitchingProfileOp::RemoveMember {
                        name: name.clone(),
                        broadcast_domain,
                    }),
                    after: PathAfter::Stay,
                },
                Path::Root
                | Path::BgpInstance(_)
                | Path::BgpPeerGroup { .. }
                | Path::RoutingTable(_)
                | Path::StaticRoutingInstance(_)
                | Path::Interface(_)
                | Path::Subinterface { .. }
                | Path::PolicyDefinition(_)
                | Path::CommunityAlias(_)
                | Path::CommunityGroup(_)
                | Path::PrefixList(_)
                | Path::BroadcastDomain(_) => {
                    Resolved::Error(NO_CURRENT_SWITCHING_PROFILE.to_string())
                }
            }
        }
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
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
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::HoldTime) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearHoldTime {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::KeepaliveInterval) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearKeepaliveInterval {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::ConnectRetryTime) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearConnectRetryTime {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::Auth) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearAuth {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::AoKey(send_id)) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::RemoveAoKey {
                    instance: instance.clone(),
                    name: group.clone(),
                    send_id,
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::NextHop) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearNextHop {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::RouteReflectorClient) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearRouteReflectorClient {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::RouteServerClient) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearRouteServerClient {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::ImportPolicy) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearImportPolicy {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::ExportPolicy) => match path {
            Path::BgpPeerGroup { instance, group } => Resolved::ApplyOp {
                op: ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearExportPolicy {
                    instance: instance.clone(),
                    name: group.clone(),
                }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_PEER_GROUP.to_string()),
        },
        Command::Delete(DeleteTarget::BgpInstanceClusterId { name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpInstance(BgpInstanceOp::ClearClusterId { name }),
            after: PathAfter::Stay,
        },
        Command::Delete(DeleteTarget::BgpInstanceClusterIdRelative) => match path {
            Path::BgpInstance(name) => Resolved::ApplyOp {
                op: ConfigOp::BgpInstance(BgpInstanceOp::ClearClusterId { name: name.clone() }),
                after: PathAfter::Stay,
            },
            Path::Root
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::Error(NO_CURRENT_INSTANCE.to_string()),
        },

        // `top` always lands at the root, however deep the current path is.
        Command::Top => match path {
            Path::Root => Resolved::Error("already at the top level".to_string()),
            Path::BgpInstance(_)
            | Path::BgpPeerGroup { .. }
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::NavigateTop,
        },
        // `up` moves exactly one level — from an instance that's the root
        // (coinciding with `top`), but from a peer-group it's the owning
        // instance, not the root. Routing tables, static routing instances,
        // interfaces, and policy-definitions have no navigable child (routes/
        // addresses/source aren't a `Path` position), so they behave like a
        // BGP instance here.
        Command::Up => match path {
            Path::Root => Resolved::Error("already at the top level".to_string()),
            Path::BgpInstance(_)
            | Path::RoutingTable(_)
            | Path::StaticRoutingInstance(_)
            | Path::Interface(_)
            | Path::Subinterface { .. }
            | Path::PolicyDefinition(_)
            | Path::CommunityAlias(_)
            | Path::CommunityGroup(_)
            | Path::PrefixList(_)
            | Path::BroadcastDomain(_)
            | Path::SwitchingProfile(_) => Resolved::NavigateTop,
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
        | Command::ShowLog { .. }
        | Command::ShowBgpBrief
        | Command::ClearBgpSoftIn { .. }
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::{NextHopMode, Redistribute, RedistributeSource, RedistributeTarget};

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
}
