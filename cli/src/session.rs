use nos_proto::{BgpInstanceOp, ConfigOp, TransactionBase};

use crate::command::{BgpInstanceField, Command, DeleteTarget, EditTarget, SetTarget};

/// Navigation position within the transaction's config tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path {
    Root,
    BgpInstance(String),
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
    ShowRunningConfig,
    /// Bare `show` in configuration mode — fetch the transaction and render
    /// it at the current path.
    ShowTransaction,
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
    Error(String),
}

pub fn resolve(mode: &Mode, cmd: Command) -> Resolved {
    match cmd {
        Command::Empty => Resolved::Nothing,
        Command::Help => Resolved::Help,
        Command::ShowConfig => Resolved::ShowRunningConfig,
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
fn resolve_in_transaction(path: &Path, cmd: Command) -> Resolved {
    match cmd {
        Command::Show => Resolved::ShowTransaction,

        Command::Edit(EditTarget::BgpInstance { name }) => Resolved::ApplyOp {
            op: ConfigOp::BgpInstance(BgpInstanceOp::Ensure { name: name.clone() }),
            after: PathAfter::To(Path::BgpInstance(name)),
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
            Path::Root => Resolved::Error(
                "no current instance — use 'edit bgp instance <name>' or the fully-qualified 'set bgp instance <name> ...' form".to_string(),
            ),
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
            Path::Root => Resolved::Error(
                "nothing to delete at the top level — use 'delete bgp instance <name>'".to_string(),
            ),
        },

        // Only one level of nesting exists today, so Up and Top coincide.
        Command::Up | Command::Top => match path {
            Path::Root => Resolved::Error("already at the top level".to_string()),
            Path::BgpInstance(_) => Resolved::NavigateTop,
        },

        Command::Commit => Resolved::Commit,
        Command::Discard => Resolved::Discard,

        Command::Configure { .. }
        | Command::Empty
        | Command::Help
        | Command::ShowConfig
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
    fn bare_show_requires_configuration_mode() {
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
    fn unknown_command_errors() {
        assert!(matches!(
            resolve(
                &Mode::Operational,
                Command::Unknown("frobnicate".to_string())
            ),
            Resolved::Error(_)
        ));
    }
}
