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

/// What kind of value an argument slot accepts — `BgpInstanceName` is the
/// one slot Tab-completion can fill from live daemon state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    Plain,
    BgpInstanceName,
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
        availability: Availability::ConfigurationInstance,
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
        tokens: &[Token::Literal("up")],
        usage: "up",
        doc: Doc::Local {
            summary: "Navigate back to the transaction root.",
            detail: "Moves the current navigation position up one level. Only one level of \
                     nesting exists today, so this always lands at the transaction root, \
                     same as `top`.",
        },
        availability: Availability::ConfigurationInstance,
    },
    CommandSpec {
        tokens: &[Token::Literal("top")],
        usage: "top",
        doc: Doc::Local {
            summary: "Navigate back to the transaction root.",
            detail: "Moves the current navigation position directly to the transaction \
                     root, regardless of how deep it is. Only one level of nesting exists \
                     today, so this is equivalent to `up`.",
        },
        availability: Availability::ConfigurationInstance,
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
    }

    #[test]
    fn operational_mode_hides_every_configuration_only_command() {
        for spec in COMMAND_SPECS {
            if matches!(
                spec.availability,
                Availability::Configuration | Availability::ConfigurationInstance
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
