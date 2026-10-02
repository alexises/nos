use std::net::IpAddr;

use crate::spec;
use nos_proto::TransactionBase;

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
    /// `show fdb <domain>` — one broadcast domain's forwarding database.
    ShowFdb {
        domain: String,
    },
    /// `show interface` (every interface) or `show interface <name>` (one).
    ShowInterface {
        name: Option<String>,
    },
    /// `show port-aggregate` (every aggregate) or `show port-aggregate
    /// <name>` (one).
    ShowPortAggregate {
        name: Option<String>,
    },
    /// `show lacp` (every aggregate) or `show lacp <name>` (one).
    ShowLacp {
        name: Option<String>,
    },
    /// `show lldp neighbors` — every LLDP neighbor heard on any interface.
    ShowLldpNeighbors,
    /// `show log [<source>] [--follow]` — a one-shot buffer snapshot,
    /// optionally filtered to one source, or a live tail with `--follow`.
    ShowLog {
        source: Option<String>,
        follow: bool,
    },
    /// `show bgp brief` — a one-line-per-peer session summary across every
    /// configured BGP instance.
    ShowBgpBrief,
    /// `show bgp evpn` — every EVPN route received by every configured BGP
    /// instance.
    ShowBgpEvpn,
    /// `show bgp rpki` — every configured BGP instance's RPKI cache sessions.
    ShowBgpRpki,
    /// `show ospf neigh` — a one-line-per-link neighbor summary across every
    /// configured OSPF instance.
    ShowOspfNeigh,
    /// `show ospf database` — every installed LSA's header, across every
    /// configured OSPF instance.
    ShowOspfDatabase,
    /// `show ospfv3 neigh` — mirrors `ShowOspfNeigh`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Neigh,
    /// `show ospfv3 database` — mirrors `ShowOspfDatabase`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Database,
    /// `clear bgp <instance> <peer> soft-in` — ask `<peer>`'s live session
    /// on `<instance>` to resend its routes (RFC 2918 route refresh).
    ClearBgpSoftIn {
        instance: String,
        peer: IpAddr,
    },
    /// `clear bgp <instance> <peer>` — release `<peer>`'s maximum-prefix
    /// hold and reset its session (Cease/Administrative Reset).
    ClearBgpPeer {
        instance: String,
        peer: IpAddr,
    },
    Save,
    Help,
    /// `exit` | `quit` | `end`
    Exit,
    Configure {
        name: String,
        /// `None` when `from ...` was omitted (defaults to `Current`).
        base: Option<TransactionBase>,
    },
    /// An `edit`/`set`/`delete` line, resolved against the config tree by
    /// `config_grammar` once the current position and config are known.
    Config(String),
    /// `edit source` — only valid while navigated into a policy-definition;
    /// opens `$EDITOR`/`$VISUAL`/`nano` on its current source. See root
    /// `CLAUDE.md`'s "nos-cli editing UX".
    EditSource,
    /// `show source` — only valid while navigated into a policy-definition.
    ShowSource,
    /// `set source line <n> <text>` — only valid while navigated into a
    /// policy-definition. `<text>` is the raw remainder of the line
    /// (leading whitespace preserved) since RPL's indentation is
    /// semantically meaningful — parsed outside the generic
    /// `split_whitespace()` matcher below, see `parse`'s doc comment.
    SetSourceLine {
        line: usize,
        text: String,
    },
    /// `delete source line <n>` — only valid while navigated into a
    /// policy-definition.
    DeleteSourceLine {
        line: usize,
    },
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
    /// Show and shell commands come from `spec::COMMAND_SPECS`' `cmd!` rows;
    /// any other `edit`/`set`/`delete` line is a config edit, left for
    /// `config_grammar` — which needs the current position and config — to
    /// resolve (#109).
    pub fn parse(line: &str) -> Self {
        let trimmed = line.trim();
        if let Some((_, command)) = spec::parse(trimmed) {
            return command.unwrap_or_else(|| Command::Unknown(trimmed.to_string()));
        }
        match trimmed.split_whitespace().next() {
            None => Command::Empty,
            Some("edit" | "set" | "delete") => Command::Config(trimmed.to_string()),
            Some(_) => Command::Unknown(trimmed.to_string()),
        }
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
    fn show_lldp_neighbors() {
        assert_eq!(
            Command::parse("show lldp neighbors"),
            Command::ShowLldpNeighbors
        );
        assert_eq!(
            Command::parse("show lldp"),
            Command::Unknown("show lldp".to_string())
        );
    }

    #[test]
    fn show_lacp() {
        assert_eq!(
            Command::parse("show lacp"),
            Command::ShowLacp { name: None }
        );
        assert_eq!(
            Command::parse("show lacp bond1"),
            Command::ShowLacp {
                name: Some("bond1".to_string()),
            }
        );
    }

    #[test]
    fn show_port_aggregate() {
        assert_eq!(
            Command::parse("show port-aggregate"),
            Command::ShowPortAggregate { name: None }
        );
        assert_eq!(
            Command::parse("show port-aggregate bond1"),
            Command::ShowPortAggregate {
                name: Some("bond1".to_string()),
            }
        );
    }

    #[test]
    fn set_source_line_preserves_leading_whitespace() {
        assert_eq!(
            Command::parse("set source line 2     accept"),
            Command::SetSourceLine {
                line: 2,
                text: "    accept".to_string(),
            }
        );
    }

    #[test]
    fn set_source_line_preserves_deep_indentation() {
        // The generic split_whitespace() matcher used by every other
        // command would collapse this to a single space — this command's
        // whole reason for a dedicated pre-check is that RPL's indentation
        // is semantically meaningful and must survive verbatim.
        assert_eq!(
            Command::parse("set source line 5         set this.bgp.local_pref = 150"),
            Command::SetSourceLine {
                line: 5,
                text: "        set this.bgp.local_pref = 150".to_string(),
            }
        );
    }

    #[test]
    fn set_source_line_with_no_text_is_not_a_source_edit() {
        // Not the `set source line` row: left to the config grammar, which
        // rejects it (`source` takes one value).
        assert_eq!(
            Command::parse("set source line 3"),
            Command::Config("set source line 3".to_string())
        );
    }

    #[test]
    fn set_source_line_with_non_numeric_line_is_unknown() {
        assert_eq!(
            Command::parse("set source line abc accept"),
            Command::Unknown("set source line abc accept".to_string())
        );
    }

    #[test]
    fn delete_source_line() {
        assert_eq!(
            Command::parse("delete source line 4"),
            Command::DeleteSourceLine { line: 4 }
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
    fn show_bgp_evpn() {
        assert_eq!(Command::parse("show bgp evpn"), Command::ShowBgpEvpn);
        assert_eq!(Command::parse("show bgp rpki"), Command::ShowBgpRpki);
    }

    #[test]
    fn show_ospf_neigh() {
        assert_eq!(Command::parse("show ospf neigh"), Command::ShowOspfNeigh);
    }

    #[test]
    fn clear_bgp_peer() {
        assert_eq!(
            Command::parse("clear bgp r1 10.0.0.1"),
            Command::ClearBgpPeer {
                instance: "r1".to_string(),
                peer: "10.0.0.1".parse().unwrap(),
            }
        );
        assert_eq!(
            Command::parse("clear bgp r1 not-an-ip"),
            Command::Unknown("clear bgp r1 not-an-ip".to_string())
        );
    }

    #[test]
    fn clear_bgp_soft_in() {
        assert_eq!(
            Command::parse("clear bgp r1 10.0.0.1 soft-in"),
            Command::ClearBgpSoftIn {
                instance: "r1".to_string(),
                peer: "10.0.0.1".parse().unwrap(),
            }
        );
        assert_eq!(
            Command::parse("clear bgp r1 not-an-ip soft-in"),
            Command::Unknown("clear bgp r1 not-an-ip soft-in".to_string())
        );
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
    fn show_ospfv3_neigh_and_database() {
        assert_eq!(
            Command::parse("show ospfv3 neigh"),
            Command::ShowOspfv3Neigh
        );
        assert_eq!(
            Command::parse("show ospfv3 database"),
            Command::ShowOspfv3Database
        );
    }

    #[test]
    fn show_fdb_takes_one_domain() {
        assert_eq!(
            Command::parse("show fdb bd1"),
            Command::ShowFdb {
                domain: "bd1".to_string()
            }
        );
        assert_eq!(
            Command::parse("show fdb"),
            Command::Unknown("show fdb".to_string())
        );
    }

    #[test]
    fn config_verbs_are_left_to_the_config_grammar() {
        assert_eq!(
            Command::parse("  set bgp instance r1 asn 65000 "),
            Command::Config("set bgp instance r1 asn 65000".to_string())
        );
        assert_eq!(
            Command::parse("delete"),
            Command::Config("delete".to_string())
        );
    }
}
