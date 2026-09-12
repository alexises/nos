use std::net::Ipv4Addr;

use nos_proto::TransactionBase;

/// A single field edit targeting a BGP instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpInstanceField {
    Asn(u32),
    RouterId(Ipv4Addr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditTarget {
    BgpInstance { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetTarget {
    /// Fully-qualified — works from anywhere in configuration mode.
    BgpInstance {
        name: String,
        field: BgpInstanceField,
    },
    /// Context-relative — only valid while navigated into a BGP instance.
    Relative { field: BgpInstanceField },
    /// A top-level scalar with no navigation context — works from anywhere
    /// in configuration mode, regardless of the current path.
    Hostname(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteTarget {
    /// Bare `delete` — deletes whatever the current navigation context is.
    Current,
    BgpInstance {
        name: String,
    },
}

/// A parsed REPL input line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ShowConfig,
    /// `show this` — only meaningful in configuration mode.
    Show,
    Save,
    Help,
    /// `exit` | `quit` | `end`
    Exit,
    Configure {
        name: String,
        /// `None` when `from ...` was omitted (defaults to `Current`).
        base: Option<TransactionBase>,
    },
    Edit(EditTarget),
    Set(SetTarget),
    Delete(DeleteTarget),
    Up,
    Top,
    Commit,
    /// `discard` | `abort`
    Discard,
    Empty,
    Unknown(String),
}

impl Command {
    pub fn parse(line: &str) -> Self {
        let trimmed = line.trim();
        match trimmed.split_whitespace().collect::<Vec<_>>().as_slice() {
            [] => Command::Empty,
            ["show", "config"] => Command::ShowConfig,
            ["show", "this"] => Command::Show,
            ["save"] => Command::Save,
            ["help"] => Command::Help,
            ["exit" | "quit" | "end"] => Command::Exit,
            ["commit"] => Command::Commit,
            ["discard" | "abort"] => Command::Discard,
            ["up"] => Command::Up,
            ["top"] => Command::Top,
            ["configure", name] => Command::Configure {
                name: (*name).to_string(),
                base: None,
            },
            ["configure", name, "from", "blank"] => Command::Configure {
                name: (*name).to_string(),
                base: Some(TransactionBase::Blank),
            },
            ["configure", name, "from", "current"] => Command::Configure {
                name: (*name).to_string(),
                base: Some(TransactionBase::Current),
            },
            ["edit", "bgp", "instance", name] => Command::Edit(EditTarget::BgpInstance {
                name: (*name).to_string(),
            }),
            ["set", "bgp", "instance", name, "asn", n] => match n.parse::<u32>() {
                Ok(asn) => Command::Set(SetTarget::BgpInstance {
                    name: (*name).to_string(),
                    field: BgpInstanceField::Asn(asn),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "bgp", "instance", name, "router-id", ip] => match ip.parse::<Ipv4Addr>() {
                Ok(router_id) => Command::Set(SetTarget::BgpInstance {
                    name: (*name).to_string(),
                    field: BgpInstanceField::RouterId(router_id),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "asn", n] => match n.parse::<u32>() {
                Ok(asn) => Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::Asn(asn),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "router-id", ip] => match ip.parse::<Ipv4Addr>() {
                Ok(router_id) => Command::Set(SetTarget::Relative {
                    field: BgpInstanceField::RouterId(router_id),
                }),
                Err(_) => Command::Unknown(trimmed.to_string()),
            },
            ["set", "hostname", name] => Command::Set(SetTarget::Hostname((*name).to_string())),
            ["delete"] => Command::Delete(DeleteTarget::Current),
            ["delete", "bgp", "instance", name] => Command::Delete(DeleteTarget::BgpInstance {
                name: (*name).to_string(),
            }),
            _ => Command::Unknown(trimmed.to_string()),
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
    fn edit_bgp_instance() {
        assert_eq!(
            Command::parse("edit bgp instance R1"),
            Command::Edit(EditTarget::BgpInstance {
                name: "R1".to_string()
            })
        );
    }

    #[test]
    fn set_bgp_instance_asn_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 asn 65001"),
            Command::Set(SetTarget::BgpInstance {
                name: "R1".to_string(),
                field: BgpInstanceField::Asn(65001),
            })
        );
    }

    #[test]
    fn set_bgp_instance_router_id_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 router-id 10.0.0.1"),
            Command::Set(SetTarget::BgpInstance {
                name: "R1".to_string(),
                field: BgpInstanceField::RouterId(Ipv4Addr::new(10, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn set_asn_qualified_with_malformed_number_is_unknown() {
        assert_eq!(
            Command::parse("set bgp instance R1 asn abc"),
            Command::Unknown("set bgp instance R1 asn abc".to_string())
        );
    }

    #[test]
    fn set_asn_relative() {
        assert_eq!(
            Command::parse("set asn 65001"),
            Command::Set(SetTarget::Relative {
                field: BgpInstanceField::Asn(65001),
            })
        );
    }

    #[test]
    fn set_router_id_relative() {
        assert_eq!(
            Command::parse("set router-id 10.0.0.1"),
            Command::Set(SetTarget::Relative {
                field: BgpInstanceField::RouterId(Ipv4Addr::new(10, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn set_router_id_relative_malformed_ip_is_unknown() {
        assert_eq!(
            Command::parse("set router-id not-an-ip"),
            Command::Unknown("set router-id not-an-ip".to_string())
        );
    }

    #[test]
    fn set_hostname() {
        assert_eq!(
            Command::parse("set hostname router1"),
            Command::Set(SetTarget::Hostname("router1".to_string()))
        );
    }

    #[test]
    fn delete_bare() {
        assert_eq!(
            Command::parse("delete"),
            Command::Delete(DeleteTarget::Current)
        );
    }

    #[test]
    fn delete_bgp_instance_qualified() {
        assert_eq!(
            Command::parse("delete bgp instance R1"),
            Command::Delete(DeleteTarget::BgpInstance {
                name: "R1".to_string()
            })
        );
    }
}
