use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::log::LogLevel;
use crate::schema::{Config, SyslogFacility, SyslogServer, SyslogTransport};

use super::OpError;

/// An edit to one remote syslog collector in `Config.logging.syslog`. The
/// optional fields take `None` to clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoggingOp {
    /// Creates the collector (address `0.0.0.0`, which commit refuses until
    /// set) if missing; no-op if present.
    EnsureSyslog {
        name: String,
    },
    RemoveSyslog {
        name: String,
    },
    SetSyslogAddress {
        name: String,
        address: IpAddr,
    },
    SetSyslogPort {
        name: String,
        port: Option<u16>,
    },
    SetSyslogTransport {
        name: String,
        transport: SyslogTransport,
    },
    SetSyslogRoutingTable {
        name: String,
        routing_table: Option<String>,
    },
    SetSyslogLevel {
        name: String,
        level: Option<LogLevel>,
    },
    SetSyslogFacility {
        name: String,
        facility: Option<SyslogFacility>,
    },
}

impl LoggingOp {
    fn name(&self) -> &str {
        match self {
            LoggingOp::EnsureSyslog { name }
            | LoggingOp::RemoveSyslog { name }
            | LoggingOp::SetSyslogAddress { name, .. }
            | LoggingOp::SetSyslogPort { name, .. }
            | LoggingOp::SetSyslogTransport { name, .. }
            | LoggingOp::SetSyslogRoutingTable { name, .. }
            | LoggingOp::SetSyslogLevel { name, .. }
            | LoggingOp::SetSyslogFacility { name, .. } => name,
        }
    }

    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        let list = &mut config.logging.syslog;
        let name = self.name();
        let pos = list.iter().position(|s| s.name == name);
        if let LoggingOp::EnsureSyslog { name } = self {
            if pos.is_none() {
                list.push(SyslogServer {
                    name: name.clone(),
                    ..SyslogServer::default()
                });
            }
            return Ok(());
        }
        let Some(pos) = pos else {
            return Err(OpError::SyslogServerNotFound(name.to_string()));
        };
        let s = &mut list[pos];
        match self {
            LoggingOp::EnsureSyslog { .. } => {}
            LoggingOp::RemoveSyslog { .. } => {
                list.remove(pos);
            }
            LoggingOp::SetSyslogAddress { address, .. } => s.address = *address,
            LoggingOp::SetSyslogPort { port, .. } => s.port = *port,
            LoggingOp::SetSyslogTransport { transport, .. } => s.transport = *transport,
            LoggingOp::SetSyslogRoutingTable { routing_table, .. } => {
                s.routing_table.clone_from(routing_table);
            }
            LoggingOp::SetSyslogLevel { level, .. } => s.level = *level,
            LoggingOp::SetSyslogFacility { facility, .. } => s.facility = *facility,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_set_clear_remove() {
        let mut cfg = Config::default();
        let name = || "c1".to_string();
        LoggingOp::EnsureSyslog { name: name() }
            .apply(&mut cfg)
            .unwrap();
        LoggingOp::EnsureSyslog { name: name() }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.logging.syslog.len(), 1);
        let addr: IpAddr = "192.0.2.9".parse().unwrap();
        for op in [
            LoggingOp::SetSyslogAddress {
                name: name(),
                address: addr,
            },
            LoggingOp::SetSyslogPort {
                name: name(),
                port: Some(1514),
            },
            LoggingOp::SetSyslogTransport {
                name: name(),
                transport: SyslogTransport::Tcp,
            },
            LoggingOp::SetSyslogRoutingTable {
                name: name(),
                routing_table: Some("rt1".into()),
            },
            LoggingOp::SetSyslogLevel {
                name: name(),
                level: Some(LogLevel::Debug),
            },
            LoggingOp::SetSyslogFacility {
                name: name(),
                facility: Some(SyslogFacility::Local3),
            },
        ] {
            op.apply(&mut cfg).unwrap();
        }
        let s = &cfg.logging.syslog[0];
        assert_eq!(s.address, addr);
        assert_eq!(s.effective_port(), 1514);
        assert_eq!(s.transport, SyslogTransport::Tcp);
        assert_eq!(s.routing_table.as_deref(), Some("rt1"));
        assert_eq!(s.level, Some(LogLevel::Debug));
        assert_eq!(s.facility, Some(SyslogFacility::Local3));

        LoggingOp::SetSyslogPort {
            name: name(),
            port: None,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.logging.syslog[0].port, None);
        LoggingOp::RemoveSyslog { name: name() }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.logging.syslog, Vec::<SyslogServer>::new());
    }

    #[test]
    fn missing_server_is_an_error() {
        let mut cfg = Config::default();
        let missing = LoggingOp::SetSyslogLevel {
            name: "x".into(),
            level: None,
        };
        assert!(matches!(
            missing.apply(&mut cfg),
            Err(OpError::SyslogServerNotFound(_))
        ));
        assert!(LoggingOp::RemoveSyslog { name: "x".into() }
            .apply(&mut cfg)
            .is_err());
    }
}
