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
        /// Name of the syslog server this op targets.
        name: String,
    },
    /// Removes syslog from the syslog server.
    RemoveSyslog {
        /// Name of the syslog server this op targets.
        name: String,
    },
    /// Sets the syslog address of the syslog server to `address`.
    SetSyslogAddress {
        /// Name of the syslog server this op targets.
        name: String,
        /// IP address of the syslog server.
        address: IpAddr,
    },
    /// Sets the syslog port of the syslog server to `port`.
    SetSyslogPort {
        /// Name of the syslog server this op targets.
        name: String,
        /// Server port; `None` selects the transport default.
        port: Option<u16>,
    },
    /// Sets the syslog transport of the syslog server to `transport`.
    SetSyslogTransport {
        /// Name of the syslog server this op targets.
        name: String,
        /// Transport protocol: UDP, TCP or TLS.
        transport: SyslogTransport,
    },
    /// Sets the syslog routing table of the syslog server to `routing_table`.
    SetSyslogRoutingTable {
        /// Name of the syslog server this op targets.
        name: String,
        /// Routing table (VRF) the server is reached through; `None` selects the default.
        routing_table: Option<String>,
    },
    /// Sets the syslog level of the syslog server to `level`.
    SetSyslogLevel {
        /// Name of the syslog server this op targets.
        name: String,
        /// Minimum severity forwarded; `None` reverts to the default.
        level: Option<LogLevel>,
    },
    /// Sets the syslog facility of the syslog server to `facility`.
    SetSyslogFacility {
        /// Name of the syslog server this op targets.
        name: String,
        /// Syslog facility; `None` reverts to the default.
        facility: Option<SyslogFacility>,
    },
    /// Creates the `tls` block if missing.
    SetSyslogTlsTrustAnchor {
        /// Name of the syslog server this op targets.
        name: String,
        /// PEM-encoded certificate or key.
        pem: Option<String>,
    },
    /// Sets the syslog TLS fingerprint of the syslog server to `fingerprint`.
    SetSyslogTlsFingerprint {
        /// Name of the syslog server this op targets.
        name: String,
        /// Pinned SHA-256 fingerprint of the server certificate; `None` clears it.
        fingerprint: Option<String>,
    },
    /// Sets the syslog TLS server name of the syslog server to `server_name`.
    SetSyslogTlsServerName {
        /// Name of the syslog server this op targets.
        name: String,
        /// Name checked against the server certificate; `None` clears it.
        server_name: Option<String>,
    },
    /// Sets the syslog TLS allow TLS 1.2 of the syslog server to `allow`.
    SetSyslogTlsAllowTls12 {
        /// Name of the syslog server this op targets.
        name: String,
        /// `true` allows TLS 1.2 as a fallback to TLS 1.3.
        allow: bool,
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
            | LoggingOp::SetSyslogFacility { name, .. }
            | LoggingOp::SetSyslogTlsTrustAnchor { name, .. }
            | LoggingOp::SetSyslogTlsFingerprint { name, .. }
            | LoggingOp::SetSyslogTlsServerName { name, .. }
            | LoggingOp::SetSyslogTlsAllowTls12 { name, .. } => name,
        }
    }

    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
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
            LoggingOp::SetSyslogTlsTrustAnchor { pem, .. } => {
                s.tls
                    .get_or_insert_with(Default::default)
                    .trust_anchor
                    .clone_from(pem);
            }
            LoggingOp::SetSyslogTlsFingerprint { fingerprint, .. } => {
                s.tls
                    .get_or_insert_with(Default::default)
                    .fingerprint
                    .clone_from(fingerprint);
            }
            LoggingOp::SetSyslogTlsServerName { server_name, .. } => {
                s.tls
                    .get_or_insert_with(Default::default)
                    .server_name
                    .clone_from(server_name);
            }
            LoggingOp::SetSyslogTlsAllowTls12 { allow, .. } => {
                s.tls.get_or_insert_with(Default::default).allow_tls12 = *allow;
            }
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

        for op in [
            LoggingOp::SetSyslogTlsFingerprint {
                name: name(),
                fingerprint: Some("SHA-256:00".into()),
            },
            LoggingOp::SetSyslogTlsAllowTls12 {
                name: name(),
                allow: true,
            },
        ] {
            op.apply(&mut cfg).unwrap();
        }
        let t = cfg.logging.syslog[0].tls.clone().unwrap();
        assert_eq!(t.fingerprint.as_deref(), Some("SHA-256:00"));
        assert!(t.allow_tls12);

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
