//! Log export settings (`Config.logging`): RFC 5424 syslog to remote
//! collectors, sent by `nos-logd` (#71).

use std::net::IpAddr;

use garde::Validate;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use crate::log::LogLevel;
use crate::validators::{routing_table_reference_valid, unique_in};

use super::Config;

/// System-wide logging settings.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct LoggingSettings {
    /// Remote syslog collectors every log entry is exported to.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = LoggingSyslog, words = "syslog")]
    pub syslog: Vec<SyslogServer>,
}

/// One remote syslog collector (RFC 5424 messages).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct SyslogServer {
    #[garde(
        length(min = 1, max = 64),
        custom(|n: &String, ctx: &Config| unique_in(n, &ctx.logging.syslog, |s| &s.name))
    )]
    #[cli(key)]
    pub name: String,

    /// The collector's address. An IP, not a name: there is no resolver
    /// inside a VRF.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[garde(custom(|a: &IpAddr, _ctx: &Config| valid_address(a)))]
    #[cli(topic = SyslogAddress)]
    pub address: IpAddr,

    /// Destination port. Default: 514 (udp), 601 (tcp).
    #[serde(default)]
    #[garde(custom(|p: &Option<u16>, _ctx: &Config| valid_port(*p)))]
    #[cli(topic = SyslogPort)]
    pub port: Option<u16>,

    /// Transport. Default `udp` (RFC 5426); `tcp` uses RFC 6587 octet counting.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = SyslogTransport)]
    pub transport: SyslogTransport,

    /// Send from inside this routing table's VRF. Default: the default netns.
    #[serde(default)]
    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    #[cli(topic = SyslogRoutingTable)]
    pub routing_table: Option<String>,

    /// Minimum severity exported. Default `info`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = SyslogLevel)]
    pub level: Option<LogLevel>,

    /// Syslog facility of every message. Default `local7`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = SyslogFacility)]
    pub facility: Option<SyslogFacility>,
}

impl Default for SyslogServer {
    fn default() -> Self {
        SyslogServer {
            name: String::new(),
            address: IpAddr::from([0, 0, 0, 0]),
            port: None,
            transport: SyslogTransport::default(),
            routing_table: None,
            level: None,
            facility: None,
        }
    }
}

impl SyslogServer {
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(match self.transport {
            SyslogTransport::Udp => 514,
            SyslogTransport::Tcp => 601,
        })
    }

    pub fn effective_level(&self) -> LogLevel {
        self.level.unwrap_or(LogLevel::Info)
    }

    pub fn effective_facility(&self) -> SyslogFacility {
        self.facility.unwrap_or(SyslogFacility::Local7)
    }
}

fn valid_address(a: &IpAddr) -> garde::Result {
    if a.is_unspecified() || a.is_multicast() {
        return Err(garde::Error::new(
            "syslog address must be a unicast address",
        ));
    }
    Ok(())
}

fn valid_port(p: Option<u16>) -> garde::Result {
    if p == Some(0) {
        return Err(garde::Error::new("syslog port must be 1-65535"));
    }
    Ok(())
}

// ponytail: no `Tls` transport yet (RFC 5425/9662, #71 PR 2); it needs a new
// `nos-pki` policy and trust configuration. Appended later, postcard-safe.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum SyslogTransport {
    /// RFC 5426: one message per datagram.
    #[default]
    Udp,
    /// RFC 6587 octet-counted frames on one connection.
    Tcp,
}

/// The user-level facilities, `local0`-`local7`; the others are reserved for
/// operating-system subsystems.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub enum SyslogFacility {
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    #[default]
    Local7,
}

impl SyslogFacility {
    /// RFC 5424 Table 1 numerical code (local0 is 16).
    pub const fn code(self) -> u8 {
        16 + self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str) -> SyslogServer {
        SyslogServer {
            name: name.into(),
            address: "192.0.2.9".parse().unwrap(),
            ..SyslogServer::default()
        }
    }

    fn cfg(servers: Vec<SyslogServer>) -> Config {
        let mut c = Config::default();
        c.logging.syslog = servers;
        c
    }

    fn ok(c: &Config) -> bool {
        c.validate_with(c).is_ok()
    }

    #[test]
    fn defaults() {
        let s = server("c1");
        assert_eq!(s.effective_port(), 514);
        assert_eq!(s.effective_level(), LogLevel::Info);
        assert_eq!(s.effective_facility().code(), 23);
        let t = SyslogServer {
            transport: SyslogTransport::Tcp,
            ..s
        };
        assert_eq!(t.effective_port(), 601);
    }

    #[test]
    fn facility_codes_follow_rfc_5424() {
        assert_eq!(SyslogFacility::Local0.code(), 16);
        assert_eq!(SyslogFacility::Local3.code(), 19);
    }

    #[test]
    fn validation_rules() {
        assert!(ok(&cfg(vec![server("a"), server("b")])));
        assert!(!ok(&cfg(vec![server("a"), server("a")])));
        let mut s = server("a");
        s.port = Some(0);
        assert!(!ok(&cfg(vec![s])));
        let mut s = server("a");
        s.address = "0.0.0.0".parse().unwrap();
        assert!(!ok(&cfg(vec![s])));
        let mut s = server("a");
        s.address = "224.0.0.1".parse().unwrap();
        assert!(!ok(&cfg(vec![s])));
        let mut s = server("a");
        s.routing_table = Some("nope".into());
        assert!(!ok(&cfg(vec![s])));
    }

    #[test]
    fn routing_table_must_exist() {
        let mut c = cfg(vec![]);
        c.routing_tables.push(crate::schema::RoutingTable {
            name: "rt1".into(),
            ..Default::default()
        });
        let mut s = server("a");
        s.routing_table = Some("rt1".into());
        c.logging.syslog = vec![s];
        assert!(ok(&c));
        c.routing_tables.clear();
        assert!(!ok(&c));
    }

    #[test]
    fn config_without_logging_still_loads() {
        let json = serde_json::to_value(Config::default()).unwrap();
        let mut obj = json.as_object().unwrap().clone();
        obj.remove("logging");
        let c: Config = serde_json::from_value(obj.into()).unwrap();
        assert_eq!(c.logging, LoggingSettings::default());
    }
}
