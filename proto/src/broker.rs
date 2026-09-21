use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Identifies one addressable IPC service that a client might want to reach.
/// Resolved by `nos-watchdogd`'s broker (`Request::ResolveEndpoint` in
/// `WatchdogRequest`) rather than assumed from a hardcoded default, since the
/// watchdog is the one process that actually spawns every other daemon and
/// knows where it currently lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceRef {
    /// `nos-configd`'s own IPC socket. The watchdog always knows this — it's
    /// passed to the watchdog itself via its own `--config-socket` arg.
    Config,
    /// The `nos-ribd` instance currently serving one routing table, named by
    /// the table's config key.
    RibTable(String),
    /// The single `nos-interfaced` instance, which manages every configured
    /// interface in one process (unlike `RibTable`, there is no per-name
    /// variant — see root `CLAUDE.md`'s "Endpoint broker" section).
    Interfaces,
    /// The single `nos-logd` instance, resolved directly like `Config`/
    /// `Interfaces` rather than through the registry — there is exactly one
    /// log collector regardless of how many other daemons are running.
    Log,
    /// The `nos-bgpd` instance currently serving one BGP instance, named by
    /// the instance's config key — resolved through the registry the same
    /// way as `RibTable`, since there can be many.
    BgpInstance(String),
    /// The `nos-ospfd` instance currently serving one OSPF instance, named by
    /// the instance's config key — resolved through the registry the same
    /// way as `RibTable`/`BgpInstance`.
    OspfInstance(String),
    /// The `nos-ospfv3d` instance currently serving one `OSPFv3` instance,
    /// named by the instance's config key — resolved through the registry
    /// the same way as `OspfInstance`, a separate variant since v2/v3 are
    /// two independent daemon families.
    Ospfv3Instance(String),
    /// The single `nos-lacpd` instance, resolved directly like `Interfaces`/
    /// `Log` rather than through the registry — there is exactly one LACP
    /// engine regardless of how many `Lacp`-mode `PortAggregate`s exist.
    Lacp,
    /// The single `nos-lldpd` instance, resolved directly like `Lacp` — one
    /// LLDP engine handles every LLDP-enabled interface.
    Lldp,
}

impl ServiceRef {
    /// The role the daemon behind this service authenticates as — what a
    /// client must see in its certificate before it sends anything.
    pub fn role(&self) -> Role {
        match self {
            ServiceRef::Config => Role::Configd,
            ServiceRef::RibTable(_) => Role::Ribd,
            ServiceRef::Interfaces => Role::Interfaced,
            ServiceRef::Log => Role::Logd,
            ServiceRef::BgpInstance(_) => Role::Bgpd,
            ServiceRef::OspfInstance(_) => Role::Ospfd,
            ServiceRef::Ospfv3Instance(_) => Role::Ospfv3d,
            ServiceRef::Lacp => Role::Lacpd,
            ServiceRef::Lldp => Role::Lldpd,
        }
    }

    /// The instance name in that daemon's certificate: the table/instance key,
    /// or `""` for the singleton daemons.
    pub fn instance(&self) -> &str {
        match self {
            ServiceRef::RibTable(n)
            | ServiceRef::BgpInstance(n)
            | ServiceRef::OspfInstance(n)
            | ServiceRef::Ospfv3Instance(n) => n,
            ServiceRef::Config
            | ServiceRef::Interfaces
            | ServiceRef::Log
            | ServiceRef::Lacp
            | ServiceRef::Lldp => "",
        }
    }
}

impl AsRef<str> for Role {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// What kind of process an authenticated IPC peer is, as asserted by the
/// `nos://<role>/<name>` URI SAN in its certificate (`nos-pki`). Servers
/// allow-list by role; clients check the role of whoever they dialed. Never
/// on the wire — it lives in the certificate — so no serde derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Watchdog,
    Configd,
    Logd,
    Bgpd,
    Ribd,
    Ospfd,
    Ospfv3d,
    Interfaced,
    Lacpd,
    Lldpd,
    Restd,
    /// A person, authenticated by login; the certificate's name is the username.
    User,
}

impl Role {
    pub const ALL: [Role; 12] = [
        Role::Watchdog,
        Role::Configd,
        Role::Logd,
        Role::Bgpd,
        Role::Ribd,
        Role::Ospfd,
        Role::Ospfv3d,
        Role::Interfaced,
        Role::Lacpd,
        Role::Lldpd,
        Role::Restd,
        Role::User,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Watchdog => "watchdog",
            Role::Configd => "configd",
            Role::Logd => "logd",
            Role::Bgpd => "bgpd",
            Role::Ribd => "ribd",
            Role::Ospfd => "ospfd",
            Role::Ospfv3d => "ospfv3d",
            Role::Interfaced => "interfaced",
            Role::Lacpd => "lacpd",
            Role::Lldpd => "lldpd",
            Role::Restd => "restd",
            Role::User => "user",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// Every role except `User` — the daemons `nos-watchdogd` itself spawns.
    pub fn is_daemon(self) -> bool {
        self != Role::User
    }
}

/// The one `WatchdogEvent::Denied` message for a failed login, identical for an
/// unknown user and a wrong password so it reveals nothing about which exist.
pub const INVALID_CREDENTIALS: &str = "invalid credentials";

/// Messages sent from a client to `nos-watchdogd`'s broker socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Serialize, Deserialize)]
pub enum WatchdogRequest {
    /// One-shot: resolve where to reach the given service right now.
    /// Requires a client certificate.
    ResolveEndpoint { service: ServiceRef },
    /// The only request an unauthenticated peer may send: prove who you are
    /// with a local user's password and get a short-lived client certificate
    /// for the public key in `csr_der` (the private key never leaves the
    /// caller). Answered with `Issued` or `Denied`.
    Login {
        user: String,
        password: String,
        csr_der: Vec<u8>,
    },
    /// Trade a still-valid `user` certificate for a fresh one on the key in
    /// `csr_der`, with no password. Refused if the user no longer exists.
    RenewCert { csr_der: Vec<u8> },
    /// `nos-restd` only: a TLS *server* certificate for its listener, valid
    /// for `addresses`, on the key in `csr_der`. Answered with `RestServerCert`.
    IssueRestServerCert {
        addresses: Vec<IpAddr>,
        csr_der: Vec<u8>,
    },
    /// `nos-restd` only, on behalf of a REST client: `Login`, but the
    /// certificate is issued by the REST CA (`Issued`). The failed-login
    /// throttle is `nos-restd`'s, not the broker connection's.
    RestLogin {
        user: String,
        password: String,
        csr_der: Vec<u8>,
    },
    /// `nos-restd` only: `RenewCert` for a REST client whose still-valid
    /// certificate `nos-restd` has just verified. Refused if the user is gone.
    RestRenew { user: String, csr_der: Vec<u8> },
}

// Manual `Debug`: a `Login` is one log line away from leaking a password.
impl fmt::Debug for WatchdogRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WatchdogRequest::ResolveEndpoint { service } => f
                .debug_struct("ResolveEndpoint")
                .field("service", service)
                .finish(),
            WatchdogRequest::Login { user, .. } => f
                .debug_struct("Login")
                .field("user", user)
                .field("password", &"<hidden>")
                .finish_non_exhaustive(),
            WatchdogRequest::RestLogin { user, .. } => f
                .debug_struct("RestLogin")
                .field("user", user)
                .field("password", &"<hidden>")
                .finish_non_exhaustive(),
            WatchdogRequest::RenewCert { .. } => {
                f.debug_struct("RenewCert").finish_non_exhaustive()
            }
            WatchdogRequest::IssueRestServerCert { addresses, .. } => f
                .debug_struct("IssueRestServerCert")
                .field("addresses", addresses)
                .finish_non_exhaustive(),
            WatchdogRequest::RestRenew { user, .. } => f
                .debug_struct("RestRenew")
                .field("user", user)
                .finish_non_exhaustive(),
        }
    }
}

/// Messages sent from `nos-watchdogd` to a broker client.
#[derive(Debug, Serialize, Deserialize)]
pub enum WatchdogEvent {
    /// The service is currently reachable at this Unix socket path.
    Endpoint(PathBuf),
    /// No such service is currently running/known (e.g. the routing table
    /// isn't configured, or its `nos-ribd` hasn't finished starting yet).
    NotAvailable,
    /// Reply to `Login`/`RenewCert`: the DER client certificate, and how long
    /// it is valid for so the caller knows when to renew.
    Issued {
        cert_der: Vec<u8>,
        lifetime_secs: u64,
    },
    /// Reply to `Login`/`RenewCert`: refused. Deliberately one opaque
    /// message for unknown user and wrong password alike.
    Denied(String),
    /// Reply to `IssueRestServerCert`: the listener's certificate, the REST CA
    /// that signed it (the trust anchor for client certificates), and how long
    /// the certificate is valid.
    RestServerCert {
        cert_der: Vec<u8>,
        ca_der: Vec<u8>,
        lifetime_secs: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_round_trip_through_their_certificate_spelling() {
        for r in Role::ALL {
            assert_eq!(Role::parse(r.as_str()), Some(r));
        }
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn a_service_is_expected_to_authenticate_as_its_own_daemon() {
        let rib = ServiceRef::RibTable("rt1".into());
        assert_eq!((rib.role(), rib.instance()), (Role::Ribd, "rt1"));
        assert_eq!(
            (ServiceRef::Config.role(), ServiceRef::Config.instance()),
            (Role::Configd, "")
        );
        assert_eq!(ServiceRef::Ospfv3Instance("a".into()).role(), Role::Ospfv3d);
    }

    #[test]
    fn login_debug_never_shows_the_password() {
        let req = WatchdogRequest::Login {
            user: "alice".into(),
            password: "hunter2".into(),
            csr_der: vec![1, 2, 3],
        };
        let shown = format!("{req:?}");
        assert!(shown.contains("alice") && !shown.contains("hunter2"));
    }
}
