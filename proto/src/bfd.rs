//! `nos-bfdd`'s IPC protocol (RFC 5880 sessions on behalf of other daemons).
//! One-shot request/event pairs framed by `IpcCodec` over a Unix socket
//! resolved via the watchdog broker (`ServiceRef::Bfd`, a single system-wide
//! instance). Clients (`bgpd`/`ribd`/`ospfd`/`ospfv3d`) `Register` a session
//! and are told of state changes; `nos-cli`/`nos-restd` query with `GetSessions`.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::schema::{BfdAuthMethod, BfdProfile};

/// What identifies one BFD session: a routing table, the remote system and
/// the path to it (RFC 5881 single-hop is bound to an interface, RFC 5883
/// multihop is not).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey {
    pub table: String,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub local: Option<IpAddr>,
    pub interface: Option<String>,
    pub multihop: bool,
}

/// RFC 5880 §4.1 `Sta` values.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BfdState {
    AdminDown,
    Down,
    Init,
    Up,
}

impl BfdState {
    /// The 2-bit wire value.
    pub const fn code(self) -> u8 {
        match self {
            BfdState::AdminDown => 0,
            BfdState::Down => 1,
            BfdState::Init => 2,
            BfdState::Up => 3,
        }
    }

    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => BfdState::AdminDown,
            1 => BfdState::Down,
            2 => BfdState::Init,
            3 => BfdState::Up,
            _ => return None,
        })
    }
}

impl fmt::Display for BfdState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BfdState::AdminDown => "admin-down",
            BfdState::Down => "down",
            BfdState::Init => "init",
            BfdState::Up => "up",
        })
    }
}

/// RFC 5880 §4.1 diagnostic codes 0-8.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BfdDiag {
    NoDiagnostic,
    ControlDetectionTimeExpired,
    EchoFunctionFailed,
    NeighborSignaledSessionDown,
    ForwardingPlaneReset,
    PathDown,
    ConcatenatedPathDown,
    AdministrativelyDown,
    ReverseConcatenatedPathDown,
}

impl BfdDiag {
    /// The 5-bit wire value.
    pub const fn code(self) -> u8 {
        match self {
            BfdDiag::NoDiagnostic => 0,
            BfdDiag::ControlDetectionTimeExpired => 1,
            BfdDiag::EchoFunctionFailed => 2,
            BfdDiag::NeighborSignaledSessionDown => 3,
            BfdDiag::ForwardingPlaneReset => 4,
            BfdDiag::PathDown => 5,
            BfdDiag::ConcatenatedPathDown => 6,
            BfdDiag::AdministrativelyDown => 7,
            BfdDiag::ReverseConcatenatedPathDown => 8,
        }
    }

    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => BfdDiag::NoDiagnostic,
            1 => BfdDiag::ControlDetectionTimeExpired,
            2 => BfdDiag::EchoFunctionFailed,
            3 => BfdDiag::NeighborSignaledSessionDown,
            4 => BfdDiag::ForwardingPlaneReset,
            5 => BfdDiag::PathDown,
            6 => BfdDiag::ConcatenatedPathDown,
            7 => BfdDiag::AdministrativelyDown,
            8 => BfdDiag::ReverseConcatenatedPathDown,
            _ => return None,
        })
    }
}

impl fmt::Display for BfdDiag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BfdDiag::NoDiagnostic => "no-diagnostic",
            BfdDiag::ControlDetectionTimeExpired => "control-detection-time-expired",
            BfdDiag::EchoFunctionFailed => "echo-function-failed",
            BfdDiag::NeighborSignaledSessionDown => "neighbor-signaled-session-down",
            BfdDiag::ForwardingPlaneReset => "forwarding-plane-reset",
            BfdDiag::PathDown => "path-down",
            BfdDiag::ConcatenatedPathDown => "concatenated-path-down",
            BfdDiag::AdministrativelyDown => "administratively-down",
            BfdDiag::ReverseConcatenatedPathDown => "reverse-concatenated-path-down",
        })
    }
}

/// One session, for `show bfd sessions`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfdSessionView {
    pub key: SessionKey,
    pub state: BfdState,
    pub diag: BfdDiag,
    pub local_discriminator: u32,
    pub remote_discriminator: u32,
    /// Negotiated transmit interval, microseconds.
    pub tx_interval_us: u32,
    /// Detection time, microseconds.
    pub detection_time_us: u32,
    /// The configured authentication (never the key), `None` when off.
    pub auth_method: Option<BfdAuthMethod>,
    pub auth_key_id: Option<u8>,
    /// Packets dropped by RFC 5880 §6.7 authentication since the session started.
    pub auth_failures: u64,
    /// The Echo function is running (RFC 5880 §6.4).
    pub echo_active: bool,
    /// Negotiated Echo transmit interval, microseconds; 0 while inactive.
    pub echo_interval_us: u32,
    /// RFC 9747 unaffiliated Echo: no Control traffic at all.
    pub echo_only: bool,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BfdRequest {
    /// Start (or refresh) a session; the reply stream is `BfdEvent::State`.
    Register {
        table: String,
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        peer: IpAddr,
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        local: Option<IpAddr>,
        interface: Option<String>,
        profile: BfdProfile,
        multihop: bool,
    },
    Deregister {
        key: SessionKey,
    },
    GetSessions {
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        peer: Option<IpAddr>,
    },
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BfdEvent {
    State {
        key: SessionKey,
        state: BfdState,
        diag: BfdDiag,
        /// The C bit (RFC 5880 §4.1) set at both ends: the local session and
        /// the last packet received. RFC 5882 §4.3: only then is a BFD Down a
        /// forwarding failure a graceful restart must not outlive.
        control_plane_independent: bool,
    },
    Sessions(Vec<BfdSessionView>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::IpcCodec;
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    fn key() -> SessionKey {
        SessionKey {
            table: "rt1".into(),
            peer: "192.0.2.1".parse().unwrap(),
            local: None,
            interface: Some("eth1".into()),
            multihop: false,
        }
    }

    #[test]
    fn requests_and_events_round_trip() {
        let mut c = IpcCodec::<BfdRequest>::default();
        for r in [
            BfdRequest::Register {
                table: "rt1".into(),
                peer: "2001:db8::1".parse().unwrap(),
                local: Some("2001:db8::2".parse().unwrap()),
                interface: None,
                profile: BfdProfile::default(),
                multihop: true,
            },
            BfdRequest::Deregister { key: key() },
            BfdRequest::GetSessions { peer: None },
        ] {
            let mut b = BytesMut::new();
            c.encode(r.clone(), &mut b).unwrap();
            assert_eq!(c.decode(&mut b).unwrap(), Some(r));
        }
        let mut c = IpcCodec::<BfdEvent>::default();
        let e = BfdEvent::State {
            key: key(),
            state: BfdState::Up,
            diag: BfdDiag::NoDiagnostic,
            control_plane_independent: true,
        };
        let mut b = BytesMut::new();
        c.encode(e.clone(), &mut b).unwrap();
        assert_eq!(c.decode(&mut b).unwrap(), Some(e));
    }

    #[test]
    fn wire_codes_and_names() {
        for c in 0..=3 {
            assert_eq!(BfdState::from_code(c).unwrap().code(), c);
        }
        assert_eq!(BfdState::from_code(4), None);
        for c in 0..=8 {
            assert_eq!(BfdDiag::from_code(c).unwrap().code(), c);
        }
        assert_eq!(BfdDiag::from_code(9), None);
        assert_eq!(
            BfdDiag::ControlDetectionTimeExpired.to_string(),
            "control-detection-time-expired"
        );
        assert_eq!(BfdState::AdminDown.to_string(), "admin-down");
    }
}
