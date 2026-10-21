//! RFC 5880 §4.1 control packet codec. The optional authentication section is
//! only parsed here (`auth`); checking and signing it is `auth::AuthState`.

use nos_proto::BfdState;

use crate::auth::{self, AuthSection};
use thiserror::Error;

/// Length of the mandatory section, bytes.
pub const LEN: usize = 24;
const LEN_U8: u8 = 24;

#[allow(clippy::struct_excessive_bools, reason = "the RFC 5880 §4.1 flag bits")]
/// A decoded control packet. Intervals are microseconds, as on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Raw 5-bit diagnostic (a peer may send a value we do not name).
    pub diag: u8,
    pub state: BfdState,
    pub poll: bool,
    pub final_: bool,
    pub control_plane_independent: bool,
    pub demand: bool,
    pub detect_mult: u8,
    pub my_discriminator: u32,
    pub your_discriminator: u32,
    pub desired_min_tx: u32,
    pub required_min_rx: u32,
    pub required_min_echo_rx: u32,
    /// The authentication section of a received packet (A bit set). Ignored
    /// by `encode`: `AuthState::sign` appends it.
    pub auth: Option<AuthSection>,
}

/// Why a packet fails the RFC 5880 §6.8.6 checks that need no session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("shorter than the 24-byte mandatory section")]
    Truncated,
    #[error("version {0}, expected 1")]
    Version(u8),
    #[error("length field {0} is below 24")]
    LengthTooSmall(u8),
    #[error("length field {0} exceeds the payload")]
    LengthExceedsPayload(u8),
    #[error("detect multiplier is zero")]
    ZeroDetectMult,
    #[error("multipoint bit set")]
    Multipoint,
    #[error("my discriminator is zero")]
    ZeroMyDiscriminator,
    #[error("your discriminator is zero while the sender is not Down/AdminDown")]
    ZeroYourDiscriminator,
    #[error("authentication bit set but the section is malformed or of an unknown type")]
    BadAuthSection,
}

const FLAG_POLL: u8 = 0x20;
const FLAG_FINAL: u8 = 0x10;
const FLAG_CPI: u8 = 0x08;
use auth::FLAG_AUTH;
const FLAG_DEMAND: u8 = 0x02;
const FLAG_MULTIPOINT: u8 = 0x01;

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Decodes and applies the stateless §6.8.6 checks. Never panics.
pub fn decode(b: &[u8]) -> Result<Packet, DecodeError> {
    let (Some(&b0), Some(&b1), Some(&mult), Some(&len)) = (b.first(), b.get(1), b.get(2), b.get(3))
    else {
        return Err(DecodeError::Truncated);
    };
    let version = b0 >> 5;
    if version != 1 {
        return Err(DecodeError::Version(version));
    }
    if usize::from(len) < LEN {
        return Err(DecodeError::LengthTooSmall(len));
    }
    if usize::from(len) > b.len() {
        return Err(DecodeError::LengthExceedsPayload(len));
    }
    if mult == 0 {
        return Err(DecodeError::ZeroDetectMult);
    }
    if b1 & FLAG_MULTIPOINT != 0 {
        return Err(DecodeError::Multipoint);
    }
    let auth = if b1 & FLAG_AUTH != 0 {
        Some(
            b.get(..usize::from(len))
                .and_then(auth::parse)
                .ok_or(DecodeError::BadAuthSection)?,
        )
    } else {
        None
    };
    let (Some(my), Some(your), Some(tx), Some(rx), Some(echo)) = (
        u32_at(b, 4),
        u32_at(b, 8),
        u32_at(b, 12),
        u32_at(b, 16),
        u32_at(b, 20),
    ) else {
        return Err(DecodeError::Truncated);
    };
    if my == 0 {
        return Err(DecodeError::ZeroMyDiscriminator);
    }
    // The 2-bit state field is always a valid BfdState.
    let state = BfdState::from_code(b1 >> 6).ok_or(DecodeError::Truncated)?;
    if your == 0 && !matches!(state, BfdState::Down | BfdState::AdminDown) {
        return Err(DecodeError::ZeroYourDiscriminator);
    }
    Ok(Packet {
        diag: b0 & 0x1f,
        state,
        poll: b1 & FLAG_POLL != 0,
        final_: b1 & FLAG_FINAL != 0,
        control_plane_independent: b1 & FLAG_CPI != 0,
        demand: b1 & FLAG_DEMAND != 0,
        detect_mult: mult,
        my_discriminator: my,
        your_discriminator: your,
        desired_min_tx: tx,
        required_min_rx: rx,
        required_min_echo_rx: echo,
        auth,
    })
}

impl Packet {
    pub fn encode(&self) -> [u8; LEN] {
        let mut o = [0u8; LEN];
        o[0] = (1 << 5) | (self.diag & 0x1f);
        let mut flags = self.state.code() << 6;
        for (on, bit) in [
            (self.poll, FLAG_POLL),
            (self.final_, FLAG_FINAL),
            (self.control_plane_independent, FLAG_CPI),
            (self.demand, FLAG_DEMAND),
        ] {
            if on {
                flags |= bit;
            }
        }
        o[1] = flags;
        o[2] = self.detect_mult;
        o[3] = LEN_U8;
        o[4..8].copy_from_slice(&self.my_discriminator.to_be_bytes());
        o[8..12].copy_from_slice(&self.your_discriminator.to_be_bytes());
        o[12..16].copy_from_slice(&self.desired_min_tx.to_be_bytes());
        o[16..20].copy_from_slice(&self.required_min_rx.to_be_bytes());
        o[20..24].copy_from_slice(&self.required_min_echo_rx.to_be_bytes());
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt() -> Packet {
        Packet {
            diag: 1,
            state: BfdState::Up,
            poll: false,
            final_: false,
            control_plane_independent: false,
            demand: false,
            detect_mult: 3,
            my_discriminator: 0x0102_0304,
            your_discriminator: 0x0a0b_0c0d,
            desired_min_tx: 300_000,
            required_min_rx: 300_000,
            required_min_echo_rx: 0,
            auth: None,
        }
    }

    #[test]
    fn round_trip_with_every_flag() {
        for state in [
            BfdState::AdminDown,
            BfdState::Down,
            BfdState::Init,
            BfdState::Up,
        ] {
            let p = Packet {
                state,
                poll: true,
                final_: true,
                control_plane_independent: true,
                demand: true,
                ..pkt()
            };
            assert_eq!(decode(&p.encode()), Ok(p));
        }
        let p = pkt();
        assert_eq!(decode(&p.encode()), Ok(p));
    }

    #[test]
    fn known_wire_bytes() {
        let b = pkt().encode();
        assert_eq!(&b[..4], &[0x21, 0xc0, 3, 24]);
        assert_eq!(&b[4..8], &[1, 2, 3, 4]);
    }

    #[test]
    fn rx_version_not_1() {
        let mut b = pkt().encode();
        b[0] = (2 << 5) | 1;
        assert_eq!(decode(&b), Err(DecodeError::Version(2)));
    }

    #[test]
    fn rx_length_below_24() {
        let mut b = pkt().encode();
        b[3] = 23;
        assert_eq!(decode(&b), Err(DecodeError::LengthTooSmall(23)));
    }

    #[test]
    fn rx_length_exceeds_payload() {
        let mut b = pkt().encode();
        b[3] = 25;
        assert_eq!(decode(&b), Err(DecodeError::LengthExceedsPayload(25)));
    }

    #[test]
    fn rx_detect_mult_zero() {
        let mut b = pkt().encode();
        b[2] = 0;
        assert_eq!(decode(&b), Err(DecodeError::ZeroDetectMult));
    }

    #[test]
    fn rx_multipoint_set() {
        let mut b = pkt().encode();
        b[1] |= FLAG_MULTIPOINT;
        assert_eq!(decode(&b), Err(DecodeError::Multipoint));
    }

    #[test]
    fn rx_my_discriminator_zero() {
        let p = Packet {
            my_discriminator: 0,
            ..pkt()
        };
        assert_eq!(decode(&p.encode()), Err(DecodeError::ZeroMyDiscriminator));
    }

    #[test]
    fn rx_your_discriminator_zero_unless_down() {
        for (state, ok) in [
            (BfdState::Down, true),
            (BfdState::AdminDown, true),
            (BfdState::Init, false),
            (BfdState::Up, false),
        ] {
            let p = Packet {
                state,
                your_discriminator: 0,
                ..pkt()
            };
            let r = decode(&p.encode());
            assert_eq!(r.is_ok(), ok, "{state}");
            if !ok {
                assert_eq!(r, Err(DecodeError::ZeroYourDiscriminator));
            }
        }
    }

    #[test]
    fn rx_auth_section_is_parsed_or_rejected() {
        use nos_proto::schema::{BfdAuth, BfdAuthMethod};
        let cfg = BfdAuth {
            key_id: 4,
            method: BfdAuthMethod::KeyedSha1,
            key: "label".into(),
        };
        let w = auth::sign(&pkt().encode(), &auth::AuthKey::new(&cfg, "k"), 77);
        let p = decode(&w).unwrap();
        let s = p.auth.as_ref().unwrap();
        assert_eq!((s.kind, s.key_id, s.seq), (4, 4, 77));
        assert_eq!(Packet { auth: None, ..p }, pkt());
        // A bit set without a section, or with a cut one
        let mut b = pkt().encode();
        b[1] |= FLAG_AUTH;
        assert_eq!(decode(&b), Err(DecodeError::BadAuthSection));
        let mut cut = w.clone();
        cut[3] -= 4;
        cut.truncate(cut.len() - 4);
        assert_eq!(decode(&cut), Err(DecodeError::BadAuthSection));
    }

    #[test]
    fn trailing_bytes_beyond_length_are_ignored() {
        let mut b = pkt().encode().to_vec();
        b.extend_from_slice(&[0xff; 10]);
        assert_eq!(decode(&b), Ok(pkt()));
    }

    #[test]
    fn truncated_and_mutated_input_never_panics() {
        let good = pkt().encode();
        for n in 0..=good.len() + 2 {
            let mut b = good.to_vec();
            b.resize(n, 0);
            let _ = decode(&b[..n.min(b.len())]);
        }
        for i in 0..good.len() {
            for v in [0u8, 1, 0x7f, 0x80, 0xff] {
                let mut b = good;
                b[i] = v;
                let _ = decode(&b);
            }
        }
        assert_eq!(decode(&[]), Err(DecodeError::Truncated));
    }
}
