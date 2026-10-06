//! Hand-rolled LACPDU encode/decode — IEEE 802.1AX-2014 §6.4.2.3 (Figure
//! 6-2). Pure, no I/O, no `nos-proto` dependency, mirroring `ospf::packet`'s
//! shape. A LACPDU's body is always exactly [`LACPDU_LEN`] bytes: fixed-size
//! Actor/Partner/Collector Information TLVs plus a Terminator TLV and
//! trailing reserved padding — no variable-length fields, so there is
//! nothing a parsing crate would buy over hand-rolled offsets.

const SUBTYPE_LACP: u8 = 0x01;
const VERSION_NUMBER: u8 = 0x01;

const TLV_TYPE_TERMINATOR: u8 = 0x00;
const TLV_TYPE_ACTOR: u8 = 0x01;
const TLV_TYPE_PARTNER: u8 = 0x02;
const TLV_TYPE_COLLECTOR: u8 = 0x03;

const ACTOR_PARTNER_INFO_LEN: u8 = 20;
const COLLECTOR_INFO_LEN: u8 = 16;

/// The LACPDU body's fixed on-wire length (Subtype through the trailing
/// Reserved field, 802.1AX Figure 6-2) — never anything else, so a decode
/// whose input is a different length is rejected outright rather than
/// partially parsed.
pub const LACPDU_LEN: usize = 110;

const SUBTYPE_MARKER: u8 = 0x02;
const TLV_MARKER_INFO: u8 = 0x01;
const TLV_MARKER_RESPONSE: u8 = 0x02;
const MARKER_INFO_LEN: u8 = 16;

/// A Marker PDU's requester fields (802.1AX §6.5.3.3) — exactly what a
/// Marker Response must echo back. We only ever respond, never generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    pub requester_port: u16,
    pub requester_system: [u8; 6],
    pub transaction_id: u32,
}

/// Decodes a Marker *request* (TLV 0x01); a Marker Response, a LACPDU or
/// anything short gives `None`. Like `decode`, reads fixed offsets only: the
/// length, version and terminator bytes are not validated (Linux sends 0x16
/// where the standard says 16).
pub fn decode_marker(data: &[u8]) -> Option<Marker> {
    if data.len() < 16 || data[0] != SUBTYPE_MARKER || data[2] != TLV_MARKER_INFO {
        return None;
    }
    Some(Marker {
        requester_port: u16::from_be_bytes([data[4], data[5]]),
        requester_system: data[6..12].try_into().unwrap(),
        transaction_id: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
    })
}

/// A clean Marker Response PDU (same 110-byte body as a LACPDU).
pub fn encode_marker_response(m: &Marker) -> Vec<u8> {
    let mut buf = Vec::with_capacity(LACPDU_LEN);
    buf.extend_from_slice(&[
        SUBTYPE_MARKER,
        VERSION_NUMBER,
        TLV_MARKER_RESPONSE,
        MARKER_INFO_LEN,
    ]);
    buf.extend_from_slice(&m.requester_port.to_be_bytes());
    buf.extend_from_slice(&m.requester_system);
    buf.extend_from_slice(&m.transaction_id.to_be_bytes());
    buf.resize(LACPDU_LEN, 0); // pad, terminator TLV and reserved are all zero
    buf
}

/// 802.1AX Table 6-4 Actor/Partner State bit positions (LSB-first).
pub mod state_bit {
    pub const ACTIVITY: u8 = 1 << 0;
    pub const TIMEOUT: u8 = 1 << 1;
    pub const AGGREGATION: u8 = 1 << 2;
    pub const SYNCHRONIZATION: u8 = 1 << 3;
    pub const COLLECTING: u8 = 1 << 4;
    pub const DISTRIBUTING: u8 = 1 << 5;
    pub const DEFAULTED: u8 = 1 << 6;
    pub const EXPIRED: u8 = 1 << 7;
}

/// One side's (Actor's or Partner's) Information TLV contents — identical
/// shape for both, per 802.1AX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortInfo {
    pub system_priority: u16,
    pub system: [u8; 6],
    pub key: u16,
    pub port_priority: u16,
    pub port: u16,
    pub state: u8,
}

impl PortInfo {
    pub fn has_state(&self, bit: u8) -> bool {
        self.state & bit != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lacpdu {
    pub actor: PortInfo,
    pub partner: PortInfo,
    /// 802.1AX's `Collector_Max_Delay` — advertised but never acted on by
    /// this implementation (no frame-collection/distribution delay logic;
    /// the kernel bond handles actual frame forwarding once a port is
    /// pushed into the active-member set). Round-tripped so a real partner
    /// switch sees a plausible, non-zero value.
    pub collector_max_delay: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("LACPDU has wrong length: expected {LACPDU_LEN}, got {0}")]
    WrongLength(usize),
    #[error("not an LACP slow-protocol frame (subtype {0:#04x})")]
    WrongSubtype(u8),
}

fn encode_port_info(buf: &mut Vec<u8>, tlv_type: u8, info: &PortInfo) {
    buf.push(tlv_type);
    buf.push(ACTOR_PARTNER_INFO_LEN);
    buf.extend_from_slice(&info.system_priority.to_be_bytes());
    buf.extend_from_slice(&info.system);
    buf.extend_from_slice(&info.key.to_be_bytes());
    buf.extend_from_slice(&info.port_priority.to_be_bytes());
    buf.extend_from_slice(&info.port.to_be_bytes());
    buf.push(info.state);
    buf.extend_from_slice(&[0u8; 3]); // reserved
}

pub fn encode(pdu: &Lacpdu) -> Vec<u8> {
    let mut buf = Vec::with_capacity(LACPDU_LEN);
    buf.push(SUBTYPE_LACP);
    buf.push(VERSION_NUMBER);
    encode_port_info(&mut buf, TLV_TYPE_ACTOR, &pdu.actor);
    encode_port_info(&mut buf, TLV_TYPE_PARTNER, &pdu.partner);
    buf.push(TLV_TYPE_COLLECTOR);
    buf.push(COLLECTOR_INFO_LEN);
    buf.extend_from_slice(&pdu.collector_max_delay.to_be_bytes());
    buf.extend_from_slice(&[0u8; 12]); // reserved
    buf.push(TLV_TYPE_TERMINATOR);
    buf.push(0);
    buf.extend_from_slice(&[0u8; 50]); // reserved
    debug_assert_eq!(buf.len(), LACPDU_LEN);
    buf
}

fn decode_port_info(buf: &[u8]) -> PortInfo {
    PortInfo {
        system_priority: u16::from_be_bytes([buf[0], buf[1]]),
        system: buf[2..8].try_into().unwrap(),
        key: u16::from_be_bytes([buf[8], buf[9]]),
        port_priority: u16::from_be_bytes([buf[10], buf[11]]),
        port: u16::from_be_bytes([buf[12], buf[13]]),
        state: buf[14],
        // buf[15..18] is reserved, ignored.
    }
}

/// Decodes a LACPDU body (the raw slow-protocol payload, Ethernet header
/// already stripped — see `socket::LacpSocket::recv`). Deliberately
/// tolerant of TLV type/length fields that don't match a real partner's own
/// implementation exactly (never rejects on those), since only the fixed
/// byte offsets are actually read — every real-world LACP implementation
/// sends this same fixed layout, and rejecting on cosmetic mismatches would
/// only make interop worse, not safer.
pub fn decode(data: &[u8]) -> Result<Lacpdu, PacketError> {
    if data.len() != LACPDU_LEN {
        return Err(PacketError::WrongLength(data.len()));
    }
    if data[0] != SUBTYPE_LACP {
        return Err(PacketError::WrongSubtype(data[0]));
    }
    // data[1] is the version number — not validated: 802.1AX requires an
    // implementation compliant with a later revision to still interoperate
    // with 802.1AX-2014's fixed TLV layout, which is all this decodes.
    // Layout (802.1AX Figure 6-2): Subtype(1) + Version(1) = 2, then each
    // TLV is `type(1) + length(1) + content`. Actor TLV content starts at
    // offset 4 (18 content bytes, its own trailing 3-byte reserved field
    // included but unread below); Partner TLV's header is at 22-23, its
    // content at 24; Collector TLV's header is at 42-43, its content
    // (`Collector_Max_Delay`) at 44.
    let actor = decode_port_info(&data[4..22]);
    let partner = decode_port_info(&data[24..42]);
    let collector_max_delay = u16::from_be_bytes([data[44], data[45]]);
    Ok(Lacpdu {
        actor,
        partner,
        collector_max_delay,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> PortInfo {
        PortInfo {
            system_priority: 32768,
            system: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            key: 7,
            port_priority: 32768,
            port: 1,
            state: state_bit::ACTIVITY | state_bit::AGGREGATION | state_bit::SYNCHRONIZATION,
        }
    }

    #[test]
    fn round_trips() {
        let pdu = Lacpdu {
            actor: sample_info(),
            partner: sample_info(),
            collector_max_delay: 0,
        };
        let encoded = encode(&pdu);
        assert_eq!(encoded.len(), LACPDU_LEN);
        assert_eq!(decode(&encoded).unwrap(), pdu);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert_eq!(decode(&[0u8; 50]), Err(PacketError::WrongLength(50)));
    }

    #[test]
    fn wrong_subtype_is_rejected() {
        let mut buf = encode(&Lacpdu {
            actor: sample_info(),
            partner: sample_info(),
            collector_max_delay: 0,
        });
        buf[0] = 0x02; // Marker protocol subtype, not LACP
        assert_eq!(decode(&buf), Err(PacketError::WrongSubtype(0x02)));
    }

    fn marker_pdu(tlv: u8, len_byte: u8) -> Vec<u8> {
        let mut b = vec![0u8; LACPDU_LEN];
        b[..4].copy_from_slice(&[0x02, 0x01, tlv, len_byte]);
        b[4..6].copy_from_slice(&7u16.to_be_bytes());
        b[6..12].copy_from_slice(&[2, 0, 0, 0, 0x0b, 7]);
        b[12..16].copy_from_slice(&0x4e4f_5359_u32.to_be_bytes());
        b
    }

    #[test]
    fn marker_response_echoes_requester() {
        let m = decode_marker(&marker_pdu(1, 0x16)).expect("linux-shaped marker");
        assert_eq!(m.requester_port, 7);
        let r = encode_marker_response(&m);
        assert_eq!(r.len(), LACPDU_LEN);
        assert_eq!(&r[..4], &[0x02, 0x01, 0x02, 0x10]);
        assert_eq!(&r[4..16], &marker_pdu(1, 0)[4..16]);
        assert!(r[16..].iter().all(|b| *b == 0));
    }

    #[test]
    fn decode_marker_ignores_responses_lacpdus_and_short() {
        assert_eq!(decode_marker(&marker_pdu(2, 0x10)), None);
        assert_eq!(decode_marker(&marker_pdu(1, 0x10)[..15]), None);
        let lacpdu = encode(&Lacpdu {
            actor: sample_info(),
            partner: sample_info(),
            collector_max_delay: 0,
        });
        assert_eq!(decode_marker(&lacpdu), None);
    }

    #[test]
    fn state_bits_round_trip() {
        let info = sample_info();
        assert!(info.has_state(state_bit::ACTIVITY));
        assert!(!info.has_state(state_bit::COLLECTING));
    }
}
