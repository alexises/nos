//! Cisco SSTP framing for PVST+/Rapid-PVST+ (#322; proprietary, no RFC): an
//! 802.3 frame to `01:00:0c:cc:cc:cd`, LLC `AA AA 03`, SNAP OUI `00:00:0c`
//! PID `0x010b`, the 802.1D/RSTP BPDU as in [`crate::bpdu`], then the
//! optional Originating VLAN TLV (type 0, length 2, VLAN id).
//!
//! The layout follows Wireshark's `packet-stp.c` (SSTP: `stp_pvid` trailer
//! after the BPDU, `SNAP PID 0x010b`); the test vectors are assembled by hand
//! from that layout, not captured from a Cisco switch.

use crate::bpdu::{self, Bpdu, BpduError};

pub const SSTP_GROUP_MAC: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd];
/// LLC `AA AA 03`, OUI `00:00:0c`, PID `0x010b`.
pub const LLC_SNAP: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x0b];
const TLV_VLAN: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SstpError {
    #[error("truncated SSTP frame")]
    Truncated,
    #[error("frame destination is not the SSTP group address")]
    BadDestination,
    #[error("length field {0} is an ethertype or exceeds 1500")]
    LengthField(usize),
    #[error("LLC/SNAP header is not AA AA 03 00 00 0C 01 0B")]
    BadSnap,
    #[error("originating VLAN TLV is malformed")]
    BadTlv,
    #[error(transparent)]
    Bpdu(#[from] BpduError),
}

/// What an SSTP frame carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sstp {
    pub bpdu: Bpdu,
    /// The sender's Originating VLAN TLV; `None` from an older PVST+.
    pub pvid: Option<u16>,
}

/// The body length of the BPDU at the start of `b`.
fn bpdu_len(b: &[u8]) -> usize {
    match b.get(3) {
        Some(0x80) => bpdu::TCN_LEN,
        Some(0x02) => bpdu::RST_LEN,
        _ => bpdu::CONFIG_LEN,
    }
}

/// A complete frame: `bpdu` followed by the TLV naming `vid`.
pub fn encode_frame(src_mac: [u8; 6], bpdu: &Bpdu, vid: u16) -> Vec<u8> {
    let body = bpdu::encode(bpdu);
    let len = LLC_SNAP.len() + body.len() + 6;
    let mut f = Vec::with_capacity(14 + len);
    f.extend_from_slice(&SSTP_GROUP_MAC);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&u16::try_from(len).expect("small").to_be_bytes());
    f.extend_from_slice(&LLC_SNAP);
    f.extend_from_slice(&body);
    f.extend_from_slice(&TLV_VLAN.to_be_bytes());
    f.extend_from_slice(&2u16.to_be_bytes());
    f.extend_from_slice(&vid.to_be_bytes());
    f
}

/// Decodes a frame as received; padding past the length field is ignored.
pub fn decode_frame(f: &[u8]) -> Result<([u8; 6], Sstp), SstpError> {
    if f.len() < 14 {
        return Err(SstpError::Truncated);
    }
    if f[..6] != SSTP_GROUP_MAC {
        return Err(SstpError::BadDestination);
    }
    let len = usize::from(u16::from_be_bytes([f[12], f[13]]));
    if len > bpdu::MAX_LENGTH_FIELD {
        return Err(SstpError::LengthField(len));
    }
    let payload = f.get(14..14 + len).ok_or(SstpError::Truncated)?;
    if payload.len() < LLC_SNAP.len() || payload[..8] != LLC_SNAP {
        return Err(SstpError::BadSnap);
    }
    let body = &payload[8..];
    let parsed = bpdu::decode(body)?;
    let rest = &body[bpdu_len(body)..];
    let pvid = match rest {
        [] => None,
        [0, 0, 0, 2, a, b, ..] => Some(u16::from_be_bytes([*a, *b])),
        _ => return Err(SstpError::BadTlv),
    };
    Ok((
        f[6..12].try_into().expect("6 bytes"),
        Sstp { bpdu: parsed, pvid },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpdu::{Flags, Params};
    use crate::vector::{BridgeId, PortId};

    fn params() -> Params {
        Params {
            flags: Flags(0x3c),
            root: BridgeId::new(4096, 10, [0, 0x1b, 0x54, 1, 2, 3]).unwrap(),
            root_path_cost: 4,
            bridge: BridgeId::new(32768, 10, [0, 0x1b, 0x54, 1, 2, 3]).unwrap(),
            port: PortId::new(128, 1).unwrap(),
            message_age: 0,
            max_age: 20 << 8,
            hello_time: 2 << 8,
            forward_delay: 15 << 8,
        }
    }

    const SRC: [u8; 6] = [0, 0x1b, 0x54, 1, 2, 3];

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        b.iter().fold(String::new(), |mut s, x| {
            write!(s, "{x:02x}").unwrap();
            s
        })
    }

    /// Rapid-PVST+ VLAN 10 frame laid out as in Wireshark's packet-stp.c.
    #[test]
    fn rapid_pvst_frame_has_the_documented_layout() {
        let f = encode_frame(SRC, &Bpdu::Rst(params()), 10);
        assert_eq!(
            hex(&f),
            concat!(
                "01000ccccccd",
                "001b54010203",
                "0032", // 802.3: 8 + 36 + 6 = 50
                "aaaa03",
                "00000c",
                "010b", // LLC + SNAP
                "0000",
                "02",
                "02",
                "3c", // proto, version 2, type RST, flags
                "100a001b54010203",
                "00000004", // root id, path cost
                "800a001b54010203",
                "8001", // bridge id, port id
                "0000",
                "1400",
                "0200",
                "0f00",
                "00", // ages, version 1 length
                "0000",
                "0002",
                "000a", // originating VLAN TLV
            )
        );
        let (src, d) = decode_frame(&f).unwrap();
        assert_eq!((src, d.bpdu, d.pvid), (SRC, Bpdu::Rst(params()), Some(10)));
    }

    #[test]
    fn config_and_tcn_round_trip_with_their_tlv() {
        for bpdu in [Bpdu::Config(params()), Bpdu::Tcn] {
            let f = encode_frame(SRC, &bpdu, 4094);
            let (_, d) = decode_frame(&f).unwrap();
            assert_eq!((d.bpdu, d.pvid), (bpdu, Some(4094)));
            assert_eq!(encode_frame(SRC, &d.bpdu, d.pvid.unwrap()), f);
        }
    }

    #[test]
    fn a_frame_without_the_tlv_is_an_older_pvst_plus() {
        let mut f = encode_frame(SRC, &Bpdu::Config(params()), 1);
        f.truncate(f.len() - 6);
        let len = u16::try_from(f.len() - 14).unwrap();
        f[12..14].copy_from_slice(&len.to_be_bytes());
        let (_, d) = decode_frame(&f).unwrap();
        assert_eq!(d.pvid, None);
        // NIC padding past the length field is not a TLV
        f.resize(60, 0);
        assert_eq!(decode_frame(&f).unwrap().1.pvid, None);
    }

    #[test]
    fn rejects_bad_destination_snap_tlv_and_truncation() {
        let good = encode_frame(SRC, &Bpdu::Rst(params()), 10);
        let mut f = good.clone();
        f[0] = 0x02;
        assert_eq!(decode_frame(&f), Err(SstpError::BadDestination));
        let mut f = good.clone();
        f[19] = 0x0d; // OUI byte
        assert_eq!(decode_frame(&f), Err(SstpError::BadSnap));
        let mut f = good.clone();
        f[21] = 0x0b; // PID 0x0b0b
        f[20] = 0x0b;
        assert_eq!(decode_frame(&f), Err(SstpError::BadSnap));
        let mut f = good.clone();
        let n = f.len();
        f[n - 3] = 3; // TLV length 3
        assert_eq!(decode_frame(&f), Err(SstpError::BadTlv));
        let mut f = good.clone();
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(decode_frame(&f), Err(SstpError::LengthField(0x0800)));
        assert_eq!(decode_frame(&good[..20]), Err(SstpError::Truncated));
        assert_eq!(decode_frame(&good[..5]), Err(SstpError::Truncated));
    }
}
