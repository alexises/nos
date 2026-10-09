//! BPDU encoding and decoding, IEEE 802.1Q-2022 clause 14 (and the 802.3
//! framing of 14.x: LLC `42 42 03`, group address `01:80:c2:00:00:00`).
//!
//! Hand-rolled fixed offsets, like `nos-lacp`'s `packet.rs`. Timers stay raw
//! `u16` in 1/256 s so any value a peer sends round-trips byte-exactly.

use crate::vector::{BridgeId, PortId};

pub const STP_GROUP_MAC: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
pub const LLC: [u8; 3] = [0x42, 0x42, 0x03];
/// Longest legal 802.3 length field; above it the field is an ethertype.
pub const MAX_LENGTH_FIELD: usize = 1500;

pub const CONFIG_LEN: usize = 35;
pub const RST_LEN: usize = 36;
pub const TCN_LEN: usize = 4;

const TYPE_CONFIG: u8 = 0x00;
const TYPE_RST: u8 = 0x02;
const TYPE_TCN: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BpduError {
    #[error("truncated BPDU: need {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },
    #[error("protocol identifier {0:#06x} is not 0")]
    BadProtocolId(u16),
    #[error("unknown BPDU type {0:#04x}")]
    UnknownType(u8),
    #[error("RST BPDU with version {0} (need 2 or more)")]
    BadVersion(u8),
    #[error("frame destination is not the bridge group address")]
    BadDestination,
    #[error("length field {0} is an ethertype or exceeds 1500")]
    LengthField(usize),
    #[error("LLC header is not 42 42 03")]
    BadLlc,
}

/// Role carried in an RST BPDU's flags (bits 2-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRole {
    Unknown,
    AlternateBackup,
    Root,
    Designated,
}

/// The flags octet. A Configuration BPDU uses only TC and TC Ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u8);

impl Flags {
    pub const TC: u8 = 1 << 0;
    pub const PROPOSAL: u8 = 1 << 1;
    pub const LEARNING: u8 = 1 << 4;
    pub const FORWARDING: u8 = 1 << 5;
    pub const AGREEMENT: u8 = 1 << 6;
    pub const TC_ACK: u8 = 1 << 7;

    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    #[must_use]
    pub fn with(self, bit: u8, on: bool) -> Self {
        Flags(if on { self.0 | bit } else { self.0 & !bit })
    }

    pub fn role(self) -> PortRole {
        match (self.0 >> 2) & 0b11 {
            0 => PortRole::Unknown,
            1 => PortRole::AlternateBackup,
            2 => PortRole::Root,
            _ => PortRole::Designated,
        }
    }

    #[must_use]
    pub fn with_role(self, role: PortRole) -> Self {
        Flags((self.0 & !0b1100) | ((role as u8) << 2))
    }
}

/// Fields shared by Configuration and RST BPDUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub flags: Flags,
    pub root: BridgeId,
    pub root_path_cost: u32,
    pub bridge: BridgeId,
    pub port: PortId,
    /// Raw 1/256 s units, see [`secs`].
    pub message_age: u16,
    pub max_age: u16,
    pub hello_time: u16,
    pub forward_delay: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bpdu {
    Config(Params),
    Rst(Params),
    Tcn,
}

/// Whole seconds of a raw 1/256 s timer field.
pub fn secs(raw: u16) -> u8 {
    (raw >> 8) as u8
}

/// Raw 1/256 s field for whole seconds.
pub fn raw_secs(s: u8) -> u16 {
    u16::from(s) << 8
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn bridge_at(b: &[u8], at: usize) -> BridgeId {
    BridgeId::from_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// Decode a BPDU body (the bytes after the LLC header). Trailing bytes are
/// ignored; a type 0x02 BPDU of version >= 2 (incl. MSTP's 3) decodes as RST.
pub fn decode(b: &[u8]) -> Result<Bpdu, BpduError> {
    let need = |n: usize| {
        if b.len() < n {
            Err(BpduError::Truncated {
                need: n,
                got: b.len(),
            })
        } else {
            Ok(())
        }
    };
    need(4)?;
    let proto = be16(b, 0);
    if proto != 0 {
        return Err(BpduError::BadProtocolId(proto));
    }
    match b[3] {
        TYPE_TCN => Ok(Bpdu::Tcn),
        TYPE_CONFIG => {
            need(CONFIG_LEN)?;
            Ok(Bpdu::Config(params(b)))
        }
        TYPE_RST => {
            need(RST_LEN)?;
            if b[2] < 2 {
                return Err(BpduError::BadVersion(b[2]));
            }
            Ok(Bpdu::Rst(params(b)))
        }
        t => Err(BpduError::UnknownType(t)),
    }
}

fn params(b: &[u8]) -> Params {
    Params {
        flags: Flags(b[4]),
        root: bridge_at(b, 5),
        root_path_cost: u32::from_be_bytes([b[13], b[14], b[15], b[16]]),
        bridge: bridge_at(b, 17),
        port: PortId::from_u16(be16(b, 25)),
        message_age: be16(b, 27),
        max_age: be16(b, 29),
        hello_time: be16(b, 31),
        forward_delay: be16(b, 33),
    }
}

/// Encode a BPDU body.
pub fn encode(bpdu: &Bpdu) -> Vec<u8> {
    let (version, ty, p) = match bpdu {
        Bpdu::Tcn => return vec![0, 0, 0, TYPE_TCN],
        Bpdu::Config(p) => (0, TYPE_CONFIG, p),
        Bpdu::Rst(p) => (2, TYPE_RST, p),
    };
    let mut v = Vec::with_capacity(RST_LEN);
    v.extend_from_slice(&[0, 0, version, ty, p.flags.0]);
    v.extend_from_slice(&p.root.to_bytes());
    v.extend_from_slice(&p.root_path_cost.to_be_bytes());
    v.extend_from_slice(&p.bridge.to_bytes());
    v.extend_from_slice(&p.port.to_u16().to_be_bytes());
    for t in [p.message_age, p.max_age, p.hello_time, p.forward_delay] {
        v.extend_from_slice(&t.to_be_bytes());
    }
    if version == 2 {
        v.push(0); // Version 1 Length
    }
    v
}

/// A full 802.3 frame: group address, `src_mac`, length field, LLC, body.
pub fn encode_frame(src_mac: [u8; 6], bpdu: &Bpdu) -> Vec<u8> {
    let body = encode(bpdu);
    let mut f = Vec::with_capacity(17 + body.len());
    f.extend_from_slice(&STP_GROUP_MAC);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(
        &u16::try_from(LLC.len() + body.len())
            .expect("small")
            .to_be_bytes(),
    );
    f.extend_from_slice(&LLC);
    f.extend_from_slice(&body);
    f
}

/// Decode a frame as received (padding past the length field is ignored).
/// Returns the source MAC and the BPDU.
pub fn decode_frame(f: &[u8]) -> Result<([u8; 6], Bpdu), BpduError> {
    if f.len() < 14 {
        return Err(BpduError::Truncated {
            need: 14,
            got: f.len(),
        });
    }
    if f[..6] != STP_GROUP_MAC {
        return Err(BpduError::BadDestination);
    }
    let len = usize::from(be16(f, 12));
    if len > MAX_LENGTH_FIELD {
        return Err(BpduError::LengthField(len));
    }
    if f.len() < 14 + len {
        return Err(BpduError::Truncated {
            need: 14 + len,
            got: f.len(),
        });
    }
    let payload = &f[14..14 + len];
    if payload.len() < LLC.len() {
        return Err(BpduError::Truncated {
            need: LLC.len(),
            got: payload.len(),
        });
    }
    if payload[..3] != LLC {
        return Err(BpduError::BadLlc);
    }
    Ok((
        f[6..12].try_into().expect("6 bytes"),
        decode(&payload[3..])?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn params() -> Params {
        Params {
            flags: Flags::default(),
            root: BridgeId::new(4096, 7, [1, 2, 3, 4, 5, 6]).unwrap(),
            root_path_cost: 20_000,
            bridge: BridgeId::new(32768, 0, [6, 5, 4, 3, 2, 1]).unwrap(),
            port: PortId::new(128, 9).unwrap(),
            message_age: 0x0102,
            max_age: raw_secs(20),
            hello_time: raw_secs(2),
            forward_delay: raw_secs(15),
        }
    }

    // Real captures: Config BPDUs sent by the kernel STP of Linux bridges
    // (7.2.9, `ip link add br0 type bridge stp_state 1`, two bridges joined by
    // a veth pair, AF_PACKET socket in a user+net namespace), 802.3 frames
    // without FCS. The kernel speaks legacy STP only: no RST or TCN was
    // emitted, those two vectors below are built from the clause 14 layout.
    const LINUX_ROOT: &str = "0180c20000006ede9ab9a7120026424203000000000080006ede9ab9a7120000000080006ede9ab9a71280020000140002000f00";
    const LINUX_RELAYED: &str = "0180c20000006ede9ab9a7120026424203000000000010000a43176bd8560000000280006ede9ab9a71280020117140002000f00";
    const LINUX_RELAYED_AGE1: &str = "0180c20000006ede9ab9a7120026424203000000000010000a43176bd8560000000280006ede9ab9a71280020001140002000f00";

    #[test]
    fn linux_config_bpdus_decode_byte_exact() {
        let (src, b) = decode_frame(&unhex(LINUX_ROOT)).unwrap();
        assert_eq!(src, [0x6e, 0xde, 0x9a, 0xb9, 0xa7, 0x12]);
        let Bpdu::Config(p) = b else {
            panic!("not config")
        };
        assert_eq!(p.root, p.bridge, "the root names itself");
        assert_eq!(
            (p.root.priority(), p.root_path_cost, p.port.to_u16()),
            (32768, 0, 0x8002)
        );
        assert_eq!(
            (secs(p.max_age), secs(p.hello_time), secs(p.forward_delay)),
            (20, 2, 15)
        );
        assert_eq!(encode_frame(src, &b), unhex(LINUX_ROOT));

        let (src, b) = decode_frame(&unhex(LINUX_RELAYED)).unwrap();
        let Bpdu::Config(p) = b else {
            panic!("not config")
        };
        assert_eq!(
            (p.root.priority(), p.root.mac()),
            (4096, [0x0a, 0x43, 0x17, 0x6b, 0xd8, 0x56])
        );
        assert_eq!((p.root_path_cost, p.message_age), (2, 0x0117));
        assert_eq!(p.bridge.mac(), src);
        assert_eq!(
            encode_frame(src, &b),
            unhex(LINUX_RELAYED),
            "odd message age round-trips"
        );

        let (src, b) = decode_frame(&unhex(LINUX_RELAYED_AGE1)).unwrap();
        assert_eq!(encode_frame(src, &b), unhex(LINUX_RELAYED_AGE1));
    }

    #[test]
    fn rst_and_tcn_vectors_from_the_layout() {
        // Clause 14: RST = 36 bytes, version 2, type 2, Version 1 Length 0.
        // flags 0x7c = agreement + forwarding + learning + role Designated.
        let body = unhex(concat!(
            "000002027c",
            "8000000000000001",
            "00000000",
            "8000000000000002",
            "8001",
            "0000",
            "1400",
            "0200",
            "0f00",
            "00"
        ));
        assert_eq!(body.len(), RST_LEN);
        let Bpdu::Rst(p) = decode(&body).unwrap() else {
            panic!("not rst")
        };
        assert_eq!(p.flags.role(), PortRole::Designated);
        assert!(p.flags.has(Flags::FORWARDING | Flags::LEARNING) && p.flags.has(Flags::AGREEMENT));
        assert!(!p.flags.has(Flags::PROPOSAL));
        assert_eq!(encode(&Bpdu::Rst(p)), body);
        // Clause 14: TCN = protocol id 0, version 0, type 0x80.
        assert_eq!(decode(&[0, 0, 0, 0x80]), Ok(Bpdu::Tcn));
        assert_eq!(encode(&Bpdu::Tcn), [0, 0, 0, 0x80]);
    }

    #[test]
    fn round_trip_every_flag_and_role() {
        for flags in 0..=u8::MAX {
            let p = Params {
                flags: Flags(flags),
                ..params()
            };
            for b in [Bpdu::Config(p), Bpdu::Rst(p)] {
                assert_eq!(decode(&encode(&b)), Ok(b));
            }
        }
        for role in [
            PortRole::Unknown,
            PortRole::AlternateBackup,
            PortRole::Root,
            PortRole::Designated,
        ] {
            let f = Flags(0xff).with_role(role);
            assert_eq!(f.role(), role);
            assert_eq!(f.0 & !0b1100, 0xf3, "other bits untouched");
        }
        let f = Flags::default()
            .with(Flags::TC_ACK, true)
            .with(Flags::TC, true)
            .with(Flags::TC, false);
        assert!(f.has(Flags::TC_ACK) && !f.has(Flags::TC));
        assert_eq!(decode(&encode(&Bpdu::Tcn)), Ok(Bpdu::Tcn));
    }

    #[test]
    fn length_boundaries() {
        for (b, len) in [
            (Bpdu::Config(params()), CONFIG_LEN),
            (Bpdu::Rst(params()), RST_LEN),
            (Bpdu::Tcn, TCN_LEN),
        ] {
            let body = encode(&b);
            assert_eq!(body.len(), len);
            assert_eq!(decode(&body), Ok(b));
            let mut long = body.clone();
            long.extend_from_slice(&[0xaa, 0xbb]);
            assert_eq!(decode(&long), Ok(b), "trailing bytes ignored");
            assert_eq!(
                decode(&body[..len - 1]),
                Err(BpduError::Truncated {
                    need: len,
                    got: len - 1
                })
            );
        }
        assert_eq!(decode(&[]), Err(BpduError::Truncated { need: 4, got: 0 }));
    }

    #[test]
    fn rejects_malformed() {
        let mut b = encode(&Bpdu::Config(params()));
        b[1] = 1;
        assert_eq!(decode(&b), Err(BpduError::BadProtocolId(1)));
        let mut b = encode(&Bpdu::Config(params()));
        b[3] = 0x42;
        assert_eq!(decode(&b), Err(BpduError::UnknownType(0x42)));
        let mut b = encode(&Bpdu::Rst(params()));
        b[2] = 1;
        assert_eq!(decode(&b), Err(BpduError::BadVersion(1)));
        b[2] = 3; // MSTP: version 3 still decodes as RST.
        assert!(matches!(decode(&b), Ok(Bpdu::Rst(_))));
    }

    #[test]
    fn frame_checks() {
        let src = [2, 0, 0, 0, 0, 1];
        let f = encode_frame(src, &Bpdu::Config(params()));
        assert_eq!(&f[12..17], &[0, 38, 0x42, 0x42, 0x03]);
        assert_eq!(decode_frame(&f), Ok((src, Bpdu::Config(params()))));
        let mut padded = f.clone();
        padded.resize(60, 0);
        assert_eq!(
            decode_frame(&padded),
            Ok((src, Bpdu::Config(params()))),
            "NIC padding ignored"
        );
        assert!(matches!(
            decode_frame(&f[..f.len() - 1]),
            Err(BpduError::Truncated { .. })
        ));
        assert!(matches!(
            decode_frame(&f[..10]),
            Err(BpduError::Truncated { need: 14, got: 10 })
        ));
        let mut g = f.clone();
        g[0] = 0x02;
        assert_eq!(decode_frame(&g), Err(BpduError::BadDestination));
        let mut g = f.clone();
        g[12..14].copy_from_slice(&1500u16.to_be_bytes());
        assert!(
            matches!(decode_frame(&g), Err(BpduError::Truncated { .. })),
            "1500 is still a length"
        );
        g[12..14].copy_from_slice(&1501u16.to_be_bytes());
        assert_eq!(decode_frame(&g), Err(BpduError::LengthField(1501)));
        let mut g = f.clone();
        g[14] = 0xaa;
        assert_eq!(decode_frame(&g), Err(BpduError::BadLlc));
        let mut g = f[..16].to_vec();
        g[12..14].copy_from_slice(&2u16.to_be_bytes());
        assert!(matches!(
            decode_frame(&g),
            Err(BpduError::Truncated { need: 3, got: 2 })
        ));
    }
}
