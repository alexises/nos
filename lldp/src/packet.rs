//! Hand-rolled LLDPDU encode/decode (IEEE 802.1AB §8): a run of TLVs, each a
//! 16-bit header (7-bit type, 9-bit length) plus a value, terminated by an End
//! TLV. Pure, no I/O — mirrors `nos-lacp`'s `packet.rs` style. Input is
//! untrusted wire data, so `decode` bounds-checks every length and never
//! panics.

use thiserror::Error;

const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
const TLV_TTL: u8 = 3;
const TLV_PORT_DESCRIPTION: u8 = 4;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESCRIPTION: u8 = 6;
const TLV_SYSTEM_CAPABILITIES: u8 = 7;

/// Chassis ID subtype 4: a MAC address.
pub const CHASSIS_SUBTYPE_MAC: u8 = 4;
/// Port ID subtype 5: an interface name.
pub const PORT_SUBTYPE_IF_NAME: u8 = 5;

/// System Capabilities bit for "Router" (802.1AB Table 8-4).
pub const CAP_ROUTER: u16 = 0x0010;

/// Longest value any single TLV can carry (9-bit length field).
const MAX_TLV_VALUE: usize = 511;
/// Chassis/Port ID values are a 1-byte subtype plus up to 255 bytes.
const MAX_ID_VALUE: usize = 255;

/// A Chassis ID or Port ID: a subtype byte plus an opaque value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id {
    pub subtype: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub supported: u16,
    pub enabled: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lldpdu {
    pub chassis_id: Id,
    pub port_id: Id,
    /// Seconds the receiver should keep this neighbor. `0` is a shutdown
    /// LLDPDU: the sender is going away, forget it now.
    pub ttl: u16,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub capabilities: Option<Capabilities>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("truncated TLV")]
    Truncated,
    #[error("mandatory TLVs missing or out of order")]
    MissingMandatory,
    #[error("malformed {0} TLV")]
    Malformed(&'static str),
    #[error("duplicate mandatory TLV")]
    Duplicate,
}

impl Lldpdu {
    /// Chassis ID rendered for humans and logs: a MAC as `aa:bb:..`, a text
    /// subtype as its text, anything else as hex.
    pub fn chassis_display(&self) -> String {
        match (self.chassis_id.subtype, self.chassis_id.value.len()) {
            (CHASSIS_SUBTYPE_MAC, 6) => mac_str(&self.chassis_id.value),
            // interface alias / port component / interface name / locally assigned
            (1..=3 | 6 | 7, _) => text_or_hex(&self.chassis_id.value),
            _ => hex(&self.chassis_id.value),
        }
    }

    /// Port ID rendered like `chassis_display`.
    pub fn port_display(&self) -> String {
        match (self.port_id.subtype, self.port_id.value.len()) {
            (3, 6) => mac_str(&self.port_id.value),
            // interface alias / port component / interface name / circuit id / locally assigned
            (1 | 2 | 5..=7, _) => text_or_hex(&self.port_id.value),
            _ => hex(&self.port_id.value),
        }
    }

    /// Names of the capabilities the sender has *enabled*.
    pub fn enabled_capability_names(&self) -> Vec<String> {
        const NAMES: [(u16, &str); 11] = [
            (0x0001, "other"),
            (0x0002, "repeater"),
            (0x0004, "bridge"),
            (0x0008, "wlan-ap"),
            (0x0010, "router"),
            (0x0020, "telephone"),
            (0x0040, "docsis"),
            (0x0080, "station"),
            (0x0100, "c-vlan"),
            (0x0200, "s-vlan"),
            (0x0400, "tpmr"),
        ];
        let enabled = self.capabilities.map_or(0, |c| c.enabled);
        NAMES
            .iter()
            .filter(|(bit, _)| enabled & bit != 0)
            .map(|(_, name)| (*name).to_string())
            .collect()
    }
}

fn mac_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

fn text_or_hex(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.chars().all(|c| !c.is_control()) => s.to_string(),
        _ => hex(bytes),
    }
}

fn push_tlv(out: &mut Vec<u8>, tlv_type: u8, value: &[u8]) {
    let value = &value[..value.len().min(MAX_TLV_VALUE)];
    let header = (u16::from(tlv_type) << 9) | u16::try_from(value.len()).expect("<= 511");
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(value);
}

fn push_id(out: &mut Vec<u8>, tlv_type: u8, id: &Id) {
    let mut value = vec![id.subtype];
    value.extend_from_slice(&id.value[..id.value.len().min(MAX_ID_VALUE)]);
    push_tlv(out, tlv_type, &value);
}

/// Encodes `pdu` as an LLDPDU (no Ethernet header), ending with the End TLV.
pub fn encode(pdu: &Lldpdu) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    push_id(&mut out, TLV_CHASSIS_ID, &pdu.chassis_id);
    push_id(&mut out, TLV_PORT_ID, &pdu.port_id);
    push_tlv(&mut out, TLV_TTL, &pdu.ttl.to_be_bytes());
    if let Some(s) = &pdu.port_description {
        push_tlv(&mut out, TLV_PORT_DESCRIPTION, s.as_bytes());
    }
    if let Some(s) = &pdu.system_name {
        push_tlv(&mut out, TLV_SYSTEM_NAME, s.as_bytes());
    }
    if let Some(s) = &pdu.system_description {
        push_tlv(&mut out, TLV_SYSTEM_DESCRIPTION, s.as_bytes());
    }
    if let Some(c) = pdu.capabilities {
        let mut value = c.supported.to_be_bytes().to_vec();
        value.extend_from_slice(&c.enabled.to_be_bytes());
        push_tlv(&mut out, TLV_SYSTEM_CAPABILITIES, &value);
    }
    push_tlv(&mut out, TLV_END, &[]);
    out
}

/// Decodes an LLDPDU. The first three TLVs must be Chassis ID, Port ID and TTL
/// in that order; unknown optional TLVs are skipped; anything after the End TLV
/// (Ethernet padding) is ignored.
pub fn decode(mut data: &[u8]) -> Result<Lldpdu, DecodeError> {
    let mut chassis_id = None;
    let mut port_id = None;
    let mut ttl = None;
    let mut pdu = Lldpdu {
        chassis_id: Id {
            subtype: 0,
            value: Vec::new(),
        },
        port_id: Id {
            subtype: 0,
            value: Vec::new(),
        },
        ttl: 0,
        port_description: None,
        system_name: None,
        system_description: None,
        capabilities: None,
    };

    while !data.is_empty() {
        if data.len() < 2 {
            return Err(DecodeError::Truncated);
        }
        let header = u16::from_be_bytes([data[0], data[1]]);
        let tlv_type = u8::try_from(header >> 9).expect("7 bits");
        let len = usize::from(header & 0x01ff);
        let value = data.get(2..2 + len).ok_or(DecodeError::Truncated)?;
        data = &data[2 + len..];

        // The three mandatory TLVs come first, in order, and only once.
        match (
            tlv_type,
            chassis_id.is_some(),
            port_id.is_some(),
            ttl.is_some(),
        ) {
            (TLV_CHASSIS_ID, false, false, false) => {
                chassis_id = Some(decode_id(value, "chassis id")?);
                continue;
            }
            (TLV_PORT_ID, true, false, false) => {
                port_id = Some(decode_id(value, "port id")?);
                continue;
            }
            (TLV_TTL, true, true, false) => {
                let bytes: [u8; 2] = value
                    .try_into()
                    .map_err(|_| DecodeError::Malformed("ttl"))?;
                ttl = Some(u16::from_be_bytes(bytes));
                continue;
            }
            (TLV_CHASSIS_ID | TLV_PORT_ID | TLV_TTL, ..) if ttl.is_some() => {
                return Err(DecodeError::Duplicate)
            }
            (TLV_END, ..) => break,
            (_, true, true, true) => {}
            _ => return Err(DecodeError::MissingMandatory),
        }

        match tlv_type {
            TLV_PORT_DESCRIPTION => pdu.port_description = Some(lossy(value)),
            TLV_SYSTEM_NAME => pdu.system_name = Some(lossy(value)),
            TLV_SYSTEM_DESCRIPTION => pdu.system_description = Some(lossy(value)),
            TLV_SYSTEM_CAPABILITIES => {
                if value.len() != 4 {
                    return Err(DecodeError::Malformed("system capabilities"));
                }
                pdu.capabilities = Some(Capabilities {
                    supported: u16::from_be_bytes([value[0], value[1]]),
                    enabled: u16::from_be_bytes([value[2], value[3]]),
                });
            }
            _ => {} // unknown / organizationally specific: skip
        }
    }

    pdu.chassis_id = chassis_id.ok_or(DecodeError::MissingMandatory)?;
    pdu.port_id = port_id.ok_or(DecodeError::MissingMandatory)?;
    pdu.ttl = ttl.ok_or(DecodeError::MissingMandatory)?;
    Ok(pdu)
}

fn decode_id(value: &[u8], what: &'static str) -> Result<Id, DecodeError> {
    match value.split_first() {
        Some((&subtype, rest)) if !rest.is_empty() && rest.len() <= MAX_ID_VALUE => Ok(Id {
            subtype,
            value: rest.to_vec(),
        }),
        _ => Err(DecodeError::Malformed(what)),
    }
}

/// Text from the wire, made safe to print. These strings end up in `nos-cli`
/// output and in logs, and a neighbor is untrusted: control characters (an
/// ANSI escape sequence, a carriage return that overwrites a line) are
/// replaced rather than passed through.
fn lossy(value: &[u8]) -> String {
    String::from_utf8_lossy(value)
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Lldpdu {
        Lldpdu {
            chassis_id: Id {
                subtype: CHASSIS_SUBTYPE_MAC,
                value: vec![2, 0, 0, 0, 0, 1],
            },
            port_id: Id {
                subtype: PORT_SUBTYPE_IF_NAME,
                value: b"eth1".to_vec(),
            },
            ttl: 120,
            port_description: Some("eth1".to_string()),
            system_name: Some("router-a".to_string()),
            system_description: Some("nos 0.1.0".to_string()),
            capabilities: Some(Capabilities {
                supported: CAP_ROUTER,
                enabled: CAP_ROUTER,
            }),
        }
    }

    #[test]
    fn round_trips() {
        let pdu = sample();
        assert_eq!(decode(&encode(&pdu)).unwrap(), pdu);
    }

    #[test]
    fn mandatory_only_round_trips_and_shutdown_ttl_is_zero() {
        let mut pdu = sample();
        pdu.ttl = 0;
        pdu.port_description = None;
        pdu.system_name = None;
        pdu.system_description = None;
        pdu.capabilities = None;
        assert_eq!(decode(&encode(&pdu)).unwrap().ttl, 0);
    }

    #[test]
    fn display_and_capabilities() {
        let pdu = sample();
        assert_eq!(pdu.chassis_display(), "02:00:00:00:00:01");
        assert_eq!(pdu.port_display(), "eth1");
        assert_eq!(pdu.enabled_capability_names(), vec!["router".to_string()]);
    }

    #[test]
    fn trailing_padding_after_end_tlv_is_ignored() {
        let mut bytes = encode(&sample());
        bytes.extend_from_slice(&[0; 20]);
        assert_eq!(decode(&bytes).unwrap(), sample());
    }

    #[test]
    fn unknown_optional_tlv_is_skipped() {
        let mut bytes = encode(&sample());
        // Splice an organizationally-specific TLV (type 127) in before the End TLV.
        bytes.truncate(bytes.len() - 2);
        push_tlv(&mut bytes, 127, &[0x00, 0x80, 0xc2, 0x01, 0xff]);
        push_tlv(&mut bytes, TLV_END, &[]);
        assert_eq!(decode(&bytes).unwrap(), sample());
    }

    #[test]
    fn rejects_truncated_tlv() {
        let bytes = encode(&sample());
        assert_eq!(decode(&bytes[..10]), Err(DecodeError::Truncated));
        assert_eq!(decode(&bytes[..1]), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_missing_or_misordered_mandatory_tlvs() {
        // Port ID first.
        let mut bytes = Vec::new();
        push_id(&mut bytes, TLV_PORT_ID, &sample().port_id);
        push_id(&mut bytes, TLV_CHASSIS_ID, &sample().chassis_id);
        push_tlv(&mut bytes, TLV_TTL, &120u16.to_be_bytes());
        assert_eq!(decode(&bytes), Err(DecodeError::MissingMandatory));

        // No TTL.
        let mut bytes = Vec::new();
        push_id(&mut bytes, TLV_CHASSIS_ID, &sample().chassis_id);
        push_id(&mut bytes, TLV_PORT_ID, &sample().port_id);
        push_tlv(&mut bytes, TLV_END, &[]);
        assert_eq!(decode(&bytes), Err(DecodeError::MissingMandatory));

        assert_eq!(decode(&[]), Err(DecodeError::MissingMandatory));
    }

    #[test]
    fn rejects_duplicate_mandatory_tlv_and_bad_lengths() {
        let mut bytes = encode(&sample());
        bytes.truncate(bytes.len() - 2);
        push_id(&mut bytes, TLV_CHASSIS_ID, &sample().chassis_id);
        assert_eq!(decode(&bytes), Err(DecodeError::Duplicate));

        let mut bytes = Vec::new();
        push_id(&mut bytes, TLV_CHASSIS_ID, &sample().chassis_id);
        push_id(&mut bytes, TLV_PORT_ID, &sample().port_id);
        push_tlv(&mut bytes, TLV_TTL, &[1]); // 1 byte, not 2
        assert_eq!(decode(&bytes), Err(DecodeError::Malformed("ttl")));

        let mut bytes = Vec::new();
        push_tlv(&mut bytes, TLV_CHASSIS_ID, &[CHASSIS_SUBTYPE_MAC]); // subtype, no value
        assert_eq!(decode(&bytes), Err(DecodeError::Malformed("chassis id")));
    }

    #[test]
    fn control_characters_in_neighbor_text_are_neutralized() {
        let mut pdu = sample();
        pdu.system_name = Some("evil\x1b[2Jname\r".to_string());
        pdu.port_description = Some("a\nb".to_string());
        let decoded = decode(&encode(&pdu)).unwrap();
        assert_eq!(
            decoded.system_name.as_deref(),
            Some("evil\u{fffd}[2Jname\u{fffd}")
        );
        assert_eq!(decoded.port_description.as_deref(), Some("a\u{fffd}b"));
    }

    #[test]
    fn non_text_ids_fall_back_to_hex() {
        let mut pdu = sample();
        pdu.port_id = Id {
            subtype: PORT_SUBTYPE_IF_NAME,
            value: vec![0xff, 0x00, 0x01],
        };
        pdu.chassis_id = Id {
            subtype: 5,
            value: vec![1, 10, 0, 0, 1],
        };
        assert_eq!(pdu.port_display(), "ff0001");
        assert_eq!(pdu.chassis_display(), "010a000001");
    }
}
