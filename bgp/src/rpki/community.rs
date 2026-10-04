//! RFC 8097 BGP Prefix Origin Validation State Extended Community: type
//! 0x43 (opaque, non-transitive), subtype 0x00, the state in the last octet.

use nos_rpl::ValidationState;

const HI: u64 = 0x4300 << 48;
const HI_MASK: u64 = 0xffff << 48;

/// Whether `c` is an RFC 8097 community, whatever its state octet.
pub fn is_ov(c: u64) -> bool {
    c & HI_MASK == HI
}

pub fn encode(state: ValidationState) -> u64 {
    HI | match state {
        ValidationState::Valid => 0,
        ValidationState::NotFound => 1,
        ValidationState::Invalid => 2,
    }
}

/// `None` for anything but an RFC 8097 community carrying 0, 1 or 2 — the
/// middle octets are reserved and ignored.
pub fn decode(c: u64) -> Option<ValidationState> {
    if !is_ov(c) {
        return None;
    }
    match c & 0xff {
        0 => Some(ValidationState::Valid),
        1 => Some(ValidationState::NotFound),
        2 => Some(ValidationState::Invalid),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejects() {
        for s in [
            ValidationState::Valid,
            ValidationState::NotFound,
            ValidationState::Invalid,
        ] {
            assert_eq!(decode(encode(s)), Some(s));
        }
        assert_eq!(encode(ValidationState::Invalid), 0x4300_0000_0000_0002);
        assert_eq!(decode(0x4300_0000_0000_0003), None, "unknown state");
        assert_eq!(decode(0x4301_0000_0000_0002), None, "wrong subtype");
        assert_eq!(decode(0x0300_0000_0000_0002), None, "transitive type");
        assert!(is_ov(0x4300_0000_0000_0007));
    }
}
