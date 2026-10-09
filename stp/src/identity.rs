//! The bridge identifier's MAC, derived (pure core plus two file reads).

use crate::vector::{BridgeId, IdError};

/// FNV-1a over hostname and machine-id, 48 bits, locally administered unicast
/// (first byte 0x02). Reimplements `lacp::aggregate::local_system_id` (star
/// dependency graph). Two hosts sharing both inputs (cloned images with the
/// default hostname) would collide; upgrade path is a persisted random id.
pub fn derive_mac(hostname: &str, machine_id: &str) -> [u8; 6] {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in hostname.bytes().chain([0]).chain(machine_id.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let b = hash.to_be_bytes();
    [0x02, b[3], b[4], b[5], b[6], b[7]]
}

pub fn local_mac() -> [u8; 6] {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    derive_mac(
        read("/proc/sys/kernel/hostname").trim(),
        read("/etc/machine-id").trim(),
    )
}

/// CIST bridge identifier: configured priority, system id extension 0.
pub fn bridge_id(priority: u16, mac: [u8; 6]) -> Result<BridgeId, IdError> {
    BridgeId::new(priority, 0, mac)
}

/// `8000.02:aa:bb:cc:dd:ee`, for logs.
pub fn show(id: &BridgeId) -> String {
    let m = id.mac();
    format!(
        "{:04x}.{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        id.priority(),
        m[0],
        m[1],
        m[2],
        m[3],
        m[4],
        m[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_stable_distinct_and_locally_administered_unicast() {
        let a = derive_mac("router-a", "m1");
        assert_eq!(a, derive_mac("router-a", "m1"));
        assert_ne!(a, derive_mac("router-b", "m1"));
        assert_ne!(a, derive_mac("router-a", "m2"));
        assert_eq!(a[0] & 0x03, 0x02);
    }

    #[test]
    fn id_carries_priority_and_prints() {
        let id = bridge_id(4096, [2, 0, 0, 0, 0, 0xab]).unwrap();
        assert_eq!(show(&id), "1000.02:00:00:00:00:ab");
        assert!(bridge_id(100, [2; 6]).is_err());
    }
}
