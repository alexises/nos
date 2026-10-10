//! MST Configuration Digest, IEEE 802.1Q-2022 13.8: HMAC-MD5 over the
//! 4096-entry VID to MSTID table (2 bytes each, big-endian, entry `i` is VID
//! `i`) with the fixed key below. Pure.

use hmac::{Hmac, Mac};
use md5::Md5;

/// The fixed key of 13.8: `13AC06A62E47FD51F95D2BA243CD0346`.
const KEY: [u8; 16] = [
    0x13, 0xac, 0x06, 0xa6, 0x2e, 0x47, 0xfd, 0x51, 0xf9, 0x5d, 0x2b, 0xa2, 0x43, 0xcd, 0x03, 0x46,
];

pub type VidTable = [u16; 4096];

pub fn digest(table: &VidTable) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(&KEY).expect("HMAC takes any key length");
    for mstid in table {
        mac.update(&mstid.to_be_bytes());
    }
    mac.finalize().into_bytes().into()
}

pub fn hex(d: &[u8; 16]) -> String {
    use std::fmt::Write;
    d.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_is_the_well_known_default_digest() {
        // 802.1Q: every VID in the CIST gives AC36177F50283CD4B83821D8AB26DE62.
        assert_eq!(hex(&digest(&[0; 4096])), "ac36177f50283cd4b83821d8ab26de62");
    }

    #[test]
    fn mapped_table_matches_an_independent_oracle() {
        // python3: hmac.new(bytes.fromhex("13AC06A62E47FD51F95D2BA243CD0346"),
        //   b"".join(m.to_bytes(2, "big") for m in t), hashlib.md5).hexdigest()
        // with t = [0]*4096, t[10] = 1, t[20] = 2.
        let mut t = [0; 4096];
        t[10] = 1;
        t[20] = 2;
        assert_eq!(hex(&digest(&t)), "9357ebb7a8d74dd5fef4f2bab50531aa");
        // and with t[1..4095] = 1.
        let mut t = [0; 4096];
        t[1..4095].fill(1);
        assert_eq!(hex(&digest(&t)), "e13a80f11ed0856acd4ee3476941c73b");
    }
}
