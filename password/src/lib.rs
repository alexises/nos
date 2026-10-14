//! Password hashing for NOS users — argon2id, PHC-string encoded (`$argon2id$…`),
//! with a random per-hash salt. No NOS dependencies, like `nos-tcp-auth`/`nos-rpl`.
#![warn(missing_docs)]

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use std::sync::LazyLock;

/// Prefix every stored hash carries; anything else in a `User.password` is a
/// clear-text password waiting to be hashed.
pub const HASH_PREFIX: &str = "$argon2id$";

/// Whether `s` already looks like a PHC argon2id hash (prefix check only, no parsing).
pub fn is_hash(s: &str) -> bool {
    s.starts_with(HASH_PREFIX)
}

fn params() -> Params {
    Params::new(65536, 3, 4, None).expect("valid argon2 params")
}

/// `true` iff `hash` is a well-formed hash made with weaker parameters than
/// [`hash`] uses today — the caller re-hashes it after a successful login.
pub fn needs_rehash(hash: &str) -> bool {
    let cur = params();
    PasswordHash::new(hash)
        .ok()
        .and_then(|h| Params::try_from(&h).ok())
        .is_some_and(|p| {
            p.m_cost() < cur.m_cost() || p.t_cost() < cur.t_cost() || p.p_cost() < cur.p_cost()
        })
}

/// Hashes `password` with a fresh random salt, using RFC 9106 §4's
/// memory-constrained profile (m=64 MiB, t=3, p=4). Verification reads the
/// parameters from the stored PHC string, so older hashes keep working.
pub fn hash(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params())
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 with valid params and a generated salt cannot fail")
        .to_string()
}

/// `true` iff `password` matches the PHC string `hash`; a malformed `hash` never matches.
pub fn verify(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}

/// Login check: `stored` is the named user's stored hash, or `None` when there
/// is no such user. An unknown user still pays for a full argon2 verify
/// (against a throwaway hash, and always `false`), so response time doesn't
/// reveal which usernames exist.
pub fn verify_or_dummy(password: &str, stored: Option<&str>) -> bool {
    static DUMMY: LazyLock<String> = LazyLock::new(|| hash("dummy"));
    if let Some(h) = stored {
        verify(password, h)
    } else {
        let _ = verify(password, &DUMMY);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_wrong_password() {
        let h = hash("hunter2");
        assert!(is_hash(&h));
        assert!(verify("hunter2", &h));
        assert!(!verify("hunter3", &h));
    }

    #[test]
    fn rfc9106_params_and_legacy_hashes_still_verify() {
        assert!(hash("pw").contains("m=65536,t=3,p=4"));
        assert!(!needs_rehash(&hash("pw")));
        assert!(!needs_rehash("garbage"));
        let salt = SaltString::generate(&mut OsRng);
        let old = Argon2::default()
            .hash_password(b"pw", &salt)
            .unwrap()
            .to_string();
        assert!(verify("pw", &old));
        assert!(needs_rehash(&old));
    }

    /// A PHC string with the given cost parameters (no real hashing: only the
    /// parameters are read).
    fn phc(m: u32, t: u32, p: u32) -> String {
        format!("$argon2id$v=19$m={m},t={t},p={p}$c29tZXNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")
    }

    #[test]
    fn needs_rehash_compares_each_dimension() {
        // One dimension weaker at a time, or a mix of weaker and stronger.
        for (m, t, p) in [
            (32, 3, 4),
            (65536, 2, 4),
            (65536, 3, 3),
            (32, 4, 4),
            (65536, 4, 3),
        ] {
            assert!(needs_rehash(&phc(m, t, p)), "{m},{t},{p}");
        }
        // Equal or stronger everywhere.
        for (m, t, p) in [(65536, 3, 4), (65537, 3, 4), (65536, 4, 4), (65536, 3, 5)] {
            assert!(!needs_rehash(&phc(m, t, p)), "{m},{t},{p}");
        }
        for bad in ["", "garbage", "$argon2id$"] {
            assert!(!needs_rehash(bad), "{bad:?}");
        }
    }

    #[test]
    fn salted_so_hashes_differ() {
        assert_ne!(hash("same"), hash("same"));
    }

    #[test]
    fn unknown_user_never_verifies() {
        let h = hash("pw");
        assert!(verify_or_dummy("pw", Some(&h)));
        assert!(!verify_or_dummy("pw", None));
    }

    #[test]
    fn clear_text_and_garbage_are_not_hashes() {
        assert!(!is_hash("admin"));
        assert!(!verify("admin", "admin"));
    }
}
