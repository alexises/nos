//! Password hashing for NOS users — argon2id, PHC-string encoded (`$argon2id$…`),
//! with a random per-hash salt. No NOS dependencies, like `nos-tcp-auth`/`nos-rpl`.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::sync::LazyLock;

/// Prefix every stored hash carries; anything else in a `User.password` is a
/// clear-text password waiting to be hashed.
pub const HASH_PREFIX: &str = "$argon2id$";

pub fn is_hash(s: &str) -> bool {
    s.starts_with(HASH_PREFIX)
}

/// Hashes `password` with a fresh random salt.
pub fn hash(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 with default params and a generated salt cannot fail")
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
