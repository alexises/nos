//! Password handling for `Config.users`: hashing clear-text passwords on the
//! way in (keeping an existing hash when it still matches, so re-setting the
//! same password isn't a change) and the first-boot default user.

use nos_proto::{Config, User, PASSWORD_HASH_PREFIX};
use tracing::warn;

pub const DEFAULT_USER: &str = "admin";
pub const DEFAULT_PASSWORD: &str = "admin";

fn is_clear(u: &User) -> bool {
    !u.password.starts_with(PASSWORD_HASH_PREFIX)
}

/// Replaces every clear-text password in `users` with an argon2id hash. If a
/// `known` list (earlier states of the same config — the transaction before
/// this edit, then running) holds a hash for that user which the clear text
/// still verifies against, that hash is reused verbatim instead of salting a
/// new one — this is what keeps "set the same password again" from showing up
/// as a diff.
///
/// ponytail: hashes synchronously under the store's lock (tens of ms per
/// password); move to `spawn_blocking` if user edits ever get frequent.
pub(crate) fn hash_clear_passwords(users: &mut [User], known: &[&[User]]) {
    for u in users.iter_mut().filter(|u| is_clear(u)) {
        let same = known
            .iter()
            .flat_map(|list| list.iter())
            .filter(|k| k.name == u.name && !is_clear(k))
            .find(|k| nos_password::verify(&u.password, &k.password));
        u.password = match same {
            Some(k) => k.password.clone(),
            None => nos_password::hash(&u.password),
        };
    }
}

/// Adds `admin`/`admin` (clear text — `ConfigStore::new` hashes it) when the
/// config has no users at all, so a fresh box (or one upgraded from before
/// users existed) isn't locked out of both the CLI and REST.
pub fn seed_default_user(config: &mut Config) {
    if config.users.is_empty() {
        warn!(
            user = DEFAULT_USER,
            "no users configured, creating the default user — change its password"
        );
        config.users.push(User {
            name: DEFAULT_USER.to_string(),
            password: DEFAULT_PASSWORD.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(name: &str, pw: &str) -> User {
        User {
            name: name.to_string(),
            password: pw.to_string(),
        }
    }

    #[test]
    fn hash_prefix_matches_nos_password() {
        assert_eq!(PASSWORD_HASH_PREFIX, nos_password::HASH_PREFIX);
    }

    #[test]
    fn clear_becomes_hash_and_same_clear_keeps_it() {
        let mut users = vec![u("a", "pw")];
        hash_clear_passwords(&mut users, &[]);
        let h = users[0].password.clone();
        assert!(nos_password::verify("pw", &h));

        let mut again = vec![u("a", "pw")];
        hash_clear_passwords(&mut again, &[&users]);
        assert_eq!(again[0].password, h);

        let mut other = vec![u("a", "different")];
        hash_clear_passwords(&mut other, &[&users]);
        assert_ne!(other[0].password, h);
        assert!(nos_password::verify("different", &other[0].password));
    }

    #[test]
    fn existing_hashes_are_untouched() {
        let mut users = vec![u("a", "$argon2id$v=19$keep")];
        hash_clear_passwords(&mut users, &[]);
        assert_eq!(users[0].password, "$argon2id$v=19$keep");
    }

    #[test]
    fn seeds_only_when_empty() {
        let mut c = Config::default();
        seed_default_user(&mut c);
        assert_eq!(c.users.len(), 1);
        seed_default_user(&mut c);
        assert_eq!(c.users.len(), 1);
    }
}
