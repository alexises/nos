use std::fmt;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;

/// Prefix of every stored password hash (argon2id PHC string, see
/// `nos-password`). Anything else in `User.password` is clear text that
/// `nos-configd` hashes on the way in, so a committed config never has any.
pub const PASSWORD_HASH_PREFIX: &str = "$argon2id$";

/// A local user who may log in to `nos-cli` and call the REST API (HTTP
/// Basic). Every user is a full administrator — there are no roles.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct User {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.users, |u| &u.name))
    )]
    pub name: String,

    /// An argon2id hash at rest. Setting a clear-text value is allowed — the
    /// config daemon replaces it with a hash (keeping the old hash when the
    /// clear text still matches it, so re-setting the same password is not a
    /// change).
    #[garde(custom(|p: &String, _ctx: &Config| valid_password_hash(p)))]
    pub password: String,
}

// Manual `Debug`: never print the password field (a hash, or briefly clear text).
impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("password", &"<hidden>")
            .finish()
    }
}

fn valid_password_hash(p: &str) -> garde::Result {
    if !p.starts_with(PASSWORD_HASH_PREFIX) {
        return Err(garde::Error::new(
            "password must be stored as an argon2id hash",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(users: Vec<User>) -> Config {
        Config {
            users,
            ..Default::default()
        }
    }

    fn user(name: &str, password: &str) -> User {
        User {
            name: name.to_string(),
            password: password.to_string(),
        }
    }

    #[test]
    fn hashed_user_passes() {
        let c = cfg(vec![user("alice", "$argon2id$v=19$whatever")]);
        assert!(c.validate_with(&c).is_ok());
    }

    #[test]
    fn clear_text_password_is_rejected() {
        let c = cfg(vec![user("alice", "hunter2")]);
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let c = cfg(vec![user("a", "$argon2id$x"), user("a", "$argon2id$y")]);
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    fn debug_hides_password() {
        assert!(!format!("{:?}", user("a", "hunter2")).contains("hunter2"));
    }
}
