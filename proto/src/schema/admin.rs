//! The admin keystore (`Config.admin`, #383): secrets stored once under a
//! label and referenced by label from the sections that need a key. It is
//! the one place a secret lives, so log, REST and `show` redaction only has
//! to protect this type (and `User.password`).

use std::fmt;

use garde::Validate;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use crate::cli::render::HIDDEN;
use crate::validators::{name_charset, unique_in};

use super::Config;

/// Longest secret a key may hold (the TCP-MD5 limit, the largest consumer).
pub const SECRET_MAX_LEN: usize = 80;

/// The admin section: labelled secrets for other sections to reference.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct Admin {
    /// Labelled secrets. Write-only: values print as `<hidden>` everywhere.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = AdminKey, words = "key")]
    pub keys: Vec<AdminKey>,
}

/// One labelled secret.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct AdminKey {
    #[garde(
        length(min = 1, max = 64),
        custom(|l: &String, _ctx: &Config| name_charset(l)),
        custom(|l: &String, ctx: &Config| unique_in(l, &ctx.admin.keys, |k| &k.label))
    )]
    #[cli(key)]
    /// Label other sections reference, 1 to 64 characters (letters, digits, `_`, `-`), unique among keys.
    pub label: String,

    /// The secret, 1 to 80 bytes. Write-only: never printed, logged or returned by the REST API.
    #[cfg_attr(feature = "openapi", schema(write_only))]
    #[garde(custom(|s: &String, _ctx: &Config| valid_secret(s)))]
    #[cli(topic = AdminKeySecret, secret)]
    pub secret: String,
}

// Manual `Debug`: a config, an op or a diff is logged with `?`.
impl fmt::Debug for AdminKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminKey")
            .field("label", &self.label)
            .field("secret", &HIDDEN)
            .finish()
    }
}

impl fmt::Debug for Admin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admin").field("keys", &self.keys).finish()
    }
}

fn valid_secret(s: &str) -> garde::Result {
    if s.is_empty() || s.len() > SECRET_MAX_LEN {
        return Err(garde::Error::new("secret must be 1 to 80 bytes"));
    }
    // The REST mask round-trip: a value equal to the mask is never a real secret.
    if s == HIDDEN {
        return Err(garde::Error::new(
            "secret must not be the mask text '<hidden>'",
        ));
    }
    Ok(())
}

impl Config {
    /// The secret stored under `label` in the admin keystore.
    pub fn key(&self, label: &str) -> Option<&str> {
        self.admin
            .keys
            .iter()
            .find(|k| k.label == label)
            .map(|k| k.secret.as_str())
    }

    /// The config as JSON with every `#[cli(secret)]` field replaced by the
    /// mask text, for anything that leaves the daemons (REST, logs). Walks
    /// `cli::root()` like `show config`, so a new secret field is covered by
    /// declaring it `secret`.
    pub fn redacted(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("a config serializes");
        redact_value(&mut v, &crate::cli::Kind::Struct(crate::cli::root()));
        v
    }
}

/// Masks the secret fields of `v` (a value of `kind`) in place.
pub fn redact_value(v: &mut serde_json::Value, kind: &crate::cli::Kind) {
    use crate::cli::{Kind, Payload};
    use serde_json::Value;
    match kind {
        Kind::Option(inner) => redact_value(v, &inner()),
        Kind::List(inner) => {
            let inner = inner();
            for e in v.as_array_mut().into_iter().flatten() {
                redact_value(e, &inner);
            }
        }
        Kind::Struct(node) => redact_fields(v, node.fields),
        Kind::Enum(variants) => {
            // Externally tagged: `{"Variant": payload}`; unit variants are strings.
            if let Value::Object(o) = v {
                for var in *variants {
                    let Some(p) = o.get_mut(var.name) else {
                        continue;
                    };
                    match &var.payload {
                        Payload::Unit => {}
                        Payload::Newtype(k) => redact_value(p, &k()),
                        Payload::Struct(fields) => redact_fields(p, fields),
                    }
                }
            }
        }
        _ => {}
    }
}

fn redact_fields(v: &mut serde_json::Value, fields: &[crate::cli::Field]) {
    for f in fields {
        let Some(child) = v.get_mut(f.name) else {
            continue;
        };
        if f.secret {
            if !child.is_null() {
                *child = HIDDEN.into();
            }
        } else {
            redact_value(child, &(f.kind)());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(label: &str, secret: &str) -> AdminKey {
        AdminKey {
            label: label.into(),
            secret: secret.into(),
        }
    }

    fn cfg(keys: Vec<AdminKey>) -> Config {
        Config {
            admin: Admin { keys },
            ..Default::default()
        }
    }

    fn ok(keys: Vec<AdminKey>) -> bool {
        let c = cfg(keys);
        c.validate_with(&c).is_ok()
    }

    #[test]
    fn valid_key_passes_and_resolves() {
        let c = cfg(vec![key("bgp-1", "s3cret")]);
        assert!(c.validate_with(&c).is_ok());
        assert_eq!(c.key("bgp-1"), Some("s3cret"));
        assert_eq!(c.key("other"), None);
    }

    #[test]
    fn label_rules() {
        assert!(!ok(vec![key("", "x")]));
        assert!(!ok(vec![key(&"a".repeat(65), "x")]));
        assert!(ok(vec![key(&"a".repeat(64), "x")]));
        assert!(!ok(vec![key("has space", "x")]));
        assert!(!ok(vec![key("a", "x"), key("a", "y")]));
    }

    #[test]
    fn secret_rules() {
        assert!(!ok(vec![key("a", "")]));
        assert!(!ok(vec![key("a", &"x".repeat(81))]));
        assert!(ok(vec![key("a", &"x".repeat(80))]));
        assert!(!ok(vec![key("a", HIDDEN)]));
    }

    #[test]
    fn debug_hides_secret() {
        let c = cfg(vec![key("a", "hunter2")]);
        assert!(!format!("{:?}", c.admin).contains("hunter2"));
        assert!(!format!("{:?}", c.admin.keys[0]).contains("hunter2"));
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn old_config_without_admin_loads() {
        let mut v = serde_json::to_value(Config::default()).unwrap();
        v.as_object_mut().unwrap().remove("admin");
        let c: Config = serde_json::from_value(v).unwrap();
        assert_eq!(c.admin, Admin::default());
    }

    #[test]
    fn redacted_masks_secrets_only() {
        let mut c = cfg(vec![key("a", "hunter2")]);
        c.users.push(crate::schema::User {
            name: "u".into(),
            password: "$argon2id$x".into(),
        });
        let r = c.redacted();
        assert_eq!(r["admin"]["keys"][0]["secret"], HIDDEN);
        assert_eq!(r["admin"]["keys"][0]["label"], "a");
        assert_eq!(r["users"][0]["password"], HIDDEN);
        assert_eq!(r["users"][0]["name"], "u");
        assert!(!r.to_string().contains("hunter2"));
        // Everything else is untouched.
        let mut plain = serde_json::to_value(&c).unwrap();
        plain["admin"]["keys"][0]["secret"] = HIDDEN.into();
        plain["users"][0]["password"] = HIDDEN.into();
        assert_eq!(r, plain);
    }
}
