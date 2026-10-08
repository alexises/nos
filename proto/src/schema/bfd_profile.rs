use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;
use nos_proto_derive::Cli;

pub const MIN_INTERVAL_DEFAULT: u32 = 300;
pub const DETECT_MULTIPLIER_DEFAULT: u8 = 3;
/// Default `minimum-ttl`: single-hop BFD (RFC 5881 §5) is sent with TTL 255,
/// so 254 accepts one routed hop of slack.
pub const MINIMUM_TTL_DEFAULT: u8 = 254;
/// RFC 5880 carries intervals in microseconds as a `u32`: the largest whole
/// number of milliseconds that fits, so the daemon's ms-to-us conversion
/// cannot overflow.
pub const INTERVAL_MAX_MS: u32 = 4_294_967;
pub const INTERVAL_MIN_MS: u32 = 10;
/// Default `echo-interval`, milliseconds.
pub const ECHO_INTERVAL_DEFAULT: u32 = 50;

/// A named set of BFD (RFC 5880) session parameters, referenced by bare name
/// from a BGP peer-group, an OSPF/OSPFv3 profile or a static route
/// (`bfd <name>`). Declaration only for now: no daemon consumes it yet, so
/// attaching one is inert.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct BfdProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.bfd_profiles, |p| &p.name))
    )]
    #[cli(key)]
    pub name: String,

    /// Desired minimum transmit interval, milliseconds.
    #[serde(default = "min_interval_default")]
    #[garde(range(min = INTERVAL_MIN_MS, max = INTERVAL_MAX_MS))]
    #[cli(topic = BfdProfileMinTx)]
    pub min_tx_interval: u32,

    /// Required minimum receive interval, milliseconds.
    #[serde(default = "min_interval_default")]
    #[garde(range(min = INTERVAL_MIN_MS, max = INTERVAL_MAX_MS))]
    #[cli(topic = BfdProfileMinRx)]
    pub min_rx_interval: u32,

    #[serde(default = "detect_multiplier_default")]
    #[garde(range(min = 1))]
    #[cli(topic = BfdProfileDetectMultiplier)]
    pub detect_multiplier: u8,

    /// Passive role: wait for the peer's first packet instead of starting
    /// the session (RFC 5880 §6.1).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BfdProfilePassive, words = "passive enable", alias = "passive")]
    pub passive: bool,

    #[serde(default = "minimum_ttl_default")]
    #[garde(skip)]
    #[cli(topic = BfdProfileMinimumTtl)]
    pub minimum_ttl: u8,

    /// Administratively down: sessions using this profile stay `AdminDown`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BfdProfileShutdown, words = "shutdown enable", alias = "shutdown")]
    pub shutdown: bool,

    /// `None` is RFC 5880 `AuthType` 0: no authentication. Secrets are
    /// stored clear-text, like `BgpAuth`.
    #[serde(default)]
    #[garde(custom(|a: &Option<BfdAuth>, _ctx: &Config| valid_auth(a.as_ref())))]
    #[cli(topic = BfdProfileAuth)]
    pub auth: Option<BfdAuth>,

    /// RFC 5880 §6.4 Echo function (single-hop sessions only).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BfdProfileEchoMode)]
    pub echo_mode: EchoMode,

    /// Echo transmit interval, and the Required Min Echo RX Interval this
    /// system advertises, milliseconds.
    #[serde(default = "echo_interval_default")]
    #[garde(range(min = INTERVAL_MIN_MS, max = INTERVAL_MAX_MS))]
    #[cli(topic = BfdProfileEchoInterval)]
    pub echo_interval: u32,
}

/// Whether this system loops its own Echo packets through the peer (RFC 5880
/// §6.4). `Affiliated`: the Echo function runs alongside the Control session,
/// which then slows to one packet a second.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum EchoMode {
    #[default]
    Disabled,
    Affiliated,
}

fn echo_interval_default() -> u32 {
    ECHO_INTERVAL_DEFAULT
}

fn min_interval_default() -> u32 {
    MIN_INTERVAL_DEFAULT
}
fn detect_multiplier_default() -> u8 {
    DETECT_MULTIPLIER_DEFAULT
}
fn minimum_ttl_default() -> u8 {
    MINIMUM_TTL_DEFAULT
}

/// The placeholder a new `BfdProfile` starts from (`edit` on a missing one).
impl Default for BfdProfile {
    fn default() -> Self {
        BfdProfile {
            name: String::new(),
            min_tx_interval: MIN_INTERVAL_DEFAULT,
            min_rx_interval: MIN_INTERVAL_DEFAULT,
            detect_multiplier: DETECT_MULTIPLIER_DEFAULT,
            passive: false,
            minimum_ttl: MINIMUM_TTL_DEFAULT,
            shutdown: false,
            auth: None,
            echo_mode: EchoMode::Disabled,
            echo_interval: ECHO_INTERVAL_DEFAULT,
        }
    }
}

/// RFC 5880 §4.2/§4.3 authentication section: the method picks the
/// `AuthType`, `key_id` is the wire Auth Key ID.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BfdAuth {
    #[cli(topic = BfdProfileAuth)]
    pub key_id: u8,
    #[cli(topic = BfdProfileAuth)]
    pub method: BfdAuthMethod,
    #[cli(topic = BfdProfileAuth)]
    pub key: String,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub enum BfdAuthMethod {
    #[default]
    #[cli(words = "simple-password")]
    SimplePassword,
    #[cli(words = "keyed-md5")]
    KeyedMd5,
    #[cli(words = "meticulous-md5")]
    MeticulousMd5,
    #[cli(words = "keyed-sha1")]
    KeyedSha1,
    #[cli(words = "meticulous-sha1")]
    MeticulousSha1,
}

fn valid_auth(auth: Option<&BfdAuth>) -> garde::Result {
    let Some(a) = auth else { return Ok(()) };
    // RFC 5880 §4.2 (password 1..16 bytes), §4.3 (MD5 key 1..16, SHA1 1..20).
    let max = match a.method {
        BfdAuthMethod::SimplePassword | BfdAuthMethod::KeyedMd5 | BfdAuthMethod::MeticulousMd5 => {
            16
        }
        BfdAuthMethod::KeyedSha1 | BfdAuthMethod::MeticulousSha1 => 20,
    };
    if a.key.is_empty() || a.key.len() > max {
        return Err(garde::Error::new(format!(
            "bfd auth key must be 1 to {max} bytes long for this method"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::BgpPeerGroup;

    fn profile(name: &str) -> BfdProfile {
        BfdProfile {
            name: name.into(),
            ..Default::default()
        }
    }

    fn ok(p: BfdProfile) -> bool {
        let c = Config {
            bfd_profiles: vec![p],
            ..Default::default()
        };
        c.validate_with(&c).is_ok()
    }

    #[test]
    fn defaults() {
        let p = BfdProfile::default();
        assert_eq!(
            (
                p.min_tx_interval,
                p.min_rx_interval,
                p.detect_multiplier,
                p.minimum_ttl
            ),
            (300, 300, 3, 254)
        );
        assert!(ok(profile("fast")));
    }

    #[test]
    fn old_config_without_bfd_profiles_loads() {
        let mut v = serde_json::to_value(Config::default()).unwrap();
        v.as_object_mut().unwrap().remove("bfd_profiles");
        let c: Config = serde_json::from_value(v).unwrap();
        assert_eq!(c.bfd_profiles.len(), 0);
        let p: BfdProfile = serde_json::from_str(r#"{"name":"x"}"#).unwrap();
        assert_eq!(p, profile("x"));
    }

    #[test]
    fn ranges() {
        let mut p = profile("a");
        p.min_tx_interval = 9;
        assert!(!ok(p));
        let mut p = profile("a");
        p.min_rx_interval = INTERVAL_MAX_MS + 1;
        assert!(!ok(p));
        let mut p = profile("a");
        p.detect_multiplier = 0;
        assert!(!ok(p));
        let mut p = profile("a");
        p.min_tx_interval = 10;
        p.min_rx_interval = INTERVAL_MAX_MS;
        assert!(ok(p));
    }

    #[test]
    fn auth_key_length_per_method() {
        let with = |method, len| {
            let mut p = profile("a");
            p.auth = Some(BfdAuth {
                key_id: 1,
                method,
                key: "k".repeat(len),
            });
            ok(p)
        };
        assert!(with(BfdAuthMethod::SimplePassword, 16));
        assert!(!with(BfdAuthMethod::SimplePassword, 17));
        assert!(!with(BfdAuthMethod::KeyedMd5, 0));
        assert!(!with(BfdAuthMethod::MeticulousMd5, 17));
        assert!(with(BfdAuthMethod::KeyedSha1, 20));
        assert!(!with(BfdAuthMethod::MeticulousSha1, 21));
    }

    /// Errors reported on a `bfd` field when `v` is validated against `cfg`.
    fn bfd_errors<T: Validate<Context = Config>>(v: &T, cfg: &Config) -> Vec<String>
    where
        T::Context: Sized,
    {
        match v.validate_with(cfg) {
            Ok(()) => Vec::new(),
            Err(r) => r
                .iter()
                .filter(|(p, _)| p.to_string() == "bfd")
                .map(|(_, e)| e.to_string())
                .collect(),
        }
    }

    #[test]
    fn each_attach_point_reports_a_dangling_reference() {
        use crate::schema::{OspfProfile, Ospfv3Profile, StaticRoute};
        let bfd = Some("gone".to_string());
        let with_profile = Config {
            bfd_profiles: vec![profile("gone")],
            ..Default::default()
        };
        let without = Config::default();
        let pg = BgpPeerGroup {
            bfd: bfd.clone(),
            ..Default::default()
        };
        let ospf = OspfProfile {
            bfd: bfd.clone(),
            ..Default::default()
        };
        let ospfv3 = Ospfv3Profile {
            bfd: bfd.clone(),
            ..Default::default()
        };
        let route = StaticRoute {
            bfd,
            ..Default::default()
        };
        for (name, errs, ok) in [
            (
                "peer-group",
                bfd_errors(&pg, &without),
                bfd_errors(&pg, &with_profile),
            ),
            (
                "ospf",
                bfd_errors(&ospf, &without),
                bfd_errors(&ospf, &with_profile),
            ),
            (
                "ospfv3",
                bfd_errors(&ospfv3, &without),
                bfd_errors(&ospfv3, &with_profile),
            ),
            (
                "static",
                bfd_errors(&route, &without),
                bfd_errors(&route, &with_profile),
            ),
        ] {
            assert_eq!(errs, ["bfd profile 'gone' does not exist"], "{name}");
            assert!(ok.is_empty(), "{name}: {ok:?}");
        }
    }

    #[test]
    fn duplicate_name_rejected() {
        let c = Config {
            bfd_profiles: vec![profile("a"), profile("a")],
            ..Default::default()
        };
        assert!(c.validate_with(&c).is_err());
    }
}
