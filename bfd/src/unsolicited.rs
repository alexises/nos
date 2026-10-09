//! RFC 9468 unsolicited BFD, pure: which packets may create a passive session
//! (`decide`) and when an idle one goes (`age_step`). The session table is
//! `manager`'s, the config follow loop `micro_sessions`'.
//!
//! - §2: a packet with Your Discriminator 0 that matches no session creates
//!   one unless local policy prohibits it; on a numbered interface its source
//!   must be in the interface's subnet. The passive side stays silent until
//!   it has seen the active side (`Core` with `passive`), and stops sending
//!   when the session fails or goes down (`Core` forgets the remote
//!   discriminator on detection expiry), then deletes it (`age_step`).
//! - §6.1: single-hop only; the TTL 255 check (GTSM) stays, and the number of
//!   sessions is capped: nothing else bounds what a spoofed source can create.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use nos_proto::schema::BfdProfile;
use nos_proto::{BfdState, Config};

use crate::packet::Packet;

/// How long a session may stay not-Up before it is deleted (decision 2 of
/// the plan: a constant, not a profile field).
pub const AGE: Duration = Duration::from_secs(60);

/// Most unsolicited sessions per subinterface (decision 3: fixed).
pub const MAX_PER_INTERFACE: usize = 256;

/// One subinterface that answers unsolicited BFD.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub table: String,
    /// The kernel device: `<interface>` for tag 0, else `<interface>.<tag>`.
    pub interface: String,
    /// The subinterface's addresses: a source must be in one of the subnets.
    pub subnets: Vec<IpNet>,
    /// The named profile, with `passive` forced on.
    pub profile: BfdProfile,
}

/// The rules `cfg` asks for. A subinterface without a routing table or with a
/// missing profile gets none (the commit-time check forbids both).
pub fn wanted(cfg: &Config) -> Vec<Rule> {
    let mut out = Vec::new();
    for i in &cfg.interfaces {
        for s in &i.subinterfaces {
            let (Some(name), Some(table)) = (&s.bfd_unsolicited, &s.routing_table) else {
                continue;
            };
            let Some(p) = cfg.bfd_profiles.iter().find(|p| &p.name == name) else {
                continue;
            };
            out.push(Rule {
                table: table.clone(),
                interface: if s.tag == 0 {
                    i.name.clone()
                } else {
                    format!("{}.{}", i.name, s.tag)
                },
                subnets: s.addresses.iter().map(|a| a.address.trunc()).collect(),
                // Decision 4: the profile's own `passive` is ignored.
                profile: BfdProfile {
                    passive: true,
                    ..p.clone()
                },
            });
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Create,
    /// Not for us: dropped silently, as without the feature.
    Ignore,
    /// Would create, but the interface is at its cap.
    Capped,
}

/// Whether `p`, which matched no session, arriving from `src` with `ttl`,
/// makes a session under `rule` (the subinterface whose subnet holds `src`).
/// `existing`: the unsolicited sessions already on that interface.
pub fn decide(p: &Packet, src: IpAddr, ttl: Option<u8>, rule: &Rule, existing: usize) -> Decision {
    // §6.8.6: a zero Your Discriminator is only valid from Down/AdminDown, and
    // AdminDown says the peer wants no session.
    if p.your_discriminator != 0
        || p.state != BfdState::Down
        || ttl != Some(255)
        || !rule.subnets.iter().any(|n| n.contains(&src))
    {
        return Decision::Ignore;
    }
    if existing >= MAX_PER_INTERFACE {
        Decision::Capped
    } else {
        Decision::Create
    }
}

/// The first rule of `table` whose subnet holds `src`.
pub fn rule_for<'a>(rules: &'a [Rule], table: &str, src: IpAddr) -> Option<&'a Rule> {
    rules
        .iter()
        .find(|r| r.table == table && r.subnets.iter().any(|n| n.contains(&src)))
}

/// One look at a session: `since` is when it stopped being Up (None while Up
/// or not yet seen). Returns the new `since` and whether to delete now.
pub fn age_step(up: bool, since: Option<Instant>, now: Instant) -> (Option<Instant>, bool) {
    if up {
        return (None, false);
    }
    let since = since.unwrap_or(now);
    (Some(since), now.saturating_duration_since(since) >= AGE)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn rule() -> Rule {
        Rule {
            table: "rt1".into(),
            interface: "eth1".into(),
            subnets: vec!["10.0.0.0/24".parse().unwrap()],
            profile: BfdProfile::default(),
        }
    }

    pub(crate) fn pkt(state: BfdState, your: u32) -> Packet {
        Packet {
            diag: 0,
            state,
            poll: false,
            final_: false,
            control_plane_independent: false,
            demand: false,
            detect_mult: 3,
            my_discriminator: 7,
            your_discriminator: your,
            desired_min_tx: 1_000_000,
            required_min_rx: 1_000_000,
            required_min_echo_rx: 0,
            auth: None,
        }
    }

    #[test]
    fn decide_cases() {
        let r = rule();
        let src: IpAddr = "10.0.0.2".parse().unwrap();
        let d = |p: &Packet, s: IpAddr, ttl, n| decide(p, s, ttl, &r, n);
        let down = pkt(BfdState::Down, 0);
        assert_eq!(d(&down, src, Some(255), 0), Decision::Create);
        assert_eq!(d(&down, src, Some(254), 0), Decision::Ignore, "GTSM");
        assert_eq!(d(&down, src, None, 0), Decision::Ignore);
        let off: IpAddr = "10.0.1.2".parse().unwrap();
        assert_eq!(d(&down, off, Some(255), 0), Decision::Ignore);
        assert_eq!(
            d(&pkt(BfdState::Down, 5), src, Some(255), 0),
            Decision::Ignore
        );
        assert_eq!(
            d(&pkt(BfdState::Init, 0), src, Some(255), 0),
            Decision::Ignore
        );
        assert_eq!(
            d(&pkt(BfdState::AdminDown, 0), src, Some(255), 0),
            Decision::Ignore
        );
        assert_eq!(
            d(&down, src, Some(255), MAX_PER_INTERFACE - 1),
            Decision::Create
        );
        assert_eq!(
            d(&down, src, Some(255), MAX_PER_INTERFACE),
            Decision::Capped
        );
    }

    #[test]
    fn rule_lookup_is_per_table_and_subnet() {
        let rules = [rule()];
        let a: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(rule_for(&rules, "rt1", a).is_some());
        assert!(rule_for(&rules, "rt2", a).is_none());
        assert!(rule_for(&rules, "rt1", "10.9.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn ageing() {
        let t0 = Instant::now();
        let (since, gone) = age_step(false, None, t0);
        assert_eq!((since, gone), (Some(t0), false));
        assert!(!age_step(false, since, t0 + Duration::from_secs(59)).1);
        assert!(age_step(false, since, t0 + AGE).1);
        assert_eq!(
            age_step(true, since, t0 + AGE),
            (None, false),
            "back Up resets"
        );
    }
}
