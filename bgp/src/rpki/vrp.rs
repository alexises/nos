//! Validated ROA Payloads and RFC 6811 §2 origin validation.

use std::collections::{BTreeSet, HashMap};

use ipnet::IpNet;
use nos_rpl::ValidationState;

use crate::as_path::{AsPath, SegKind};

/// One VRP: `asn` may originate `prefix` and its more-specifics up to
/// `max_len` (RFC 6811 §2, RFC 8210 §5.6/§5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vrp {
    pub prefix: IpNet,
    pub max_len: u8,
    pub asn: u32,
}

/// Every VRP, keyed by its exact prefix. A lookup walks the route's
/// supernets: at most 33 (v4) or 129 (v6) hash probes.
// ponytail: a hash per prefix length, not a trie; switch to one if
// tools/bench-bgp.sh with a full VRP table says the probes cost.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VrpTable {
    by_prefix: HashMap<IpNet, BTreeSet<(u8, u32)>>,
    len: usize,
}

impl VrpTable {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Adds `vrp`; `false` if it was already there.
    pub fn announce(&mut self, vrp: Vrp) -> bool {
        let added = self
            .by_prefix
            .entry(vrp.prefix)
            .or_default()
            .insert((vrp.max_len, vrp.asn));
        self.len += usize::from(added);
        added
    }

    /// Removes `vrp`; `false` if it wasn't there.
    pub fn withdraw(&mut self, vrp: Vrp) -> bool {
        let Some(set) = self.by_prefix.get_mut(&vrp.prefix) else {
            return false;
        };
        let removed = set.remove(&(vrp.max_len, vrp.asn));
        if set.is_empty() {
            self.by_prefix.remove(&vrp.prefix);
        }
        self.len -= usize::from(removed);
        removed
    }

    /// RFC 6811 §2. `origin` is `None` when the route's origin AS is NONE
    /// (its `AS_PATH` ends in an `AS_SET`), which no VRP can match.
    pub fn validate(&self, prefix: IpNet, origin: Option<u32>) -> ValidationState {
        let len = prefix.prefix_len();
        let mut covered = false;
        for plen in (0..=len).rev() {
            let Ok(net) = IpNet::new(prefix.addr(), plen) else {
                continue;
            };
            let Some(set) = self.by_prefix.get(&net.trunc()) else {
                continue;
            };
            covered = true;
            if let Some(origin) = origin {
                if set
                    .iter()
                    .any(|&(max_len, asn)| asn == origin && asn != 0 && len <= max_len)
                {
                    return ValidationState::Valid;
                }
            }
        }
        if covered {
            ValidationState::Invalid
        } else {
            ValidationState::NotFound
        }
    }
}

/// RFC 6811 §2 origin AS: the last ASN of a trailing `AS_SEQUENCE`, NONE
/// (`None`) for a trailing `AS_SET`, and `local` (this router's AS) when the
/// path has no non-confederation segment at all — a route originated inside
/// our AS or confederation.
pub fn origin_as(path: &AsPath, local: u32) -> Option<u32> {
    match path.segments().filter(|(k, _)| !k.is_confed()).last() {
        None => Some(local),
        Some((SegKind::Sequence, s)) => s.last().copied(),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ValidationState::{Invalid, NotFound, Valid};

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp {
            prefix: prefix.parse().unwrap(),
            max_len,
            asn,
        }
    }

    fn table(vrps: &[Vrp]) -> VrpTable {
        let mut t = VrpTable::default();
        for v in vrps {
            t.announce(*v);
        }
        t
    }

    fn check(t: &VrpTable, prefix: &str, origin: Option<u32>) -> ValidationState {
        t.validate(prefix.parse().unwrap(), origin)
    }

    #[test]
    fn rfc6811_cases() {
        let t = table(&[
            vrp("10.0.0.0/16", 24, 65001),
            vrp("10.0.0.0/16", 16, 65002),
            vrp("192.0.2.0/24", 24, 0),
            vrp("2001:db8::/32", 48, 65001),
        ]);
        assert_eq!(check(&t, "10.0.1.0/24", Some(65001)), Valid);
        assert_eq!(
            check(&t, "10.0.1.0/25", Some(65001)),
            Invalid,
            "too specific"
        );
        assert_eq!(check(&t, "10.0.0.0/16", Some(65002)), Valid, "second vrp");
        assert_eq!(check(&t, "10.0.1.0/24", Some(65002)), Invalid, "max-len 16");
        assert_eq!(check(&t, "10.0.1.0/24", Some(65003)), Invalid, "wrong asn");
        assert_eq!(check(&t, "10.0.1.0/24", None), Invalid, "origin NONE");
        assert_eq!(check(&t, "10.1.0.0/16", Some(65001)), NotFound);
        assert_eq!(
            check(&t, "10.0.0.0/8", Some(65001)),
            NotFound,
            "less specific"
        );
        assert_eq!(
            check(&t, "192.0.2.0/24", Some(0)),
            Invalid,
            "AS0 never matches"
        );
        assert_eq!(check(&t, "2001:db8:1::/48", Some(65001)), Valid);
        assert_eq!(check(&t, "2001:db8:1::/49", Some(65001)), Invalid);
        assert_eq!(check(&t, "2001:db9::/32", Some(65001)), NotFound);
    }

    #[test]
    fn announce_withdraw_count() {
        let mut t = VrpTable::default();
        assert!(t.announce(vrp("10.0.0.0/8", 8, 1)));
        assert!(!t.announce(vrp("10.0.0.0/8", 8, 1)));
        assert!(t.announce(vrp("10.0.0.0/8", 16, 1)));
        assert_eq!(t.len(), 2);
        assert!(t.withdraw(vrp("10.0.0.0/8", 8, 1)));
        assert!(!t.withdraw(vrp("10.0.0.0/8", 8, 1)));
        assert!(t.withdraw(vrp("10.0.0.0/8", 16, 1)));
        assert_eq!(t.len(), 0);
        assert_eq!(t, VrpTable::default());
    }

    #[test]
    fn origin_as_per_rfc6811() {
        assert_eq!(origin_as(&AsPath::default(), 65000), Some(65000), "local");
        assert_eq!(origin_as(&vec![1, 2, 3].into(), 65000), Some(3));
        let mut set = AsPath::from(vec![1]);
        set.push_segment(SegKind::Set, &[2, 3]);
        assert_eq!(origin_as(&set, 65000), None, "trailing AS_SET is NONE");
        let mut confed = AsPath::default();
        confed.push_segment(SegKind::ConfedSequence, &[65101]);
        assert_eq!(origin_as(&confed, 65100), Some(65100), "confed only");
        confed.push_segment(SegKind::Sequence, &[7]);
        assert_eq!(origin_as(&confed, 65100), Some(7));
    }
}
