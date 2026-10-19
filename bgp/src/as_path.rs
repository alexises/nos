//! A structured `AS_PATH` (RFC 4271 §4.3, RFC 5065 §3): the ASNs in wire
//! order plus the segment boundaries, so `AS_SET` and the RFC 5065
//! confederation segments keep their meaning through best-path selection,
//! loop detection and re-advertisement.
//!
//! Stored flat (`asns`) with a parallel segment list (`segs`) rather than a
//! `Vec<Segment>`: `flat()` is then a borrowed slice, which is what RPL's
//! `Input.as_path` and the logs want, at no copy.

use std::fmt;

/// RFC 4271 §4.3 / RFC 5065 §3 segment types — the discriminant is the wire
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegKind {
    Set = 1,
    Sequence = 2,
    ConfedSequence = 3,
    ConfedSet = 4,
}

impl SegKind {
    pub fn from_wire(t: u8) -> Option<Self> {
        match t {
            1 => Some(Self::Set),
            2 => Some(Self::Sequence),
            3 => Some(Self::ConfedSequence),
            4 => Some(Self::ConfedSet),
            _ => None,
        }
    }

    pub fn is_confed(self) -> bool {
        matches!(self, Self::ConfedSequence | Self::ConfedSet)
    }
}

/// A segment's count is one octet on the wire.
pub const MAX_SEGMENT_LEN: usize = 255;

/// Nearest hop first. Invariant: every segment holds 1..=255 ASNs and the
/// counts sum to `asns.len()`.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct AsPath {
    asns: Vec<u32>,
    segs: Vec<(SegKind, u8)>,
}

/// One `AS_SEQUENCE` (split every 255 ASNs).
impl From<Vec<u32>> for AsPath {
    fn from(asns: Vec<u32>) -> Self {
        let mut p = Self::default();
        p.push_segment(SegKind::Sequence, &asns);
        p
    }
}

impl AsPath {
    /// Appends one segment (wire decoding). A sequence continues a trailing
    /// sequence of the same kind up to 255 ASNs — the same path, so equal
    /// paths compare equal however they were split on the wire. Sets never
    /// merge: two sets are two hops.
    pub fn push_segment(&mut self, kind: SegKind, mut asns: &[u32]) {
        if matches!(kind, SegKind::Sequence | SegKind::ConfedSequence)
            && let Some((k, n)) = self.segs.last_mut()
            && *k == kind
        {
            let take = (MAX_SEGMENT_LEN - usize::from(*n)).min(asns.len());
            *n += u8::try_from(take).unwrap_or(0);
            self.asns.extend_from_slice(&asns[..take]);
            asns = &asns[take..];
        }
        for c in asns.chunks(MAX_SEGMENT_LEN) {
            self.segs
                .push((kind, u8::try_from(c.len()).unwrap_or(u8::MAX)));
            self.asns.extend_from_slice(c);
        }
    }

    /// Every ASN in wire order, segment boundaries ignored — RPL input, logs.
    pub fn flat(&self) -> &[u32] {
        &self.asns
    }

    pub fn is_empty(&self) -> bool {
        self.asns.is_empty()
    }

    pub fn segments(&self) -> impl Iterator<Item = (SegKind, &[u32])> {
        let mut at = 0;
        self.segs.iter().map(move |&(kind, n)| {
            let s = &self.asns[at..at + usize::from(n)];
            at += usize::from(n);
            (kind, s)
        })
    }

    /// RFC 4271 §9.1.2.2 (a) path length: a sequence counts each ASN, a set
    /// counts one, confederation segments count zero (RFC 5065 §5.3).
    pub fn selection_len(&self) -> usize {
        self.segments()
            .map(|(k, s)| match k {
                SegKind::Sequence => s.len(),
                SegKind::Set => 1,
                SegKind::ConfedSequence | SegKind::ConfedSet => 0,
            })
            .sum()
    }

    /// The neighbouring AS for MED comparison: the first ASN of the first
    /// non-confederation segment, if that segment is an `AS_SEQUENCE`.
    pub fn neighbor_as(&self) -> Option<u32> {
        match self.segments().find(|(k, _)| !k.is_confed())? {
            (SegKind::Sequence, s) => s.first().copied(),
            _ => None,
        }
    }

    /// `asn` appears in a non-confederation segment.
    pub fn contains(&self, asn: u32) -> bool {
        self.segments()
            .any(|(k, s)| !k.is_confed() && s.contains(&asn))
    }

    /// `asn` appears in a confederation segment.
    pub fn contains_confed(&self, asn: u32) -> bool {
        self.segments()
            .any(|(k, s)| k.is_confed() && s.contains(&asn))
    }

    pub fn has_confed(&self) -> bool {
        self.segs.iter().any(|(k, _)| k.is_confed())
    }

    fn prepend(&mut self, kind: SegKind, asn: u32) {
        self.asns.insert(0, asn);
        match self.segs.first_mut() {
            Some((k, n)) if *k == kind && usize::from(*n) < MAX_SEGMENT_LEN => *n += 1,
            _ => self.segs.insert(0, (kind, 1)),
        }
    }

    /// Prepends `asn` to the leading `AS_SEQUENCE` (a new one if the path
    /// starts with another kind, or that one is full).
    pub fn prepend_seq(&mut self, asn: u32) {
        self.prepend(SegKind::Sequence, asn);
    }

    /// RFC 5065 §4.1: toward a confederation-external peer.
    pub fn prepend_confed_seq(&mut self, asn: u32) {
        self.prepend(SegKind::ConfedSequence, asn);
    }

    /// RFC 5065 §4.1: every confederation segment removed, toward a peer
    /// outside the confederation.
    pub fn strip_confed(&mut self) {
        if !self.has_confed() {
            return;
        }
        let mut out = AsPath::default();
        for (k, s) in self.segments().filter(|(k, _)| !k.is_confed()) {
            out.push_segment(k, s);
        }
        *self = out;
    }

    /// RFC 6793 §4.2.3: rebuilds the real path from a 2-octet `AS_PATH`
    /// (`self`) and an `AS4_PATH` — leading segments of `self` are kept until
    /// what's left has as many AS numbers (RFC 4271 counting) as `as4`, then
    /// `as4` is appended. Leading confederation segments are always kept.
    /// An `AS4_PATH` longer than `AS_PATH` is ignored.
    pub fn merge_as4(&mut self, as4: &AsPath) {
        let Some(mut keep) = self.selection_len().checked_sub(as4.selection_len()) else {
            return;
        };
        let mut out = AsPath::default();
        for (k, s) in self.segments() {
            match k {
                SegKind::ConfedSequence | SegKind::ConfedSet => out.push_segment(k, s),
                _ if keep == 0 => break,
                SegKind::Set => {
                    out.push_segment(k, s);
                    keep -= 1;
                }
                SegKind::Sequence => {
                    let n = keep.min(s.len());
                    out.push_segment(k, &s[..n]);
                    keep -= n;
                }
            }
        }
        for (k, s) in as4.segments() {
            out.push_segment(k, s);
        }
        *self = out;
    }
}

/// Test fixtures compare against a plain list, read as one `AS_SEQUENCE`.
#[cfg(test)]
impl PartialEq<Vec<u32>> for AsPath {
    fn eq(&self, other: &Vec<u32>) -> bool {
        self.segs.iter().all(|(k, _)| *k == SegKind::Sequence) && self.asns == *other
    }
}

/// Operator text: sequence ASNs space-separated, `{..}` set, `(..)` confed
/// sequence, `[..]` confed set (`show bgp routes`).
impl fmt::Display for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let join =
            |s: &[u32], sep: &str| s.iter().map(u32::to_string).collect::<Vec<_>>().join(sep);
        let parts: Vec<String> = self
            .segments()
            .map(|(k, s)| match k {
                SegKind::Sequence => join(s, " "),
                SegKind::Set => format!("{{{}}}", join(s, ",")),
                SegKind::ConfedSequence => format!("({})", join(s, " ")),
                SegKind::ConfedSet => format!("[{}]", join(s, ",")),
            })
            .collect();
        f.write_str(&parts.join(" "))
    }
}

/// A pure `AS_SEQUENCE` path prints like a `Vec` (`[65001, 65002]`), so log
/// lines are unchanged for the common case; otherwise a confederation
/// sequence is `(..)`, a set `{..}`, a confederation set `[..]`.
impl fmt::Debug for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let join = |s: &[u32]| s.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
        let parts: Vec<String> = self
            .segments()
            .map(|(k, s)| match k {
                SegKind::Sequence => join(s),
                SegKind::Set => format!("{{{}}}", join(s)),
                SegKind::ConfedSequence => format!("({})", join(s)),
                SegKind::ConfedSet => format!("[{}]", join(s)),
            })
            .collect();
        write!(f, "[{}]", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_operator_text() {
        let p = path(&[(SegKind::Sequence, &[1, 2]), (SegKind::Set, &[3, 4])]);
        assert_eq!(p.to_string(), "1 2 {3,4}");
        assert_eq!(AsPath::default().to_string(), "");
    }

    fn path(segs: &[(SegKind, &[u32])]) -> AsPath {
        let mut p = AsPath::default();
        for (k, s) in segs {
            p.push_segment(*k, s);
        }
        p
    }

    #[test]
    fn selection_len_counts_set_once_and_confed_not_at_all() {
        let p = path(&[
            (SegKind::ConfedSequence, &[65101, 65102]),
            (SegKind::Sequence, &[65003, 65004]),
            (SegKind::Set, &[1, 2, 3]),
        ]);
        assert_eq!(p.selection_len(), 3);
        assert_eq!(p.flat(), [65101, 65102, 65003, 65004, 1, 2, 3]);
    }

    #[test]
    fn neighbor_as_skips_confed_segments() {
        let p = path(&[
            (SegKind::ConfedSequence, &[65101]),
            (SegKind::Sequence, &[65003]),
        ]);
        assert_eq!(p.neighbor_as(), Some(65003));
        assert_eq!(
            path(&[(SegKind::ConfedSequence, &[65101])]).neighbor_as(),
            None
        );
        assert_eq!(path(&[(SegKind::Set, &[1, 2])]).neighbor_as(), None);
    }

    #[test]
    fn contains_splits_confed_and_plain() {
        let p = path(&[
            (SegKind::ConfedSet, &[65101]),
            (SegKind::Sequence, &[65003]),
        ]);
        assert!(p.contains(65003) && !p.contains(65101));
        assert!(p.contains_confed(65101) && !p.contains_confed(65003));
    }

    #[test]
    fn prepend_merges_and_splits_at_255() {
        let mut p = AsPath::from(vec![1]);
        p.prepend_seq(2);
        assert_eq!(p, AsPath::from(vec![2, 1]));
        p.prepend_confed_seq(9);
        p.prepend_confed_seq(8);
        assert_eq!(format!("{p:?}"), "[(8, 9), 2, 1]");
        p.strip_confed();
        assert_eq!(p, AsPath::from(vec![2, 1]));

        let mut full = AsPath::from(vec![7; 255]);
        full.prepend_seq(6);
        assert_eq!(full.segments().count(), 2);
        assert_eq!(full.segments().next().unwrap().1, [6]);
    }

    #[test]
    fn debug_is_vec_like_for_a_pure_sequence() {
        assert_eq!(
            format!("{:?}", AsPath::from(vec![65001, 65002])),
            "[65001, 65002]"
        );
        assert_eq!(format!("{:?}", AsPath::default()), "[]");
        let p = path(&[
            (SegKind::ConfedSequence, &[65101]),
            (SegKind::Sequence, &[65003]),
            (SegKind::Set, &[1, 2]),
        ]);
        assert_eq!(format!("{p:?}"), "[(65101), 65003, {1, 2}]");
    }

    #[test]
    fn as4_merge_keeps_leading_confed_and_counts_sets_once() {
        // 2-octet path (65101) 65001 23456 {23456, 2} ; AS4_PATH 4200000000 {4200000001, 2}
        let mut p = path(&[
            (SegKind::ConfedSequence, &[65101]),
            (SegKind::Sequence, &[65001, 23456]),
            (SegKind::Set, &[23456, 2]),
        ]);
        let as4 = path(&[
            (SegKind::Sequence, &[4_200_000_000]),
            (SegKind::Set, &[4_200_000_001, 2]),
        ]);
        p.merge_as4(&as4);
        assert_eq!(
            p,
            path(&[
                (SegKind::ConfedSequence, &[65101]),
                (SegKind::Sequence, &[65001, 4_200_000_000]),
                (SegKind::Set, &[4_200_000_001, 2]),
            ])
        );
        // A longer AS4_PATH is ignored.
        let mut short = AsPath::from(vec![65001]);
        short.merge_as4(&AsPath::from(vec![1, 2]));
        assert_eq!(short, AsPath::from(vec![65001]));
    }
}
