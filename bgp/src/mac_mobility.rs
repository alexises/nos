//! RFC 7432 §15 EVPN MAC mobility: which advertisement (local or received
//! from a peer) for a given `(VNI, MAC)` is authoritative, and RFC 7432
//! §15.1/§15.2 duplicate-MAC detection. Pure state, modeled on
//! `damping::Damping` — the RIB decides when a candidate arrives and applies
//! the verdict.
//!
//! There is deliberately no "withdraw" here: a route disappearing from
//! `evpn_adj_rib_in`/`evpn_local` doesn't erase what this module remembers
//! about its `(VNI, MAC)` — RFC 7432's sequence numbers only ever mean
//! anything relative to the last one seen, so forgetting on withdrawal would
//! let a stale, lower-sequence re-announcement win a tie-break it shouldn't.
//! `tick`'s `EXPIRE` bounds memory for a MAC that stops being advertised
//! entirely instead.
//!
//! A MAC is held by one owner *or* by one Ethernet Segment: every PE
//! advertising it with the holder's non-zero ESI is on the same multi-homed
//! segment (RFC 7432 §8.4/§14.1.1 all-active), not a competing claim — §15
//! mobility only applies to a MAC showing up behind a *different* ESI. Those
//! PEs all `holds` it and share one sequence.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tracing::warn;

/// RFC 7432 §15.2's example thresholds: more than this many real moves
/// within the window below is a duplicate MAC.
pub const MOVE_LIMIT: usize = 5;
pub const MOVE_WINDOW: Duration = Duration::from_secs(180);

/// An entry with no candidate at all for this long is forgotten, so a MAC
/// that stops being advertised entirely doesn't sit in memory forever.
const EXPIRE: Duration = Duration::from_secs(3600);

struct MacState {
    seq: u32,
    sticky: bool,
    owner: IpAddr,
    /// The holder's ESI; non-zero means every PE on that segment holds it.
    esi: [u8; 10],
    moves: VecDeque<Instant>,
    frozen: bool,
    last_seen: Instant,
}

impl MacState {
    fn same_segment(&self, esi: [u8; 10]) -> bool {
        esi != [0; 10] && esi == self.esi
    }

    fn holds(&self, owner: IpAddr, esi: [u8; 10]) -> bool {
        owner == self.owner || self.same_segment(esi)
    }
}

/// One `(VNI, MAC)`'s current mobility state.
#[derive(Default)]
pub struct MacMobility {
    entries: HashMap<(u32, [u8; 6]), MacState>,
}

impl MacMobility {
    /// A candidate advertisement for `(vni, mac)` from `owner` (its VTEP —
    /// used consistently as "which PE" throughout `fdb/`'s own ESI/DF-election
    /// code), carrying `seq`/`sticky` decoded from its extended communities
    /// (`(0, false)` when it carried no MAC Mobility community at all).
    ///
    /// Returns whether `owner` is (now) the winner for `(vni, mac)`. A real
    /// ownership change is a "move"; more than `MOVE_LIMIT` within
    /// `MOVE_WINDOW` freezes the entry — a frozen entry keeps reporting its
    /// last winner regardless of further candidates until `tick` lifts the
    /// freeze. A sticky MAC's owner is never displaced by a plain (later)
    /// candidate; a conflicting candidate for a sticky MAC freezes at once,
    /// skipping the move-count threshold (RFC 7432 §15: a sticky/static MAC
    /// must never move).
    ///
    /// A candidate on the holder's own non-zero `esi` is the same segment:
    /// always held, never a move, never a sticky conflict, and its sequence
    /// is shared (the larger one is kept).
    #[allow(clippy::too_many_arguments)]
    pub fn candidate(
        &mut self,
        vni: u32,
        mac: [u8; 6],
        owner: IpAddr,
        esi: [u8; 10],
        seq: u32,
        sticky: bool,
        now: Instant,
    ) -> bool {
        let key = (vni, mac);
        let Some(state) = self.entries.get_mut(&key) else {
            self.entries.insert(
                key,
                MacState {
                    seq,
                    sticky,
                    owner,
                    esi,
                    moves: VecDeque::new(),
                    frozen: false,
                    last_seen: now,
                },
            );
            return true;
        };
        state.last_seen = now;

        if state.frozen {
            return state.holds(owner, esi);
        }
        if state.owner == owner {
            // Same PE re-asserting: track its latest seq/sticky/esi, never a
            // move; on an unchanged segment the sequence stays shared.
            state.seq = if state.same_segment(esi) {
                state.seq.max(seq)
            } else {
                seq
            };
            state.sticky = sticky;
            state.esi = esi;
            return true;
        }
        if state.same_segment(esi) {
            // Another PE on the holder's segment: not a competing claim.
            state.seq = state.seq.max(seq);
            return true;
        }

        // A different PE claiming this MAC: RFC 7432 §15.1 — higher sequence
        // wins, a tie breaks on the lower owner IP. A sticky incumbent is
        // never displaced by an ordinary claim; any conflicting claim against
        // a sticky MAC is an immediate duplicate.
        let wins = if state.sticky {
            false
        } else {
            seq > state.seq || (seq == state.seq && owner < state.owner)
        };
        if !wins {
            if state.sticky {
                Self::freeze(&mut state.moves, &mut state.frozen, vni, mac, now, true);
            }
            return false;
        }

        state
            .moves
            .retain(|t| now.saturating_duration_since(*t) < MOVE_WINDOW);
        state.moves.push_back(now);
        state.seq = seq;
        state.sticky = sticky;
        state.owner = owner;
        state.esi = esi;
        if state.moves.len() > MOVE_LIMIT {
            Self::freeze(&mut state.moves, &mut state.frozen, vni, mac, now, false);
        }
        true
    }

    fn freeze(
        moves: &mut VecDeque<Instant>,
        frozen: &mut bool,
        vni: u32,
        mac: [u8; 6],
        now: Instant,
        sticky_conflict: bool,
    ) {
        *frozen = true;
        moves.push_back(now);
        warn!(
            vni,
            mac = %format_mac(mac),
            moves = moves.len(),
            sticky_conflict,
            "duplicate mac detected, freezing"
        );
    }

    /// The sequence number a local advertisement for `(vni, mac)` from
    /// `owner` behind `esi` should use: the current sequence, unchanged, if
    /// it already holds `(vni, mac)` on that same ESI — itself, or its
    /// segment (an ordinary re-push, or a re-learn behind the shared bond,
    /// isn't a move and must not keep bumping the sequence); otherwise one
    /// past it, so a genuine local re-learn always outranks a stale remote
    /// copy (RFC 7432 §15.1). `0` when nothing is known about this MAC yet.
    #[must_use]
    pub fn local_seq(&self, vni: u32, mac: [u8; 6], owner: IpAddr, esi: [u8; 10]) -> u32 {
        match self.entries.get(&(vni, mac)) {
            Some(s) if (s.owner == owner && s.esi == esi) || s.same_segment(esi) => s.seq,
            Some(s) => s.seq.wrapping_add(1),
            None => 0,
        }
    }

    /// Whether `owner` advertising `(vni, mac)` behind `esi` currently holds
    /// it: it is the winner, or on the winner's (non-zero) segment.
    #[must_use]
    pub fn holds(&self, vni: u32, mac: [u8; 6], owner: IpAddr, esi: [u8; 10]) -> bool {
        self.entries
            .get(&(vni, mac))
            .is_some_and(|s| s.holds(owner, esi))
    }

    #[cfg(test)]
    fn winner(&self, vni: u32, mac: [u8; 6]) -> Option<IpAddr> {
        self.entries.get(&(vni, mac)).map(|s| s.owner)
    }

    /// Expires old move timestamps and lifts a freeze once `MOVE_WINDOW` has
    /// passed with no further contention; forgets any `(VNI, MAC)` with no
    /// candidate at all for `EXPIRE`.
    ///
    /// ponytail: RFC 7432 §15.2's real remedy is administrative
    /// clear-and-investigate; this is a time-boxed auto-recovery instead —
    /// upgrade path is a `clear mac-mobility` operator command if silent
    /// auto-recovery ever proves too permissive.
    pub fn tick(&mut self, now: Instant) {
        self.entries
            .retain(|_, state| now.saturating_duration_since(state.last_seen) < EXPIRE);
        for state in self.entries.values_mut() {
            state
                .moves
                .retain(|t| now.saturating_duration_since(*t) < MOVE_WINDOW);
            if state.frozen && state.moves.is_empty() {
                state.frozen = false;
            }
        }
    }
}

pub(crate) fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    const Z: [u8; 10] = [0; 10];
    const E1: [u8; 10] = [0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
    const E2: [u8; 10] = [0, 1, 0, 0, 0, 0, 0, 0, 0, 2];

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn same_esi_from_two_pes_is_not_a_move() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        let (a, b) = (ip("10.0.0.2"), ip("10.0.0.1"));
        assert!(m.candidate(100, [1; 6], a, E1, 0, false, t0));
        for i in 0..20u32 {
            // b has the lower address and sometimes a higher seq: still no move.
            assert!(m.candidate(100, [1; 6], b, E1, i % 2, false, t0));
            assert!(m.candidate(100, [1; 6], a, E1, 0, false, t0));
        }
        assert!(m.holds(100, [1; 6], a, E1) && m.holds(100, [1; 6], b, E1));
        assert_eq!(m.winner(100, [1; 6]), Some(a));
        // Shared sequence: a segment peer's re-learn doesn't bump it.
        assert_eq!(m.local_seq(100, [1; 6], a, E1), 1);
        assert_eq!(m.local_seq(100, [1; 6], b, E1), 1);
    }

    #[test]
    fn different_esi_is_still_a_move() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        let (a, b) = (ip("10.0.0.2"), ip("10.0.0.1"));
        assert!(m.candidate(100, [1; 6], a, E1, 0, false, t0));
        assert!(m.candidate(100, [1; 6], b, E2, 0, false, t0));
        assert!(!m.holds(100, [1; 6], a, E1));
        assert!(m.holds(100, [1; 6], b, E2));
        assert_eq!(m.local_seq(100, [1; 6], a, E1), 1);
    }

    #[test]
    fn zero_esi_is_never_the_same_segment() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        let (a, b) = (ip("10.0.0.1"), ip("10.0.0.2"));
        assert!(m.candidate(100, [1; 6], a, Z, 0, false, t0));
        assert!(!m.candidate(100, [1; 6], b, Z, 0, false, t0));
        assert!(!m.holds(100, [1; 6], b, Z));
    }

    #[test]
    fn moving_off_the_segment_bumps_and_displaces_it() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        let (a, b) = (ip("10.0.0.1"), ip("10.0.0.2"));
        m.candidate(100, [1; 6], a, E1, 3, false, t0);
        m.candidate(100, [1; 6], b, E1, 3, false, t0);
        // b now sees the MAC behind a single-homed port.
        let seq = m.local_seq(100, [1; 6], b, Z);
        assert_eq!(seq, 4);
        assert!(m.candidate(100, [1; 6], b, Z, seq, false, t0));
        assert!(!m.holds(100, [1; 6], a, E1));
    }

    #[test]
    fn sticky_same_esi_is_not_a_duplicate() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        let (a, b) = (ip("10.0.0.1"), ip("10.0.0.2"));
        assert!(m.candidate(100, [1; 6], a, E1, 0, true, t0));
        assert!(m.candidate(100, [1; 6], b, E1, 0, true, t0));
        // A real conflict from another segment still freezes it (sticky),
        // but the frozen entry keeps admitting every PE on the segment.
        assert!(!m.candidate(100, [1; 6], ip("10.0.0.3"), E2, 9, false, t0));
        assert!(m.holds(100, [1; 6], b, E1));
    }

    #[test]
    fn first_candidate_always_wins() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        assert!(m.candidate(100, [1; 6], ip("10.0.0.1"), Z, 0, false, t0));
        assert_eq!(m.winner(100, [1; 6]), Some(ip("10.0.0.1")));
    }

    #[test]
    fn higher_sequence_wins() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        assert!(m.candidate(100, [1; 6], ip("10.0.0.1"), Z, 0, false, t0));
        assert!(m.candidate(100, [1; 6], ip("10.0.0.2"), Z, 1, false, t0));
        assert_eq!(m.winner(100, [1; 6]), Some(ip("10.0.0.2")));
        // A stale, lower-sequence re-claim loses.
        assert!(!m.candidate(100, [1; 6], ip("10.0.0.1"), Z, 0, false, t0));
        assert_eq!(m.winner(100, [1; 6]), Some(ip("10.0.0.2")));
    }

    #[test]
    fn tie_breaks_on_lower_owner_ip() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        assert!(m.candidate(100, [1; 6], ip("10.0.0.5"), Z, 3, false, t0));
        // Same seq, lower IP: wins.
        assert!(m.candidate(100, [1; 6], ip("10.0.0.2"), Z, 3, false, t0));
        assert_eq!(m.winner(100, [1; 6]), Some(ip("10.0.0.2")));
        // Same seq, higher IP: loses.
        assert!(!m.candidate(100, [1; 6], ip("10.0.0.9"), Z, 3, false, t0));
        assert_eq!(m.winner(100, [1; 6]), Some(ip("10.0.0.2")));
    }

    #[test]
    fn local_seq_outranks_a_different_owner_but_not_itself() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        let me = ip("10.0.0.1");
        let remote = ip("10.0.0.9");
        assert_eq!(m.local_seq(100, [1; 6], me, Z), 0);
        m.candidate(100, [1; 6], remote, Z, 5, false, t0);
        // A different owner (`me`) must outrank the remote's sequence.
        assert_eq!(m.local_seq(100, [1; 6], me, Z), 6);
        m.candidate(100, [1; 6], me, Z, 6, false, t0);
        // Re-asking for the owner that already won doesn't keep bumping it.
        assert_eq!(m.local_seq(100, [1; 6], me, Z), 6);
    }

    #[test]
    fn sticky_owner_is_never_displaced_and_a_conflict_freezes_at_once() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        assert!(m.candidate(100, [1; 6], ip("10.0.0.1"), Z, 0, true, t0));
        // Even a much higher sequence from elsewhere doesn't win.
        assert!(!m.candidate(100, [1; 6], ip("10.0.0.2"), Z, 99, false, t0));
        assert_eq!(m.winner(100, [1; 6]), Some(ip("10.0.0.1")));
        // The conflict froze it: the sticky owner's own re-assertion is
        // still reported as the winner (frozen keeps the last winner).
        assert!(m.candidate(100, [1; 6], ip("10.0.0.1"), Z, 0, true, t0));
    }

    #[test]
    fn n_moves_within_the_window_freezes_and_auto_recovers() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        // First candidate: not a move.
        m.candidate(100, [1; 6], a, Z, 0, false, t0);
        // MOVE_LIMIT real ownership changes: not frozen yet (len == MOVE_LIMIT).
        for i in 0..MOVE_LIMIT {
            let t = t0 + Duration::from_secs(i as u64 + 1);
            let owner = if i % 2 == 0 { b } else { a };
            assert!(m.candidate(
                100,
                [1; 6],
                owner,
                Z,
                u32::try_from(i).unwrap() + 1,
                false,
                t
            ));
        }
        let winner_before = m.winner(100, [1; 6]).unwrap();
        // One more real move crosses the threshold (len == MOVE_LIMIT + 1) and freezes.
        let flip = if winner_before == a { b } else { a };
        let t_extra = t0 + Duration::from_secs(MOVE_LIMIT as u64 + 1);
        assert!(m.candidate(100, [1; 6], flip, Z, 999, false, t_extra));
        let frozen_winner = m.winner(100, [1; 6]);
        assert_eq!(frozen_winner, Some(flip));
        // Further candidates are ignored while frozen, even a higher sequence.
        assert!(!m.candidate(100, [1; 6], ip("10.0.0.3"), Z, 1000, false, t_extra));
        assert_eq!(m.winner(100, [1; 6]), frozen_winner);
        // After the window passes quietly, it recovers and accepts a fresh candidate.
        let t_after = t_extra + MOVE_WINDOW + Duration::from_secs(1);
        m.tick(t_after);
        assert!(m.candidate(100, [1; 6], ip("10.0.0.3"), Z, 1001, false, t_after));
    }

    #[test]
    fn a_withdrawal_does_not_forget_the_sequence_but_a_long_silence_does() {
        let mut m = MacMobility::default();
        let t0 = Instant::now();
        m.candidate(100, [1; 6], ip("10.0.0.9"), Z, 5, false, t0);
        // No `withdraw` API at all: the RIB just stops feeding candidates for
        // a withdrawn route. A later local re-learn still outranks it.
        assert_eq!(m.local_seq(100, [1; 6], ip("10.0.0.1"), Z), 6);
        // Only a long silence (EXPIRE) forgets it, resetting to 0.
        m.tick(t0 + EXPIRE + Duration::from_secs(1));
        assert_eq!(m.local_seq(100, [1; 6], ip("10.0.0.1"), Z), 0);
        assert_eq!(m.winner(100, [1; 6]), None);
    }
}
