//! Keyset paging over a per-connection sorted key snapshot (#714/#722),
//! generic over the key so the EVPN/Flowspec/VPN queries (#723) reuse it.
//!
//! The snapshot holds keys only, never the rows: a page binary-searches its
//! `after` key and reads just that page's rows from the live RIB. It is a
//! cache, never required for correctness: a page on a connection with no
//! (or an expired) snapshot builds one and searches it.

use std::time::{Duration, Instant};

/// A snapshot older than this at the next page request is rebuilt.
pub const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

/// Byte budget of one page: half the codec's `MAX_FRAME`.
pub const PAGE_BYTES: usize = nos_proto::codec::MAX_FRAME / 2;

/// `limit` as a usable page size: 0 or over `max` is `max`.
#[must_use]
pub fn clamp_limit(limit: u32, max: u32) -> usize {
    match limit {
        0 => max as usize,
        n => n.min(max) as usize,
    }
}

/// One query kind's snapshot on one connection.
#[derive(Debug)]
pub struct Snapshot<K> {
    keys: Vec<K>,
    built: Instant,
}

impl<K> Default for Snapshot<K> {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            built: Instant::now(),
        }
    }
}

impl<K: Ord + Clone> Snapshot<K> {
    /// Up to `limit` keys strictly after `after`, and whether keys remain
    /// beyond them. A first page (`after == None`), or a snapshot older than
    /// [`SNAPSHOT_TTL`] at `now`, rebuilds it with `build` (sorted).
    pub fn window(
        &mut self,
        after: Option<&K>,
        limit: usize,
        now: Instant,
        build: impl FnOnce() -> Vec<K>,
    ) -> (Vec<K>, bool) {
        let stale = now.saturating_duration_since(self.built) > SNAPSHOT_TTL;
        if after.is_none() || stale || self.keys.is_empty() {
            self.keys = build();
            self.built = now;
        }
        let start = after.map_or(0, |a| self.keys.partition_point(|k| k <= a));
        let end = start.saturating_add(limit).min(self.keys.len());
        (self.keys[start..end].to_vec(), end < self.keys.len())
    }

    /// Frees the keys (the last page was served).
    pub fn release(&mut self) {
        self.keys = Vec::new();
    }

    /// Whether keys are held.
    #[must_use]
    pub fn is_held(&self) -> bool {
        !self.keys.is_empty()
    }
}

/// Reads the rows of `window` with `fetch` (`None`: the key vanished, skip
/// it), stopping once their `size` passes `budget` (a page always holds at
/// least one row, so a walk advances). Returns the rows and how many keys of
/// the window were consumed.
pub fn fill<K, T>(
    window: &[K],
    budget: usize,
    mut fetch: impl FnMut(&K) -> Option<T>,
    size: impl Fn(&T) -> usize,
) -> (Vec<T>, usize) {
    let mut rows = Vec::with_capacity(window.len());
    let mut bytes = 0;
    for (i, key) in window.iter().enumerate() {
        let Some(row) = fetch(key) else { continue };
        bytes += size(&row);
        if bytes > budget && !rows.is_empty() {
            return (rows, i);
        }
        rows.push(row);
    }
    (rows, window.len())
}

/// What one page request asks for.
pub struct Ask<'a, K> {
    /// The previous page's last key.
    pub after: Option<&'a K>,
    /// Most keys wanted (already clamped).
    pub limit: usize,
    /// Byte budget of the rows (see [`fill`]).
    pub budget: usize,
    /// The current time, for the snapshot's age.
    pub now: Instant,
}

/// One page: the rows and the cursor to continue from (`None`: last page).
pub fn page<K: Ord + Clone, T>(
    snapshot: &mut Snapshot<K>,
    ask: &Ask<'_, K>,
    build: impl FnOnce() -> Vec<K>,
    fetch: impl FnMut(&K) -> Option<T>,
    size: impl Fn(&T) -> usize,
) -> (Vec<T>, Option<K>) {
    let (window, more) = snapshot.window(ask.after, ask.limit, ask.now, build);
    let (rows, consumed) = fill(&window, ask.budget, fetch, size);
    let cut = consumed < window.len();
    let next = (more || cut)
        .then(|| consumed.checked_sub(1).map(|i| window[i].clone()))
        .flatten();
    if next.is_none() {
        snapshot.release();
    }
    (rows, next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(limit: usize, budget: usize, n: u32) -> Vec<Vec<u32>> {
        let mut snap = Snapshot::default();
        let mut after = None;
        let mut pages = Vec::new();
        let now = Instant::now();
        loop {
            let (rows, next) = page(
                &mut snap,
                &Ask {
                    after: after.as_ref(),
                    limit,
                    budget,
                    now,
                },
                || (0..n).collect(),
                |k| Some(*k),
                |_| 1,
            );
            pages.push(rows);
            match next {
                Some(k) => after = Some(k),
                None => return pages,
            }
        }
    }

    #[test]
    fn pages_cover_every_key_once_in_order() {
        for (limit, n) in [(1, 5), (2, 4), (3, 4), (10, 4), (4, 4), (3, 0)] {
            let flat: Vec<u32> = walk(limit, usize::MAX, n).concat();
            assert_eq!(flat, (0..n).collect::<Vec<_>>(), "limit {limit} n {n}");
        }
        // An exact multiple of the limit ends on a full page with no next.
        assert_eq!(walk(2, usize::MAX, 4), vec![vec![0, 1], vec![2, 3]]);
    }

    #[test]
    fn a_byte_budget_cuts_the_page_but_always_advances() {
        let pages = walk(10, 3, 7);
        assert_eq!(pages, vec![vec![0, 1, 2], vec![3, 4, 5], vec![6]]);
        // A budget below one row still serves one row per page.
        assert_eq!(walk(10, 0, 3), vec![vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn a_vanished_key_is_skipped_and_a_cursor_on_one_still_works() {
        let mut snap = Snapshot::default();
        let now = Instant::now();
        // Key 1 is gone from the live table.
        let (rows, next) = page(
            &mut snap,
            &Ask {
                after: None,
                limit: 2,
                budget: usize::MAX,
                now,
            },
            || vec![0, 1, 2, 3],
            |k| (*k != 1).then_some(*k),
            |_| 1,
        );
        assert_eq!((rows, next), (vec![0], Some(1)));
        // The cursor key 1 no longer exists anywhere: partition_point still finds the spot.
        let (rows, next) = page(
            &mut snap,
            &Ask {
                after: Some(&1),
                limit: 2,
                budget: usize::MAX,
                now,
            },
            Vec::new,
            |k| Some(*k),
            |_| 1,
        );
        assert_eq!((rows, next), (vec![2, 3], None));
    }

    #[test]
    fn snapshot_lifecycle() {
        let mut snap = Snapshot::default();
        let t0 = Instant::now();
        let mut builds = 0;
        let mut ask = |snap: &mut Snapshot<u32>, after: Option<u32>, now: Instant| {
            let (w, _) = snap.window(after.as_ref(), 2, now, || {
                builds += 1;
                vec![0, 1, 2, 3, 4]
            });
            w
        };
        assert_eq!(ask(&mut snap, None, t0), vec![0, 1]);
        // A later page reuses the snapshot.
        assert_eq!(ask(&mut snap, Some(1), t0), vec![2, 3]);
        // A new first page rebuilds.
        assert_eq!(ask(&mut snap, None, t0), vec![0, 1]);
        // Older than the TTL: rebuilt, and the cursor still searches correctly.
        let later = t0 + SNAPSHOT_TTL + Duration::from_secs(1);
        assert_eq!(ask(&mut snap, Some(3), later), vec![4]);
        // Released (the last page): the next later page builds again.
        snap.release();
        assert!(!snap.is_held());
        assert_eq!(ask(&mut snap, Some(0), later), vec![1, 2]);
        assert_eq!(builds, 4);
    }

    #[test]
    fn limits_clamp() {
        assert_eq!(clamp_limit(0, 1000), 1000);
        assert_eq!(clamp_limit(5, 1000), 5);
        assert_eq!(clamp_limit(5000, 1000), 1000);
    }
}
