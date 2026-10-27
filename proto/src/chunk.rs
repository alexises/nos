//! Chunking of a `Full` snapshot too large for one IPC frame, shared by every
//! `Full`/`FullPart` protocol (`BgpRouteUpdate`, `EvpnUpdate`, ...). The
//! caller's `weight` closure says what a budget counts: items, paths or
//! encoded bytes. Each protocol keeps its own `FullPart` variant and budget.

/// Cuts `items` greedily, in order, into `parts` that each weigh at most
/// `budget` (a part always holds at least one item, so an oversized item
/// travels alone) and a `closing` chunk: the last one. A set within the
/// budget (empty included) is just `closing`. The sender emits each part as a
/// `FullPart` and the closing chunk as the `Full`.
pub fn split_full<T>(
    items: Vec<T>,
    budget: usize,
    weight: impl Fn(&T) -> usize,
) -> (Vec<Vec<T>>, Vec<T>) {
    let mut parts = Vec::new();
    let (mut cur, mut used) = (Vec::new(), 0usize);
    for item in items {
        let w = weight(&item);
        if used.saturating_add(w) > budget && !cur.is_empty() {
            parts.push(std::mem::take(&mut cur));
            used = 0;
        }
        cur.push(item);
        used = used.saturating_add(w);
    }
    (parts, cur)
}

/// One connection's chunked `Full` snapshot in progress: nothing is applied
/// until the closing `Full`, so a table never shows half a snapshot. Drop it
/// with the connection (a snapshot lost mid-way is resent whole on reconnect).
/// ponytail: staged parts are uncapped (owner decision); the sender is an
/// authenticated daemon.
#[derive(Debug)]
pub struct FullStaging<T> {
    items: Vec<T>,
    parts: usize,
}

impl<T> Default for FullStaging<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            parts: 0,
        }
    }
}

impl<T> FullStaging<T> {
    /// Stages one `FullPart`.
    pub fn part(&mut self, mut items: Vec<T>) {
        self.items.append(&mut items);
        self.parts += 1;
    }

    /// Whether a snapshot is mid-way (a `Full` now would close it).
    #[must_use]
    pub fn is_staging(&self) -> bool {
        self.parts > 0
    }

    /// Closes with the `Full`'s items: the whole snapshot, in order, and the
    /// number of frames it took (the closing one included; 1 when nothing was
    /// staged). Resets the staging.
    pub fn close(&mut self, mut items: Vec<T>) -> (Vec<T>, usize) {
        let mut all = std::mem::take(&mut self.items);
        all.append(&mut items);
        (all, std::mem::take(&mut self.parts) + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::ptr_arg, reason = "must match Fn(&T) with T = String")]
    fn by_len(s: &String) -> usize {
        s.len()
    }

    fn strs(sizes: &[usize]) -> Vec<String> {
        sizes.iter().map(|n| "x".repeat(*n)).collect()
    }

    #[test]
    fn within_budget_is_one_closing_chunk() {
        let (p, c) = split_full(Vec::<String>::new(), 10, by_len);
        assert!(p.is_empty() && c.is_empty());
        let (p, c) = split_full(strs(&[4, 6]), 10, by_len);
        assert!(p.is_empty(), "exact fit stays whole");
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn parts_respect_the_budget_and_keep_order() {
        let items: Vec<String> = (1..=9).map(|i| i.to_string().repeat(i % 4 + 1)).collect();
        let (p, c) = split_full(items.clone(), 5, by_len);
        assert!(p.len() > 1);
        for part in p.iter().chain([&c]) {
            assert!(part.iter().map(String::len).sum::<usize>() <= 5);
        }
        let rejoined: Vec<String> = p.into_iter().flatten().chain(c).collect();
        assert_eq!(rejoined, items);
    }

    #[test]
    fn an_oversized_item_travels_alone() {
        let (p, c) = split_full(strs(&[2, 50, 2]), 10, by_len);
        assert_eq!((p.len(), c.len()), (2, 1));
        assert_eq!(p[1][0].len(), 50);
        // A leading oversized item must not yield an empty part.
        let (p, c) = split_full(strs(&[50, 2]), 10, by_len);
        assert_eq!((p.len(), c.len()), (1, 1));
    }

    #[test]
    fn staging_parts_then_close_then_drop() {
        let mut s = FullStaging::<u8>::default();
        assert!(!s.is_staging());
        assert_eq!(s.close(vec![7]), (vec![7], 1));
        s.part(vec![1, 2]);
        s.part(vec![3]);
        assert!(s.is_staging());
        assert_eq!(s.close(vec![4]), (vec![1, 2, 3, 4], 3));
        assert!(!s.is_staging());
        s.part(vec![9]);
        drop(s); // connection lost mid-snapshot: nothing leaks to the next
        assert_eq!(FullStaging::<u8>::default().close(vec![]), (vec![], 1));
    }
}
