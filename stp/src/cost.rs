//! Long path costs, IEEE 802.1Q-2022 Table 13-4.

/// Cost of the slowest row (<= 100 kb/s), also the answer for an unknown speed.
pub const MAX_COST: u32 = 200_000_000;

/// Path cost of a link of `speed_mbps`. The table rows are `20 Gb / speed`
/// (20 000 000 000 / speed in kb/s), clamped to `1..=MAX_COST`; speeds between
/// rows (2.5, 25, 40 Gb/s) use the same formula. Speed 0 (unknown) gives
/// `MAX_COST`; callers treat that as "unknown".
pub fn path_cost(speed_mbps: u32) -> u32 {
    cost_of(u64::from(speed_mbps))
}

/// Path cost of a bond: the formula applied to the sum of its (active)
/// members' speeds. The caller chooses which members count.
pub fn bond_path_cost(member_speeds_mbps: &[u32]) -> u32 {
    cost_of(member_speeds_mbps.iter().map(|&s| u64::from(s)).sum())
}

fn cost_of(speed_mbps: u64) -> u32 {
    if speed_mbps == 0 {
        return MAX_COST;
    }
    u32::try_from((20_000_000 / speed_mbps).clamp(1, u64::from(MAX_COST))).unwrap_or(MAX_COST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_13_4_rows() {
        // (speed in Mb/s, cost). The 100 kb/s row is below 1 Mb/s: it is MAX_COST.
        for (mbps, cost) in [
            (1, 20_000_000),
            (10, 2_000_000),
            (100, 200_000),
            (1_000, 20_000),
            (10_000, 2_000),
            (100_000, 200),
            (1_000_000, 20),
            (10_000_000, 2),
        ] {
            assert_eq!(path_cost(mbps), cost, "{mbps} Mb/s");
        }
    }

    #[test]
    fn off_table_speeds_and_edges() {
        assert_eq!(path_cost(2_500), 8_000);
        assert_eq!(path_cost(25_000), 800);
        assert_eq!(path_cost(40_000), 500);
        assert_eq!(path_cost(0), MAX_COST);
        assert_eq!(path_cost(u32::MAX), 1, "clamped to the minimum");
    }

    #[test]
    fn bond_sums_members() {
        assert_eq!(bond_path_cost(&[1_000, 1_000]), path_cost(2_000));
        assert_eq!(bond_path_cost(&[10_000, 10_000, 10_000, 10_000]), 500);
        assert_eq!(bond_path_cost(&[]), MAX_COST);
        assert_eq!(bond_path_cost(&[0, 0]), MAX_COST);
    }
}
