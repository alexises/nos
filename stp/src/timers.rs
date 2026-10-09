//! Bridge timer parameters, IEEE 802.1Q-2022 Table 13-5 and 13.25.

/// Seconds. `max_hops` (MSTP) is not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timers {
    pub hello: u8,
    pub max_age: u8,
    pub forward_delay: u8,
    pub tx_hold_count: u8,
    pub migrate_time: u8,
}

pub const HELLO_RANGE: (u8, u8) = (1, 10);
pub const MAX_AGE_RANGE: (u8, u8) = (6, 40);
pub const FORWARD_DELAY_RANGE: (u8, u8) = (4, 30);
pub const TX_HOLD_COUNT_RANGE: (u8, u8) = (1, 10);
/// Migrate Time is fixed at 3 s by the standard.
pub const MIGRATE_TIME: u8 = 3;

impl Default for Timers {
    fn default() -> Self {
        Timers {
            hello: 2,
            max_age: 20,
            forward_delay: 15,
            tx_hold_count: 6,
            migrate_time: MIGRATE_TIME,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimersError {
    #[error("{name} {value} outside {min}..={max}")]
    OutOfRange {
        name: &'static str,
        value: u8,
        min: u8,
        max: u8,
    },
    #[error("migrate time must be {MIGRATE_TIME}")]
    MigrateTime,
    #[error("2*(forward-delay-1) >= max-age >= 2*(hello+1) does not hold (13.25)")]
    Relation,
}

impl Timers {
    /// Table 13-5 ranges plus the 13.25 relation.
    pub fn validate(&self) -> Result<(), TimersError> {
        for (name, value, (min, max)) in [
            ("hello", self.hello, HELLO_RANGE),
            ("max-age", self.max_age, MAX_AGE_RANGE),
            ("forward-delay", self.forward_delay, FORWARD_DELAY_RANGE),
            ("tx-hold-count", self.tx_hold_count, TX_HOLD_COUNT_RANGE),
        ] {
            if !(min..=max).contains(&value) {
                return Err(TimersError::OutOfRange {
                    name,
                    value,
                    min,
                    max,
                });
            }
        }
        if self.migrate_time != MIGRATE_TIME {
            return Err(TimersError::MigrateTime);
        }
        // ponytail: the 13.25 rule is also in nos-proto's commit check (nos-stp stays dependency-free); a cross-test with nos-proto as dev-dependency can pin them together.
        let (h, m, f) = (
            u16::from(self.hello),
            u16::from(self.max_age),
            u16::from(self.forward_delay),
        );
        if 2 * (f - 1) >= m && m >= 2 * (h + 1) {
            Ok(())
        } else {
            Err(TimersError::Relation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(hello: u8, max_age: u8, forward_delay: u8) -> Timers {
        Timers {
            hello,
            max_age,
            forward_delay,
            ..Timers::default()
        }
    }

    #[test]
    fn defaults_valid() {
        assert_eq!(Timers::default().validate(), Ok(()));
    }

    #[test]
    fn relation_both_sides() {
        // 2*(15-1) = 28 >= 28 ok, 29 not; 2*(2+1) = 6 <= 6 ok, hello 3 needs 8.
        assert_eq!(t(2, 28, 15).validate(), Ok(()));
        assert_eq!(t(2, 29, 15).validate(), Err(TimersError::Relation));
        assert_eq!(t(2, 6, 15).validate(), Ok(()));
        assert_eq!(t(3, 6, 15).validate(), Err(TimersError::Relation));
    }

    #[test]
    fn range_edges() {
        let out = |t: Timers, n: &str| matches!(t.validate(), Err(TimersError::OutOfRange { name, .. }) if name == n);
        assert!(out(t(0, 20, 15), "hello"));
        assert!(out(t(11, 40, 30), "hello"));
        assert_eq!(t(10, 40, 30).validate(), Ok(()));
        assert_eq!(t(1, 6, 4).validate(), Ok(()), "all minima, 2*(4-1) = 6");
        assert!(out(t(2, 5, 15), "max-age"));
        assert!(out(t(2, 41, 30), "max-age"));
        assert!(out(t(2, 6, 3), "forward-delay"));
        assert!(out(t(2, 20, 31), "forward-delay"));
        for (v, ok) in [(0, false), (1, true), (10, true), (11, false)] {
            let timers = Timers {
                tx_hold_count: v,
                ..Timers::default()
            };
            assert_eq!(timers.validate().is_ok(), ok, "tx hold {v}");
        }
        let m = Timers {
            migrate_time: 4,
            ..Timers::default()
        };
        assert_eq!(m.validate(), Err(TimersError::MigrateTime));
    }
}
