//! `log` rules (#544): each packet a `log` rule matches is sampled to psample
//! group [`ACL_PSAMPLE_GROUP`] with the rule's cookie (its index); one
//! thread turns the samples into `acl log` lines, rate-limited per (device,
//! direction, rule).
//!
//! The device and direction come from psample's ifindexes (egress: `out` is
//! the device; ingress: `out` is 0, `in` the device), the ACL and the rule
//! name from what the engine installed there.
//!
//! ponytail: a sample decoded just after a recompile is named from the new
//! compile (rule indices are the user's, so only a rule inserted or removed
//! before it misnames it); exact naming needs a generation in the cookie.

pub mod packet;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use nos_tc::{psample, Sample, SampleSocket};
use tracing::{info, warn};

use crate::driver::{Direction, Driver, ACL_PSAMPLE_GROUP};
use crate::engine::Shared;
use packet::{parse_frame, FiveTuple, Show};

/// Lines per second per (device, direction, rule), and the burst.
const RATE: f64 = 10.0;
const BURST: f64 = 10.0;
/// At most one `acl log overrun` warning per this.
const OVERRUN_EVERY: Duration = Duration::from_secs(10);
/// Wait before reopening psample after a failure.
const RETRY: Duration = Duration::from_secs(10);
const ENOBUFS: i32 = 105;

/// One `acl log` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub acl: String,
    pub rule: String,
    pub interface: String,
    pub direction: Direction,
    pub tuple: FiveTuple,
    /// Lines the rate limit dropped since the previous one.
    pub suppressed: u64,
}

impl Line {
    pub fn emit(&self) {
        let t = &self.tuple;
        info!(
            acl = %self.acl, rule = %self.rule, interface = %self.interface,
            direction = %self.direction, src = %Show(t.src), dst = %Show(t.dst),
            proto = %Show(t.proto), sport = %Show(t.sport), dport = %Show(t.dport),
            suppressed = self.suppressed, "acl log"
        );
    }
}

struct Bucket {
    tokens: f64,
    at: Instant,
    suppressed: u64,
}

/// `(ifindex, direction, rule)`.
type Key = (u32, Direction, u32);

/// The pure part of the thread: samples in, lines out.
///
/// ponytail: buckets are never pruned; bounded by devices x rules ever
/// logged, small next to the ACLs themselves.
#[derive(Default)]
pub struct Logger {
    buckets: HashMap<Key, Bucket>,
    overruns: u64,
    last_overrun: Option<Instant>,
}

impl Logger {
    /// The line of `s`, or `None`: another group, no cookie, rate-limited,
    /// or nothing `lookup` knows (`(interface, acl, rule)` of a sample).
    pub fn sample(
        &mut self,
        s: &Sample,
        now: Instant,
        lookup: impl FnOnce(u32, Direction, u32) -> Option<(String, String, String)>,
    ) -> Option<Line> {
        if s.group != ACL_PSAMPLE_GROUP {
            return None;
        }
        let rule = u32::from_be_bytes(s.cookie.as_deref()?.try_into().ok()?);
        let (ifindex, direction) = if s.out_ifindex == 0 {
            (s.in_ifindex, Direction::In)
        } else {
            (s.out_ifindex, Direction::Out)
        };
        let suppressed = self.allow((ifindex, direction, rule), now)?;
        let (interface, acl, rule) = lookup(ifindex, direction, rule)?;
        Some(Line {
            acl,
            rule,
            interface,
            direction,
            tuple: parse_frame(&s.data),
            suppressed,
        })
    }

    /// A token bucket per key: `Some(suppressed so far)` when a line may go.
    fn allow(&mut self, key: Key, now: Instant) -> Option<u64> {
        let b = self.buckets.entry(key).or_insert(Bucket {
            tokens: BURST,
            at: now,
            suppressed: 0,
        });
        let refill = now.saturating_duration_since(b.at).as_secs_f64() * RATE;
        b.tokens = (b.tokens + refill).min(BURST);
        b.at = now;
        if b.tokens < 1.0 {
            b.suppressed += 1;
            return None;
        }
        b.tokens -= 1.0;
        Some(std::mem::take(&mut b.suppressed))
    }

    /// The kernel dropped samples (`ENOBUFS`): the running total, at most
    /// once per [`OVERRUN_EVERY`].
    pub fn overrun(&mut self, now: Instant) -> Option<u64> {
        self.overruns += 1;
        if self
            .last_overrun
            .is_some_and(|t| now.saturating_duration_since(t) < OVERRUN_EVERY)
        {
            return None;
        }
        self.last_overrun = Some(now);
        Some(self.overruns)
    }
}

/// Starts the thread; the engine calls it once, when a `log` rule is first
/// installed.
///
/// ponytail: a detached blocking thread, never joined: it dies with the
/// process, and stays (idle) after the last `log` rule goes.
pub fn spawn<D: Driver>(engine: Shared<D>) {
    std::thread::Builder::new()
        .name("acl-log".into())
        .spawn(move || run(&engine))
        .expect("spawning the acl log thread");
}

fn run<D: Driver>(engine: &Shared<D>) {
    let mut logger = Logger::default();
    let mut warned = false;
    loop {
        let mut socket = match psample().and_then(|p| SampleSocket::open(&p)) {
            Ok(s) => s,
            Err(e) => {
                if !std::mem::replace(&mut warned, true) {
                    warn!(error = %e, "psample unavailable: acl log disabled");
                }
                std::thread::sleep(RETRY);
                continue;
            }
        };
        info!("acl log listening");
        loop {
            match socket.recv() {
                Ok(samples) => {
                    for s in &samples {
                        let lookup = |i, d, r| engine.lock().unwrap().log_target(i, d, r);
                        if let Some(line) = logger.sample(s, Instant::now(), lookup) {
                            line.emit();
                        }
                    }
                }
                Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
                    if let Some(overruns) = logger.overrun(Instant::now()) {
                        warn!(overruns, "acl log overrun");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "psample socket failed, reopening");
                    std::thread::sleep(RETRY);
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(iif: u32, oif: u32, cookie: Option<u32>) -> Sample {
        Sample {
            group: ACL_PSAMPLE_GROUP,
            in_ifindex: iif,
            out_ifindex: oif,
            cookie: cookie.map(|c| c.to_be_bytes().to_vec()),
            data: Vec::new(),
        }
    }

    #[allow(clippy::unnecessary_wraps, reason = "a `lookup`")]
    fn names(ifindex: u32, dir: Direction, rule: u32) -> Option<(String, String, String)> {
        Some((format!("if{ifindex}-{dir}"), "E".into(), format!("r{rule}")))
    }

    #[test]
    fn direction_and_device_come_from_the_ifindexes() {
        let (mut l, now) = (Logger::default(), Instant::now());
        let line = l.sample(&sample(3, 0, Some(1)), now, names).unwrap();
        assert_eq!(
            (
                &line.interface[..],
                line.direction,
                &line.acl[..],
                &line.rule[..]
            ),
            ("if3-in", Direction::In, "E", "r1")
        );
        // Egress: the device is `out`, whatever `in` (a forwarded packet's).
        let line = l.sample(&sample(3, 4, Some(1)), now, names).unwrap();
        assert_eq!((&line.interface[..], line.suppressed), ("if4-out", 0));
        assert_eq!(line.tuple, FiveTuple::default());
        line.emit();
    }

    #[test]
    fn foreign_groups_missing_cookies_and_unknown_rules_log_nothing() {
        let (mut l, now) = (Logger::default(), Instant::now());
        let mut other = sample(3, 0, Some(1));
        other.group = 1;
        assert_eq!(l.sample(&other, now, names), None);
        assert_eq!(l.sample(&sample(3, 0, None), now, names), None);
        let mut short = sample(3, 0, None);
        short.cookie = Some(vec![1, 2]);
        assert_eq!(l.sample(&short, now, names), None);
        assert_eq!(l.sample(&sample(3, 0, Some(9)), now, |_, _, _| None), None);
    }

    #[test]
    fn the_rate_limit_bursts_refills_and_counts_what_it_dropped() {
        let (mut l, t0) = (Logger::default(), Instant::now());
        let s = sample(3, 0, Some(1));
        for _ in 0..10 {
            assert_eq!(l.sample(&s, t0, names).map(|x| x.suppressed), Some(0));
        }
        for _ in 0..5 {
            assert_eq!(l.sample(&s, t0, names), None);
        }
        // Another rule (and another direction) has its own bucket.
        assert!(l.sample(&sample(3, 0, Some(2)), t0, names).is_some());
        assert!(l.sample(&sample(0, 3, Some(1)), t0, names).is_some());
        // 100 ms refills one line, which carries the 5 dropped.
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!(l.sample(&s, t1, names).map(|x| x.suppressed), Some(5));
        assert_eq!(l.sample(&s, t1, names), None);
        // A long pause refills the burst, not more.
        let t2 = t1 + Duration::from_secs(60);
        let lines = (0..12)
            .filter(|_| l.sample(&s, t2, names).is_some())
            .count();
        assert_eq!(lines, 10);
    }

    #[test]
    fn overruns_warn_at_most_every_ten_seconds() {
        let (mut l, t0) = (Logger::default(), Instant::now());
        assert_eq!(l.overrun(t0), Some(1));
        assert_eq!(l.overrun(t0 + Duration::from_secs(1)), None);
        assert_eq!(l.overrun(t0 + Duration::from_secs(10)), Some(3));
    }
}
