//! `LogEntry` → one RFC 5424 message. Pure: no I/O, no clock.
//!
//! `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`,
//! with MSG a UTF-8 string led by the BOM (RFC 5424 §6.4).

use std::fmt::Write;

use nos_proto::{LogEntry, LogLevel, SyslogFacility};

/// Octets of the UTF-8 byte order mark that RFC 5424 §6.4 puts before a UTF-8 MSG.
const BOM: char = '\u{FEFF}';

// ponytail: the entry's `target` and fields go into MSG as ` k=v` text, not
// into a private STRUCTURED-DATA element: RFC 5424 §6.3.2 needs a
// `name@<IANA enterprise number>` SD-ID and nos has no number (32473 is
// documentation-only). Switch once a PEN exists.
const STRUCTURED_DATA: &str = "[timeQuality tzKnown=\"1\" isSynced=\"0\"]";

/// RFC 5424 §6.2.1 severity of a nos level (Table 2).
pub const fn severity(level: LogLevel) -> u8 {
    match level {
        LogLevel::Error => 3,
        LogLevel::Warn => 4,
        LogLevel::Info => 6,
        LogLevel::Debug | LogLevel::Trace => 7,
    }
}

/// Whether `level` is at least as severe as `minimum`.
pub const fn at_least(level: LogLevel, minimum: LogLevel) -> bool {
    rank(level) <= rank(minimum)
}

const fn rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Error => 0,
        LogLevel::Warn => 1,
        LogLevel::Info => 2,
        LogLevel::Debug => 3,
        LogLevel::Trace => 4,
    }
}

/// A header field restricted to PRINTUSASCII (33-126) and `max` octets;
/// NILVALUE when nothing is left.
fn header_field(s: &str, max: usize) -> String {
    let f: String = s
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .take(max)
        .collect();
    if f.is_empty() {
        "-".to_string()
    } else {
        f
    }
}

/// `1970-01-01T00:00:00.000Z` from milliseconds since the epoch (RFC 3339,
/// upper-case `T`/`Z`, UTC, no leap seconds — RFC 5424 §6.2.3).
fn timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil-from-days.
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

/// `nos-ribd[rt1]` → (`nos-ribd`, `rt1`).
fn app_and_proc(source: &str) -> (&str, Option<&str>) {
    match source.split_once('[') {
        Some((app, rest)) => (app, Some(rest.trim_end_matches(']'))),
        None => (source, None),
    }
}

/// The message for `entry`, cut to at most `max` octets (on a character
/// boundary) so it fits one datagram or frame.
pub fn render(entry: &LogEntry, hostname: &str, facility: SyslogFacility, max: usize) -> String {
    let pri = u16::from(facility.code()) * 8 + u16::from(severity(entry.level));
    let (app, proc) = app_and_proc(&entry.source);
    let mut m = String::new();
    // Writing to a String cannot fail.
    let _ = write!(
        m,
        "<{pri}>1 {} {} {} {} - {STRUCTURED_DATA} {BOM}{}",
        timestamp(entry.timestamp_ms),
        header_field(hostname, 255),
        header_field(app, 48),
        proc.map_or_else(|| "-".to_string(), |p| header_field(p, 128)),
        entry.message,
    );
    for (k, v) in &entry.fields {
        let _ = write!(m, " {k}={v}");
    }
    if m.len() > max {
        let mut end = max;
        while !m.is_char_boundary(end) {
            end -= 1;
        }
        m.truncate(end);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(level: LogLevel, source: &str, message: &str) -> LogEntry {
        LogEntry {
            // 2026-10-05T12:34:56.789Z
            timestamp_ms: 1_791_203_696_789,
            level,
            source: source.into(),
            target: "t".into(),
            message: message.into(),
            fields: vec![("table".into(), "rt1".into())],
        }
    }

    #[test]
    fn golden_message() {
        let m = render(
            &entry(LogLevel::Warn, "nos-ribd[rt1]", "route added"),
            "r1",
            SyslogFacility::Local3,
            2048,
        );
        assert_eq!(
            m,
            "<156>1 2026-10-05T12:34:56.789Z r1 nos-ribd rt1 - \
             [timeQuality tzKnown=\"1\" isSynced=\"0\"] \u{FEFF}route added table=rt1"
        );
    }

    #[test]
    fn pri_is_facility_times_eight_plus_severity() {
        let pri = |l, f| {
            let m = render(&entry(l, "x", "m"), "h", f, 2048);
            m[1..m.find('>').unwrap()].parse::<u16>().unwrap()
        };
        assert_eq!(pri(LogLevel::Error, SyslogFacility::Local0), 16 * 8 + 3);
        assert_eq!(pri(LogLevel::Info, SyslogFacility::Local7), 23 * 8 + 6);
        assert_eq!(pri(LogLevel::Trace, SyslogFacility::Local7), 23 * 8 + 7);
        assert_eq!(pri(LogLevel::Debug, SyslogFacility::Local7), 23 * 8 + 7);
    }

    #[test]
    fn timestamps() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(timestamp(1_791_203_696_789), "2026-10-05T12:34:56.789Z");
    }

    #[test]
    fn nil_procid_and_sanitized_header() {
        let m = render(
            &entry(LogLevel::Info, "nos-configd", "x"),
            "my host\u{e9}",
            SyslogFacility::Local7,
            2048,
        );
        let h: Vec<&str> = m.split(' ').collect();
        assert_eq!(h[2], "my_host_");
        assert_eq!(h[3], "nos-configd");
        assert_eq!(h[4], "-");
        let long = "a".repeat(100);
        let m = render(
            &entry(LogLevel::Info, &format!("{long}[{long}{long}]"), "x"),
            &"h".repeat(300),
            SyslogFacility::Local7,
            2048,
        );
        let h: Vec<&str> = m.split(' ').collect();
        assert_eq!(
            (h[2].len(), h[3].len(), h[4].len()),
            (255, 48, 128),
            "limits of RFC 5424 §6"
        );
    }

    #[test]
    fn truncates_on_a_char_boundary() {
        let e = entry(LogLevel::Info, "x", &"é".repeat(100));
        for max in [60, 61, 62, 63] {
            let m = render(&e, "h", SyslogFacility::Local7, max);
            assert!(m.len() <= max);
            assert!(std::str::from_utf8(m.as_bytes()).is_ok());
        }
    }

    #[test]
    fn level_filter_orders_by_severity() {
        assert!(at_least(LogLevel::Error, LogLevel::Info));
        assert!(at_least(LogLevel::Info, LogLevel::Info));
        assert!(!at_least(LogLevel::Debug, LogLevel::Info));
        assert!(at_least(LogLevel::Trace, LogLevel::Trace));
    }

    mod props {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn any_entry_renders_valid_and_bounded(
                source in ".{0,200}", message in ".{0,300}", host in ".{0,300}",
                k in ".{0,40}", v in ".{0,40}", ms in 0u64..4_000_000_000_000u64,
                max in 700usize..2048,
            ) {
                let e = LogEntry {
                    timestamp_ms: ms,
                    level: LogLevel::Info,
                    source,
                    target: String::new(),
                    message,
                    fields: vec![(k, v)],
                };
                let m = render(&e, &host, SyslogFacility::Local7, max);
                prop_assert!(m.len() <= max);
                // Header (up to MSGID) is `<PRI>1 TS HOST APP PROC -` — all PRINTUSASCII.
                let h: Vec<&str> = m.splitn(8, ' ').collect();
                prop_assert!(h[0].starts_with('<') && h[0].ends_with(">1"));
                prop_assert!(h.len() >= 7);
                for f in &h[2..6] {
                    prop_assert!(!f.is_empty() && f.bytes().all(|b| (33..=126).contains(&b)));
                }
                prop_assert!(h[2].len() <= 255 && h[3].len() <= 48 && h[4].len() <= 128);
            }
        }
    }
}
