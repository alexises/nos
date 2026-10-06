use crate::schema::{LoggingSettings, SyslogServer};

use super::FieldDiff;

/// One collector's settings as `(label suffix, rendered value)`.
fn fields(s: &SyslogServer) -> Vec<(&'static str, String)> {
    vec![
        ("address", s.address.to_string()),
        ("port", s.effective_port().to_string()),
        ("transport", format!("{:?}", s.transport).to_lowercase()),
        (
            "routing-table",
            s.routing_table.clone().unwrap_or_else(|| "unset".into()),
        ),
        ("level", format!("{:?}", s.effective_level()).to_lowercase()),
        (
            "facility",
            format!("{:?}", s.effective_facility()).to_lowercase(),
        ),
    ]
}

/// Field-level diff of the singleton `Config.logging` section: one field per
/// collector setting, a whole collector appearing or vanishing as its fields
/// with an absent side.
pub fn diff_logging(base: &LoggingSettings, candidate: &LoggingSettings) -> Vec<FieldDiff> {
    let mut out = Vec::new();
    for b in &base.syslog {
        let new = candidate
            .syslog
            .iter()
            .find(|c| c.name == b.name)
            .map(fields);
        for (i, (label, old)) in fields(b).into_iter().enumerate() {
            let new = new.as_ref().map(|n| n[i].1.clone());
            if new.as_ref() != Some(&old) {
                out.push(FieldDiff {
                    label: format!("logging syslog {} {label}", b.name),
                    old: Some(old),
                    new,
                });
            }
        }
    }
    for c in &candidate.syslog {
        if !base.syslog.iter().any(|b| b.name == c.name) {
            for (label, new) in fields(c) {
                out.push(FieldDiff {
                    label: format!("logging syslog {} {label}", c.name),
                    old: None,
                    new: Some(new),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(name: &str) -> SyslogServer {
        SyslogServer {
            name: name.into(),
            ..SyslogServer::default()
        }
    }

    fn cfg(v: Vec<SyslogServer>) -> LoggingSettings {
        LoggingSettings { syslog: v }
    }

    #[test]
    fn unchanged_is_empty() {
        assert_eq!(diff_logging(&cfg(vec![s("a")]), &cfg(vec![s("a")])), []);
    }

    #[test]
    fn changed_field_added_and_removed_server() {
        let mut b = s("a");
        b.port = Some(1514);
        let d = diff_logging(&cfg(vec![s("a")]), &cfg(vec![b]));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].label, "logging syslog a port");
        assert_eq!(d[0].new.as_deref(), Some("1514"));

        let added = diff_logging(&cfg(vec![]), &cfg(vec![s("a")]));
        assert!(added.iter().all(|f| f.old.is_none() && f.new.is_some()));
        let removed = diff_logging(&cfg(vec![s("a")]), &cfg(vec![]));
        assert!(removed.iter().all(|f| f.new.is_none() && f.old.is_some()));
        assert_eq!(added.len(), removed.len());
    }
}
