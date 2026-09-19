use crate::schema::LldpSettings;

use super::FieldDiff;

fn interval_str(s: &LldpSettings) -> String {
    s.tx_interval_secs
        .map_or_else(|| "default".to_string(), |v| v.to_string())
}

fn hold_str(s: &LldpSettings) -> String {
    s.tx_hold
        .map_or_else(|| "default".to_string(), |v| v.to_string())
}

fn address_str(s: &LldpSettings) -> String {
    s.management_address
        .map_or_else(|| "unset".to_string(), |v| v.to_string())
}

/// Field-level diff of the singleton `Config.lldp` section.
pub fn diff_lldp(base: &LldpSettings, candidate: &LldpSettings) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    let mut push = |label: &str, old: String, new: String| {
        if old != new {
            fields.push(FieldDiff {
                label: label.to_string(),
                old: Some(old),
                new: Some(new),
            });
        }
    };
    push(
        "lldp tx-interval",
        interval_str(base),
        interval_str(candidate),
    );
    push("lldp tx-hold", hold_str(base), hold_str(candidate));
    push(
        "lldp management-address",
        address_str(base),
        address_str(candidate),
    );
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_changed_fields_are_reported() {
        let base = LldpSettings::default();
        assert!(diff_lldp(&base, &base).is_empty());
        let candidate = LldpSettings {
            tx_interval_secs: Some(5),
            ..LldpSettings::default()
        };
        let diff = diff_lldp(&base, &candidate);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].label, "lldp tx-interval");
        assert_eq!(diff[0].old.as_deref(), Some("default"));
        assert_eq!(diff[0].new.as_deref(), Some("5"));
    }
}
