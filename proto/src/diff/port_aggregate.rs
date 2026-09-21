use crate::schema::PortAggregate;

use super::{subinterface, DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `PortAggregate`s, matched by `name`. No flat
/// addresses/routing-table fields to diff (unlike `diff_broadcast_domains`)
/// — all L3 config is nested under `subinterfaces`, mirroring
/// `diff_interfaces`'s own subsection handling.
pub fn diff_port_aggregates(
    base: &[PortAggregate],
    candidate: &[PortAggregate],
) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let fields = changed_fields(b, c);
                let subsections =
                    subinterface::diff_subinterfaces(&b.subinterfaces, &c.subinterfaces);
                if !fields.is_empty() || !subsections.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(&b.name),
                        name: b.name.clone(),
                        status: DiffStatus::Modified,
                        fields,
                        subsections,
                    });
                }
            }
        }
    }

    for c in candidate {
        if !base.iter().any(|b| b.name == c.name) {
            sections.push(added_section(c));
        }
    }

    sections
}

fn header_for(name: &str) -> String {
    format!("port aggregate {name}")
}

fn switching_profile_str(agg: &PortAggregate) -> String {
    agg.switching_profile
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn mtu_str(agg: &PortAggregate) -> String {
    agg.mtu
        .map_or_else(|| "unset".to_string(), |m| m.to_string())
}

fn mode_str(agg: &PortAggregate) -> String {
    format!("{:?}", agg.mode)
}

fn changed_fields(base: &PortAggregate, candidate: &PortAggregate) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.mode != candidate.mode {
        fields.push(FieldDiff {
            label: "mode".to_string(),
            old: Some(mode_str(base)),
            new: Some(mode_str(candidate)),
        });
    }
    if base.lacp_rate != candidate.lacp_rate {
        fields.push(FieldDiff {
            label: "lacp-rate".to_string(),
            old: Some(format!("{:?}", base.lacp_rate)),
            new: Some(format!("{:?}", candidate.lacp_rate)),
        });
    }
    for (label, old, new) in [
        ("esi", &base.esi, &candidate.esi),
        (
            "lacp-system-id",
            &base.lacp_system_id,
            &candidate.lacp_system_id,
        ),
    ] {
        if old != new {
            fields.push(FieldDiff {
                label: label.to_string(),
                old: Some(old.clone().unwrap_or_else(|| "unset".to_string())),
                new: Some(new.clone().unwrap_or_else(|| "unset".to_string())),
            });
        }
    }
    if base.switching_profile != candidate.switching_profile {
        fields.push(FieldDiff {
            label: "switching-profile".to_string(),
            old: Some(switching_profile_str(base)),
            new: Some(switching_profile_str(candidate)),
        });
    }
    if base.mtu != candidate.mtu {
        fields.push(FieldDiff {
            label: "mtu".to_string(),
            old: Some(mtu_str(base)),
            new: Some(mtu_str(candidate)),
        });
    }
    fields
}

fn removed_section(agg: &PortAggregate) -> SectionDiff {
    SectionDiff {
        header: header_for(&agg.name),
        name: agg.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "mode".to_string(),
                old: Some(mode_str(agg)),
                new: None,
            },
            FieldDiff {
                label: "switching-profile".to_string(),
                old: Some(switching_profile_str(agg)),
                new: None,
            },
            FieldDiff {
                label: "mtu".to_string(),
                old: Some(mtu_str(agg)),
                new: None,
            },
        ],
        subsections: subinterface::diff_subinterfaces(&agg.subinterfaces, &[]),
    }
}

fn added_section(agg: &PortAggregate) -> SectionDiff {
    SectionDiff {
        header: header_for(&agg.name),
        name: agg.name.clone(),
        status: DiffStatus::Added,
        fields: vec![
            FieldDiff {
                label: "mode".to_string(),
                old: None,
                new: Some(mode_str(agg)),
            },
            FieldDiff {
                label: "switching-profile".to_string(),
                old: None,
                new: Some(switching_profile_str(agg)),
            },
            FieldDiff {
                label: "mtu".to_string(),
                old: None,
                new: Some(mtu_str(agg)),
            },
        ],
        subsections: subinterface::diff_subinterfaces(&[], &agg.subinterfaces),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::PortAggregateMode;

    fn aggregate(name: &str) -> PortAggregate {
        PortAggregate {
            name: name.to_string(),
            mode: PortAggregateMode::Xor,
            lacp_rate: crate::schema::LacpRate::default(),
            esi: None,
            lacp_system_id: None,
            switching_profile: None,
            mtu: None,
            subinterfaces: Vec::new(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![aggregate("bond1")];
        let candidate = base.clone();
        assert!(diff_port_aggregates(&base, &candidate).is_empty());
    }

    #[test]
    fn added_aggregate() {
        let sections = diff_port_aggregates(&[], &[aggregate("bond1")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "port aggregate bond1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_aggregate() {
        let sections = diff_port_aggregates(&[aggregate("bond1")], &[]);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_switching_profile_only_lists_that_field() {
        let base = vec![aggregate("bond1")];
        let mut candidate_agg = aggregate("bond1");
        candidate_agg.switching_profile = Some("sp1".to_string());
        let sections = diff_port_aggregates(&base, &[candidate_agg]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "switching-profile");
    }
}
