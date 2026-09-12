use crate::schema::BgpInstance;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `BgpInstance`s, matched by `name` (the field
/// `garde`'s `unique_in` validator already treats as each instance's key).
/// Instances present on only one side are emitted wholesale as
/// `Added`/`Removed`; instances present on both sides are compared
/// field-by-field and only included at all if `router_id` or `asn` actually
/// changed.
pub fn diff_bgp_instances(base: &[BgpInstance], candidate: &[BgpInstance]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let fields = changed_fields(b, c);
                if !fields.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(&b.name),
                        status: DiffStatus::Modified,
                        fields,
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
    format!("bgp instance {name}")
}

fn changed_fields(base: &BgpInstance, candidate: &BgpInstance) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.router_id != candidate.router_id {
        fields.push(FieldDiff {
            label: "router-id".to_string(),
            old: Some(base.router_id.to_string()),
            new: Some(candidate.router_id.to_string()),
        });
    }
    if base.asn != candidate.asn {
        fields.push(FieldDiff {
            label: "asn".to_string(),
            old: Some(base.asn.to_string()),
            new: Some(candidate.asn.to_string()),
        });
    }
    fields
}

fn removed_section(instance: &BgpInstance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "router-id".to_string(),
                old: Some(instance.router_id.to_string()),
                new: None,
            },
            FieldDiff {
                label: "asn".to_string(),
                old: Some(instance.asn.to_string()),
                new: None,
            },
        ],
    }
}

fn added_section(instance: &BgpInstance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        status: DiffStatus::Added,
        fields: vec![
            FieldDiff {
                label: "router-id".to_string(),
                old: None,
                new: Some(instance.router_id.to_string()),
            },
            FieldDiff {
                label: "asn".to_string(),
                old: None,
                new: Some(instance.asn.to_string()),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![instance("r1", 65000)];
        let candidate = base.clone();
        assert!(diff_bgp_instances(&base, &candidate).is_empty());
    }

    #[test]
    fn added_instance() {
        let base = vec![];
        let candidate = vec![instance("r1", 65000)];
        let sections = diff_bgp_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "bgp instance r1");
        assert_eq!(sections[0].status, DiffStatus::Added);
        assert_eq!(sections[0].fields.len(), 2);
        assert!(sections[0].fields.iter().all(|f| f.old.is_none()));
    }

    #[test]
    fn removed_instance() {
        let base = vec![instance("r1", 65000)];
        let candidate = vec![];
        let sections = diff_bgp_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
        assert!(sections[0].fields.iter().all(|f| f.new.is_none()));
    }

    #[test]
    fn modified_instance_only_lists_changed_fields() {
        let base = vec![instance("r1", 65000)];
        let candidate = vec![instance("r1", 65001)];
        let sections = diff_bgp_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "asn");
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("65000"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("65001"));
    }

    #[test]
    fn unrelated_unchanged_instance_is_omitted() {
        let base = vec![instance("r1", 65000), instance("r2", 65002)];
        let candidate = vec![instance("r1", 65001), instance("r2", 65002)];
        let sections = diff_bgp_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "bgp instance r1");
    }
}
