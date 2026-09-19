use crate::schema::{InterfaceAddress, Subinterface};

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `Subinterface`s, matched by `tag` (unique within the
/// owning interface — see `schema::interface::unique_subinterface_tags`).
pub fn diff_subinterfaces(base: &[Subinterface], candidate: &[Subinterface]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.tag == b.tag) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let fields = changed_fields(b, c);
                if !fields.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(b.tag),
                        name: b.tag.to_string(),
                        status: DiffStatus::Modified,
                        fields,
                        subsections: Vec::new(),
                    });
                }
            }
        }
    }

    for c in candidate {
        if !base.iter().any(|b| b.tag == c.tag) {
            sections.push(added_section(c));
        }
    }

    sections
}

fn header_for(tag: u16) -> String {
    format!("subinterface {tag}")
}

fn format_address(addr: &InterfaceAddress) -> String {
    match &addr.label {
        Some(label) => format!("{} (label {label})", addr.address),
        None => addr.address.to_string(),
    }
}

fn addresses_str(sub: &Subinterface) -> String {
    if sub.addresses.is_empty() {
        return "none".to_string();
    }
    let mut addrs: Vec<String> = sub.addresses.iter().map(format_address).collect();
    addrs.sort();
    addrs.join(", ")
}

fn routing_table_str(sub: &Subinterface) -> String {
    sub.routing_table
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn ospf_profile_str(sub: &Subinterface) -> String {
    sub.ospf_profile
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn changed_fields(base: &Subinterface, candidate: &Subinterface) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    let mut base_addrs = base.addresses.clone();
    let mut candidate_addrs = candidate.addresses.clone();
    base_addrs.sort();
    candidate_addrs.sort();
    if base_addrs != candidate_addrs {
        fields.push(FieldDiff {
            label: "addresses".to_string(),
            old: Some(addresses_str(base)),
            new: Some(addresses_str(candidate)),
        });
    }
    if base.routing_table != candidate.routing_table {
        fields.push(FieldDiff {
            label: "routing-table".to_string(),
            old: Some(routing_table_str(base)),
            new: Some(routing_table_str(candidate)),
        });
    }
    if base.ospf_profile != candidate.ospf_profile {
        fields.push(FieldDiff {
            label: "ospf-profile".to_string(),
            old: Some(ospf_profile_str(base)),
            new: Some(ospf_profile_str(candidate)),
        });
    }
    fields
}

fn removed_section(sub: &Subinterface) -> SectionDiff {
    SectionDiff {
        header: header_for(sub.tag),
        name: sub.tag.to_string(),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "addresses".to_string(),
                old: Some(addresses_str(sub)),
                new: None,
            },
            FieldDiff {
                label: "routing-table".to_string(),
                old: Some(routing_table_str(sub)),
                new: None,
            },
            FieldDiff {
                label: "ospf-profile".to_string(),
                old: Some(ospf_profile_str(sub)),
                new: None,
            },
        ],
        subsections: Vec::new(),
    }
}

fn added_section(sub: &Subinterface) -> SectionDiff {
    SectionDiff {
        header: header_for(sub.tag),
        name: sub.tag.to_string(),
        status: DiffStatus::Added,
        fields: vec![
            FieldDiff {
                label: "addresses".to_string(),
                old: None,
                new: Some(addresses_str(sub)),
            },
            FieldDiff {
                label: "routing-table".to_string(),
                old: None,
                new: Some(routing_table_str(sub)),
            },
            FieldDiff {
                label: "ospf-profile".to_string(),
                old: None,
                new: Some(ospf_profile_str(sub)),
            },
        ],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(tag: u16, addresses: &[&str], routing_table: Option<&str>) -> Subinterface {
        Subinterface {
            ospfv3_profile: None,
            tag,
            addresses: addresses
                .iter()
                .map(|a| InterfaceAddress {
                    address: a.parse().unwrap(),
                    label: None,
                })
                .collect(),
            routing_table: routing_table.map(str::to_string),
            ospf_profile: None,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![sub(0, &["10.0.0.1/24"], Some("rt1"))];
        let candidate = base.clone();
        assert!(diff_subinterfaces(&base, &candidate).is_empty());
    }

    #[test]
    fn added_subinterface() {
        let sections = diff_subinterfaces(&[], &[sub(100, &[], None)]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "subinterface 100");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_subinterface() {
        let sections = diff_subinterfaces(&[sub(100, &[], None)], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_routing_table_only_lists_that_field() {
        let base = vec![sub(0, &[], None)];
        let candidate = vec![sub(0, &[], Some("rt1"))];
        let sections = diff_subinterfaces(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "routing-table");
    }

    #[test]
    fn modified_ospf_profile_only_lists_that_field() {
        let mut base_sub = sub(0, &[], None);
        let mut candidate_sub = base_sub.clone();
        candidate_sub.ospf_profile = Some("p1".to_string());
        base_sub.ospf_profile = None;
        let sections = diff_subinterfaces(&[base_sub], &[candidate_sub]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "ospf-profile");
    }

    #[test]
    fn modified_addresses_only_lists_that_field() {
        let base = vec![sub(0, &["10.0.0.1/24"], None)];
        let candidate = vec![sub(0, &["10.0.0.2/24"], None)];
        let sections = diff_subinterfaces(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "addresses");
    }

    #[test]
    fn reordered_addresses_are_not_a_change() {
        let base = vec![sub(0, &["10.0.0.1/24", "10.0.0.2/24"], None)];
        let candidate = vec![sub(0, &["10.0.0.2/24", "10.0.0.1/24"], None)];
        assert!(diff_subinterfaces(&base, &candidate).is_empty());
    }

    #[test]
    fn unrelated_tag_is_omitted() {
        let base = vec![sub(0, &[], None), sub(100, &[], None)];
        let mut candidate = base.clone();
        candidate[0].routing_table = Some("rt1".to_string());
        let sections = diff_subinterfaces(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "subinterface 0");
    }
}
