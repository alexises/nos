use crate::schema::Interface;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `Interface`s, matched by `name` (the field `garde`'s
/// `unique_in` validator already treats as each interface's key).
pub fn diff_interfaces(base: &[Interface], candidate: &[Interface]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let fields = changed_fields(b, c);
                if !fields.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(&b.name),
                        name: b.name.clone(),
                        status: DiffStatus::Modified,
                        fields,
                        subsections: Vec::new(),
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
    format!("interface {name}")
}

fn addresses_str(iface: &Interface) -> String {
    if iface.addresses.is_empty() {
        return "none".to_string();
    }
    let mut addrs: Vec<String> = iface.addresses.iter().map(ToString::to_string).collect();
    addrs.sort();
    addrs.join(", ")
}

fn routing_table_str(iface: &Interface) -> String {
    iface
        .routing_table
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn changed_fields(base: &Interface, candidate: &Interface) -> Vec<FieldDiff> {
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
    fields
}

fn removed_section(iface: &Interface) -> SectionDiff {
    SectionDiff {
        header: header_for(&iface.name),
        name: iface.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "addresses".to_string(),
                old: Some(addresses_str(iface)),
                new: None,
            },
            FieldDiff {
                label: "routing-table".to_string(),
                old: Some(routing_table_str(iface)),
                new: None,
            },
        ],
        subsections: Vec::new(),
    }
}

fn added_section(iface: &Interface) -> SectionDiff {
    SectionDiff {
        header: header_for(&iface.name),
        name: iface.name.clone(),
        status: DiffStatus::Added,
        fields: vec![
            FieldDiff {
                label: "addresses".to_string(),
                old: None,
                new: Some(addresses_str(iface)),
            },
            FieldDiff {
                label: "routing-table".to_string(),
                old: None,
                new: Some(routing_table_str(iface)),
            },
        ],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, addresses: &[&str], routing_table: Option<&str>) -> Interface {
        Interface {
            name: name.to_string(),
            addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
            routing_table: routing_table.map(str::to_string),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![interface("eth0", &["10.0.0.1/24"], Some("rt1"))];
        let candidate = base.clone();
        assert!(diff_interfaces(&base, &candidate).is_empty());
    }

    #[test]
    fn added_interface() {
        let sections = diff_interfaces(&[], &[interface("eth0", &[], None)]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "interface eth0");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_interface() {
        let sections = diff_interfaces(&[interface("eth0", &[], None)], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_routing_table_only_lists_that_field() {
        let base = vec![interface("eth0", &[], None)];
        let candidate = vec![interface("eth0", &[], Some("rt1"))];
        let sections = diff_interfaces(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "routing-table");
    }

    #[test]
    fn modified_addresses_only_lists_that_field() {
        let base = vec![interface("eth0", &["10.0.0.1/24"], None)];
        let candidate = vec![interface("eth0", &["10.0.0.2/24"], None)];
        let sections = diff_interfaces(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "addresses");
    }

    #[test]
    fn reordered_addresses_are_not_a_change() {
        let base = vec![interface("eth0", &["10.0.0.1/24", "10.0.0.2/24"], None)];
        let candidate = vec![interface("eth0", &["10.0.0.2/24", "10.0.0.1/24"], None)];
        assert!(diff_interfaces(&base, &candidate).is_empty());
    }
}
