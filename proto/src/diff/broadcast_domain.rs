use crate::schema::{BroadcastDomain, InterfaceAddress};

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `BroadcastDomain`s, matched by `name` (the field
/// `garde`'s `unique_in` validator already treats as each domain's key).
pub fn diff_broadcast_domains(
    base: &[BroadcastDomain],
    candidate: &[BroadcastDomain],
) -> Vec<SectionDiff> {
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
    format!("broadcast-domain {name}")
}

fn format_address(addr: &InterfaceAddress) -> String {
    match &addr.label {
        Some(label) => format!("{} (label {label})", addr.address),
        None => addr.address.to_string(),
    }
}

fn addresses_str(domain: &BroadcastDomain) -> String {
    if domain.addresses.is_empty() {
        return "none".to_string();
    }
    let mut addrs: Vec<String> = domain.addresses.iter().map(format_address).collect();
    addrs.sort();
    addrs.join(", ")
}

fn routing_table_str(domain: &BroadcastDomain) -> String {
    domain
        .routing_table
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn changed_fields(base: &BroadcastDomain, candidate: &BroadcastDomain) -> Vec<FieldDiff> {
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

fn removed_section(domain: &BroadcastDomain) -> SectionDiff {
    SectionDiff {
        header: header_for(&domain.name),
        name: domain.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "addresses".to_string(),
                old: Some(addresses_str(domain)),
                new: None,
            },
            FieldDiff {
                label: "routing-table".to_string(),
                old: Some(routing_table_str(domain)),
                new: None,
            },
        ],
        subsections: Vec::new(),
    }
}

fn added_section(domain: &BroadcastDomain) -> SectionDiff {
    SectionDiff {
        header: header_for(&domain.name),
        name: domain.name.clone(),
        status: DiffStatus::Added,
        fields: vec![
            FieldDiff {
                label: "addresses".to_string(),
                old: None,
                new: Some(addresses_str(domain)),
            },
            FieldDiff {
                label: "routing-table".to_string(),
                old: None,
                new: Some(routing_table_str(domain)),
            },
        ],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> BroadcastDomain {
        BroadcastDomain {
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![domain("bd1")];
        let candidate = base.clone();
        assert!(diff_broadcast_domains(&base, &candidate).is_empty());
    }

    #[test]
    fn added_domain() {
        let sections = diff_broadcast_domains(&[], &[domain("bd1")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "broadcast-domain bd1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_domain() {
        let sections = diff_broadcast_domains(&[domain("bd1")], &[]);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_routing_table_only_lists_that_field() {
        let base = vec![domain("bd1")];
        let mut candidate_domain = domain("bd1");
        candidate_domain.routing_table = Some("rt1".to_string());
        let sections = diff_broadcast_domains(&base, &[candidate_domain]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "routing-table");
    }

    #[test]
    fn modified_addresses_only_lists_that_field() {
        let base = vec![domain("bd1")];
        let mut candidate_domain = domain("bd1");
        candidate_domain.addresses = vec![InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        }];
        let sections = diff_broadcast_domains(&base, &[candidate_domain]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "addresses");
    }

    #[test]
    fn reordered_addresses_are_not_a_change() {
        let mut base_domain = domain("bd1");
        base_domain.addresses = vec![
            InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            },
            InterfaceAddress {
                address: "10.0.0.2/24".parse().unwrap(),
                label: None,
            },
        ];
        let mut candidate_domain = base_domain.clone();
        candidate_domain.addresses.reverse();
        assert!(diff_broadcast_domains(&[base_domain], &[candidate_domain]).is_empty());
    }
}
