use crate::schema::RoutingTable;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `RoutingTable`s, matched by `name` (the field
/// `garde`'s `unique_in` validator already treats as each table's key).
pub fn diff_routing_tables(base: &[RoutingTable], candidate: &[RoutingTable]) -> Vec<SectionDiff> {
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
    format!("routing-table {name}")
}

fn bgp_instance_str(t: &RoutingTable) -> String {
    t.bgp_instance
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn static_routing_instance_str(t: &RoutingTable) -> String {
    t.static_routing_instance
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn changed_fields(base: &RoutingTable, candidate: &RoutingTable) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.bgp_instance != candidate.bgp_instance {
        fields.push(FieldDiff {
            label: "bgp-instance".to_string(),
            old: Some(bgp_instance_str(base)),
            new: Some(bgp_instance_str(candidate)),
        });
    }
    if base.static_routing_instance != candidate.static_routing_instance {
        fields.push(FieldDiff {
            label: "static-routing-instance".to_string(),
            old: Some(static_routing_instance_str(base)),
            new: Some(static_routing_instance_str(candidate)),
        });
    }
    fields
}

fn removed_section(table: &RoutingTable) -> SectionDiff {
    SectionDiff {
        header: header_for(&table.name),
        name: table.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "bgp-instance".to_string(),
                old: Some(bgp_instance_str(table)),
                new: None,
            },
            FieldDiff {
                label: "static-routing-instance".to_string(),
                old: Some(static_routing_instance_str(table)),
                new: None,
            },
        ],
        subsections: Vec::new(),
    }
}

fn added_section(table: &RoutingTable) -> SectionDiff {
    SectionDiff {
        header: header_for(&table.name),
        name: table.name.clone(),
        status: DiffStatus::Added,
        fields: vec![
            FieldDiff {
                label: "bgp-instance".to_string(),
                old: None,
                new: Some(bgp_instance_str(table)),
            },
            FieldDiff {
                label: "static-routing-instance".to_string(),
                old: None,
                new: Some(static_routing_instance_str(table)),
            },
        ],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(name: &str, bgp_instance: Option<&str>, sri: Option<&str>) -> RoutingTable {
        RoutingTable {
            name: name.to_string(),
            bgp_instance: bgp_instance.map(str::to_string),
            static_routing_instance: sri.map(str::to_string),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![table("rt1", Some("r1"), None)];
        let candidate = base.clone();
        assert!(diff_routing_tables(&base, &candidate).is_empty());
    }

    #[test]
    fn added_table() {
        let sections = diff_routing_tables(&[], &[table("rt1", None, None)]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "routing-table rt1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_table() {
        let sections = diff_routing_tables(&[table("rt1", None, None)], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_bgp_instance_only_lists_that_field() {
        let base = vec![table("rt1", None, None)];
        let candidate = vec![table("rt1", Some("r1"), None)];
        let sections = diff_routing_tables(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "bgp-instance");
    }
}
