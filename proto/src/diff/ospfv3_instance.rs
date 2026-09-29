use crate::schema::Ospfv3Instance;

use super::{ospfv3_area, DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `Ospfv3Instance`s, matched by `name` — mirrors
/// `diff_ospf_instances` exactly. `routing_table` is deliberately not
/// compared, same reasoning as `OspfInstance`'s own diff.
pub fn diff_ospfv3_instances(
    base: &[Ospfv3Instance],
    candidate: &[Ospfv3Instance],
) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let fields = changed_fields(b, c);
                let subsections = ospfv3_area::diff_ospfv3_areas(&b.areas, &c.areas);
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
    format!("ospfv3 instance {name}")
}

fn changed_fields(base: &Ospfv3Instance, candidate: &Ospfv3Instance) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.router_id != candidate.router_id {
        fields.push(FieldDiff {
            label: "router-id".to_string(),
            old: Some(base.router_id.to_string()),
            new: Some(candidate.router_id.to_string()),
        });
    }
    if base.extended_lsa != candidate.extended_lsa {
        fields.push(FieldDiff {
            label: "extended-lsa".to_string(),
            old: Some(base.extended_lsa.to_string()),
            new: Some(candidate.extended_lsa.to_string()),
        });
    }
    if base.graceful_restart_grace_period != candidate.graceful_restart_grace_period {
        let render = |p: Option<u16>| p.map_or("unset".to_string(), |p| p.to_string());
        fields.push(FieldDiff {
            label: "graceful-restart grace-period".to_string(),
            old: Some(render(base.graceful_restart_grace_period)),
            new: Some(render(candidate.graceful_restart_grace_period)),
        });
    }
    fields
}

fn removed_section(instance: &Ospfv3Instance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        name: instance.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "router-id".to_string(),
            old: Some(instance.router_id.to_string()),
            new: None,
        }],
        subsections: ospfv3_area::diff_ospfv3_areas(&instance.areas, &[]),
    }
}

fn added_section(instance: &Ospfv3Instance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        name: instance.name.clone(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "router-id".to_string(),
            old: None,
            new: Some(instance.router_id.to_string()),
        }],
        subsections: ospfv3_area::diff_ospfv3_areas(&[], &instance.areas),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn instance(name: &str, router_id: Ipv4Addr) -> Ospfv3Instance {
        Ospfv3Instance {
            name: name.to_string(),
            router_id,
            areas: Vec::new(),
            routing_table: None,
            extended_lsa: false,
            graceful_restart_grace_period: None,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let candidate = base.clone();
        assert!(diff_ospfv3_instances(&base, &candidate).is_empty());
    }

    #[test]
    fn added_instance() {
        let base = vec![];
        let candidate = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let sections = diff_ospfv3_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospfv3 instance o1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_instance() {
        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let candidate = vec![];
        let sections = diff_ospfv3_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_instance_only_lists_changed_fields() {
        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let candidate = vec![instance("o1", Ipv4Addr::new(2, 2, 2, 2))];
        let sections = diff_ospfv3_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "router-id");
    }
}
