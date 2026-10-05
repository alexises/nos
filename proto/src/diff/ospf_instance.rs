use crate::schema::OspfInstance;

use super::{ospf_area, DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `OspfInstance`s, matched by `name` (the field
/// `garde`'s `unique_in` validator already treats as each instance's key).
/// `routing_table` is deliberately not compared — it's a derived echo of
/// the owning `RoutingTable.ospf_instance`, already surfaced by
/// `diff_routing_tables`. Reports a change when either its own scalar
/// fields (`router_id`) or its `areas` changed — mirrors `diff_bgp_instances`'
/// combined fields+subsections shape.
pub fn diff_ospf_instances(base: &[OspfInstance], candidate: &[OspfInstance]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let fields = changed_fields(b, c);
                let subsections = ospf_area::diff_ospf_areas(&b.areas, &c.areas);
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
    format!("ospf instance {name}")
}

fn changed_fields(base: &OspfInstance, candidate: &OspfInstance) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.router_id != candidate.router_id {
        fields.push(FieldDiff {
            label: "router-id".to_string(),
            old: Some(base.router_id.to_string()),
            new: Some(candidate.router_id.to_string()),
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
    if base.prefix_suppression != candidate.prefix_suppression {
        fields.push(FieldDiff {
            label: "prefix-suppression".to_string(),
            old: Some(base.prefix_suppression.to_string()),
            new: Some(candidate.prefix_suppression.to_string()),
        });
    }
    let render = |p: Option<u32>| p.map_or("unset".to_string(), |p| p.to_string());
    for (label, old, new) in [
        (
            "max-metric router-lsa on-startup",
            base.max_metric_on_startup,
            candidate.max_metric_on_startup,
        ),
        (
            "max-metric router-lsa on-shutdown",
            base.max_metric_on_shutdown.map(u32::from),
            candidate.max_metric_on_shutdown.map(u32::from),
        ),
    ] {
        if old != new {
            fields.push(FieldDiff {
                label: label.to_string(),
                old: Some(render(old)),
                new: Some(render(new)),
            });
        }
    }
    if base.max_metric_administrative != candidate.max_metric_administrative {
        fields.push(FieldDiff {
            label: "max-metric router-lsa administrative".to_string(),
            old: Some(base.max_metric_administrative.to_string()),
            new: Some(candidate.max_metric_administrative.to_string()),
        });
    }
    fields
}

fn removed_section(instance: &OspfInstance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        name: instance.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "router-id".to_string(),
            old: Some(instance.router_id.to_string()),
            new: None,
        }],
        subsections: ospf_area::diff_ospf_areas(&instance.areas, &[]),
    }
}

fn added_section(instance: &OspfInstance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        name: instance.name.clone(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "router-id".to_string(),
            old: None,
            new: Some(instance.router_id.to_string()),
        }],
        subsections: ospf_area::diff_ospf_areas(&[], &instance.areas),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn instance(name: &str, router_id: Ipv4Addr) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id,
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            prefix_suppression: false,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
        }
    }

    #[test]
    fn max_metric_changes_are_reported() {
        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let mut candidate = base.clone();
        candidate[0].max_metric_on_startup = Some(30);
        candidate[0].max_metric_on_shutdown = Some(2);
        candidate[0].max_metric_administrative = true;
        let diff = diff_ospf_instances(&base, &candidate);
        let field = |label: &str, old: &str, new: &str| FieldDiff {
            label: label.to_string(),
            old: Some(old.to_string()),
            new: Some(new.to_string()),
        };
        assert_eq!(
            diff[0].fields,
            vec![
                field("max-metric router-lsa on-startup", "unset", "30"),
                field("max-metric router-lsa on-shutdown", "unset", "2"),
                field("max-metric router-lsa administrative", "false", "true"),
            ]
        );
    }

    #[test]
    fn prefix_suppression_change_is_reported() {
        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let mut candidate = base.clone();
        candidate[0].prefix_suppression = true;
        let diff = diff_ospf_instances(&base, &candidate);
        assert_eq!(diff.len(), 1);
        assert_eq!(
            diff[0].fields,
            vec![FieldDiff {
                label: "prefix-suppression".to_string(),
                old: Some("false".to_string()),
                new: Some("true".to_string()),
            }]
        );
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let candidate = base.clone();
        assert_eq!(diff_ospf_instances(&base, &candidate), []);
    }

    #[test]
    fn added_instance() {
        let base = vec![];
        let candidate = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let sections = diff_ospf_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospf instance o1");
        assert_eq!(sections[0].status, DiffStatus::Added);
        assert!(sections[0].fields.iter().all(|f| f.old.is_none()));
    }

    #[test]
    fn removed_instance() {
        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let candidate = vec![];
        let sections = diff_ospf_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
        assert!(sections[0].fields.iter().all(|f| f.new.is_none()));
    }

    #[test]
    fn modified_instance_only_lists_changed_fields() {
        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let candidate = vec![instance("o1", Ipv4Addr::new(2, 2, 2, 2))];
        let sections = diff_ospf_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "router-id");
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("1.1.1.1"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("2.2.2.2"));
    }

    #[test]
    fn unrelated_unchanged_instance_is_omitted() {
        let base = vec![
            instance("o1", Ipv4Addr::new(1, 1, 1, 1)),
            instance("o2", Ipv4Addr::new(2, 2, 2, 2)),
        ];
        let candidate = vec![
            instance("o1", Ipv4Addr::new(9, 9, 9, 9)),
            instance("o2", Ipv4Addr::new(2, 2, 2, 2)),
        ];
        let sections = diff_ospf_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospf instance o1");
    }

    /// An instance with no changed scalar fields must still surface as
    /// `Modified`, with empty `fields` and the change nested in
    /// `subsections`, when only its areas changed.
    #[test]
    fn changed_area_is_modified_with_empty_fields() {
        use crate::schema::OspfArea;

        let base = vec![instance("o1", Ipv4Addr::new(1, 1, 1, 1))];
        let mut candidate = base.clone();
        candidate[0].areas.push(OspfArea {
            area_id: "0.0.0.0".parse().unwrap(),
            area_type: crate::schema::OspfAreaType::Normal,
            stub_default_cost: None,
            ranges: Vec::new(),
            nssa_translate_always: false,
            nssa_default_originate: false,
            profiles: Vec::new(),
        });

        let sections = diff_ospf_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields, []);
        assert_eq!(sections[0].subsections.len(), 1);
        assert_eq!(sections[0].subsections[0].header, "ospf area 0.0.0.0");
    }
}
