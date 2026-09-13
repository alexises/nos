use crate::schema::StaticRoutingInstance;

use super::{static_route, DiffStatus, SectionDiff};

/// Diffs two lists of `StaticRoutingInstance`s, matched by `name`. Unlike
/// `diff_bgp_instances`, there are no own scalar fields to compare — a
/// `StaticRoutingInstance` has only `name`/`routes` — so `fields` is always
/// empty and an instance is only ever reported when its routes changed,
/// nested in `subsections`.
pub fn diff_static_routing_instances(
    base: &[StaticRoutingInstance],
    candidate: &[StaticRoutingInstance],
) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let subsections = static_route::diff_static_routes(&b.routes, &c.routes);
                if !subsections.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(&b.name),
                        status: DiffStatus::Modified,
                        fields: Vec::new(),
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
    format!("static-routing-instance {name}")
}

fn removed_section(instance: &StaticRoutingInstance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        status: DiffStatus::Removed,
        fields: Vec::new(),
        subsections: static_route::diff_static_routes(&instance.routes, &[]),
    }
}

fn added_section(instance: &StaticRoutingInstance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        status: DiffStatus::Added,
        fields: Vec::new(),
        subsections: static_route::diff_static_routes(&[], &instance.routes),
    }
}

#[cfg(test)]
mod tests {
    use crate::schema::StaticRoute;

    use super::*;

    fn route(subnet: &str, gateway: &str) -> StaticRoute {
        StaticRoute {
            subnet: subnet.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
        }
    }

    fn instance(name: &str, routes: Vec<StaticRoute>) -> StaticRoutingInstance {
        StaticRoutingInstance {
            name: name.to_string(),
            routes,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![instance("sri1", vec![route("10.0.0.0/24", "10.0.0.1")])];
        let candidate = base.clone();
        assert!(diff_static_routing_instances(&base, &candidate).is_empty());
    }

    #[test]
    fn added_instance() {
        let sections = diff_static_routing_instances(
            &[],
            &[instance("sri1", vec![route("10.0.0.0/24", "10.0.0.1")])],
        );
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "static-routing-instance sri1");
        assert_eq!(sections[0].status, DiffStatus::Added);
        assert_eq!(sections[0].subsections.len(), 1);
    }

    #[test]
    fn removed_instance() {
        let sections = diff_static_routing_instances(
            &[instance("sri1", vec![route("10.0.0.0/24", "10.0.0.1")])],
            &[],
        );
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    /// An instance with no scalar fields of its own must still surface as
    /// `Modified`, with empty `fields` and the change nested in
    /// `subsections`, when only its routes changed.
    #[test]
    fn changed_route_is_modified_with_empty_fields() {
        let base = vec![instance("sri1", vec![route("10.0.0.0/24", "10.0.0.1")])];
        let candidate = vec![instance("sri1", vec![route("10.0.0.0/24", "10.0.0.2")])];
        let sections = diff_static_routing_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert!(sections[0].fields.is_empty());
        assert_eq!(sections[0].subsections.len(), 1);
    }

    #[test]
    fn unrelated_unchanged_instance_is_omitted() {
        let base = vec![
            instance("sri1", vec![route("10.0.0.0/24", "10.0.0.1")]),
            instance("sri2", vec![route("10.0.1.0/24", "10.0.1.1")]),
        ];
        let mut candidate = base.clone();
        candidate[0].routes[0].gateway = "10.0.0.2".parse().unwrap();
        let sections = diff_static_routing_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "static-routing-instance sri1");
    }
}
