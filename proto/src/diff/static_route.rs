use crate::schema::StaticRoute;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `StaticRoute`s, matched by `subnet` (unique within the
/// owning instance — see `schema::static_routing_instance::unique_subnets`).
pub fn diff_static_routes(base: &[StaticRoute], candidate: &[StaticRoute]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.subnet == b.subnet) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                if b.gateway != c.gateway {
                    sections.push(SectionDiff {
                        header: header_for(&b.subnet),
                        name: b.subnet.to_string(),
                        status: DiffStatus::Modified,
                        fields: vec![FieldDiff {
                            label: "gateway".to_string(),
                            old: Some(b.gateway.to_string()),
                            new: Some(c.gateway.to_string()),
                        }],
                        subsections: Vec::new(),
                    });
                }
            }
        }
    }

    for c in candidate {
        if !base.iter().any(|b| b.subnet == c.subnet) {
            sections.push(added_section(c));
        }
    }

    sections
}

fn header_for(subnet: &ipnet::IpNet) -> String {
    format!("route {subnet}")
}

fn removed_section(route: &StaticRoute) -> SectionDiff {
    SectionDiff {
        header: header_for(&route.subnet),
        name: route.subnet.to_string(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "gateway".to_string(),
            old: Some(route.gateway.to_string()),
            new: None,
        }],
        subsections: Vec::new(),
    }
}

fn added_section(route: &StaticRoute) -> SectionDiff {
    SectionDiff {
        header: header_for(&route.subnet),
        name: route.subnet.to_string(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "gateway".to_string(),
            old: None,
            new: Some(route.gateway.to_string()),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(subnet: &str, gateway: &str) -> StaticRoute {
        StaticRoute {
            subnet: subnet.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![route("10.0.0.0/24", "10.0.0.1")];
        let candidate = base.clone();
        assert_eq!(diff_static_routes(&base, &candidate), []);
    }

    #[test]
    fn added_route() {
        let sections = diff_static_routes(&[], &[route("10.0.0.0/24", "10.0.0.1")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "route 10.0.0.0/24");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_route() {
        let sections = diff_static_routes(&[route("10.0.0.0/24", "10.0.0.1")], &[]);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn repointed_gateway_is_modified() {
        let base = vec![route("10.0.0.0/24", "10.0.0.1")];
        let candidate = vec![route("10.0.0.0/24", "10.0.0.2")];
        let sections = diff_static_routes(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("10.0.0.1"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("10.0.0.2"));
    }
}
