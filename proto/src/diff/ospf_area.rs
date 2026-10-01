use std::net::Ipv4Addr;

use crate::schema::OspfArea;

use super::{ospf_profile, DiffStatus, SectionDiff};

/// Diffs two lists of `OspfArea`s, matched by `area_id` (unique within the
/// owning instance — see `schema::ospf_instance::unique_area_ids`). No own
/// scalar fields to compare — an `OspfArea` has only `area_id`/`profiles` —
/// so `fields` is always empty and an area is only ever reported when its
/// profiles changed, nested in `subsections` — mirrors
/// `diff_static_routing_instances`.
pub fn diff_ospf_areas(base: &[OspfArea], candidate: &[OspfArea]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.area_id == b.area_id) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let subsections = ospf_profile::diff_ospf_profiles(&b.profiles, &c.profiles);
                if !subsections.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(b.area_id),
                        name: b.area_id.to_string(),
                        status: DiffStatus::Modified,
                        fields: Vec::new(),
                        subsections,
                    });
                }
            }
        }
    }

    for c in candidate {
        if !base.iter().any(|b| b.area_id == c.area_id) {
            sections.push(added_section(c));
        }
    }

    sections
}

fn header_for(area_id: Ipv4Addr) -> String {
    format!("ospf area {area_id}")
}

fn removed_section(area: &OspfArea) -> SectionDiff {
    SectionDiff {
        header: header_for(area.area_id),
        name: area.area_id.to_string(),
        status: DiffStatus::Removed,
        fields: Vec::new(),
        subsections: ospf_profile::diff_ospf_profiles(&area.profiles, &[]),
    }
}

fn added_section(area: &OspfArea) -> SectionDiff {
    SectionDiff {
        header: header_for(area.area_id),
        name: area.area_id.to_string(),
        status: DiffStatus::Added,
        fields: Vec::new(),
        subsections: ospf_profile::diff_ospf_profiles(&[], &area.profiles),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::OspfProfile;

    fn area_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn area(id: &str, profiles: Vec<OspfProfile>) -> OspfArea {
        OspfArea {
            area_id: area_id(id),
            profiles,
        }
    }

    fn profile(name: &str) -> OspfProfile {
        OspfProfile {
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            mtu: None,
            network_type: None,
            auth: None,
            extended_sequence_numbers: false,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![area("0.0.0.0", vec![profile("p1")])];
        let candidate = base.clone();
        assert_eq!(diff_ospf_areas(&base, &candidate), []);
    }

    #[test]
    fn added_area() {
        let sections = diff_ospf_areas(&[], &[area("0.0.0.0", vec![])]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospf area 0.0.0.0");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_area() {
        let sections = diff_ospf_areas(&[area("0.0.0.0", vec![])], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    /// An area with no scalar fields of its own must still surface as
    /// `Modified`, with empty `fields` and the change nested in
    /// `subsections`, when only its profiles changed.
    #[test]
    fn changed_profiles_is_modified_with_empty_fields() {
        let base = vec![area("0.0.0.0", vec![])];
        let candidate = vec![area("0.0.0.0", vec![profile("p1")])];
        let sections = diff_ospf_areas(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields, []);
        assert_eq!(sections[0].subsections.len(), 1);
    }

    #[test]
    fn unrelated_unchanged_area_is_omitted() {
        let base = vec![area("0.0.0.0", vec![]), area("0.0.0.1", vec![])];
        let mut candidate = base.clone();
        candidate[0].profiles.push(profile("p1"));
        let sections = diff_ospf_areas(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospf area 0.0.0.0");
    }
}
