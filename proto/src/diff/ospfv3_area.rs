use std::net::Ipv4Addr;

use crate::schema::Ospfv3Area;

use super::{ospfv3_profile, DiffStatus, SectionDiff};

/// Diffs two lists of `Ospfv3Area`s, matched by `area_id` — mirrors
/// `diff_ospf_areas` exactly.
pub fn diff_ospfv3_areas(base: &[Ospfv3Area], candidate: &[Ospfv3Area]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.area_id == b.area_id) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let subsections = ospfv3_profile::diff_ospfv3_profiles(&b.profiles, &c.profiles);
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
    format!("ospfv3 area {area_id}")
}

fn removed_section(area: &Ospfv3Area) -> SectionDiff {
    SectionDiff {
        header: header_for(area.area_id),
        name: area.area_id.to_string(),
        status: DiffStatus::Removed,
        fields: Vec::new(),
        subsections: ospfv3_profile::diff_ospfv3_profiles(&area.profiles, &[]),
    }
}

fn added_section(area: &Ospfv3Area) -> SectionDiff {
    SectionDiff {
        header: header_for(area.area_id),
        name: area.area_id.to_string(),
        status: DiffStatus::Added,
        fields: Vec::new(),
        subsections: ospfv3_profile::diff_ospfv3_profiles(&[], &area.profiles),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn area(id: &str) -> Ospfv3Area {
        Ospfv3Area {
            area_id: area_id(id),
            profiles: Vec::new(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![area("0.0.0.0")];
        let candidate = base.clone();
        assert_eq!(diff_ospfv3_areas(&base, &candidate), []);
    }

    #[test]
    fn added_area() {
        let sections = diff_ospfv3_areas(&[], &[area("0.0.0.0")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospfv3 area 0.0.0.0");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_area() {
        let sections = diff_ospfv3_areas(&[area("0.0.0.0")], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }
}
