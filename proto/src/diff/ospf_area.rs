use std::net::Ipv4Addr;

use crate::schema::{OspfArea, OspfAreaType};

use super::{ospf_profile, DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `OspfArea`s, matched by `area_id` (unique within the
/// owning instance — see `schema::ospf_instance::unique_area_ids`). The
/// area's own `area_type`/`stub_default_cost`/`nssa_*`/`ranges` go in
/// `fields`, its
/// profiles' changes nested in `subsections`.
pub fn diff_ospf_areas(base: &[OspfArea], candidate: &[OspfArea]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.area_id == b.area_id) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let subsections = ospf_profile::diff_ospf_profiles(&b.profiles, &c.profiles);
                let fields = changed_fields(b, c);
                if !subsections.is_empty() || !fields.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(b.area_id),
                        name: b.area_id.to_string(),
                        status: DiffStatus::Modified,
                        fields,
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

fn area_type_str(t: OspfAreaType) -> &'static str {
    match t {
        OspfAreaType::Normal => "normal",
        OspfAreaType::Stub => "stub",
        OspfAreaType::TotallyStubby => "totally-stubby",
        OspfAreaType::Nssa => "nssa",
        OspfAreaType::NssaNoSummary => "nssa-no-summary",
    }
}

fn ranges_str(a: &OspfArea) -> String {
    let rendered: Vec<String> = a
        .ranges
        .iter()
        .map(|r| {
            if r.not_advertise {
                format!("{} not-advertise", r.cidr)
            } else {
                r.cidr.to_string()
            }
        })
        .collect();
    format!("[{}]", rendered.join(", "))
}

fn changed_fields(base: &OspfArea, candidate: &OspfArea) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.area_type != candidate.area_type {
        fields.push(FieldDiff {
            label: "area-type".to_string(),
            old: Some(area_type_str(base.area_type).to_string()),
            new: Some(area_type_str(candidate.area_type).to_string()),
        });
    }
    if base.stub_default_cost != candidate.stub_default_cost {
        let cost = |a: &OspfArea| {
            a.stub_default_cost
                .map_or_else(|| "default (1)".to_string(), |c| c.to_string())
        };
        fields.push(FieldDiff {
            label: "stub-default-cost".to_string(),
            old: Some(cost(base)),
            new: Some(cost(candidate)),
        });
    }
    for (label, old, new) in [
        (
            "nssa-translate-always",
            base.nssa_translate_always,
            candidate.nssa_translate_always,
        ),
        (
            "nssa-default-originate",
            base.nssa_default_originate,
            candidate.nssa_default_originate,
        ),
    ] {
        if old != new {
            fields.push(FieldDiff {
                label: label.to_string(),
                old: Some(old.to_string()),
                new: Some(new.to_string()),
            });
        }
    }
    if base.ranges != candidate.ranges {
        fields.push(FieldDiff {
            label: "ranges".to_string(),
            old: Some(ranges_str(base)),
            new: Some(ranges_str(candidate)),
        });
    }
    fields
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
            ..Default::default()
        }
    }

    #[test]
    fn stub_settings_and_ranges_are_fields() {
        let base = vec![area("0.0.0.1", vec![])];
        let mut candidate = base.clone();
        candidate[0].area_type = OspfAreaType::Stub;
        candidate[0].stub_default_cost = Some(5);
        candidate[0].ranges.push(crate::schema::OspfAreaRange {
            cidr: "10.0.0.0/16".parse().unwrap(),
            not_advertise: true,
        });
        let sections = diff_ospf_areas(&base, &candidate);
        assert_eq!(sections.len(), 1);
        let labels: Vec<_> = sections[0]
            .fields
            .iter()
            .map(|f| f.label.as_str())
            .collect();
        assert_eq!(labels, ["area-type", "stub-default-cost", "ranges"]);
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("stub"));
        assert_eq!(
            sections[0].fields[2].new.as_deref(),
            Some("[10.0.0.0/16 not-advertise]")
        );
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
