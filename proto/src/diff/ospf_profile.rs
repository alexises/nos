use crate::schema::OspfProfile;

use super::{DiffStatus, SectionDiff};

/// Diffs two lists of `OspfProfile`s, matched by `name` (globally unique —
/// see `schema::ospf_profile::unique_name`). No own fields beyond `name`
/// today, so only `Added`/`Removed` are ever produced — mirrors
/// `diff_static_routes` before `StaticRoute` grew a second field.
pub fn diff_ospf_profiles(base: &[OspfProfile], candidate: &[OspfProfile]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        if !candidate.iter().any(|c| c.name == b.name) {
            sections.push(SectionDiff {
                header: header_for(&b.name),
                name: b.name.clone(),
                status: DiffStatus::Removed,
                fields: Vec::new(),
                subsections: Vec::new(),
            });
        }
    }

    for c in candidate {
        if !base.iter().any(|b| b.name == c.name) {
            sections.push(SectionDiff {
                header: header_for(&c.name),
                name: c.name.clone(),
                status: DiffStatus::Added,
                fields: Vec::new(),
                subsections: Vec::new(),
            });
        }
    }

    sections
}

fn header_for(name: &str) -> String {
    format!("ospf profile {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> OspfProfile {
        OspfProfile {
            name: name.to_string(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![profile("p1")];
        let candidate = base.clone();
        assert!(diff_ospf_profiles(&base, &candidate).is_empty());
    }

    #[test]
    fn added_profile() {
        let sections = diff_ospf_profiles(&[], &[profile("p1")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospf profile p1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_profile() {
        let sections = diff_ospf_profiles(&[profile("p1")], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn unrelated_unchanged_profile_is_omitted() {
        let base = vec![profile("p1"), profile("p2")];
        let candidate = vec![profile("p1")];
        let sections = diff_ospf_profiles(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospf profile p2");
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }
}
