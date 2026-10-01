use crate::schema::CommunityGroup;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `CommunityGroup`s, matched by `name` (unique across
/// the whole config). `members` is compared and rendered as a whole
/// (joined list), not per-member — mirroring `PolicyDefinition.source`
/// rather than `Interface.addresses`, since a group's membership is small
/// and usually changes alongside itself.
pub fn diff_community_groups(
    base: &[CommunityGroup],
    candidate: &[CommunityGroup],
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
    format!("community-group {name}")
}

fn render_members(members: &[String]) -> String {
    members.join(", ")
}

fn changed_fields(base: &CommunityGroup, candidate: &CommunityGroup) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.members != candidate.members {
        fields.push(FieldDiff {
            label: "members".to_string(),
            old: Some(render_members(&base.members)),
            new: Some(render_members(&candidate.members)),
        });
    }
    fields
}

fn removed_section(group: &CommunityGroup) -> SectionDiff {
    SectionDiff {
        header: header_for(&group.name),
        name: group.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "members".to_string(),
            old: Some(render_members(&group.members)),
            new: None,
        }],
        subsections: Vec::new(),
    }
}

fn added_section(group: &CommunityGroup) -> SectionDiff {
    SectionDiff {
        header: header_for(&group.name),
        name: group.name.clone(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "members".to_string(),
            old: None,
            new: Some(render_members(&group.members)),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(name: &str, members: &[&str]) -> CommunityGroup {
        CommunityGroup {
            name: name.to_string(),
            members: members.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![group("g1", &["65000:100"])];
        let candidate = base.clone();
        assert_eq!(diff_community_groups(&base, &candidate), []);
    }

    #[test]
    fn added_group() {
        let sections = diff_community_groups(&[], &[group("g1", &["65000:100"])]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_group() {
        let sections = diff_community_groups(&[group("g1", &["65000:100"])], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_members_only_lists_that_field() {
        let base = vec![group("g1", &["65000:100"])];
        let candidate = vec![group("g1", &["65000:100", "65000:200"])];
        let sections = diff_community_groups(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields[0].label, "members");
    }
}
