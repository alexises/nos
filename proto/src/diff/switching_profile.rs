use crate::schema::{SwitchingProfile, SwitchingProfileMember, VlanTag};

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `SwitchingProfile`s, matched by `name`. Like
/// `diff_static_routing_instances`, there are no own scalar fields to
/// compare — a `SwitchingProfile` has only `name`/`members` — so `fields` is
/// always empty and a profile is only ever reported when its members
/// changed, nested in `subsections`.
pub fn diff_switching_profiles(
    base: &[SwitchingProfile],
    candidate: &[SwitchingProfile],
) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let subsections = diff_members(&b.members, &c.members);
                if !subsections.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(&b.name),
                        name: b.name.clone(),
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
    format!("switching-profile {name}")
}

fn removed_section(profile: &SwitchingProfile) -> SectionDiff {
    SectionDiff {
        header: header_for(&profile.name),
        name: profile.name.clone(),
        status: DiffStatus::Removed,
        fields: Vec::new(),
        subsections: diff_members(&profile.members, &[]),
    }
}

fn added_section(profile: &SwitchingProfile) -> SectionDiff {
    SectionDiff {
        header: header_for(&profile.name),
        name: profile.name.clone(),
        status: DiffStatus::Added,
        fields: Vec::new(),
        subsections: diff_members(&[], &profile.members),
    }
}

fn tag_str(tag: VlanTag) -> String {
    match tag {
        VlanTag::Untagged => "untagged".to_string(),
        VlanTag::Dot1q(id) => format!("dot1q {id}"),
    }
}

/// Diffs two lists of `SwitchingProfileMember`s, matched by
/// `broadcast_domain` (unique within the owning profile — see
/// `schema::switching_profile::unique_broadcast_domains`).
fn diff_members(
    base: &[SwitchingProfileMember],
    candidate: &[SwitchingProfileMember],
) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate
            .iter()
            .find(|c| c.broadcast_domain == b.broadcast_domain)
        {
            None => sections.push(member_section(b, DiffStatus::Removed, Some(b.tag), None)),
            Some(c) if b.tag != c.tag => sections.push(member_section(
                b,
                DiffStatus::Modified,
                Some(b.tag),
                Some(c.tag),
            )),
            Some(_) => {}
        }
    }

    for c in candidate {
        if !base
            .iter()
            .any(|b| b.broadcast_domain == c.broadcast_domain)
        {
            sections.push(member_section(c, DiffStatus::Added, None, Some(c.tag)));
        }
    }

    sections
}

fn member_section(
    member: &SwitchingProfileMember,
    status: DiffStatus,
    old: Option<VlanTag>,
    new: Option<VlanTag>,
) -> SectionDiff {
    SectionDiff {
        header: format!("broadcast-domain {}", member.broadcast_domain),
        name: member.broadcast_domain.clone(),
        status,
        fields: vec![FieldDiff {
            label: "tag".to_string(),
            old: old.map(tag_str),
            new: new.map(tag_str),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(broadcast_domain: &str, tag: VlanTag) -> SwitchingProfileMember {
        SwitchingProfileMember {
            broadcast_domain: broadcast_domain.to_string(),
            tag,
        }
    }

    fn profile(name: &str, members: Vec<SwitchingProfileMember>) -> SwitchingProfile {
        SwitchingProfile {
            name: name.to_string(),
            members,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![profile("sp1", vec![member("bd1", VlanTag::Dot1q(100))])];
        let candidate = base.clone();
        assert_eq!(diff_switching_profiles(&base, &candidate), []);
    }

    #[test]
    fn added_profile() {
        let sections = diff_switching_profiles(
            &[],
            &[profile("sp1", vec![member("bd1", VlanTag::Dot1q(100))])],
        );
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "switching-profile sp1");
        assert_eq!(sections[0].status, DiffStatus::Added);
        assert_eq!(sections[0].subsections.len(), 1);
    }

    #[test]
    fn removed_profile() {
        let sections = diff_switching_profiles(
            &[profile("sp1", vec![member("bd1", VlanTag::Dot1q(100))])],
            &[],
        );
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn changed_member_tag_is_modified_with_empty_fields() {
        let base = vec![profile("sp1", vec![member("bd1", VlanTag::Dot1q(100))])];
        let candidate = vec![profile("sp1", vec![member("bd1", VlanTag::Untagged)])];
        let sections = diff_switching_profiles(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields, []);
        assert_eq!(sections[0].subsections.len(), 1);
        assert_eq!(
            sections[0].subsections[0].fields[0].old.as_deref(),
            Some("dot1q 100")
        );
        assert_eq!(
            sections[0].subsections[0].fields[0].new.as_deref(),
            Some("untagged")
        );
    }

    #[test]
    fn added_member_within_existing_profile() {
        let base = vec![profile("sp1", vec![member("bd1", VlanTag::Dot1q(100))])];
        let candidate = vec![profile(
            "sp1",
            vec![
                member("bd1", VlanTag::Dot1q(100)),
                member("bd2", VlanTag::Untagged),
            ],
        )];
        let sections = diff_switching_profiles(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].subsections.len(), 1);
        assert_eq!(sections[0].subsections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_member_within_existing_profile() {
        let base = vec![profile(
            "sp1",
            vec![
                member("bd1", VlanTag::Dot1q(100)),
                member("bd2", VlanTag::Untagged),
            ],
        )];
        let candidate = vec![profile("sp1", vec![member("bd1", VlanTag::Dot1q(100))])];
        let sections = diff_switching_profiles(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].subsections.len(), 1);
        assert_eq!(sections[0].subsections[0].status, DiffStatus::Removed);
    }
}
