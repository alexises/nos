use crate::schema::CommunityAlias;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `CommunityAlias`es, matched by `name` (unique across
/// the whole config).
pub fn diff_community_aliases(
    base: &[CommunityAlias],
    candidate: &[CommunityAlias],
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
    format!("community-alias {name}")
}

fn changed_fields(base: &CommunityAlias, candidate: &CommunityAlias) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.value != candidate.value {
        fields.push(FieldDiff {
            label: "value".to_string(),
            old: Some(base.value.clone()),
            new: Some(candidate.value.clone()),
        });
    }
    fields
}

fn removed_section(alias: &CommunityAlias) -> SectionDiff {
    SectionDiff {
        header: header_for(&alias.name),
        name: alias.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "value".to_string(),
            old: Some(alias.value.clone()),
            new: None,
        }],
        subsections: Vec::new(),
    }
}

fn added_section(alias: &CommunityAlias) -> SectionDiff {
    SectionDiff {
        header: header_for(&alias.name),
        name: alias.name.clone(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "value".to_string(),
            old: None,
            new: Some(alias.value.clone()),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(name: &str, value: &str) -> CommunityAlias {
        CommunityAlias {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![alias("a1", "65000:100")];
        let candidate = base.clone();
        assert!(diff_community_aliases(&base, &candidate).is_empty());
    }

    #[test]
    fn added_alias() {
        let sections = diff_community_aliases(&[], &[alias("a1", "65000:100")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_alias() {
        let sections = diff_community_aliases(&[alias("a1", "65000:100")], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_value_only_lists_that_field() {
        let base = vec![alias("a1", "65000:100")];
        let candidate = vec![alias("a1", "65000:200")];
        let sections = diff_community_aliases(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "value");
    }
}
