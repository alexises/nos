use crate::schema::PolicyDefinition;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `PolicyDefinition`s, matched by `name` (unique across
/// the whole config — see `schema::policy_definition::valid_name`).
pub fn diff_policy_definitions(
    base: &[PolicyDefinition],
    candidate: &[PolicyDefinition],
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
    format!("policy-definition {name}")
}

fn changed_fields(base: &PolicyDefinition, candidate: &PolicyDefinition) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.source != candidate.source {
        fields.push(FieldDiff {
            label: "source".to_string(),
            old: Some(base.source.clone()),
            new: Some(candidate.source.clone()),
        });
    }
    fields
}

fn removed_section(policy: &PolicyDefinition) -> SectionDiff {
    SectionDiff {
        header: header_for(&policy.name),
        name: policy.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "source".to_string(),
            old: Some(policy.source.clone()),
            new: None,
        }],
        subsections: Vec::new(),
    }
}

fn added_section(policy: &PolicyDefinition) -> SectionDiff {
    SectionDiff {
        header: header_for(&policy.name),
        name: policy.name.clone(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "source".to_string(),
            old: None,
            new: Some(policy.source.clone()),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(name: &str, source: &str) -> PolicyDefinition {
        PolicyDefinition {
            name: name.to_string(),
            source: source.to_string(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![policy("p1", "accept\n")];
        let candidate = base.clone();
        assert!(diff_policy_definitions(&base, &candidate).is_empty());
    }

    #[test]
    fn added_policy() {
        let sections = diff_policy_definitions(&[], &[policy("p1", "accept\n")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "policy-definition p1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_policy() {
        let sections = diff_policy_definitions(&[policy("p1", "accept\n")], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_source_only_lists_that_field() {
        let base = vec![policy("p1", "accept\n")];
        let candidate = vec![policy("p1", "reject\n")];
        let sections = diff_policy_definitions(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "source");
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("accept\n"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("reject\n"));
    }
}
