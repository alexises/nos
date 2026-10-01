use crate::schema::AsPathList;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `AsPathList`s, matched by `name` (unique across
/// the whole config). `patterns` is compared and rendered as a whole
/// (joined list), not per-pattern — mirroring `PolicyDefinition.source`
/// rather than `Interface.addresses`, since a list's patternship is small
/// and usually changes alongside itself.
pub fn diff_as_path_lists(base: &[AsPathList], candidate: &[AsPathList]) -> Vec<SectionDiff> {
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
    format!("as-path-list {name}")
}

fn render_patterns(patterns: &[String]) -> String {
    patterns.join(", ")
}

fn changed_fields(base: &AsPathList, candidate: &AsPathList) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.patterns != candidate.patterns {
        fields.push(FieldDiff {
            label: "patterns".to_string(),
            old: Some(render_patterns(&base.patterns)),
            new: Some(render_patterns(&candidate.patterns)),
        });
    }
    fields
}

fn removed_section(list: &AsPathList) -> SectionDiff {
    SectionDiff {
        header: header_for(&list.name),
        name: list.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "patterns".to_string(),
            old: Some(render_patterns(&list.patterns)),
            new: None,
        }],
        subsections: Vec::new(),
    }
}

fn added_section(list: &AsPathList) -> SectionDiff {
    SectionDiff {
        header: header_for(&list.name),
        name: list.name.clone(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "patterns".to_string(),
            old: None,
            new: Some(render_patterns(&list.patterns)),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(name: &str, patterns: &[&str]) -> AsPathList {
        AsPathList {
            name: name.to_string(),
            patterns: patterns.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![list("g1", &["65000:100"])];
        let candidate = base.clone();
        assert_eq!(diff_as_path_lists(&base, &candidate), []);
    }

    #[test]
    fn added_list() {
        let sections = diff_as_path_lists(&[], &[list("g1", &["65000:100"])]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_list() {
        let sections = diff_as_path_lists(&[list("g1", &["65000:100"])], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_patterns_only_lists_that_field() {
        let base = vec![list("g1", &["65000:100"])];
        let candidate = vec![list("g1", &["65000:100", "65000:200"])];
        let sections = diff_as_path_lists(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields[0].label, "patterns");
    }
}
