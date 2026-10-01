use crate::schema::{PrefixList, PrefixListEntry};

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `PrefixList`s, matched by `name` (unique across the
/// whole config). `entries` is compared and rendered as a whole (joined
/// list), mirroring `CommunityGroup.members`.
pub fn diff_prefix_lists(base: &[PrefixList], candidate: &[PrefixList]) -> Vec<SectionDiff> {
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
    format!("prefix-list {name}")
}

fn render_entry(entry: &PrefixListEntry) -> String {
    match entry.range {
        None => entry.cidr.to_string(),
        Some((min, max)) => format!("{} range({min},{max})", entry.cidr),
    }
}

fn render_entries(entries: &[PrefixListEntry]) -> String {
    entries
        .iter()
        .map(render_entry)
        .collect::<Vec<_>>()
        .join(", ")
}

fn changed_fields(base: &PrefixList, candidate: &PrefixList) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.entries != candidate.entries {
        fields.push(FieldDiff {
            label: "entries".to_string(),
            old: Some(render_entries(&base.entries)),
            new: Some(render_entries(&candidate.entries)),
        });
    }
    fields
}

fn removed_section(list: &PrefixList) -> SectionDiff {
    SectionDiff {
        header: header_for(&list.name),
        name: list.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "entries".to_string(),
            old: Some(render_entries(&list.entries)),
            new: None,
        }],
        subsections: Vec::new(),
    }
}

fn added_section(list: &PrefixList) -> SectionDiff {
    SectionDiff {
        header: header_for(&list.name),
        name: list.name.clone(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "entries".to_string(),
            old: None,
            new: Some(render_entries(&list.entries)),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cidr: &str, range: Option<(u8, u8)>) -> PrefixListEntry {
        PrefixListEntry {
            cidr: cidr.parse().unwrap(),
            range,
        }
    }

    fn list(name: &str, entries: Vec<PrefixListEntry>) -> PrefixList {
        PrefixList {
            name: name.to_string(),
            entries,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![list("l1", vec![entry("10.0.0.0/8", None)])];
        let candidate = base.clone();
        assert_eq!(diff_prefix_lists(&base, &candidate), []);
    }

    #[test]
    fn added_list() {
        let sections = diff_prefix_lists(&[], &[list("l1", vec![entry("10.0.0.0/8", None)])]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_list() {
        let sections = diff_prefix_lists(&[list("l1", vec![entry("10.0.0.0/8", None)])], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_entries_only_lists_that_field() {
        let base = vec![list("l1", vec![entry("10.0.0.0/8", None)])];
        let candidate = vec![list("l1", vec![entry("10.0.0.0/8", Some((24, 32)))])];
        let sections = diff_prefix_lists(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields[0].label, "entries");
        assert!(sections[0].fields[0]
            .new
            .as_deref()
            .unwrap()
            .contains("range(24,32)"));
    }
}
