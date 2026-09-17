use crate::schema::BroadcastDomain;

use super::{DiffStatus, SectionDiff};

/// Diffs two lists of `BroadcastDomain`s, matched by `name`. `name` is the
/// only field, so unlike every other `diff_*` helper here, no `Modified`
/// section is ever produced — only `Added`/`Removed`.
pub fn diff_broadcast_domains(
    base: &[BroadcastDomain],
    candidate: &[BroadcastDomain],
) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        if !candidate.iter().any(|c| c.name == b.name) {
            sections.push(section(b, DiffStatus::Removed));
        }
    }

    for c in candidate {
        if !base.iter().any(|b| b.name == c.name) {
            sections.push(section(c, DiffStatus::Added));
        }
    }

    sections
}

fn section(domain: &BroadcastDomain, status: DiffStatus) -> SectionDiff {
    SectionDiff {
        header: format!("broadcast-domain {}", domain.name),
        name: domain.name.clone(),
        status,
        fields: Vec::new(),
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> BroadcastDomain {
        BroadcastDomain {
            name: name.to_string(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![domain("bd1")];
        let candidate = base.clone();
        assert!(diff_broadcast_domains(&base, &candidate).is_empty());
    }

    #[test]
    fn added_domain() {
        let sections = diff_broadcast_domains(&[], &[domain("bd1")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "broadcast-domain bd1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_domain() {
        let sections = diff_broadcast_domains(&[domain("bd1")], &[]);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }
}
