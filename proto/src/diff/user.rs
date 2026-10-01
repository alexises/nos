use crate::schema::User;

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Value shown for a password in a diff — the hash itself is never surfaced.
const HIDDEN: &str = "<hidden>";

/// Diffs two lists of `User`s, matched by `name`. A `Modified` section means
/// the stored hash changed; re-setting the same password keeps the hash, so
/// produces no diff at all.
pub fn diff_users(base: &[User], candidate: &[User]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(section(&b.name, DiffStatus::Removed, Some(HIDDEN), None)),
            Some(c) if c.password != b.password => sections.push(section(
                &b.name,
                DiffStatus::Modified,
                Some(HIDDEN),
                Some("<changed>"),
            )),
            Some(_) => {}
        }
    }
    for c in candidate {
        if !base.iter().any(|b| b.name == c.name) {
            sections.push(section(&c.name, DiffStatus::Added, None, Some(HIDDEN)));
        }
    }
    sections
}

fn section(name: &str, status: DiffStatus, old: Option<&str>, new: Option<&str>) -> SectionDiff {
    SectionDiff {
        header: format!("user {name}"),
        name: name.to_string(),
        status,
        fields: vec![FieldDiff {
            label: "password".to_string(),
            old: old.map(str::to_string),
            new: new.map(str::to_string),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(name: &str, pw: &str) -> User {
        User {
            name: name.to_string(),
            password: pw.to_string(),
        }
    }

    #[test]
    fn same_hash_is_no_diff() {
        assert_eq!(
            diff_users(&[u("a", "$argon2id$1")], &[u("a", "$argon2id$1")]),
            []
        );
    }

    #[test]
    fn changed_hash_is_modified_and_hidden() {
        let d = diff_users(&[u("a", "$argon2id$1")], &[u("a", "$argon2id$2")]);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].status, DiffStatus::Modified);
        assert!(!format!("{d:?}").contains("argon2id"));
    }

    #[test]
    fn added_and_removed() {
        let d = diff_users(&[u("a", "$argon2id$1")], &[u("b", "$argon2id$2")]);
        assert_eq!(d.len(), 2);
    }
}
