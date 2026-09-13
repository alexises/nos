use crate::schema::{AddressFamily, BgpPeerGroup};

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `BgpPeerGroup`s, matched by `name` (unique across the
/// whole config — see `schema::bgp_peer_group::unique_name`).
pub fn diff_bgp_peer_groups(base: &[BgpPeerGroup], candidate: &[BgpPeerGroup]) -> Vec<SectionDiff> {
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
    format!("peer-group {name}")
}

fn source_address_str(pg: &BgpPeerGroup) -> String {
    pg.source_address
        .map_or_else(|| "unset".to_string(), |a| a.to_string())
}

fn address_families_str(pg: &BgpPeerGroup) -> String {
    if pg.address_families.is_empty() {
        "none".to_string()
    } else {
        pg.address_families
            .iter()
            .map(AddressFamily::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn changed_fields(base: &BgpPeerGroup, candidate: &BgpPeerGroup) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.remote_as != candidate.remote_as {
        fields.push(FieldDiff {
            label: "remote-as".to_string(),
            old: Some(base.remote_as.to_string()),
            new: Some(candidate.remote_as.to_string()),
        });
    }
    if base.source_address != candidate.source_address {
        fields.push(FieldDiff {
            label: "source-address".to_string(),
            old: Some(source_address_str(base)),
            new: Some(source_address_str(candidate)),
        });
    }
    if base.address_families != candidate.address_families {
        fields.push(FieldDiff {
            label: "address-family".to_string(),
            old: Some(address_families_str(base)),
            new: Some(address_families_str(candidate)),
        });
    }
    fields
}

fn removed_section(pg: &BgpPeerGroup) -> SectionDiff {
    SectionDiff {
        header: header_for(&pg.name),
        name: pg.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "remote-as".to_string(),
                old: Some(pg.remote_as.to_string()),
                new: None,
            },
            FieldDiff {
                label: "source-address".to_string(),
                old: Some(source_address_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "address-family".to_string(),
                old: Some(address_families_str(pg)),
                new: None,
            },
        ],
        subsections: Vec::new(),
    }
}

fn added_section(pg: &BgpPeerGroup) -> SectionDiff {
    SectionDiff {
        header: header_for(&pg.name),
        name: pg.name.clone(),
        status: DiffStatus::Added,
        fields: vec![
            FieldDiff {
                label: "remote-as".to_string(),
                old: None,
                new: Some(pg.remote_as.to_string()),
            },
            FieldDiff {
                label: "source-address".to_string(),
                old: None,
                new: Some(source_address_str(pg)),
            },
            FieldDiff {
                label: "address-family".to_string(),
                old: None,
                new: Some(address_families_str(pg)),
            },
        ],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::schema::AddressFamily;

    use super::*;

    fn group(name: &str, remote_as: u32) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: vec![AddressFamily::Ipv4Unicast],
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![group("pg1", 65000)];
        let candidate = base.clone();
        assert!(diff_bgp_peer_groups(&base, &candidate).is_empty());
    }

    #[test]
    fn added_group() {
        let sections = diff_bgp_peer_groups(&[], &[group("pg1", 65000)]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "peer-group pg1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_group() {
        let sections = diff_bgp_peer_groups(&[group("pg1", 65000)], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_remote_as_only_lists_that_field() {
        let base = vec![group("pg1", 65000)];
        let candidate = vec![group("pg1", 65001)];
        let sections = diff_bgp_peer_groups(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "remote-as");
    }
}
