use crate::schema::{AddressFamily, BgpAoAlgorithm, BgpAuth, BgpPeerGroup, SourceAddress};

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
        .as_ref()
        .map_or_else(|| "unset".to_string(), SourceAddress::to_string)
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

fn hold_time_str(pg: &BgpPeerGroup) -> String {
    pg.hold_time
        .map_or_else(|| "default (90s)".to_string(), |h| h.to_string())
}

fn keepalive_interval_str(pg: &BgpPeerGroup) -> String {
    pg.keepalive_interval
        .map_or_else(|| "default (hold-time / 3)".to_string(), |k| k.to_string())
}

fn connect_retry_time_str(pg: &BgpPeerGroup) -> String {
    pg.connect_retry_time
        .map_or_else(|| "default (120s)".to_string(), |c| c.to_string())
}

/// Rendered in clear text, like every other field — see `BgpAuth`'s doc
/// comment on why secrets are never masked in this codebase.
fn auth_str(pg: &BgpPeerGroup) -> String {
    match &pg.auth {
        None => "none".to_string(),
        Some(BgpAuth::Md5 { password }) => format!("md5-password {password}"),
        Some(BgpAuth::Ao { keys }) => {
            let rendered = keys
                .iter()
                .map(|k| {
                    let algorithm = match k.algorithm {
                        BgpAoAlgorithm::HmacSha1_96 => "hmac-sha1",
                        BgpAoAlgorithm::AesCmac96 => "aes-cmac",
                    };
                    let flags = match (k.is_current, k.is_rnext) {
                        (true, true) => " (current, rnext)",
                        (true, false) => " (current)",
                        (false, true) => " (rnext)",
                        (false, false) => "",
                    };
                    format!("send-id {} {algorithm} {}{flags}", k.send_id, k.key)
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("ao-keys [{rendered}]")
        }
    }
}

/// Renders the effective policy name, not the raw `Option` — `None` really
/// does mean `deny-all` at runtime (see `BgpPeerGroup.import_policy`'s doc
/// comment), so the diff should say that rather than "unset".
fn import_policy_str(pg: &BgpPeerGroup) -> String {
    pg.import_policy
        .clone()
        .unwrap_or_else(|| nos_rpl::DENY_ALL_NAME.to_string())
}

fn export_policy_str(pg: &BgpPeerGroup) -> String {
    pg.export_policy
        .clone()
        .unwrap_or_else(|| nos_rpl::DENY_ALL_NAME.to_string())
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
    if base.hold_time != candidate.hold_time {
        fields.push(FieldDiff {
            label: "hold-time".to_string(),
            old: Some(hold_time_str(base)),
            new: Some(hold_time_str(candidate)),
        });
    }
    if base.keepalive_interval != candidate.keepalive_interval {
        fields.push(FieldDiff {
            label: "keepalive-interval".to_string(),
            old: Some(keepalive_interval_str(base)),
            new: Some(keepalive_interval_str(candidate)),
        });
    }
    if base.connect_retry_time != candidate.connect_retry_time {
        fields.push(FieldDiff {
            label: "connect-retry-time".to_string(),
            old: Some(connect_retry_time_str(base)),
            new: Some(connect_retry_time_str(candidate)),
        });
    }
    if base.auth != candidate.auth {
        fields.push(FieldDiff {
            label: "auth".to_string(),
            old: Some(auth_str(base)),
            new: Some(auth_str(candidate)),
        });
    }
    if base.import_policy != candidate.import_policy {
        fields.push(FieldDiff {
            label: "import-policy".to_string(),
            old: Some(import_policy_str(base)),
            new: Some(import_policy_str(candidate)),
        });
    }
    if base.export_policy != candidate.export_policy {
        fields.push(FieldDiff {
            label: "export-policy".to_string(),
            old: Some(export_policy_str(base)),
            new: Some(export_policy_str(candidate)),
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
            FieldDiff {
                label: "hold-time".to_string(),
                old: Some(hold_time_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "keepalive-interval".to_string(),
                old: Some(keepalive_interval_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "connect-retry-time".to_string(),
                old: Some(connect_retry_time_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "auth".to_string(),
                old: Some(auth_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "import-policy".to_string(),
                old: Some(import_policy_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "export-policy".to_string(),
                old: Some(export_policy_str(pg)),
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
            FieldDiff {
                label: "hold-time".to_string(),
                old: None,
                new: Some(hold_time_str(pg)),
            },
            FieldDiff {
                label: "keepalive-interval".to_string(),
                old: None,
                new: Some(keepalive_interval_str(pg)),
            },
            FieldDiff {
                label: "connect-retry-time".to_string(),
                old: None,
                new: Some(connect_retry_time_str(pg)),
            },
            FieldDiff {
                label: "auth".to_string(),
                old: None,
                new: Some(auth_str(pg)),
            },
            FieldDiff {
                label: "import-policy".to_string(),
                old: None,
                new: Some(import_policy_str(pg)),
            },
            FieldDiff {
                label: "export-policy".to_string(),
                old: None,
                new: Some(export_policy_str(pg)),
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
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
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
