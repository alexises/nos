use crate::schema::{NetworkType, OspfAuth, OspfCryptoAlgorithm, OspfProfile};

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `OspfProfile`s, matched by `name` (globally unique —
/// see `schema::ospf_profile::unique_name`).
pub fn diff_ospf_profiles(base: &[OspfProfile], candidate: &[OspfProfile]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(SectionDiff {
                header: header_for(&b.name),
                name: b.name.clone(),
                status: DiffStatus::Removed,
                fields: Vec::new(),
                subsections: Vec::new(),
            }),
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
            sections.push(SectionDiff {
                header: header_for(&c.name),
                name: c.name.clone(),
                status: DiffStatus::Added,
                fields: Vec::new(),
                subsections: Vec::new(),
            });
        }
    }

    sections
}

fn header_for(name: &str) -> String {
    format!("ospf profile {name}")
}

fn hello_interval_str(p: &OspfProfile) -> String {
    p.hello_interval
        .map_or_else(|| "default (10s)".to_string(), |h| h.to_string())
}

fn dead_interval_str(p: &OspfProfile) -> String {
    p.dead_interval
        .map_or_else(|| "default (40s)".to_string(), |d| d.to_string())
}

fn cost_str(p: &OspfProfile) -> String {
    p.cost
        .map_or_else(|| "default (1)".to_string(), |c| c.to_string())
}

fn priority_str(p: &OspfProfile) -> String {
    p.priority
        .map_or_else(|| "default (1)".to_string(), |pr| pr.to_string())
}

fn mtu_str(p: &OspfProfile) -> String {
    p.mtu.map_or_else(
        || "unset (uses real interface mtu)".to_string(),
        |m| m.to_string(),
    )
}

fn network_type_str(p: &OspfProfile) -> String {
    match p.network_type {
        None => "unset (derived from attach point)".to_string(),
        Some(NetworkType::PointToPoint) => "point-to-point".to_string(),
        Some(NetworkType::Broadcast) => "broadcast".to_string(),
    }
}

/// Rendered in clear text, like every other field — see `OspfAuth`'s doc
/// comment (mirrors `BgpAuth`'s own, in `diff::bgp_peer_group::auth_str`) on
/// why secrets are never masked in this codebase.
fn auth_str(p: &OspfProfile) -> String {
    match &p.auth {
        None => "none".to_string(),
        Some(OspfAuth::Simple { password }) => format!("simple-password {password}"),
        Some(OspfAuth::Crypto { keys }) => {
            let rendered = keys
                .iter()
                .map(|k| {
                    let algorithm = match k.algorithm {
                        OspfCryptoAlgorithm::Md5 => "md5",
                        OspfCryptoAlgorithm::HmacSha1 => "hmac-sha1",
                        OspfCryptoAlgorithm::HmacSha256 => "hmac-sha256",
                        OspfCryptoAlgorithm::HmacSha384 => "hmac-sha384",
                        OspfCryptoAlgorithm::HmacSha512 => "hmac-sha512",
                    };
                    let flags = if k.is_current { " (current)" } else { "" };
                    format!("key-id {} {algorithm} {}{flags}", k.key_id, k.key)
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("crypto-keys [{rendered}]")
        }
    }
}

fn changed_fields(base: &OspfProfile, candidate: &OspfProfile) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.hello_interval != candidate.hello_interval {
        fields.push(FieldDiff {
            label: "hello-interval".to_string(),
            old: Some(hello_interval_str(base)),
            new: Some(hello_interval_str(candidate)),
        });
    }
    if base.dead_interval != candidate.dead_interval {
        fields.push(FieldDiff {
            label: "dead-interval".to_string(),
            old: Some(dead_interval_str(base)),
            new: Some(dead_interval_str(candidate)),
        });
    }
    if base.cost != candidate.cost {
        fields.push(FieldDiff {
            label: "cost".to_string(),
            old: Some(cost_str(base)),
            new: Some(cost_str(candidate)),
        });
    }
    if base.priority != candidate.priority {
        fields.push(FieldDiff {
            label: "priority".to_string(),
            old: Some(priority_str(base)),
            new: Some(priority_str(candidate)),
        });
    }
    if base.mtu != candidate.mtu {
        fields.push(FieldDiff {
            label: "mtu".to_string(),
            old: Some(mtu_str(base)),
            new: Some(mtu_str(candidate)),
        });
    }
    if base.network_type != candidate.network_type {
        fields.push(FieldDiff {
            label: "network-type".to_string(),
            old: Some(network_type_str(base)),
            new: Some(network_type_str(candidate)),
        });
    }
    if base.auth != candidate.auth {
        fields.push(FieldDiff {
            label: "auth".to_string(),
            old: Some(auth_str(base)),
            new: Some(auth_str(candidate)),
        });
    }
    if base.extended_sequence_numbers != candidate.extended_sequence_numbers {
        fields.push(FieldDiff {
            label: "extended-sequence-numbers".to_string(),
            old: Some(base.extended_sequence_numbers.to_string()),
            new: Some(candidate.extended_sequence_numbers.to_string()),
        });
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> OspfProfile {
        OspfProfile {
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            mtu: None,
            network_type: None,
            auth: None,
            extended_sequence_numbers: false,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![profile("p1")];
        let candidate = base.clone();
        assert!(diff_ospf_profiles(&base, &candidate).is_empty());
    }

    #[test]
    fn added_profile() {
        let sections = diff_ospf_profiles(&[], &[profile("p1")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospf profile p1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_profile() {
        let sections = diff_ospf_profiles(&[profile("p1")], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn unrelated_unchanged_profile_is_omitted() {
        let base = vec![profile("p1"), profile("p2")];
        let candidate = vec![profile("p1")];
        let sections = diff_ospf_profiles(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospf profile p2");
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_hello_interval_reports_only_that_field() {
        let base = vec![profile("p1")];
        let mut modified = profile("p1");
        modified.hello_interval = Some(5);
        let sections = diff_ospf_profiles(&base, &[modified]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "hello-interval");
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("default (10s)"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("5"));
    }

    #[test]
    fn modified_dead_interval_reports_only_that_field() {
        let base = vec![profile("p1")];
        let mut modified = profile("p1");
        modified.dead_interval = Some(30);
        let sections = diff_ospf_profiles(&base, &[modified]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "dead-interval");
    }

    #[test]
    fn modified_cost_reports_only_that_field() {
        let base = vec![profile("p1")];
        let mut modified = profile("p1");
        modified.cost = Some(20);
        let sections = diff_ospf_profiles(&base, &[modified]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "cost");
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("default (1)"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("20"));
    }

    #[test]
    fn modified_priority_reports_only_that_field() {
        let base = vec![profile("p1")];
        let mut modified = profile("p1");
        modified.priority = Some(200);
        let sections = diff_ospf_profiles(&base, &[modified]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "priority");
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("default (1)"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("200"));
    }

    #[test]
    fn modified_network_type_reports_only_that_field() {
        let base = vec![profile("p1")];
        let mut modified = profile("p1");
        modified.network_type = Some(NetworkType::Broadcast);
        let sections = diff_ospf_profiles(&base, &[modified]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "network-type");
        assert_eq!(
            sections[0].fields[0].old.as_deref(),
            Some("unset (derived from attach point)")
        );
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("broadcast"));
    }

    #[test]
    fn modified_auth_reports_only_that_field_in_clear_text() {
        let base = vec![profile("p1")];
        let mut modified = profile("p1");
        modified.auth = Some(OspfAuth::Simple {
            password: "abcdefgh".to_string(),
        });
        let sections = diff_ospf_profiles(&base, &[modified]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "auth");
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("none"));
        assert_eq!(
            sections[0].fields[0].new.as_deref(),
            Some("simple-password abcdefgh")
        );
    }
}
