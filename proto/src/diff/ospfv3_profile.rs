use crate::schema::{NetworkType, OspfCryptoAlgorithm, Ospfv3Profile};

use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `Ospfv3Profile`s, matched by `name` — mirrors
/// `diff_ospf_profiles` exactly.
pub fn diff_ospfv3_profiles(
    base: &[Ospfv3Profile],
    candidate: &[Ospfv3Profile],
) -> Vec<SectionDiff> {
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
    format!("ospfv3 profile {name}")
}

fn hello_interval_str(p: &Ospfv3Profile) -> String {
    p.hello_interval
        .map_or_else(|| "default (10s)".to_string(), |h| h.to_string())
}

fn dead_interval_str(p: &Ospfv3Profile) -> String {
    p.dead_interval
        .map_or_else(|| "default (40s)".to_string(), |d| d.to_string())
}

fn cost_str(p: &Ospfv3Profile) -> String {
    p.cost
        .map_or_else(|| "default (1)".to_string(), |c| c.to_string())
}

fn priority_str(p: &Ospfv3Profile) -> String {
    p.priority
        .map_or_else(|| "default (1)".to_string(), |pr| pr.to_string())
}

fn mtu_str(p: &Ospfv3Profile) -> String {
    p.mtu.map_or_else(
        || "unset (uses real interface mtu)".to_string(),
        |m| m.to_string(),
    )
}

fn network_type_str(p: &Ospfv3Profile) -> String {
    match p.network_type {
        None => "unset (derived from attach point)".to_string(),
        Some(NetworkType::PointToPoint) => "point-to-point".to_string(),
        Some(NetworkType::Broadcast) => "broadcast".to_string(),
    }
}

/// Clear text, like `diff::ospf_profile::auth_str`.
fn auth_str(p: &Ospfv3Profile) -> String {
    match &p.auth {
        None => "none".to_string(),
        Some(keys) => {
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

fn changed_fields(base: &Ospfv3Profile, candidate: &Ospfv3Profile) -> Vec<FieldDiff> {
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
    if base.instance_id != candidate.instance_id {
        fields.push(FieldDiff {
            label: "instance-id".to_string(),
            old: Some(base.instance_id.unwrap_or(0).to_string()),
            new: Some(candidate.instance_id.unwrap_or(0).to_string()),
        });
    }
    if base.auth != candidate.auth {
        fields.push(FieldDiff {
            label: "auth".to_string(),
            old: Some(auth_str(base)),
            new: Some(auth_str(candidate)),
        });
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> Ospfv3Profile {
        Ospfv3Profile {
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            mtu: None,
            network_type: None,
            auth: None,
            instance_id: None,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![profile("p1")];
        let candidate = base.clone();
        assert_eq!(diff_ospfv3_profiles(&base, &candidate), []);
    }

    #[test]
    fn added_profile() {
        let sections = diff_ospfv3_profiles(&[], &[profile("p1")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "ospfv3 profile p1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_profile() {
        let sections = diff_ospfv3_profiles(&[profile("p1")], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_hello_interval_reports_only_that_field() {
        let base = vec![profile("p1")];
        let mut modified = profile("p1");
        modified.hello_interval = Some(5);
        let sections = diff_ospfv3_profiles(&base, &[modified]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "hello-interval");
    }
}
