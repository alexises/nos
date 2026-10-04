use crate::schema::{BgpConfederation, BgpInstance};

use super::{bgp_peer, bgp_peer_group, DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `BgpInstance`s, matched by `name` (the field
/// `garde`'s `unique_in` validator already treats as each instance's key).
/// Instances present on only one side are emitted wholesale as
/// `Added`/`Removed`, with their peer-groups/peers nested underneath at the
/// same status; instances present on both sides are compared field-by-field
/// and only included at all if `router_id`/`asn` changed, or a nested
/// peer-group/peer changed.
pub fn diff_bgp_instances(base: &[BgpInstance], candidate: &[BgpInstance]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let fields = changed_fields(b, c);
                let subsections = [
                    bgp_peer_group::diff_bgp_peer_groups(&b.peer_groups, &c.peer_groups),
                    bgp_peer::diff_bgp_peers(&b.peers, &c.peers),
                ]
                .concat();
                if !fields.is_empty() || !subsections.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(&b.name),
                        name: b.name.clone(),
                        status: DiffStatus::Modified,
                        fields,
                        subsections,
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
    format!("bgp instance {name}")
}

fn changed_fields(base: &BgpInstance, candidate: &BgpInstance) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    if base.router_id != candidate.router_id {
        fields.push(FieldDiff {
            label: "router-id".to_string(),
            old: Some(base.router_id.to_string()),
            new: Some(candidate.router_id.to_string()),
        });
    }
    if base.asn != candidate.asn {
        fields.push(FieldDiff {
            label: "asn".to_string(),
            old: Some(base.asn.to_string()),
            new: Some(candidate.asn.to_string()),
        });
    }
    if base.rpki_caches != candidate.rpki_caches {
        let render = |i: &BgpInstance| {
            (!i.rpki_caches.is_empty()).then(|| {
                i.rpki_caches
                    .iter()
                    .map(|c| format!("{} port {} preference {}", c.address, c.port, c.preference))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
        };
        fields.push(FieldDiff {
            label: "rpki-cache".to_string(),
            old: render(base),
            new: render(candidate),
        });
    }
    if base.aggregates != candidate.aggregates {
        let render = |i: &BgpInstance| {
            (!i.aggregates.is_empty()).then(|| {
                i.aggregates
                    .iter()
                    .map(|a| {
                        let mut s = a.prefix.to_string();
                        if a.as_set {
                            s.push_str(" as-set");
                        }
                        if a.summary_only {
                            s.push_str(" summary-only");
                        }
                        s
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
        };
        fields.push(FieldDiff {
            label: "aggregate-address".to_string(),
            old: render(base),
            new: render(candidate),
        });
    }
    if base.maximum_paths != candidate.maximum_paths {
        fields.push(FieldDiff {
            label: "maximum-paths".to_string(),
            old: base.maximum_paths.map(|n| n.to_string()),
            new: candidate.maximum_paths.map(|n| n.to_string()),
        });
    }
    if base.confederation != candidate.confederation {
        fields.push(FieldDiff {
            label: "confederation".to_string(),
            old: render_confederation(&base.confederation),
            new: render_confederation(&candidate.confederation),
        });
    }
    fields
}

fn render_confederation(c: &BgpConfederation) -> Option<String> {
    if *c == BgpConfederation::default() {
        return None;
    }
    let id = c
        .identifier
        .map_or_else(|| "unset".to_string(), |i| i.to_string());
    let peers: Vec<String> = c.peers.iter().map(u32::to_string).collect();
    Some(format!("identifier {id} peers [{}]", peers.join(", ")))
}

fn removed_section(instance: &BgpInstance) -> SectionDiff {
    SectionDiff {
        header: header_for(&instance.name),
        name: instance.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "router-id".to_string(),
                old: Some(instance.router_id.to_string()),
                new: None,
            },
            FieldDiff {
                label: "asn".to_string(),
                old: Some(instance.asn.to_string()),
                new: None,
            },
        ],
        subsections: [
            bgp_peer_group::diff_bgp_peer_groups(&instance.peer_groups, &[]),
            bgp_peer::diff_bgp_peers(&instance.peers, &[]),
        ]
        .concat(),
    }
}

fn added_section(instance: &BgpInstance) -> SectionDiff {
    let mut fields = changed_fields(&BgpInstance::default(), instance);
    fields.retain(|f| {
        matches!(
            f.label.as_str(),
            "confederation" | "rpki-cache" | "maximum-paths" | "aggregate-address"
        )
    });
    SectionDiff {
        header: header_for(&instance.name),
        name: instance.name.clone(),
        status: DiffStatus::Added,
        fields: [
            vec![
                FieldDiff {
                    label: "router-id".to_string(),
                    old: None,
                    new: Some(instance.router_id.to_string()),
                },
                FieldDiff {
                    label: "asn".to_string(),
                    old: None,
                    new: Some(instance.asn.to_string()),
                },
            ],
            fields,
        ]
        .concat(),
        subsections: [
            bgp_peer_group::diff_bgp_peer_groups(&[], &instance.peer_groups),
            bgp_peer::diff_bgp_peers(&[], &instance.peers),
        ]
        .concat(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            aggregates: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![instance("r1", 65000)];
        let candidate = base.clone();
        assert_eq!(diff_bgp_instances(&base, &candidate), []);
    }

    #[test]
    fn added_instance() {
        let base = vec![];
        let candidate = vec![instance("r1", 65000)];
        let sections = diff_bgp_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "bgp instance r1");
        assert_eq!(sections[0].status, DiffStatus::Added);
        assert_eq!(sections[0].fields.len(), 2);
        assert!(sections[0].fields.iter().all(|f| f.old.is_none()));
    }

    #[test]
    fn removed_instance() {
        let base = vec![instance("r1", 65000)];
        let candidate = vec![];
        let sections = diff_bgp_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
        assert!(sections[0].fields.iter().all(|f| f.new.is_none()));
    }

    #[test]
    fn modified_instance_only_lists_changed_fields() {
        let base = vec![instance("r1", 65000)];
        let candidate = vec![instance("r1", 65001)];
        let sections = diff_bgp_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "asn");
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("65000"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("65001"));
    }

    #[test]
    fn confederation_change_is_a_field_diff() {
        let base = vec![instance("r1", 65101)];
        let mut c = instance("r1", 65101);
        c.confederation = BgpConfederation {
            identifier: Some(65100),
            peers: vec![65102],
        };
        let sections = diff_bgp_instances(&base, &[c]);
        assert_eq!(sections[0].fields[0].label, "confederation");
        assert_eq!(
            sections[0].fields[0].new.as_deref(),
            Some("identifier 65100 peers [65102]")
        );
    }

    #[test]
    fn unrelated_unchanged_instance_is_omitted() {
        let base = vec![instance("r1", 65000), instance("r2", 65002)];
        let candidate = vec![instance("r1", 65001), instance("r2", 65002)];
        let sections = diff_bgp_instances(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "bgp instance r1");
    }

    /// An instance whose own fields are unchanged but whose nested
    /// peer-group changed must still surface as `Modified`, with empty
    /// top-level `fields` and the change nested in `subsections`.
    #[test]
    fn unchanged_own_fields_but_changed_peer_group_is_modified() {
        use crate::schema::{AddressFamily, BgpPeerGroup};

        let group = |remote_as: u32| BgpPeerGroup {
            name: "pg1".to_string(),
            remote_as,
            source_address: None,
            address_families: vec![AddressFamily::Ipv4Unicast],
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            mrai: None,
            route_refresh_stale_time: None,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
            shutdown: None,
            maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
            announce_rpki_state: false,
            local_as: None,
        };

        let mut base_instance = instance("r1", 65000);
        base_instance.peer_groups = vec![group(65001)];
        let mut candidate_instance = instance("r1", 65000);
        candidate_instance.peer_groups = vec![group(65002)];

        let sections = diff_bgp_instances(&[base_instance], &[candidate_instance]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields, []);
        assert_eq!(sections[0].subsections.len(), 1);
        assert_eq!(sections[0].subsections[0].header, "peer-group pg1");
    }
}
