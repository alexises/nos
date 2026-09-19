use crate::schema::{Interface, InterfaceAddress};

use super::{subinterface, DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `Interface`s, matched by `name` (the field `garde`'s
/// `unique_in` validator already treats as each interface's key). A
/// modified interface is reported when either its own flat fields (loopback
/// L3 config, switching-profile) or its `subinterfaces` (physical L3
/// config) changed — mirroring `diff_static_routing_instances`' combined
/// fields+subsections emptiness check.
pub fn diff_interfaces(base: &[Interface], candidate: &[Interface]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate.iter().find(|c| c.name == b.name) {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let fields = changed_fields(b, c);
                let subsections =
                    subinterface::diff_subinterfaces(&b.subinterfaces, &c.subinterfaces);
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
    format!("interface {name}")
}

fn format_address(addr: &InterfaceAddress) -> String {
    match &addr.label {
        Some(label) => format!("{} (label {label})", addr.address),
        None => addr.address.to_string(),
    }
}

fn addresses_str(iface: &Interface) -> String {
    if iface.addresses.is_empty() {
        return "none".to_string();
    }
    let mut addrs: Vec<String> = iface.addresses.iter().map(format_address).collect();
    addrs.sort();
    addrs.join(", ")
}

fn routing_table_str(iface: &Interface) -> String {
    iface
        .routing_table
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn switching_profile_str(iface: &Interface) -> String {
    iface
        .switching_profile
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn port_aggregate_str(iface: &Interface) -> String {
    iface
        .port_aggregate
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn ospf_profile_str(iface: &Interface) -> String {
    iface
        .ospf_profile
        .clone()
        .unwrap_or_else(|| "unset".to_string())
}

fn mtu_str(iface: &Interface) -> String {
    iface
        .mtu
        .map_or_else(|| "unset".to_string(), |m| m.to_string())
}

fn changed_fields(base: &Interface, candidate: &Interface) -> Vec<FieldDiff> {
    let mut fields = Vec::new();
    let mut base_addrs = base.addresses.clone();
    let mut candidate_addrs = candidate.addresses.clone();
    base_addrs.sort();
    candidate_addrs.sort();
    if base_addrs != candidate_addrs {
        fields.push(FieldDiff {
            label: "addresses".to_string(),
            old: Some(addresses_str(base)),
            new: Some(addresses_str(candidate)),
        });
    }
    if base.routing_table != candidate.routing_table {
        fields.push(FieldDiff {
            label: "routing-table".to_string(),
            old: Some(routing_table_str(base)),
            new: Some(routing_table_str(candidate)),
        });
    }
    if base.switching_profile != candidate.switching_profile {
        fields.push(FieldDiff {
            label: "switching-profile".to_string(),
            old: Some(switching_profile_str(base)),
            new: Some(switching_profile_str(candidate)),
        });
    }
    if base.port_aggregate != candidate.port_aggregate {
        fields.push(FieldDiff {
            label: "port-aggregate".to_string(),
            old: Some(port_aggregate_str(base)),
            new: Some(port_aggregate_str(candidate)),
        });
    }
    if base.ospf_profile != candidate.ospf_profile {
        fields.push(FieldDiff {
            label: "ospf-profile".to_string(),
            old: Some(ospf_profile_str(base)),
            new: Some(ospf_profile_str(candidate)),
        });
    }
    if base.mtu != candidate.mtu {
        fields.push(FieldDiff {
            label: "mtu".to_string(),
            old: Some(mtu_str(base)),
            new: Some(mtu_str(candidate)),
        });
    }
    fields
}

fn removed_section(iface: &Interface) -> SectionDiff {
    SectionDiff {
        header: header_for(&iface.name),
        name: iface.name.clone(),
        status: DiffStatus::Removed,
        fields: vec![
            FieldDiff {
                label: "addresses".to_string(),
                old: Some(addresses_str(iface)),
                new: None,
            },
            FieldDiff {
                label: "routing-table".to_string(),
                old: Some(routing_table_str(iface)),
                new: None,
            },
            FieldDiff {
                label: "switching-profile".to_string(),
                old: Some(switching_profile_str(iface)),
                new: None,
            },
            FieldDiff {
                label: "port-aggregate".to_string(),
                old: Some(port_aggregate_str(iface)),
                new: None,
            },
            FieldDiff {
                label: "ospf-profile".to_string(),
                old: Some(ospf_profile_str(iface)),
                new: None,
            },
            FieldDiff {
                label: "mtu".to_string(),
                old: Some(mtu_str(iface)),
                new: None,
            },
        ],
        subsections: subinterface::diff_subinterfaces(&iface.subinterfaces, &[]),
    }
}

fn added_section(iface: &Interface) -> SectionDiff {
    SectionDiff {
        header: header_for(&iface.name),
        name: iface.name.clone(),
        status: DiffStatus::Added,
        fields: vec![
            FieldDiff {
                label: "addresses".to_string(),
                old: None,
                new: Some(addresses_str(iface)),
            },
            FieldDiff {
                label: "routing-table".to_string(),
                old: None,
                new: Some(routing_table_str(iface)),
            },
            FieldDiff {
                label: "switching-profile".to_string(),
                old: None,
                new: Some(switching_profile_str(iface)),
            },
            FieldDiff {
                label: "port-aggregate".to_string(),
                old: None,
                new: Some(port_aggregate_str(iface)),
            },
            FieldDiff {
                label: "ospf-profile".to_string(),
                old: None,
                new: Some(ospf_profile_str(iface)),
            },
            FieldDiff {
                label: "mtu".to_string(),
                old: None,
                new: Some(mtu_str(iface)),
            },
        ],
        subsections: subinterface::diff_subinterfaces(&[], &iface.subinterfaces),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, addresses: &[&str], routing_table: Option<&str>) -> Interface {
        Interface {
            ospfv3_profile: None,
            name: name.to_string(),
            addresses: addresses
                .iter()
                .map(|a| InterfaceAddress {
                    address: a.parse().unwrap(),
                    label: None,
                })
                .collect(),
            routing_table: routing_table.map(str::to_string),
            ospf_profile: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: None,
            subinterfaces: Vec::new(),
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![interface("eth0", &["10.0.0.1/24"], Some("rt1"))];
        let candidate = base.clone();
        assert!(diff_interfaces(&base, &candidate).is_empty());
    }

    #[test]
    fn added_interface() {
        let sections = diff_interfaces(&[], &[interface("eth0", &[], None)]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "interface eth0");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_interface() {
        let sections = diff_interfaces(&[interface("eth0", &[], None)], &[]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn modified_routing_table_only_lists_that_field() {
        let base = vec![interface("eth0", &[], None)];
        let candidate = vec![interface("eth0", &[], Some("rt1"))];
        let sections = diff_interfaces(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "routing-table");
    }

    #[test]
    fn modified_switching_profile_only_lists_that_field() {
        let mut base_iface = interface("eth0", &[], None);
        let mut candidate_iface = base_iface.clone();
        candidate_iface.switching_profile = Some("sp1".to_string());
        base_iface.switching_profile = None;
        let sections = diff_interfaces(&[base_iface], &[candidate_iface]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "switching-profile");
    }

    #[test]
    fn modified_ospf_profile_only_lists_that_field() {
        let mut base_iface = interface("eth0", &[], None);
        let mut candidate_iface = base_iface.clone();
        candidate_iface.ospf_profile = Some("p1".to_string());
        base_iface.ospf_profile = None;
        let sections = diff_interfaces(&[base_iface], &[candidate_iface]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "ospf-profile");
    }

    #[test]
    fn modified_addresses_only_lists_that_field() {
        let base = vec![interface("eth0", &["10.0.0.1/24"], None)];
        let candidate = vec![interface("eth0", &["10.0.0.2/24"], None)];
        let sections = diff_interfaces(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "addresses");
    }

    #[test]
    fn reordered_addresses_are_not_a_change() {
        let base = vec![interface("eth0", &["10.0.0.1/24", "10.0.0.2/24"], None)];
        let candidate = vec![interface("eth0", &["10.0.0.2/24", "10.0.0.1/24"], None)];
        assert!(diff_interfaces(&base, &candidate).is_empty());
    }

    #[test]
    fn modified_label_only_lists_addresses_field() {
        let base = vec![Interface {
            ospfv3_profile: None,
            name: "eth0".to_string(),
            addresses: vec![InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            }],
            routing_table: None,
            ospf_profile: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: None,
            subinterfaces: Vec::new(),
        }];
        let candidate = vec![Interface {
            ospfv3_profile: None,
            name: "eth0".to_string(),
            addresses: vec![InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: Some("mgmt".to_string()),
            }],
            routing_table: None,
            ospf_profile: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: None,
            subinterfaces: Vec::new(),
        }];
        let sections = diff_interfaces(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields.len(), 1);
        assert_eq!(sections[0].fields[0].label, "addresses");
    }

    /// An interface with no changed flat fields must still surface as
    /// `Modified`, with empty `fields` and the change nested in
    /// `subsections`, when only its subinterfaces changed — mirrors
    /// `diff_static_routing_instances`' equivalent test.
    #[test]
    fn changed_subinterface_is_modified_with_empty_fields() {
        use crate::schema::Subinterface;

        let mut base_iface = interface("eth0", &[], None);
        base_iface.subinterfaces = vec![Subinterface {
            ospfv3_profile: None,
            tag: 100,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
        }];
        let mut candidate_iface = base_iface.clone();
        candidate_iface.subinterfaces[0].routing_table = Some("rt1".to_string());

        let sections = diff_interfaces(&[base_iface], &[candidate_iface]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert!(sections[0].fields.is_empty());
        assert_eq!(sections[0].subsections.len(), 1);
        assert_eq!(sections[0].subsections[0].header, "subinterface 100");
    }
}
