use std::net::IpAddr;

use crate::schema::BgpPeer;

use super::bgp_peer_group::shutdown_str;
use super::{DiffStatus, FieldDiff, SectionDiff};

/// Diffs two lists of `BgpPeer`s, matched by `remote_address` (unique
/// across the whole config — see `schema::bgp_peer::unique_remote_address`).
pub fn diff_bgp_peers(base: &[BgpPeer], candidate: &[BgpPeer]) -> Vec<SectionDiff> {
    let mut sections = Vec::new();

    for b in base {
        match candidate
            .iter()
            .find(|c| c.remote_address == b.remote_address)
        {
            None => sections.push(removed_section(b)),
            Some(c) => {
                let mut fields = Vec::new();
                if b.peer_group != c.peer_group {
                    fields.push(FieldDiff {
                        label: "peer-group".to_string(),
                        old: Some(b.peer_group.clone()),
                        new: Some(c.peer_group.clone()),
                    });
                }
                if b.shutdown != c.shutdown {
                    fields.push(FieldDiff {
                        label: "shutdown".to_string(),
                        old: Some(shutdown_str(b.shutdown.as_ref())),
                        new: Some(shutdown_str(c.shutdown.as_ref())),
                    });
                }
                if !fields.is_empty() {
                    sections.push(SectionDiff {
                        header: header_for(&b.remote_address),
                        name: b.remote_address.to_string(),
                        status: DiffStatus::Modified,
                        fields,
                        subsections: Vec::new(),
                    });
                }
            }
        }
    }

    for c in candidate {
        if !base.iter().any(|b| b.remote_address == c.remote_address) {
            sections.push(added_section(c));
        }
    }

    sections
}

fn header_for(addr: &IpAddr) -> String {
    format!("peer {addr}")
}

fn removed_section(peer: &BgpPeer) -> SectionDiff {
    SectionDiff {
        header: header_for(&peer.remote_address),
        name: peer.remote_address.to_string(),
        status: DiffStatus::Removed,
        fields: vec![FieldDiff {
            label: "peer-group".to_string(),
            old: Some(peer.peer_group.clone()),
            new: None,
        }],
        subsections: Vec::new(),
    }
}

fn added_section(peer: &BgpPeer) -> SectionDiff {
    SectionDiff {
        header: header_for(&peer.remote_address),
        name: peer.remote_address.to_string(),
        status: DiffStatus::Added,
        fields: vec![FieldDiff {
            label: "peer-group".to_string(),
            old: None,
            new: Some(peer.peer_group.clone()),
        }],
        subsections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn peer(addr: u8, group: &str) -> BgpPeer {
        BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, addr)),
            peer_group: group.to_string(),
            shutdown: None,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![peer(1, "pg1")];
        let candidate = base.clone();
        assert_eq!(diff_bgp_peers(&base, &candidate), []);
    }

    #[test]
    fn added_peer() {
        let sections = diff_bgp_peers(&[], &[peer(1, "pg1")]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].header, "peer 192.0.2.1");
        assert_eq!(sections[0].status, DiffStatus::Added);
    }

    #[test]
    fn removed_peer() {
        let sections = diff_bgp_peers(&[peer(1, "pg1")], &[]);
        assert_eq!(sections[0].status, DiffStatus::Removed);
    }

    #[test]
    fn repointed_peer_group_is_modified() {
        let base = vec![peer(1, "pg1")];
        let candidate = vec![peer(1, "pg2")];
        let sections = diff_bgp_peers(&base, &candidate);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].status, DiffStatus::Modified);
        assert_eq!(sections[0].fields[0].old.as_deref(), Some("pg1"));
        assert_eq!(sections[0].fields[0].new.as_deref(), Some("pg2"));
    }

    #[test]
    fn shutdown_change_is_modified() {
        let mut shut = peer(1, "pg1");
        shut.shutdown = Some(crate::schema::BgpShutdown {
            message: Some("maint".to_string()),
        });
        let sections = diff_bgp_peers(&[peer(1, "pg1")], &[shut]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].fields[0].label, "shutdown");
        assert_eq!(
            sections[0].fields[0].new.as_deref(),
            Some("yes, message \"maint\"")
        );
    }
}
