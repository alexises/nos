use std::fmt::Write as _;

use crate::schema::{
    AddressFamily, BgpAoAlgorithm, BgpAuth, BgpPeerGroup, BgpShutdown, SourceAddress,
};

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

/// Shared with `bgp_peer.rs`, whose `shutdown` renders identically.
pub(super) fn shutdown_str(s: Option<&BgpShutdown>) -> String {
    match s {
        None => "no".to_string(),
        Some(BgpShutdown { message: None }) => "yes".to_string(),
        Some(BgpShutdown { message: Some(m) }) => format!("yes, message \"{m}\""),
    }
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

fn mrai_str(pg: &BgpPeerGroup) -> String {
    pg.mrai
        .map_or_else(|| "default (0s, unpaced)".to_string(), |m| m.to_string())
}

fn route_refresh_stale_time_str(pg: &BgpPeerGroup) -> String {
    pg.route_refresh_stale_time.map_or_else(
        || {
            format!(
                "default ({}s)",
                crate::schema::ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS
            )
        },
        |s| s.to_string(),
    )
}

fn damping_str(pg: &BgpPeerGroup) -> String {
    pg.damping.map_or_else(
        || "unset".to_string(),
        |d| {
            format!(
                "half-life {} reuse {} suppress {} max-suppress {}",
                d.half_life, d.reuse, d.suppress, d.max_suppress
            )
        },
    )
}

fn local_as_str(pg: &BgpPeerGroup) -> String {
    pg.local_as.map_or_else(
        || "unset".to_string(),
        |l| {
            let mut s = l.asn.to_string();
            if l.no_prepend {
                s.push_str(" no-prepend");
            }
            if l.replace_as {
                s.push_str(" replace-as");
            }
            s
        },
    )
}

fn prefix_limit_str(l: Option<crate::schema::BgpPrefixLimit>) -> String {
    l.map_or_else(
        || "unset".to_string(),
        |l| {
            let mut s = format!("limit {}", l.limit);
            if l.warning_only {
                s.push_str(" warning-only");
            }
            if l.restart_interval > 0 {
                let _ = write!(s, " restart-interval {}", l.restart_interval);
            }
            s
        },
    )
}

fn max_hops_str(pg: &BgpPeerGroup) -> String {
    pg.max_hops
        .map_or_else(|| "unset".to_string(), |h| h.to_string())
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
    if base.mrai != candidate.mrai {
        fields.push(FieldDiff {
            label: "mrai".to_string(),
            old: Some(mrai_str(base)),
            new: Some(mrai_str(candidate)),
        });
    }
    if base.route_refresh_stale_time != candidate.route_refresh_stale_time {
        fields.push(FieldDiff {
            label: "route-refresh-stale-time".to_string(),
            old: Some(route_refresh_stale_time_str(base)),
            new: Some(route_refresh_stale_time_str(candidate)),
        });
    }
    if base.damping != candidate.damping {
        fields.push(FieldDiff {
            label: "damping".to_string(),
            old: Some(damping_str(base)),
            new: Some(damping_str(candidate)),
        });
    }
    if base.max_hops != candidate.max_hops {
        fields.push(FieldDiff {
            label: "max-hops".to_string(),
            old: Some(max_hops_str(base)),
            new: Some(max_hops_str(candidate)),
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
    if base.shutdown != candidate.shutdown {
        fields.push(FieldDiff {
            label: "shutdown".to_string(),
            old: Some(shutdown_str(base.shutdown.as_ref())),
            new: Some(shutdown_str(candidate.shutdown.as_ref())),
        });
    }
    if base.announce_rpki_state != candidate.announce_rpki_state {
        let yes_no = |b: bool| if b { "yes" } else { "no" }.to_string();
        fields.push(FieldDiff {
            label: "announce-rpki-state".to_string(),
            old: Some(yes_no(base.announce_rpki_state)),
            new: Some(yes_no(candidate.announce_rpki_state)),
        });
    }
    if base.local_as != candidate.local_as {
        fields.push(FieldDiff {
            label: "local-as".to_string(),
            old: Some(local_as_str(base)),
            new: Some(local_as_str(candidate)),
        });
    }
    if base.add_path != candidate.add_path {
        let mode = |pg: &BgpPeerGroup| pg.add_path.map_or("unset", |m| m.as_str()).to_string();
        fields.push(FieldDiff {
            label: "add-path".to_string(),
            old: Some(mode(base)),
            new: Some(mode(candidate)),
        });
    }
    if base.add_path_send_count != candidate.add_path_send_count {
        let count = |pg: &BgpPeerGroup| {
            pg.add_path_send_count
                .map_or("unset".to_string(), |n| n.to_string())
        };
        fields.push(FieldDiff {
            label: "add-path-send-count".to_string(),
            old: Some(count(base)),
            new: Some(count(candidate)),
        });
    }
    for af in crate::schema::AddressFamily::ALL {
        let (old, new) = (
            base.maximum_prefix.get(af),
            candidate.maximum_prefix.get(af),
        );
        if old != new {
            fields.push(FieldDiff {
                label: format!("maximum-prefix {af}"),
                old: Some(prefix_limit_str(old)),
                new: Some(prefix_limit_str(new)),
            });
        }
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
                label: "mrai".to_string(),
                old: Some(mrai_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "route-refresh-stale-time".to_string(),
                old: Some(route_refresh_stale_time_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "damping".to_string(),
                old: Some(damping_str(pg)),
                new: None,
            },
            FieldDiff {
                label: "max-hops".to_string(),
                old: Some(max_hops_str(pg)),
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
                label: "mrai".to_string(),
                old: None,
                new: Some(mrai_str(pg)),
            },
            FieldDiff {
                label: "route-refresh-stale-time".to_string(),
                old: None,
                new: Some(route_refresh_stale_time_str(pg)),
            },
            FieldDiff {
                label: "damping".to_string(),
                old: None,
                new: Some(damping_str(pg)),
            },
            FieldDiff {
                label: "max-hops".to_string(),
                old: None,
                new: Some(max_hops_str(pg)),
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
            add_path: None,
            add_path_send_count: None,
        }
    }

    #[test]
    fn no_changes_produces_no_sections() {
        let base = vec![group("pg1", 65000)];
        let candidate = base.clone();
        assert_eq!(diff_bgp_peer_groups(&base, &candidate), []);
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

    fn ao_key(
        send_id: u8,
        algorithm: BgpAoAlgorithm,
        current: bool,
        rnext: bool,
    ) -> crate::schema::BgpAoKey {
        crate::schema::BgpAoKey {
            send_id,
            recv_id: send_id,
            algorithm,
            key: "k".to_string(),
            is_current: current,
            is_rnext: rnext,
            exclude_options: false,
        }
    }

    #[test]
    fn every_changed_field_is_listed_with_old_and_new() {
        let base = group("pg1", 65000);
        let candidate = BgpPeerGroup {
            source_address: Some(SourceAddress::Interface {
                interface: "eth0".to_string(),
                label: None,
            }),
            address_families: Vec::new(),
            hold_time: Some(30),
            keepalive_interval: Some(10),
            connect_retry_time: Some(3),
            mrai: Some(5),
            route_refresh_stale_time: Some(0),
            damping: Some(crate::schema::BgpDamping {
                half_life: 900,
                reuse: 750,
                suppress: 2000,
                max_suppress: 3600,
            }),
            max_hops: Some(1),
            auth: Some(BgpAuth::Ao {
                keys: vec![
                    ao_key(1, BgpAoAlgorithm::HmacSha1_96, true, true),
                    ao_key(2, BgpAoAlgorithm::AesCmac96, true, false),
                    ao_key(3, BgpAoAlgorithm::AesCmac96, false, true),
                    ao_key(4, BgpAoAlgorithm::AesCmac96, false, false),
                ],
            }),
            import_policy: Some("in".to_string()),
            export_policy: Some("out".to_string()),
            shutdown: Some(BgpShutdown { message: None }),
            announce_rpki_state: true,
            local_as: Some(crate::schema::BgpLocalAs {
                asn: 65009,
                no_prepend: true,
                replace_as: true,
            }),
            add_path: Some(crate::schema::BgpAddPath::Receive),
            add_path_send_count: Some(4),
            maximum_prefix: crate::schema::BgpMaximumPrefix {
                ipv4: Some(crate::schema::BgpPrefixLimit {
                    limit: 2,
                    warning_only: true,
                    restart_interval: 5,
                }),
                l2vpn_evpn: Some(crate::schema::BgpPrefixLimit {
                    limit: 9,
                    ..Default::default()
                }),
                ipv6: None,
            },
            ..base.clone()
        };
        let sections = diff_bgp_peer_groups(std::slice::from_ref(&base), &[candidate]);
        let fields: Vec<(&str, &str, &str)> = sections[0]
            .fields
            .iter()
            .map(|f| {
                (
                    f.label.as_str(),
                    f.old.as_deref().unwrap(),
                    f.new.as_deref().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            fields,
            [
                ("source-address", "unset", "interface eth0"),
                ("address-family", "ipv4", "none"),
                ("hold-time", "default (90s)", "30"),
                ("keepalive-interval", "default (hold-time / 3)", "10"),
                ("connect-retry-time", "default (120s)", "3"),
                ("mrai", "default (0s, unpaced)", "5"),
                ("route-refresh-stale-time", "default (360s)", "0"),
                ("damping", "unset", "half-life 900 reuse 750 suppress 2000 max-suppress 3600"),
                ("max-hops", "unset", "1"),
                (
                    "auth",
                    "none",
                    "ao-keys [send-id 1 hmac-sha1 k (current, rnext), send-id 2 aes-cmac k (current), \
                     send-id 3 aes-cmac k (rnext), send-id 4 aes-cmac k]"
                ),
                ("import-policy", nos_rpl::DENY_ALL_NAME, "in"),
                ("export-policy", nos_rpl::DENY_ALL_NAME, "out"),
                ("shutdown", "no", "yes"),
                ("announce-rpki-state", "no", "yes"),
                ("local-as", "unset", "65009 no-prepend replace-as"),
                ("add-path", "unset", "receive"),
                ("add-path-send-count", "unset", "4"),
                (
                    "maximum-prefix ipv4",
                    "unset",
                    "limit 2 warning-only restart-interval 5"
                ),
                ("maximum-prefix l2vpn-evpn", "unset", "limit 9"),
            ]
        );
        // md5 and a shutdown message render too.
        let md5 = BgpPeerGroup {
            auth: Some(BgpAuth::Md5 {
                password: "pw".to_string(),
            }),
            shutdown: Some(BgpShutdown {
                message: Some("bye".to_string()),
            }),
            ..base.clone()
        };
        let sections = diff_bgp_peer_groups(&[base], &[md5]);
        let new: Vec<_> = sections[0]
            .fields
            .iter()
            .map(|f| f.new.clone().unwrap())
            .collect();
        assert_eq!(new, ["md5-password pw", "yes, message \"bye\""]);
    }
}
