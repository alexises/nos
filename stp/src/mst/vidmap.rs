//! The VID to MSTID table derived from the config (pure). A domain's VID is
//! its dot1q tag (an untagged-only membership is VID 1, the native VLAN, as
//! the commit check of `spanning-tree` has it); its MSTID is its
//! `stp-instance` (unset: 0, the CIST). Every VID no domain owns maps to 0.
//! The commit check already guarantees one VID per domain and one domain per VID.

use nos_proto::{Config, VlanTag};

use super::digest::VidTable;

/// `(domain, vid, mstid)` of every domain a switching profile uses, sorted by VID.
pub fn domains(cfg: &Config) -> Vec<(String, u16, u16)> {
    let profiles = cfg
        .interfaces
        .iter()
        .filter_map(|i| i.switching_profile.as_ref())
        .chain(
            cfg.port_aggregates
                .iter()
                .filter_map(|a| a.switching_profile.as_ref()),
        );
    let mut v: Vec<(String, u16, u16)> = Vec::new();
    for sp in profiles.filter_map(|n| cfg.switching_profiles.iter().find(|p| &p.name == n)) {
        for m in &sp.members {
            if v.iter().any(|(d, ..)| *d == m.broadcast_domain) {
                continue;
            }
            let vid = match m.tag {
                VlanTag::Untagged => 1,
                VlanTag::Dot1q(n) => n,
            };
            let mstid = cfg
                .broadcast_domains
                .iter()
                .find(|d| d.name == m.broadcast_domain)
                .and_then(|d| d.stp_instance)
                .unwrap_or(0);
            v.push((m.broadcast_domain.clone(), vid, mstid));
        }
    }
    v.sort_by_key(|&(_, vid, _)| vid);
    v
}

pub fn table(domains: &[(String, u16, u16)]) -> Box<VidTable> {
    let mut t = Box::new([0; 4096]);
    for &(_, vid, mstid) in domains {
        if let Some(e) = t.get_mut(usize::from(vid)) {
            *e = mstid;
        }
    }
    t
}

/// `10,20-30` for the VIDs mapped to `mstid`; empty when none.
pub fn ranges(domains: &[(String, u16, u16)], mstid: u16) -> String {
    let mut vids: Vec<u16> = domains
        .iter()
        .filter(|d| d.2 == mstid)
        .map(|d| d.1)
        .collect();
    vids.sort_unstable();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < vids.len() {
        let mut j = i;
        while j + 1 < vids.len() && vids[j + 1] == vids[j] + 1 {
            j += 1;
        }
        out.push(if j == i {
            vids[i].to_string()
        } else {
            format!("{}-{}", vids[i], vids[j])
        });
        i = j + 1;
    }
    out.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::{BroadcastDomain, Interface, SwitchingProfile, SwitchingProfileMember};

    type Member<'a> = (&'a str, VlanTag, Option<u16>);

    fn cfg(members: &[Member]) -> Config {
        Config {
            broadcast_domains: members
                .iter()
                .map(|&(n, _, inst)| BroadcastDomain {
                    name: n.into(),
                    stp_instance: inst,
                    ..Default::default()
                })
                .collect(),
            switching_profiles: vec![SwitchingProfile {
                name: "sw".into(),
                members: members
                    .iter()
                    .map(|&(n, tag, _)| SwitchingProfileMember {
                        broadcast_domain: n.into(),
                        tag,
                        ..Default::default()
                    })
                    .collect(),
            }],
            interfaces: vec![Interface {
                name: "eth1".into(),
                switching_profile: Some("sw".into()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn tag_is_the_vid_and_instance_the_mstid() {
        let c = cfg(&[
            ("bd2", VlanTag::Dot1q(20), Some(2)),
            ("bd1", VlanTag::Dot1q(10), Some(1)),
        ]);
        let d = domains(&c);
        assert_eq!(d, [("bd1".into(), 10, 1), ("bd2".into(), 20, 2)]);
        let t = table(&d);
        assert_eq!((t[10], t[20], t[11]), (1, 2, 0), "unmapped VIDs are CIST");
        assert_eq!(ranges(&d, 1), "10");
    }

    #[test]
    fn untagged_only_is_vid_1_and_no_instance_is_the_cist() {
        let d = domains(&cfg(&[("d", VlanTag::Untagged, None)]));
        assert_eq!(d, [("d".into(), 1, 0)]);
        assert_eq!(table(&d)[1], 0);
        assert_eq!(ranges(&d, 0), "1");
    }

    #[test]
    fn ranges_merge_consecutive_vids() {
        let d: Vec<_> = [10, 11, 12, 20, 30, 31]
            .iter()
            .map(|&v| (format!("d{v}"), v, 3))
            .collect();
        assert_eq!(ranges(&d, 3), "10-12,20,30-31");
        assert_eq!(ranges(&d, 4), "");
    }

    #[test]
    fn input_order_does_not_change_the_table() {
        let a: [Member; 2] = [
            ("a", VlanTag::Dot1q(5), Some(1)),
            ("b", VlanTag::Dot1q(6), Some(2)),
        ];
        let b = [a[1], a[0]];
        assert_eq!(table(&domains(&cfg(&a))), table(&domains(&cfg(&b))));
    }
}
