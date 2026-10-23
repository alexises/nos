use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `NOS_TC_CAPTURE=1 unshare -Urn .../kernel --ignored --nocapture psample`
/// on Linux 7.2 (x86-64): the `FAMILY_REPLY` and `SAMPLE_MSG` lines.
const FAMILY_REPLY: &str = "8c000000100000000100000052ce1200010200000c0002007073616d706c6500060001002c0000000800030001000000080004000000000008000500100000001800060014000100080001000100000008000200040000003400070018000100080002001e0000000b000100636f6e666967000018000200080002001f0000000c0001007061636b65747300";
const SAMPLE_MSG: &str = "900000002c00000000000000000000000001000006000100040000000800050001000000080002003100000008000300534f4e0008000400000000000c000d009c12112f682ce11806000e000008000035000600020000000102020000000101080045000023704f400040117609c6336401c6336409c1d01770000f54927073616d706c6500000008000f0000000001";

#[test]
fn family_request_bytes() {
    let m = family_request("psample", 1);
    assert_eq!(m.len(), 32);
    assert_eq!(u32_at(&m, 0), 32);
    assert_eq!(u16_at(&m, 4), GENL_ID_CTRL);
    assert_eq!(&m[16..20], &[CTRL_CMD_GETFAMILY, 1, 0, 0]);
    assert_eq!(&m[24..32], b"psample\0");
}

#[test]
fn a_captured_family_reply_names_the_packets_group() {
    let p = psample_reply(&unhex(FAMILY_REPLY)).unwrap();
    assert_eq!(
        p,
        Psample {
            family: 44,
            group: 31,
            user_cookie: true
        }
    );
}

/// A reply built from `(type, payload)` attributes.
fn reply(attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (k, v) in attrs {
        nla(&mut body, *k, v);
    }
    let mut m = Vec::new();
    m.extend_from_slice(&u32::try_from(HEADER + body.len()).unwrap().to_ne_bytes());
    m.extend_from_slice(&GENL_ID_CTRL.to_ne_bytes());
    m.extend_from_slice(&[0; 10]);
    m.extend_from_slice(&[1, 2, 0, 0]);
    m.extend_from_slice(&body);
    m
}

fn group(name: &str, id: u32) -> Vec<u8> {
    let mut g = Vec::new();
    nla(&mut g, CTRL_ATTR_MCAST_GRP_NAME, &cstr(name));
    nla(&mut g, CTRL_ATTR_MCAST_GRP_ID, &id.to_ne_bytes());
    let mut list = Vec::new();
    nla(&mut list, 1, &g);
    list
}

#[test]
fn an_old_kernel_has_no_user_cookie() {
    let r = reply(&[
        (CTRL_ATTR_FAMILY_ID, 30u16.to_ne_bytes().to_vec()),
        (CTRL_ATTR_MAXATTR, 14u32.to_ne_bytes().to_vec()),
        (CTRL_ATTR_MCAST_GROUPS, group("packets", 9)),
    ]);
    let p = psample_reply(&r).unwrap();
    assert_eq!((p.family, p.group, p.user_cookie), (30, 9, false));
}

#[test]
fn a_missing_group_family_or_family_id_is_an_error() {
    let no_group = reply(&[
        (CTRL_ATTR_FAMILY_ID, 30u16.to_ne_bytes().to_vec()),
        (CTRL_ATTR_MCAST_GROUPS, group("config", 9)),
    ]);
    let e = psample_reply(&no_group).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
    assert!(psample_reply(&reply(&[])).is_err(), "no family id");
    assert!(psample_reply(&[]).is_err(), "empty");
    assert!(psample_reply(&reply(&[])[..18]).is_err(), "short");
    // NLMSG_ERROR -ENOENT: the module is not loaded.
    let mut err = vec![0u8; 36];
    err[..4].copy_from_slice(&36u32.to_ne_bytes());
    err[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    err[16..20].copy_from_slice(&(-2i32).to_ne_bytes());
    assert_eq!(psample_reply(&err).unwrap_err().raw_os_error(), Some(2));
}

#[test]
fn a_captured_egress_sample() {
    let s = samples(&unhex(SAMPLE_MSG), 44).unwrap();
    assert_eq!(s.len(), 1);
    let s = &s[0];
    assert_eq!((s.group, s.in_ifindex, s.out_ifindex), (0x4e_4f53, 0, 4));
    assert_eq!(s.cookie.as_deref(), Some(&[0, 0, 0, 1][..]));
    assert_eq!(s.data.len(), 49);
    assert_eq!(&s.data[12..14], &[8, 0]);
}

#[test]
fn other_families_commands_and_short_messages_are_skipped() {
    let buf = unhex(SAMPLE_MSG);
    assert!(samples(&buf, 45).unwrap().is_empty(), "other family");
    let mut cmd = buf.clone();
    cmd[16] = 1;
    assert!(samples(&cmd, 44).unwrap().is_empty(), "other command");
    let mut short = buf[..16].to_vec();
    short[..4].copy_from_slice(&16u32.to_ne_bytes());
    assert!(samples(&short, 44).unwrap().is_empty(), "no genl header");
    assert!(samples(&buf[..40], 44).is_err(), "truncated");
    // No cookie (an old kernel) and a 4-byte ifindex.
    let mut body = Vec::new();
    nla(&mut body, PSAMPLE_ATTR_IIFINDEX, &7u32.to_ne_bytes());
    nla(&mut body, PSAMPLE_ATTR_OIFINDEX, &[1]);
    let mut m = Vec::new();
    m.extend_from_slice(&u32::try_from(HEADER + body.len()).unwrap().to_ne_bytes());
    m.extend_from_slice(&44u16.to_ne_bytes());
    m.extend_from_slice(&[0; 14]);
    m.extend_from_slice(&body);
    let s = samples(&m, 44).unwrap();
    assert_eq!((s[0].in_ifindex, s[0].out_ifindex), (7, 0));
    assert_eq!((s[0].cookie.clone(), s[0].data.len()), (None, 0));
}
