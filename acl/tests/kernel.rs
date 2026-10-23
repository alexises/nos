//! `LinuxDriver` against the real kernel, `tc` as the oracle: needs
//! `CAP_NET_ADMIN`, so run it in a throwaway netns:
//! `unshare -Urn cargo test -p nos-acl --test kernel -- --ignored`.
#![allow(
    clippy::disallowed_types,
    reason = "test code: `ip`/`tc` are the independent oracle for the driver (#228)"
)]

use std::process::Command;

use nos_acl::compile::compile;
use nos_acl::driver::{Direction, Driver, LinuxDriver, ACL_CHAIN_A, ACL_CHAIN_B};
use nos_proto::schema::{Acl, AclAction, AclProtocol, AclRule, PortRange};

fn run(args: &[&str]) -> String {
    let o = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn idx(name: &str) -> u32 {
    run(&["ip", "-o", "link", "show", name])
        .split(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn show(dev: &str, hook: &str, chain: u32) -> String {
    run(&[
        "tc",
        "filter",
        "show",
        "dev",
        dev,
        hook,
        "chain",
        &chain.to_string(),
    ])
}

fn acl(rules: Vec<AclRule>) -> Acl {
    Acl {
        name: "E".into(),
        default_action: AclAction::Permit,
        rules,
    }
}

#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
fn attach_replace_detach_leave_foreign_filters() {
    run(&["ip", "link", "add", "acl0", "type", "dummy"]);
    run(&["ip", "link", "set", "acl0", "up"]);
    let i = idx("acl0");
    // A foreign owner's clsact and prio-1 filter (as nos-interfaced's BPDU trap).
    run(&["tc", "qdisc", "add", "dev", "acl0", "clsact"]);
    run(&[
        "tc", "filter", "add", "dev", "acl0", "ingress", "prio", "1", "protocol", "arp", "flower",
        "action", "drop",
    ]);
    let mut d = LinuxDriver;
    assert_eq!(d.live_chain(i, Direction::In).unwrap(), None);

    let deny_bgp = AclRule {
        name: "d-bgp".into(),
        action: AclAction::Deny,
        protocol: Some(AclProtocol::Tcp),
        destination_port: Some(PortRange {
            start: 179,
            end: 179,
        }),
        ..Default::default()
    };
    let established = AclRule {
        name: "est".into(),
        action: AclAction::Permit,
        protocol: Some(AclProtocol::Tcp),
        source: Some("10.0.0.0/8".parse().unwrap()),
        source_port: Some(PortRange {
            start: 1000,
            end: 2000,
        }),
        established: true,
        ..Default::default()
    };
    let one = compile(&acl(vec![deny_bgp.clone()])).unwrap();
    d.install(i, Direction::In, ACL_CHAIN_A, &one).unwrap();
    d.switch(i, Direction::In, ACL_CHAIN_A).unwrap();
    let entry = show("acl0", "ingress", 0);
    assert!(
        entry.contains("pref 100") && entry.contains("goto chain 1000"),
        "{entry}"
    );
    let chain = show("acl0", "ingress", ACL_CHAIN_A);
    assert!(
        chain.contains("dst_port 179") && chain.contains("drop"),
        "{chain}"
    );
    assert_eq!(d.live_chain(i, Direction::In).unwrap(), Some(ACL_CHAIN_A));

    let two = compile(&acl(vec![established, deny_bgp])).unwrap();
    d.install(i, Direction::In, ACL_CHAIN_B, &two).unwrap();
    d.switch(i, Direction::In, ACL_CHAIN_B).unwrap();
    d.flush(i, Direction::In, ACL_CHAIN_A).unwrap();
    assert!(show("acl0", "ingress", 0).contains("goto chain 1001"));
    assert_eq!(show("acl0", "ingress", ACL_CHAIN_A), "");
    let chain = show("acl0", "ingress", ACL_CHAIN_B);
    assert!(
        chain.contains("tcp_flags 0x10/10") && chain.contains("tcp_flags 0x4/4"),
        "{chain}"
    );
    assert!(chain.contains("src_port 1000-2000"), "{chain}");
    assert_eq!(d.live_chain(i, Direction::In).unwrap(), Some(ACL_CHAIN_B));
    // Flushing an empty chain again is fine.
    d.flush(i, Direction::In, ACL_CHAIN_A).unwrap();

    // Egress is independent.
    d.install(i, Direction::Out, ACL_CHAIN_A, &one).unwrap();
    d.switch(i, Direction::Out, ACL_CHAIN_A).unwrap();
    assert!(show("acl0", "egress", 0).contains("goto chain 1000"));
    d.detach(i, Direction::Out).unwrap();
    assert_eq!(show("acl0", "egress", 0), "");

    d.detach(i, Direction::In).unwrap();
    let left = show("acl0", "ingress", 0);
    assert!(
        left.contains("pref 1 ") && !left.contains("pref 100"),
        "{left}"
    );
    assert_eq!(show("acl0", "ingress", ACL_CHAIN_B), "");
    assert_eq!(d.live_chain(i, Direction::In).unwrap(), None);
    // Detaching twice is fine; the qdisc stays.
    d.detach(i, Direction::In).unwrap();
    assert!(run(&["tc", "qdisc", "show", "dev", "acl0"]).contains("clsact"));
    run(&["ip", "link", "del", "acl0"]);
}
