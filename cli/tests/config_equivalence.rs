//! Equivalence harness for the generic config grammar (#109, 2 of 3):
//! every config line the legacy parser's tests use, in every navigation
//! position, from two fixtures (populated and empty). Wherever the legacy
//! pipeline (`Command::parse` → `session::resolve` → `ConfigOp::apply`)
//! makes an edit, the tree grammar (`config_grammar::parse` → its
//! `SetTransactionPath` writes through `config_path::set`) must make the
//! same one — the same resulting `Config`, and for `edit` the same
//! navigation. A line the legacy parser can't parse must be rejected too.

use nos_cli::command::Command;
use nos_cli::config_grammar;
use nos_cli::session::{resolve, Mode, Path, PathAfter, Resolved};
use nos_cli::spec::{ArgKind, Token, COMMAND_SPECS};
use nos_proto::schema::*;
use nos_proto::{config_path, Config};

/// Every distinct `edit`/`set`/`delete` line in `command.rs`'s tests.
const CORPUS: &[&str] = &[
    "set shutdown planned maintenance",
    "set peer 192.0.2.1 shutdown",
    "delete shutdown",
    "delete bgp instance r1 peer 192.0.2.1 shutdown",
    "set max-hops 1",
    "delete max-hops",
    "set damping suppress 2000 half-life 30",
    "delete damping",
    "set mrai 30",
    "delete mrai",
    "edit port-aggregate bond1",
    "set port-aggregate bond1 mode xor",
    "set mode xor",
    "set interface eth0 port-aggregate bond1",
    "set port-aggregate bond1",
    "delete interface eth0 port-aggregate",
    "delete port-aggregate",
    "delete port-aggregate bond1",
    "set interface eth1 lldp transmit",
    "set lldp receive",
    "delete interface eth1 lldp receive",
    "delete lldp transmit",
    "set lldp both",
    "set port-aggregate bond1 lacp-rate fast",
    "set lacp-rate slow",
    "set lacp-rate medium",
    "set port-aggregate bond1 redundancy-mode single-active",
    "set redundancy-mode all-active",
    "set redundancy-mode both",
    "set source line 2     accept",
    "set source line 5         set this.bgp.local_pref = 150",
    "set source line 3",
    "set source line abc accept",
    "delete source line 4",
    "edit policy-definition p1",
    "edit source",
    "set import-policy accept-all",
    "set export-policy deny-all",
    "delete import-policy",
    "delete export-policy",
    "edit bgp instance R1",
    "set bgp instance R1 asn 65001",
    "set bgp instance R1 router-id 10.0.0.1",
    "set bgp instance R1 asn abc",
    "set asn 65001",
    "set router-id 10.0.0.1",
    "set router-id not-an-ip",
    "set interface eth1 lldp destination customer-bridge",
    "set lldp destination non-tpmr",
    "set lldp destination bogus",
    "set lldp tx-interval 5",
    "set lldp tx-hold 3",
    "set lldp management-address 2001:db8::1",
    "set lldp tx-interval fast",
    "delete interface eth1 lldp destination",
    "delete lldp destination",
    "delete lldp management-address",
    "set hostname router1",
    "set user alice password s3cret",
    "delete user alice",
    "delete",
    "delete bgp instance R1",
    "edit bgp instance R1 peer-group PG1",
    "edit peer-group PG1",
    "set bgp instance R1 peer-group PG1 remote-as 65001",
    "set bgp instance R1 peer-group PG1 source-address interface eth0",
    "set bgp instance R1 peer-group PG1 source-address interface eth0 label mgmt",
    "set bgp instance R1 peer-group PG1 source-address loopback",
    "set bgp instance R1 peer-group PG1 source-address loopback label mgmt",
    "set source-address interface eth0",
    "set source-address interface eth0 label mgmt",
    "set source-address loopback",
    "set source-address loopback label mgmt",
    "set bgp instance R1 peer-group PG1 address-family ipv4",
    "set bgp instance R1 peer-group PG1 address-family ipv6",
    "set bgp instance R1 peer-group PG1 hold-time 30",
    "set bgp instance R1 peer-group PG1 keepalive-interval 10",
    "set bgp instance R1 peer-group PG1 connect-retry-time 45",
    "set bgp instance R1 peer-group PG1 next-hop self",
    "set bgp instance R1 peer-group PG1 next-hop unchanged",
    "set next-hop self",
    "set next-hop unchanged",
    "delete next-hop",
    "set bgp instance R1 peer-group PG1 route-reflector-client",
    "set bgp instance R1 peer-group PG1 route-server-client",
    "set route-reflector-client",
    "set route-server-client",
    "delete route-reflector-client",
    "delete route-server-client",
    "set bgp instance R1 cluster-id 1.2.3.4",
    "delete bgp instance R1 cluster-id",
    "set cluster-id 1.2.3.4",
    "delete cluster-id",
    "set hold-time 30",
    "set keepalive-interval 10",
    "set connect-retry-time 45",
    "delete hold-time",
    "delete keepalive-interval",
    "delete connect-retry-time",
    "set ospf instance o1 area 0.0.0.0 profile p1 hello-interval 5",
    "set ospf instance o1 area 0.0.0.0 profile p1 dead-interval 20",
    "set ospf instance o1 area 0.0.0.0 profile p1 cost 15",
    "set ospf instance o1 area 0.0.0.0 profile p1 priority 200",
    "set ospf instance o1 area 0.0.0.0 profile p1 network-type point-to-point",
    "set ospf instance o1 area 0.0.0.0 profile p1 network-type broadcast",
    "set hello-interval 5",
    "set dead-interval 20",
    "set cost 15",
    "set priority 200",
    "set network-type point-to-point",
    "set network-type broadcast",
    "delete hello-interval",
    "delete dead-interval",
    "delete cost",
    "delete priority",
    "delete network-type",
    "set ospf instance o1 area 0.0.0.0 profile p1 simple-password hunter2",
    "set simple-password hunter2",
    "set ospf instance o1 area 0.0.0.0 profile p1 crypto-key 1 hmac-sha256 secret",
    "set crypto-key 1 md5 secret",
    "set crypto-key 1 rot13 secret",
    "set crypto-key 1 current",
    "set ospf instance o1 area 0.0.0.0 profile p1 crypto-key 1 current",
    "delete crypto-key 1",
    "set bgp instance R1 peer-group PG1 md5-password hunter2",
    "set md5-password hunter2",
    "set bgp instance R1 peer-group PG1 ao-key 1 2 hmac-sha1 secret",
    "set ao-key 1 2 aes-cmac secret",
    "set ao-key 1 2 rot13 secret",
    "set ao-key 1 current",
    "set bgp instance R1 peer-group PG1 ao-key 1 rnext",
    "delete auth",
    "delete ao-key 1",
    "set remote-as 65001",
    "set bgp instance R1 peer 192.0.2.1 peer-group PG1",
    "set peer 192.0.2.1 peer-group PG1",
    "delete bgp instance R1 peer-group PG1",
    "delete peer-group PG1",
    "delete bgp instance R1 peer 192.0.2.1",
    "delete peer 192.0.2.1",
    "edit routing-table rt1",
    "edit static-routing-instance sri1",
    "set routing-table rt1 bgp-instance r1",
    "set bgp-instance r1",
    "set routing-table rt1 static-routing-instance sri1",
    "set static-routing-instance sri1",
    "set routing-table rt1 redistribute from static to bgp",
    "set redistribute from static to bgp",
    "set routing-table rt1 redistribute from static to bgp policy p1",
    "set redistribute from static to bgp policy p1",
    "set routing-table rt1 redistribute from static to ospf",
    "set redistribute from static to ospf",
    "set routing-table rt1 redistribute from static to ospf policy p1",
    "set redistribute from static to ospf policy p1",
    "set static-routing-instance sri1 route 10.0.0.0/24 gateway 10.0.0.1",
    "set route 10.0.0.0/24 gateway 10.0.0.1",
    "set route not-a-subnet gateway 10.0.0.1",
    "delete routing-table rt1",
    "delete routing-table rt1 bgp-instance",
    "delete bgp-instance",
    "delete routing-table rt1 static-routing-instance",
    "delete static-routing-instance",
    "delete routing-table rt1 redistribute",
    "delete redistribute",
    "delete static-routing-instance sri1",
    "delete static-routing-instance sri1 route 10.0.0.0/24",
    "delete route 10.0.0.0/24",
    "delete source-address",
    "delete address-family ipv4",
    "delete address-family ipv6",
    "delete address-family l2vpn-evpn",
    "set address-family l2vpn-evpn",
    "set bgp instance R1 peer-group PG1 address-family l2vpn-evpn",
    "edit interface eth0",
    "set interface eth0 address 10.0.0.1/24",
    "set address 10.0.0.1/24",
    "set interface eth0 address 10.0.0.1/24 label mgmt",
    "set address 10.0.0.1/24 label mgmt",
    "set interface eth0 address not-a-cidr",
    "set interface eth0 routing-table rt1",
    "set routing-table rt1",
    "set interface eth0 mtu 9000",
    "set mtu 9000",
    "set ospf instance o1 area 0.0.0.0 profile p1 mtu 1400",
    "set ospf instance o1 area 0.0.0.0 profile p1 extended-sequence-numbers enable",
    "set interface eth0 switching-profile sp1",
    "set switching-profile sp1",
    "edit ospf instance o1 area 0.0.0.0",
    "edit area 0.0.0.0",
    "edit ospf instance o1 area 0.0.0.0 profile p1",
    "edit profile p1",
    "set interface eth0 ospf p1",
    "set ospf p1",
    "delete ospf instance o1 area 0.0.0.0",
    "delete area 0.0.0.0",
    "delete ospf instance o1 area 0.0.0.0 profile p1",
    "delete profile p1",
    "delete interface eth0 ospf",
    "delete ospf",
    "delete interface eth0",
    "delete interface eth0 address 10.0.0.1/24",
    "delete address 10.0.0.1/24",
    "delete interface eth0 routing-table",
    "delete routing-table",
    "delete interface eth0 mtu",
    "delete mtu",
    "delete interface eth0 switching-profile",
    "delete switching-profile",
    "edit community-alias CUSTOMER_A",
    "edit community-group CUSTOMERS",
    "edit prefix-list BLOCKS",
    "set community-alias CUSTOMER_A value 65000:100",
    "set value 65000:100",
    "edit as-path-list TRANSIT",
    "set as-path-list TRANSIT pattern ^65001_",
    "delete pattern ^65001_",
    "set community-group CUSTOMERS member CUSTOMER_A",
    "set member 65000:200",
    "set prefix-list BLOCKS entry 10.0.0.0/8 orlonger",
    "set entry 10.0.0.0/8 upto 24",
    "set prefix-list BLOCKS entry 10.0.0.0/8",
    "set prefix-list BLOCKS entry 10.0.0.0/8 range 24 32",
    "set entry 10.0.0.0/8",
    "set entry 10.0.0.0/8 range 24 32",
    "set prefix-list BLOCKS entry not-a-cidr",
    "set entry 10.0.0.0/8 range not-a-number 32",
    "delete community-alias CUSTOMER_A",
    "delete community-group CUSTOMERS member CUSTOMER_A",
    "delete member CUSTOMER_A",
    "delete prefix-list BLOCKS",
    "delete prefix-list BLOCKS entry 10.0.0.0/8 range 24 32",
    "delete entry 10.0.0.0/8",
    "set ospfv3 instance o1 area 0.0.0.0 profile p1 crypto-key 300 hmac-sha256 secret",
    "set ospfv3 instance o1 area 0.0.0.0 profile p1 crypto-key 65535 current",
    "delete crypto-key 65536",
    "edit ospfv3 instance o1",
    "edit ospfv3 instance o1 area 0.0.0.0",
    "edit ospfv3 instance o1 area 0.0.0.0 profile p1",
    "set ospfv3 instance o1 extended-lsa",
    "delete ospfv3 instance o1 extended-lsa",
    "set ospfv3 instance o1 router-id 2.2.2.2",
    "set ospfv3 instance o1 area 0.0.0.0 profile p1 hello-interval 5",
    "set ospfv3 instance o1 area 0.0.0.0 profile p1 network-type point-to-point",
    "delete ospfv3 instance o1",
    "delete ospfv3 instance o1 area 0.0.0.0",
    "delete ospfv3 instance o1 area 0.0.0.0 profile p1",
    "set interface eth0 ospfv3 p1",
    "set ospfv3 p1",
    "delete interface eth0 ospfv3",
    "delete ospfv3",
    "set routing-table rt1 ospfv3-instance o1",
    "set ospfv3-instance o1",
    "delete routing-table rt1 ospfv3-instance",
    "delete ospfv3-instance",
    "set routing-table rt1 rest-api address 10.0.0.1",
    "set rest-api address 10.0.0.1 port 9000",
    "set rest-api address not-an-ip",
    "delete routing-table rt1 rest-api",
    "delete rest-api",
    "set port-aggregate bond1 esi 00:11:22:33:44:55:66:77:88:99",
    "delete port-aggregate bond1 lacp-system-id",
    "set esi 00:11:22:33:44:55:66:77:88:99",
    "set lacp-system-id 02:00:00:00:00:01",
    "delete esi",
    "delete lacp-system-id",
    "set broadcast domain bd1 vni 10100",
    "set broadcast domain bd1 route-target import 65000:10100",
    "set broadcast domain bd1 redistribute from mac to bgp r1",
    "delete broadcast domain bd1 redistribute",
    "set broadcast domain bd1 redistribute from arp to bgp r1",
    "set broadcast domain bd1 redistribute from connected to bgp r1",
    "set broadcast domain bd1 routing-table rt1",
];

fn populated() -> Config {
    let pg = BgpPeerGroup {
        name: "PG1".into(),
        remote_as: 65001,
        ..Default::default()
    };
    let bgp = |name: &str| BgpInstance {
        name: name.into(),
        asn: 65000,
        router_id: "1.1.1.1".parse().unwrap(),
        peer_groups: vec![pg.clone()],
        peers: vec![BgpPeer {
            remote_address: "192.0.2.1".parse().unwrap(),
            peer_group: "PG1".into(),
            shutdown: None,
        }],
        ..Default::default()
    };
    let area = OspfArea {
        area_id: "0.0.0.0".parse().unwrap(),
        profiles: vec![OspfProfile {
            name: "p1".into(),
            ..Default::default()
        }],
    };
    let area3 = Ospfv3Area {
        area_id: "0.0.0.0".parse().unwrap(),
        profiles: vec![Ospfv3Profile {
            name: "p1".into(),
            ..Default::default()
        }],
    };
    let iface = |name: &str| Interface {
        name: name.into(),
        subinterfaces: vec![Subinterface::default()],
        ..Default::default()
    };
    Config {
        bgp_instances: vec![bgp("R1"), bgp("r1")],
        routing_tables: vec![RoutingTable {
            name: "rt1".into(),
            ..Default::default()
        }],
        ospf_instances: vec![OspfInstance {
            name: "o1".into(),
            areas: vec![area],
            ..Default::default()
        }],
        ospfv3_instances: vec![Ospfv3Instance {
            name: "o1".into(),
            areas: vec![area3],
            ..Default::default()
        }],
        static_routing_instances: vec![StaticRoutingInstance {
            name: "sri1".into(),
            routes: vec![StaticRoute {
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: "10.0.0.254".parse().unwrap(),
            }],
        }],
        interfaces: vec![
            iface("eth0"),
            iface("eth1"),
            Interface {
                name: "loopback-rt1".into(),
                ..Default::default()
            },
        ],
        policy_definitions: vec![PolicyDefinition {
            name: "p1".into(),
            source: "accept\n".into(),
        }],
        community_aliases: vec![CommunityAlias {
            name: "CUSTOMER_A".into(),
            value: "65000:1".into(),
        }],
        community_groups: vec![CommunityGroup {
            name: "CUSTOMERS".into(),
            members: vec!["CUSTOMER_A".into()],
        }],
        prefix_lists: vec![PrefixList {
            name: "BLOCKS".into(),
            entries: vec![PrefixListEntry {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((24, 32)),
            }],
        }],
        as_path_lists: vec![AsPathList {
            name: "TRANSIT".into(),
            patterns: vec!["^65001_".into()],
        }],
        broadcast_domains: vec![BroadcastDomain {
            name: "bd1".into(),
            ..Default::default()
        }],
        switching_profiles: vec![SwitchingProfile {
            name: "sp1".into(),
            ..Default::default()
        }],
        port_aggregates: vec![PortAggregate {
            name: "bond1".into(),
            ..Default::default()
        }],
        users: vec![User {
            name: "alice".into(),
            password: "x".into(),
        }],
        ..Default::default()
    }
}

/// Each legacy navigation position, with the same position as REST segments.
fn contexts() -> Vec<(Path, Vec<&'static str>)> {
    let area = || "0.0.0.0".parse().unwrap();
    vec![
        (Path::Root, vec![]),
        (Path::BgpInstance("R1".into()), vec!["bgp-instance", "R1"]),
        (
            Path::BgpPeerGroup {
                instance: "R1".into(),
                group: "PG1".into(),
            },
            vec!["bgp-instance", "R1", "peer-group", "PG1"],
        ),
        (
            Path::RoutingTable("rt1".into()),
            vec!["routing-table", "rt1"],
        ),
        (Path::OspfInstance("o1".into()), vec!["ospf-instance", "o1"]),
        (
            Path::OspfArea {
                instance: "o1".into(),
                area_id: area(),
            },
            vec!["ospf-instance", "o1", "area", "0.0.0.0"],
        ),
        (
            Path::OspfProfile {
                instance: "o1".into(),
                area_id: area(),
                name: "p1".into(),
            },
            vec!["ospf-instance", "o1", "area", "0.0.0.0", "profile", "p1"],
        ),
        (
            Path::Ospfv3Instance("o1".into()),
            vec!["ospfv3-instance", "o1"],
        ),
        (
            Path::Ospfv3Area {
                instance: "o1".into(),
                area_id: area(),
            },
            vec!["ospfv3-instance", "o1", "area", "0.0.0.0"],
        ),
        (
            Path::Ospfv3Profile {
                instance: "o1".into(),
                area_id: area(),
                name: "p1".into(),
            },
            vec!["ospfv3-instance", "o1", "area", "0.0.0.0", "profile", "p1"],
        ),
        (
            Path::StaticRoutingInstance("sri1".into()),
            vec!["static-routing-instance", "sri1"],
        ),
        (Path::Interface("eth0".into()), vec!["interface", "eth0"]),
        (Path::Interface("eth1".into()), vec!["interface", "eth1"]),
        (
            Path::Interface("loopback-rt1".into()),
            vec!["interface", "loopback-rt1"],
        ),
        (
            Path::Subinterface {
                interface: "eth0".into(),
                tag: 0,
            },
            vec!["interface", "eth0", "subinterface", "0"],
        ),
        (
            Path::PolicyDefinition("p1".into()),
            vec!["policy-definition", "p1"],
        ),
        (
            Path::CommunityAlias("CUSTOMER_A".into()),
            vec!["community-alias", "CUSTOMER_A"],
        ),
        (
            Path::CommunityGroup("CUSTOMERS".into()),
            vec!["community-group", "CUSTOMERS"],
        ),
        (
            Path::AsPathList("TRANSIT".into()),
            vec!["as-path-list", "TRANSIT"],
        ),
        (
            Path::PrefixList("BLOCKS".into()),
            vec!["prefix-list", "BLOCKS"],
        ),
        (
            Path::BroadcastDomain("bd1".into()),
            vec!["broadcast-domain", "bd1"],
        ),
        (
            Path::SwitchingProfile("sp1".into()),
            vec!["switching-profile", "sp1"],
        ),
        (
            Path::PortAggregate("bond1".into()),
            vec!["port-aggregate", "bond1"],
        ),
    ]
}

/// The REST segments of a legacy position — any position, including one
/// `edit` creates.
fn segments(path: &Path) -> Vec<String> {
    let s = |v: &[&str]| v.iter().map(ToString::to_string).collect();
    match path {
        Path::Root => vec![],
        Path::BgpInstance(n) => s(&["bgp-instance", n]),
        Path::BgpPeerGroup { instance, group } => {
            s(&["bgp-instance", instance, "peer-group", group])
        }
        Path::RoutingTable(n) => s(&["routing-table", n]),
        Path::OspfInstance(n) => s(&["ospf-instance", n]),
        Path::OspfArea { instance, area_id } => {
            s(&["ospf-instance", instance, "area", &area_id.to_string()])
        }
        Path::OspfProfile {
            instance,
            area_id,
            name,
        } => s(&[
            "ospf-instance",
            instance,
            "area",
            &area_id.to_string(),
            "profile",
            name,
        ]),
        Path::Ospfv3Instance(n) => s(&["ospfv3-instance", n]),
        Path::Ospfv3Area { instance, area_id } => {
            s(&["ospfv3-instance", instance, "area", &area_id.to_string()])
        }
        Path::Ospfv3Profile {
            instance,
            area_id,
            name,
        } => s(&[
            "ospfv3-instance",
            instance,
            "area",
            &area_id.to_string(),
            "profile",
            name,
        ]),
        Path::StaticRoutingInstance(n) => s(&["static-routing-instance", n]),
        Path::Interface(n) => s(&["interface", n]),
        Path::Subinterface { interface, tag } => {
            s(&["interface", interface, "subinterface", &tag.to_string()])
        }
        Path::PolicyDefinition(n) => s(&["policy-definition", n]),
        Path::CommunityAlias(n) => s(&["community-alias", n]),
        Path::CommunityGroup(n) => s(&["community-group", n]),
        Path::AsPathList(n) => s(&["as-path-list", n]),
        Path::PrefixList(n) => s(&["prefix-list", n]),
        Path::BroadcastDomain(n) => s(&["broadcast-domain", n]),
        Path::SwitchingProfile(n) => s(&["switching-profile", n]),
        Path::PortAggregate(n) => s(&["port-aggregate", n]),
    }
}

/// The tree grammar's edit, applied the way `nos-configd` applies
/// `SetTransactionPath`, and where it navigates.
fn tree(line: &str, context: &[String], config: &Config) -> Option<(Config, Option<Vec<String>>)> {
    let mut doc = serde_json::to_value(config).unwrap();
    let edit = config_grammar::parse(line, context, &doc)?;
    for (path, value) in edit.writes {
        config_path::set(&mut doc, &path, value).ok()?;
    }
    Some((serde_json::from_value(doc).ok()?, edit.navigate))
}

#[derive(Default)]
struct Tally {
    same: usize,
    both_rejected: usize,
    tree_only: usize,
    unknown_rejected: usize,
    failures: Vec<String>,
}

impl Tally {
    /// Runs `line` through both pipelines at every position that exists in
    /// each fixture.
    fn check(&mut self, line: &str) {
        let command = Command::parse(line);
        let unknown = matches!(command, Command::Unknown(_));
        for (fixture_name, fixture) in [("populated", populated()), ("empty", Config::default())] {
            let doc = serde_json::to_value(&fixture).unwrap();
            for (path, segs) in contexts() {
                let segs: Vec<String> = segs.into_iter().map(str::to_string).collect();
                // The shell only ever stands on an object that exists.
                if config_path::get(&doc, &segs).is_err() {
                    continue;
                }
                let mode = Mode::Configuration {
                    transaction: "t".into(),
                    path,
                    dirty: false,
                };
                let new = tree(line, &segs, &fixture);
                let at = format!("[{fixture_name} @ /{}] {line}", segs.join("/"));
                match resolve(&mode, command.clone()) {
                    Resolved::ApplyOp { op, after } => {
                        let mut expected = fixture.clone();
                        match (op.apply(&mut expected), new) {
                            (Ok(()), Some((got, nav))) if got == expected => match after {
                                PathAfter::To(p) if nav != Some(segments(&p)) => {
                                    self.failures.push(format!(
                                        "{at}: navigates to {nav:?}, legacy {:?}",
                                        segments(&p)
                                    ));
                                }
                                _ => self.same += 1,
                            },
                            (Ok(()), Some((got, _))) => self.failures.push(format!(
                                "{at}: differs\n  legacy: {}\n  tree:   {}",
                                serde_json::to_string(&expected).unwrap(),
                                serde_json::to_string(&got).unwrap()
                            )),
                            (Ok(()), None) => self
                                .failures
                                .push(format!("{at}: tree rejects, legacy {op:?}")),
                            // Legacy refuses to edit an object that doesn't exist;
                            // the tree creates it, like REST's PUT.
                            (Err(_), Some((got, _))) if got != fixture => self.tree_only += 1,
                            (Err(_), _) => self.both_rejected += 1,
                        }
                    }
                    _ if unknown => match new {
                        None => self.unknown_rejected += 1,
                        Some(_) => self
                            .failures
                            .push(format!("{at}: tree accepts a line legacy can't parse")),
                    },
                    _ => {}
                }
            }
        }
    }

    fn assert(self, what: &str) {
        println!(
            "{what}: equivalent {}, both rejected {}, tree-only (creates a missing object) {}, \
             unknown rejected {}, failures {}",
            self.same,
            self.both_rejected,
            self.tree_only,
            self.unknown_rejected,
            self.failures.len()
        );
        assert!(self.failures.is_empty(), "{}", self.failures.join("\n"));
    }
}

#[test]
fn tree_grammar_matches_the_legacy_parser_on_its_test_lines() {
    let mut tally = Tally::default();
    for line in CORPUS {
        tally.check(line);
    }
    tally.assert("parser test lines");
}

/// Words tried in a legacy help row's free argument slots until the legacy
/// parser accepts the line.
const FILLERS: &[&str] = &[
    "1",
    "10.0.0.1",
    "10.0.0.0/24",
    "hmac-sha256",
    "hmac-sha1",
    "p1",
    "65000:1",
];

/// A fixture name for a legacy help row's named argument slot.
fn name_for(kind: ArgKind) -> &'static [&'static str] {
    match kind {
        ArgKind::BgpInstanceName => &["R1"],
        ArgKind::BgpPeerGroupName => &["PG1"],
        ArgKind::RoutingTableName => &["rt1"],
        ArgKind::OspfInstanceName | ArgKind::Ospfv3InstanceName => &["o1"],
        ArgKind::OspfProfileName | ArgKind::Ospfv3ProfileName => &["p1"],
        ArgKind::StaticRoutingInstanceName => &["sri1"],
        ArgKind::InterfaceName => &["eth0"],
        ArgKind::BroadcastDomainName => &["bd1"],
        ArgKind::SwitchingProfileName => &["sp1"],
        ArgKind::PortAggregateName => &["bond1"],
        _ => FILLERS,
    }
}

/// Every config help row (the legacy `spec!` rows), filled with the first
/// words the legacy parser accepts — the syntax PR 3 must keep.
#[test]
fn tree_grammar_matches_the_legacy_parser_on_every_help_row() {
    let mut tally = Tally::default();
    let (mut rows, mut filled) = (0, 0);
    for spec in COMMAND_SPECS.iter().filter(|s| s.build.is_none()) {
        rows += 1;
        let mut lines: Vec<Vec<&str>> = vec![vec![]];
        for token in spec.tokens {
            let words: &[&str] = match token {
                Token::Literal(l) => std::slice::from_ref(l),
                Token::Arg(kind) => name_for(*kind),
            };
            lines = lines
                .into_iter()
                .flat_map(|l| {
                    words.iter().map(move |w| {
                        let mut l = l.clone();
                        l.push(*w);
                        l
                    })
                })
                .collect();
        }
        if let Some(line) = lines
            .into_iter()
            .map(|l| l.join(" "))
            .find(|l| !matches!(Command::parse(l), Command::Unknown(_)))
        {
            filled += 1;
            tally.check(&line);
        }
    }
    println!("help rows: {filled} of {rows} filled");
    tally.assert("help rows");
}
