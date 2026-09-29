//! The config grammar's regression suite (#109): every `edit`/`set`/`delete`
//! line the legacy hand-written parser was tested with, and a filled-in line
//! for every one of its help rows, with the `SetTransactionPath` writes (and
//! navigation) the tree grammar must produce for it — recorded, in
//! `config_corpus.jsonl`, while the legacy parser still existed and agreed
//! on the resulting `Config`. Lines the legacy parser couldn't parse must
//! still be rejected everywhere.

use nos_cli::config_grammar;
use nos_proto::schema::*;
use nos_proto::{config_path, Config};
use serde_json::Value;

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

/// Every navigation position the populated fixture has, as REST segments.
fn positions(doc: &Value) -> Vec<Vec<String>> {
    let mut out = vec![vec![]];
    let mut i = 0;
    while i < out.len() {
        let here = out[i].clone();
        if let Ok(Value::Object(obj)) = config_path::get(doc, &here) {
            for (field, v) in obj {
                let Value::Array(items) = v else { continue };
                for item in items {
                    let Value::Object(e) = item else { continue };
                    let Some(key) = config_path::key_field(e.keys().map(String::as_str)) else {
                        continue;
                    };
                    let key = e[key]
                        .as_str()
                        .map_or_else(|| e[key].to_string(), str::to_string);
                    let mut p = here.clone();
                    p.push(config_path::field_segment(field, true));
                    p.push(key);
                    out.push(p);
                }
            }
        }
        i += 1;
    }
    out
}

#[test]
fn every_corpus_line_makes_its_recorded_edit() {
    let populated = serde_json::to_value(populated()).unwrap();
    let empty = serde_json::to_value(Config::default()).unwrap();
    let everywhere = positions(&populated);
    let (mut edits, mut rejected) = (0, 0);
    let mut failures = Vec::new();
    for entry in include_str!("config_corpus.jsonl").lines() {
        let entry: Value = serde_json::from_str(entry).unwrap();
        let line = entry["line"].as_str().unwrap();
        if entry["rejected"] == Value::Bool(true) {
            for at in &everywhere {
                if config_grammar::parse(line, at, &populated).is_some() {
                    failures.push(format!("/{}: accepts '{line}'", at.join("/")));
                }
            }
            rejected += 1;
            continue;
        }
        let doc = if entry["fixture"] == "empty" {
            &empty
        } else {
            &populated
        };
        let at: Vec<String> = serde_json::from_value(entry["at"].clone()).unwrap();
        match config_grammar::parse(line, &at, doc) {
            Some(edit) => {
                let got = serde_json::json!({ "writes": edit.writes, "navigate": edit.navigate });
                let want =
                    serde_json::json!({ "writes": entry["writes"], "navigate": entry["navigate"] });
                if got != want {
                    failures.push(format!(
                        "/{}: '{line}'\n  want {want}\n  got  {got}",
                        at.join("/")
                    ));
                }
                // And the writes apply, like nos-configd applies them.
                let mut applied = doc.clone();
                for (path, value) in edit.writes {
                    config_path::set(&mut applied, &path, value).unwrap();
                }
                serde_json::from_value::<Config>(applied).unwrap();
            }
            None => failures.push(format!("/{}: rejects '{line}'", at.join("/"))),
        }
        edits += 1;
    }
    println!(
        "{edits} edits, {rejected} rejected lines, {} failures",
        failures.len()
    );
    assert!(edits > 300 && rejected > 10);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The writes a line typed at the root makes, as JSON, or `None` if it's rejected.
fn writes(line: &str, doc: &Value) -> Option<Value> {
    config_grammar::parse(line, &[], doc).map(|e| serde_json::json!(e.writes))
}

/// #120: absolute forms that #109 made work; pinned so they stay.
#[test]
fn absolute_peer_group_field_and_policy_definition_deletes() {
    let doc = serde_json::to_value(populated()).unwrap();
    for field in ["hold-time", "import-policy"] {
        let line = format!("delete bgp instance r1 peer-group PG1 {field}");
        assert_eq!(
            writes(&line, &doc),
            Some(serde_json::json!([[
                ["bgp-instance", "r1", "peer-group", "PG1", field],
                null
            ]])),
            "{line}"
        );
    }
    assert_eq!(
        writes("delete policy-definition p1", &doc),
        // The list is rewritten without it (the fixture's only one).
        Some(serde_json::json!([[["policy-definition"], []]]))
    );
}

/// #120: `ao-key <send-id> exclude-options` sets that one key's flag,
/// `delete … exclude-options` clears it, and an unknown send-id is refused.
#[test]
fn ao_key_exclude_options() {
    let key = |send_id, exclude_options| BgpAoKey {
        send_id,
        recv_id: send_id,
        algorithm: BgpAoAlgorithm::HmacSha1_96,
        key: "k".into(),
        is_current: send_id == 1,
        is_rnext: false,
        exclude_options,
    };
    let with_keys = |second_excluded| {
        let mut cfg = populated();
        cfg.bgp_instances[1].peer_groups[0].auth = Some(BgpAuth::Ao {
            keys: vec![key(1, false), key(2, second_excluded)],
        });
        serde_json::to_value(&cfg).unwrap()
    };
    let flags_after = |line: &str, doc: &Value| -> Vec<bool> {
        let w = writes(line, doc).unwrap_or_else(|| panic!("rejected: {line}"));
        let BgpAuth::Ao { keys } = serde_json::from_value(w[0][1].clone()).unwrap() else {
            panic!("not ao: {w}")
        };
        keys.iter().map(|k| k.exclude_options).collect()
    };
    let pg = "bgp instance r1 peer-group PG1";
    assert_eq!(
        flags_after(
            &format!("set {pg} ao-key 2 exclude-options"),
            &with_keys(false)
        ),
        [false, true]
    );
    assert_eq!(
        flags_after(
            &format!("delete {pg} ao-key 2 exclude-options"),
            &with_keys(true)
        ),
        [false, false]
    );
    assert_eq!(
        writes(
            &format!("set {pg} ao-key 9 exclude-options"),
            &with_keys(false)
        ),
        None
    );
}
