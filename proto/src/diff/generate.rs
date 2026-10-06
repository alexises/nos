//! The config diff, generated from the CLI tree (#116): the two configs' JSON
//! are walked field by field through `cli::root()`, so no field is named here
//! and none can be forgotten — a field the shell can set is a field whose
//! change wakes the daemons. Labels and headers are the CLI's own words
//! (`bgp instance r1`, `route-reflector-client`); values are the same text
//! `show config` writes, `unset` for an absent one.
//!
//! A keyed list of structs is a section (`SectionDiff`, nested ones in
//! `subsections`); everything else is one `FieldDiff` per changed field. A
//! plain struct field (`evpn`, `logging`) and, below the root, every list
//! inside one, is flattened to labels prefixed with its words
//! (`logging syslog s1 address`). Hidden fields (derived state) are skipped.

use serde_json::Value;

use crate::cli::render::{name, unwrap_option, words, HIDDEN};
use crate::cli::{root, Field, Kind, Node};
use crate::Config;

use super::{ConfigDiff, DiffStatus, FieldDiff, SectionDiff};

/// A secret that is still there but changed.
const CHANGED: &str = "<changed>";

pub fn diff_configs(base: &Config, candidate: &Config) -> ConfigDiff {
    diff_values(&to_value(base), &to_value(candidate))
}

/// `diff_configs` on the configs' JSON (the round-trip tests build configs
/// that are only shaped like one).
pub fn diff_values(b: &Value, c: &Value) -> ConfigDiff {
    let mut out = ConfigDiff::default();
    for f in root().fields.iter().filter(|f| !f.hidden) {
        let (mut fields, mut subs) = (Vec::new(), Vec::new());
        field(f, "", Some(b), Some(c), false, &mut fields, &mut subs);
        assert!(
            put(&mut out, f.name, fields, subs),
            "Config.{} has no ConfigDiff slot",
            f.name
        );
    }
    out
}

fn to_value(c: &Config) -> Value {
    serde_json::to_value(c).expect("a config serializes")
}

/// Stores one root field's diff in its `ConfigDiff` slot; `false` for a
/// field with none (a new `Config` field must get one — pinned by a test).
fn put(d: &mut ConfigDiff, name: &str, mut fields: Vec<FieldDiff>, subs: Vec<SectionDiff>) -> bool {
    match name {
        "hostname" => d.hostname = fields.pop(),
        "bgp_instances" => d.bgp_instances = subs,
        "routing_tables" => d.routing_tables = subs,
        "ospf_instances" => d.ospf_instances = subs,
        "ospfv3_instances" => d.ospfv3_instances = subs,
        "static_routing_instances" => d.static_routing_instances = subs,
        "interfaces" => d.interfaces = subs,
        "policy_definitions" => d.policy_definitions = subs,
        "community_aliases" => d.community_aliases = subs,
        "community_groups" => d.community_groups = subs,
        "as_path_lists" => d.as_path_lists = subs,
        "prefix_lists" => d.prefix_lists = subs,
        "broadcast_domains" => d.broadcast_domains = subs,
        "switching_profiles" => d.switching_profiles = subs,
        "port_aggregates" => d.port_aggregates = subs,
        "lldp" => d.lldp = fields,
        "users" => d.users = subs,
        "logging" => d.logging = fields,
        _ => return false,
    }
    true
}

fn key_of(n: &Node) -> Option<&Field> {
    n.fields.iter().find(|k| k.key)
}

/// A keyed list's element, as `(key words, element)`.
fn key_words(key: &Field, e: &Value) -> String {
    words(&(key.kind)(), &e[key.name]).join(" ")
}

fn join(prefix: &str, rest: &str) -> String {
    if prefix.is_empty() {
        rest.to_string()
    } else {
        format!("{prefix} {rest}")
    }
}

/// One field of `b`/`c` (`None`: that side's object is absent — an added or
/// removed element).
fn field(
    f: &Field,
    prefix: &str,
    b: Option<&Value>,
    c: Option<&Value>,
    flat: bool,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    let label = join(prefix, &name(f));
    let (bv, cv) = (get(b, f), get(c, f));
    let plain = !f.secret && f.render.is_none();
    match unwrap_option((f.kind)()) {
        Kind::List(elem) if plain => {
            if let Kind::Struct(n) = elem() {
                if let Some(key) = key_of(n) {
                    let items = |v: Option<&Value>| v.and_then(Value::as_array).cloned();
                    return list(
                        &Ctx {
                            f,
                            n,
                            key,
                            label: &label,
                            flat,
                        },
                        &items(bv).unwrap_or_default(),
                        &items(cv).unwrap_or_default(),
                        fields,
                        subs,
                    );
                }
            }
        }
        // A plain struct is a section of the field's words.
        Kind::Struct(n) if plain && matches!((f.kind)(), Kind::Struct(_)) => {
            return object(n, &label, bv, cv, true, fields, subs);
        }
        _ => {}
    }
    if bv == cv {
        return;
    }
    let show = |v: Option<&Value>| v.map(|v| show(f, v));
    let (old, new) = if f.secret {
        (
            bv.map(|_| HIDDEN.to_string()),
            cv.map(|_| if bv.is_some() { CHANGED } else { HIDDEN }.to_string()),
        )
    } else {
        (show(bv), show(cv))
    };
    fields.push(FieldDiff { label, old, new });
}

fn get<'v>(o: Option<&'v Value>, f: &Field) -> Option<&'v Value> {
    o.map(|o| o.get(f.name).unwrap_or(&Value::Null))
}

struct Ctx<'a> {
    f: &'a Field,
    n: &'a Node,
    key: &'a Field,
    label: &'a str,
    flat: bool,
}

fn list(
    cx: &Ctx,
    base: &[Value],
    cand: &[Value],
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    let find =
        |l: &'_ [Value], e: &Value| l.iter().find(|x| x[cx.key.name] == e[cx.key.name]).cloned();
    let pairs = base.iter().map(|b| (Some(b.clone()), find(cand, b))).chain(
        cand.iter()
            .filter(|c| find(base, c).is_none())
            .map(|c| (None, Some(c.clone()))),
    );
    for (b, c) in pairs {
        let key = key_words(cx.key, b.as_ref().or(c.as_ref()).expect("one side"));
        if cx.flat {
            let prefix = format!("{} {key}", cx.label);
            object(cx.n, &prefix, b.as_ref(), c.as_ref(), true, fields, subs);
            continue;
        }
        let status = match (&b, &c) {
            (None, _) => DiffStatus::Added,
            (_, None) => DiffStatus::Removed,
            _ => DiffStatus::Modified,
        };
        let (mut f, mut s) = (Vec::new(), Vec::new());
        object(cx.n, "", b.as_ref(), c.as_ref(), false, &mut f, &mut s);
        if status == DiffStatus::Modified && f.is_empty() && s.is_empty() {
            continue;
        }
        subs.push(SectionDiff {
            header: format!("{} {key}", name(cx.f)),
            name: key,
            status,
            fields: f,
            subsections: s,
        });
    }
}

/// The fields of one struct. An absent side is compared as the struct's
/// default, so a new element lists only what it sets.
fn object(
    n: &Node,
    prefix: &str,
    b: Option<&Value>,
    c: Option<&Value>,
    flat: bool,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    let default = n
        .default
        .map_or_else(|| Value::Object(serde_json::Map::new()), |d| d());
    for f in n.fields.iter().filter(|f| !f.hidden && !f.key) {
        // Compare against the default, then drop the absent side's text.
        let (mut df, mut ds) = (Vec::new(), Vec::new());
        field(
            f,
            prefix,
            Some(b.unwrap_or(&default)),
            Some(c.unwrap_or(&default)),
            flat,
            &mut df,
            &mut ds,
        );
        for d in &mut df {
            if b.is_none() {
                d.old = None;
            }
            if c.is_none() {
                d.new = None;
            }
        }
        fields.extend(df);
        subs.extend(ds);
    }
}

/// The text `show config` would write for the field's value; `unset` when
/// it has none.
fn show(f: &Field, v: &Value) -> String {
    if let Some(render) = f.render {
        let lines = if v.is_null() { Vec::new() } else { render(v) };
        return if lines.is_empty() {
            "unset".into()
        } else {
            lines.join("; ")
        };
    }
    show_kind(&(f.kind)(), v)
}

fn show_kind(kind: &Kind, v: &Value) -> String {
    match kind {
        Kind::Option(_) if v.is_null() => "unset".into(),
        Kind::Option(inner) => show_kind(&inner(), v),
        Kind::Bool => v.as_bool().unwrap_or_default().to_string(),
        Kind::List(elem) => {
            let items: Vec<String> = v
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| show_kind(&elem(), e))
                .collect();
            if items.is_empty() {
                "none".into()
            } else {
                items.join(", ")
            }
        }
        k => {
            let w = words(k, v).join(" ");
            if w.is_empty() {
                "unset".into()
            } else {
                w
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::default_json;
    use crate::schema::{BgpInstance, BgpPeerGroup, OspfArea, OspfInstance, OspfProfile, User};
    use serde::de::DeserializeOwned;

    fn dflt<T: Default + serde::Serialize + DeserializeOwned>() -> T {
        serde_json::from_value(default_json::<T>()).unwrap()
    }

    fn list_node(root_field: &str) -> &'static Node {
        let f = root().fields.iter().find(|f| f.name == root_field).unwrap();
        let Kind::List(e) = (f.kind)() else { panic!() };
        let Kind::Struct(n) = e() else { panic!() };
        n
    }

    fn label(node: &Node, field: &str) -> String {
        name(node.fields.iter().find(|f| f.name == field).unwrap())
    }

    #[test]
    fn every_config_field_has_a_diff_slot() {
        let missing: Vec<_> = root()
            .fields
            .iter()
            .filter(|f| !put(&mut ConfigDiff::default(), f.name, Vec::new(), Vec::new()))
            .map(|f| f.name)
            .collect();
        assert!(missing.is_empty(), "no ConfigDiff slot for {missing:?}");
    }

    /// `nos-watchdogd` keys its opt-in daemons on these two labels.
    #[test]
    fn watchdog_labels_are_the_cli_words() {
        assert_eq!(
            label(list_node("routing_tables"), "rest_api"),
            super::super::REST_API_LABEL
        );
        assert_eq!(
            label(list_node("broadcast_domains"), "vni"),
            super::super::VNI_LABEL
        );
    }

    #[test]
    fn identical_configs_are_empty() {
        let c = Config::default();
        assert!(diff_configs(&c, &c).is_empty());
    }

    /// The bug this replaced: no event for a commit changing only this.
    #[test]
    fn a_route_reflector_client_change_alone_is_a_diff() {
        let inst = |rr| BgpInstance {
            name: "r1".into(),
            peer_groups: vec![BgpPeerGroup {
                name: "g".into(),
                route_reflector_client: rr,
                ..dflt()
            }],
            ..dflt()
        };
        let cfg = |rr| Config {
            bgp_instances: vec![inst(rr)],
            ..Default::default()
        };
        let d = diff_configs(&cfg(false), &cfg(true));
        let g = &d.bgp_instances[0].subsections[0];
        assert_eq!(g.header, "peer-group g");
        assert_eq!(g.fields[0].label, "route-reflector-client");
        assert_eq!(g.fields[0].new.as_deref(), Some("true"));
    }

    #[test]
    fn an_added_nested_element_lists_only_what_it_sets() {
        let inst = |profiles| OspfInstance {
            name: "o1".into(),
            areas: vec![OspfArea { profiles, ..dflt() }],
            ..dflt()
        };
        let p = OspfProfile {
            name: "p1".into(),
            cost: Some(10),
            ..dflt()
        };
        let cfg = |profiles| Config {
            ospf_instances: vec![inst(profiles)],
            ..Default::default()
        };
        let d = diff_configs(&cfg(vec![]), &cfg(vec![p]));
        let prof = &d.ospf_instances[0].subsections[0].subsections[0];
        assert_eq!(prof.header, "profile p1");
        assert_eq!(prof.status, DiffStatus::Added);
        assert_eq!(prof.fields.len(), 1);
        assert_eq!(prof.fields[0].label, "cost");
        assert_eq!(prof.fields[0].old, None);
        assert_eq!(prof.fields[0].new.as_deref(), Some("10"));
    }

    #[test]
    fn a_password_is_never_shown() {
        let cfg = |pw: &str| Config {
            users: vec![User {
                name: "u".into(),
                password: pw.into(),
            }],
            ..Default::default()
        };
        let d = diff_configs(&cfg("a"), &cfg("b"));
        assert_eq!(d.users[0].status, DiffStatus::Modified);
        let f = &d.users[0].fields[0];
        assert_eq!(
            (f.old.as_deref(), f.new.as_deref()),
            (Some("<hidden>"), Some("<changed>"))
        );
    }
}
