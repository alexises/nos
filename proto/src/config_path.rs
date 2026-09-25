//! Addresses a subsection of a [`Config`](crate::Config)'s JSON form by a
//! URL-style path, e.g. `["bgp-instance", "r1", "peer-group", "pg1"]`.
//!
//! Pure `serde_json::Value` walkers shared by `nos-config` (which mutates a
//! transaction's config) and `nos-restd` (which reads it back and documents
//! the paths in its `OpenAPI` spec), so the two can't disagree about what a
//! path means.
//!
//! **Resolution rules.** A segment names an object field, compared after
//! lowercasing and dropping `-`/`_`, and tried as-is, plus `s`, plus `es`
//! (`bgp-instance` → `bgp_instances`, `community-alias` →
//! `community_aliases`, `entry` → `entries`; it also matches an externally-tagged enum variant,
//! `ao` → `Ao`). If that field is an array, the *next* segment selects one
//! element by its identifying field ([`ELEMENT_KEYS`], first one present),
//! or by value for scalar elements. Selecting an element that doesn't exist
//! is only legal as the last segment of a [`set`], which appends it.
//!
//! ponytail: `ELEMENT_KEYS` is a fixed list; extend it if a new list section
//! is identified by a field that isn't in it (a test walks every list in the
//! schema-shaped fixture below).

use serde_json::{Map, Value};
use thiserror::Error;

/// Fields that identify one element of a list, in priority order — the first
/// one present in an element object is its key. `broadcast_domain` precedes
/// `tag` because a `SwitchingProfileMember` has both and `tag` isn't unique;
/// `address` precedes `tag` only by virtue of `InterfaceAddress` having no `tag`.
pub const ELEMENT_KEYS: &[&str] = &[
    "name",
    "area_id",
    "remote_address",
    "broadcast_domain",
    "subnet",
    "cidr",
    "key_id",
    "send_id",
    "address",
    "tag",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    #[error("no such config path: /{0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
}

/// One resolved hop from a parent value to a child.
enum Step {
    Key(String),
    Index(usize),
}

enum Located {
    Existing(Vec<Step>),
    /// The path names a list element that doesn't exist yet: `array` leads
    /// to the list, `key` is the requested element key.
    NewElement {
        array: Vec<Step>,
        key: String,
    },
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn find_key(map: &Map<String, Value>, seg: &str) -> Option<String> {
    let n = norm(seg);
    let mut candidates = vec![n.clone(), format!("{n}s"), format!("{n}es")];
    if let Some(stem) = n.strip_suffix('y') {
        candidates.push(format!("{stem}ies"));
    }
    candidates
        .iter()
        .find_map(|c| map.keys().find(|k| &norm(k) == c))
        .cloned()
}

/// The element-identifying field among `fields` (see [`ELEMENT_KEYS`]).
pub fn key_field<'a>(fields: impl IntoIterator<Item = &'a str>) -> Option<&'static str> {
    let fields: Vec<&str> = fields.into_iter().collect();
    ELEMENT_KEYS.iter().copied().find(|k| fields.contains(k))
}

fn element_key_field(obj: &Map<String, Value>) -> Option<&'static str> {
    key_field(obj.keys().map(String::as_str))
}

/// Whether URL segment `seg` addresses config field `field`.
pub fn field_matches(field: &str, seg: &str) -> bool {
    let mut m = Map::new();
    m.insert(field.to_string(), Value::Null);
    find_key(&m, seg).as_deref() == Some(field)
}

fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn find_element(items: &[Value], sel: &str) -> Option<usize> {
    items.iter().position(|el| match el {
        Value::Object(o) => element_key_field(o)
            .and_then(|k| scalar_text(&o[k]))
            .is_some_and(|t| t == sel),
        Value::String(s) => s == sel || norm(s) == norm(sel),
        Value::Number(n) => n.to_string() == sel,
        _ => false,
    })
}

fn describe(path: &[String]) -> String {
    path.join("/")
}

fn resolve(root: &Value, path: &[String]) -> Result<Located, PathError> {
    let mut steps = Vec::new();
    let mut cur = root;
    let mut i = 0;
    while i < path.len() {
        let Value::Object(map) = cur else {
            return Err(PathError::NotFound(describe(&path[..=i])));
        };
        let key =
            find_key(map, &path[i]).ok_or_else(|| PathError::NotFound(describe(&path[..=i])))?;
        cur = &map[&key];
        steps.push(Step::Key(key));
        i += 1;
        if let (Value::Array(items), true) = (cur, i < path.len()) {
            match find_element(items, &path[i]) {
                Some(idx) => {
                    cur = &items[idx];
                    steps.push(Step::Index(idx));
                }
                None if i == path.len() - 1 => {
                    return Ok(Located::NewElement {
                        array: steps,
                        key: path[i].clone(),
                    })
                }
                None => return Err(PathError::NotFound(describe(&path[..=i]))),
            }
            i += 1;
        }
    }
    Ok(Located::Existing(steps))
}

fn at<'a>(root: &'a Value, steps: &[Step]) -> &'a Value {
    steps.iter().fold(root, |v, s| match s {
        Step::Key(k) => &v[k.as_str()],
        Step::Index(i) => &v[*i],
    })
}

fn at_mut<'a>(root: &'a mut Value, steps: &[Step]) -> &'a mut Value {
    steps.iter().fold(root, |v, s| match s {
        Step::Key(k) => &mut v[k.as_str()],
        Step::Index(i) => &mut v[*i],
    })
}

/// The subsection at `path`; an empty path is the whole document.
pub fn get<'a>(root: &'a Value, path: &[String]) -> Result<&'a Value, PathError> {
    match resolve(root, path)? {
        Located::Existing(steps) => Ok(at(root, &steps)),
        Located::NewElement { .. } => Err(PathError::NotFound(describe(path))),
    }
}

/// A list element's body must agree with the key in the URL it was PUT to.
fn check_element_key(value: &Value, key: &str) -> Result<(), PathError> {
    let Value::Object(o) = value else {
        return Ok(());
    };
    let Some(field) = element_key_field(o) else {
        return Ok(());
    };
    match scalar_text(&o[field]) {
        Some(t) if t != key => Err(PathError::Invalid(format!(
            "body {field} '{t}' does not match path key '{key}'"
        ))),
        _ => Ok(()),
    }
}

/// Replaces the subsection at `path` with `value`, appending it if it names
/// a list element that doesn't exist yet. An empty path replaces the whole
/// document.
pub fn set(root: &mut Value, path: &[String], value: Value) -> Result<(), PathError> {
    match resolve(root, path)? {
        Located::Existing(steps) => {
            if matches!(steps.last(), Some(Step::Index(_))) {
                check_element_key(&value, &path[path.len() - 1])?;
            }
            *at_mut(root, &steps) = value;
        }
        Located::NewElement { array, key } => {
            check_element_key(&value, &key)?;
            match at_mut(root, &array) {
                Value::Array(items) => items.push(value),
                _ => return Err(PathError::NotFound(describe(path))),
            }
        }
    }
    Ok(())
}

/// Removes the subsection at `path`: a list element is deleted from its
/// list, a whole list is emptied, any other field is set to `null` (which
/// clears an `Option`; a required field then fails the caller's
/// re-deserialization, leaving the config untouched).
pub fn remove(root: &mut Value, path: &[String]) -> Result<(), PathError> {
    let Located::Existing(mut steps) = resolve(root, path)? else {
        return Err(PathError::NotFound(describe(path)));
    };
    let Some(last) = steps.pop() else {
        return Err(PathError::Invalid(
            "cannot remove the whole config; set it to an empty config instead".to_string(),
        ));
    };
    let parent = at_mut(root, &steps);
    match last {
        Step::Index(i) => {
            if let Value::Array(items) = parent {
                items.remove(i);
            }
        }
        Step::Key(k) => {
            let field = &mut parent[k.as_str()];
            *field = if field.is_array() {
                Value::Array(Vec::new())
            } else {
                Value::Null
            };
        }
    }
    Ok(())
}

/// The URL segment naming a config field (`bgp_instances` → `bgp-instance`,
/// `community_aliases` → `community-alias`) — the inverse of [`find_key`]'s
/// plural candidates, used to generate `OpenAPI` paths.
pub fn field_segment(field: &str, is_list: bool) -> String {
    let mut f = field.to_string();
    if is_list {
        if f.ends_with("ies") {
            f.truncate(f.len() - 3);
            f.push('y');
        } else if f.ends_with("ses") {
            f.truncate(f.len() - 2);
        } else if f.ends_with('s') {
            f.truncate(f.len() - 1);
        }
    }
    f.replace('_', "-")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn p(s: &str) -> Vec<String> {
        s.split('/')
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn doc() -> Value {
        json!({
            "hostname": "nos",
            "bgp_instances": [{
                "name": "r1", "asn": 65000,
                "peer_groups": [{"name": "pg1", "remote_as": 1, "auth": {"Ao": {"keys": [{"send_id": 1}]}}}],
                "peers": [{"remote_address": "10.0.0.2", "peer_group": "pg1"}],
            }],
            "ospf_instances": [{"name": "o1", "areas": [{"area_id": "0.0.0.0", "profiles": [{"name": "p1"}]}]}],
            "community_aliases": [{"name": "a1"}],
            "static_routing_instances": [{"name": "s1", "routes": [{"subnet": "10.1.0.0/16", "gateway": "10.0.0.1"}]}],
            "interfaces": [{"name": "eth0", "subinterfaces": [{"tag": 0, "addresses": [{"address": "10.0.0.1/24", "label": null}]}]}],
            "switching_profiles": [{"name": "sw", "members": [{"broadcast_domain": "bd", "tag": {"Dot1q": 5}}]}],
            "prefix_lists": [{"name": "pl", "entries": [{"cidr": "10.0.0.0/8", "range": null}]}],
            "lldp": {"tx_hold": null},
        })
    }

    #[test]
    fn empty_path_is_whole_document() {
        assert_eq!(get(&doc(), &[]).unwrap(), &doc());
    }

    #[test]
    fn scalar_and_nested_get() {
        let d = doc();
        assert_eq!(get(&d, &p("hostname")).unwrap(), &json!("nos"));
        assert_eq!(
            get(&d, &p("bgp-instance/r1/peer-group/pg1/remote-as")).unwrap(),
            &json!(1)
        );
        assert_eq!(get(&d, &p("community-alias/a1")).unwrap()["name"], "a1");
        assert_eq!(
            get(&d, &p("ospf-instance/o1/area/0.0.0.0/profile/p1")).unwrap()["name"],
            "p1"
        );
    }

    #[test]
    fn every_list_in_the_fixture_is_addressable_by_its_key() {
        let d = doc();
        // A key containing `/` arrives as one already-decoded segment.
        for segs in [
            vec!["bgp-instance", "r1", "peer", "10.0.0.2"],
            vec!["static-routing-instance", "s1", "route", "10.1.0.0/16"],
            vec![
                "interface",
                "eth0",
                "subinterface",
                "0",
                "address",
                "10.0.0.1/24",
            ],
            vec!["switching-profile", "sw", "member", "bd"],
            vec!["prefix-list", "pl", "entry", "10.0.0.0/8"],
            vec![
                "bgp-instance",
                "r1",
                "peer-group",
                "pg1",
                "auth",
                "ao",
                "keys",
                "1",
            ],
        ] {
            let segs: Vec<String> = segs.into_iter().map(String::from).collect();
            assert!(get(&d, &segs).is_ok(), "{segs:?}");
        }
    }

    #[test]
    fn set_replaces_existing_element() {
        let mut d = doc();
        set(
            &mut d,
            &p("bgp-instance/r1/peer-group/pg1"),
            json!({"name": "pg1", "remote_as": 9}),
        )
        .unwrap();
        assert_eq!(d["bgp_instances"][0]["peer_groups"][0]["remote_as"], 9);
    }

    #[test]
    fn set_appends_missing_last_element() {
        let mut d = doc();
        set(
            &mut d,
            &p("bgp-instance/r1/peer-group/pg2"),
            json!({"name": "pg2"}),
        )
        .unwrap();
        assert_eq!(d["bgp_instances"][0]["peer_groups"][1]["name"], "pg2");
    }

    #[test]
    fn set_rejects_body_key_mismatch() {
        let mut d = doc();
        let err = set(&mut d, &p("bgp-instance/r2"), json!({"name": "other"})).unwrap_err();
        assert!(matches!(err, PathError::Invalid(_)));
        assert_eq!(d, doc());
    }

    #[test]
    fn set_whole_document() {
        let mut d = doc();
        set(&mut d, &[], json!({"hostname": "x"})).unwrap();
        assert_eq!(d, json!({"hostname": "x"}));
    }

    #[test]
    fn missing_parent_is_not_found() {
        let mut d = doc();
        assert!(matches!(
            set(
                &mut d,
                &p("bgp-instance/nope/peer-group/pg"),
                json!({"name": "pg"})
            ),
            Err(PathError::NotFound(_))
        ));
        assert!(matches!(
            get(&d, &p("nonsense")),
            Err(PathError::NotFound(_))
        ));
    }

    #[test]
    fn remove_element_list_and_scalar() {
        let mut d = doc();
        remove(&mut d, &p("bgp-instance/r1/peer/10.0.0.2")).unwrap();
        assert_eq!(d["bgp_instances"][0]["peers"], json!([]));
        remove(&mut d, &p("ospf-instance")).unwrap();
        assert_eq!(d["ospf_instances"], json!([]));
        remove(&mut d, &p("hostname")).unwrap();
        assert_eq!(d["hostname"], Value::Null);
        assert!(matches!(remove(&mut d, &[]), Err(PathError::Invalid(_))));
        assert!(matches!(
            remove(&mut d, &p("community-alias/zzz")),
            Err(PathError::NotFound(_))
        ));
    }

    #[test]
    fn field_segment_inverts_the_plural_candidates() {
        for (field, seg) in [
            ("bgp_instances", "bgp-instance"),
            ("community_aliases", "community-alias"),
            ("addresses", "address"),
            ("peer_groups", "peer-group"),
            ("interfaces", "interface"),
            ("entries", "entry"),
        ] {
            assert_eq!(field_segment(field, true), seg);
            let mut m = Map::new();
            m.insert(field.to_string(), Value::Array(vec![]));
            assert_eq!(find_key(&m, seg).as_deref(), Some(field));
        }
        assert_eq!(field_segment("router_id", false), "router-id");
    }
}
