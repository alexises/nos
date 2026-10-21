//! CLI sugar: today's shell syntax for the few fields whose edits aren't a
//! plain "field value" — each function is named by a `#[cli(sugar(...))]`
//! on the field it edits (see `crate::cli::SugarFn`), and returns that
//! field's new JSON value (or the canonical words it stands for). Semantics mirror the `ops/` variants the shell
//! used before (e.g. `ao-key <id> current` clears the flag on every other
//! key, like `BgpPeerGroupOp::SetAoCurrentKey`).

use serde_json::{json, Value};

use crate::cli::{enum_word, CliValue, SugarOut, Verb};

use super::{BgpAoAlgorithm, OspfCryptoAlgorithm};

/// `shutdown [<message…>]` — the message is every remaining word.
pub fn shutdown(verb: Verb, args: &[&str], obj: &Value) -> Option<SugarOut> {
    shutdown_value(verb, args, obj).map(SugarOut::Value)
}

fn shutdown_value(verb: Verb, args: &[&str], _: &Value) -> Option<Value> {
    Some(match verb {
        Verb::Set if args.is_empty() => json!({ "message": null }),
        Verb::Set => json!({ "message": args.join(" ") }),
        Verb::Delete => args.is_empty().then_some(Value::Null)?,
    })
}

/// `md5-password <admin-key-label>` (RFC 2385) — replaces any TCP-AO keys.
pub fn md5_password(verb: Verb, args: &[&str], obj: &Value) -> Option<SugarOut> {
    md5_password_value(verb, args, obj).map(SugarOut::Value)
}

fn md5_password_value(verb: Verb, args: &[&str], _: &Value) -> Option<Value> {
    match (verb, args) {
        (Verb::Set, [label]) => Some(json!({ "Md5": { "key_ref": label } })),
        _ => None,
    }
}

/// `simple-password <admin-key-label>` (RFC 2328 Appendix D type 1).
pub fn simple_password(verb: Verb, args: &[&str], obj: &Value) -> Option<SugarOut> {
    simple_password_value(verb, args, obj).map(SugarOut::Value)
}

fn simple_password_value(verb: Verb, args: &[&str], _: &Value) -> Option<Value> {
    match (verb, args) {
        (Verb::Set, [label]) => Some(json!({ "Simple": { "key": label } })),
        _ => None,
    }
}

/// Upserts `key` by `id_field`, or sets one key's `flag` (clearing it on
/// the others), or removes a key — the shape shared by every keyed auth list.
fn edit_keys(
    keys: &mut Vec<Value>,
    verb: Verb,
    id_field: &str,
    id: u64,
    new: Option<Value>,
    flag: Option<&str>,
) -> Option<()> {
    let is = |k: &Value| k[id_field].as_u64() == Some(id);
    match (verb, new, flag) {
        (Verb::Set, Some(new), None) => match keys.iter_mut().find(|k| is(k)) {
            Some(existing) => *existing = new,
            None => keys.push(new),
        },
        (Verb::Set, None, Some(flag)) => {
            keys.iter().any(is).then_some(())?;
            for k in keys.iter_mut() {
                k[flag] = Value::Bool(is(k));
            }
        }
        (Verb::Delete, None, None) => keys.retain(|k| !is(k)),
        _ => return None,
    }
    Some(())
}

/// `ao-key <send-id> <recv-id> <algorithm> <key>` / `ao-key <send-id>
/// current|rnext` / `[delete] ao-key <send-id> exclude-options` / `delete
/// ao-key <send-id>` (RFC 5925).
pub fn ao_key(verb: Verb, args: &[&str], obj: &Value) -> Option<SugarOut> {
    ao_key_value(verb, args, obj).map(SugarOut::Value)
}

fn ao_key_value(verb: Verb, args: &[&str], group: &Value) -> Option<Value> {
    let auth = &group["auth"];
    let send_id: u8 = args.first()?.parse().ok()?;
    let mut keys = match auth.get("Ao") {
        Some(ao) => ao["keys"].as_array()?.clone(),
        None if verb == Verb::Delete => return (args.len() == 1).then(|| auth.clone()),
        None => Vec::new(),
    };
    // A per-key flag, not exclusive like current/rnext.
    if args[1..] == ["exclude-options"] {
        let key = keys
            .iter_mut()
            .find(|k| k["send_id"].as_u64() == Some(send_id.into()))?;
        key["exclude_options"] = Value::Bool(verb == Verb::Set);
        return Some(json!({ "Ao": { "keys": keys } }));
    }
    let (new, flag) = match (verb, &args[1..]) {
        (Verb::Set, [recv_id, algorithm, key]) => (
            Some(json!({
                "send_id": send_id,
                "recv_id": recv_id.parse::<u8>().ok()?,
                "algorithm": enum_word(&BgpAoAlgorithm::kind(), algorithm)?,
                "key_ref": key,
                "is_current": false,
                "is_rnext": false,
                "exclude_options": false,
            })),
            None,
        ),
        (Verb::Set, ["current"]) if auth.get("Ao").is_some() => (None, Some("is_current")),
        (Verb::Set, ["rnext"]) if auth.get("Ao").is_some() => (None, Some("is_rnext")),
        (Verb::Delete, []) => (None, None),
        _ => return None,
    };
    edit_keys(&mut keys, verb, "send_id", send_id.into(), new, flag)?;
    Some(json!({ "Ao": { "keys": keys } }))
}

/// A `crypto-key` edit on a key list: `<key-id> <algorithm> <key>`,
/// `<key-id> current`, or `delete crypto-key <key-id>`.
fn crypto_keys(verb: Verb, args: &[&str], mut keys: Vec<Value>, known: bool) -> Option<Vec<Value>> {
    let key_id: u16 = args.first()?.parse().ok()?;
    let (new, flag) = match (verb, &args[1..]) {
        (Verb::Set, [algorithm, key]) => (
            Some(json!({
                "key_id": key_id,
                "algorithm": enum_word(&OspfCryptoAlgorithm::kind(), algorithm)?,
                "key": key,
                "is_current": false,
            })),
            None,
        ),
        (Verb::Set, ["current"]) if known => (None, Some("is_current")),
        (Verb::Delete, []) => (None, None),
        _ => return None,
    };
    edit_keys(&mut keys, verb, "key_id", key_id.into(), new, flag)?;
    Some(keys)
}

/// `OSPFv2` `crypto-key` (RFC 2328 Appendix D / RFC 5709) — replaces a simple password.
pub fn ospf_crypto_key(verb: Verb, args: &[&str], obj: &Value) -> Option<SugarOut> {
    ospf_crypto_key_value(verb, args, obj).map(SugarOut::Value)
}

fn ospf_crypto_key_value(verb: Verb, args: &[&str], profile: &Value) -> Option<Value> {
    let auth = &profile["auth"];
    let current = auth.get("Crypto").map(|c| c["keys"].as_array().cloned());
    if verb == Verb::Delete && current.is_none() {
        return valid_key_id(args).then(|| auth.clone());
    }
    let known = current.is_some();
    let keys = crypto_keys(verb, args, current.flatten().unwrap_or_default(), known)?;
    Some(json!({ "Crypto": { "keys": keys } }))
}

/// `OSPFv3` `crypto-key` (RFC 7166 authentication trailer; `auth` is the key list).
pub fn ospfv3_crypto_key(verb: Verb, args: &[&str], obj: &Value) -> Option<SugarOut> {
    ospfv3_crypto_key_value(verb, args, obj).map(SugarOut::Value)
}

fn ospfv3_crypto_key_value(verb: Verb, args: &[&str], profile: &Value) -> Option<Value> {
    let auth = &profile["auth"];
    if verb == Verb::Delete && auth.is_null() {
        return valid_key_id(args).then_some(Value::Null);
    }
    let keys = crypto_keys(
        verb,
        args,
        auth.as_array().cloned().unwrap_or_default(),
        !auth.is_null(),
    )?;
    Some(Value::Array(keys))
}

/// `[<key-id>]` — a `delete crypto-key` with nothing to remove still needs
/// a well-formed id.
fn valid_key_id(args: &[&str]) -> bool {
    matches!(args, [id] if id.parse::<u16>().is_ok())
}

fn cidr_len(entry: &Value) -> Option<(u8, u8)> {
    let cidr: ipnet::IpNet = entry["cidr"].as_str()?.parse().ok()?;
    Some((cidr.prefix_len(), cidr.max_prefix_len()))
}

/// `orlonger` — the entry's own prefix length up to the family maximum.
pub fn orlonger(verb: Verb, args: &[&str], obj: &Value) -> Option<SugarOut> {
    orlonger_value(verb, args, obj).map(SugarOut::Value)
}

fn orlonger_value(_: Verb, args: &[&str], entry: &Value) -> Option<Value> {
    let (len, max) = cidr_len(entry)?;
    args.is_empty().then(|| json!([len, max]))
}

/// `upto <max>` — the entry's own prefix length up to `<max>`.
pub fn upto(verb: Verb, args: &[&str], obj: &Value) -> Option<SugarOut> {
    upto_value(verb, args, obj).map(SugarOut::Value)
}

fn upto_value(_: Verb, args: &[&str], entry: &Value) -> Option<Value> {
    let (len, _) = cidr_len(entry)?;
    match args {
        [max] => Some(json!([len, max.parse::<u8>().ok()?])),
        _ => None,
    }
}

/// On a physical interface (not `loopback-*`), its L3 fields live on the
/// untagged subinterface: `address …` means `subinterface 0 address …`.
fn untagged(word: &str, args: &[&str], interface: &Value) -> Option<SugarOut> {
    let name = interface["name"].as_str()?;
    if name.starts_with(super::LOOPBACK_PREFIX) {
        return None;
    }
    let words = ["subinterface", "0", word]
        .into_iter()
        .chain(args.iter().copied());
    Some(SugarOut::Words(words.map(str::to_string).collect()))
}

/// Sugar: `address ...` on a physical interface means `subinterface 0 address ...`.
pub fn untagged_address(_: Verb, args: &[&str], interface: &Value) -> Option<SugarOut> {
    untagged("address", args, interface)
}

/// Sugar: `routing-table ...` on a physical interface means `subinterface 0 routing-table ...`.
pub fn untagged_routing_table(_: Verb, args: &[&str], interface: &Value) -> Option<SugarOut> {
    untagged("routing-table", args, interface)
}

/// Sugar: `ospf ...` on a physical interface means `subinterface 0 ospf ...`.
pub fn untagged_ospf(_: Verb, args: &[&str], interface: &Value) -> Option<SugarOut> {
    untagged("ospf", args, interface)
}

/// Sugar: `ospfv3 ...` on a physical interface means `subinterface 0 ospfv3 ...`.
pub fn untagged_ospfv3(_: Verb, args: &[&str], interface: &Value) -> Option<SugarOut> {
    untagged("ospfv3", args, interface)
}

// ---- `show config` halves (`#[cli(render = …)]`): the sugar lines that
// re-enter each value, so the generic round-trip test covers them too.

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// `crypto-key <id> <algorithm> <key>`, then `crypto-key <id> current`.
fn crypto_key_lines(keys: &Value) -> Vec<String> {
    let keys = keys.as_array().map_or(&[][..], Vec::as_slice);
    let alg = |k: &Value| {
        crate::cli::render::words(&OspfCryptoAlgorithm::kind(), &k["algorithm"]).join(" ")
    };
    let mut out: Vec<String> = keys
        .iter()
        .map(|k| format!("crypto-key {} {} {}", k["key_id"], alg(k), text(&k["key"])))
        .collect();
    out.extend(
        keys.iter()
            .filter(|k| k["is_current"] == Value::Bool(true))
            .map(|k| format!("crypto-key {} current", k["key_id"])),
    );
    out
}

/// `OspfProfile.auth`.
pub fn render_ospf_auth(auth: &Value) -> Vec<String> {
    match (auth.get("Simple"), auth.get("Crypto")) {
        (Some(s), _) => vec![format!("simple-password {}", text(&s["key"]))],
        (_, Some(c)) => crypto_key_lines(&c["keys"]),
        _ => Vec::new(),
    }
}

/// `Ospfv3Profile.auth` (the key list itself).
pub fn render_ospfv3_auth(auth: &Value) -> Vec<String> {
    crypto_key_lines(auth)
}

/// `BgpPeerGroup.auth`.
pub fn render_bgp_auth(auth: &Value) -> Vec<String> {
    if let Some(m) = auth.get("Md5") {
        return vec![format!("md5-password {}", text(&m["key_ref"]))];
    }
    let keys = auth["Ao"]["keys"].as_array().map_or(&[][..], Vec::as_slice);
    let alg =
        |k: &Value| crate::cli::render::words(&BgpAoAlgorithm::kind(), &k["algorithm"]).join(" ");
    let mut out = Vec::new();
    for k in keys {
        out.push(format!(
            "ao-key {} {} {} {}",
            k["send_id"],
            k["recv_id"],
            alg(k),
            text(&k["key_ref"])
        ));
        if k["exclude_options"] == Value::Bool(true) {
            out.push(format!("ao-key {} exclude-options", k["send_id"]));
        }
    }
    for (flag, word) in [("is_current", "current"), ("is_rnext", "rnext")] {
        out.extend(
            keys.iter()
                .filter(|k| k[flag] == Value::Bool(true))
                .map(|k| format!("ao-key {} {word}", k["send_id"])),
        );
    }
    out
}

/// `shutdown [<message…>]`.
pub fn render_shutdown(shutdown: &Value) -> Vec<String> {
    match shutdown["message"].as_str() {
        Some(m) => vec![format!("shutdown {m}")],
        None => vec!["shutdown".to_string()],
    }
}

#[cfg(test)]
#[path = "sugar_tests.rs"]
mod tests;
