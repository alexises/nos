//! Rejecting and boundary cases for the CLI sugar functions (#360).

use super::*;
use Verb::{Delete, Set};

fn ao_group(keys: &Value) -> Value {
    json!({ "auth": { "Ao": { "keys": keys } } })
}

fn ao(send: u8, recv: u8, current: bool, rnext: bool, excl: bool) -> Value {
    json!({ "send_id": send, "recv_id": recv, "algorithm": "HmacSha1_96", "key_ref": "k",
            "is_current": current, "is_rnext": rnext, "exclude_options": excl })
}

fn keys_of(v: &Value) -> &Vec<Value> {
    v["Ao"]["keys"].as_array().unwrap()
}

fn flags(keys: &[Value], flag: &str) -> Vec<bool> {
    keys.iter().map(|k| k[flag] == json!(true)).collect()
}

#[test]
fn shutdown_message_is_the_remaining_words() {
    let o = Value::Null;
    assert_eq!(
        shutdown_value(Set, &[], &o),
        Some(json!({ "message": null }))
    );
    assert_eq!(
        shutdown_value(Set, &["a", "b"], &o),
        Some(json!({ "message": "a b" }))
    );
    assert_eq!(shutdown_value(Delete, &[], &o), Some(Value::Null));
    assert_eq!(shutdown_value(Delete, &["x"], &o), None);
}

#[test]
fn simple_and_md5_password_take_exactly_one_word_on_set() {
    let o = Value::Null;
    assert_eq!(
        simple_password_value(Set, &["pw"], &o),
        Some(json!({ "Simple": { "password": "pw" } }))
    );
    assert_eq!(
        md5_password_value(Set, &["pw"], &o),
        Some(json!({ "Md5": { "key_ref": "pw" } }))
    );
    for f in [simple_password_value, md5_password_value] {
        assert_eq!(f(Set, &[], &o), None);
        assert_eq!(f(Set, &["a", "b"], &o), None);
        assert_eq!(f(Delete, &[], &o), None);
        assert_eq!(f(Delete, &["pw"], &o), None);
    }
}

#[test]
fn ao_key_set_builds_a_key_with_all_flags_off() {
    let g = json!({ "auth": null });
    let out = ao_key_value(Set, &["1", "2", "hmac-sha1", "secret"], &g).unwrap();
    assert_eq!(
        out,
        json!({ "Ao": { "keys": [{
            "send_id": 1, "recv_id": 2, "algorithm": "HmacSha1_96", "key_ref": "secret",
            "is_current": false, "is_rnext": false, "exclude_options": false,
        }] } })
    );
    // Upsert replaces the same send-id rather than appending.
    let g = json!({ "auth": out });
    let out = ao_key_value(Set, &["1", "9", "aes-cmac", "other"], &g).unwrap();
    assert_eq!(keys_of(&out).len(), 1);
    assert_eq!(keys_of(&out)[0]["recv_id"], 9);
    let out = ao_key_value(Set, &["2", "3", "aes-cmac", "x"], &json!({ "auth": out })).unwrap();
    assert_eq!(keys_of(&out).len(), 2);
}

#[test]
fn ao_key_current_and_rnext_are_exclusive_flags() {
    let g = ao_group(&json!([
        ao(1, 1, true, false, false),
        ao(2, 2, false, true, false)
    ]));
    let out = ao_key_value(Set, &["2", "current"], &g).unwrap();
    assert_eq!(flags(keys_of(&out), "is_current"), [false, true]);
    // `current` leaves rnext alone.
    assert_eq!(flags(keys_of(&out), "is_rnext"), [false, true]);
    let out = ao_key_value(Set, &["1", "rnext"], &g).unwrap();
    assert_eq!(flags(keys_of(&out), "is_rnext"), [true, false]);
    assert_eq!(flags(keys_of(&out), "is_current"), [true, false]);
    // Unknown send-id, or no Ao auth at all, is not a flag edit.
    assert_eq!(ao_key_value(Set, &["9", "current"], &g), None);
    assert_eq!(ao_key_value(Set, &["9", "rnext"], &g), None);
    let none = json!({ "auth": null });
    assert_eq!(ao_key_value(Set, &["1", "current"], &none), None);
    assert_eq!(ao_key_value(Set, &["1", "rnext"], &none), None);
    let md5 = json!({ "auth": { "Md5": { "key_ref": "p" } } });
    assert_eq!(ao_key_value(Set, &["1", "current"], &md5), None);
}

#[test]
fn ao_key_exclude_options_toggles_per_key() {
    let g = ao_group(&json!([
        ao(1, 1, true, false, false),
        ao(2, 2, false, false, true)
    ]));
    let out = ao_key_value(Set, &["1", "exclude-options"], &g).unwrap();
    assert_eq!(flags(keys_of(&out), "exclude_options"), [true, true]);
    let out = ao_key_value(Delete, &["2", "exclude-options"], &g).unwrap();
    assert_eq!(flags(keys_of(&out), "exclude_options"), [false, false]);
    assert_eq!(ao_key_value(Set, &["9", "exclude-options"], &g), None);
}

#[test]
fn ao_key_rejects_malformed_ids_and_shapes() {
    let none = json!({ "auth": null });
    assert!(ao_key_value(Set, &["255", "2", "hmac-sha1", "k"], &none).is_some());
    assert!(ao_key_value(Set, &["1", "255", "hmac-sha1", "k"], &none).is_some());
    assert_eq!(
        ao_key_value(Set, &["256", "2", "hmac-sha1", "k"], &none),
        None
    );
    assert_eq!(
        ao_key_value(Set, &["x", "2", "hmac-sha1", "k"], &none),
        None
    );
    assert_eq!(
        ao_key_value(Set, &["1", "256", "hmac-sha1", "k"], &none),
        None
    );
    assert_eq!(
        ao_key_value(Set, &["1", "x", "hmac-sha1", "k"], &none),
        None
    );
    assert_eq!(ao_key_value(Set, &["1", "2", "nope", "k"], &none), None);
    assert_eq!(ao_key_value(Set, &["1", "2", "hmac-sha1"], &none), None);
    assert_eq!(ao_key_value(Set, &[], &none), None);
    let g = ao_group(&json!([ao(1, 1, true, false, false)]));
    assert_eq!(ao_key_value(Delete, &["1", "junk"], &g), None);
}

#[test]
fn ao_key_delete_removes_only_that_key_or_returns_auth() {
    let g = ao_group(&json!([
        ao(1, 1, true, false, false),
        ao(2, 2, false, false, false)
    ]));
    let out = ao_key_value(Delete, &["1"], &g).unwrap();
    assert_eq!(keys_of(&out).len(), 1);
    assert_eq!(keys_of(&out)[0]["send_id"], 2);
    // No Ao: the auth (here Md5) is returned untouched, only for `<id>` alone.
    let md5 = json!({ "auth": { "Md5": { "key_ref": "p" } } });
    assert_eq!(
        ao_key_value(Delete, &["1"], &md5),
        Some(md5["auth"].clone())
    );
    assert_eq!(ao_key_value(Delete, &["1", "2"], &md5), None);
    assert_eq!(ao_key_value(Delete, &["1", "current"], &md5), None);
}

fn crypto(id: u16, current: bool) -> Value {
    json!({ "key_id": id, "algorithm": "HmacSha256", "key": "k", "is_current": current })
}

fn crypto_profile(keys: &[Value]) -> Value {
    json!({ "auth": { "Crypto": { "keys": keys } } })
}

fn crypto_keys_of(v: &Value) -> &Vec<Value> {
    v["Crypto"]["keys"].as_array().unwrap()
}

#[test]
fn ospf_crypto_key_upserts_flags_and_deletes() {
    let none = json!({ "auth": null });
    let out = ospf_crypto_key_value(Set, &["1", "hmac-sha256", "k"], &none).unwrap();
    assert_eq!(out, json!({ "Crypto": { "keys": [crypto(1, false)] } }));
    // `current` needs existing Crypto auth (and the key).
    assert_eq!(ospf_crypto_key_value(Set, &["1", "current"], &none), None);
    let simple = json!({ "auth": { "Simple": { "password": "p" } } });
    assert_eq!(ospf_crypto_key_value(Set, &["1", "current"], &simple), None);
    // Upsert replaces the same id rather than appending, a new id appends.
    let p = crypto_profile(&[crypto(1, true)]);
    let out = ospf_crypto_key_value(Set, &["1", "hmac-sha1", "z"], &p).unwrap();
    assert_eq!(crypto_keys_of(&out).len(), 1);
    assert_eq!(crypto_keys_of(&out)[0]["algorithm"], "HmacSha1");
    let out = ospf_crypto_key_value(Set, &["2", "hmac-sha1", "z"], &p).unwrap();
    assert_eq!(crypto_keys_of(&out).len(), 2);
    // `current` moves the flag.
    let p = crypto_profile(&[crypto(1, true), crypto(2, false)]);
    let out = ospf_crypto_key_value(Set, &["2", "current"], &p).unwrap();
    assert_eq!(flags(crypto_keys_of(&out), "is_current"), [false, true]);
    assert_eq!(ospf_crypto_key_value(Set, &["3", "current"], &p), None);
    // Delete removes only that id.
    let out = ospf_crypto_key_value(Delete, &["1"], &p).unwrap();
    assert_eq!(crypto_keys_of(&out).len(), 1);
    assert_eq!(crypto_keys_of(&out)[0]["key_id"], 2);
    assert_eq!(
        ospf_crypto_key_value(Set, &["70000", "hmac-sha1", "z"], &p),
        None
    );
    assert_eq!(ospf_crypto_key_value(Set, &["1", "nope", "z"], &p), None);
}

#[test]
fn delete_crypto_key_without_auth_needs_one_valid_id() {
    let none = json!({ "auth": null });
    let simple = json!({ "auth": { "Simple": { "password": "p" } } });
    for bad in [&[][..], &["x"], &["70000"], &["1", "2"]] {
        assert_eq!(ospf_crypto_key_value(Delete, bad, &none), None, "{bad:?}");
        assert_eq!(ospfv3_crypto_key_value(Delete, bad, &none), None, "{bad:?}");
    }
    assert_eq!(
        ospf_crypto_key_value(Delete, &["65535"], &none),
        Some(Value::Null)
    );
    assert_eq!(
        ospf_crypto_key_value(Delete, &["65535"], &simple),
        Some(simple["auth"].clone())
    );
    assert_eq!(
        ospfv3_crypto_key_value(Delete, &["65535"], &none),
        Some(Value::Null)
    );
    assert!(valid_key_id(&["0"]) && !valid_key_id(&["65536"]));
}

#[test]
fn ospfv3_crypto_key_upserts_flags_and_deletes() {
    let none = json!({ "auth": null });
    let out = ospfv3_crypto_key_value(Set, &["1", "hmac-sha256", "k"], &none).unwrap();
    assert_eq!(out, json!([crypto(1, false)]));
    assert_eq!(ospfv3_crypto_key_value(Set, &["1", "current"], &none), None);
    let p = json!({ "auth": [crypto(1, true), crypto(2, false)] });
    let out = ospfv3_crypto_key_value(Set, &["2", "current"], &p).unwrap();
    assert_eq!(flags(out.as_array().unwrap(), "is_current"), [false, true]);
    let out = ospfv3_crypto_key_value(Set, &["1", "hmac-sha1", "z"], &p).unwrap();
    assert_eq!(out.as_array().unwrap().len(), 2);
    assert_eq!(out[0]["algorithm"], "HmacSha1");
    let out = ospfv3_crypto_key_value(Delete, &["2"], &p).unwrap();
    assert_eq!(out.as_array().unwrap().len(), 1);
    assert_eq!(out[0]["key_id"], 1);
}

#[test]
fn orlonger_and_upto_use_the_entry_prefix_length() {
    let v4 = json!({ "cidr": "10.0.0.0/8" });
    let v6 = json!({ "cidr": "2001:db8::/32" });
    assert_eq!(orlonger_value(Set, &[], &v4), Some(json!([8, 32])));
    assert_eq!(orlonger_value(Set, &[], &v6), Some(json!([32, 128])));
    assert_eq!(orlonger_value(Set, &["x"], &v4), None);
    assert_eq!(orlonger_value(Set, &[], &json!({ "cidr": "bogus" })), None);
    assert_eq!(upto_value(Set, &["24"], &v4), Some(json!([8, 24])));
    assert_eq!(upto_value(Set, &[], &v4), None);
    assert_eq!(upto_value(Set, &["24", "25"], &v4), None);
    assert_eq!(upto_value(Set, &["x"], &v4), None);
}

/// Feeds each rendered `<word> <args…>` line back through `f`.
fn replay(
    lines: &[String],
    mut auth: Value,
    f: fn(Verb, &[&str], &Value) -> Option<Value>,
) -> Value {
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().skip(1).collect();
        auth = f(Set, &words, &json!({ "auth": auth })).unwrap_or_else(|| panic!("{line}"));
    }
    auth
}

#[test]
fn render_ospf_auth_lines_and_round_trip() {
    assert_eq!(
        render_ospf_auth(&json!({ "Simple": { "password": "pw" } })),
        ["simple-password pw"]
    );
    let c = json!({ "Crypto": { "keys": [crypto(1, false), crypto(2, true)] } });
    let lines = render_ospf_auth(&c);
    assert_eq!(
        lines,
        [
            "crypto-key 1 hmac-sha256 k",
            "crypto-key 2 hmac-sha256 k",
            "crypto-key 2 current"
        ]
    );
    assert_eq!(replay(&lines, Value::Null, ospf_crypto_key_value), c);
    assert_eq!(render_ospf_auth(&Value::Null), Vec::<String>::new());
    assert_eq!(
        render_ospf_auth(&json!({ "Other": 1 })),
        Vec::<String>::new()
    );
}

#[test]
fn render_ospfv3_auth_round_trips() {
    let keys = json!([crypto(1, true), crypto(2, false)]);
    let lines = render_ospfv3_auth(&keys);
    assert_eq!(
        lines,
        [
            "crypto-key 1 hmac-sha256 k",
            "crypto-key 2 hmac-sha256 k",
            "crypto-key 1 current"
        ]
    );
    assert_eq!(replay(&lines, Value::Null, ospfv3_crypto_key_value), keys);
    assert_eq!(render_ospfv3_auth(&Value::Null), Vec::<String>::new());
}

#[test]
fn render_bgp_auth_lines_and_round_trip() {
    assert_eq!(
        render_bgp_auth(&json!({ "Md5": { "key_ref": "pw" } })),
        ["md5-password pw"]
    );
    let keys = json!([ao(1, 2, true, false, true), ao(3, 4, false, true, false)]);
    let auth = json!({ "Ao": { "keys": keys } });
    let lines = render_bgp_auth(&auth);
    assert_eq!(
        lines,
        [
            "ao-key 1 2 hmac-sha1 k",
            "ao-key 1 exclude-options",
            "ao-key 3 4 hmac-sha1 k",
            "ao-key 1 current",
            "ao-key 3 rnext",
        ]
    );
    assert_eq!(replay(&lines, Value::Null, ao_key_value), auth);
    assert_eq!(render_bgp_auth(&Value::Null), Vec::<String>::new());
}

#[test]
fn render_shutdown_with_and_without_message() {
    assert_eq!(
        render_shutdown(&json!({ "message": "bye" })),
        ["shutdown bye"]
    );
    assert_eq!(render_shutdown(&json!({ "message": null })), ["shutdown"]);
}

#[test]
fn public_entry_points_wrap_the_value_in_sugar_out() {
    let none = json!({ "auth": null });
    let v = |o: Option<SugarOut>| match o {
        Some(SugarOut::Value(v)) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!(v(shutdown(Set, &[], &none)), json!({ "message": null }));
    assert_eq!(
        v(md5_password(Set, &["p"], &none)),
        json!({ "Md5": { "key_ref": "p" } })
    );
    assert_eq!(
        v(simple_password(Set, &["p"], &none)),
        json!({ "Simple": { "password": "p" } })
    );
    assert!(ao_key(Set, &["1", "2", "hmac-sha1", "k"], &none).is_some());
    assert!(ospf_crypto_key(Set, &["1", "hmac-sha1", "k"], &none).is_some());
    assert!(ospfv3_crypto_key(Set, &["1", "hmac-sha1", "k"], &none).is_some());
    let e = json!({ "cidr": "10.0.0.0/8" });
    assert_eq!(v(orlonger(Set, &[], &e)), json!([8, 32]));
    assert_eq!(v(upto(Set, &["16"], &e)), json!([8, 16]));
}

#[test]
fn untagged_rewrites_physical_interfaces_only() {
    let eth = json!({ "name": "eth0" });
    assert_eq!(
        untagged_address(Set, &["10.0.0.1/24"], &eth),
        Some(SugarOut::Words(
            ["subinterface", "0", "address", "10.0.0.1/24"]
                .map(String::from)
                .to_vec()
        ))
    );
    assert!(untagged_routing_table(Set, &[], &eth).is_some());
    assert!(untagged_ospf(Set, &[], &eth).is_some());
    assert!(untagged_ospfv3(Set, &[], &eth).is_some());
    let lo = json!({ "name": "loopback-0" });
    assert_eq!(untagged_address(Set, &[], &lo), None);
}
