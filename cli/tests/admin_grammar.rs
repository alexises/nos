//! The keystore (#507) is reachable through the generic config grammar like
//! any other section: `edit admin`, `set admin key <label> secret <value>`.

use nos_cli::config_grammar;
use nos_proto::{config_path, Config};

#[test]
fn the_admin_keystore_is_editable_through_the_generic_grammar() {
    let empty = serde_json::to_value(Config::default()).unwrap();
    let edit = config_grammar::parse("edit admin", &[], &empty).expect("`edit admin`");
    assert_eq!(edit.navigate, Some(vec!["admin".to_string()]));

    for (line, at) in [
        ("set admin key k1 secret hunter2", vec![]),
        ("set key k1 secret hunter2", vec!["admin".to_string()]),
    ] {
        let edit = config_grammar::parse(line, &at, &empty).unwrap_or_else(|| panic!("`{line}`"));
        let mut applied = empty.clone();
        for (path, value) in edit.writes {
            config_path::set(&mut applied, &path, value).unwrap();
        }
        let cfg: Config = serde_json::from_value(applied).unwrap();
        assert_eq!(cfg.key("k1"), Some("hunter2"), "{line}");
    }
}
