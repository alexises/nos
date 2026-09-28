//! `docs/openapi.json` is the checked-in copy of the `OpenAPI` document the user
//! docs link to. This fails as soon as it no longer matches what `nos-restd`
//! serves; `make docs-fix` (which sets `UPDATE_OPENAPI_SNAPSHOT`) rewrites it.

use std::path::PathBuf;

#[test]
fn docs_openapi_snapshot_is_current() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/openapi.json");
    let fresh = serde_json::to_string_pretty(&nos_rest::api::openapi_document()).unwrap() + "\n";
    if std::env::var_os("UPDATE_OPENAPI_SNAPSHOT").is_some() {
        std::fs::write(&path, &fresh).unwrap();
        return;
    }
    let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        checked_in == fresh,
        "docs/openapi.json is stale: run `make docs-fix` and commit the result"
    );
}
