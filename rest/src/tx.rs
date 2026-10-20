//! Transaction endpoints. The config tree is the URL tree: `/v1/transactions/<tx>`
//! is the whole in-progress config, and everything below it is a subsection
//! addressed by `nos_proto::config_path` (e.g.
//! `/v1/transactions/t1/bgp-instance/r1/peer-group/pg1`).
//!
//! Handlers take the raw `Uri` and split its path themselves, so a key that
//! contains an encoded `/` (a static route's subnet, `10.1.0.0%2F16`) stays one
//! segment — decoding only happens per segment, after the split.

use crate::auth::PeerUser;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use nos_proto::config_path;
use nos_proto::{Config, ConfigDiff, Event, Request, TransactionBase, TransactionSnapshot};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde_json::{json, Value};

use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::ipc::{unexpected, Daemons};

const PREFIX: &str = "/v1/transactions/";

#[derive(serde::Serialize, ToSchema)]
pub struct CommitResult {
    committed: String,
    /// Non-blocking advice about the committed config; `[]` when none.
    warnings: Vec<String>,
}

/// `(transaction name, config path segments)` from the request URI.
fn split(uri: &Uri) -> ApiResult<(String, Vec<String>)> {
    let rest = uri
        .path()
        .strip_prefix(PREFIX)
        .ok_or_else(|| ApiError::BadRequest("not a transaction path".to_string()))?;
    let mut segs = rest.split('/').filter(|s| !s.is_empty()).map(|s| {
        percent_decode_str(s)
            .decode_utf8()
            .map(std::borrow::Cow::into_owned)
            .map_err(|_| ApiError::BadRequest(format!("path segment '{s}' is not UTF-8")))
    });
    let tx = segs
        .next()
        .ok_or_else(|| ApiError::BadRequest("missing transaction name".to_string()))??;
    Ok((tx, segs.collect::<ApiResult<_>>()?))
}

fn snapshot(ev: Event) -> ApiResult<TransactionSnapshot> {
    match ev {
        Event::Transaction(s) => Ok(s),
        other => Err(unexpected("nos-configd", &other)),
    }
}

/// The subsection of `snap`'s config at `path` (the whole config for an empty path).
fn subsection(snap: &TransactionSnapshot, path: &[String]) -> ApiResult<Value> {
    let doc = serde_json::to_value(&snap.config)
        .map_err(|e| ApiError::BadGateway(format!("config is not JSON-representable: {e}")))?;
    config_path::get(&doc, path)
        .cloned()
        .map_err(|e| ApiError::NotFound(e.to_string()))
}

#[derive(Deserialize)]
pub struct OpenQuery {
    base: Option<String>,
}

/// The transaction's `ETag` (RFC 9110 §8.8.3): its generation as a strong,
/// quoted decimal — every edit is a real content change, never `W/`.
fn etag(generation: u64) -> (HeaderName, HeaderValue) {
    (
        header::ETAG,
        HeaderValue::from_str(&format!("\"{generation}\"")).expect("digits are valid"),
    )
}

/// A parsed `If-Match`/`If-None-Match` (RFC 9110 §13.1.1/§13.1.2).
#[derive(Debug, PartialEq, Eq)]
enum Condition {
    /// `*` — any current representation.
    Any,
    /// `"<generation>"`.
    Generation(u64),
}

impl Condition {
    /// The header, if sent. Only one strong `"<digits>"` entity tag or `*` is
    /// meaningful against a monotonic counter; anything else is a 400.
    fn from_header(headers: &HeaderMap, name: &HeaderName) -> ApiResult<Option<Self>> {
        let Some(raw) = headers.get(name) else {
            return Ok(None);
        };
        let bad = || ApiError::BadRequest(format!("{name} must be * or a quoted decimal ETag"));
        let s = raw.to_str().map_err(|_| bad())?.trim();
        if s == "*" {
            return Ok(Some(Condition::Any));
        }
        s.strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .and_then(|s| s.parse().ok())
            .map(|g| Some(Condition::Generation(g)))
            .ok_or_else(bad)
    }

    fn matches(&self, generation: u64) -> bool {
        match self {
            Condition::Any => true,
            Condition::Generation(g) => *g == generation,
        }
    }
}

/// `If-Match` as the store's `if_match`: `*` is no store-side precondition,
/// since the transaction's existence is already checked there (404).
fn if_match(headers: &HeaderMap) -> ApiResult<Option<u64>> {
    Ok(match Condition::from_header(headers, &header::IF_MATCH)? {
        Some(Condition::Generation(g)) => Some(g),
        Some(Condition::Any) | None => None,
    })
}

/// `POST /v1/transactions/<tx>?base=blank|current` — open, or resume if it exists.
#[utoipa::path(post, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Open (or resume) a transaction", params(("tx" = String, Path, description = "transaction name"), ("base" = Option<String>, Query, description = "blank | current (default current)")), responses((status = 201, body = TransactionSnapshot, description = "created; `ETag` is the transaction's generation"), (status = 200, body = TransactionSnapshot, description = "resumed; `ETag` is the transaction's generation"), (status = 400, body = ErrorBody)))]
pub async fn open(
    State(d): State<Daemons>,
    Extension(PeerUser(actor, _)): Extension<PeerUser>,
    uri: Uri,
    Query(q): Query<OpenQuery>,
) -> ApiResult<Response> {
    let (name, path) = split(&uri)?;
    if !path.is_empty() {
        return Err(ApiError::BadRequest(
            "POST opens a transaction; use PUT to set a subsection".to_string(),
        ));
    }
    let base = match q.base.as_deref() {
        None | Some("current") => TransactionBase::Current,
        Some("blank") => TransactionBase::Blank,
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "base must be 'blank' or 'current', not '{other}'"
            )))
        }
    };
    let snap = snapshot(
        d.config(Request::OpenTransaction { name, base, actor })
            .await?,
    )?;
    let status = if snap.resumed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, [etag(snap.generation)], Json(snap)).into_response())
}

/// `GET /v1/transactions/<tx>[/<path>]` — the transaction, or one subsection of it.
/// `If-None-Match` against the transaction's `ETag` gives `304` on a match.
#[utoipa::path(get, path = "/v1/transactions/{tx}", tag = "transactions", summary = "The whole in-progress config", params(("tx" = String, Path, description = "transaction name"), ("If-None-Match" = Option<String>, Header, description = "RFC 9110 §13.1.2: `*` or the `ETag` of an earlier reply; 304 if it still matches")), responses((status = 200, body = TransactionSnapshot, description = "`ETag` is the transaction's generation"), (status = 304, description = "If-None-Match matched the transaction's current generation"), (status = 404, body = ErrorBody, description = "no such transaction or config path")))]
pub async fn get(State(d): State<Daemons>, uri: Uri, headers: HeaderMap) -> ApiResult<Response> {
    let (name, path) = split(&uri)?;
    let snap = snapshot(d.config(Request::GetTransaction { name }).await?)?;
    let value = if path.is_empty() {
        json!(snap)
    } else {
        subsection(&snap, &path)?
    };
    let tag = etag(snap.generation);
    if Condition::from_header(&headers, &header::IF_NONE_MATCH)?
        .is_some_and(|c| c.matches(snap.generation))
    {
        // RFC 9110 §15.4.5: no body on a 304.
        return Ok((StatusCode::NOT_MODIFIED, [tag]).into_response());
    }
    Ok(([tag], Json(value)).into_response())
}

/// `PUT /v1/transactions/<tx>[/<path>]` — set the whole config, or one
/// subsection (creating a list element that doesn't exist yet). Replies with
/// the stored value.
#[utoipa::path(put, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Set the whole config", params(("tx" = String, Path, description = "transaction name"), ("If-Match" = Option<String>, Header, description = "RFC 9110 §13.1.1: `*` or the `ETag` of an earlier reply; the edit is refused (412) unless it still matches")), request_body = Config, responses((status = 200, body = TransactionSnapshot, description = "`ETag` is the transaction's new generation"), (status = 400, body = ErrorBody), (status = 404, body = ErrorBody, description = "no such transaction or config path"), (status = 412, body = ErrorBody, description = "If-Match did not match the transaction's current generation")))]
pub async fn put(
    State(d): State<Daemons>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let (name, path) = split(&uri)?;
    let if_match = if_match(&headers)?;
    let value = String::from_utf8(body.to_vec())
        .map_err(|_| ApiError::BadRequest("body is not UTF-8".to_string()))?;
    let snap = snapshot(
        d.config(Request::SetTransactionPath {
            name,
            path: path.clone(),
            value: Some(value),
            if_match,
        })
        .await?,
    )?;
    let value = if path.is_empty() {
        json!(snap)
    } else {
        subsection(&snap, &path)?
    };
    Ok(([etag(snap.generation)], Json(value)).into_response())
}

/// `DELETE /v1/transactions/<tx>` discards the transaction;
/// `DELETE /v1/transactions/<tx>/<path>` removes that subsection (the reply's
/// `ETag` is the transaction's new generation).
#[utoipa::path(delete, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Discard the transaction", params(("tx" = String, Path, description = "transaction name"), ("If-Match" = Option<String>, Header, description = "RFC 9110 §13.1.1: `*` or the `ETag` of an earlier reply; refused (412) unless it still matches")), responses((status = 204), (status = 404, body = ErrorBody, description = "no such transaction or config path"), (status = 412, body = ErrorBody, description = "If-Match did not match the transaction's current generation")))]
pub async fn delete(State(d): State<Daemons>, uri: Uri, headers: HeaderMap) -> ApiResult<Response> {
    let (name, path) = split(&uri)?;
    let if_match = if_match(&headers)?;
    if path.is_empty() {
        match d
            .config(Request::DiscardTransaction { name, if_match })
            .await?
        {
            Event::Discarded => Ok(StatusCode::NO_CONTENT.into_response()),
            other => Err(unexpected("nos-configd", &other)),
        }
    } else {
        let snap = snapshot(
            d.config(Request::SetTransactionPath {
                name,
                path,
                value: None,
                if_match,
            })
            .await?,
        )?;
        Ok((StatusCode::NO_CONTENT, [etag(snap.generation)]).into_response())
    }
}

/// `GET /v1/transactions/<tx>/diff` — what a commit would change.
#[utoipa::path(get, path = "/v1/transactions/{tx}/diff", tag = "transactions", summary = "What a commit would change", params(("tx" = String, Path, description = "transaction name")), responses((status = 200, body = ConfigDiff), (status = 404, body = ErrorBody, description = "no such transaction or config path")))]
pub async fn diff(State(d): State<Daemons>, uri: Uri) -> ApiResult<Json<ConfigDiff>> {
    let (name, _) = split(&uri)?;
    match d.config(Request::DiffTransaction { name }).await? {
        Event::Diff(diff) => Ok(Json(diff)),
        other => Err(unexpected("nos-configd", &other)),
    }
}

/// `POST /v1/transactions/<tx>/commit` — validate and promote to running.
/// On a validation error (or a failed `If-Match`) the transaction stays open.
#[utoipa::path(post, path = "/v1/transactions/{tx}/commit", tag = "transactions", summary = "Validate and commit", params(("tx" = String, Path, description = "transaction name"), ("If-Match" = Option<String>, Header, description = "RFC 9110 §13.1.1: `*` or the `ETag` of an earlier reply; refused (412) unless it still matches")), responses((status = 200, body = CommitResult), (status = 422, body = ErrorBody, description = "validation failed; the transaction stays open"), (status = 404, body = ErrorBody, description = "no such transaction or config path"), (status = 412, body = ErrorBody, description = "If-Match did not match the transaction's current generation; the transaction stays open")))]
pub async fn commit(
    State(d): State<Daemons>,
    Extension(PeerUser(actor, _)): Extension<PeerUser>,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let (name, _) = split(&uri)?;
    let if_match = if_match(&headers)?;
    match d
        .config(Request::CommitTransaction {
            actor,
            name: name.clone(),
            if_match,
        })
        .await?
    {
        Event::Committed { warnings } => Ok(Json(json!(CommitResult {
            committed: name,
            warnings
        }))),
        other => Err(unexpected("nos-configd", &other)),
    }
}

/// `POST /v1/config/save` — persist the running config to disk, like the
/// CLI's `save`. A commit is live but not persisted until this is called.
#[utoipa::path(post, path = "/v1/config/save", tag = "transactions", summary = "Save the running config to disk", responses((status = 204, description = "the running config was written to disk"), (status = 502, body = ErrorBody, description = "nos-configd has no config file, or could not write it")))]
pub async fn save(State(d): State<Daemons>) -> ApiResult<StatusCode> {
    match d.config(Request::Save).await {
        Ok(Event::Saved) => Ok(StatusCode::NO_CONTENT),
        Ok(other) => Err(unexpected("nos-configd", &other)),
        // A failed save is nos-configd's fault (no --config-file, or a disk
        // error), not the client's: `from_config` would make it a 400.
        Err(ApiError::BadRequest(m)) => Err(ApiError::BadGateway(m)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(name: HeaderName, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn commit_result_always_carries_warnings() {
        let r = |warnings: Vec<String>| {
            serde_json::to_value(CommitResult {
                committed: "t".into(),
                warnings,
            })
            .unwrap()
        };
        assert_eq!(r(vec![]), json!({"committed": "t", "warnings": []}));
        assert_eq!(r(vec!["w".into()])["warnings"], json!(["w"]));
    }

    #[test]
    fn conditions_parse_star_and_quoted_generation_only() {
        let h = HeaderMap::new();
        assert_eq!(Condition::from_header(&h, &header::IF_MATCH).unwrap(), None);
        for (raw, want) in [("*", Condition::Any), ("\"17\"", Condition::Generation(17))] {
            let h = headers(header::IF_MATCH, raw);
            assert_eq!(
                Condition::from_header(&h, &header::IF_MATCH).unwrap(),
                Some(want)
            );
        }
        for raw in ["17", "W/\"17\"", "\"x\"", "\"1\", \"2\""] {
            let h = headers(header::IF_NONE_MATCH, raw);
            assert!(matches!(
                Condition::from_header(&h, &header::IF_NONE_MATCH),
                Err(ApiError::BadRequest(_))
            ));
        }
        assert_eq!(if_match(&headers(header::IF_MATCH, "*")).unwrap(), None);
        assert_eq!(
            if_match(&headers(header::IF_MATCH, "\"3\"")).unwrap(),
            Some(3)
        );
        assert_eq!(etag(3).1, "\"3\"");
    }
}
