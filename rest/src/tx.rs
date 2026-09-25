//! Transaction endpoints. The config tree is the URL tree: `/v1/transactions/<tx>`
//! is the whole in-progress config, and everything below it is a subsection
//! addressed by `nos_proto::config_path` (e.g.
//! `/v1/transactions/t1/bgp-instance/r1/peer-group/pg1`).
//!
//! Handlers take the raw `Uri` and split its path themselves, so a key that
//! contains an encoded `/` (a static route's subnet, `10.1.0.0%2F16`) stays one
//! segment — decoding only happens per segment, after the split.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri};
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

/// `POST /v1/transactions/<tx>?base=blank|current` — open, or resume if it exists.
#[utoipa::path(post, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Open (or resume) a transaction", params(("tx" = String, Path, description = "transaction name"), ("base" = Option<String>, Query, description = "blank | current (default current)")), responses((status = 201, body = TransactionSnapshot, description = "created"), (status = 200, body = TransactionSnapshot, description = "resumed"), (status = 400, body = ErrorBody)))]
pub async fn open(
    State(d): State<Daemons>,
    uri: Uri,
    Query(q): Query<OpenQuery>,
) -> ApiResult<(StatusCode, Json<TransactionSnapshot>)> {
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
    let snap = snapshot(d.config(Request::OpenTransaction { name, base }).await?)?;
    let status = if snap.resumed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(snap)))
}

/// `GET /v1/transactions/<tx>[/<path>]` — the transaction, or one subsection of it.
#[utoipa::path(get, path = "/v1/transactions/{tx}", tag = "transactions", summary = "The whole in-progress config", params(("tx" = String, Path, description = "transaction name")), responses((status = 200, body = TransactionSnapshot), (status = 404, body = ErrorBody, description = "no such transaction or config path")))]
pub async fn get(State(d): State<Daemons>, uri: Uri) -> ApiResult<Json<Value>> {
    let (name, path) = split(&uri)?;
    let snap = snapshot(d.config(Request::GetTransaction { name }).await?)?;
    if path.is_empty() {
        return Ok(Json(json!(snap)));
    }
    Ok(Json(subsection(&snap, &path)?))
}

/// `PUT /v1/transactions/<tx>[/<path>]` — set the whole config, or one
/// subsection (creating a list element that doesn't exist yet). Replies with
/// the stored value.
#[utoipa::path(put, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Set the whole config", params(("tx" = String, Path, description = "transaction name")), request_body = Config, responses((status = 200, body = TransactionSnapshot), (status = 400, body = ErrorBody), (status = 404, body = ErrorBody, description = "no such transaction or config path")))]
pub async fn put(State(d): State<Daemons>, uri: Uri, body: Bytes) -> ApiResult<Json<Value>> {
    let (name, path) = split(&uri)?;
    let value = String::from_utf8(body.to_vec())
        .map_err(|_| ApiError::BadRequest("body is not UTF-8".to_string()))?;
    let snap = snapshot(
        d.config(Request::SetTransactionPath {
            name,
            path: path.clone(),
            value: Some(value),
        })
        .await?,
    )?;
    if path.is_empty() {
        return Ok(Json(json!(snap)));
    }
    Ok(Json(subsection(&snap, &path)?))
}

/// `DELETE /v1/transactions/<tx>` discards the transaction;
/// `DELETE /v1/transactions/<tx>/<path>` removes that subsection.
#[utoipa::path(delete, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Discard the transaction", params(("tx" = String, Path, description = "transaction name")), responses((status = 204), (status = 404, body = ErrorBody, description = "no such transaction or config path")))]
pub async fn delete(State(d): State<Daemons>, uri: Uri) -> ApiResult<StatusCode> {
    let (name, path) = split(&uri)?;
    if path.is_empty() {
        match d.config(Request::DiscardTransaction { name }).await? {
            Event::Discarded => {}
            other => return Err(unexpected("nos-configd", &other)),
        }
    } else {
        snapshot(
            d.config(Request::SetTransactionPath {
                name,
                path,
                value: None,
            })
            .await?,
        )?;
    }
    Ok(StatusCode::NO_CONTENT)
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
/// On a validation error the transaction stays open (422).
#[utoipa::path(post, path = "/v1/transactions/{tx}/commit", tag = "transactions", summary = "Validate and commit", params(("tx" = String, Path, description = "transaction name")), responses((status = 200, body = CommitResult), (status = 422, body = ErrorBody, description = "validation failed; the transaction stays open"), (status = 404, body = ErrorBody, description = "no such transaction or config path")))]
pub async fn commit(State(d): State<Daemons>, uri: Uri) -> ApiResult<Json<Value>> {
    let (name, _) = split(&uri)?;
    match d
        .config(Request::CommitTransaction { name: name.clone() })
        .await?
    {
        Event::Committed => Ok(Json(json!(CommitResult { committed: name }))),
        other => Err(unexpected("nos-configd", &other)),
    }
}
