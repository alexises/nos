use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Every failure a handler can report, rendered as an RFC 9457 problem document.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    /// No valid client certificate, or a login that failed.
    Unauthorized(String),
    NotFound(String),
    /// Well-formed request the config rejected (commit-time validation).
    Unprocessable(String),
    /// A daemon this endpoint needs isn't reachable right now.
    Unavailable(String),
    /// A daemon answered with something this endpoint can't interpret.
    BadGateway(String),
}

impl ApiError {
    /// Maps an `Event::Error` message from `nos-configd` onto a status. The
    /// daemon sends plain strings, so this keys on the stable prefixes of
    /// `nos-config`'s `ConfigError` messages.
    pub fn from_config(msg: String) -> Self {
        if msg.starts_with("no transaction named") {
            ApiError::NotFound(msg)
        } else if msg.starts_with("validation failed") {
            ApiError::Unprocessable(msg)
        } else {
            ApiError::BadRequest(msg)
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized(m) => {
                // RFC 9110 §15.5.2: a 401 MUST carry a challenge. The scheme is
                // a client certificate, so this names the flow that gets one.
                let mut resp = problem(StatusCode::UNAUTHORIZED, m);
                resp.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(r#"Mutual realm="nos", login="/v1/login""#),
                );
                return resp;
            }
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            ApiError::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            ApiError::BadGateway(m) => (StatusCode::BAD_GATEWAY, m),
        };
        problem(status, msg)
    }
}

fn problem(status: StatusCode, detail: String) -> Response {
    let body = ErrorBody {
        type_: "about:blank".to_string(),
        title: status.canonical_reason().unwrap_or("Error").to_string(),
        status: status.as_u16(),
        detail,
    };
    (
        status,
        [(header::CONTENT_TYPE, PROBLEM_JSON)],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

/// Outermost layer: errors the framework produces itself (unknown route 404,
/// 405, a malformed path/query/JSON body rejected by an extractor) are bare
/// or plain text; re-render them as problem documents. Anything already a
/// problem, and every non-error response (incl. the SSE stream), passes through.
pub async fn problem_for_framework_errors(resp: Response) -> Response {
    let is_error = resp.status().is_client_error() || resp.status().is_server_error();
    let is_problem = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v == PROBLEM_JSON);
    if !is_error || is_problem {
        return resp;
    }
    let status = resp.status();
    // RFC 9110 §15.5.6: axum's 405 carries `Allow`; keep it.
    let allow = resp.headers().get(header::ALLOW).cloned();
    // Framework messages are one short line; cap the read anyway.
    let bytes = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    let detail = if text.is_empty() {
        status.canonical_reason().unwrap_or("Error").to_string()
    } else {
        text
    };
    let mut out = problem(status, detail);
    if let Some(allow) = allow {
        out.headers_mut().insert(header::ALLOW, allow);
    }
    out
}

/// Media type of every error response (RFC 9457).
pub const PROBLEM_JSON: &str = "application/problem+json";

/// The body of every error response: an RFC 9457 problem document.
/// `instance` is omitted (optional in the RFC; a handler can't see the URI).
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    /// Always `about:blank`: the status code alone says what kind of problem it is.
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub type_: String,
    /// The HTTP status' reason phrase.
    pub title: String,
    pub status: u16,
    /// What went wrong, for this request.
    pub detail: String,
}

pub type ApiResult<T> = Result<T, ApiError>;
