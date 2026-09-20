use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Every failure a handler can report, rendered as `{"error": "..."}`.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
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
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            ApiError::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            ApiError::BadGateway(m) => (StatusCode::BAD_GATEWAY, m),
        };
        (status, Json(ErrorBody { error: msg })).into_response()
    }
}

/// The JSON body of every error response.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

pub type ApiResult<T> = Result<T, ApiError>;
