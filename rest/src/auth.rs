//! Client-certificate authentication for every route (including `/openapi.json`,
//! `/swagger-ui/` and the SSE log stream). The TLS layer has already verified
//! the certificate against the REST CA; `PeerUser` is the user its URI SAN
//! names (`listen.rs` puts it on each connection's requests). Here the user
//! must also *still exist* in `Config.users` — fetched from `nos-configd` per
//! request like every handler's config read — so a deleted user is locked out
//! on the very next request rather than when their certificate expires.
//! Fails closed: a request with no verified user is 401, and if `nos-configd`
//! can't be reached it is refused (503), never let through.
//!
//! The one exception is `POST /v1/login`, which is how a client with no
//! certificate yet gets one (`login.rs`).
//!
//! ponytail: one config `Get` per request (a pooled IPC round trip, no
//! handshake). Add a short-TTL cache of the user list only if that is measured
//! to matter.

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use utoipa::openapi::security::SecurityScheme;

use crate::error::ErrorBody;
use crate::ipc::Daemons;

pub const LOGIN_PATH: &str = "/v1/login";

/// The user named by the client certificate this request's connection
/// presented; `None` if it presented none. Set per connection by the listener.
#[derive(Clone, Debug)]
pub struct PeerUser(pub Option<String>);

/// Declares the mutual-TLS scheme in the `OpenAPI` document — the global
/// `security` requirement is on `ApiDoc`.
pub struct MutualTlsScheme;

impl utoipa::Modify for MutualTlsScheme {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "mtls",
                SecurityScheme::MutualTls {
                    description: Some(
                        "A client certificate issued by POST /v1/login (or /v1/renew)".to_string(),
                    ),
                    extensions: None,
                },
            );
    }
}

pub async fn client_auth(State(daemons): State<Daemons>, req: Request, next: Next) -> Response {
    if req.method() == Method::POST && req.uri().path() == LOGIN_PATH {
        return next.run(req).await;
    }
    let Some(user) = req.extensions().get::<PeerUser>().and_then(|p| p.0.clone()) else {
        return unauthorized();
    };
    match daemons.running_config().await {
        Ok(config) if config.users.iter().any(|u| u.name == user) => next.run(req).await,
        Ok(_) => unauthorized(),
        Err(e) => e.into_response(),
    }
}

fn unauthorized() -> Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(ErrorBody {
            error: "a client certificate is required (POST /v1/login to get one)".to_string(),
        }),
    )
        .into_response()
}
