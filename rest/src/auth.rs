//! HTTP Basic authentication for every route (including `/openapi.json`,
//! `/swagger-ui/` and the SSE log stream). Credentials are checked against
//! `Config.users` (argon2id hashes) fetched from `nos-configd` per request, the
//! same way every handler reads config — so a user added/removed/re-passworded
//! by a commit takes effect on the very next request. Fails closed: if
//! `nos-configd` can't be reached the request is refused (503), never let through.
//!
//! ponytail: one config `Get` plus one argon2 verify per request. Add a short-TTL
//! cache of verified credentials only if that is ever measured to matter.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::error::ErrorBody;
use crate::ipc::Daemons;

/// Declares the HTTP Basic scheme in the `OpenAPI` document (so Swagger UI offers
/// an "Authorize" button) — the global `security` requirement is on `ApiDoc`.
pub struct BasicAuthScheme;

impl utoipa::Modify for BasicAuthScheme {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "basic",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Basic).build()),
            );
    }
}

pub async fn basic_auth(State(daemons): State<Daemons>, req: Request, next: Next) -> Response {
    let Some((user, password)) = credentials(req.headers()) else {
        return unauthorized();
    };
    let config = match daemons.running_config().await {
        Ok(config) => config,
        Err(e) => return e.into_response(),
    };
    let hash = config
        .users
        .into_iter()
        .find(|u| u.name == user)
        .map(|u| u.password);
    let ok = tokio::task::spawn_blocking(move || {
        nos_password::verify_or_dummy(&password, hash.as_deref())
    })
    .await
    .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        unauthorized()
    }
}

/// `(user, password)` from an `Authorization: Basic <base64(user:password)>` header.
fn credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let (user, password) = String::from_utf8(decoded)
        .ok()?
        .split_once(':')
        .map(|(u, p)| (u.to_string(), p.to_string()))?;
    Some((user, password))
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Basic realm="nos""#),
        )],
        axum::Json(ErrorBody {
            error: "authentication required".to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, v.parse().unwrap());
        h
    }

    #[test]
    fn parses_basic_and_keeps_colons_in_the_password() {
        // "alice:pa:ss"
        let h = headers("Basic YWxpY2U6cGE6c3M=");
        assert_eq!(credentials(&h), Some(("alice".into(), "pa:ss".into())));
        assert_eq!(
            credentials(&headers("basic YWxpY2U6cGE6c3M=")),
            Some(("alice".into(), "pa:ss".into()))
        );
    }

    #[test]
    fn rejects_other_schemes_and_garbage() {
        assert_eq!(credentials(&headers("Bearer abc")), None);
        assert_eq!(credentials(&headers("Basic !!!")), None);
        assert_eq!(credentials(&HeaderMap::new()), None);
    }
}
