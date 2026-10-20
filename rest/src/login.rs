//! Getting a client certificate. `POST /v1/login` trades a password for one —
//! the only route reachable without a certificate — and `POST /v1/renew`
//! trades a still-valid one for a fresh one. Both ask `nos-watchdogd` (the CA)
//! over the shared IPC connection; the client's private key never leaves it.
//!
//! The certificate is issued by the REST CA on the public key in the CSR the
//! client sends (an ECDSA P-256 key — `openssl req -new -newkey ec
//! -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -outform DER`, the
//! DER base64-encoded). Later requests present it in the TLS handshake and
//! carry no password.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::{Extension, Json};
use base64::Engine as _;
use nos_proto::{WatchdogEvent, WatchdogRequest, INVALID_CREDENTIALS, SESSION_EXPIRED};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::PeerUser;
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::ipc::Daemons;

/// A failed login costs the account this much before the next attempt on it.
// ponytail: per-username only — many usernames in parallel are unthrottled
// (each still costs an argon2 verify). Add a per-source limit if that matters.
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(1);

/// After this many failures inside `FAILED_LOGIN_WINDOW` (counted from the
/// first), further attempts on the account get `429` until the window ends.
const MAX_FAILED_LOGINS: u32 = 5;
const FAILED_LOGIN_WINDOW: Duration = Duration::from_secs(60);

/// One attempt at a time per username, so guessing one account's password is
/// limited to one guess per `FAILED_LOGIN_DELAY` however many streams or
/// connections the guesses arrive on.
#[derive(Default)]
pub struct LoginGate {
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Per username: failures so far and when the window opened.
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginGate {
    /// Seconds until `user` may try again, if it is locked out.
    fn retry_after(&self, user: &str) -> Option<u64> {
        let failures = self.failures.lock().expect("login gate lock");
        let &(count, since) = failures.get(user)?;
        let left = FAILED_LOGIN_WINDOW.checked_sub(since.elapsed())?;
        (count >= MAX_FAILED_LOGINS).then(|| left.as_secs() + 1)
    }

    fn record_failure(&self, user: &str) {
        let mut failures = self.failures.lock().expect("login gate lock");
        // Drop expired windows so made-up usernames can't grow the map forever.
        failures.retain(|_, (_, since)| since.elapsed() < FAILED_LOGIN_WINDOW);
        failures
            .entry(user.to_string())
            .or_insert((0, Instant::now()))
            .0 += 1;
    }

    fn clear(&self, user: &str) {
        self.failures.lock().expect("login gate lock").remove(user);
    }

    fn lock_for(&self, user: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .expect("login gate lock")
            .entry(user.to_string())
            .or_default()
            .clone()
    }

    /// Forgets `user` once nobody else is waiting on it.
    fn release(&self, user: &str, mine: &Arc<tokio::sync::Mutex<()>>) {
        let mut gates = self.locks.lock().expect("login gate lock");
        // The map's copy and ours: nobody else holds it.
        if Arc::strong_count(mine) == 2 {
            gates.remove(user);
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub user: String,
    pub password: String,
    /// Base64 of a DER PKCS#10 certificate request for an ECDSA P-256 key you generated.
    pub csr: String,
}

// A `Debug` that hides the password: request bodies must never be one log line
// from leaking it.
impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("user", &self.user)
            .field("password", &"<hidden>")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RenewRequest {
    /// As `LoginRequest::csr`, for a fresh key.
    pub csr: String,
}

#[derive(Serialize, ToSchema)]
pub struct Certificate {
    /// Base64 of the DER client certificate, issued by the REST CA.
    pub certificate: String,
    /// Seconds it is valid for; renew at half of that.
    pub lifetime_secs: u64,
}

fn decode_csr(csr: &str) -> ApiResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(csr.trim())
        .map_err(|_| ApiError::BadRequest("csr is not valid base64".to_string()))
}

fn certificate(reply: WatchdogEvent) -> ApiResult<Json<Certificate>> {
    match reply {
        WatchdogEvent::Issued {
            cert_der,
            lifetime_secs,
        } => Ok(Json(Certificate {
            certificate: base64::engine::general_purpose::STANDARD.encode(cert_der),
            lifetime_secs,
        })),
        WatchdogEvent::Denied(m)
            if m == INVALID_CREDENTIALS || m == "no such user" || m == SESSION_EXPIRED =>
        {
            Err(ApiError::Unauthorized(m))
        }
        WatchdogEvent::Denied(m) if m == "bad certificate request" => Err(ApiError::BadRequest(m)),
        WatchdogEvent::Denied(m) => Err(ApiError::Unavailable(m)),
        other => Err(crate::ipc::unexpected("nos-watchdogd", &other)),
    }
}

/// Trade a password for a client certificate.
#[utoipa::path(
    post, path = "/v1/login", tag = "auth", summary = "Trade a password for a client certificate",
    description = "The only route that needs no client certificate. Send a certificate request for a key you generated; the response is the certificate.",
    security(()),
    request_body = LoginRequest,
    responses(
        (status = 200, body = Certificate),
        (status = 400, body = ErrorBody, description = "malformed certificate request"),
        (status = 401, body = ErrorBody, description = "unknown user or wrong password"),
        (status = 429, body = ErrorBody, description = "too many failed attempts for this user; see Retry-After")
    )
)]
pub async fn login(
    State(d): State<Daemons>,
    Json(body): Json<LoginRequest>,
) -> ApiResult<Json<Certificate>> {
    let csr_der = decode_csr(&body.csr)?;
    let gate = d.login_gate.lock_for(&body.user);
    let held = gate.lock().await;
    if let Some(retry_after_secs) = d.login_gate.retry_after(&body.user) {
        drop(held);
        d.login_gate.release(&body.user, &gate);
        return Err(ApiError::TooManyRequests {
            detail: "too many failed logins for this user".into(),
            retry_after_secs,
        });
    }
    let reply = d
        .broker(WatchdogRequest::RestLogin {
            user: body.user.clone(),
            password: body.password,
            csr_der,
        })
        .await;
    if matches!(&reply, Ok(WatchdogEvent::Denied(m)) if m == INVALID_CREDENTIALS) {
        d.login_gate.record_failure(&body.user);
        tokio::time::sleep(FAILED_LOGIN_DELAY).await;
    } else if matches!(&reply, Ok(WatchdogEvent::Issued { .. })) {
        d.login_gate.clear(&body.user);
    }
    drop(held);
    d.login_gate.release(&body.user, &gate);
    certificate(reply?)
}

/// Trade the certificate this connection presented for a fresh one.
#[utoipa::path(
    post, path = "/v1/renew", tag = "auth", summary = "Renew the client certificate",
    request_body = RenewRequest,
    responses(
        (status = 200, body = Certificate),
        (status = 401, body = ErrorBody, description = "no valid certificate, or the user no longer exists")
    )
)]
pub async fn renew(
    State(d): State<Daemons>,
    Extension(PeerUser(user, serial)): Extension<PeerUser>,
    Json(body): Json<RenewRequest>,
) -> ApiResult<Json<Certificate>> {
    // The middleware only lets a request with a certificate this far.
    let (Some(user), Some(serial)) = (user, serial) else {
        return Err(ApiError::Unauthorized("authentication required".into()));
    };
    let csr_der = decode_csr(&body.csr)?;
    certificate(
        d.broker(WatchdogRequest::RestRenew {
            user,
            serial,
            csr_der,
        })
        .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_forgets_the_user_only_when_nobody_else_waits() {
        let gate = LoginGate::default();
        let a = gate.lock_for("u");
        gate.release("u", &a);
        assert!(gate.locks.lock().unwrap().is_empty());

        let a = gate.lock_for("u");
        let b = gate.lock_for("u");
        assert!(Arc::ptr_eq(&a, &b));
        gate.release("u", &a);
        assert!(Arc::ptr_eq(&gate.lock_for("u"), &b));
    }

    #[test]
    fn lockout_after_max_failures_until_cleared() {
        let gate = LoginGate::default();
        for _ in 0..MAX_FAILED_LOGINS - 1 {
            gate.record_failure("u");
        }
        assert_eq!(gate.retry_after("u"), None);
        gate.record_failure("u");
        // A fresh window: 60s minus a sliver, rounded up to whole seconds.
        assert_eq!(gate.retry_after("u"), Some(60));
        assert_eq!(gate.retry_after("other"), None);
        gate.clear("u");
        assert_eq!(gate.retry_after("u"), None);
    }

    #[test]
    fn debug_hides_the_password() {
        let r = LoginRequest {
            user: "alice".into(),
            password: "hunter2".into(),
            csr: "x".into(),
        };
        let s = format!("{r:?}");
        assert!(s.contains("alice") && s.contains("<hidden>") && !s.contains("hunter2"));
    }

    fn err(reply: WatchdogEvent) -> ApiError {
        match certificate(reply) {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    #[test]
    fn issued_becomes_a_base64_certificate() {
        let Ok(Json(c)) = certificate(WatchdogEvent::Issued {
            cert_der: vec![1, 2, 3],
            lifetime_secs: 7,
        }) else {
            panic!("expected a certificate");
        };
        assert_eq!(c.certificate, "AQID");
        assert_eq!(c.lifetime_secs, 7);
    }

    #[test]
    fn denials_map_to_distinct_statuses() {
        for m in [INVALID_CREDENTIALS, "no such user", SESSION_EXPIRED] {
            assert!(
                matches!(err(WatchdogEvent::Denied(m.into())), ApiError::Unauthorized(x) if x == m)
            );
        }
        assert!(matches!(
            err(WatchdogEvent::Denied("bad certificate request".into())),
            ApiError::BadRequest(x) if x == "bad certificate request"
        ));
        assert!(matches!(
            err(WatchdogEvent::Denied("other".into())),
            ApiError::Unavailable(x) if x == "other"
        ));
        assert!(matches!(
            err(WatchdogEvent::NotAvailable),
            ApiError::BadGateway(_)
        ));
    }
}
