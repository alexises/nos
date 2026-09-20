use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_pki::{Incoming, PeerId};
use nos_proto::{IpcCodec, Role, WatchdogEvent, WatchdogRequest};
use tokio::io::split;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::config_client;
use crate::pki::Pki;
use crate::registry::EndpointRegistry;

/// A failed login costs the caller this much wall time, and the connection is
/// dropped after `MAX_FAILED_LOGINS` of them.
// ponytail: per-connection throttle only — a client can reconnect. A global
// or per-user lockout needs shared state; add it if guessing becomes a threat.
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(1);
const MAX_FAILED_LOGINS: u32 = 3;

/// Where the singleton daemons listen — answered directly for their
/// `ServiceRef`s, not through the registry.
pub struct Sockets {
    pub config: PathBuf,
    pub interfaces: PathBuf,
    pub log: PathBuf,
    pub lacp: PathBuf,
    pub lldp: PathBuf,
}

/// Everything one broker connection needs.
struct Ctx {
    registry: EndpointRegistry,
    sockets: Sockets,
    pki: Arc<Pki>,
}

/// Binds `listen_socket` and spawns the accept loop for the endpoint-broker
/// IPC: any authenticated daemon or client can dial this socket to ask where
/// to reach another service, instead of assuming a hardcoded default.
///
/// The socket accepts TLS peers *without* a client certificate too, but only
/// for `Login` — the one request that turns a password into a certificate.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    registry: EndpointRegistry,
    sockets: Sockets,
    pki: Arc<Pki>,
) -> io::Result<JoinHandle<()>> {
    let listener = pki.identity.listen_optional_client_auth(listen_socket)?;
    info!(listen_socket = %listen_socket.display(), "broker IPC listening");
    let ctx = Arc::new(Ctx {
        registry,
        sockets,
        pki,
    });
    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(incoming) => {
                    tokio::spawn(handle_connection(incoming, ctx.clone()));
                }
                Err(e) => {
                    error!(error = %e, "broker IPC accept loop terminated");
                    break;
                }
            }
        }
    }))
}

async fn handle_connection(incoming: Incoming, ctx: Arc<Ctx>) {
    let (stream, peer) = match incoming.handshake().await {
        Ok(ok) => ok,
        Err(e) => {
            debug!(error = %e, "broker tls handshake failed");
            return;
        }
    };
    let (read_half, write_half) = split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<WatchdogRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<WatchdogEvent>::default());
    let mut failed_logins = 0;

    while let Some(msg) = reader.next().await {
        let request = match msg {
            Ok(request) => request,
            Err(e) => {
                warn!(error = %e, "broker IPC read error");
                break;
            }
        };
        let event = dispatch(&ctx, peer.as_ref(), request).await;
        let rejected_login = matches!(&event, WatchdogEvent::Denied(m) if m == INVALID_CREDENTIALS);
        if rejected_login {
            failed_logins += 1;
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
        }
        if writer.send(event).await.is_err() || failed_logins >= MAX_FAILED_LOGINS {
            break;
        }
    }
}

const INVALID_CREDENTIALS: &str = "invalid credentials";

async fn dispatch(ctx: &Ctx, peer: Option<&PeerId>, request: WatchdogRequest) -> WatchdogEvent {
    match request {
        // The one thing an unauthenticated peer may do.
        WatchdogRequest::Login {
            user,
            password,
            csr_der,
        } => login(ctx, &user, password, &csr_der).await,
        _ if peer.is_none() => {
            debug!("refusing an unauthenticated broker request");
            WatchdogEvent::Denied("authentication required".to_string())
        }
        WatchdogRequest::ResolveEndpoint { service } => {
            let s = &ctx.sockets;
            let resolved = ctx
                .registry
                .resolve(&service, &s.config, &s.interfaces, &s.log, &s.lacp, &s.lldp)
                .await;
            if let Some(path) = resolved {
                trace!(?service, "resolved endpoint");
                WatchdogEvent::Endpoint(path)
            } else {
                debug!(?service, "endpoint not available");
                WatchdogEvent::NotAvailable
            }
        }
        WatchdogRequest::RenewCert { csr_der } => match peer {
            Some(p) if p.role == Role::User.as_str() => renew(ctx, &p.name, &csr_der).await,
            _ => WatchdogEvent::Denied("only a logged-in user can renew".to_string()),
        },
    }
}

/// Checks `password` against the running config's users (argon2, run off the
/// async threads — it is deliberately slow) and, on success, certifies the
/// caller's own public key as that user.
async fn login(ctx: &Ctx, user: &str, password: String, csr_der: &[u8]) -> WatchdogEvent {
    let users = match config_client::fetch_users(&ctx.pki.identity, &ctx.sockets.config).await {
        Ok(users) => users,
        Err(e) => {
            warn!(error = %e, "cannot read users from nos-configd, refusing login");
            return WatchdogEvent::Denied("login unavailable".to_string());
        }
    };
    let stored = users
        .into_iter()
        .find(|u| u.name == user)
        .map(|u| u.password);
    // `verify_or_dummy` burns the same time for an unknown user as for a wrong
    // password, so response time doesn't reveal which usernames exist.
    let ok = tokio::task::spawn_blocking(move || {
        nos_password::verify_or_dummy(&password, stored.as_deref())
    })
    .await
    .unwrap_or(false);
    if !ok {
        info!(user = %user, "login rejected");
        return WatchdogEvent::Denied(INVALID_CREDENTIALS.to_string());
    }
    let event = issue(ctx, user, csr_der);
    if matches!(event, WatchdogEvent::Issued { .. }) {
        info!(user = %user, "login accepted");
    }
    event
}

/// A still-valid certificate is proof enough — but a user deleted since must
/// not be able to keep renewing.
async fn renew(ctx: &Ctx, user: &str, csr_der: &[u8]) -> WatchdogEvent {
    match config_client::fetch_users(&ctx.pki.identity, &ctx.sockets.config).await {
        Ok(users) if users.iter().any(|u| u.name == user) => {
            let event = issue(ctx, user, csr_der);
            if matches!(event, WatchdogEvent::Issued { .. }) {
                info!(user = %user, "user certificate renewed");
            }
            event
        }
        Ok(_) => {
            info!(user = %user, "renewal refused, user no longer exists");
            WatchdogEvent::Denied("no such user".to_string())
        }
        Err(e) => {
            warn!(error = %e, "cannot read users from nos-configd, refusing renewal");
            WatchdogEvent::Denied("renewal unavailable".to_string())
        }
    }
}

fn issue(ctx: &Ctx, user: &str, csr_der: &[u8]) -> WatchdogEvent {
    match ctx.pki.sign_user(csr_der, user) {
        Ok(cert_der) => WatchdogEvent::Issued {
            cert_der,
            lifetime_secs: ctx.pki.user_lifetime.as_secs(),
        },
        Err(e) => {
            warn!(user = %user, error = %e, "rejected a malformed certificate request");
            WatchdogEvent::Denied("bad certificate request".to_string())
        }
    }
}
