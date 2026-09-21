use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener};
use nos_proto::{FdbEvent, FdbRequest, IpcCodec, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::fdb::Fdb;

struct Context {
    domain: String,
    fdb: Arc<Fdb>,
}

/// Binds `listen_socket` and spawns the accept loop.
pub fn start(
    listen_socket: &Path,
    domain: String,
    fdb: Arc<Fdb>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(domain = %domain, socket = %listen_socket.display(), "FDB IPC server listening");
    let ctx = Arc::new(Context { domain, fdb });
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

/// Who may send what. The route push becomes kernel forwarding state, so it
/// is `nos-bgpd`'s alone; queries are for people (and `Restd` for them).
// ponytail: role-level only — `bgpd/r2` could still push into r1's domain;
// binding an instance to its domains needs a config lookup.
fn allowed(role: Role, req: &FdbRequest) -> bool {
    match req {
        FdbRequest::GetMacs => matches!(role, Role::User | Role::Restd),
        FdbRequest::PushEvpnRoutes(_) => role == Role::Bgpd,
    }
}

async fn accept_loop(listener: Listener, ctx: Arc<Context>) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, ctx.clone()));
            }
            Err(e) => {
                error!(domain = %ctx.domain, error = %e, "FDB IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn serve(incoming: Incoming, ctx: Arc<Context>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, ctx).await,
        Err(e) => debug!(domain = %ctx.domain, error = %e, "FDB IPC handshake refused"),
    }
}

async fn handle_connection(stream: nos_pki::Stream, role: Role, name: String, ctx: Arc<Context>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<FdbRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<FdbEvent>::default());

    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) if !allowed(role, &req) => {
                warn!(
                    domain = %ctx.domain, role = role.as_str(), name = %name,
                    "FDB request refused: this role may not send it"
                );
                break;
            }
            Ok(req) => req,
            Err(e) => {
                warn!(domain = %ctx.domain, error = %e, "FDB IPC read error");
                break;
            }
        };
        trace!(domain = %ctx.domain, request = ?req, "serving FDB request");
        match req {
            FdbRequest::GetMacs => {
                if writer
                    .send(FdbEvent::Table(ctx.fdb.table().await))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            // Fire-and-forget, no reply.
            FdbRequest::PushEvpnRoutes(update) => ctx.fdb.apply_push(update).await,
        }
    }
}

#[cfg(test)]
mod authz_tests {
    use nos_proto::EvpnUpdate;

    use super::*;

    #[test]
    fn only_bgpd_pushes_and_only_people_query() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &FdbRequest::PushEvpnRoutes(EvpnUpdate::Full(vec![]))),
                role == Role::Bgpd,
                "{role:?} push"
            );
            assert_eq!(
                allowed(role, &FdbRequest::GetMacs),
                matches!(role, Role::User | Role::Restd),
                "{role:?} query"
            );
        }
    }
}
