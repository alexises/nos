use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{
    BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec,
    PortAggregateStatus, Role, SubinterfaceStatus,
};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::driver::InterfaceDriver;
use crate::state::{BroadcastDomainState, InterfaceState, Interfaces, PortAggregateState};

/// Bundles this instance's shared in-memory state (for the read-only query
/// kinds) and its driver (so a `PushLacpMembers` push can apply the newly
/// gated interfaces to the kernel immediately) — mirrors `nos-ribd`'s own
/// `Context`.
struct Context {
    interfaces: Arc<RwLock<Interfaces>>,
    driver: Arc<dyn InterfaceDriver>,
}

/// Binds `listen_socket` and spawns the IPC accept loop for interface
/// queries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    interfaces: Arc<RwLock<Interfaces>>,
    driver: Arc<dyn InterfaceDriver>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "interface IPC server listening");
    let ctx = Arc::new(Context { interfaces, driver });
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

/// Status queries: people, the REST API on their behalf, and the routing
/// daemons that resolve an interface's address (`nos-bgpd`'s `source-address`,
/// the OSPF daemons' link addressing, `nos-fdbd`'s VTEP address and bridge). The LACP member
/// push rewrites kernel bond membership, so it is `nos-lacpd`'s alone. No
/// wildcard arm: a new request must be classified.
fn allowed(role: Role, req: &InterfaceRequest) -> bool {
    match req {
        InterfaceRequest::GetInterfaces
        | InterfaceRequest::GetInterface { .. }
        | InterfaceRequest::GetBroadcastDomain { .. }
        | InterfaceRequest::GetPortAggregates
        | InterfaceRequest::GetPortAggregate { .. } => {
            matches!(
                role,
                Role::User | Role::Restd | Role::Bgpd | Role::Ospfd | Role::Ospfv3d | Role::Fdbd
            )
        }
        InterfaceRequest::PushLacpMembers(_) => role == Role::Lacpd,
    }
}

async fn accept_loop(listener: Listener, ctx: Arc<Context>) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, ctx.clone()));
            }
            Err(e) => {
                error!(error = %e, "interface IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn serve(incoming: Incoming, ctx: Arc<Context>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, ctx).await,
        Err(e) => debug!(error = %e, "interface IPC handshake refused"),
    }
}

async fn handle_connection(stream: Stream, role: Role, name: String, ctx: Arc<Context>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<InterfaceRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<InterfaceEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(req) if !allowed(role, &req) => {
                warn!(
                    role = role.as_str(), name = %name,
                    "interface request refused: this role may not send it"
                );
                break;
            }
            Ok(req) => dispatch(&ctx, req).await,
            Err(e) => {
                warn!(error = %e, "interface IPC read error");
                break;
            }
        };
        if let Some(event) = event {
            if writer.send(event).await.is_err() {
                break;
            }
        }
    }
}

async fn dispatch(ctx: &Context, req: InterfaceRequest) -> Option<InterfaceEvent> {
    trace!(request = ?req, "serving interface query");
    match req {
        InterfaceRequest::GetInterfaces => {
            let guard = ctx.interfaces.read().await;
            Some(InterfaceEvent::Interfaces(
                guard.all().into_iter().map(to_status).collect(),
            ))
        }
        InterfaceRequest::GetInterface { name } => {
            let guard = ctx.interfaces.read().await;
            Some(match guard.get(&name) {
                Some(iface) => InterfaceEvent::Interface(to_status(iface.clone())),
                None => InterfaceEvent::NotFound,
            })
        }
        InterfaceRequest::GetBroadcastDomain { name } => {
            let guard = ctx.interfaces.read().await;
            Some(match guard.get_domain(&name) {
                Some(domain) => InterfaceEvent::BroadcastDomain(to_domain_status(domain.clone())),
                None => InterfaceEvent::NotFound,
            })
        }
        InterfaceRequest::GetPortAggregates => {
            let guard = ctx.interfaces.read().await;
            Some(InterfaceEvent::PortAggregates(
                guard
                    .all_port_aggregates()
                    .into_iter()
                    .map(to_port_aggregate_status)
                    .collect(),
            ))
        }
        InterfaceRequest::GetPortAggregate { name } => {
            let guard = ctx.interfaces.read().await;
            Some(match guard.get_port_aggregate(&name) {
                Some(agg) => InterfaceEvent::PortAggregate(to_port_aggregate_status(agg.clone())),
                None => InterfaceEvent::NotFound,
            })
        }
        InterfaceRequest::PushLacpMembers(msg) => {
            apply_lacp_push(ctx, msg).await;
            None
        }
    }
}

/// Applies one `nos-lacpd` push: replaces the aggregate's active-member set
/// and immediately re-`apply`s every affected interface, rather than
/// waiting for the periodic re-apply tick — mirrors `nos-ribd`'s
/// `apply_bgp_route_update`'s immediate-apply precedent.
async fn apply_lacp_push(ctx: &Context, msg: nos_proto::LacpAggregateMembers) {
    let updated = ctx
        .interfaces
        .write()
        .await
        .set_lacp_active_members(&msg.aggregate, msg.active_members);
    for iface in updated {
        if let Err(e) = ctx.driver.apply(&iface).await {
            warn!(interface = %iface.name, error = %e, "failed to apply lacp-pushed enslavement");
        }
    }
}

/// Linux's own default MTU for a freshly created link — reported here when
/// `Interface.mtu` is unset, since `nos-interfaced` never resets a link's
/// MTU to a default (see `InterfaceState.mtu`'s doc comment).
const DEFAULT_MTU: u32 = 1500;

fn to_status(iface: InterfaceState) -> InterfaceStatus {
    InterfaceStatus {
        name: iface.name,
        addresses: iface.addresses,
        routing_table: iface.routing_table,
        switching_profile: iface.switching_profile,
        port_aggregate: iface.port_aggregate,
        mtu: iface.mtu.unwrap_or(DEFAULT_MTU),
        subinterfaces: iface
            .subinterfaces
            .into_iter()
            .map(|s| SubinterfaceStatus {
                tag: s.tag,
                addresses: s.addresses,
                routing_table: s.routing_table,
                link_local_address: s.link_local_address,
            })
            .collect(),
        // A loopback interface's own flat L3 config has no live link-local
        // Hello exchange to source (see `InterfaceState`'s doc comment) —
        // never populated for this attach-point kind.
        link_local_address: None,
    }
}

fn to_domain_status(domain: BroadcastDomainState) -> BroadcastDomainStatus {
    BroadcastDomainStatus {
        name: domain.name,
        addresses: domain.addresses,
        routing_table: domain.routing_table,
        bridge_name: domain.bridge_name,
        link_local_address: domain.link_local_address,
    }
}

fn to_port_aggregate_status(agg: PortAggregateState) -> PortAggregateStatus {
    PortAggregateStatus {
        name: agg.name,
        mode: agg.mode,
        switching_profile: agg.switching_profile,
        mtu: agg.mtu.unwrap_or(DEFAULT_MTU),
        subinterfaces: agg
            .subinterfaces
            .into_iter()
            .map(|s| SubinterfaceStatus {
                tag: s.tag,
                addresses: s.addresses,
                routing_table: s.routing_table,
                link_local_address: s.link_local_address,
            })
            .collect(),
        link_local_address: agg.link_local_address,
        bond_name: agg.bond_name,
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;

    #[test]
    fn only_lacpd_may_rewrite_bond_membership() {
        let push = InterfaceRequest::PushLacpMembers(nos_proto::LacpAggregateMembers {
            aggregate: String::new(),
            active_members: Vec::new(),
        });
        for role in Role::ALL {
            assert_eq!(allowed(role, &push), role == Role::Lacpd, "{role:?} push");
            assert_eq!(
                allowed(role, &InterfaceRequest::GetInterfaces),
                matches!(
                    role,
                    Role::User
                        | Role::Restd
                        | Role::Bgpd
                        | Role::Ospfd
                        | Role::Ospfv3d
                        | Role::Fdbd
                ),
                "{role:?} query"
            );
        }
    }
}
