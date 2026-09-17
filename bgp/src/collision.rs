//! RFC 4271 §6.8 connection collision resolution.
//!
//! Both an actively-initiated (outbound) and passively-accepted (inbound)
//! TCP connection for the same peer are allowed to proceed through OPEN
//! exchange — each side needs the other's BGP Identifier before a winner can
//! be decided. The rule implemented here (matching how production BGP
//! stacks apply §6.8, not a literal "first past `OpenConfirm` wins" reading,
//! which would be timing-dependent):
//!
//! - local BGP Identifier > remote BGP Identifier: keep the connection this
//!   system initiated (active); close the accepted (passive) one.
//! - local BGP Identifier < remote BGP Identifier: keep the connection the
//!   peer initiated (passive); close the one this system initiated (active).
//! - equal (duplicate/misconfigured router-id): keep whichever reached this
//!   decision point first, log a warning — RFC 4271 doesn't resolve true
//!   ties.
//! - Established-precedence override: a connection already `Established`
//!   always beats a later collision, regardless of ID comparison.
//!
//! The loser is torn down with `NOTIFICATION(Cease, ConnectionCollisionResolution)`,
//! signaled via its `Notify` handle so its own `fsm::run` task can send that
//! notification itself before closing — never a bare socket drop.

use std::cmp::Ordering;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::{mpsc, watch, Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::session::ResolvedPeer;
use crate::status::{PeerStatus, StatusHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Active,
    Passive,
}

/// An operator-triggered action against a peer's live session, delivered
/// through `PeerSlot`'s command channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmCommand {
    /// `clear bgp <instance> <peer> soft-in` — ask this peer to resend its
    /// Adj-RIB-Out to us, for every address family this session negotiated.
    SendRouteRefresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    PostOpen,
    Established,
}

struct ConnectionRecord {
    stage: Stage,
    remote_bgp_id: Ipv4Addr,
    cease: Arc<Notify>,
}

#[derive(Default)]
struct RoleState {
    /// Set while a connection for this role is being processed (from
    /// accept/connect success through the FSM ending), independent of
    /// whether it has received an OPEN yet — guards the degenerate
    /// double-inbound case, distinct from real active/passive collision.
    occupied: bool,
    connection: Option<ConnectionRecord>,
}

#[derive(Default)]
struct CollisionState {
    active: RoleState,
    passive: RoleState,
}

pub enum Decision {
    Proceed,
    Lose,
}

/// One configured peer's collision-arbitration state, shared between its
/// active-connect task and the shared passive listener's accept handler.
/// Also the canonical owner of `status` (see `crate::status`) — since both
/// an active and a passive connection can be in flight for the same peer at
/// once but only one becomes canonical, `PeerSlot` (already the single
/// per-peer arbitration point) is the natural place for `fsm::run` to report
/// into, rather than either individual connection owning it.
pub struct PeerSlot {
    pub peer: ResolvedPeer,
    state: Mutex<CollisionState>,
    pub status: StatusHandle,
    command_tx: mpsc::UnboundedSender<FsmCommand>,
    /// Locked fresh on every poll by whichever `fsm::run` task currently owns
    /// this peer's `Established` session — see `recv_command`. Created once
    /// here (peer lifetime, not per-connection), so no take/hand-off dance is
    /// needed across a peer's active/passive reconnects.
    command_rx: Mutex<mpsc::UnboundedReceiver<FsmCommand>>,
    /// The currently-running passively-accepted session's task, if any.
    ///
    /// The active side's task is owned by `SessionManager::peer_tasks`, but a
    /// passive session is spawned per accepted connection
    /// (`SessionManager::handle_inbound`) and would otherwise be tracked
    /// nowhere — so reconciliation had no way to stop it, and a peer whose
    /// config changed kept serving an established *passive* session with the
    /// `ResolvedPeer` it was accepted with: stale policies, auth and timers,
    /// indefinitely. Parked here because the slot is already the one
    /// per-peer object shared across both roles.
    passive_task: Mutex<Option<JoinHandle<()>>>,
}

impl PeerSlot {
    pub fn new(peer: ResolvedPeer) -> Arc<Self> {
        let (status, _) = watch::channel(PeerStatus::default());
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            peer,
            state: Mutex::new(CollisionState::default()),
            status,
            command_tx,
            command_rx: Mutex::new(command_rx),
            passive_task: Mutex::new(None),
        })
    }

    /// Records the task running this peer's passively-accepted session,
    /// replacing (and aborting) any previous one.
    pub async fn set_passive_task(&self, task: JoinHandle<()>) {
        if let Some(previous) = self.passive_task.lock().await.replace(task) {
            previous.abort();
        }
    }

    /// Stops this peer's passively-accepted session, if one is running —
    /// called when the peer is being torn down or respawned with a changed
    /// `ResolvedPeer`.
    pub async fn stop_passive(&self) {
        if let Some(task) = self.passive_task.lock().await.take() {
            task.abort();
        }
    }

    /// A snapshot receiver for `session::SessionManager::peer_summaries` to
    /// read the current status from.
    pub fn status_receiver(&self) -> watch::Receiver<PeerStatus> {
        self.status.subscribe()
    }

    /// Delivers an operator command to this peer's live session. `false` if
    /// no `fsm::run` task is around to receive it (channel closed).
    pub fn send_command(&self, cmd: FsmCommand) -> bool {
        self.command_tx.send(cmd).is_ok()
    }

    /// Waits for the next operator command. Callers must only poll this while
    /// their own connection is `Established` (e.g. a `tokio::select!` guard)
    /// — collision resolution always happens before either side reaches
    /// `Established`, so gating on it guarantees only the one canonical
    /// session ever locks this shared receiver, never a connection that's
    /// about to lose (or has lost) the collision.
    pub async fn recv_command(&self) -> Option<FsmCommand> {
        self.command_rx.lock().await.recv().await
    }

    /// Whether this peer already has an `Established` session, in either
    /// role. `active_connect_loop` checks this before dialing out again on
    /// its retry timer — without it, a stable session held open by the
    /// passive side would still see a redundant outbound connect attempt,
    /// and thus a real (harmlessly-resolved-by-precedence, but pointless)
    /// collision, every `CONNECT_RETRY_TIME`.
    pub async fn is_established(&self) -> bool {
        let state = self.state.lock().await;
        let is_established = |role: &RoleState| {
            matches!(
                role.connection,
                Some(ConnectionRecord {
                    stage: Stage::Established,
                    ..
                })
            )
        };
        is_established(&state.active) || is_established(&state.passive)
    }

    /// Reserves this role's slot. `false` means a connection for this same
    /// role is already being processed (e.g. a second inbound connection
    /// arriving before the first finished) — the caller must reject the new
    /// connection outright without engaging the FSM.
    pub async fn begin(&self, role: Role) -> bool {
        let mut state = self.state.lock().await;
        let this = role_state_mut(&mut state, role);
        if this.occupied {
            false
        } else {
            this.occupied = true;
            true
        }
    }

    /// Called once this connection has received a structurally-valid OPEN,
    /// just before its FSM would otherwise commit to `OpenConfirm`. Records
    /// this connection and, if the other role already has one, resolves the
    /// collision per RFC 4271 §6.8 — notifying the loser's `cease` handle
    /// and dropping its record when this side wins. `local_router_id` is
    /// supplied by the caller (read fresh from `SessionManager`'s current
    /// config at connect/accept time) rather than stored on the slot, so a
    /// router-id config change is picked up by the next connection attempt
    /// without needing to recreate the slot.
    pub async fn on_open(
        &self,
        role: Role,
        local_router_id: Ipv4Addr,
        remote_bgp_id: Ipv4Addr,
        cease: Arc<Notify>,
    ) -> Decision {
        let mut state = self.state.lock().await;
        let (this, other) = role_states_mut(&mut state, role);
        this.connection = Some(ConnectionRecord {
            stage: Stage::PostOpen,
            remote_bgp_id,
            cease,
        });

        let Some(other_conn) = other.connection.take() else {
            return Decision::Proceed;
        };

        if other_conn.stage == Stage::Established {
            this.connection = None;
            other.connection = Some(other_conn);
            return Decision::Lose;
        }

        match collision_winner(local_router_id, other_conn.remote_bgp_id, role) {
            Decision::Proceed => {
                other_conn.cease.notify_one();
                Decision::Proceed
            }
            Decision::Lose => {
                this.connection = None;
                other.connection = Some(other_conn);
                Decision::Lose
            }
        }
    }

    pub async fn mark_established(&self, role: Role) {
        let mut state = self.state.lock().await;
        if let Some(conn) = role_state_mut(&mut state, role).connection.as_mut() {
            conn.stage = Stage::Established;
        }
    }

    pub async fn clear(&self, role: Role) {
        let mut state = self.state.lock().await;
        let this = role_state_mut(&mut state, role);
        this.occupied = false;
        this.connection = None;
    }
}

fn role_state_mut(state: &mut CollisionState, role: Role) -> &mut RoleState {
    match role {
        Role::Active => &mut state.active,
        Role::Passive => &mut state.passive,
    }
}

fn role_states_mut(state: &mut CollisionState, role: Role) -> (&mut RoleState, &mut RoleState) {
    match role {
        Role::Active => (&mut state.active, &mut state.passive),
        Role::Passive => (&mut state.passive, &mut state.active),
    }
}

/// The actual §6.8 comparison. `role` is the side whose `on_open` call
/// triggered this decision — i.e. the *later* of the two connections to
/// receive its OPEN, since the earlier one already proceeded trivially (the
/// other role had no record yet).
fn collision_winner(local_id: Ipv4Addr, remote_id: Ipv4Addr, role: Role) -> Decision {
    match local_id.cmp(&remote_id) {
        Ordering::Greater => {
            if role == Role::Active {
                Decision::Proceed
            } else {
                Decision::Lose
            }
        }
        Ordering::Less => {
            if role == Role::Passive {
                Decision::Proceed
            } else {
                Decision::Lose
            }
        }
        Ordering::Equal => {
            warn!(
                %local_id, %remote_id,
                "bgp collision: tied router-ids, keeping the earlier-established connection"
            );
            Decision::Lose
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    use super::*;

    fn addr(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn higher_local_id_keeps_active() {
        let local = addr(10, 0, 0, 2);
        let remote = addr(10, 0, 0, 1);
        assert!(matches!(
            collision_winner(local, remote, Role::Active),
            Decision::Proceed
        ));
        assert!(matches!(
            collision_winner(local, remote, Role::Passive),
            Decision::Lose
        ));
    }

    #[test]
    fn higher_remote_id_keeps_passive() {
        let local = addr(10, 0, 0, 1);
        let remote = addr(10, 0, 0, 2);
        assert!(matches!(
            collision_winner(local, remote, Role::Passive),
            Decision::Proceed
        ));
        assert!(matches!(
            collision_winner(local, remote, Role::Active),
            Decision::Lose
        ));
    }

    #[test]
    fn tied_ids_keep_the_earlier_connection() {
        let id = addr(10, 0, 0, 1);
        assert!(matches!(
            collision_winner(id, id, Role::Active),
            Decision::Lose
        ));
        assert!(matches!(
            collision_winner(id, id, Role::Passive),
            Decision::Lose
        ));
    }

    fn peer_slot() -> Arc<PeerSlot> {
        PeerSlot::new(ResolvedPeer {
            remote_address: "10.0.0.1".parse().unwrap(),
            source_address: None,
            remote_as: 65000,
            peer_group: "pg1".to_string(),
            hold_time: 90,
            keepalive_interval: None,
            connect_retry_time: std::time::Duration::from_secs(120),
            auth: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            route_reflector_client: false,
            route_server_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        })
    }

    #[tokio::test]
    async fn first_side_proceeds_when_the_other_has_not_opened_yet() {
        let slot = peer_slot();
        let decision = slot
            .on_open(
                Role::Active,
                addr(1, 1, 1, 1),
                addr(2, 2, 2, 2),
                Arc::new(Notify::new()),
            )
            .await;
        assert!(matches!(decision, Decision::Proceed));
    }

    #[tokio::test]
    async fn second_arrival_resolves_by_id_higher_local_keeps_active() {
        let slot = peer_slot();
        let local_id = addr(10, 0, 0, 2);
        let remote_id = addr(10, 0, 0, 1);

        let passive_cease = Arc::new(Notify::new());
        let decision = slot
            .on_open(Role::Passive, local_id, remote_id, passive_cease.clone())
            .await;
        assert!(matches!(decision, Decision::Proceed));

        let decision = slot
            .on_open(Role::Active, local_id, remote_id, Arc::new(Notify::new()))
            .await;
        assert!(matches!(decision, Decision::Proceed));

        // The passive connection, recorded first, must have been signaled to
        // tear itself down once the (higher-local-id-favored) active side
        // arrived and won.
        assert!(
            passive_cease.notified().now_or_never().is_some(),
            "expected the earlier passive connection's cease handle to be notified"
        );
    }

    #[tokio::test]
    async fn second_arrival_resolves_by_id_higher_remote_keeps_passive() {
        let slot = peer_slot();
        let local_id = addr(10, 0, 0, 1);
        let remote_id = addr(10, 0, 0, 2);

        let active_cease = Arc::new(Notify::new());
        let decision = slot
            .on_open(Role::Active, local_id, remote_id, active_cease.clone())
            .await;
        assert!(matches!(decision, Decision::Proceed));

        let decision = slot
            .on_open(Role::Passive, local_id, remote_id, Arc::new(Notify::new()))
            .await;
        assert!(matches!(decision, Decision::Proceed));

        assert!(
            active_cease.notified().now_or_never().is_some(),
            "expected the earlier active connection's cease handle to be notified"
        );
    }

    #[tokio::test]
    async fn established_connection_beats_a_later_collision_regardless_of_id() {
        let slot = peer_slot();
        // IDs alone would favor the passive side (remote > local), but the
        // active side is already Established, so it must win regardless.
        let local_id = addr(10, 0, 0, 1);
        let remote_id = addr(10, 0, 0, 2);

        let decision = slot
            .on_open(Role::Active, local_id, remote_id, Arc::new(Notify::new()))
            .await;
        assert!(matches!(decision, Decision::Proceed));
        slot.mark_established(Role::Active).await;

        let decision = slot
            .on_open(Role::Passive, local_id, remote_id, Arc::new(Notify::new()))
            .await;
        assert!(matches!(decision, Decision::Lose));
    }

    #[tokio::test]
    async fn degenerate_double_begin_for_the_same_role_is_rejected() {
        let slot = peer_slot();
        assert!(slot.begin(Role::Passive).await);
        assert!(!slot.begin(Role::Passive).await);
        slot.clear(Role::Passive).await;
        assert!(slot.begin(Role::Passive).await);
    }

    #[tokio::test]
    async fn is_established_reflects_either_role() {
        let slot = peer_slot();
        assert!(!slot.is_established().await);

        slot.on_open(
            Role::Passive,
            addr(1, 1, 1, 1),
            addr(2, 2, 2, 2),
            Arc::new(Notify::new()),
        )
        .await;
        assert!(!slot.is_established().await);

        slot.mark_established(Role::Passive).await;
        assert!(slot.is_established().await);

        slot.clear(Role::Passive).await;
        assert!(!slot.is_established().await);
    }
}
