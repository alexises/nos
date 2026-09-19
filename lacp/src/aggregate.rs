//! `AggregateManager` — one per configured `Lacp`-mode `PortAggregate`,
//! the LACP analogue of `ospf::link::LinkManager`: spawns/stops one
//! `link::run` task per currently-configured member port, re-runs
//! `selection::select` whenever any port's observation changes, and pushes
//! the resulting `Distributing`-state port set to `nos-interfaced`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nos_proto::{
    LacpAggregateMembers, LacpMuxState, LacpPortStatus, LacpRate, LacpReceiveState,
    PortAggregateLacpSummary,
};
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::link::{self, LinkConfig, PortObservation};
use crate::mux_machine::MuxState;
use crate::packet::state_bit;
use crate::receive_machine::ReceiveState;
use crate::selection::{self, PortCandidate};

/// 802.1AX defaults — no CLI-exposed knobs in v1 (see `lacp/CLAUDE.md`).
const ACTOR_SYSTEM_PRIORITY: u16 = 32768;
const ACTOR_PORT_PRIORITY: u16 = 32768;

type SelectedTxs = Arc<Mutex<HashMap<String, watch::Sender<bool>>>>;

pub struct AggregateManager {
    name: String,
    /// The rate the currently-running member tasks were started with — a
    /// change restarts them all (their advertised `LACP_Timeout` and timers
    /// are fixed for a task's lifetime).
    rate: Mutex<LacpRate>,
    /// Assigned once, sequentially, the first time `reconcile.rs` sees this
    /// aggregate name (see `reconcile.rs`) — not persisted, only needs to
    /// differ between simultaneously-active aggregates on this instance.
    key: u16,
    members: Mutex<HashMap<String, JoinHandle<()>>>,
    selected_txs: SelectedTxs,
    observations: Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: Arc<Notify>,
    /// This aggregate's Actor System ID — see [`derive_system_id`]. Fixed for
    /// the life of the process: it must not depend on any member port,
    /// because bonding rewrites a slave's MAC (the first slave enslaved lends
    /// its MAC to the bond, and every other slave takes it over), so a
    /// port-derived ID changed whenever enslavement order did, restarting
    /// every link in a loop.
    system_id: [u8; 6],
    selection_task: JoinHandle<()>,
}

impl AggregateManager {
    pub fn new(name: &str, key: u16, push_tx: mpsc::Sender<LacpAggregateMembers>) -> Arc<Self> {
        let observations = Arc::new(Mutex::new(HashMap::new()));
        let changed = Arc::new(Notify::new());
        let selected_txs: SelectedTxs = Arc::new(Mutex::new(HashMap::new()));
        let selection_task = tokio::spawn(selection_loop(
            name.to_string(),
            observations.clone(),
            changed.clone(),
            selected_txs.clone(),
            push_tx,
        ));
        Arc::new(Self {
            name: name.to_string(),
            rate: Mutex::new(LacpRate::default()),
            key,
            members: Mutex::new(HashMap::new()),
            selected_txs,
            observations,
            changed,
            system_id: local_system_id(),
            selection_task,
        })
    }

    /// Diffs `desired_members` (real kernel interface names) against the
    /// currently-running set, spawning/stopping `link::run` tasks as needed.
    /// A changed `rate` restarts every member (each renegotiates from
    /// scratch, briefly dropping out of the active set).
    pub fn reconcile(&self, mut desired_members: Vec<String>, rate: LacpRate) {
        desired_members.sort();
        let rate_changed = {
            let mut current = self.rate.lock().unwrap();
            let changed = *current != rate;
            *current = rate;
            changed
        };

        let mut members = self.members.lock().unwrap();
        let mut selected_txs = self.selected_txs.lock().unwrap();
        let mut observations = self.observations.lock().unwrap();

        let to_remove: Vec<String> = members
            .keys()
            .filter(|k| rate_changed || !desired_members.contains(k))
            .cloned()
            .collect();
        for interface in to_remove {
            if let Some(task) = members.remove(&interface) {
                task.abort();
            }
            selected_txs.remove(&interface);
            observations.remove(&interface);
        }

        let system_id = self.system_id;

        for interface in &desired_members {
            // A task that ended on its own (its socket failed hard, e.g. the
            // interface vanished) is not "running" — fall through and
            // respawn it on this pass, like `ospf::link::LinkManager` does.
            if members.get(interface).is_some_and(|t| !t.is_finished()) {
                continue;
            }
            let (selected_tx, selected_rx) = watch::channel(false);
            let config = LinkConfig {
                interface: interface.clone(),
                actor_system_id: system_id,
                actor_system_priority: ACTOR_SYSTEM_PRIORITY,
                actor_key: self.key,
                actor_port_priority: ACTOR_PORT_PRIORITY,
                rate,
                selected_rx,
            };
            let task = tokio::spawn(link::run(
                config,
                self.observations.clone(),
                self.changed.clone(),
            ));
            members.insert(interface.clone(), task);
            selected_txs.insert(interface.clone(), selected_tx);
        }
        drop((members, selected_txs, observations));
        self.changed.notify_one();
    }

    /// This aggregate's current LACP state, for `show lacp`.
    pub fn summary(&self) -> PortAggregateLacpSummary {
        let observations = self.observations.lock().unwrap();
        let selected_txs = self.selected_txs.lock().unwrap();
        let mut ports: Vec<LacpPortStatus> = observations
            .iter()
            .map(|(interface, obs)| LacpPortStatus {
                interface: interface.clone(),
                actor_port_number: obs.actor_port,
                receive_state: wire_receive_state(obs.receive_state),
                mux_state: wire_mux_state(obs.mux_state),
                partner_system_id: obs.partner.map(|p| p.system),
                partner_key: obs.partner.map(|p| p.key),
                partner_port_number: obs.partner.map(|p| p.port),
                selected: selected_txs.get(interface).is_some_and(|tx| *tx.borrow()),
                synchronized: obs
                    .partner
                    .is_some_and(|p| p.has_state(state_bit::SYNCHRONIZATION)),
            })
            .collect();
        ports.sort_by(|a, b| a.interface.cmp(&b.interface));
        PortAggregateLacpSummary {
            aggregate: self.name.clone(),
            actor_system_id: self.system_id,
            actor_key: self.key,
            rate: *self.rate.lock().unwrap(),
            ports,
        }
    }

    /// Stops every member task and the selection loop — called when this
    /// aggregate is removed from config entirely (see `reconcile.rs`).
    pub fn shutdown(&self) {
        for (_, task) in self.members.lock().unwrap().drain() {
            task.abort();
        }
        self.selection_task.abort();
    }
}

/// Re-runs Selection Logic and recomputes the active (`Distributing`)
/// member set every time any port's observation changes, feeds each
/// port's own `selected_tx` (driving its `mux_machine::Event::
/// SelectionChanged`), and pushes the active set when it changes — the one
/// natural edge-triggered mutation point `interface_client`'s own doc
/// comment refers to.
async fn selection_loop(
    aggregate: String,
    observations: Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: Arc<Notify>,
    selected_txs: SelectedTxs,
    push_tx: mpsc::Sender<LacpAggregateMembers>,
) {
    let mut last_pushed: Option<Vec<String>> = None;
    loop {
        changed.notified().await;

        let snapshot: HashMap<String, PortObservation> = observations.lock().unwrap().clone();
        let candidates: Vec<PortCandidate> = snapshot
            .iter()
            .map(|(interface, obs)| PortCandidate {
                interface: interface.clone(),
                current: obs.current(),
                partner_system_id: obs.partner.map(|p| p.system).unwrap_or_default(),
                partner_key: obs.partner.map(|p| p.key).unwrap_or_default(),
            })
            .collect();
        let selected = selection::select(&candidates);

        for (interface, tx) in selected_txs.lock().unwrap().iter() {
            set_if_changed(tx, selected.contains(interface));
        }

        let mut active_members: Vec<String> = snapshot
            .iter()
            .filter(|(interface, obs)| {
                selected.contains(*interface) && obs.mux_state == MuxState::Distributing
            })
            .map(|(interface, _)| interface.clone())
            .collect();
        active_members.sort();

        if last_pushed.as_ref() != Some(&active_members) {
            info!(
                aggregate = %aggregate,
                members = active_members.len(),
                "lacp reconciled aggregate members"
            );
            if push_tx
                .send(LacpAggregateMembers {
                    aggregate: aggregate.clone(),
                    active_members: active_members.clone(),
                })
                .await
                .is_err()
            {
                warn!(aggregate = %aggregate, "lacp interface_client channel closed, stopping selection loop");
                return;
            }
            last_pushed = Some(active_members);
        }
    }
}

fn wire_receive_state(state: ReceiveState) -> LacpReceiveState {
    match state {
        ReceiveState::Expired => LacpReceiveState::Expired,
        ReceiveState::Defaulted => LacpReceiveState::Defaulted,
        ReceiveState::Current => LacpReceiveState::Current,
    }
}

fn wire_mux_state(state: MuxState) -> LacpMuxState {
    match state {
        MuxState::Detached => LacpMuxState::Detached,
        MuxState::Waiting => LacpMuxState::Waiting,
        MuxState::Attached => LacpMuxState::Attached,
        MuxState::Collecting => LacpMuxState::Collecting,
        MuxState::Distributing => LacpMuxState::Distributing,
    }
}

/// This machine's Actor System ID: a locally-administered unicast MAC
/// derived from stable per-machine identity (hostname + machine-id), never
/// from a port — see `AggregateManager::system_id`. `ponytail:` two machines
/// sharing both (e.g. cloned images with the default hostname) would collide
/// and each see the other as itself; upgrade path is a persisted random id
/// file.
fn local_system_id() -> [u8; 6] {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    derive_system_id(
        read("/proc/sys/kernel/hostname").trim(),
        read("/etc/machine-id").trim(),
    )
}

fn derive_system_id(hostname: &str, machine_id: &str) -> [u8; 6] {
    // FNV-1a — no dependency needed for a non-cryptographic 48-bit spread.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in hostname.bytes().chain([0]).chain(machine_id.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let b = hash.to_be_bytes();
    // 0x02: locally administered, unicast.
    [0x02, b[3], b[4], b[5], b[6], b[7]]
}

/// Updates `tx` only if the verdict actually changed. `watch::Sender::send`
/// wakes the receiver even for an identical value, and a woken link task
/// reports back, which re-runs this loop — sending unconditionally made an
/// infinite feedback loop that flooded the log.
fn set_if_changed(tx: &watch::Sender<bool>, value: bool) -> bool {
    tx.send_if_modified(|current| {
        if *current == value {
            false
        } else {
            *current = value;
            true
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_id_is_stable_distinct_and_locally_administered_unicast() {
        let a = derive_system_id("router-a", "m1");
        assert_eq!(a, derive_system_id("router-a", "m1"));
        assert_ne!(a, derive_system_id("router-b", "m1"));
        assert_ne!(a, derive_system_id("router-a", "m2"));
        assert_eq!(a[0], 0x02);
    }

    #[test]
    fn unchanged_verdict_does_not_wake_the_port() {
        let (tx, mut rx) = watch::channel(false);
        assert!(!set_if_changed(&tx, false));
        assert!(!rx.has_changed().unwrap());

        assert!(set_if_changed(&tx, true));
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();

        assert!(!set_if_changed(&tx, true));
        assert!(!rx.has_changed().unwrap());
    }
}
