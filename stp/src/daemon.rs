//! The single actor that owns the [`Engine`] and every port's BPDU socket.
//!
//! The core is bridge-wide, so one task drives it deterministically: port
//! reader tasks, the link table, plan changes and a 1 s tick all arrive as
//! events on this task, no locks. A changed plan rebuilds the bridge (and the
//! protocol restarts); sockets of ports that stay are kept.
//! ponytail: no in-place update of priority/cost/timers, a config change
//! costs one reconvergence; add `set_bridge_id`/`set_path_cost` calls if
//! live tuning matters.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use nos_l2_socket::L2Socket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::bpdu::{decode_frame_any, encode_frame, encode_mst_frame};
use crate::engine::{Engine, Out};
use crate::identity;
use crate::interface_client::Push;
use crate::link;
use crate::link_client::{gate, Gate, LinkTable};
use crate::ports::Plan;
use crate::server::{Cmd, Snapshot};

const TICK: Duration = Duration::from_secs(1);
/// Seconds between full re-pushes of the kernel port states.
const RESYNC_EVERY: u32 = 10;
/// Seconds between the per-port BPDU receive summaries.
const SUMMARY_EVERY: u32 = 10;

struct Io {
    socket: Arc<L2Socket>,
    reader: JoinHandle<()>,
}

#[derive(Default)]
struct PortRt {
    /// Last carrier verdict logged; `None` before the first.
    carrier: Option<bool>,
    /// What the core was last told.
    enabled: bool,
    open_warned: bool,
    rx: u64,
}

struct Daemon {
    mac: [u8; 6],
    plan: Option<Plan>,
    engine: Option<Engine>,
    rt: Vec<PortRt>,
    io: HashMap<String, Io>,
    links: LinkTable,
    push_tx: mpsc::Sender<Push>,
    frames_tx: mpsc::Sender<(String, Vec<u8>)>,
    ticks: u32,
    /// What `show spanning-tree` serves; refreshed after every event.
    snapshot: Snapshot,
}

pub async fn run(
    mut plan_rx: watch::Receiver<Option<Plan>>,
    mut links_rx: watch::Receiver<LinkTable>,
    push_tx: mpsc::Sender<Push>,
    snapshot: Snapshot,
    mut cmds: mpsc::Receiver<Cmd>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (frames_tx, mut frames_rx) = mpsc::channel(256);
    let mut d = Daemon {
        mac: identity::local_mac(),
        plan: None,
        engine: None,
        rt: Vec::new(),
        io: HashMap::new(),
        links: LinkTable::default(),
        push_tx,
        frames_tx,
        ticks: 0,
        snapshot,
    };
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            r = plan_rx.changed() => {
                if r.is_err() { break }
                let plan = plan_rx.borrow_and_update().clone();
                d.apply_plan(plan).await;
            }
            r = links_rx.changed() => {
                if r.is_err() { break }
                d.links = links_rx.borrow_and_update().clone();
                d.sync_links().await;
            }
            Some((name, frame)) = frames_rx.recv() => d.receive(&name, &frame).await,
            Some(cmd) = cmds.recv() => d.command(cmd).await,
            _ = tick.tick() => d.on_tick().await,
            _ = shutdown.changed() => if *shutdown.borrow() { break },
        }
        d.publish();
    }
    for (_, io) in d.io.drain() {
        io.reader.abort();
    }
    info!("stp engine stopped");
}

/// Forwards every frame of one port to the actor until the socket fails.
async fn read_loop(socket: Arc<L2Socket>, name: String, tx: mpsc::Sender<(String, Vec<u8>)>) {
    loop {
        match socket.recv_frame().await {
            Ok(f) => {
                if tx.send((name.clone(), f)).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                warn!(port = %name, error = %e, "bpdu socket failed");
                return;
            }
        }
    }
}

impl Daemon {
    /// Disabled mode (no engine) answers `enabled: false`.
    fn publish(&self) {
        let s = self
            .engine
            .as_ref()
            .map(Engine::summary)
            .unwrap_or_default();
        *self.snapshot.write().expect("snapshot lock") = s;
    }

    async fn apply_plan(&mut self, plan: Option<Plan>) {
        if plan == self.plan {
            return;
        }
        let names: Vec<&str> = plan
            .iter()
            .flat_map(|p| p.ports.iter().map(|p| p.name.as_str()))
            .collect();
        self.io.retain(|name, io| {
            let keep = names.contains(&name.as_str());
            if !keep {
                io.reader.abort();
            }
            keep
        });
        self.rt = plan
            .iter()
            .flat_map(|p| p.ports.iter().map(|_| PortRt::default()))
            .collect();
        // A rebuilt bridge must not silently recover err-disabled ports.
        let carried = self
            .engine
            .as_ref()
            .map(Engine::err_disabled)
            .unwrap_or_default();
        let first = self.engine.is_none();
        self.engine = None;
        let mut init = Vec::new();
        if let Some(p) = &plan {
            info!(
                ports = p.ports.len(),
                priority = p.priority,
                "spanning tree plan applied"
            );
            match Engine::new(p, self.mac) {
                Ok((e, out)) => {
                    self.engine = Some(e);
                    init = out;
                }
                Err(e) => error!(error = %e, "cannot build the spanning tree bridge"),
            }
        } else {
            info!("spanning tree idle (mode is not rstp or mstp)");
        }
        let release = |port: String| Out::ErrDisabled {
            port,
            disabled: false,
        };
        for (port, remaining) in carried {
            let kept = self
                .engine
                .as_mut()
                .is_some_and(|e| e.restore_err_disabled(&port, remaining));
            if !kept {
                info!(port = %port, "port err-disabled recovered");
                init.push(release(port));
            }
        }
        // ponytail: a fresh start cannot know which links an earlier nos-stpd
        // left down, so it releases every guarded port once; a still-wrong
        // port is err-disabled again by its next BPDU.
        if let (true, Some(e)) = (first, self.engine.as_ref()) {
            init.extend(
                e.ports()
                    .iter()
                    .filter(|p| p.prot.bpdu_guard)
                    .map(|p| release(p.name.clone())),
            );
        }
        self.plan = plan;
        self.emit(init).await;
        self.sync_links().await;
    }

    /// Opens missing sockets and tells the core each port's `portEnabled`,
    /// `operPointToPoint` and cost when they changed.
    async fn sync_links(&mut self) {
        let Some(n) = self.engine.as_ref().map(|e| e.ports().len()) else {
            return;
        };
        for i in 0..n {
            let cfg = self.engine.as_ref().expect("checked").ports()[i].clone();
            let g = gate(&self.links, &cfg.name);
            let carrier = !matches!(g, Gate::Down(_));
            if self.rt[i].carrier != Some(carrier) {
                if carrier {
                    info!(port = %cfg.name, "port carrier up");
                } else {
                    info!(port = %cfg.name, "port carrier lost");
                }
            }
            if carrier {
                self.ensure_io(i, &cfg.name);
            }
            let enabled = carrier && self.io.contains_key(&cfg.name);
            if self.rt[i].carrier == Some(carrier) && self.rt[i].enabled == enabled {
                continue;
            }
            self.rt[i].carrier = Some(carrier);
            self.rt[i].enabled = enabled;
            let info = link::read(&cfg.name);
            if enabled && info.speed_mbps.is_none() {
                warn!(port = %cfg.name, fallback_mbps = link::FALLBACK_SPEED_MBPS, "link speed unknown, using the fallback cost");
            }
            let out = self.engine.as_mut().expect("checked").set_link(
                i,
                enabled,
                link::point_to_point(cfg.link_type, info),
                link::path_cost(cfg.cost, info),
            );
            self.emit(out).await;
        }
    }

    fn ensure_io(&mut self, i: usize, name: &str) {
        if self.io.get(name).is_some_and(|io| io.reader.is_finished()) {
            self.io.remove(name);
        }
        if self.io.contains_key(name) {
            return;
        }
        match L2Socket::open_bpdu(name) {
            Ok(s) => {
                let socket = Arc::new(s);
                let tx = self.frames_tx.clone();
                let (rs, n) = (socket.clone(), name.to_string());
                let reader = tokio::spawn(read_loop(rs, n, tx));
                self.io.insert(name.to_string(), Io { socket, reader });
                self.rt[i].open_warned = false;
                info!(port = %name, "bpdu socket open");
            }
            Err(e) => {
                if !self.rt[i].open_warned {
                    warn!(port = %name, error = %e, "cannot open the bpdu socket, will retry");
                }
                self.rt[i].open_warned = true;
            }
        }
    }

    async fn receive(&mut self, name: &str, frame: &[u8]) {
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let Some(i) = engine.ports().iter().position(|p| p.name == name) else {
            return;
        };
        self.rt[i].rx += 1;
        match decode_frame_any(frame) {
            Ok((_, rx)) => {
                let out = engine.receive_rx(i, rx);
                self.emit(out).await;
            }
            Err(e) => debug!(port = %name, error = %e, "dropping malformed bpdu"),
        }
    }

    async fn command(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Mcheck { interface, reply } => {
                let Some(engine) = self.engine.as_mut() else {
                    let _ = reply.send(0);
                    return;
                };
                let (ports, out) = engine.mcheck(interface.as_deref());
                info!(ports, "mcheck requested");
                let _ = reply.send(ports);
                self.emit(out).await;
            }
            Cmd::ClearErrDisabled { interface, reply } => {
                let Some(engine) = self.engine.as_mut() else {
                    let _ = reply.send(false);
                    return;
                };
                let (cleared, out) = engine.clear_err_disabled(&interface);
                let _ = reply.send(cleared);
                self.emit(out).await;
            }
        }
    }

    async fn on_tick(&mut self) {
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let out = engine.tick();
        self.emit(out).await;
        self.ticks += 1;
        // ponytail: a full re-push every RESYNC_EVERY seconds heals a state
        // that a concurrent `nos-interfaced` resync overwrote with a stale one
        // (seen after a plan rebuild); upgrade path is an ack from interfaced.
        if self.ticks.is_multiple_of(RESYNC_EVERY) {
            if let Some(e) = &self.engine {
                let out = e.all_states();
                self.emit(out).await;
            }
        }
        if self.ticks.is_multiple_of(SUMMARY_EVERY) {
            if let Some(e) = &self.engine {
                for (p, rt) in e.ports().iter().zip(self.rt.iter_mut()) {
                    if rt.enabled {
                        info!(port = %p.name, count = rt.rx, "bpdu rx");
                    }
                    rt.rx = 0;
                }
            }
        }
        // Retries a failed socket open and notices a finished reader.
        self.sync_links().await;
    }

    async fn emit(&mut self, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Tx { port, bpdu } => {
                    let name = &self
                        .engine
                        .as_ref()
                        .expect("outputs imply an engine")
                        .ports()[port]
                        .name;
                    if let Some(io) = self.io.get(name) {
                        let frame = encode_frame(io.socket.own_hw_addr(), &bpdu);
                        match io.socket.send_frame(&frame) {
                            Err(e) if !nos_l2_socket::is_link_down(&e) => {
                                warn!(port = %name, error = %e, "bpdu send failed");
                            }
                            _ => {}
                        }
                    }
                }
                Out::TxMst { port, bpdu } => {
                    let name = &self
                        .engine
                        .as_ref()
                        .expect("outputs imply an engine")
                        .ports()[port]
                        .name;
                    if let Some(io) = self.io.get(name) {
                        let frame = encode_mst_frame(io.socket.own_hw_addr(), &bpdu);
                        match io.socket.send_frame(&frame) {
                            Err(e) if !nos_l2_socket::is_link_down(&e) => {
                                warn!(port = %name, error = %e, "bpdu send failed");
                            }
                            _ => {}
                        }
                    }
                }
                Out::States(list) => {
                    let _ = self.push_tx.send(Push::States(list)).await;
                }
                Out::Flush(list) => {
                    let _ = self.push_tx.send(Push::Flush(list)).await;
                }
                Out::ErrDisabled { port, disabled } => {
                    let _ = self
                        .push_tx
                        .send(Push::ErrDisabled { port, disabled })
                        .await;
                }
            }
        }
    }
}
