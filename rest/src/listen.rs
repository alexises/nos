//! Owns the HTTP listener: which address it is bound to, inside which VRF.
//!
//! Every tick (and immediately on a routing-table config change) it compares
//! what this table's `rest_api` config *wants* with what is *bound*, and
//! converges: bind when wanted and possible, rebind when the address/port/VRF
//! changed, drop when unpinned. "Not possible yet" — the owning `nos-ribd`
//! hasn't created the VRF, or `nos-interfaced` hasn't yet put the address on
//! an interface in it — is an ordinary transient state, retried next tick,
//! exactly like `nos-bgpd`'s VRF resolution.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{
    DiffScope, Event, IpcCodec, Request, RestApi, RibEvent, RibRequest, Role, ServiceRef,
};
use socket2::SockRef;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use crate::ipc::{call, Daemons};
use crate::watchdog_client::resolve_once;

const TICK: Duration = Duration::from_secs(1);

/// What one bound listener was bound *to*, so a later tick can tell whether
/// it is still the right one.
struct Bound {
    want: RestApi,
    vrf: String,
    /// The VRF device's ifindex at bind time. `SO_BINDTODEVICE` resolves the
    /// name once, so a VRF deleted and recreated under the same name (its
    /// `nos-ribd` restarted) leaves this socket bound to a device that no
    /// longer exists — detected by the ifindex changing.
    ifindex: Option<u32>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

pub struct Listener {
    pub table: String,
    pub daemons: Daemons,
    pub router: axum::Router,
}

impl Listener {
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut bound: Option<Bound> = None;
        // Last "can't bind" reason logged, so a retry loop logs once per change.
        let mut last_problem = String::new();
        let mut diffs = self.config_trigger().await;

        while !*shutdown.borrow() {
            self.converge(&mut bound, &mut last_problem).await;
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                Some(()) = async { match diffs.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {}
                _ = shutdown.changed() => {}
            }
        }
        if let Some(b) = bound.take() {
            stop(b, &self.table).await;
        }
    }

    /// A channel that fires when routing-table config changes, so a change is
    /// applied immediately instead of on the next tick. Best effort: `None`
    /// (tick-only) if `nos-configd` can't be subscribed to right now, and not
    /// re-established if the subscription later drops — the 1s tick still
    /// converges, just later. ponytail: resubscribe if that latency matters.
    async fn config_trigger(&self) -> Option<tokio::sync::mpsc::Receiver<()>> {
        let stream = nos_pki::connect(&self.daemons.config_socket, Role::Configd, "")
            .await
            .ok()?;
        let (r, w) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
        writer
            .send(Request::SubscribeDiff {
                scopes: vec![DiffScope::RoutingTables],
            })
            .await
            .ok()?;
        let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let _keep_write_half_open = writer;
            while let Some(Ok(_)) = reader.next().await {
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        });
        Some(rx)
    }

    async fn converge(&self, bound: &mut Option<Bound>, last_problem: &mut String) {
        let Some(want) = self.wanted().await else {
            return; // config unreadable: keep whatever is bound
        };

        // Drop a listener that is no longer the right one.
        if let Some(b) = bound.as_ref() {
            let vrf_now = self.vrf_name().await;
            let stale = want.as_ref() != Some(&b.want)
                || vrf_now.as_deref() != Some(b.vrf.as_str())
                || ifindex(&b.vrf) != b.ifindex;
            if stale {
                if let Some(b) = bound.take() {
                    stop(b, &self.table).await;
                }
            }
        }
        let (Some(want), None) = (want, bound.as_ref()) else {
            return;
        };

        let problem = match self.bind(&want).await {
            Ok(b) => {
                info!(
                    table = %self.table, vrf = %b.vrf, address = %want.address, port = want.port,
                    "rest api listening"
                );
                *bound = Some(b);
                last_problem.clear();
                return;
            }
            Err(problem) => problem,
        };
        if *last_problem != problem {
            warn!(table = %self.table, address = %want.address, port = want.port, "rest api not listening yet: {problem}");
            *last_problem = problem;
        }
    }

    /// This table's pinned `rest_api` (`Some(None)` = read fine, not pinned);
    /// `None` if the config couldn't be read, so a `nos-configd` blip never
    /// tears down a healthy listener.
    async fn wanted(&self) -> Option<Option<RestApi>> {
        match self.daemons.running_config().await {
            Ok(cfg) => Some(
                cfg.routing_tables
                    .into_iter()
                    .find(|t| t.name == self.table)
                    .and_then(|t| t.rest_api),
            ),
            Err(e) => {
                debug!(error = ?e, "could not read config; keeping current listener");
                None
            }
        }
    }

    async fn vrf_name(&self) -> Option<String> {
        let socket = resolve_once(
            &self.daemons.watchdog_socket,
            &ServiceRef::RibTable(self.table.clone()),
        )
        .await?;
        match call::<_, RibEvent>(&socket, Role::Ribd, &self.table, RibRequest::GetVrfName).await {
            Ok(RibEvent::VrfName(name)) => name,
            _ => None,
        }
    }

    async fn bind(&self, want: &RestApi) -> Result<Bound, String> {
        let vrf = self
            .vrf_name()
            .await
            .ok_or_else(|| format!("vrf of table '{}' does not exist yet", self.table))?;
        let listener = bind_listener(SocketAddr::new(want.address, want.port), &vrf)
            .map_err(|e| format!("bind in vrf {vrf} failed: {e}"))?;
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let app = self.router.clone();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stop_rx.wait_for(|s| *s).await;
                })
                .await;
        });
        Ok(Bound {
            want: want.clone(),
            ifindex: ifindex(&vrf),
            vrf,
            stop: stop_tx,
            task,
        })
    }
}

async fn stop(b: Bound, table: &str) {
    let _ = b.stop.send(true);
    // Graceful shutdown waits for open connections; don't let a keep-alive
    // client hold a rebind hostage.
    if tokio::time::timeout(Duration::from_secs(2), b.task)
        .await
        .is_err()
    {
        debug!(table = %table, "listener did not drain in time");
    }
    info!(table = %table, vrf = %b.vrf, address = %b.want.address, port = b.want.port, "rest api stopped listening");
}

/// `SO_BINDTODEVICE` into `vrf`, then bind the one configured address (a
/// per-crate copy of `nos-bgpd`'s `tcp::bind_listener`, narrowed to that
/// address rather than a wildcard).
fn bind_listener(local: SocketAddr, vrf: &str) -> io::Result<TcpListener> {
    let socket = if local.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    SockRef::from(&socket).bind_device(Some(vrf.as_bytes()))?;
    socket.bind(local)?;
    socket.listen(1024)
}

fn ifindex(dev: &str) -> Option<u32> {
    std::fs::read_to_string(Path::new("/sys/class/net").join(dev).join("ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}
