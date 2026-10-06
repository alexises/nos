//! One task per configured collector: reads the store's live broadcast and
//! sends each entry at or above the collector's level, as one RFC 5424
//! message. Never blocks `Push`: the task owns its own broadcast receiver, so
//! a slow collector only lags itself (RFC 5424 §8.5 — drop, not buffer).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use nos_proto::{parse_fingerprint, LogEntry, SyslogServer, SyslogTransport};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};

use super::client;
use super::render::{at_least, render};
use crate::LogStore;

/// RFC 5426 §3.2: receivers must take 480 octets over IPv4 and 1180 over
/// IPv6; 1180 also avoids fragmentation on any 1280-MTU path.
const UDP_MAX: usize = 1180;
/// RFC 5425 §4.3.1 (applied to plain TCP too): receivers should take 8192.
const TCP_MAX: usize = 8192;
/// Fixed retry delay, like every other reconnect loop in this codebase.
const RETRY: Duration = Duration::from_secs(1);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const DROP_REPORT: Duration = Duration::from_secs(60);

/// Everything one sink needs. `watchdog_socket` is only used to resolve a
/// routing table's VRF.
#[derive(Clone)]
pub struct SinkConfig {
    pub server: SyslogServer,
    pub hostname: String,
    pub watchdog_socket: PathBuf,
}

/// Runs until `stop` fires.
pub async fn run(cfg: SinkConfig, store: LogStore, mut stop: watch::Receiver<bool>) {
    let dest = SocketAddr::new(cfg.server.address, cfg.server.effective_port());
    let mut drops = Drops::new(&cfg.server.name);
    loop {
        if *stop.borrow() {
            return;
        }
        // Resolved fresh on every attempt: the VRF may not exist yet, and a
        // restarted `nos-ribd` may have a new one. A transient `None` is retried.
        let mut vrf = None;
        if let Some(table) = &cfg.server.routing_table {
            vrf = client::vrf_name(&cfg.watchdog_socket, table).await;
            if vrf.is_none() {
                drops.state_change(Some(format!("vrf of table '{table}' not available")));
                if sleep_or_stop(&mut stop).await {
                    return;
                }
                continue;
            }
        }
        let result = match cfg.server.transport {
            SyslogTransport::Udp => {
                run_udp(&cfg, dest, vrf.as_deref(), &store, &mut stop, &mut drops).await
            }
            SyslogTransport::Tcp | SyslogTransport::Tls => {
                run_tcp(&cfg, dest, vrf.as_deref(), &store, &mut stop, &mut drops).await
            }
        };
        match result {
            Ended::Stopped => return,
            Ended::Failed(e) => {
                drops.state_change(Some(e));
                if sleep_or_stop(&mut stop).await {
                    return;
                }
            }
        }
    }
}

enum Ended {
    Stopped,
    Failed(String),
}

/// Tracks the "only log transitions" rule and the periodic drop summary.
struct Drops {
    name: String,
    dropped: u64,
    /// The last failure reported; `None` while healthy.
    failing: Option<String>,
}

impl Drops {
    fn new(name: &str) -> Self {
        Drops {
            name: name.to_string(),
            dropped: 0,
            failing: None,
        }
    }

    fn connected(&mut self, transport: &str) {
        self.failing = None;
        info!(server = %self.name, transport, "syslog connected");
    }

    /// A TLS session is up: what it negotiated is visible in the log, and a
    /// TLS 1.2 one (always classical key exchange) is called out.
    fn connected_tls(&mut self, n: &nos_pki::syslog::Negotiated) {
        self.failing = None;
        info!(
            server = %self.name, version = %n.version, kx = %n.kx, suite = %n.suite,
            peer_key = %n.peer_key, "syslog connected"
        );
        if n.is_tls12() {
            warn!(server = %self.name, "syslog tls12 classical key exchange");
        }
    }

    /// Logs `failure` only when it differs from the last one reported.
    fn state_change(&mut self, failure: Option<String>) {
        if failure != self.failing {
            if let Some(f) = &failure {
                warn!(server = %self.name, error = %f, "syslog collector unavailable");
            }
            self.failing = failure;
        }
    }

    fn report(&mut self) {
        if self.dropped > 0 {
            warn!(server = %self.name, dropped = self.dropped, "syslog drops");
            self.dropped = 0;
        }
    }
}

async fn sleep_or_stop(stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(RETRY) => false,
        _ = stop.changed() => *stop.borrow(),
    }
}

fn bind_vrf(socket: &Socket, vrf: Option<&str>) -> io::Result<()> {
    match vrf {
        Some(v) => socket.bind_device(Some(v.as_bytes())),
        None => Ok(()),
    }
}

async fn run_udp(
    cfg: &SinkConfig,
    dest: SocketAddr,
    vrf: Option<&str>,
    store: &LogStore,
    stop: &mut watch::Receiver<bool>,
    drops: &mut Drops,
) -> Ended {
    let socket = match udp_socket(dest, vrf) {
        Ok(s) => s,
        Err(e) => return Ended::Failed(format!("udp socket: {e}")),
    };
    let mut rx = store.subscribe();
    drops.connected("udp");
    let mut report = tokio::time::interval(DROP_REPORT);
    report.tick().await;
    loop {
        tokio::select! {
            _ = stop.changed() => return Ended::Stopped,
            _ = report.tick() => drops.report(),
            got = rx.recv() => match got {
                Ok(entry) => {
                    if let Some(msg) = message(cfg, &entry, UDP_MAX) {
                        // A connected UDP socket reports a refused port as an
                        // error on a later send: count it, log the transition only.
                        match socket.send(msg.as_bytes()).await {
                            Ok(_) => drops.state_change(None),
                            Err(e) => {
                                drops.dropped += 1;
                                drops.state_change(Some(e.to_string()));
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => drops.dropped += n,
                Err(broadcast::error::RecvError::Closed) => return Ended::Stopped,
            },
        }
    }
}

fn udp_socket(dest: SocketAddr, vrf: Option<&str>) -> io::Result<UdpSocket> {
    let domain = if dest.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    bind_vrf(&socket, vrf)?;
    socket.set_nonblocking(true)?;
    let wildcard: SocketAddr = if dest.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    socket.bind(&wildcard.into())?;
    socket.connect(&dest.into())?;
    UdpSocket::from_std(socket.into())
}

async fn run_tcp(
    cfg: &SinkConfig,
    dest: SocketAddr,
    vrf: Option<&str>,
    store: &LogStore,
    stop: &mut watch::Receiver<bool>,
    drops: &mut Drops,
) -> Ended {
    let connect = async {
        let socket = if dest.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(v) = vrf {
            SockRef::from(&socket).bind_device(Some(v.as_bytes()))?;
        }
        socket.connect(dest).await
    };
    let tcp: TcpStream = tokio::select! {
        _ = stop.changed() => return Ended::Stopped,
        r = tokio::time::timeout(WRITE_TIMEOUT, connect) => match r {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Ended::Failed(format!("connect: {e}")),
            Err(_) => return Ended::Failed("connect: timed out".to_string()),
        },
    };
    if cfg.server.transport == SyslogTransport::Tls {
        let connector = match connector(&cfg.server) {
            Ok(c) => c,
            Err(e) => return Ended::Failed(format!("tls config: {e}")),
        };
        let (stream, negotiated) = tokio::select! {
            _ = stop.changed() => return Ended::Stopped,
            r = connector.connect(tcp) => match r {
                Ok(v) => v,
                Err(e) => return Ended::Failed(format!("tls handshake: {e}")),
            },
        };
        drops.connected_tls(&negotiated);
        serve(cfg, stream, store, stop, drops).await
    } else {
        drops.connected("tcp");
        debug!(server = %cfg.server.name, %dest, "syslog tcp connected");
        serve(cfg, tcp, store, stop, drops).await
    }
}

/// RFC 5425 §5: the collector is trusted by the configured CA, or by its
/// certificate's fingerprint. Rebuilt on every attempt: cheap, and a stale
/// config can never outlive its sink (a change restarts it).
fn connector(server: &SyslogServer) -> Result<nos_pki::syslog::Connector, String> {
    let tls = server.tls.as_ref().ok_or("no tls block")?;
    let trust = match (&tls.fingerprint, &tls.trust_anchor) {
        (Some(f), _) => nos_pki::syslog::Trust::Fingerprint(
            parse_fingerprint(f).ok_or("malformed fingerprint")?,
        ),
        (None, Some(pem)) => nos_pki::syslog::Trust::AnchorPem(pem),
        (None, None) => return Err("neither trust-anchor nor fingerprint".into()),
    };
    nos_pki::syslog::Connector::new(
        &trust,
        tls.server_name.as_deref(),
        server.address,
        tls.allow_tls12,
    )
    .map_err(|e| e.to_string())
}

/// Octet-counted frames on an established (plain or TLS) stream.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    cfg: &SinkConfig,
    stream: S,
    store: &LogStore,
    stop: &mut watch::Receiver<bool>,
    drops: &mut Drops,
) -> Ended {
    // Subscribed only now: entries logged while the collector was down are
    // not replayed (the ring buffer still has them for `show log`).
    let mut rx = store.subscribe();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut report = tokio::time::interval(DROP_REPORT);
    report.tick().await;
    let mut scratch = [0u8; 64];
    loop {
        tokio::select! {
            _ = stop.changed() => {
                // FIN, or TLS close_notify (RFC 5425 §4.4).
                let _ = wr.shutdown().await;
                return Ended::Stopped;
            }
            _ = report.tick() => drops.report(),
            // A collector never sends on this connection: any read result is
            // its close (or a reset), noticed now rather than at the next write.
            r = read_any(&mut rd, &mut scratch) => {
                return Ended::Failed(match r {
                    Ok(()) => "closed by the collector".to_string(),
                    Err(e) => e.to_string(),
                });
            }
            got = rx.recv() => match got {
                Ok(entry) => {
                    if let Some(msg) = message(cfg, &entry, TCP_MAX) {
                        // RFC 6587 §3.4.1 octet counting: `MSG-LEN SP SYSLOG-MSG`.
                        let frame = format!("{} {msg}", msg.len());
                        match tokio::time::timeout(WRITE_TIMEOUT, wr.write_all(frame.as_bytes())).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => { drops.dropped += 1; return Ended::Failed(e.to_string()); }
                            Err(_) => { drops.dropped += 1; return Ended::Failed("write timed out".to_string()); }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => drops.dropped += n,
                Err(broadcast::error::RecvError::Closed) => return Ended::Stopped,
            },
        }
    }
}

/// Resolves when the peer sent anything or closed.
async fn read_any<S: AsyncRead + Unpin>(rd: &mut ReadHalf<S>, buf: &mut [u8]) -> io::Result<()> {
    rd.read(buf).await.map(|_| ())
}

fn message(cfg: &SinkConfig, entry: &LogEntry, max: usize) -> Option<String> {
    at_least(entry.level, cfg.server.effective_level())
        .then(|| render(entry, &cfg.hostname, cfg.server.effective_facility(), max))
}
