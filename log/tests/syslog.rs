//! The syslog sink against real loopback collectors (no VRF, no IPC).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use nos_log::syslog::sink::{self, SinkConfig};
use nos_log::LogStore;
use nos_proto::{LogEntry, LogLevel, SyslogServer, SyslogTls, SyslogTransport};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};

const WAIT: Duration = Duration::from_secs(5);

fn entry(level: LogLevel, message: &str) -> LogEntry {
    LogEntry {
        timestamp_ms: 1_791_203_696_789,
        level,
        source: "nos-ribd[rt1]".into(),
        target: "t".into(),
        message: message.into(),
        fields: vec![],
    }
}

fn start(
    transport: SyslogTransport,
    addr: SocketAddr,
    level: Option<LogLevel>,
) -> (LogStore, watch::Sender<bool>) {
    start_tls(transport, addr, level, None)
}

fn start_tls(
    transport: SyslogTransport,
    addr: SocketAddr,
    level: Option<LogLevel>,
    tls: Option<SyslogTls>,
) -> (LogStore, watch::Sender<bool>) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let store = LogStore::new(100, Vec::new(), tx);
    let (stop, stop_rx) = watch::channel(false);
    let cfg = SinkConfig {
        server: SyslogServer {
            name: "c1".into(),
            address: addr.ip(),
            port: Some(addr.port()),
            transport,
            level,
            tls,
            ..SyslogServer::default()
        },
        hostname: "r1".into(),
        watchdog_socket: "/nonexistent".into(),
    };
    tokio::spawn(sink::run(cfg, store.clone(), stop_rx));
    (store, stop)
}

#[tokio::test]
async fn udp_sends_one_datagram_per_message_and_filters_by_level() {
    let collector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (store, _stop) = start(SyslogTransport::Udp, collector.local_addr().unwrap(), None);
    // Default level is info: the debug entry must not arrive, the info one must.
    let mut buf = [0u8; 2048];
    let mut seen = None;
    for _ in 0..100 {
        store.record(entry(LogLevel::Debug, "quiet")).await;
        store.record(entry(LogLevel::Info, "hello")).await;
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(50), collector.recv(&mut buf)).await
        {
            seen = Some(String::from_utf8(buf[..n].to_vec()).unwrap());
            break;
        }
    }
    let msg = seen.expect("no datagram");
    assert!(
        msg.starts_with("<190>1 2026-10-05T12:34:56.789Z r1 nos-ribd rt1 - "),
        "{msg}"
    );
    assert!(msg.ends_with("\u{FEFF}hello"), "{msg}");
    // Drain whatever else arrived: none of it may be the debug entry.
    while let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(200), collector.recv(&mut buf)).await
    {
        assert!(!String::from_utf8_lossy(&buf[..n]).contains("quiet"));
    }
}

#[tokio::test]
async fn udp_debug_level_lets_debug_through() {
    let collector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (store, _stop) = start(
        SyslogTransport::Udp,
        collector.local_addr().unwrap(),
        Some(LogLevel::Debug),
    );
    let mut buf = [0u8; 2048];
    for _ in 0..100 {
        store.record(entry(LogLevel::Debug, "dbg")).await;
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(50), collector.recv(&mut buf)).await
        {
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("<191>1 "));
            return;
        }
    }
    panic!("no datagram");
}

/// Reads one octet-counted frame.
async fn frame(s: &mut tokio::net::TcpStream) -> String {
    let mut len = String::new();
    loop {
        let b = s.read_u8().await.unwrap();
        if b == b' ' {
            break;
        }
        len.push(char::from(b));
    }
    let mut msg = vec![0u8; len.parse().unwrap()];
    s.read_exact(&mut msg).await.unwrap();
    String::from_utf8(msg).unwrap()
}

#[tokio::test]
async fn tcp_frames_are_octet_counted_and_reconnect() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (store, _stop) = start(SyslogTransport::Tcp, listener.local_addr().unwrap(), None);

    let (mut s, _) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    // The sink subscribes right after connecting; keep recording until a frame lands.
    let rec = {
        let store = store.clone();
        tokio::spawn(async move {
            for i in 0..u32::MAX {
                store.record(entry(LogLevel::Info, &format!("m{i}"))).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    };
    let first = tokio::time::timeout(WAIT, frame(&mut s)).await.unwrap();
    assert!(first.starts_with("<190>1 "), "{first}");
    assert!(first.contains("\u{FEFF}m"), "{first}");

    // The collector goes away: the sink must notice and connect again.
    drop(s);
    let (mut s2, _) = tokio::time::timeout(WAIT * 2, listener.accept())
        .await
        .unwrap()
        .unwrap();
    let again = tokio::time::timeout(WAIT, frame(&mut s2)).await.unwrap();
    assert!(again.starts_with("<190>1 "));
    rec.abort();
}

#[tokio::test]
async fn stopping_closes_the_tcp_connection() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (store, stop) = start(SyslogTransport::Tcp, listener.local_addr().unwrap(), None);
    let (mut s, _) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    let _ = &store;
    stop.send(true).unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(
        tokio::time::timeout(WAIT, s.read(&mut buf))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

mod tls {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};
    use tokio_rustls::TlsAcceptor;

    struct Collector {
        acceptor: TlsAcceptor,
        ca_pem: String,
        fingerprint: String,
    }

    fn collector() -> Collector {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.subject_alt_names = vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
        let leaf = p.signed_by(&key, &issuer).unwrap();
        let digest = Sha256::digest(leaf.der().as_ref());
        let fingerprint = format!(
            "SHA-256:{}",
            digest
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        );
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
        let cfg = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        Collector {
            acceptor: TlsAcceptor::from(std::sync::Arc::new(cfg)),
            ca_pem: ca.pem(),
            fingerprint,
        }
    }

    fn recorder(store: &LogStore) -> tokio::task::JoinHandle<()> {
        let store = store.clone();
        tokio::spawn(async move {
            for i in 0..u32::MAX {
                store.record(entry(LogLevel::Info, &format!("m{i}"))).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    }

    async fn first_frame(l: &TcpListener, c: &Collector) -> Option<String> {
        let (tcp, _) = tokio::time::timeout(WAIT, l.accept()).await.ok()?.ok()?;
        let mut s = c.acceptor.accept(tcp).await.ok()?;
        let mut len = String::new();
        loop {
            let b = tokio::time::timeout(WAIT, s.read_u8()).await.ok()?.ok()?;
            if b == b' ' {
                break;
            }
            len.push(char::from(b));
        }
        let mut msg = vec![0u8; len.parse().ok()?];
        s.read_exact(&mut msg).await.ok()?;
        String::from_utf8(msg).ok()
    }

    #[tokio::test]
    async fn delivers_with_a_trust_anchor_and_with_a_fingerprint() {
        let c = collector();
        for tls in [
            SyslogTls {
                trust_anchor: Some(c.ca_pem.clone()),
                ..SyslogTls::default()
            },
            SyslogTls {
                fingerprint: Some(c.fingerprint.clone()),
                ..SyslogTls::default()
            },
        ] {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let (store, _stop) = start_tls(
                SyslogTransport::Tls,
                l.local_addr().unwrap(),
                None,
                Some(tls),
            );
            let rec = recorder(&store);
            let f = first_frame(&l, &c).await.expect("no frame");
            assert!(f.starts_with("<190>1 "), "{f}");
            rec.abort();
        }
    }

    #[tokio::test]
    async fn a_wrong_fingerprint_delivers_nothing() {
        let c = collector();
        let other = collector();
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tls = SyslogTls {
            fingerprint: Some(other.fingerprint),
            ..SyslogTls::default()
        };
        let (store, _stop) = start_tls(
            SyslogTransport::Tls,
            l.local_addr().unwrap(),
            None,
            Some(tls),
        );
        let rec = recorder(&store);
        assert!(first_frame(&l, &c).await.is_none());
        rec.abort();
    }
}
