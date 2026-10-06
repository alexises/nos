//! The syslog sink against real loopback collectors (no VRF, no IPC).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use nos_log::syslog::sink::{self, SinkConfig};
use nos_log::LogStore;
use nos_proto::{LogEntry, LogLevel, SyslogServer, SyslogTransport};
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
