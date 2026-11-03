//! A minimal RFC 8210 RPKI-to-Router cache for `nos-e2e`'s `rpki` phase (#498):
//! `StayRTR` cannot sign its TCP session, so this one installs a `TCP_MD5SIG`
//! key (via `nos-tcp-auth`) on its listener for the one client it serves.
//!
//! `nos-rtr-stub <listen-addr> <prefix/len> <max-len> <asn> [<md5-key> <client-ip>]`
//!
//! It serves one fixed VRP and never changes it. A line on stdout per accepted
//! connection is what the e2e phase asserts on. Needs `CAP_NET_ADMIN` when a
//! key is given (file capability in the image, `cap_add` on the container).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SERIAL_QUERY: u8 = 1;
const RESET_QUERY: u8 = 2;
const SESSION: u16 = 1;
const SERIAL: u32 = 1;

/// The fixed VRP served to every client.
#[derive(Clone, Copy)]
struct Vrp {
    prefix: Ipv4Addr,
    len: u8,
    max_len: u8,
    asn: u32,
}

fn header(version: u8, kind: u8, field: u16, len: u32) -> Vec<u8> {
    let mut b = vec![version, kind];
    b.extend(field.to_be_bytes());
    b.extend(len.to_be_bytes());
    b
}

/// Cache Response, the IPv4 Prefix PDU (when `with_vrp`) and End of Data.
fn answer(version: u8, vrp: Vrp, with_vrp: bool) -> Vec<u8> {
    let mut out = header(version, 3, SESSION, 8);
    if with_vrp {
        out.extend(header(version, 4, 0, 20));
        out.extend([1, vrp.len, vrp.max_len, 0]);
        out.extend(vrp.prefix.octets());
        out.extend(vrp.asn.to_be_bytes());
    }
    let eod_len = if version == 0 { 12 } else { 24 };
    out.extend(header(version, 7, SESSION, eod_len));
    out.extend(SERIAL.to_be_bytes());
    if version != 0 {
        for secs in [3600u32, 600, 7200] {
            out.extend(secs.to_be_bytes());
        }
    }
    out
}

async fn serve_conn(mut s: TcpStream, vrp: Vrp) -> io::Result<()> {
    loop {
        let mut head = [0u8; 8];
        s.read_exact(&mut head).await?;
        let len = u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize;
        let mut rest = vec![0u8; len.saturating_sub(8)];
        s.read_exact(&mut rest).await?;
        match head[1] {
            RESET_QUERY => s.write_all(&answer(head[0], vrp, true)).await?,
            // Nothing ever changes: an empty delta at the same serial.
            SERIAL_QUERY => s.write_all(&answer(head[0], vrp, false)).await?,
            _ => {}
        }
    }
}

async fn serve(listener: TcpListener, vrp: Vrp) -> io::Result<()> {
    loop {
        let (s, peer) = listener.accept().await?;
        println!("rtr-stub accepted peer={peer}");
        tokio::spawn(async move {
            let _ = serve_conn(s, vrp).await;
        });
    }
}

type Parsed = (SocketAddr, Vrp, Option<(String, IpAddr)>);

fn parse(args: &[String]) -> Option<Parsed> {
    let [listen, prefix, max_len, asn, rest @ ..] = args else {
        return None;
    };
    let (addr, len) = prefix.split_once('/')?;
    let vrp = Vrp {
        prefix: addr.parse().ok()?,
        len: len.parse().ok()?,
        max_len: max_len.parse().ok()?,
        asn: asn.parse().ok()?,
    };
    let key = match rest {
        [] => None,
        [key, client] => Some((key.clone(), client.parse().ok()?)),
        _ => return None,
    };
    Some((listen.parse().ok()?, vrp, key))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    // nosemgrep: rust.lang.security.args.args -- stub parses its own flags
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((listen, vrp, key)) = parse(&args) else {
        eprintln!(
            "usage: nos-rtr-stub <listen> <prefix/len> <max-len> <asn> [<md5-key> <client-ip>]"
        );
        std::process::exit(2);
    };
    let listener = TcpListener::bind(listen).await?;
    if let Some((key, client)) = key {
        nos_tcp_auth::set_md5_key(listener.as_raw_fd(), client, key.as_bytes())?;
    }
    println!("rtr-stub listening addr={listen}");
    serve(listener, vrp).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const VRP: Vrp = Vrp {
        prefix: Ipv4Addr::new(10, 0, 0, 0),
        len: 16,
        max_len: 24,
        asn: 65001,
    };

    #[test]
    fn parses_with_and_without_a_key() {
        let a = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let (l, v, k) = parse(&a(&["0.0.0.0:323", "10.0.0.0/16", "24", "65001"])).unwrap();
        assert_eq!((l.port(), v.len, v.max_len, v.asn), (323, 16, 24, 65001));
        assert!(k.is_none());
        let keyed = a(&["0.0.0.0:323", "10.0.0.0/16", "24", "1", "pw", "10.50.0.2"]);
        assert_eq!(parse(&keyed).unwrap().2.unwrap().0, "pw");
        assert!(parse(&a(&["0.0.0.0:323", "10.0.0.0/16", "24", "1", "pw"])).is_none());
    }

    #[test]
    fn answer_has_the_rfc_8210_lengths() {
        // 8 (Cache Response) + 20 (IPv4 Prefix) + 24 (End of Data v1)
        assert_eq!(answer(1, VRP, true).len(), 52);
        assert_eq!(answer(1, VRP, false).len(), 32);
        assert_eq!(answer(0, VRP, true).len(), 8 + 20 + 12);
    }

    #[tokio::test]
    async fn reset_query_gets_the_vrp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, VRP));
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&header(1, RESET_QUERY, 0, 8)).await.unwrap();
        let mut got = vec![0u8; 52];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(got, answer(1, VRP, true));
        let mut q = header(1, SERIAL_QUERY, SESSION, 12);
        q.extend(SERIAL.to_be_bytes());
        c.write_all(&q).await.unwrap();
        let mut got = vec![0u8; 32];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(got, answer(1, VRP, false));
    }
}
