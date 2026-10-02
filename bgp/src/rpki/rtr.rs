//! RFC 8210 RPKI-to-Router protocol: the PDU codec and the router side of
//! the session (RFC 6810 version 0 as a fallback).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use ipnet::IpNet;
use nos_proto::{RpkiCache, RpkiSessionState};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{sleep, sleep_until, Instant};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tracing::{info, warn};

use super::vrp::{Vrp, VrpTable};
use super::SharedStatus;
use crate::tcp;

const SERIAL_NOTIFY: u8 = 0;
const SERIAL_QUERY: u8 = 1;
const RESET_QUERY: u8 = 2;
const CACHE_RESPONSE: u8 = 3;
const IPV4_PREFIX: u8 = 4;
const IPV6_PREFIX: u8 = 6;
const END_OF_DATA: u8 = 7;
const CACHE_RESET: u8 = 8;
const ROUTER_KEY: u8 = 9;
const ERROR_REPORT: u8 = 10;

/// RFC 8210 §12 Error Report code: the cache has no data yet.
pub const ERR_NO_DATA: u16 = 2;
/// RFC 8210 §12: a PDU this side can't parse.
pub const ERR_CORRUPT_DATA: u16 = 0;

/// The highest version this router speaks.
pub const VERSION: u8 = 1;

/// Generous: an Error Report is the only variable-size PDU we parse, and it
/// only carries the small PDU we sent plus a text.
const MAX_PDU: usize = 1 << 16;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// RFC 8210 §6 timing parameters, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intervals {
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
}

/// RFC 8210 §6's defaults, also used for a version 0 cache, which sends none.
impl Default for Intervals {
    fn default() -> Self {
        Self {
            refresh: 3600,
            retry: 600,
            expire: 7200,
        }
    }
}

impl Intervals {
    /// Clamped to RFC 8210 §6's maxima. The minima are not enforced (a 600s
    /// expire floor would make every lab test wait ten minutes); only 0 is
    /// raised to 1.
    fn clamped(self) -> Self {
        Self {
            refresh: self.refresh.clamp(1, 86_400),
            retry: self.retry.clamp(1, 7_200),
            expire: self.expire.clamp(1, 172_800),
        }
    }
}

fn secs(s: u32) -> Duration {
    Duration::from_secs(u64::from(s))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pdu {
    SerialNotify {
        session: u16,
        serial: u32,
    },
    SerialQuery {
        session: u16,
        serial: u32,
    },
    ResetQuery,
    CacheResponse {
        session: u16,
    },
    /// IPv4 or IPv6 Prefix PDU; `announce` is flags bit 0.
    Prefix {
        announce: bool,
        vrp: Vrp,
    },
    /// `intervals` is `Some` from version 1 on.
    EndOfData {
        session: u16,
        serial: u32,
        intervals: Option<Intervals>,
    },
    CacheReset,
    /// `BGPsec` router key (version 1): parsed only to be skipped.
    RouterKey,
    ErrorReport {
        code: u16,
        pdu: Bytes,
        text: String,
    },
}

/// One decoded PDU and the version in its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub pdu: Pdu,
}

/// Encodes with `version`; decodes any version, reporting it per frame.
#[derive(Debug, Clone, Copy)]
pub struct RtrCodec {
    pub version: u8,
}

fn corrupt(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("rtr: {what}"))
}

impl Decoder for RtrCodec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Frame>> {
        if src.len() < 8 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([src[4], src[5], src[6], src[7]]) as usize;
        if !(8..=MAX_PDU).contains(&len) {
            return Err(corrupt("bad pdu length"));
        }
        if src.len() < len {
            src.reserve(len - src.len());
            return Ok(None);
        }
        let mut b = src.split_to(len).freeze();
        let version = b.get_u8();
        let ty = b.get_u8();
        let field = b.get_u16();
        b.advance(4);
        Ok(Some(Frame {
            version,
            pdu: parse(version, ty, field, b)?,
        }))
    }
}

fn parse(version: u8, ty: u8, field: u16, mut b: Bytes) -> io::Result<Pdu> {
    let need = |b: &Bytes, n: usize| {
        if b.remaining() < n {
            Err(corrupt("truncated pdu"))
        } else {
            Ok(())
        }
    };
    Ok(match ty {
        SERIAL_NOTIFY | SERIAL_QUERY => {
            need(&b, 4)?;
            let serial = b.get_u32();
            if ty == SERIAL_NOTIFY {
                Pdu::SerialNotify {
                    session: field,
                    serial,
                }
            } else {
                Pdu::SerialQuery {
                    session: field,
                    serial,
                }
            }
        }
        RESET_QUERY => Pdu::ResetQuery,
        CACHE_RESPONSE => Pdu::CacheResponse { session: field },
        IPV4_PREFIX | IPV6_PREFIX => {
            let alen = if ty == IPV4_PREFIX { 4 } else { 16 };
            need(&b, 8 + alen)?;
            let flags = b.get_u8();
            let plen = b.get_u8();
            let max_len = b.get_u8();
            b.advance(1);
            let addr = if ty == IPV4_PREFIX {
                IpAddr::V4(Ipv4Addr::from(b.get_u32()))
            } else {
                IpAddr::V6(Ipv6Addr::from(b.get_u128()))
            };
            let asn = b.get_u32();
            let prefix = IpNet::new(addr, plen)
                .map_err(|_| corrupt("bad prefix length"))?
                .trunc();
            if max_len < plen || max_len > prefix.max_prefix_len() {
                return Err(corrupt("bad max length"));
            }
            Pdu::Prefix {
                announce: flags & 1 == 1,
                vrp: Vrp {
                    prefix,
                    max_len,
                    asn,
                },
            }
        }
        END_OF_DATA => {
            need(&b, 4)?;
            let serial = b.get_u32();
            let intervals = if version >= 1 {
                need(&b, 12)?;
                Some(Intervals {
                    refresh: b.get_u32(),
                    retry: b.get_u32(),
                    expire: b.get_u32(),
                })
            } else {
                None
            };
            Pdu::EndOfData {
                session: field,
                serial,
                intervals,
            }
        }
        CACHE_RESET => Pdu::CacheReset,
        ROUTER_KEY => Pdu::RouterKey,
        ERROR_REPORT => {
            need(&b, 4)?;
            let n = b.get_u32() as usize;
            need(&b, n)?;
            let pdu = b.split_to(n);
            need(&b, 4)?;
            let t = b.get_u32() as usize;
            need(&b, t)?;
            let text = String::from_utf8_lossy(&b.split_to(t)).into_owned();
            Pdu::ErrorReport {
                code: field,
                pdu,
                text,
            }
        }
        _ => return Err(corrupt("unsupported pdu type")),
    })
}

impl Encoder<Pdu> for RtrCodec {
    type Error = io::Error;

    fn encode(&mut self, pdu: Pdu, dst: &mut BytesMut) -> io::Result<()> {
        let mut body = BytesMut::new();
        let (ty, field) = match pdu {
            Pdu::SerialNotify { session, serial } => {
                body.put_u32(serial);
                (SERIAL_NOTIFY, session)
            }
            Pdu::SerialQuery { session, serial } => {
                body.put_u32(serial);
                (SERIAL_QUERY, session)
            }
            Pdu::ResetQuery => (RESET_QUERY, 0),
            Pdu::CacheResponse { session } => (CACHE_RESPONSE, session),
            Pdu::Prefix { announce, vrp } => {
                body.put_u8(u8::from(announce));
                body.put_u8(vrp.prefix.prefix_len());
                body.put_u8(vrp.max_len);
                body.put_u8(0);
                let ty = match vrp.prefix.addr() {
                    IpAddr::V4(a) => {
                        body.put_slice(&a.octets());
                        IPV4_PREFIX
                    }
                    IpAddr::V6(a) => {
                        body.put_slice(&a.octets());
                        IPV6_PREFIX
                    }
                };
                body.put_u32(vrp.asn);
                (ty, 0)
            }
            Pdu::EndOfData {
                session,
                serial,
                intervals,
            } => {
                body.put_u32(serial);
                if let Some(i) = intervals.filter(|_| self.version >= 1) {
                    body.put_u32(i.refresh);
                    body.put_u32(i.retry);
                    body.put_u32(i.expire);
                }
                (END_OF_DATA, session)
            }
            Pdu::CacheReset => (CACHE_RESET, 0),
            Pdu::RouterKey => return Err(corrupt("router key pdus are never sent")),
            Pdu::ErrorReport { code, pdu, text } => {
                body.put_u32(u32::try_from(pdu.len()).map_err(|_| corrupt("too long"))?);
                body.put_slice(&pdu);
                body.put_u32(u32::try_from(text.len()).map_err(|_| corrupt("too long"))?);
                body.put_slice(text.as_bytes());
                (ERROR_REPORT, code)
            }
        };
        dst.put_u8(self.version);
        dst.put_u8(ty);
        dst.put_u16(field);
        dst.put_u32(u32::try_from(8 + body.len()).map_err(|_| corrupt("too long"))?);
        dst.put_slice(&body);
        Ok(())
    }
}

/// Why a session with one cache ended.
#[derive(Debug, PartialEq, Eq)]
enum End {
    Closed,
    /// The cache answered with an older protocol version: reconnect with it.
    Downgrade(u8),
}

/// Runs the RTR client for one `BgpInstance` until aborted: one cache at a
/// time, in `preference` order (RFC 8210 §10), publishing every changed VRP
/// set on `out`. A failed or closed session moves on to the next cache; once
/// every cache has been tried it waits the retry interval and starts over.
// ponytail: no preemption — a session on a less preferred cache is kept until
// it drops, even when a more preferred one comes back.
pub async fn run(
    caches: Vec<RpkiCache>,
    vrf: Option<String>,
    status: SharedStatus,
    out: watch::Sender<Arc<VrpTable>>,
) {
    let current = out.borrow().clone();
    let mut client = Client {
        caches,
        vrf,
        status,
        out,
        current,
        intervals: Intervals::default(),
        data_at: None,
    };
    client.run().await;
}

struct Client {
    /// Already in preference order, matching `status`.
    caches: Vec<RpkiCache>,
    vrf: Option<String>,
    status: SharedStatus,
    out: watch::Sender<Arc<VrpTable>>,
    current: Arc<VrpTable>,
    intervals: Intervals,
    /// The last End of Data — the expire interval runs from it.
    data_at: Option<Instant>,
}

impl Client {
    async fn run(&mut self) {
        loop {
            for i in 0..self.caches.len() {
                let mut version = VERSION;
                loop {
                    let end = match self.connect(i).await {
                        Ok(stream) => self.session(i, stream, version).await,
                        Err(e) => {
                            warn!(cache = %self.addr(i), error = %e, "rpki cache unreachable");
                            End::Closed
                        }
                    };
                    match end {
                        End::Downgrade(v) if v < version => {
                            info!(cache = %self.addr(i), version = v, "rpki cache speaks an older version, reconnecting with it");
                            version = v;
                        }
                        _ => break,
                    }
                }
                self.update(i, |s| {
                    s.state = RpkiSessionState::Idle;
                    s.active = false;
                });
                self.expire_if_due();
            }
            let mut wait = secs(self.intervals.retry);
            if let Some(at) = self.expire_at() {
                wait = wait.min(at.saturating_duration_since(Instant::now()));
            }
            sleep(wait).await;
            self.expire_if_due();
        }
    }

    fn addr(&self, i: usize) -> SocketAddr {
        SocketAddr::new(self.caches[i].address, self.caches[i].port)
    }

    async fn connect(&self, i: usize) -> io::Result<TcpStream> {
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            tcp::connect(self.addr(i), None, self.vrf.as_deref(), None, None),
        )
        .await
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")))
    }

    fn update(&self, i: usize, f: impl FnOnce(&mut super::CacheStatus)) {
        if let Some(s) = self.status.lock().expect("rpki status lock").get_mut(i) {
            f(s);
        }
    }

    fn expire_at(&self) -> Option<Instant> {
        self.data_at.map(|t| t + secs(self.intervals.expire))
    }

    /// RFC 8210 §6: data older than the expire interval is dropped, so every
    /// route goes back to not-found.
    fn expire_if_due(&mut self) {
        if self.expire_at().is_some_and(|at| at <= Instant::now()) {
            self.data_at = None;
            warn!(
                vrps = self.current.len(),
                "rpki data expired, every route is not-found until a cache answers"
            );
            self.publish(VrpTable::default());
            for s in self.status.lock().expect("rpki status lock").iter_mut() {
                s.active = false;
                s.vrp_count = 0;
            }
        }
    }

    fn publish(&mut self, table: VrpTable) {
        if table != *self.current {
            self.current = Arc::new(table);
            self.out.send_replace(self.current.clone());
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn session(&mut self, i: usize, stream: TcpStream, version: u8) -> End {
        let addr = self.addr(i);
        let (r, w) = stream.into_split();
        let mut reader = FramedRead::new(r, RtrCodec { version });
        let mut writer = FramedWrite::new(w, RtrCodec { version });
        info!(cache = %addr, version, "rpki cache connected");
        self.update(i, |s| {
            s.state = RpkiSessionState::Syncing;
            s.version = Some(version);
        });
        let mut negotiated = false;
        let mut session_id: Option<u16> = None;
        let mut serial = 0u32;
        // The VRP set being received; `Some` between Cache Response and End
        // of Data.
        let mut work: Option<VrpTable> = None;
        // The outstanding query is a Reset Query: start from an empty set.
        let mut full = true;
        let mut refresh_at: Option<Instant> = None;
        if writer.send(Pdu::ResetQuery).await.is_err() {
            return End::Closed;
        }
        loop {
            let expire_at = self.expire_at();
            let frame = tokio::select! {
                frame = reader.next() => frame,
                () = sleep_until(refresh_at.unwrap_or_else(Instant::now)), if refresh_at.is_some() => {
                    refresh_at = Some(Instant::now() + secs(self.intervals.refresh));
                    if let Some(session) = session_id {
                        if writer.send(Pdu::SerialQuery { session, serial }).await.is_err() {
                            return End::Closed;
                        }
                    }
                    continue;
                }
                () = sleep_until(expire_at.unwrap_or_else(Instant::now)), if expire_at.is_some() => {
                    self.expire_if_due();
                    continue;
                }
            };
            let frame = match frame {
                Some(Ok(f)) => f,
                Some(Err(e)) => {
                    warn!(cache = %addr, error = %e, "rpki session error");
                    let _ = writer
                        .send(Pdu::ErrorReport {
                            code: ERR_CORRUPT_DATA,
                            pdu: Bytes::new(),
                            text: e.to_string(),
                        })
                        .await;
                    return End::Closed;
                }
                None => {
                    info!(cache = %addr, "rpki cache closed the session");
                    return End::Closed;
                }
            };
            // RFC 8210 §7: the cache's first answer settles the version.
            if frame.version != version {
                if !negotiated && frame.version < version {
                    return End::Downgrade(frame.version);
                }
                warn!(cache = %addr, version = frame.version, "rpki pdu with an unexpected version");
                return End::Closed;
            }
            negotiated = true;
            match frame.pdu {
                Pdu::CacheResponse { session } => {
                    if !full && session_id != Some(session) {
                        // RFC 8210 §5.1: a new session id means the cache
                        // restarted; its serials mean nothing any more.
                        warn!(cache = %addr, "rpki cache session id changed, resetting");
                        full = true;
                        work = None;
                        if writer.send(Pdu::ResetQuery).await.is_err() {
                            return End::Closed;
                        }
                        continue;
                    }
                    session_id = Some(session);
                    work = Some(if full {
                        VrpTable::default()
                    } else {
                        (*self.current).clone()
                    });
                }
                Pdu::Prefix { announce, vrp } => {
                    let Some(table) = work.as_mut() else {
                        warn!(cache = %addr, "rpki prefix pdu outside a cache response");
                        return End::Closed;
                    };
                    // ponytail: a duplicate announce or an unknown withdraw
                    // (RFC 8210 §12 codes 6/7) is tolerated, not an error.
                    if announce {
                        table.announce(vrp);
                    } else {
                        table.withdraw(vrp);
                    }
                }
                Pdu::EndOfData {
                    session,
                    serial: s,
                    intervals,
                } => {
                    let Some(table) = work.take() else {
                        warn!(cache = %addr, "rpki end of data outside a cache response");
                        return End::Closed;
                    };
                    if session_id != Some(session) {
                        warn!(cache = %addr, "rpki end of data for another session");
                        return End::Closed;
                    }
                    serial = s;
                    full = false;
                    if let Some(iv) = intervals {
                        self.intervals = iv.clamped();
                    }
                    let now = Instant::now();
                    self.data_at = Some(now);
                    refresh_at = Some(now + secs(self.intervals.refresh));
                    self.publish(table);
                    let vrps = self.current.len();
                    for (j, st) in self
                        .status
                        .lock()
                        .expect("rpki status lock")
                        .iter_mut()
                        .enumerate()
                    {
                        st.active = j == i;
                        if j == i {
                            st.state = RpkiSessionState::Established;
                            st.session_id = Some(session);
                            st.serial = Some(serial);
                            st.vrp_count = vrps;
                            st.last_update = Some(now.into_std());
                        } else {
                            st.vrp_count = 0;
                        }
                    }
                    info!(
                        cache = %addr, session_id = session, serial, vrps,
                        "rpki end of data"
                    );
                }
                Pdu::SerialNotify { .. } => {
                    if let (Some(session), None) = (session_id, &work) {
                        if writer
                            .send(Pdu::SerialQuery { session, serial })
                            .await
                            .is_err()
                        {
                            return End::Closed;
                        }
                    }
                }
                Pdu::CacheReset => {
                    full = true;
                    work = None;
                    if writer.send(Pdu::ResetQuery).await.is_err() {
                        return End::Closed;
                    }
                }
                Pdu::RouterKey => {}
                Pdu::ErrorReport { code, text, .. } => {
                    warn!(cache = %addr, code, text = %text, "rpki cache sent an error report");
                    return End::Closed;
                }
                Pdu::SerialQuery { .. } | Pdu::ResetQuery => {
                    warn!(cache = %addr, "rpki cache sent a router-only pdu");
                    return End::Closed;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp {
            prefix: prefix.parse().unwrap(),
            max_len,
            asn,
        }
    }

    fn roundtrip(version: u8, pdu: Pdu) -> Frame {
        let mut codec = RtrCodec { version };
        let mut buf = BytesMut::new();
        codec.encode(pdu, &mut buf).unwrap();
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert!(buf.is_empty());
        frame
    }

    #[test]
    fn pdus_roundtrip() {
        for pdu in [
            Pdu::SerialNotify {
                session: 7,
                serial: 9,
            },
            Pdu::SerialQuery {
                session: 7,
                serial: 9,
            },
            Pdu::ResetQuery,
            Pdu::CacheResponse { session: 7 },
            Pdu::Prefix {
                announce: true,
                vrp: vrp("10.0.0.0/8", 24, 65001),
            },
            Pdu::Prefix {
                announce: false,
                vrp: vrp("2001:db8::/32", 48, 65001),
            },
            Pdu::EndOfData {
                session: 7,
                serial: 9,
                intervals: Some(Intervals::default()),
            },
            Pdu::CacheReset,
            Pdu::ErrorReport {
                code: ERR_NO_DATA,
                pdu: Bytes::from_static(&[1, 2, 0, 0, 0, 0, 0, 8]),
                text: "no data".into(),
            },
        ] {
            assert_eq!(roundtrip(1, pdu.clone()), Frame { version: 1, pdu });
        }
        // Version 0 End of Data carries no intervals.
        assert_eq!(
            roundtrip(
                0,
                Pdu::EndOfData {
                    session: 1,
                    serial: 2,
                    intervals: Some(Intervals::default())
                }
            )
            .pdu,
            Pdu::EndOfData {
                session: 1,
                serial: 2,
                intervals: None
            }
        );
    }

    #[test]
    fn wire_layout_and_bad_input() {
        let mut buf = BytesMut::new();
        RtrCodec { version: 1 }
            .encode(
                Pdu::Prefix {
                    announce: true,
                    vrp: vrp("192.0.2.0/24", 24, 65010),
                },
                &mut buf,
            )
            .unwrap();
        assert_eq!(
            &buf[..],
            &[1, 4, 0, 0, 0, 0, 0, 20, 1, 24, 24, 0, 192, 0, 2, 0, 0, 0, 0xfd, 0xf2]
        );
        let mut codec = RtrCodec { version: 1 };
        // Partial frame: wait for more.
        let mut partial = BytesMut::from(&buf[..10]);
        assert_eq!(codec.decode(&mut partial).unwrap(), None);
        // max length shorter than the prefix.
        let mut bad = buf.clone();
        bad[10] = 16;
        assert!(codec.decode(&mut bad).is_err());
        let mut bad = BytesMut::from(&[1u8, 4, 0, 0, 0, 0, 0, 4][..]);
        assert!(codec.decode(&mut bad).is_err(), "length below the header");
        let mut bad = BytesMut::from(&[1u8, 99, 0, 0, 0, 0, 0, 8][..]);
        assert!(codec.decode(&mut bad).is_err(), "unknown type");
    }

    /// A scripted cache: answers one connection with the given PDUs per
    /// received query, in order.
    async fn fake_cache(
        listener: TcpListener,
        version: u8,
        script: Vec<(Option<Pdu>, Vec<Pdu>)>,
    ) -> TcpStream {
        let (stream, _) = listener.accept().await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = FramedRead::new(r, RtrCodec { version });
        let mut writer = FramedWrite::new(w, RtrCodec { version });
        for (expect, replies) in script {
            if let Some(expect) = expect {
                let got = reader.next().await.unwrap().unwrap();
                assert_eq!(got.pdu, expect);
            }
            for p in replies {
                writer.send(p).await.unwrap();
            }
        }
        reader.into_inner().reunite(writer.into_inner()).unwrap()
    }

    fn cache(addr: SocketAddr, preference: u8) -> RpkiCache {
        RpkiCache {
            address: addr.ip(),
            port: addr.port(),
            preference,
        }
    }

    async fn wait_len(rx: &mut watch::Receiver<Arc<VrpTable>>, len: usize) -> Arc<VrpTable> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let t = rx.borrow_and_update().clone();
                if t.len() == len {
                    return t;
                }
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("vrp table never reached the expected size")
    }

    #[allow(clippy::unnecessary_wraps)] // reads as the field it fills
    fn intervals(expire: u32) -> Option<Intervals> {
        Some(Intervals {
            refresh: 3600,
            retry: 1,
            expire,
        })
    }

    #[tokio::test]
    async fn reset_serial_and_cache_reset() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let a = vrp("10.0.0.0/16", 24, 65001);
        let b = vrp("2001:db8::/32", 48, 65002);
        let server = tokio::spawn(fake_cache(
            listener,
            1,
            vec![
                (
                    Some(Pdu::ResetQuery),
                    vec![
                        Pdu::CacheResponse { session: 5 },
                        Pdu::Prefix {
                            announce: true,
                            vrp: a,
                        },
                        Pdu::Prefix {
                            announce: true,
                            vrp: b,
                        },
                        Pdu::EndOfData {
                            session: 5,
                            serial: 1,
                            intervals: intervals(7200),
                        },
                        Pdu::SerialNotify {
                            session: 5,
                            serial: 2,
                        },
                    ],
                ),
                (
                    Some(Pdu::SerialQuery {
                        session: 5,
                        serial: 1,
                    }),
                    vec![
                        Pdu::CacheResponse { session: 5 },
                        Pdu::Prefix {
                            announce: false,
                            vrp: a,
                        },
                        Pdu::EndOfData {
                            session: 5,
                            serial: 2,
                            intervals: intervals(7200),
                        },
                        Pdu::CacheReset,
                    ],
                ),
                (
                    Some(Pdu::ResetQuery),
                    vec![
                        Pdu::CacheResponse { session: 5 },
                        Pdu::EndOfData {
                            session: 5,
                            serial: 3,
                            intervals: intervals(7200),
                        },
                    ],
                ),
            ],
        ));
        let (tx, mut rx) = watch::channel(Arc::new(VrpTable::default()));
        let status = super::super::new_status(&[cache(addr, 0)]);
        let client = tokio::spawn(run(vec![cache(addr, 0)], None, status.clone(), tx));
        let t = wait_len(&mut rx, 2).await;
        assert_eq!(
            t.validate("10.0.1.0/24".parse().unwrap(), Some(65001)),
            nos_rpl::ValidationState::Valid
        );
        let t = wait_len(&mut rx, 1).await;
        assert_eq!(
            t.validate("10.0.1.0/24".parse().unwrap(), Some(65001)),
            nos_rpl::ValidationState::NotFound,
            "serial update withdrew it"
        );
        wait_len(&mut rx, 0).await;
        let _stream = server.await.unwrap();
        let s = status.lock().unwrap()[0].clone();
        assert_eq!(
            (s.state, s.active, s.serial, s.session_id, s.version),
            (
                RpkiSessionState::Established,
                true,
                Some(3),
                Some(5),
                Some(1)
            )
        );
        client.abort();
    }

    #[tokio::test]
    async fn downgrades_to_version_0() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // First connection: a v0-only cache refuses v1.
            let (stream, _) = listener.accept().await.unwrap();
            let mut framed = tokio_util::codec::Framed::new(stream, RtrCodec { version: 0 });
            assert_eq!(framed.next().await.unwrap().unwrap().version, 1);
            framed
                .send(Pdu::ErrorReport {
                    code: 4,
                    pdu: Bytes::new(),
                    text: "unsupported version".into(),
                })
                .await
                .unwrap();
            drop(framed);
            fake_cache(
                listener,
                0,
                vec![(
                    Some(Pdu::ResetQuery),
                    vec![
                        Pdu::CacheResponse { session: 1 },
                        Pdu::Prefix {
                            announce: true,
                            vrp: vrp("10.0.0.0/8", 8, 1),
                        },
                        Pdu::EndOfData {
                            session: 1,
                            serial: 1,
                            intervals: None,
                        },
                    ],
                )],
            )
            .await
        });
        let (tx, mut rx) = watch::channel(Arc::new(VrpTable::default()));
        let status = super::super::new_status(&[cache(addr, 0)]);
        let client = tokio::spawn(run(vec![cache(addr, 0)], None, status.clone(), tx));
        wait_len(&mut rx, 1).await;
        let _stream = server.await.unwrap();
        assert_eq!(status.lock().unwrap()[0].version, Some(0));
        client.abort();
    }

    #[tokio::test]
    async fn fails_over_and_expires() {
        // The preferred cache refuses connections (nothing listens there).
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(fake_cache(
            listener,
            1,
            vec![(
                Some(Pdu::ResetQuery),
                vec![
                    Pdu::CacheResponse { session: 1 },
                    Pdu::Prefix {
                        announce: true,
                        vrp: vrp("10.0.0.0/8", 8, 1),
                    },
                    Pdu::EndOfData {
                        session: 1,
                        serial: 1,
                        intervals: intervals(1),
                    },
                ],
            )],
        ));
        let caches = super::super::sorted(vec![cache(addr, 2), cache(dead_addr, 1)]);
        assert_eq!(caches[0].port, dead_addr.port(), "preference order");
        let (tx, mut rx) = watch::channel(Arc::new(VrpTable::default()));
        let status = super::super::new_status(&caches);
        let client = tokio::spawn(run(caches, None, status.clone(), tx));
        wait_len(&mut rx, 1).await;
        assert!(status.lock().unwrap()[1].active);
        // The cache goes silent (the stream is kept open, nothing more is
        // sent): after the 1s expire the VRPs are dropped.
        let _stream = server.await.unwrap();
        wait_len(&mut rx, 0).await;
        assert!(!status.lock().unwrap()[1].active);
        client.abort();
    }
}
