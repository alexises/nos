//! RFC 2328 §10.6-10.8's Database Description negotiation and summary-list
//! exchange (unchanged by RFC 5340 beyond the widened `LsaKey`/`LsaHeader`
//! flowing through it) — ported near-verbatim from `ospf::exchange`. Pure
//! with respect to I/O (no sockets, no timers), but — unlike
//! `nos_ospf_common::neighbor::step` — mutates the `AdjacencyData` it's
//! given directly, since that data (request/retransmission lists) is built
//! up incrementally across many packets rather than swapped wholesale.
//!
//! Real RFC 2328 §10.8 pagination: the local LSDB summary is chunked into
//! `max_headers`-sized pieces, one chunk per DD sequence number, each acked
//! before the next is sent, in both directions. Like `ospf::exchange`,
//! `max_headers` is derived from the link's effective MTU
//! (`mtu_based_max_headers`) unless `nos-ospfv3d`'s `--dbd-max-headers`
//! test/debug flag overrides it.

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};
use crate::lsdb::Lsdb;
use crate::neighbor::{Event, NeighborState};
use crate::packet::{DbdPacket, LsAckPacket, LsrPacket, LsuPacket};

/// Fixed per-DBD-packet LSA-header budget for tests that don't care about
/// the real MTU-derived one (`mtu_based_max_headers`).
pub const DEFAULT_DBD_MAX_HEADERS: usize = 64;

/// How many LSA headers fit in one DBD packet on a link of this MTU: the
/// MTU minus the IPv6 header (40), the `OSPFv3` header (16) and the fixed DBD
/// body (12), over `LSA_HEADER_LEN` — floored at 1 so a tiny MTU still makes
/// progress.
pub fn mtu_based_max_headers(mtu: u16) -> usize {
    (mtu as usize)
        .saturating_sub(40 + 16 + 12)
        .checked_div(lsa::LSA_HEADER_LEN)
        .unwrap_or(0)
        .max(1)
}

/// One neighbor's DBD/LSR/LSU exchange state, from `ExStart` onward.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AdjacencyData {
    pub is_master: bool,
    pub dd_sequence_number: u32,
    /// LSAs this router still needs a full copy of via LSR/LSU.
    pub request_list: Vec<LsaKey>,
    /// LSAs sent via LSU, awaiting an `LSAck` — resent by `link.rs`'s
    /// retransmit sweep until acked.
    pub retransmission_list: HashMap<LsaKey, Arc<Lsa>>,
    /// The most recent DBD this router sent this neighbor (negotiation
    /// packet, poll, or reply) — resent by `link.rs`'s retransmit sweep
    /// until superseded by the next stage of the exchange.
    pub last_dbd_sent: Option<DbdPacket>,
    /// RFC 2328 §10.8: local LSDB headers not yet sent to this neighbor —
    /// seeded once from a full LSDB snapshot at `ExStart` exit, then drained
    /// `max_headers` at a time (`pop_chunk`), one chunk per DD sequence
    /// number, until empty.
    pub summary_remaining: VecDeque<LsaHeader>,
}

/// Pops up to `max` headers off the front of `remaining` for the next DBD
/// packet, returning the chunk plus whether any remain after it (the `more`
/// bit).
fn pop_chunk(remaining: &mut VecDeque<LsaHeader>, max: usize) -> (Vec<LsaHeader>, bool) {
    let chunk: Vec<LsaHeader> = std::iter::from_fn(|| remaining.pop_front())
        .take(max)
        .collect();
    (chunk, !remaining.is_empty())
}

/// One effect `link.rs` must carry out — sending a packet, or feeding an
/// `Event` back into `neighbor::step`.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    SendDbd(DbdPacket),
    SendLsr(Vec<LsaKey>),
    SendLsu(Vec<Arc<Lsa>>),
    SendLsAck(Vec<LsaHeader>),
    NeighborEvent(Event),
}

/// Handles one received DBD packet, given `state` (the neighbor's state
/// *before* this packet — `link.rs` applies any resulting `NeighborEvent`
/// via `neighbor::step` itself and passes the pre-transition state in on
/// the next call), driving RFC 2328 §10.6's master/slave negotiation
/// (`ExStart`) and §10.8's summary exchange (`Exchange`).
///
/// `local_lsdb_headers` is a snapshot the caller takes from its LSDB before
/// calling this — kept out of this function's own state so it stays free of
/// any lock/await.
#[allow(clippy::too_many_arguments)]
pub fn on_dbd_received(
    adj: &mut AdjacencyData,
    state: NeighborState,
    local_router_id: Ipv4Addr,
    neighbor_router_id: Ipv4Addr,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
    max_headers: usize,
    mtu: u16,
) -> Vec<Action> {
    match state {
        NeighborState::ExStart => on_dbd_in_exstart(
            adj,
            local_router_id,
            neighbor_router_id,
            dbd,
            local_lsdb_headers,
            max_headers,
            mtu,
        ),
        NeighborState::Exchange => on_dbd_in_exchange(
            adj,
            local_router_id,
            dbd,
            local_lsdb_headers,
            max_headers,
            mtu,
        ),
        NeighborState::Loading | NeighborState::Full => on_dbd_in_loading_or_full(adj, dbd),
        // `Down`/`Init`/`TwoWay`: no adjacency exists yet to receive a DBD
        // for in the first place.
        NeighborState::Down | NeighborState::Init | NeighborState::TwoWay => Vec::new(),
    }
}

/// RFC 2328 §10.6 (RFC 5340 keeps it), a DBD received in `Loading`/`Full`:
/// - I-bit set: `SeqNumberMismatch`. Hello alone doesn't catch a peer that
///   hit `SeqNumberMismatch` on its own side (`BadLSReq`, an out-of-sequence
///   DBD, a packet lost in an auth key-change window) while Hellos still
///   list both routers: it sits in `ExStart` sending Init DBDs, and
///   ignoring them would leave it there for good. This also covers a
///   graceful-restart helper whose neighbor restarted while still `Full`.
/// - We are the slave and this is the master's duplicate of its last poll:
///   resend our last DBD. Without it, a lost final reply leaves the master
///   stuck in `Exchange` while we are already `Full`.
/// - Anything else (the master's duplicate, other strays): discarded.
fn on_dbd_in_loading_or_full(adj: &AdjacencyData, dbd: &DbdPacket) -> Vec<Action> {
    if dbd.init {
        return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
    }
    if !adj.is_master && dbd.master && dbd.dd_sequence_number == adj.dd_sequence_number {
        return adj
            .last_dbd_sent
            .clone()
            .map(Action::SendDbd)
            .into_iter()
            .collect();
    }
    Vec::new()
}

fn on_dbd_in_exstart(
    adj: &mut AdjacencyData,
    local_router_id: Ipv4Addr,
    neighbor_router_id: Ipv4Addr,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
    max_headers: usize,
    mtu: u16,
) -> Vec<Action> {
    let is_negotiation_attempt = dbd.init && dbd.more && dbd.master;

    match neighbor_router_id.cmp(&local_router_id) {
        Ordering::Greater => {
            // Neighbor has the higher router-id: it is master, we are
            // slave. Accept either its genuine negotiation attempt
            // (I=1,M=1,MS=1) or its poll/reply (I=0,MS=1) as the trigger —
            // see `ospf::exchange::on_dbd_in_exstart`'s doc comment for the
            // full reasoning (the two sides' Hello-driven `ExStart` entry
            // isn't synchronized).
            let is_master_reply = !dbd.init && dbd.master;
            if !is_negotiation_attempt && !is_master_reply {
                return Vec::new();
            }
            adj.is_master = false;
            adj.summary_remaining = local_lsdb_headers.iter().copied().collect();
            let (reply, done) = slave_process_poll(
                adj,
                local_router_id,
                dbd,
                local_lsdb_headers,
                max_headers,
                mtu,
            );
            let mut actions = vec![
                Action::SendDbd(reply),
                Action::NeighborEvent(Event::NegotiationDone),
            ];
            if done {
                actions.push(Action::NeighborEvent(Event::ExchangeDone {
                    more_to_load: !adj.request_list.is_empty(),
                }));
            }
            actions
        }
        Ordering::Less => {
            // We have the higher router-id: we are master.
            if !is_negotiation_attempt && dbd.master {
                return Vec::new();
            }
            adj.is_master = true;
            adj.summary_remaining = local_lsdb_headers.iter().copied().collect();
            if is_negotiation_attempt {
                return vec![Action::NeighborEvent(Event::NegotiationDone)];
            }
            let (maybe_poll, done) = master_process_reply(
                adj,
                local_router_id,
                dbd,
                local_lsdb_headers,
                max_headers,
                mtu,
            );
            let mut actions = Vec::new();
            if let Some(poll) = maybe_poll {
                actions.push(Action::SendDbd(poll));
            }
            actions.push(Action::NeighborEvent(Event::NegotiationDone));
            if done {
                actions.push(Action::NeighborEvent(Event::ExchangeDone {
                    more_to_load: !adj.request_list.is_empty(),
                }));
            }
            actions
        }
        // Equal router-ids can't happen on a real network.
        Ordering::Equal => Vec::new(),
    }
}

/// The slave's side of one round: adopt the sender's sequence number,
/// extend the request list from its chunk, and reply with our own next
/// chunk. Returns the reply to send plus whether both sides have now
/// declared themselves out of data (RFC 2328 §10.8's termination test).
fn slave_process_poll(
    adj: &mut AdjacencyData,
    local_router_id: Ipv4Addr,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
    max_headers: usize,
    mtu: u16,
) -> (DbdPacket, bool) {
    adj.dd_sequence_number = dbd.dd_sequence_number;
    adj.request_list
        .extend(compute_request_list(&dbd.lsa_headers, local_lsdb_headers));
    let (chunk, more) = pop_chunk(&mut adj.summary_remaining, max_headers);
    let reply = DbdPacket {
        router_id: local_router_id,
        area_id: dbd.area_id,
        options: 0,
        interface_mtu: mtu,
        init: false,
        more,
        master: false,
        dd_sequence_number: adj.dd_sequence_number,
        lsa_headers: chunk,
    };
    let done = !dbd.more && !more;
    (reply, done)
}

/// The master's side of one round: extend the request list from the
/// slave's reply, then — unless both sides have now declared themselves out
/// of data — advance the sequence number and pop our own next chunk to
/// poll with.
fn master_process_reply(
    adj: &mut AdjacencyData,
    local_router_id: Ipv4Addr,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
    max_headers: usize,
    mtu: u16,
) -> (Option<DbdPacket>, bool) {
    adj.request_list
        .extend(compute_request_list(&dbd.lsa_headers, local_lsdb_headers));
    if !dbd.more && adj.summary_remaining.is_empty() {
        return (None, true);
    }
    adj.dd_sequence_number = adj.dd_sequence_number.wrapping_add(1);
    let (chunk, more) = pop_chunk(&mut adj.summary_remaining, max_headers);
    let poll = DbdPacket {
        router_id: local_router_id,
        area_id: dbd.area_id,
        options: 0,
        interface_mtu: mtu,
        init: false,
        more,
        master: true,
        dd_sequence_number: adj.dd_sequence_number,
        lsa_headers: chunk,
    };
    (Some(poll), false)
}

fn on_dbd_in_exchange(
    adj: &mut AdjacencyData,
    local_router_id: Ipv4Addr,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
    max_headers: usize,
    mtu: u16,
) -> Vec<Action> {
    // A negotiation-shaped packet here means the peer is still
    // retransmitting its very first message — an expected, harmless
    // duplicate, not a genuine restart (see `ospf::exchange`'s identical
    // reasoning).
    if dbd.init && dbd.more && dbd.master {
        return Vec::new();
    }

    if adj.is_master {
        if dbd.dd_sequence_number != adj.dd_sequence_number || dbd.master {
            return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
        }
        let (maybe_poll, done) = master_process_reply(
            adj,
            local_router_id,
            dbd,
            local_lsdb_headers,
            max_headers,
            mtu,
        );
        let mut actions = Vec::new();
        if let Some(poll) = maybe_poll {
            actions.push(Action::SendDbd(poll));
        }
        if done {
            actions.push(Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: !adj.request_list.is_empty(),
            }));
        }
        actions
    } else {
        if !dbd.master || dbd.dd_sequence_number != adj.dd_sequence_number.wrapping_add(1) {
            return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
        }
        let (reply, done) = slave_process_poll(
            adj,
            local_router_id,
            dbd,
            local_lsdb_headers,
            max_headers,
            mtu,
        );
        let mut actions = vec![Action::SendDbd(reply)];
        if done {
            actions.push(Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: !adj.request_list.is_empty(),
            }));
        }
        actions
    }
}

/// Handles one received LSR: looks up every requested LSA in the link's
/// area store, its own link-local store or the AS-scope store (a key only
/// ever lives in one — see `on_lsu_received`). If any requested LSA isn't held, that's RFC 2328
/// §10.7's `BadLSReq` — negotiation restarts from scratch rather than
/// sending a partial/wrong answer.
pub fn on_lsr_received(
    adj: &mut AdjacencyData,
    area_lsdb: &Lsdb,
    link_local_lsdb: &Lsdb,
    as_lsdb: &Lsdb,
    lsr: &LsrPacket,
) -> Vec<Action> {
    let mut found = Vec::with_capacity(lsr.requests.len());
    for key in &lsr.requests {
        let held = area_lsdb
            .get(key)
            .or_else(|| link_local_lsdb.get(key))
            .or_else(|| as_lsdb.get(key));
        match held {
            Some(l) => found.push(l),
            None => return vec![Action::NeighborEvent(Event::SeqNumberMismatch)],
        }
    }
    if found.is_empty() {
        return Vec::new();
    }
    for l in &found {
        adj.retransmission_list.insert(l.header.key(), l.clone());
    }
    vec![Action::SendLsu(found)]
}

/// Handles one received LSU: installs every carried LSA — a link-local-scoped
/// one (RFC 5340 §4.5.1, Link-LSA/E-Link-LSA) into this link's own
/// `link_local_lsdb`, an AS-scoped one (AS-External-LSA) into `as_lsdb`,
/// anything else into the area's `area_lsdb`; one LSU legitimately mixes
/// them — clears any now-satisfied entries from the
/// request list, and acks every LSA. Fires `LoadingDone` once the request
/// list is fully drained. Returns the actions to carry out alongside the
/// headers that were *actually* installed/superseded (excluding rejected
/// duplicates).
pub fn on_lsu_received(
    adj: &mut AdjacencyData,
    area_lsdb: &mut Lsdb,
    link_local_lsdb: &mut Lsdb,
    as_lsdb: &mut Lsdb,
    lsu: &LsuPacket,
) -> (Vec<Action>, Vec<LsaHeader>) {
    let mut acked = Vec::with_capacity(lsu.lsas.len());
    let mut newly_installed = Vec::new();
    for l in &lsu.lsas {
        let store = if lsa::is_link_local_scope(l.header.lsa_type) {
            &mut *link_local_lsdb
        } else if lsa::is_as_scope(l.header.lsa_type) {
            &mut *as_lsdb
        } else {
            &mut *area_lsdb
        };
        let key = l.header.key();
        // RFC 2328 §13 step 4 (`ospf::exchange::on_lsu_received`): a MaxAge
        // instance of an LSA held nowhere here, and not requested, is acked
        // and discarded — otherwise two routers each holding a flushed copy
        // for `lsdb::MAX_AGE_HOLD_TICKS` would reinstall each other's echo
        // forever. A Grace-LSA is exempt: it is never held (`handle_lsu`
        // acts on it at once), and its MaxAge copy is what ends a grace.
        if l.header.age >= lsa::MAX_AGE
            && l.header.lsa_type != lsa::LSA_TYPE_GRACE
            && store.get(&key).is_none()
            && !adj.request_list.contains(&key)
        {
            acked.push(l.header);
            continue;
        }
        if !matches!(
            store.install(l.clone()),
            crate::lsdb::InstallOutcome::Rejected
        ) {
            newly_installed.push(l.header);
        }
        acked.push(l.header);
        adj.request_list.retain(|k| *k != key);
    }
    let mut actions = vec![Action::SendLsAck(acked)];
    if adj.request_list.is_empty() {
        actions.push(Action::NeighborEvent(Event::LoadingDone));
    }
    (actions, newly_installed)
}

/// Handles one received `LSAck`: RFC 2328 §10.9 — stop retransmitting
/// whatever it acknowledges.
pub fn on_lsack_received(adj: &mut AdjacencyData, ack: &LsAckPacket) {
    for header in &ack.lsa_headers {
        adj.retransmission_list.remove(&header.key());
    }
}

/// RFC 2328 §10.8: request any LSA the neighbor's summary lists that this
/// router either doesn't have, or holds an older instance of.
fn compute_request_list(
    neighbor_headers: &[LsaHeader],
    local_headers: &[LsaHeader],
) -> Vec<LsaKey> {
    neighbor_headers
        .iter()
        .filter(
            |nh| match local_headers.iter().find(|lh| lh.key() == nh.key()) {
                None => true,
                Some(lh) => lsa::is_newer(nh, lh) == Ordering::Greater,
            },
        )
        .map(LsaHeader::key)
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn mtu_derived_budget() {
        assert_eq!(super::mtu_based_max_headers(1500), 71);
        assert_eq!(super::mtu_based_max_headers(68), 1);
        assert_eq!(super::mtu_based_max_headers(0), 1);
    }

    use super::*;

    fn router_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn negotiation_dbd(router_id: Ipv4Addr, seq: u32) -> DbdPacket {
        DbdPacket {
            router_id,
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 0,
            init: true,
            more: true,
            master: true,
            dd_sequence_number: seq,
            lsa_headers: Vec::new(),
        }
    }

    fn header(link_state_id: &str, seq: i32) -> LsaHeader {
        LsaHeader {
            age: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id(link_state_id),
            advertising_router: router_id(link_state_id),
            sequence_number: seq,
            checksum: 0,
            length: 24,
        }
    }

    #[test]
    fn higher_neighbor_router_id_makes_us_slave() {
        let mut adj = AdjacencyData {
            dd_sequence_number: 99,
            ..Default::default()
        };
        let dbd = negotiation_dbd(router_id("9.9.9.10"), 42);
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::ExStart,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &dbd,
            &[],
            100,
            1500,
        );
        assert!(!adj.is_master);
        assert_eq!(adj.dd_sequence_number, 42);
        assert!(matches!(
            actions.as_slice(),
            [Action::SendDbd(reply), Action::NeighborEvent(Event::NegotiationDone)]
                if !reply.master && reply.dd_sequence_number == 42
        ));
    }

    #[test]
    fn slave_accepts_masters_reply_as_exstart_trigger() {
        let mut adj = AdjacencyData::default();
        let master_lsa = header("1.1.1.1", 0x8000_0001u32.cast_signed());
        let poll = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 0,
            init: false,
            more: false,
            master: true,
            dd_sequence_number: 42,
            lsa_headers: vec![master_lsa],
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::ExStart,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &poll,
            &[],
            100,
            1500,
        );
        assert!(!adj.is_master);
        assert_eq!(adj.dd_sequence_number, 42);
        assert_eq!(adj.request_list, vec![master_lsa.key()]);
        assert_eq!(
            actions,
            vec![
                Action::SendDbd(DbdPacket {
                    router_id: router_id("9.9.9.9"),
                    area_id: Ipv4Addr::UNSPECIFIED,
                    options: 0,
                    interface_mtu: 1500,
                    init: false,
                    more: false,
                    master: false,
                    dd_sequence_number: 42,
                    lsa_headers: Vec::new(),
                }),
                Action::NeighborEvent(Event::NegotiationDone),
                Action::NeighborEvent(Event::ExchangeDone { more_to_load: true }),
            ]
        );
    }

    #[test]
    fn lower_neighbor_router_id_makes_us_master() {
        let mut adj = AdjacencyData {
            dd_sequence_number: 7,
            ..Default::default()
        };
        let dbd = negotiation_dbd(router_id("9.9.9.5"), 1);
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::ExStart,
            router_id("9.9.9.9"),
            router_id("9.9.9.5"),
            &dbd,
            &[],
            100,
            1500,
        );
        assert!(adj.is_master);
        assert_eq!(adj.dd_sequence_number, 7);
        assert_eq!(actions, vec![Action::NeighborEvent(Event::NegotiationDone)]);
    }

    #[test]
    fn master_accepts_neighbors_reply_as_exstart_trigger() {
        let mut adj = AdjacencyData {
            dd_sequence_number: 7,
            ..Default::default()
        };
        let neighbor_lsa = header("1.1.1.1", 0x8000_0001u32.cast_signed());
        let reply = DbdPacket {
            router_id: router_id("9.9.9.5"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 0,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: 999,
            lsa_headers: vec![neighbor_lsa],
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::ExStart,
            router_id("9.9.9.9"),
            router_id("9.9.9.5"),
            &reply,
            &[],
            100,
            1500,
        );
        assert!(adj.is_master);
        assert_eq!(adj.dd_sequence_number, 7, "must keep our own chosen seed");
        assert_eq!(adj.request_list, vec![neighbor_lsa.key()]);
        assert_eq!(
            actions,
            vec![
                Action::NeighborEvent(Event::NegotiationDone),
                Action::NeighborEvent(Event::ExchangeDone { more_to_load: true }),
            ]
        );
    }

    #[test]
    fn slave_ignores_a_reply_shaped_packet_in_exstart() {
        let mut adj = AdjacencyData::default();
        let reply = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 0,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: 1,
            lsa_headers: Vec::new(),
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::ExStart,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &reply,
            &[],
            100,
            1500,
        );
        assert_eq!(actions, []);
    }

    #[test]
    fn exchange_as_master_with_empty_summaries_reaches_exchange_done() {
        let mut adj = AdjacencyData {
            is_master: true,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 0,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: 5,
            lsa_headers: Vec::new(),
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &dbd,
            &[],
            100,
            1500,
        );
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: false
            })]
        );
        assert_eq!(adj.request_list, []);
    }

    #[test]
    fn exchange_requests_lsas_missing_locally() {
        let mut adj = AdjacencyData {
            is_master: true,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let neighbor_header = header("1.1.1.1", 0x8000_0001u32.cast_signed());
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 0,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: 5,
            lsa_headers: vec![neighbor_header],
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &dbd,
            &[],
            100,
            1500,
        );
        assert_eq!(adj.request_list, vec![neighbor_header.key()]);
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: true
            })]
        );
    }

    #[test]
    fn master_paginates_own_summary_across_multiple_rounds() {
        let h1 = header("2.2.2.2", 1);
        let h2 = header("3.3.3.3", 1);
        let mut adj = AdjacencyData {
            is_master: true,
            dd_sequence_number: 5,
            summary_remaining: VecDeque::from(vec![h1, h2]),
            ..Default::default()
        };
        let empty_slave_reply = |seq: u32| DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 0,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: seq,
            lsa_headers: Vec::new(),
        };

        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &empty_slave_reply(5),
            &[],
            1,
            1500,
        );
        assert_eq!(adj.dd_sequence_number, 6);
        assert_eq!(adj.summary_remaining, VecDeque::from(vec![h2]));
        assert_eq!(
            actions,
            vec![Action::SendDbd(DbdPacket {
                router_id: router_id("9.9.9.9"),
                area_id: Ipv4Addr::UNSPECIFIED,
                options: 0,
                interface_mtu: 1500,
                init: false,
                more: true,
                master: true,
                dd_sequence_number: 6,
                lsa_headers: vec![h1],
            })]
        );

        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &empty_slave_reply(6),
            &[],
            1,
            1500,
        );
        assert_eq!(adj.dd_sequence_number, 7);
        assert!(adj.summary_remaining.is_empty());
        assert_eq!(
            actions,
            vec![Action::SendDbd(DbdPacket {
                router_id: router_id("9.9.9.9"),
                area_id: Ipv4Addr::UNSPECIFIED,
                options: 0,
                interface_mtu: 1500,
                init: false,
                more: false,
                master: true,
                dd_sequence_number: 7,
                lsa_headers: vec![h2],
            })]
        );

        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &empty_slave_reply(7),
            &[],
            1,
            1500,
        );
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: false
            })]
        );
    }

    #[test]
    fn exchange_mismatch_as_master_triggers_seq_number_mismatch() {
        let mut adj = AdjacencyData {
            is_master: true,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 0,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: 6,
            lsa_headers: Vec::new(),
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &dbd,
            &[],
            100,
            1500,
        );
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
        );
    }

    #[test]
    fn exchange_ignores_negotiation_shaped_duplicate_as_master() {
        let mut adj = AdjacencyData {
            is_master: true,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let dbd = negotiation_dbd(router_id("9.9.9.10"), 999);
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &dbd,
            &[],
            100,
            1500,
        );
        assert_eq!(actions, []);
        assert_eq!(adj.dd_sequence_number, 5, "must not adopt the stray seq");
    }

    /// Feeds `dbd` to `adj` in `state` (local 9.9.9.9, neighbor 9.9.9.10).
    fn dbd_in(adj: &mut AdjacencyData, state: NeighborState, dbd: &DbdPacket) -> Vec<Action> {
        on_dbd_received(
            adj,
            state,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            dbd,
            &[],
            100,
            1500,
        )
    }

    #[test]
    fn init_dbd_while_full_is_seq_number_mismatch() {
        // RFC 2328 §10.6: the peer restarted negotiation on its own side
        // (its Hellos may still list us), so we must restart too (#146).
        for state in [NeighborState::Loading, NeighborState::Full] {
            let mut adj = AdjacencyData::default();
            let dbd = negotiation_dbd(router_id("9.9.9.10"), 1);
            assert_eq!(
                dbd_in(&mut adj, state, &dbd),
                vec![Action::NeighborEvent(Event::SeqNumberMismatch)],
                "{state:?}"
            );
        }
    }

    #[test]
    fn stray_non_init_dbd_while_full_is_ignored() {
        for state in [NeighborState::Loading, NeighborState::Full] {
            let mut adj = AdjacencyData::default();
            let mut dbd = negotiation_dbd(router_id("9.9.9.10"), 1);
            dbd.init = false;
            assert!(dbd_in(&mut adj, state, &dbd).is_empty(), "{state:?}");
        }
    }

    /// A slave adjacency that already sent its final reply at seq 42, and
    /// the master's poll at that seq (its duplicate once we are `Full`).
    fn slave_after_final_reply() -> (AdjacencyData, DbdPacket, DbdPacket) {
        let mut reply = negotiation_dbd(router_id("9.9.9.9"), 42);
        reply.init = false;
        reply.more = false;
        reply.master = false;
        let adj = AdjacencyData {
            is_master: false,
            dd_sequence_number: 42,
            last_dbd_sent: Some(reply.clone()),
            ..Default::default()
        };
        let mut poll = negotiation_dbd(router_id("9.9.9.10"), 42);
        poll.init = false;
        poll.more = false;
        (adj, reply, poll)
    }

    #[test]
    fn slave_resends_last_dbd_for_masters_duplicate_in_full() {
        for state in [NeighborState::Loading, NeighborState::Full] {
            let (mut adj, reply, poll) = slave_after_final_reply();
            assert_eq!(
                dbd_in(&mut adj, state, &poll),
                vec![Action::SendDbd(reply)],
                "{state:?}"
            );
        }
    }

    #[test]
    fn slave_ignores_other_master_dbds_in_full() {
        // A different sequence number is no duplicate of our last reply.
        let (mut adj, _, mut poll) = slave_after_final_reply();
        poll.dd_sequence_number = 43;
        assert_eq!(dbd_in(&mut adj, NeighborState::Full, &poll), []);
        // Nothing kept to resend.
        let (mut adj, _, poll) = slave_after_final_reply();
        adj.last_dbd_sent = None;
        assert_eq!(dbd_in(&mut adj, NeighborState::Full, &poll), []);
    }

    #[test]
    fn master_discards_duplicate_in_full() {
        let (mut adj, _, mut dup) = slave_after_final_reply();
        adj.is_master = true;
        dup.master = false;
        assert_eq!(dbd_in(&mut adj, NeighborState::Full, &dup), []);
        dup.master = true;
        assert_eq!(dbd_in(&mut adj, NeighborState::Full, &dup), []);
    }

    fn full_lsa(link_state_id: &str, seq: i32) -> Lsa {
        Lsa {
            header: header(link_state_id, seq),
            body: lsa::LsaBody::Router(lsa::RouterLsaBody {
                flags: 0,
                options: 0,
                links: Vec::new(),
            }),
        }
    }

    #[test]
    fn lsr_for_held_lsa_sends_lsu_and_tracks_retransmission() {
        let mut adj = AdjacencyData::default();
        let mut lsdb = Lsdb::new();
        let l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        lsdb.install(l.clone());
        let lsr = LsrPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![l.header.key()],
        };
        let actions = on_lsr_received(&mut adj, &lsdb, &Lsdb::new(), &Lsdb::new(), &lsr);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::SendLsu(lsas) if lsas.len() == 1));
        assert!(adj.retransmission_list.contains_key(&l.header.key()));
    }

    fn link_lsa(seq: i32) -> Lsa {
        let mut l = full_lsa("1.1.1.1", seq);
        l.header.lsa_type = lsa::LSA_TYPE_LINK;
        l.header.link_state_id = Ipv4Addr::new(0, 0, 0, 3);
        l.body = lsa::LsaBody::Link(lsa::LinkLsaBody {
            priority: 1,
            options: 0,
            link_local_address: "fe80::1".parse().unwrap(),
            prefixes: Vec::new(),
        });
        l
    }

    #[test]
    fn lsr_is_answered_from_whichever_store_holds_the_key() {
        let mut adj = AdjacencyData::default();
        let mut area = Lsdb::new();
        let mut link_local = Lsdb::new();
        let router = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let link = link_lsa(0x8000_0001u32.cast_signed());
        area.install(router.clone());
        link_local.install(link.clone());
        let lsr = LsrPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![router.header.key(), link.header.key()],
        };
        let actions = on_lsr_received(&mut adj, &area, &link_local, &Lsdb::new(), &lsr);
        assert!(matches!(&actions[0], Action::SendLsu(lsas) if lsas.len() == 2));
        // A Link-LSA held only by a *different* link's store is not servable
        // here — that is exactly the RFC 5340 §4.5.1 leak this guards.
        let actions = on_lsr_received(&mut adj, &area, &Lsdb::new(), &Lsdb::new(), &lsr);
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
        );
    }

    #[test]
    fn lsr_for_unknown_lsa_triggers_seq_number_mismatch() {
        let mut adj = AdjacencyData::default();
        let lsdb = Lsdb::new();
        let lsr = LsrPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![header("1.1.1.1", 1).key()],
        };
        let actions = on_lsr_received(&mut adj, &lsdb, &Lsdb::new(), &Lsdb::new(), &lsr);
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
        );
    }

    #[test]
    fn lsu_installs_and_acks_and_clears_request_list() {
        let mut adj = AdjacencyData {
            request_list: vec![header("1.1.1.1", 1).key()],
            ..Default::default()
        };
        let mut lsdb = Lsdb::new();
        let l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l.clone()],
        };
        let (actions, newly_installed) = on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut Lsdb::new(),
            &mut Lsdb::new(),
            &lsu,
        );
        assert_eq!(adj.request_list, []);
        assert!(lsdb.get(&l.header.key()).is_some());
        assert_eq!(
            actions,
            vec![
                Action::SendLsAck(vec![l.header]),
                Action::NeighborEvent(Event::LoadingDone),
            ]
        );
        assert_eq!(newly_installed, vec![l.header]);
    }

    /// RFC 2328 §13 step 4: an unrequested `MaxAge` LSA with no held copy is
    /// acked but not installed; with a held copy, it supersedes it.
    #[test]
    fn lsu_discards_unheld_max_age_lsa() {
        let mut adj = AdjacencyData::default();
        let mut lsdb = Lsdb::new();
        let live = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let mut flushed = live.clone();
        flushed.header.age = lsa::MAX_AGE;
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![flushed.clone()],
        };
        let (actions, newly_installed) = on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut Lsdb::new(),
            &mut Lsdb::new(),
            &lsu,
        );
        assert_eq!(newly_installed, []);
        assert!(lsdb.get(&flushed.header.key()).is_none());
        assert!(actions.contains(&Action::SendLsAck(vec![flushed.header])));

        lsdb.install(live);
        let (_, newly_installed) = on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut Lsdb::new(),
            &mut Lsdb::new(),
            &lsu,
        );
        assert_eq!(newly_installed, vec![flushed.header]);
        assert_eq!(
            lsdb.get(&flushed.header.key()).unwrap().header.age,
            lsa::MAX_AGE
        );
    }

    #[test]
    fn lsu_routes_each_lsa_to_its_scope_store() {
        let mut adj = AdjacencyData::default();
        let mut area = Lsdb::new();
        let mut link_local = Lsdb::new();
        let router = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let link = link_lsa(0x8000_0001u32.cast_signed());
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![router.clone(), link.clone()],
        };
        let mut external = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        external.header.lsa_type = lsa::LSA_TYPE_AS_EXTERNAL;
        let mut lsu = lsu;
        lsu.lsas.push(external.clone());
        let mut as_scope = Lsdb::new();
        let (_, newly_installed) =
            on_lsu_received(&mut adj, &mut area, &mut link_local, &mut as_scope, &lsu);
        assert_eq!(newly_installed.len(), 3);
        assert!(as_scope.get(&external.header.key()).is_some());
        assert!(area.get(&external.header.key()).is_none());
        assert!(area.get(&router.header.key()).is_some());
        assert!(area.get(&link.header.key()).is_none());
        assert!(link_local.get(&link.header.key()).is_some());
        assert!(link_local.get(&router.header.key()).is_none());
    }

    #[test]
    fn lsack_clears_retransmission_list() {
        let l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let mut adj = AdjacencyData {
            retransmission_list: HashMap::from([(l.header.key(), Arc::new(l.clone()))]),
            ..Default::default()
        };
        let ack = LsAckPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_headers: vec![l.header],
        };
        on_lsack_received(&mut adj, &ack);
        assert!(adj.retransmission_list.is_empty());
    }
}
