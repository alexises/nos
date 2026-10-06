//! RFC 2328 §10.6-10.8's Database Description negotiation and summary-list
//! exchange — the heavier per-neighbor logic `neighbor.rs` deliberately
//! stays too thin to hold. Pure with respect to I/O (no sockets, no
//! timers), but — unlike `neighbor::step` — mutates the `AdjacencyData` it's
//! given directly, since that data (request/retransmission lists) is built
//! up incrementally across many packets rather than swapped wholesale like
//! `bgp::fsm`'s `RemoteInfo`.
//!
//! Real RFC 2328 §10.8 pagination: the local LSDB summary is chunked into
//! `max_headers`-sized pieces, one chunk per DD sequence number, each acked
//! before the next is sent, in both directions. `max_headers` is normally
//! derived per-link from that link's own effective MTU (`mtu_based_max_headers`,
//! `link::LinkConfig.mtu` — see `reconcile::resolve_effective_mtu`), falling
//! back to the fixed `DEFAULT_DBD_MAX_HEADERS` budget only when
//! `link.rs`'s `--dbd-max-headers` CLI flag explicitly overrides it (test/debug
//! use only, e.g. `tools/verify-e2e.sh ospf-dbd-pagination`'s deterministic
//! pagination check). `DbdPacket.interface_mtu` is populated from that same
//! effective MTU on send, but still never enforced/validated on receive —
//! RFC 2328 allows disabling that check, and this NOS never implements it.

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};
use crate::lsdb::Lsdb;
use crate::neighbor::{Event, NeighborState};
use crate::packet::{DbdPacket, LsAckPacket, LsrPacket, LsuPacket, OPTION_E, OPTION_O};

/// Options this router sends in every DBD of a normal area: RFC 2328's
/// E-bit (as in its Hellos) and RFC 5250's O-bit.
pub const DBD_OPTIONS: u8 = OPTION_E | OPTION_O;

/// The DBD options for a link: `DBD_OPTIONS`, without the E-bit in a stub
/// area (RFC 2328 §3.6).
pub fn dbd_options(stub: bool) -> u8 {
    if stub {
        OPTION_O
    } else {
        DBD_OPTIONS
    }
}

/// A conservative per-DBD-packet LSA-header budget: 1500-byte Ethernet MTU
/// − 20 (IP) − 24 (OSPF common header) − 8 (`DBD_BODY_FIXED_LEN`) ≈ 1448
/// bytes ÷ 20 (`LSA_HEADER_LEN`) ≈ 72, rounded down for crypto-auth trailer
/// headroom. Used as `link.rs`'s `--dbd-max-headers` CLI flag's own default
/// value when a test/debug run wants a fixed override rather than the real
/// MTU-derived budget (`mtu_based_max_headers`) — see this module's own doc
/// comment above.
pub const DEFAULT_DBD_MAX_HEADERS: usize = 64;

/// Same formula `DEFAULT_DBD_MAX_HEADERS`'s doc comment spells out, applied
/// to a real link's effective MTU instead of a fixed 1500 assumption —
/// floored at 1 so a pathologically small MTU still makes progress one LSA
/// header at a time rather than producing an empty/zero-sized chunk budget.
pub fn mtu_based_max_headers(mtu: u16) -> usize {
    (mtu as usize)
        .saturating_sub(20 + 24 + 8)
        .checked_div(lsa::LSA_HEADER_LEN)
        .unwrap_or(0)
        .max(1)
}

/// RFC 2328 §10.6 (RFC 5340 §4.2.1 keeps it): a DBD whose Interface MTU
/// exceeds this link's effective MTU is rejected, since the neighbor could send
/// DBDs we can't receive whole. Smaller, equal and 0 (not advertised) are fine,
/// and `ignore` (`mtu-ignore`) skips the check.
pub fn mtu_acceptable(neighbor_mtu: u16, local_mtu: u16, ignore: bool) -> bool {
    ignore || neighbor_mtu <= local_mtu
}

/// One neighbor's DBD/LSR/LSU exchange state, from `ExStart` onward.
// Independent flags, each read on its own.
#[allow(clippy::struct_excessive_bools)]
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
    /// until superseded by the next stage of the exchange. Necessary
    /// because the two sides' Hello-driven `TwoWay`/`ExStart` transitions
    /// aren't synchronized: whichever side reaches `ExStart` first sends a
    /// negotiation packet the other side isn't ready to receive yet (its
    /// own adjacency data doesn't exist until it too reaches `ExStart`),
    /// so without a resend, that first packet is silently dropped forever.
    pub last_dbd_sent: Option<DbdPacket>,
    /// RFC 2328 §10.8: local LSDB headers not yet sent to this neighbor —
    /// seeded once from a full LSDB snapshot at `ExStart` exit, then drained
    /// `max_headers` at a time (`pop_chunk`), one chunk per DD sequence
    /// number, until empty.
    pub summary_remaining: VecDeque<LsaHeader>,
    /// RFC 2328 §13.5 delayed acknowledgment: headers of LSAs received from
    /// this neighbor and not yet acknowledged. `on_lsu_received` appends
    /// here instead of answering each LSU with its own `LSAck`; `link.rs`'s
    /// `RXMT_INTERVAL` sweep (`flush_pending_acks`) sends them as one packet.
    pub pending_acks: Vec<LsaHeader>,
    /// When `pending_acks` last went from empty to non-empty — purely for
    /// the "how long was this batch held" figure the flush logs.
    pub pending_acks_since: Option<std::time::Instant>,
    /// RFC 5250 §3: the neighbor's DBD set the O-bit, so it may be sent
    /// opaque LSAs (types 9-11). Learnt in `ExStart`.
    pub opaque_capable: bool,
    /// The link is in a stub area (RFC 2328 §3.6) or an NSSA: DBDs go
    /// without the E-bit, and AS-scope LSAs (Type-5/11) are never
    /// summarized, accepted or requested.
    pub stub: bool,
    /// The link is in an NSSA (RFC 3101): the only kind of link a Type-7 is
    /// summarized, accepted or requested on (`lsa::in_area_scope`).
    pub nssa: bool,
}

/// Pops up to `max` headers off the front of `remaining` for the next DBD
/// packet, returning the chunk plus whether any remain after it (the `more`
/// bit). `VecDeque::pop_front` keeps this O(chunk size) per call rather than
/// the O(n) a `Vec::drain(0..n)` would cost when called repeatedly.
fn pop_chunk(remaining: &mut VecDeque<LsaHeader>, max: usize) -> (Vec<LsaHeader>, bool) {
    let chunk: Vec<LsaHeader> = std::iter::from_fn(|| remaining.pop_front())
        .take(max)
        .collect();
    (chunk, !remaining.is_empty())
}

/// One effect `link.rs` must carry out — sending a packet, or feeding an
/// `Event` back into `neighbor::step`. Mirrors `bgp::fsm::step`'s
/// pure-transition-returns-actions shape.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    SendDbd(DbdPacket),
    SendLsr(Vec<LsaKey>),
    SendLsu(Vec<Arc<Lsa>>),
    SendLsAck(Vec<LsaHeader>),
    /// A newly-received LSA that's newer than what's held (or new outright).
    /// Never emitted: `on_lsu_received` installs directly into the `Lsdb` it's
    /// handed, and cross-link propagation is left entirely to `link.rs`'s
    /// periodic `flood_full_neighbors` resend (every link in an area shares
    /// one `Lsdb`, so the LSA is already "installed" everywhere that matters
    /// the moment `on_lsu_received` runs — only *telling already-`Full`
    /// neighbors sooner* is missing, and nothing here needs that told
    /// quickly). This variant is kept, unused, as the natural extension point
    /// if a future SPF phase ever needs event-driven flooding's tighter
    /// latency bound — see `link.rs`'s `flood_full_neighbors` `ponytail:` note.
    InstallAndFlood(Arc<Lsa>),
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
    // RFC 2328 §10.6: an AS-external LSA listed on a stub area's link (or a
    // Type-7 outside an NSSA) means the two databases can't agree — restart
    // the exchange.
    if matches!(state, NeighborState::ExStart | NeighborState::Exchange)
        && dbd
            .lsa_headers
            .iter()
            .any(|h| !lsa::in_area_scope(h.lsa_type, adj.stub, adj.nssa))
    {
        return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
    }
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

/// RFC 2328 §10.6, a DBD received in `Loading`/`Full`:
/// - I-bit set: `SeqNumberMismatch`. Hello alone doesn't catch a peer that
///   hit `SeqNumberMismatch` on its own side (`BadLSReq`, an out-of-sequence
///   DBD) while Hellos still list both routers: it sits in `ExStart`
///   sending Init DBDs, and ignoring them would leave it there for good.
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
            // (I=1,M=1,MS=1) or its poll/reply (I=0,MS=1 — `more` may be
            // either value now that a paginated first poll can legitimately
            // still have data left) as the trigger — symmetric to the
            // `Ordering::Less` branch's own "accept either" reasoning
            // below, and for the same underlying cause: the two sides'
            // Hello-driven ExStart entry isn't synchronized, so if the
            // master reaches ExStart (and sends its attempt) before *we*
            // reach 2-Way with it, `handle_dbd` has no adjacency yet to
            // receive that attempt into and silently drops it (see its own
            // doc comment) — including every retransmitted copy, since the
            // master, having since moved on, only ever resends its most
            // recent packet. By the time we create our own adjacency and
            // send our own (late) attempt, the only packet we ever get back
            // is the master's reply to *that* — never its original attempt,
            // which is gone for good. Without this, we'd wait here forever
            // for a message that will never come again (a real bug this
            // NOS's `ospf-dr` Docker scenario found: a third router joining
            // a segment with an already-converged DR/BDR pair got stuck
            // exactly this way). The `!dbd.more` requirement this check
            // used to carry was only ever correct while the summary always
            // fit in one packet — dropped now that a legitimate first poll
            // can span more than one.
            let is_master_reply = !dbd.init && dbd.master;
            if !is_negotiation_attempt && !is_master_reply {
                return Vec::new();
            }
            adj.is_master = false;
            seed_summary(adj, dbd, local_lsdb_headers);
            // Real content always starts with *our* reply (slave replies
            // to the master's bare attempt with its own first chunk
            // immediately, RFC 2328 §10.6) — correct whether `dbd` is the
            // bare attempt itself (its own `lsa_headers` is empty, so this
            // is a no-op beyond adopting the seed) or the master's poll
            // arriving first (per this branch's own doc comment above).
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
            // We have the higher router-id: we are master. Accept either
            // the (lower-id) neighbor's own negotiation attempt, or its
            // reply (MS bit clear) — RFC 2328 §10.6 allows either as the
            // trigger, and accepting the reply matters in practice: the
            // two sides' Hello-driven ExStart entry isn't synchronized, so
            // by the time we ourselves reach ExStart and are ready to
            // process anything, the neighbor may already be replying to
            // an earlier attempt of ours we never got to see — discarding
            // that reply (because it isn't itself negotiation-shaped)
            // would leave us stuck here forever, since the neighbor
            // (already past ExStart) has no reason to resend that attempt.
            if !is_negotiation_attempt && dbd.master {
                return Vec::new();
            }
            adj.is_master = true;
            seed_summary(adj, dbd, local_lsdb_headers);
            if is_negotiation_attempt {
                // The bare handshake only — no content from either side
                // yet. RFC 2328 §10.8: the master's *own* content-sending
                // only begins once the slave's real reply arrives (handled
                // below, or by `on_dbd_in_exchange` once this transitions
                // out of `ExStart`) — sending our own first chunk here too,
                // at this same round, would race the slave's identically-
                // numbered reply instead of properly following it (the bug
                // this design point exists to avoid: two independently-sent
                // "round 0" packets can never be a request/response pair to
                // each other). Our already-sent negotiation attempt
                // (`start_negotiation`) keeps being retransmitted as-is
                // (`AdjacencyData::last_dbd_sent`) until superseded.
                return vec![Action::NeighborEvent(Event::NegotiationDone)];
            }
            // `dbd` is the neighbor's actual reply, arriving before we ever
            // processed a bare attempt from it (per this branch's own doc
            // comment) — process it exactly like a normal in-`Exchange`
            // reply: extend the request list, then advance to our own
            // first real chunk if either side still has data.
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
        // Equal router-ids can't happen on a real network (every router-id
        // is required to be unique) — nothing sensible to negotiate.
        Ordering::Equal => Vec::new(),
    }
}

/// Learns whether the neighbor is opaque-capable from its DBD and seeds the
/// summary list — without opaque LSAs for one that isn't (RFC 5250 §3).
fn seed_summary(adj: &mut AdjacencyData, dbd: &DbdPacket, local_lsdb_headers: &[LsaHeader]) {
    adj.opaque_capable = dbd.options & OPTION_O != 0;
    adj.summary_remaining = local_lsdb_headers
        .iter()
        .filter(|h| adj.opaque_capable || !lsa::is_opaque(h.lsa_type))
        .filter(|h| lsa::in_area_scope(h.lsa_type, adj.stub, adj.nssa))
        .copied()
        .collect();
}

/// The slave's side of one round: adopt the sender's sequence number,
/// extend the request list from its chunk, and reply with our own next
/// chunk. Shared by `on_dbd_in_exstart` (the very first round, where the
/// sequence number is adopted unconditionally rather than validated — RFC
/// 2328 §10.6: the master is always authoritative) and `on_dbd_in_exchange`
/// (every later round, after the caller has already validated it). Returns
/// the reply to send plus whether both sides have now declared themselves
/// out of data (RFC 2328 §10.8's termination test).
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
        interface_mtu: mtu,
        options: dbd_options(adj.stub),
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
/// poll with. Shared by `on_dbd_in_exstart` (the neighbor's reply arriving
/// before we ever saw a bare attempt, so its own sequence number is
/// informational only — RFC 2328 §10.6: as master, only *our* sequence
/// number is authoritative) and `on_dbd_in_exchange` (every later round,
/// after the caller has already validated the reply's sequence number
/// matches our last poll). Returns the next poll to send (`None` once
/// nothing more needs polling for) plus whether both sides are now done.
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
    // RFC 2328 §10.8's termination test: both sides have declared
    // themselves out of summary data (M-bit clear on both this reply and
    // whatever we last sent).
    if !dbd.more && adj.summary_remaining.is_empty() {
        return (None, true);
    }
    // Otherwise keep polling — even with nothing left of our own, we still
    // need to poll again (an empty chunk) purely to let the slave send its
    // next one.
    adj.dd_sequence_number = adj.dd_sequence_number.wrapping_add(1);
    let (chunk, more) = pop_chunk(&mut adj.summary_remaining, max_headers);
    let poll = DbdPacket {
        router_id: local_router_id,
        area_id: dbd.area_id,
        interface_mtu: mtu,
        options: dbd_options(adj.stub),
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
    // A negotiation-shaped packet (I=1,M=1,MS=1) here means the peer is
    // still retransmitting its very first message — its own view hasn't
    // caught up to the fact that negotiation already succeeded on our end.
    // The two sides' retransmit timers race independently, so this is an
    // expected, harmless duplicate, not a genuine restart (a genuine
    // restart is instead caught via Hello — losing 2-way already clears
    // `adjacency`, see `link::handle_hello`). Ignoring it here matters:
    // treating it as `SeqNumberMismatch` would force us to restart too,
    // and since both sides pick a fresh random sequence number on every
    // restart, that cascades into a live, unrecoverable ping-pong between
    // the two peers instead of ever settling.
    if dbd.init && dbd.more && dbd.master {
        return Vec::new();
    }

    if adj.is_master {
        // Expect the slave's reply to our last poll: same sequence number,
        // MS bit clear.
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
        // Expect the master's next poll: MS bit set, sequence number one
        // past the last one we accepted.
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

/// Handles one received LSR: looks up every requested LSA in the area
/// store, then this link's own (type 9, RFC 5250). If any
/// requested LSA isn't held, that's RFC 2328 §10.7's `BadLSReq` — the two
/// databases have diverged, so negotiation restarts from scratch rather
/// than sending a partial/wrong answer. Otherwise, sends everything found
/// as one LSU and records it as outstanding until acked (see
/// `on_lsack_received`).
pub fn on_lsr_received(
    adj: &mut AdjacencyData,
    lsdb: &Lsdb,
    link_local_lsdb: &Lsdb,
    lsr: &LsrPacket,
) -> Vec<Action> {
    let mut found = Vec::with_capacity(lsr.requests.len());
    for key in &lsr.requests {
        match lsdb.get(key).or_else(|| link_local_lsdb.get(key)) {
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

/// Handles one received LSU: installs every carried LSA into its store (RFC
/// 2328 §13's "is this instance newer" check, via `Lsdb::install`), clears
/// any now-satisfied entries from the request list, and queues an ack for
/// every LSA regardless of whether it was actually newer — an ack for a
/// stale instance still stops the sender retransmitting it forever. Acks
/// are *delayed* (RFC 2328 §13.5): appended to `adj.pending_acks` for
/// `link.rs`'s next `RXMT_INTERVAL` sweep to send as one `LSAck`, not
/// returned as a `SendLsAck` action — `ponytail:` the RFC's direct
/// (immediate) ack cases key off "was this LSA flooded back out in
/// response", a signal this crate's periodic-resend flooding has no
/// equivalent of, so every ack is delayed. Fires `LoadingDone` once the
/// request list is fully drained. Returns the actions to carry out
/// alongside the headers that were *actually* installed/superseded
/// (excluding rejected duplicates) — `link.rs` uses the latter to avoid
/// logging a fresh "installed" line for a duplicate its own periodic
/// resend produces.
pub fn on_lsu_received(
    adj: &mut AdjacencyData,
    area_lsdb: &mut Lsdb,
    link_local_lsdb: &mut Lsdb,
    lsu: &LsuPacket,
    now: Instant,
) -> (Vec<Action>, Vec<LsaHeader>) {
    let acked = &mut adj.pending_acks;
    let mut newly_installed = Vec::new();
    for l in &lsu.lsas {
        // RFC 2328 §13 step 3: an AS-external (or AS-scope opaque) LSA on a
        // stub area's or NSSA's link, or a Type-7 outside an NSSA (RFC 3101
        // §2.4), is discarded — neither installed nor acked.
        if !lsa::in_area_scope(l.header.lsa_type, adj.stub, adj.nssa) {
            continue;
        }
        let key = l.header.key();
        // RFC 5250 §3: a type-9 LSA lives in the store of the link it arrived
        // on, so no other link's resend floods it.
        let lsdb = if lsa::is_link_local_scope(l.header.lsa_type) {
            &mut *link_local_lsdb
        } else {
            &mut *area_lsdb
        };
        // RFC 2328 §13 step 4: a MaxAge instance of an LSA this router holds
        // no copy of is acknowledged and discarded, never installed — except
        // one it asked for during exchange (the RFC's "a neighbor is in
        // Exchange/Loading" carve-out, narrowed to this adjacency's own
        // request list). Without this, two routers each holding the flushed
        // copy for its flood window (`Lsdb::MAX_AGE_HOLD_TICKS`) would keep
        // reinstalling each other's echo of it forever.
        if l.header.age >= lsa::MAX_AGE
            && lsdb.get(&key).is_none()
            && !adj.request_list.contains(&key)
        {
            acked.push(l.header);
            continue;
        }
        match lsdb.install_received(l.clone(), now) {
            // RFC 2328 §13 step 5a (`MinLSArrival`): discarded, and neither
            // acknowledged nor treated as answering a request — the sender's
            // retransmission brings it back.
            crate::lsdb::InstallOutcome::TooSoon => continue,
            crate::lsdb::InstallOutcome::Rejected => {}
            crate::lsdb::InstallOutcome::Installed | crate::lsdb::InstallOutcome::Superseded => {
                newly_installed.push(l.header);
            }
        }
        acked.push(l.header);
        adj.request_list.retain(|k| *k != key);
    }
    let mut actions = Vec::new();
    if adj.request_list.is_empty() {
        actions.push(Action::NeighborEvent(Event::LoadingDone));
    }
    (actions, newly_installed)
}

/// RFC 2328 §13.5: takes every queued ack for this neighbor as one `LSAck`
/// to send now — `None` if nothing is pending. Called by `link.rs` on every
/// `RXMT_INTERVAL` sweep.
pub fn take_pending_acks(adj: &mut AdjacencyData) -> Option<Action> {
    if adj.pending_acks.is_empty() {
        return None;
    }
    adj.pending_acks_since = None;
    Some(Action::SendLsAck(std::mem::take(&mut adj.pending_acks)))
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
    fn mtu_acceptable_only_rejects_a_larger_neighbor_mtu() {
        assert!(mtu_acceptable(1500, 1500, false));
        assert!(mtu_acceptable(1400, 1500, false));
        assert!(mtu_acceptable(0, 1500, false));
        assert!(!mtu_acceptable(1500, 1400, false));
        assert!(mtu_acceptable(1500, 1400, true));
    }
    use super::*;

    fn router_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn negotiation_dbd(router_id: Ipv4Addr, seq: u32) -> DbdPacket {
        DbdPacket {
            router_id,
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
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
            options: 0,
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
        // Regression test (found via a real three-router Docker scenario,
        // `ospf-dr`, not a unit test): symmetric to
        // `master_accepts_neighbors_reply_as_exstart_trigger` below, but for
        // the *slave* side. If the master reaches ExStart (and sends its
        // attempt) before we ourselves reach 2-Way with it, `handle_dbd` has
        // no adjacency yet to receive that attempt into and drops it — and
        // every retransmitted copy, since the master, once it processes our
        // own (later) attempt, only ever resends its reply to that. Without
        // this, the slave waits here forever for a message that will never
        // come again.
        let mut adj = AdjacencyData::default();
        let master_lsa = header("1.1.1.1", 0x8000_0001u32.cast_signed());
        let poll = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
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
        // The master's poll already says `more: false`, and our own reply
        // carries no data of its own (empty local LSDB) — both sides are
        // done in this same round, so `ExchangeDone` fires alongside it.
        assert_eq!(
            actions,
            vec![
                Action::SendDbd(DbdPacket {
                    router_id: router_id("9.9.9.9"),
                    area_id: Ipv4Addr::UNSPECIFIED,
                    interface_mtu: 1500,
                    options: DBD_OPTIONS,
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
        // A bare negotiation attempt carries no content from either side —
        // real content-sending only begins once the slave's actual reply
        // arrives (RFC 2328 §10.8), so this fires only `NegotiationDone`,
        // no `SendDbd`. Our already-sent negotiation attempt keeps being
        // retransmitted as-is until then.
        assert_eq!(actions, vec![Action::NeighborEvent(Event::NegotiationDone)]);
    }

    #[test]
    fn master_accepts_neighbors_reply_as_exstart_trigger() {
        // Regression test: the two sides' Hello-driven ExStart entry isn't
        // synchronized, so the master may receive the (lower-id)
        // neighbor's reply (MS=0) before/instead of ever seeing its
        // negotiation attempt — e.g. because that attempt was sent before
        // this side even reached ExStart. A reply alone must still be
        // accepted as proof the neighbor deferred to us as master, or this
        // side gets stuck in ExStart forever (the neighbor, already past
        // ExStart itself, never resends the original attempt). Since that
        // reply is also the *only* copy of the neighbor's summary we'll
        // ever see (it won't send another once it's moved on), its
        // content must be processed immediately too — not just used to
        // learn our role — or *this* side gets stuck instead, waiting on
        // a second message that never comes.
        let mut adj = AdjacencyData {
            dd_sequence_number: 7,
            ..Default::default()
        };
        let neighbor_lsa = header("1.1.1.1", 0x8000_0001u32.cast_signed());
        let reply = DbdPacket {
            router_id: router_id("9.9.9.5"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: 999, // the neighbor's own, irrelevant to us
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
        // The neighbor's reply already says `more: false`, and our own
        // local LSDB is empty (nothing to poll back with) — both sides are
        // done immediately, with no `SendDbd` at all (we have nothing of
        // our own to send).
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
        // A lower-id neighbor sending MS=0 to us would be nonsensical (we'd
        // be slave, so it can't also think it's slave) — ignored rather
        // than acted on.
        let mut adj = AdjacencyData::default();
        let reply = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
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
    fn non_negotiation_dbd_in_exstart_is_ignored() {
        let mut adj = AdjacencyData::default();
        let mut dbd = negotiation_dbd(router_id("9.9.9.10"), 42);
        dbd.more = false;
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
            interface_mtu: 0,
            options: DBD_OPTIONS,
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
    fn exchange_as_slave_with_master_poll_reaches_exchange_done() {
        // `adj.dd_sequence_number == 5` models round 5 already having
        // happened via `on_dbd_in_exstart` (which now always sends the
        // slave's own first chunk immediately) — this poll is round 6, the
        // master's next (and, since both sides carry no more data, final)
        // poll.
        let mut adj = AdjacencyData {
            is_master: false,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.5"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
            init: false,
            more: false,
            master: true,
            dd_sequence_number: 6,
            lsa_headers: Vec::new(),
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.5"),
            &dbd,
            &[],
            100,
            1500,
        );
        assert_eq!(adj.dd_sequence_number, 6);
        // The slave must still send its own (empty) reply at the new
        // sequence number alongside declaring the exchange done — the
        // master needs to see it to know the slave has nothing left too.
        assert_eq!(
            actions,
            vec![
                Action::SendDbd(DbdPacket {
                    router_id: router_id("9.9.9.9"),
                    area_id: Ipv4Addr::UNSPECIFIED,
                    interface_mtu: 1500,
                    options: DBD_OPTIONS,
                    init: false,
                    more: false,
                    master: false,
                    dd_sequence_number: 6,
                    lsa_headers: Vec::new(),
                }),
                Action::NeighborEvent(Event::ExchangeDone {
                    more_to_load: false
                }),
            ]
        );
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
            interface_mtu: 0,
            options: DBD_OPTIONS,
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
    fn exchange_does_not_request_lsas_already_current_locally() {
        let mut adj = AdjacencyData {
            is_master: true,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let local = header("1.1.1.1", 0x8000_0002u32.cast_signed());
        let neighbor_header = header("1.1.1.1", 0x8000_0001u32.cast_signed());
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
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
            &[local],
            100,
            1500,
        );
        assert_eq!(adj.request_list, []);
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: false
            })]
        );
    }

    #[test]
    fn master_paginates_own_summary_across_multiple_rounds() {
        // Models round 5 (`on_dbd_in_exstart`) already having sent the
        // first chunk (`h0`, not itself constructed here), leaving two more
        // headers to drain one at a time (`max_headers: 1`).
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
            interface_mtu: 0,
            options: DBD_OPTIONS,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: seq,
            lsa_headers: Vec::new(),
        };

        // Round 5's reply: master still has h1/h2 left, so it must poll
        // again rather than declare done.
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
                interface_mtu: 1500,
                options: DBD_OPTIONS,
                init: false,
                more: true,
                master: true,
                dd_sequence_number: 6,
                lsa_headers: vec![h1],
            })]
        );

        // Round 6's reply: one header (h2) left, still not done.
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
                interface_mtu: 1500,
                options: DBD_OPTIONS,
                init: false,
                more: false,
                master: true,
                dd_sequence_number: 7,
                lsa_headers: vec![h2],
            })]
        );

        // Round 7's reply: both sides now empty -- done.
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
    fn slave_paginates_own_summary_across_multiple_rounds() {
        // Symmetric to `master_paginates_own_summary_across_multiple_rounds`,
        // for the slave side: round 5 already sent the first chunk, two
        // more headers remain, drained one at a time.
        let h1 = header("2.2.2.2", 1);
        let h2 = header("3.3.3.3", 1);
        let mut adj = AdjacencyData {
            is_master: false,
            dd_sequence_number: 5,
            summary_remaining: VecDeque::from(vec![h1, h2]),
            ..Default::default()
        };
        let master_poll = |seq: u32, more: bool| DbdPacket {
            router_id: router_id("9.9.9.5"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
            init: false,
            more,
            master: true,
            dd_sequence_number: seq,
            lsa_headers: Vec::new(),
        };

        // Master's next poll (round 6) -- master has nothing else, but the
        // slave still has h1/h2 to send.
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.5"),
            &master_poll(6, false),
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
                interface_mtu: 1500,
                options: DBD_OPTIONS,
                init: false,
                more: true,
                master: false,
                dd_sequence_number: 6,
                lsa_headers: vec![h1],
            })]
        );

        // Round 7: slave's last header, both sides now declare done in the
        // same round.
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.5"),
            &master_poll(7, false),
            &[],
            1,
            1500,
        );
        assert_eq!(adj.dd_sequence_number, 7);
        assert!(adj.summary_remaining.is_empty());
        assert_eq!(
            actions,
            vec![
                Action::SendDbd(DbdPacket {
                    router_id: router_id("9.9.9.9"),
                    area_id: Ipv4Addr::UNSPECIFIED,
                    interface_mtu: 1500,
                    options: DBD_OPTIONS,
                    init: false,
                    more: false,
                    master: false,
                    dd_sequence_number: 7,
                    lsa_headers: vec![h2],
                }),
                Action::NeighborEvent(Event::ExchangeDone {
                    more_to_load: false
                }),
            ]
        );
    }

    #[test]
    fn master_keeps_polling_with_empty_chunk_while_slave_still_has_data() {
        // Master's own summary is already fully sent (`summary_remaining`
        // empty), but the slave's `more` bit is still set -- master must
        // keep polling (with an empty chunk of its own) purely to let the
        // slave send what it has left, and `request_list` must accumulate
        // across both rounds rather than losing round 5's entry.
        let h_a = header("4.4.4.4", 1);
        let h_b = header("5.5.5.5", 1);
        let mut adj = AdjacencyData {
            is_master: true,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let slave_reply = |seq: u32, more: bool, header: LsaHeader| DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
            init: false,
            more,
            master: false,
            dd_sequence_number: seq,
            lsa_headers: vec![header],
        };

        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &slave_reply(5, true, h_a),
            &[],
            100,
            1500,
        );
        assert_eq!(adj.request_list, vec![h_a.key()]);
        assert_eq!(
            actions,
            vec![Action::SendDbd(DbdPacket {
                router_id: router_id("9.9.9.9"),
                area_id: Ipv4Addr::UNSPECIFIED,
                interface_mtu: 1500,
                options: DBD_OPTIONS,
                init: false,
                more: false,
                master: true,
                dd_sequence_number: 6,
                lsa_headers: Vec::new(),
            })]
        );

        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &slave_reply(6, false, h_b),
            &[],
            100,
            1500,
        );
        assert_eq!(
            adj.request_list,
            vec![h_a.key(), h_b.key()],
            "request_list must accumulate across rounds, not overwrite"
        );
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: true
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
            interface_mtu: 0,
            options: DBD_OPTIONS,
            init: false,
            more: false,
            master: false,
            dd_sequence_number: 6, // wrong sequence number
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
    fn exchange_mismatch_as_slave_triggers_seq_number_mismatch() {
        // The slave expects the master's next poll to be exactly one past
        // the last sequence number it accepted -- a repeated or skipped
        // value is a mismatch, not just an equal one (equal was the
        // pre-pagination check; every subsequent round now legitimately
        // increments).
        let mut adj = AdjacencyData {
            is_master: false,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.5"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
            init: false,
            more: false,
            master: true,
            dd_sequence_number: 5, // stale, not 6
            lsa_headers: Vec::new(),
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.5"),
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
        // The slave's own retransmitted original negotiation packet,
        // arriving after we've already moved past ExStart — a real, common
        // race (the two sides' retransmit timers run independently), not a
        // restart signal.
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

    #[test]
    fn exchange_ignores_negotiation_shaped_duplicate_as_slave() {
        let mut adj = AdjacencyData {
            is_master: false,
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
        let actions = on_lsr_received(&mut adj, &lsdb, &Lsdb::new(), &lsr);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::SendLsu(lsas) if lsas.len() == 1));
        assert!(adj.retransmission_list.contains_key(&l.header.key()));
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
        let actions = on_lsr_received(&mut adj, &lsdb, &Lsdb::new(), &lsr);
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
        let (actions, newly_installed) =
            on_lsu_received(&mut adj, &mut lsdb, &mut Lsdb::new(), &lsu, Instant::now());
        assert_eq!(adj.request_list, []);
        assert!(lsdb.get(&l.header.key()).is_some());
        assert_eq!(actions, vec![Action::NeighborEvent(Event::LoadingDone)]);
        assert_eq!(adj.pending_acks, vec![l.header]);
        assert_eq!(newly_installed, vec![l.header]);
        // RFC 2328 §13.5: the ack goes out on the next sweep, as one packet.
        assert_eq!(
            take_pending_acks(&mut adj),
            Some(Action::SendLsAck(vec![l.header]))
        );
        assert_eq!(adj.pending_acks, []);
        assert_eq!(take_pending_acks(&mut adj), None);
    }

    #[test]
    fn lsu_with_stale_duplicate_is_acked_but_not_reported_as_newly_installed() {
        let mut adj = AdjacencyData::default();
        let mut lsdb = Lsdb::new();
        let l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        lsdb.install(l.clone());
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l.clone()],
        };
        let (actions, newly_installed) =
            on_lsu_received(&mut adj, &mut lsdb, &mut Lsdb::new(), &lsu, Instant::now());
        assert_eq!(actions, vec![Action::NeighborEvent(Event::LoadingDone)]);
        assert_eq!(adj.pending_acks, vec![l.header]);
        assert_eq!(newly_installed, []);
    }

    #[test]
    fn lsu_without_emptying_request_list_does_not_fire_loading_done() {
        let mut adj = AdjacencyData {
            request_list: vec![header("1.1.1.1", 1).key(), header("2.2.2.2", 1).key()],
            ..Default::default()
        };
        let mut lsdb = Lsdb::new();
        let l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l.clone()],
        };
        let (actions, newly_installed) =
            on_lsu_received(&mut adj, &mut lsdb, &mut Lsdb::new(), &lsu, Instant::now());
        assert_eq!(adj.request_list, vec![header("2.2.2.2", 1).key()]);
        assert_eq!(actions, []);
        assert_eq!(adj.pending_acks, vec![l.header]);
        assert_eq!(newly_installed, vec![l.header]);
    }

    /// RFC 2328 §13 step 4: a `MaxAge` LSA with no held instance is acked but
    /// not installed — unless this adjacency asked for it.
    #[test]
    fn lsu_with_unheld_max_age_lsa_is_acked_but_discarded() {
        let mut adj = AdjacencyData::default();
        let mut lsdb = Lsdb::new();
        let mut l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        l.header.age = lsa::MAX_AGE;
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l.clone()],
        };
        let (actions, newly_installed) =
            on_lsu_received(&mut adj, &mut lsdb, &mut Lsdb::new(), &lsu, Instant::now());
        assert!(lsdb.get(&l.header.key()).is_none());
        assert_eq!(newly_installed, []);
        assert!(!actions.iter().any(|a| matches!(a, Action::SendLsAck(_))));
        assert_eq!(adj.pending_acks, vec![l.header]);

        let mut adj = AdjacencyData {
            request_list: vec![l.header.key()],
            ..Default::default()
        };
        let (_, newly_installed) =
            on_lsu_received(&mut adj, &mut lsdb, &mut Lsdb::new(), &lsu, Instant::now());
        assert_eq!(newly_installed, vec![l.header]);
        assert_eq!(adj.request_list, []);
    }

    /// A flushed copy (same sequence/checksum, age `MaxAge`) of a held LSA
    /// supersedes it — `is_newer`'s `MaxAge` tie-break.
    #[test]
    fn lsu_with_max_age_copy_of_held_lsa_supersedes_it() {
        let mut adj = AdjacencyData::default();
        let mut lsdb = Lsdb::new();
        let l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        lsdb.install(l.clone());
        let mut flushed = l.clone();
        flushed.header.age = lsa::MAX_AGE;
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![flushed.clone()],
        };
        let (_, newly_installed) =
            on_lsu_received(&mut adj, &mut lsdb, &mut Lsdb::new(), &lsu, Instant::now());
        assert_eq!(newly_installed, vec![flushed.header]);
        assert_eq!(lsdb.get(&l.header.key()).unwrap().header.age, lsa::MAX_AGE);
    }

    /// RFC 2328 §13.5: acks for LSAs from several LSUs accumulate into one
    /// `LSAck` at the next sweep.
    #[test]
    fn lsu_acks_accumulate_across_lsus_until_taken() {
        let mut adj = AdjacencyData::default();
        let mut lsdb = Lsdb::new();
        let first = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let second = full_lsa("2.2.2.2", 0x8000_0001u32.cast_signed());
        for l in [&first, &second] {
            let lsu = LsuPacket {
                router_id: router_id("9.9.9.10"),
                area_id: Ipv4Addr::UNSPECIFIED,
                lsas: vec![l.clone()],
            };
            on_lsu_received(&mut adj, &mut lsdb, &mut Lsdb::new(), &lsu, Instant::now());
        }
        assert_eq!(
            take_pending_acks(&mut adj),
            Some(Action::SendLsAck(vec![first.header, second.header]))
        );
    }

    /// RFC 2328 §13 step 5a: a newer instance within `MinLSArrival` of the
    /// last received one is discarded — not installed, not acked, and not
    /// counted as answering a request.
    #[test]
    fn lsu_with_newer_instance_too_soon_is_discarded_without_ack() {
        let first = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let second = full_lsa("1.1.1.1", 0x8000_0002u32.cast_signed());
        let mut adj = AdjacencyData {
            request_list: vec![second.header.key()],
            ..Default::default()
        };
        let mut lsdb = Lsdb::new();
        let t0 = Instant::now();
        lsdb.install_received(first.clone(), t0);
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![second.clone()],
        };
        let (actions, newly_installed) = on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut Lsdb::new(),
            &lsu,
            t0 + crate::lsdb::MIN_LS_ARRIVAL / 2,
        );
        assert_eq!(newly_installed, []);
        assert_eq!(adj.pending_acks, []);
        assert_eq!(actions, []);
        assert_eq!(adj.request_list, vec![second.header.key()]);
        assert_eq!(
            lsdb.get(&first.header.key())
                .unwrap()
                .header
                .sequence_number,
            first.header.sequence_number
        );

        let (actions, newly_installed) = on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut Lsdb::new(),
            &lsu,
            t0 + crate::lsdb::MIN_LS_ARRIVAL,
        );
        assert_eq!(newly_installed, vec![second.header]);
        assert_eq!(adj.pending_acks, vec![second.header]);
        assert_eq!(actions, vec![Action::NeighborEvent(Event::LoadingDone)]);
    }

    fn opaque(lsa_type: u8) -> Lsa {
        Lsa {
            header: LsaHeader {
                lsa_type,
                link_state_id: router_id("4.0.0.1"),
                ..header("9.9.9.10", 1)
            },
            body: lsa::LsaBody::Opaque(vec![1, 2, 3, 4]),
        }
    }

    /// RFC 5250: a type-9 LSA lands in the link store, a type-10 in the area
    /// store, and an LSR for either is answered.
    #[test]
    fn opaque_lsas_are_stored_by_scope_and_requestable() {
        let mut adj = AdjacencyData::default();
        let (mut area, mut link) = (Lsdb::new(), Lsdb::new());
        let (l9, l10) = (
            opaque(lsa::LSA_TYPE_OPAQUE_LINK),
            opaque(lsa::LSA_TYPE_OPAQUE_AREA),
        );
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l9.clone(), l10.clone()],
        };
        on_lsu_received(&mut adj, &mut area, &mut link, &lsu, Instant::now());
        assert!(link.get(&l9.header.key()).is_some());
        assert!(area.get(&l9.header.key()).is_none());
        assert!(area.get(&l10.header.key()).is_some());
        assert!(link.get(&l10.header.key()).is_none());

        let lsr = LsrPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![l9.header.key(), l10.header.key()],
        };
        let actions = on_lsr_received(&mut adj, &area, &link, &lsr);
        assert!(matches!(&actions[..], [Action::SendLsu(lsas)] if lsas.len() == 2));
    }

    /// RFC 5250 §3: opaque headers are summarized only to a neighbor whose
    /// DBD set the O-bit.
    #[test]
    fn opaque_headers_are_summarized_only_to_an_opaque_capable_neighbor() {
        let local = [
            header("1.1.1.1", 1),
            opaque(lsa::LSA_TYPE_OPAQUE_AREA).header,
            opaque(lsa::LSA_TYPE_OPAQUE_AS).header,
        ];
        for (options, expected) in [(DBD_OPTIONS, 3), (OPTION_E, 1)] {
            let mut adj = AdjacencyData::default();
            let dbd = DbdPacket {
                options,
                ..negotiation_dbd(router_id("9.9.9.10"), 1)
            };
            seed_summary(&mut adj, &dbd, &local);
            assert_eq!(adj.opaque_capable, options & OPTION_O != 0);
            assert_eq!(adj.summary_remaining.len(), expected);
        }
    }

    /// RFC 2328 §3.6: on a stub area's link, AS-scope LSAs are never
    /// summarized, a DBD listing one restarts the exchange, an LSU carrying
    /// one is dropped unacked, and our DBDs go without the E-bit.
    #[test]
    fn stub_link_keeps_as_scope_lsas_out() {
        let as_scope = opaque(lsa::LSA_TYPE_OPAQUE_AS);
        let local = [header("1.1.1.1", 1), as_scope.header];
        let mut adj = AdjacencyData {
            stub: true,
            ..Default::default()
        };
        seed_summary(&mut adj, &negotiation_dbd(router_id("9.9.9.10"), 1), &local);
        assert_eq!(adj.summary_remaining.len(), 1);
        assert_eq!(dbd_options(true) & OPTION_E, 0);
        assert_eq!(dbd_options(false), DBD_OPTIONS);

        let listing = DbdPacket {
            lsa_headers: vec![as_scope.header],
            ..negotiation_dbd(router_id("9.9.9.10"), 1)
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &listing,
            &[],
            100,
            1500,
        );
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
        );

        let (mut area, mut link) = (Lsdb::default(), Lsdb::default());
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![as_scope.clone()],
        };
        on_lsu_received(&mut adj, &mut area, &mut link, &lsu, Instant::now());
        assert!(area.get(&as_scope.header.key()).is_none());
        assert_eq!(adj.pending_acks, vec![]);
    }

    /// RFC 3101 §2.4: a Type-7 is accepted only on an NSSA's link, and a
    /// Type-5 never there.
    #[test]
    fn type7_only_in_an_nssa_and_type5_never_there() {
        let external = |lsa_type| {
            let mut l = Lsa {
                header: LsaHeader {
                    lsa_type,
                    link_state_id: router_id("192.0.2.0"),
                    ..header("9.9.9.10", 0x8000_0001u32.cast_signed())
                },
                body: lsa::LsaBody::AsExternal(lsa::AsExternalLsaBody {
                    network_mask: router_id("255.255.255.0"),
                    metric: 0,
                    e_type2: false,
                    forwarding_address: Ipv4Addr::UNSPECIFIED,
                    external_route_tag: 0,
                }),
            };
            lsa::fill_checksum(&mut l);
            l
        };
        let (type5, type7) = (
            external(lsa::LSA_TYPE_AS_EXTERNAL),
            external(lsa::LSA_TYPE_NSSA_EXTERNAL),
        );
        for (stub, nssa, installed) in [(false, false, [true, false]), (true, true, [false, true])]
        {
            let mut adj = AdjacencyData {
                stub,
                nssa,
                ..Default::default()
            };
            let (mut area, mut link) = (Lsdb::default(), Lsdb::default());
            let lsu = LsuPacket {
                router_id: router_id("9.9.9.10"),
                area_id: Ipv4Addr::UNSPECIFIED,
                lsas: vec![type5.clone(), type7.clone()],
            };
            on_lsu_received(&mut adj, &mut area, &mut link, &lsu, Instant::now());
            for (l, want) in [&type5, &type7].into_iter().zip(installed) {
                assert_eq!(area.get(&l.header.key()).is_some(), want, "nssa={nssa}");
            }
            assert_eq!(adj.pending_acks.len(), 1);
        }
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
