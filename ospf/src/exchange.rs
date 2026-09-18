//! RFC 2328 §10.6-10.8's Database Description negotiation and summary-list
//! exchange — the heavier per-neighbor logic `neighbor.rs` deliberately
//! stays too thin to hold. Pure with respect to I/O (no sockets, no
//! timers), but — unlike `neighbor::step` — mutates the `AdjacencyData` it's
//! given directly, since that data (request/retransmission lists) is built
//! up incrementally across many packets rather than swapped wholesale like
//! `bgp::fsm`'s `RemoteInfo`.
//!
//! # ponytail: one-shot summary exchange, no DBD pagination
//! RFC 2328 lets the master paginate its summary list across many DBD
//! polls (`more` bit), each acked by the slave before the next is sent.
//! This crate always sends its *entire* local LSDB summary in a single DBD
//! (`more: false`) in each direction — correct only because this NOS's
//! LSDB is lab-scale (a handful of Router/Network-LSAs), always well under
//! one packet's `RECV_BUF_LEN`. Upgrade to real pagination if a summary
//! list ever risks exceeding one packet.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};
use crate::lsdb::Lsdb;
use crate::neighbor::{Event, NeighborState};
use crate::packet::{DbdPacket, LsAckPacket, LsrPacket, LsuPacket};

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
    /// until superseded by the next stage of the exchange. Necessary
    /// because the two sides' Hello-driven `TwoWay`/`ExStart` transitions
    /// aren't synchronized: whichever side reaches `ExStart` first sends a
    /// negotiation packet the other side isn't ready to receive yet (its
    /// own adjacency data doesn't exist until it too reaches `ExStart`),
    /// so without a resend, that first packet is silently dropped forever.
    pub last_dbd_sent: Option<DbdPacket>,
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
pub fn on_dbd_received(
    adj: &mut AdjacencyData,
    state: NeighborState,
    local_router_id: Ipv4Addr,
    neighbor_router_id: Ipv4Addr,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
) -> Vec<Action> {
    match state {
        NeighborState::ExStart => on_dbd_in_exstart(
            adj,
            local_router_id,
            neighbor_router_id,
            dbd,
            local_lsdb_headers,
        ),
        NeighborState::Exchange => on_dbd_in_exchange(adj, dbd, local_lsdb_headers),
        // `Loading`/`Full`: ignore everything here, negotiation-shaped or
        // not. A genuine peer restart is instead caught via Hello — losing
        // 2-way already clears `adjacency` (see `link::handle_hello`) — so
        // a DBD-level restart signal isn't needed, and treating a stray
        // negotiation-shaped retransmission (the peer's own view hasn't
        // caught up to ours yet) as an error would just force an
        // unnecessary, self-inflicted restart of our own.
        // `Down`/`Init`/`TwoWay`: no adjacency exists yet to receive a DBD
        // for in the first place.
        NeighborState::Loading
        | NeighborState::Full
        | NeighborState::Down
        | NeighborState::Init
        | NeighborState::TwoWay => Vec::new(),
    }
}

fn on_dbd_in_exstart(
    adj: &mut AdjacencyData,
    local_router_id: Ipv4Addr,
    neighbor_router_id: Ipv4Addr,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
) -> Vec<Action> {
    let is_negotiation_attempt = dbd.init && dbd.more && dbd.master;

    match neighbor_router_id.cmp(&local_router_id) {
        Ordering::Greater => {
            // Neighbor has the higher router-id: it is master, we are
            // slave. Accept either its genuine negotiation attempt
            // (I=1,M=1,MS=1) or its one poll reply (I=0,M=0,MS=1) as the
            // trigger — symmetric to the `Ordering::Less` branch's own
            // "accept either" reasoning below, and for the same underlying
            // cause: the two sides' Hello-driven ExStart entry isn't
            // synchronized, so if the master reaches ExStart (and sends its
            // attempt) before *we* reach 2-Way with it, `handle_dbd` has no
            // adjacency yet to receive that attempt into and silently drops
            // it (see its own doc comment) — including every retransmitted
            // copy, since the master, having since moved on, only ever
            // resends its most recent packet. By the time we create our own
            // adjacency and send our own (late) attempt, the only packet we
            // ever get back is the master's reply to *that* — never its
            // original attempt, which is gone for good. Without this,
            // we'd wait here forever for a message that will never come
            // again (a real bug this NOS's `ospf-dr` Docker scenario found:
            // a third router joining a segment with an already-converged
            // DR/BDR pair got stuck exactly this way).
            let is_master_reply = !dbd.init && !dbd.more && dbd.master;
            if !is_negotiation_attempt && !is_master_reply {
                return Vec::new();
            }
            adj.is_master = false;
            adj.dd_sequence_number = dbd.dd_sequence_number;
            let reply = DbdPacket {
                router_id: local_router_id,
                area_id: dbd.area_id,
                interface_mtu: 0,
                options: 0,
                init: false,
                more: false,
                master: false,
                dd_sequence_number: dbd.dd_sequence_number,
                lsa_headers: local_lsdb_headers.to_vec(),
            };
            if is_negotiation_attempt {
                // Normal case: this is the master's own fresh attempt,
                // carrying no summary of its own yet. Reply with ours and
                // wait separately for any further exchange.
                vec![
                    Action::SendDbd(reply),
                    Action::NeighborEvent(Event::NegotiationDone),
                ]
            } else {
                // This packet *is* the master's reply/poll — its actual
                // completing summary too, since (per this branch's own
                // doc comment) we never got to see its separate initial
                // attempt. Process its content immediately rather than
                // waiting forever for a second message the master will
                // never send again.
                adj.request_list = compute_request_list(&dbd.lsa_headers, local_lsdb_headers);
                vec![
                    Action::SendDbd(reply),
                    Action::NeighborEvent(Event::NegotiationDone),
                    Action::NeighborEvent(Event::ExchangeDone {
                        more_to_load: !adj.request_list.is_empty(),
                    }),
                ]
            }
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
            let poll = DbdPacket {
                router_id: local_router_id,
                area_id: dbd.area_id,
                interface_mtu: 0,
                options: 0,
                init: false,
                more: false,
                master: true,
                dd_sequence_number: adj.dd_sequence_number,
                lsa_headers: local_lsdb_headers.to_vec(),
            };
            if is_negotiation_attempt {
                // Normal case: this is the neighbor's own fresh attempt,
                // carrying no summary of its own yet. Respond with our
                // poll and wait separately for its reply.
                vec![
                    Action::SendDbd(poll),
                    Action::NeighborEvent(Event::NegotiationDone),
                ]
            } else {
                // This packet *is* the neighbor's reply — proof of role
                // and the actual completing summary at once, since (per
                // this branch's own doc comment) we never got to see its
                // separate initial attempt. Nothing else is coming
                // separately, so process its content immediately too,
                // rather than waiting forever for a second message the
                // neighbor (already past its own ExStart) will never send.
                adj.request_list = compute_request_list(&dbd.lsa_headers, local_lsdb_headers);
                vec![
                    Action::SendDbd(poll),
                    Action::NeighborEvent(Event::NegotiationDone),
                    Action::NeighborEvent(Event::ExchangeDone {
                        more_to_load: !adj.request_list.is_empty(),
                    }),
                ]
            }
        }
        // Equal router-ids can't happen on a real network (every router-id
        // is required to be unique) — nothing sensible to negotiate.
        Ordering::Equal => Vec::new(),
    }
}

fn on_dbd_in_exchange(
    adj: &mut AdjacencyData,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
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

    let valid = if adj.is_master {
        // Expect the slave's one reply to our poll: same sequence number,
        // MS bit clear.
        dbd.dd_sequence_number == adj.dd_sequence_number && !dbd.master
    } else {
        // Expect the master's one real poll: MS bit set, matching the
        // sequence number negotiated in ExStart.
        dbd.master && dbd.dd_sequence_number == adj.dd_sequence_number
    };
    if !valid {
        return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
    }

    adj.request_list = compute_request_list(&dbd.lsa_headers, local_lsdb_headers);
    vec![Action::NeighborEvent(Event::ExchangeDone {
        more_to_load: !adj.request_list.is_empty(),
    })]
}

/// Handles one received LSR: looks up every requested LSA in `lsdb`. If any
/// requested LSA isn't held, that's RFC 2328 §10.7's `BadLSReq` — the two
/// databases have diverged, so negotiation restarts from scratch rather
/// than sending a partial/wrong answer. Otherwise, sends everything found
/// as one LSU and records it as outstanding until acked (see
/// `on_lsack_received`).
pub fn on_lsr_received(adj: &mut AdjacencyData, lsdb: &Lsdb, lsr: &LsrPacket) -> Vec<Action> {
    let mut found = Vec::with_capacity(lsr.requests.len());
    for key in &lsr.requests {
        match lsdb.get(key) {
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

/// Handles one received LSU: installs every carried LSA into `lsdb` (RFC
/// 2328 §13's "is this instance newer" check, via `Lsdb::install`), clears
/// any now-satisfied entries from the request list, and acks every LSA
/// regardless of whether it was actually newer — an ack for a stale
/// instance still stops the sender retransmitting it forever. Fires
/// `LoadingDone` once the request list is fully drained. Returns the
/// actions to carry out alongside the headers that were *actually*
/// installed/superseded (excluding rejected duplicates) — `link.rs` uses
/// the latter to avoid logging a fresh "installed" line for a duplicate its
/// own periodic resend produces.
pub fn on_lsu_received(
    adj: &mut AdjacencyData,
    lsdb: &mut Lsdb,
    lsu: &LsuPacket,
) -> (Vec<Action>, Vec<LsaHeader>) {
    let mut acked = Vec::with_capacity(lsu.lsas.len());
    let mut newly_installed = Vec::new();
    for l in &lsu.lsas {
        if !matches!(
            lsdb.install(l.clone()),
            crate::lsdb::InstallOutcome::Rejected
        ) {
            newly_installed.push(l.header);
        }
        acked.push(l.header);
        adj.request_list.retain(|k| *k != l.header.key());
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
    use super::*;

    fn router_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn negotiation_dbd(router_id: Ipv4Addr, seq: u32) -> DbdPacket {
        DbdPacket {
            router_id,
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: 0,
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
        let master_lsa = header("1.1.1.1", 0x8000_0001u32 as i32);
        let poll = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: 0,
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
                    interface_mtu: 0,
                    options: 0,
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
        );
        assert!(adj.is_master);
        assert_eq!(adj.dd_sequence_number, 7);
        assert!(matches!(
            actions.as_slice(),
            [Action::SendDbd(poll), Action::NeighborEvent(Event::NegotiationDone)]
                if poll.master && poll.dd_sequence_number == 7
        ));
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
        let neighbor_lsa = header("1.1.1.1", 0x8000_0001u32 as i32);
        let reply = DbdPacket {
            router_id: router_id("9.9.9.5"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: 0,
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
        );
        assert!(adj.is_master);
        assert_eq!(adj.dd_sequence_number, 7, "must keep our own chosen seed");
        assert_eq!(adj.request_list, vec![neighbor_lsa.key()]);
        assert_eq!(
            actions,
            vec![
                Action::SendDbd(DbdPacket {
                    router_id: router_id("9.9.9.9"),
                    area_id: Ipv4Addr::UNSPECIFIED,
                    interface_mtu: 0,
                    options: 0,
                    init: false,
                    more: false,
                    master: true,
                    dd_sequence_number: 7,
                    lsa_headers: Vec::new(),
                }),
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
            options: 0,
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
        );
        assert!(actions.is_empty());
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
        );
        assert!(actions.is_empty());
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
            options: 0,
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
        );
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: false
            })]
        );
        assert!(adj.request_list.is_empty());
    }

    #[test]
    fn exchange_as_slave_with_master_poll_reaches_exchange_done() {
        let mut adj = AdjacencyData {
            is_master: false,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.5"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: 0,
            init: false,
            more: false,
            master: true,
            dd_sequence_number: 5,
            lsa_headers: Vec::new(),
        };
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Exchange,
            router_id("9.9.9.9"),
            router_id("9.9.9.5"),
            &dbd,
            &[],
        );
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: false
            })]
        );
    }

    #[test]
    fn exchange_requests_lsas_missing_locally() {
        let mut adj = AdjacencyData {
            is_master: true,
            dd_sequence_number: 5,
            ..Default::default()
        };
        let neighbor_header = header("1.1.1.1", 0x8000_0001u32 as i32);
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: 0,
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
        let local = header("1.1.1.1", 0x8000_0002u32 as i32);
        let neighbor_header = header("1.1.1.1", 0x8000_0001u32 as i32);
        let dbd = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: 0,
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
        );
        assert!(adj.request_list.is_empty());
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
            interface_mtu: 0,
            options: 0,
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
        );
        assert!(actions.is_empty());
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
        );
        assert!(actions.is_empty());
        assert_eq!(adj.dd_sequence_number, 5, "must not adopt the stray seq");
    }

    #[test]
    fn negotiation_shaped_dbd_while_full_is_ignored() {
        // A stray/duplicate negotiation-shaped DBD while already Full is
        // ignored, not treated as a restart signal — a genuine restart is
        // instead caught via Hello (see `link::handle_hello`), so this
        // never forces a self-inflicted reset from a stale retransmission.
        let mut adj = AdjacencyData::default();
        let dbd = negotiation_dbd(router_id("9.9.9.10"), 1);
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Full,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &dbd,
            &[],
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn stray_non_init_dbd_while_full_is_ignored() {
        let mut adj = AdjacencyData::default();
        let mut dbd = negotiation_dbd(router_id("9.9.9.10"), 1);
        dbd.init = false;
        let actions = on_dbd_received(
            &mut adj,
            NeighborState::Full,
            router_id("9.9.9.9"),
            router_id("9.9.9.10"),
            &dbd,
            &[],
        );
        assert!(actions.is_empty());
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
        let l = full_lsa("1.1.1.1", 0x8000_0001u32 as i32);
        lsdb.install(l.clone());
        let lsr = LsrPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![l.header.key()],
        };
        let actions = on_lsr_received(&mut adj, &lsdb, &lsr);
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
        let actions = on_lsr_received(&mut adj, &lsdb, &lsr);
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
        let l = full_lsa("1.1.1.1", 0x8000_0001u32 as i32);
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l.clone()],
        };
        let (actions, newly_installed) = on_lsu_received(&mut adj, &mut lsdb, &lsu);
        assert!(adj.request_list.is_empty());
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

    #[test]
    fn lsu_with_stale_duplicate_is_acked_but_not_reported_as_newly_installed() {
        let mut adj = AdjacencyData::default();
        let mut lsdb = Lsdb::new();
        let l = full_lsa("1.1.1.1", 0x8000_0001u32 as i32);
        lsdb.install(l.clone());
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l.clone()],
        };
        let (actions, newly_installed) = on_lsu_received(&mut adj, &mut lsdb, &lsu);
        assert_eq!(
            actions,
            vec![
                Action::SendLsAck(vec![l.header]),
                Action::NeighborEvent(Event::LoadingDone),
            ]
        );
        assert!(newly_installed.is_empty());
    }

    #[test]
    fn lsu_without_emptying_request_list_does_not_fire_loading_done() {
        let mut adj = AdjacencyData {
            request_list: vec![header("1.1.1.1", 1).key(), header("2.2.2.2", 1).key()],
            ..Default::default()
        };
        let mut lsdb = Lsdb::new();
        let l = full_lsa("1.1.1.1", 0x8000_0001u32 as i32);
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l.clone()],
        };
        let (actions, newly_installed) = on_lsu_received(&mut adj, &mut lsdb, &lsu);
        assert_eq!(adj.request_list, vec![header("2.2.2.2", 1).key()]);
        assert_eq!(actions, vec![Action::SendLsAck(vec![l.header])]);
        assert_eq!(newly_installed, vec![l.header]);
    }

    #[test]
    fn lsack_clears_retransmission_list() {
        let l = full_lsa("1.1.1.1", 0x8000_0001u32 as i32);
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
