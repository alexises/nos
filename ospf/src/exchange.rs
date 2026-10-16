//! `OSPFv2`'s side of the RFC 2328 §10.6-10.8 exchange. The DBD
//! negotiation, summary pagination, delayed-ack queue and `LSAck` handling
//! are `nos_ospf_common::exchange`'s, shared with `nos-ospfv3`; this module
//! supplies the v2 closures (stub/NSSA scope, opaque LSAs, the DBD Options)
//! and keeps the LSR/LSU handlers, whose store layout is v2's (one area
//! store plus the link's type-9 store).

use std::time::Instant;

use nos_ospf_common::exchange as common;
pub use nos_ospf_common::exchange::{
    mtu_acceptable, on_lsack_received, take_pending_acks, Params, DEFAULT_DBD_MAX_HEADERS,
};

use crate::lsa::{self, Lsa, LsaHeader};
use crate::lsdb::Lsdb;
use crate::neighbor::{Event, NeighborState};
use crate::packet::{DbdPacket, LsrPacket, LsuPacket, OPTION_E, OPTION_O};

pub type AdjacencyData = common::AdjacencyData<Lsa>;
pub type Action = common::Action<Lsa>;

/// Options this router sends in every DBD of a normal area: RFC 2328's
/// E-bit (as in its Hellos) and RFC 5250's O-bit.
pub const DBD_OPTIONS: u32 = (OPTION_E | OPTION_O) as u32;

/// The DBD options for a link: `DBD_OPTIONS`, without the E-bit in a stub
/// area (RFC 2328 §3.6).
pub fn dbd_options(stub: bool) -> u32 {
    if stub {
        u32::from(OPTION_O)
    } else {
        DBD_OPTIONS
    }
}

/// RFC 5250 §3: the neighbor's DBD set the O-bit, so it may be sent opaque
/// LSAs (`Params::peer_opaque_capable`).
pub fn peer_opaque_capable(dbd: &DbdPacket) -> bool {
    dbd.options & u32::from(OPTION_O) != 0
}

/// LSA headers per DBD on a link of this MTU: IPv4 (20) + OSPF header (24)
/// + DBD body (8) of overhead (`nos_ospf_common::exchange`).
pub fn mtu_based_max_headers(mtu: u16) -> usize {
    common::mtu_based_max_headers(mtu, 20 + 24 + 8)
}

/// `nos_ospf_common::exchange::on_dbd_received` with v2's scope rule
/// (`lsa::in_area_scope`: Type-5/11 out of stub/NSSA, Type-7 only in an
/// NSSA) and RFC 5250 opaque filtering.
pub fn on_dbd_received(
    adj: &mut AdjacencyData,
    state: NeighborState,
    p: &Params,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
) -> Vec<Action> {
    let (stub, nssa) = (adj.stub, adj.nssa);
    common::on_dbd_received(
        adj,
        state,
        p,
        dbd,
        local_lsdb_headers,
        |h| lsa::in_area_scope(h.lsa_type, stub, nssa),
        |h| lsa::is_opaque(h.lsa_type),
    )
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use super::*;
    use crate::packet::LsAckPacket;

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

    /// Runs `dbd` from 9.9.9.10 (the higher id, so we are slave) in `state`.
    fn dbd_in(
        adj: &mut AdjacencyData,
        state: NeighborState,
        dbd: &DbdPacket,
        local: &[LsaHeader],
    ) -> Vec<Action> {
        let p = Params {
            local_router_id: router_id("9.9.9.9"),
            max_headers: 100,
            mtu: 1500,
            dbd_options: dbd_options(adj.stub),
            peer_opaque_capable: peer_opaque_capable(dbd),
        };
        on_dbd_received(adj, state, &p, dbd, local)
    }

    #[test]
    fn mtu_budget_uses_the_ipv4_overhead() {
        assert_eq!(mtu_based_max_headers(1500), 72);
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
        for (options, expected) in [(DBD_OPTIONS, 3), (u32::from(OPTION_E), 1)] {
            let mut adj = AdjacencyData::default();
            let dbd = DbdPacket {
                options,
                ..negotiation_dbd(router_id("9.9.9.10"), 1)
            };
            let actions = dbd_in(&mut adj, NeighborState::ExStart, &dbd, &local);
            assert_eq!(adj.opaque_capable, options & u32::from(OPTION_O) != 0);
            assert!(
                matches!(&actions[0], Action::SendDbd(reply) if reply.lsa_headers.len() == expected),
                "{actions:?}"
            );
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
        let negotiation = negotiation_dbd(router_id("9.9.9.10"), 1);
        let actions = dbd_in(&mut adj, NeighborState::ExStart, &negotiation, &local);
        assert!(
            matches!(&actions[0], Action::SendDbd(reply)
                if reply.lsa_headers == [local[0]] && reply.options & u32::from(OPTION_E) == 0),
            "{actions:?}"
        );
        assert_eq!(dbd_options(false), DBD_OPTIONS);

        let listing = DbdPacket {
            lsa_headers: vec![as_scope.header],
            ..negotiation_dbd(router_id("9.9.9.10"), 1)
        };
        let actions = dbd_in(&mut adj, NeighborState::Exchange, &listing, &[]);
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
        on_lsack_received(&mut adj, &ack.lsa_headers);
        assert!(adj.retransmission_list.is_empty());
    }
}
