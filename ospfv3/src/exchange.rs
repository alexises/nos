//! `OSPFv3`'s side of the RFC 2328 §10.6-10.8 exchange (RFC 5340 keeps it
//! unchanged). The DBD negotiation, summary pagination, delayed-ack queue
//! and `LSAck` handling are `nos_ospf_common::exchange`'s, shared with
//! `nos-ospfd`; this module keeps the LSR/LSU handlers, whose store layout is
//! v3's (area, link-local and AS-scope stores, RFC 5340 §4.5.1).

use std::time::Instant;

use nos_ospf_common::exchange as common;
pub use nos_ospf_common::exchange::{
    mtu_acceptable, on_lsack_received, take_pending_acks, Params, DEFAULT_DBD_MAX_HEADERS,
};

use crate::lsa::{self, Lsa, LsaHeader};
use crate::lsdb::Lsdb;
use crate::neighbor::{Event, NeighborState};
use crate::packet::{DbdPacket, LsrPacket, LsuPacket};

pub type AdjacencyData = common::AdjacencyData<Lsa>;
pub type Action = common::Action<Lsa>;

/// LSA headers per DBD on a link of this MTU: IPv6 (40) + `OSPFv3` header
/// (16) + DBD body (12) of overhead (`nos_ospf_common::exchange`).
pub fn mtu_based_max_headers(mtu: u16) -> usize {
    common::mtu_based_max_headers(mtu, 40 + 16 + 12)
}

/// `nos_ospf_common::exchange::on_dbd_received` for v3: no stub/NSSA scope
/// (RFC 5340 §3.4 deprecated it) and no opaque LSAs. `p.dbd_options` is
/// `link::link_options`, so every DBD carries the link's Options (RFC 5340
/// A.3.3), the AT-bit included.
pub fn on_dbd_received(
    adj: &mut AdjacencyData,
    state: NeighborState,
    p: &Params,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
) -> Vec<Action> {
    common::on_dbd_received(adj, state, p, dbd, local_lsdb_headers, |_| true, |_| false)
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
/// request list, and queues an ack for every LSA in `adj.pending_acks`
/// (delayed, RFC 2328 §13.5; `ponytail:` every ack is delayed, as in
/// `ospf::exchange`). Fires `LoadingDone` once the request
/// list is fully drained. Returns the actions to carry out alongside the
/// headers that were *actually* installed/superseded (excluding rejected
/// duplicates).
pub fn on_lsu_received(
    adj: &mut AdjacencyData,
    area_lsdb: &mut Lsdb,
    link_local_lsdb: &mut Lsdb,
    as_lsdb: &mut Lsdb,
    lsu: &LsuPacket,
    now: Instant,
) -> (Vec<Action>, Vec<LsaHeader>) {
    let acked = &mut adj.pending_acks;
    let mut newly_installed = Vec::new();
    for l in &lsu.lsas {
        // RFC 5340 §4.5 step (3): S2/S1 "reserved" is discarded, not acked.
        if lsa::is_reserved_scope(l.header.lsa_type) {
            continue;
        }
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
        match store.install_received(l.clone(), now) {
            // RFC 2328 §13 step 5a (`MinLSArrival`): discarded, and neither
            // acknowledged nor treated as answering a request — the
            // sender's retransmission brings it back.
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

    #[test]
    fn mtu_derived_budget() {
        assert_eq!(mtu_based_max_headers(1500), 71);
        assert_eq!(mtu_based_max_headers(68), 1);
    }

    #[test]
    fn dbd_replies_carry_the_link_options() {
        let p = Params {
            local_router_id: router_id("9.9.9.9"),
            max_headers: 100,
            mtu: 1500,
            dbd_options: 0x0413,
            peer_opaque_capable: false,
        };
        let poll = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0x13,
            interface_mtu: 1500,
            init: false,
            more: false,
            master: true,
            dd_sequence_number: 7,
            lsa_headers: vec![header("1.1.1.1", 1)],
        };
        let mut adj = AdjacencyData::default();
        let actions = on_dbd_received(&mut adj, NeighborState::ExStart, &p, &poll, &[]);
        assert!(
            matches!(&actions[0], Action::SendDbd(reply) if reply.options == 0x0413),
            "{actions:?}"
        );
    }

    fn router_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
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
            Instant::now(),
        );
        assert_eq!(adj.request_list, []);
        assert!(lsdb.get(&l.header.key()).is_some());
        assert_eq!(actions, vec![Action::NeighborEvent(Event::LoadingDone)]);
        assert_eq!(newly_installed, vec![l.header]);
        // Delayed (RFC 2328 §13.5): queued, sent by the next flush.
        assert_eq!(
            take_pending_acks(&mut adj),
            Some(Action::SendLsAck(vec![l.header]))
        );
        assert_eq!(take_pending_acks(&mut adj), None);
    }

    /// RFC 2328 §13 step 5a: a newer instance within `MIN_LS_ARRIVAL` of the
    /// last received one is dropped unacked and its request stays pending.
    #[test]
    fn lsu_drops_too_soon_instance_unacked() {
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
        let run = |adj: &mut AdjacencyData, lsdb: &mut Lsdb, at: Instant| {
            on_lsu_received(adj, lsdb, &mut Lsdb::new(), &mut Lsdb::new(), &lsu, at)
        };
        let (_, newly_installed) = run(&mut adj, &mut lsdb, t0 + crate::lsdb::MIN_LS_ARRIVAL / 2);
        assert_eq!(newly_installed, []);
        assert_eq!(adj.pending_acks, []);
        assert_eq!(adj.request_list, vec![second.header.key()]);
        assert_eq!(
            lsdb.get(&first.header.key())
                .unwrap()
                .header
                .sequence_number,
            first.header.sequence_number
        );
        let (_, newly_installed) = run(&mut adj, &mut lsdb, t0 + crate::lsdb::MIN_LS_ARRIVAL);
        assert_eq!(newly_installed, vec![second.header]);
        assert_eq!(adj.pending_acks, vec![second.header]);
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
        let (_, newly_installed) = on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut Lsdb::new(),
            &mut Lsdb::new(),
            &lsu,
            Instant::now(),
        );
        assert_eq!(newly_installed, []);
        assert!(lsdb.get(&flushed.header.key()).is_none());
        assert_eq!(adj.pending_acks, vec![flushed.header]);

        lsdb.install(live);
        let (_, newly_installed) = on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut Lsdb::new(),
            &mut Lsdb::new(),
            &lsu,
            Instant::now(),
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
        let (_, newly_installed) = on_lsu_received(
            &mut adj,
            &mut area,
            &mut link_local,
            &mut as_scope,
            &lsu,
            Instant::now(),
        );
        assert_eq!(newly_installed.len(), 3);
        assert!(as_scope.get(&external.header.key()).is_some());
        assert!(area.get(&external.header.key()).is_none());
        assert!(area.get(&router.header.key()).is_some());
        assert!(area.get(&link.header.key()).is_none());
        assert!(link_local.get(&link.header.key()).is_some());
        assert!(link_local.get(&router.header.key()).is_none());
    }

    /// RFC 5340 §2.9/§4.5: unknown types land by effective scope; a reserved
    /// scope is discarded without an ack.
    #[test]
    fn lsu_stores_unknown_types_by_effective_scope() {
        let mut adj = AdjacencyData::default();
        let (mut area, mut link_local, mut as_scope) = (Lsdb::new(), Lsdb::new(), Lsdb::new());
        let mk = |t: u16| {
            let mut l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
            l.header.lsa_type = t;
            l.body = lsa::LsaBody::Opaque(vec![9; 8]);
            l
        };
        let (u_area, u_as, u_link, no_u, reserved) =
            (mk(0xA0FF), mk(0xC0FF), mk(0x80FF), mk(0x20FF), mk(0xE0FF));
        let lsu = LsuPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![
                u_area.clone(),
                u_as.clone(),
                u_link.clone(),
                no_u.clone(),
                reserved.clone(),
            ],
        };
        let (_, installed) = on_lsu_received(
            &mut adj,
            &mut area,
            &mut link_local,
            &mut as_scope,
            &lsu,
            Instant::now(),
        );
        assert_eq!(installed.len(), 4);
        assert!(area.get(&u_area.header.key()).is_some());
        assert!(as_scope.get(&u_as.header.key()).is_some());
        assert!(link_local.get(&u_link.header.key()).is_some());
        assert!(link_local.get(&no_u.header.key()).is_some());
        assert!(area.get(&no_u.header.key()).is_none());
        for s in [&area, &link_local, &as_scope] {
            assert!(s.get(&reserved.header.key()).is_none());
        }
        assert_eq!(adj.pending_acks.len(), 4);
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
