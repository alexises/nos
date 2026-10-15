use super::*;

#[test]
fn ifindex_change_restarts_but_cost_does_not() {
    let current = HashMap::from([("eth0.0".to_string(), link("eth0.0", 10))]);
    let mut cheaper = link("eth0.0", 10);
    cheaper.cost = 9;
    let (stop, spawn) = diff_links(&current, &HashMap::from([("eth0.0".to_string(), cheaper)]));
    assert!(stop.is_empty() && spawn.is_empty());
    let mut recreated = link("eth0.0", 10);
    recreated.ifindex = 7;
    let (stop, spawn) = diff_links(
        &current,
        &HashMap::from([("eth0.0".to_string(), recreated)]),
    );
    assert_eq!((stop.len(), spawn.len()), (1, 1));
}

#[tokio::test(start_paused = true)]
async fn running_config_follows_the_task() {
    let wire = Arc::new(wire::Wire::default());
    let a = router(&wire);
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::PointToPoint);
    assert!(a.running_config(&cfg.attach_point).await.is_none());
    a.reconcile(vec![cfg.clone()], HashMap::new(), id(1)).await;
    assert_eq!(a.running_config(&cfg.attach_point).await, Some(cfg.clone()));
    a.reconcile(vec![], HashMap::new(), id(1)).await;
    assert!(a.running_config(&cfg.attach_point).await.is_none());
}

#[test]
fn no_changes_produces_no_diff() {
    let mut current = HashMap::new();
    current.insert("eth0.0".to_string(), link("eth0.0", 10));
    let desired = current.clone();
    let (to_stop, to_spawn) = diff_links(&current, &desired);
    assert_eq!(to_stop, [] as [String; 0]);
    assert_eq!(to_spawn, []);
}

#[test]
fn new_link_is_spawned() {
    let current = HashMap::new();
    let mut desired = HashMap::new();
    desired.insert("eth0.0".to_string(), link("eth0.0", 10));
    let (to_stop, to_spawn) = diff_links(&current, &desired);
    assert_eq!(to_stop, [] as [String; 0]);
    assert_eq!(to_spawn, vec![link("eth0.0", 10)]);
}

#[test]
fn removed_link_is_stopped() {
    let mut current = HashMap::new();
    current.insert("eth0.0".to_string(), link("eth0.0", 10));
    let desired = HashMap::new();
    let (to_stop, to_spawn) = diff_links(&current, &desired);
    assert_eq!(to_stop, vec!["eth0.0".to_string()]);
    assert_eq!(to_spawn, []);
}

#[test]
fn changed_link_is_stopped_and_respawned() {
    let mut current = HashMap::new();
    current.insert("eth0.0".to_string(), link("eth0.0", 10));
    let mut desired = HashMap::new();
    desired.insert("eth0.0".to_string(), link("eth0.0", 5));
    let (to_stop, to_spawn) = diff_links(&current, &desired);
    assert_eq!(to_stop, vec!["eth0.0".to_string()]);
    assert_eq!(to_spawn, vec![link("eth0.0", 5)]);
}

#[test]
fn network_type_change_is_stopped_and_respawned() {
    let mut current = HashMap::new();
    current.insert("eth0.0".to_string(), link("eth0.0", 10));
    let mut desired = HashMap::new();
    let mut broadcast = link("eth0.0", 10);
    broadcast.network_type = NetworkType::Broadcast;
    desired.insert("eth0.0".to_string(), broadcast.clone());
    let (to_stop, to_spawn) = diff_links(&current, &desired);
    assert_eq!(to_stop, vec!["eth0.0".to_string()]);
    assert_eq!(to_spawn, vec![broadcast]);
}

#[test]
fn new_point_to_point_link_status_is_point_to_point_with_no_neighbors() {
    let status = LinkStatus::new(NetworkType::PointToPoint);
    assert_eq!(status.interface_state, InterfaceState::PointToPoint);
    assert!(status.neighbors.is_empty());
    assert_eq!(status.dr, None);
    assert_eq!(status.bdr, None);
}

#[test]
fn new_broadcast_link_status_is_waiting_with_no_neighbors() {
    let status = LinkStatus::new(NetworkType::Broadcast);
    assert_eq!(status.interface_state, InterfaceState::Waiting);
    assert!(status.neighbors.is_empty());
}

#[test]
fn point_to_point_neighbor_is_always_adjacency_eligible() {
    assert!(should_form_adjacency(
        InterfaceState::PointToPoint,
        Ipv4Addr::new(1, 1, 1, 1),
        None,
        None,
    ));
}

#[test]
fn dr_other_pair_is_not_adjacency_eligible() {
    assert!(!should_form_adjacency(
        InterfaceState::DrOther,
        Ipv4Addr::new(1, 1, 1, 1),
        Some(Ipv4Addr::new(2, 2, 2, 2)),
        Some(Ipv4Addr::new(3, 3, 3, 3)),
    ));
}

#[test]
fn dr_is_eligible_with_every_neighbor() {
    assert!(should_form_adjacency(
        InterfaceState::Dr,
        Ipv4Addr::new(1, 1, 1, 1),
        Some(Ipv4Addr::new(9, 9, 9, 9)),
        None,
    ));
}

#[test]
fn dr_other_is_eligible_with_the_dr() {
    let dr = Ipv4Addr::new(2, 2, 2, 2);
    assert!(should_form_adjacency(
        InterfaceState::DrOther,
        dr,
        Some(dr),
        None,
    ));
}

#[test]
fn dr_other_is_eligible_with_the_bdr() {
    let bdr = Ipv4Addr::new(3, 3, 3, 3);
    assert!(should_form_adjacency(
        InterfaceState::DrOther,
        bdr,
        None,
        Some(bdr),
    ));
}

#[test]
fn to_neighbor_state_maps_every_variant_one_to_one() {
    assert_eq!(
        to_neighbor_state(NeighborState::Down),
        OspfNeighborState::Down
    );
    assert_eq!(
        to_neighbor_state(NeighborState::Init),
        OspfNeighborState::Init
    );
    assert_eq!(
        to_neighbor_state(NeighborState::TwoWay),
        OspfNeighborState::TwoWay
    );
    assert_eq!(
        to_neighbor_state(NeighborState::ExStart),
        OspfNeighborState::ExStart
    );
    assert_eq!(
        to_neighbor_state(NeighborState::Exchange),
        OspfNeighborState::Exchange
    );
    assert_eq!(
        to_neighbor_state(NeighborState::Loading),
        OspfNeighborState::Loading
    );
    assert_eq!(
        to_neighbor_state(NeighborState::Full),
        OspfNeighborState::Full
    );
}

#[test]
fn router_lsa_links_p2p_with_no_neighbor_still_emits_stub_network() {
    // RFC 2328 §12.4.1.1: a numbered p2p interface always advertises
    // its own subnet, independent of neighbor state.
    let cfg = link("eth0.0", 10);
    let status = LinkStatus::new(NetworkType::PointToPoint);
    let links = router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)], false, false);
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].link_type, LINK_TYPE_STUB_NETWORK);
    assert_eq!(links[0].link_id, Ipv4Addr::new(10, 0, 0, 0));
    assert_eq!(links[0].link_data, Ipv4Addr::new(255, 255, 255, 0));
}
