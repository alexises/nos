//! OSPFv2 / OSPFv3 phases: real Hello/DBD/LSR/LSU/LSAck adjacencies over raw
//! protocol-89 sockets between real containers, SPF routes into real kernel
//! tables, DR/BDR election on a real Linux bridge, authentication, aging.

use anyhow::bail;

use crate::consts::*;
use crate::router::{log, strings, Router, A, B};
use crate::world::World;

const BD: &str = OSPF_BROADCAST_DOMAIN;

// --- provisioning flags (each mirrors one `provision_*` of the old script) ---

/// An OSPF instance + area + profile, attached to eth0's tag-0 subinterface.
fn ospf(router_id: &str) -> Vec<String> {
    let mut f = ospf_instance_only(router_id);
    f.extend(strings(&["--ospf-interface-profile", OSPF_PROFILE]));
    f
}

/// Same, but never attached to eth0.0 — for router-c, which must not form a
/// second, unwanted point-to-point adjacency there (raw sockets have no
/// per-peer demux) and only joins OSPF via the broadcast-domain bridge.
fn ospf_instance_only(router_id: &str) -> Vec<String> {
    strings(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        router_id,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-profile",
        OSPF_PROFILE,
    ])
}

fn with_mtu(mut f: Vec<String>) -> Vec<String> {
    f.extend(strings(&[
        "--ospf-profile-mtu",
        &OSPF_MTU_VALUE.to_string(),
    ]));
    f
}

/// A static route redistributed into OSPF — makes this router a real ASBR.
/// (Overwrites rt1's single `redistribute` rule: that is why `asbr` runs
/// after every bgp-redistribution-dependent phase.)
fn asbr(mut f: Vec<String>) -> Vec<String> {
    f.extend(strings(&[
        "--static-route",
        ASBR_PREFIX,
        "--static-gateway",
        ASBR_GATEWAY,
        "--redistribute-to-ospf",
    ]));
    f
}

/// Trunks eth0 into the ospf broadcast domain (dot1q 400), addresses the
/// domain's bridge (an SVI) and points the domain's ospf field at the profile.
fn ospf_broadcast(svi: &str) -> Vec<String> {
    strings(&[
        "--routing-table",
        "rt1",
        "--switching-profile",
        "sp-ospf",
        "--switching-profile-member",
        &format!("{BD}:{OSPF_BROADCAST_TAG}"),
        "--broadcast-domain",
        BD,
        "--broadcast-domain-svi-address",
        svi,
        "--ospf-broadcast-domain-profile",
        OSPF_PROFILE,
    ])
}

fn ospfv3_instance_only(router_id: &str) -> Vec<String> {
    strings(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        router_id,
        "--ospfv3-area",
        OSPFV3_AREA,
        "--ospfv3-profile",
        OSPFV3_PROFILE,
    ])
}

fn ospfv3(address: &str, router_id: &str) -> Vec<String> {
    let mut f = strings(&["--ospfv3-address", address]);
    f.extend(ospfv3_instance_only(router_id));
    f.extend(strings(&["--ospfv3-interface-profile", OSPFV3_PROFILE]));
    f
}

fn ospfv3_broadcast(svi6: &str) -> Vec<String> {
    strings(&[
        "--routing-table",
        "rt1",
        "--broadcast-domain",
        BD,
        "--ospfv3-broadcast-domain-svi-address",
        svi6,
        "--ospfv3-broadcast-domain-profile",
        OSPFV3_PROFILE,
    ])
}

/// `ospfv3_broadcast` for a router whose bridge isn't set up yet: also trunks
/// eth0 into the domain and gives it an IPv4 SVI address (which is what
/// associates the domain with `rt1` — the IPv6-only flags don't, and OSPFv3
/// refuses a domain without a routing table). After `ospf-aging` and the
/// pagination phases restart router-a/b, that setup no longer exists.
fn ospfv3_broadcast_with_l2(svi4: &str, svi6: &str) -> Vec<String> {
    strings(&[
        "--routing-table",
        "rt1",
        "--switching-profile",
        "sp-ospf",
        "--switching-profile-member",
        &format!("{BD}:{OSPF_BROADCAST_TAG}"),
        "--broadcast-domain",
        BD,
        "--broadcast-domain-svi-address",
        svi4,
        "--ospfv3-broadcast-domain-svi-address",
        svi6,
        "--ospfv3-broadcast-domain-profile",
        OSPFV3_PROFILE,
    ])
}

// --- shared checks ---

fn full_p2p(neighbor: &str) -> String {
    format!("ospf neighbor reached full link=eth0.0 neighbor={neighbor}")
}

async fn both_full_p2p(a: &Router, b: &Router) -> anyhow::Result<()> {
    a.wait(&full_p2p(OSPF_ROUTER_ID_B)).await?;
    b.wait(&full_p2p(OSPF_ROUTER_ID)).await
}

/// At least one router logged a DBD chunk with more remaining.
async fn paginated(a: &Router, b: &Router) -> anyhow::Result<()> {
    let pat = "ospf dbd chunk sent, more remaining";
    if a.wait(pat).await.is_ok() || b.wait(pat).await.is_ok() {
        log("pagination triggered: a dbd chunk with more remaining was sent");
        Ok(())
    } else {
        bail!("no paginated dbd chunk was ever sent")
    }
}

/// Pagination needs router-a's Router-LSA *and* its redistributed AS-external
/// LSA already in its LSDB when the DBD exchange starts: a single-LSA summary
/// fits in one chunk at any size. REST provisioning is fast enough now that
/// router-b can be up before the static route has become an LSA, so wait for it.
async fn router_a_holds_two_lsas(a: &Router) -> anyhow::Result<()> {
    a.wait("ospf lsa originated.*lsa_type=5").await
}

// --- phases ---

pub async fn ospf_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;

    // nos-watchdogd really spawned a nos-ospfd for the new OspfInstance, and
    // it resolved its own instance/area/profile over IPC to nos-configd.
    a.wait(&format!(
        "ospf instance config resolved instance={OSPF_INSTANCE}"
    ))
    .await?;
    a.wait(&format!(
        "ospf area resolved instance={OSPF_INSTANCE} area={OSPF_AREA}"
    ))
    .await?;
    a.wait(&format!(
        "ospf profile resolved instance={OSPF_INSTANCE} area={OSPF_AREA} profile={OSPF_PROFILE}"
    ))
    .await?;

    // A real RFC 2328 Hello exchange over a real VRF-scoped raw protocol-89
    // socket, on eth0.0 (already carrying the BGP session's address), reaching
    // 2-Way then — after real DBD/LSR/LSU/LSAck — Full.
    a.wait(&format!(
        "ospf neighbor reached two-way link=eth0.0 neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospf neighbor reached two-way link=eth0.0 neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    both_full_p2p(a, b).await?;
    // Real LSA content flows and is installed. Not pinned to a link: a
    // router's LSDB is per-area, so which link sees an LSA first is a race.
    a.wait(&format!("ospf lsa installed.*neighbor={OSPF_ROUTER_ID_B}"))
        .await?;
    b.wait(&format!("ospf lsa installed.*neighbor={OSPF_ROUTER_ID}"))
        .await?;

    // The same profile on a broadcast (multi-access) link: each router's own
    // bd-ospf bridge, trunked from eth0 over dot1q. Equal priority, so the
    // higher router-id wins DR and the other becomes Backup.
    a.provision_flags(&with_base(A, ospf_broadcast(OSPF_BROADCAST_ADDRESS_A)))
        .await?;
    b.provision_flags(&with_base(B, ospf_broadcast(OSPF_BROADCAST_ADDRESS_B)))
        .await?;
    let link = format!("link=broadcast-domain:{BD}");
    a.wait(&format!(
        "ospf neighbor reached two-way {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospf neighbor reached two-way {link} neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    b.wait(&format!(
        "ospf interface became dr {link} dr={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "ospf interface became backup {link} dr={OSPF_ROUTER_ID_B} bdr={OSPF_ROUTER_ID}"
    ))
    .await?;
    a.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID}"
    ))
    .await
}

/// `Router::provision_flags` wants the *complete* flag list; this prepends the
/// router's own base flags to a scenario's extras.
fn with_base(id: crate::router::Id, extra: Vec<String>) -> Vec<String> {
    let mut f = id.base_flags();
    f.extend(extra);
    f
}

pub async fn asbr_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let originated = a.count("ospf lsa originated.*lsa_type=5");
    let installed = b.count("ospf lsa installed.*lsa_type=5");
    let route_pat = format!("added route prefix={ASBR_PREFIX}.*source=Some(Ospf)");
    let route = b.count(&route_pat);
    a.provision_flags(&with_base(A, asbr(ospf(OSPF_ROUTER_ID))))
        .await?;

    a.wait_new("ospf lsa originated.*lsa_type=5", originated, 60)
        .await?;
    b.wait_new("ospf lsa installed.*lsa_type=5", installed, 60)
        .await?;
    // `add_route`'s source is an `Option<RouteSource>`, so it renders "Some(Ospf)".
    b.wait_new(
        &format!("added route prefix={ASBR_PREFIX}.*source=Some(Ospf)"),
        route,
        60,
    )
    .await
}

/// A third router with a lower router-id joins the broadcast segment: the
/// incumbent DR/BDR stay put (RFC 2328 §9.4 stability) and it settles as
/// DrOther, still forming Full adjacencies with the DR and BDR (§8).
pub async fn ospf_dr(w: &mut World) -> anyhow::Result<()> {
    w.start(crate::router::C, None, &[]).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    c.provision_flags(&with_base(
        crate::router::C,
        ospf_instance_only(OSPF_ROUTER_ID_C),
    ))
    .await?;
    c.provision_flags(&with_base(
        crate::router::C,
        ospf_broadcast(OSPF_BROADCAST_ADDRESS_C),
    ))
    .await?;

    let link = format!("link=broadcast-domain:{BD}");
    c.wait(&format!(
        "ospf neighbor reached two-way {link} neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospf neighbor reached two-way {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    c.wait(&format!(
        "ospf interface became dr-other {link} dr={OSPF_ROUTER_ID_B} bdr={OSPF_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_C}"
    ))
    .await?;
    b.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_C}"
    ))
    .await
}

/// OSPF on router-b's loopback (a destination with no neighbor of its own):
/// router-a must compute a route to it via a real SPF over its LSDB and install
/// it into its kernel table, then withdraw it.
pub async fn ospf_spf(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let before = a.count(&format!(
        "ospf lsa installed.*advertising_router={OSPF_ROUTER_ID_B}"
    ));
    b.provision(&[
        "--loopback-address",
        OSPF_SPF_LOOPBACK_ADDRESS,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new(
        &format!("ospf lsa installed.*advertising_router={OSPF_ROUTER_ID_B}"),
        before,
        60,
    )
    .await?;
    a.wait(&format!(
        "added route prefix={OSPF_SPF_LOOPBACK_ADDRESS}.*source=Some(Ospf)"
    ))
    .await?;

    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait(&format!("removed route prefix={OSPF_SPF_LOOPBACK_ADDRESS}"))
        .await
}

/// RFC 5286 loop-free alternate: with router-c also on the broadcast segment,
/// router-a can reach router-b's loopback via b itself (primary) or via c (c's
/// own shortest path to b doesn't run back through a). `nos-ospfd` must push
/// both and `nos-ribd` install the backup as a second kernel route (higher
/// metric), and remove both again when the loopback leaves OSPF.
pub async fn ospf_lfa(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let prefix = OSPF_SPF_LOOPBACK_ADDRESS;
    let primary = format!("added route prefix={prefix}.*source=Some(Ospf) backup=false");
    let backup = format!("added route prefix={prefix}.*source=Some(Ospf) backup=true");
    let (p0, b0) = (a.count(&primary), a.count(&backup));
    b.provision(&[
        "--loopback-address",
        prefix,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new(&primary, p0, 60).await?;
    a.wait_new(&backup, b0, 60).await?;

    let removed = format!("removed route prefix={prefix}.*backup=true");
    let r0 = a.count(&removed);
    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait_new(&removed, r0, 60).await
}

/// Router-b's loopback moves into a second area, making it a real ABR: it must
/// originate a Type-3 summary-LSA, and router-a (backbone only) must install a
/// kernel route to a prefix that is not in its own area.
pub async fn abr(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let originated = b.count("ospf lsa originated.*lsa_type=3");
    let installed = a.count("ospf lsa installed.*lsa_type=3");
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA_1,
        "--ospf-profile",
        OSPF_PROFILE_AREA1,
        "--loopback-remove-address",
        OSPF_SPF_LOOPBACK_ADDRESS,
        "--loopback-address",
        OSPF_ABR_LOOPBACK_ADDRESS,
        "--ospf-loopback-profile",
        OSPF_PROFILE_AREA1,
    ])
    .await?;
    b.wait_new("ospf lsa originated.*lsa_type=3", originated, 60)
        .await?;
    a.wait_new("ospf lsa installed.*lsa_type=3", installed, 60)
        .await?;
    // A fresh prefix no earlier phase installed, so a baseline of 0 is right.
    a.wait(&format!(
        "added route prefix={OSPF_ABR_LOOPBACK_ADDRESS}.*source=Some(Ospf)"
    ))
    .await
}

/// RFC 5709 HMAC-SHA-256: matching keys reach/stay Full with real per-packet
/// digest checks; a mismatched key on router-a logs a real verification failure
/// on router-b and blocks a new Full; restoring it lets Full form again.
pub async fn ospf_auth(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let key = |k: &str| {
        [
            "--ospf-crypto-key".to_string(),
            format!("1:hmac-sha256:{k}"),
        ]
    };
    let with_key = |k: &str, rid: &str| {
        let mut f = ospf(rid);
        f.extend(key(k));
        f
    };
    a.provision_flags(&with_base(A, with_key("topsecretkey", OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, with_key("topsecretkey", OSPF_ROUTER_ID_B)))
        .await?;
    both_full_p2p(a, b).await?;

    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    log("reconfiguring router-a with a mismatched crypto key");
    a.provision_flags(&with_base(A, with_key("wrong-key", OSPF_ROUTER_ID)))
        .await?;
    b.wait_new("ospf packet authentication failed link=eth0.0", 0, 30)
        .await?;
    log("waiting 8s to confirm no new ospf full adjacency forms with mismatched crypto keys");
    a.assert_quiet(&full_p2p(OSPF_ROUTER_ID_B), before, 8)
        .await?;

    log("restoring the matching crypto key on router-a");
    a.provision_flags(&with_base(A, with_key("topsecretkey", OSPF_ROUTER_ID)))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await
}

/// RFC 2328 §14 aging. Self-contained: both nos-ospfd processes start with a
/// real `--lsa-age-multiplier` (1800s/3600s become 10s/20s).
pub async fn ospf_aging(w: &mut World) -> anyhow::Result<()> {
    let mult = format!("--ospfd-arg=--lsa-age-multiplier={OSPF_AGE_MULTIPLIER}");
    w.up(&[&mult]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    both_full_p2p(a, b).await?;

    // router-a's Router-LSA content never changes here, so a bumped sequence
    // number with refreshed=true can only come from the age-based refresh path.
    a.wait_new(
        &format!("ospf lsa originated.*advertising_router={OSPF_ROUTER_ID}.*refreshed=true"),
        0,
        45,
    )
    .await?;
    b.wait_new(
        &format!("ospf lsa installed.*advertising_router={OSPF_ROUTER_ID}"),
        0,
        20,
    )
    .await?;

    // Stop router-a's nos-ospfd so it stops refreshing: router-b's held copy
    // must then age out purely on its own local clock.
    log("killing router-a's nos-ospfd to stop further refreshes");
    w.dock.kill_process("router-a", "nos-ospfd").await?;
    b.wait_new(
        &format!("ospf lsa maxage flushed.*advertising_router={OSPF_ROUTER_ID}"),
        0,
        45,
    )
    .await
}

/// RFC 2328 §10.8 DBD pagination, forced by `--dbd-max-headers=1`. router-a
/// also redistributes a static route (two distinct LSAs before the exchange
/// starts), since a single-LSA summary fits in one chunk even at 1.
pub async fn ospf_dbd_pagination(w: &mut World) -> anyhow::Result<()> {
    w.up(&["--ospfd-arg=--dbd-max-headers=1"]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, asbr(ospf(OSPF_ROUTER_ID))))
        .await?;
    router_a_holds_two_lsas(a).await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    paginated(a, b).await?;
    both_full_p2p(a, b).await
}

/// The same, driven purely by a real `OspfProfile.mtu` override (the RFC 791
/// minimum) via `exchange::mtu_based_max_headers` — no `--dbd-max-headers` flag.
pub async fn ospf_mtu_pagination(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, asbr(with_mtu(ospf(OSPF_ROUTER_ID)))))
        .await?;
    router_a_holds_two_lsas(a).await?;
    b.provision_flags(&with_base(B, with_mtu(ospf(OSPF_ROUTER_ID_B))))
        .await?;
    a.wait(&format!("ospf profile resolved instance={OSPF_INSTANCE}"))
        .await?;
    paginated(a, b).await?;
    both_full_p2p(a, b).await
}

// --- OSPFv3 (RFC 5340) ---

pub async fn ospfv3_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
        .await?;

    a.wait(&format!(
        "ospfv3 instance config resolved instance={OSPFV3_INSTANCE}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 area resolved instance={OSPFV3_INSTANCE} area={OSPFV3_AREA}"
    ))
    .await?;
    a.wait(&format!("ospfv3 profile resolved instance={OSPFV3_INSTANCE} area={OSPFV3_AREA} profile={OSPFV3_PROFILE}")).await?;

    a.wait(&format!(
        "ospfv3 neighbor reached two-way link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached two-way link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;

    // router-a's loopback: a destination with no neighbor of its own, so
    // router-b can only learn it via its own RFC 5340 §16 SPF computation.
    let route_pat = format!("added route prefix={OSPFV3_LOOPBACK_ADDRESS}.*source=Some(Ospf)");
    let route_before = b.count(&route_pat);
    let lsa_installed = b.count(&format!(
        "ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID}"
    ));
    a.provision(&[
        "--ospfv3-loopback-address",
        OSPFV3_LOOPBACK_ADDRESS,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait("ospfv3 lsa originated").await?;
    // (The old script's baseline of 1 here was a fixed guess at the install
    // count; a live baseline is exact.)
    b.wait_new(
        &format!("ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID}"),
        lsa_installed,
        60,
    )
    .await?;
    b.wait_new(
        &format!("added route prefix={OSPFV3_LOOPBACK_ADDRESS}.*source=Some(Ospf)"),
        route_before,
        60,
    )
    .await?;

    // RFC 8362 Full mode on both routers: adjacency survives (mixed or not,
    // E-LSAs are known types), each originates E-LSAs, and the peer decodes
    // and installs them (E-Router 0xA021, E-Link 0x8028, E-Intra-Area-Prefix
    // 0xA029). The SPF side is covered by a unit test: the loopback route is
    // already installed from the legacy LSAs, and the daemon only advertises
    // an interface's first IPv6 address, so no new route can prove it here.
    let e_pat = format!("ospfv3 lsa originated lsa_type={LSA_TYPE_E_ROUTER}");
    let (a_before, b_before) = (a.count(&e_pat), b.count(&e_pat));
    a.provision_flags(&with_base(
        A,
        [
            ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
            strings(&["--ospfv3-extended-lsa"]),
        ]
        .concat(),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        [
            ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
            strings(&["--ospfv3-extended-lsa"]),
        ]
        .concat(),
    ))
    .await?;
    a.wait_new(&e_pat, a_before, 60).await?;
    b.wait_new(&e_pat, b_before, 60).await?;
    for lsa_type in [0xA021u16, 0x8028, 0xA029] {
        b.wait(&format!(
            "ospfv3 lsa installed.*lsa_type={lsa_type}.*advertising_router={OSPFV3_ROUTER_ID}"
        ))
        .await?;
    }
    Ok(())
}

/// Reuses `ospf-dr`'s router-c and the same bd-ospf bridge (a BroadcastDomain
/// has independent `ospf_profile`/`ospfv3_profile` fields, so both protocols
/// run over one real bridge): the identical DR/BDR election and DrOther-Full
/// restriction, over the new address family.
pub async fn ospfv3_dr(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    c.provision_flags(&with_base(
        crate::router::C,
        ospfv3_instance_only(OSPFV3_ROUTER_ID_C),
    ))
    .await?;
    a.provision_flags(&with_base(
        A,
        ospfv3_broadcast_with_l2(OSPF_BROADCAST_ADDRESS_A, OSPFV3_BROADCAST_ADDRESS_A),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        ospfv3_broadcast_with_l2(OSPF_BROADCAST_ADDRESS_B, OSPFV3_BROADCAST_ADDRESS_B),
    ))
    .await?;
    c.provision_flags(&with_base(
        crate::router::C,
        ospfv3_broadcast(OSPFV3_BROADCAST_ADDRESS_C),
    ))
    .await?;

    let link = format!("link=broadcast-domain:{BD}");
    a.wait(&format!(
        "ospfv3 neighbor reached two-way {link} neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached two-way {link} neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 interface became dr {link} dr={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 interface became backup {link} dr={OSPFV3_ROUTER_ID_B} bdr={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached two-way {link} neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached two-way {link} neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 interface became dr-other {link} dr={OSPFV3_ROUTER_ID_B} bdr={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID_C}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID_C}"
    ))
    .await
}
