//! OSPFv2 / OSPFv3 phases: real Hello/DBD/LSR/LSU/LSAck adjacencies over raw
//! protocol-89 sockets between real containers, SPF routes into real kernel
//! tables, DR/BDR election on a real Linux bridge, authentication, aging.

use std::time::Duration;

use anyhow::bail;
use reqwest::Method;

use crate::consts::*;
use crate::router::{log, strings, Router, A, B, C};
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
    ospf_broadcast_profile(svi, OSPF_PROFILE)
}

fn ospf_broadcast_profile(svi: &str, profile: &str) -> Vec<String> {
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
        profile,
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
    let mut f = strings(&["--address6", address]);
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
    paginated_with(a, b, "ospf dbd chunk sent, more remaining").await
}

async fn paginated_with(a: &Router, b: &Router, pat: &str) -> anyhow::Result<()> {
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

    // RFC 2328 §10.5's Hello packet-validity check (issue #31): a mismatched
    // hello-interval must be dropped before the neighbor even reaches Init,
    // not accepted into the FSM (where a real mismatch would just flap the
    // adjacency at whichever dead interval is shorter).
    let hello_interval = |mut f: Vec<String>, secs: u16| {
        f.extend(strings(&[
            "--ospf-profile-hello-interval",
            &secs.to_string(),
        ]));
        f
    };
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, hello_interval(ospf(OSPF_ROUTER_ID_B), 5)))
        .await?;
    a.wait("dropping ospf hello with mismatched hello-interval")
        .await?;
    log("confirming the mismatched-hello-interval neighbor never reaches init");
    a.assert_quiet(
        &format!("ospf neighbor state changed to init link=eth0.0 neighbor={OSPF_ROUTER_ID_B}"),
        0,
        8,
    )
    .await?;

    // Restore explicitly to router-a's own default (10s, `HELLO_INTERVAL_DEFAULT`)
    // rather than just re-provisioning `ospf(...)` with no override — a
    // transaction is built onto the *current* running config, so omitting
    // the flag would leave the mismatched value from above still set.
    log("restoring router-b's matching hello-interval");
    b.provision_flags(&with_base(B, hello_interval(ospf(OSPF_ROUTER_ID_B), 10)))
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
    // RFC 2328 §13.3: every LSA crosses the link with InfTransDelay added to
    // its age, so nothing ever lands at age 0 — not even a just-originated one.
    a.wait_new("ospf lsa installed.*age=[1-9]", 0, 15).await?;
    a.assert_quiet("ospf lsa installed.*age=0$", 0, 0).await?;

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
    .await?;

    // RFC 2328 §14.1: dropping the redistribute rule must flush the Type-5 —
    // prematurely aged on router-a, MaxAge-flushed on router-b and its kernel
    // route removed — in seconds, not after the 3600s MaxAge. The static route
    // itself stays. (nos-ospfd re-filters its redistributed set on its 10s
    // resync, so the bound is that plus one resend period plus the MaxAge hold.)
    let aged = a.count("ospf lsa prematurely aged.*lsa_type=5");
    let flushed_pat =
        format!("ospf lsa maxage flushed.*lsa_type=5.*advertising_router={OSPF_ROUTER_ID}");
    let flushed = b.count(&flushed_pat);
    let removed_pat = format!("removed route prefix={ASBR_PREFIX}");
    let removed = b.count(&removed_pat);
    log("removing the redistribute rule on router-a; its type-5 must be flushed");
    a.provision(&["--clear-redistribute-to-ospf"]).await?;
    a.wait_new("ospf lsa prematurely aged.*lsa_type=5", aged, 30)
        .await?;
    b.wait_new(&flushed_pat, flushed, 30).await?;
    b.wait_new(&removed_pat, removed, 30).await?;

    // RFC 2328 §13.5 delayed acknowledgment: router-b acks router-a's periodic
    // LSUs on its own RxmtInterval sweep, so some batch is held a second or
    // more before it goes out — impossible with an immediate per-LSU ack.
    b.wait_new("ospf lsack sent.*delayed_ms=[1-9][0-9][0-9][0-9]", 0, 30)
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
    .await?;
    // #139: router-c's eth0.0 subnet is connected in rt1 but not in OSPF, so
    // router-a/b advertise it to c as a stub and c's SPF computes an OSPF
    // route for it. The connected route wins: nos-ribd must leave the prefix
    // to the kernel — no add (which used to fail with EEXIST every 10s
    // reapply), no add-then-remove flap. Over 15s, more than one reapply tick.
    c.assert_quiet(&format!("route prefix={SUBNET}"), 0, 15)
        .await
}

/// OSPF on router-b's loopback (a destination with no neighbor of its own):
/// router-a must compute a route to it via a real SPF over its LSDB and install
/// it into its kernel table — over both of its equal-cost links to router-b
/// (ECMP) — then withdraw it.
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
    // RFC 2328 §16.1 2(d) ECMP (#33): router-b is one hop away over both the
    // p2p eth0.0 link and the bd-ospf bridge, both at cost 1, so the route
    // carries both of router-b's addresses as one RTA_MULTIPATH kernel route.
    a.wait(&format!(
        "added route prefix={OSPF_SPF_LOOPBACK_ADDRESS}.*next_hops=2.*source=Some(Ospf)"
    ))
    .await?;
    // Issue #20: router-a's nos-bgpd polls nos-ribd's IGP costs (BGP decision
    // step d) and must see the OSPF route with its real, non-zero SPF metric.
    a.wait(&format!(
        "igp costs updated.*{OSPF_SPF_LOOPBACK_ADDRESS}: [1-9]"
    ))
    .await?;

    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait(&format!("removed route prefix={OSPF_SPF_LOOPBACK_ADDRESS}"))
        .await?;
    // `next-hop-reachability` needs the loopback unreachable from its start.
    a.wait_ospf_route_gone(OSPF_SPF_LOOPBACK_ADDRESS, 15).await
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
    .await?;

    // RFC 2328 §14.1: the loopback leaving area 1 (router-b's only presence
    // there) must flush the Type-3 — prematurely aged on router-b, MaxAge-
    // flushed on router-a and its kernel route removed — within seconds.
    let aged = b.count("ospf lsa prematurely aged.*lsa_type=3");
    let flushed = a.count("ospf lsa maxage flushed.*lsa_type=3");
    log("removing router-b's area-1 loopback; its type-3 summary must be flushed");
    b.provision(&[
        "--loopback-remove-address",
        OSPF_ABR_LOOPBACK_ADDRESS,
        "--clear-ospf-loopback-profile",
    ])
    .await?;
    b.wait_new("ospf lsa prematurely aged.*lsa_type=3", aged, 30)
        .await?;
    a.wait_new("ospf lsa maxage flushed.*lsa_type=3", flushed, 30)
        .await?;
    a.wait(&format!("removed route prefix={OSPF_ABR_LOOPBACK_ADDRESS}"))
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
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await?;

    // RFC 7474: AuType 3 with a persisted boot count. Both ends enabled reach
    // Full again; one end alone is an auth-type mismatch and blocks it.
    let ext = |k: &str, rid: &str, on: bool| {
        let mut f = with_key(k, rid);
        f.extend(["--ospf-extended-seq".to_string(), on.to_string()]);
        f
    };
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    log("enabling rfc 7474 extended sequence numbers on router-a only");
    let auth_failures = b.count("ospf packet authentication failed link=eth0.0");
    a.provision_flags(&with_base(A, ext("topsecretkey", OSPF_ROUTER_ID, true)))
        .await?;
    b.wait_new(
        "ospf packet authentication failed link=eth0.0",
        auth_failures,
        30,
    )
    .await?;
    a.assert_quiet(&full_p2p(OSPF_ROUTER_ID_B), before, 8)
        .await?;

    log("enabling rfc 7474 extended sequence numbers on router-b too");
    b.provision_flags(&with_base(B, ext("topsecretkey", OSPF_ROUTER_ID_B, true)))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await?;
    a.wait("ospf link using rfc 7474 extended sequence numbers")
        .await?;

    // Restart router-b's nos-ospfd: a fresh process must take a higher boot
    // count from the persisted file, so router-a's replay check accepts it.
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    let boots = b.count("ospf link using rfc 7474 extended sequence numbers");
    let replays = a.count("crypto sequence number not increasing");
    log("killing router-b's nos-ospfd; it must return to Full without replay drops");
    w.dock.kill_process("router-b", "nos-ospfd").await?;
    b.wait_new(
        "ospf link using rfc 7474 extended sequence numbers",
        boots,
        60,
    )
    .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 90).await?;
    a.assert_quiet("crypto sequence number not increasing", replays, 5)
        .await
}

/// RFC 3623 graceful restart (requires `ospf`, runs after `ospf-auth`):
/// router-a, with a grace period configured and its loopback in OSPF, is
/// restarted with SIGTERM. It must send a Grace-LSA and keep its LSAs instead
/// of flushing them, and router-b must help: hold the eth0.0 adjacency and
/// keep router-a's loopback route installed through the whole restart, then
/// resynchronize with the respawned process.
pub async fn ospf_graceful_restart(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let instance = |extra: &[&str]| {
        let mut f = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
        ]);
        f.extend(strings(extra));
        f
    };
    a.provision_flags(&with_base(
        A,
        instance(&[
            "--ospf-graceful-restart-grace-period",
            "120",
            "--loopback-address",
            OSPF_GR_LOOPBACK_ADDRESS,
            "--ospf-loopback-profile",
            OSPF_PROFILE,
        ]),
    ))
    .await?;
    a.wait("ospf instance config resolved.*graceful_restart_grace_period=Some(120)")
        .await?;
    b.wait(&format!(
        "added route prefix={OSPF_GR_LOOPBACK_ADDRESS}.*source=Some(Ospf)"
    ))
    .await?;

    let torn = "ospf neighbor adjacency torn down, back to init link=eth0.0\\|ospf neighbor state changed to down link=eth0.0";
    let flushed = format!("ospf lsa maxage flushed.*advertising_router={OSPF_ROUTER_ID}$");
    let flush_on_a = "ospf flushing self-originated lsas before shutdown";
    let (full_on_b, full_on_a) = (full_p2p(OSPF_ROUTER_ID), full_p2p(OSPF_ROUTER_ID_B));
    let (torn0, flushed0, flush_a0, full_b0, full_a0) = (
        b.count(torn),
        b.count(&flushed),
        a.count(flush_on_a),
        b.count(&full_on_b),
        a.count(&full_on_a),
    );
    log("sending SIGTERM to router-a's nos-ospfd; it must announce a grace period first");
    w.dock
        .signal_process("router-a", "nos-ospfd", "-TERM")
        .await?;
    let restart = async {
        a.wait("ospf graceful restart: announcing grace period before shutdown grace_period=120")
            .await?;
        a.wait(&format!(
            "ospf graceful restart: grace-lsa sent link=eth0.0 neighbor={OSPF_ROUTER_ID_B} grace_period=120"
        ))
        .await?;
        b.wait(&format!(
            "ospf helper: grace period entered link=eth0.0 neighbor={OSPF_ROUTER_ID} grace_period=120 restart_reason=1"
        ))
        .await?;
        // The watchdog respawns router-a; the fresh process resynchronizes
        // with the neighbor that held it Full the whole time.
        b.wait_new(&full_on_b, full_b0, 90).await?;
        a.wait_new(&full_on_a, full_a0, 90).await?;
        b.wait(&format!(
            "ospf helper: neighbor reformed, exiting grace early link=eth0.0 neighbor={OSPF_ROUTER_ID}"
        ))
        .await?;
        tokio::time::sleep(Duration::from_secs(5)).await;
        anyhow::Ok(())
    };
    // router-b's RIB must hold the OSPF route at every sample of the restart.
    // (Its next hops may still change — the bridge adjacency, not covered by
    // this phase, can come up meanwhile — which the kernel driver logs as a
    // remove + add, so the kernel log alone can't tell a drop from that.)
    let route_held = async {
        loop {
            if !b.rt1_has(OSPF_GR_LOOPBACK_ADDRESS, "Ospf").await? {
                bail!(
                    "router-b lost its ospf route to {OSPF_GR_LOOPBACK_ADDRESS} during the restart"
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    tokio::select! {
        r = restart => r?,
        r = route_held => r?,
    }
    log("router-b held its ospf route to router-a's loopback through the restart");
    // RFC 3623 §2: the restarter keeps its LSAs; the helper never tears the
    // adjacency down and never flushes them.
    a.assert_quiet(flush_on_a, flush_a0, 0).await?;
    b.assert_quiet(torn, torn0, 0).await?;
    b.assert_quiet(&flushed, flushed0, 0).await?;

    log("restoring router-a: loopback out of ospf, graceful restart off");
    a.provision_flags(&with_base(
        A,
        instance(&[
            "--ospf-graceful-restart-grace-period",
            "0",
            "--loopback-remove-address",
            OSPF_GR_LOOPBACK_ADDRESS,
            "--clear-ospf-loopback-profile",
        ]),
    ))
    .await?;
    b.wait_ospf_route_gone(OSPF_GR_LOOPBACK_ADDRESS, 5).await
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

    // Graceful shutdown (SIGTERM — a SIGKILL never reaches the handler):
    // router-b's nos-ospfd must prematurely age its own LSAs (RFC 2328 §14.1)
    // and keep flooding long enough for router-a to flush them within
    // seconds. The watchdog then respawns it; reconverge before the
    // router-a-focused steps below.
    let flushed_pat = format!("ospf lsa maxage flushed.*advertising_router={OSPF_ROUTER_ID_B}");
    let flushed = a.count(&flushed_pat);
    let (full_a, full_b) = (
        a.count(&full_p2p(OSPF_ROUTER_ID_B)),
        b.count(&full_p2p(OSPF_ROUTER_ID)),
    );
    log("sending SIGTERM to router-b's nos-ospfd; it must flush its lsas before exiting");
    w.dock
        .signal_process("router-b", "nos-ospfd", "-TERM")
        .await?;
    b.wait("ospf flushing self-originated lsas before shutdown")
        .await?;
    a.wait_new(&flushed_pat, flushed, 30).await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), full_a, 90).await?;
    b.wait_new(&full_p2p(OSPF_ROUTER_ID), full_b, 90).await?;

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

/// RFC 2328 §3.5/§3.6 stub areas and area ranges, self-contained. eth0.0 is
/// in area 1, router-a's only area; router-b's loopback is in area 0, making
/// router-b the ABR, and router-b redistributes a static route (a Type-5 that
/// must never reach the stub area).
#[allow(clippy::too_many_lines)]
pub async fn ospf_stub(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let loopback = OSPF_STUB_LOOPBACK_ADDRESS;
    let loopback_id = loopback.trim_end_matches("/32");
    let range = OSPF_STUB_RANGE;
    let range_id = range.split('/').next().unwrap_or(range);
    let area = |router_id: &str, extra: &[&str]| {
        let mut f = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            "--ospf-area",
            OSPF_AREA_1,
        ]);
        f.extend(strings(extra));
        f
    };
    let on_eth0 = |router_id: &str, area_type: &str| {
        area(
            router_id,
            &[
                "--ospf-area-type",
                area_type,
                "--ospf-profile",
                OSPF_PROFILE_AREA1,
                "--ospf-interface-profile",
                OSPF_PROFILE_AREA1,
            ],
        )
    };

    // Area 1 a stub on router-a only: the Hello E-bits disagree.
    let mismatch = "dropping ospf hello with mismatched e-bit";
    a.provision_flags(&with_base(A, on_eth0(OSPF_ROUTER_ID, "stub")))
        .await?;
    b.provision_flags(&with_base(B, asbr(on_eth0(OSPF_ROUTER_ID_B, "normal"))))
        .await?;
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-profile",
        OSPF_PROFILE,
        "--loopback-address",
        loopback,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait(mismatch).await?;
    b.wait(mismatch).await?;
    b.wait("ospf lsa originated.*lsa_type=5").await?;
    log("confirming the e-bit mismatch never reaches init");
    a.assert_quiet(
        &format!("ospf neighbor state changed to init link=eth0.0 neighbor={OSPF_ROUTER_ID_B}"),
        0,
        8,
    )
    .await?;

    // Stub on both: Full; router-b (ABR) originates a default Type-3 and a
    // summary of its loopback; router-a installs both as kernel routes and
    // never a Type-5.
    b.provision(&area(OSPF_ROUTER_ID_B, &["--ospf-area-type", "stub"]))
        .await?;
    both_full_p2p(a, b).await?;
    a.wait("ospf lsa installed.*lsa_type=3 link_state_id=0.0.0.0")
        .await?;
    a.wait("added route prefix=0.0.0.0/0 .*source=Some(Ospf)")
        .await?;
    a.wait(&format!(
        "added route prefix={loopback} .*source=Some(Ospf)"
    ))
    .await?;
    log("confirming no as-external lsa reaches the stub area");
    a.assert_quiet("ospf lsa installed.*lsa_type=5", 0, 10)
        .await?;

    // A range over the loopback on area 0: router-a gets the range instead of
    // the /32 (flushed), and router-b installs a discard route for it.
    let discard =
        format!("added route prefix={range} .*source=Some(Ospf) backup=false discard=true");
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-area-range",
        range,
    ])
    .await?;
    a.wait(&format!(
        "ospf lsa installed.*lsa_type=3 link_state_id={range_id}"
    ))
    .await?;
    a.wait(&format!("added route prefix={range} .*source=Some(Ospf)"))
        .await?;
    b.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=3 link_state_id={loopback_id}"
    ))
    .await?;
    a.wait(&format!("removed route prefix={loopback}")).await?;
    b.wait(&discard).await?;
    if !b.rt1_has(range, "Ospf").await? {
        bail!("router-b's rt1 does not list the discard route {range}");
    }
    // The dumped RTN_BLACKHOLE is recognised as ours: no EEXIST re-add on the
    // next 10s reapply.
    log("confirming router-b's discard route survives a reapply");
    let failed = format!("failed to add route prefix={range}");
    b.assert_quiet(&failed, b.count(&failed), 15).await?;
    b.assert_quiet(&discard, 1, 0).await?;

    // not-advertise: the range Type-3 is flushed, router-a's route and
    // router-b's discard route removed.
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-area-range",
        &format!("{range}:not-advertise"),
    ])
    .await?;
    a.wait(&format!(
        "ospf lsa maxage flushed.*lsa_type=3 link_state_id={range_id}"
    ))
    .await?;
    a.wait(&format!("removed route prefix={range}")).await?;
    b.wait(&format!("removed route prefix={range} .*discard=true"))
        .await?;

    // Totally stubby: with the range gone the /32 summary is back, then
    // flushed again, and only the default is left.
    let added = format!("added route prefix={loopback} .*source=Some(Ospf)");
    let added_before = a.count(&added);
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-clear-area-range",
        range,
    ])
    .await?;
    a.wait_new(&added, added_before, 60).await?;
    let removed = format!("removed route prefix={loopback}");
    let removed_before = a.count(&removed);
    let default_removed = "removed route prefix=0.0.0.0/0";
    b.provision(&area(
        OSPF_ROUTER_ID_B,
        &["--ospf-area-type", "totally-stubby"],
    ))
    .await?;
    a.wait_new(&removed, removed_before, 60).await?;
    log("confirming the default route stays in the totally-stubby area");
    a.assert_quiet(default_removed, 0, 10).await?;
    if !a.rt1_has("0.0.0.0/0", "Ospf").await? {
        bail!("router-a lost its default route in the totally-stubby area");
    }
    Ok(())
}

/// RFC 3101 NSSA, self-contained, three routers. eth0.0 (a-b) is the
/// backbone; the bd-ospf bridge (a, b and c) is NSSA area 1, so router-a and
/// router-b are its two ABRs and router-c is internal to it. Router-c
/// redistributes a static route as a Type-7; router-b, the higher router-id,
/// is the elected translator and floods the Type-5 into the backbone, which
/// router-a learns over eth0.0. No Type-5 ever enters the NSSA.
pub async fn ospf_nssa(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    w.start(C, None, &[]).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let lsid = ASBR_PREFIX.split('/').next().unwrap_or(ASBR_PREFIX);
    let nssa = |router_id: &str, svi: &str| {
        let mut flags = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            "--ospf-area",
            OSPF_AREA_1,
            "--ospf-area-type",
            "nssa",
            "--ospf-profile",
            OSPF_PROFILE_AREA1,
        ]);
        flags.extend(ospf_broadcast_profile(svi, OSPF_PROFILE_AREA1));
        flags
    };
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    a.provision_flags(&with_base(
        A,
        nssa(OSPF_ROUTER_ID, OSPF_BROADCAST_ADDRESS_A),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        nssa(OSPF_ROUTER_ID_B, OSPF_BROADCAST_ADDRESS_B),
    ))
    .await?;
    c.provision_flags(&with_base(
        C,
        asbr(nssa(OSPF_ROUTER_ID_C, OSPF_BROADCAST_ADDRESS_C)),
    ))
    .await?;

    both_full_p2p(a, b).await?;
    let link = format!("link=broadcast-domain:{BD}");
    for neighbor in [OSPF_ROUTER_ID, OSPF_ROUTER_ID_B] {
        c.wait(&format!(
            "ospf neighbor reached full {link} neighbor={neighbor}"
        ))
        .await?;
    }
    // Router-c's Type-7, translated by router-b alone into a Type-5 that
    // router-a learns over the backbone and routes.
    c.wait(&format!(
        "ospf lsa originated.*lsa_type=7 link_state_id={lsid}"
    ))
    .await?;
    b.wait(&format!(
        "ospf nssa translator role changed area={OSPF_AREA_1} translating=true"
    ))
    .await?;
    b.wait(&format!(
        "ospf lsa originated.*lsa_type=5 link_state_id={lsid}"
    ))
    .await?;
    a.wait(&format!(
        "ospf lsa installed link=eth0.0 .*lsa_type=5 link_state_id={lsid} advertising_router={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "added route prefix={ASBR_PREFIX} .*source=Some(Ospf)"
    ))
    .await?;
    log("confirming router-a doesn't translate too and no type-5 enters the nssa");
    let a_type5 = "ospf lsa originated.*lsa_type=5";
    a.assert_quiet(a_type5, a.count(a_type5), 10).await?;
    c.assert_quiet("ospf lsa installed.*lsa_type=5", 0, 0)
        .await?;

    // Redistribution removed: the Type-7 and the Type-5 translated from it
    // are both flushed (RFC 2328 §14.1) and router-a's route goes.
    let removed = format!("removed route prefix={ASBR_PREFIX}");
    c.provision(&["--clear-redistribute-to-ospf"]).await?;
    c.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=7 link_state_id={lsid}"
    ))
    .await?;
    b.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=5 link_state_id={lsid}"
    ))
    .await?;
    a.wait(&removed).await
}

/// RFC 5250 opaque LSAs against a real third-party router, self-contained.
/// FRR (`router-f`) peers router-a over router-a's eth1 on its own network
/// and originates a type 10 (segment routing's Extended Link, opaque type 8)
/// and a type 11 (Router Information, AS scope) — which FRR only does once a
/// neighbor's DBD carried the O-bit — then a type 9 (an RFC 3623 Grace-LSA, `graceful-restart
/// prepare`, which FRR sends without restarting). router-a must install all
/// three, flood the type 10 and 11 on to router-b over eth0.0, and never the
/// type 9 (link-local scope).
pub async fn ospf_opaque(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    if !w.dock.network_exists(NET_OSPF_FRR).await {
        w.dock
            .network_create(NET_OSPF_FRR, &[OSPF_FRR_SUBNET], false)
            .await?;
    }
    w.dock
        .network_connect_ip(NET_OSPF_FRR, "router-a", OSPF_FRR_IP_A)
        .await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    // eth1 is router-a's second subinterface: its own base flags with eth1's
    // address instead of eth0's, the same instance/area/profile attached.
    let mut eth1 = strings(&[
        "--interface",
        "eth1",
        "--address",
        &format!("{OSPF_FRR_IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_B.to_string(),
        "--peer",
        IP_B,
    ]);
    eth1.extend(ospf(OSPF_ROUTER_ID));
    a.provision_flags(&eth1).await?;
    both_full_p2p(a, b).await?;

    log("starting FRR (router-f) on router-a's eth1");
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    // Not `mpls-te` for the type 10: FRR 10.7.1's ospfd segfaults with it
    // here (in `ospf_read`, and with `router-info as` in type-11 origination).
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\n\
         interface eth0\n ip ospf network point-to-point\n ip ospf area {OSPF_AREA}\nexit\n!\n\
         router ospf\n ospf router-id {OSPF_ROUTER_ID_F}\n capability opaque\n \
         router-info as\n segment-routing on\n \
         graceful-restart grace-period 120\nexit\n"
    );
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET_OSPF_FRR,
            OSPF_FRR_IP_F,
            &[
                "sh",
                "-c",
                "sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;

    let link = "link=eth1.0";
    a.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_F}"
    ))
    .await?;
    // "installed on `at` (link and neighbor), of type `t`, originated by FRR"
    let from_frr = |at: &str, t: u8| {
        format!("ospf lsa installed {at} lsa_type={t} .*advertising_router={OSPF_ROUTER_ID_F} ")
    };
    let on_a = format!("{link} neighbor={OSPF_ROUTER_ID_F}");
    let on_b = format!("link=eth0.0 neighbor={OSPF_ROUTER_ID}");
    for t in [10, 11] {
        a.wait(&from_frr(&on_a, t)).await?;
        // Flooded on by router-a, which set the O-bit in its DBD to router-b.
        b.wait(&from_frr(&on_b, t)).await?;
    }

    // RFC 2328 A.4.2 (#34): router-a becomes an ASBR (a redistributed static)
    // and an ABR (a loopback in area 1). FRR builds a router route — needed to
    // resolve a Type-5's ASBR or a Type-3's ABR — only from a Router-LSA with
    // E or B set, so without the bits it never lists router-a as a border
    // router nor installs either prefix.
    log("making router-a an asbr and an abr; FRR must see its E and B bits");
    a.provision_flags(&with_base(
        A,
        asbr(strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
            "--ospf-area",
            OSPF_AREA_1,
            "--ospf-profile",
            OSPF_PROFILE_AREA1,
            "--loopback-address",
            OSPF_ABR_LOOPBACK_ADDRESS,
            "--ospf-loopback-profile",
            OSPF_PROFILE_AREA1,
        ])),
    ))
    .await?;
    frr_until(w, "show ip ospf border-routers", 60, |out| {
        out.lines()
            .any(|l| l.contains(OSPF_ROUTER_ID) && l.contains("ABR,") && l.contains("ASBR"))
    })
    .await?;
    frr_until(w, "show ip ospf route", 60, |out| {
        out.contains(ASBR_PREFIX) && out.contains(OSPF_ABR_LOOPBACK_ADDRESS)
    })
    .await?;

    log("FRR announces a graceful restart: a type-9 grace-lsa, link-local");
    let b9 = b.count(&from_frr(".*", 9));
    let (code, out) = w
        .dock
        .exec(
            "router-f",
            &["vtysh", "-c", "graceful-restart prepare ip ospf"],
        )
        .await?;
    anyhow::ensure!(code == 0, "graceful-restart prepare failed: {out}");
    a.wait(&from_frr(&on_a, 9)).await?;
    a.wait(&format!(
        "ospf helper: grace period entered {link} neighbor={OSPF_ROUTER_ID_F} grace_period=120"
    ))
    .await?;
    // Three RXMT_INTERVALs of periodic resend: never flooded past eth1.
    b.assert_quiet(&from_frr(".*", 9), b9, 15).await?;

    let body = a
        .rest_expect(Method::GET, "/v1/ospf/database", None, 200)
        .await?;
    let report: serde_json::Value = serde_json::from_str(&body)?;
    let mut types: Vec<u64> = report[0]["result"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("ospf database has no result: {body}"))?
        .iter()
        .filter(|row| row["advertising_router"] == OSPF_ROUTER_ID_F)
        .filter_map(|row| row["lsa_type"].as_u64())
        .filter(|t| *t >= 9)
        .collect();
    types.sort_unstable();
    anyhow::ensure!(
        types == [10, 11],
        "router-a's database lists FRR opaque types {types:?}, want [10, 11]: {body}"
    );

    w.dock.container_remove("router-f").await;
    Ok(())
}

/// Polls `vtysh -c <cmd>` on router-f every second until `ok` holds.
async fn frr_until(
    w: &World,
    cmd: &str,
    secs: u64,
    ok: impl Fn(&str) -> bool,
) -> anyhow::Result<()> {
    let mut out = String::new();
    for _ in 0..secs {
        out = w.dock.exec("router-f", &["vtysh", "-c", cmd]).await?.1;
        if ok(&out) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("FRR `{cmd}` never matched within {secs}s:\n{out}")
}

// --- OSPFv3 (RFC 5340) ---

/// `ospf_mtu_pagination` for `OSPFv3`, self-contained: a real
/// `Ospfv3Profile.mtu` override alone (no `--dbd-max-headers`) drives
/// `exchange::mtu_based_max_headers` — each router already holds several LSAs
/// (Router, Link, Intra-Area-Prefix) before the DBD exchange, so no ASBR needed.
pub async fn ospfv3_mtu_pagination(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let mtu = |mut f: Vec<String>| {
        f.extend(strings(&[
            "--ospfv3-profile-mtu",
            &OSPF_MTU_VALUE.to_string(),
        ]));
        f
    };
    a.provision_flags(&with_base(
        A,
        mtu(ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        mtu(ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)),
    ))
    .await?;
    paginated_with(a, b, "ospfv3 dbd chunk sent, more remaining").await?;
    a.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await
}

/// RFC 7166: matching HMAC-SHA-256 trailer keys on both routers' eth0.0
/// profile reach/stay Full with real per-packet digest checks; a mismatched
/// key on router-a logs a real verification failure on router-b and blocks a
/// new Full; restoring it lets Full form again. `ospf_auth` minus its RFC
/// 7474 half (no OSPFv3 equivalent). Requires `ospfv3` to have run. Leaves
/// the profile unauthenticated again, for `ospfv3-dr`'s keyless router-c.
pub async fn ospfv3_auth(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let full =
        |neighbor: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={neighbor}");
    let with_key = |k: &str, addr: &str, rid: &str| {
        let mut f = ospfv3(addr, rid);
        f.extend([
            "--ospfv3-crypto-key".to_string(),
            format!("300:hmac-sha256:{k}"),
        ]);
        f
    };
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    log("configuring a matching rfc 7166 key (sa id 300, hmac-sha256) on both routers");
    a.provision_flags(&with_base(
        A,
        with_key("topsecretkey", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        with_key("topsecretkey", OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ))
    .await?;
    a.wait("ospfv3 link driver started link=eth0.0.*authenticated=true")
        .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;

    let before = a.count(&full(OSPFV3_ROUTER_ID_B));
    let failures = b.count("ospfv3 packet authentication failed link=eth0.0");
    log("reconfiguring router-a with a mismatched key");
    a.provision_flags(&with_base(
        A,
        with_key("wrong-key", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.wait_new(
        "ospfv3 packet authentication failed link=eth0.0",
        failures,
        30,
    )
    .await?;
    log("waiting 8s to confirm no new ospfv3 full adjacency forms with mismatched keys");
    a.assert_quiet(&full(OSPFV3_ROUTER_ID_B), before, 8).await?;

    log("restoring the matching key on router-a");
    a.provision_flags(&with_base(
        A,
        with_key("topsecretkey", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), before, 60).await?;
    let replays = a.count("ospfv3 packet crypto sequence number not increasing");
    a.assert_quiet(
        "ospfv3 packet crypto sequence number not increasing",
        replays,
        5,
    )
    .await?;

    // `provision_flags` edits on top of the running config, so leaving the
    // flag out would keep the key: clear it, since `ospfv3-dr` reuses this
    // profile on the bridge with a keyless router-c (#138).
    log("clearing the rfc 7166 key on both routers");
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    for r in [a, b] {
        r.edit(|c| {
            nos_proto::Ospfv3ProfileOp::ClearAuth {
                instance: OSPFV3_INSTANCE.into(),
                area_id: OSPFV3_AREA.parse()?,
                name: OSPFV3_PROFILE.into(),
            }
            .apply(c)
            .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await?;
    }
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await
}

/// RFC 5340 §A.3.1 Instance ID: instance-id 1 on router-a alone gets its
/// packets dropped by router-b (logged at debug) and no new Full forms; 1 on
/// both reaches Full with a non-zero id on the wire both ways. Requires
/// `ospfv3` to have run; leaves both back at 0 for `ospfv3-dr`'s router-c.
pub async fn ospfv3_instance_id(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let full =
        |neighbor: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={neighbor}");
    let with_id = |id: &str, addr: &str, rid: &str| {
        let mut f = ospfv3(addr, rid);
        f.extend(strings(&["--ospfv3-instance-id", id]));
        f
    };
    let mismatch =
        "ospfv3 packet instance id mismatch, dropping link=eth0.0.*received=1 expected=0";
    let (a_full, drops) = (a.count(&full(OSPFV3_ROUTER_ID_B)), b.count(mismatch));
    log("setting instance-id 1 on router-a only");
    a.provision_flags(&with_base(
        A,
        with_id("1", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.wait_new(mismatch, drops, 30).await?;
    log("waiting 8s to confirm no new ospfv3 full adjacency forms with mismatched instance ids");
    a.assert_quiet(&full(OSPFV3_ROUTER_ID_B), a_full, 8).await?;

    log("setting instance-id 1 on router-b too");
    let b_full = b.count(&full(OSPFV3_ROUTER_ID));
    b.provision_flags(&with_base(
        B,
        with_id("1", OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;

    log("resetting instance-id to 0 on both routers");
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    a.provision_flags(&with_base(
        A,
        with_id("0", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        with_id("0", OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await
}

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
    // The legacy Router-LSA (0x2001) each side flushes on the switch (#149).
    let flushed =
        |id: &str| format!("ospfv3 lsa maxage flushed.*lsa_type=8193 .*advertising_router={id}");
    let (a_flushed, b_flushed) = (
        a.count(&flushed(OSPFV3_ROUTER_ID_B)),
        b.count(&flushed(OSPFV3_ROUTER_ID)),
    );
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

    // RFC 2328 §14.1 on the switch (#149): each side prematurely ages its
    // own legacy set, the peer flushes it, and no legacy LSA from it is left.
    a.wait(&format!(
        "ospfv3 lsa prematurely aged lsa_type=8193 .*advertising_router={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 lsa prematurely aged lsa_type=8193 .*advertising_router={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait_new(&flushed(OSPFV3_ROUTER_ID), b_flushed, 30)
        .await?;
    a.wait_new(&flushed(OSPFV3_ROUTER_ID_B), a_flushed, 30)
        .await?;
    assert_no_legacy_lsas(b, OSPFV3_ROUTER_ID).await?;
    assert_no_legacy_lsas(a, OSPFV3_ROUTER_ID_B).await
}

/// Polls `router`'s `GET /v1/ospfv3/database` (up to 15s: the Link- and
/// Intra-Area-Prefix-LSAs are evicted around the Router-LSA's flush, not on
/// the same tick) until it holds no legacy Router (0x2001), Link (0x0008) or
/// Intra-Area-Prefix (0x2009) LSA from `router_id`.
async fn assert_no_legacy_lsas(router: &Router, router_id: &str) -> anyhow::Result<()> {
    let mut left = Vec::new();
    for _ in 0..15 {
        let body = router
            .rest_expect(Method::GET, "/v1/ospfv3/database", None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        left = report[0]["result"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("ospfv3 database has no result: {body}"))?
            .iter()
            .filter(|row| {
                row["advertising_router"] == router_id
                    && matches!(row["lsa_type"].as_u64(), Some(0x2001 | 0x0008 | 0x2009))
            })
            .cloned()
            .collect();
        if left.is_empty() {
            log(format!("no legacy lsa from {router_id} left"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("legacy lsas from {router_id} still held: {left:?}")
}

/// RFC 5187 graceful restart (requires `ospfv3`): router-a, with a grace
/// period configured, is restarted with SIGTERM. It must send a Grace-LSA
/// before exiting, and router-b must help: hold the adjacency and keep
/// router-a's loopback route (learned in `ospfv3`) installed through the whole
/// restart, then resynchronize with the restarted process.
pub async fn ospfv3_graceful_restart(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let full_on_b = format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID}");
    let full_on_a =
        format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}");
    a.provision_flags(&with_base(
        A,
        [
            ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
            strings(&["--ospfv3-graceful-restart-grace-period", "120"]),
        ]
        .concat(),
    ))
    .await?;
    // No link config changed, so the adjacency from `ospfv3` stays up.
    a.wait("ospfv3 instance config resolved.*graceful_restart_grace_period=Some(120)")
        .await?;

    let torn = "ospfv3 neighbor adjacency torn down\\|ospfv3 neighbor state changed to down";
    let removed = format!("removed route prefix={OSPFV3_LOOPBACK_ADDRESS}");
    let (torn_before, removed_before, full_b_before, full_a_before) = (
        b.count(torn),
        b.count(&removed),
        b.count(&full_on_b),
        a.count(&full_on_a),
    );
    log("sending SIGTERM to router-a's nos-ospfv3d; it must announce a grace period first");
    w.dock
        .signal_process("router-a", "nos-ospfv3d", "-TERM")
        .await?;
    a.wait("ospfv3 graceful restart: announcing grace period before shutdown grace_period=120")
        .await?;
    a.wait(&format!(
        "ospfv3 graceful restart: grace-lsa sent link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B} grace_period=120"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 helper: grace period entered link=eth0.0 neighbor={OSPFV3_ROUTER_ID} grace_period=120 restart_reason=1"
    ))
    .await?;

    // The watchdog respawns router-a; the fresh process resynchronizes with
    // the neighbor that held it Full the whole time.
    b.wait_new(&full_on_b, full_b_before, 90).await?;
    a.wait_new(&full_on_a, full_a_before, 90).await?;
    b.wait(&format!(
        "ospfv3 helper: neighbor reformed, exiting grace early link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    b.assert_quiet(torn, torn_before, 0).await?;
    b.assert_quiet(&removed, removed_before, 5).await
}

/// RFC 5340 §4.5.1 (#46): every Link-LSA (legacy 8 or RFC 8362 E-Link
/// 0x8028 — both may coexist after `ospfv3` toggled extended-lsa) router-c
/// holds from `router_id` must belong to the bridge link, the only link it
/// shares with that router — router-a/b also run `eth0.0` in the same area,
/// and its Link-LSA must never have been offered over the bridge.
async fn assert_only_broadcast_link_lsas(c: &Router, router_id: &str) -> anyhow::Result<()> {
    let body = c
        .rest_expect(Method::GET, "/v1/ospfv3/database", None, 200)
        .await?;
    let report: serde_json::Value = serde_json::from_str(&body)?;
    let rows = report[0]["result"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("ospfv3 database has no result: {body}"))?;
    let want = serde_json::json!(format!("broadcast-domain:{BD}"));
    let mut seen = 0;
    for row in rows {
        if row["advertising_router"] == router_id
            && matches!(row["lsa_type"].as_u64(), Some(8 | 0x8028))
        {
            seen += 1;
            if row["link"] != want {
                bail!("leaked link-local lsa from {router_id} on router-c: {row}");
            }
        }
    }
    if seen == 0 {
        bail!("router-c holds no link-lsa from {router_id} at all: {body}");
    }
    Ok(())
}

/// Reuses `ospf-dr`'s router-c and the same bd-ospf bridge (a BroadcastDomain
/// has independent `ospf_profile`/`ospfv3_profile` fields, so both protocols
/// run over one real bridge): the identical DR/BDR election and DrOther-Full
/// restriction, over the new address family. Then, with router-c `Full` to
/// both, that no Link-LSA from router-a/b's *other* link leaked onto the
/// bridge — right at `Full` (the DBD-summary path) and again after a
/// periodic full resend (`RXMT_INTERVAL`, the flood path).
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
    .await?;

    log("router-c holds only the bridge's own link-lsas (rfc 5340 §4.5.1)");
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID).await?;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID_B).await?;
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID).await?;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID_B).await
}

/// RFC 5286 loop-free alternate over OSPFv3 (requires `ospfv3-dr`, which puts
/// router-c on the shared bridge): router-a reaches router-b's loopback via b
/// itself (primary) or via c, whose own shortest path to b doesn't run back
/// through a. The backup is a link-local next hop, so `nos-ribd` must install
/// it with its own outgoing interface and at a metric *above* the primary's
/// (an IPv6 primary is 1024).
pub async fn ospfv3_lfa(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let prefix = OSPFV3_LFA_LOOPBACK_ADDRESS;
    let primary = format!("added route prefix={prefix}.*source=Some(Ospf) backup=false");
    let backup = format!("added route prefix={prefix}.*source=Some(Ospf) backup=true");
    let (p0, b0) = (a.count(&primary), a.count(&backup));
    b.provision(&[
        "--ospfv3-loopback-address",
        prefix,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait_new(&primary, p0, 60).await?;
    a.wait_new(&backup, b0, 60).await?;

    let removed = format!("removed route prefix={prefix}.*backup=true");
    let r0 = a.count(&removed);
    b.provision(&["--clear-ospfv3-loopback-profile"]).await?;
    a.wait_new(&removed, r0, 60).await
}

/// #157, RFC 2328 §14.1 (requires `ospfv3-dr`): router-a and router-c leave
/// the bridge, so router-b — its DR — loses its last `Full` neighbor there
/// and prematurely ages its Network-LSA (legacy 0x2002 or, after `ospfv3`
/// turned extended-lsa on, E-Network 0xa022); router-a, still adjacent over
/// `eth0.0`, flushes it within seconds instead of at `MaxAge` an hour later.
pub async fn ospfv3_flush(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    // `logs::bre` has top-level `\|` only, no `\( \)` groups.
    let either = |f: &dyn Fn(u16) -> String| format!(r"{}\|{}", f(0x2002), f(0xa022));
    let aged = either(&|t| format!("ospfv3 lsa prematurely aged lsa_type={t} "));
    let flushed = either(&|t| {
        format!(
            "ospfv3 lsa maxage flushed .*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID_B}"
        )
    });
    let (aged0, flushed0) = (b.count(&aged), a.count(&flushed));
    let leave = strings(&[
        "--broadcast-domain",
        BD,
        "--clear-ospfv3-broadcast-domain-profile",
    ]);
    a.provision(&leave).await?;
    c.provision_flags(&with_base(crate::router::C, leave))
        .await?;
    // Dead interval (40s) on router-b, then one origination tick.
    b.wait_new(&aged, aged0, 90).await?;
    a.wait_new(&flushed, flushed0, 60).await
}
