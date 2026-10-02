//! BGP phases: sessions, redistribution, authentication, RPL policy, and the
//! reflector / route-server topologies.

use std::time::Duration;

use anyhow::{bail, Context};
use reqwest::Method;

use crate::consts::*;
use crate::logs::bre;
use crate::router::{log, strings, Id, Router, A, B, C};
use crate::world::World;

/// `--static-route` + `--redistribute` flags: router-a (or a client) redistributes
/// `REDISTRIBUTE_PREFIX` from static into bgp.
pub(super) fn redistribute() -> Vec<&'static str> {
    vec![
        "--static-route",
        REDISTRIBUTE_PREFIX,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ]
}

/// The ASN router-a's export policy prepends twice in the `communities` phase.
const PREPEND_ASN: u32 = 64999;

fn loc_rib() -> String {
    format!("loc-rib best path for {REDISTRIBUTE_PREFIX} updated")
}

pub(super) fn learned() -> String {
    format!("learned route for {REDISTRIBUTE_PREFIX} into adj-rib-in")
}

/// Writes an RPL source file `nos-provision` reads on the host.
fn policy_file(name: &str, source: &str) -> anyhow::Result<String> {
    let path = std::env::temp_dir().join(format!("nos-e2e-{}-{name}.rpl", std::process::id()));
    std::fs::write(&path, source).with_context(|| format!("writing {}", path.display()))?;
    Ok(path.to_string_lossy().into_owned())
}

/// A *new* session after `baseline` (a config change restarts sessions).
async fn reestablished(r: &Router, baseline: usize) -> anyhow::Result<()> {
    r.wait_new("bgp session established", baseline, 60).await
}

pub async fn established(w: &mut World) -> anyhow::Result<()> {
    let waited = async {
        w.a()?.established().await?;
        w.b()?.established().await
    };
    if let Err(e) = waited.await {
        dump_bgp_state(w).await;
        return Err(e);
    }
    // RFC 8654: both nos-bgpd always advertise Extended Message, so each side
    // must have negotiated it with the other.
    w.a()?
        .wait("extended message negotiated extended_message=true")
        .await?;
    w.b()?
        .wait("extended message negotiated extended_message=true")
        .await
}

/// On an `established` timeout (#158): each router's port-179 sockets
/// (`/proc/net/tcp*` — the image has no `ss`; `00B3` is 179, `st` 02 is
/// SYN_SENT) and its recent BGP log lines, so a flake arrives with evidence.
async fn dump_bgp_state(w: &World) {
    for r in [w.a(), w.b()].into_iter().flatten() {
        let tcp = w
            .dock
            .exec(r.name(), &["cat", "/proc/net/tcp", "/proc/net/tcp6"])
            .await
            .map_or_else(|e| e.to_string(), |(_, out)| out);
        log(format!("{}: port 179 sockets:", r.name()));
        for l in tcp.lines().filter(|l| l.contains(":00B3")) {
            log(format!("  {l}"));
        }
        log(format!("{}: last bgp log lines:", r.name()));
        for l in r.logs.tail("bgp", 40) {
            log(format!("  {l}"));
        }
    }
}

pub async fn reconnect(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    log("killing router-b's nos-bgpd to force a hold-timer/reconnect cycle on router-a");
    w.dock.kill_process("router-b", "nos-bgpd").await?;
    a.wait_new(
        "outbound bgp session ended\\|inbound bgp session ended",
        0,
        120,
    )
    .await?;
    log("waiting for the watchdog to respawn router-b's nos-bgpd and re-establish");
    reestablished(b, base_b).await?;
    reestablished(a, base_a).await
}

pub async fn collision(w: &mut World) -> anyhow::Result<()> {
    // Baselines first: the sessions killed below already logged "established",
    // so the next phase must wait for a *new* one on each side or it provisions
    // a router whose restarted nos-bgpd has no session yet.
    let (base_a, base_b) = (
        w.a()?.count("bgp session established"),
        w.b()?.count("bgp session established"),
    );
    log("restarting both nos-bgpd processes at once to try to trigger a real collision");
    w.dock.kill_process("router-a", "nos-bgpd").await?;
    w.dock.kill_process("router-b", "nos-bgpd").await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Scoped to nos_bgp's own CollisionLost outcome — a bare "collision"
    // also hits rtnetlink's unrelated per-link packet-stat counter.
    let seen = w.a()?.count("nos_bgp::.*CollisionLost") + w.b()?.count("nos_bgp::.*CollisionLost");
    if seen > 0 {
        log("observed a collision-resolution log line");
    } else {
        log("no collision observed this cycle (timing-dependent, not a failure by itself)");
    }
    reestablished(w.a()?, base_a).await?;
    reestablished(w.b()?, base_b).await
}

pub async fn redistribute_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    // router-b has no static routes of its own here, so a new "added route" on
    // it can only be this BGP-learned route landing in its kernel table (rt1).
    let kernel_baseline = b.count("added route");
    a.provision(&redistribute()).await?;
    a.wait(&loc_rib()).await?;
    b.wait(&learned()).await?;
    b.wait(&loc_rib()).await?;
    b.wait_new("added route", kernel_baseline, 60).await
}

pub async fn auth(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let password = "correct-horse-battery-staple";
    // Baselines first: the matching-password change itself re-establishes the
    // session, and that (delayed) event must not count as a mismatched one.
    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    a.provision(&["--md5-password", password]).await?;
    b.provision(&["--md5-password", password]).await?;
    reestablished(a, base_a).await?;
    reestablished(b, base_b).await?;

    let (before_a, before_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    log("reconfiguring router-a with a mismatched md5 password");
    a.provision(&["--md5-password", "wrong-password"]).await?;
    log("waiting 8s to confirm the session does NOT (re-)establish with mismatched md5 passwords");
    a.assert_quiet("bgp session established", before_a, 8)
        .await?;
    if b.count("bgp session established") > before_b {
        bail!("session established despite mismatched md5 passwords");
    }

    log("restoring the matching md5 password on router-a");
    a.provision(&["--md5-password", password]).await?;
    reestablished(a, before_a).await
}

fn expect_body(body: &str, needle: &str) -> anyhow::Result<()> {
    if body.contains(needle) {
        Ok(())
    } else {
        bail!("body lacks '{needle}': {body}")
    }
}

/// RFC 5925 TCP-AO: `exclude_options` must match on both sides to establish,
/// `TCP_AO_INFO` readback surfaces sane current/rnext key ids, and a real
/// key-rollover sequence (add key 2 as rnext, promote it to current, remove
/// key 1) keeps authenticating throughout. Each config change here restarts
/// this peer's session — an auth change is an ordinary `ResolvedPeer` diff,
/// like a changed `remote_as` (see `bgp/CLAUDE.md`'s "Session
/// authentication") — so this proves the sequence keeps authenticating end
/// to end, not that the session survives without a reconnect.
pub async fn ao(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let secret = "correct-horse-battery-staple";

    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    for r in [a, b] {
        r.provision(&[
            "--ao-send-id",
            "1",
            "--ao-key-secret",
            secret,
            "--ao-current",
        ])
        .await?;
    }
    reestablished(a, base_a).await?;
    reestablished(b, base_b).await?;

    let (before_a, before_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    log("setting exclude-options on router-a only (mismatched with router-b)");
    a.provision(&[
        "--ao-send-id",
        "1",
        "--ao-key-secret",
        secret,
        "--ao-current",
        "--ao-exclude-options",
    ])
    .await?;
    log("waiting 8s to confirm the session does NOT (re-)establish with mismatched TCP-AO exclude-options");
    a.assert_quiet("bgp session established", before_a, 8)
        .await?;
    if b.count("bgp session established") > before_b {
        bail!("session established despite mismatched TCP-AO exclude-options");
    }

    log("matching exclude-options on router-b too");
    b.provision(&[
        "--ao-send-id",
        "1",
        "--ao-key-secret",
        secret,
        "--ao-current",
        "--ao-exclude-options",
    ])
    .await?;
    reestablished(a, before_a).await?;
    reestablished(b, before_b).await?;

    log("checking TCP_AO_INFO readback surfaces key 1 as current on both sides");
    expect_body(
        &a.rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?,
        "\"ao_current_key\":1",
    )?;
    expect_body(
        &b.rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?,
        "\"ao_current_key\":1",
    )?;

    log("rolling over to a second TCP-AO key (RFC 5925 §7.5)");
    let (before_a, before_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    for r in [a, b] {
        r.provision(&[
            "--ao-send-id",
            "2",
            "--ao-key-secret",
            "second-secret",
            "--ao-rnext",
            "--ao-exclude-options",
        ])
        .await?;
    }
    reestablished(a, before_a).await?;
    reestablished(b, before_b).await?;

    let (before_a, before_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    for r in [a, b] {
        r.provision(&["--ao-promote-current", "2"]).await?;
    }
    reestablished(a, before_a).await?;
    reestablished(b, before_b).await?;

    let (before_a, before_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    for r in [a, b] {
        r.provision(&["--ao-remove-key", "1"]).await?;
    }
    reestablished(a, before_a).await?;
    reestablished(b, before_b).await?;

    log("checking TCP_AO_INFO readback surfaces key 2 as current on both sides after rollover");
    expect_body(
        &a.rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?,
        "\"ao_current_key\":2",
    )?;
    expect_body(
        &b.rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?,
        "\"ao_current_key\":2",
    )
}

/// RFC 4456 route reflector: router-a reflects between router-b and router-c,
/// which are not peered with each other.
pub async fn reflector(w: &mut World) -> anyhow::Result<()> {
    let hub = |peer: &str| {
        strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            "pg1",
            "--remote-as",
            &ASN_A.to_string(),
            "--peer",
            peer,
            "--route-reflector-client",
            "--cluster-id",
            RID_A,
        ])
    };
    let client = |rid: &str, ip: &str| {
        strings(&[
            "--address",
            &format!("{ip}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            rid,
            "--remote-as",
            &ASN_A.to_string(),
            "--peer",
            IP_A,
        ])
    };
    w.start(A, Some(hub(IP_B)), &[]).await?;
    w.start(B, Some(client(RID_B, IP_B)), &[]).await?;
    w.start(C, Some(client(RID_C, IP_C)), &[]).await?;
    w.a()?.provision_flags(&hub(IP_C)).await?;

    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    for r in [a, b, c] {
        r.established().await?;
    }
    let mut flags = client(RID_B, IP_B);
    flags.extend(strings(&redistribute()));
    b.provision_flags(&flags).await?;
    log("waiting for router-c to learn the prefix purely via the reflector");
    c.wait(&learned()).await?;
    c.wait(&loc_rib()).await
}

/// RFC 7947 route server: router-a relays between two eBGP clients in distinct
/// ASes, transparently (its own ASN is never prepended).
pub async fn route_server(w: &mut World) -> anyhow::Result<()> {
    let hub = |pg: &str, remote_as: u32, peer: &str| {
        strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            pg,
            "--remote-as",
            &remote_as.to_string(),
            "--peer",
            peer,
            "--route-server-client",
        ])
    };
    // router-b sets a MED on export, so the hub has a received MED to pass
    // through (RFC 7947 §2.2). Seeded rather than provisioned: a later policy
    // change would restart the session.
    let med_file = policy_file(
        "route-server-med",
        &format!("set this.bgp.med = {MED}\naccept\n"),
    )?;
    let mut b_flags = B.base_flags();
    b_flags.extend(strings(&[
        "--policy-name",
        "route-server-med",
        "--policy-source-file",
        &med_file,
        "--export-policy",
        "route-server-med",
    ]));
    w.start(A, Some(hub("pg-b", ASN_B, IP_B)), &[]).await?;
    w.start(B, Some(b_flags.clone()), &[]).await?;
    w.start(C, None, &[]).await?;
    w.a()?.provision_flags(&hub("pg-c", ASN_C, IP_C)).await?;

    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    for r in [a, b, c] {
        r.established().await?;
    }
    // The policy flags stay: provision_flags replaces the whole flag list.
    b_flags.extend(strings(&redistribute()));
    b.provision_flags(&b_flags).await?;
    log("waiting for router-c to learn the prefix via the route server");
    c.wait(&learned()).await?;
    c.wait(&loc_rib()).await?;

    log("confirming router-c sees router-b's asn but not router-a's — rfc 7947 transparency");
    let line = c.logs.last(&loc_rib()).unwrap_or_default();
    if !line.contains(&format!("as_path=[{ASN_B}]")) || line.contains(&ASN_A.to_string()) {
        bail!("expected as_path [{ASN_B}] with no route-server asn prepended, got: {line}")
    }
    // No `next-hop` is provisioned: the route-server default is `unchanged`
    // (RFC 7947 §2.2.1), so router-c sees router-b's address, not the hub's.
    if !line.contains(&format!("next_hop=Some({IP_B})")) {
        bail!("expected next_hop {IP_B} passed through unchanged, got: {line}")
    }
    log("confirming router-c sees router-b's med — passed through by the route server");
    c.wait(&format!("{} .*med=Some({MED})", loc_rib())).await
}

/// An import policy on router-b rejecting the redistributed prefix, then reverted.
pub async fn policy(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let before = b.count(&learned());
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let file = policy_file(
        "reject-redistribute-prefix",
        // Neighbor context (`peer_as`) and an as-path regex, on a real
        // session: router-a's route arrives with the path [ASN_A] from ASN_A.
        &format!(
            "if this.bgp.peer_as == {ASN_A} and this.bgp.as_path.matches(\"^{ASN_A}$\"):\n    reject\nelse:\n    accept\n"
        ),
    )?;
    b.provision(&[
        "--policy-name",
        "reject-redistribute-prefix",
        "--policy-source-file",
        &file,
        "--import-policy",
        "reject-redistribute-prefix",
    ])
    .await?;
    // A genuinely new session: provisioning `redistribute` on router-a while
    // router-b's is still coming back up leaves both Idle on a retry timer.
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;

    a.provision(&redistribute()).await?;
    a.wait(&loc_rib()).await?;
    log("waiting 6s to confirm router-b's import policy rejects the prefix");
    b.assert_quiet(&learned(), before, 6).await?;

    log("reverting router-b's import policy to the accept-all default");
    let after = b.count(&learned());
    b.provision::<&str>(&[]).await?;
    b.wait_new(&learned(), after, 60).await
}

/// A policy on router-a's own `redistribute` rule: filtering must happen at the
/// redistribution point, before router-a's own loc-rib.
pub async fn redistribute_policy(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (before_a, before_b) = (a.count(&loc_rib()), b.count(&learned()));
    let file = policy_file(
        "reject-at-redistribute",
        &format!("if this.prefix in {REDISTRIBUTE_PREFIX}:\n    reject\nelse:\n    accept\n"),
    )?;
    let mut flags = redistribute();
    flags.extend([
        "--policy-name",
        "reject-at-redistribute",
        "--policy-source-file",
        &file,
        "--redistribute-policy",
        "reject-at-redistribute",
    ]);
    a.provision(&flags).await?;
    log("waiting 6s to confirm the redistribute policy filters the prefix at the source");
    tokio::time::sleep(Duration::from_secs(6)).await;
    let (after_a, after_b) = (a.count(&loc_rib()), b.count(&learned()));
    if after_a > before_a {
        bail!("router-a installed the prefix into its own loc-rib despite its redistribute policy");
    }
    if after_b > before_b {
        bail!("router-b learned the prefix despite router-a's redistribute policy");
    }

    log("reverting router-a's redistribute rule to accept-all (no policy)");
    a.provision(&redistribute()).await?;
    a.wait_new(&loc_rib(), after_a, 60).await?;
    b.wait_new(&learned(), after_b, 60).await
}

/// RFC 4271 §9.1.2 next-hop feasibility. Requires `ospf-spf` to have run:
/// router-b's loopback (`OSPF_SPF_LOOPBACK_ADDRESS`) exists but is out of OSPF
/// again, so router-a has no route to it. Router-b advertises `NHR_PREFIX` with
/// that loopback as NEXT_HOP (an export policy): router-a must see the
/// candidate and exclude it, then admit it once the loopback is back in OSPF
/// and its own SPF route makes the next hop resolvable — with no BGP event in
/// between, purely off the IGP poll. First checks that nos-ribd lists
/// router-a's own connected prefixes (its eth0 subnet and its ospf SVI's) as
/// `Connected` — what makes a directly-connected next hop resolvable at all.
/// The kernel side of the accepted route (a gateway that is itself only
/// reachable via another route — Linux has no recursive next hops) is out of
/// scope here.
pub async fn next_hop_reachability(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);

    for subnet in [SUBNET, OSPF_BROADCAST_SUBNET] {
        a.wait_connected(subnet).await?;
    }

    let next_hop = OSPF_SPF_LOOPBACK_ADDRESS
        .split('/')
        .next()
        .unwrap_or_default();
    let file = policy_file(
        "next-hop-loopback",
        &format!("set this.bgp.next_hop = {next_hop}\naccept\n"),
    )?;
    // Two commits: the export policy alone first (it restarts the session),
    // then the prefix. In one commit, nos-ribd's redistribution push can
    // reach the old session before the restart and announce the prefix under
    // the previous policy, with router-b's own (resolvable) address (#159).
    let policy = vec![
        "--policy-name",
        "next-hop-loopback",
        "--policy-source-file",
        &file,
        "--export-policy",
        "next-hop-loopback",
    ];
    let mut advertise = policy.clone();
    advertise.extend([
        "--static-route",
        NHR_PREFIX,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ]);
    let mut with_ospf = advertise.clone();
    with_ospf.extend(["--ospf-loopback-profile", OSPF_PROFILE]);
    let mut withdraw = advertise.clone();
    withdraw.extend([
        "--redistribute-policy",
        "deny-all",
        "--clear-ospf-loopback-profile",
    ]);

    let excluded = format!("candidate excluded, next hop unresolvable.*prefix={NHR_PREFIX}");
    let loc = format!("loc-rib best path for {NHR_PREFIX} updated");
    let via_loopback = format!("{loc}.*next_hop=Some({next_hop})");
    let (ex0, loc0, via0) = (a.count(&excluded), a.count(&loc), a.count(&via_loopback));
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    b.provision(&policy).await?;
    // A new export policy restarts router-b's session.
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    // Same policy, so no restart: the first UPDATE already carries the loopback.
    b.provision(&advertise).await?;
    a.wait(&format!("learned route for {NHR_PREFIX} into adj-rib-in"))
        .await?;
    a.wait_new(&excluded, ex0, 60).await?;
    log("waiting 6s to confirm router-a keeps the unfeasible route out of its loc-rib");
    a.assert_quiet(&loc, loc0, 6).await?;

    log("putting router-b's loopback back into ospf: the next hop becomes resolvable via spf");
    let route = format!("added route prefix={OSPF_SPF_LOOPBACK_ADDRESS}.*source=Some(Ospf)");
    let r0 = a.count(&route);
    b.provision(&with_ospf).await?;
    a.wait_new(&route, r0, 60).await?;
    a.wait_new(&via_loopback, via0, 60).await?;

    log("withdrawing the prefix and taking router-b's loopback out of ospf again");
    let withdrawn = format!("loc-rib route for {NHR_PREFIX} withdrawn");
    let w0 = a.count(&withdrawn);
    b.provision(&withdraw).await?;
    a.wait_new(&withdrawn, w0, 60).await?;
    // `ospf-lfa` puts the loopback back next and waits for a *new* install,
    // which never comes if the route is still up.
    a.wait_ospf_route_gone(OSPF_SPF_LOOPBACK_ADDRESS, 15).await
}

/// RFC 4271 §9.2.1.1 pacing: with `mrai 30` on router-a's peer-group, the first
/// advertisement of the prefix goes out at once, a withdrawal is never held,
/// and a re-advertisement seconds later is held until 30s after the first.
/// Flapped through router-a's redistribute policy, like `redistribute-policy`.
pub async fn mrai(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let withdrawn = format!("loc-rib route for {REDISTRIBUTE_PREFIX} withdrawn");
    let file = policy_file(
        "reject-for-mrai",
        &format!("if this.prefix in {REDISTRIBUTE_PREFIX}:\n    reject\nelse:\n    accept\n"),
    )?;
    let mut accept = redistribute();
    accept.extend(["--mrai", "30"]);
    let mut reject = accept.clone();
    reject.extend([
        "--policy-name",
        "reject-for-mrai",
        "--policy-source-file",
        &file,
        "--redistribute-policy",
        "reject-for-mrai",
    ]);

    // A new mrai restarts the session, so the first advertisement is a fresh one.
    let (est, learned_before) = (a.count("bgp session established"), b.count(&learned()));
    a.provision(&accept).await?;
    reestablished(a, est).await?;
    b.wait_new(&learned(), learned_before, 60).await?;

    log("withdrawing the prefix: must reach router-b at once, not after the mrai");
    let withdrawn_before = b.count(&withdrawn);
    a.provision(&reject).await?;
    b.wait_new(&withdrawn, withdrawn_before, 10).await?;

    log("re-advertising the prefix: must be held back until the mrai elapses");
    let learned_before = b.count(&learned());
    a.provision(&accept).await?;
    b.assert_quiet(&learned(), learned_before, 8).await?;
    b.wait_new(&learned(), learned_before, 40).await
}

/// RFC 2439 flap damping: router-a damps what it receives from router-b
/// (half-life 20s, suppress 2000, reuse 750). Router-b flaps its redistributed
/// prefix three times (via its redistribute policy) -> router-a suppresses it,
/// so a fourth announcement reaches adj-rib-in but never loc-rib, until the
/// penalty decays below reuse and the route is released.
pub async fn damping(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let withdrawn = format!("loc-rib route for {REDISTRIBUTE_PREFIX} withdrawn");
    let file = policy_file(
        "reject-for-damping",
        &format!("if this.prefix in {REDISTRIBUTE_PREFIX}:\n    reject\nelse:\n    accept\n"),
    )?;
    let accept = redistribute();
    let mut reject = accept.clone();
    reject.extend([
        "--policy-name",
        "reject-for-damping",
        "--policy-source-file",
        &file,
        "--redistribute-policy",
        "reject-for-damping",
    ]);

    // Earlier phases leave router-a redistributing the same prefix, and its own
    // `Local` copy outranks router-b's in best-path: router-b's flaps would then
    // never reach router-a's Loc-RIB. Reject it at router-a's source for the phase.
    let mut a_damped = reject.clone();
    a_damped.extend([
        "--damping-half-life",
        "20",
        "--damping-reuse",
        "750",
        "--damping-suppress",
        "2000",
        "--damping-max-suppress",
        "40",
    ]);
    let (est, own_withdrawn) = (a.count("bgp session established"), a.count(&withdrawn));
    a.provision(&a_damped).await?;
    reestablished(a, est).await?;
    a.wait_new(&withdrawn, own_withdrawn, 30).await?;

    log("flapping router-b's prefix three times: router-a must suppress it");
    let suppressed = format!("route suppressed by flap damping.*{REDISTRIBUTE_PREFIX}");
    let suppressed_before = a.count(&suppressed);
    for _ in 0..3 {
        let learned_before = a.count(&learned());
        b.provision(&accept).await?;
        a.wait_new(&learned(), learned_before, 30).await?;
        let withdrawn_before = a.count(&withdrawn);
        b.provision(&reject).await?;
        a.wait_new(&withdrawn, withdrawn_before, 30).await?;
    }
    a.wait_new(&suppressed, suppressed_before, 10).await?;

    log("announcing it again: learned into adj-rib-in, but held out of loc-rib");
    let (learned_before, loc_before) = (a.count(&learned()), a.count(&loc_rib()));
    b.provision(&accept).await?;
    a.wait_new(&learned(), learned_before, 30).await?;
    a.assert_quiet(&loc_rib(), loc_before, 8).await?;

    log("waiting for the penalty to decay below reuse: the route must be released");
    a.wait_new(
        &format!("route released from flap damping.*{REDISTRIBUTE_PREFIX}"),
        0,
        90,
    )
    .await?;
    a.wait_new(&loc_rib(), loc_before, 10).await?;

    log("removing damping from router-a's peer-group, redistributing its prefix again");
    let est = a.count("bgp session established");
    let mut a_restored = accept.clone();
    a_restored.push("--clear-damping");
    a.provision(&a_restored).await?;
    reestablished(a, est).await
}

/// RFC 4486 / RFC 9003 administrative shutdown: shutting router-a's peer-group,
/// then its one peer alone, must send router-b a Cease/Administrative Shutdown
/// carrying the operator's message, and keep the session down (router-b keeps
/// dialling, router-a refuses) until it is cleared; removing the peer from
/// router-a's config must send Cease/Peer De-configured.
pub async fn shutdown(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let sent = |subcode: u8| format!("sent cease notification peer=.* subcode={subcode}");
    let received = |subcode: u8, msg: &str| {
        format!("received notification peer=.* code=6 subcode={subcode} shutdown_message=.*{msg}")
    };
    let rejected = "rejecting inbound tcp connection from administratively shut peer";

    for (what, set, clear, msg) in [
        (
            "peer-group",
            "--shutdown-peer-group",
            "--unshutdown-peer-group",
            "group maintenance",
        ),
        (
            "peer",
            "--shutdown-peer",
            "--unshutdown-peer",
            "peer maintenance",
        ),
    ] {
        log(format!("shutting router-a's {what} with a message"));
        let (sent_before, recv_before, est_b, rej_before) = (
            a.count(&sent(2)),
            b.count(&received(2, msg)),
            b.count("bgp session established"),
            a.count(rejected),
        );
        a.provision(&[set, msg]).await?;
        a.wait_new(&sent(2), sent_before, 20).await?;
        b.wait_new(&received(2, msg), recv_before, 20).await?;
        // The session stays down: router-b keeps dialling, router-a refuses.
        a.wait_new(rejected, rej_before, 20).await?;
        b.assert_quiet("bgp session established", est_b, 10).await?;

        log(format!("clearing the {what} shutdown"));
        let (est_a, est_b) = (
            a.count("bgp session established"),
            b.count("bgp session established"),
        );
        a.provision(&[clear]).await?;
        reestablished(a, est_a).await?;
        reestablished(b, est_b).await?;
    }

    log("removing the peer from router-a's config: Cease / Peer De-configured");
    let recv_before = b.count(&received(3, ""));
    let est_b = b.count("bgp session established");
    a.edit(|config| {
        for instance in &mut config.bgp_instances {
            instance.peers.clear();
        }
        Ok(())
    })
    .await?;
    b.wait_new(&received(3, ""), recv_before, 20).await?;
    // The base flags upsert the peer again.
    a.provision::<&str>(&[]).await?;
    reestablished(b, est_b).await
}

/// An export policy tagging the prefix with an RFC 1997 community that must
/// survive encoding, the real session, and decoding into router-b's loc-rib.
pub async fn communities(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let (listener_a, listener_b) = (a.count("bgp listener bound"), b.count("bgp listener bound"));
    // Taken before any restart: nos-ribd's restart-triggered resend can land
    // within ~100ms of nos-bgpd's listener coming back.
    let local_a = format!("{} origin=Local", loc_rib());
    let before_local_a = a.count(&local_a);

    let file = policy_file(
        "tag-redistribute-with-community",
        // The prepend lands behind router-a's own ASN (added on export).
        &format!(
            "this.bgp.communities.add({COMMUNITY_AA}:{COMMUNITY_NN})\nthis.bgp.as_path.prepend({PREPEND_ASN}, 2)\nset this.bgp.med = {MED}\naccept\n"
        ),
    )?;
    let mut flags = redistribute();
    flags.extend([
        "--policy-name",
        "tag-redistribute-with-community",
        "--policy-source-file",
        &file,
        "--export-policy",
        "tag-redistribute-with-community",
    ]);
    a.provision(&flags).await?;

    // Then restart both sides, so the policy is resolved from each fresh
    // process's own startup config fetch with no Established session left. A
    // policy change on its own restarts the session, and can lose RFC 4271
    // §6.8 collision resolution against an already-Established connection —
    // which leaves both sides Idle on a connect-retry timer. (Applying the
    // policy *after* the restart races the first session coming back up.)
    // nos-ribd is killed too: its push connection to nos-bgpd is write-only,
    // so it only notices a dead peer on its next write, and a fresh connection
    // is what triggers the full re-send.
    log("restarting both sides' nos-bgpd (and router-a's nos-ribd)");
    w.dock.kill_process("router-a", "nos-bgpd").await?;
    w.dock.kill_process("router-a", "nos-ribd").await?;
    w.dock.kill_process("router-b", "nos-bgpd").await?;
    a.wait_new("bgp listener bound", listener_a, 60).await?;
    b.wait_new("bgp listener bound", listener_b, 60).await?;

    a.wait_new(&local_a, before_local_a, 60).await?;
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    // The tagged route can land a moment after the session is up.
    b.wait(&format!(
        "{} .*communities=\\[{COMMUNITY_PACKED}\\]",
        loc_rib()
    ))
    .await?;
    b.wait(&format!(
        "{} .*as_path=\\[{ASN_A}, {PREPEND_ASN}, {PREPEND_ASN}\\]",
        loc_rib()
    ))
    .await?;
    // An export-policy MED reaches an eBGP peer (RFC 4271 §5.1.4, #120).
    b.wait(&format!("{} .*med=Some({MED})", loc_rib())).await?;
    Ok(())
}

/// RFC 6793 against a real old speaker: ExaBGP with `asn4 disable` never sends
/// the four-octet AS capability, so router-a (ASN > 65535) must talk 2-byte
/// AS_PATH with AS_TRANS + AS4_PATH both ways.
///
/// Send: router-a redistributes a static route; its path is `[ASN_A4]`, which
/// ExaBGP must receive as AS_PATH `[23456]` plus AS4_PATH `[ASN_A4]`. Receive:
/// ExaBGP announces a route with AS_PATH `[65010 23456]` and an AS4_PATH
/// carrying `AS4_HIDDEN_ASN`; router-a's Loc-RIB must hold the merged path. The
/// same route carries ATOMIC_AGGREGATE and an AGGREGATOR/AS4_AGGREGATOR pair
/// (`AS4_AGGREGATOR_ASN`), which router-a must store merged (RFC 4271 §5.1.6,
/// RFC 6793 §4.2.3; re-advertisement is covered by unit tests).
pub async fn as4(w: &mut World) -> anyhow::Result<()> {
    let mut flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A4.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    flags.extend(redistribute().into_iter().map(str::to_string));
    w.start(A, Some(flags), &[]).await?;

    log("building/starting the 2-byte-AS ExaBGP speaker (router-g)");
    w.dock
        .ensure_image(
            EXABGP_IMAGE,
            &format!(
                "FROM ghcr.io/exa-networks/exabgp:{EXABGP_VERSION}\n\
                 ENV exabgp_daemon_daemonize=false exabgp_log_destination=stdout \\\n    \
                 exabgp_log_level=DEBUG exabgp_log_all=true\n"
            ),
        )
        .await?;
    // AS4_PATH (type 17, optional transitive): one AS_SEQUENCE of one ASN.
    let as4_value = format!("0201{AS4_HIDDEN_ASN:08X}");
    // AGGREGATOR (type 7, 2-byte AS = AS_TRANS) + AS4_AGGREGATOR (type 18), and
    // ATOMIC_AGGREGATE (type 6, empty): router-a must merge the real ASN.
    let agg_value = format!("{AS_TRANS:04X}C0000209");
    let as4_agg_value = format!("{AS4_AGGREGATOR_ASN:08X}C0000209");
    let conf = format!(
        "process rx {{\n    run /bin/sh -c \"cat > /tmp/rx.json\";\n    encoder json;\n}}\n\
         neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {AS_TRANS};\n    capability {{ asn4 disable; }}\n    \
         family {{ ipv4 unicast; }}\n    \
         api {{ processes [ rx ]; receive {{ parsed; update; }} }}\n    \
         static {{\n        route {AS4_LEARNED_PREFIX} next-hop {IP_G} \
         as-path [ {ASN_G} {AS_TRANS} ] atomic-aggregate \
         attribute [ 0x11 0xc0 0x{as4_value} ] \
         attribute [ 0x07 0xc0 0x{agg_value} ] attribute [ 0x12 0xc0 0x{as4_agg_value} ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;

    let a = w.a()?;
    a.established().await?;

    log("receive: ExaBGP's 2-byte AS_PATH + AS4_PATH must merge into the real path");
    a.wait(&format!(
        "loc-rib best path for {AS4_LEARNED_PREFIX} updated .*as_path=\\[{ASN_G}, {AS4_HIDDEN_ASN}\\]"
    ))
    .await?;

    log("receive: ATOMIC_AGGREGATE kept, AGGREGATOR merged with AS4_AGGREGATOR");
    a.wait(&format!(
        "learned route for {AS4_LEARNED_PREFIX} into adj-rib-in .*atomic_aggregate=true aggregator=Some(({AS4_AGGREGATOR_ASN}, {AS4_AGGREGATOR_ID}))"
    ))
    .await?;

    // ExaBGP 5.0.13 parses both attributes (its debug log shows them) and then
    // crashes in its own AS4_PATH merge (`'ASPath' object has no attribute
    // 'as_seq'`), answering with a NOTIFICATION — so the session flaps and the
    // wire bytes, as decoded by an independent implementation's parser, are
    // what we assert on instead of an API dump.
    log("send: router-a's redistributed route must reach ExaBGP as AS_TRANS + AS4_PATH");
    let as_path_wire = format!("as-path .* payload 0201 {AS_TRANS:04X}");
    let as4_path_wire = format!(
        "as4-path .* payload 0201 {:04X} {:04X}",
        ASN_A4 >> 16,
        ASN_A4 & 0xFFFF
    );
    let mut last = String::new();
    for _ in 0..30 {
        last = w.dock.logs("router-g").await?;
        let seen = |pat: &str| last.lines().any(|l| bre(pat).is_match(l));
        if seen(&as_path_wire) && seen(&as4_path_wire) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("ExaBGP never parsed AS_PATH [{AS_TRANS}] + AS4_PATH [{ASN_A4}]: {last}")
}

/// RFC 7606: an UPDATE whose COMMUNITY has a 3-byte value (malformed) must be
/// treated as a withdraw, not reset the session. ExaBGP announces such a route
/// beside a good one; router-a (no redistribution, so nothing that crashes
/// ExaBGP's AS4 merge, see `as4`) must learn only the good one and stay up.
pub async fn malformed_update(w: &mut World) -> anyhow::Result<()> {
    let flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    w.start(A, Some(flags), &[]).await?;
    w.dock
        .ensure_image(
            EXABGP_IMAGE,
            &format!(
                "FROM ghcr.io/exa-networks/exabgp:{EXABGP_VERSION}\n\
                 ENV exabgp_daemon_daemonize=false exabgp_log_destination=stdout \\\n    \
                 exabgp_log_level=DEBUG exabgp_log_all=true\n"
            ),
        )
        .await?;
    let conf = format!(
        "neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {ASN_A};\n    family {{ ipv4 unicast; }}\n    \
         static {{\n        route {AS4_LEARNED_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ];\n        \
         route {AS4_BAD_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ] \
         attribute [ 0x08 0xc0 0x010203 ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;
    let a = w.a()?;
    a.established().await?;
    let established = a.count("bgp session established");
    a.wait(&format!(
        "loc-rib best path for {AS4_LEARNED_PREFIX} updated"
    ))
    .await?;
    a.wait("treating announced routes as withdrawn").await?;
    anyhow::ensure!(
        a.count(&format!("loc-rib best path for {AS4_BAD_PREFIX}")) == 0,
        "router-a learned {AS4_BAD_PREFIX} despite its malformed COMMUNITY"
    );
    anyhow::ensure!(
        a.count("bgp session established") == established,
        "the malformed UPDATE reset the session"
    );
    Ok(())
}

/// RFC 5065 confederation (#15): router-a (member AS `CONFED_ASN_A`) and
/// router-b (`CONFED_ASN_B`) form confederation `CONFED_ID` and peer as
/// confederation-external; ExaBGP (router-g) is outside it and peers router-a
/// with `peer-as CONFED_ID`, so the session coming up proves router-a's OPEN
/// carries the identifier. Then: ExaBGP's route reaches router-b behind an
/// AS_CONFED_SEQUENCE of router-a's member AS; router-b's redistributed route
/// reaches router-a the same way and ExaBGP with only the identifier
/// (asserted on ExaBGP's parser log, like `as4`); a path holding the
/// identifier is a loop; and a confed segment from ExaBGP is treat-as-withdraw
/// without resetting the session.
pub async fn confederation(w: &mut World) -> anyhow::Result<()> {
    let confed = |own: u32, peer: u32| {
        strings(&[
            "--confederation-id",
            &CONFED_ID.to_string(),
            "--confederation-peer",
            &peer.to_string(),
            "--asn",
            &own.to_string(),
        ])
    };
    let mut a_flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--router-id",
        RID_A,
        "--peer-group",
        "pg-b",
        "--remote-as",
        &CONFED_ASN_B.to_string(),
        "--peer",
        IP_B,
    ]);
    a_flags.extend(confed(CONFED_ASN_A, CONFED_ASN_B));
    let mut b_flags = strings(&[
        "--address",
        &format!("{IP_B}/24"),
        "--router-id",
        RID_B,
        "--remote-as",
        &CONFED_ASN_A.to_string(),
        "--peer",
        IP_A,
    ]);
    b_flags.extend(confed(CONFED_ASN_B, CONFED_ASN_A));
    b_flags.extend(strings(&redistribute()));
    w.start(A, Some(a_flags), &[]).await?;
    w.start(B, Some(b_flags), &[]).await?;
    let mut g_flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--router-id",
        RID_A,
        "--peer-group",
        "pg-g",
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    g_flags.extend(confed(CONFED_ASN_A, CONFED_ASN_B));
    w.a()?.provision_flags(&g_flags).await?;

    w.dock
        .ensure_image(
            EXABGP_IMAGE,
            &format!(
                "FROM ghcr.io/exa-networks/exabgp:{EXABGP_VERSION}\n\
                 ENV exabgp_daemon_daemonize=false exabgp_log_destination=stdout \\\n    \
                 exabgp_log_level=DEBUG exabgp_log_all=true\n"
            ),
        )
        .await?;
    // ExaBGP's config syntax has no way to write a confed segment (`{` opens
    // a block), so the bad route carries a raw AS_PATH: AS_CONFED_SEQUENCE
    // [65109] then AS_SEQUENCE [ASN_G].
    let bad_as_path = format!("0301{:08X}0201{ASN_G:08X}", 65109);
    let conf = format!(
        "neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {CONFED_ID};\n    family {{ ipv4 unicast; }}\n    \
         static {{\n        route {CONFED_LEARNED_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ];\n        \
         route {CONFED_LOOP_PREFIX} next-hop {IP_G} as-path [ {ASN_G} {CONFED_ID} ];\n        \
         route {CONFED_BAD_PREFIX} next-hop {IP_G} attribute [ 0x02 0x40 0x{bad_as_path} ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;

    let (a, b) = (w.a()?, w.b()?);
    log("member ASes in OPEN between router-a and router-b, the identifier toward ExaBGP");
    b.wait(&format!(
        "bgp session established peer={IP_A} remote_asn={CONFED_ASN_A}"
    ))
    .await?;
    a.wait(&format!(
        "bgp session established peer={IP_G} remote_asn={ASN_G}"
    ))
    .await?;
    let established = a.count("bgp session established");

    log("ExaBGP's route reaches router-b behind router-a's member AS, as a confed segment");
    b.wait(&format!(
        "loc-rib best path for {CONFED_LEARNED_PREFIX} updated .*as_path=\\[({CONFED_ASN_A}), {ASN_G}\\] .*next_hop=Some({IP_G})"
    ))
    .await?;
    log("router-b's route reaches router-a as a confed segment");
    a.wait(&format!("{} .*as_path=\\[({CONFED_ASN_B})\\]", loc_rib()))
        .await?;

    log("a path holding the confederation identifier is a loop");
    a.wait(&format!(
        "dropping bgp update: as_path already contains our own asn .*peer={IP_G} as_path=\\[{ASN_G}, {CONFED_ID}\\]"
    ))
    .await?;
    log("a confed segment from outside the confederation is treat-as-withdraw");
    a.wait(&format!(
        "treating bgp update as withdraw: as_path has confederation segments .*peer={IP_G}"
    ))
    .await?;
    for p in [CONFED_LOOP_PREFIX, CONFED_BAD_PREFIX] {
        anyhow::ensure!(
            a.count(&format!("loc-rib best path for {p}")) == 0,
            "router-a installed {p}"
        );
    }
    anyhow::ensure!(
        a.count("bgp session established") == established,
        "a confederation check reset a session"
    );

    log("ExaBGP sees router-b's route with only the identifier: AS_SEQUENCE [65100]");
    // `len 0x06`: one segment holding one ASN, nothing else.
    let identifier_only = format!(
        "as-path .* len 0x06 payload 0201 {:04X} {:04X}",
        CONFED_ID >> 16,
        CONFED_ID & 0xFFFF
    );
    let mut last = String::new();
    for _ in 0..30 {
        last = w.dock.logs("router-g").await?;
        let as_paths: Vec<&str> = last
            .lines()
            .filter(|l| bre("as-path .* payload").is_match(l))
            .collect();
        if as_paths.iter().any(|l| bre(&identifier_only).is_match(l)) {
            // A member AS or a confed segment type would mean a leak.
            let leak = as_paths.iter().find(|l| {
                l.contains(&format!("{CONFED_ASN_A:04X}"))
                    || l.contains(&format!("{CONFED_ASN_B:04X}"))
                    || l.contains("payload 03")
                    || l.contains("payload 04")
            });
            if let Some(l) = leak {
                bail!("router-a leaked the confederation to ExaBGP: {l}");
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("ExaBGP never parsed AS_PATH [{CONFED_ID}]: {last}")
}

/// RFC 4486 §4 maximum-prefix (#79): ExaBGP (router-g) announces
/// `MAX_PREFIX_ROUTES` (3) IPv4 routes to router-a, whose peer-group allows
/// fewer. A trip closes the session with Cease subcode 1 and holds the peer
/// down until a REST clear or a shut/no-shut; raising the limit lets the
/// routes in; `warning-only` only logs; a restart interval retries by itself.
pub async fn maximum_prefix(w: &mut World) -> anyhow::Result<()> {
    let base = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    let with = |extra: &[&str]| {
        let mut f = base.clone();
        f.extend(strings(extra));
        f
    };
    w.start(A, Some(with(&["--maximum-prefix", "ipv4=2"])), &[])
        .await?;
    w.dock
        .ensure_image(
            EXABGP_IMAGE,
            &format!(
                "FROM ghcr.io/exa-networks/exabgp:{EXABGP_VERSION}\n\
                 ENV exabgp_daemon_daemonize=false exabgp_log_destination=stdout \\\n    \
                 exabgp_log_level=DEBUG exabgp_log_all=true\n"
            ),
        )
        .await?;
    let routes = MAX_PREFIX_ROUTES
        .map(|p| format!("        route {p} next-hop {IP_G} as-path [ {ASN_G} ];\n"))
        .concat();
    let conf = format!(
        "neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {ASN_A};\n    family {{ ipv4 unicast; }}\n    \
         static {{\n{routes}    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;
    let a = w.a()?;
    let est = "bgp session established";
    let tripped = "maximum prefix limit exceeded.*family=ipv4 count=3 limit=2 warning_only=false";
    let cease1 = "sent cease notification peer=.* subcode=1";
    let summary = || a.rest_expect(Method::GET, "/v1/bgp/summary", None, 200);

    log("limit 2: the third prefix trips it, and the peer stays down");
    a.wait(tripped).await?;
    a.wait(cease1).await?;
    let held_since = a.count(est);
    a.assert_quiet(est, held_since, 12).await?;
    anyhow::ensure!(
        summary().await?.contains("\"max_prefix_held\":true"),
        "show bgp brief does not report the max-prefix hold"
    );

    log("a REST clear releases the hold; ExaBGP still sends 3, so it trips again");
    let ceases = a.count(cease1);
    a.rest_expect(
        Method::POST,
        &format!("/v1/bgp/r1/peer/{IP_G}/clear"),
        None,
        200,
    )
    .await?;
    a.wait_new(est, held_since, 30).await?;
    a.wait_new(cease1, ceases, 30).await?;

    log("a shutdown and un-shutdown releases it too");
    let (est_before, ceases) = (a.count(est), a.count(cease1));
    a.provision_flags(&with(&["--shutdown-peer-group", ""]))
        .await?;
    a.provision_flags(&with(&["--unshutdown-peer-group"]))
        .await?;
    a.wait_new(est, est_before, 30).await?;
    a.wait_new(cease1, ceases, 30).await?;

    log("limit 5: all three routes are learned, no cease");
    let (est_before, ceases) = (a.count(est), a.count(cease1));
    a.provision_flags(&with(&["--maximum-prefix", "ipv4=5"]))
        .await?;
    a.wait_new(est, est_before, 30).await?;
    let mut counted = false;
    for _ in 0..30 {
        if summary().await?.contains("\"accepted_prefixes\":[3,0,0]") {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(
        counted,
        "show bgp brief never counted the 3 accepted prefixes"
    );
    a.assert_quiet(cease1, ceases, 8).await?;

    log("limit 2 warning-only: a warning, the session stays up");
    let (est_before, ceases) = (a.count(est), a.count(cease1));
    let warned = "maximum prefix limit exceeded.*count=3 limit=2 warning_only=true";
    let warned_before = a.count(warned);
    a.provision_flags(&with(&[
        "--maximum-prefix",
        "ipv4=2",
        "--maximum-prefix-warning-only",
    ]))
    .await?;
    a.wait_new(est, est_before, 30).await?;
    a.wait_new(warned, warned_before, 30).await?;
    let est_now = a.count(est);
    a.assert_quiet(cease1, ceases, 10).await?;
    anyhow::ensure!(a.count(est) == est_now, "warning-only reset the session");

    log("limit 2 restart-interval 5: it trips and retries by itself");
    let ceases = a.count(cease1);
    a.provision_flags(&with(&[
        "--maximum-prefix",
        "ipv4=2",
        "--maximum-prefix-restart-interval",
        "5",
    ]))
    .await?;
    a.wait_new(cease1, ceases + 1, 40).await?;
    Ok(())
}

/// StayRTR's VRP file (`-cache`): one VRP for `REDISTRIBUTE_PREFIX`.
fn rpki_vrps(asn: u32) -> String {
    format!(
        "{{\"roas\":[{{\"prefix\":\"{REDISTRIBUTE_PREFIX}\",\"maxLength\":24,\"asn\":\"AS{asn}\"}}]}}\n"
    )
}

/// RFC 6811 origin validation fed over RFC 8210 by a real cache (StayRTR,
/// self-contained): router-a validates router-b's redistributed prefix and
/// its import policy rejects `rpki.invalid`.
///
/// - router-a's preferred cache doesn't answer; it fails over to StayRTR;
/// - the VRP set authorizes another AS: the prefix is invalid, not learned;
/// - the VRP file changes: StayRTR's Serial Notify brings the new set, router-a
///   asks router-b for a route refresh and learns it as valid — no session reset;
/// - StayRTR goes away: after its 10s expire interval the VRPs are dropped and
///   the prefix is not-found (still accepted).
pub async fn rpki(w: &mut World) -> anyhow::Result<()> {
    w.dock.ensure_pulled(STAYRTR_IMAGE).await?;
    w.ensure_network().await?;
    w.dock
        .start_plain(
            RPKI_CACHE,
            STAYRTR_IMAGE,
            NET,
            IP_RPKI,
            &[
                "-cache",
                "/vrps.json",
                "-checktime=false",
                "-refresh",
                "2",
                // Refresh well inside the 10s expire, or a healthy session's
                // VRPs would expire between two serial queries.
                "-rtr.refresh",
                "4",
                "-rtr.retry",
                "2",
                "-rtr.expire",
                "10",
                "-bind",
                ":323",
            ],
            ("/", "vrps.json", rpki_vrps(RPKI_WRONG_ASN).as_bytes()),
        )
        .await?;
    let policy = policy_file(
        "rpki-reject-invalid",
        "if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n",
    )?;
    let mut a_flags = A.base_flags();
    a_flags.extend(strings(&[
        "--policy-name",
        "rpki-reject-invalid",
        "--policy-source-file",
        &policy,
        "--import-policy",
        "rpki-reject-invalid",
        "--rpki-cache",
        &format!("{IP_RPKI_DEAD}:323"),
        "--rpki-cache",
        &format!("{IP_RPKI}:323"),
    ]));
    let mut b_flags = B.base_flags();
    b_flags.extend(strings(&redistribute()));
    w.start(A, Some(a_flags), &[]).await?;
    w.start(B, Some(b_flags), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let cache = format!("cache={IP_RPKI}:323");

    log("the preferred cache never answers: router-a fails over to StayRTR");
    a.wait(&format!("rpki cache unreachable cache={IP_RPKI_DEAD}:323"))
        .await?;
    a.wait(&format!("rpki cache connected {cache} version=1"))
        .await?;
    a.wait(&format!("rpki end of data {cache} .*vrps=1"))
        .await?;
    a.established().await?;
    let summary = a
        .rest_expect(Method::GET, "/v1/bgp/rpki", None, 200)
        .await?;
    anyhow::ensure!(
        summary.contains(&format!(
            "\"address\":\"{IP_RPKI}\",\"port\":323,\"preference\":1,\"state\":\"Established\",\"active\":true,\"version\":1"
        )) && summary.contains("\"vrp_count\":1"),
        "GET /v1/bgp/rpki does not show the StayRTR session in use: {summary}"
    );

    log(format!(
        "VRPs authorize AS{RPKI_WRONG_ASN}: router-b's prefix is invalid and rejected"
    ));
    b.wait(&loc_rib()).await?;
    // It can reach router-a before the first End of Data (then it is
    // not-found, accepted, and only dropped by the route refresh that follows
    // the VRP change): wait until rt1 no longer holds it from BGP.
    let mut gone = false;
    for _ in 0..30 {
        if !a.rt1_has(REDISTRIBUTE_PREFIX, "Bgp").await? {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(gone, "router-a still holds the invalid route");
    let learned_before = a.count(&learned());
    a.assert_quiet(&learned(), learned_before, 8).await?;

    log(format!(
        "the VRP file now authorizes AS{ASN_B}: serial update, route refresh, learned as valid"
    ));
    // From here on the session must never reset (the start-up one may have
    // flapped once already: that is router-b provisioning, not RPKI).
    let mut peers = String::new();
    for _ in 0..30 {
        peers = a
            .rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?;
        if peers.contains("\"state\":\"Established\"") {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(
        peers.contains("\"state\":\"Established\""),
        "the session with router-b is not up: {peers}"
    );
    let sessions = a.count("bgp session established");
    let refreshes = a.count("rpki change: requesting route refresh");
    let valid = format!("{} .*validation_state=Valid", learned());
    let valid_before = a.count(&valid);
    w.dock
        .upload(RPKI_CACHE, "/", "vrps.json", rpki_vrps(ASN_B).as_bytes())
        .await?;
    a.wait(&format!("rpki end of data {cache} .*serial=1 vrps=1"))
        .await?;
    a.wait_new(
        &format!("rpki change: requesting route refresh .*peer={IP_B}"),
        refreshes,
        30,
    )
    .await?;
    a.wait_new(&valid, valid_before, 30).await?;

    log("StayRTR goes away: its VRPs expire after 10s and the prefix is not-found");
    let not_found = format!("{} .*validation_state=NotFound", learned());
    let not_found_before = a.count(&not_found);
    let refreshes = a.count("rpki change: requesting route refresh");
    w.dock.container_remove(RPKI_CACHE).await;
    a.wait("rpki data expired").await?;
    a.wait_new(
        &format!("rpki change: requesting route refresh .*peer={IP_B}"),
        refreshes,
        30,
    )
    .await?;
    a.wait_new(&not_found, not_found_before, 30).await?;
    anyhow::ensure!(
        a.count("bgp session established") == sessions,
        "a VRP change reset the BGP session"
    );
    Ok(())
}

/// GoBGP release image, built once — same recipe as `tools/bench-bgp.sh`.
fn gobgp_dockerfile() -> String {
    format!(
        "FROM debian:bookworm-slim\n\
         RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \\\n \
         && curl -fsSL https://github.com/osrg/gobgp/releases/download/v{GOBGP_VERSION}/gobgp_{GOBGP_VERSION}_linux_amd64.tar.gz \\\n \
         | tar -xz -C /usr/local/bin gobgp gobgpd \\\n \
         && apt-get purge -y --auto-remove curl && rm -rf /var/lib/apt/lists/*\n"
    )
}

/// Runs one `gobgp` CLI command inside the GoBGP container; its output.
async fn gobgp(w: &World, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = vec!["gobgp"];
    cmd.extend_from_slice(args);
    let (code, out) = w.dock.exec("router-g", &cmd).await?;
    if code != 0 {
        bail!("gobgp {}: exit {code}: {}", args.join(" "), out.trim());
    }
    Ok(out)
}

/// router-a's flags for both EVPN phases: one eBGP peer-group toward GoBGP
/// with `address-family l2vpn-evpn`.
fn evpn_flags() -> Vec<String> {
    strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--peer-group",
        "pg-evpn",
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
        "--evpn",
    ])
}

/// Starts router-a with `evpn_flags` (and `watchdog_args`), builds/starts the GoBGP speaker
/// (router-g) peering it over l2vpn-evpn, and waits for the session and
/// gobgpd's gRPC API.
async fn evpn_speaker(w: &mut World, watchdog_args: &[&str]) -> anyhow::Result<()> {
    w.start(A, Some(evpn_flags()), watchdog_args).await?;

    log("building/starting the GoBGP speaker (router-g)");
    w.dock
        .ensure_image(GOBGP_IMAGE, &gobgp_dockerfile())
        .await?;
    let conf = format!(
        "[global.config]\n  as = {ASN_G}\n  router-id = \"{RID_G}\"\n\n\
         [[neighbors]]\n  [neighbors.config]\n    neighbor-address = \"{IP_A}\"\n    peer-as = {ASN_A}\n  \
         [neighbors.transport.config]\n    local-address = \"{IP_G}\"\n  \
         [neighbors.timers.config]\n    connect-retry = 5\n  \
         [[neighbors.afi-safis]]\n    [neighbors.afi-safis.config]\n      afi-safi-name = \"l2vpn-evpn\"\n"
    );
    w.dock
        .start_plain(
            "router-g",
            GOBGP_IMAGE,
            NET,
            IP_G,
            &["gobgpd", "-f", "/etc/gobgpd.toml"],
            ("/etc", "gobgpd.toml", conf.as_bytes()),
        )
        .await?;

    let a = w.a()?;
    a.established().await?;
    // gobgpd's gRPC API can lag its BGP listener by a moment.
    let mut ready = Err(anyhow::anyhow!("gobgpd never answered"));
    for _ in 0..30 {
        ready = gobgp(w, &["global"]).await.map(drop);
        if ready.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    ready
}

/// RFC 7432 EVPN, receive side. No NOS router originates EVPN yet, so an
/// independent implementation does: GoBGP announces one MAC/IP (Type 2) and
/// one Inclusive Multicast (Type 3) route, with a Route Target and the VXLAN
/// Encapsulation community, to router-a. Router-a must negotiate AFI 25 /
/// SAFI 70 (its peer-group's only family besides IPv4 unicast), decode both,
/// hold them per peer, serve them on `show bgp evpn`, and drop them on an
/// explicit withdrawal and, for what is left, when the session goes away.
pub async fn evpn(w: &mut World) -> anyhow::Result<()> {
    evpn_speaker(w, &[]).await?;
    let a = w.a()?;

    let (mac, ip, rd, rt) = ("aa:bb:cc:00:00:01", "192.0.2.10", "65010:1", "65010:10000");
    gobgp(
        w,
        &[
            "global", "rib", "add", "-a", "evpn", "macadv", mac, ip, "etag", "0", "label", "10000",
            "rd", rd, "rt", rt, "encap", "vxlan",
        ],
    )
    .await?;
    gobgp(
        w,
        &[
            "global",
            "rib",
            "add",
            "-a",
            "evpn",
            "multicast",
            IP_G,
            "etag",
            "0",
            "rd",
            rd,
            "rt",
            rt,
            "encap",
            "vxlan",
        ],
    )
    .await?;

    let learned = |t: u8| format!("evpn route learned peer={IP_G} route_type={t}");
    let withdrawn = |t: u8| format!("evpn route withdrawn peer={IP_G} route_type={t}");
    a.wait(&learned(2)).await?;
    a.wait(&learned(3)).await?;

    // `show bgp evpn`, over REST: NLRI fields, Route Target and VXLAN encap
    // all decoded from another implementation's encoding.
    let show = || a.rest_expect(reqwest::Method::GET, "/v1/bgp/evpn", None, 200);
    let body = show().await?;
    for want in [
        "\"route_type\":2",
        "\"route_type\":3",
        mac,
        ip,
        rd,
        "RT:65010:10000",
        "encap:8",
    ] {
        if !body.contains(want) {
            bail!("show bgp evpn is missing {want}: {body}");
        }
    }

    log("withdrawing the Type-2 route explicitly");
    let base = a.count(&withdrawn(2));
    gobgp(
        w,
        &[
            "global", "rib", "del", "-a", "evpn", "macadv", mac, ip, "etag", "0", "label", "10000",
            "rd", rd,
        ],
    )
    .await?;
    a.wait_new(&withdrawn(2), base, 30).await?;
    let body = show().await?;
    if body.contains("\"route_type\":2") || !body.contains("\"route_type\":3") {
        bail!("expected only the Type-3 route after the withdrawal: {body}");
    }

    log("removing the speaker: its remaining route must go with the session");
    let base = a.count(&withdrawn(3));
    w.dock.container_remove("router-g").await;
    a.wait_new(&withdrawn(3), base, 60).await?;
    let body = show().await?;
    if body.contains("\"route_type\"") {
        bail!("EVPN routes outlived their session: {body}");
    }
    Ok(())
}

/// Reads the real bridge port `dev` back, in `container`'s netns, until its
/// unicast and multicast flood flags are both `on`.
async fn bridge_port_flood(w: &World, container: &str, dev: &str, on: bool) -> anyhow::Result<()> {
    let want = if on { "on" } else { "off" };
    let mut last = String::new();
    for _ in 0..30 {
        last = w
            .dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                container,
                &["bridge", "-d", "link", "show", "dev", dev],
            )
            .await?;
        if last.contains(&format!(" flood {want}")) && last.contains(&format!("mcast_flood {want}"))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("bridge port {dev} never read flood {want}: {last}")
}

async fn gobgp_owned(w: &World, args: Vec<String>) -> anyhow::Result<String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    gobgp(w, &refs).await
}

/// Runs an iproute2 command inside router-a's network namespace.
async fn netns_a(w: &World, cmd: &[&str]) -> anyhow::Result<String> {
    w.dock.in_netns(NETNS_HELPER_IMAGE, "router-a", cmd).await
}

/// Polls GoBGP's EVPN RIB until `want(rib)` holds.
async fn gobgp_evpn_rib(w: &World, what: &str, want: impl Fn(&str) -> bool) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..30 {
        last = gobgp(w, &["global", "rib", "-a", "evpn"]).await?;
        if want(&last) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("GoBGP's EVPN RIB never {what}: {last}")
}

/// `nos-fdbd`, both directions, against GoBGP as the remote VTEP. A broadcast
/// domain with a VNI, RD, import/export Route Targets, a VTEP source and
/// `redistribute from mac to bgp` gets a real VXLAN device on its bridge.
///
/// Remote -> kernel: GoBGP's Type-3 becomes a flood entry, its Type-2 (with a
/// matching Route Target) a remote MAC; a Type-2 with another Route Target is
/// ignored; a withdrawal removes the MAC. Local -> BGP: a MAC pinned on a
/// port of the domain's bridge (by a helper container in router-a's netns —
/// the runtime image has no iproute2) is originated as a Type-2, next to the
/// domain's Type-3, and GoBGP sees both; removing it withdraws it. Finally
/// unsetting the VNI must stop `nos-fdbd` and delete the VXLAN device.
///
/// Type-2 with an IP: GoBGP's `macadv <mac> <ip>` also becomes a kernel
/// neighbour on the bridge (`remote neighbour installed`); `redistribute from
/// connected` originates the domain's SVI address with the bridge's MAC, and
/// `redistribute from arp` an ARP binding pinned on the bridge (`ip neigh add
/// ... nud permanent`) for a MAC behind a local port — both seen by GoBGP.
pub async fn evpn_fdb(w: &mut World) -> anyhow::Result<()> {
    evpn_speaker(w, &[]).await?;
    let a = w.a()?;

    let mut flags = evpn_flags();
    flags.extend(strings(&[
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-vni",
        &EVPN_VNI.to_string(),
        "--evpn-rd",
        EVPN_RD,
        "--evpn-rt-import",
        EVPN_RT_IMPORT,
        "--evpn-rt-export",
        EVPN_RT_EXPORT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-redistribute-bgp",
        "r1",
        "--evpn-redistribute-arp-bgp",
        "r1",
        "--evpn-redistribute-connected-bgp",
        "r1",
        "--broadcast-domain-svi-address",
        EVPN_SVI_ADDRESS,
    ]));
    a.provision_flags(&flags).await?;
    let vxlan = format!("vx{EVPN_VNI}");
    a.wait(&format!(
        "vxlan device ready domain={EVPN_DOMAIN} vni={EVPN_VNI} vxlan={vxlan}"
    ))
    .await?;

    log("remote -> kernel: GoBGP originates a Type-3 and Type-2 routes");
    let (rd_g, rt_g) = ("65010:1", EVPN_RT_IMPORT);
    gobgp(
        w,
        &[
            "global",
            "rib",
            "add",
            "-a",
            "evpn",
            "multicast",
            IP_G,
            "etag",
            "0",
            "rd",
            rd_g,
            "rt",
            rt_g,
            "encap",
            "vxlan",
        ],
    )
    .await?;
    a.wait(&format!(
        "flood entry installed domain={EVPN_DOMAIN} vtep={IP_G}"
    ))
    .await?;
    let macadv = |verb: &'static str, mac: &'static str, rt: &'static str| {
        let vni = EVPN_VNI.to_string();
        let mut v = strings(&[
            "global",
            "rib",
            verb,
            "-a",
            "evpn",
            "macadv",
            mac,
            EVPN_REMOTE_IP,
            "etag",
            "0",
            "label",
            &vni,
            "rd",
            rd_g,
        ]);
        if verb == "add" {
            v.extend(strings(&["rt", rt, "encap", "vxlan"]));
        }
        v
    };
    let installed =
        |mac: &str| format!("remote mac installed domain={EVPN_DOMAIN} mac={mac} vtep={IP_G}");
    let removed =
        |mac: &str| format!("remote mac removed domain={EVPN_DOMAIN} mac={mac} vtep={IP_G}");

    let other_base = a.count(&installed(EVPN_OTHER_RT_MAC));
    gobgp_owned(w, macadv("add", EVPN_OTHER_RT_MAC, "65010:99")).await?;
    gobgp_owned(w, macadv("add", EVPN_REMOTE_MAC, rt_g)).await?;
    a.wait(&installed(EVPN_REMOTE_MAC)).await?;
    // Its IP is a kernel neighbour on the bridge too.
    let neigh_installed = format!(
        "remote neighbour installed domain={EVPN_DOMAIN} mac={EVPN_REMOTE_MAC} ip={EVPN_REMOTE_IP} vtep={IP_G}"
    );
    a.wait(&neigh_installed).await?;
    // Same UPDATE cadence as the accepted route, so a few seconds is proof.
    a.assert_quiet(&installed(EVPN_OTHER_RT_MAC), other_base, 5)
        .await?;

    log("`show fdb` over REST reflects the kernel-facing table");
    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    for want in [EVPN_REMOTE_MAC, EVPN_REMOTE_IP, IP_G, &vxlan] {
        if !body.contains(want) {
            bail!("show fdb is missing {want}: {body}");
        }
    }
    if body.contains(EVPN_OTHER_RT_MAC) {
        bail!("a route with a foreign Route Target reached the fdb: {body}");
    }
    let fdb: serde_json::Value = serde_json::from_str(&body)?;
    let bridge = fdb["bridge"]
        .as_str()
        .context("show fdb has no bridge name")?
        .to_string();

    log("a withdrawal removes the MAC again");
    let base = a.count(&removed(EVPN_REMOTE_MAC));
    gobgp_owned(w, macadv("del", EVPN_REMOTE_MAC, rt_g)).await?;
    a.wait_new(&removed(EVPN_REMOTE_MAC), base, 30).await?;
    a.wait(&format!(
        "remote neighbour removed domain={EVPN_DOMAIN} mac={EVPN_REMOTE_MAC} ip={EVPN_REMOTE_IP} vtep={IP_G}"
    ))
    .await?;

    log("local -> BGP: pinning a MAC on a port of the domain's bridge");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    netns_a(w, &["ip", "link", "add", EVPN_PORT, "type", "dummy"]).await?;
    netns_a(w, &["ip", "link", "set", EVPN_PORT, "master", &bridge]).await?;
    netns_a(w, &["ip", "link", "set", EVPN_PORT, "up"]).await?;
    netns_a(
        w,
        &[
            "bridge",
            "fdb",
            "add",
            EVPN_LOCAL_MAC,
            "dev",
            EVPN_PORT,
            "master",
            "static",
        ],
    )
    .await?;
    a.wait(&format!(
        "local mac learned domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC}"
    ))
    .await?;
    // GoBGP sees the Type-2 (with our RD) and the domain's own Type-3.
    gobgp_evpn_rib(w, "showed the local MAC", |rib| {
        rib.contains(EVPN_LOCAL_MAC) && rib.contains(&format!("rd:{EVPN_RD}"))
    })
    .await?;
    gobgp_evpn_rib(w, "showed router-a's Type-3", |rib| {
        rib.lines()
            .any(|l| l.contains("multicast") && l.contains(&format!("rd:{EVPN_RD}")))
    })
    .await?;

    log("redistribute from connected: the SVI address is a Type-2 with the bridge's MAC");
    a.wait(&format!(
        "local neighbour learned domain={EVPN_DOMAIN} mac=.* ip={EVPN_SVI_IP}"
    ))
    .await?;
    gobgp_evpn_rib(w, "showed the SVI address", |rib| {
        rib.lines()
            .any(|l| l.contains("macadv") && l.contains(EVPN_SVI_IP))
    })
    .await?;
    // RFC 7432 §7.8: the SVI's own Type-2 carries the Default Gateway
    // extended community, so a remote PE knows it may proxy ARP/ND for it.
    gobgp_evpn_rib(w, "tagged the SVI address as the default gateway", |rib| {
        rib.lines()
            .any(|l| l.contains(EVPN_SVI_IP) && l.contains("[default-gateway]"))
    })
    .await?;

    log("redistribute from arp: a neighbour behind a local port is a Type-2 with the IP");
    netns_a(
        w,
        &[
            "ip",
            "neigh",
            "add",
            EVPN_HOST_IP,
            "lladdr",
            EVPN_LOCAL_MAC,
            "dev",
            &bridge,
            "nud",
            "permanent",
        ],
    )
    .await?;
    a.wait(&format!(
        "local neighbour learned domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC} ip={EVPN_HOST_IP}"
    ))
    .await?;
    gobgp_evpn_rib(w, "showed the neighbour's MAC+IP", |rib| {
        rib.lines()
            .any(|l| l.contains(EVPN_LOCAL_MAC) && l.contains(EVPN_HOST_IP))
    })
    .await?;
    // The default-gateway community is scoped to the SVI's own route, never
    // a real ARP-learned host.
    gobgp_evpn_rib(w, "did not tag the ARP-learned host as a gateway", |rib| {
        rib.lines()
            .any(|l| l.contains(EVPN_HOST_IP) && !l.contains("[default-gateway]"))
    })
    .await?;
    let base = a.count(&format!(
        "local neighbour removed domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC} ip={EVPN_HOST_IP}"
    ));
    netns_a(w, &["ip", "neigh", "del", EVPN_HOST_IP, "dev", &bridge]).await?;
    a.wait_new(
        &format!(
            "local neighbour removed domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC} ip={EVPN_HOST_IP}"
        ),
        base,
        30,
    )
    .await?;
    gobgp_evpn_rib(w, "withdrew the neighbour's MAC+IP", |rib| {
        !rib.contains(EVPN_HOST_IP)
    })
    .await?;

    log("removing the MAC withdraws it");
    let base = a.count(&format!(
        "local mac removed domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC}"
    ));
    netns_a(
        w,
        &[
            "bridge",
            "fdb",
            "del",
            EVPN_LOCAL_MAC,
            "dev",
            EVPN_PORT,
            "master",
        ],
    )
    .await?;
    a.wait_new(
        &format!("local mac removed domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC}"),
        base,
        30,
    )
    .await?;
    gobgp_evpn_rib(w, "dropped the local MAC", |rib| {
        !rib.contains(EVPN_LOCAL_MAC)
    })
    .await?;

    log("mac mobility (RFC 7432 §15): GoBGP announces a MAC, then the local helper pins the same one — the local claim must win");
    gobgp_owned(w, macadv("add", EVPN_MOBILE_MAC, rt_g)).await?;
    a.wait(&installed(EVPN_MOBILE_MAC)).await?;
    let removed_base = a.count(&removed(EVPN_MOBILE_MAC));
    // A real frame's dynamic learning clears the kernel's own extern_learn
    // bridge entry as it moves to the new port; this manual pin (standing in
    // for that, like the earlier `EVPN_LOCAL_MAC` one) has to do the same
    // explicitly, or `bridge fdb add` refuses the still-conflicting entry
    // nos-fdbd installed for GoBGP's remote copy.
    netns_a(
        w,
        &[
            "bridge",
            "fdb",
            "del",
            EVPN_MOBILE_MAC,
            "dev",
            &vxlan,
            "master",
        ],
    )
    .await?;
    netns_a(
        w,
        &[
            "bridge",
            "fdb",
            "add",
            EVPN_MOBILE_MAC,
            "dev",
            EVPN_PORT,
            "master",
            "static",
        ],
    )
    .await?;
    a.wait(&format!(
        "local mac learned domain={EVPN_DOMAIN} mac={EVPN_MOBILE_MAC}"
    ))
    .await?;
    // A genuine local re-learn always outranks GoBGP's stale (sequence-0)
    // remote copy (RFC 7432 §7.7), so nos-bgpd stops advertising it to
    // nos-fdbd and the earlier remote installation is torn down.
    a.wait_new(&removed(EVPN_MOBILE_MAC), removed_base, 30)
        .await?;

    log("unsetting the vni stops nos-fdbd and deletes the vxlan device");
    netns_a(w, &["ip", "link", "del", EVPN_PORT]).await?;
    let mut clear = evpn_flags();
    clear.extend(strings(&[
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-clear",
        "--evpn-rt-import",
        EVPN_RT_IMPORT,
        "--evpn-rt-export",
        EVPN_RT_EXPORT,
    ]));
    a.provision_flags(&clear).await?;
    a.wait(&format!(
        "broadcast domain removed from config, stopping nos-fdbd name={EVPN_DOMAIN}"
    ))
    .await?;
    // `nos-fdbd` deletes the device on SIGINT, after its own log forwarding has
    // already shut down — so, like the `rest` phase's teardown checks, read the
    // container's stdout (which carries ANSI colour, hence two separate checks).
    for _ in 0..30 {
        let logs = w.dock.logs("router-a").await?;
        if logs.contains("deleted vxlan device") && logs.contains(&vxlan) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("nos-fdbd never logged deleting {vxlan}")
}

/// GoBGP's spelling of `ESI` (`arbitrary` + the nine value bytes).
const GOBGP_ESI: [&str; 2] = ["arbitrary", "11:22:33:44:55:66:77:88:99"];
/// How GoBGP prints that ESI in its RIB.
const GOBGP_ESI_TEXT: &str = "ESI_ARBITRARY | 11:22:33:44:55:66:77:88:99";

/// EVPN multi-homing (RFC 7432 §8): a port aggregate with an `esi` that is an
/// untagged member of the EVPN broadcast domain.
///
/// A MAC pinned behind the bond is originated as a Type-2 carrying the ESI, a
/// MAC behind an ordinary port keeps ESI 0, and the domain originates a
/// Type-4 Ethernet Segment route — all seen by GoBGP. GoBGP then plays a
/// second PE on the segment with a lower address, which wins the DF election
/// for the (even) VNI: router-a must become the non-DF and turn flooding off on
/// the bond in the real kernel (read back with the helper's `bridge -d link`);
/// when that PE's Type-4 is withdrawn router-a is the DF again and floods.
/// Clearing the ESI while non-DF must restore flooding and withdraw the
/// Type-4 and the Type-2's ESI. Control plane and kernel port state only, not
/// forwarding.
pub async fn evpn_esi(w: &mut World) -> anyhow::Result<()> {
    evpn_speaker(w, &[DF_WAIT_ARG]).await?;
    w.connect_bond_networks().await?;
    let a = w.a()?;

    let mut flags = evpn_flags();
    flags.extend(strings(&[
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-vni",
        &EVPN_VNI.to_string(),
        "--evpn-rd",
        EVPN_RD,
        "--evpn-rt-import",
        EVPN_RT_IMPORT,
        "--evpn-rt-export",
        EVPN_RT_EXPORT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-redistribute-bgp",
        "r1",
        "--port-aggregate",
        "bond1",
        "--port-aggregate-esi",
        ESI,
        "--port-aggregate-untagged-domain",
        EVPN_DOMAIN,
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--enslave-interface-into-port-aggregate",
        "eth2",
    ]));
    a.provision_flags(&flags).await?;
    let vxlan = format!("vx{EVPN_VNI}");
    a.wait(&format!(
        "vxlan device ready domain={EVPN_DOMAIN} vni={EVPN_VNI} vxlan={vxlan}"
    ))
    .await?;

    let bond = bond_name(a, "bond1").await?;
    let role = |r: &str| format!("df elected domain={EVPN_DOMAIN} esi={ESI} port={bond} role={r}");
    let flooding =
        |on: bool| format!("segment port flooding set domain={EVPN_DOMAIN} port={bond} flood={on}");

    // The DF wait timer, against the real kernel: the port is held blocked
    // (whatever the election would say) until it ends, and only then elected.
    // The wait is long enough (12s) for the helper container to read the port.
    log("DF wait timer: the bond is blocked before any election is applied");
    a.wait(&format!(
        "df wait started domain={EVPN_DOMAIN} esi={ESI} port={bond} seconds={DF_WAIT_SECS}"
    ))
    .await?;
    if a.count(&role("df")) != 0 {
        bail!("router-a elected before its DF wait timer ended");
    }
    a.wait(&flooding(false)).await?;
    bridge_port_flood(w, "router-a", &bond, false).await?;
    let table = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let table: serde_json::Value = serde_json::from_str(&table)?;
    if table["segments"][0]["designated_forwarder"] != false {
        bail!("show fdb lists router-a as the DF during its wait timer: {table}");
    }

    log("alone on the segment: once the timer ends router-a is the DF and the bond floods");
    a.wait(&role("df")).await?;
    a.wait(&flooding(true)).await?;

    log("pinning a MAC behind the bond and another behind an ordinary port");
    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let fdb: serde_json::Value = serde_json::from_str(&body)?;
    let bridge = fdb["bridge"]
        .as_str()
        .context("show fdb has no bridge name")?
        .to_string();
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    netns_a(w, &["ip", "link", "add", EVPN_PORT, "type", "dummy"]).await?;
    netns_a(w, &["ip", "link", "set", EVPN_PORT, "master", &bridge]).await?;
    netns_a(w, &["ip", "link", "set", EVPN_PORT, "up"]).await?;
    for (mac, dev) in [(ESI_MAC, bond.as_str()), (EVPN_LOCAL_MAC, EVPN_PORT)] {
        netns_a(
            w,
            &["bridge", "fdb", "add", mac, "dev", dev, "master", "static"],
        )
        .await?;
    }
    a.wait(&format!(
        "local mac learned domain={EVPN_DOMAIN} mac={ESI_MAC} port={bond}"
    ))
    .await?;
    a.wait(&format!(
        "local mac learned domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC} port={EVPN_PORT}"
    ))
    .await?;

    log("GoBGP sees the ESI on the Type-2 behind the bond, none on the other, and a Type-4");
    gobgp_evpn_rib(w, "showed the segment's Type-2", |rib| {
        rib.lines()
            .any(|l| l.contains(ESI_MAC) && l.contains(GOBGP_ESI_TEXT))
    })
    .await?;
    gobgp_evpn_rib(w, "showed the other MAC without an ESI", |rib| {
        rib.lines()
            .any(|l| l.contains(EVPN_LOCAL_MAC) && !l.contains(GOBGP_ESI_TEXT))
    })
    .await?;
    let es_route = |rib: &str| {
        rib.lines().any(|l| {
            l.contains("[type:esi]")
                && l.contains(&format!("rd:{EVPN_RD}"))
                && l.contains(GOBGP_ESI_TEXT)
                && l.contains(&format!("ip:{IP_A}"))
        })
    };
    gobgp_evpn_rib(w, "showed router-a's Type-4", es_route).await?;

    // Type-1 (RFC 7432 §8.2/§8.4): per-ES is MAX-ET with an ESI Label community
    // (all-active here), per-EVI is tag 0 with the VNI in the label.
    log("Type-1: GoBGP sees router-a's per-ES A-D (MAX-ET, ESI Label) and per-EVI A-D (VNI)");
    let ad_route = |rib: &str, per_es: bool| {
        rib.lines().any(|l| {
            l.contains("[type:A-D]")
                && l.contains(&format!("rd:{EVPN_RD}"))
                && l.contains(GOBGP_ESI_TEXT)
                && l.contains(EVPN_RT_EXPORT)
                && if per_es {
                    l.contains("[etag:4294967295]") && l.contains("[esi-label: 0]")
                } else {
                    l.contains("[etag:0]")
                        && l.contains(&format!("[{EVPN_VNI}]"))
                        && !l.contains("esi-label")
                }
        })
    };
    gobgp_evpn_rib(w, "showed router-a's per-ES A-D", |rib| ad_route(rib, true)).await?;
    gobgp_evpn_rib(w, "showed router-a's per-EVI A-D", |rib| {
        ad_route(rib, false)
    })
    .await?;

    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let table: serde_json::Value = serde_json::from_str(&body)?;
    if table["segments"][0]["designated_forwarder"] != true
        || table["segments"][0]["port"] != bond
        || table["segments"][0]["up"] != true
    {
        bail!("show fdb does not list the segment up with router-a as DF: {body}");
    }

    let peer_es = |verb: &'static str| {
        let mut v = strings(&["global", "rib", verb, "-a", "evpn", "esi", ESI_PEER_ORIGIN]);
        v.push("esi".to_string());
        v.extend(strings(&GOBGP_ESI));
        v.extend(strings(&["rd", "65010:1"]));
        if verb == "add" {
            v.extend(strings(&["rt", "65010:1", "encap", "vxlan"]));
        }
        v
    };
    bridge_port_flood(w, "router-a", &bond, true).await?;

    log("a peer with only a bare Type-4 (no per-EVI A-D) is not a df candidate for this domain");
    let peer_es_no_evi = |verb: &'static str| {
        let mut v = strings(&[
            "global",
            "rib",
            verb,
            "-a",
            "evpn",
            "esi",
            ESI_PEER_NO_EVI_ORIGIN,
        ]);
        v.push("esi".to_string());
        v.extend(strings(&GOBGP_ESI));
        v.extend(strings(&["rd", "65010:2"]));
        if verb == "add" {
            v.extend(strings(&["rt", "65010:2", "encap", "vxlan"]));
        }
        v
    };
    let base = a.count(&role("non-df"));
    gobgp_owned(w, peer_es_no_evi("add")).await?;
    a.assert_quiet(&role("non-df"), base, 5).await?;
    gobgp_owned(w, peer_es_no_evi("del")).await?;

    log("a second PE on the segment, also attached to this EVI (per-EVI A-D), with a lower address wins the election");
    let base = a.count(&role("non-df"));
    gobgp_owned(w, peer_es("add")).await?;
    gobgp_owned(
        w,
        gobgp_ad("add", &GOBGP_ESI, false, (ESI_PEER_ORIGIN, "65010:1")),
    )
    .await?;
    a.wait_new(&role("non-df"), base, 30).await?;
    a.wait(&flooding(false)).await?;
    bridge_port_flood(w, "router-a", &bond, false).await?;

    log("its Type-4 and per-EVI A-D withdrawn: router-a is the DF again and the bond floods");
    let base = a.count(&role("df"));
    gobgp_owned(w, peer_es("del")).await?;
    gobgp_owned(
        w,
        gobgp_ad("del", &GOBGP_ESI, false, (ESI_PEER_ORIGIN, "65010:1")),
    )
    .await?;
    a.wait_new(&role("df"), base, 30).await?;
    bridge_port_flood(w, "router-a", &bond, true).await?;

    log("mass withdrawal: MACs of a segment router-a is not on wait for their PE's per-ES A-D");
    let vni = EVPN_VNI.to_string();
    let macadv2 = |verb: &'static str, mac: &'static str, ip: &'static str| {
        let mut v = strings(&[
            "global", "rib", verb, "-a", "evpn", "macadv", mac, ip, "esi",
        ]);
        v.extend(strings(&ESI2));
        v.extend(strings(&["etag", "0", "label", &vni, "rd", ESI2_RD]));
        if verb == "add" {
            v.extend(strings(&["rt", EVPN_RT_IMPORT, "encap", "vxlan"]));
        }
        v
    };
    let ad2 = |verb: &'static str| {
        let mut v = strings(&["global", "rib", verb, "-a", "evpn", "a-d", "esi"]);
        v.extend(strings(&ESI2));
        v.extend(strings(&[
            "etag",
            "4294967295",
            "label",
            "0",
            "rd",
            ESI2_RD,
        ]));
        if verb == "add" {
            v.extend(strings(&[
                "rt",
                EVPN_RT_IMPORT,
                "encap",
                "vxlan",
                "esi-label",
                "0",
                "all-active",
            ]));
        }
        v
    };
    let installed =
        |mac: &str| format!("remote mac installed domain={EVPN_DOMAIN} mac={mac} vtep={IP_G}");
    let removed =
        |mac: &str| format!("remote mac removed domain={EVPN_DOMAIN} mac={mac} vtep={IP_G}");
    let installed_base: Vec<usize> = ESI2_MACS
        .iter()
        .map(|(m, _)| a.count(&installed(m)))
        .collect();
    for (m, ip) in ESI2_MACS {
        gobgp_owned(w, macadv2("add", m, ip)).await?;
    }
    // Their PE has not advertised the segment yet: the MACs are not usable.
    a.assert_quiet(&installed(ESI2_MACS[0].0), installed_base[0], 5)
        .await?;
    gobgp_owned(w, ad2("add")).await?;
    for (i, (m, _)) in ESI2_MACS.iter().enumerate() {
        a.wait_new(&installed(m), installed_base[i], 30).await?;
    }
    let body = a
        .rest_expect(Method::GET, "/v1/bgp/evpn", None, 200)
        .await?;
    if !body.contains("esi-label:all-active") {
        bail!("show bgp evpn does not decode the ESI Label community: {body}");
    }
    log("withdrawing that one route takes every MAC of the segment away at once");
    let removed_base: Vec<usize> = ESI2_MACS
        .iter()
        .map(|(m, _)| a.count(&removed(m)))
        .collect();
    gobgp_owned(w, ad2("del")).await?;
    for (i, (m, _)) in ESI2_MACS.iter().enumerate() {
        a.wait_new(&removed(m), removed_base[i], 30).await?;
    }
    log("advertising it again brings them back");
    let installed_base: Vec<usize> = ESI2_MACS
        .iter()
        .map(|(m, _)| a.count(&installed(m)))
        .collect();
    gobgp_owned(w, ad2("add")).await?;
    for (i, (m, _)) in ESI2_MACS.iter().enumerate() {
        a.wait_new(&installed(m), installed_base[i], 30).await?;
    }
    gobgp_owned(w, ad2("del")).await?;
    for (m, ip) in ESI2_MACS {
        gobgp_owned(w, macadv2("del", m, ip)).await?;
    }

    log("aliasing: a MAC on a segment two PEs serve is balanced over both, in the real kernel");
    let alias_mac = ESI3_MAC.0;
    let [pe1, pe2] = ESI3_PES;
    let group_installed = format!(
        "remote mac group installed domain={EVPN_DOMAIN} mac={alias_mac} vteps={},{}",
        pe1.0, pe2.0
    );
    let group_base = a.count(&group_installed);
    gobgp_owned(w, gobgp_macadv("add", &ESI3, ESI3_MAC, pe1)).await?;
    for pe in [pe1, pe2] {
        gobgp_owned(w, gobgp_ad("add", &ESI3, true, pe)).await?;
        gobgp_owned(w, gobgp_ad("add", &ESI3, false, pe)).await?;
    }
    a.wait_new(&group_installed, group_base, 30).await?;
    let (nexthops, entry) = kernel_aliasing(w, alias_mac).await?;
    if !entry.contains("nhid") {
        bail!("the aliased MAC's FDB entry does not use a nexthop group: {entry:?}");
    }
    let groups = nexthops.lines().filter(|l| l.contains("group ")).count();
    if groups != 1
        || !nexthops.contains(&format!("via {}", pe1.0))
        || !nexthops.contains(&format!("via {}", pe2.0))
    {
        bail!("expected one FDB group over both PEs: {nexthops}");
    }
    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let table: serde_json::Value = serde_json::from_str(&body)?;
    let aliased = table["macs"]
        .as_array()
        .and_then(|m| m.iter().find(|e| e["mac"] == alias_mac))
        .context("show fdb lacks the aliased MAC")?;
    if aliased["vteps"].as_array().map(Vec::len) != Some(2) {
        bail!("show fdb does not list both VTEPs of the aliased MAC: {aliased}");
    }

    log("the second PE stops serving the EVI: the MAC is back on the one PE that does");
    let removed = format!(
        "remote mac group removed domain={EVPN_DOMAIN} mac={alias_mac} vteps={},{}",
        pe1.0, pe2.0
    );
    let removed_base = a.count(&removed);
    gobgp_owned(w, gobgp_ad("del", &ESI3, false, pe2)).await?;
    a.wait_new(&removed, removed_base, 30).await?;
    a.wait(&format!(
        "remote mac installed domain={EVPN_DOMAIN} mac={alias_mac} vtep={}",
        pe1.0
    ))
    .await?;
    let (_, entry) = kernel_aliasing(w, alias_mac).await?;
    if entry.contains("nhid") || !entry.contains(&format!("dst {}", pe1.0)) {
        bail!("the MAC did not fall back to its one PE: {entry:?}");
    }

    log("cleaning up the aliasing routes");
    gobgp_owned(w, gobgp_macadv("del", &ESI3, ESI3_MAC, pe1)).await?;
    for pe in [pe1, pe2] {
        gobgp_owned(w, gobgp_ad("del", &ESI3, true, pe)).await?;
    }
    gobgp_owned(w, gobgp_ad("del", &ESI3, false, pe1)).await?;

    log("ES down: the bond losing carrier withdraws Type-4 and both Type-1, carrier back restores them");
    netns_a(w, &["ip", "link", "set", &bond, "down"]).await?;
    a.wait(&format!(
        "segment port carrier changed domain={EVPN_DOMAIN} port={bond} up=false"
    ))
    .await?;
    gobgp_evpn_rib(w, "dropped router-a's segment routes", |rib| {
        !es_route(rib) && !ad_route(rib, true) && !ad_route(rib, false)
    })
    .await?;
    let carrier_up =
        format!("segment port carrier changed domain={EVPN_DOMAIN} port={bond} up=true");
    let base = a.count(&carrier_up);
    netns_a(w, &["ip", "link", "set", &bond, "up"]).await?;
    a.wait_new(&carrier_up, base, 30).await?;
    gobgp_evpn_rib(w, "re-advertised router-a's segment routes", |rib| {
        es_route(rib) && ad_route(rib, true) && ad_route(rib, false)
    })
    .await?;

    log("back to non-DF, then clearing the ESI restores flooding and withdraws it");
    let base = a.count(&role("non-df"));
    gobgp_owned(w, peer_es("add")).await?;
    gobgp_owned(
        w,
        gobgp_ad("add", &GOBGP_ESI, false, (ESI_PEER_ORIGIN, "65010:1")),
    )
    .await?;
    a.wait_new(&role("non-df"), base, 30).await?;
    bridge_port_flood(w, "router-a", &bond, false).await?;
    let mut clear = flags.clone();
    let at = clear
        .iter()
        .position(|f| f == "--port-aggregate-esi")
        .context("the ESI flag is in the base flags")?;
    clear.drain(at..=at + 1);
    clear.push("--delete-port-aggregate-esi".to_string());
    a.provision_flags(&clear).await?;
    bridge_port_flood(w, "router-a", &bond, true).await?;
    gobgp_evpn_rib(
        w,
        "dropped router-a's Type-4, Type-1s and the Type-2's ESI",
        |rib| {
            !es_route(rib)
                && !ad_route(rib, true)
                && !ad_route(rib, false)
                && rib
                    .lines()
                    .any(|l| l.contains(ESI_MAC) && !l.contains(GOBGP_ESI_TEXT))
        },
    )
    .await
}

/// GoBGP arguments to add/delete one PE's A-D route for `esi`: per-ES (MAX-ET,
/// all-active ESI Label) or per-EVI (tag 0, the VNI in the label), advertised
/// with `nexthop` as its VTEP.
fn gobgp_ad(
    verb: &'static str,
    esi: &[&str; 2],
    per_es: bool,
    (nexthop, rd): (&str, &str),
) -> Vec<String> {
    let (etag, label) = if per_es {
        ("4294967295".to_string(), "0".to_string())
    } else {
        ("0".to_string(), EVPN_VNI.to_string())
    };
    let mut v = strings(&["global", "rib", verb, "-a", "evpn", "a-d", "esi"]);
    v.extend(strings(esi));
    v.extend(strings(&["etag", &etag, "label", &label, "rd", rd]));
    if verb == "add" {
        v.extend(strings(&["rt", EVPN_RT_IMPORT, "encap", "vxlan"]));
        if per_es {
            v.extend(strings(&["esi-label", "0", "all-active"]));
        }
        v.extend(strings(&["nexthop", nexthop]));
    }
    v
}

/// GoBGP arguments to add/delete a MAC (with an IP, which GoBGP requires) on
/// `esi`, advertised by the PE `nexthop`.
fn gobgp_macadv(
    verb: &'static str,
    esi: &[&str; 2],
    (mac, ip): (&str, &str),
    (nexthop, rd): (&str, &str),
) -> Vec<String> {
    let mut v = strings(&[
        "global", "rib", verb, "-a", "evpn", "macadv", mac, ip, "esi",
    ]);
    v.extend(strings(esi));
    v.extend(strings(&[
        "etag",
        "0",
        "label",
        &EVPN_VNI.to_string(),
        "rd",
        rd,
    ]));
    if verb == "add" {
        v.extend(strings(&[
            "rt",
            EVPN_RT_IMPORT,
            "encap",
            "vxlan",
            "nexthop",
            nexthop,
        ]));
    }
    v
}

/// `evpn-esi`'s kernel read-back: router-a's FDB nexthop groups, and the
/// `vx<vni>` FDB entry for `mac` (empty when there is none).
async fn kernel_aliasing(w: &World, mac: &str) -> anyhow::Result<(String, String)> {
    let nexthops = netns_a(w, &["ip", "nexthop", "show"]).await?;
    let fdb = netns_a(
        w,
        &["bridge", "fdb", "show", "dev", &format!("vx{EVPN_VNI}")],
    )
    .await?;
    let entry = fdb
        .lines()
        .filter(|l| l.contains(mac) && l.contains(" self"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok((nexthops, entry))
}

/// The kernel name `router`'s `nos-interfaced` gave the port aggregate `name`.
async fn bond_name(r: &Router, name: &str) -> anyhow::Result<String> {
    for _ in 0..30 {
        let body = r
            .rest_expect(Method::GET, "/v1/port-aggregates", None, 200)
            .await?;
        let aggregates: serde_json::Value = serde_json::from_str(&body)?;
        if let Some(bond) = aggregates
            .as_array()
            .and_then(|v| v.iter().find(|s| s["name"] == name))
            .and_then(|s| s["bond_name"].as_str())
        {
            return Ok(bond.to_string());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: nos-interfaced never created a bond for {name}",
        r.name()
    )
}

/// `evpn-dataplane`: one PE's whole EVPN config — an eBGP session to the other
/// PE with `address-family l2vpn-evpn` and the domain, sharing one Route Target.
fn evpn_pe_flags(id: Id, rd: &str) -> Vec<String> {
    let mut flags = id.base_flags();
    flags.extend(strings(&[
        "--peer-group",
        "pg-evpn",
        "--evpn",
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-vni",
        &EVPN_VNI.to_string(),
        "--evpn-rd",
        rd,
        "--evpn-rt-import",
        EVPN_DP_RT,
        "--evpn-rt-export",
        EVPN_DP_RT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-redistribute-bgp",
        "r1",
    ]));
    flags
}

/// A one-member static port aggregate, untagged in the EVPN domain, on the
/// docker-network `member` link; `esi` makes it an Ethernet Segment.
fn bond_flags(name: &str, esi: bool, member: &str) -> Vec<String> {
    let mut flags = strings(&["--port-aggregate", name]);
    if esi {
        flags.extend(strings(&["--port-aggregate-esi", ESI]));
    }
    flags.extend(strings(&[
        "--port-aggregate-untagged-domain",
        EVPN_DOMAIN,
        "--enslave-interface-into-port-aggregate",
        member,
    ]));
    flags
}

/// Runs a shell script in an end-host container; errors on a non-zero exit.
async fn host_sh(w: &World, host: &str, script: &str) -> anyhow::Result<String> {
    let (code, out) = w.dock.exec(host, &["sh", "-c", script]).await?;
    if code != 0 {
        bail!("{host}: `{script}` exited {code}: {}", out.trim());
    }
    Ok(out)
}

/// How many ARP requests for `target` from `sender` a capture file on `host`
/// holds. `arping` prints the target MAC (`who-has X (ff:ff:..) tell Y`), the
/// kernel's own requests don't.
async fn arp_requests(
    w: &World,
    host: &str,
    file: &str,
    target: &str,
    sender: &str,
) -> anyhow::Result<usize> {
    let script = format!("grep -c -E 'who-has {target}( .*)? tell {sender}' {file} || true");
    let out = host_sh(w, host, &script).await?;
    out.trim()
        .parse()
        .with_context(|| format!("counting ARP requests in {file}: {out:?}"))
}

async fn dataplane_setup(w: &mut World, single_active: bool) -> anyhow::Result<(String, String)> {
    w.start(A, Some(evpn_pe_flags(A, EVPN_DP_RD_A)), &[])
        .await?;
    w.start(B, Some(evpn_pe_flags(B, EVPN_DP_RD_B)), &[])
        .await?;
    let (a, b) = (w.a()?, w.b()?);
    a.established().await?;
    b.established().await?;

    // The underlay is in a VRF (`rt1`): its VXLAN sockets only accept packets
    // that came in through a VRF slave with this set. Nothing in nos sets it
    // (the daemons are unprivileged and /proc/sys is read-only in the
    // container), so it is an operator prerequisite the harness applies.
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    for router in ["router-a", "router-b"] {
        w.dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                router,
                &["sh", "-c", "echo 1 > /proc/sys/net/ipv4/udp_l3mdev_accept"],
            )
            .await?;
    }

    log("wiring the CE (to both PEs) and the host (to router-b) over docker networks");
    for net in [NET_CE_A, NET_CE_B, NET_H] {
        if !w.dock.network_exists(net).await {
            w.dock.network_create(net, &[], false).await?;
        }
    }
    w.dock.network_connect(NET_CE_A, "router-a").await;
    w.dock.network_connect(NET_CE_B, "router-b").await;
    w.dock.network_connect(NET_H, "router-b").await;
    w.dock
        .ensure_image(
            HOST_IMAGE,
            "FROM debian:bookworm-slim\n\
             RUN apt-get update && apt-get install -y --no-install-recommends \\\n \
             iproute2 iputils-ping iputils-arping tcpdump && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    w.dock.start_host(CE_HOST, HOST_IMAGE, NET_CE_A).await?;
    w.dock.network_connect(NET_CE_B, CE_HOST).await;
    w.dock.start_host(H_HOST, HOST_IMAGE, NET_H).await?;

    let mut on_a = evpn_pe_flags(A, EVPN_DP_RD_A);
    on_a.extend(bond_flags("bond1", true, "eth1"));
    if single_active {
        on_a.extend(strings(&[
            "--port-aggregate-redundancy-mode",
            "single-active",
        ]));
    }
    a.provision_flags(&on_a).await?;
    let mut on_b = evpn_pe_flags(B, EVPN_DP_RD_B);
    on_b.extend(bond_flags("bond1", true, "eth1"));
    if single_active {
        on_b.extend(strings(&[
            "--port-aggregate-redundancy-mode",
            "single-active",
        ]));
    }
    b.provision_flags(&on_b).await?;
    let mut host_port = evpn_pe_flags(B, EVPN_DP_RD_B);
    host_port.extend(bond_flags("bond2", false, "eth2"));
    b.provision_flags(&host_port).await?;

    let vxlan = format!("vx{EVPN_VNI}");
    for r in [a, b] {
        r.wait(&format!(
            "vxlan device ready domain={EVPN_DOMAIN} vni={EVPN_VNI} vxlan={vxlan}"
        ))
        .await?;
    }
    a.wait(&format!(
        "flood entry installed domain={EVPN_DOMAIN} vtep={IP_B}"
    ))
    .await?;
    b.wait(&format!(
        "flood entry installed domain={EVPN_DOMAIN} vtep={IP_A}"
    ))
    .await?;

    log("election: router-a (lower address) is the segment's DF, router-b is not");
    let (bond_a, bond_b) = (bond_name(a, "bond1").await?, bond_name(b, "bond1").await?);
    let role = |bond: &str, r: &str| {
        format!("df elected domain={EVPN_DOMAIN} esi={ESI} port={bond} role={r}")
    };
    a.wait(&role(&bond_a, "df")).await?;
    b.wait(&role(&bond_b, "non-df")).await?;
    Ok((bond_a, bond_b))
}

/// The dual-homed CE's bond (`bond_opts` picks its mode) and the host's address.
async fn dataplane_ce(w: &World, bond_opts: &str) -> anyhow::Result<()> {
    host_sh(
        w,
        CE_HOST,
        &format!(
            "set -e; for i in eth0 eth1; do ip addr flush dev $i; ip link set $i down; done; \
             ip link add bond0 type bond {bond_opts}; \
             ip link set eth0 master bond0; ip link set eth1 master bond0; \
             ip link set bond0 up; ip addr add {CE_IP}/24 dev bond0"
        ),
    )
    .await?;
    host_sh(w, H_HOST, &format!("ip addr add {H_IP}/24 dev eth0")).await?;

    Ok(())
}

/// Removes the CE, the host and their networks.
async fn dataplane_teardown(w: &World) -> anyhow::Result<()> {
    for host in [CE_HOST, H_HOST] {
        w.dock.container_remove(host).await;
    }
    for (net, router) in [
        (NET_CE_A, "router-a"),
        (NET_CE_B, "router-b"),
        (NET_H, "router-b"),
    ] {
        w.dock.network_disconnect(net, router).await;
        w.dock.network_remove(net).await;
    }
    Ok(())
}

/// The EVPN data plane, for real: two `nos` PEs over a VXLAN underlay in a
/// VRF, a CE dual-homed to both through one Ethernet Segment (a bond of one
/// docker-network link to each PE), and a host behind router-b. Unlike
/// `evpn-fdb`/`evpn-esi` (control plane and kernel state, against GoBGP) this
/// sends frames.
///
/// Router-a has the lower address, so for the even VNI it is the segment's DF
/// and router-b is not. With the CE's link to router-b down, every frame the
/// CE sends enters router-a and must cross the VXLAN to reach the host, and
/// back; with both up, one broadcast from the host reaches the CE through the
/// DF only — once — while the non-DF's link stays silent; with the link to
/// router-a down instead, the CE is bridged locally on router-b.
pub async fn evpn_dataplane(w: &mut World) -> anyhow::Result<()> {
    let (bond_a, bond_b) = dataplane_setup(w, false).await?;
    bridge_port_flood(w, "router-a", &bond_a, true).await?;
    bridge_port_flood(w, "router-b", &bond_b, false).await?;

    log("the CE bonds its two links; the host takes an address");
    dataplane_ce(w, "mode balance-xor miimon 100 xmit_hash_policy layer2").await?;

    log("unicast across the VXLAN: the CE's link to router-b is down, so every frame enters router-a");
    host_sh(w, CE_HOST, "ip link set eth1 down; sleep 1").await?;
    host_sh(w, CE_HOST, &format!("ping -c 3 -W 2 {H_IP}")).await?;
    host_sh(w, H_HOST, &format!("ping -c 3 -W 2 {CE_IP}")).await?;

    neigh_suppression(w).await?;

    log("BUM: one broadcast from the host reaches the CE once, through the DF only");
    host_sh(w, CE_HOST, "ip link set eth1 up; sleep 1").await?;
    host_sh(
        w,
        CE_HOST,
        "rm -f /tmp/e0 /tmp/e1; \
         timeout 8 tcpdump -l -n -Q in -i eth0 arp and ether broadcast >/tmp/e0 2>&1 & \
         timeout 8 tcpdump -l -n -Q in -i eth1 arp and ether broadcast >/tmp/e1 2>&1 & \
         sleep 2",
    )
    .await?;
    let arping = host_sh(
        w,
        H_HOST,
        &format!("arping -c 1 -w 3 -I eth0 -s {H_IP} {CE_IP}"),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (via_df, via_non_df) = (
        arp_requests(w, CE_HOST, "/tmp/e0", CE_IP, H_IP).await?,
        arp_requests(w, CE_HOST, "/tmp/e1", CE_IP, H_IP).await?,
    );
    if (via_df, via_non_df) != (1, 0) {
        bail!(
            "the host's broadcast reached the CE {via_df}x through router-a (the DF) and \
             {via_non_df}x through router-b (the non-DF); expected exactly 1 and 0\n\
             arping: {arping}\ncaptures: {}",
            host_sh(w, CE_HOST, "tail -n +1 /tmp/e0 /tmp/e1").await?
        );
    }

    log("the CE's link to router-a goes down: it is bridged locally on router-b");
    host_sh(w, CE_HOST, "ip link set eth0 down; sleep 1").await?;
    host_sh(w, CE_HOST, &format!("ping -c 3 -W 2 {H_IP}")).await?;

    dataplane_teardown(w).await
}

/// The CE ARPs for the host once (`arping` from its bond, entering router-a);
/// returns arping's exit code and how many of those requests reached the host
/// across the VXLAN.
async fn ce_arps_host(w: &World) -> anyhow::Result<(i64, usize)> {
    host_sh(
        w,
        H_HOST,
        "rm -f /tmp/h; timeout 8 tcpdump -l -n -Q in -i eth0 arp >/tmp/h 2>&1 & sleep 2",
    )
    .await?;
    let (code, _) = w
        .dock
        .exec(
            CE_HOST,
            &[
                "arping", "-c", "1", "-w", "3", "-I", "bond0", "-s", CE_IP, H_IP,
            ],
        )
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok((code, arp_requests(w, H_HOST, "/tmp/h", H_IP, CE_IP).await?))
}

/// ARP suppression (`neigh-suppress`, RFC 7432 §10): with the CE's link to
/// router-b down, the CE's ARP for the host enters router-a. Once router-b
/// originates the host's MAC+IP (`redistribute from arp`, its binding pinned
/// on router-b's bridge) and router-a holds it as a neighbour, router-a's
/// bridge answers the request itself and nothing crosses the VXLAN; with the
/// setting cleared the request floods to the host again.
async fn neigh_suppression(w: &World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let vxlan = format!("vx{EVPN_VNI}");

    log("neigh-suppress: without it, the CE's ARP for the host crosses the VXLAN");
    let (code, seen) = ce_arps_host(w).await?;
    if code != 0 || seen != 1 {
        bail!("control: arping exited {code}, the host saw {seen} request(s); expected 0 and 1");
    }

    log("neigh-suppress on router-a; router-b originates the host's MAC+IP");
    let mut on_a = evpn_pe_flags(A, EVPN_DP_RD_A);
    on_a.extend(strings(&["--evpn-neigh-suppress", "true"]));
    a.provision_flags(&on_a).await?;
    let mut on_b = evpn_pe_flags(B, EVPN_DP_RD_B);
    on_b.extend(strings(&["--evpn-redistribute-arp-bgp", "r1"]));
    b.provision_flags(&on_b).await?;
    let fdb: serde_json::Value = serde_json::from_str(
        &b.rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
            .await?,
    )?;
    let bridge_b = fdb["bridge"]
        .as_str()
        .context("router-b's show fdb has no bridge name")?
        .to_string();
    let h_mac = host_sh(w, H_HOST, "cat /sys/class/net/eth0/address")
        .await?
        .trim()
        .to_string();
    w.dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-b",
            &[
                "ip",
                "neigh",
                "add",
                H_IP,
                "lladdr",
                &h_mac,
                "dev",
                &bridge_b,
                "nud",
                "permanent",
            ],
        )
        .await?;
    a.wait(&format!(
        "vxlan neigh suppression set vxlan={vxlan} suppress=true"
    ))
    .await?;
    a.wait(&format!(
        "remote neighbour installed domain={EVPN_DOMAIN} mac={h_mac} ip={H_IP} vtep={IP_B}"
    ))
    .await?;
    let link = w
        .dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-a",
            &["bridge", "-d", "link", "show", "dev", &vxlan],
        )
        .await?;
    if !link.contains("neigh_suppress on") {
        bail!("router-a's {vxlan} does not read neigh_suppress on: {link}");
    }
    let fdb: serde_json::Value = serde_json::from_str(
        &a.rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
            .await?,
    )?;
    if fdb["neigh_suppress"] != true {
        bail!("router-a's show fdb does not report neigh_suppress: {fdb}");
    }

    log("router-a's bridge answers the CE's ARP itself: nothing reaches the host");
    let (code, seen) = ce_arps_host(w).await?;
    if code != 0 || seen != 0 {
        bail!("suppressed: arping exited {code}, the host saw {seen} request(s); expected 0 and 0");
    }

    log("neigh-suppress off again: the request floods to the host");
    let base = a.count(&format!(
        "vxlan neigh suppression set vxlan={vxlan} suppress=false"
    ));
    let mut off_a = evpn_pe_flags(A, EVPN_DP_RD_A);
    off_a.extend(strings(&["--evpn-neigh-suppress", "false"]));
    a.provision_flags(&off_a).await?;
    a.wait_new(
        &format!("vxlan neigh suppression set vxlan={vxlan} suppress=false"),
        base,
        30,
    )
    .await?;
    let (code, seen) = ce_arps_host(w).await?;
    if code != 0 || seen != 1 {
        bail!(
            "unsuppressed: arping exited {code}, the host saw {seen} request(s); expected 0 and 1"
        );
    }

    w.dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-b",
            &["ip", "neigh", "del", H_IP, "dev", &bridge_b],
        )
        .await?;
    Ok(())
}

/// Reads the real bridge port `dev` back, in `container`'s netns, until its STP
/// state is `want` (`disabled` / `forwarding`).
async fn bridge_port_state(
    w: &World,
    container: &str,
    dev: &str,
    want: &str,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..30 {
        last = w
            .dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                container,
                &["bridge", "-d", "link", "show", "dev", dev],
            )
            .await?;
        if last.contains(&format!(" state {want}")) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("bridge port {dev} never read state {want}: {last}")
}

/// Pings `ip` from `host` until one reply comes back, for at most `secs`.
async fn ping_until(w: &World, host: &str, ip: &str, secs: u32) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..secs {
        let (code, out) = w
            .dock
            .exec(host, &["ping", "-c", "1", "-W", "1", ip])
            .await?;
        if code == 0 {
            return Ok(());
        }
        last = out;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("{host} never reached {ip} within {secs}s: {}", last.trim())
}

/// `evpn-single-active`: EVPN single-active multi-homing (RFC 7432 §8.5), for
/// real. The same topology as `evpn-dataplane` — two `nos` PEs, a CE dual-homed
/// to both through one Ethernet Segment, a host behind router-b — with
/// `redundancy-mode single-active` on both PEs' bonds and the CE running an
/// ARP-monitored active-backup bond instead of an all-active one.
///
/// Router-a (the lower address) is the DF, so its port forwards and router-b's
/// is *disabled* in the kernel (STP state, read back with `bridge -d link`) —
/// unicast included, not just BUM — while its flooding flags stay on. Router-a
/// sees router-b's per-ES A-D carrying the Single-Active ESI Label. The CE talks
/// to the host through the DF. Router-a's bond then goes down: it
/// withdraws the segment, router-b becomes the DF and unblocks, and the CE (its
/// ARP probes unanswered on router-a's dead link) moves over; when the carrier
/// returns router-a is elected again and router-b is blocked again.
pub async fn evpn_single_active(w: &mut World) -> anyhow::Result<()> {
    let (bond_a, bond_b) = dataplane_setup(w, true).await?;
    let (a, b) = (w.a()?, w.b()?);
    let role = |bond: &str, r: &str| {
        format!("df elected domain={EVPN_DOMAIN} esi={ESI} port={bond} role={r}")
    };
    let carrier = |bond: &str, up: bool| {
        format!("segment port carrier changed domain={EVPN_DOMAIN} port={bond} up={up}")
    };

    log("single-active: the non-DF's port is blocked outright, the DF's forwards");
    bridge_port_state(w, "router-b", &bond_b, "disabled").await?;
    bridge_port_state(w, "router-a", &bond_a, "forwarding").await?;
    // It is the state that blocks, not the flood flags.
    bridge_port_flood(w, "router-b", &bond_b, true).await?;
    for (r, want_df) in [(a, true), (b, false)] {
        let body = r
            .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
            .await?;
        let table: serde_json::Value = serde_json::from_str(&body)?;
        if table["segments"][0]["single_active"] != true
            || table["segments"][0]["designated_forwarder"] != want_df
        {
            bail!(
                "{}: show fdb does not list a single-active segment (DF={want_df}): {body}",
                r.name()
            );
        }
    }

    log("router-a decodes router-b's per-ES A-D and its Single-Active ESI Label");
    let body = a
        .rest_expect(Method::GET, "/v1/bgp/evpn", None, 200)
        .await?;
    if !body.contains("esi-label:single-active") {
        bail!("router-a does not show router-b's Single-Active ESI Label: {body}");
    }

    log("the CE: an ARP-monitored active-backup bond preferring router-a's link");
    dataplane_ce(
        w,
        &format!("mode active-backup arp_interval 200 arp_ip_target {H_IP} primary eth0"),
    )
    .await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;
    ping_until(w, H_HOST, CE_IP, 30).await?;
    let active = host_sh(w, CE_HOST, "cat /sys/class/net/bond0/bonding/active_slave").await?;
    if active.trim() != "eth0" {
        bail!(
            "the CE is active on {:?}, expected eth0 (router-a, the DF)",
            active.trim()
        );
    }

    log("router-a's bond goes down: router-b takes over and unblocks, the CE follows");
    let df_base = b.count(&role(&bond_b, "df"));
    // The bond itself, not its member: the bond has no link monitoring, so a
    // member going down would leave its carrier up.
    netns_a(w, &["ip", "link", "set", &bond_a, "down"]).await?;
    a.wait(&carrier(&bond_a, false)).await?;
    b.wait_new(&role(&bond_b, "df"), df_base, 60).await?;
    bridge_port_state(w, "router-b", &bond_b, "forwarding").await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;
    ping_until(w, H_HOST, CE_IP, 30).await?;

    log("carrier back: router-a is elected again and router-b is blocked again");
    let a_df = a.count(&role(&bond_a, "df"));
    let b_non_df = b.count(&role(&bond_b, "non-df"));
    let up_base = a.count(&carrier(&bond_a, true));
    netns_a(w, &["ip", "link", "set", &bond_a, "up"]).await?;
    a.wait_new(&carrier(&bond_a, true), up_base, 30).await?;
    a.wait_new(&role(&bond_a, "df"), a_df, 60).await?;
    b.wait_new(&role(&bond_b, "non-df"), b_non_df, 60).await?;
    bridge_port_state(w, "router-b", &bond_b, "disabled").await?;
    bridge_port_state(w, "router-a", &bond_a, "forwarding").await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;

    dataplane_teardown(w).await
}

/// RFC 5082 GTSM: `max-hops 1` on both peer-groups (TTL 255 out, kernel drops
/// below 255 in) still establishes in both directions over the directly
/// connected network — proving the SYN-ACK and accepted sockets really carry
/// TTL 255. No negative check: a peer with max-hops only on one side still
/// gets a session, since the listener always sends 255 (see `bind_listener`),
/// so the packets that side would drop never exist in this topology.
pub async fn gtsm(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    a.provision(&["--max-hops", "1"]).await?;
    b.provision(&["--max-hops", "1"]).await?;
    a.wait("max hops applied").await?;
    b.wait("max hops applied").await?;
    reestablished(a, base_a).await?;
    reestablished(b, base_b).await
}
