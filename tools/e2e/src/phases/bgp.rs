//! BGP phases: sessions, redistribution, authentication, RPL policy, and the
//! reflector / route-server topologies.

use std::time::Duration;

use anyhow::{bail, Context};

use crate::consts::*;
use crate::router::{log, strings, Router, B, C};
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
    w.a()?.established().await?;
    w.b()?.established().await
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
    established(w).await
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
    w.start(crate::router::A, Some(hub(IP_B)), &[]).await?;
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
    w.start(crate::router::A, Some(hub("pg-b", ASN_B, IP_B)), &[])
        .await?;
    w.start(B, None, &[]).await?;
    w.start(C, None, &[]).await?;
    w.a()?.provision_flags(&hub("pg-c", ASN_C, IP_C)).await?;

    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    for r in [a, b, c] {
        r.established().await?;
    }
    let mut flags = B.base_flags();
    flags.extend(strings(&redistribute()));
    b.provision_flags(&flags).await?;
    log("waiting for router-c to learn the prefix via the route server");
    c.wait(&learned()).await?;
    c.wait(&loc_rib()).await?;

    log("confirming router-c sees router-b's asn but not router-a's — rfc 7947 transparency");
    let line = c.logs.last(&loc_rib()).unwrap_or_default();
    if line.contains(&format!("as_path=[{ASN_B}]")) && !line.contains(&ASN_A.to_string()) {
        Ok(())
    } else {
        bail!("expected as_path [{ASN_B}] with no route-server asn prepended, got: {line}")
    }
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
        &format!("if this.prefix in {REDISTRIBUTE_PREFIX}:\n    reject\nelse:\n    accept\n"),
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
        &format!("this.bgp.communities.add({COMMUNITY_AA}:{COMMUNITY_NN})\naccept\n"),
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

/// Runs one `gobgp` CLI command inside the GoBGP container.
async fn gobgp(w: &World, args: &[&str]) -> anyhow::Result<()> {
    let mut cmd = vec!["gobgp"];
    cmd.extend_from_slice(args);
    let (code, out) = w.dock.exec("router-g", &cmd).await?;
    if code != 0 {
        bail!("gobgp {}: exit {code}: {}", args.join(" "), out.trim());
    }
    Ok(())
}

/// RFC 7432 EVPN, receive side. No NOS router originates EVPN yet, so an
/// independent implementation does: GoBGP announces one MAC/IP (Type 2) and
/// one Inclusive Multicast (Type 3) route, with a Route Target and the VXLAN
/// Encapsulation community, to router-a. Router-a must negotiate AFI 25 /
/// SAFI 70 (its peer-group's only family besides IPv4 unicast), decode both,
/// hold them per peer, serve them on `show bgp evpn`, and drop them on an
/// explicit withdrawal and, for what is left, when the session goes away.
pub async fn evpn(w: &mut World) -> anyhow::Result<()> {
    let flags = strings(&[
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
    ]);
    w.start(crate::router::A, Some(flags), &[]).await?;

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
        ready = gobgp(w, &["global"]).await;
        if ready.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    ready?;

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
