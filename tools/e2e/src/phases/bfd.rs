//! BFD (RFC 5880/5881) phases.

use reqwest::Method;

use crate::consts::*;
use crate::router::{log, strings, A, B};
use crate::world::World;

/// `--static-route` flags: a BFD-guarded static route to `prefix` via `gateway`.
pub(super) fn bfd_route(prefix: &str, gateway: &str) -> Vec<String> {
    strings(&[
        "--static-route",
        prefix,
        "--static-gateway",
        gateway,
        "--bfd-static",
    ])
}

/// `tc <args>` in router-a's network namespace (the runtime image has no iproute2).
pub(super) async fn tc(dock: &crate::docker::Dock, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = vec!["tc"];
    cmd.extend_from_slice(args);
    dock.in_netns(NETNS_HELPER_IMAGE, "router-a", &cmd).await
}

/// Polls `GET /v1/bfd/sessions?peer=<peer>` on `r` until its one session has
/// `state` (and `diag`, if given) — REST is a snapshot, not a log.
pub(super) async fn session_is(
    r: &crate::router::Router,
    peer: &str,
    state: &str,
    diag: Option<&str>,
    secs: u64,
) -> anyhow::Result<()> {
    let path = format!("/v1/bfd/sessions?peer={peer}");
    let mut last = String::new();
    for _ in 0..secs * 5 {
        last = r.rest_expect(Method::GET, &path, None, 200).await?;
        let v: serde_json::Value = serde_json::from_str(&last)?;
        if let Some(s) = v.as_array().and_then(|a| a.first()) {
            if s["state"] == state
                && diag.is_none_or(|d| s["diag"] == d)
                && s["key"]["peer"] == peer
            {
                return Ok(());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    anyhow::bail!(
        "{}: bfd session to {peer} never reached {state} {diag:?}: {last}",
        r.name()
    )
}

/// `bfd`, self-contained. Each router has a static route to a test prefix via
/// the other, guarded by `bfd-profile fast` (100 ms x 3): the route is
/// installed only once the session is Up. A `tc` filter in router-a's
/// namespace then drops UDP 3784 (the BFD port) on ingress: the session goes
/// Down by detection time and ribd withdraws the route; lifting it brings both
/// back. Finally a real FRR `bfdd` (`router-f`) reaches Up with router-a.
pub async fn bfd(w: &mut World) -> anyhow::Result<()> {
    let mut fa = A.base_flags();
    fa.extend(bfd_route(BFD_PREFIX_B, IP_B));
    let mut fb = B.base_flags();
    fb.extend(bfd_route(BFD_PREFIX_A, IP_A));
    w.start(A, Some(fa), &[]).await?;
    w.start(B, Some(fb), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);

    let up_a = format!("bfd session up peer={IP_B}");
    let up_b = format!("bfd session up peer={IP_A}");
    let down_a = format!("bfd session down peer={IP_B} diag=control-detection-time-expired");
    let added = format!("added route prefix={BFD_PREFIX_B} gateway={IP_B}");
    let removed = format!("removed route prefix={BFD_PREFIX_B}");

    log("both ways: sessions Up, then the guarded routes are installed");
    a.wait(&up_a).await?;
    b.wait(&up_b).await?;
    a.wait(&added).await?;

    log("GET /v1/bfd/sessions: Up; a bad ?peer= is 400");
    session_is(a, IP_B, "Up", None, 5).await?;
    session_is(b, IP_A, "Up", None, 5).await?;
    a.rest_expect(Method::GET, "/v1/bfd/sessions?peer=nope", None, 400)
        .await?;

    log("dropping UDP 3784 on router-a: Down by detection time, route withdrawn");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let (n_down, n_removed, n_up, n_added) = (
        a.count(&down_a),
        a.count(&removed),
        a.count(&up_a),
        a.count(&added),
    );
    tc(&w.dock, &["qdisc", "add", "dev", "eth0", "clsact"]).await?;
    let dropped = tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth0", "ingress", "protocol", "ip", "u32", "match", "ip",
            "protocol", "17", "0xff", "match", "ip", "dport", "3784", "0xffff", "action", "drop",
        ],
    )
    .await;
    let result = async {
        dropped?;
        a.wait_new(&down_a, n_down, 10).await?;
        a.wait_new(&removed, n_removed, 10).await?;
        session_is(a, IP_B, "Down", Some("ControlDetectionTimeExpired"), 5).await
    }
    .await;
    // Lift it whatever happened, so a failure does not leave the lab broken.
    let lifted = tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"]).await;
    result?;
    lifted?;

    log("filter lifted: Up again and the route is re-added");
    a.wait_new(&up_a, n_up, 30).await?;
    a.wait_new(&added, n_added, 30).await?;
    // The diag is whatever last took the session down: it sticks while Up,
    // so Up is only asserted without one.
    session_is(a, IP_B, "Up", None, 5).await?;

    log("interop: FRR bfdd reaches Up with router-a");
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\nbfd\n peer {IP_A}\n  \
         detect-multiplier 3\n  receive-interval 100\n  transmit-interval 100\n  \
         no shutdown\n exit\nexit\n"
    );
    w.dock.container_remove("router-f").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            IP_G,
            &[
                "sh",
                "-c",
                "sed -i 's/^bfdd=no/bfdd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;
    // FRR only answers sessions it has configured; router-a registers one
    // when a BFD static route points at FRR.
    w.a()?.provision(&bfd_route(BFD_PREFIX_F, IP_G)).await?;
    w.a()?.wait(&format!("bfd session up peer={IP_G}")).await?;
    super::ospf::frr_until(w, "show bfd peers json", 60, |out| {
        out.contains("\"status\":\"up\"")
    })
    .await?;
    w.dock.container_remove("router-f").await;
    Ok(())
}

/// Drops UDP `port` on router-a's ingress and waits for both routers to close
/// their BGP session on the resulting BFD Down (Cease/10 wrapped in a Hard
/// Reset), then lifts the filter and waits for both to re-establish.
async fn drop_udp_and_recover(w: &World, port: &str) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let est = "bgp session established";
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let closing = format!("bgp: bfd session down, closing peer={IP_B}");
    let sent = format!("sent cease notification peer={IP_B} .*subcode=10 hard_reset=true");
    // Router-b's own BFD goes Down a moment later (the peer signals it), so
    // both close at once and neither reads the other's NOTIFICATION.
    let closing_b = format!("bgp: bfd session down, closing peer={IP_A}");
    let sent_b = format!("sent cease notification peer={IP_A} .*subcode=10 hard_reset=true");
    let (n_closing, n_sent, n_closing_b, n_sent_b, est_a, est_b) = (
        a.count(&closing),
        a.count(&sent),
        b.count(&closing_b),
        b.count(&sent_b),
        a.count(est),
        b.count(est),
    );
    tc(&w.dock, &["qdisc", "add", "dev", "eth0", "clsact"]).await?;
    let dropped = tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth0", "ingress", "protocol", "ip", "u32", "match", "ip",
            "protocol", "17", "0xff", "match", "ip", "dport", port, "0xffff", "action", "drop",
        ],
    )
    .await;
    let result = async {
        dropped?;
        a.wait_new(&closing, n_closing, 10).await?;
        a.wait_new(&sent, n_sent, 10).await?;
        b.wait_new(&closing_b, n_closing_b, 10).await?;
        b.wait_new(&sent_b, n_sent_b, 10).await
    }
    .await;
    let lifted = tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"]).await;
    result?;
    lifted?;

    a.wait_new(est, est_a, 60).await?;
    b.wait_new(est, est_b, 60).await?;
    Ok(())
}

/// `bgp-bfd`, on the base lab (run after `established`). Both peer-groups get
/// `bfd fast` (100 ms x 3) without resetting the session; dropping UDP 3784
/// on router-a's ingress takes the BFD session Down by detection time and
/// both routers close the BGP session at once (Cease/10 wrapped in a Hard
/// Reset, RFC 9384 + RFC 5882 §4.3.1: N is exchanged and both ends set the C
/// bit) while the 90 s hold time is nowhere near expiring; lifting the drop
/// re-establishes; `max-hops 2` turns both into multihop sessions (UDP 4784,
/// #287) with the same behaviour; removing `bfd` again resets nothing.
pub async fn bgp_bfd(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let cease = "sent cease notification";
    let est = "bgp session established";

    a.established().await?;
    b.established().await?;
    log("adding bfd to the peer-group must not reset the session");
    let (cease_a, cease_b, est_a, est_b) =
        (a.count(cease), b.count(cease), a.count(est), b.count(est));
    a.provision(&["--bfd-bgp"]).await?;
    b.provision(&["--bfd-bgp"]).await?;
    session_is(a, IP_B, "Up", None, 30).await?;
    session_is(b, IP_A, "Up", None, 30).await?;
    a.assert_quiet(cease, cease_a, 3).await?;
    b.assert_quiet(cease, cease_b, 0).await?;
    a.assert_quiet(est, est_a, 0).await?;
    b.assert_quiet(est, est_b, 0).await?;

    log("dropping UDP 3784 on router-a: BFD Down closes the BGP session within seconds");
    drop_udp_and_recover(w, "3784").await?;
    session_is(a, IP_B, "Up", None, 30).await?;

    log("max-hops 2 makes both sessions multihop (RFC 5883, UDP 4784, TTL >= 254)");
    let registered =
        |peer: &str, hop: bool| format!("bfd session registered peer={peer} .*multihop={hop}");
    let (reg_a, reg_b) = (
        a.count(&registered(IP_B, true)),
        b.count(&registered(IP_A, true)),
    );
    a.provision(&["--max-hops", "2"]).await?;
    b.provision(&["--max-hops", "2"]).await?;
    a.wait_new(&registered(IP_B, true), reg_a, 30).await?;
    b.wait_new(&registered(IP_A, true), reg_b, 30).await?;
    a.established().await?;
    session_is(a, IP_B, "Up", None, 30).await?;
    session_is(b, IP_A, "Up", None, 30).await?;
    let path = format!("/v1/bfd/sessions?peer={IP_B}");
    let sessions = a.rest_expect(Method::GET, &path, None, 200).await?;
    let v: serde_json::Value = serde_json::from_str(&sessions)?;
    anyhow::ensure!(
        v[0]["key"]["multihop"] == true && v[0]["key"]["interface"].is_null(),
        "expected one multihop session without an interface: {sessions}"
    );
    log("dropping UDP 4784 on router-a: the multihop session closes BGP too");
    drop_udp_and_recover(w, "4784").await?;
    session_is(a, IP_B, "Up", None, 30).await?;

    log("max-hops 1 again: back to single-hop sessions");
    let (reg_a, reg_b) = (
        a.count(&registered(IP_B, false)),
        b.count(&registered(IP_A, false)),
    );
    a.provision(&["--max-hops", "1"]).await?;
    b.provision(&["--max-hops", "1"]).await?;
    a.wait_new(&registered(IP_B, false), reg_a, 30).await?;
    b.wait_new(&registered(IP_A, false), reg_b, 30).await?;
    a.established().await?;
    session_is(a, IP_B, "Up", None, 30).await?;

    log("removing bfd from the peer-group resets nothing");
    let (cease_a, cease_b, est_a, est_b) =
        (a.count(cease), b.count(cease), a.count(est), b.count(est));
    a.provision(&["--no-bfd-bgp"]).await?;
    b.provision(&["--no-bfd-bgp"]).await?;
    a.assert_quiet(cease, cease_a, 3).await?;
    b.assert_quiet(cease, cease_b, 0).await?;
    a.assert_quiet(est, est_a, 0).await?;
    b.assert_quiet(est, est_b, 0).await?;
    a.established().await
}
