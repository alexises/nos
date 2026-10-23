//! `acl` (#541): `nos-acld` compiles an ACL to tc on router-a's `eth0`
//! ingress; the BGP session from router-b is the signal.

use reqwest::Method;

use crate::consts::*;
use crate::router::{log, Router};
use crate::world::World;

const ESTABLISHED: &str = "bgp session established";
const ENDED: &str = "bgp session ended";
/// `wait_new` counts its own pattern, so each compile has its full line.
const COMPILED_2: &str = "compiled acl acl=EDGE rules=2 filters=4 levels=2 shadowed=0";
const COMPILED_3: &str = "compiled acl acl=EDGE rules=3 filters=5 levels=3 shadowed=0";
const ATTACHED: &str = "acl attached interface=eth0 direction=in acl=EDGE";
const DETACHED: &str = "acl detached interface=eth0 direction=in";
/// Short enough that a blocked session drops within a wait; negotiated
/// down on both sides (the lower hold time wins, RFC 4271 §4.2).
const HOLD_TIME: &str = "9";

/// `PUT`s rule `d-bgp` (deny every TCP segment from router-b) at `place`
/// (`before=p-bgp`, `after=p-bgp`) in one REST transaction, then commits.
async fn put_d_bgp(a: &Router, place: &str) -> anyhow::Result<()> {
    let tx = format!("/v1/transactions/{REST_TX}");
    let _ = a.rest(Method::DELETE, &tx, None).await;
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    let rule = serde_json::json!({
        "name": "d-bgp",
        "action": "Deny",
        "protocol": "tcp",
        "source": format!("{IP_B}/32"),
    });
    a.rest_expect(
        Method::PUT,
        &format!("{tx}/acl/EDGE/rule/d-bgp?{place}"),
        Some(&rule.to_string()),
        200,
    )
    .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await
        .map(drop)
}

pub async fn acl(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    // A hold-time change restarts the session (`diff_peers`).
    let est = a.count(ESTABLISHED);
    a.provision(&["--hold-time", HOLD_TIME]).await?;
    a.wait_new(ESTABLISHED, est, 60).await?;

    // The rules match router-b's address, not port 179: who opened the
    // session (so which side owns port 179) is collision resolution's
    // choice, and router-a's REST API (from the harness host) must stay
    // reachable through every step.
    log("step 1: EDGE (default permit, p-bgp, p-icmp) on eth0 in: the session stays");
    let (compiled, attached, ended) = (a.count(COMPILED_2), a.count(ATTACHED), a.count(ENDED));
    a.provision(&[
        "--acl-default",
        "EDGE=permit",
        "--acl-rule",
        &format!("EDGE,p-bgp,permit,tcp,{IP_B}/32,any,any"),
        "--acl-rule",
        "EDGE,p-icmp,permit,icmp,any,any,any",
        "--acl-in",
        "eth0=EDGE",
    ])
    .await?;
    a.wait_new(COMPILED_2, compiled, 30).await?;
    a.wait_new(ATTACHED, attached, 30).await?;
    a.assert_quiet(ENDED, ended, 12).await?;

    log("step 2: d-bgp inserted before p-bgp: the session drops");
    let (compiled, ended) = (a.count(COMPILED_3), a.count(ENDED));
    put_d_bgp(a, "before=p-bgp").await?;
    a.wait_new(COMPILED_3, compiled, 30).await?;
    a.wait_new(ENDED, ended, 60).await?;

    log("step 3: d-bgp moved after p-bgp: the session comes back");
    let (est, compiled) = (a.count(ESTABLISHED), a.count(COMPILED_3));
    put_d_bgp(a, "after=p-bgp").await?;
    a.wait_new(COMPILED_3, compiled, 30).await?;
    a.wait_new(ESTABLISHED, est, 60).await?;

    log("step 4: acl in removed: detached, the session stays");
    let (detached, ended) = (a.count(DETACHED), a.count(ENDED));
    a.provision(&["--acl-in", "eth0="]).await?;
    a.wait_new(DETACHED, detached, 30).await?;
    a.assert_quiet(ENDED, ended, 12).await?;

    // Leave the default hold time to the phases after this one.
    let est = a.count(ESTABLISHED);
    a.provision(&["--no-hold-time"]).await?;
    a.wait_new(ESTABLISHED, est, 60).await
}
