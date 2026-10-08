//! BFD (RFC 5880/5881) phases.

use crate::consts::*;
use crate::router::{log, strings, A, B};
use crate::world::World;

/// `--static-route` flags: a BFD-guarded static route to `prefix` via `gateway`.
fn bfd_route(prefix: &str, gateway: &str) -> Vec<String> {
    strings(&[
        "--static-route",
        prefix,
        "--static-gateway",
        gateway,
        "--bfd-static",
    ])
}

/// `tc <args>` in router-a's network namespace (the runtime image has no iproute2).
async fn tc(dock: &crate::docker::Dock, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = vec!["tc"];
    cmd.extend_from_slice(args);
    dock.in_netns(NETNS_HELPER_IMAGE, "router-a", &cmd).await
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
        a.wait_new(&removed, n_removed, 10).await
    }
    .await;
    // Lift it whatever happened, so a failure does not leave the lab broken.
    let lifted = tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"]).await;
    result?;
    lifted?;

    log("filter lifted: Up again and the route is re-added");
    a.wait_new(&up_a, n_up, 30).await?;
    a.wait_new(&added, n_added, 30).await?;

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
