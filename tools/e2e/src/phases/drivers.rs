//! Driver phases: what nos-interfaced / nos-ribd / nos-lacpd / nos-lldpd
//! actually program into a real kernel, proven by the log line each driver
//! emits when it does.

use std::time::Duration;

use anyhow::{bail, Context as _};
use reqwest::Method;

use crate::consts::*;
use crate::router::{log, strings, Router, R};
use crate::world::World;

pub async fn loopback(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    // #275: the link watcher streams the kernel's own view; baselines because
    // an earlier phase may already have created lo100.
    let changed = format!("link state changed name={LOOPBACK_DEVICE}");
    let removed = format!("link removed name={LOOPBACK_DEVICE}");
    let (changed_base, removed_base) = (a.count(&changed), a.count(&removed));
    a.provision(&["--loopback-address", LOOPBACK_ADDRESS])
        .await?;
    a.wait(&format!("created loopback device device={LOOPBACK_DEVICE}"))
        .await?;
    a.wait_new(&changed, changed_base, 30).await?;
    a.wait("enslaved interface to vrf interface=loopback-rt1")
        .await?;
    a.wait(&format!(
        "added interface address interface=loopback-rt1 address={LOOPBACK_ADDRESS}"
    ))
    .await?;
    // #117: `--loopback-address` sets no routing-table; the name alone puts
    // it in rt1, connected route included.
    a.wait_connected(LOOPBACK_ADDRESS).await?;

    log("removing router-a's loopback interface");
    a.provision(&["--delete-loopback"]).await?;
    a.wait(&format!(
        "deleted loopback device interface=loopback-rt1 device={LOOPBACK_DEVICE}"
    ))
    .await?;
    a.wait_new(&removed, removed_base, 30).await
}

/// Sets eth0's MTU, then clears it: unset is 1500, enforced (#117), and
/// REST reports what the link is held at. Leaves eth0 at the docker default
/// for later phases.
pub async fn mtu(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.provision(&["--mtu", &MTU_VALUE.to_string()]).await?;
    a.wait(&format!(
        "applied interface mtu interface=eth0 mtu={MTU_VALUE}"
    ))
    .await?;
    expect_eth0_mtu(a, MTU_VALUE).await?;

    let reset = "applied interface mtu interface=eth0 mtu=1500";
    let base = a.count(reset);
    a.provision(&["--clear-mtu"]).await?;
    a.wait_new(reset, base, 30).await?;
    expect_eth0_mtu(a, 1500).await
}

async fn expect_eth0_mtu(a: &Router, want: u32) -> anyhow::Result<()> {
    let body = a
        .rest_expect(Method::GET, "/v1/interfaces/eth0", None, 200)
        .await?;
    let status: serde_json::Value = serde_json::from_str(&body)?;
    if status["mtu"] != want {
        bail!(
            "router-a: GET /v1/interfaces/eth0 reports mtu {}, want {want}",
            status["mtu"]
        );
    }
    log(format!("router-a: rest reports eth0 mtu {want}"));
    Ok(())
}

pub async fn port_aggregate(w: &mut World) -> anyhow::Result<()> {
    w.connect_bond_networks().await?;
    let a = w.a()?;
    let members = [
        "--port-aggregate",
        "bond1",
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--enslave-interface-into-port-aggregate",
        "eth2",
    ];
    a.provision(&members).await?;
    a.wait("created port aggregate bond port_aggregate=bond1 bond=bond1 mode=Xor")
        .await?;
    a.wait("enslaved interface to bond interface=eth1 bond=bond1")
        .await?;
    a.wait("enslaved interface to bond interface=eth2 bond=bond1")
        .await?;
    // #117: a bond subinterface's address is a connected route too.
    a.provision(
        &[
            &members[..],
            &["--port-aggregate-address", PORT_AGGREGATE_ADDRESS],
        ]
        .concat(),
    )
    .await?;
    a.wait_connected(PORT_AGGREGATE_SUBNET).await?;

    let mut delete = members.to_vec();
    delete.push("--delete-port-aggregate");
    a.provision(&delete).await?;
    // Deleting the bond already releases both slaves as a kernel side effect
    // of destroying their master, so there is no separate "unenslaved" line:
    // the bond's own deletion is this phase's teardown assertion.
    a.wait("deleted port aggregate bond port_aggregate=bond1 bond=bond1")
        .await
}

fn lacp_flags(extra: &[&str]) -> Vec<String> {
    let mut f = strings(&[
        "--port-aggregate",
        LACP_AGGREGATE,
        "--port-aggregate-mode",
        "lacp",
    ]);
    f.extend(strings(extra));
    f
}

pub async fn lacp(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    // The kernel bond is named from nos-interfaced's registry id (bond<id>),
    // which depends on which aggregates earlier phases created — so match any
    // bond name, with baselines taken before provisioning.
    let mut enslave_base = Vec::new();
    for r in [a, b] {
        for iface in ["eth1", "eth2"] {
            enslave_base.push(r.count(&format!(
                "enslaved interface to bond interface={iface} bond=bond"
            )));
        }
    }
    let release_base = a.count("removed interface from master enslavement interface=eth2");

    w.link_veths().await?;
    let both = [
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--enslave-interface-into-port-aggregate",
        "eth2",
    ];
    // A configured Actor System ID per router (`lacp-system-id`), proven on
    // the wire below by each side seeing the other's as its partner.
    let mut on = lacp_flags(&["--lacp-rate", "fast"]);
    on.extend(strings(&both));
    let mut on_a = on.clone();
    on_a.extend(strings(&["--lacp-system-id", LACP_SYSTEM_ID_A]));
    on_a.extend(strings(&[
        "--lacp-system-priority",
        &LACP_SYSTEM_PRIORITY_A.to_string(),
        "--lacp-port-priority",
        &LACP_PORT_PRIORITY_A.to_string(),
    ]));
    let mut on_b = on;
    on_b.extend(strings(&["--lacp-system-id", LACP_SYSTEM_ID_B]));
    on_b.extend(strings(&[
        "--lacp-system-priority",
        &LACP_SYSTEM_PRIORITY_B.to_string(),
        "--lacp-port-priority",
        &LACP_PORT_PRIORITY_B.to_string(),
    ]));
    a.provision(&on_a).await?;
    b.provision(&on_b).await?;

    let reconciled =
        format!("lacp reconciled aggregate members aggregate={LACP_AGGREGATE} members=2");
    a.wait(&reconciled).await?;
    b.wait(&reconciled).await?;

    log("waiting for real lacpdu negotiation to reach Distributing on both routers/both links");
    for r in [a, b] {
        for iface in ["eth1", "eth2"] {
            r.wait(&format!(
                "interface={iface} receive_state=Current mux_state=Distributing"
            ))
            .await?;
        }
    }

    log("the configured lacp-system-id is the actor id, and the partner sees it");
    let body = a
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    let summary: serde_json::Value = serde_json::from_str(&body)?;
    let agg = summary
        .as_array()
        .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
        .with_context(|| format!("no {LACP_AGGREGATE} in show lacp: {body}"))?;
    let id = |mac: [u8; 6]| serde_json::json!(mac);
    if agg["actor_system_id"] != id([2, 0, 0, 0, 0x0a, 1]) {
        bail!("router-a's actor system id is not the configured one: {body}");
    }
    if !agg["ports"].as_array().is_some_and(|p| {
        p.iter()
            .all(|p| p["partner_system_id"] == id([2, 0, 0, 0, 0x0b, 1]))
    }) {
        bail!("router-a's partners are not router-b's configured system id: {body}");
    }

    log("configured system/port priorities are advertised, and each side sees the other's");
    for (r, sys, port, p_sys, p_port) in [
        (
            a,
            LACP_SYSTEM_PRIORITY_A,
            LACP_PORT_PRIORITY_A,
            LACP_SYSTEM_PRIORITY_B,
            LACP_PORT_PRIORITY_B,
        ),
        (
            b,
            LACP_SYSTEM_PRIORITY_B,
            LACP_PORT_PRIORITY_B,
            LACP_SYSTEM_PRIORITY_A,
            LACP_PORT_PRIORITY_A,
        ),
    ] {
        let body = r
            .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
            .await?;
        let summary: serde_json::Value = serde_json::from_str(&body)?;
        let agg = summary
            .as_array()
            .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
            .with_context(|| format!("no {LACP_AGGREGATE} in show lacp: {body}"))?;
        if agg["actor_system_priority"] != sys
            || !agg["ports"].as_array().is_some_and(|ports| {
                ports.iter().all(|p| {
                    p["actor_port_priority"] == port
                        && p["partner_system_priority"] == p_sys
                        && p["partner_port_priority"] == p_port
                })
            })
        {
            bail!("lacp priorities are not the configured ones (want sys {sys} port {port}, partner {p_sys}/{p_port}): {body}");
        }
    }

    log("waiting for both routers to actually enslave eth1/eth2 into the real kernel bond");
    let mut base = enslave_base.into_iter();
    for r in [a, b] {
        for iface in ["eth1", "eth2"] {
            r.wait_new(
                &format!("enslaved interface to bond interface={iface} bond=bond"),
                base.next().unwrap_or(0),
                60,
            )
            .await?;
        }
    }

    // 802.1AX §6.5 Marker responder: a real Marker PDU injected on router-b's
    // eth1 (source = its own MAC, so only router-a answers) must come back as
    // a byte-correct Marker Response, and router-a logs it.
    log("router-a answers a real injected Marker PDU on eth1");
    w.dock
        .ensure_image(
            PYTHON_HELPER_IMAGE,
            "FROM debian:bookworm-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    let marker_base = a.count("lacp marker answered interface=eth1");
    w.dock
        .in_netns(
            PYTHON_HELPER_IMAGE,
            "router-b",
            &["python3", "-c", include_str!("marker.py")],
        )
        .await?;
    a.wait_new(
        "lacp marker answered interface=eth1 requester_port=7 .* transaction_id=1313821529",
        marker_base,
        15,
    )
    .await?;

    // Withdraw eth2 from router-b's aggregate (its veth stays up): router-a's
    // nos-lacpd must detect the silence via its real Receive Machine timeout
    // and nos-interfaced must release eth2 — proving the enslavement is
    // dynamic. Both sides run `lacp-rate fast`, so the 30s budget is far under
    // the 90s Long timer, which proves the fast rate is really in effect. The
    // Expired baseline is taken here since a port also passes through Expired
    // while first starting up.
    let expired_base = a.count("interface=eth2 receive_state=Expired");
    let churn = "lacp partner churn machine transitioned interface=eth2 churn=Churn";
    let churn_base = a.count(churn);
    let mut withdraw = lacp_flags(&["--lacp-rate", "fast"]);
    withdraw.extend(strings(&[
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--clear-port-aggregate-member",
        "eth2",
    ]));
    b.provision(&withdraw).await?;
    a.wait_new("interface=eth2 receive_state=Expired", expired_base, 30)
        .await?;
    a.wait_new(
        "removed interface from master enslavement interface=eth2",
        release_base,
        30,
    )
    .await?;

    // 802.1AX churn detection: eth2 stays out of sync past the (shortened)
    // churn-detection time, so it is flagged churned — and, being kept out of
    // the active set, stays out of the bond — while eth1 is untouched.
    log("the silent partner port is flagged as churned in show lacp");
    a.wait_new(churn, churn_base, 30).await?;
    let body = a
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    let summary: serde_json::Value = serde_json::from_str(&body)?;
    let port = |name: &str| {
        summary
            .as_array()
            .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
            .and_then(|s| s["ports"].as_array())
            .and_then(|p| p.iter().find(|p| p["interface"] == name))
            .cloned()
    };
    let (eth1, eth2) = (port("eth1"), port("eth2"));
    if eth2.is_none_or(|p| p["partner_churn"] != true)
        || eth1.is_none_or(|p| p["partner_churn"] != false)
    {
        bail!("expected eth2 partner_churn=true and eth1 partner_churn=false: {body}");
    }

    // Recovery: router-b takes eth2 back, the partner syncs again, so the
    // churn flag clears and nos-interfaced enslaves eth2 into the bond anew.
    log("the partner port comes back: churn clears and eth2 rejoins the bond");
    let cleared = "lacp partner churn machine transitioned interface=eth2 churn=NoChurn";
    let cleared_base = a.count(cleared);
    let rejoin_base = a.count("enslaved interface to bond interface=eth2 bond=bond");
    let mut restore = lacp_flags(&["--lacp-rate", "fast"]);
    restore.extend(strings(&both));
    b.provision(&restore).await?;
    a.wait_new(cleared, cleared_base, 60).await?;
    a.wait_new(
        "enslaved interface to bond interface=eth2 bond=bond",
        rejoin_base,
        60,
    )
    .await?;
    let body = a
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    if body.contains("\"partner_churn\":true") {
        bail!("a partner is still flagged churned after recovery: {body}");
    }

    // A changed system priority restarts router-a's members, which
    // renegotiate: router-b ends up seeing the new value from a Current,
    // Distributing partner again.
    log("changing router-a's system priority restarts its members and they renegotiate");
    let mut changed = lacp_flags(&["--lacp-rate", "fast"]);
    changed.extend(strings(&both));
    changed.extend(strings(&[
        "--lacp-system-priority",
        &LACP_SYSTEM_PRIORITY_A_CHANGED.to_string(),
    ]));
    a.provision(&changed).await?;
    let mut seen = false;
    for _ in 0..30 {
        let body = b
            .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
            .await?;
        let summary: serde_json::Value = serde_json::from_str(&body)?;
        seen = summary
            .as_array()
            .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
            .and_then(|s| s["ports"].as_array())
            .is_some_and(|ports| {
                ports.iter().all(|p| {
                    p["partner_system_priority"] == LACP_SYSTEM_PRIORITY_A_CHANGED
                        && p["mux_state"] == "Distributing"
                })
            });
        if seen {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if !seen {
        bail!("router-b never saw router-a's changed system priority on Distributing ports");
    }

    lacp_passive(a, b, &both).await?;
    lacp_min_links(w, &both).await?;

    let mut off = lacp_flags(&[]);
    off.extend(strings(&both));
    off.push("--delete-port-aggregate".into());
    a.provision(&off).await?;
    b.provision(&off).await?;
    let deleted = format!("deleted port aggregate bond port_aggregate={LACP_AGGREGATE} bond=");
    a.wait(&deleted).await?;
    b.wait(&deleted).await?;

    w.unlink_veths().await;
    Ok(())
}

/// Polls `GET /v1/lacp` on `r` until every port of the aggregate satisfies
/// `want` (and there is at least one), up to 40s.
async fn wait_lacp_ports(
    r: &Router,
    what: &str,
    want: impl Fn(&serde_json::Value) -> bool,
) -> anyhow::Result<()> {
    let mut body = String::new();
    for _ in 0..40 {
        body = r
            .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
            .await?;
        let summary: serde_json::Value = serde_json::from_str(&body)?;
        if summary
            .as_array()
            .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
            .and_then(|s| s["ports"].as_array())
            .is_some_and(|ports| !ports.is_empty() && ports.iter().all(&want))
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    bail!("{}: {what} never held: {body}", r.name())
}

/// One member port of `LACP_AGGREGATE` in `r`'s `GET /v1/lacp`.
async fn lacp_port(r: &Router, name: &str) -> anyhow::Result<serde_json::Value> {
    let body = r
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    let summary: serde_json::Value = serde_json::from_str(&body)?;
    summary
        .as_array()
        .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
        .and_then(|s| s["ports"].as_array())
        .and_then(|p| p.iter().find(|p| p["interface"] == name))
        .cloned()
        .with_context(|| format!("no port {name} in show lacp: {body}"))
}

/// `min-links`: with 2 and one member silent the bond is emptied (the other
/// port keeps negotiating), and refills when it returns; then a scripted
/// partner that clears Actor_State.Aggregation makes eth2 an Individual port,
/// which is never selected. (No kernel bond can play that partner: bonding
/// always sets Aggregation, even on an unknown-duplex slave.)
async fn lacp_min_links(w: &World, both: &[&str]) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let min_links = |n: &str| {
        let mut f = lacp_flags(&["--lacp-rate", "fast", "--min-links", n]);
        f.extend(strings(both));
        f
    };
    let reconciled = format!("lacp reconciled aggregate members aggregate={LACP_AGGREGATE}");
    let base = a.count(&reconciled);
    log("min-links 2 with both members Distributing changes nothing");
    a.provision(&min_links("2")).await?;
    a.assert_quiet(&reconciled, base, 5).await?;

    log("router-b withdraws eth2: below min-links the bond is emptied, eth1 keeps negotiating");
    let emptied = "lacp min-links not met, bond emptied";
    let emptied_base = a.count(emptied);
    let release_base = a.count("removed interface from master enslavement interface=eth1");
    let enslave_base = a.count("enslaved interface to bond interface=eth1 bond=bond");
    let mut withdraw = lacp_flags(&["--lacp-rate", "fast"]);
    withdraw.extend(strings(&[
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--clear-port-aggregate-member",
        "eth2",
    ]));
    b.provision(&withdraw).await?;
    a.wait_new(emptied, emptied_base, 30).await?;
    a.wait_new(
        "removed interface from master enslavement interface=eth1",
        release_base,
        30,
    )
    .await?;
    let eth1 = lacp_port(a, "eth1").await?;
    if eth1["mux_state"] != "Distributing" || eth1["selected"] != true {
        bail!("eth1 stopped negotiating when min-links emptied the bond: {eth1}");
    }

    log("a partner that clears Aggregation makes eth2 an Individual port: never selected");
    w.dock
        .ensure_image(
            PYTHON_HELPER_IMAGE,
            "FROM debian:bookworm-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    let inject = w.dock.in_netns(
        PYTHON_HELPER_IMAGE,
        "router-b",
        &["python3", "-c", include_str!("individual.py")],
    );
    let check = async {
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let eth2 = lacp_port(a, "eth2").await?;
            if eth2["individual"] == true {
                let eth1 = lacp_port(a, "eth1").await?;
                if eth2["receive_state"] != "Current"
                    || eth2["selected"] != false
                    || eth2["mux_state"] == "Distributing"
                    || eth1["selected"] != true
                {
                    bail!("individual eth2 was selected or cost eth1 its selection: {eth2} {eth1}");
                }
                return Ok(());
            }
        }
        bail!("eth2 never showed individual=true")
    };
    let (injected, checked) = tokio::join!(inject, check);
    injected?;
    checked?;

    log("router-b restores eth2: the bond refills");
    let mut restore = lacp_flags(&["--lacp-rate", "fast"]);
    restore.extend(strings(both));
    b.provision(&restore).await?;
    a.wait_new(
        "enslaved interface to bond interface=eth1 bond=bond",
        enslave_base,
        60,
    )
    .await?;
    wait_lacp_ports(a, "both ports Distributing again", |p| {
        p["mux_state"] == "Distributing" && p["individual"] == false
    })
    .await?;

    a.provision(&min_links("1")).await
}

/// `lacp-mode` (802.1AX LACP_Activity, NO_PERIODIC): passive against active
/// still converges, passive against passive never forms a bundle and stays
/// silent, and back to active converges again.
async fn lacp_passive(a: &Router, b: &Router, both: &[&str]) -> anyhow::Result<()> {
    let flags = |mode: &str| {
        let mut f = lacp_flags(&["--lacp-rate", "fast", "--lacp-mode", mode]);
        f.extend(strings(both));
        f
    };
    let distributing = |p: &serde_json::Value| p["mux_state"] == "Distributing";

    log("router-a passive, router-b active: the passive port still answers and both converge");
    a.provision(&flags("passive")).await?;
    wait_lacp_ports(a, "passive port Distributing", |p| {
        distributing(p) && p["mode"] == "Passive"
    })
    .await?;
    wait_lacp_ports(b, "active port Distributing", distributing).await?;

    log("both passive: nobody speaks, no port is Distributing and the bond is emptied");
    let none = "lacp periodic transmission machine transitioned interface=eth1 no_periodic=true";
    let (none_a, none_b) = (a.count(none), b.count(none));
    let release = a.count("removed interface from master enslavement interface=eth1");
    b.provision(&flags("passive")).await?;
    a.wait_new(none, none_a, 30).await?;
    b.wait_new(none, none_b, 30).await?;
    a.wait_new(
        "removed interface from master enslavement interface=eth1",
        release,
        30,
    )
    .await?;
    for r in [a, b] {
        wait_lacp_ports(r, "no port Distributing", |p| !distributing(p)).await?;
    }
    // Let the last in-flight LACPDUs drain, then nothing may arrive.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let rx = "lacp lacpdu received";
    let (rx_a, rx_b) = (a.count(rx), b.count(rx));
    a.assert_quiet(rx, rx_a, 10).await?;
    b.assert_quiet(rx, rx_b, 0).await?;

    log("router-a back to active: the pair converges again");
    a.provision(&flags("active")).await?;
    for r in [a, b] {
        wait_lacp_ports(r, "Distributing again", distributing).await?;
    }
    // b is still passive; put it back so later phases see the default.
    b.provision(&flags("active")).await?;
    for r in [a, b] {
        wait_lacp_ports(r, "Distributing, both active", |p| {
            distributing(p) && p["mode"] == "Active"
        })
        .await?;
    }
    Ok(())
}

pub async fn lldp(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let learned_a = |extra: &str| {
        format!("lldp neighbor learned interface=eth1 .* system_name=router-b{extra}")
    };
    let learned_b = |extra: &str| {
        format!("lldp neighbor learned interface=eth1 .* system_name=router-a{extra}")
    };
    let shutdown = "lldp neighbor removed interface=eth1 .* reason=\"shutdown\"";
    // Each router advertises its container name as its System Name.
    let host = |name: &'static str, extra: &[&str]| {
        let mut f = vec!["--hostname", name];
        f.extend_from_slice(extra);
        f.into_iter().map(String::from).collect::<Vec<_>>()
    };
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    let started_a = a.count("lldp link started interface=eth1 transmit=true receive=false");
    // The last frame of an 802.1AB fast-start burst (txFastInit = 4 at 1s).
    let burst_done = "lldp fast-start tx interface=eth1 remaining=0";
    let (burst_a, burst_b) = (a.count(burst_done), b.count(burst_done));

    w.link_veths().await?;
    let on = [
        "--lldp-transmit-interface",
        "eth1",
        "--lldp-receive-interface",
        "eth1",
    ];
    a.provision(&host("router-a", &on)).await?;
    b.provision(&host("router-b", &on)).await?;

    log("waiting for both routers' nos-lldpd to learn the other over the real veth");
    // ttl=120 is the 802.1AB default (tx-interval 30 x tx-hold 4).
    a.wait_new(
        &learned_a(" ttl=120").replace(".* system_name", ".* port_id=eth1 system_name"),
        base_a,
        60,
    )
    .await?;
    b.wait_new(
        &learned_b(" ttl=120").replace(".* system_name", ".* port_id=eth1 system_name"),
        base_b,
        60,
    )
    .await?;
    // Link start and the new neighbor each open a fast-start burst: all four
    // frames go out within seconds (at 1s spacing), not one per 30s interval.
    a.wait_new(burst_done, burst_a, 15).await?;
    b.wait_new(burst_done, burst_b, 15).await?;

    // Tunable timers + Management Address TLVs: tx-interval 5 x tx-hold 3 must
    // show up as the TTL the neighbor learned (15), and each router's own
    // address as a management address carrying its eth0's real ifIndex
    // (resolved in the sender's netns; docker keeps the veth's host-side
    // index, so only non-zero is checked). router-b also advertises an
    // address on no interface, sent with the "unknown" numbering: two TLVs in
    // one LLDPDU.
    let on_if = |ip: &str| format!("{ip} (ifindex [1-9][0-9]*)");
    let mgmt_a = learned_a(&format!(
        " ttl=15 management_addresses={},{MGMT_NOWHERE} capabilities=",
        on_if(IP_B)
    ));
    let mgmt_b = learned_b(&format!(
        " ttl=15 management_addresses={} capabilities=",
        on_if(IP_A)
    ));
    let (base_ma, base_mb) = (a.count(&mgmt_a), b.count(&mgmt_b));
    a.provision(&host(
        "router-a",
        &[
            "--lldp-tx-interval",
            "5",
            "--lldp-tx-hold",
            "3",
            "--lldp-management-address",
            IP_A,
        ],
    ))
    .await?;
    b.provision(&host(
        "router-b",
        &[
            "--lldp-tx-interval",
            "5",
            "--lldp-tx-hold",
            "3",
            "--lldp-management-address",
            IP_B,
            "--lldp-management-address",
            MGMT_NOWHERE,
        ],
    ))
    .await?;
    a.wait_new(&mgmt_a, base_ma, 60).await?;
    b.wait_new(&mgmt_b, base_mb, 60).await?;

    // Removing one address restarts router-b's link; router-a relearns it
    // with only the other.
    let only_b = learned_a(&format!(
        " ttl=15 management_addresses={} capabilities=",
        on_if(IP_B)
    ));
    let base_ob = a.count(&only_b);
    b.provision(&host(
        "router-b",
        &["--no-lldp-management-address", MGMT_NOWHERE],
    ))
    .await?;
    a.wait_new(&only_b, base_ob, 60).await?;

    lldp_org_tlvs(w).await?;

    // 802.1AB counters over REST: both sides sent and received real frames,
    // none of them bad, and nos sends only TLVs nos recognizes.
    for r in [a, b] {
        let s = lldp_eth1_stats(r).await?;
        if s.frames_out == 0
            || s.frames_in == 0
            || s.frames_in_errors != 0
            || s.tlvs_unrecognized != 0
        {
            bail!("{}: unexpected lldp counters on eth1: {s:?}", r.name());
        }
    }

    // TTL expiry for real: freeze router-b's nos-lldpd (no shutdown frame) and
    // router-a must age it out on the 15s TTL alone, counting it, then learn
    // it again once it resumes.
    let expired = "lldp neighbor removed interface=eth1 .* reason=\"expired\"";
    let (base_exp, ageouts) = (a.count(expired), lldp_eth1_stats(a).await?.ageouts);
    log("freezing router-b's nos-lldpd: router-a must age it out within its 15s ttl");
    w.dock
        .signal_process("router-b", "nos-lldpd", "-STOP")
        .await?;
    let aged = a.wait_new(expired, base_exp, 25).await;
    let base_a = a.count(&learned_a(""));
    w.dock
        .signal_process("router-b", "nos-lldpd", "-CONT")
        .await?;
    aged?;
    if lldp_eth1_stats(a).await?.ageouts != ageouts + 1 {
        bail!("router-a's lldp ageouts counter did not go up by one");
    }
    a.wait_new(&learned_a(""), base_a, 30).await?;

    // Destination group. Both on customer-bridge: still neighbors. Then only
    // router-b back on nearest-bridge: the groups never see each other, though
    // both keep transmitting. Then router-a follows and both learn again.
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    let cb = ["--lldp-destination-interface", "eth1=customer-bridge"];
    a.provision(&host("router-a", &cb)).await?;
    b.provision(&host("router-b", &cb)).await?;
    a.wait_new(&learned_a(""), base_a, 60).await?;
    b.wait_new(&learned_b(""), base_b, 60).await?;

    let removed = a.count(shutdown);
    let nb = ["--lldp-destination-interface", "eth1=nearest-bridge"];
    b.provision(&host("router-b", &nb)).await?;
    a.wait_new(shutdown, removed, 30).await?;
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    log("mismatched destination groups: neither side may learn the other (waiting 15s)");
    tokio::time::sleep(Duration::from_secs(15)).await;
    if a.count(&learned_a("")) != base_a || b.count(&learned_b("")) != base_b {
        bail!("a neighbor was learned across mismatched destination groups");
    }
    a.provision(&host("router-a", &nb)).await?;
    a.wait_new(&learned_a(""), base_a, 60).await?;
    b.wait_new(&learned_b(""), base_b, 60).await?;

    // router-b stops transmitting: on the way out its link sends a real TTL-0
    // shutdown LLDPDU, which router-a must act on within seconds (far under the
    // 120s TTL) — proving shutdown handling rather than aging.
    let removed = a.count(shutdown);
    b.provision(&host("router-b", &["--no-lldp-transmit-interface", "eth1"]))
        .await?;
    a.wait_new(shutdown, removed, 30).await?;

    // Transmit comes back: router-a learns router-b again, and router-b (which
    // restarted with an empty table) learns router-a quickly, because learning
    // a *new* neighbor triggers a fast-start burst.
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    b.provision(&host("router-b", &["--lldp-transmit-interface", "eth1"]))
        .await?;
    a.wait_new(&learned_a(""), base_a, 30).await?;
    b.wait_new(&learned_b(""), base_b, 15).await?;

    // Drop receive on router-a: its link restarts as transmit-only.
    a.provision(&host("router-a", &["--no-lldp-receive-interface", "eth1"]))
        .await?;
    a.wait_new(
        "lldp link started interface=eth1 transmit=true receive=false",
        started_a,
        30,
    )
    .await?;

    // Tear down. The baseline is taken here: every restart above also logs a
    // "link stopped" line.
    let stopped = a.count("lldp link stopped interface=eth1");
    a.provision(&host("router-a", &["--no-lldp-transmit-interface", "eth1"]))
        .await?;
    b.provision(&host(
        "router-b",
        &[
            "--no-lldp-transmit-interface",
            "eth1",
            "--no-lldp-receive-interface",
            "eth1",
        ],
    ))
    .await?;
    a.wait_new("lldp link stopped interface=eth1", stopped, 30)
        .await?;

    w.unlink_veths().await;
    Ok(())
}

/// 802.1/802.3 org TLVs (#63), router-a sending, router-b receiving. The
/// domain and profile are `switching`'s own `bd1`/`sp1`: bridge ids are
/// allocated once per name and never freed, so a new domain here would take
/// the `br1` that phase expects for `bd1`.
async fn lldp_org_tlvs(w: &World) -> anyhow::Result<()> {
    let host = |name: &str, extra: &[&str]| {
        let mut f = vec!["--hostname", name];
        f.extend_from_slice(extra);
        strings(&f)
    };
    let (a, b) = (w.a()?, w.b()?);
    let learned = |iface: &str, extra: &str| {
        format!("lldp neighbor learned interface={iface} .* system_name=router-a .*{extra}$")
    };
    // A switching-profile port with a jumbo MTU: the Bridge bit, Maximum
    // Frame Size (MTU + 18) and one VLAN Name per dot1q member. The link
    // restarts on the change (shutdown frame, then a fresh "learned").
    let trunk = learned(
        "eth1",
        " capabilities=bridge,router max_frame_size=9018 vlans=100:bd1 aggregation=-",
    );
    let base = b.count(&trunk);
    a.provision(&host(
        "router-a",
        &[
            "--link-interface",
            "eth1",
            "--mtu",
            "9000",
            "--switching-profile",
            "sp1",
            "--switching-profile-member",
            "bd1:100",
        ],
    ))
    .await?;
    b.wait_new(&trunk, base, 60).await?;

    // A port-aggregate member, enslaved first so the very first LLDPDU
    // already carries the bond's ifIndex (only non-zero is checked: it
    // depends on how many links the container created before).
    let bond = [
        "--port-aggregate",
        "po-lldp",
        "--enslave-interface-into-port-aggregate",
        "eth2",
    ];
    let enslaved = "enslaved interface to bond interface=eth2 bond=";
    let base = a.count(enslaved);
    a.provision(&host("router-a", &bond)).await?;
    a.wait_new(enslaved, base, 60).await?;
    let member = learned(
        "eth2",
        " max_frame_size=1518 vlans= aggregation=enabled/[1-9][0-9]*",
    );
    let base = b.count(&member);
    a.provision(&host("router-a", &["--lldp-transmit-interface", "eth2"]))
        .await?;
    b.provision(&host("router-b", &["--lldp-receive-interface", "eth2"]))
        .await?;
    b.wait_new(&member, base, 60).await?;

    // Back to the base state the rest of the phase expects.
    let plain = learned(
        "eth1",
        " capabilities=router max_frame_size=1518 vlans= aggregation=-",
    );
    let base = b.count(&plain);
    let mut undo = bond.to_vec();
    undo.extend([
        "--delete-port-aggregate",
        "--no-lldp-transmit-interface",
        "eth2",
        "--link-interface",
        "eth1",
        "--clear-mtu",
        "--delete-switching-profile",
    ]);
    a.provision(&host("router-a", &undo)).await?;
    b.provision(&host("router-b", &["--no-lldp-receive-interface", "eth2"]))
        .await?;
    b.wait_new(&plain, base, 60).await
}

/// `eth1`'s row of `GET /v1/lldp/statistics`.
async fn lldp_eth1_stats(r: &Router) -> anyhow::Result<nos_proto::LldpLinkStats> {
    let body = r
        .rest_expect(Method::GET, "/v1/lldp/statistics", None, 200)
        .await?;
    let rows: Vec<nos_proto::LldpLinkStats> = serde_json::from_str(&body)?;
    rows.into_iter()
        .find(|s| s.interface == "eth1")
        .with_context(|| format!("{}: no eth1 row in lldp statistics: {body}", r.name()))
}

pub async fn switching(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.provision(&[
        "--switching-profile",
        "sp1",
        "--switching-profile-member",
        "bd1:100",
        "--switching-profile-member",
        "bd2:200",
    ])
    .await?;
    a.wait("created broadcast domain bridge domain=bd1 bridge=br1")
        .await?;
    a.wait("created broadcast domain bridge domain=bd2 bridge=br2")
        .await?;
    a.wait("created vlan sub-interface interface=eth0 sub_interface=eth0.100 tag=100")
        .await?;
    a.wait("created vlan sub-interface interface=eth0 sub_interface=eth0.200 tag=200")
        .await?;
    a.wait("enslaved interface to bridge interface=eth0.100 bridge=br1")
        .await?;
    a.wait("enslaved interface to bridge interface=eth0.200 bridge=br2")
        .await?;

    a.provision(&["--delete-switching-profile"]).await?;
    a.wait("deleted vlan sub-interface interface=eth0 sub_interface=eth0.100")
        .await?;
    a.wait("deleted vlan sub-interface interface=eth0 sub_interface=eth0.200")
        .await
}

pub async fn svi(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.provision(&[
        "--routing-table",
        "rt1",
        "--broadcast-domain",
        "bd-svi",
        "--broadcast-domain-svi-address",
        SVI_ADDRESS,
    ])
    .await?;
    // bd-svi's bridge id depends on how many domains this container allocated
    // before, so its name is read from the line the driver just emitted.
    let created = "created broadcast domain bridge domain=bd-svi bridge=br[0-9]*";
    a.wait(created).await?;
    let line = a.logs.last(created).unwrap_or_default();
    let Some(bridge) = regex::Regex::new(r"domain=bd-svi bridge=(br[0-9]+)")?
        .captures(&line)
        .map(|c| c[1].to_string())
    else {
        bail!("no bridge name in: {line}");
    };
    log(format!("router-a: created {bridge} for bd-svi"));
    a.wait(&format!("enslaved interface to vrf interface={bridge}"))
        .await?;
    a.wait(&format!(
        "added interface address interface={bridge} address={SVI_ADDRESS}"
    ))
    .await?;

    a.provision(&[
        "--broadcast-domain",
        "bd-svi",
        "--delete-broadcast-domain-svi",
    ])
    .await?;
    a.wait(&format!(
        "deleted broadcast domain bridge domain=bd-svi bridge={bridge}"
    ))
    .await
}

pub async fn routed_subinterface(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let tag = SUBINTERFACE_TAG;
    let sub = |extra: &[&str]| {
        let mut f = strings(&[
            "--address",
            SUBINTERFACE_ADDRESS,
            "--subinterface-tag",
            &tag.to_string(),
        ]);
        f.extend(strings(&[
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--remote-as",
            &ASN_B.to_string(),
            "--peer",
            IP_B,
        ]));
        f.extend(strings(extra));
        f
    };
    a.provision_flags(&sub(&["--routing-table", "rt1"])).await?;
    a.wait(&format!(
        "created vlan sub-interface interface=eth0 sub_interface=eth0.{tag} tag={tag}"
    ))
    .await?;
    // The same VRF eth0 itself is already a member of — a VRF has many members.
    a.wait(&format!("enslaved interface to vrf interface=eth0.{tag}"))
        .await?;
    a.wait(&format!(
        "added interface address interface=eth0.{tag} address={SUBINTERFACE_ADDRESS}"
    ))
    .await?;

    a.provision_flags(&sub(&["--delete-subinterface"])).await?;
    a.wait(&format!(
        "deleted vlan sub-interface interface=eth0 sub_interface=eth0.{tag}"
    ))
    .await
}

/// `source-address` is resolved by nos-bgpd itself over a real IPC round trip to
/// nos-interfaced, including `loopback` derived from its own routing table.
pub async fn source_address(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    a.provision(&["--source-address-interface", "eth0"]).await?;
    a.wait(&format!(
        "resolved peer-group source-address peer_group=pg1 addresses=\\[{IP_A}\\]"
    ))
    .await?;
    a.established().await?;
    b.established().await?;

    a.provision(&["--loopback-address", LOOPBACK_ADDRESS])
        .await?;
    a.wait(&format!(
        "added interface address interface=loopback-rt1 address={LOOPBACK_ADDRESS}"
    ))
    .await?;

    a.provision(&["--source-address-loopback"]).await?;
    let loopback_ip = LOOPBACK_ADDRESS
        .split('/')
        .next()
        .unwrap_or(LOOPBACK_ADDRESS);
    a.wait(&format!(
        "resolved peer-group source-address peer_group=pg1 addresses=\\[{loopback_ip}\\]"
    ))
    .await?;

    a.provision(&["--clear-source-address"]).await?;
    a.provision(&["--delete-loopback"]).await?;
    a.established().await
}

/// Polls `container`'s docker logs for `needle` — only for the checks below,
/// where REST (and so its log stream) is exactly what is being killed.
async fn wait_docker_log(
    w: &World,
    container: &str,
    needle: &str,
    secs: u64,
) -> anyhow::Result<()> {
    for _ in 0..secs {
        if w.dock.logs(container).await?.contains(needle) {
            log(format!("{container}: saw '{needle}'"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("{container}: no '{needle}' in its logs within {secs}s")
}

pub async fn rest(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let tx = format!("/v1/transactions/{REST_TX}");

    // Every router in this harness is booted with its REST API pinned, so the
    // pin's own effects are already in the log.
    a.wait("spawning nos-restd for new REST API").await?;
    a.wait(&format!(
        "rest api listening table=rt1 .* address={IP_A} port={REST_PORT}"
    ))
    .await?;

    // Authentication is mutual TLS: every route refuses a client with no
    // certificate, and the one way to get a certificate — `POST /v1/login` —
    // refuses a wrong password and an unknown user alike.
    let anonymous = a.rest.anonymous()?;
    for path in ["/v1/config", "/openapi.json", "/swagger-ui/"] {
        let (status, body) = a.rest_with(&anonymous, Method::GET, path, None).await?;
        if status != 401 {
            bail!("router-a: GET {path} without a certificate -> {status}, want 401");
        }
        // Errors are RFC 9457 problem documents, whose status repeats the HTTP one.
        let problem: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            anyhow::anyhow!("router-a: GET {path} 401 body is not JSON ({e}): {body}")
        })?;
        if problem["status"] != 401
            || problem["type"] != "about:blank"
            || problem["title"] != "Unauthorized"
        {
            bail!("router-a: GET {path} 401 body is not a problem document: {body}");
        }
    }
    // The same over an authenticated request: an unknown transaction is a 404
    // problem document, not a bare status.
    let (status, body) = a
        .rest(Method::GET, "/v1/transactions/no-such-tx", None)
        .await?;
    if status != 404 || !body.contains(r#""status":404"#) {
        bail!("router-a: GET of an unknown transaction -> {status} {body}, want a 404 problem");
    }
    for (user, password) in [(E2E_USER, "wrong-password"), ("nobody", E2E_PASSWORD)] {
        match a.rest.login(user, password).await? {
            Err(401) => {}
            Err(status) => bail!("router-a: login as {user} -> {status}, want 401"),
            Ok(_) => bail!("router-a: login as {user} with '{password}' was accepted"),
        }
    }
    log("router-a: REST refuses no certificate, a wrong password and an unknown user with 401");
    rest_transport(a).await?;

    // Show endpoints, answered by other daemons (config, rib, bgp, interface).
    let config = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    let config: serde_json::Value = serde_json::from_str(&config)?;
    let Some(orig_hostname) = config["hostname"].as_str().map(str::to_string) else {
        bail!("no hostname in /v1/config");
    };
    a.rest_expect(Method::GET, "/v1/routes/rt1", None, 200)
        .await?;
    expect_body(
        &a.rest_expect(Method::GET, "/v1/interfaces", None, 200)
            .await?,
        "\"eth0\"",
    )?;
    expect_body(
        &a.rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?,
        "\"instance\":\"r1\"",
    )?;
    a.rest_expect(Method::GET, "/v1/routes/nonexistent-table", None, 503)
        .await?;
    expect_body(
        &a.rest_expect(
            Method::GET,
            "/v1/logs?source=nos-configd&limit=3",
            None,
            200,
        )
        .await?,
        "\"source\":\"nos-configd\"",
    )?;

    // `clear bgp r1 <peer> soft-in` as a POST: the Established session to
    // router-b really gets a ROUTE-REFRESH, and a peer with no session is a 404.
    let refresh = format!("bgp: sent route refresh request to peer peer={IP_B}");
    let refresh_base = a.count(&refresh);
    // RFC 7313: both nos speakers negotiate Enhanced Route Refresh, so the
    // resend comes back bracketed by BoRR/EoRR.
    let borr = format!("bgp: received BoRR peer={IP_B}");
    let eorr = format!("bgp: received EoRR peer={IP_B}");
    let (borr_base, eorr_base) = (a.count(&borr), a.count(&eorr));
    expect_body(
        &a.rest_expect(
            Method::POST,
            &format!("/v1/bgp/r1/peer/{IP_B}/soft-in"),
            None,
            200,
        )
        .await?,
        "\"route_refresh\":\"sent\"",
    )?;
    a.wait_new(&refresh, refresh_base, 30).await?;
    a.wait_new(&borr, borr_base, 30).await?;
    a.wait_new(&eorr, eorr_base, 30).await?;
    a.rest_expect(
        Method::POST,
        "/v1/bgp/r1/peer/10.50.0.99/soft-in",
        None,
        404,
    )
    .await?;

    // A transaction driven purely through the config-tree URLs.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    expect_body(
        &a.rest_expect(
            Method::PUT,
            &format!("{tx}/hostname"),
            Some("\"rest-host\""),
            200,
        )
        .await?,
        "\"rest-host\"",
    )?;
    expect_body(
        &a.rest_expect(
            Method::PUT,
            &format!("{tx}/prefix-list/rest-pl"),
            Some(r#"{"name":"rest-pl","entries":[{"cidr":"10.0.0.0/8","range":null}]}"#),
            200,
        )
        .await?,
        "\"rest-pl\"",
    )?;
    // A key containing '/' travels as one percent-encoded segment.
    expect_body(
        &a.rest_expect(
            Method::GET,
            &format!("{tx}/prefix-list/rest-pl/entry/10.0.0.0%2F8"),
            None,
            200,
        )
        .await?,
        "\"10.0.0.0/8\"",
    )?;
    a.rest_expect(
        Method::PUT,
        &format!("{tx}/hostname"),
        Some(r#"{"bad":true}"#),
        400,
    )
    .await?;
    a.rest_expect(Method::GET, &format!("{tx}/diff"), None, 200)
        .await?;
    // Nothing is running yet.
    if a.rest_expect(Method::GET, "/v1/config", None, 200)
        .await?
        .contains("rest-pl")
    {
        bail!("uncommitted transaction leaked into the running config");
    }
    expect_body(
        &a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
            .await?,
        &format!("\"committed\":\"{REST_TX}\""),
    )?;
    let running = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    if !running.contains("\"rest-pl\"") || !running.contains("\"hostname\":\"rest-host\"") {
        bail!("committed transaction is not in the running config");
    }
    // Persisted only once saved: the real nos-configd writes its real
    // --config-file. Any later phase that restarts nos-configd boots from this
    // file (with the undo below still unsaved) rather than from the seed.
    let saved_path = "/var/lib/nos/config.yaml";
    a.rest_expect(Method::POST, "/v1/config/save", None, 204)
        .await?;
    match w.dock.exec("router-a", &["cat", saved_path]).await? {
        (0, saved) if saved.contains("rest-pl") && saved.contains("rest-host") => {}
        (code, saved) => bail!("router-a: {saved_path} after save (exit {code}):\n{saved}"),
    }
    log("router-a: POST /v1/config/save wrote the running config to disk");

    // Undo it the same way, exercising DELETE on a subsection and on the tx.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(
        Method::DELETE,
        &format!("{tx}/prefix-list/rest-pl"),
        None,
        204,
    )
    .await?;
    a.rest_expect(
        Method::PUT,
        &format!("{tx}/hostname"),
        Some(&format!("\"{orig_hostname}\"")),
        200,
    )
    .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    if a.rest_expect(Method::GET, "/v1/config", None, 200)
        .await?
        .contains("rest-pl")
    {
        bail!("rest-pl still present after DELETE + commit");
    }
    a.rest_expect(Method::POST, &format!("{tx}?base=blank"), None, 201)
        .await?;
    a.rest_expect(Method::DELETE, &tx, None, 204).await?;
    a.rest_expect(Method::GET, &tx, None, 404).await?;
    rest_etag(a).await?;

    expect_body(
        &a.rest_expect(Method::GET, "/openapi.json", None, 200)
            .await?,
        "/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}",
    )?;
    expect_body(
        &a.rest_expect(Method::GET, "/swagger-ui/", None, 200)
            .await?,
        "Swagger UI",
    )?;

    // `show log --follow`: an SSE stream carrying a *live* entry, not just the
    // backlog. Follow nos-configd, then commit an empty transaction so it logs
    // "config committed" while the stream is open.
    let url = format!(
        "{}/v1/logs/follow?source=nos-configd&limit=1",
        a.rest.base()
    );
    let client = a.rest.client().await?;
    let stream = tokio::spawn(async move {
        let mut text = String::new();
        let Ok(resp) = client.get(&url).send().await else {
            return text;
        };
        let mut chunks = futures::StreamExt::boxed(resp.bytes_stream());
        let _ = tokio::time::timeout(Duration::from_secs(6), async {
            while let Some(Ok(chunk)) = futures::StreamExt::next(&mut chunks).await {
                text.push_str(&String::from_utf8_lossy(&chunk));
            }
        })
        .await;
        text
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    let streamed = stream.await?;
    if !streamed.contains("event: log") || !streamed.contains("config committed") {
        bail!("the log follow stream carried no live 'config committed' entry:\n{streamed}");
    }
    log("router-a: log follow streamed a live entry over sse");

    rest_users(a).await?;
    rest_destructive(w).await
}

/// RFC 9110 §8.8/§13.1 on the transaction endpoints, against the real daemon:
/// a strong `ETag` on every reply, a stale `If-Match` refused with 412 and
/// nothing changed, the current one accepted, `If-None-Match` → 304.
async fn rest_etag(a: &Router) -> anyhow::Result<()> {
    let tx = format!("/v1/transactions/{REST_TX}");
    let host = format!("{tx}/hostname");
    let quoted = |etag: &Option<String>| -> anyhow::Result<String> {
        let Some(e) = etag else {
            bail!("router-a: reply carried no ETag")
        };
        let digits = e.strip_prefix('"').and_then(|s| s.strip_suffix('"'));
        if digits.is_none_or(|d| d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit())) {
            bail!("router-a: ETag {e} is not a quoted decimal");
        }
        Ok(e.clone())
    };
    let orig = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    let orig: serde_json::Value = serde_json::from_str(&orig)?;
    let orig_hostname = orig["hostname"].as_str().unwrap_or_default().to_string();

    let (etag, _) = a
        .rest_expect_full(Method::POST, &format!("{tx}?base=current"), None, None, 201)
        .await?;
    let opened = quoted(&etag)?;
    let (etag, _) = a
        .rest_expect_full(Method::GET, &tx, None, None, 200)
        .await?;
    if quoted(&etag)? != opened {
        bail!("router-a: GET ETag {etag:?} differs from the opened one {opened}");
    }

    // Stale If-Match: 412 problem document, the value untouched.
    let stale = "\"999999\"";
    let (_, body) = a
        .rest_expect_full(
            Method::PUT,
            &host,
            Some("\"etag-host\""),
            Some(("if-match", stale)),
            412,
        )
        .await?;
    expect_body(&body, "\"status\":412")?;
    let (_, body) = a
        .rest_expect_full(Method::GET, &host, None, None, 200)
        .await?;
    if body != format!("\"{orig_hostname}\"") {
        bail!("router-a: hostname changed by a refused PUT: {body}");
    }
    // The current one: accepted, and the reply's tag moves on.
    let (etag, _) = a
        .rest_expect_full(
            Method::PUT,
            &host,
            Some("\"etag-host\""),
            Some(("if-match", &opened)),
            200,
        )
        .await?;
    let after_put = quoted(&etag)?;
    if after_put == opened {
        bail!("router-a: ETag did not change after a PUT ({opened})");
    }

    // A subsection DELETE: stale → 412, current → 204 with the new tag.
    a.rest_expect_full(
        Method::PUT,
        &format!("{tx}/prefix-list/etag-pl"),
        Some(r#"{"name":"etag-pl","entries":[]}"#),
        Some(("if-match", &after_put)),
        200,
    )
    .await?;
    a.rest_expect_full(
        Method::DELETE,
        &format!("{tx}/prefix-list/etag-pl"),
        None,
        Some(("if-match", &after_put)),
        412,
    )
    .await?;
    let (etag, _) = a
        .rest_expect_full(
            Method::DELETE,
            &format!("{tx}/prefix-list/etag-pl"),
            None,
            Some(("if-match", "*")),
            204,
        )
        .await?;
    let current = quoted(&etag)?;

    // If-None-Match: current → 304 with no body; stale → 200 with the value.
    let (etag, body) = a
        .rest_expect_full(
            Method::GET,
            &tx,
            None,
            Some(("if-none-match", &current)),
            304,
        )
        .await?;
    if quoted(&etag)? != current || !body.is_empty() {
        bail!("router-a: 304 carried ETag {etag:?} and body {body:?}");
    }
    let (_, body) = a
        .rest_expect_full(
            Method::GET,
            &host,
            None,
            Some(("if-none-match", &opened)),
            200,
        )
        .await?;
    expect_body(&body, "\"etag-host\"")?;

    // Commit: stale → 412 and the transaction stays open; current → 200.
    a.rest_expect_full(
        Method::POST,
        &format!("{tx}/commit"),
        None,
        Some(("if-match", stale)),
        412,
    )
    .await?;
    a.rest_expect(Method::GET, &tx, None, 200).await?;
    a.rest_expect_full(
        Method::POST,
        &format!("{tx}/commit"),
        None,
        Some(("if-match", &current)),
        200,
    )
    .await?;
    expect_body(
        &a.rest_expect(Method::GET, "/v1/config", None, 200).await?,
        "\"hostname\":\"etag-host\"",
    )?;
    log("router-a: transaction ETag/If-Match (412) and If-None-Match (304) verified");

    // Put the hostname back the way the other phases expect it.
    a.edit(|c| {
        c.hostname = orig_hostname;
        Ok(())
    })
    .await
}

/// The transport itself: post-quantum key exchange is mandatory, and requests
/// share connections instead of paying a handshake each — HTTP/2 multiplexing
/// on the client side, pooled IPC connections behind it.
async fn rest_transport(a: &Router) -> anyhow::Result<()> {
    // A client offering only classical X25519 is refused at the handshake.
    let failed = a.count("rest tls handshake failed");
    if classical_handshake(a).await.is_ok() {
        bail!(
            "router-a: the REST listener completed a handshake without post-quantum key exchange"
        );
    }
    a.wait_new("rest tls handshake failed", failed, 15).await?;
    log("router-a: REST refuses a classical-only key exchange");

    // One connection carries every request of a client: a warm-up call learns
    // that the server speaks h2, then 40 concurrent ones multiplex over it.
    let Ok(identity) = a.rest.login(E2E_USER, E2E_PASSWORD).await? else {
        bail!("router-a: login as {E2E_USER} failed");
    };
    let client = a.rest.with_identity(&identity)?;
    let handshake = "rest tls handshake ok user=e2e alpn=h2 kx=Some(X25519MLKEM768)";
    let before = a.count(handshake);
    a.rest_with(&client, Method::GET, "/v1/interfaces", None)
        .await?;
    let calls = (0..40).map(|_| a.rest_with(&client, Method::GET, "/v1/interfaces", None));
    for (status, _) in futures::future::try_join_all(calls).await? {
        if status != 200 {
            bail!("router-a: a multiplexed request -> {status}");
        }
    }
    a.wait_new(handshake, before, 15).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let opened = a.count(handshake) - before;
    if opened != 1 {
        bail!("router-a: 41 requests took {opened} TLS handshakes, want exactly 1 (h2 over post-quantum TLS 1.3)");
    }
    log("router-a: 41 requests shared one post-quantum h2 connection");

    // Behind it, nos-restd reuses its IPC connections: a request that touches
    // the config, the broker and nos-ribd used to cost three handshakes, so 40
    // of them would show >=120 server-side handshakes across the daemons. The
    // margin is wide because other daemons reconnect in the background too.
    let ipc = "ipc tls handshake ok side=server";
    a.rest_with(&client, Method::GET, "/v1/routes/rt1", None)
        .await?;
    let before = a.count(ipc);
    for _ in 0..40 {
        a.rest_with(&client, Method::GET, "/v1/routes/rt1", None)
            .await?;
    }
    let opened = a.count(ipc) - before;
    if opened >= 30 {
        bail!("router-a: 40 sequential requests opened {opened} IPC handshakes — connections are not being reused");
    }
    log(format!(
        "router-a: 40 requests opened {opened} IPC handshakes (pooled)"
    ));
    Ok(())
}

/// Dials the REST port offering only the classical X25519 key exchange.
async fn classical_handshake(a: &Router) -> anyhow::Result<()> {
    use rustls::crypto::aws_lc_rs;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};

    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(a.rest.ca_pem())?)?;
    let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect((a.id.ip, REST_PORT)).await?;
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg))
        .connect(
            ServerName::IpAddress(a.id.ip.parse::<std::net::IpAddr>()?.into()),
            tcp,
        )
        .await?;
    Ok(())
}

/// A clear password set through the config tree is stored as a hash; setting
/// the same one again changes nothing (no diff, identical hash); a different
/// one replaces it and the old one stops working.
async fn rest_users(a: &Router) -> anyhow::Result<()> {
    let tx = format!("/v1/transactions/{REST_TX}");
    let user = format!("{tx}/user/{REST_USER}");
    let set = |password: &str| format!(r#"{{"name":"{REST_USER}","password":"{password}"}}"#);
    // `POST /v1/login` as the user: 200 with a certificate, or the refusal.
    let login = |password: &'static str| async move {
        a.rest
            .login(REST_USER, password)
            .await
            .map(|r| r.map_or_else(|status| status, |_| 200))
    };
    let stored_hash = || async {
        let config = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
        let config: serde_json::Value = serde_json::from_str(&config)?;
        config["users"]
            .as_array()
            .and_then(|users| users.iter().find(|u| u["name"] == REST_USER))
            .and_then(|u| u["password"].as_str().map(str::to_string))
            .with_context(|| format!("no user {REST_USER} in /v1/config"))
    };

    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::PUT, &user, Some(&set("first")), 200)
        .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    let hash = stored_hash().await?;
    if !hash.starts_with("$argon2id$") || hash.contains("first") {
        bail!("router-a: password is not stored as an argon2id hash: {hash}");
    }
    // The certificate that login issued is what the user's later calls carry.
    let Ok(identity) = a.rest.login(REST_USER, "first").await? else {
        bail!("router-a: the new user cannot log in with its password");
    };
    let as_user = a.rest.with_identity(&identity)?;
    let (status, _) = a
        .rest_with(&as_user, Method::GET, "/v1/config", None)
        .await?;
    if status != 200 {
        bail!("router-a: the new user's certificate is refused: {status}");
    }

    // Same clear password again: empty diff, identical hash after commit.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::PUT, &user, Some(&set("first")), 200)
        .await?;
    let diff = a
        .rest_expect(Method::GET, &format!("{tx}/diff"), None, 200)
        .await?;
    let diff: serde_json::Value = serde_json::from_str(&diff)?;
    if diff["users"].as_array().is_none_or(|u| !u.is_empty()) {
        bail!("router-a: re-setting the same password shows a diff: {diff}");
    }
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    if stored_hash().await? != hash {
        bail!("router-a: re-setting the same password changed its hash");
    }
    log("router-a: re-setting the same password left the hash and diff unchanged");

    // A different password replaces it; the old one stops working.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::PUT, &user, Some(&set("second")), 200)
        .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    if stored_hash().await? == hash {
        bail!("router-a: a different password kept the old hash");
    }
    if login("first").await? != 401 || login("second").await? != 200 {
        bail!("router-a: after the change only the new password should log in");
    }

    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::DELETE, &user, None, 204).await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    if login("second").await? != 401 {
        bail!("router-a: a deleted user can still log in");
    }
    // Their certificate is still valid for hours, but the user is gone: it is
    // refused on the very next request, even on the connection already open.
    let (status, _) = a
        .rest_with(&as_user, Method::GET, "/v1/config", None)
        .await?;
    if status != 401 {
        bail!("router-a: a deleted user's certificate still works: {status}");
    }
    log("router-a: user password change and deletion verified over REST");
    Ok(())
}

/// The two checks that sever the very channel they are driven over, run on a
/// throwaway router: an address that is not on the VRF is retried rather than
/// fatal, and unpinning stops the process and closes the port.
async fn rest_destructive(w: &mut World) -> anyhow::Result<()> {
    w.start(R, None, &[]).await?;
    let r = w.get(R)?;
    r.provision(&[
        "--rest-api-address",
        REST_ABSENT_ADDRESS,
        "--rest-api-port",
        &REST_PORT.to_string(),
    ])
    .await?;
    wait_docker_log(w, "router-r", "rest api stopped listening", 30).await?;
    wait_docker_log(w, "router-r", "rest api not listening yet", 30).await?;

    w.start(R, None, &[]).await?;
    let r = w.get(R)?;
    r.provision(&["--clear-rest-api"]).await?;
    wait_docker_log(
        w,
        "router-r",
        "REST API removed from config, stopping nos-restd",
        30,
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    if let Ok((200, _)) = r.rest(Method::GET, "/v1/config", None).await {
        bail!("the rest api still answers after being unpinned");
    }
    log("router-r: the rest api port is closed after unpinning");

    w.remove(R).await;
    Ok(())
}

// --- syslog (#71) ---

const SYSLOG_UDP_LOG: &str = "/var/log/udp.log";
const SYSLOG_TCP_LOG: &str = "/var/log/tcp.log";
/// One file per TLS listener: 6514 (defaults), 6515 (TLS 1.2 only, RSA leaf),
/// 6516 (TLS 1.3 with a classical group only).
const SYSLOG_TLS_LOG: &str = "/var/log/tls.log";
const SYSLOG_TLS12_LOG: &str = "/var/log/tls12.log";
const SYSLOG_TLSC_LOG: &str = "/var/log/tlsc.log";

/// A collector that parses RFC 5424 itself (syslog-ng's `syslog()` source),
/// writing one `HOST|PROGRAM|PID|LEVEL|FACILITY|SDATA|MSG` line per message
/// to a file per transport.
fn syslog_dockerfile() -> &'static str {
    "FROM debian:trixie-slim\n\
     RUN apt-get update && apt-get install -y --no-install-recommends syslog-ng-core \\\n \
     && rm -rf /var/lib/apt/lists/*\n"
}

fn syslog_conf() -> String {
    // peer-verify(no): nos presents no client certificate (server auth only).
    let tls = |port: u16, cert: &str, extra: &str| {
        format!(
            "syslog(ip(0.0.0.0) transport(\"tls\") port({port}) \
             tls(key-file(\"/etc/syslog-ng/{cert}.key\") cert-file(\"/etc/syslog-ng/{cert}.crt\") \
             peer-verify(no) {extra}));"
        )
    };
    let (s_tls, s_tls12, s_tlsc) = (
        tls(6514, "ecdsa", ""),
        // RFC 9662's SHOULD-offer TLS 1.2 suite, and nothing newer.
        tls(
            6515,
            "rsa",
            "ssl-options(no-tlsv13) cipher-suite(\"ECDHE-RSA-AES128-GCM-SHA256\")",
        ),
        // TLS 1.3, but only a classical group: must be refused in every case.
        tls(
            6516,
            "ecdsa",
            "ssl-options(no-tlsv12) ecdh-curve-list(\"X25519\")",
        ),
    );
    format!(
        "@version: current\n\
         options {{ keep-hostname(yes); chain-hostnames(no); }};\n\
         source s_udp {{ syslog(ip(0.0.0.0) transport(\"udp\") port(514)); }};\n\
         source s_tcp {{ syslog(ip(0.0.0.0) transport(\"tcp\") port(601)); }};\n\
         source s_tls {{ {s_tls} }};\n\
         source s_tls12 {{ {s_tls12} }};\n\
         source s_tlsc {{ {s_tlsc} }};\n\
         template t_line {{ template(\"$HOST|$PROGRAM|$PID|$LEVEL|$FACILITY|$SDATA|$MSG\\n\"); }};\n\
         destination d_udp {{ file(\"{SYSLOG_UDP_LOG}\" template(t_line)); }};\n\
         destination d_tcp {{ file(\"{SYSLOG_TCP_LOG}\" template(t_line)); }};\n\
         destination d_tls {{ file(\"{SYSLOG_TLS_LOG}\" template(t_line)); }};\n\
         destination d_tls12 {{ file(\"{SYSLOG_TLS12_LOG}\" template(t_line)); }};\n\
         destination d_tlsc {{ file(\"{SYSLOG_TLSC_LOG}\" template(t_line)); }};\n\
         log {{ source(s_udp); destination(d_udp); }};\n\
         log {{ source(s_tcp); destination(d_tcp); }};\n\
         log {{ source(s_tls); destination(d_tls); }};\n\
         log {{ source(s_tls12); destination(d_tls12); }};\n\
         log {{ source(s_tlsc); destination(d_tlsc); }};\n"
    )
}

/// The collector's certificates, generated per run: one CA signing an ECDSA
/// and an RSA-2048 leaf (an IP SAN for the collector's address plus a DNS SAN),
/// and an unrelated CA to be refused.
struct SyslogCerts {
    ecdsa_crt: String,
    ecdsa_key: String,
    rsa_crt: String,
    rsa_key: String,
    /// `SHA-256:AB:CD:...` of the ECDSA leaf and of a certificate that is not
    /// the collector's.
    ecdsa_fingerprint: String,
    wrong_fingerprint: String,
    /// Host files for `--syslog-trust-anchor-file`.
    ca_file: std::path::PathBuf,
    other_ca_file: std::path::PathBuf,
}

const SYSLOG_DNS_NAME: &str = "syslog.e2e";

impl SyslogCerts {
    fn generate() -> anyhow::Result<Self> {
        use rcgen::{
            BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, RsaKeySize, SanType,
            PKCS_RSA_SHA256,
        };
        use sha2::{Digest, Sha256};
        let ca = |name: &str| -> anyhow::Result<(String, Issuer<'static, KeyPair>)> {
            let key = KeyPair::generate()?;
            let mut p = CertificateParams::new(Vec::<String>::new())?;
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.distinguished_name
                .push(rcgen::DnType::CommonName, name.to_string());
            let cert = p.self_signed(&key)?;
            Ok((cert.pem(), Issuer::new(p, key)))
        };
        let (ca_pem, issuer) = ca("nos-e2e syslog CA")?;
        let (other_pem, _) = ca("nos-e2e unrelated CA")?;
        let leaf = |key: &KeyPair| -> anyhow::Result<rcgen::Certificate> {
            let mut p = CertificateParams::new(vec![SYSLOG_DNS_NAME.to_string()])?;
            p.subject_alt_names
                .push(SanType::IpAddress(IP_SYSLOG.parse()?));
            Ok(p.signed_by(key, &issuer)?)
        };
        let ecdsa = KeyPair::generate()?;
        let rsa = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;
        let (ecdsa_cert, rsa_cert) = (leaf(&ecdsa)?, leaf(&rsa)?);
        let fingerprint = |der: &[u8]| {
            let hex: Vec<String> = Sha256::digest(der)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect();
            format!("SHA-256:{}", hex.join(":"))
        };
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- public CA certificates, not secrets.
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let write = |name: &str, pem: &str| -> anyhow::Result<std::path::PathBuf> {
            let path = dir.join(format!("nos-e2e-syslog-{pid}-{name}.pem"));
            std::fs::write(&path, pem)?;
            Ok(path)
        };
        Ok(Self {
            ecdsa_crt: ecdsa_cert.pem(),
            ecdsa_key: ecdsa.serialize_pem(),
            rsa_crt: rsa_cert.pem(),
            rsa_key: rsa.serialize_pem(),
            ecdsa_fingerprint: fingerprint(ecdsa_cert.der()),
            wrong_fingerprint: fingerprint(rsa_cert.der()),
            ca_file: write("ca", &ca_pem)?,
            other_ca_file: write("other-ca", &other_pem)?,
        })
    }
}

/// Starts the collector. syslog-ng reads its certificates at startup, so the
/// container waits for a `ready` file uploaded after them.
async fn start_syslog_collector(w: &World, certs: &SyslogCerts) -> anyhow::Result<()> {
    let conf = syslog_conf();
    w.dock
        .start_plain(
            SYSLOG_COLLECTOR,
            SYSLOG_IMAGE,
            NET,
            IP_SYSLOG,
            &[
                "sh",
                "-c",
                "while [ ! -e /etc/syslog-ng/ready ]; do sleep 0.2; done; \
                 exec syslog-ng -F --no-caps -f /etc/syslog-ng/syslog-ng.conf",
            ],
            ("/etc/syslog-ng", "syslog-ng.conf", conf.as_bytes()),
        )
        .await?;
    for (file, contents) in [
        ("ecdsa.crt", &certs.ecdsa_crt),
        ("ecdsa.key", &certs.ecdsa_key),
        ("rsa.crt", &certs.rsa_crt),
        ("rsa.key", &certs.rsa_key),
        ("ready", &String::new()),
    ] {
        w.dock
            .upload(
                SYSLOG_COLLECTOR,
                "/etc/syslog-ng",
                file,
                contents.as_bytes(),
            )
            .await?;
    }
    Ok(())
}

/// Every line the collector wrote to `file` (empty before the first one).
async fn collected(w: &World, file: &str) -> anyhow::Result<Vec<Vec<String>>> {
    let (_, out) = w.dock.exec(SYSLOG_COLLECTOR, &["cat", file]).await?;
    Ok(out
        .lines()
        .filter(|l| l.matches('|').count() >= 6)
        .map(|l| l.splitn(7, '|').map(str::to_string).collect())
        .collect())
}

/// Waits for a collected line `f` accepts and returns it.
async fn wait_collected(
    w: &World,
    file: &str,
    what: &str,
    secs: u64,
    f: impl Fn(&[String]) -> bool,
) -> anyhow::Result<Vec<String>> {
    for _ in 0..secs {
        if let Some(l) = collected(w, file).await?.into_iter().find(|l| f(l)) {
            log(format!("collector {file}: saw {what}"));
            return Ok(l);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("collector {file}: no line matching {what} within {secs}s")
}

/// `docker logs` of `container` with ANSI colour codes removed (the daemons'
/// `fmt` layer colours field names even into a pipe).
async fn plain_docker_logs(w: &World, container: &str) -> anyhow::Result<String> {
    let raw = w.dock.logs(container).await?;
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for e in chars.by_ref() {
                if e.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// RFC 5424 export from `nos-logd` to a real syslog-ng, over both transports,
/// from inside `rt1`'s VRF (eth0 is enslaved to it, so an unscoped socket
/// could not reach the collector): hostname, program, instance, facility and
/// level parsed by an independent implementation, the level filter, a TCP
/// reconnect after the collector restarts, and removal.
pub async fn syslog(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    log("building/starting the syslog collector");
    w.dock
        .ensure_image(SYSLOG_IMAGE, syslog_dockerfile())
        .await?;
    let certs = SyslogCerts::generate()?;
    start_syslog_collector(w, &certs).await?;

    let addr = IP_SYSLOG.to_string();
    a.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
    for (name, transport) in [("c-udp", "udp"), ("c-tcp", "tcp")] {
        a.provision(&[
            "--hostname",
            SYSLOG_HOSTNAME,
            "--syslog-server",
            name,
            "--syslog-address",
            &addr,
            "--syslog-transport",
            transport,
            "--syslog-routing-table",
            "rt1",
            "--syslog-facility",
            "local3",
        ])
        .await?;
    }

    // Nothing logs at info in steady state, and each sink only sees what is
    // logged after it connected: one more commit gives both a line.
    a.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
    for file in [SYSLOG_UDP_LOG, SYSLOG_TCP_LOG] {
        // nos-configd's own commit line, with the hostname we configured,
        // the facility and an info level; its PROCID is the NILVALUE.
        let mut found = None;
        for _ in 0..30 {
            // A sink that connected late missed the earlier commits.
            a.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
            found = collected(w, file).await?.into_iter().find(|l| {
                l[0] == SYSLOG_HOSTNAME
                    && l[1] == "nos-configd"
                    && l[3] == "info"
                    && l[4] == "local3"
            });
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let l = found.with_context(|| format!("{file}: no nos-configd info line"))?;
        if !l[5].contains("timeQuality") || !l[6].contains("config committed") {
            bail!("unexpected structured data or text in {l:?}");
        }
    }

    // The routers run with RUST_LOG=debug; the default minimum is info, so a
    // collector with no level never sees a debug line.
    let debug = |l: &[String]| l[3] == "debug";
    if collected(w, SYSLOG_TCP_LOG).await?.iter().any(|l| debug(l)) {
        bail!("a debug line reached a collector at the default level");
    }
    a.provision(&[
        "--hostname",
        SYSLOG_HOSTNAME,
        "--syslog-server",
        "c-tcp",
        "--syslog-level",
        "debug",
    ])
    .await?;
    wait_collected(w, SYSLOG_TCP_LOG, "a debug line", 60, debug).await?;
    // An instance daemon: APP-NAME nos-ribd/nos-bgpd, PROCID its instance.
    wait_collected(w, SYSLOG_TCP_LOG, "an instance daemon's line", 60, |l| {
        (l[1] == "nos-ribd" && l[2] == "rt1") || (l[1] == "nos-bgpd" && l[2] == "r1")
    })
    .await?;
    if collected(w, SYSLOG_UDP_LOG).await?.iter().any(|l| debug(l)) {
        bail!("a debug line reached the udp collector, still at the default level");
    }

    log("restarting the collector: the tcp sink must reconnect");
    let connected = |logs: &str| logs.matches("syslog connected server=c-tcp").count();
    let before = connected(&plain_docker_logs(w, "router-a").await?);
    start_syslog_collector(w, &certs).await?;
    let mut after = before;
    for _ in 0..60 {
        after = connected(&plain_docker_logs(w, "router-a").await?);
        if after > before {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if after <= before {
        bail!("nos-logd never logged a new 'syslog connected server=c-tcp'");
    }
    wait_collected(w, SYSLOG_TCP_LOG, "a line after the restart", 60, |_| true).await?;

    log("removing both collectors");
    a.provision(&[
        "--hostname",
        SYSLOG_HOSTNAME,
        "--no-syslog-server",
        "c-udp",
        "--no-syslog-server",
        "c-tcp",
    ])
    .await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (udp, tcp) = (
        collected(w, SYSLOG_UDP_LOG).await?.len(),
        collected(w, SYSLOG_TCP_LOG).await?.len(),
    );
    tokio::time::sleep(Duration::from_secs(10)).await;
    if collected(w, SYSLOG_UDP_LOG).await?.len() != udp
        || collected(w, SYSLOG_TCP_LOG).await?.len() != tcp
    {
        bail!("a collector kept receiving lines after its removal");
    }

    syslog_tls(w, &certs).await?;

    a.provision(&["--hostname", "nos"]).await?;
    w.dock.container_remove(SYSLOG_COLLECTOR).await;
    Ok(())
}

/// Polls router-a's `docker logs` (nos-logd does not forward its own logs to
/// the REST stream) until `pattern` shows up more often than `before` times.
async fn wait_router_a_log(w: &World, pattern: &str, before: usize) -> anyhow::Result<()> {
    for _ in 0..60 {
        if plain_docker_logs(w, "router-a")
            .await?
            .matches(pattern)
            .count()
            > before
        {
            log(format!("router-a: saw '{pattern}'"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("nos-logd never logged '{pattern}'")
}

async fn router_a_log_count(w: &World, pattern: &str) -> anyhow::Result<usize> {
    Ok(plain_docker_logs(w, "router-a")
        .await?
        .matches(pattern)
        .count())
}

/// Adds/updates TLS collector `name` on `port`; `extra` are the trust flags.
async fn tls_server(w: &World, name: &str, port: u16, extra: &[&str]) -> anyhow::Result<()> {
    let (addr, port) = (IP_SYSLOG.to_string(), port.to_string());
    let mut args = vec![
        "--hostname",
        SYSLOG_HOSTNAME,
        "--syslog-server",
        name,
        "--syslog-address",
        &addr,
        "--syslog-transport",
        "tls",
        "--syslog-port",
        &port,
        "--syslog-routing-table",
        "rt1",
        "--syslog-facility",
        "local3",
    ];
    args.extend_from_slice(extra);
    w.a()?.provision(&args).await
}

/// The collector received a line `file` did not hold before: commits keep
/// producing `nos-configd` info lines until a connected sink forwards one.
async fn expect_tls_delivery(w: &World, file: &str) -> anyhow::Result<()> {
    let before = collected(w, file).await?.len();
    for _ in 0..30 {
        w.a()?.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
        if collected(w, file).await?.len() > before {
            log(format!("collector {file}: a line arrived over tls"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("collector {file}: no line arrived over tls")
}

/// The handshake was refused: `nos-logd` logs it and no collector file grows.
async fn expect_tls_refused(
    w: &World,
    name: &str,
    file: &str,
    before: usize,
) -> anyhow::Result<()> {
    wait_router_a_log(
        w,
        &format!("syslog collector unavailable server={name} error=tls handshake"),
        before,
    )
    .await?;
    let lines = collected(w, file).await?.len();
    for _ in 0..3 {
        w.a()?.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if collected(w, file).await?.len() != lines {
        bail!("a line reached {file} from '{name}', whose handshake was refused");
    }
    Ok(())
}

async fn remove_syslog_server(w: &World, name: &str) -> anyhow::Result<()> {
    w.a()?
        .provision(&["--hostname", SYSLOG_HOSTNAME, "--no-syslog-server", name])
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

/// RFC 5425 / RFC 9662 against syslog-ng (OpenSSL 3.5, which offers
/// `X25519MLKEM768`): trust by CA and by fingerprint over post-quantum TLS 1.3;
/// an unrelated CA, a wrong fingerprint, a wrong name, a TLS 1.2-only collector
/// and a TLS 1.3 collector with a classical group only are all refused by
/// default; `allow-tls12` reaches the TLS 1.2 one (classical, warned) but still
/// never a classical TLS 1.3 one, and turning it off again refuses it once more.
async fn syslog_tls(w: &World, certs: &SyslogCerts) -> anyhow::Result<()> {
    let ca = certs.ca_file.to_str().context("ca path")?;
    let other_ca = certs.other_ca_file.to_str().context("other ca path")?;
    let connected = |name: &str, version: &str, kx: &str| {
        format!("syslog connected server={name} version={version} kx={kx}")
    };
    let refused =
        |name: &str| format!("syslog collector unavailable server={name} error=tls handshake");

    log("tls: trust anchor, then fingerprint, on the default (post-quantum TLS 1.3) listener");
    for (name, trust) in [
        ("c-tls-ca", ["--syslog-trust-anchor-file", ca]),
        (
            "c-tls-fp",
            ["--syslog-fingerprint", &certs.ecdsa_fingerprint],
        ),
    ] {
        tls_server(w, name, 6514, &trust).await?;
        wait_router_a_log(w, &connected(name, "TLSv1_3", "X25519MLKEM768"), 0).await?;
        expect_tls_delivery(w, SYSLOG_TLS_LOG).await?;
        remove_syslog_server(w, name).await?;
    }

    log("tls: server-name, right and wrong");
    tls_server(
        w,
        "c-tls-name",
        6514,
        &[
            "--syslog-trust-anchor-file",
            ca,
            "--syslog-server-name",
            SYSLOG_DNS_NAME,
        ],
    )
    .await?;
    wait_router_a_log(w, &connected("c-tls-name", "TLSv1_3", "X25519MLKEM768"), 0).await?;
    remove_syslog_server(w, "c-tls-name").await?;
    tls_server(
        w,
        "c-tls-badname",
        6514,
        &[
            "--syslog-trust-anchor-file",
            ca,
            "--syslog-server-name",
            "other.e2e",
        ],
    )
    .await?;
    expect_tls_refused(w, "c-tls-badname", SYSLOG_TLS_LOG, 0).await?;
    remove_syslog_server(w, "c-tls-badname").await?;

    log("tls: an unrelated CA and a wrong fingerprint are refused");
    tls_server(
        w,
        "c-tls-badca",
        6514,
        &["--syslog-trust-anchor-file", other_ca],
    )
    .await?;
    expect_tls_refused(w, "c-tls-badca", SYSLOG_TLS_LOG, 0).await?;
    remove_syslog_server(w, "c-tls-badca").await?;
    tls_server(
        w,
        "c-tls-badfp",
        6514,
        &["--syslog-fingerprint", &certs.wrong_fingerprint],
    )
    .await?;
    expect_tls_refused(w, "c-tls-badfp", SYSLOG_TLS_LOG, 0).await?;
    remove_syslog_server(w, "c-tls-badfp").await?;

    log("tls: policy refuses TLS 1.2 and classical TLS 1.3 by default");
    tls_server(w, "c-tls12", 6515, &["--syslog-trust-anchor-file", ca]).await?;
    expect_tls_refused(w, "c-tls12", SYSLOG_TLS12_LOG, 0).await?;
    tls_server(w, "c-tlsc", 6516, &["--syslog-trust-anchor-file", ca]).await?;
    expect_tls_refused(w, "c-tlsc", SYSLOG_TLSC_LOG, 0).await?;

    log("tls: allow-tls12 reaches the TLS 1.2 collector, nothing classical on TLS 1.3");
    tls_server(w, "c-tls12", 6515, &["--syslog-allow-tls12"]).await?;
    wait_router_a_log(w, &connected("c-tls12", "TLSv1_2", ""), 0).await?;
    wait_router_a_log(w, "syslog tls12 classical key exchange server=c-tls12", 0).await?;
    wait_router_a_log(w, "suite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0).await?;
    expect_tls_delivery(w, SYSLOG_TLS12_LOG).await?;
    // The opt-in never downgrades a collector that does the hybrid exchange.
    remove_syslog_server(w, "c-tlsc").await?;
    tls_server(
        w,
        "c-tls-ca",
        6514,
        &["--syslog-trust-anchor-file", ca, "--syslog-allow-tls12"],
    )
    .await?;
    wait_router_a_log(w, &connected("c-tls-ca", "TLSv1_3", "X25519MLKEM768"), 1).await?;
    remove_syslog_server(w, "c-tls-ca").await?;
    // ... and still refuses the TLS 1.3 listener that offers a classical group only.
    let before = router_a_log_count(w, &refused("c-tlsc")).await?;
    tls_server(
        w,
        "c-tlsc",
        6516,
        &["--syslog-trust-anchor-file", ca, "--syslog-allow-tls12"],
    )
    .await?;
    expect_tls_refused(w, "c-tlsc", SYSLOG_TLSC_LOG, before).await?;
    remove_syslog_server(w, "c-tlsc").await?;

    log("tls: allow-tls12 off again refuses the TLS 1.2 collector");
    let before = router_a_log_count(w, &refused("c-tls12")).await?;
    tls_server(w, "c-tls12", 6515, &["--no-syslog-allow-tls12"]).await?;
    expect_tls_refused(w, "c-tls12", SYSLOG_TLS12_LOG, before).await?;
    remove_syslog_server(w, "c-tls12").await
}

fn expect_body(body: &str, needle: &str) -> anyhow::Result<()> {
    if body.contains(needle) {
        Ok(())
    } else {
        bail!("body lacks '{needle}': {body}")
    }
}
