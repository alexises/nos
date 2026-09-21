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
    a.provision(&["--loopback-address", LOOPBACK_ADDRESS])
        .await?;
    a.wait(&format!("created loopback device device={LOOPBACK_DEVICE}"))
        .await?;
    a.wait("enslaved interface to vrf interface=loopback-rt1")
        .await?;
    a.wait(&format!(
        "added interface address interface=loopback-rt1 address={LOOPBACK_ADDRESS}"
    ))
    .await?;

    log("removing router-a's loopback interface");
    a.provision(&["--delete-loopback"]).await?;
    a.wait(&format!(
        "deleted loopback device interface=loopback-rt1 device={LOOPBACK_DEVICE}"
    ))
    .await
}

pub async fn mtu(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.provision(&["--mtu", &MTU_VALUE.to_string()]).await?;
    a.wait(&format!(
        "applied interface mtu interface=eth0 mtu={MTU_VALUE}"
    ))
    .await
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
    let mut on_b = on;
    on_b.extend(strings(&["--lacp-system-id", LACP_SYSTEM_ID_B]));
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

    // Withdraw eth2 from router-b's aggregate (its veth stays up): router-a's
    // nos-lacpd must detect the silence via its real Receive Machine timeout
    // and nos-interfaced must release eth2 — proving the enslavement is
    // dynamic. Both sides run `lacp-rate fast`, so the 30s budget is far under
    // the 90s Long timer, which proves the fast rate is really in effect. The
    // Expired baseline is taken here since a port also passes through Expired
    // while first starting up.
    let expired_base = a.count("interface=eth2 receive_state=Expired");
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

    // Tunable timers + Management Address TLV: tx-interval 5 x tx-hold 3 must
    // show up as the TTL the neighbor learned (15), and each router's own
    // address as the management address it advertised.
    let mgmt_a = learned_a(&format!(" ttl=15 management_addresses={IP_B}"));
    let mgmt_b = learned_b(&format!(" ttl=15 management_addresses={IP_A}"));
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
        ],
    ))
    .await?;
    a.wait_new(&mgmt_a, base_ma, 60).await?;
    b.wait_new(&mgmt_b, base_mb, 60).await?;

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
    // a *new* neighbor triggers an immediate reply.
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
        let (status, _) = a.rest_with(&anonymous, Method::GET, path, None).await?;
        if status != 401 {
            bail!("router-a: GET {path} without a certificate -> {status}, want 401");
        }
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

fn expect_body(body: &str, needle: &str) -> anyhow::Result<()> {
    if body.contains(needle) {
        Ok(())
    } else {
        bail!("body lacks '{needle}': {body}")
    }
}
