use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use nos_log_client::ForwardingLayer;
use nos_proto::diff::REST_API_LABEL;
use nos_proto::diff::VNI_LABEL;
use nos_proto::{
    DiffScope, Role, DEFAULT_CONFIG_SOCKET, DEFAULT_LOG_SOCKET, DEFAULT_PKI_DIR,
    DEFAULT_WATCHDOG_SOCKET,
};
use nos_watchdog::{
    broker::{self, Sockets},
    instances, supervise_one, BackoffPolicy, Endpoint, EndpointKind, EndpointRegistry, Managed,
    Pki, ProcessSpec,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "nos-watchdogd", about = "NOS process supervisor")]
struct Args {
    /// Path to the nos-configd binary to supervise.
    #[arg(long, default_value = "/usr/local/bin/nos-configd")]
    configd_bin: PathBuf,

    /// Extra arguments forwarded to nos-configd (e.g. --listen, --config-file).
    #[arg(long = "configd-arg", allow_hyphen_values = true)]
    configd_flags: Vec<String>,

    /// Path to the nos-bgpd binary to supervise (one instance is spawned per
    /// BGP instance in the running config).
    #[arg(long, default_value = "/usr/local/bin/nos-bgpd")]
    bgpd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-bgpd instance.
    #[arg(long = "bgpd-arg", allow_hyphen_values = true)]
    bgpd_flags: Vec<String>,

    /// Path to the nos-ribd binary to supervise (one instance is spawned per
    /// routing table in the running config).
    #[arg(long, default_value = "/usr/local/bin/nos-ribd")]
    ribd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-ribd instance.
    #[arg(long = "ribd-arg", allow_hyphen_values = true)]
    ribd_flags: Vec<String>,

    /// Path to the nos-fdbd binary to supervise (one instance is spawned per
    /// broadcast domain that has a `vni`).
    #[arg(long, default_value = "/usr/local/bin/nos-fdbd")]
    fdbd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-fdbd instance.
    #[arg(long = "fdbd-arg", allow_hyphen_values = true)]
    fdbd_flags: Vec<String>,

    /// Path to the nos-ospfd binary to supervise (one instance is spawned
    /// per OSPF instance in the running config).
    #[arg(long, default_value = "/usr/local/bin/nos-ospfd")]
    ospfd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-ospfd instance.
    #[arg(long = "ospfd-arg", allow_hyphen_values = true)]
    ospfd_flags: Vec<String>,

    /// Path to the nos-ospfv3d binary to supervise (one instance is spawned
    /// per `OSPFv3` instance in the running config) — the RFC 5340 (IPv6)
    /// counterpart of nos-ospfd, a fully independent daemon family.
    #[arg(long, default_value = "/usr/local/bin/nos-ospfv3d")]
    ospfv3d_bin: PathBuf,

    /// Extra arguments forwarded to every nos-ospfv3d instance.
    #[arg(long = "ospfv3d-arg", allow_hyphen_values = true)]
    ospfv3d_flags: Vec<String>,

    /// Path to the nos-restd binary to supervise (one instance is spawned
    /// per routing table that has `rest-api` pinned to it).
    #[arg(long, default_value = "/usr/local/bin/nos-restd")]
    restd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-restd instance.
    #[arg(long = "restd-arg", allow_hyphen_values = true)]
    restd_flags: Vec<String>,

    /// Path to the nos-interfaced binary to supervise. Unlike nos-bgpd/
    /// nos-ribd, exactly one instance is always supervised regardless of how
    /// many interfaces are configured — see `interface/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-interfaced")]
    interfaced_bin: PathBuf,

    /// Extra arguments forwarded to nos-interfaced.
    #[arg(long = "interfaced-arg", allow_hyphen_values = true)]
    interfaced_flags: Vec<String>,

    /// Unix socket nos-interfaced listens on for interface queries (e.g.
    /// from `nos show interface`). Also served out as the resolved address
    /// for `ServiceRef::Interfaces` broker queries, the same way
    /// `--config-socket` is for `ServiceRef::Config`.
    #[arg(long, default_value = "/run/nos/interface.sock")]
    interfaced_listen_socket: PathBuf,

    /// Path to the nos-logd binary to supervise. Like nos-interfaced, exactly
    /// one instance is always supervised regardless of how many other
    /// daemons are running.
    #[arg(long, default_value = "/usr/local/bin/nos-logd")]
    logd_bin: PathBuf,

    /// Extra arguments forwarded to nos-logd.
    #[arg(long = "logd-arg", allow_hyphen_values = true)]
    logd_flags: Vec<String>,

    /// Unix socket nos-logd listens on for pushed log entries and queries
    /// (e.g. from `nos show log`). Also served out as the resolved address
    /// for `ServiceRef::Log` broker queries, the same way
    /// `--interfaced-listen-socket` is for `ServiceRef::Interfaces` — and
    /// passed via `--log-socket` to every other supervised process so it can
    /// forward its own logs here.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Path to the nos-lacpd binary to supervise. Like nos-interfaced/
    /// nos-logd, exactly one instance is always supervised regardless of how
    /// many `Lacp`-mode port aggregates are configured — see
    /// `lacp/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-lacpd")]
    lacpd_bin: PathBuf,

    /// Extra arguments forwarded to nos-lacpd.
    #[arg(long = "lacpd-arg", allow_hyphen_values = true)]
    lacpd_flags: Vec<String>,

    /// Unix socket nos-lacpd listens on for LACP status queries (e.g. from
    /// `nos show lacp`). Also served out as the resolved address for
    /// `ServiceRef::Lacp` broker queries, the same way
    /// `--interfaced-listen-socket` is for `ServiceRef::Interfaces`.
    #[arg(long, default_value = "/run/nos/lacp.sock")]
    lacpd_listen_socket: PathBuf,

    /// Path to the nos-lldpd binary to supervise. Like nos-lacpd, exactly
    /// one instance is always supervised regardless of how many interfaces
    /// have LLDP enabled — see `lldp/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-lldpd")]
    lldpd_bin: PathBuf,

    /// Extra arguments forwarded to nos-lldpd.
    #[arg(long = "lldpd-arg", allow_hyphen_values = true)]
    lldpd_flags: Vec<String>,

    /// Unix socket nos-lldpd listens on for LLDP neighbor queries (e.g. from
    /// `nos show lldp neighbors`). Also served out as the resolved address
    /// for `ServiceRef::Lldp` broker queries, the same way
    /// `--lacpd-listen-socket` is for `ServiceRef::Lacp`.
    #[arg(long, default_value = "/run/nos/lldp.sock")]
    lldpd_listen_socket: PathBuf,

    /// Path to nos-configd's IPC Unix socket, used by the watchdog itself to
    /// subscribe to BGP instance and routing table changes. Independent of
    /// `--configd-arg`, which is an opaque pass-through to the child — if
    /// the child's actual listen address is overridden via `--configd-arg
    /// --listen=...`, this must be updated to match. Also served out as the
    /// resolved address for `ServiceRef::Config` broker queries, since the
    /// watchdog itself is the one process every other client asks instead of
    /// assuming this default.
    #[arg(long, default_value = DEFAULT_CONFIG_SOCKET)]
    config_socket: PathBuf,

    /// Directory the per-instance daemon sockets (`bgp-<name>.sock`,
    /// `rib-<name>.sock`, …) are created in. The fixed sockets have their
    /// own flags.
    #[arg(long, default_value = "/run/nos")]
    run_dir: PathBuf,

    /// Unix socket the endpoint-resolution broker listens on. Every other
    /// daemon/CLI dials this first to learn where to reach nos-configd or a
    /// specific nos-ribd instance, instead of assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    listen_socket: PathBuf,

    /// Directory the watchdog publishes `ca.crt` in — the public trust
    /// anchor every IPC client (including `nos-cli`, from another container
    /// sharing this volume) bootstraps from.
    #[arg(long, default_value = DEFAULT_PKI_DIR)]
    pki_dir: PathBuf,

    /// Seconds a daemon's IPC certificate is valid for.
    #[arg(long, default_value_t = 24 * 3600)]
    pki_leaf_lifetime: u64,

    /// Seconds between fresh certificates pushed to every running daemon.
    /// Must be shorter than `--pki-leaf-lifetime`. (Short values let
    /// `nos-e2e` exercise rotation in seconds.)
    #[arg(long, default_value_t = 8 * 3600)]
    pki_rotate_every: u64,

    /// Seconds a logged-in user's certificate (`nos` shell, `nos-provision`)
    /// is valid for; the client renews it at half-life.
    #[arg(long, default_value_t = 8 * 3600)]
    pki_user_lifetime: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Before tracing: the log forwarder itself needs an identity to reach
    // nos-logd, so the CA has to exist first.
    let pki = Pki::start(
        &args.pki_dir,
        Duration::from_secs(args.pki_leaf_lifetime),
        Duration::from_secs(args.pki_rotate_every),
        Duration::from_secs(args.pki_user_lifetime),
    )
    .context("starting the ipc certificate authority")?;
    tracing_subscriber::registry()
        // `RUST_LOG` support: defaults to `trace`, i.e. exactly the
        // unfiltered behavior this process had before, so an unset
        // `RUST_LOG` changes nothing. Added so `tools/bench-bgp.sh` can run
        // the stack quietly enough to measure BGP rather than logging.
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            "nos-watchdogd",
            args.log_socket.clone(),
            pki.identity.clone(),
            shutdown_rx.clone(),
        ))
        .init();

    info!(
        ca = %args.pki_dir.join("ca.crt").display(),
        leaf_lifetime_secs = args.pki_leaf_lifetime,
        rotate_every_secs = args.pki_rotate_every,
        "ipc certificate authority ready"
    );
    let policy = BackoffPolicy::default();
    let registry = EndpointRegistry::default();
    let mut tasks = vec![
        pki.spawn_self_rotation(shutdown_rx.clone()),
        tokio::spawn(
            pki.clone()
                .follow_users(args.config_socket.clone(), shutdown_rx.clone()),
        ),
    ];

    // nos-logd is spawned first (still just one more supervised process,
    // with no ordering guarantee enforced) so the window in which every
    // other process's own forwarder has nothing to connect to is as short
    // as possible — a fixed 1s retry (see `nos_log_client`) covers the
    // rest.
    let logd_args = std::iter::once("--listen-socket".to_string())
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(std::iter::once("--watchdog-socket".to_string()))
        .chain(std::iter::once(args.listen_socket.display().to_string()))
        .chain(args.logd_flags)
        .collect();
    let logd_spec = ProcessSpec::new("nos-logd", args.logd_bin, logd_args).with_identity(
        pki.clone(),
        Role::Logd,
        "",
    );
    tasks.push(tokio::spawn(supervise_one(
        logd_spec,
        policy,
        shutdown_rx.clone(),
    )));

    let configd_args = std::iter::once("--log-socket".to_string())
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(args.configd_flags)
        .collect();
    let configd_spec = ProcessSpec::new("nos-configd", args.configd_bin, configd_args)
        .with_identity(pki.clone(), Role::Configd, "");
    tasks.push(tokio::spawn(supervise_one(
        configd_spec,
        policy,
        shutdown_rx.clone(),
    )));
    // The three dynamically-spawned daemon families: one process per named
    // config object, all supervised by the same `instances::manage`.
    let managed = [
        Managed {
            scope: DiffScope::BgpInstances,
            section: |d| &d.bgp_instances,
            bin: args.bgpd_bin,
            flags: args.bgpd_flags,
            name_flag: "--instance",
            daemon: "nos-bgpd",
            role: Role::Bgpd,
            pki: pki.clone(),
            noun: "BGP instance",
            endpoint: Some(Endpoint {
                kind: EndpointKind::BgpInstance,
                socket_prefix: "bgp",
            }),
            claim_label: None,
            config_socket: args.config_socket.clone(),
            log_socket: args.log_socket.clone(),
            watchdog_listen_socket: args.listen_socket.clone(),
            run_dir: args.run_dir.clone(),
            policy,
            registry: registry.clone(),
        },
        Managed {
            scope: DiffScope::RoutingTables,
            section: |d| &d.routing_tables,
            bin: args.ribd_bin,
            flags: args.ribd_flags,
            name_flag: "--table",
            daemon: "nos-ribd",
            role: Role::Ribd,
            pki: pki.clone(),
            noun: "routing table",
            endpoint: Some(Endpoint {
                kind: EndpointKind::RibTable,
                socket_prefix: "rib",
            }),
            claim_label: None,
            config_socket: args.config_socket.clone(),
            log_socket: args.log_socket.clone(),
            watchdog_listen_socket: args.listen_socket.clone(),
            run_dir: args.run_dir.clone(),
            policy,
            registry: registry.clone(),
        },
        Managed {
            scope: DiffScope::OspfInstances,
            section: |d| &d.ospf_instances,
            bin: args.ospfd_bin,
            flags: args.ospfd_flags,
            name_flag: "--instance",
            daemon: "nos-ospfd",
            role: Role::Ospfd,
            pki: pki.clone(),
            noun: "OSPF instance",
            endpoint: Some(Endpoint {
                kind: EndpointKind::OspfInstance,
                socket_prefix: "ospf",
            }),
            claim_label: None,
            config_socket: args.config_socket.clone(),
            log_socket: args.log_socket.clone(),
            watchdog_listen_socket: args.listen_socket.clone(),
            run_dir: args.run_dir.clone(),
            policy,
            registry: registry.clone(),
        },
        Managed {
            scope: DiffScope::Ospfv3Instances,
            section: |d| &d.ospfv3_instances,
            bin: args.ospfv3d_bin,
            flags: args.ospfv3d_flags,
            name_flag: "--instance",
            daemon: "nos-ospfv3d",
            role: Role::Ospfv3d,
            pki: pki.clone(),
            noun: "OSPFv3 instance",
            endpoint: Some(Endpoint {
                kind: EndpointKind::Ospfv3Instance,
                socket_prefix: "ospfv3",
            }),
            claim_label: None,
            config_socket: args.config_socket.clone(),
            log_socket: args.log_socket.clone(),
            watchdog_listen_socket: args.listen_socket.clone(),
            run_dir: args.run_dir.clone(),
            policy,
            registry: registry.clone(),
        },
        // One `nos-fdbd` per broadcast domain, but only while the domain has a
        // `vni` (`claim_label`, like `nos-restd` on `rest-api`) — a plain L2
        // domain has no EVPN/VXLAN state for a daemon to own.
        Managed {
            scope: DiffScope::BroadcastDomains,
            section: |d| &d.broadcast_domains,
            bin: args.fdbd_bin,
            flags: args.fdbd_flags,
            name_flag: "--domain",
            daemon: "nos-fdbd",
            role: Role::Fdbd,
            pki: pki.clone(),
            noun: "broadcast domain",
            endpoint: Some(Endpoint {
                kind: EndpointKind::FdbDomain,
                socket_prefix: "fdb",
            }),
            claim_label: Some(VNI_LABEL),
            config_socket: args.config_socket.clone(),
            log_socket: args.log_socket.clone(),
            watchdog_listen_socket: args.listen_socket.clone(),
            run_dir: args.run_dir.clone(),
            policy,
            registry: registry.clone(),
        },
        // Opt-in per routing table (its `rest_api` field), not one per
        // table — hence `claim_label`. No IPC query listener of its own, so
        // no endpoint registration.
        Managed {
            scope: DiffScope::RoutingTables,
            section: |d| &d.routing_tables,
            bin: args.restd_bin,
            flags: args.restd_flags,
            name_flag: "--table",
            daemon: "nos-restd",
            role: Role::Restd,
            pki: pki.clone(),
            noun: "REST API",
            endpoint: None,
            claim_label: Some(REST_API_LABEL),
            config_socket: args.config_socket.clone(),
            log_socket: args.log_socket.clone(),
            watchdog_listen_socket: args.listen_socket.clone(),
            run_dir: args.run_dir.clone(),
            policy,
            registry: registry.clone(),
        },
    ];
    for m in managed {
        tasks.push(tokio::spawn(instances::manage(m, shutdown_rx.clone())));
    }

    let interfaced_args = std::iter::once("--listen-socket".to_string())
        .chain(std::iter::once(
            args.interfaced_listen_socket.display().to_string(),
        ))
        .chain(std::iter::once("--watchdog-socket".to_string()))
        .chain(std::iter::once(args.listen_socket.display().to_string()))
        .chain(std::iter::once("--log-socket".to_string()))
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(args.interfaced_flags)
        .collect();
    let interfaced_spec = ProcessSpec::new("nos-interfaced", args.interfaced_bin, interfaced_args)
        .with_identity(pki.clone(), Role::Interfaced, "");
    tasks.push(tokio::spawn(supervise_one(
        interfaced_spec,
        policy,
        shutdown_rx.clone(),
    )));

    let lacpd_args = std::iter::once("--listen-socket".to_string())
        .chain(std::iter::once(
            args.lacpd_listen_socket.display().to_string(),
        ))
        .chain(std::iter::once("--watchdog-socket".to_string()))
        .chain(std::iter::once(args.listen_socket.display().to_string()))
        .chain(std::iter::once("--log-socket".to_string()))
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(args.lacpd_flags)
        .collect();
    let lacpd_spec = ProcessSpec::new("nos-lacpd", args.lacpd_bin, lacpd_args).with_identity(
        pki.clone(),
        Role::Lacpd,
        "",
    );
    tasks.push(tokio::spawn(supervise_one(
        lacpd_spec,
        policy,
        shutdown_rx.clone(),
    )));

    let lldpd_args = std::iter::once("--listen-socket".to_string())
        .chain(std::iter::once(
            args.lldpd_listen_socket.display().to_string(),
        ))
        .chain(std::iter::once("--watchdog-socket".to_string()))
        .chain(std::iter::once(args.listen_socket.display().to_string()))
        .chain(std::iter::once("--log-socket".to_string()))
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(args.lldpd_flags)
        .collect();
    let lldpd_spec = ProcessSpec::new("nos-lldpd", args.lldpd_bin, lldpd_args).with_identity(
        pki.clone(),
        Role::Lldpd,
        "",
    );
    tasks.push(tokio::spawn(supervise_one(
        lldpd_spec,
        policy,
        shutdown_rx.clone(),
    )));

    let broker_task = broker::start(
        &args.listen_socket,
        registry,
        Sockets {
            config: args.config_socket,
            interfaces: args.interfaced_listen_socket,
            log: args.log_socket,
            lacp: args.lacpd_listen_socket,
            lldp: args.lldpd_listen_socket,
        },
        pki.clone(),
    )
    .inspect_err(|e| tracing::error!(error = %e, "failed to start broker IPC server"))
    .context("starting broker IPC server")?;

    info!(task_count = tasks.len(), "nos-watchdogd supervising tasks");

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received, stopping supervised processes");

    let _ = shutdown_tx.send(true);
    for task in tasks {
        if let Err(e) = task.await {
            error!(error = %e, "supervisor task panicked");
        }
    }
    // The broker's accept loop has no shutdown signal of its own (it never
    // needs to drain in-flight state the way a supervised process does) —
    // aborting it directly avoids blocking shutdown on a loop that would
    // otherwise run forever.
    broker_task.abort();

    info!("shutting down");
    Ok(())
}

/// Waits for either SIGTERM (the signal `docker stop` sends) or SIGINT
/// (Ctrl-C, for interactive/local runs).
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;

    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
        let args = Args::try_parse_from(["nos-watchdogd", "--bgpd-arg", "--profile-memory-out=x"])
            .unwrap();
        assert_eq!(args.bgpd_flags, ["--profile-memory-out=x"]);
    }
}
