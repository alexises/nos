//! One-shot config provisioning tool for manually verifying the nos-bgpd
//! FSM feature end to end across two real containers. Not part of the nos
//! workspace — nos-cli's interactive shell (reedline) can't be driven over
//! a plain pipe, so this speaks nos-configd's IPC protocol directly,
//! reusing nos-proto's own types for wire compatibility.
//!
//! Sets up exactly one "router": one interface (one address) enslaved to
//! one routing table, one BGP instance (asn/router-id) owning that routing
//! table, one peer-group (remote-as + ipv4-unicast), one peer using that
//! peer-group. Opens a transaction, applies every op, commits, and (if
//! `--save` is passed) persists it.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use ipnet::IpNet;
use nos_proto::{
    AddressFamily, BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp, ConfigOp, Event, InterfaceOp,
    IpcCodec, PolicyDefinitionOp, Redistribute, RedistributeSource, RedistributeTarget, Request,
    RoutingTableOp, StaticRouteOp, StaticRoutingInstanceOp, TransactionBase,
};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Parser)]
#[allow(clippy::struct_excessive_bools)] // one CLI flag per independent provisioning toggle
struct Args {
    #[arg(long)]
    config_socket: PathBuf,

    #[arg(long, default_value = "eth0")]
    interface: String,
    #[arg(long)]
    address: IpNet,

    #[arg(long, default_value = "rt1")]
    routing_table: String,

    #[arg(long, default_value = "r1")]
    bgp_instance: String,
    #[arg(long)]
    asn: u32,
    #[arg(long)]
    router_id: Ipv4Addr,

    #[arg(long, default_value = "pg1")]
    peer_group: String,
    #[arg(long)]
    remote_as: u32,

    #[arg(long)]
    peer: IpAddr,

    /// If set, adds one static route (`--static-gateway` required) to a
    /// static-routing-instance associated with `--routing-table`.
    #[arg(long)]
    static_route: Option<IpNet>,
    #[arg(long)]
    static_gateway: Option<IpAddr>,
    #[arg(long, default_value = "sri1")]
    static_routing_instance: String,

    /// If set, configures `redistribute from static to bgp` on
    /// `--routing-table` — requires `--static-route` to also be set (so the
    /// table has a `static_routing_instance` to redistribute from).
    #[arg(long)]
    redistribute: bool,

    /// If set, configures an RFC 2385 TCP MD5 password on `--peer-group`
    /// (`BgpPeerGroupOp::SetMd5Auth`) — for verifying session authentication
    /// end to end (matching passwords on both routers establish; a
    /// mismatched one on either side does not).
    #[arg(long)]
    md5_password: Option<String>,

    /// If set, marks `--peer-group` as an RFC 4456 route-reflector client
    /// (requires `--remote-as` to equal `--asn`, i.e. an iBGP peer-group).
    /// Calling this tool again with the same `--peer-group` but a different
    /// `--peer` adds a second client to the same peer-group, since
    /// `BgpPeerOp::Set` upserts by remote-address.
    #[arg(long)]
    route_reflector_client: bool,

    /// If set, marks `--peer-group` as an RFC 7947 route-server client
    /// (requires `--remote-as` to differ from `--asn`, i.e. an eBGP
    /// peer-group). Mutually exclusive with `--route-reflector-client`.
    #[arg(long)]
    route_server_client: bool,

    /// If set, configures `--bgp-instance`'s RFC 4456 cluster-id
    /// (`BgpInstanceOp::SetClusterId`) — only meaningful alongside
    /// `--route-reflector-client`.
    #[arg(long)]
    cluster_id: Option<Ipv4Addr>,

    #[arg(long)]
    save: bool,

    /// If set (with `--policy-source-file`), creates/updates a
    /// `PolicyDefinition` named `<policy-name>` from that file's content —
    /// for verifying RPL import/export policy end to end. Independent of
    /// `--import-policy`/`--export-policy`, which point a peer-group *at* a
    /// policy by name; this just defines one.
    #[arg(long)]
    policy_name: Option<String>,
    #[arg(long)]
    policy_source_file: Option<PathBuf>,

    /// Overrides `--peer-group`'s import policy (defaults to `accept-all` —
    /// see root CLAUDE.md's "Default-deny rollout impact": every peer-group
    /// this tool provisions needs an explicit policy in each direction, or
    /// the two-router scenarios below would establish sessions but exchange
    /// zero routes).
    #[arg(long, default_value = "accept-all")]
    import_policy: String,
    #[arg(long, default_value = "accept-all")]
    export_policy: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let stream = UnixStream::connect(&args.config_socket)
        .await
        .with_context(|| format!("connecting to {}", args.config_socket.display()))?;
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());

    let txn = "verify".to_string();

    send(
        &mut writer,
        &mut reader,
        Request::OpenTransaction {
            name: txn.clone(),
            base: TransactionBase::Current,
        },
    )
    .await?;

    let mut ops = vec![
        ConfigOp::Interface(InterfaceOp::Ensure {
            name: args.interface.clone(),
        }),
        ConfigOp::Interface(InterfaceOp::AddAddress {
            name: args.interface.clone(),
            address: args.address,
        }),
        ConfigOp::Interface(InterfaceOp::SetRoutingTable {
            name: args.interface.clone(),
            routing_table: args.routing_table.clone(),
        }),
        ConfigOp::RoutingTable(RoutingTableOp::Ensure {
            name: args.routing_table.clone(),
        }),
        ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance {
            name: args.routing_table.clone(),
            bgp_instance: args.bgp_instance.clone(),
        }),
        ConfigOp::BgpInstance(BgpInstanceOp::Ensure {
            name: args.bgp_instance.clone(),
        }),
        ConfigOp::BgpInstance(BgpInstanceOp::SetAsn {
            name: args.bgp_instance.clone(),
            asn: args.asn,
        }),
        ConfigOp::BgpInstance(BgpInstanceOp::SetRouterId {
            name: args.bgp_instance.clone(),
            router_id: args.router_id,
        }),
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Ensure {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
        }),
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRemoteAs {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            remote_as: args.remote_as,
        }),
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::AddAddressFamily {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            af: AddressFamily::Ipv4Unicast,
        }),
        // `import_policy`/`export_policy` default to `deny-all` (see root
        // CLAUDE.md's "Default-deny rollout impact") — every router this
        // tool provisions needs both set explicitly (`accept-all` unless
        // overridden via `--import-policy`/`--export-policy`), or
        // verify-bgp.sh's phases (which predate RPL and expect every route
        // to flow unconditionally) would establish sessions but exchange
        // zero routes.
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetImportPolicy {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            import_policy: args.import_policy.clone(),
        }),
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetExportPolicy {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            export_policy: args.export_policy.clone(),
        }),
        ConfigOp::BgpPeer(BgpPeerOp::Set {
            instance: args.bgp_instance.clone(),
            remote_address: args.peer,
            peer_group: args.peer_group.clone(),
        }),
    ];

    if let Some(subnet) = args.static_route {
        let gateway = args
            .static_gateway
            .context("--static-gateway is required when --static-route is set")?;
        ops.push(ConfigOp::StaticRoutingInstance(
            StaticRoutingInstanceOp::Ensure {
                name: args.static_routing_instance.clone(),
            },
        ));
        ops.push(ConfigOp::StaticRoute(StaticRouteOp::Set {
            instance: args.static_routing_instance.clone(),
            subnet,
            gateway,
        }));
        ops.push(ConfigOp::RoutingTable(
            RoutingTableOp::SetStaticRoutingInstance {
                name: args.routing_table.clone(),
                static_routing_instance: args.static_routing_instance.clone(),
            },
        ));
    } else if args.redistribute {
        bail!("--redistribute requires --static-route (and --static-gateway) to also be set");
    }

    if args.redistribute {
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
            name: args.routing_table.clone(),
            redistribute: Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
            },
        }));
    }

    if let Some(password) = args.md5_password.clone() {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetMd5Auth {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            password,
        }));
    }

    if args.route_reflector_client {
        ops.push(ConfigOp::BgpPeerGroup(
            BgpPeerGroupOp::SetRouteReflectorClient {
                instance: args.bgp_instance.clone(),
                name: args.peer_group.clone(),
            },
        ));
    }
    if args.route_server_client {
        ops.push(ConfigOp::BgpPeerGroup(
            BgpPeerGroupOp::SetRouteServerClient {
                instance: args.bgp_instance.clone(),
                name: args.peer_group.clone(),
            },
        ));
    }
    if let Some(cluster_id) = args.cluster_id {
        ops.push(ConfigOp::BgpInstance(BgpInstanceOp::SetClusterId {
            name: args.bgp_instance.clone(),
            cluster_id,
        }));
    }

    if let Some(name) = args.policy_name.clone() {
        let path = args
            .policy_source_file
            .context("--policy-source-file is required when --policy-name is set")?;
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        ops.push(ConfigOp::PolicyDefinition(PolicyDefinitionOp::Ensure {
            name: name.clone(),
        }));
        ops.push(ConfigOp::PolicyDefinition(PolicyDefinitionOp::SetSource {
            name,
            source,
        }));
    } else if args.policy_source_file.is_some() {
        bail!("--policy-source-file requires --policy-name to also be set");
    }

    for op in ops {
        send(
            &mut writer,
            &mut reader,
            Request::ApplyOp {
                name: txn.clone(),
                op,
            },
        )
        .await?;
    }

    send(
        &mut writer,
        &mut reader,
        Request::CommitTransaction { name: txn.clone() },
    )
    .await?;

    if args.save {
        send(&mut writer, &mut reader, Request::Save).await?;
    }

    println!("provisioning complete");
    Ok(())
}

async fn send(
    writer: &mut FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<Request>>,
    reader: &mut FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<Event>>,
    req: Request,
) -> anyhow::Result<()> {
    let label = format!("{req:?}");
    writer.send(req).await.context("sending request")?;
    match reader.next().await {
        Some(Ok(Event::Error(e))) => bail!("{label} -> error: {e}"),
        Some(Ok(event)) => {
            eprintln!("{label} -> {event:?}");
            Ok(())
        }
        Some(Err(e)) => bail!("{label} -> transport error: {e}"),
        None => bail!("{label} -> connection closed"),
    }
}
