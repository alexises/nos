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
    AddressFamily, BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp, BroadcastDomainOp, ConfigOp, Event,
    InterfaceOp, IpcCodec, OspfAreaOp, OspfInstanceOp, OspfProfileOp, PolicyDefinitionOp,
    Redistribute, RedistributeSource, RedistributeTarget, Request, RoutingTableOp, SourceAddress,
    StaticRouteOp, StaticRoutingInstanceOp, SubinterfaceOp, SwitchingProfileOp, TransactionBase,
    VlanTag,
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

    /// Which of `--interface`'s subinterfaces `--address`/`--routing-table`
    /// target — `0` (default) for the untagged/native subinterface,
    /// matching a bare `set interface <name> address ...` in nos-cli.
    /// `1..=4094` targets a real 802.1q VLAN subinterface instead.
    #[arg(long, default_value_t = 0)]
    subinterface_tag: u16,

    /// If set, deletes `--interface`'s `--subinterface-tag` subinterface
    /// instead of setting its address/routing-table.
    #[arg(long)]
    delete_subinterface: bool,

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

    /// Names an RPL policy (or `accept-all`/`deny-all`) to filter
    /// redistributed routes through — the redistribute rule's optional
    /// `policy <name>` clause. Only meaningful with `--redistribute`;
    /// omitted, redistribution stays unfiltered.
    #[arg(long)]
    redistribute_policy: Option<String>,

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
    /// for verifying RPL import/export/redistribute policy end to end.
    /// Independent of `--import-policy`/`--export-policy`/
    /// `--redistribute-policy`, which point a peer-group or redistribute
    /// rule *at* a policy by name; this just defines one.
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

    /// If set, ensures a loopback interface for `--routing-table` (named
    /// `loopback-<routing-table>`, per `nos_proto::LOOPBACK_PREFIX` — the
    /// naming convention alone marks it as a loopback, no separate flag)
    /// and adds this address to it. Mutually exclusive with
    /// `--delete-loopback`.
    #[arg(long)]
    loopback_address: Option<IpNet>,

    /// If set, deletes `--routing-table`'s loopback interface
    /// (`loopback-<routing-table>`) instead of creating/updating one.
    /// Mutually exclusive with `--loopback-address`.
    #[arg(long)]
    delete_loopback: bool,

    /// Which broadcast domain `--broadcast-domain-svi-address`/
    /// `--delete-broadcast-domain-svi` target.
    #[arg(long, default_value = "bd-svi")]
    broadcast_domain: String,

    /// If set, ensures `--broadcast-domain` and adds this address to it,
    /// associating it with `--routing-table` (its VRF) — making the
    /// domain's own bridge device an SVI (switch virtual interface).
    /// Mutually exclusive with `--delete-broadcast-domain-svi`.
    #[arg(long)]
    broadcast_domain_svi_address: Option<IpNet>,

    /// If set, deletes `--broadcast-domain` outright instead of
    /// creating/updating its SVI. Mutually exclusive with
    /// `--broadcast-domain-svi-address`.
    #[arg(long)]
    delete_broadcast_domain_svi: bool,

    /// If set, points `--peer-group`'s source-address at this named
    /// interface (`BgpPeerGroupOp::SetSourceAddress` with
    /// `SourceAddress::Interface`). Mutually exclusive with
    /// `--source-address-loopback`/`--clear-source-address`.
    #[arg(long)]
    source_address_interface: Option<String>,

    /// If set, points `--peer-group`'s source-address at this instance's own
    /// loopback interface (`SourceAddress::Loopback`) — no interface name
    /// needed, derived from `--routing-table` by nos-bgpd itself at
    /// runtime. Mutually exclusive with
    /// `--source-address-interface`/`--clear-source-address`.
    #[arg(long)]
    source_address_loopback: bool,

    /// Paired with `--source-address-interface`/`--source-address-loopback`
    /// to disambiguate which of that interface's addresses to use.
    #[arg(long)]
    source_address_label: Option<String>,

    /// If set, clears `--peer-group`'s source-address
    /// (`BgpPeerGroupOp::ClearSourceAddress`). Mutually exclusive with
    /// `--source-address-interface`/`--source-address-loopback`.
    #[arg(long)]
    clear_source_address: bool,

    /// If set, creates this switching profile (if missing), populates it
    /// from `--switching-profile-member`, and assigns it to `--interface`
    /// (`InterfaceOp::SetSwitchingProfile`). Mutually exclusive with
    /// `--delete-switching-profile`.
    #[arg(long)]
    switching_profile: Option<String>,

    /// One `DOMAIN:TAG` pair per repetition (`TAG` is `untagged` or a
    /// dot1q id `1..=4094`), added as a member of `--switching-profile`
    /// (creating the named broadcast domain if missing). Only meaningful
    /// with `--switching-profile` also set.
    #[arg(long = "switching-profile-member")]
    switching_profile_members: Vec<String>,

    /// If set, clears `--interface`'s switching-profile assignment
    /// instead of setting one. Mutually exclusive with
    /// `--switching-profile`.
    #[arg(long)]
    delete_switching_profile: bool,

    /// If set, ensures this OSPF instance, sets its router-id
    /// (`--ospf-router-id`, required alongside this), and associates it
    /// with `--routing-table` (`RoutingTableOp::SetOspfInstance`) — for
    /// verifying `nos-watchdogd` dynamically spawns `nos-ospfd` for it.
    #[arg(long)]
    ospf_instance: Option<String>,
    #[arg(long)]
    ospf_router_id: Option<Ipv4Addr>,

    /// If set (requires `--ospf-instance`), ensures this OSPF area under it
    /// (`OspfAreaOp::Ensure`).
    #[arg(long)]
    ospf_area: Option<Ipv4Addr>,
    /// If set (requires `--ospf-area`), ensures this OSPF profile under it
    /// (`OspfProfileOp::Ensure`).
    #[arg(long)]
    ospf_profile: Option<String>,
    /// If set, attaches this profile name to `--interface`'s
    /// `--subinterface-tag` subinterface (`SubinterfaceOp::SetOspfProfile`)
    /// — for verifying `nos-ospfd` logs the attachment.
    #[arg(long)]
    ospf_interface_profile: Option<String>,
    /// If set, attaches this profile name to `--broadcast-domain`'s own SVI
    /// (`BroadcastDomainOp::SetOspfProfile`) — for verifying `nos-ospfd`'s
    /// broadcast-network-type Hello/DR-BDR-election path. Combine with
    /// `--broadcast-domain-svi-address`/`--switching-profile`/
    /// `--switching-profile-member` to build the whole attach point.
    #[arg(long)]
    ospf_broadcast_domain_profile: Option<String>,
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

    let mut ops = vec![ConfigOp::Interface(InterfaceOp::Ensure {
        name: args.interface.clone(),
    })];
    if args.delete_subinterface {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::Delete {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
        }));
    } else {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
            address: args.address,
            label: None,
        }));
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
            routing_table: args.routing_table.clone(),
        }));
    }
    ops.extend([
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
    ]);

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
                policy: args.redistribute_policy.clone(),
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

    if args.loopback_address.is_some() && args.delete_loopback {
        bail!("--loopback-address and --delete-loopback are mutually exclusive");
    }
    let loopback_name = format!("loopback-{}", args.routing_table);
    if let Some(address) = args.loopback_address {
        ops.push(ConfigOp::Interface(InterfaceOp::Ensure {
            name: loopback_name.clone(),
        }));
        ops.push(ConfigOp::Interface(InterfaceOp::AddAddress {
            name: loopback_name.clone(),
            address,
            label: None,
        }));
    }
    if args.delete_loopback {
        ops.push(ConfigOp::Interface(InterfaceOp::Delete {
            name: loopback_name,
        }));
    }

    if args.broadcast_domain_svi_address.is_some() && args.delete_broadcast_domain_svi {
        bail!(
            "--broadcast-domain-svi-address and --delete-broadcast-domain-svi are mutually \
             exclusive"
        );
    }
    if let Some(address) = args.broadcast_domain_svi_address {
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Ensure {
            name: args.broadcast_domain.clone(),
        }));
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::AddAddress {
            name: args.broadcast_domain.clone(),
            address,
            label: None,
        }));
        ops.push(ConfigOp::BroadcastDomain(
            BroadcastDomainOp::SetRoutingTable {
                name: args.broadcast_domain.clone(),
                routing_table: args.routing_table.clone(),
            },
        ));
    }
    if args.delete_broadcast_domain_svi {
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Delete {
            name: args.broadcast_domain.clone(),
        }));
    }

    let source_address_flags = [
        args.source_address_interface.is_some(),
        args.source_address_loopback,
        args.clear_source_address,
    ];
    if source_address_flags.iter().filter(|set| **set).count() > 1 {
        bail!(
            "--source-address-interface, --source-address-loopback, and \
             --clear-source-address are mutually exclusive"
        );
    }
    if let Some(interface) = args.source_address_interface.clone() {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetSourceAddress {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            source: SourceAddress::Interface {
                interface,
                label: args.source_address_label.clone(),
            },
        }));
    } else if args.source_address_loopback {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetSourceAddress {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            source: SourceAddress::Loopback {
                label: args.source_address_label.clone(),
            },
        }));
    } else if args.clear_source_address {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearSourceAddress {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
        }));
    }

    if args.switching_profile.is_some() && args.delete_switching_profile {
        bail!("--switching-profile and --delete-switching-profile are mutually exclusive");
    }
    if let Some(profile) = args.switching_profile.clone() {
        ops.push(ConfigOp::SwitchingProfile(SwitchingProfileOp::Ensure {
            name: profile.clone(),
        }));
        for member in &args.switching_profile_members {
            let (domain, tag) = member.split_once(':').with_context(|| {
                format!("--switching-profile-member {member} must be DOMAIN:TAG")
            })?;
            let tag = if tag.eq_ignore_ascii_case("untagged") {
                VlanTag::Untagged
            } else {
                VlanTag::Dot1q(tag.parse().with_context(|| {
                    format!("invalid vlan tag '{tag}' in --switching-profile-member {member}")
                })?)
            };
            ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Ensure {
                name: domain.to_string(),
            }));
            ops.push(ConfigOp::SwitchingProfile(SwitchingProfileOp::AddMember {
                name: profile.clone(),
                broadcast_domain: domain.to_string(),
                tag,
            }));
        }
        ops.push(ConfigOp::Interface(InterfaceOp::SetSwitchingProfile {
            name: args.interface.clone(),
            switching_profile: profile,
        }));
    } else if !args.switching_profile_members.is_empty() {
        bail!("--switching-profile-member requires --switching-profile to also be set");
    }
    if args.delete_switching_profile {
        ops.push(ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile {
            name: args.interface.clone(),
        }));
    }

    if let Some(name) = args.ospf_instance.clone() {
        let router_id = args
            .ospf_router_id
            .context("--ospf-router-id is required when --ospf-instance is set")?;
        ops.push(ConfigOp::OspfInstance(OspfInstanceOp::Ensure {
            name: name.clone(),
        }));
        ops.push(ConfigOp::OspfInstance(OspfInstanceOp::SetRouterId {
            name: name.clone(),
            router_id,
        }));
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetOspfInstance {
            name: args.routing_table.clone(),
            ospf_instance: name,
        }));
    } else if args.ospf_router_id.is_some() {
        bail!("--ospf-router-id requires --ospf-instance to also be set");
    }

    if let Some(area_id) = args.ospf_area {
        let instance = args
            .ospf_instance
            .clone()
            .context("--ospf-area requires --ospf-instance to also be set")?;
        ops.push(ConfigOp::OspfArea(OspfAreaOp::Ensure {
            instance: instance.clone(),
            area_id,
        }));
        if let Some(name) = args.ospf_profile.clone() {
            ops.push(ConfigOp::OspfProfile(OspfProfileOp::Ensure {
                instance,
                area_id,
                name,
            }));
        }
    } else if args.ospf_profile.is_some() {
        bail!("--ospf-profile requires --ospf-area to also be set");
    }

    if let Some(profile) = args.ospf_interface_profile.clone() {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::SetOspfProfile {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
            ospf_profile: profile,
        }));
    }

    if let Some(profile) = args.ospf_broadcast_domain_profile.clone() {
        ops.push(ConfigOp::BroadcastDomain(
            BroadcastDomainOp::SetOspfProfile {
                name: args.broadcast_domain.clone(),
                ospf_profile: profile,
            },
        ));
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
