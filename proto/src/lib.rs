// `#[derive(Cli)]` emits `::nos_proto::…` paths, which must resolve here too.
extern crate self as nos_proto;

pub mod bgp;
pub mod broker;
pub mod cli;
pub mod codec;
pub mod config_path;
pub mod derive;
pub mod diff;
pub mod docs;
pub mod evpn_id;
pub mod fdb;
pub mod interface;
pub mod ipc;
pub mod lacp;
pub mod lldp;
pub mod log;
pub mod ops;
pub mod ospf;
pub mod ospfv3;
pub mod paths;
pub mod rib;
pub mod schema;
pub mod validators;

pub use bgp::{
    BgpEvent, BgpRequest, BgpSessionState, EvpnRouteSummary, GrSummary, PeerSummary,
    RedistributeUpdate, RedistributedRoute, RpkiCacheStatus, RpkiSessionState,
};
pub use broker::{Role, ServiceRef, WatchdogEvent, WatchdogRequest, INVALID_CREDENTIALS};
pub use codec::IpcCodec;
pub use derive::sync_routing_table_refs;
pub use diff::{diff_configs, ConfigDiff, DiffScope, DiffStatus, FieldDiff, SectionDiff};
pub use docs::{CommandDoc, Topic};
pub use fdb::{
    EsEntry, EvpnKey, EvpnRoute, EvpnUpdate, FdbEvent, FdbRequest, FdbTable, MacEntry, MacSource,
    NeighEntry,
};
pub use interface::{
    BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus, LacpAggregateMembers,
    PortAggregateStatus, SubinterfaceStatus,
};
pub use ipc::{Event, Request, TransactionBase, TransactionSnapshot};
pub use ipnet::IpNet;
pub use lacp::{
    LacpEvent, LacpMuxState, LacpPortStatus, LacpReceiveState, LacpRequest,
    PortAggregateLacpSummary,
};
pub use lldp::{LldpEvent, LldpLinkStats, LldpNeighbor, LldpRequest};
pub use log::{LogEntry, LogEvent, LogLevel, LogRequest};
pub use ops::{
    AsPathListOp, BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp, BroadcastDomainOp, CommunityAliasOp,
    CommunityGroupOp, ConfigOp, InterfaceOp, LldpOp, LoggingOp, OpError, OspfAreaOp,
    OspfInstanceOp, OspfProfileOp, Ospfv3AreaOp, Ospfv3InstanceOp, Ospfv3ProfileOp,
    PolicyDefinitionOp, PortAggregateOp, PortAggregateSubinterfaceOp, PrefixListOp, RoutingTableOp,
    StaticRouteOp, StaticRoutingInstanceOp, SubinterfaceOp, SwitchingProfileOp, UserOp,
};
pub use ospf::{
    LinkInterfaceState, LsaSummary, NeighborSummary, OspfEvent, OspfNeighborState, OspfRequest,
};
pub use ospfv3::{Ospfv3Event, Ospfv3LsaSummary, Ospfv3NeighborSummary, Ospfv3Request};
pub use paths::{
    DEFAULT_CONFIG_SOCKET, DEFAULT_LOG_SOCKET, DEFAULT_PKI_CA, DEFAULT_PKI_DIR,
    DEFAULT_WATCHDOG_SOCKET,
};
pub use rib::{
    BgpRoute, BgpRouteUpdate, EvpnRouteInfo, OspfRoute, OspfRouteUpdate, PrefixRoutes, RibEvent,
    RibRequest, RouteEntry, RouteSourceKind,
};
pub use schema::{
    loopback_table_name, parse_fingerprint, AddressFamily, AsPathList, BgpAddPath, BgpAggregate,
    BgpAoAlgorithm, BgpAoKey, BgpAuth, BgpConfederation, BgpDamping, BgpGracefulRestart,
    BgpInstance, BgpLocalAs, BgpMaximumPrefix, BgpPeer, BgpPeerGroup, BgpPrefixLimit, BgpShutdown,
    BroadcastDomain, CommunityAlias, CommunityGroup, Config, DfAlgorithm, EsRedundancy, Interface,
    InterfaceAddress, LacpMode, LacpRate, LldpDestination, LldpSettings, LoggingSettings,
    NetworkType, NextHopMode, OspfArea, OspfAreaRange, OspfAreaType, OspfAuth, OspfCryptoAlgorithm,
    OspfCryptoKey, OspfInstance, OspfProfile, Ospfv3Area, Ospfv3Instance, Ospfv3Profile,
    PolicyDefinition, PortAggregate, PortAggregateMode, PrefixList, PrefixListEntry, Redistribute,
    RedistributeSource, RedistributeTarget, RestApi, RoutingTable, RoutingTableEvpn, RpkiCache,
    SourceAddress, StaticRoute, StaticRoutingInstance, Subinterface, SwitchingProfile,
    SwitchingProfileMember, SyslogFacility, SyslogServer, SyslogTls, SyslogTransport, User,
    VlanTag, CONNECT_RETRY_TIME_DEFAULT_SECS, DEAD_INTERVAL_DEFAULT, GR_RESTART_TIME_DEFAULT,
    GR_SELECTION_DEFERRAL_TIME_DEFAULT, GR_STALE_TIME_DEFAULT, HELLO_INTERVAL_DEFAULT,
    HOLD_TIME_DEFAULT, HOLD_TIME_FLOOR, LOOPBACK_PREFIX, PASSWORD_HASH_PREFIX, PRIORITY_DEFAULT,
    REST_API_PORT_DEFAULT, ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS, RPKI_RTR_PORT_DEFAULT,
};
