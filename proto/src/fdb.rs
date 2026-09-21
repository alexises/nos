//! `nos-fdbd`'s wire protocol: the EVPN route shape it exchanges with
//! `nos-bgpd` in both directions, and its own MAC-table query.
//!
//! `nos-proto` can't depend on `nos-bgp`, so EVPN routes cross the wire in
//! this small structured form rather than as `bgp::evpn::EvpnNlri`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Route identity: what a withdrawal names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvpnKey {
    /// Type-2 MAC advertisement (no IP, ESI 0, Ethernet tag 0).
    Mac { rd: [u8; 8], mac: [u8; 6] },
    /// Type-3 inclusive multicast: `origin` is the advertising VTEP.
    Imet { rd: [u8; 8], origin: IpAddr },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvpnRoute {
    pub key: EvpnKey,
    /// The VXLAN VNI. Always set on a Type-2; on a *received* Type-3 it is 0
    /// (the VNI rides in the PMSI Tunnel attribute, which `nos-bgpd` does not
    /// decode yet — receivers match the domain by Route Target instead).
    pub vni: u32,
    /// The remote VTEP (BGP next-hop).
    pub next_hop: IpAddr,
    /// Raw RFC 4360 extended communities (Route Targets, encapsulation).
    pub ext_communities: Vec<u64>,
}

/// A persistent, long-lived push in either direction (`nos-fdbd` ->
/// `nos-bgpd` local MACs, `nos-bgpd` -> `nos-fdbd` received routes): `Full`
/// on connect, then incremental `Add`/`Remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvpnUpdate {
    Full(Vec<EvpnRoute>),
    Add(EvpnRoute),
    Remove(EvpnKey),
}

/// Messages to one `nos-fdbd` instance's socket. Append-only (postcard).
#[derive(Debug, Serialize, Deserialize)]
pub enum FdbRequest {
    GetMacs,
    /// Fire-and-forget, `nos-bgpd` only: every EVPN route the BGP instance
    /// named by the domain's `redistribute from mac to bgp` received.
    PushEvpnRoutes(EvpnUpdate),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum FdbEvent {
    Table(FdbTable),
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdbTable {
    pub domain: String,
    pub vni: u32,
    /// Bridge and VXLAN device names, once nos-fdbd has resolved/created them.
    pub bridge: Option<String>,
    pub vxlan: Option<String>,
    pub macs: Vec<MacEntry>,
    /// Remote VTEPs BUM traffic is replicated to (one per received Type-3).
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub flood: Vec<IpAddr>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacEntry {
    /// `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    pub source: MacSource,
    /// The remote VTEP for a `Remote` entry.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub vtep: Option<IpAddr>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacSource {
    /// Learned by the bridge on a local port.
    Local,
    /// Learned from an EVPN Type-2 route.
    Remote,
}
