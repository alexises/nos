//! `nos-fdbd`'s wire protocol: the EVPN route shape it exchanges with
//! `nos-bgpd` in both directions, and its own MAC-table query.
//!
//! `nos-proto` can't depend on `nos-bgp`, so EVPN routes cross the wire in
//! this small structured form rather than as `bgp::evpn::EvpnNlri`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// An Ethernet Segment Identifier; all-zero is "single-homed".
pub use crate::evpn_id::Esi;

/// Route identity: what a withdrawal names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvpnKey {
    /// Type-2 MAC advertisement (no IP, Ethernet tag 0).
    Mac { rd: [u8; 8], mac: [u8; 6] },
    /// Type-3 inclusive multicast: `origin` is the advertising VTEP.
    Imet { rd: [u8; 8], origin: IpAddr },
    /// Type-2 MAC/IP advertisement (Ethernet tag 0). Appended:
    /// postcard indexes variants by position.
    MacIp {
        rd: [u8; 8],
        mac: [u8; 6],
        ip: IpAddr,
    },
    /// Type-4 Ethernet Segment route: `origin` is the advertising PE. Appended
    /// (postcard indexes variants by position).
    EthernetSegment {
        rd: [u8; 8],
        esi: Esi,
        origin: IpAddr,
    },
    /// Type-1 Ethernet Auto-Discovery: per-ES when `tag == AD_TAG_ES`, per-EVI
    /// otherwise (its VNI is `EvpnRoute::vni`). `origin` is the advertising PE
    /// — the BGP next hop on a received route, our VTEP on a local one. It is
    /// *not* on the wire (the NLRI has no originator), so it is only here to
    /// keep two PEs' routes apart. Appended (postcard indexes by position).
    EthernetAd {
        rd: [u8; 8],
        esi: Esi,
        tag: u32,
        origin: IpAddr,
    },
}

/// The Ethernet Tag ID of a per-ES Ethernet A-D route (RFC 7432 §8.2.1,
/// "MAX-ET").
pub const AD_TAG_ES: u32 = 0xFFFF_FFFF;

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
    /// The Ethernet Segment of a Type-2 (all-zero = single-homed). Deliberately
    /// in the value, not the key: a MAC moving onto or off a segment is a
    /// replacement of one route, not a second one. (`bgp` withdraws the old
    /// NLRI itself, since the ESI is part of the wire identity.)
    pub esi: Esi,
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
    /// IP-to-MAC bindings: local ARP/ND and SVI addresses, and remote Type-2
    /// routes carrying an IP.
    pub neighbours: Vec<NeighEntry>,
    /// Remote VTEPs BUM traffic is replicated to (one per received Type-3).
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub flood: Vec<IpAddr>,
    /// The Ethernet Segments this domain is attached to (an aggregate with an
    /// `esi` that is a member of the domain) and this PE's Designated
    /// Forwarder role on each.
    pub segments: Vec<EsEntry>,
    /// Whether ARP/ND suppression (`neigh-suppress`) is in effect on the
    /// VXLAN bridge port: the value nos-fdbd last applied to the kernel,
    /// not merely the configured one.
    pub neigh_suppress: bool,
}

/// One locally attached Ethernet Segment, as seen from one broadcast domain.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsEntry {
    /// `00:11:22:33:44:55:66:77:88:99`.
    pub esi: String,
    /// The bridge port the segment attaches through (the bond or its VLAN
    /// sub-link).
    pub port: String,
    /// Whether this PE is the segment's Designated Forwarder for the domain's
    /// BUM traffic. A non-DF has flooding to `port` turned off.
    pub designated_forwarder: bool,
    /// Every PE attached to the segment (this one included), in the order the
    /// DF election ranks them.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub pes: Vec<IpAddr>,
    /// The PEs whose per-ES Ethernet A-D route for this segment is currently
    /// held (this one excluded): a remote MAC on the segment is only installed
    /// while its PE is listed here.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub ad_pes: Vec<IpAddr>,
    /// Whether the segment's port is up (carrier). A down segment withdraws its
    /// Type-4 and Type-1 routes and stops being a DF candidate.
    pub up: bool,
    /// Single-active redundancy: a non-DF blocks the port outright (unicast
    /// too), instead of only refusing BUM.
    pub single_active: bool,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacEntry {
    /// `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    pub source: MacSource,
    /// The remote VTEP for a `Remote` entry (the first of `vteps`).
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub vtep: Option<IpAddr>,
    /// Every VTEP a `Remote` entry is reached through: one, or several when
    /// the MAC sits on an all-active Ethernet Segment and traffic is balanced
    /// over its PEs (aliasing, RFC 7432 §8.4.1.1). Empty for a `Local` MAC.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub vteps: Vec<IpAddr>,
    /// The Ethernet Segment a `Local` MAC was learned on, when its port is one.
    pub esi: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighEntry {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: IpAddr,
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
