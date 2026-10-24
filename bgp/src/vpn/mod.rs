//! VPN-IPv4/IPv6 (RFC 4364, RFC 4659) wire pieces: the SAFI 128 NLRI codec
//! and the Route Target / Site of Origin extended-community helpers.
//! Import/export logic (`VpnKey`, `VrfSet`) lands here with #578/#579.

mod ext_comm;
mod nlri;

pub use crate::evpn::{format_ext_community, format_rd, Rd};
pub use ext_comm::{is_route_target, route_targets, rt, sites_of_origin};
pub use nlri::{
    decode_next_hop, decode_vpn_reach, decode_vpn_unreach, encode_next_hop, encode_vpn_reach,
    encode_vpn_unreach,
};

use ipnet::IpNet;

/// One labelled VPN route (RFC 4364 section 4.3.4): the label stack, the
/// Route Distinguisher and the customer prefix. `labels` is empty for a
/// withdrawal (RFC 8277 section 2.4: the label field there is a fixed
/// compatibility value, not a label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnNlri {
    pub labels: Vec<u32>,
    pub rd: Rd,
    pub prefix: IpNet,
}
