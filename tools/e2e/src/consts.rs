//! Addresses, ASNs, names and IDs shared by the phases. Every prefix/address
//! comes from an RFC 5737 (IPv4) / RFC 3849 (IPv6) documentation block, with a
//! distinct sub-block per scenario so log lines from different phases are
//! never confusable.

pub const NET: &str = "nos-verify-net";
/// Two extra single-purpose docker networks, connected only to router-a, for
/// `port-aggregate` — bonding needs >=2 real distinct links, which no other
/// scenario's shared eth0 can provide. Docker names interfaces in connection
/// order, so router-a ends up with eth1/eth2.
pub const NET_BOND1: &str = "nos-verify-net-bond1";
pub const NET_BOND2: &str = "nos-verify-net-bond2";
pub const SUBNET: &str = "10.50.0.0/24";
/// A fixed ULA (RFC 4193) block so the docker network itself — and thus each
/// container's eth0 — has IPv6 enabled at the kernel level at all. Never
/// assigned to nos's own config.
pub const SUBNET6: &str = "fd00:10:50::/64";

pub const IP_A: &str = "10.50.0.2";
pub const IP_B: &str = "10.50.0.3";
pub const IP_C: &str = "10.50.0.4";
/// The throwaway router of the `rest` phase's destructive checks.
pub const IP_R: &str = "10.50.0.5";
pub const ASN_A: u32 = 65001;
pub const ASN_B: u32 = 65002;
/// Only `route-server` (router-b and router-c must be in distinct ASes from
/// each other and from router-a) and `ospf-dr`'s router-c use this.
pub const ASN_C: u32 = 65003;
pub const RID_A: &str = "1.1.1.1";
pub const RID_B: &str = "2.2.2.2";
pub const RID_C: &str = "3.3.3.3";

/// TEST-NET-2 — a fake redistributed prefix.
pub const REDISTRIBUTE_PREFIX: &str = "198.51.100.0/24";
pub const REDISTRIBUTE_GATEWAY: &str = "10.50.0.99";
/// TEST-NET-3 — the loopback scenario's address.
pub const LOOPBACK_ADDRESS: &str = "203.0.113.1/32";
/// TEST-NET-1 — the routed-subinterface scenario. The tag is distinct from
/// `switching`'s 100/200 and the ospf broadcast tag (400).
pub const SUBINTERFACE_TAG: u16 = 300;
pub const SUBINTERFACE_ADDRESS: &str = "192.0.2.1/24";
/// router-a's table-id registry starts empty and allocates from 100; `rt1` is
/// the only routing table any scenario configures, so it is always the first
/// and gets id 100 and kernel device name `lo100`.
pub const LOOPBACK_DEVICE: &str = "lo100";
pub const SVI_ADDRESS: &str = "203.0.113.9/32";

pub const OSPF_INSTANCE: &str = "ospf1";
pub const OSPF_ROUTER_ID: &str = "9.9.9.9";
pub const OSPF_ROUTER_ID_B: &str = "9.9.9.10";
/// Deliberately lower than both, so router-b stays DR and router-a Backup
/// (RFC 2328 §9.4 incumbent stickiness) and router-c settles as DrOther.
pub const OSPF_ROUTER_ID_C: &str = "9.9.9.8";
pub const OSPF_AREA: &str = "0.0.0.0";
pub const OSPF_PROFILE: &str = "ospf-profile1";
pub const OSPF_BROADCAST_DOMAIN: &str = "bd-ospf";
pub const OSPF_BROADCAST_TAG: u16 = 400;
pub const OSPF_BROADCAST_ADDRESS_A: &str = "203.0.113.65/28";
pub const OSPF_BROADCAST_ADDRESS_B: &str = "203.0.113.66/28";
pub const OSPF_BROADCAST_ADDRESS_C: &str = "203.0.113.67/28";
/// A destination with no neighbor of its own, on router-b's loopback, so
/// router-a can only learn it through a real SPF computation.
pub const OSPF_SPF_LOOPBACK_ADDRESS: &str = "203.0.113.80/32";
/// `abr`: a fresh prefix in a second area (reusing the same prefix would
/// recompute to the identical next-hop and produce no new "added route").
pub const OSPF_AREA_1: &str = "0.0.0.1";
pub const OSPF_PROFILE_AREA1: &str = "ospf-profile-area1";
pub const OSPF_ABR_LOOPBACK_ADDRESS: &str = "203.0.113.96/32";
/// Scales nos-ospfd's LSA age clock: 1800/180 = 10s, 3600/180 = 20s.
pub const OSPF_AGE_MULTIPLIER: u32 = 180;
pub const ASBR_PREFIX: &str = "192.0.2.128/25";
pub const ASBR_GATEWAY: &str = "10.50.0.98";
pub const MTU_VALUE: u32 = 9000;
/// The RFC 791 minimum: resolves to one header per DBD packet.
pub const OSPF_MTU_VALUE: u32 = 68;

pub const OSPFV3_INSTANCE: &str = "ospfv3-1";
pub const OSPFV3_ROUTER_ID: &str = "9.9.9.9";
pub const OSPFV3_ROUTER_ID_B: &str = "9.9.9.10";
pub const OSPFV3_ROUTER_ID_C: &str = "9.9.9.8";
pub const OSPFV3_AREA: &str = "0.0.0.0";
pub const OSPFV3_PROFILE: &str = "ospfv3-profile1";
pub const OSPFV3_ADDRESS_A: &str = "2001:db8:1::1/64";
pub const OSPFV3_ADDRESS_B: &str = "2001:db8:1::2/64";
pub const OSPFV3_LOOPBACK_ADDRESS: &str = "2001:db8:2::1/128";
pub const OSPFV3_BROADCAST_ADDRESS_A: &str = "2001:db8:3::1/64";
pub const OSPFV3_BROADCAST_ADDRESS_B: &str = "2001:db8:3::2/64";
pub const OSPFV3_BROADCAST_ADDRESS_C: &str = "2001:db8:3::3/64";

/// Distinct from `port-aggregate`'s "bond1" so the two phases' log greps never collide.
pub const LACP_AGGREGATE: &str = "bond-lacp";
pub const NETNS_HELPER_IMAGE: &str = "nos-verify-netns-helper:local";

pub const COMMUNITY_AA: u32 = 65001;
pub const COMMUNITY_NN: u32 = 100;
pub const COMMUNITY_PACKED: u32 = (COMMUNITY_AA << 16) | COMMUNITY_NN;

pub const REST_PORT: u16 = 8080;
/// Not assigned to any interface, so binding it fails with EADDRNOTAVAIL.
pub const REST_ABSENT_ADDRESS: &str = "10.50.0.77";
pub const REST_TX: &str = "rest-e2e";
