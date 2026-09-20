#!/usr/bin/env bash
# End-to-end verification harness for nos-bgpd's session-establishment FSM
# and route redistribution/propagation: stands up two independent
# nos-watchdogd containers ("router-a"/"router-b") on a shared docker
# network, configures each as a full BGP router peering the other, and
# checks the logs for a real OPEN/KEEPALIVE handshake reaching Established,
# a hold-timer/reconnect cycle, (best-effort) a collision-resolution event,
# (via the `redistribute` subcommand) a static route configured on router-a
# actually being redistributed into its bgp instance, advertised over the
# wire, and learned into router-b's Adj-RIB-In/Loc-RIB, (via the `auth`
# subcommand) that matching RFC 2385 TCP MD5 passwords on both routers still
# establish while a mismatched password on either side does not, (via the
# `loopback` subcommand) that a real loopback interface (named
# `loopback-rt1`, detected purely from that name — no separate config field)
# actually gets a real dummy kernel device created (named from its routing
# table's allocated kernel table id), enslaved into that table's VRF, and
# addressed, then deleted again on removal, (via the `mtu` subcommand) that a
# non-default MTU configured directly on an interface (a link-layer
# property, not per-subinterface) actually gets applied to the real kernel
# link by nos-interfaced's Linux driver, (via the `port-aggregate`
# subcommand) that a static (non-LACP, Xor) Linux bonding device actually
# gets created and two real dedicated member interfaces (eth1/eth2, on their
# own docker networks -- bonding needs >=2 real distinct links) actually get
# enslaved into it by nos-interfaced's Linux driver, then torn down again,
# (via the `switching` subcommand)
# that a real L2 switching profile trunking an interface into two broadcast
# domains at two different local dot1q tags actually gets one real Linux
# bridge device created per domain and one real 802.1q sub-interface per
# tagged member, each enslaved into its own domain's bridge, then deleted
# again on removal, (via the `svi` subcommand) that a broadcast domain's own
# address/routing-table config actually addresses its bridge device and
# enslaves it into a VRF -- an SVI (switch virtual interface) -- over a real
# kernel, then clears both and confirms the bridge itself is untouched,
# (via the `routed-subinterface` subcommand) that a real
# L3 routed subinterface (a second, tagged `<interface>.<tag>` VLAN
# sub-interface on the same physical interface eth0 already uses for its
# untagged/tag-0 BGP session address, assigned to the same "rt1" VRF)
# actually gets a real 802.1q VLAN sub-interface created, enslaved into that
# VRF, and addressed, then deleted again on removal, (via the `source-address`
# subcommand) that a peer-group's source-address is resolved by nos-bgpd
# itself, over a real IPC round trip to nos-interfaced, from an interface
# name (+ optional label) rather than a literal address, and that
# `source-address loopback` derives its target interface's name purely from
# the owning bgp instance's own routing table with no routing-table name
# given at all, and (via the `policy` subcommand) that a real RPL import
# policy on router-b
# actually rejects a specific redistributed prefix from router-a — proving
# the policy hook against the kernel-real two-container path, not just unit
# tests — and that reverting to the `accept-all` default lets it back in,
# and (via the `communities` subcommand) that a real RPL export policy on
# router-a can `.add()` an RFC 1997 COMMUNITY value that survives wire
# encoding, the real kernel session, wire decoding, and lands in router-b's
# loc-rib, and (via the `redistribute-policy` subcommand) that a real RPL
# policy attached directly to router-a's `redistribute from static to bgp`
# rule filters a prefix at the redistribution point itself — before it ever
# enters router-a's own loc-rib, and thus before router-b ever sees it —
# distinct from the `policy` subcommand above, which filters at the
# *receiving* peer's import policy after the prefix has already entered the
# advertiser's loc-rib. Reverting to `accept-all` lets it flow through again.
#
# (via the `ospf` subcommand) that declaring a basic OSPF instance (name,
# router-id, routing-table association -- see ospf/CLAUDE.md), a nested
# area/profile, and attaching that profile to both routers' own eth0 tag-0
# subinterface actually gets nos-watchdogd to dynamically spawn a real
# nos-ospfd process for each, which itself resolves its own instance's
# router-id/routing-table over a real IPC round trip to nos-configd, and
# actually exchanges real RFC 2328 Hello packets over a real VRF-scoped raw
# protocol-89 socket between the two containers, reaching neighbor state
# 2-Way on both sides -- and that the same profile, attached a second time to
# each router's own broadcast-domain bridge (a real Linux bridge trunked from
# eth0 via a dot1q sub-interface, reachable over the same docker network),
# reaches 2-Way there too and runs a real RFC 2328 §9.4 DR/BDR election,
# converging deterministically on the higher-router-id side as DR and the
# other as Backup.
#
# Two further subcommands, `reflector` and `route-server`, stand up a third
# container ("router-c") and reconfigure all three into a hub-and-spoke
# topology (router-a is the hub; router-b/router-c are not peered with each
# other) to verify RFC 4456 route reflection and RFC 7947 route-server
# transparency actually work over real sessions, not just in unit tests.
#
# A third, `ospf-dr` (requires `ospf` to have already run), adds router-c
# onto router-a/router-b's own bd-ospf broadcast segment with a deliberately
# lower OSPF router-id, confirming RFC 2328 §9.4's election-stability
# property (router-b stays DR, router-a stays Backup, router-c settles at
# DrOther without disturbing the incumbents) and that a DrOther still forms
# a real Full adjacency with both the DR and the BDR (RFC 2328 §8's positive
# restriction) over real containers.
#
# A fourth, `ospf-spf` (also requires `ospf` to have already run), attaches
# OSPF to router-b's own loopback interface at a distinct subnet -- a
# destination with no neighbor of its own -- confirming router-a's own
# nos-ospfd actually runs a real RFC 2328 §16.1/§16.2 SPF computation over
# its LSDB, derives the correct next-hop purely from the LSDB (never a live
# neighbor table), and pushes the computed route to its own nos-ribd for
# real kernel installation, then withdraws it again on removal.
#
# A fifth, `ospf-aging`, is self-contained (its own router-a/router-b,
# launched with a real --lsa-age-multiplier so RFC 2328 §14's real
# 1800s/3600s timers resolve in seconds), confirming a real age-increment
# timer runs against the LSDB, a self-originated LSA is actually
# reoriginated (bumped sequence number) once its own age crosses
# LSRefreshTime even with unchanged content, and that once its originator
# stops refreshing it (nos-ospfd killed), the receiving router's own held
# copy actually ages out and gets flushed at MaxAge purely on its own local
# clock.
#
# A sixth, `ospf-auth` (requires `ospf` to have already run), configures a
# real RFC 2328 Appendix D.3 / RFC 5709 HMAC-SHA-256 crypto key on
# router-a/router-b's own eth0.0 point-to-point ospf-profile, confirming the
# adjacency reaches/stays Full with matching keys, that a mismatched key on
# either side produces a real logged digest-verification failure and blocks
# any new Full adjacency (real per-packet HMAC verification, not
# simulated), and that reverting to a matching key lets a fresh Full
# adjacency form again.
#
# A seventh, `asbr` (requires `ospf` to have already run), configures a
# static route + "redistribute from static to ospf" on router-a, confirming
# real RFC 2328 ASBR behavior: router-a actually originates a Type-5
# AS-external-LSA for the redistributed prefix, router-b learns and installs
# it into its own LSDB over the real adjacency, and router-b's own SPF
# computes and pushes a real kernel route for it via nos-ribd -- see
# ospf/CLAUDE.md's "ASBR and AS-external-LSA origination".
#
# An eighth, `abr` (requires `ospf-spf` to have already run), reassigns
# router-b's own loopback into a real second OSPF area, making router-b a
# genuine RFC 2328 ABR, confirming real Type-3 Summary-LSA origination and
# translation: router-b actually originates one for its reassigned loopback,
# router-a learns and installs it into its own (backbone-only) LSDB over the
# real adjacency, and router-a's own SPF computes and pushes a real kernel
# route for a prefix that is not in its own area at all -- see
# ospf/CLAUDE.md's "ABR and Summary-LSA origination".
#
# A ninth, `ospf-dbd-pagination`, is self-contained (its own router-a/
# router-b, launched with a real --dbd-max-headers=1 so RFC 2328 §10.8's DBD
# pagination triggers deterministically -- router-a also redistributes a
# static route into ospf, the same provisioning `asbr` uses, purely to give
# it two distinct LSAs already installed before the DBD exchange starts,
# since a single-LSA summary still fits in one chunk even at
# --dbd-max-headers=1), confirming real multi-packet DBD pagination
# actually happens over the wire (at least one "more remaining" chunk
# logged) and that the adjacency still reaches Full correctly despite it --
# see ospf/CLAUDE.md's "Exchange".
#
# A tenth, `ospf-mtu-pagination`, is the same scenario with no
# --dbd-max-headers flag at all, launching its own router-a/router-b and
# instead configuring a real OspfProfile.mtu override (the RFC 791 minimum,
# 68 bytes) on their shared point-to-point profile, confirming the identical
# real multi-packet DBD pagination and Full adjacency, driven purely by
# `exchange::mtu_based_max_headers` resolving that override -- proving the
# real production MTU-driven pagination path, not just the test-only CLI
# override `ospf-dbd-pagination` exercises.
#
# nos-cli's interactive shell (reedline) can't be scripted over a plain
# pipe, so provisioning goes through `nos-provision` (tools/nos-provision) —
# a small standalone tool that speaks nos-configd's IPC protocol directly,
# reusing nos-proto's own types for wire compatibility.
#
# An eleventh, `ospfv3` (RFC 5340, IPv6 OSPF), configures a parallel
# Ospfv3Instance/area/profile on the same eth0.0 attach point (a second,
# independent protocol instance alongside OSPFv2, no conflict), confirming
# the identical real Hello/DBD/LSR/LSU/LSAck exchange reaches 2-Way then
# Full over a real IPv6 raw protocol-89 socket, and that attaching the
# profile to router-a's own loopback (a destination with no neighbor of its
# own) gets router-b's real RFC 5340 SPF computation to derive the correct
# IPv6 next-hop purely from the LSDB's Link-LSAs and push a real kernel
# route via nos-ribd. A twelfth, `ospfv3-dr` (requires `ospfv3` AND
# `ospf-dr` to have already run), attaches the profile a second time to the
# same bd-ospf bridge `ospf-dr` already stood up a third router on,
# confirming the identical real RFC 2328 §9.4 DR/BDR election and §8
# DrOther-to-DR/BDR Full-adjacency restriction hold over the new address
# family too. A thirteenth, `lldp` (IEEE 802.1AB), reuses the `lacp` scenario's
# direct veth pairs (a Linux bridge never forwards LLDP's 01:80:C2:00:00:0E
# address either) and enables `lldp transmit`/`lldp receive` on both routers'
# eth1, confirming nos-lldpd runs a real LLDPDU exchange over a real raw
# AF_PACKET socket and learns the other router's System Name and port id,
# then that tuned timers (tx-interval 5 x tx-hold 3 -> a learned TTL of 15) and
# a Management Address TLV really reach the neighbor, that both routers on the
# customer-bridge destination group still hear each other while a mismatched
# pair never does, then that turning transmit off on one side makes it send a real TTL-0
# shutdown LLDPDU that the other side acts on immediately (not after the 120s
# TTL), that transmit coming back is learned again, and that dropping receive
# restarts the link as transmit-only. A fourteenth, `rest`, pins the REST API
# (nos-restd) to router-a's rt1 on eth0's address and drives it over real HTTP
# from the host: show endpoints, a whole config-tree transaction committed
# through the URLs, the OpenAPI document, retry of an address not on the VRF,
# and the watchdog stopping the process once the table is unpinned.
#
# Usage: tools/verify-e2e.sh {up|established|reconnect|collision|redistribute|auth|loopback|mtu|port-aggregate|lacp|lldp|switching|svi|routed-subinterface|source-address|rest|policy|redistribute-policy|communities|reflector|route-server|ospf|asbr|ospf-dr|ospf-spf|abr|ospf-aging|ospf-auth|ospf-dbd-pagination|ospf-mtu-pagination|ospfv3|ospfv3-dr|logs [n]|down|base|drivers|rpl|ospf-suite|multi|all}
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# A separate target dir from the host's own `target/` — nos-provision must
# be built against bookworm's glibc (matching the runtime image) rather
# than whatever the host toolchain produces, and mixing the two under one
# target dir just thrashes cargo's build cache.
PROVISION_BIN="$REPO/target/docker-verify/release/nos-provision"
IMAGE=nos:local
NET=nos-verify-net
# Two extra single-purpose docker networks, connected only to router-a, for
# the `port-aggregate` scenario -- bonding needs >=2 real distinct links,
# which no other scenario's shared eth0 (already carrying the BGP session's
# own address) can provide. Docker assigns interface names in connection
# order, so router-a ends up with eth1/eth2 alongside its primary eth0.
NET_BOND1=nos-verify-net-bond1
NET_BOND2=nos-verify-net-bond2
SUBNET=10.50.0.0/24
# A fixed ULA (RFC 4193) block for the docker network's own IPv6 subnet --
# see ensure_network's own comment. Never assigned to nos's own config
# directly (every OSPFv3_* address below lives in a distinct block, see
# their own comments) -- this is purely so the network itself, and thus each
# container's eth0, has IPv6 enabled at the kernel level at all.
SUBNET6=fd00:10:50::/64
IP_A=10.50.0.2
IP_B=10.50.0.3
IP_C=10.50.0.4
ASN_A=65001
ASN_B=65002
# Only used by the `route-server` scenario, where router-b and router-c must
# be in distinct ASes from each other (and from router-a) for the topology
# to actually exercise eBGP-to-eBGP relaying rather than iBGP.
ASN_C=65003
RID_A=1.1.1.1
RID_B=2.2.2.2
RID_C=3.3.3.3
# TEST-NET-2 (RFC 5737) — reserved for documentation, safe to use as a
# fake redistributed prefix without colliding with anything real.
REDISTRIBUTE_PREFIX=198.51.100.0/24
REDISTRIBUTE_GATEWAY=10.50.0.99
# TEST-NET-3 (RFC 5737) — used for the loopback scenario's address, a
# separate reserved block from REDISTRIBUTE_PREFIX so the two scenarios'
# log lines are never confusable with each other.
LOOPBACK_ADDRESS=203.0.113.1/32
# TEST-NET-1 (RFC 5737) — used for the routed-subinterface scenario's
# address, a third reserved block distinct from REDISTRIBUTE_PREFIX/
# LOOPBACK_ADDRESS. SUBINTERFACE_TAG is an arbitrary dot1q id distinct from
# the `switching` scenario's own 100/200 (so a run of `all` never confuses
# the two scenarios' log lines with each other, even though each tears its
# own sub-interfaces down before the next phase runs).
SUBINTERFACE_TAG=300
SUBINTERFACE_ADDRESS=192.0.2.1/24
# router-a's table-id registry (`--table-registry-path`, per-container,
# starts empty) allocates ids starting at MIN_TABLE_ID=100 — "rt1" is the
# only routing table any scenario in this script ever configures, so it's
# always the first (and only) table allocated, deterministically getting id
# 100 and kernel device name `lo100` for the loopback scenario below.
LOOPBACK_TABLE_ID=100
LOOPBACK_DEVICE="lo$LOOPBACK_TABLE_ID"
# TEST-NET-3 (RFC 5737) — used for the svi scenario's address, a distinct
# host address within the same block the loopback scenario already uses (the
# differing interface name in each grepped log line keeps the two scenarios'
# lines unambiguous even so).
SVI_ADDRESS=203.0.113.9/32
# Arbitrary name/router-id for the ospf scenario's OspfInstance -- distinct
# from OSPF_INSTANCE's own asn/router-id concepts, since it names a
# different section entirely. Both routers use the same OSPF_INSTANCE name
# (each is its own container/config, so that's not a conflict) but distinct
# OSPF router-ids, needed to identify each other in Hello packets.
OSPF_INSTANCE=ospf1
OSPF_ROUTER_ID=9.9.9.9
OSPF_ROUTER_ID_B=9.9.9.10
# The ospf scenario's area/profile -- 0.0.0.0 (the backbone) is the obvious
# choice for a single-area test, and the profile is attached to eth0's own
# tag-0 subinterface (the same one already carrying the BGP session's
# address and rt1 routing-table association).
OSPF_AREA=0.0.0.0
OSPF_PROFILE=ospf-profile1
# The ospf scenario's broadcast-domain (multi-access) link -- reuses
# $OSPF_PROFILE as-is (network-type is derived per attach-point kind when
# left unset, so the same profile runs point-to-point on eth0.0 and
# broadcast on this domain simultaneously). Dot1q tag 400 is distinct from
# switching's 100/200 and routed-subinterface's $SUBINTERFACE_TAG (300).
# 203.0.113.64/28 is a fresh sub-block of the loopback/svi scenarios' own
# 203.0.113.0/24 (TEST-NET-3), clear of their .1/.9 host addresses, wide
# enough for both routers' own host address on the shared segment.
OSPF_BROADCAST_DOMAIN=bd-ospf
OSPF_BROADCAST_TAG=400
OSPF_BROADCAST_ADDRESS_A=203.0.113.65/28
OSPF_BROADCAST_ADDRESS_B=203.0.113.66/28
# The `ospf-dr` scenario's third router on the same broadcast segment.
# Deliberately lower than both $OSPF_ROUTER_ID (router-a, 9.9.9.9) and
# $OSPF_ROUTER_ID_B (router-b, 9.9.9.10) so the election's expected outcome
# is deterministic: router-b stays DR, router-a stays Backup (RFC 2328
# §9.4's incumbent-stickiness — a lower-router-id newcomer never displaces
# an already-elected DR/BDR), and router-c becomes DrOther.
OSPF_ROUTER_ID_C=9.9.9.8
OSPF_BROADCAST_ADDRESS_C=203.0.113.67/28
# The `ospf-spf` scenario's own stub-network destination -- a fourth host
# address in the same TEST-NET-3 (RFC 5737) block already used by
# loopback/svi/ospf-broadcast, distinct from every one of them (.1/.9/
# .64-.79), attached to router-b's own loopback interface so router-a must
# learn it purely via a real RFC 2328 §16 SPF computation, never a
# directly-connected address.
OSPF_SPF_LOOPBACK_ADDRESS=203.0.113.80/32
# The `abr` scenario's own second OSPF area/profile and its destination
# prefix -- reassigns router-b's own loopback (see OSPF_SPF_LOOPBACK_ADDRESS
# above, from the `ospf-spf` scenario) from the backbone into a real second
# area, making router-b a genuine RFC 2328 ABR (attached to areas
# $OSPF_AREA and $OSPF_AREA_1 at once, purely as derived from live LSDB
# state -- see ospf/CLAUDE.md's "ABR and Summary-LSA origination"), while
# router-a stays in $OSPF_AREA only. A distinct address (a fifth host in the
# same TEST-NET-3 block already used by loopback/svi/ospf-broadcast/ospf-spf)
# is required, not just a re-profiled loopback at the same address --
# nos-ribd/rib_push_client diffs by (prefix, next-hop), and reusing the exact
# same prefix would recompute to the identical next-hop (still router-b's
# own eth0.0 address), producing no new "added route" kernel event to assert
# on at all.
OSPF_AREA_1=0.0.0.1
OSPF_PROFILE_AREA1=ospf-profile-area1
OSPF_ABR_LOOPBACK_ADDRESS=203.0.113.96/32
# The `ospf-aging` scenario's --lsa-age-multiplier: scales nos-ospfd's
# per-second LSA-age-clock so RFC 2328 §14's real 1800s (LSRefreshTime) /
# 3600s (MaxAge) timers resolve in CI-friendly seconds instead of tens of
# minutes -- 1800/180=10s, 3600/180=20s.
OSPF_AGE_MULTIPLIER=180
# The `asbr` scenario's own redistribute-into-ospf static route: a distinct
# sub-block of TEST-NET-1 (RFC 5737) from routed-subinterface's own
# 192.0.2.1/24 subinterface address, so the two scenarios' log lines are
# never confusable. ASBR_GATEWAY is on-link within the shared docker network
# (10.50.0.0/24), same convention as REDISTRIBUTE_GATEWAY, so the kernel
# accepts installing the resulting route even though nothing listens there.
ASBR_PREFIX=192.0.2.128/25
ASBR_GATEWAY=10.50.0.98
# The `mtu` scenario's own non-default MTU for router-a's eth0 -- comfortably
# above Ethernet's 1500-byte default (and below this docker network's own
# link MTU) so a successful kernel apply is unambiguous.
MTU_VALUE=9000
# The `ospf-mtu-pagination` scenario's own OspfProfile.mtu override -- the
# RFC 791 IPv4 minimum (68), which `exchange::mtu_based_max_headers` resolves
# to a budget of exactly 1 header per DBD packet (same effective value the
# `ospf-dbd-pagination` scenario forces via --dbd-max-headers=1), purely from
# this config override, with no --dbd-max-headers CLI flag involved.
OSPF_MTU_VALUE=68

# --- OSPFv3 (RFC 5340) scenario variables ---
#
# Every address below lives in RFC 3849's documentation block (2001:db8::/32)
# -- distinct sub-prefixes per attach point, mirroring how the OSPFv2
# scenarios above each get their own TEST-NET-{1,2,3} sub-block, and all of
# them distinct from $SUBNET6 (the docker network's own IPv6 subnet, never
# itself assigned to nos's config).
OSPFV3_INSTANCE=ospfv3-1
OSPFV3_ROUTER_ID=9.9.9.9
OSPFV3_ROUTER_ID_B=9.9.9.10
# Same area/profile-naming convention as $OSPF_AREA/$OSPF_PROFILE, on eth0's
# own tag-0 subinterface -- the same attach point already carrying
# $OSPF_PROFILE (OSPFv2) and the BGP session's own IPv4 address; a
# BgpInstance/OspfInstance/Ospfv3Instance can all reference the same
# routing-table/attach-point simultaneously, no conflict.
OSPFV3_AREA=0.0.0.0
OSPFV3_PROFILE=ospfv3-profile1
OSPFV3_ADDRESS_A=2001:db8:1::1/64
OSPFV3_ADDRESS_B=2001:db8:1::2/64
# router-a's loopback prefix -- OSPFv3 only ever advertises IPv6 prefixes,
# so this is a second (IPv6) address on the same loopback-rt1 interface the
# OSPFv2 `loopback` scenario already may have created (a distinct address
# family, never colliding with $LOOPBACK_ADDRESS). A destination with no
# neighbor of its own, so router-b can only ever learn it via a real RFC
# 5340 SPF computation, never a directly-connected address.
OSPFV3_LOOPBACK_ADDRESS=2001:db8:2::1/128
# The `ospfv3-dr` scenario's own broadcast-link addresses -- reuses the OSPFv2
# `ospf`/`ospf-dr` scenarios' own bd-ospf bridge/switching-profile (a
# BroadcastDomain carries independent `ospf_profile`/`ospfv3_profile`
# fields, so both protocols run over the same real Linux bridge with no
# conflict) rather than building a second one.
OSPFV3_BROADCAST_ADDRESS_A=2001:db8:3::1/64
OSPFV3_BROADCAST_ADDRESS_B=2001:db8:3::2/64
OSPFV3_BROADCAST_ADDRESS_C=2001:db8:3::3/64
# Deliberately lower than both $OSPFV3_ROUTER_ID/$OSPFV3_ROUTER_ID_B, same
# incumbent-stickiness rationale as $OSPF_ROUTER_ID_C.
OSPFV3_ROUTER_ID_C=9.9.9.8

# The `lacp` scenario's own port-aggregate name -- deliberately distinct
# from the `port-aggregate` scenario's own "bond1" so the two phases' log
# greps never collide when both run in the same `all`/`drivers` sequence,
# even though they're otherwise structurally independent (different
# Interface.port_aggregate targets, no shared kernel state). Reuses the
# same NET_BOND1/NET_BOND2 networks/eth1+eth2 member interfaces as
# `port-aggregate`, but connects both to *both* routers (real LACP needs a
# real partner negotiating on both ends, unlike static Xor).
LACP_AGGREGATE=bond-lacp

log() { echo "[verify-e2e] $*" >&2; }

build_provision_tool() {
  log "building nos-provision (bookworm-glibc-compatible, matching the runtime image)"
  docker run --rm \
    -v "$REPO:$REPO:z" \
    -w "$REPO" \
    rust:1-slim-bookworm \
    cargo build --release -p nos-provision --target-dir target/docker-verify
}

build_image() {
  log "building $IMAGE"
  (cd "$REPO" && make docker-build)
}

ensure_network() {
  if ! docker network inspect "$NET" >/dev/null 2>&1; then
    log "creating network $NET ($SUBNET, $SUBNET6)"
    # --ipv6 + a fixed ULA subnet: needed even for the ospfv3/ospfv3-dr
    # phases' point-to-point link alone -- Docker disables IPv6 entirely on
    # a container's veth (net.ipv6.conf.eth0.disable_ipv6=1) unless the
    # network itself was created dual-stack, which would also kill
    # nos-ospfv3d's link-local-multicast (FF02::5) Hello exchange, not just
    # routed/ULA traffic. This can fail if the Docker daemon itself wasn't
    # started with IPv6 support (see /etc/docker/daemon.json's
    # "ipv6"/"fixed-cidr-v6" -- a fresh host/CI runner may need this set
    # once) -- an external prerequisite this script can't itself fix, so on
    # failure it falls back to the original IPv4-only network rather than
    # aborting every phase over it: every non-ospfv3 phase (including the
    # existing base/drivers/rpl/multi CI matrix jobs) never touches IPv6 at
    # all and must keep working on a host without it: only ospfv3/ospfv3-dr
    # actually need $SUBNET6, and they'll fail clearly (containers with no
    # IPv6 configured) rather than mysteriously if it's missing.
    if ! docker network create --subnet "$SUBNET" --ipv6 --subnet "$SUBNET6" "$NET" >/dev/null 2>&1; then
      log "warning: dual-stack network create failed (Docker daemon may lack IPv6 support) -- falling back to IPv4-only; ospfv3/ospfv3-dr will not work on this host"
      docker network create --subnet "$SUBNET" "$NET" >/dev/null
    fi
  fi
}

# cmd_up/cmd_up_reflector/cmd_up_route_server each need the image/provision
# tool/network ready -- guarded so a run that calls more than one of them
# (e.g. `all`) doesn't rebuild nos-provision (no persisted CARGO_HOME, so a
# repeat call pays real container-startup/registry overhead for nothing)
# three times over.
ENV_READY=0
ensure_env_up() {
  [[ "$ENV_READY" -eq 1 ]] && return 0
  build_image
  build_provision_tool
  ensure_network
  ENV_READY=1
}

start_router() {
  local name=$1 ip=$2
  shift 2
  log "starting $name at $ip"
  docker volume create "${name}-run" >/dev/null
  docker volume create "${name}-data" >/dev/null
  docker rm -f "$name" >/dev/null 2>&1 || true
  # The hard memory cap keeps a runaway daemon (a logging hot loop once grew
  # nos-logd to ~14 GB) from taking down the host instead of just its own
  # container.
  # "$@" (any remaining args) is forwarded to nos-watchdogd -- e.g.
  # `ospf-aging`'s `--ospfd-arg --lsa-age-multiplier=...`. Every other call
  # site passes none, so this is backward-compatible.
  docker run -d --name "$name" \
    --network "$NET" --ip "$ip" \
    --memory 2g --memory-swap 2g \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
    -v "${name}-run:/run/nos" \
    -v "${name}-data:/var/lib/nos" \
    "$IMAGE" "$@" >/dev/null
}

wait_for_config_socket() {
  local name=$1
  log "waiting for $name's nos-configd socket"
  for _ in $(seq 1 60); do
    if docker run --rm --entrypoint /bin/sh -v "${name}-run:/run/nos" "$IMAGE" \
        -c 'test -S /run/nos/config.sock'; then
      return 0
    fi
    sleep 1
  done
  log "timed out waiting for $name's config socket"
  return 1
}

provision() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name (asn=$asn router-id=$router_id peer=$peer_ip)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip"
}

provision_redistribute() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with a static route + 'redistribute from static to bgp'"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --static-route "$REDISTRIBUTE_PREFIX" \
    --static-gateway "$REDISTRIBUTE_GATEWAY" \
    --redistribute
}

provision_auth() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 password=$6
  log "provisioning $name with md5-password (peer=$peer_ip)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --md5-password "$password"
}

# --- Loopback interface scenario ---
#
# Adds a loopback interface (`loopback-rt1`, per nos_proto::LOOPBACK_PREFIX
# — the naming convention alone marks it as a loopback) to router-a's
# already-established "rt1" routing table, verifying nos-interfaced's Linux
# driver actually creates a real dummy kernel device named from rt1's
# allocated table id (`lo100`), enslaves it into the table's VRF, and
# applies the configured address — over a real kernel, not a unit test.
# Then removes it and confirms the device is deleted again.

provision_loopback() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 loopback_addr=$6
  log "provisioning $name with a loopback interface (address=$loopback_addr)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --loopback-address "$loopback_addr"
}

provision_source_address_interface() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name's peer-group source-address as interface eth0"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --source-address-interface eth0
}

provision_source_address_loopback() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name's peer-group source-address as loopback (no routing-table name given)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --source-address-loopback
}

provision_clear_source_address() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "clearing $name's peer-group source-address"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --clear-source-address
}

provision_delete_loopback() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with its loopback interface removed"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --delete-loopback
}

# --- Interface MTU scenario ---
#
# Configures a non-default MTU directly on router-a's own eth0 interface
# (InterfaceOp::SetMtu -- a link-layer property, not per-subinterface, see
# proto/CLAUDE.md), verifying nos-interfaced's Linux driver actually applies
# it to the real kernel link.

provision_mtu() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 mtu=$6
  log "provisioning $name's eth0 with mtu=$mtu"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --mtu "$mtu"
}

# --- Port aggregate scenario ---
#
# Configures a static (non-LACP, Xor) Linux bonding device ("bond1") on
# router-a and enslaves two dedicated member links (eth1/eth2 -- see
# NET_BOND1/NET_BOND2 above) into it, verifying nos-interfaced's Linux
# driver actually creates a real kernel bond device and enslaves both real
# member interfaces into it -- over a real kernel, not a unit test -- then
# deletes the aggregate and confirms the bond device (and both members'
# enslavement) is torn down again.

ensure_bond_networks() {
  docker network inspect "$NET_BOND1" >/dev/null 2>&1 || docker network create "$NET_BOND1" >/dev/null
  docker network inspect "$NET_BOND2" >/dev/null 2>&1 || docker network create "$NET_BOND2" >/dev/null
}

provision_port_aggregate() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  ensure_bond_networks
  docker network connect "$NET_BOND1" "$name" 2>/dev/null || true
  docker network connect "$NET_BOND2" "$name" 2>/dev/null || true
  log "provisioning $name with a static (xor) port aggregate bond1 over eth1+eth2"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --port-aggregate bond1 \
    --enslave-interface-into-port-aggregate eth1 \
    --enslave-interface-into-port-aggregate eth2
}

provision_delete_port_aggregate() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with its port aggregate bond1 removed"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --port-aggregate bond1 \
    --enslave-interface-into-port-aggregate eth1 \
    --enslave-interface-into-port-aggregate eth2 \
    --delete-port-aggregate
}

# --- LACP scenario ---
#
# Configures a real IEEE 802.1AX LACP-mode Linux bonding device
# ("bond-lacp") on *both* routers over two dedicated member links (eth1/eth2),
# verifying nos-lacpd runs a real LACPDU exchange over a real raw AF_PACKET
# socket between the two containers, converges its Receive/Mux state machines
# to `Distributing` on both ends, and pushes the negotiated active-member set
# to nos-interfaced, which actually enslaves both real member interfaces into
# the kernel bond device -- over a real kernel, not a unit test. Then severs
# one member link for real and confirms nos-lacpd detects the loss and
# nos-interfaced releases it from the bond, before tearing the aggregate down.
#
# The two links are direct veth pairs between the two containers' network
# namespaces, NOT docker networks (unlike the static `port-aggregate`
# scenario's NET_BOND1/NET_BOND2): a docker network is a Linux bridge, and a
# Linux bridge never forwards the 01:80:C2:00:00:02 slow-protocols address
# (the kernel refuses to enable it -- it's in the restricted link-local group
# range), so no LACPDU could ever cross one. A veth pair is a plain L2 wire.
# Creating one across two containers needs iproute2 and CAP_NET_ADMIN, which
# the runtime image deliberately lacks, so a throwaway privileged helper
# container does it (see ensure_netns_helper).

NETNS_HELPER_IMAGE=nos-verify-netns-helper:local

ensure_netns_helper() {
  docker image inspect "$NETNS_HELPER_IMAGE" >/dev/null 2>&1 && return 0
  log "building $NETNS_HELPER_IMAGE (debian + iproute2)"
  docker build -q -t "$NETNS_HELPER_IMAGE" - >/dev/null <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
DOCKERFILE
}

# Runs `ip ...` inside container $1's network namespace.
ip_in() {
  local container=$1
  shift
  docker run --rm --privileged --net="container:$container" "$NETNS_HELPER_IMAGE" ip "$@"
}

lacp_link_veths() {
  ensure_netns_helper
  # The `port-aggregate` scenario leaves both routers attached to its
  # NET_BOND1/NET_BOND2 docker networks, whose eth1/eth2 would otherwise be
  # reused below in place of a veth -- and no LACPDU/LLDPDU can cross a docker
  # bridge. Detach them first (a no-op when that scenario never ran), so the
  # `lacp` and `lldp` scenarios get a real wire whatever ran before them.
  local router net
  for router in router-a router-b; do
    for net in "$NET_BOND1" "$NET_BOND2"; do
      docker network disconnect "$net" "$router" >/dev/null 2>&1 || true
    done
  done
  local pid_a pid_b iface
  pid_a=$(docker inspect -f '{{.State.Pid}}' router-a)
  pid_b=$(docker inspect -f '{{.State.Pid}}' router-b)
  for iface in eth1 eth2; do
    if ip_in router-a link show "$iface" >/dev/null 2>&1; then
      continue
    fi
    log "creating veth pair $iface between router-a and router-b"
    docker run --rm --privileged --pid=host "$NETNS_HELPER_IMAGE" \
      ip link add "$iface" netns "$pid_a" type veth peer name "$iface" netns "$pid_b"
  done
}

# Deleting one end of a veth pair deletes both.
lacp_unlink_veths() {
  ip_in router-a link del eth1 2>/dev/null || true
  ip_in router-a link del eth2 2>/dev/null || true
}

provision_lacp() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with a real lacp port aggregate $LACP_AGGREGATE over eth1+eth2"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --port-aggregate "$LACP_AGGREGATE" \
    --port-aggregate-mode lacp \
    --lacp-rate fast \
    --enslave-interface-into-port-aggregate eth1 \
    --enslave-interface-into-port-aggregate eth2
}

provision_delete_lacp() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with its lacp port aggregate $LACP_AGGREGATE removed"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --port-aggregate "$LACP_AGGREGATE" \
    --port-aggregate-mode lacp \
    --enslave-interface-into-port-aggregate eth1 \
    --enslave-interface-into-port-aggregate eth2 \
    --delete-port-aggregate
}

# Withdraws one member (eth2) from $1's aggregate by config, leaving the rest
# in place -- so that router's nos-lacpd stops speaking LACP on it while the
# link itself stays up. (Taking the link down instead wouldn't hold: each
# nos-interfaced re-applies "admin up" on every 10s resync.)
provision_lacp_withdraw_eth2() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with eth2 withdrawn from $LACP_AGGREGATE"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --port-aggregate "$LACP_AGGREGATE" \
    --port-aggregate-mode lacp \
    --enslave-interface-into-port-aggregate eth1 \
    --clear-port-aggregate-member eth2
}

# --- OSPF instance scenario ---
#
# Declares an OSPF instance on a router and associates it with the same
# "rt1" routing table its BGP instance already owns, attaching its profile
# to that router's own eth0 tag-0 subinterface -- the same one already
# carrying the BGP session's own address -- verifying nos-watchdogd actually
# spawns a real nos-ospfd process for it, that process resolves its own
# instance's router-id/routing-table over a real IPC round trip to
# nos-configd, and (when called for both routers, see cmd_check_ospf) that a
# real RFC 2328 Hello exchange over a real VRF-scoped raw protocol-89 socket
# reaches neighbor state 2-Way -- over real containers, not a unit test.

provision_ospf() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 ospf_instance=$6 ospf_router_id=$7
  log "provisioning $name with ospf instance $ospf_instance (router-id=$ospf_router_id)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospf-instance "$ospf_instance" \
    --ospf-router-id "$ospf_router_id" \
    --ospf-area "$OSPF_AREA" \
    --ospf-profile "$OSPF_PROFILE" \
    --ospf-interface-profile "$OSPF_PROFILE"
}

# Same as `provision_ospf`, but also sets a real OspfProfile.mtu override
# ($OSPF_MTU_VALUE) -- for the `ospf-mtu-pagination` scenario, verifying real
# MTU-driven DBD pagination with no --dbd-max-headers CLI flag involved.
provision_ospf_mtu() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 ospf_instance=$6 ospf_router_id=$7
  log "provisioning $name with ospf instance $ospf_instance and profile mtu=$OSPF_MTU_VALUE"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospf-instance "$ospf_instance" \
    --ospf-router-id "$ospf_router_id" \
    --ospf-area "$OSPF_AREA" \
    --ospf-profile "$OSPF_PROFILE" \
    --ospf-interface-profile "$OSPF_PROFILE" \
    --ospf-profile-mtu "$OSPF_MTU_VALUE"
}

# --- ASBR / AS-external-LSA scenario ---
#
# Configures a static route + "redistribute from static to ospf" on
# router-a (the ASBR) -- requires `provision_ospf`/`cmd_check_ospf` to have
# already run for both routers, since this reuses their existing ospf
# instance/area/profile. Verifies real RFC 2328 ASBR behavior: router-a
# actually originates a Type-5 AS-external-LSA for $ASBR_PREFIX, router-b
# learns and installs it into its own LSDB over the real adjacency, and
# router-b's own SPF computes and pushes a real kernel route for it via
# nos-ribd -- see ospf/CLAUDE.md's "ASBR and AS-external-LSA origination".
#
# NOTE: `RoutingTableOp::SetRedistribute` stores only one `Redistribute` rule
# per table, and this script's own rt1 is the only routing table any
# scenario configures -- so provisioning this overwrites rt1's earlier
# "redistribute from static to bgp" rule (from `provision_redistribute`) with
# "from static to ospf". This is why `cmd_check_asbr` runs late in the `all`
# sequence, after every bgp-redistribution-dependent check (`redistribute`/
# `policy`/`redistribute-policy`/`communities`) has already completed.
provision_asbr() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 ospf_instance=$6 ospf_router_id=$7
  log "provisioning $name with a static route + 'redistribute from static to ospf' (real asbr)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospf-instance "$ospf_instance" \
    --ospf-router-id "$ospf_router_id" \
    --ospf-area "$OSPF_AREA" \
    --ospf-profile "$OSPF_PROFILE" \
    --ospf-interface-profile "$OSPF_PROFILE" \
    --static-route "$ASBR_PREFIX" \
    --static-gateway "$ASBR_GATEWAY" \
    --redistribute-to-ospf
}

# Same as `provision_asbr`, but also sets a real OspfProfile.mtu override
# ($OSPF_MTU_VALUE) -- for the `ospf-mtu-pagination` scenario, giving
# router-a two distinct LSAs (its own Router-LSA plus a self-originated
# Type-5) the same way `provision_asbr` does for the flag-based
# `ospf-dbd-pagination` scenario, purely to guarantee a real second DBD round
# (a single-LSA summary would still fit in one chunk even at max_headers=1).
provision_asbr_mtu() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 ospf_instance=$6 ospf_router_id=$7
  log "provisioning $name with a static route + 'redistribute from static to ospf' and profile mtu=$OSPF_MTU_VALUE"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospf-instance "$ospf_instance" \
    --ospf-router-id "$ospf_router_id" \
    --ospf-area "$OSPF_AREA" \
    --ospf-profile "$OSPF_PROFILE" \
    --ospf-interface-profile "$OSPF_PROFILE" \
    --ospf-profile-mtu "$OSPF_MTU_VALUE" \
    --static-route "$ASBR_PREFIX" \
    --static-gateway "$ASBR_GATEWAY" \
    --redistribute-to-ospf
}

# Same as `provision_ospf`, but also sets a single RFC 2328 Appendix D.3 /
# RFC 5709 crypto key ($crypto_key_spec, "<key-id>:<algorithm>:<key>") on
# $OSPF_PROFILE -- for verifying OSPF session authentication end to end
# (matching keys on both routers stay/reach full; a mismatched one on
# either side does not). Requires `provision_ospf`/`cmd_check_ospf` to have
# already committed $OSPF_PROFILE for $name.
provision_ospf_auth() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 ospf_instance=$6 ospf_router_id=$7 crypto_key_spec=$8
  log "provisioning $name with an ospf crypto key on $OSPF_PROFILE ($crypto_key_spec)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospf-instance "$ospf_instance" \
    --ospf-router-id "$ospf_router_id" \
    --ospf-area "$OSPF_AREA" \
    --ospf-profile "$OSPF_PROFILE" \
    --ospf-interface-profile "$OSPF_PROFILE" \
    --ospf-crypto-key "$crypto_key_spec"
}

# Same as `provision_ospf`, but never attaches the profile to eth0's own
# tag-0 subinterface (no `--ospf-interface-profile`) -- for the `ospf-dr`
# scenario's router-c, which shares router-a/router-b's docker network (and
# thus eth0's own broadcast domain) but must not run a second, unwanted
# point-to-point OSPF adjacency there: router-a/router-b's eth0.0 Hellos
# would otherwise reach router-c's eth0.0 socket too (raw sockets have no
# per-peer demux -- see socket.rs's own doc comment on this exact class of
# bug), and a point-to-point link was never designed to track more than one
# neighbor. router-c only ever joins OSPF via the broadcast-domain bridge,
# provisioned separately by `provision_ospf_broadcast`.
provision_ospf_instance_only() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 ospf_instance=$6 ospf_router_id=$7
  log "provisioning $name with ospf instance $ospf_instance (router-id=$ospf_router_id), no point-to-point attach point"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospf-instance "$ospf_instance" \
    --ospf-router-id "$ospf_router_id" \
    --ospf-area "$OSPF_AREA" \
    --ospf-profile "$OSPF_PROFILE"
}

# Attaches $OSPF_PROFILE to a second, multi-access link too: trunks eth0
# (via a dedicated switching profile, dot1q $OSPF_BROADCAST_TAG -- distinct
# from eth0.0's own untagged BGP/point-to-point-OSPF address, so it never
# conflicts) into a broadcast domain, addresses that domain's own bridge
# (an SVI) with a real host address on a shared subnet, and points the
# domain's ospf field at $OSPF_PROFILE (`BroadcastDomainOp::SetOspfProfile`)
# -- verifying nos-ospfd's network-type-Broadcast path: real RFC 2328 §9.4
# DR/BDR election over the same raw protocol-89 socket mechanism the
# point-to-point link above already proved, this time with multiple
# neighbors and an elected DR. Requires `provision_ospf` to have already
# committed $OSPF_PROFILE for this router.
provision_ospf_broadcast() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 svi_addr=$6
  log "provisioning $name with an ospf broadcast-domain link ($OSPF_BROADCAST_DOMAIN, dot1q $OSPF_BROADCAST_TAG, address=$svi_addr)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --routing-table rt1 \
    --switching-profile sp-ospf \
    --switching-profile-member "$OSPF_BROADCAST_DOMAIN:$OSPF_BROADCAST_TAG" \
    --broadcast-domain "$OSPF_BROADCAST_DOMAIN" \
    --broadcast-domain-svi-address "$svi_addr" \
    --ospf-broadcast-domain-profile "$OSPF_PROFILE"
}

# Ensures a loopback interface for $name (same `loopback-<table>` naming
# convention as `provision_loopback`) and attaches $OSPF_PROFILE to it
# (`InterfaceOp::SetOspfProfile`) -- a destination with no neighbor of its
# own, exercising RFC 2328 §16.2's stub-network leaf processing. Requires
# `provision_ospf`/`cmd_check_ospf` to have already committed $OSPF_PROFILE
# for $name.
provision_ospf_loopback() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 loopback_addr=$6
  log "provisioning $name with a loopback interface joined to ospf (address=$loopback_addr, profile=$OSPF_PROFILE)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --loopback-address "$loopback_addr" \
    --ospf-loopback-profile "$OSPF_PROFILE"
}

# Clears $name's loopback ospf-profile attachment (keeps the loopback
# interface/address itself in place).
provision_clear_ospf_loopback() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "clearing $name's loopback ospf-profile attachment"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --clear-ospf-loopback-profile
}

# --- OSPFv3 (RFC 5340) scenario ---
#
# Mirrors the OSPFv2 `ospf`/`ospf-dr` provisioning functions above, over the
# same eth0.0 point-to-point attach point (already carrying the BGP
# session's own IPv4 address and, if `ospf` has already run, $OSPF_PROFILE
# too -- a second, independent protocol instance on the same subinterface,
# no conflict) plus $own_ip6 as a second (IPv6) address on it.
provision_ospfv3() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 own_ip6=$6 ospfv3_instance=$7 ospfv3_router_id=$8
  log "provisioning $name with ospfv3 instance $ospfv3_instance (router-id=$ospfv3_router_id, address=$own_ip6)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospfv3-address "$own_ip6" \
    --ospfv3-instance "$ospfv3_instance" \
    --ospfv3-router-id "$ospfv3_router_id" \
    --ospfv3-area "$OSPFV3_AREA" \
    --ospfv3-profile "$OSPFV3_PROFILE" \
    --ospfv3-interface-profile "$OSPFV3_PROFILE"
}

# Ensures router-a's loopback interface and attaches $OSPFV3_PROFILE to it
# (a second, IPv6 address on the same `loopback-rt1` interface the OSPFv2
# `loopback` scenario may already have created) -- a destination with no
# neighbor of its own, exercising real RFC 5340 SPF next-hop/prefix
# derivation purely from the LSDB. Requires `provision_ospfv3` to have
# already committed $OSPFV3_PROFILE for $name.
provision_ospfv3_loopback() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 loopback_addr6=$6
  log "provisioning $name with a loopback interface joined to ospfv3 (address=$loopback_addr6, profile=$OSPFV3_PROFILE)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospfv3-loopback-address "$loopback_addr6" \
    --ospfv3-loopback-profile "$OSPFV3_PROFILE"
}

# Same as `provision_ospfv3`, but never attaches the profile to eth0's own
# tag-0 subinterface -- for the `ospfv3-dr` scenario's router-c, mirroring
# `provision_ospf_instance_only`'s exact rationale (raw sockets have no
# per-peer demux, so a second unwanted point-to-point adjacency on eth0.0
# would otherwise form between router-c and router-a/router-b).
provision_ospfv3_instance_only() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 ospfv3_instance=$6 ospfv3_router_id=$7
  log "provisioning $name with ospfv3 instance $ospfv3_instance (router-id=$ospfv3_router_id), no point-to-point attach point"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospfv3-instance "$ospfv3_instance" \
    --ospfv3-router-id "$ospfv3_router_id" \
    --ospfv3-area "$OSPFV3_AREA" \
    --ospfv3-profile "$OSPFV3_PROFILE"
}

# Attaches $OSPFV3_PROFILE to the OSPFv2 `ospf`/`ospf-dr` scenarios' own
# bd-ospf bridge too (a second, independent protocol on the same real Linux
# bridge -- see this section's own doc comment) -- a second (IPv6) address
# on the same SVI `provision_ospf_broadcast` already addresses. Requires
# `provision_ospf_broadcast` to have already trunked $name's eth0 into
# $OSPF_BROADCAST_DOMAIN, and `provision_ospfv3` to have committed
# $OSPFV3_PROFILE for $name.
provision_ospfv3_broadcast() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 svi_addr6=$6
  log "provisioning $name with an ospfv3 broadcast-domain link ($OSPF_BROADCAST_DOMAIN, address=$svi_addr6)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --routing-table rt1 \
    --broadcast-domain "$OSPF_BROADCAST_DOMAIN" \
    --ospfv3-broadcast-domain-svi-address "$svi_addr6" \
    --ospfv3-broadcast-domain-profile "$OSPFV3_PROFILE"
}

# --- ABR / Summary-LSA scenario ---
#
# Requires `ospf-spf` to have already run (router-b's loopback interface,
# `loopback-rt1`, already exists with $OSPF_SPF_LOOPBACK_ADDRESS attached and
# its ospf-profile already cleared by `cmd_check_ospf_spf`'s own withdrawal
# check). Ensures a second `OspfArea`/`OspfProfile` under router-b's existing
# $OSPF_INSTANCE, then reassigns the loopback: removes the old
# $OSPF_SPF_LOOPBACK_ADDRESS, adds $OSPF_ABR_LOOPBACK_ADDRESS, and attaches
# $OSPF_PROFILE_AREA1 to it -- a genuinely new prefix, in a genuinely new
# area, with no neighbor of its own. This makes router-b attached to 2 areas
# at once -- a real RFC 2328 ABR by this NOS's purely-derived definition (no
# config flag, see ospf/CLAUDE.md's "ABR and Summary-LSA origination") --
# while router-a stays in $OSPF_AREA only, so any route it learns to
# $OSPF_ABR_LOOPBACK_ADDRESS can only have arrived via a real Type-3
# Summary-LSA translated across areas by router-b.
#
# No LSA-withdrawal verification here (Summary-LSAs have no withdrawal path
# in this crate, same as every other LSA type -- they age out at MaxAge),
# mirroring `asbr`'s own scope decision.
provision_abr() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 ospf_instance=$6 ospf_router_id=$7
  log "provisioning $name with a second ospf area ($OSPF_AREA_1) and a reassigned loopback (address=$OSPF_ABR_LOOPBACK_ADDRESS) -- real abr scenario"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --ospf-instance "$ospf_instance" \
    --ospf-router-id "$ospf_router_id" \
    --ospf-area "$OSPF_AREA_1" \
    --ospf-profile "$OSPF_PROFILE_AREA1" \
    --loopback-remove-address "$OSPF_SPF_LOOPBACK_ADDRESS" \
    --loopback-address "$OSPF_ABR_LOOPBACK_ADDRESS" \
    --ospf-loopback-profile "$OSPF_PROFILE_AREA1"
}

# --- L2 switching-profile scenario ---
#
# Trunks router-a's own eth0 (already addressed/vrf-enslaved for the BGP
# session above -- untouched by this scenario, since both switching-profile
# members below are dot1q-tagged, not untagged, so they never conflict with
# eth0's own routing-table master) into two broadcast domains (bd1/bd2) at
# two different local dot1q tags (100/200), verifying nos-interfaced's Linux
# driver actually creates one real bridge device per domain, one real 802.1q
# sub-interface per tagged member (eth0.100/eth0.200), and enslaves each
# sub-interface into its own domain's bridge -- over a real kernel, not a
# unit test. Then clears the assignment and confirms both sub-interfaces are
# deleted again.

provision_switching() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with a switching profile trunking eth0 into bd1 (dot1q 100) and bd2 (dot1q 200)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --switching-profile sp1 \
    --switching-profile-member bd1:100 \
    --switching-profile-member bd2:200
}

provision_clear_switching_profile() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "clearing $name's interface switching-profile assignment"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --delete-switching-profile
}

# --- Broadcast-domain SVI scenario ---
#
# Configures an address and routing-table (VRF) directly on a broadcast
# domain ("bd-svi", distinct from bd1/bd2 above) rather than on any member
# interface, verifying nos-interfaced's Linux driver applies that L3 config
# straight onto the domain's own bridge device -- an SVI (switch virtual
# interface) -- over a real kernel: the bridge itself gets addressed and
# enslaved into rt1's VRF, the same reconciliation an ordinary interface's
# own L3 config already gets. Then deletes the domain outright and confirms
# its bridge is deleted, the same teardown the `loopback` scenario already
# proves for a dummy device -- proving the address/VRF enslavement this
# scenario added doesn't leave the bridge in a state deletion can't clean up.

provision_svi() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5 svi_addr=$6
  log "provisioning $name with an SVI on broadcast domain bd-svi (address=$svi_addr, routing-table=rt1)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --routing-table rt1 \
    --broadcast-domain bd-svi \
    --broadcast-domain-svi-address "$svi_addr"
}

provision_delete_svi() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with bd-svi's SVI removed"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --broadcast-domain bd-svi \
    --delete-broadcast-domain-svi
}

# --- L3 routed subinterface scenario ---
#
# Adds a second, routed subinterface (eth0.$SUBINTERFACE_TAG) to router-a's
# eth0 -- already addressed/vrf-enslaved on its tag-0 (untagged/native)
# subinterface for the BGP session above, untouched by this scenario -- and
# assigns it to the same "rt1" routing table/VRF, verifying nos-interfaced's
# Linux driver actually creates a real 802.1q VLAN sub-interface, enslaves it
# into rt1's VRF (the same VRF eth0 itself is already a member of -- a VRF
# legitimately has more than one member interface), and applies the
# configured address -- over a real kernel, not a unit test. Then removes it
# and confirms the sub-interface is deleted again.

provision_routed_subinterface() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "provisioning $name with a routed subinterface eth0.$SUBINTERFACE_TAG (address=$SUBINTERFACE_ADDRESS, routing-table=rt1)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "$SUBINTERFACE_ADDRESS" \
    --subinterface-tag "$SUBINTERFACE_TAG" \
    --routing-table rt1 \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip"
}

provision_delete_routed_subinterface() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  log "removing $name's eth0.$SUBINTERFACE_TAG routed subinterface"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "$SUBINTERFACE_ADDRESS" \
    --subinterface-tag "$SUBINTERFACE_TAG" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --delete-subinterface
}

# --- RFC 4456 route reflector scenario ---
#
# router-a is the reflector (cluster-id = its own router-id), with one iBGP
# peer-group ("pg1", remote-as = its own asn) shared by both router-b and
# router-c as route-reflector clients — calling nos-provision twice against
# the same peer-group with a different `--peer` adds a second client, since
# `BgpPeerOp::Set` upserts by remote-address (see nos-provision's doc
# comment). router-b and router-c are each just a plain iBGP peer of
# router-a — neither is configured to know about the other at all.

provision_reflector_hub() {
  local peer_ip=$1
  log "provisioning router-a as route reflector (cluster-id=$RID_A) for peer $peer_ip"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "router-a-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${IP_A}/24" \
    --asn "$ASN_A" \
    --router-id "$RID_A" \
    --peer-group pg1 \
    --remote-as "$ASN_A" \
    --peer "$peer_ip" \
    --route-reflector-client \
    --cluster-id "$RID_A"
}

provision_reflector_client() {
  local name=$1 router_id=$2 own_ip=$3
  log "provisioning $name as a plain iBGP route-reflector client of router-a"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$ASN_A" \
    --router-id "$router_id" \
    --remote-as "$ASN_A" \
    --peer "$IP_A"
}

provision_reflector_client_redistribute() {
  local name=$1 router_id=$2 own_ip=$3
  log "provisioning $name with a static route + 'redistribute from static to bgp'"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$ASN_A" \
    --router-id "$router_id" \
    --remote-as "$ASN_A" \
    --peer "$IP_A" \
    --static-route "$REDISTRIBUTE_PREFIX" \
    --static-gateway "$REDISTRIBUTE_GATEWAY" \
    --redistribute
}

cmd_up_reflector() {
  ensure_env_up
  start_router router-a "$IP_A"
  start_router router-b "$IP_B"
  start_router router-c "$IP_C"
  wait_for_config_socket router-a
  wait_for_config_socket router-b
  wait_for_config_socket router-c
  provision_reflector_hub "$IP_B"
  provision_reflector_hub "$IP_C"
  provision_reflector_client router-b "$RID_B" "$IP_B"
  provision_reflector_client router-c "$RID_C" "$IP_C"
}

cmd_check_reflector() {
  cmd_up_reflector
  local ok=0
  wait_for_log router-a "bgp session established" 60 && log "router-a: established" || { log "router-a: FAILED to establish"; ok=1; }
  wait_for_log router-b "bgp session established" 60 && log "router-b: established" || { log "router-b: FAILED to establish"; ok=1; }
  wait_for_log router-c "bgp session established" 60 && log "router-c: established" || { log "router-c: FAILED to establish"; ok=1; }
  if [[ $ok -ne 0 ]]; then return 1; fi

  provision_reflector_client_redistribute router-b "$RID_B" "$IP_B"
  log "waiting for router-c to learn $REDISTRIBUTE_PREFIX purely via the reflector (router-c has no direct session to router-b)"
  wait_for_log router-c "learned route for $REDISTRIBUTE_PREFIX into adj-rib-in" 60 \
    && log "router-c: received the reflected prefix into adj-rib-in" \
    || { log "router-c: FAILED to receive the reflected prefix"; return 1; }
  wait_for_log router-c "loc-rib best path for $REDISTRIBUTE_PREFIX updated" 60 \
    && log "router-c: installed the reflected prefix as its loc-rib best path" \
    || { log "router-c: FAILED to install the reflected prefix"; return 1; }
}

# --- RFC 7947 route server scenario ---
#
# router-a is the route server, with two eBGP peer-groups (distinct
# remote-as per client, both `route_server_client`) — router-b and router-c
# are ordinary eBGP routers, each in its own AS, each peering only with
# router-a. Verifies both session establishment and AS_PATH transparency:
# router-c should see router-b's ASN in the path but never router-a's own.

provision_route_server_hub() {
  local peer_group=$1 remote_as=$2 peer_ip=$3
  log "provisioning router-a as route server for $peer_ip (asn=$remote_as)"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "router-a-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${IP_A}/24" \
    --asn "$ASN_A" \
    --router-id "$RID_A" \
    --peer-group "$peer_group" \
    --remote-as "$remote_as" \
    --peer "$peer_ip" \
    --route-server-client
}

provision_route_server_client() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4
  log "provisioning $name as an eBGP route-server client of router-a"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$ASN_A" \
    --peer "$IP_A"
}

provision_route_server_client_redistribute() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4
  log "provisioning $name with a static route + 'redistribute from static to bgp'"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$ASN_A" \
    --peer "$IP_A" \
    --static-route "$REDISTRIBUTE_PREFIX" \
    --static-gateway "$REDISTRIBUTE_GATEWAY" \
    --redistribute
}

cmd_up_route_server() {
  ensure_env_up
  start_router router-a "$IP_A"
  start_router router-b "$IP_B"
  start_router router-c "$IP_C"
  wait_for_config_socket router-a
  wait_for_config_socket router-b
  wait_for_config_socket router-c
  provision_route_server_hub pg-b "$ASN_B" "$IP_B"
  provision_route_server_hub pg-c "$ASN_C" "$IP_C"
  provision_route_server_client router-b "$ASN_B" "$RID_B" "$IP_B"
  provision_route_server_client router-c "$ASN_C" "$RID_C" "$IP_C"
}

cmd_check_route_server() {
  cmd_up_route_server
  local ok=0
  wait_for_log router-a "bgp session established" 60 && log "router-a: established" || { log "router-a: FAILED to establish"; ok=1; }
  wait_for_log router-b "bgp session established" 60 && log "router-b: established" || { log "router-b: FAILED to establish"; ok=1; }
  wait_for_log router-c "bgp session established" 60 && log "router-c: established" || { log "router-c: FAILED to establish"; ok=1; }
  if [[ $ok -ne 0 ]]; then return 1; fi

  provision_route_server_client_redistribute router-b "$ASN_B" "$RID_B" "$IP_B"
  log "waiting for router-c to learn $REDISTRIBUTE_PREFIX via the route server"
  wait_for_log router-c "learned route for $REDISTRIBUTE_PREFIX into adj-rib-in" 60 \
    && log "router-c: received the relayed prefix into adj-rib-in" \
    || { log "router-c: FAILED to receive the relayed prefix"; return 1; }
  wait_for_log router-c "loc-rib best path for $REDISTRIBUTE_PREFIX updated" 60 \
    && log "router-c: installed the relayed prefix into its loc-rib" \
    || { log "router-c: FAILED to install the relayed prefix"; return 1; }

  log "confirming router-c sees router-b's asn ($ASN_B) but not router-a's own asn ($ASN_A) in as_path -- rfc 7947 transparency"
  local logs_c line
  # tracing's colored log output interleaves ANSI escape codes between
  # field names/separators/values (e.g. "as_path" ESC[0m ESC[2m "="
  # ESC[0m "[65002]") — strip them first so a plain substring match works.
  logs_c=$(docker logs router-c 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g') || true
  line=$(grep "loc-rib best path for $REDISTRIBUTE_PREFIX updated" <<<"$logs_c" | tail -n1) || true
  if [[ -n "$line" ]] && grep -q "as_path=\[$ASN_B\]" <<<"$line" && ! grep -q "$ASN_A" <<<"$line"; then
    log "router-c: as_path is transparently [$ASN_B] -- route-server's own asn was not prepended"
  else
    log "router-c: FAILED -- expected as_path [$ASN_B] with no route-server asn prepended, got: $line"
    return 1
  fi
}

established_count() {
  local name=$1
  docker logs "$name" 2>&1 | grep -c "bgp session established" || true
}

# Like `wait_for_log`, but for a re-triggered event on a container whose
# logs already contain the pattern from an earlier phase -- a bare presence
# check would false-positive on that stale line, so this polls a log-line
# *count* past an already-captured baseline instead (same technique as
# `established_count`/`learned_prefix_count`'s before/after comparisons,
# just as a polling wait instead of a single check after a fixed sleep).
wait_for_count_increase() {
  local name=$1 pattern=$2 baseline=$3 timeout=${4:-60}
  log "waiting for a new '$pattern' in $name's logs (baseline=$baseline, up to ${timeout}s)"
  for _ in $(seq 1 "$timeout"); do
    local count
    # tracing's colored output interleaves ANSI escape codes between a
    # structured field's name/separator/value (e.g. "origin" ESC[0m ESC[2m
    # "=" ESC[0m "Local") -- strip them first, same as the route-server and
    # communities checks' own log reads, or a pattern spanning a field like
    # `foo=bar` never matches at all.
    count=$(docker logs "$name" 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "$pattern") || true
    if [[ "$count" -gt "$baseline" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Current number of ANSI-stripped log lines matching PATTERN -- the baseline
# for wait_for_count_increase when an earlier phase may already have emitted
# the same line.
log_count() {
  local name=$1 pattern=$2 count
  count=$(docker logs "$name" 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "$pattern") || true
  echo "${count:-0}"
}

wait_for_log() {
  local name=$1 pattern=$2 timeout=${3:-60}
  log "waiting for '$pattern' in $name's logs (up to ${timeout}s)"
  local logs
  for _ in $(seq 1 "$timeout"); do
    # Capture into a variable rather than piping straight into `grep -q`:
    # under `pipefail`, grep's early exit on match sends SIGPIPE to
    # `docker logs` mid-write, and pipefail then reports the pipeline as
    # failed even though the pattern *was* found — a real, silent flake
    # found while writing this script.
    logs=$(docker logs "$name" 2>&1) || true
    if grep -q "$pattern" <<<"$logs"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

cmd_up() {
  ensure_env_up
  start_router router-a "$IP_A"
  start_router router-b "$IP_B"
  wait_for_config_socket router-a
  wait_for_config_socket router-b
  provision router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  provision router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A"
}

cmd_check_established() {
  local ok=0
  wait_for_log router-a "bgp session established" 60 && log "router-a: session established" || { log "router-a: FAILED to establish"; ok=1; }
  wait_for_log router-b "bgp session established" 60 && log "router-b: session established" || { log "router-b: FAILED to establish"; ok=1; }
  return $ok
}

# The runtime image has no ps/pgrep, so find the pid by scanning /proc's
# comm files directly (POSIX sh + kill builtin only).
kill_process_by_name() {
  local container=$1 name=$2
  docker exec "$container" sh -c "
    for p in /proc/[0-9]*; do
      [ -r \"\$p/comm\" ] || continue
      if [ \"\$(cat \"\$p/comm\" 2>/dev/null)\" = \"$name\" ]; then
        kill -9 \"\${p#/proc/}\"
      fi
    done
  "
}

cmd_check_reconnect() {
  log "killing router-b's nos-bgpd process to force a hold-timer/reconnect cycle on router-a"
  kill_process_by_name router-b nos-bgpd
  wait_for_log router-a "outbound bgp session ended\|inbound bgp session ended" 120 \
    && log "router-a: observed session end after peer vanished" \
    || { log "router-a: did not observe session end"; return 1; }
  log "waiting for the watchdog to respawn router-b's nos-bgpd and re-establish"
  wait_for_log router-b "bgp session established" 60 && log "router-b: re-established" || { log "router-b: FAILED to re-establish"; return 1; }
  wait_for_log router-a "bgp session established" 60 && log "router-a: re-established" || { log "router-a: FAILED to re-establish"; return 1; }
}

cmd_check_collision() {
  log "restarting both nos-bgpd processes at once to try to trigger a real collision"
  kill_process_by_name router-a nos-bgpd || true
  kill_process_by_name router-b nos-bgpd || true
  sleep 2
  local logs_a logs_b
  logs_a=$(docker logs router-a 2>&1) || true
  logs_b=$(docker logs router-b 2>&1) || true
  # Scoped to nos_bgp's own CollisionLost outcome — a bare "collision"
  # substring match also hits rtnetlink's unrelated per-link "collisions"
  # packet-stat counter (always present, always 0), a real false positive
  # found while writing this check.
  if grep -q "nos_bgp::.*CollisionLost" <<<"$logs_a" || grep -q "nos_bgp::.*CollisionLost" <<<"$logs_b"; then
    log "observed a collision-resolution log line"
  else
    log "no collision observed this cycle (timing-dependent, not a failure by itself)"
  fi
  cmd_check_established
}

cmd_check_redistribute() {
  # Baseline before router-b learns anything: router-b has no static routes
  # of its own in this scenario, so any later "added route" line on it can
  # only come from installing this newly-learned BGP route into its own
  # kernel routing table (rt1) — see the bgp-push check below.
  local kernel_route_baseline
  kernel_route_baseline=$(docker logs router-b 2>&1 | grep -c "added route" || true)

  provision_redistribute router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  log "waiting for router-a to redistribute $REDISTRIBUTE_PREFIX into its bgp instance"
  wait_for_log router-a "loc-rib best path for $REDISTRIBUTE_PREFIX updated" 60 \
    && log "router-a: installed redistributed static route into its own loc-rib" \
    || { log "router-a: FAILED to install redistributed route locally"; return 1; }
  log "waiting for router-b to learn $REDISTRIBUTE_PREFIX over the bgp session"
  wait_for_log router-b "learned route for $REDISTRIBUTE_PREFIX into adj-rib-in" 60 \
    && log "router-b: received redistributed prefix into adj-rib-in" \
    || { log "router-b: FAILED to receive redistributed prefix"; return 1; }
  wait_for_log router-b "loc-rib best path for $REDISTRIBUTE_PREFIX updated" 60 \
    && log "router-b: installed redistributed prefix as its loc-rib best path" \
    || { log "router-b: FAILED to install redistributed prefix into loc-rib"; return 1; }
  log "waiting for router-b to push $REDISTRIBUTE_PREFIX to nos-ribd and install it into its own kernel routing table (rt1)"
  wait_for_count_increase router-b "added route" "$kernel_route_baseline" 60 \
    && log "router-b: installed the bgp-learned route into the real kernel routing table" \
    || { log "router-b: FAILED to install the bgp-learned route into the kernel"; return 1; }
}

cmd_check_auth() {
  local password="correct-horse-battery-staple"
  provision_auth router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$password"
  provision_auth router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$password"
  log "waiting for both sides to (re-)establish with matching md5 passwords"
  wait_for_log router-a "bgp session established" 60 \
    && log "router-a: established with matching md5 password" \
    || { log "router-a: FAILED to establish with matching md5 password"; return 1; }
  wait_for_log router-b "bgp session established" 60 \
    && log "router-b: established with matching md5 password" \
    || { log "router-b: FAILED to establish with matching md5 password"; return 1; }

  local before_a before_b
  before_a=$(established_count router-a)
  before_b=$(established_count router-b)

  log "reconfiguring router-a with a mismatched md5 password"
  provision_auth router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "wrong-password"

  log "waiting 8s to confirm the session does NOT (re-)establish with mismatched md5 passwords"
  sleep 8
  local after_a after_b
  after_a=$(established_count router-a)
  after_b=$(established_count router-b)
  if [[ "$after_a" -gt "$before_a" || "$after_b" -gt "$before_b" ]]; then
    log "FAILED: session established despite mismatched md5 passwords"
    return 1
  fi
  log "confirmed: no new session established with mismatched md5 passwords"

  log "restoring the matching md5 password on router-a"
  provision_auth router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$password"
  wait_for_log router-a "bgp session established" 60 \
    && log "router-a: re-established after fixing the password" \
    || { log "router-a: FAILED to re-establish after fixing the password"; return 1; }
}

cmd_check_loopback() {
  provision_loopback router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$LOOPBACK_ADDRESS"

  # `wait_for_count_increase` strips tracing's ANSI color codes before
  # matching (see its own comment) -- needed here since every pattern below
  # spans a `field=value` boundary that colored output splits with escape
  # codes; a baseline of 0 makes it behave as a first-occurrence wait.
  log "waiting for router-a to create the loopback device ($LOOPBACK_DEVICE, rt1's allocated table id)"
  wait_for_count_increase router-a "created loopback device device=$LOOPBACK_DEVICE" 0 60 \
    && log "router-a: created $LOOPBACK_DEVICE" \
    || { log "router-a: FAILED to create the loopback device"; return 1; }

  log "waiting for router-a to enslave the loopback interface into rt1's vrf"
  wait_for_count_increase router-a "enslaved interface to vrf interface=loopback-rt1" 0 60 \
    && log "router-a: enslaved loopback-rt1 into its vrf" \
    || { log "router-a: FAILED to enslave the loopback interface"; return 1; }

  log "waiting for router-a to apply $LOOPBACK_ADDRESS to the loopback interface"
  wait_for_count_increase router-a "added interface address interface=loopback-rt1 address=$LOOPBACK_ADDRESS" 0 60 \
    && log "router-a: applied $LOOPBACK_ADDRESS to loopback-rt1" \
    || { log "router-a: FAILED to apply the loopback address"; return 1; }

  log "removing router-a's loopback interface"
  provision_delete_loopback router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  log "waiting for router-a to delete the loopback device"
  wait_for_count_increase router-a "deleted loopback device interface=loopback-rt1 device=$LOOPBACK_DEVICE" 0 60 \
    && log "router-a: deleted $LOOPBACK_DEVICE" \
    || { log "router-a: FAILED to delete the loopback device"; return 1; }
}

cmd_check_mtu() {
  provision_mtu router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$MTU_VALUE"

  log "waiting for router-a to apply mtu=$MTU_VALUE to eth0"
  wait_for_count_increase router-a "applied interface mtu interface=eth0 mtu=$MTU_VALUE" 0 60 \
    && log "router-a: applied mtu $MTU_VALUE to eth0" \
    || { log "router-a: FAILED to apply the interface mtu"; return 1; }
}

cmd_check_port_aggregate() {
  provision_port_aggregate router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  log "waiting for router-a to create the port aggregate bond device"
  wait_for_count_increase router-a "created port aggregate bond port_aggregate=bond1 bond=bond1 mode=Xor" 0 60 \
    && log "router-a: created port aggregate bond1 (mode=Xor)" \
    || { log "router-a: FAILED to create the port aggregate bond device"; return 1; }

  log "waiting for router-a to enslave eth1/eth2 into bond1"
  wait_for_count_increase router-a "enslaved interface to bond interface=eth1 bond=bond1" 0 60 \
    && log "router-a: enslaved eth1 into bond1" \
    || { log "router-a: FAILED to enslave eth1 into bond1"; return 1; }
  wait_for_count_increase router-a "enslaved interface to bond interface=eth2 bond=bond1" 0 60 \
    && log "router-a: enslaved eth2 into bond1" \
    || { log "router-a: FAILED to enslave eth2 into bond1"; return 1; }

  provision_delete_port_aggregate router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  # Deleting the bond device (below) already releases both slaves as a
  # kernel-level side effect of destroying their master — unlike deleting a
  # vlan sub-interface (see cmd_check_switching), there is no separate
  # explicit "unenslaved" netlink call/log line for this driver to emit on
  # its next resync, since the kernel gets there first. Real effect
  # confirmed manually against the live container while writing this check
  # (both members come back up with no master once bond1 is gone) — the
  # bond device's own deletion log line below is this phase's teardown
  # assertion, mirroring cmd_check_switching's own precedent of asserting
  # only on log lines the driver actually emits.
  log "waiting for router-a to delete the port aggregate bond device"
  wait_for_count_increase router-a "deleted port aggregate bond port_aggregate=bond1 bond=bond1" 0 60 \
    && log "router-a: deleted port aggregate bond1" \
    || { log "router-a: FAILED to delete the port aggregate bond device"; return 1; }
}

cmd_check_lacp() {
  # The kernel bond device is named from nos-interfaced's registry id
  # (bond<id>), not from the aggregate's config name, and that id depends on
  # which aggregates earlier phases created (`port-aggregate` takes bond1
  # first in `all`) -- so match any bond name, with baselines taken before
  # provisioning so earlier phases' identical lines never count.
  declare -A enslave_base
  local name iface
  for name in router-a router-b; do
    for iface in eth1 eth2; do
      enslave_base["$name/$iface"]=$(log_count "$name" "enslaved interface to bond interface=$iface bond=bond")
    done
  done
  local release_base
  release_base=$(log_count router-a "removed interface from master enslavement interface=eth2")

  lacp_link_veths
  provision_lacp router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  provision_lacp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A"

  log "waiting for both routers' nos-lacpd to reconcile $LACP_AGGREGATE's members"
  wait_for_count_increase router-a "lacp reconciled aggregate members aggregate=$LACP_AGGREGATE members=2" 0 60 \
    && log "router-a: nos-lacpd reconciled $LACP_AGGREGATE to 2 active members" \
    || { log "router-a: FAILED to reconcile lacp aggregate members"; return 1; }
  wait_for_count_increase router-b "lacp reconciled aggregate members aggregate=$LACP_AGGREGATE members=2" 0 60 \
    && log "router-b: nos-lacpd reconciled $LACP_AGGREGATE to 2 active members" \
    || { log "router-b: FAILED to reconcile lacp aggregate members"; return 1; }

  log "waiting for real lacpdu negotiation to reach Distributing on both routers/both links"
  for name in router-a router-b; do
    for iface in eth1 eth2; do
      wait_for_count_increase "$name" \
        "interface=$iface receive_state=Current mux_state=Distributing" 0 60 \
        && log "$name: $iface mux machine reached Distributing" \
        || { log "$name: FAILED -- $iface never reached Distributing"; return 1; }
    done
  done

  log "waiting for both routers to actually enslave eth1/eth2 into the real kernel bond"
  for name in router-a router-b; do
    for iface in eth1 eth2; do
      wait_for_count_increase "$name" \
        "enslaved interface to bond interface=$iface bond=bond" "${enslave_base["$name/$iface"]}" 60 \
        && log "$name: enslaved $iface into $LACP_AGGREGATE" \
        || { log "$name: FAILED to enslave $iface into $LACP_AGGREGATE"; return 1; }
    done
  done

  # Make router-b stop speaking LACP on eth2 (withdrawn from its aggregate
  # by config; the veth itself stays up) and confirm nos-lacpd on router-a
  # actually detects the silence (real Receive Machine timeout, no packets
  # from the other end at all) and nos-interfaced actually releases eth2 from
  # its kernel bond as a result -- proving the LACP-gated enslavement is
  # genuinely dynamic, not just applied once at provisioning time. Both sides
  # run `lacp-rate fast`, so router-a's Current_While_Timer is the Short 3s
  # one: the 30s budgets below are far under the 90s Long timer, so passing
  # them proves the fast rate is genuinely in effect, not just configured.
  # The Expired baseline is taken here, not at 0, since a port also passes
  # through Expired while first starting up.
  local expired_base
  expired_base=$(log_count router-a "interface=eth2 receive_state=Expired")
  provision_lacp_withdraw_eth2 router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A"

  log "waiting for router-a's lacp receive machine to expire on eth2 (within 30s -- fast rate's 3s timer, not the 90s long one)"
  wait_for_count_increase router-a "interface=eth2 receive_state=Expired" "$expired_base" 30 \
    && log "router-a: eth2 lacp receive machine expired" \
    || { log "router-a: FAILED -- eth2 receive machine never expired"; return 1; }

  log "waiting for router-a to release eth2 from the kernel bond"
  wait_for_count_increase router-a "removed interface from master enslavement interface=eth2" "$release_base" 30 \
    && log "router-a: released eth2 from $LACP_AGGREGATE" \
    || { log "router-a: FAILED to release eth2 from the kernel bond"; return 1; }

  provision_delete_lacp router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  provision_delete_lacp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A"

  log "waiting for both routers to delete the lacp port aggregate bond device"
  wait_for_count_increase router-a "deleted port aggregate bond port_aggregate=$LACP_AGGREGATE bond=" 0 60 \
    && log "router-a: deleted $LACP_AGGREGATE" \
    || { log "router-a: FAILED to delete the lacp port aggregate bond device"; return 1; }
  wait_for_count_increase router-b "deleted port aggregate bond port_aggregate=$LACP_AGGREGATE bond=" 0 60 \
    && log "router-b: deleted $LACP_AGGREGATE" \
    || { log "router-b: FAILED to delete the lacp port aggregate bond device"; return 1; }

  lacp_unlink_veths
}

# ---------------------------------------------------------------------------
# LLDP scenario
# ---------------------------------------------------------------------------
# Enables `lldp transmit`/`lldp receive` on both routers' eth1 (the veth pair
# `lacp_link_veths` creates -- a plain L2 wire, since a Linux bridge never
# forwards LLDP's 01:80:C2:00:00:0E address) and verifies nos-lldpd's real
# LLDPDU exchange over a real raw AF_PACKET socket.

# Base provisioning (address/asn/peer, hostname = container name so each router
# advertises a distinct LLDP System Name) plus any extra nos-provision flags
# after the fifth argument.
provision_lldp() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  shift 5
  log "provisioning $name: $*"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --hostname "$name" \
    "$@"
}

cmd_check_lldp() {
  # Baselines first, so an earlier phase's identical log lines never count.
  local learned_a_base learned_b_base removed_a_base started_a_base stopped_a_base=0
  learned_a_base=$(log_count router-a "lldp neighbor learned interface=eth1 .* system_name=router-b")
  learned_b_base=$(log_count router-b "lldp neighbor learned interface=eth1 .* system_name=router-a")
  removed_a_base=$(log_count router-a "lldp neighbor removed interface=eth1 .* reason=\"shutdown\"")
  started_a_base=$(log_count router-a "lldp link started interface=eth1 transmit=true receive=false")

  lacp_link_veths
  provision_lldp router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" \
    --lldp-transmit-interface eth1 --lldp-receive-interface eth1
  provision_lldp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" \
    --lldp-transmit-interface eth1 --lldp-receive-interface eth1

  log "waiting for both routers' nos-lldpd to learn the other over the real veth"
  # ttl=120 is the 802.1AB default (tx-interval 30 x tx-hold 4): nothing here
  # configures a timer yet.
  wait_for_count_increase router-a "lldp neighbor learned interface=eth1 .* port_id=eth1 system_name=router-b ttl=120" "$learned_a_base" 60 \
    && log "router-a: learned router-b via lldp on eth1 (default ttl 120)" \
    || { log "router-a: FAILED to learn router-b via lldp"; return 1; }
  wait_for_count_increase router-b "lldp neighbor learned interface=eth1 .* port_id=eth1 system_name=router-a ttl=120" "$learned_b_base" 60 \
    && log "router-b: learned router-a via lldp on eth1 (default ttl 120)" \
    || { log "router-b: FAILED to learn router-a via lldp"; return 1; }

  # Tunable timers + Management Address TLV. tx-interval 5 x tx-hold 3 must show
  # up as the TTL the *neighbor* learned (15), and each router's own address as
  # the management address it advertised. A config change restarts the link, so
  # each side re-learns the other with the new values.
  local mgmt_a_base mgmt_b_base
  mgmt_a_base=$(log_count router-a "lldp neighbor learned interface=eth1 .* system_name=router-b ttl=15 management_addresses=$IP_B")
  mgmt_b_base=$(log_count router-b "lldp neighbor learned interface=eth1 .* system_name=router-a ttl=15 management_addresses=$IP_A")
  provision_lldp router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" \
    --lldp-tx-interval 5 --lldp-tx-hold 3 --lldp-management-address "$IP_A"
  provision_lldp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" \
    --lldp-tx-interval 5 --lldp-tx-hold 3 --lldp-management-address "$IP_B"
  wait_for_count_increase router-a "lldp neighbor learned interface=eth1 .* system_name=router-b ttl=15 management_addresses=$IP_B" "$mgmt_a_base" 60 \
    && log "router-a: learned router-b with ttl 15 and management address $IP_B" \
    || { log "router-a: FAILED to see router-b's tuned ttl / management address"; return 1; }
  wait_for_count_increase router-b "lldp neighbor learned interface=eth1 .* system_name=router-a ttl=15 management_addresses=$IP_A" "$mgmt_b_base" 60 \
    && log "router-b: learned router-a with ttl 15 and management address $IP_A" \
    || { log "router-b: FAILED to see router-a's tuned ttl / management address"; return 1; }

  # Destination group. Both on customer-bridge (01:80:C2:00:00:00): still
  # neighbors. Then only router-b back on nearest-bridge: the two groups never
  # see each other -- router-a first drops router-b on its shutdown LLDPDU
  # (sent to the group router-a is still on), and after that neither re-learns
  # the other, though both keep transmitting every 5s. Then router-a follows and
  # both learn again.
  learned_a_base=$(log_count router-a "lldp neighbor learned interface=eth1 .* system_name=router-b")
  learned_b_base=$(log_count router-b "lldp neighbor learned interface=eth1 .* system_name=router-a")
  provision_lldp router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" --lldp-destination-interface eth1=customer-bridge
  provision_lldp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" --lldp-destination-interface eth1=customer-bridge
  wait_for_count_increase router-a "lldp neighbor learned interface=eth1 .* system_name=router-b" "$learned_a_base" 60 \
    && log "router-a: learned router-b over the customer-bridge group" \
    || { log "router-a: FAILED to learn router-b over the customer-bridge group"; return 1; }
  wait_for_count_increase router-b "lldp neighbor learned interface=eth1 .* system_name=router-a" "$learned_b_base" 60 \
    && log "router-b: learned router-a over the customer-bridge group" \
    || { log "router-b: FAILED to learn router-a over the customer-bridge group"; return 1; }

  removed_a_base=$(log_count router-a "lldp neighbor removed interface=eth1 .* reason=\"shutdown\"")
  provision_lldp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" --lldp-destination-interface eth1=nearest-bridge
  wait_for_count_increase router-a "lldp neighbor removed interface=eth1 .* reason=\"shutdown\"" "$removed_a_base" 30 \
    && log "router-a: dropped router-b on its shutdown LLDPDU (sent to the old group)" \
    || { log "router-a: FAILED to see router-b leave the customer-bridge group"; return 1; }
  learned_a_base=$(log_count router-a "lldp neighbor learned interface=eth1 .* system_name=router-b")
  learned_b_base=$(log_count router-b "lldp neighbor learned interface=eth1 .* system_name=router-a")
  log "mismatched destination groups: neither side may learn the other (waiting 15s, ~3 transmit intervals)"
  sleep 15
  if [[ $(log_count router-a "lldp neighbor learned interface=eth1 .* system_name=router-b") -ne $learned_a_base \
     || $(log_count router-b "lldp neighbor learned interface=eth1 .* system_name=router-a") -ne $learned_b_base ]]; then
    log "FAILED: a neighbor was learned across mismatched destination groups"
    return 1
  fi
  log "no neighbor learned across mismatched destination groups"

  provision_lldp router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" --lldp-destination-interface eth1=nearest-bridge
  wait_for_count_increase router-a "lldp neighbor learned interface=eth1 .* system_name=router-b" "$learned_a_base" 60 \
    && log "router-a: learned router-b again once both are back on nearest-bridge" \
    || { log "router-a: FAILED to re-learn router-b on nearest-bridge"; return 1; }
  wait_for_count_increase router-b "lldp neighbor learned interface=eth1 .* system_name=router-a" "$learned_b_base" 60 \
    && log "router-b: re-learned router-a on nearest-bridge" \
    || { log "router-b: FAILED to re-learn router-a on nearest-bridge"; return 1; }

  # Retake the baseline: the destination steps above also logged "shutdown"
  # removals, which must not satisfy the check below.
  removed_a_base=$(log_count router-a "lldp neighbor removed interface=eth1 .* reason=\"shutdown\"")

  # router-b stops transmitting: its link restarts, and on the way out sends a
  # real TTL-0 shutdown LLDPDU. router-a must drop router-b on receiving it --
  # within seconds, far under the 120s TTL, so this proves shutdown handling
  # rather than aging.
  provision_lldp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" --no-lldp-transmit-interface eth1
  log "waiting for router-a to act on router-b's shutdown LLDPDU (within 30s, not the 120s TTL)"
  wait_for_count_increase router-a "lldp neighbor removed interface=eth1 .* reason=\"shutdown\"" "$removed_a_base" 30 \
    && log "router-a: removed router-b on its shutdown LLDPDU" \
    || { log "router-a: FAILED to remove router-b on shutdown"; return 1; }

  # Transmit comes back: router-a must learn router-b again (the shutdown
  # emptied its table), and router-b -- which restarted with an empty table --
  # learns router-a well inside router-a's 30s transmit interval, because
  # learning a *new* neighbor triggers an immediate reply.
  learned_a_base=$(log_count router-a "lldp neighbor learned interface=eth1 .* system_name=router-b")
  learned_b_base=$(log_count router-b "lldp neighbor learned interface=eth1 .* system_name=router-a")
  provision_lldp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" --lldp-transmit-interface eth1
  wait_for_count_increase router-a "lldp neighbor learned interface=eth1 .* system_name=router-b" "$learned_a_base" 30 \
    && log "router-a: learned router-b again after it resumed transmitting" \
    || { log "router-a: FAILED to re-learn router-b"; return 1; }
  wait_for_count_increase router-b "lldp neighbor learned interface=eth1 .* system_name=router-a" "$learned_b_base" 15 \
    && log "router-b: re-learned router-a" \
    || { log "router-b: FAILED to re-learn router-a"; return 1; }

  # Drop receive on router-a: its link restarts as transmit-only.
  provision_lldp router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" --no-lldp-receive-interface eth1
  wait_for_count_increase router-a "lldp link started interface=eth1 transmit=true receive=false" "$started_a_base" 30 \
    && log "router-a: eth1 link restarted transmit-only" \
    || { log "router-a: FAILED to restart eth1 as transmit-only"; return 1; }

  # Tear down: disable everything and confirm router-a's link goes away. (The
  # baseline is taken here, not at the start: every restart above also logs a
  # "link stopped" line.)
  stopped_a_base=$(log_count router-a "lldp link stopped interface=eth1")
  provision_lldp router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" --no-lldp-transmit-interface eth1
  provision_lldp router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" \
    --no-lldp-transmit-interface eth1 --no-lldp-receive-interface eth1
  wait_for_count_increase router-a "lldp link stopped interface=eth1" "$stopped_a_base" 30 \
    && log "router-a: lldp link on eth1 stopped" \
    || { log "router-a: FAILED to stop the eth1 lldp link"; return 1; }

  lacp_unlink_veths
}

# ---------------------------------------------------------------------------
# REST API scenario
# ---------------------------------------------------------------------------
# Pins the REST API (nos-restd) to router-a's rt1 on router-a's own eth0
# address, and verifies -- over real HTTP from the host, across the docker
# bridge into a listener bound inside rt1's VRF -- that: nos-watchdogd spawns
# a real nos-restd for the pinned table, it binds address:port in the VRF, show
# endpoints return live data from other daemons, a transaction driven purely
# over the config-tree URLs (a scalar, a whole list element, a %2F-encoded key)
# commits into the real running config, the OpenAPI document is served, an
# address not (yet) configured on the VRF is retried rather than fatal, and
# unpinning stops the process and closes the port.

REST_PORT=8080
# Not assigned to any interface, so binding it fails with EADDRNOTAVAIL.
REST_ABSENT_ADDRESS=10.50.0.77
REST_TX=rest-e2e

provision_rest() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  shift 5
  log "provisioning $name: $*"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    "$@"
}

# rest_call METHOD URL [BODY] -- sets REST_STATUS / REST_BODY (never fails).
rest_call() {
  local method=$1 url=$2 body=${3-} out
  if [[ -n "$body" ]]; then
    out=$(curl -sS --max-time 5 -X "$method" -H 'content-type: application/json' \
      --data "$body" -w '\n%{http_code}' "$url" 2>&1) || true
  else
    out=$(curl -sS --max-time 5 -X "$method" -w '\n%{http_code}' "$url" 2>&1) || true
  fi
  REST_STATUS=${out##*$'\n'}
  REST_BODY=${out%$'\n'*}
}

# rest_expect METHOD URL STATUS [BODY] [BODY_PATTERN] -- asserts the status
# and, if given, that the body contains BODY_PATTERN (fixed-string match).
rest_expect() {
  local method=$1 url=$2 want=$3 body=${4-} pattern=${5-}
  rest_call "$method" "$url" "$body"
  if [[ "$REST_STATUS" != "$want" ]]; then
    log "FAILED: $method $url -> $REST_STATUS (want $want): $REST_BODY"
    return 1
  fi
  if [[ -n "$pattern" && "$REST_BODY" != *"$pattern"* ]]; then
    log "FAILED: $method $url body lacks '$pattern': $REST_BODY"
    return 1
  fi
}

cmd_check_rest() {
  local base="http://$IP_A:$REST_PORT" tx="/v1/transactions/$REST_TX"
  command -v curl >/dev/null || { log "curl is required on the host for the rest scenario"; return 1; }

  local spawn_base listen_base
  spawn_base=$(log_count router-a "spawning nos-restd for new REST API")
  listen_base=$(log_count router-a "rest api listening table=rt1 .* address=$IP_A port=$REST_PORT")
  provision_rest router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" \
    --rest-api-address "$IP_A" --rest-api-port "$REST_PORT"

  # Only nos-watchdogd logs the first, only nos-restd itself the second: the
  # process really was spawned for the newly-pinned table, and really bound
  # inside rt1's VRF.
  wait_for_count_increase router-a "spawning nos-restd for new REST API" "$spawn_base" 60 \
    && log "router-a: watchdog spawned nos-restd for rt1" \
    || { log "router-a: FAILED to see nos-restd spawned"; return 1; }
  wait_for_count_increase router-a "rest api listening table=rt1 .* address=$IP_A port=$REST_PORT" "$listen_base" 60 \
    && log "router-a: nos-restd listening on $IP_A:$REST_PORT inside rt1's vrf" \
    || { log "router-a: FAILED to see nos-restd listening"; return 1; }

  # Show endpoints, answered by other daemons (config, rib, bgp, interface).
  local orig_hostname
  rest_expect GET "$base/v1/config" 200 "" '"hostname"' || return 1
  orig_hostname=$(sed -E 's/.*"hostname":"([^"]*)".*/\1/' <<<"$REST_BODY")
  rest_expect GET "$base/v1/routes/rt1" 200 || return 1
  rest_expect GET "$base/v1/interfaces" 200 "" '"eth0"' || return 1
  rest_expect GET "$base/v1/bgp/summary" 200 "" '"instance":"r1"' || return 1
  rest_expect GET "$base/v1/routes/nonexistent-table" 503 || return 1
  log "router-a: show endpoints answered over http"

  # A transaction driven purely through the config-tree URLs.
  rest_expect POST "$base$tx?base=current" 201 || return 1
  rest_expect PUT "$base$tx/hostname" 200 '"rest-host"' '"rest-host"' || return 1
  rest_expect PUT "$base$tx/prefix-list/rest-pl" 200 \
    '{"name":"rest-pl","entries":[{"cidr":"10.0.0.0/8","range":null}]}' '"rest-pl"' || return 1
  # A key containing '/' travels as one percent-encoded segment.
  rest_expect GET "$base$tx/prefix-list/rest-pl/entry/10.0.0.0%2F8" 200 "" '"10.0.0.0/8"' || return 1
  rest_expect PUT "$base$tx/hostname" 400 '{"bad":true}' || return 1
  rest_expect GET "$base$tx/diff" 200 || return 1
  # Nothing is running yet.
  rest_expect GET "$base/v1/config" 200 || return 1
  if [[ "$REST_BODY" == *rest-pl* ]]; then
    log "FAILED: uncommitted transaction leaked into the running config"; return 1
  fi
  rest_expect POST "$base$tx/commit" 200 "" "\"committed\":\"$REST_TX\"" || return 1
  rest_expect GET "$base/v1/config" 200 "" '"rest-pl"' || return 1
  [[ "$REST_BODY" == *'"hostname":"rest-host"'* ]] \
    || { log "FAILED: committed hostname not in the running config"; return 1; }
  log "router-a: rest-driven transaction committed into the running config"

  # Undo it the same way, exercising DELETE on a subsection and on the tx.
  rest_expect POST "$base$tx?base=current" 201 || return 1
  rest_expect DELETE "$base$tx/prefix-list/rest-pl" 204 || return 1
  rest_expect PUT "$base$tx/hostname" 200 "\"$orig_hostname\"" || return 1
  rest_expect POST "$base$tx/commit" 200 || return 1
  rest_expect GET "$base/v1/config" 200 || return 1
  if [[ "$REST_BODY" == *rest-pl* ]]; then
    log "FAILED: rest-pl still present after DELETE + commit"; return 1
  fi
  rest_expect POST "$base$tx?base=blank" 201 || return 1
  rest_expect DELETE "$base$tx" 204 || return 1
  rest_expect GET "$base$tx" 404 || return 1

  rest_expect GET "$base/openapi.json" 200 "" '/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}' || return 1
  log "router-a: openapi document served"

  # An address that is not on the VRF (yet) is retried, not fatal: the old
  # listener is dropped, the new bind fails with EADDRNOTAVAIL, nothing crashes.
  local stopped_base absent_base
  stopped_base=$(log_count router-a "rest api stopped listening")
  absent_base=$(log_count router-a "rest api not listening yet")
  provision_rest router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" \
    --rest-api-address "$REST_ABSENT_ADDRESS" --rest-api-port "$REST_PORT"
  wait_for_count_increase router-a "rest api stopped listening" "$stopped_base" 30 \
    && log "router-a: nos-restd dropped the listener when its address changed" \
    || { log "router-a: FAILED to see the listener dropped"; return 1; }
  wait_for_count_increase router-a "rest api not listening yet" "$absent_base" 30 \
    && log "router-a: nos-restd retries an address that is not on the vrf" \
    || { log "router-a: FAILED to see the not-listening-yet retry"; return 1; }

  # Back to a real address, then unpin: the watchdog stops the process and
  # the port closes.
  listen_base=$(log_count router-a "rest api listening table=rt1 .* address=$IP_A port=$REST_PORT")
  provision_rest router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" \
    --rest-api-address "$IP_A" --rest-api-port "$REST_PORT"
  wait_for_count_increase router-a "rest api listening table=rt1 .* address=$IP_A port=$REST_PORT" "$listen_base" 30 \
    && log "router-a: nos-restd listening again on $IP_A" \
    || { log "router-a: FAILED to rebind on the real address"; return 1; }
  rest_expect GET "$base/v1/config" 200 || return 1

  local removed_base
  removed_base=$(log_count router-a "REST API removed from config, stopping nos-restd")
  provision_rest router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" --clear-rest-api
  wait_for_count_increase router-a "REST API removed from config, stopping nos-restd" "$removed_base" 30 \
    && log "router-a: watchdog stopped nos-restd after the table was unpinned" \
    || { log "router-a: FAILED to see nos-restd stopped"; return 1; }
  sleep 2
  rest_call GET "$base/v1/config"
  if [[ "$REST_STATUS" == 200 ]]; then
    log "FAILED: the rest api still answers after being unpinned"; return 1
  fi
  log "router-a: the rest api port is closed after unpinning"
}

cmd_check_ospf() {
  provision_ospf router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID"
  provision_ospf router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID_B"

  # Confirms nos-watchdogd actually spawned a real nos-ospfd process for the
  # new OspfInstance (not just that config accepted it) -- only nos-ospfd
  # itself, once running and connected to nos-configd, ever logs this line.
  log "waiting for nos-ospfd to resolve its own instance config"
  wait_for_count_increase router-a "ospf instance config resolved instance=$OSPF_INSTANCE" 0 60 \
    && log "router-a: nos-ospfd resolved $OSPF_INSTANCE (router-id=$OSPF_ROUTER_ID, routing-table=rt1)" \
    || { log "router-a: FAILED to see nos-ospfd resolve its instance config"; return 1; }

  # Confirms the area/profile config (nested under the instance) round-trips
  # through nos-configd and is resolved by nos-ospfd on the same resync --
  # not just accepted at commit time.
  log "waiting for nos-ospfd to resolve its area/profile config"
  # Field order matches the `info!(instance, area, ..., "...")` call sites in
  # ospf/src/reconcile.rs -- tracing renders fields after the message in
  # declaration order, so the pattern must be a contiguous substring of that.
  wait_for_count_increase router-a "ospf area resolved instance=$OSPF_INSTANCE area=$OSPF_AREA" 0 60 \
    && log "router-a: nos-ospfd resolved area $OSPF_AREA" \
    || { log "router-a: FAILED to see nos-ospfd resolve its area config"; return 1; }
  wait_for_count_increase router-a "ospf profile resolved instance=$OSPF_INSTANCE area=$OSPF_AREA profile=$OSPF_PROFILE" 0 60 \
    && log "router-a: nos-ospfd resolved profile $OSPF_PROFILE" \
    || { log "router-a: FAILED to see nos-ospfd resolve its profile config"; return 1; }

  # Confirms a real RFC 2328 Hello exchange over a real raw protocol-89
  # socket, VRF-scoped, actually reaches 2-Way on both sides -- both
  # routers' eth0 tag-0 subinterface (the same one already carrying their
  # BGP session's own address/rt1 association) is the ospf-profile1 attach
  # point, so this is a real point-to-point link between two containers, not
  # a loopback/simulated one. Field order matches `link.rs`'s
  # `info!(link, neighbor, "ospf neighbor reached two-way")` call site.
  log "waiting for router-a/router-b to reach ospf 2-way"
  wait_for_count_increase router-a "ospf neighbor reached two-way link=eth0.0 neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospf 2-way with $OSPF_ROUTER_ID_B" \
    || { log "router-a: FAILED to reach ospf 2-way"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached two-way link=eth0.0 neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: reached ospf 2-way with $OSPF_ROUTER_ID" \
    || { log "router-b: FAILED to reach ospf 2-way"; return 1; }

  # Confirms the adjacency actually completes RFC 2328 §10.6-10.8's real
  # DBD/LSR/LSU/LSAck exchange and reaches Full -- not just 2-Way -- over
  # the same raw socket. Field order matches `link.rs`'s
  # `info!(link, neighbor, "ospf neighbor reached full")` call site.
  log "waiting for router-a/router-b to reach ospf full on the point-to-point link"
  wait_for_count_increase router-a "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospf full with $OSPF_ROUTER_ID_B" \
    || { log "router-a: FAILED to reach ospf full"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: reached ospf full with $OSPF_ROUTER_ID" \
    || { log "router-b: FAILED to reach ospf full"; return 1; }

  # Confirms real LSA content (this NOS's own self-originated Router-LSA)
  # actually flows over the wire and gets installed into the receiving
  # side's LSDB -- not asserted against a specific link, since a router's
  # LSDB is shared per-area across every one of its links (real RFC 2328
  # behavior), so which link an LSA's install is first observed on is a
  # legitimate race, not something to pin down. Field order matches
  # `link.rs`'s `info!(link, neighbor, lsa_type, link_state_id,
  # advertising_router, "ospf lsa installed")` call site.
  log "waiting for router-a/router-b to install a real lsa learned from each other"
  wait_for_count_increase router-a "ospf lsa installed.*neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: installed an lsa learned from $OSPF_ROUTER_ID_B" \
    || { log "router-a: FAILED to install an lsa"; return 1; }
  wait_for_count_increase router-b "ospf lsa installed.*neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: installed an lsa learned from $OSPF_ROUTER_ID" \
    || { log "router-b: FAILED to install an lsa"; return 1; }

  provision_ospf_broadcast router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_BROADCAST_ADDRESS_A"
  provision_ospf_broadcast router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPF_BROADCAST_ADDRESS_B"

  # Confirms the same Hello protocol also reaches 2-Way on a broadcast
  # (multi-access) link -- this time via each router's own bd-ospf bridge
  # rather than a raw subinterface -- and that real RFC 2328 §9.4 DR/BDR
  # election converges deterministically: with equal (default) priority on
  # both sides, the higher router-id (router-b's $OSPF_ROUTER_ID_B) wins DR,
  # and with only two eligible routers the other side becomes Backup, never
  # DROther. Field order matches `link.rs`'s `info!(link, dr, [bdr],
  # "ospf interface became ...")` call sites.
  log "waiting for router-a/router-b to reach ospf 2-way on the broadcast link"
  wait_for_count_increase router-a "ospf neighbor reached two-way link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospf 2-way with $OSPF_ROUTER_ID_B on the broadcast link" \
    || { log "router-a: FAILED to reach ospf 2-way on the broadcast link"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached two-way link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: reached ospf 2-way with $OSPF_ROUTER_ID on the broadcast link" \
    || { log "router-b: FAILED to reach ospf 2-way on the broadcast link"; return 1; }

  log "waiting for router-a/router-b to elect a dr/backup on the broadcast link"
  wait_for_count_increase router-b "ospf interface became dr link=broadcast-domain:$OSPF_BROADCAST_DOMAIN dr=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-b: became dr" \
    || { log "router-b: FAILED to become dr"; return 1; }
  wait_for_count_increase router-a "ospf interface became backup link=broadcast-domain:$OSPF_BROADCAST_DOMAIN dr=$OSPF_ROUTER_ID_B bdr=$OSPF_ROUTER_ID" 0 60 \
    && log "router-a: became backup" \
    || { log "router-a: FAILED to become backup"; return 1; }

  # Confirms the broadcast-link adjacency also completes the real DBD/LSR/
  # LSU/LSAck exchange and reaches Full, restricted to the DR/BDR pair per
  # RFC 2328 §7.5/§10.4 (the only two eligible routers on this 2-router
  # segment, so both proceed).
  log "waiting for router-a/router-b to reach ospf full on the broadcast link"
  wait_for_count_increase router-a "ospf neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospf full with $OSPF_ROUTER_ID_B on the broadcast link" \
    || { log "router-a: FAILED to reach ospf full on the broadcast link"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: reached ospf full with $OSPF_ROUTER_ID on the broadcast link" \
    || { log "router-b: FAILED to reach ospf full on the broadcast link"; return 1; }
}

# --- OSPFv3 (RFC 5340) scenario ---
#
# Mirrors `cmd_check_ospf`'s point-to-point half exactly, over the real
# IPv6 Hello/DBD/LSR/LSU/LSAck exchange on eth0.0 -- reaching 2-Way then
# Full, with a real self-originated Router-LSA/Link-LSA/Intra-Area-Prefix-LSA
# flooded and installed on the other side -- then attaches router-a's own
# loopback (a destination with no neighbor of its own) and confirms
# router-b's own real RFC 5340 §4.8 SPF computation derives the correct
# IPv6 next-hop purely from the LSDB's Link-LSAs (never a live neighbor
# table) and pushes a real kernel route for it via nos-ribd.
cmd_check_ospfv3() {
  provision_ospfv3 router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPFV3_ADDRESS_A" "$OSPFV3_INSTANCE" "$OSPFV3_ROUTER_ID"
  provision_ospfv3 router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPFV3_ADDRESS_B" "$OSPFV3_INSTANCE" "$OSPFV3_ROUTER_ID_B"

  # Confirms nos-watchdogd actually spawned a real nos-ospfv3d process for
  # the new Ospfv3Instance (not just that config accepted it) -- mirrors
  # cmd_check_ospf's own first check. Field order matches
  # ospfv3/src/reconcile.rs's `info!(instance, router_id, routing_table,
  # area_count, "ospfv3 instance config resolved")` call site.
  log "waiting for nos-ospfv3d to resolve its own instance config"
  wait_for_count_increase router-a "ospfv3 instance config resolved instance=$OSPFV3_INSTANCE" 0 60 \
    && log "router-a: nos-ospfv3d resolved $OSPFV3_INSTANCE (router-id=$OSPFV3_ROUTER_ID, routing-table=rt1)" \
    || { log "router-a: FAILED to see nos-ospfv3d resolve its instance config"; return 1; }

  log "waiting for nos-ospfv3d to resolve its area/profile config"
  wait_for_count_increase router-a "ospfv3 area resolved instance=$OSPFV3_INSTANCE area=$OSPFV3_AREA" 0 60 \
    && log "router-a: nos-ospfv3d resolved area $OSPFV3_AREA" \
    || { log "router-a: FAILED to see nos-ospfv3d resolve its area config"; return 1; }
  wait_for_count_increase router-a "ospfv3 profile resolved instance=$OSPFV3_INSTANCE area=$OSPFV3_AREA profile=$OSPFV3_PROFILE" 0 60 \
    && log "router-a: nos-ospfv3d resolved profile $OSPFV3_PROFILE" \
    || { log "router-a: FAILED to see nos-ospfv3d resolve its profile config"; return 1; }

  # Real RFC 5340 Hello exchange over a real VRF-scoped raw IPv6 protocol-89
  # socket, reaching 2-Way on both sides. Field order matches `link.rs`'s
  # `info!(link, neighbor, "ospfv3 neighbor reached two-way")` call site.
  log "waiting for router-a/router-b to reach ospfv3 2-way"
  wait_for_count_increase router-a "ospfv3 neighbor reached two-way link=eth0.0 neighbor=$OSPFV3_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospfv3 2-way with $OSPFV3_ROUTER_ID_B" \
    || { log "router-a: FAILED to reach ospfv3 2-way"; return 1; }
  wait_for_count_increase router-b "ospfv3 neighbor reached two-way link=eth0.0 neighbor=$OSPFV3_ROUTER_ID" 0 60 \
    && log "router-b: reached ospfv3 2-way with $OSPFV3_ROUTER_ID" \
    || { log "router-b: FAILED to reach ospfv3 2-way"; return 1; }

  log "waiting for router-a/router-b to reach ospfv3 full"
  wait_for_count_increase router-a "ospfv3 neighbor reached full link=eth0.0 neighbor=$OSPFV3_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospfv3 full with $OSPFV3_ROUTER_ID_B" \
    || { log "router-a: FAILED to reach ospfv3 full"; return 1; }
  wait_for_count_increase router-b "ospfv3 neighbor reached full link=eth0.0 neighbor=$OSPFV3_ROUTER_ID" 0 60 \
    && log "router-b: reached ospfv3 full with $OSPFV3_ROUTER_ID" \
    || { log "router-b: FAILED to reach ospfv3 full"; return 1; }

  # Confirms real LSA content actually flows over the wire and gets
  # installed into the receiving side's LSDB. Field order matches
  # `link.rs`'s `info!(link, neighbor, lsa_type, link_state_id,
  # advertising_router, "ospfv3 lsa installed")` call site.
  log "waiting for router-a/router-b to install a real lsa learned from each other"
  wait_for_count_increase router-a "ospfv3 lsa installed.*neighbor=$OSPFV3_ROUTER_ID_B" 0 60 \
    && log "router-a: installed an lsa learned from $OSPFV3_ROUTER_ID_B" \
    || { log "router-a: FAILED to install an lsa"; return 1; }
  wait_for_count_increase router-b "ospfv3 lsa installed.*neighbor=$OSPFV3_ROUTER_ID" 0 60 \
    && log "router-b: installed an lsa learned from $OSPFV3_ROUTER_ID" \
    || { log "router-b: FAILED to install an lsa"; return 1; }

  local route_before
  route_before=$(docker logs router-b 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "added route" || true)

  provision_ospfv3_loopback router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPFV3_LOOPBACK_ADDRESS"

  log "waiting for router-a to originate a real intra-area-prefix-lsa for its loopback"
  wait_for_count_increase router-a "ospfv3 lsa originated" 0 60 \
    && log "router-a: originated an lsa for its loopback prefix" \
    || { log "router-a: FAILED to originate a loopback lsa"; return 1; }

  log "waiting for router-b to learn router-a's loopback lsa"
  wait_for_count_increase router-b "ospfv3 lsa installed.*neighbor=$OSPFV3_ROUTER_ID" 1 60 \
    && log "router-b: installed router-a's loopback lsa into its own lsdb" \
    || { log "router-b: FAILED to learn the loopback lsa"; return 1; }

  # Same `add_route`/`Option<RouteSource>` rendering quirk as
  # `cmd_check_ospf_spf`'s own check -- a fresh, never-before-installed
  # IPv6 prefix, so router-b's own real RFC 5340 §16 SPF computation is the
  # only possible source of this kernel route.
  log "waiting for router-b to compute (via ospfv3 spf) and install a real kernel route to $OSPFV3_LOOPBACK_ADDRESS"
  wait_for_count_increase router-b "added route prefix=$OSPFV3_LOOPBACK_ADDRESS.*source=Some(Ospf)" "$route_before" 60 \
    && log "router-b: installed the ospfv3-computed route into the real kernel routing table" \
    || { log "router-b: FAILED to install the ospfv3-computed route"; return 1; }
}

# --- Multi-router OSPFv3 DR/BDR scenario ---
#
# Requires `ospfv3` AND `ospf-dr` to have already run -- the latter, not
# just the former, because this reuses router-c's already-running container
# from `ospf-dr` rather than starting a fresh one: router-c's OSPFv2 config
# lives only in nos-configd's in-memory state (never `--save`d), so
# restarting its container here would silently wipe it. Otherwise mirrors
# `cmd_check_ospf_dr` exactly, over the same bd-ospf bridge OSPFv2's own
# `ospf`/`ospf-dr` scenarios already trunked router-a/router-b/router-c's
# eth0 into -- reused as-is (a BroadcastDomain carries independent
# `ospf_profile`/`ospfv3_profile` fields, so both protocols'
# Hello/election/adjacency run over the same real Linux bridge with no
# conflict). router-c's OSPFv3 router-id ($OSPFV3_ROUTER_ID_C) is
# deliberately lower than both router-a's
# and router-b's, for the identical RFC 2328 §9.4 incumbent-stickiness
# reason `cmd_check_ospf_dr` documents.
cmd_check_ospfv3_dr() {
  provision_ospfv3_instance_only router-c "$ASN_C" "$RID_C" "$IP_C" "$IP_A" "$OSPFV3_INSTANCE" "$OSPFV3_ROUTER_ID_C"
  provision_ospfv3_broadcast router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPFV3_BROADCAST_ADDRESS_A"
  provision_ospfv3_broadcast router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPFV3_BROADCAST_ADDRESS_B"
  provision_ospfv3_broadcast router-c "$ASN_C" "$RID_C" "$IP_C" "$IP_A" "$OSPFV3_BROADCAST_ADDRESS_C"

  log "waiting for router-a/router-b to reach ospfv3 2-way on the broadcast link"
  wait_for_count_increase router-a "ospfv3 neighbor reached two-way link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPFV3_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospfv3 2-way with $OSPFV3_ROUTER_ID_B on the broadcast link" \
    || { log "router-a: FAILED to reach ospfv3 2-way on the broadcast link"; return 1; }
  wait_for_count_increase router-b "ospfv3 neighbor reached two-way link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPFV3_ROUTER_ID" 0 60 \
    && log "router-b: reached ospfv3 2-way with $OSPFV3_ROUTER_ID on the broadcast link" \
    || { log "router-b: FAILED to reach ospfv3 2-way on the broadcast link"; return 1; }

  log "waiting for router-a/router-b to elect a dr/backup on the ospfv3 broadcast link"
  wait_for_count_increase router-b "ospfv3 interface became dr link=broadcast-domain:$OSPF_BROADCAST_DOMAIN dr=$OSPFV3_ROUTER_ID_B" 0 60 \
    && log "router-b: became dr" \
    || { log "router-b: FAILED to become dr"; return 1; }
  wait_for_count_increase router-a "ospfv3 interface became backup link=broadcast-domain:$OSPF_BROADCAST_DOMAIN dr=$OSPFV3_ROUTER_ID_B bdr=$OSPFV3_ROUTER_ID" 0 60 \
    && log "router-a: became backup" \
    || { log "router-a: FAILED to become backup"; return 1; }

  log "waiting for router-c to reach ospfv3 2-way with router-a and router-b on the broadcast link"
  wait_for_count_increase router-c "ospfv3 neighbor reached two-way link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPFV3_ROUTER_ID" 0 60 \
    && log "router-c: reached ospfv3 2-way with $OSPFV3_ROUTER_ID (router-a)" \
    || { log "router-c: FAILED to reach ospfv3 2-way with router-a"; return 1; }
  wait_for_count_increase router-c "ospfv3 neighbor reached two-way link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPFV3_ROUTER_ID_B" 0 60 \
    && log "router-c: reached ospfv3 2-way with $OSPFV3_ROUTER_ID_B (router-b)" \
    || { log "router-c: FAILED to reach ospfv3 2-way with router-b"; return 1; }

  log "waiting for router-c to settle as dr-other (router-b stays dr, router-a stays backup)"
  wait_for_count_increase router-c "ospfv3 interface became dr-other link=broadcast-domain:$OSPF_BROADCAST_DOMAIN dr=$OSPFV3_ROUTER_ID_B bdr=$OSPFV3_ROUTER_ID" 0 60 \
    && log "router-c: became dr-other" \
    || { log "router-c: FAILED to become dr-other"; return 1; }

  log "waiting for router-a/router-b/router-c to reach ospfv3 full with each other as required"
  wait_for_count_increase router-c "ospfv3 neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPFV3_ROUTER_ID" 0 60 \
    && log "router-c: reached ospfv3 full with $OSPFV3_ROUTER_ID (router-a, backup)" \
    || { log "router-c: FAILED to reach ospfv3 full with router-a"; return 1; }
  wait_for_count_increase router-c "ospfv3 neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPFV3_ROUTER_ID_B" 0 60 \
    && log "router-c: reached ospfv3 full with $OSPFV3_ROUTER_ID_B (router-b, dr)" \
    || { log "router-c: FAILED to reach ospfv3 full with router-b"; return 1; }
  wait_for_count_increase router-a "ospfv3 neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPFV3_ROUTER_ID_C" 0 60 \
    && log "router-a: reached ospfv3 full with $OSPFV3_ROUTER_ID_C (router-c, dr-other)" \
    || { log "router-a: FAILED to reach ospfv3 full with router-c"; return 1; }
  wait_for_count_increase router-b "ospfv3 neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPFV3_ROUTER_ID_C" 0 60 \
    && log "router-b: reached ospfv3 full with $OSPFV3_ROUTER_ID_C (router-c, dr-other)" \
    || { log "router-b: FAILED to reach ospfv3 full with router-c"; return 1; }
}

cmd_check_asbr() {
  local originated_before installed_before route_before
  originated_before=$(docker logs router-a 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "ospf lsa originated.*lsa_type=5" || true)
  installed_before=$(docker logs router-b 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "ospf lsa installed.*lsa_type=5" || true)
  route_before=$(docker logs router-b 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "added route" || true)

  provision_asbr router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID"

  # Field order matches `link.rs`'s `install_self_originated`'s
  # `info!(lsa_type, link_state_id, advertising_router, refreshed, "ospf lsa
  # originated")` call site.
  log "waiting for router-a to originate a real as-external-lsa for $ASBR_PREFIX"
  wait_for_count_increase router-a "ospf lsa originated.*lsa_type=5" "$originated_before" 60 \
    && log "router-a: originated an as-external-lsa (real asbr behavior)" \
    || { log "router-a: FAILED to originate an as-external-lsa"; return 1; }

  log "waiting for router-b to learn router-a's as-external-lsa"
  wait_for_count_increase router-b "ospf lsa installed.*lsa_type=5" "$installed_before" 60 \
    && log "router-b: installed router-a's as-external-lsa into its own lsdb" \
    || { log "router-b: FAILED to learn the as-external-lsa"; return 1; }

  # Same `add_route`/`Option<RouteSource>` rendering quirk as
  # `cmd_check_ospf_spf`'s own check -- see its comment.
  log "waiting for router-b to compute (via ospf spf) and install a real kernel route to $ASBR_PREFIX"
  wait_for_count_increase router-b "added route prefix=$ASBR_PREFIX.*source=Some(Ospf)" "$route_before" 60 \
    && log "router-b: installed the asbr-redistributed route into the real kernel routing table" \
    || { log "router-b: FAILED to install the asbr-redistributed route"; return 1; }
}

# --- OSPF authentication scenario ---
#
# Requires `ospf` to have already run (router-a/router-b's real p2p
# adjacency over eth0.0, the same one already carrying $OSPF_PROFILE).
# Configures a matching RFC 5709 HMAC-SHA-256 crypto key on both sides
# (confirming the adjacency reaches/stays Full with real per-packet digest
# verification, not simulated), then a mismatched key on router-a only
# (confirming router-b logs a real digest-verification failure and no new
# Full adjacency forms -- router-a's own link task restarts with empty
# state on the config change and can never reach Full again while the
# mismatch persists, since every Hello either side sends is rejected by the
# other), then restores the matching key (confirming a fresh Full adjacency
# forms again).
ospf_full_count() {
  local name=$1 neighbor=$2
  # Strips ANSI escape codes first, same as `wait_for_count_increase` --
  # this pattern spans a `field=value` boundary that colored output splits.
  docker logs "$name" 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
    | grep -c "ospf neighbor reached full link=eth0.0 neighbor=$neighbor" || true
}

cmd_check_ospf_auth() {
  local key="topsecretkey"
  provision_ospf_auth router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID" "1:hmac-sha256:$key"
  provision_ospf_auth router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID_B" "1:hmac-sha256:$key"

  log "waiting for router-a/router-b to (re-)reach ospf full with a matching hmac-sha256 crypto key"
  wait_for_count_increase router-a "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospf full with a matching crypto key" \
    || { log "router-a: FAILED to reach ospf full with a matching crypto key"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: reached ospf full with a matching crypto key" \
    || { log "router-b: FAILED to reach ospf full with a matching crypto key"; return 1; }

  local before_a
  before_a=$(ospf_full_count router-a "$OSPF_ROUTER_ID_B")

  log "reconfiguring router-a with a mismatched crypto key"
  provision_ospf_auth router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID" "1:hmac-sha256:wrong-key"

  log "waiting for router-b to log a real ospf digest-verification failure from router-a"
  wait_for_count_increase router-b "ospf packet authentication failed link=eth0.0" 0 30 \
    && log "router-b: logged an ospf authentication failure" \
    || { log "router-b: FAILED to log an ospf authentication failure"; return 1; }

  log "waiting 8s to confirm no new ospf full adjacency forms with mismatched crypto keys"
  sleep 8
  local after_a
  after_a=$(ospf_full_count router-a "$OSPF_ROUTER_ID_B")
  if [[ "$after_a" -gt "$before_a" ]]; then
    log "FAILED: ospf reached full again despite mismatched crypto keys"
    return 1
  fi
  log "confirmed: no new ospf full adjacency with mismatched crypto keys"

  log "restoring the matching crypto key on router-a"
  provision_ospf_auth router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID" "1:hmac-sha256:$key"
  wait_for_count_increase router-a "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID_B" "$before_a" 60 \
    && log "router-a: re-reached ospf full after fixing the crypto key" \
    || { log "router-a: FAILED to re-reach ospf full after fixing the crypto key"; return 1; }
}

# --- OSPF SPF route computation scenario ---
#
# Requires `ospf` to have already run (router-a/router-b's real p2p
# adjacency over eth0.0). Attaches OSPF to router-b's own loopback
# interface (`loopback-rt1`) at a distinct subnet ($OSPF_SPF_LOOPBACK_
# ADDRESS) -- a destination with no neighbor of its own, exercising RFC
# 2328 §16.2's stub-network leaf processing -- and confirms router-a's own
# nos-ospfd actually runs a real RFC 2328 §16.1 Dijkstra over its LSDB,
# derives the correct next-hop (router-b's own eth0.0 address, read from
# router-b's own Router-LSA -- never a live neighbor table, see
# `ospf/src/spf.rs`), and pushes the computed route to its own nos-ribd for
# real kernel installation -- over real containers, not a unit test. The
# real per-route kernel-install/withdraw log lines (`rib/src/driver/
# linux.rs`'s "added route"/"removed route", already generic across every
# `RouteSource`) are reused rather than adding a new one, filtered by
# `source=Ospf` to distinguish this route from anything BGP might install.
cmd_check_ospf_spf() {
  local before
  before=$(docker logs router-a 2>&1 | grep -c "ospf lsa installed.*advertising_router=$OSPF_ROUTER_ID_B" || true)

  provision_ospf_loopback router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPF_SPF_LOOPBACK_ADDRESS"

  log "waiting for router-a to learn router-b's reoriginated router-lsa (with the new stub-network link)"
  wait_for_count_increase router-a "ospf lsa installed.*advertising_router=$OSPF_ROUTER_ID_B" "$before" 60 \
    && log "router-a: learned router-b's updated router-lsa" \
    || { log "router-a: FAILED to learn router-b's updated router-lsa"; return 1; }

  log "waiting for router-a to compute and install a real kernel route to $OSPF_SPF_LOOPBACK_ADDRESS via ospf spf"
  # add_route's `source` field is `Option<RouteSource>` (the full apply()
  # path passes a source-less None for its bulk kernel-drift reconcile), so
  # its Debug rendering is "Some(Ospf)", not "Ospf".
  wait_for_count_increase router-a "added route prefix=$OSPF_SPF_LOOPBACK_ADDRESS.*source=Some(Ospf)" 0 60 \
    && log "router-a: installed a real spf-computed route to $OSPF_SPF_LOOPBACK_ADDRESS" \
    || { log "router-a: FAILED to install the spf-computed route"; return 1; }

  provision_clear_ospf_loopback router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A"

  log "waiting for router-a to withdraw the spf-computed route"
  wait_for_count_increase router-a "removed route prefix=$OSPF_SPF_LOOPBACK_ADDRESS" 0 60 \
    && log "router-a: withdrew the route to $OSPF_SPF_LOOPBACK_ADDRESS" \
    || { log "router-a: FAILED to withdraw the spf-computed route"; return 1; }
}

# --- ABR / Summary-LSA scenario ---
#
# Requires `ospf-spf` to have already run (see `provision_abr`'s own
# comment). Confirms real RFC 2328 multi-area ABR behavior: router-b
# actually originates a Type-3 network-summary LSA for its reassigned
# loopback, router-a learns and installs it into its own (backbone-only)
# LSDB over the real adjacency, and router-a's own SPF computes and installs
# a real kernel route for a prefix that is NOT in router-a's own area --
# purely via router-b's ABR summary, never a direct intra-area path -- see
# ospf/CLAUDE.md's "ABR and Summary-LSA origination". Type-4/ASBR-summary
# behavior has no Docker phase of its own (this 2-router/2-area topology has
# no cross-area ASBR to exercise it -- covered by unit tests only, same
# ponytail-flagged scope decision `asbr` made for its own simplifications).
cmd_check_abr() {
  local originated_before installed_before
  originated_before=$(docker logs router-b 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "ospf lsa originated.*lsa_type=3" || true)
  installed_before=$(docker logs router-a 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "ospf lsa installed.*lsa_type=3" || true)

  provision_abr router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID_B"

  # Field order matches `link.rs`'s `install_self_originated`'s
  # `info!(lsa_type, link_state_id, advertising_router, refreshed, "ospf lsa
  # originated")` call site, same as `cmd_check_asbr`'s own check.
  log "waiting for router-b to originate a real type-3 summary-lsa for $OSPF_ABR_LOOPBACK_ADDRESS (real abr behavior)"
  wait_for_count_increase router-b "ospf lsa originated.*lsa_type=3" "$originated_before" 60 \
    && log "router-b: originated a type-3 summary-lsa" \
    || { log "router-b: FAILED to originate a type-3 summary-lsa"; return 1; }

  log "waiting for router-a to learn router-b's type-3 summary-lsa into its own (backbone-only) lsdb"
  wait_for_count_increase router-a "ospf lsa installed.*lsa_type=3" "$installed_before" 60 \
    && log "router-a: installed router-b's type-3 summary-lsa" \
    || { log "router-a: FAILED to learn the type-3 summary-lsa"; return 1; }

  # $OSPF_ABR_LOOPBACK_ADDRESS is a fresh prefix never installed by any
  # earlier phase, so (unlike a generic pre-count) a literal `0` baseline is
  # correct here -- same as `cmd_check_ospf_spf`'s own check, and the same
  # `add_route`/`Option<RouteSource>` rendering quirk as its and
  # `cmd_check_asbr`'s checks.
  log "waiting for router-a to compute (via ospf spf) and install a real kernel route to $OSPF_ABR_LOOPBACK_ADDRESS -- a prefix not in router-a's own area"
  wait_for_count_increase router-a "added route prefix=$OSPF_ABR_LOOPBACK_ADDRESS.*source=Some(Ospf)" 0 60 \
    && log "router-a: installed the abr-summarized route into the real kernel routing table" \
    || { log "router-a: FAILED to install the abr-summarized route"; return 1; }
}

# --- Multi-router OSPF DR/BDR scenario (Stage 5) ---
#
# Adds a third router ("router-c") onto the same bd-ospf broadcast segment
# `cmd_check_ospf` already established between router-a/router-b -- assumes
# that phase has already run in this invocation (`up && established && ospf`
# first, per this file's own header comment). router-c's OSPF router-id
# ($OSPF_ROUTER_ID_C) is deliberately lower than both router-a's and
# router-b's, so RFC 2328 §9.4's incumbent-stickiness keeps router-b DR and
# router-a Backup unchanged -- router-c simply becomes DrOther. This proves
# both the election's stability property (a new, lower-id candidate never
# displaces an already-elected DR/BDR) and RFC 2328 §8's restriction that a
# DrOther still forms a real Full adjacency with the DR and the BDR (never
# with another DrOther, which is the negative half -- not proven here, see
# `link::should_form_adjacency`'s own unit test for that; a real end-to-end
# proof of the negative half needs a fourth router, out of scope for now).
cmd_check_ospf_dr() {
  start_router router-c "$IP_C"
  wait_for_config_socket router-c
  provision_ospf_instance_only router-c "$ASN_C" "$RID_C" "$IP_C" "$IP_A" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID_C"
  provision_ospf_broadcast router-c "$ASN_C" "$RID_C" "$IP_C" "$IP_A" "$OSPF_BROADCAST_ADDRESS_C"

  log "waiting for router-c to reach ospf 2-way with router-a and router-b on the broadcast link"
  wait_for_count_increase router-c "ospf neighbor reached two-way link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-c: reached ospf 2-way with $OSPF_ROUTER_ID (router-a)" \
    || { log "router-c: FAILED to reach ospf 2-way with router-a"; return 1; }
  wait_for_count_increase router-c "ospf neighbor reached two-way link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-c: reached ospf 2-way with $OSPF_ROUTER_ID_B (router-b)" \
    || { log "router-c: FAILED to reach ospf 2-way with router-b"; return 1; }

  # The positive half of RFC 2328 §9.4's stability property: router-b/
  # router-a's incumbent DR/Backup roles are unchanged (no new "became dr"/
  # "became backup" log line fires for them -- nothing to wait for), while
  # router-c, the new lower-id arrival, settles at DrOther.
  log "waiting for router-c to settle as dr-other (router-b stays dr, router-a stays backup)"
  wait_for_count_increase router-c "ospf interface became dr-other link=broadcast-domain:$OSPF_BROADCAST_DOMAIN dr=$OSPF_ROUTER_ID_B bdr=$OSPF_ROUTER_ID" 0 60 \
    && log "router-c: became dr-other" \
    || { log "router-c: FAILED to become dr-other"; return 1; }

  # RFC 2328 §8's positive half: a DrOther still forms a real Full adjacency
  # with both the DR and the BDR.
  log "waiting for router-c to reach ospf full with both router-a and router-b"
  wait_for_count_increase router-c "ospf neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-c: reached ospf full with $OSPF_ROUTER_ID (router-a, backup)" \
    || { log "router-c: FAILED to reach ospf full with router-a"; return 1; }
  wait_for_count_increase router-c "ospf neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-c: reached ospf full with $OSPF_ROUTER_ID_B (router-b, dr)" \
    || { log "router-c: FAILED to reach ospf full with router-b"; return 1; }
  wait_for_count_increase router-a "ospf neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID_C" 0 60 \
    && log "router-a: reached ospf full with $OSPF_ROUTER_ID_C (router-c, dr-other)" \
    || { log "router-a: FAILED to reach ospf full with router-c"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached full link=broadcast-domain:$OSPF_BROADCAST_DOMAIN neighbor=$OSPF_ROUTER_ID_C" 0 60 \
    && log "router-b: reached ospf full with $OSPF_ROUTER_ID_C (router-c, dr-other)" \
    || { log "router-b: FAILED to reach ospf full with router-c"; return 1; }
}

# --- OSPF LSA aging/refresh/flush scenario (RFC 2328 §14) ---
#
# Self-contained (own router-a/router-b, not chained onto `ospf`/`ospf-dr`/
# `ospf-spf`'s containers), since it needs both routers' nos-ospfd launched
# with a real --lsa-age-multiplier from process start (`--ospfd-arg`,
# forwarded straight through by nos-watchdogd, see root CLAUDE.md's
# "Process supervision") -- an already-running container can't have that
# retro-fitted onto it. $OSPF_AGE_MULTIPLIER scales the per-second age clock
# so LSRefreshTime (1800s) and MaxAge (3600s) resolve in ~10s/~20s instead of
# 30/60 real minutes.
cmd_up_ospf_aging() {
  ensure_env_up
  start_router router-a "$IP_A" --ospfd-arg "--lsa-age-multiplier=$OSPF_AGE_MULTIPLIER"
  start_router router-b "$IP_B" --ospfd-arg "--lsa-age-multiplier=$OSPF_AGE_MULTIPLIER"
  wait_for_config_socket router-a
  wait_for_config_socket router-b
  provision_ospf router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID"
  provision_ospf router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID_B"
}

cmd_check_ospf_aging() {
  cmd_up_ospf_aging

  log "waiting for router-a/router-b to reach ospf full on the point-to-point link"
  wait_for_count_increase router-a "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospf full with $OSPF_ROUTER_ID_B" \
    || { log "router-a: FAILED to reach ospf full"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: reached ospf full with $OSPF_ROUTER_ID" \
    || { log "router-b: FAILED to reach ospf full"; return 1; }

  # router-a's own Router-LSA content never changes on this link, so a
  # bumped sequence number with refreshed=true can only come from the
  # RFC 2328 §14 age-based refresh path, not the content-diff path.
  log "waiting for router-a to self-refresh its router-lsa purely due to elapsed age (content unchanged)"
  wait_for_count_increase router-a "ospf lsa originated.*advertising_router=$OSPF_ROUTER_ID.*refreshed=true" 0 45 \
    && log "router-a: refreshed its own router-lsa at LSRefreshTime" \
    || { log "router-a: FAILED to age-refresh its own router-lsa"; return 1; }

  log "waiting for router-b to install the refreshed (higher sequence number) instance"
  wait_for_count_increase router-b "ospf lsa installed.*advertising_router=$OSPF_ROUTER_ID" 0 20 \
    && log "router-b: installed router-a's refreshed router-lsa" \
    || { log "router-b: FAILED to install the refreshed router-lsa"; return 1; }

  # Stop router-a's nos-ospfd so it stops refreshing -- router-b's own held
  # copy must then age out and evict purely on its own local clock, with no
  # further packets from router-a needed at all.
  log "killing router-a's nos-ospfd to stop further refreshes"
  kill_process_by_name router-a nos-ospfd

  log "waiting for router-b to flush router-a's now-stale router-lsa at maxage"
  wait_for_count_increase router-b "ospf lsa maxage flushed.*advertising_router=$OSPF_ROUTER_ID" 0 45 \
    && log "router-b: flushed router-a's router-lsa at maxage" \
    || { log "router-b: FAILED to flush the stale router-lsa"; return 1; }
}

# --- OSPF DBD pagination scenario (RFC 2328 §10.8) ---
#
# Self-contained (own router-a/router-b, not chained onto `ospf`'s
# containers), since it needs both routers' nos-ospfd launched with a real
# --dbd-max-headers from process start (`--ospfd-arg`, forwarded straight
# through by nos-watchdogd, see root CLAUDE.md's "Process supervision") --
# an already-running container can't have that retro-fitted onto it. A cap
# of 1 forces multiple DBD rounds even over this script's small lab LSDB
# (a handful of Router-LSAs), no extra LSAs need provisioning.
cmd_up_ospf_dbd_pagination() {
  ensure_env_up
  start_router router-a "$IP_A" --ospfd-arg "--dbd-max-headers=1"
  start_router router-b "$IP_B" --ospfd-arg "--dbd-max-headers=1"
  wait_for_config_socket router-a
  wait_for_config_socket router-b
  # router-a also redistributes a static route into ospf (the same
  # provisioning `asbr` uses), purely to give it two distinct LSAs
  # (its own Router-LSA plus a self-originated Type-5) already installed
  # before the adjacency's DBD exchange even starts -- with a single-LSA
  # summary, --dbd-max-headers=1 still fits in one chunk and never
  # actually paginates.
  provision_asbr router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID"
  provision_ospf router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID_B"
}

cmd_check_ospf_dbd_pagination() {
  cmd_up_ospf_dbd_pagination

  # Proves pagination actually triggered (not just that the flag was
  # accepted) -- the log line link.rs's `execute_actions` emits for every
  # non-negotiation DBD chunk with `more: true` still set.
  log "waiting for a real multi-packet dbd chunk to be sent"
  if wait_for_count_increase router-a "ospf dbd chunk sent, more remaining" 0 60 \
      || wait_for_count_increase router-b "ospf dbd chunk sent, more remaining" 0 60; then
    log "pagination triggered: a dbd chunk with more remaining was sent"
  else
    log "FAILED: no paginated dbd chunk was ever sent"
    return 1
  fi

  log "waiting for router-a/router-b to still reach ospf full despite pagination"
  wait_for_count_increase router-a "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospf full with $OSPF_ROUTER_ID_B" \
    || { log "router-a: FAILED to reach ospf full"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: reached ospf full with $OSPF_ROUTER_ID" \
    || { log "router-b: FAILED to reach ospf full"; return 1; }
}

# --- OSPF MTU-driven DBD pagination scenario ---
#
# Self-contained (own router-a/router-b), like `ospf-dbd-pagination`, but
# launched with NO --dbd-max-headers CLI flag at all -- proving real DBD
# pagination driven purely by a real OspfProfile.mtu override
# ($OSPF_MTU_VALUE, the RFC 791 minimum), via `exchange::
# mtu_based_max_headers`, rather than the test-only CLI override. router-a
# also redistributes a static route into ospf (`provision_asbr_mtu`, the same
# provisioning `ospf-dbd-pagination` uses via `provision_asbr`), purely to
# give it two distinct LSAs already installed before the DBD exchange
# starts, since a single-LSA summary still fits in one chunk even at
# max_headers=1 -- see ospf/CLAUDE.md's "Exchange".
cmd_up_ospf_mtu_pagination() {
  ensure_env_up
  start_router router-a "$IP_A"
  start_router router-b "$IP_B"
  wait_for_config_socket router-a
  wait_for_config_socket router-b
  provision_asbr_mtu router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID"
  provision_ospf_mtu router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A" "$OSPF_INSTANCE" "$OSPF_ROUTER_ID_B"
}

cmd_check_ospf_mtu_pagination() {
  cmd_up_ospf_mtu_pagination

  log "waiting for router-a to apply its own eth0 profile mtu (no --dbd-max-headers flag involved)"
  wait_for_count_increase router-a "ospf profile resolved instance=$OSPF_INSTANCE" 0 60 \
    && log "router-a: resolved its ospf profile" \
    || { log "router-a: FAILED to resolve its ospf profile"; return 1; }

  # Same anchor `ospf-dbd-pagination` checks -- but this time nothing on
  # either process's command line forced pagination; it can only have come
  # from the real OspfProfile.mtu override resolving to a tiny max_headers.
  log "waiting for a real multi-packet dbd chunk to be sent, driven purely by the mtu override"
  if wait_for_count_increase router-a "ospf dbd chunk sent, more remaining" 0 60 \
      || wait_for_count_increase router-b "ospf dbd chunk sent, more remaining" 0 60; then
    log "pagination triggered by mtu override: a dbd chunk with more remaining was sent"
  else
    log "FAILED: no paginated dbd chunk was ever sent"
    return 1
  fi

  log "waiting for router-a/router-b to still reach ospf full despite mtu-driven pagination"
  wait_for_count_increase router-a "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID_B" 0 60 \
    && log "router-a: reached ospf full with $OSPF_ROUTER_ID_B" \
    || { log "router-a: FAILED to reach ospf full"; return 1; }
  wait_for_count_increase router-b "ospf neighbor reached full link=eth0.0 neighbor=$OSPF_ROUTER_ID" 0 60 \
    && log "router-b: reached ospf full with $OSPF_ROUTER_ID" \
    || { log "router-b: FAILED to reach ospf full"; return 1; }
}

cmd_check_switching() {
  provision_switching router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  log "waiting for router-a to create bridges for bd1 and bd2"
  wait_for_count_increase router-a "created broadcast domain bridge domain=bd1 bridge=br1" 0 60 \
    && log "router-a: created br1 for bd1" \
    || { log "router-a: FAILED to create br1"; return 1; }
  wait_for_count_increase router-a "created broadcast domain bridge domain=bd2 bridge=br2" 0 60 \
    && log "router-a: created br2 for bd2" \
    || { log "router-a: FAILED to create br2"; return 1; }

  log "waiting for router-a to create eth0's 802.1q sub-interfaces"
  wait_for_count_increase router-a "created vlan sub-interface interface=eth0 sub_interface=eth0.100 tag=100" 0 60 \
    && log "router-a: created eth0.100" \
    || { log "router-a: FAILED to create eth0.100"; return 1; }
  wait_for_count_increase router-a "created vlan sub-interface interface=eth0 sub_interface=eth0.200 tag=200" 0 60 \
    && log "router-a: created eth0.200" \
    || { log "router-a: FAILED to create eth0.200"; return 1; }

  log "waiting for router-a to enslave each sub-interface into its own domain's bridge"
  wait_for_count_increase router-a "enslaved interface to bridge interface=eth0.100 bridge=br1" 0 60 \
    && log "router-a: enslaved eth0.100 into br1" \
    || { log "router-a: FAILED to enslave eth0.100"; return 1; }
  wait_for_count_increase router-a "enslaved interface to bridge interface=eth0.200 bridge=br2" 0 60 \
    && log "router-a: enslaved eth0.200 into br2" \
    || { log "router-a: FAILED to enslave eth0.200"; return 1; }

  log "clearing router-a's interface switching-profile assignment"
  provision_clear_switching_profile router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  log "waiting for router-a to delete eth0's 802.1q sub-interfaces"
  wait_for_count_increase router-a "deleted vlan sub-interface interface=eth0 sub_interface=eth0.100" 0 60 \
    && log "router-a: deleted eth0.100" \
    || { log "router-a: FAILED to delete eth0.100"; return 1; }
  wait_for_count_increase router-a "deleted vlan sub-interface interface=eth0 sub_interface=eth0.200" 0 60 \
    && log "router-a: deleted eth0.200" \
    || { log "router-a: FAILED to delete eth0.200"; return 1; }
}

cmd_check_svi() {
  provision_svi router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$SVI_ADDRESS"

  # Unlike rt1's kernel table id (always 100, since it's the only routing
  # table any scenario configures), bd-svi's bridge id depends on how many
  # other broadcast domains this container has already allocated one for
  # before this phase ran (e.g. bd1/bd2 if `switching` ran first as part of
  # `all`, or none at all if `svi` is run standalone right after
  # `established`) — so its bridge name isn't known ahead of time and is
  # extracted from the log line the driver itself just emitted instead.
  log "waiting for router-a to create bd-svi's bridge"
  wait_for_count_increase router-a "created broadcast domain bridge domain=bd-svi" 0 60 \
    || { log "router-a: FAILED to create bd-svi's bridge"; return 1; }
  local svi_bridge
  svi_bridge=$(docker logs router-a 2>&1 \
    | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
    | grep -o "created broadcast domain bridge domain=bd-svi bridge=br[0-9]*" \
    | tail -1 | grep -o 'br[0-9]*$')
  log "router-a: created $svi_bridge for bd-svi"

  log "waiting for router-a to enslave $svi_bridge into rt1's vrf"
  wait_for_count_increase router-a "enslaved interface to vrf interface=$svi_bridge" 0 60 \
    && log "router-a: enslaved $svi_bridge into its vrf" \
    || { log "router-a: FAILED to enslave $svi_bridge"; return 1; }

  log "waiting for router-a to apply $SVI_ADDRESS to $svi_bridge"
  wait_for_count_increase router-a "added interface address interface=$svi_bridge address=$SVI_ADDRESS" 0 60 \
    && log "router-a: applied $SVI_ADDRESS to $svi_bridge" \
    || { log "router-a: FAILED to apply the svi address"; return 1; }

  log "deleting router-a's bd-svi broadcast domain"
  provision_delete_svi router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  log "waiting for router-a to delete $svi_bridge"
  wait_for_count_increase router-a "deleted broadcast domain bridge domain=bd-svi bridge=$svi_bridge" 0 60 \
    && log "router-a: deleted $svi_bridge" \
    || { log "router-a: FAILED to delete $svi_bridge"; return 1; }
}

cmd_check_routed_subinterface() {
  provision_routed_subinterface router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  log "waiting for router-a to create eth0's routed subinterface (eth0.$SUBINTERFACE_TAG)"
  wait_for_count_increase router-a "created vlan sub-interface interface=eth0 sub_interface=eth0.$SUBINTERFACE_TAG tag=$SUBINTERFACE_TAG" 0 60 \
    && log "router-a: created eth0.$SUBINTERFACE_TAG" \
    || { log "router-a: FAILED to create eth0.$SUBINTERFACE_TAG"; return 1; }

  log "waiting for router-a to enslave eth0.$SUBINTERFACE_TAG into rt1's vrf (the same vrf eth0 itself is already a member of)"
  wait_for_count_increase router-a "enslaved interface to vrf interface=eth0.$SUBINTERFACE_TAG" 0 60 \
    && log "router-a: enslaved eth0.$SUBINTERFACE_TAG into its vrf" \
    || { log "router-a: FAILED to enslave eth0.$SUBINTERFACE_TAG"; return 1; }

  log "waiting for router-a to apply $SUBINTERFACE_ADDRESS to eth0.$SUBINTERFACE_TAG"
  wait_for_count_increase router-a "added interface address interface=eth0.$SUBINTERFACE_TAG address=$SUBINTERFACE_ADDRESS" 0 60 \
    && log "router-a: applied $SUBINTERFACE_ADDRESS to eth0.$SUBINTERFACE_TAG" \
    || { log "router-a: FAILED to apply the subinterface address"; return 1; }

  log "removing router-a's routed subinterface"
  provision_delete_routed_subinterface router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  log "waiting for router-a to delete eth0.$SUBINTERFACE_TAG"
  wait_for_count_increase router-a "deleted vlan sub-interface interface=eth0 sub_interface=eth0.$SUBINTERFACE_TAG" 0 60 \
    && log "router-a: deleted eth0.$SUBINTERFACE_TAG" \
    || { log "router-a: FAILED to delete eth0.$SUBINTERFACE_TAG"; return 1; }
}

# --- Peer-group source-address scenario ---
#
# Verifies BgpPeerGroup.source_address is resolved by nos-bgpd itself, over a
# real IPC round trip to nos-interfaced (via the watchdog broker), from an
# interface name (+ optional label) rather than a literal address -- and
# that `source-address loopback` derives its target interface
# (`loopback-rt1`) purely from the owning bgp instance's own routing table,
# with no routing-table name given at all. Self-contained: creates and
# removes its own loopback interface rather than depending on the (already
# torn down) `loopback` scenario above.

cmd_check_source_address() {
  log "pointing router-a's peer-group source-address at interface eth0 (its own already-established address, $IP_A)"
  provision_source_address_interface router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  wait_for_count_increase router-a "resolved peer-group source-address peer_group=pg1 addresses=\[$IP_A\]" 0 60 \
    && log "router-a: resolved source-address to interface eth0's own address ($IP_A)" \
    || { log "router-a: FAILED to resolve interface-based source-address"; return 1; }
  log "confirming the session still establishes bound to the explicit interface source-address"
  wait_for_log router-a "bgp session established" 60 \
    && log "router-a: established with interface source-address" \
    || { log "router-a: FAILED to establish with interface source-address"; return 1; }
  wait_for_log router-b "bgp session established" 60 \
    && log "router-b: established" \
    || { log "router-b: FAILED to establish"; return 1; }

  log "adding a loopback interface to router-a's routing table (rt1) for the loopback source-address check"
  provision_loopback router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B" "$LOOPBACK_ADDRESS"
  wait_for_count_increase router-a "added interface address interface=loopback-rt1 address=$LOOPBACK_ADDRESS" 0 60 \
    && log "router-a: loopback-rt1 addressed" \
    || { log "router-a: FAILED to address loopback-rt1"; return 1; }

  log "pointing router-a's peer-group source-address at 'loopback' -- no routing-table name given, derived from its own bgp instance's routing table (rt1)"
  provision_source_address_loopback router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  local loopback_ip=${LOOPBACK_ADDRESS%/*}
  wait_for_count_increase router-a "resolved peer-group source-address peer_group=pg1 addresses=\[$loopback_ip\]" 0 60 \
    && log "router-a: resolved 'source-address loopback' to loopback-rt1's own address ($loopback_ip), with no routing-table name given" \
    || { log "router-a: FAILED to resolve 'source-address loopback'"; return 1; }

  log "reverting router-a's peer-group source-address and removing the loopback interface"
  provision_clear_source_address router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  provision_delete_loopback router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  wait_for_log router-a "bgp session established" 60 \
    && log "router-a: still established after reverting source-address" \
    || { log "router-a: FAILED to remain established after reverting source-address"; return 1; }
}

# --- RPL import policy scenario ---
#
# Reuses the same two-router topology and the same $REDISTRIBUTE_PREFIX as
# the `redistribute` scenario: router-a redistributes it as usual, but
# router-b's peer-group gets a real compiled RPL policy
# (`reject-redistribute-prefix`) as its import policy instead of the default
# `accept-all` every other scenario uses. Verifies the policy hook actually
# runs against a real received UPDATE over a real kernel socket, not just in
# unit tests.

provision_policy_reject() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  # Not under target/docker-verify/: that tree is root-owned (created by the
  # containerized `cargo build` in build_provision_tool), so this host shell
  # can't write into it.
  local policy_file
  policy_file=$(mktemp /tmp/nos-verify-policy-XXXXXX.rpl)
  # `nos-provision` runs as the container's unprivileged `nos` user, a
  # different uid than this host shell — mktemp's default 0600 would leave
  # it unreadable through the bind mount.
  chmod 644 "$policy_file"
  cat >"$policy_file" <<EOF
if this.prefix in $REDISTRIBUTE_PREFIX:
    reject
else:
    accept
EOF
  log "provisioning $name with an import policy rejecting $REDISTRIBUTE_PREFIX"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "$policy_file:/tmp/reject-redistribute-prefix.rpl:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --policy-name reject-redistribute-prefix \
    --policy-source-file /tmp/reject-redistribute-prefix.rpl \
    --import-policy reject-redistribute-prefix
  rm -f "$policy_file"
}

# Counts (not just checks presence of) "learned route ... into adj-rib-in"
# for $REDISTRIBUTE_PREFIX — this scenario runs against the same long-lived
# containers other phases (`redistribute`) already ran against, so a bare
# presence check would false-positive on a stale line from an earlier phase.
# Mirrors `established_count`'s same before/after-count technique, used by
# `cmd_check_auth` for exactly this reason.
learned_prefix_count() {
  local name=$1
  docker logs "$name" 2>&1 | grep -c "learned route for $REDISTRIBUTE_PREFIX into adj-rib-in" || true
}

cmd_check_policy() {
  local before_reject
  before_reject=$(learned_prefix_count router-b)

  provision_policy_reject router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A"
  log "waiting for both sides to (re-)establish after router-b's import-policy change"
  wait_for_log router-a "bgp session established" 60 \
    && log "router-a: established" \
    || { log "router-a: FAILED to establish"; return 1; }
  wait_for_log router-b "bgp session established" 60 \
    && log "router-b: established" \
    || { log "router-b: FAILED to establish"; return 1; }

  provision_redistribute router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  log "waiting for router-a to redistribute $REDISTRIBUTE_PREFIX into its bgp instance"
  wait_for_log router-a "loc-rib best path for $REDISTRIBUTE_PREFIX updated" 60 \
    && log "router-a: installed redistributed static route into its own loc-rib" \
    || { log "router-a: FAILED to install redistributed route locally"; return 1; }

  log "waiting 6s to confirm router-b's import policy rejects $REDISTRIBUTE_PREFIX (does not re-enter adj-rib-in)"
  sleep 6
  local after_reject
  after_reject=$(learned_prefix_count router-b)
  if [[ "$after_reject" -gt "$before_reject" ]]; then
    log "FAILED: router-b learned $REDISTRIBUTE_PREFIX despite its import policy rejecting it"
    return 1
  fi
  log "confirmed: router-b's import policy rejected $REDISTRIBUTE_PREFIX -- it did not re-enter adj-rib-in"

  log "reverting router-b's import policy to the accept-all default"
  provision router-b "$ASN_B" "$RID_B" "$IP_B" "$IP_A"
  local ok=1
  for _ in $(seq 1 60); do
    if [[ "$(learned_prefix_count router-b)" -gt "$after_reject" ]]; then
      ok=0
      break
    fi
    sleep 1
  done
  if [[ $ok -eq 0 ]]; then
    log "router-b: learned $REDISTRIBUTE_PREFIX once its import policy reverted to accept-all"
  else
    log "router-b: FAILED to learn $REDISTRIBUTE_PREFIX after reverting the import policy"
    return 1
  fi
}

# --- RPL redistribute-policy scenario ---
#
# Reuses the same two-router topology and $REDISTRIBUTE_PREFIX as the
# `redistribute`/`policy` scenarios, but the RPL policy is attached directly
# to router-a's `redistribute from static to bgp` rule (`policy <name>`)
# instead of to a peer-group's import/export policy. Verifies filtering
# happens at the redistribution point itself: a rejecting policy here must
# keep the prefix out of router-a's own loc-rib entirely, not just out of
# router-b's adj-rib-in.

provision_redistribute_policy() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  local policy_file
  policy_file=$(mktemp /tmp/nos-verify-policy-XXXXXX.rpl)
  chmod 644 "$policy_file"
  cat >"$policy_file" <<EOF
if this.prefix in $REDISTRIBUTE_PREFIX:
    reject
else:
    accept
EOF
  log "provisioning $name with a redistribute policy rejecting $REDISTRIBUTE_PREFIX at the source"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "$policy_file:/tmp/reject-at-redistribute.rpl:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --static-route "$REDISTRIBUTE_PREFIX" \
    --static-gateway "$REDISTRIBUTE_GATEWAY" \
    --redistribute \
    --policy-name reject-at-redistribute \
    --policy-source-file /tmp/reject-at-redistribute.rpl \
    --redistribute-policy reject-at-redistribute
  rm -f "$policy_file"
}

# Counts (not just checks presence of) "loc-rib best path for
# $REDISTRIBUTE_PREFIX updated" for $name — mirrors `learned_prefix_count`'s
# same before/after-count technique, needed for the same reason: this
# scenario can run against containers other phases already touched.
loc_rib_prefix_count() {
  local name=$1
  docker logs "$name" 2>&1 | grep -c "loc-rib best path for $REDISTRIBUTE_PREFIX updated" || true
}

cmd_check_redistribute_policy() {
  local before_a before_b
  before_a=$(loc_rib_prefix_count router-a)
  before_b=$(learned_prefix_count router-b)

  provision_redistribute_policy router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  log "waiting 6s to confirm router-a's redistribute policy filters $REDISTRIBUTE_PREFIX before it reaches router-a's own loc-rib"
  sleep 6
  local after_a
  after_a=$(loc_rib_prefix_count router-a)
  if [[ "$after_a" -gt "$before_a" ]]; then
    log "FAILED: router-a installed $REDISTRIBUTE_PREFIX into its own loc-rib despite its redistribute policy rejecting it"
    return 1
  fi
  local after_b
  after_b=$(learned_prefix_count router-b)
  if [[ "$after_b" -gt "$before_b" ]]; then
    log "FAILED: router-b learned $REDISTRIBUTE_PREFIX despite router-a's redistribute policy rejecting it at the source"
    return 1
  fi
  log "confirmed: router-a's redistribute policy rejected $REDISTRIBUTE_PREFIX at the source -- it never entered router-a's loc-rib or router-b's adj-rib-in"

  log "reverting router-a's redistribute rule to the accept-all default (no policy)"
  provision_redistribute router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"
  local ok=1
  for _ in $(seq 1 60); do
    if [[ "$(loc_rib_prefix_count router-a)" -gt "$after_a" ]]; then
      ok=0
      break
    fi
    sleep 1
  done
  if [[ $ok -eq 0 ]]; then
    log "router-a: installed $REDISTRIBUTE_PREFIX into its own loc-rib once its redistribute policy reverted to accept-all"
  else
    log "router-a: FAILED to install $REDISTRIBUTE_PREFIX after reverting the redistribute policy"
    return 1
  fi

  ok=1
  for _ in $(seq 1 60); do
    if [[ "$(learned_prefix_count router-b)" -gt "$after_b" ]]; then
      ok=0
      break
    fi
    sleep 1
  done
  if [[ $ok -eq 0 ]]; then
    log "router-b: learned $REDISTRIBUTE_PREFIX once router-a's redistribute policy reverted to accept-all"
  else
    log "router-b: FAILED to learn $REDISTRIBUTE_PREFIX after router-a reverted its redistribute policy"
    return 1
  fi
}

# --- RPL community scenario ---
#
# Reuses the same two-router topology and $REDISTRIBUTE_PREFIX as the
# `redistribute`/`policy` scenarios, but router-a's peer-group toward
# router-b gets a real compiled RPL export policy
# (`tag-redistribute-with-community`) that runs `this.bgp.communities.add(..)`
# instead of the default `accept-all`. Verifies a real RFC 1997 COMMUNITY
# value survives RPL mutation -> wire encoding -> the kernel-real two-
# container path -> wire decoding -> router-b's loc-rib, not just unit tests.
COMMUNITY_AA=65001
COMMUNITY_NN=100
COMMUNITY_PACKED=$(( (COMMUNITY_AA << 16) | COMMUNITY_NN ))

provision_communities_export() {
  local name=$1 asn=$2 router_id=$3 own_ip=$4 peer_ip=$5
  local policy_file
  policy_file=$(mktemp /tmp/nos-verify-policy-XXXXXX.rpl)
  chmod 644 "$policy_file"
  cat >"$policy_file" <<EOF
this.bgp.communities.add($COMMUNITY_AA:$COMMUNITY_NN)
accept
EOF
  log "provisioning $name with an export policy tagging $REDISTRIBUTE_PREFIX with community $COMMUNITY_AA:$COMMUNITY_NN"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "$policy_file:/tmp/tag-redistribute-with-community.rpl:ro,z" \
    -v "${name}-run:/run/nos" \
    "$IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "${own_ip}/24" \
    --asn "$asn" \
    --router-id "$router_id" \
    --remote-as "$( [[ $asn == "$ASN_A" ]] && echo "$ASN_B" || echo "$ASN_A" )" \
    --peer "$peer_ip" \
    --static-route "$REDISTRIBUTE_PREFIX" \
    --static-gateway "$REDISTRIBUTE_GATEWAY" \
    --redistribute \
    --policy-name tag-redistribute-with-community \
    --policy-source-file /tmp/tag-redistribute-with-community.rpl \
    --export-policy tag-redistribute-with-community
  rm -f "$policy_file"
}

cmd_check_communities() {
  local before_a before_b before_listener_a before_listener_b before_local_a
  before_a=$(established_count router-a)
  before_b=$(established_count router-b)
  before_listener_a=$(docker logs router-a 2>&1 | grep -c "bgp listener bound" || true)
  before_listener_b=$(docker logs router-b 2>&1 | grep -c "bgp listener bound" || true)
  # Captured here, before any restart, not after: nos-ribd's restart-
  # triggered resend (see the kill step below) can land within ~100ms of
  # nos-bgpd's listener coming back up, well before this function would
  # otherwise get around to checking -- a baseline taken after the restart
  # can already include that one push, leaving nothing left to wait for.
  before_local_a=$(docker logs router-a 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -c "loc-rib best path for $REDISTRIBUTE_PREFIX updated origin=Local" || true)

  # Restart both sides *before* applying the new export policy, not after.
  # A policy change alone can lose RFC 4271 §6.8 collision resolution against
  # whichever side already has an Established session from an earlier phase
  # -- an existing connection always beats a later collision (see
  # bgp/CLAUDE.md's "Collision resolution") -- and which side that is is
  # non-deterministic this late in the sequence. Restarting both processes
  # first means neither side has anything left to collide against by the
  # time the new policy is applied.
  # Also kill router-a's nos-ribd (a separate process in the same
  # container, owning redistribution -- see root CLAUDE.md's "Process
  # supervision"): nos-ribd's push connection to nos-bgpd is write-only and
  # fire-and-forget, so it has no passive way to notice the old nos-bgpd
  # process died (see rib/src/bgp_client.rs's "a fresh connection always
  # gets a complete update" -- that's the operative word, *connection*, not
  # *config change*). Without this, nos-ribd would only rediscover the dead
  # connection on its next write attempt, which never comes unless the
  # redistributed route set itself changes -- leaving router-a's freshly
  # restarted nos-bgpd permanently missing the route it's supposed to
  # advertise. Killing nos-ribd too forces a brand new connection on its
  # own restart, which unconditionally re-sends the full snapshot.
  log "restarting both sides' nos-bgpd (and router-a's nos-ribd) for a clean baseline"
  kill_process_by_name router-a nos-bgpd
  kill_process_by_name router-a nos-ribd
  kill_process_by_name router-b nos-bgpd
  wait_for_count_increase router-a "bgp listener bound" "$before_listener_a" 60 \
    && log "router-a: nos-bgpd back up" \
    || { log "router-a: FAILED to come back up"; return 1; }
  wait_for_count_increase router-b "bgp listener bound" "$before_listener_b" 60 \
    && log "router-b: nos-bgpd back up" \
    || { log "router-b: FAILED to come back up"; return 1; }

  # Only now apply the new export policy: router-a's fresh process resolves
  # it straight from its own startup config fetch, with no established
  # session yet for a config-diff-triggered restart to race against.
  provision_communities_export router-a "$ASN_A" "$RID_A" "$IP_A" "$IP_B"

  log "waiting for router-a to learn the redistributed route from nos-ribd"
  wait_for_count_increase router-a "loc-rib best path for $REDISTRIBUTE_PREFIX updated origin=Local" "$before_local_a" 60 \
    && log "router-a: learned $REDISTRIBUTE_PREFIX from nos-ribd" \
    || { log "router-a: FAILED to learn $REDISTRIBUTE_PREFIX from nos-ribd"; return 1; }

  log "waiting for both sides to establish with router-a's new export policy"
  wait_for_count_increase router-a "bgp session established" "$before_a" 60 \
    && log "router-a: established" \
    || { log "router-a: FAILED to establish"; return 1; }
  wait_for_count_increase router-b "bgp session established" "$before_b" 60 \
    && log "router-b: established" \
    || { log "router-b: FAILED to establish"; return 1; }

  # Both sides' processes just restarted, so router-b's own loc-rib for this
  # prefix was wiped along with everything else -- this line is guaranteed
  # to be a genuinely fresh occurrence, not a stale one from an earlier phase.
  log "waiting for router-b to have $REDISTRIBUTE_PREFIX with community $COMMUNITY_AA:$COMMUNITY_NN in loc-rib"
  wait_for_log router-b "loc-rib best path for $REDISTRIBUTE_PREFIX updated" 60 \
    && log "router-b: has $REDISTRIBUTE_PREFIX installed" \
    || { log "router-b: FAILED to install $REDISTRIBUTE_PREFIX"; return 1; }

  local logs_b line
  # Same ANSI-stripping as the route-server scenario's as_path check.
  logs_b=$(docker logs router-b 2>&1 | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g') || true
  line=$(grep "loc-rib best path for $REDISTRIBUTE_PREFIX updated" <<<"$logs_b" | tail -n1) || true
  if [[ -n "$line" ]] && grep -q "communities=\[$COMMUNITY_PACKED\]" <<<"$line"; then
    log "router-b: learned route carries the RPL-tagged community $COMMUNITY_AA:$COMMUNITY_NN (packed=$COMMUNITY_PACKED)"
  else
    log "router-b: FAILED -- expected communities=[$COMMUNITY_PACKED] in: $line"
    return 1
  fi
}

cmd_logs() {
  echo "===== router-a ====="
  docker logs router-a 2>&1 | tail -n "${1:-200}"
  echo "===== router-b ====="
  docker logs router-b 2>&1 | tail -n "${1:-200}"
  if docker inspect router-c >/dev/null 2>&1; then
    echo "===== router-c ====="
    docker logs router-c 2>&1 | tail -n "${1:-200}"
  fi
}

cmd_down() {
  docker rm -f router-a router-b router-c >/dev/null 2>&1 || true
  docker volume rm router-a-run router-a-data router-b-run router-b-data router-c-run router-c-data \
    >/dev/null 2>&1 || true
  docker network rm "$NET" "$NET_BOND1" "$NET_BOND2" >/dev/null 2>&1 || true
}

# --- Self-contained group subcommands ---
#
# Each bundles a set of related phases (its own `up` + checks) and tears
# itself down on exit, whether it passes or fails -- unlike `all` below, which
# leaves containers running for a human to inspect via `logs`. Meant to run as
# independent parallel CI jobs (see .github/workflows/verify-e2e.yml), each on
# its own runner/VM, so the hardcoded container names/network below never
# collide between them.

cleanup_on_exit() {
  # Set VERIFY_E2E_KEEP=1 to skip auto-teardown for local debugging (inspect
  # via `tools/verify-e2e.sh logs`, then `tools/verify-e2e.sh down` manually).
  [[ "${VERIFY_E2E_KEEP:-0}" -eq 1 ]] && return
  cmd_down
}

cmd_group_base() {
  trap cleanup_on_exit EXIT
  cmd_up
  cmd_check_established
  cmd_check_reconnect
  cmd_check_collision
  cmd_check_redistribute
  cmd_check_auth
}

cmd_group_drivers() {
  trap cleanup_on_exit EXIT
  cmd_up
  cmd_check_established
  cmd_check_loopback
  cmd_check_mtu
  cmd_check_port_aggregate
  cmd_check_lacp
  cmd_check_lldp
  cmd_check_switching
  cmd_check_svi
  cmd_check_routed_subinterface
  cmd_check_source_address
  cmd_check_rest
}

cmd_group_rpl() {
  trap cleanup_on_exit EXIT
  cmd_up
  cmd_check_established
  cmd_check_redistribute
  cmd_check_policy
  cmd_check_redistribute_policy
  cmd_check_communities
}

cmd_group_ospf_suite() {
  trap cleanup_on_exit EXIT
  cmd_up
  cmd_check_established
  cmd_check_ospf
  cmd_check_asbr
  cmd_check_ospf_dr
  cmd_check_ospf_spf
  cmd_check_abr
  cmd_check_ospf_auth
  cmd_check_ospf_aging
  cmd_check_ospf_dbd_pagination
  cmd_check_ospf_mtu_pagination
  cmd_check_ospfv3
  cmd_check_ospfv3_dr
}

cmd_group_multi() {
  trap cleanup_on_exit EXIT
  cmd_check_reflector
  cmd_check_route_server
}

case "${1:-}" in
  up) cmd_up ;;
  established) cmd_check_established ;;
  reconnect) cmd_check_reconnect ;;
  collision) cmd_check_collision ;;
  redistribute) cmd_check_redistribute ;;
  auth) cmd_check_auth ;;
  loopback) cmd_check_loopback ;;
  mtu) cmd_check_mtu ;;
  port-aggregate) cmd_check_port_aggregate ;;
  lacp) cmd_check_lacp ;;
  lldp) cmd_check_lldp ;;
  switching) cmd_check_switching ;;
  svi) cmd_check_svi ;;
  routed-subinterface) cmd_check_routed_subinterface ;;
  source-address) cmd_check_source_address ;;
  rest) cmd_check_rest ;;
  policy) cmd_check_policy ;;
  redistribute-policy) cmd_check_redistribute_policy ;;
  communities) cmd_check_communities ;;
  reflector) cmd_check_reflector ;;
  route-server) cmd_check_route_server ;;
  ospf) cmd_check_ospf ;;
  asbr) cmd_check_asbr ;;
  ospf-dr) cmd_check_ospf_dr ;;
  ospf-spf) cmd_check_ospf_spf ;;
  abr) cmd_check_abr ;;
  ospf-aging) cmd_check_ospf_aging ;;
  ospf-auth) cmd_check_ospf_auth ;;
  ospf-dbd-pagination) cmd_check_ospf_dbd_pagination ;;
  ospf-mtu-pagination) cmd_check_ospf_mtu_pagination ;;
  ospfv3) cmd_check_ospfv3 ;;
  ospfv3-dr) cmd_check_ospfv3_dr ;;
  logs) shift; cmd_logs "$@" ;;
  down) cmd_down ;;
  base) cmd_group_base ;;
  drivers) cmd_group_drivers ;;
  rpl) cmd_group_rpl ;;
  ospf-suite) cmd_group_ospf_suite ;;
  multi) cmd_group_multi ;;
  all)
    cmd_up
    cmd_check_established
    cmd_check_reconnect
    cmd_check_collision
    cmd_check_redistribute
    cmd_check_auth
    cmd_check_loopback
    cmd_check_mtu
    cmd_check_port_aggregate
    cmd_check_lacp
    cmd_check_lldp
    cmd_check_switching
    cmd_check_svi
    cmd_check_routed_subinterface
    cmd_check_source_address
    cmd_check_rest
    cmd_check_policy
    cmd_check_redistribute_policy
    cmd_check_communities
    cmd_check_reflector
    cmd_check_route_server
    cmd_check_ospf
    cmd_check_asbr
    cmd_check_ospf_dr
    cmd_check_ospf_spf
    cmd_check_abr
    cmd_check_ospf_auth
    cmd_check_ospf_aging
    cmd_check_ospf_dbd_pagination
    cmd_check_ospf_mtu_pagination
    cmd_check_ospfv3
    cmd_check_ospfv3_dr
    ;;
  *)
    echo "usage: $0 {up|established|reconnect|collision|redistribute|auth|loopback|mtu|port-aggregate|lacp|lldp|switching|svi|routed-subinterface|source-address|rest|policy|redistribute-policy|communities|reflector|route-server|ospf|asbr|ospf-dr|ospf-spf|abr|ospf-aging|ospf-auth|ospf-dbd-pagination|ospf-mtu-pagination|ospfv3|ospfv3-dr|logs [n]|down|base|drivers|rpl|ospf-suite|multi|all}" >&2
    exit 2
    ;;
esac
