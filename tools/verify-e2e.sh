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
# addressed, then deleted again on removal, (via the `switching` subcommand)
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
# nos-cli's interactive shell (reedline) can't be scripted over a plain
# pipe, so provisioning goes through `nos-provision` (tools/nos-provision) —
# a small standalone tool that speaks nos-configd's IPC protocol directly,
# reusing nos-proto's own types for wire compatibility.
#
# Usage: tools/verify-e2e.sh {up|established|reconnect|collision|redistribute|auth|loopback|switching|svi|routed-subinterface|source-address|policy|redistribute-policy|communities|reflector|route-server|ospf|ospf-dr|ospf-spf|logs [n]|down|base|drivers|rpl|ospf-suite|multi|all}
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# A separate target dir from the host's own `target/` — nos-provision must
# be built against bookworm's glibc (matching the runtime image) rather
# than whatever the host toolchain produces, and mixing the two under one
# target dir just thrashes cargo's build cache.
PROVISION_BIN="$REPO/target/docker-verify/release/nos-provision"
IMAGE=nos:local
NET=nos-verify-net
SUBNET=10.50.0.0/24
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
    log "creating network $NET ($SUBNET)"
    docker network create --subnet "$SUBNET" "$NET" >/dev/null
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
  log "starting $name at $ip"
  docker volume create "${name}-run" >/dev/null
  docker volume create "${name}-data" >/dev/null
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" \
    --network "$NET" --ip "$ip" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
    -v "${name}-run:/run/nos" \
    -v "${name}-data:/var/lib/nos" \
    "$IMAGE" >/dev/null
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
  docker network rm "$NET" >/dev/null 2>&1 || true
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
  cmd_check_switching
  cmd_check_svi
  cmd_check_routed_subinterface
  cmd_check_source_address
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
  cmd_check_ospf_dr
  cmd_check_ospf_spf
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
  switching) cmd_check_switching ;;
  svi) cmd_check_svi ;;
  routed-subinterface) cmd_check_routed_subinterface ;;
  source-address) cmd_check_source_address ;;
  policy) cmd_check_policy ;;
  redistribute-policy) cmd_check_redistribute_policy ;;
  communities) cmd_check_communities ;;
  reflector) cmd_check_reflector ;;
  route-server) cmd_check_route_server ;;
  ospf) cmd_check_ospf ;;
  ospf-dr) cmd_check_ospf_dr ;;
  ospf-spf) cmd_check_ospf_spf ;;
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
    cmd_check_switching
    cmd_check_svi
    cmd_check_routed_subinterface
    cmd_check_source_address
    cmd_check_policy
    cmd_check_redistribute_policy
    cmd_check_communities
    cmd_check_reflector
    cmd_check_route_server
    cmd_check_ospf
    cmd_check_ospf_dr
    cmd_check_ospf_spf
    ;;
  *)
    echo "usage: $0 {up|established|reconnect|collision|redistribute|auth|loopback|switching|svi|routed-subinterface|source-address|policy|redistribute-policy|communities|reflector|route-server|ospf|ospf-dr|ospf-spf|logs [n]|down|base|drivers|rpl|ospf-suite|multi|all}" >&2
    exit 2
    ;;
esac
