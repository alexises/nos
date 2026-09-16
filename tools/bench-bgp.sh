#!/usr/bin/env bash
# BGP performance benchmark: nos-bgpd vs GoBGP / BIRD / FRR.
#
# Same shape as tools/verify-bgp.sh (docker network, subcommands, everything
# observed from outside the container), but measuring instead of asserting.
# One daemon under test at a time, in a fixed three-container topology:
#
#   exabgp x PEERS (injectors)     DUT under test          gobgp (monitor)
#   10.60.0.11 .. 10.60.0.1n  ─▶  10.60.0.2  ─────────▶  10.60.0.3
#   each announces the same N       nos | gobgp |          counts the best
#   prefixes, AS 65100+k            bird | frr             paths that survive
#                                   AS 65001               AS 65200
#
# Every injector announces the same N prefixes, so the DUT holds PEERS paths
# per prefix and runs best-path selection over all of them; AS_PATH padding
# hands each peer an even share of the winning paths (peer k wins prefix i
# when i % PEERS == k-1), so convergence needs every peer's view, not one.
# With POLICY=1 (the default) each injector session also carries an import
# policy -- reject anything tagged $DROP_COMMUNITY (every DROP_EVERY-th
# prefix), set local-pref on the rest -- expressed natively per daemon: RPL
# for nos, a filter for BIRD, a route-map for FRR, a policy-definition for
# GoBGP. That is what the numbers are meant to represent: a router taking
# several full views through real policy, not one clean table.
#
# The monitor is how every daemon is measured uniformly: `nos`'s shell is
# reedline-only (no one-shot command mode) and nos-bgpd's IPC surface has no
# route counters at all, so there is no scriptable way to ask nos how many
# routes it holds. A GoBGP monitor peering the DUT counts prefixes the same
# way for all four, and measures the whole receive -> best-path ->
# re-advertise pipeline rather than just "bytes arrived".
#
# Fairness notes, because the numbers are meaningless without them:
#   * nos-bgpd never programs the kernel with BGP routes (the BGP->RIB data
#     plane is future work), so BIRD and FRR are run BGP-only -- no `protocol
#     kernel`, no zebra -- rather than being charged for netlink work nos
#     does not do.
#   * The nos container runs five daemons under the watchdog, so memory/CPU
#     is sampled per *process* (nos-bgpd only), never per container.
#   * nos is measured twice: `nos` as it ships (per-route `info!` logging in
#     bgp/src/rib.rs, plus rtnetlink TRACE dumps from the other daemons) and
#     `nos-quiet` (RUST_LOG=info,nos_bgp::rib=warn), which is the comparable
#     number -- the other three do not log per route by default.
#   * No per-daemon tuning: default timers, one peer-group per neighbour, and
#     one import policy shared by every injector session -- the same rule in
#     four syntaxes, never a different rule per daemon.
#
# Usage: tools/bench-bgp.sh {up|run <dut> [N]|all [N]|report|logs [n]|down}
#        dut = nos | nos-quiet | gobgp | bird | frr
#        N   = prefixes announced *per peer*
#        env: PEERS=<n>          how many full views to take (default 4)
#             POLICY=0|1         apply the import policy above (default 1)
#             PROFILE_MEMORY=1   nos/nos-quiet only: pass --profile-memory-out
#                                to the DUT's nos-bgpd (needs an image built
#                                with CARGO_FEATURES=nos-bgp/dhat-heap, see
#                                bgp/CLAUDE.md's "Memory profiling"); the
#                                report is copied to
#                                target/bench-bgp/dhat-heap-<dut>-<N>.json
#                                before the DUT container is torn down
#        e.g. PEERS=1 POLICY=0 tools/bench-bgp.sh run nos 1000   # smoke test
#             CARGO_FEATURES=nos-bgp/dhat-heap tools/bench-bgp.sh up
#             PROFILE_MEMORY=1 tools/bench-bgp.sh run nos-quiet 100000
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Same split-target-dir reasoning as verify-bgp.sh: nos-provision must be
# built against bookworm's glibc to run inside the runtime image.
PROVISION_BIN="$REPO/target/docker-verify/release/nos-provision"
WORKDIR="$REPO/target/bench-bgp"
RESULTS="$WORKDIR/results.tsv"

NOS_IMAGE=${NOS_IMAGE:-nos:local}
GOBGP_IMAGE=${GOBGP_IMAGE:-nos-bench-gobgp:local}
GOBGP_VERSION=${GOBGP_VERSION:-4.9.0}
BIRD_IMAGE=${BIRD_IMAGE:-pierky/bird:2.17.1}
# quay.io, not docker.io: FRR's Docker Hub mirror stopped at v8.4.1 in 2022.
FRR_IMAGE=${FRR_IMAGE:-quay.io/frrouting/frr:10.7.1}
# 5.0.13, not 5.0.0: the published 5.0.0 image is broken (its own
# `exabgp.version` module fails to import), and `latest` is 6.x/unpinned.
EXABGP_IMAGE=${EXABGP_IMAGE:-ghcr.io/exa-networks/exabgp:5.0.13}

NET=nos-bench-net
SUBNET=10.60.0.0/24
DUT=bench-dut
MON=bench-mon
INJ=bench-inj
DUT_IP=10.60.0.2
MON_IP=10.60.0.3
INJ_IP=10.60.0.10
DUT_AS=65001
MON_AS=65200

# Injector peers. Each announces the SAME N prefixes -- one "full view" per
# transit provider -- so the DUT holds PEERS paths per prefix and has to run
# best-path selection on every one of them, rather than just inserting a
# table nobody competes for. Peer k is AS 65100+k at 10.60.0.(10+k), and wins
# every PEERS-th prefix on AS_PATH length (see gen_exabgp_config) -- an even
# share each, with the other PEERS-1 paths kept as backups.
PEERS=${PEERS:-4}
INJ_AS_BASE=65100
# Private ASN used purely to pad AS_PATH; never originates anything.
PAD_AS=64600

# Import policy applied by every daemon to every injector session when
# POLICY=1 (the default): drop anything tagged with $DROP_COMMUNITY -- every
# DROP_EVERY-th prefix carries it -- and set local-pref on what survives.
# Community matching plus an attribute write is the most common shape of
# real transit policy, and it is expressible in all four daemons without
# favouring any one of them.
POLICY=${POLICY:-1}
DROP_COMMUNITY=65000:666
DROP_EVERY=4
SET_LOCAL_PREF=150

inj_name() { echo "$INJ-$1"; }
inj_ip()   { echo "10.60.0.$(( 10 + $1 ))"; }
inj_as()   { echo $(( INJ_AS_BASE + $1 )); }

# Prefixes only this peer announces, out of 101.<k>.0.0/16, sent after its
# share of the common view. Without them, convergence could not be told apart
# from "whichever peer finished first": the monitor only ever sees one best
# path per prefix, so a common view announced by everyone is fully counted as
# soon as any single peer's copy lands, no matter what the other peers are
# still sending. A block only peer k has forces the count to wait for peer k.
UNIQUE_TAIL=${UNIQUE_TAIL:-1000}

# How many of `n` prefixes survive the import policy (it rejects every
# DROP_EVERY-th one).
kept_prefixes() {
  if [[ "$POLICY" == 1 ]]; then
    echo $(( $1 - ($1 + DROP_EVERY - 1) / DROP_EVERY ))
  else
    echo "$1"
  fi
}

# What the monitor should end up holding: one best path per common prefix,
# plus every peer's own tail block, minus everything the policy rejected.
expected_prefixes() {
  echo $(( $(kept_prefixes "$1") + PEERS * $(kept_prefixes "$UNIQUE_TAIL") ))
}

# Default prefix count. 10k is too small to tell these daemons apart -- every
# one of them absorbs it inside a couple of poll intervals -- so the default
# is 100k, about a quarter of a real IPv4 DFZ table. Pass a smaller N when
# smoke-testing a change to this script itself.
DEFAULT_PREFIXES=100000
# How long to wait for all N prefixes to reach the monitor before calling the
# run a timeout. Scales with N so a bigger run does not need a new constant.
# 200 prefixes/s is a floor none of these daemons should ever approach, so a
# run that hits this really is stuck rather than merely slow.
converge_timeout() { echo $(( 60 + $1 / 200 )); }

log() { echo "[bench-bgp] $*" >&2; }

now_ms() { date +%s%3N; }

# Elapsed seconds, 2dp, from a now_ms() baseline.
since() { awk -v a="$1" -v b="$(now_ms)" 'BEGIN { printf "%.2f", (b - a) / 1000 }'; }

# --- Images and network -----------------------------------------------------

build_provision_tool() {
  log "building nos-provision (bookworm-glibc-compatible, matching the runtime image)"
  docker run --rm \
    -v "$REPO:$REPO:z" \
    -w "$REPO" \
    rust:1-slim-bookworm \
    cargo build --release -p nos-provision --target-dir target/docker-verify
}

build_nos_image() {
  log "building $NOS_IMAGE"
  (cd "$REPO" && make docker-build)
}

# GoBGP publishes release tarballs but no maintained container image, so
# build a two-line one from the official release rather than trusting a
# random community tag.
build_gobgp_image() {
  if docker image inspect "$GOBGP_IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  log "building $GOBGP_IMAGE from the gobgp $GOBGP_VERSION release tarball"
  docker build -t "$GOBGP_IMAGE" - <<EOF
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \\
    && curl -fsSL https://github.com/osrg/gobgp/releases/download/v$GOBGP_VERSION/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz \\
       | tar -xz -C /usr/local/bin gobgp gobgpd \\
    && apt-get purge -y --auto-remove curl && rm -rf /var/lib/apt/lists/*
EOF
}

pull_images() {
  for image in "$BIRD_IMAGE" "$FRR_IMAGE" "$EXABGP_IMAGE"; do
    log "pulling $image"
    docker pull -q "$image" >/dev/null
  done
}

ensure_network() {
  if ! docker network inspect "$NET" >/dev/null 2>&1; then
    log "creating network $NET ($SUBNET)"
    docker network create --subnet "$SUBNET" "$NET" >/dev/null
  fi
}

# --- Config generation ------------------------------------------------------
#
# Every config is generated into $WORKDIR and bind-mounted in, so nothing
# daemon-specific is checked into the repo and the peer addresses above stay
# the single source of truth.

# One config per injector. All of them announce the same N host routes out of
# 100.0.0.0/8 (nowhere near the 10.60.0.0/24 the containers themselves use),
# and every DROP_EVERY-th route carries $DROP_COMMUNITY for the import policy
# to reject.
#
# AS_PATH padding is what decides which peer wins each prefix: injector k
# announces prefix i unpadded when i % PEERS == k-1 and padded otherwise, so
# the best paths are spread evenly across all PEERS peers. That matters for
# more than realism (a multi-homed router does not take everything from one
# transit): if one peer won every prefix, the monitor would reach the
# expected count as soon as that peer's view was processed, while the other
# peers' updates were still in flight -- and converge_s would be timing one
# full view while claiming to time PEERS of them.
gen_exabgp_config() {
  local count=$1 k=$2
  local pad=""
  local i
  for (( i = 0; i < k; i++ )); do
    pad="$pad $PAD_AS"
  done
  {
    cat <<EOF
neighbor $DUT_IP {
    router-id $(inj_ip "$k");
    local-address $(inj_ip "$k");
    local-as $(inj_as "$k");
    peer-as $DUT_AS;
    family {
        ipv4 unicast;
    }
    static {
EOF
    awk -v n="$count" -v nh="$(inj_ip "$k")" -v pad="$pad" -v drop="$DROP_COMMUNITY" \
        -v every="$DROP_EVERY" -v peers="$PEERS" -v k="$k" 'BEGIN {
      for (i = 0; i < n; i++) {
        line = sprintf("        route 100.%d.%d.%d/32 next-hop %s",
                       int(i / 65536) % 256, int(i / 256) % 256, i % 256, nh)
        if (i % peers != k - 1)
          line = line " as-path [" pad " ]"
        if (i % every == 0)
          line = line " community [" drop "]"
        print line ";"
      }
    }'
    awk -v n="$UNIQUE_TAIL" -v nh="$(inj_ip "$k")" -v drop="$DROP_COMMUNITY" \
        -v every="$DROP_EVERY" -v k="$k" 'BEGIN {
      for (i = 0; i < n; i++) {
        line = sprintf("        route 101.%d.%d.%d/32 next-hop %s",
                       k, int(i / 256) % 256, i % 256, nh)
        if (i % every == 0)
          line = line " community [" drop "]"
        print line ";"
      }
    }'
    printf '    }\n}\n'
  } >"$WORKDIR/exabgp-$k.conf"
}

gen_dut_configs() {
  local k

  # --- BIRD ---------------------------------------------------------------
  {
    cat <<EOF
router id $DUT_IP;
log stderr all;
# No "protocol kernel" on purpose: nos-bgpd does not install BGP routes into
# the kernel either, so neither does BIRD here.
protocol device {
}
EOF
    if [[ "$POLICY" == 1 ]]; then
      cat <<EOF
filter bench_in {
    if ($(echo "$DROP_COMMUNITY" | tr ':' ',')) ~ bgp_community then reject;
    bgp_local_pref = $SET_LOCAL_PREF;
    accept;
}
EOF
    fi
    for (( k = 1; k <= PEERS; k++ )); do
      cat <<EOF
protocol bgp inj$k {
    local $DUT_IP as $DUT_AS;
    neighbor $(inj_ip "$k") as $(inj_as "$k");
    ipv4 { import $([[ "$POLICY" == 1 ]] && echo "filter bench_in" || echo all); export all; };
}
EOF
    done
    cat <<EOF
protocol bgp mon {
    local $DUT_IP as $DUT_AS;
    neighbor $MON_IP as $MON_AS;
    ipv4 { import all; export all; };
}
EOF
  } >"$WORKDIR/bird.conf"

  # --- FRR ----------------------------------------------------------------
  {
    echo "log stdout"
    if [[ "$POLICY" == 1 ]]; then
      cat <<EOF
bgp community-list standard BENCH-DROP permit $DROP_COMMUNITY
route-map BENCH-IN deny 10
 match community BENCH-DROP
route-map BENCH-IN permit 20
 set local-preference $SET_LOCAL_PREF
EOF
    fi
    cat <<EOF
router bgp $DUT_AS
 bgp router-id $DUT_IP
 no bgp ebgp-requires-policy
EOF
    for (( k = 1; k <= PEERS; k++ )); do
      echo " neighbor $(inj_ip "$k") remote-as $(inj_as "$k")"
    done
    echo " neighbor $MON_IP remote-as $MON_AS"
    echo " address-family ipv4 unicast"
    for (( k = 1; k <= PEERS; k++ )); do
      echo "  neighbor $(inj_ip "$k") activate"
      [[ "$POLICY" == 1 ]] && echo "  neighbor $(inj_ip "$k") route-map BENCH-IN in"
    done
    echo "  neighbor $MON_IP activate"
    echo " exit-address-family"
  } >"$WORKDIR/bgpd.conf"

  # --- GoBGP --------------------------------------------------------------
  {
    cat <<EOF
[global.config]
  as = $DUT_AS
  router-id = "$DUT_IP"
EOF
    # GoBGP attaches import policy *globally* for ordinary peers -- a
    # per-neighbour `apply-policy` is only honoured for route-server clients
    # ("non-rs-client peer X doesn't have per peer policy"), which is how
    # this silently accepted everything the first time round. Global is
    # equivalent here: the monitor is the only other session and it never
    # announces anything for the policy to act on.
    if [[ "$POLICY" == 1 ]]; then
      cat <<EOF
  [global.apply-policy.config]
    import-policy-list = ["bench-in"]
    default-import-policy = "accept-route"
EOF
    fi
    for (( k = 1; k <= PEERS; k++ )); do
      cat <<EOF

[[neighbors]]
  [neighbors.config]
    neighbor-address = "$(inj_ip "$k")"
    peer-as = $(inj_as "$k")
EOF
    done
    cat <<EOF

[[neighbors]]
  [neighbors.config]
    neighbor-address = "$MON_IP"
    peer-as = $MON_AS
EOF
    if [[ "$POLICY" == 1 ]]; then
      cat <<EOF

[[defined-sets.bgp-defined-sets.community-sets]]
  community-set-name = "bench-drop"
  community-list = ["$DROP_COMMUNITY"]

[[policy-definitions]]
  name = "bench-in"
  [[policy-definitions.statements]]
    name = "drop-tagged"
    [policy-definitions.statements.conditions.bgp-conditions.match-community-set]
      community-set = "bench-drop"
      match-set-options = "any"
    [policy-definitions.statements.actions]
      route-disposition = "reject-route"
  [[policy-definitions.statements]]
    name = "prefer-rest"
    [policy-definitions.statements.actions]
      route-disposition = "accept-route"
      [policy-definitions.statements.actions.bgp-actions]
        set-local-pref = $SET_LOCAL_PREF
EOF
    fi
  } >"$WORKDIR/gobgpd.conf"

  # --- GoBGP monitor (never filters: it is the measuring instrument) ------
  cat >"$WORKDIR/gobgpd-mon.conf" <<EOF
[global.config]
  as = $MON_AS
  router-id = "$MON_IP"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "$DUT_IP"
    peer-as = $DUT_AS
EOF

  # --- nos (RPL) ----------------------------------------------------------
  # Written even when POLICY=0 so the path is always there to mount; it is
  # only referenced as an import policy when POLICY=1.
  cat >"$WORKDIR/bench-in.rpl" <<EOF
if this.bgp.communities.contains($DROP_COMMUNITY):
    reject
else:
    set this.bgp.local_pref = $SET_LOCAL_PREF
    accept
EOF
  # nos-provision runs as the container's unprivileged `nos` user, a
  # different uid than this shell (same reason verify-bgp.sh chmods its own
  # policy file).
  chmod 644 "$WORKDIR/bench-in.rpl"
}

# --- Containers -------------------------------------------------------------

start_monitor() {
  docker rm -f "$MON" >/dev/null 2>&1 || true
  log "starting monitor (gobgp, AS $MON_AS) at $MON_IP"
  docker run -d --name "$MON" --network "$NET" --ip "$MON_IP" \
    -v "$WORKDIR/gobgpd-mon.conf:/etc/gobgpd.conf:ro,z" \
    "$GOBGP_IMAGE" gobgpd -f /etc/gobgpd.conf -t toml >/dev/null
}

start_injector() {
  local k=$1
  local name
  name=$(inj_name "$k")
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "$NET" --ip "$(inj_ip "$k")" \
    -e exabgp_daemon_daemonize=false \
    -e exabgp_log_destination=stdout \
    -v "$WORKDIR/exabgp-$k.conf:/etc/exabgp/exabgp.conf:ro,z" \
    "$EXABGP_IMAGE" /etc/exabgp/exabgp.conf >/dev/null
}

start_injectors() {
  log "starting $PEERS injector(s) (exabgp, AS $(inj_as 1)..$(inj_as "$PEERS"))"
  local k
  for (( k = 1; k <= PEERS; k++ )); do
    start_injector "$k"
  done
}

stop_injectors() {
  local k
  for (( k = 1; k <= PEERS; k++ )); do
    docker rm -f "$(inj_name "$k")" >/dev/null 2>&1 || true
  done
}

# nos's DUT container is the whole watchdog-supervised stack, exactly as
# verify-bgp.sh starts it -- plus an optional RUST_LOG, which reaches
# nos-bgpd because watchdog/src/supervisor.rs spawns children with a plain
# Command that inherits the environment.
start_nos_dut() {
  local rust_log=${1:-}
  docker volume create "${DUT}-run" >/dev/null
  docker volume create "${DUT}-data" >/dev/null
  docker rm -f "$DUT" >/dev/null 2>&1 || true
  log "starting nos DUT at $DUT_IP${rust_log:+ (RUST_LOG=$rust_log)}"
  docker run -d --name "$DUT" \
    --network "$NET" --ip "$DUT_IP" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
    ${rust_log:+-e "RUST_LOG=$rust_log"} \
    -v "${DUT}-run:/run/nos" \
    -v "${DUT}-data:/var/lib/nos" \
    "$NOS_IMAGE" ${PROFILE_MEMORY:+--bgpd-arg --profile-memory-out=/var/lib/nos/dhat-heap.json} >/dev/null

  log "waiting for the nos DUT's nos-configd socket"
  local ready=1
  for _ in $(seq 1 60); do
    if docker run --rm --entrypoint /bin/sh -v "${DUT}-run:/run/nos" "$NOS_IMAGE" \
        -c 'test -S /run/nos/config.sock'; then
      ready=0
      break
    fi
    sleep 1
  done
  if [[ $ready -ne 0 ]]; then
    log "timed out waiting for the nos DUT's config socket"
    return 1
  fi

  # One nos-provision call per neighbour: BgpPeerOp::Set upserts, so each
  # call adds a peer rather than replacing the previous one (the same way
  # verify-bgp.sh's reflector scenario adds a second client). The injector
  # peer-groups get the RPL import policy; the monitor's never does -- it is
  # the measuring instrument, not part of the test.
  local k
  for (( k = 1; k <= PEERS; k++ )); do
    provision_nos_peer "inj$k" "$(inj_as "$k")" "$(inj_ip "$k")" policy
  done
  provision_nos_peer mon "$MON_AS" "$MON_IP"

  # nos-interfaced enslaves eth0 into the routing table's VRF a few seconds
  # after the commit, which kills any TCP session opened before it. Waiting
  # for both the enslavement and nos-bgpd's listener keeps that churn out of
  # the establishment measurement -- without it, the monitor's first connect
  # attempt is torn down and its retry backoff (which doubles) shows up as a
  # ~100s "establishment time" that is really gobgp's idle-hold timer.
  wait_for_dut_log "enslaved interface to vrf" 60 || return 1
  wait_for_dut_log "bgp listener bound" 60 || return 1
}

wait_for_dut_log() {
  local pattern=$1 timeout=${2:-60} logs
  for _ in $(seq 1 "$timeout"); do
    # Captured into a variable rather than piped into `grep -q`: under
    # pipefail, grep's early exit SIGPIPEs `docker logs` and the pipeline
    # reports failure even on a match (see verify-bgp.sh's wait_for_log).
    logs=$(docker logs "$DUT" 2>&1) || true
    if grep -q "$pattern" <<<"$logs"; then
      return 0
    fi
    sleep 1
  done
  log "timed out waiting for '$pattern' in the DUT's logs"
  return 1
}

provision_nos_peer() {
  local group=$1 remote_as=$2 peer=$3 with_policy=${4:-}
  local policy_args=()
  if [[ -n "$with_policy" && "$POLICY" == 1 ]]; then
    policy_args=(
      --policy-name bench-in
      --policy-source-file /tmp/bench-in.rpl
      --import-policy bench-in
    )
  fi
  log "provisioning nos peer-group $group (remote-as $remote_as, peer $peer${policy_args:+, import policy bench-in})"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "$WORKDIR/bench-in.rpl:/tmp/bench-in.rpl:ro,z" \
    -v "${DUT}-run:/run/nos" \
    "$NOS_IMAGE" \
    --config-socket /run/nos/config.sock \
    --address "$DUT_IP/24" \
    --asn "$DUT_AS" \
    --router-id "$DUT_IP" \
    --peer-group "$group" \
    --remote-as "$remote_as" \
    --peer "$peer" \
    "${policy_args[@]}" >>"$WORKDIR/provision.log" 2>&1
}

start_dut() {
  local kind=$1
  case "$kind" in
    nos) start_nos_dut ;;
    # Not a blanket `warn`: the harness itself waits on two `info!` lines
    # (VRF enslavement, listener bound) to know the stack has settled. This
    # silences the per-route firehose in nos_bgp::rib and the netlink TRACE
    # dumps from the other daemons, which is the whole point.
    nos-quiet) start_nos_dut "info,nos_bgp::rib=warn" ;;
    gobgp)
      docker rm -f "$DUT" >/dev/null 2>&1 || true
      log "starting gobgp DUT at $DUT_IP"
      docker run -d --name "$DUT" --network "$NET" --ip "$DUT_IP" \
        -v "$WORKDIR/gobgpd.conf:/etc/gobgpd.conf:ro,z" \
        "$GOBGP_IMAGE" gobgpd -f /etc/gobgpd.conf -t toml >/dev/null
      ;;
    bird)
      docker rm -f "$DUT" >/dev/null 2>&1 || true
      log "starting bird DUT at $DUT_IP"
      docker run -d --name "$DUT" --network "$NET" --ip "$DUT_IP" \
        --entrypoint /usr/local/sbin/bird \
        -v "$WORKDIR/bird.conf:/etc/bird/bird.conf:ro,z" \
        "$BIRD_IMAGE" -f -c /etc/bird/bird.conf >/dev/null
      ;;
    frr)
      docker rm -f "$DUT" >/dev/null 2>&1 || true
      # bgpd only -- no zebra, so nothing reaches the kernel, matching nos.
      log "starting frr DUT (bgpd only) at $DUT_IP"
      docker run -d --name "$DUT" --network "$NET" --ip "$DUT_IP" \
        --user root \
        --cap-add NET_ADMIN --cap-add SYS_ADMIN \
        --entrypoint /usr/lib/frr/bgpd \
        -v "$WORKDIR/bgpd.conf:/etc/frr/bgpd.conf:ro,z" \
        "$FRR_IMAGE" -f /etc/frr/bgpd.conf --log stdout >/dev/null
      ;;
    *) log "unknown dut '$kind'"; return 2 ;;
  esac
}

# The BGP process to sample inside the DUT container, per daemon.
dut_process() {
  case "$1" in
    nos|nos-quiet) echo nos-bgpd ;;
    gobgp) echo gobgpd ;;
    bird) echo bird ;;
    frr) echo bgpd ;;
  esac
}

# --- Measurement ------------------------------------------------------------

# Everything the monitor knows comes from one line of `gobgp neighbor`'s
# summary table, which carries both the session state and the received-prefix
# count -- one `docker exec` per poll rather than one per metric:
#
#   Peer         AS  Up/Down State       |#Received  Accepted
#   10.60.0.2 65001 00:00:07 Establ      |        0         0
#
# (The per-neighbour detail view has the same numbers, but spells the state
# `SESSION_STATE_ESTABLISHED` in gobgp 4.x and costs a second call.)
mon_line() {
  docker exec "$MON" gobgp neighbor 2>/dev/null \
    | awk -v peer="$DUT_IP" '$1 == peer { print; exit }'
}

mon_established() {
  [[ "$(mon_line)" == *Estab* ]]
}

mon_received() {
  mon_line | awk '{ print $(NF - 1) }'
}

# Polls are deadline-driven rather than iteration-counted, at 0.2s, because a
# fast daemon converges a small table inside a single 1s tick and would
# otherwise be reported as 0.00s. A `docker exec` round trip is ~50-100ms, so
# 0.2s is about as fine as this can usefully get.
POLL=0.2

# A daemon that swallows the whole table between two polls measures 0.00s,
# which reads as "0 prefixes/s". Flooring at the poll interval turns that into
# a lower bound instead ("at least this fast"), and is why small-N runs are
# not worth reading -- use N >= 10000.
floor_poll() {
  awk -v s="$1" -v p="$POLL" 'BEGIN { printf("%.2f", s > p ? s : p) }'
}

wait_for_established() {
  local timeout=${1:-120} start=$2
  local deadline=$(( $(now_ms) + timeout * 1000 ))
  while [[ "$(now_ms)" -lt "$deadline" ]]; do
    if mon_established; then
      since "$start"
      return 0
    fi
    sleep "$POLL"
  done
  echo "timeout"
  return 1
}

# Polls the monitor until it holds `count` prefixes, and prints the elapsed
# seconds *since the first prefix arrived* rather than since the injector
# container was started -- roughly 1.5s of that is exabgp's own startup, which
# would otherwise be charged to whichever daemon is under test. `start` is
# only the fallback for a run that finishes inside a single poll.
wait_for_prefixes() {
  local count=$1 timeout=$2 start=$3
  local got=0 first=
  local deadline=$(( $(now_ms) + timeout * 1000 ))
  while [[ "$(now_ms)" -lt "$deadline" ]]; do
    got=$(mon_received || echo 0)
    [[ -z "$first" && "${got:-0}" -gt 0 ]] && first=$(now_ms)
    if [[ "${got:-0}" -ge "$count" ]]; then
      since "${first:-$start}"
      return 0
    fi
    sleep "$POLL"
  done
  log "timed out at ${got:-0}/$count prefixes"
  echo "timeout"
  return 1
}

# One long-lived `docker exec` sampling loop, not one exec per sample. Emits
# "peak_rss_kb cpu_ticks" per second for the DUT's BGP process; the pid is
# re-resolved every tick because nos-bgpd is spawned (and respawned) by the
# watchdog rather than being the container's own pid 1. The runtime images
# have no ps/pgrep, hence the /proc/*/comm scan (same trick as
# verify-bgp.sh's kill_process_by_name).
sampler_pid=
sampler_start() {
  local proc=$1
  : >"$WORKDIR/samples.txt"
  docker exec "$DUT" sh -c "
    while :; do
      for p in /proc/[0-9]*; do
        [ -r \"\$p/comm\" ] || continue
        [ \"\$(cat \"\$p/comm\" 2>/dev/null)\" = '$proc' ] || continue
        rss=\$(awk '/VmHWM/ { print \$2 }' \"\$p/status\" 2>/dev/null)
        cpu=\$(awk '{ print \$14 + \$15 }' \"\$p/stat\" 2>/dev/null)
        [ -n \"\$rss\" ] && [ -n \"\$cpu\" ] && echo \"\$rss \$cpu\"
      done
      sleep 1
    done
  " >"$WORKDIR/samples.txt" 2>/dev/null &
  sampler_pid=$!
}

sampler_stop() {
  [[ -n "$sampler_pid" ]] || return 0
  kill "$sampler_pid" >/dev/null 2>&1 || true
  wait "$sampler_pid" 2>/dev/null || true
  sampler_pid=
}

# Peak RSS in MB and total CPU seconds (USER_HZ is 100 on Linux/x86_64).
sampler_peak_rss_mb() {
  awk 'BEGIN { m = 0 } { if ($1 > m) m = $1 } END { printf "%.1f", m / 1024 }' \
    "$WORKDIR/samples.txt"
}

sampler_cpu_secs() {
  awk 'NR == 1 { lo = $2 } { if ($2 > hi) hi = $2 } END { printf "%.2f", (hi - lo) / 100 }' \
    "$WORKDIR/samples.txt"
}

# --- Phases -----------------------------------------------------------------

cmd_up() {
  mkdir -p "$WORKDIR"
  build_nos_image
  build_provision_tool
  build_gobgp_image
  pull_images
  ensure_network
  gen_dut_configs
  log "ready -- run 'tools/bench-bgp.sh all' or 'run <dut>'"
}

cmd_run() {
  local kind=$1 count=${2:-$DEFAULT_PREFIXES}
  local timeout expected
  timeout=$(converge_timeout "$count")
  expected=$(expected_prefixes "$count")
  mkdir -p "$WORKDIR"
  gen_dut_configs
  local k
  for (( k = 1; k <= PEERS; k++ )); do
    gen_exabgp_config "$count" "$k"
  done

  log "=== $kind, ($count common + $UNIQUE_TAIL unique) prefixes x $PEERS peer(s), policy=$POLICY, expecting $expected in the monitor ==="
  docker rm -f "$DUT" "$MON" >/dev/null 2>&1 || true
  stop_injectors
  docker volume rm "${DUT}-run" "${DUT}-data" >/dev/null 2>&1 || true

  start_dut "$kind"
  sampler_start "$(dut_process "$kind")"

  # 1. Session establishment, timed from the monitor's start: the DUT is
  #    already up and configured, so this is how fast the pair gets to
  #    Established (dominated by whichever side's connect-retry timer fires
  #    first -- for nos that is usually the monitor's, since nos's own
  #    CONNECT_RETRY_TIME default is 120s).
  local t0 establish
  t0=$(now_ms)
  start_monitor
  establish=$(wait_for_established 120 "$t0") || true
  log "$kind: established in ${establish}s"

  # 2. Convergence: every injector announces the same N prefixes at once,
  #    measured until the surviving best paths have all been re-advertised
  #    into the monitor. The DUT does PEERS x N updates of work to get there.
  local converge pps
  t0=$(now_ms)
  start_injectors
  converge=$(wait_for_prefixes "$expected" "$timeout" "$t0") || true
  if [[ "$converge" == "timeout" ]]; then
    pps=0
  else
    converge=$(floor_poll "$converge")
    # Parenthesised on purpose: bare `printf "...", s > 0 ? ...` parses the
    # `>` as output redirection in awk.
    pps=$(awk -v n="$(( (count + UNIQUE_TAIL) * PEERS ))" -v s="$converge" \
      'BEGIN { printf("%.0f", s > 0 ? n / s : 0) }')
  fi
  log "$kind: converged to $expected prefixes in ${converge}s ($pps updates/s)"

  # 3. Churn: drop every injector (closing TCP, so the DUT withdraws
  #    everything) and bring them all back, then re-measure. Dropping a
  #    single peer would be the more operational test, but only part of it
  #    is timeable from here: its unique block's withdrawal shows up in the
  #    monitor's count, while the far larger job -- repathing the prefixes
  #    it was winning onto another peer's backup path -- does not move the
  #    count at all. Not worth a phase that measures the small half.
  local churn
  log "$kind: restarting the injectors to measure reconvergence"
  stop_injectors
  for _ in $(seq 1 60); do
    [[ "$(mon_received || echo 0)" -lt "$expected" ]] && break
    sleep 1
  done
  t0=$(now_ms)
  start_injectors
  churn=$(wait_for_prefixes "$expected" "$timeout" "$t0") || true
  [[ "$churn" == "timeout" ]] || churn=$(floor_poll "$churn")
  log "$kind: reconverged in ${churn}s"

  # What the monitor actually ended up holding. The convergence waits above
  # stop at ">= expected", so without this a daemon whose filter silently did
  # nothing would converge to 1000 prefixes and still look like a pass --
  # this puts the real number in the table next to the expectation.
  sleep 2
  local final
  final=$(mon_received || echo 0)
  if [[ "${final:-0}" != "$expected" ]]; then
    log "$kind: WARNING: monitor holds ${final:-0} prefixes, expected $expected -- check this daemon's import policy"
  fi

  sampler_stop
  local rss cpu
  rss=$(sampler_peak_rss_mb)
  cpu=$(sampler_cpu_secs)
  log "$kind: peak rss ${rss}MB, cpu ${cpu}s"

  [[ -s "$RESULTS" ]] || printf 'daemon\tprefixes\tpeers\tpolicy\tkept_pfx\testablish_s\tconverge_s\tupdates_per_s\tpeak_rss_mb\tcpu_s\treconverge_s\n' >"$RESULTS"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$kind" "$count" "$PEERS" "$POLICY" "${final:-0}/$expected" "$establish" "$converge" "$pps" "$rss" "$cpu" "$churn" >>"$RESULTS"

  # dhat only writes its report file when nos-bgpd exits -- SIGTERM (docker
  # stop's default) reaches it the same way SIGINT does (see root
  # CLAUDE.md's "Process supervision"), so this has to happen before the
  # unconditional `docker rm -f` below, not after.
  if [[ -n "${PROFILE_MEMORY:-}" && "$kind" == nos* ]]; then
    local profile_out="$WORKDIR/dhat-heap-$kind-$count.json"
    log "$kind: stopping DUT to flush the dhat heap-profile report"
    docker stop "$DUT" >/dev/null 2>&1 || true
    if docker cp "$DUT:/var/lib/nos/dhat-heap.json" "$profile_out" >/dev/null 2>&1; then
      log "$kind: wrote heap-profile report to $profile_out"
    else
      log "$kind: WARNING: could not extract dhat-heap.json -- was \$NOS_IMAGE built with CARGO_FEATURES=nos-bgp/dhat-heap?"
    fi
  fi

  docker rm -f "$DUT" "$MON" >/dev/null 2>&1 || true
  stop_injectors
  docker volume rm "${DUT}-run" "${DUT}-data" >/dev/null 2>&1 || true
}

cmd_all() {
  local count=${1:-$DEFAULT_PREFIXES}
  : >"$RESULTS"
  for kind in nos nos-quiet gobgp bird frr; do
    cmd_run "$kind" "$count" || log "$kind: run failed, continuing"
  done
  cmd_report
}

cmd_report() {
  if [[ ! -s "$RESULTS" ]]; then
    log "no results yet -- run 'tools/bench-bgp.sh all' first"
    return 1
  fi
  echo
  column -t -s $'\t' "$RESULTS"
  cat <<'EOF'

Read these with the caveats in this script's header: bird/frr run BGP-only
(no kernel install, matching nos); memory/cpu is the BGP process alone;
`nos` is the shipping default (an info! per learned route, plus rtnetlink
TRACE from the other daemons) and `nos-quiet` is the row comparable to the
other three. converge_s and reconverge_s measure receive -> best-path ->
re-advertise into the monitor, so they include nos-bgpd's
one-prefix-per-UPDATE outbound path.

kept_pfx is what the monitor actually held at the end over what the policy
should have let through -- anything other than n/n means that daemon's filter
did not do what the other three did, and its row is not comparable.

updates_per_s counts (prefixes + tail) x peers (every path the DUT had to
consider),
not the prefixes that survived policy -- the rejected quarter still costs a
decode, a policy evaluation and a RIB lookup.

Two things the table still cannot show. Within one injector every prefix
carries the same attributes, which flatters an implementation that shares one
attribute set across routes (BIRD's rta hashing above all) over one that
stores a copy per route -- so peak_rss_mb is a best case, not a
table-of-the-internet figure. And the injectors are themselves a ceiling:
when two daemons report the same converge_s, the honest reading is "both kept
up with exabgp", not "both are equally fast".
EOF
}

cmd_logs() {
  local n=${1:-200} c k
  local containers=("$DUT" "$MON")
  for (( k = 1; k <= PEERS; k++ )); do
    containers+=("$(inj_name "$k")")
  done
  for c in "${containers[@]}"; do
    if docker inspect "$c" >/dev/null 2>&1; then
      echo "--- $c ---"
      docker logs --tail "$n" "$c" 2>&1 || true
    fi
  done
}

cmd_down() {
  sampler_stop
  docker rm -f "$DUT" "$MON" >/dev/null 2>&1 || true
  # Not just $PEERS: a previous run may have used a larger peer count.
  docker ps -aq --filter "name=^$INJ-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume rm "${DUT}-run" "${DUT}-data" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

case "${1:-}" in
  up) cmd_up ;;
  run) shift; [[ $# -ge 1 ]] || { echo "usage: $0 run <nos|nos-quiet|gobgp|bird|frr> [N]" >&2; exit 2; }; cmd_run "$@" ;;
  all) shift; cmd_all "$@" ;;
  report) cmd_report ;;
  logs) shift; cmd_logs "$@" ;;
  down) cmd_down ;;
  *)
    echo "Usage: $0 {up|run <nos|nos-quiet|gobgp|bird|frr> [N]|all [N]|report|logs [n]|down}" >&2
    exit 2
    ;;
esac
