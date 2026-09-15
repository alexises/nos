#!/usr/bin/env bash
# End-to-end verification harness for nos-bgpd's session-establishment FSM
# and route redistribution/propagation: stands up two independent
# nos-watchdogd containers ("router-a"/"router-b") on a shared docker
# network, configures each as a full BGP router peering the other, and
# checks the logs for a real OPEN/KEEPALIVE handshake reaching Established,
# a hold-timer/reconnect cycle, (best-effort) a collision-resolution event,
# (via the `redistribute` subcommand) a static route configured on router-a
# actually being redistributed into its bgp instance, advertised over the
# wire, and learned into router-b's Adj-RIB-In/Loc-RIB, and (via the `auth`
# subcommand) that matching RFC 2385 TCP MD5 passwords on both routers still
# establish while a mismatched password on either side does not.
#
# nos-cli's interactive shell (reedline) can't be scripted over a plain
# pipe, so provisioning goes through `nos-provision` (tools/nos-provision) —
# a small standalone tool that speaks nos-configd's IPC protocol directly,
# reusing nos-proto's own types for wire compatibility.
#
# Usage: tools/verify-bgp.sh {up|established|reconnect|collision|redistribute|auth|logs [n]|down|all}
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
ASN_A=65001
ASN_B=65002
RID_A=1.1.1.1
RID_B=2.2.2.2
# TEST-NET-2 (RFC 5737) — reserved for documentation, safe to use as a
# fake redistributed prefix without colliding with anything real.
REDISTRIBUTE_PREFIX=198.51.100.0/24
REDISTRIBUTE_GATEWAY=10.50.0.99

log() { echo "[verify-bgp] $*" >&2; }

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

established_count() {
  local name=$1
  docker logs "$name" 2>&1 | grep -c "bgp session established" || true
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
  build_image
  build_provision_tool
  ensure_network
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

  log "waiting 20s to confirm the session does NOT (re-)establish with mismatched md5 passwords"
  sleep 20
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

cmd_logs() {
  echo "===== router-a ====="
  docker logs router-a 2>&1 | tail -n "${1:-200}"
  echo "===== router-b ====="
  docker logs router-b 2>&1 | tail -n "${1:-200}"
}

cmd_down() {
  docker rm -f router-a router-b >/dev/null 2>&1 || true
  docker volume rm router-a-run router-a-data router-b-run router-b-data >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

case "${1:-}" in
  up) cmd_up ;;
  established) cmd_check_established ;;
  reconnect) cmd_check_reconnect ;;
  collision) cmd_check_collision ;;
  redistribute) cmd_check_redistribute ;;
  auth) cmd_check_auth ;;
  logs) shift; cmd_logs "$@" ;;
  down) cmd_down ;;
  all)
    cmd_up
    cmd_check_established
    cmd_check_reconnect
    cmd_check_collision
    cmd_check_redistribute
    cmd_check_auth
    ;;
  *)
    echo "usage: $0 {up|established|reconnect|collision|redistribute|auth|logs [n]|down|all}" >&2
    exit 2
    ;;
esac
