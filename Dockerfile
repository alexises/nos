# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder
WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Empty by default (no new deps, no behavior change). Set to
# "nos-bgp/dhat-heap" to build nos-bgpd with dhat heap profiling — see
# bgp/CLAUDE.md's "Memory profiling" note.
ARG CARGO_FEATURES=
RUN cargo build --release ${CARGO_FEATURES:+--features "$CARGO_FEATURES"} --bin nos-configd --bin nos-bgpd --bin nos-ribd --bin nos-interfaced --bin nos-logd --bin nos-ospfd --bin nos-ospfv3d --bin nos-lacpd --bin nos-lldpd --bin nos-restd --bin nos-watchdogd --bin nos

FROM debian:bookworm-slim AS runtime

RUN groupadd --system nos \
    && useradd --system --gid nos --no-create-home --home-dir /nonexistent nos \
    && mkdir -p /run/nos /var/lib/nos \
    && chown nos:nos /run/nos /var/lib/nos

COPY --from=builder /app/target/release/nos-configd    /usr/local/bin/nos-configd
COPY --from=builder /app/target/release/nos-bgpd       /usr/local/bin/nos-bgpd
COPY --from=builder /app/target/release/nos-ribd       /usr/local/bin/nos-ribd
COPY --from=builder /app/target/release/nos-interfaced /usr/local/bin/nos-interfaced
COPY --from=builder /app/target/release/nos-logd       /usr/local/bin/nos-logd
COPY --from=builder /app/target/release/nos-ospfd      /usr/local/bin/nos-ospfd
COPY --from=builder /app/target/release/nos-ospfv3d    /usr/local/bin/nos-ospfv3d
COPY --from=builder /app/target/release/nos-lacpd      /usr/local/bin/nos-lacpd
COPY --from=builder /app/target/release/nos-lldpd      /usr/local/bin/nos-lldpd
COPY --from=builder /app/target/release/nos-restd      /usr/local/bin/nos-restd
COPY --from=builder /app/target/release/nos-watchdogd  /usr/local/bin/nos-watchdogd
COPY --from=builder /app/target/release/nos            /usr/local/bin/nos

# nos-ribd/nos-interfaced's Linux drivers need CAP_NET_ADMIN/CAP_NET_RAW to
# program the kernel (VRF devices, addresses, routes) via rtnetlink, even
# though they run as the unprivileged `nos` user — file capabilities let an
# exec'd non-root process gain exactly these two capabilities, no more.
# nos-bgpd needs CAP_NET_RAW to scope its TCP sockets into a VRF via
# SO_BINDTODEVICE, and CAP_NET_BIND_SERVICE to listen on BGP's well-known
# port 179 (<1024) as the unprivileged `nos` user.
# nos-ospfd needs CAP_NET_RAW too, for its own VRF-scoped (SO_BINDTODEVICE)
# raw protocol-89 socket used to send/receive OSPF Hello packets.
# nos-ospfv3d needs CAP_NET_RAW for the same reason, over a raw IPv6
# protocol-89 socket instead (RFC 5340 Hello/DBD/LSR/LSU/LSAck).
# nos-lacpd needs CAP_NET_RAW too, for its own raw AF_PACKET/SOCK_RAW
# slow-protocols socket per member port (real LACPDU exchange) — no
# CAP_NET_ADMIN, since it never touches rtnetlink (see lacp/CLAUDE.md).
# nos-lldpd needs CAP_NET_RAW for the same reason, over a raw AF_PACKET
# socket per LLDP-enabled interface (see lldp/CLAUDE.md).
# nos-restd needs CAP_NET_RAW for SO_BINDTODEVICE, to bind its HTTP listener
# inside its routing table's VRF (see rest/CLAUDE.md).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcap2-bin \
    && setcap 'cap_net_admin,cap_net_raw=eip' /usr/local/bin/nos-ribd \
    && setcap 'cap_net_admin,cap_net_raw=eip' /usr/local/bin/nos-interfaced \
    && setcap 'cap_net_raw,cap_net_bind_service=eip' /usr/local/bin/nos-bgpd \
    && setcap 'cap_net_raw=eip' /usr/local/bin/nos-ospfd \
    && setcap 'cap_net_raw=eip' /usr/local/bin/nos-ospfv3d \
    && setcap 'cap_net_raw=eip' /usr/local/bin/nos-lacpd \
    && setcap 'cap_net_raw=eip' /usr/local/bin/nos-lldpd \
    && setcap 'cap_net_raw=eip' /usr/local/bin/nos-restd \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# `nos`'s `edit source` (policy-definition editing, see root CLAUDE.md's
# "nos-cli editing UX") shells out to $EDITOR/$VISUAL, falling back to nano
# — kept installed (unlike libcap2-bin above) since it's a runtime tool, not
# a build-time one.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        nano \
    && rm -rf /var/lib/apt/lists/*

USER nos
ENTRYPOINT ["nos-watchdogd"]
