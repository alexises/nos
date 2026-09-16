# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder
WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --bin nos-configd --bin nos-bgpd --bin nos-ribd --bin nos-interfaced --bin nos-logd --bin nos-watchdogd --bin nos

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
COPY --from=builder /app/target/release/nos-watchdogd  /usr/local/bin/nos-watchdogd
COPY --from=builder /app/target/release/nos            /usr/local/bin/nos

# nos-ribd/nos-interfaced's Linux drivers need CAP_NET_ADMIN/CAP_NET_RAW to
# program the kernel (VRF devices, addresses, routes) via rtnetlink, even
# though they run as the unprivileged `nos` user — file capabilities let an
# exec'd non-root process gain exactly these two capabilities, no more.
# nos-bgpd needs CAP_NET_RAW to scope its TCP sockets into a VRF via
# SO_BINDTODEVICE, and CAP_NET_BIND_SERVICE to listen on BGP's well-known
# port 179 (<1024) as the unprivileged `nos` user.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcap2-bin \
    && setcap 'cap_net_admin,cap_net_raw=eip' /usr/local/bin/nos-ribd \
    && setcap 'cap_net_admin,cap_net_raw=eip' /usr/local/bin/nos-interfaced \
    && setcap 'cap_net_raw,cap_net_bind_service=eip' /usr/local/bin/nos-bgpd \
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
