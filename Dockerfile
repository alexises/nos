# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder
WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --bin nos-configd --bin nos-bgpd --bin nos-ribd --bin nos-watchdogd --bin nos

FROM debian:bookworm-slim AS runtime

RUN groupadd --system nos \
    && useradd --system --gid nos --no-create-home --home-dir /nonexistent nos \
    && mkdir -p /run/nos /var/lib/nos \
    && chown nos:nos /run/nos /var/lib/nos

COPY --from=builder /app/target/release/nos-configd   /usr/local/bin/nos-configd
COPY --from=builder /app/target/release/nos-bgpd      /usr/local/bin/nos-bgpd
COPY --from=builder /app/target/release/nos-ribd      /usr/local/bin/nos-ribd
COPY --from=builder /app/target/release/nos-watchdogd /usr/local/bin/nos-watchdogd
COPY --from=builder /app/target/release/nos           /usr/local/bin/nos

USER nos
ENTRYPOINT ["nos-watchdogd"]
