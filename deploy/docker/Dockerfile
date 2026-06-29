FROM rust:1-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
RUN cargo build --release --workspace --exclude argus-ebpf && \
    cp target/release/argus-api /argus-api && \
    cp target/release/argus-cli /argus-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /argus-api /usr/local/bin/argus-api
COPY --from=builder /argus-cli /usr/local/bin/argus-cli
COPY deploy/docker/entrypoint.sh /entrypoint.sh

RUN addgroup --system argus && adduser --system --ingroup argus argus && \
    mkdir -p /var/lib/argus && chown -R argus:argus /var/lib/argus && \
    chmod +x /entrypoint.sh

EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget --no-check-certificate -qO- https://localhost:8443/health || exit 1
USER argus
ENTRYPOINT ["/entrypoint.sh"]