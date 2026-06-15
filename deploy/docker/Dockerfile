FROM rust:1-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/argus-common crates/argus-common
COPY crates/argus-core crates/argus-core
COPY crates/argus-api crates/argus-api
COPY crates/argus-observability crates/argus-observability
RUN cargo build --release -p argus-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/argus-api /usr/local/bin/argus-api
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8443/health || exit 1
USER nobody
ENTRYPOINT ["/usr/local/bin/argus-api"]
