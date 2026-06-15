# ARGUS — Next-Gen eBPF Firewall & Router Automation Platform

Unified, self-hosted firewall + router automation platform combining kernel-level
eBPF/XDP packet filtering with a Rust control plane, infrastructure-as-code for VyOS
routers, and full observability.

**Status:** Development. Phase 1–5 implemented. eBPF data plane requires nightly Rust.

## Features

- **eBPF/XDP Firewall** — line-rate packet filtering with CIDR-based allow/deny,
  token-bucket rate limiting, stateful connection tracking, port-scan detection
- **Router Automation** — NetBox source-of-truth → VyOS config reconciliation via
  Ansible + Event-Driven Ansible, config drift detection, automatic rollback
- **Observability** — Prometheus metrics, Loki structured logging, Grafana dashboards
- **REST API + Dashboard** — Axum REST API, SvelteKit web UI, JWT auth + RBAC
- **CLI + TUI** — clap-based CLI with ratatui live monitoring terminal UI
- **AI Anomaly Detection** — statistical baseline computation, deviation alerts
- **Threat Intelligence** — auto-sync from Spamhaus DROP/EDROP, AbuseIPDB
- **GitOps** — firewall rules managed via Git, CI validation, auto-apply
- **ZTNA Mesh** — WireGuard overlay with identity-aware policy engine
- **WASM Plugin System** — sandboxed `wasmtime` plugins for flow metadata inspection
- **Tamper-Evident Audit Log** — SHA-256 hash-chained entries
- **Multi-WAN Failover** — health-probe based automatic link failover

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ARGUS Dashboard (SvelteKit)               │
│                      https://<host>:5173                     │
└──────────────────────────┬──────────────────────────────────┘
                           │ REST + WebSocket
┌──────────────────────────▼──────────────────────────────────┐
│                    argus-api (Axum)                          │
│            JWT Auth • RBAC • Rate Limiting • WebSocket        │
└──┬────────────┬────────────┬────────────┬───────────────────┘
   │            │            │            │
   ▼            ▼            ▼            ▼
┌──────┐  ┌──────────┐  ┌────────┐  ┌──────────────────┐
│ eBPF │  │ argus-core│  │ NetBox │  │ VyOS/Vyos Router │
│ XDP  │  │ (Engine)  │  │ (SoT)  │  │  (via Ansible)   │
└──────┘  └──────────┘  └────────┘  └──────────────────┘
   │            │            │            │
   ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────┐
│              Observability Stack                             │
│     Prometheus • Grafana • Loki • OpenTelemetry              │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Rust 1.75+ (stable), eBPF needs nightly
- Linux kernel 5.15+ with `CONFIG_DEBUG_INFO_BTF=y`
- `build-essential`, `pkg-config`, `libssl-dev`, `clang`, `llvm`, `libbpf-dev`

### Build & Run (API only, no eBPF)

```bash
git clone <this-repo>
cd argus

cargo build --release --workspace --exclude argus-ebpf
cargo run --release -p argus-api

./target/release/argus-cli --api-url http://127.0.0.1:8443 rules
```

### Default Credentials
- **Username:** `admin`
- **Password:** `argus-admin`
- **API:** `https://127.0.0.1:8443`
- **Metrics:** `https://127.0.0.1:8443/metrics`

> Change these via `ARGUS_JWT_SECRET` env var in production.

### Enable eBPF (requires nightly Rust + bpf target)

```bash
rustup toolchain install nightly
rustup target add --toolchain nightly bpfel-unknown-none
cargo +nightly build --release -p argus-ebpf
```

## Repository Structure

```
argus/
├── crates/
│   ├── argus-ebpf/          # aya eBPF XDP/TC programs (#![no_std])
│   ├── argus-core/          # Rule engine, connection tracker, rate limiter,
│   │                          anomaly detection, threat intel, GitOps, ZTNA,
│   │                          WASM plugin, audit log, multi-WAN
│   ├── argus-api/           # Axum REST + WebSocket + JWT auth
│   ├── argus-orchestrator/  # NetBox + VyOS + Ansible integration
│   ├── argus-observability/ # Prometheus + Loki + tracing
│   ├── argus-cli/           # clap CLI + ratatui TUI
│   └── argus-common/        # Shared types, error definitions
├── frontend/                # SvelteKit dashboard
├── ansible/playbooks/       # VyOS config reconciliation playbooks
├── deploy/
│   ├── docker/              # Dockerfile + docker-compose
│   ├── grafana/             # Grafana dashboard JSON
│   └── systemd/             # Systemd unit files with hardening
├── tests/
│   ├── integration/
│   ├── e2e/
│   └── security/
├── docs/                    # Architecture, threat model, API spec, runbooks
├── scripts/bootstrap.sh     # Full bootstrap (idempotent)
├── Cargo.toml               # Workspace
└── rust-toolchain.toml
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ARGUS_JWT_SECRET` | `argus-dev-secret-...` | JWT signing secret (change in prod) |
| `ARGUS_API_URL` | `http://127.0.0.1:8443` | API URL for CLI |
| `DATABASE_URL` | (none) | PostgreSQL connection string |
| `REDIS_URL` | (none) | Redis connection string |
| `RUST_LOG` | `argus=info` | Log level filter |

## Documentation

- [Architecture](docs/architecture.md) — System design, data flow, component details
- [Threat Model](docs/threat-model.md) — Security analysis, trust boundaries, STRIDE
- [API Specification](docs/api-spec.yaml) — OpenAPI 3.0
- [Deployment](docs/deployment.md) — Production deployment guide
- [Development](docs/development.md) — Dev setup, testing, contributing
- [Runbooks](docs/runbooks/) — Operational procedures

## Security

### Vulnerability Disclosure

If you discover a security vulnerability in ARGUS, please report it via:

- **Email:** `security@<your-org>` (replace with your contact)
- **PGP Key:** (provide your PGP fingerprint)

We aim to acknowledge reports within 48 hours and provide a fix timeline within
5 business days. Do NOT open public issues for security vulnerabilities.

### Known Limitations (Production Readiness)
- eBPF data plane requires nightly Rust — not suitable for regulated environments
  without audit (stable Rust builds are production-ready for userspace components)
- JWT auth uses HS256 (symmetric) — for multi-node deployments, switch to RS256
- No built-in TLS termination — run behind nginx/Caddy with Let's Encrypt
- In-memory rule store (dev default) — use PostgreSQL for persistence

## License

MIT
