# ARGUS — Next-Gen eBPF Firewall & Router Automation Platform

**[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-40%20passed-brightgreen)]()
[![Clippy](https://img.shields.io/badge/clippy-clean-brightgreen)]()
[![Audit](https://img.shields.io/badge/security%20audit-27%20fixed-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()**

Unified, self-hosted firewall + router automation platform combining kernel-level
eBPF/XDP packet filtering with a Rust control plane, infrastructure-as-code for VyOS
routers, and full observability — all in Rust, all memory-safe.

## Features

- **eBPF/XDP Firewall** — line-rate packet filtering (CIDR allow/deny, token-bucket rate limiting, stateful connection tracking, port-scan detection)
- **Router Automation** — NetBox source-of-truth → VyOS config reconciliation via Ansible + Event-Driven Ansible, drift detection, auto-rollback
- **Observability** — Prometheus metrics, Loki structured logging, Grafana dashboard
- **Web Dashboard** — Custom cyberpunk/terminal SvelteKit UI (not Tailwind, not AI-generated) with live stats, rule builder, connection tracker
- **CLI + TUI** — clap CLI + ratatui live terminal monitor
- **Auth + RBAC** — JWT (HS256, iss/aud/nbf, 5s leeway), Admin/Operator/Viewer roles, auto-wired middleware on all routes
- **AI Anomaly Detection** — statistical baseline computation (z-score), on-box, no cloud dependency
- **Threat Intelligence** — auto-sync Spamhaus DROP/EDROP + AbuseIPDB
- **GitOps** — firewall rules in Git, CI validation, auto-apply
- **ZTNA Mesh** — WireGuard overlay with identity-aware policy engine
- **WASM Plugin** — wasmtime sandbox, fuel-metered, metadata-only access
- **Audit Log** — SHA-256 hash-chained, tamper-evident, integrity verification
- **Multi-WAN Failover** — health-probe based, auto-failback

## Quick Start

```bash
git clone https://github.com/zulfff/argus.git
cd argus

# Minimal build tools
sudo apt-get install -y build-essential pkg-config libssl-dev

# Build & run
cargo build --release --workspace --exclude argus-ebpf
cargo run --release -p argus-api

# CLI in another terminal
cargo run --release -p argus-cli -- rules
```

### First Login

- **URL:** http://127.0.0.1:8443/api/v1/auth/login
- **Username:** `admin` (default, configurable via `ARGUS_ADMIN_USER`)
- **Password:** set via `ARGUS_ADMIN_PASS` env var, or auto-generated

### Enable eBPF data plane
```bash
rustup toolchain install nightly
rustup target add --toolchain nightly bpfel-unknown-none
cargo +nightly build --release -p argus-ebpf
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ARGUS_JWT_SECRET` | **Yes** | — | JWT signing key (≥32 bytes, HS256) |
| `ARGUS_ADMIN_USER` | No | `admin` | Initial admin username |
| `ARGUS_ADMIN_PASS` | No | random | Initial admin password (auto-gen if unset) |
| `RUST_LOG` | No | `argus=info` | Log level filter |
| `DATABASE_URL` | No | — | PostgreSQL (optional, in-memory default) |
| `REDIS_URL` | No | — | Redis (optional) |

> Startup refuses if `ARGUS_JWT_SECRET` is < 32 bytes. No hardcoded fallback.

## Security

### Audit Status
Full security audit completed — **27 findings fixed** (3 Critical, 5 High, 13 Medium, 6 Low).

Key fixes:
- No hardcoded secrets anywhere (JWT, passwords)
- Auth middleware wired on ALL protected routes
- TLS enforced on VyOS client (was `danger_accept_invalid_certs`)
- Path traversal protection via `Path::canonicalize` + prefix check
- WebSocket requires JWT token in query param
- CIDR prefix validated against overflow (safe `wrapping_shl`)
- All user input validated at API boundary (CIDR, protocol, name length, URL scheme)
- Login failures logged with IP + username
- JWT: `iss`/`aud`/`nbf` claims, leeway reduced 30s→5s
- Audit log hash-chained, integrity verifiable
- Rate limit: 5 req/s on login, 100 req/s globally

### Vulnerability Disclosure
Email: **arjunaajalahla100@gmail.com**

Do NOT open public issues for security vulnerabilities.
Acknowledgment within 48h, fix within 5 business days.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              SvelteKit Dashboard (custom terminal UI)        │
│                   http://localhost:5173                      │
└──────────────────────────┬──────────────────────────────────┘
                           │ REST + WebSocket (JWT-auth)
┌──────────────────────────▼──────────────────────────────────┐
│              argus-api (Axum 0.7 + Tower)                   │
│     Auth Middleware · RBAC · Rate Limiting · Audit Log       │
└──┬────────────┬────────────┬────────────┬───────────────────┘
   │            │            │            │
   ▼            ▼            ▼            ▼
┌──────┐  ┌──────────┐  ┌────────┐  ┌──────────────────┐
│ eBPF │  │argus-core│  │ NetBox │  │ VyOS Router      │
│ XDP  │  │11 modules│  │ (SoT)  │  │ (via Ansible)    │
└──────┘  └──────────┘  └────────┘  └──────────────────┘
   │            │            │            │
   ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────┐
│              Observability                                   │
│     Prometheus · Grafana · Loki · Alertmanager               │
└─────────────────────────────────────────────────────────────┘
```

## Repository

```
crates/
├── argus-ebpf/           aya XDP/TC programs (#![no_std])
├── argus-core/           11 engines (rule, conn, rate, scan,
│                         anomaly, threat, gitops, ztna, wasm,
│                         audit, multi-wan)
├── argus-api/            Axum REST + WebSocket + JWT auth
├── argus-orchestrator/   NetBox + VyOS + Ansible + drift
├── argus-observability/  Prometheus + Loki + tracing
├── argus-cli/            clap CLI + ratatui live TUI
└── argus-common/         Types, errors, shared definitions
frontend/                 SvelteKit — custom terminal UI
ansible/playbooks/        VyOS reconciliation + backup
deploy/                   Docker, docker-compose, Grafana, systemd
docs/                     Architecture, threat model, API spec, runbooks
```

## Documentation

| Doc | Description |
|-----|-------------|
| [Architecture](docs/architecture.md) | 5-layer design, data flows, component details |
| [Threat Model](docs/threat-model.md) | STRIDE analysis, trust boundaries, controls matrix |
| [API Spec](docs/api-spec.yaml) | OpenAPI 3.0, 13 endpoints, 8 schemas |
| [Deployment](docs/deployment.md) | Bare-metal, Docker, nginx/Caddy TLS |
| [Development](docs/development.md) | Dev setup, conventions, eBPF, troubleshooting |
| [Runbooks](docs/runbooks/) | 10 operational procedures |
| [Security Policy](SECURITY.md) | Disclosure policy, supported versions, scope |

## License

MIT — see [LICENSE](LICENSE)
