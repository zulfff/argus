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

- **eBPF/XDP Firewall** — LPM-trie CIDR allow/deny (requires nightly + `bpfel-unknown-none` to compile, `ARGUS_WAN_IFACE` to load), token-bucket rate limiting, connection tracking, port-scan detection
- **Router Automation** — NetBox source-of-truth → VyOS config reconciliation (env: `NETBOX_URL`, `NETBOX_TOKEN`, `VYOS_ADDRESS`), drift detection
- **Observability** — Prometheus metrics, Loki structured logging, Grafana dashboard
- **Web Dashboard** — Custom cyberpunk/terminal SvelteKit UI (not Tailwind, not AI-generated) with live stats, rule builder, connection tracker
- **CLI + TUI** — clap CLI + ratatui live terminal monitor
- **Auth + RBAC** — JWT (HS256, iss/aud/nbf, 5s leeway), Admin/Operator/Viewer roles, auto-wired middleware on all routes
- **Statistical Anomaly Detection** — statistical baseline computation (z-score), background polling from connection tracker, on-box, no cloud dependency
- **Threat Intelligence** — auto-sync Spamhaus DROP/EDROP + AbuseIPDB
- **GitOps** — firewall rules in Git, CI validation, auto-apply
- **ZTNA Mesh** — WireGuard config generator + identity-aware policy engine (config download via API; live WireGuard interface management not yet wired)
- **WASM Plugin** — wasmtime sandbox, fuel-metered, metadata passed to plugin (hardcoded memory offset; alloc-based memory negotiation upcoming)
- **Audit Log** — SHA-256 hash-chained, tamper-evident, integrity verification
- **Multi-WAN Failover** — health-probe based, auto-failback (configured via VyOS, not yet API-driven)

## Quick Start

```bash
git clone https://github.com/zulfff/argus.git
cd argus

# 1. Install build deps
sudo apt-get install -y build-essential pkg-config libssl-dev libpq-dev

# 2. Set JWT secret (REQUIRED — server refuses without it)
export ARGUS_JWT_SECRET="change-me-to-a-random-32-plus-character-string"

# 3. Build & run
cargo build --release --workspace --exclude argus-ebpf
cargo run --release -p argus-api
# Watch logs for auto-generated admin password: "Generated admin password: xxxx"
```

### First Login

```bash
# Health check
curl http://127.0.0.1:8443/health

# Replace <password> with the one from startup logs
curl -X POST http://127.0.0.1:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<password>"}'
```

| Setting | Value | Notes |
|---------|-------|-------|
| API URL | `http://127.0.0.1:8443` | HTTP — TLS via reverse proxy in production |
| Username | `admin` | Override with `ARGUS_ADMIN_USER` |
| Password | auto-generated | Override with `ARGUS_ADMIN_PASS` |
| JWT Secret | **required** | Set `ARGUS_JWT_SECRET` ≥ 32 bytes |
| Log Level | `argus=info` | Set `RUST_LOG` |

**GitHub Codespaces:** after running the server, open the Ports tab (bottom panel) and ensure port 8443 is forwarded. Then use `curl http://localhost:8443/health`.

**Common issues:**
| Symptom | Likely cause |
|---------|-------------|
| `curl: (7) Connection refused` | Server didn't start — check terminal output for error |
| `HTTP 502 Bad Gateway` | Using HTTPS (`https://`) — use HTTP (`http://`) |
| Server exits immediately | `ARGUS_JWT_SECRET` not set or < 32 characters |
| `Build fails` | Missing `libpq-dev` — `sudo apt install libpq-dev` |
| `cargo: command not found` | Rust not installed — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |

### Enable eBPF data plane
```bash
# Requires nightly Rust + bpfel-unknown-none target (may need -Z build-std)
rustup toolchain install nightly
rustup +nightly target add bpfel-unknown-none
cargo +nightly build --release -p argus-ebpf

# Copy object and set env vars
sudo cp target/bpfel-unknown-none/release/argus-ebpf /var/lib/argus/argus-ebpf.o
export ARGUS_WAN_IFACE=eth0
export ARGUS_EBPF_OBJECT=/var/lib/argus/argus-ebpf.o
cargo run --release -p argus-api
```

> **Note:** eBPF compilation requires nightly toolchain with the `bpfel-unknown-none` target.
> If the target is unavailable (some environments cannot build it), the server starts with
> eBPF data plane disabled — firewall rules still work via userspace `rule_engine.rs`.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ARGUS_JWT_SECRET` | **Yes** | — | JWT signing key (≥32 bytes, HS256) |
| `ARGUS_ADMIN_USER` | No | `admin` | Initial admin username |
| `ARGUS_ADMIN_PASS` | No | random | Initial admin password (auto-gen if unset) |
| `RUST_LOG` | No | `argus=info` | Log level filter |
| `DATABASE_URL` | No | — | PostgreSQL (optional, in-memory default) |
| `REDIS_URL` | No | — | Redis (optional) |
| `ARGUS_WAN_IFACE` | No | — | Interface for eBPF XDP attach (e.g. `eth0`). Requires `ARGUS_EBPF_OBJECT` |
| `ARGUS_EBPF_OBJECT` | No | `/var/lib/argus/argus-ebpf.o` | Path to compiled eBPF .o file |
| `NETBOX_URL` | No | — | NetBox API base URL (enables orchestrator) |
| `NETBOX_TOKEN` | No | — | NetBox API token (required with `NETBOX_URL`) |
| `VYOS_ADDRESS` | No | — | VyOS router address for drift detection |
| `VYOS_PORT` | No | `443` | VyOS API port |

> **Without `ARGUS_JWT_SECRET` ≥ 32 bytes, the server refuses to start.** No fallback, no hardcoded secret.

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
