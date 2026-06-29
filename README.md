# ARGUS

**eBPF Firewall & Router Automation Platform**

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

ARGUS is a unified, self-hosted platform for kernel-level packet filtering,
network observability, and router configuration management. It combines an
eBPF/XDP data plane with a Rust control plane, infrastructure-as-code for VyOS
routers, and a web dashboard for operations.

---

## Capabilities

| Domain | Description |
|--------|-------------|
| **Firewall** | eBPF/XDP LPM-trie CIDR filtering, token-bucket rate limiting, connection tracking, port-scan detection |
| **Routing** | NetBox source-of-truth → VyOS config reconciliation, drift detection, auto-remediation |
| **Auth** | JWT (HS256), Admin/Operator/Viewer RBAC, middleware-enforced on all protected routes |
| **Observability** | Prometheus metrics, Loki structured logging, Grafana dashboard |
| **Threat Intel** | Spamhaus DROP/EDROP + AbuseIPDB auto-sync |
| **ZTNA** | WireGuard config generator with identity-aware policy engine |
| **Anomaly** | Statistical baseline (z-score), on-box computation, no cloud dependency |
| **GitOps** | Firewall rules in Git, CI validation, auto-apply |
| **WASM** | wasmtime sandbox, fuel-metered plugin execution |
| **Audit** | SHA-256 hash-chained audit log with integrity verification |
| **Multi-WAN** | Health-probe failover with auto-failback |
| **Rule Analytics** | Hit statistics, dead rule detection, top-matched rules |
| **Connection Drain** | Graceful draining before IP blocks (configurable timeout) |
| **Bulk Ops** | Up to 1,000 rules per API call |
| **Health** | Deep health checks for DB, Redis, eBPF, NetBox |
| **Dashboard** | Web UI with live stats, rule builder, connection tracker |
| **CLI + TUI** | clap-powered CLI and ratatui terminal monitor |

---

## Getting Started

### Prerequisites

- Rust 1.80+
- Build dependencies: `build-essential pkg-config libssl-dev libpq-dev`
- Optional: PostgreSQL 16, Redis 7, nightly Rust (eBPF)

### Build & Run

```bash
git clone https://github.com/zulfff/argus.git
cd argus

# Install system dependencies
sudo apt-get install -y build-essential pkg-config libssl-dev libpq-dev

# Set the JWT secret (required — server refuses to start without it)
export ARGUS_JWT_SECRET="replace-with-a-random-string-at-least-32-characters"

# Build and start
cargo build --release --workspace --exclude argus-ebpf
cargo run --release -p argus-api
```

On first startup, the server creates an `admin` user with an auto-generated
password printed to the terminal output. Look for the `Password:` line.

### First API Call

```bash
# Health check
curl http://127.0.0.1:8443/health

# Login (substitute <password> from startup output)
curl -X POST http://127.0.0.1:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<password>"}'
```

Use the returned `access_token` in subsequent requests as `Authorization: Bearer <token>`.

### Default Credentials

| Setting | Default | Override |
|---------|---------|----------|
| Username | `admin` | `ARGUS_ADMIN_USER` |
| Password | auto-generated | `ARGUS_ADMIN_PASS` |
| API URL | `http://127.0.0.1:8443` | `ARGUS_TLS_CERT` / `ARGUS_TLS_KEY` |
| JWT secret | required | `ARGUS_JWT_SECRET` (≥32 bytes) |

### Troubleshooting

| Symptom | Cause |
|---------|-------|
| `Connection refused` | Server not running — check terminal output |
| `HTTP 502` on HTTPS | Use HTTP unless TLS is configured |
| Server exits immediately | `ARGUS_JWT_SECRET` missing or < 32 characters |
| Build failure | Missing `libpq-dev` — `sudo apt install libpq-dev` |
| `cargo: command not found` | Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |

---

## eBPF Data Plane

The eBPF/XDP firewall requires nightly Rust and the `bpfel-unknown-none` target.
If unavailable, the server starts with the eBPF data plane disabled — firewall
rules are enforced in userspace via the rule engine.

```bash
rustup toolchain install nightly
rustup +nightly target add bpfel-unknown-none
cargo +nightly build --release -p argus-ebpf

sudo cp target/bpfel-unknown-none/release/argus-ebpf /var/lib/argus/argus-ebpf.o
export ARGUS_WAN_IFACE=eth0
export ARGUS_EBPF_OBJECT=/var/lib/argus/argus-ebpf.o
cargo run --release -p argus-api
```

### Default Mode

The eBPF firewall starts in **default-allow** mode to prevent lockout on first
attach. To switch to **default-deny**:

```bash
# 1. Add allowlist rules INCLUDING your management IP
#    POST /api/v1/rules  { "action": "allow", "src_cidr": "10.0.0.5/32", ... }

# 2. Verify your IP is listed
#    GET /api/v1/rules

# 3. Switch to deny mode and restart
export ARGUS_EBPF_DEFAULT_MODE=deny
cargo run --release -p argus-api
```

> Setting `ARGUS_EBPF_DEFAULT_MODE=deny` without allowlisting your management
> IP first will drop all traffic including your SSH session.

---

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `ARGUS_JWT_SECRET` | **Yes** | — | JWT signing key (≥32 bytes, HS256) |
| `ARGUS_ADMIN_USER` | No | `admin` | Initial admin username |
| `ARGUS_ADMIN_PASS` | No | random | Initial admin password |
| `RUST_LOG` | No | `argus=info` | Log level filter |
| `ARGUS_PRODUCTION` | No | — | Enforce TLS and CORS origin validation |
| `ARGUS_TLS_CERT` | No | — | TLS certificate path (PEM) |
| `ARGUS_TLS_KEY` | No | — | TLS private key path (PEM) |
| `ARGUS_ALLOWED_ORIGINS` | No* | — | Comma-separated CORS origins (\*required in production) |
| `DATABASE_URL` | No | — | PostgreSQL connection string (in-memory if unset) |
| `REDIS_URL` | No | — | Redis connection string |
| `ARGUS_WAN_IFACE` | No | — | Interface for XDP attach (e.g. `eth0`) |
| `ARGUS_EBPF_OBJECT` | No | `/var/lib/argus/argus-ebpf.o` | Path to compiled eBPF object |
| `ARGUS_EBPF_DEFAULT_MODE` | No | `allow` | Default firewall action: `allow` or `deny` |
| `NETBOX_URL` | No | — | NetBox API URL (enables orchestrator) |
| `NETBOX_TOKEN` | No | — | NetBox API token |
| `VYOS_ADDRESS` | No | — | VyOS router hostname or IP |
| `VYOS_PORT` | No | `443` | VyOS API port |
| `ARGUS_SCALAR_SRI` | No | — | SRI hash for Scalar API docs CDN script |

---

## Architecture

```
   Web Dashboard              CLI / TUI
        │                         │
        ▼                         ▼
┌──────────────────────────────────────────┐
│           argus-api (Axum 0.7)            │
│   Auth · RBAC · Rate Limit · Audit Log    │
└──┬─────────┬──────────┬──────────┬───────┘
   │         │          │          │
   ▼         ▼          ▼          ▼
┌──────┐ ┌───────┐ ┌────────┐ ┌──────────────┐
│ eBPF │ │ Core  │ │ NetBox │ │ VyOS Router  │
│ XDP  │ │Engine │ │  (SoT) │ │ (via Ansible) │
└──────┘ └───────┘ └────────┘ └──────────────┘
   │         │          │          │
   └─────────┴──────────┴──────────┘
                  │
                  ▼
   ┌──────────────────────────────┐
   │       Observability          │
   │ Prometheus · Grafana · Loki  │
   └──────────────────────────────┘
```

### Source Layout

```
crates/
├── argus-ebpf/            aya XDP/TC programs (#![no_std])
├── argus-core/            Engine modules (rule, connection, rate-limit,
│                          scan, anomaly, threat, gitops, ztna, wasm,
│                          audit, multi-wan, QoS, DPI, scheduler)
├── argus-api/             Axum REST + WebSocket + JWT auth
├── argus-orchestrator/    NetBox + VyOS + Ansible + drift detection
├── argus-observability/   Prometheus + Loki + tracing
├── argus-cli/             clap CLI + ratatui TUI
└── argus-common/          Shared types, errors, audit primitives
frontend/                  Web dashboard (React + TailwindCSS)
deploy/                    Docker, docker-compose, Grafana, systemd
ansible/                   VyOS playbooks (firewall reconcile, backup)
docs/                      Architecture, threat model, API spec, runbooks
```

---

## Security

### Vulnerability Disclosure

Report security issues to `arjunaajalahla100@gmail.com`. Do not open public
issues for vulnerabilities. Acknowledgment within 48 hours, fix within 5
business days.

See [SECURITY.md](SECURITY.md) for full policy.

---

## Documentation

| Document | Content |
|----------|---------|
| [Architecture](docs/architecture.md) | Design, data flows, component details |
| [Threat Model](docs/threat-model.md) | STRIDE analysis, trust boundaries, controls |
| [API Spec](docs/api-spec.yaml) | OpenAPI 3.0 specification |
| [Deployment](docs/deployment.md) | Bare-metal, Docker, TLS via reverse proxy |
| [Development](docs/development.md) | Setup, conventions, eBPF, troubleshooting |
| [Runbooks](docs/runbooks/) | Operational procedures |
| [Codebase Guide](docs/codebase-guide.md) | Module-by-module walkthrough |

## License

MIT — see [LICENSE](LICENSE)
