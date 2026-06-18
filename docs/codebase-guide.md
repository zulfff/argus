# ARGUS — Codebase Guide & Architecture Reference

## Daftar Isi

1. [Project Overview](#1-project-overview)
2. [Repository Structure](#2-repository-structure)
3. [Workspace Cargo Crates](#3-workspace-cargo-crates)
4. [Backend Architecture (Rust)](#4-backend-architecture-rust)
5. [Frontend Architecture (SvelteKit)](#5-frontend-architecture-sveltekit)
6. [API Endpoints Reference](#6-api-endpoints-reference)
7. [Auth & RBAC Flow](#7-auth--rbac-flow)
8. [Data Flow Diagrams](#8-data-flow-diagrams)
9. [Database Models](#9-database-models)
10. [Deployment Guide](#10-deployment-guide)

---

## 1. Project Overview

**ARGUS** is a next-generation, self-hosted eBPF firewall & router automation platform. Nama "ARGUS" diambil dari mitologi Yunani — raksasa bermata seratus yang selalu waspada.

### Core Capabilities

| Layer | Teknologi | Fungsi |
|-------|-----------|--------|
| **Data Plane** | eBPF/XDP (aya) | Packet filtering line-rate, connection tracking, rate limiting |
| **Control Plane** | Rust + Tokio | Rule engine, anomaly detection, threat intel, 25+ engines |
| **API** | Axum 0.7 | REST API, WebSocket, JWT auth, RBAC |
| **Presentation** | SvelteKit 5 + Chart.js | Dashboard, live charts, WebSocket real-time |
| **Automation** | Ansible + VyOS | Config reconciliation, drift detection |
| **Observability** | Prometheus + Grafana + Loki | Metrics, logs, dashboards |

### Tech Stack Detail

```
Language: Rust (edition 2021, stable)
Async:    Tokio 1.x (full features)
HTTP:     Axum 0.7 + Tower middleware
DB:       PostgreSQL (optional, in-memory by default)
Cache:    Redis (optional)
Auth:     JWT HS256 + Argon2 password hashing
eBPF:     aya 0.1 (#![no_std] kernel programs)
Frontend: Svelte 5 + SvelteKit 2 + Vite 5
Charts:   Chart.js 4.4 + svelte-chartjs 3.1
CLI:      clap 4 + ratatui 0.28 + crossterm 0.28
WASM:     wasmtime 28 (optional, feature-gated)
```

---

## 2. Repository Structure

```
argus/
├── Cargo.toml                    # Workspace root (7 crates + shared deps)
├── rust-toolchain.toml           # Stable Rust + components
├── crates/
│   ├── argus-common/             # Shared types, error definitions
│   ├── argus-core/               # 25 engine modules (control plane)
│   ├── argus-api/                # Axum REST API (routes, auth, middleware)
│   ├── argus-ebpf/               # eBPF XDP programs (#![no_std])
│   ├── argus-orchestrator/       # NetBox + VyOS + Ansible + drift
│   ├── argus-observability/      # Prometheus + tracing + logging
│   └── argus-cli/                # clap CLI + ratatui TUI
├── frontend/                     # SvelteKit dashboard
│   ├── src/routes/               # Pages: dashboard, rules, connections, alerts, audit, login
│   ├── src/lib/stores/           # Svelte stores: auth.js, live.js, theme.js
│   └── src/app.css              # Custom design system (520 lines)
├── deploy/                       # Docker, systemd, Grafana, Prometheus
├── ansible/                      # VyOS playbooks + roles
├── docs/                         # Architecture, threat model, API spec
├── scripts/                      # bootstrap.sh, install-router.sh
├── tests/                        # Integration, e2e, security (placeholder)
└── terraform/                    # (placeholder)
```

---

## 3. Workspace Cargo Crates

### Dependency Graph

```
argus-common (no internal deps)
  ├── argus-core (25 modules)
  │     ├── argus-api (REST API)
  │     └── argus-cli (CLI + TUI)
  ├── argus-orchestrator (NetBox/VyOS/Ansible)
  └── argus-observability (Prometheus/Loki)
argus-ebpf (independent, nightly-only)
```

### argus-common (`/crates/argus-common`)

Shared types and error definitions used by all crates:

- **`types.rs`** — `CidrRule`, `Action` (Allow/Deny/RateLimit), `Direction` (Inbound/Outbound/Forward), `ConnectionEntry`, `ConnectionState` (New/Established/Closing/Closed), `RateLimitBucket`, `ScanAlert`, `ScanSeverity`, `EbpfStats`
- **`error.rs`** — `ArgusError` enum (13 variants: Config, Ebpf, Network, Database, Validation, Auth, Forbidden, NotFound, RateLimited, External, Serialization, Io, Internal), `Result<T>` type alias

### argus-core (`/crates/argus-core`)

**25 engine modules** — heart of the control plane:

| Module | File | Fungsi |
|--------|------|--------|
| **`rule_engine`** | `rule_engine.rs` | CIDR bitmask matching, protocol/port matching, priority ordering, `RuleStore` trait |
| **`connection_tracker`** | `connection_tracker.rs` | 5-tuple connection table, TTL-based expiry, LRU eviction |
| **`rate_limiter`** | `rate_limiter.rs` | Token bucket per IP, timed refill, GC idle buckets |
| **`scanner`** | `scanner.rs` | Port-scan detection (10 ports/10s), auto-block 5min |
| **`anomaly`** | `anomaly.rs` | Statistical z-score baseline, 60-min window, alert thresholds |
| **`threat_intel`** | `threat_intel.rs` | Spamhaus DROP/EDROP + AbuseIPDB sync, TTL-based blocklist |
| **`gitops`** | `gitops.rs` | Git clone/pull, diff-tree, CI validation, path traversal protection |
| **`ztna`** | `ztna.rs` | WireGuard config generator, peer management, policy engine |
| **`wasm_plugin`** | `wasm_plugin.rs` | wasmtime sandbox, fuel-metered (100k), 8 hook points (feature-gated) |
| **`audit_log`** | `audit_log.rs` | SHA-256 hash-chained log, integrity verification, query/export |
| **`multi_wan`** | `multi_wan.rs` | Health-probe HTTP checks, failover threshold, weight-based |
| **`alerting`** | `alerting.rs` | Alert rules engine, Webhook/Slack/Discord/Email notifications, cooldown |
| **`backup`** | `backup.rs` | Full config snapshot, SHA-256 checksum, restore with validation |
| **`scheduler`** | `scheduler.rs` | Cron-based rule enable/disable, background task every 60s |
| **`import_export`** | `import_export.rs` | Export rules JSON/YAML/CSV, import with validation |
| **`simulator`** | `simulator.rs` | What-if rule simulation, match path tracing |
| **`tenancy`** | `tenancy.rs` | Multi-tenant isolation, per-tenant config & users |
| **`cluster`** | `cluster.rs` | Raft-style node membership, heartbeat, leader election |
| **`reputation`** | `reputation.rs` | IP reputation scoring (-100 to 100), threat intel integration |
| **`dpi`** | `dpi.rs` | Layer 7 protocol identification (port-based + payload heuristic) |
| **`qos`** | `qos.rs` | Traffic shaping policies, bandwidth limits, DSCP marking |
| **`vpn_portal`** | `vpn_portal.rs` | WireGuard peer self-service, request/approve/revoke, client config gen |
| **`compliance`** | `compliance.rs` | Compliance report engine (audit, connections, blocked IPs, alerts) |
| **`syslog`** | `syslog.rs` | RFC 5424 syslog forwarding, TCP/UDP, severity filtering |

### argus-api (`/crates/argus-api`)

Axum REST API server with auth, middleware, and routes:

| Component | File | Fungsi |
|-----------|------|--------|
| **`main.rs`** | `main.rs` | App bootstrap, `AppState` struct (22 fields), router setup, startup |
| **`auth.rs`** | `auth.rs` | JWT (HS256), Argon2 password hashing, `Claims`, `Role`, `UserStore`, `JwtAuth` |
| **`middleware.rs`** | `middleware.rs` | Axum middleware: validasi JWT dari Authorization header, inject Claims ke request extensions |
| **`rule_store.rs`** | `rule_store.rs` | `InMemoryRuleStore` — HashMap-backed RuleStore implementation |
| **`websocket.rs`** | `websocket.rs` | `LiveEventBus` (broadcast channel), typed events (stats/connection/alert) |
| **`db_rule_store.rs`** | `db_rule_store.rs` | `PostgresRuleStore` — PostgreSQL-backed RuleStore |
| **`db_audit_store.rs`** | `db_audit_store.rs` | `PostgresAuditStore` — PostgreSQL-backed audit log |
| **`routes/`** | 18 route files | Semua handler endpoint API |

### argus-orchestrator (`/crates/argus-orchestrator`)

| Module | Fungsi |
|--------|--------|
| **`netbox.rs`** | REST API client, pagination, circuit breaker, exponential backoff |
| **`vyos.rs`** | HTTP API client, `safe_apply_config` with commit-confirm + rollback |
| **`ansible.rs`** | Ansible-playbook runner, PLAY RECAP parser, temp-file extra_vars |
| **`drift.rs`** | Compare NetBox intended vs VyOS actual, diff reports, remediation |

### argus-observability (`/crates/argus-observability`)

| Module | Fungsi |
|--------|--------|
| **`metrics.rs`** | 6 Prometheus metrics (IntCounterVec, IntGaugeVec) |
| **`logging.rs`** | Structured logging (JSON) via tracing |
| **`tracing_setup.rs`** | OpenTelemetry tracing setup |

### argus-cli (`/crates/argus-cli`)

- **`main.rs`** — clap CLI: rules, stats, connections, block, unblock, tui
- **`tui.rs`** — ratatui live terminal monitor (263 lines)

### argus-ebpf (`/crates/argus-ebpf`)

- **`xdp.rs`** — XDP firewall: blocklist, allowlist, rate limit, connection track
- **`maps.rs`** — 6 BPF maps: BLOCKLIST, ALLOWLIST, CONNTRACK, RATE_LIMIT, PER_CPU_PACKETS, EVENTS

---

## 4. Backend Architecture (Rust)

### AppState — Central State Container

Semua state aplikasi disimpan di `AppState` (dibungkus `Arc<AppState>`):

```rust
pub struct AppState {
    pub rule_engine: RuleEngine,
    pub connection_tracker: ConnectionTracker,
    pub rate_limiter: RateLimiter,
    pub scan_detector: ScanDetector,
    pub metrics: ArgusMetrics,
    pub event_bus: LiveEventBus,
    pub auth_config: AuthConfig,
    pub audit_log: AuditLog,
    pub alert_manager: AlertManager,
    pub tenant_manager: TenantManager,
    pub cluster_manager: ClusterManager,
    pub reputation_manager: ReputationManager,
    pub scheduler_engine: SchedulerEngine,
    pub vpn_portal: VpnPortalManager,
    pub dpi: DpiEngine,
    pub qos: QosManager,
    pub compliance: ComplianceEngine,
    pub syslog: SyslogForwarder,
    pub db_pool: Option<sqlx::PgPool>,
    pub backup_manager: BackupManager,
}
```

### Router Structure

Dua grup router dipisah — **public** (no auth) dan **protected** (JWT required):

```
Router.new()
  ├── /health                          (public)
  ├── /api/v1/auth/login               (public)
  ├── /api/v1/auth/refresh             (public)
  ├── /metrics                         (public)
  ├── /api/v1/ws                       (public — token in query param)
  ├── /api/v1/openapi.yaml             (public)
  ├── /docs                            (public)
  └── protected_routes (merged)
       ├── Auth middleware (JWT validation)
       ├── RBAC check on each handler
       ├── /api/v1/auth/users          (CRUD)
       ├── /api/v1/rules               (CRUD + export/import/simulate)
       ├── /api/v1/stats
       ├── /api/v1/connections
       ├── /api/v1/block
       ├── /api/v1/audit              (list/verify/export)
       ├── /api/v1/alerts             (rules + history)
       ├── /api/v1/tenants            (Admin)
       ├── /api/v1/cluster            (nodes + status)
       ├── /api/v1/reputation
       ├── /api/v1/schedules
       ├── /api/v1/vpn                (requests + config)
       ├── /api/v1/dpi/identify
       ├── /api/v1/qos/policies
       ├── /api/v1/compliance/reports
       ├── /api/v1/syslog/configs
       └── /api/v1/backup
  └── GovernorLayer (rate limit: 100 req/s, burst 200)
```

### Auth Middleware Flow

```
Request → GovernorLayer → Auth Middleware → Protected Route Handler
                                    │
                         ┌──────────┴──────────┐
                         │ Extract Bearer token │
                         │  from Authorization  │
                         │       header         │
                         └──────────┬──────────┘
                                    │
                         ┌──────────┴──────────┐
                         │  Validate JWT HS256  │
                         │  iss="argus"         │
                         │  aud="argus-api"     │
                         │  exp check + 5s      │
                         │  leeway              │
                         └──────────┬──────────┘
                                    │
                         ┌──────────┴──────────┐
                         │ Insert `Claims` into │
                         │ request extensions   │
                         └──────────┬──────────┘
                                    │
                         Handler extracts Claims
                         with Extension<Claims>
                         ↓ checks role.can_read()
                           role.can_write()
                           role.can_delete()
```

### RBAC Role Hierarchy

```
Admin   → can_read() ✓  can_write() ✓  can_delete() ✓  can_manage_users() ✓
Operator → can_read() ✓  can_write() ✓  can_delete() ✗  can_manage_users() ✗
Viewer  → can_read() ✓  can_write() ✗  can_delete() ✗  can_manage_users() ✗
```

---

## 5. Frontend Architecture (SvelteKit)

### Project Structure

```
frontend/
├── package.json              # Deps: Svelte 5, SvelteKit 2, chart.js, svelte-chartjs
├── vite.config.js            # Proxy: /api → localhost:8443, /ws → ws://localhost:8443
├── svelte.config.js          # Static adapter, $lib alias
└── src/
    ├── app.css               # Custom design system (520 lines, CSS custom properties)
    ├── lib/
    │   └── stores/
    │       ├── auth.js       # authToken, authRole, apiFetch helper
    │       ├── live.js       # WebSocket connection, liveStats, liveConnections, liveAlerts
    │       └── theme.js      # Dark/Light theme toggle (persisted in localStorage)
    └── routes/
        ├── +layout.svelte    # Shell: header (nav + theme toggle), status bar footer
        ├── login/+page.svelte    # JWT login form
        ├── dashboard/+page.svelte  # Stats cards + 3 charts (Line, Bar, Doughnut) + WS live
        ├── rules/+page.svelte    # CRUD table, search, bulk delete, pagination, templates, export
        ├── connections/+page.svelte # Live connection table, search, filter, kill, geo-flags
        ├── alerts/+page.svelte   # Alert rules config + history + acknowledge
        └── audit/+page.svelte    # Audit log table, filter by actor/action, export, verify
```

### Design System (`app.css`)

Custom terminal/cyberpunk aesthetic — **tidak pakai Tailwind**:

- CSS custom properties: `--bg-root: #0a0c0f`, `--cyan: #39d0ff`, etc.
- Fonts: JetBrains Mono + Share Tech Mono
- Components: `.card`, `.stat-card`, `.badge` (allow/deny/warn/info/on/off), `.btn`, `.input`, `.select`, `.data-table`, `.shell` (header bar), `.status-bar`
- Animations: `pulse`, `fadeIn`, `shimmer`
- Light theme: `[data-theme="light"]` — override CSS variables
- Responsive: `@media (max-width: 768px)`

### API Communication Pattern

```
Frontend → Vite Dev Proxy (/api → localhost:8443) → argus-api
           OR
           Direct in production (reverse proxy)

// Standard API call (auth.js)
export async function apiFetch(path, options = {}) {
  // Get JWT token from store
  // Add Authorization: Bearer <token> header
  // Handle 401 → clear token, redirect to login
  // Parse JSON response
}

// WebSocket real-time (live.js)
function connectWebSocket(token) {
  ws = new WebSocket(`ws://${host}/api/v1/ws?token=${token}`)
  ws.onmessage = (event) => {
    const { event_type, data } = JSON.parse(event.data)
    if (event_type === 'stats') liveStats.set(data)
    if (event_type === 'connection') liveConnections.update(...)
    if (event_type === 'alert') liveAlerts.update(...)
  }
  // Auto-reconnect on close
}
```

---

## 6. API Endpoints Reference

### Auth (Public)

| Method | Path | Body | Response |
|--------|------|------|----------|
| `POST` | `/api/v1/auth/login` | `{ username, password }` | `{ access_token, refresh_token, token_type, expires_in, role }` |
| `POST` | `/api/v1/auth/refresh` | `{ refresh_token }` | `{ access_token, refresh_token, token_type, expires_in, role }` |

### Auth (Protected — Admin)

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/auth/users` | Admin | List semua users |
| `POST` | `/api/v1/auth/users` | Admin | Create user `{ username, password, role }` |
| `DELETE` | `/api/v1/auth/users/{username}` | Admin | Delete user |
| `PUT` | `/api/v1/auth/users/{username}/password` | Admin/Self | Change password `{ password }` |

### Firewall Rules

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/rules` | All | List rules (sorted by priority) |
| `GET` | `/api/v1/rules/{id}` | All | Get rule by UUID |
| `POST` | `/api/v1/rules` | Write | Create rule `{ name, action, direction, src_cidr, dst_cidr, src_port, dst_port, protocol, priority, enabled }` |
| `PUT` | `/api/v1/rules/{id}` | Write | Update rule |
| `DELETE` | `/api/v1/rules/{id}` | Delete | Delete rule |
| `POST` | `/api/v1/rules/simulate` | All | Simulate packet `{ src_ip, dst_ip, src_port, dst_port, protocol, direction }` |
| `GET` | `/api/v1/rules/export/json` | All | Export rules as JSON (download) |
| `GET` | `/api/v1/rules/export/yaml` | All | Export rules as YAML (download) |
| `GET` | `/api/v1/rules/export/csv` | All | Export rules as CSV (download) |
| `POST` | `/api/v1/rules/import` | Write | Import rules from JSON |

### Stats & Connections

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/stats` | All | `{ packets_allowed, packets_dropped, active_connections, blocked_ips, rate_limit_buckets }` |
| `GET` | `/api/v1/connections` | All | List active connections (5-tuple + state) |
| `POST` | `/api/v1/block` | Write | Block IP `{ ip }` |
| `DELETE` | `/api/v1/block/{ip}` | Delete | Unblock IP |

### Audit Log

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/audit` | All | List audit entries `?actor=&action=&limit=` |
| `GET` | `/api/v1/audit/verify` | All | Verify hash-chain integrity |
| `GET` | `/api/v1/audit/export` | All | Download audit log as JSON |

### Alerting

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/alerts/rules` | All | List alert rules |
| `POST` | `/api/v1/alerts/rules` | Write | Create alert rule |
| `DELETE` | `/api/v1/alerts/rules/{id}` | Delete | Delete alert rule |
| `GET` | `/api/v1/alerts/history` | All | List alert history |
| `POST` | `/api/v1/alerts/history/{id}/ack` | All | Acknowledge alert |

### Multi-Tenancy (Admin)

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/tenants` | Admin | List tenants |
| `POST` | `/api/v1/tenants` | Admin | Create tenant |
| `DELETE` | `/api/v1/tenants/{id}` | Admin | Delete tenant |

### Cluster (Admin)

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/cluster/nodes` | All | List cluster nodes |
| `POST` | `/api/v1/cluster/nodes` | Write | Register node |
| `DELETE` | `/api/v1/cluster/nodes/{id}` | Delete | Remove node |
| `GET` | `/api/v1/cluster/status` | All | Cluster health status |

### IP Reputation

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/reputation` | All | List all reputations (sorted by lowest) |
| `GET` | `/api/v1/reputation/{ip}` | All | Get reputation for specific IP |

### Rule Scheduler

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `GET` | `/api/v1/schedules` | All | List schedules |
| `POST` | `/api/v1/schedules` | Write | Create schedule `{ rule_id, cron_expression, action, description }` |
| `DELETE` | `/api/v1/schedules/{id}` | Delete | Delete schedule |

### VPN Portal

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `POST` | `/api/v1/vpn/request` | Write | Submit WireGuard peer request |
| `GET` | `/api/v1/vpn/requests` | All | List requests `?status=` |
| `POST` | `/api/v1/vpn/requests/{id}/approve` | Write | Approve request |
| `POST` | `/api/v1/vpn/requests/{id}/deny` | Write | Deny request |
| `POST` | `/api/v1/vpn/requests/{id}/revoke` | Delete | Revoke peer |
| `GET` | `/api/v1/vpn/requests/{id}/config` | All | Download client WireGuard config |

### DPI, QoS, Compliance, Syslog

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `POST` | `/api/v1/dpi/identify` | All | Identify protocol from port/protocol |
| `GET` | `/api/v1/qos/policies` | All | List QoS policies |
| `POST` | `/api/v1/qos/policies` | Write | Create QoS policy |
| `DELETE` | `/api/v1/qos/policies/{id}` | Delete | Delete QoS policy |
| `POST` | `/api/v1/compliance/reports` | Write | Generate compliance report |
| `GET` | `/api/v1/compliance/reports` | All | List reports |
| `GET` | `/api/v1/compliance/reports/{id}` | All | Get specific report |
| `GET` | `/api/v1/syslog/configs` | All | List syslog configs |
| `POST` | `/api/v1/syslog/configs` | Write | Add syslog config |
| `DELETE` | `/api/v1/syslog/configs/{id}` | Delete | Remove syslog config |

### Backup

| Method | Path | RBAC | Deskripsi |
|--------|------|------|-----------|
| `POST` | `/api/v1/backup` | Admin | Create full config snapshot |
| `GET` | `/api/v1/backup` | Admin | List available backups |
| `POST` | `/api/v1/backup/restore` | Admin | Restore from backup `{ id }` or `{ data }` |
| `GET` | `/api/v1/backup/download` | Admin | Download backup as JSON `?id=` |

### Public System

| Method | Path | Deskripsi |
|--------|------|-----------|
| `GET` | `/health` | Health check — returns `"OK"` |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/api/v1/ws` | WebSocket live events `?token=` |
| `GET` | `/api/v1/openapi.yaml` | OpenAPI 3.0 spec |
| `GET` | `/docs` | Scalar API documentation UI |

---

## 7. Auth & RBAC Flow

### Login Flow

```
Client → POST /api/v1/auth/login { username, password }
  │
  ├─→ UserStore.verify_password()
  │     ├─→ Find user by username in HashMap
  │     ├─→ Check if user.enabled
  │     └─→ Argon2 verify password hash
  │
  ├─→ JwtAuth.generate_tokens(user)
  │     ├─→ ACCESS_TOKEN (15 min) — HS256 signed
  │     │     { sub, username, role, exp, iat, nbf, iss, aud, jti }
  │     └─→ REFRESH_TOKEN (24h) — same claims
  │
  ├─→ AuditLog.log("login.success")
  └─→ Response { access_token, refresh_token, role }
```

### Token Refresh Flow

```
Client → POST /api/v1/auth/refresh { refresh_token }
  │
  ├─→ JwtAuth.validate_token(refresh_token)
  │     ├─→ HS256 decode + verify signature
  │     ├─→ Check exp (leeway 5s)
  │     ├─→ Check nbf
  │     ├─→ Check iss == "argus"
  │     └─→ Check aud == "argus-api"
  │
  ├─→ Generate NEW access_token (15 min)
  ├─→ Generate NEW refresh_token (24h) ← ROTATED
  └─→ Response { access_token, refresh_token }
```

### RBAC Enforcement in Handlers

```rust
// Setiap protected handler extract Claims:
pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,  // ← dari middleware
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<RuleResponse>, Json<serde_json::Value>> {
    // RBAC check
    if !claims.role.can_write() {
        return Err(Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})));
    }
    // ... business logic ...
}
```

---

## 8. Data Flow Diagrams

### Packet Processing (eBPF XDP)

```
NIC RX ──► XDP Hook
             │
             ├──► [BLOCKLIST Check] ──── HashMap<u32, u32>
             │     source IP match? ──► XDP_DROP
             │
             ├──► [ALLOWLIST Check] ──── HashMap<u32, u32>
             │     allowlist mode? IP match? ──► XDP_PASS/DROP
             │
             ├──► [Rate Limit Check] ──── Token bucket per IP
             │     tokens < 1? ──► XDP_DROP
             │
             ├──► [Connection Track] ──── CONNTRACK HashMap<u64, u32>
             │     Insert/update 5-tuple entry
             │
             └──► [Stats Counter] ──── PER_CPU_PACKETS[4]
                   Increment per-packet counter
                   │
                   └──► XDP_PASS ──► Kernel stack ──► Userspace
```

### Rule Engine Evaluation

```
RuleEngine.evaluate(src_ip, dst_ip, src_port, dst_port, protocol, direction)
  │
  ├─► store.rules_by_direction(direction) 
  │     └─► Filter: hanya rules dengan direction yang sesuai
  │
  ├─► Sort by priority (ascending)
  │
  └─► For each rule (filter enabled):
        ├─► match src_cidr?  ──► ip_in_cidr(src_ip, rule.src_cidr)
        ├─► match dst_cidr?  ──► ip_in_cidr(dst_ip, rule.dst_cidr)
        ├─► match src_port?  ──► src_port == rule.src_port
        ├─► match dst_port?  ──► dst_port == rule.dst_port
        └─► match protocol?  ──► proto_matches(protocol, rule.protocol)
              │
              └─► Semua match? ──► return MatchResult { action, rule_id }
                    │
                    └─► Tidak ada match? ──► Default action (allow)
```

### WebSocket Real-Time Event Bus

```
┌──────────┐    publish(stats)     ┌──────────────────┐
│  Backend  │ ──────────────────►  │  LiveEventBus     │
│  Engines  │                      │  broadcast::tx    │
│          │    publish(alert)     │  capacity: 1024   │
│          │ ──────────────────►  └────────┬─────────┘
└──────────┘                               │
                                           │ subscribe()
                                           ▼
                                    ┌──────────────┐
                                    │  WebSocket    │
                                    │  handle_ws()  │
                                    │  per-client   │
                                    └──────┬───────┘
                                           │
                                    ┌──────┴───────┐
                                    │  Frontend JS  │
                                    │  live.js      │
                                    │  stores       │
                                    └──────────────┘
```

---

## 9. Database Models

### Rules Table (PostgreSQL)

```sql
CREATE TABLE IF NOT EXISTS rules (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    action TEXT NOT NULL,          -- "allow", "deny", "rate-limit:100pps"
    direction TEXT NOT NULL,        -- "inbound", "outbound", "forward"
    src_cidr TEXT,                  -- "10.0.0.0/8"
    dst_cidr TEXT,                  -- "0.0.0.0/0"
    src_port SMALLINT,
    dst_port SMALLINT,
    protocol TEXT,                  -- "tcp", "udp", "icmp", or numeric
    priority INT NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Audit Log Table (PostgreSQL)

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,           -- "rule.create", "login.success", dll
    resource TEXT NOT NULL,         -- "firewall", "auth"
    details TEXT NOT NULL DEFAULT '',
    ip_address TEXT,                -- client IP
    success BOOLEAN NOT NULL DEFAULT true,
    hash TEXT NOT NULL,             -- SHA-256 chain hash
    previous_hash TEXT NOT NULL     -- hash of previous entry
);
CREATE INDEX idx_audit_actor ON audit_log (actor);
CREATE INDEX idx_audit_action ON audit_log (action);
CREATE INDEX idx_audit_timestamp ON audit_log (timestamp DESC);
```

### Hash Chain Integrity

```
genesis_hash = SHA256("genesis")

Entry 1: hash1 = SHA256(id1 + timestamp1 + actor1 + action1 + ... + genesis_hash)
Entry 2: hash2 = SHA256(id2 + timestamp2 + actor2 + action2 + ... + hash1)
Entry 3: hash3 = SHA256(id3 + timestamp3 + actor3 + action3 + ... + hash2)
  ...
Entry N: hashN = SHA256(idN + timestampN + actorN + actionN + ... + hash(N-1))

Verification: recompute all hashes → if any differ → data has been tampered with
```

---

## 10. Deployment Guide

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ARGUS_JWT_SECRET` | **Yes** | — | JWT signing key (≥32 bytes, HS256) |
| `ARGUS_ADMIN_USER` | No | `admin` | Initial admin username |
| `ARGUS_ADMIN_PASS` | No | auto-generated | Initial admin password |
| `DATABASE_URL` | No | — | PostgreSQL (in-memory if unset) |
| `RUST_LOG` | No | `argus=info` | Log level filter |
| `ARGUS_GITOPS_DIR` | No | `/var/lib/argus/gitops-repo` | GitOps repo path |
| `ARGUS_WG_PUBLIC_KEY` | No | — | WireGuard server public key for VPN portal |
| `ARGUS_WG_ENDPOINT` | No | — | WireGuard server endpoint for VPN portal |

### Quick Start

```bash
git clone https://github.com/zulfff/argus.git
cd argus

# Set required env vars
export ARGUS_JWT_SECRET="your-32-plus-character-secret-here!!"

# Build & run (in-memory mode, no DB needed)
cargo run --release -p argus-api
```

### Docker

```bash
cd deploy/docker
export JWT_SECRET="your-secret"
export DB_PASSWORD="your-db-password"
export GRAFANA_PASSWORD="your-grafana-password"
docker compose up -d
```

### CI Pipeline

```yaml
# .github/workflows/ci.yml
steps:
  - cargo fmt --check
  - cargo clippy -- -D warnings
  - cargo test (excludes argus-ebpf)
```

---

> **Dokumen ini adalah referensi teknis untuk memahami codebase ARGUS.**
> Untuk dokumentasi API yang interaktif, buka `/docs` setelah server berjalan.