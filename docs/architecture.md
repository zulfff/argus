# ARGUS Architecture

## System Overview

ARGUS is a layered network security platform. Each layer builds on the one below:

```
┌───────────────────────────────────────────────────────────────┐
│  LAYER 5: PRESENTATION                                        │
│  SvelteKit Web UI  |  argus-cli TUI  |  Grafana Dashboards    │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│  LAYER 4: API & INTEGRATION                                   │
│  Axum REST  |  WebSocket  |  JWT Auth  |  RBAC                │
│  NetBox Client  |  VyOS Client  |  Ansible Runner             │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│  LAYER 3: CONTROL PLANE                                       │
│  RuleEngine  |  ConnectionTracker  |  RateLimiter              │
│  ScanDetector  |  AnomalyDetector  |  ThreatIntelligence      │
│  GitOpsEngine  |  ZtnaMesh  |  MultiWanManager                │
│  AuditLog  |  WasmPluginEngine                                │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│  LAYER 2: DATA PLANE (eBPF)                                   │
│  XDP Firewall  |  Connection Tracking  |  Rate Limiting        │
│  BPF Maps: BLOCKLIST, ALLOWLIST, CONNTRACK, RATE_LIMIT, STATS │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│  LAYER 1: INFRASTRUCTURE                                      │
│  Linux Kernel (XDP hook)  |  VyOS Router  |  NetBox SoT       │
└───────────────────────────────────────────────────────────────┘
```

## Data Flow

### Packet Processing Path

```
  NIC RX ──► XDP Hook ──┬──► [BLOCKLIST Check] ────► XDP_DROP
                        │
                        ├──► [ALLOWLIST Check] ────► XDP_PASS / DROP
                        │
                        ├──► [Rate Limit Check] ───► XDP_DROP (exceeded)
                        │
                        ├──► [Connection Track] ──► Update BPF maps
                        │
                        └──► [Stats Counter] ───► PER_CPU_PACKETS++
                             │
                             └──► XDP_PASS ──► Kernel stack ──► Userspace
```

XDP programs run before the kernel allocates an sk_buff — this means zero memory
allocation, minimal CPU cost, and the ability to drop packets at driver level.

### Rule Evaluation Flow

```
  API Request (create rule)
       │
       ▼
  RuleEngine.evaluate()
       │
       ├─► Fetch rules for direction (Inbound/Outbound/Forward)
       ├─► Filter enabled rules, sort by priority
       ├─► For each rule:
       │     ├─► Match source CIDR (IPv4/IPv6 bitmask)
       │     ├─► Match destination CIDR
       │     ├─► Match source/dest port
       │     └─► Match protocol (TCP/UDP/ICMP/ICMPv6/numeric)
       │
       └─► Return first MatchResult { action, rule_id }
```

### Config Reconciliation Flow (Phase 2)

```
  NetBox Webhook ──► argus-orchestrator ──► DriftDetector
                                              │
                    ┌─────────────────────────┘
                    ▼
              check_all_devices()
                    │
                    ├─► Fetch NetBox devices (API)
                    ├─► Fetch VyOS running config (HTTP API)
                    ├─► Compare intended vs actual
                    │
                    ├─► NO DRIFT ──► Log status, exit
                    │
                    └─► DRIFT DETECTED
                          │
                          ├─► determine_remediation()
                          │     ├─► Small drift ──► auto-push config
                          │     └─► Large drift ──► alert (manual review)
                          │
                          └─► VyOS safe_apply_config()
                                ├─► loadConfig
                                ├─► commit-confirm
                                ├─► health check
                                │     └─► FAIL ──► rollback
                                └─► save config
```

### Anomaly Detection Flow

```
  TrafficSample.record(interface, pps, bps, connections)
       │
       ▼
  AnomalyDetector.record_sample()
       │
       ├─► Push to interface's sample deque
       ├─► Evict samples older than BASELINE_WINDOW (60 min)
       │
       ▼
  AnomalyDetector.compute_baseline()
       │
       ├─► mean_pps = Σ(samples.pps) / N
       ├─► stddev_pps = √(Σ(pps - mean)² / N)
       ├─► Same for bps, connections
       │
       ▼
  AnomalyDetector.check_anomalies()
       │
       ├─► deviation = |current - mean| / stddev
       ├─► IF deviation > 3.0× stddev:
       │     ├─► 3–5×  → INFO
       │     ├─► 5–10× → WARNING
       │     └─► >10×  → CRITICAL
       │
       └─► Emit AnomalyAlert → audit log + event bus
```

## Component Details

### argus-ebpf (Layer 2 — Data Plane)

Compiled with `aya-ebpf`, runs at XDP hook. Operations:
- **Blocklist lookup:** HashMap keyed by `u32` BE source IP. If found → `XDP_DROP`.
- **Allowlist mode:** If `ALLOWLIST` map has entry for key `0`, operates in
  allowlist mode — only traffic from IPs in `ALLOWLIST` passes.
- **Rate limiting:** Token bucket per source IP, 100 tokens refilled per second.
  Packets exceeding tokens → `XDP_DROP`.
- **Connection tracking:** 5-tuple hash packed into `u64` key. Inserts new entries
  into `CONNTRACK` HashMap with TTL.
- **Statistics:** `PER_CPU_PACKETS` array, incremented per packet, read by userspace.

Map sizes:
| Map | Max Entries | Key Type | Value Type |
|-----|-------------|----------|------------|
| BLOCKLIST | 65,536 | u32 | u32 |
| ALLOWLIST | 65,536 | u32 | u32 |
| CONNTRACK | 262,144 | u64 | u32 |
| RATE_LIMIT_BUCKETS | 65,536 | u32 | u64 |
| PER_CPU_PACKETS | 4 | u64 | u64 |
| EVENTS | 4,096 | [u8; 256] | PerfEvent |

### argus-core (Layer 3 — Control Plane)

| Module | Responsibility | Key Types |
|--------|---------------|-----------|
| `rule_engine` | CIDR/protocol/port matching, priority ordering | `CidrRule`, `RuleStore` trait |
| `connection_tracker` | 5-tuple connection table, TTL eviction, LRU | `ConnectionKey`, `ConnectionEntry` |
| `rate_limiter` | Token bucket per IP, refill, GC | `TokenBucket`, `RateLimiter` |
| `scanner` | Port-scan detection, auto-block with expiry | `ScanDetector`, `ScanAlert` |
| `anomaly` | Statistical anomaly detection, baselines | `AnomalyDetector`, `Baseline` |
| `threat_intel` | Blocklist sync from Spamhaus/AbuseIPDB | `ThreatIntelligence`, `ThreatEntry` |
| `gitops` | Git-based config flow, CI validation | `GitOpsEngine`, `GitOpsChange` |
| `ztna` | WireGuard peer/policy management | `ZtnaMesh`, `ZtnaPolicy` |
| `wasm_plugin` | Sandboxed plugin execution (feature-gated) | `WasmPluginEngine` |
| `audit_log` | Hash-chained tamper-evident log | `AuditLog`, `AuditEntry` |
| `multi_wan` | Health-probe failover between WAN links | `MultiWanManager`, `WanLink` |

### argus-api (Layer 4 — API)

- **Framework:** Axum 0.7 with Tower middleware
- **Auth:** JWT HS256, access tokens (15 min) + refresh tokens (24h)
- **RBAC:** Admin, Operator, Viewer roles
- **Rate limiting:** `tower-governor`, 100 req/s burst 200
- **WebSocket:** `axum::extract::ws`, broadcast channel per `LiveEventBus`
- **Metrics:** Prometheus scrape endpoint at `/metrics`
- **State:** Shared via `Arc<AppState>`, contains all engine references

### argus-orchestrator (Layer 4 — Automation)

- **NetBox Client:** Full REST API wrapper with pagination, circuit breaker,
  exponential backoff retry, webhook processing
- **VyOS Client:** HTTP API client for config load/commit/compare/rollback,
  `safe_apply_config` with health check + auto-rollback
- **Ansible Runner:** Executes `ansible-playbook` as subprocess, parses PLAY RECAP
  output, supports dry-run, tags, limit-hosts
- **Drift Detector:** Compares NetBox intended state vs VyOS actual state,
  generates diff reports, triggers remediation

## Concurrency Model

- All shared state uses `std::sync::Mutex` (userspace, non-async locks are fine
  for short critical sections) and `tokio::sync::Mutex` for async-held locks
- Bounded channels: `tokio::sync::mpsc` with explicit capacity
- `broadcast` channel for WebSocket event distribution (1:N)
- Cancellation tokens for graceful shutdown
- Mutex guards are never held across `.await` points — use scoped blocks to drop
  guards before async calls

## External Dependencies

| Service | Purpose | Required |
|---------|---------|----------|
| PostgreSQL | Persistent rule store, audit log | Optional (in-memory works without) |
| Redis | Pub/sub, cache, connection state | Optional |
| NetBox | Source of truth for device/prefix data | Phase 2 |
| VyOS Router | Target for config pushes | Phase 2 |
| Prometheus | Metrics collection | Phase 3 |
| Grafana | Dashboard visualization | Phase 3 |
| Loki | Centralized log aggregation | Phase 3 |
