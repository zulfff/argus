# ARGUS Threat Model

## Scope

This threat model covers:
- argus-api (Axum REST + WebSocket)
- argus-core (control plane logic)
- argus-ebpf (XDP data plane)
- argus-orchestrator (NetBox/VyOS/Ansible integration)
- Configuration and deployment artifacts

**Out of scope:**
- Underlying OS/hypervisor security
- Physical access attacks
- Side-channel attacks (power, timing beyond constant-time auth checks)
- NetBox/VyOS/Prometheus own security

## Trust Boundaries

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Internet   │     │   Internal   │     │    Trusted   │
│  (Untrusted) │────►│    Network   │────►│     Zone     │
│              │ XDP │  (DMZ/VLAN)  │     │  (Mgmt LAN)  │
└─────────────┘     └─────────────┘     └─────────────┘
      │                    │                    │
      ▼                    ▼                    ▼
  ┌─────────┐       ┌───────────┐        ┌───────────┐
  │  XDP    │       │ argus-api │        │  NetBox   │
  │ Firewall│       │   :8443   │        │  VyOS API │
  └─────────┘       └───────────┘        └───────────┘
      │                    │                    │
      ▼                    ▼                    ▼
  ┌─────────────────────────────────────────────────┐
  │              argus-core (Engine)                │
  │  BPF Maps ◄──► Rule Engine ◄──► Audit Log       │
  └─────────────────────────────────────────────────┘
```

### Boundary 1: Internet → XDP Firewall
Packets from any source IP enter via XDP hook. XDP filters before kernel
processing. Trust level: **ZERO**.

### Boundary 2: Internal Network → argus-api
Clients (CLI, dashboard, Ansible) connect to the API. Authentication required.
Trust level: **Authenticated user with RBAC role**.

### Boundary 3: argus-api → NetBox / VyOS
API makes outbound calls to infrastructure services. Must validate that return
data is trusted (NetBox is SoT, VyOS is target). Trust level: **High but verified**.

### Boundary 4: argus-core → BPF Maps
Userspace writes to BPF maps via bpf() syscall. Only root/CAP_SYS_ADMIN can
manipulate maps. Trust level: **OS-enforced**.

## STRIDE Analysis

### Spoofing

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Fake source IP to bypass XDP rules | Attacker bypasses blocklist | XDP only permits valid IP headers; source IP validation at router level |
| Spoofed JWT token | Unauthorized API access | HS256 with server-side secret; 15-min expiry; validate `exp` + `iat` |
| Spoofed NetBox webhook | Malicious config pushed | Webhook source IP validation; webhook secret verification (TODO) |
| Spoofed VyOS response | Fake health check passes | TLS certificate validation (mTLS planned); response schema validation |

### Tampering

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Tampered audit log entries | Cover tracks, hide breaches | SHA-256 hash chain; `verify_integrity()` detects any modification |
| Tampered BPF maps from userspace | Disable firewall rules | Only root can modify maps; audit all map mutations |
| Tampered config in transit (API) | Malicious rule injection | TLS termination at reverse proxy; JWT auth on all mutating endpoints |
| Tampered Ansible playbooks | Deploy malicious config | GitOps — playbooks in version-controlled repo with CI validation |

### Repudiation

| Threat | Impact | Mitigation |
|--------|--------|------------|
| User denies making a change | No accountability | All rule changes logged to audit log with actor + IP + hash |
| Attacker deletes audit entries | Evidence destruction | Hash chain makes deletion detectable; log rotation with backup |

### Information Disclosure

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Logs contain secrets/tokens | Credential leak | `tracing` redaction layer; no secret fields in structured logs |
| API exposes internal IPs/rules | Reconnaissance | RBAC — viewer role minimum for any access; rate limiting |
| Prometheus metrics leak topology | Network mapping | `/metrics` endpoint IP-restricted or behind auth |
| Error messages leak stack traces | Vulnerability disclosure | Production errors return generic messages; debug only in dev |

### Denial of Service

| Threat | Impact | Mitigation |
|--------|--------|------------|
| SYN flood / UDP flood | Resource exhaustion | XDP token bucket rate limiting per source IP |
| API request flood | Server overload | `tower-governor` (100 req/s per client); bounded channels |
| Connection table overflow | Memory exhaustion | `ConnectionTracker` LRU eviction + max_entries cap |
| BPF map overflow | Kernel memory leak | All maps have max_entries; TTL eviction on CONNTRACK/RATE_LIMIT |
| WASM plugin infinite loop | CPU exhaustion | `wasmtime` fuel metering (100k fuel units); epoch interruption |

### Elevation of Privilege

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Viewer escalates to admin | Unauthorized rule changes | RBAC checked at handler level, not just UI; JWT role in signed claims |
| Compromised WASM plugin | Access to host memory | Wasmtime sandbox; plugins only receive serialized FlowMetadata, not raw packets |
| Ansible playbook with `become: yes` | Root on VyOS | Playbook review via GitOps; dry-run before apply |
| Direct BPF map manipulation | Bypass all rules | Requires `CAP_SYS_ADMIN`; AppArmor/SELinux policy restricts |

## Security Controls Matrix

| Control | Status | Notes |
|---------|--------|-------|
| JWT authentication | ✅ Implemented | HS256, 15-min access, 24h refresh |
| RBAC (admin/operator/viewer) | ✅ Implemented | Checked at handler level |
| Rate limiting (API) | ✅ Implemented | tower-governor, 100 req/s |
| Rate limiting (XDP) | ✅ Implemented | Token bucket per source IP |
| Audit log (hash-chained) | ✅ Implemented | SHA-256 chain, integrity verification |
| WASM sandbox (fuel limits) | ✅ Implemented | wasmtime, 100k fuel units |
| Circuit breaker (NetBox) | ✅ Implemented | 5 failures → open circuit for 30s |
| TLS (API) | ⚠️ External | Reverse proxy (nginx/Caddy) recommended |
| mTLS (internal services) | ❌ Planned | Phase 4 roadmap |
| Secrets management | ⚠️ Partial | Env vars only; Vault integration planned |
| Path traversal protection | ✅ Implicit | Rust `Path::canonicalize()` + prefix check |
| SQL injection prevention | N/A | In-memory store default; `sqlx::query!` if PostgreSQL used |
| Command injection prevention | ✅ Implemented | `std::process::Command` with `arg()` arrays |
| Constant-time auth comparison | ⚠️ Partial | argon2 for password hashing (constant-time); JWT using `jsonwebtoken` crate |

## Vulnerability Disclosure

If you discover a security issue in ARGUS, please report it via:

- **Email:** `security@<your-org>` (replace with contact)
- **PGP Key:** (provide fingerprint)

**Response targets:**
- Acknowledgment: within 48 hours
- Initial assessment: within 3 business days
- Fix timeline: within 5 business days

**Do NOT:**
- Open public issues for vulnerabilities
- Exploit the issue beyond proof-of-concept
- Disclose to third parties before our fix is released

## Threat Model Review Cadence

This threat model should be reviewed:
- When new modules are added
- When external dependencies change
- Before any production deployment
- At minimum, every 6 months
