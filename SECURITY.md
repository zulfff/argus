# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.3   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ARGUS, please **do not** open a public
issue. Instead, report it privately to:

- **Email:** [arjunaajalahla100@gmail.com](mailto:arjunaajalahla100@gmail.com)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected component(s) and version(s)
- Proof-of-concept (if available)
- Suggested fix (optional)

### Response Timeline

| Phase | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 3 business days |
| Fix & release | Within 5 business days |

### Disclosure Policy

- Vulnerabilities are acknowledged publicly **after** a fix is released
- Credit is given to the reporter (unless anonymity is requested)
- No bug bounty program — this is a community security disclosure process

### Supported Attack Vectors

We are interested in vulnerabilities affecting:

- eBPF/XDP packet processing (privilege escalation, verifier bypass)
- API authentication/authorization bypass
- Rule engine logic flaws
- Audit log tampering
- WASM sandbox escape
- Config injection via VyOS/NetBox integration
- Denial of service via resource exhaustion (CPU, memory, BPF maps)

### Out of Scope

- Vulnerabilities in dependencies (report upstream, we'll update)
- Physical access attacks
- Social engineering
- Non-ARGUS infrastructure (VyOS, NetBox, Prometheus, etc.)
