# ARGUS Runbooks

## Runbook 1: Service Status Check

### Goal
Verify ARGUS API, eBPF programs, and dependent services are healthy.

### Steps
```bash
# 1. Check API health
curl -s http://127.0.0.1:8443/health

# 2. Check CLI connectivity
argus-cli stats

# 3. Check eBPF programs (if enabled)
sudo bpftool prog list | grep argus

# 4. Check systemd status
sudo systemctl status argus-api

# 5. Check logs
sudo journalctl -u argus-api --since "5 min ago"
```

### Expected Output
- `/health` returns `OK`
- `argus-cli stats` shows non-crash metrics
- `bpftool` lists `argus_firewall` program(s)
- systemd shows `active (running)`
- Logs show normal request processing

---

## Runbook 2: Rule Management

### List Rules
```bash
argus-cli rules
# or view in dashboard: https://<host>:8443 → Rules tab
```

### Add a Rule
```bash
# Using CLI (requires JWT login first):
# Then POST via curl:
curl -X POST http://127.0.0.1:8443/api/v1/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "block-ssh-wan",
    "action": "deny",
    "direction": "inbound",
    "src_cidr": null,
    "dst_port": 22,
    "protocol": "tcp",
    "priority": 10
  }'
```

### Delete a Rule
```bash
argus-cli rules  # Find the rule ID
curl -X DELETE http://127.0.0.1:8443/api/v1/rules/<uuid> \
  -H "Authorization: Bearer <token>"
```

---

## Runbook 3: Block/Unblock an IP

### Manual Block
```bash
argus-cli block 203.0.113.5
```

### Manual Unblock
```bash
argus-cli unblock 203.0.113.5
```

### Check Blocked IPs
```bash
curl http://127.0.0.1:8443/api/v1/stats \
  -H "Authorization: Bearer <token>" | jq .blocked_ips
```

---

## Runbook 4: Investigating Dropped Packets

### Steps
```bash
# 1. Check drop statistics
argus-cli stats

# 2. Check Prometheus for drop trends
# Grafana → ARGUS Dashboard → Dropped Packets by Reason

# 3. Check if specific IP is blocked
argus-cli block 203.0.113.5  # Will show if already blocked

# 4. Check rate limiting status
# Look at rate_limit_buckets in stats output
# High count (>10000) may indicate an ongoing flood

# 5. Review rules
argus-cli rules
# Check if any deny rule matches the expected traffic
```

### Resolution
- **Legitimate traffic dropped:** Add appropriate allow rules
- **Attack traffic dropped:** Expected — monitor via Grafana
- **Rate limited:** Increase `refill_rate` or investigate traffic source

---

## Runbook 5: Config Drift Recovery

### Detect Drift
```bash
# Via API (orchestrator must be running):
curl http://127.0.0.1:8443/api/v1/drift/check \
  -H "Authorization: Bearer <token>"
```

### Manual Reconciliation
```bash
# 1. Export current NetBox intended rules
# 2. Export current VyOS running config
# 3. Compare differences
# 4. Generate and push corrected config:

# Locate playbook
cd /opt/argus/ansible/playbooks

# Run dry-run first
ansible-playbook reconcile-firewall.yml \
  --inventory inventory.yml \
  --check --diff

# Apply if changes look correct
ansible-playbook reconcile-firewall.yml \
  --inventory inventory.yml
```

### Automatic Rollback
If health check fails after push, VyOS `commit-confirm` auto-reverts.
Manual rollback:
```bash
# SSH to VyOS router
ssh vyos@<router-ip>
vyos@router:~$ configure
vyos@router# rollback 1
vyos@router# commit
vyos@router# save
```

---

## Runbook 6: Multi-WAN Failover

### Check WAN Status
```bash
# Via API:
curl http://127.0.0.1:8443/api/v1/wan/status \
  -H "Authorization: Bearer <token>"
```

### Manual Failover
```bash
# On VyOS router:
ssh vyos@<router-ip>
vyos@router:~$ configure
vyos@router# set protocols static route 0.0.0.0/0 next-hop <secondary-gateway> distance 5
vyos@router# commit
vyos@router# save
```

### Verify Active Link
```bash
# Check which link is currently active:
ip route show default
# Should show the secondary gateway
```

### Failback
Once primary link is healthy, remove the static route:
```bash
vyos@router# delete protocols static route 0.0.0.0/0
vyos@router# commit
vyos@router# save
```

---

## Runbook 7: Audit Log Review

### Query Audit Log
```bash
# Via CLI:
argus-cli audit-log --actor admin --limit 20

# Via API:
curl http://127.0.0.1:8443/api/v1/audit \
  -H "Authorization: Bearer <token>" | jq .
```

### Verify Log Integrity
```bash
curl http://127.0.0.1:8443/api/v1/audit/verify \
  -H "Authorization: Bearer <token>"
# Returns: {"valid": true, "tampered_count": 0, "total_entries": N}
```

### Export for External Review
```bash
curl http://127.0.0.1:8443/api/v1/audit/export \
  -H "Authorization: Bearer <token>" > audit-backup.json
```

### What to Look For
- Failed login attempts (possible brute force)
- Unexpected rule changes
- Block/unblock actions
- Config drift events
- `tampered_count > 0` in integrity check (possible log compromise)

---

## Runbook 8: Backup & Restore

### Automated Backup
```bash
# Via Ansible playbook (scheduled via cron/systemd timer):
cd /opt/argus/ansible/playbooks
ansible-playbook backup-config.yml
```

### Manual Backup
```bash
# 1. Backup rules
curl http://127.0.0.1:8443/api/v1/rules \
  -H "Authorization: Bearer <token>" > rules-backup.json

# 2. Backup VyOS config
ssh vyos@<router-ip> 'show configuration commands' > vyos-backup.cfg

# 3. Backup audit log
curl http://127.0.0.1:8443/api/v1/audit/export \
  -H "Authorization: Bearer <token>" > audit-backup.json

# 4. Backup env config
sudo cp /etc/argus/env /var/backups/argus/env-backup
```

### Restore Rules
```bash
# Read rules from backup and re-create:
jq -c '.[]' rules-backup.json | while read -r rule; do
  curl -X POST http://127.0.0.1:8443/api/v1/rules \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer <token>" \
    -d "$rule"
done
```

---

## Runbook 9: Emergency Response

### Immediate Triage (packet flood / DDoS)
```bash
# 1. Quick status
argus-cli stats

# 2. Block the top source
argus-cli block <attacker-ip>

# 3. If rate-limiting isn't enough, add XDP deny rule:
curl -X POST http://127.0.0.1:8443/api/v1/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "emergency-block-all",
    "action": "deny",
    "direction": "inbound",
    "priority": 0
  }'

# 4. Verify drops are happening
watch -n 1 argus-cli stats
```

### Service Recovery
```bash
# Restart argus-api
sudo systemctl restart argus-api

# Check it came back
sudo systemctl status argus-api
curl http://127.0.0.1:8443/health
```

### Full Reset to Known-Good State
```bash
# 1. Stop all ARGUS services
sudo systemctl stop argus-api

# 2. Detach eBPF programs (if loaded)
sudo bpftool prog detach pinned /sys/fs/bpf/argus_firewall xdp eth0
sudo rm /sys/fs/bpf/argus_firewall

# 3. Restore from backup
# (see Runbook 8)

# 4. Restart
sudo systemctl start argus-api
```

---

## Runbook 10: Performance Troubleshooting

### Symptoms & Checks

| Symptom | Check | Command |
|---------|-------|---------|
| High CPU | Process usage | `top -p $(pgrep argus-api)` |
| High memory | RSS | `ps aux | grep argus-api` |
| Slow API | Latency | `curl -w "\ntime: %{time_total}s\n" /health` |
| Packet drops | Drop counters | `argus-cli stats` |
| Connection table full | Active count | Watch `active_connections` in stats |

### Resolution
- **High CPU:** Check eBPF map sizes, GC intervals, anomalous traffic
- **High memory:** Check connection tracker `max_entries`, enable GC
- **Slow API:** Check PostgreSQL latency if using DB, check rate limiter
- **Connection table full:** Increase `max_entries` or reduce TTL
- **Packet drops:** Check rules, increase rate limit thresholds
