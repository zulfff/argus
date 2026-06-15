# ARGUS Deployment Guide

## Supported Platforms

- **Router OS:** VyOS 1.4+ (Debian-based, API-driven)
- **Base OS:** Debian 12 (Bookworm) / Ubuntu 22.04+
- **Kernel:** 5.15+ with `CONFIG_DEBUG_INFO_BTF=y` for eBPF
- **Arch:** x86_64 only (eBPF target limitation)

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores x86_64 | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 20 GB | 40+ GB SSD |
| Network | 2 NICs (WAN + LAN) | 4+ NICs |

## Deployment Methods

### Option 1: Bare-Metal / VyOS Router

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev clang llvm libbpf-dev curl

# 2. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 3. Build and install
cd /opt
git clone <argus-repo>
cd argus
cargo build --release --workspace --exclude argus-ebpf
sudo cp target/release/argus-api /usr/local/bin/
sudo cp target/release/argus-cli /usr/local/bin/

# 4. Create user and directories
sudo useradd -r -s /bin/false argus
sudo mkdir -p /opt/argus/data /etc/argus /var/log/argus
sudo chown -R argus:argus /opt/argus /var/log/argus

# 5. Configure environment
sudo cat > /etc/argus/env << EOF
ARGUS_JWT_SECRET=$(openssl rand -base64 32)
RUST_LOG=argus=info
EOF

# 6. Install systemd unit
sudo cp deploy/systemd/argus-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now argus-api

# 7. Verify
argus-cli --api-url http://127.0.0.1:8443 stats
```

### Option 2: Docker Compose

```bash
cd argus/deploy/docker

# Set secrets
export DB_PASSWORD=$(openssl rand -base64 32)
export JWT_SECRET=$(openssl rand -base64 32)
export GRAFANA_PASSWORD=$(openssl rand -base64 16)

docker compose up -d

# Check status
docker compose ps
curl http://localhost:8443/health

# Access services:
# API:       https://localhost:8443
# Grafana:   http://localhost:3000  (admin / $GRAFANA_PASSWORD)
# Prometheus: http://localhost:9090
```

### Option 3: Development

```bash
# Build everything except eBPF
cargo build --workspace --exclude argus-ebpf

# Run API
cargo run -p argus-api

# In another terminal, run CLI
cargo run -p argus-cli -- --api-url http://127.0.0.1:8443 rules

# Frontend (requires Node 18+)
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

## TLS Configuration

ARGUS does not terminate TLS itself. Run behind a reverse proxy:

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name firewall.your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/firewall/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/firewall/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /metrics {
        # Restrict metrics to internal monitoring
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;

        proxy_pass http://127.0.0.1:8443;
    }
}
```

### Caddy

```caddyfile
firewall.your-domain.com {
    reverse_proxy 127.0.0.1:8443

    @metrics path /metrics
    handle @metrics {
        @allowed remote_ranges 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
        handle @allowed {
            reverse_proxy 127.0.0.1:8443
        }
        respond "Forbidden" 403
    }
}
```

## VyOS Router Setup (for Phase 2)

```bash
# On VyOS router
set service https api
set service https port 443
set service https listen-address 0.0.0.0

# Create API key for ARGUS:
# Generate and add to NetBox device custom fields
vyos@router:~$ generate api key
# Copy key to NetBox custom field: argus_api_key
```

## NetBox Setup (for Phase 2)

1. Install NetBox (docker or bare-metal)
2. Create API token: Admin → Users → API Tokens
3. Add devices with custom fields:
   - `argus_api_key` — VyOS API key
   - `argus_mgmt_ip` — Management IP for config push
4. Configure webhooks:
   - Content type: `application/json`
   - URL: `http://<argus-host>:8443/api/v1/webhook/netbox`
   - Events: `dcim.device` updated, `ipam.prefix` updated

## Post-Installation Checklist

- [ ] Change default JWT secret
- [ ] Change default admin password: `argus-cli` → login with new password
- [ ] Set up TLS via reverse proxy
- [ ] Configure firewall to restrict `/metrics` endpoint
- [ ] Set up log rotation: `/var/log/argus/`
- [ ] Schedule config backups via cron or systemd timer
- [ ] Enable audit log export to external syslog
- [ ] Configure monitoring alerts (Prometheus → Alertmanager)

## Upgrade Procedure

```bash
# Stop service
sudo systemctl stop argus-api

# Backup current binary
sudo cp /usr/local/bin/argus-api /usr/local/bin/argus-api.bak

# Pull and rebuild
cd /opt/argus
git pull
cargo build --release --workspace --exclude argus-ebpf

# Install and restart
sudo cp target/release/argus-api /usr/local/bin/
sudo systemctl start argus-api

# Verify
argus-cli stats
```

## Rollback

```bash
sudo systemctl stop argus-api
sudo cp /usr/local/bin/argus-api.bak /usr/local/bin/argus-api
sudo systemctl start argus-api
```
