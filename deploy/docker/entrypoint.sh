#!/bin/sh
set -e

# ─── Auto-generate missing secrets ──────────────────────────────────

if [ -z "$ARGUS_JWT_SECRET" ]; then
  ARGUS_JWT_SECRET=$(openssl rand -hex 32)
  echo "⚠  ARGUS_JWT_SECRET not set — generated random secret for this session"
  echo "   To persist, set:  export ARGUS_JWT_SECRET=\"$ARGUS_JWT_SECRET\""
fi

if [ -z "$ARGUS_ADMIN_PASS" ]; then
  ARGUS_ADMIN_PASS=$(openssl rand -hex 16)
  echo "⚠  ARGUS_ADMIN_PASS not set — auto-generated password"
  echo "   ┌─────────────────────────────────────────────────────┐"
  echo "   │  Admin user: admin                                  │"
  echo "   │  Password:   $ARGUS_ADMIN_PASS  │"
  echo "   └─────────────────────────────────────────────────────┘"
fi

export ARGUS_JWT_SECRET
export ARGUS_ADMIN_PASS
export ARGUS_ADMIN_USER="${ARGUS_ADMIN_USER:-admin}"

# ─── Start ──────────────────────────────────────────────────────────

echo "▐ ARGUS API v0.1.1 starting..."
exec /usr/local/bin/argus-api