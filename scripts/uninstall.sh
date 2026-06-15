#!/usr/bin/env bash
# ============================================================
# ARGUS Uninstaller
# Usage: curl -sSL https://raw.githubusercontent.com/zulfff/argus/main/scripts/uninstall.sh | sudo bash
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

[ "$(id -u)" -eq 0 ] || { echo -e "${RED}Must run as root${NC}"; exit 1; }

echo -e "\n${BOLD}${RED}╔══════════════════════════════════════════════╗"
echo -e "║     ARGUS Firewall — Uninstaller              ║"
echo -e "╚══════════════════════════════════════════════╝${NC}\n"

read -p "This will remove ARGUS completely. Continue? [y/N] " -n 1 -r
echo
[[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; exit 0; }

echo -e "${CYAN}Stopping services...${NC}"
systemctl stop argus-api 2>/dev/null || true
systemctl stop argus-health.timer 2>/dev/null || true
systemctl disable argus-api 2>/dev/null || true
systemctl disable argus-health.timer 2>/dev/null || true

echo -e "${CYAN}Removing systemd units...${NC}"
rm -f /etc/systemd/system/argus-api.service
rm -f /etc/systemd/system/argus-health.service
rm -f /etc/systemd/system/argus-health.timer
systemctl daemon-reload

echo -e "${CYAN}Removing binaries...${NC}"
rm -f /usr/local/bin/argus-api /usr/local/bin/argus-cli

echo -e "${CYAN}Removing data...${NC}"
rm -rf /opt/argus /var/log/argus

read -p "Remove config and secrets in /etc/argus? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/argus
    echo -e "${GREEN}Config removed.${NC}"
else
    echo -e "${YELLOW}Config kept at /etc/argus${NC}"
fi

userdel argus 2>/dev/null || true

echo -e "\n${GREEN}${BOLD}ARGUS uninstalled.${NC}\n"
