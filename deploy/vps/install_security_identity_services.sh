#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="${DELFTCLAW_REPO_DIR:-/root/DelftClaw}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this script as root because it writes to /etc/systemd/system."
  exit 1
fi

cd "$REPO_DIR"

echo "Installing systemd service files"
cp deploy/systemd/delftclaw-identity-mcp.service.template /etc/systemd/system/delftclaw-identity-mcp.service
cp deploy/systemd/delftclaw-gateway.service.template /etc/systemd/system/delftclaw-gateway.service
cp deploy/systemd/delftclaw-security-mcp.service.template /etc/systemd/system/delftclaw-security-mcp.service

echo "Reloading systemd"
systemctl daemon-reload

echo "Enabling and starting services"
systemctl enable --now delftclaw-identity-mcp
systemctl enable --now delftclaw-gateway
systemctl enable --now delftclaw-security-mcp

echo
echo "Status commands:"
echo "  systemctl status delftclaw-identity-mcp --no-pager"
echo "  systemctl status delftclaw-gateway --no-pager"
echo "  systemctl status delftclaw-security-mcp --no-pager"
echo
echo "Logs:"
echo "  journalctl -u delftclaw-identity-mcp -f"
echo "  journalctl -u delftclaw-gateway -f"
echo "  journalctl -u delftclaw-security-mcp -f"
