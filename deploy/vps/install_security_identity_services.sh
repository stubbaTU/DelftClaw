#!/usr/bin/env bash
# Install + enable the colleagues' non-templated gateway + seedbox-audit
# systemd units.
#
# The identity-mcp and security-mcp services are NO LONGER installed here.
# They have been migrated to the templated form
# (``delftclaw-identity-mcp@<instance>.service`` and
# ``delftclaw-security-mcp@<instance>.service``) and are now installed by
# ``deploy/setup_vps.sh:step_systemd_templates`` alongside the rest of the
# DelftClaw templated units. To enable a templated instance:
#
#   sudo systemctl enable --now delftclaw-identity-mcp@<instance>.service
#   sudo systemctl enable --now delftclaw-security-mcp@<instance>.service
#
# with ``/etc/delftclaw/instances/<instance>.env`` providing NETWORK,
# IDENTITY_MCP_PORT, IDENTITY_PATH, SECURITY_MCP_PORT, PYTHONPATH, etc.

set -Eeuo pipefail

REPO_DIR="${DELFTCLAW_REPO_DIR:-/root/DelftClaw}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this script as root because it writes to /etc/systemd/system."
  exit 1
fi

cd "$REPO_DIR"

echo "Installing gateway + seedbox-audit systemd unit files (templated DelftClaw MCPs install via setup_vps.sh)"
if [[ -f deploy/systemd/delftclaw-gateway.service.template ]]; then
  cp deploy/systemd/delftclaw-gateway.service.template /etc/systemd/system/delftclaw-gateway.service
fi
if [[ -f deploy/systemd/delftclaw-seedbox-audit.service.template ]]; then
  cp deploy/systemd/delftclaw-seedbox-audit.service.template /etc/systemd/system/delftclaw-seedbox-audit.service
fi

echo "Reloading systemd"
systemctl daemon-reload

if [[ -f /etc/systemd/system/delftclaw-gateway.service ]]; then
  echo "Enabling and starting delftclaw-gateway.service"
  systemctl enable --now delftclaw-gateway.service
fi

cat <<EOF

Done. Status / logs:

  systemctl status delftclaw-gateway --no-pager
  journalctl -u delftclaw-gateway -f

To bring up identity-mcp + security-mcp as templated instances:

  sudo systemctl enable --now delftclaw-identity-mcp@<instance>.service
  sudo systemctl enable --now delftclaw-security-mcp@<instance>.service

(<instance> picks the env-file at /etc/delftclaw/instances/<instance>.env.)
EOF
