#!/usr/bin/env bash
# Bring up the templated identity + security MCP units for one instance.
#
# Prerequisites: ``deploy/setup_vps.sh`` and
# ``deploy/vps/bootstrap_security_identity.sh`` have already run for this
# INSTANCE, so the env file ``/etc/delftclaw/instances/<instance>.env``
# exists and the templated units are installed.
#
# This script is intentionally a thin systemctl wrapper — the days of
# forking the three processes from a single foreground script are over.
# The colleagues' optional gateway + seedbox-audit units (still
# non-templated) are also brought up here when their unit files exist.

set -Eeuo pipefail

INSTANCE="${INSTANCE:-${DELFTCLAW_AGENT_ID:-$(hostname -s)}}"
ENV_FILE="/etc/delftclaw/instances/${INSTANCE}.env"

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Env file not found: $ENV_FILE"
  echo "Run deploy/vps/bootstrap_security_identity.sh first (INSTANCE=${INSTANCE})."
  exit 1
fi

echo "Bringing up DelftClaw MCP stack for instance '${INSTANCE}'"

$SUDO systemctl daemon-reload

# Templated DelftClaw MCPs (installed by deploy/setup_vps.sh).
for unit in \
  "delftclaw-identity-mcp@${INSTANCE}.service" \
  "delftclaw-security-mcp@${INSTANCE}.service"; do
  echo "  enabling ${unit}"
  $SUDO systemctl reset-failed "${unit}" 2>/dev/null || true
  $SUDO systemctl enable --now "${unit}"
done

# Colleagues' non-templated gateway + seedbox-audit (optional).
for legacy in delftclaw-gateway.service delftclaw-seedbox-audit.service; do
  if [[ -f "/etc/systemd/system/${legacy}" ]]; then
    echo "  enabling ${legacy} (non-templated)"
    $SUDO systemctl reset-failed "${legacy}" 2>/dev/null || true
    $SUDO systemctl enable --now "${legacy}"
  fi
done

# Source the env file just so we can print the endpoints to the operator.
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

IDENTITY_PORT="${IDENTITY_MCP_PORT:-7701}"
SECURITY_PORT="${SECURITY_MCP_PORT:-7702}"
GATEWAY_URL="${DELFTCLAW_GATEWAY_URL:-http://127.0.0.1:8765}"

cat <<EOF

DelftClaw MCP stack is up for '${INSTANCE}'.

  Identity MCP: http://127.0.0.1:${IDENTITY_PORT}/mcp
  Security MCP: http://127.0.0.1:${SECURITY_PORT}/mcp
  Gateway:      ${GATEWAY_URL}

Tail logs:
  journalctl -u 'delftclaw-identity-mcp@${INSTANCE}' -f
  journalctl -u 'delftclaw-security-mcp@${INSTANCE}' -f

Tear down:
  sudo systemctl disable --now delftclaw-identity-mcp@${INSTANCE}.service
  sudo systemctl disable --now delftclaw-security-mcp@${INSTANCE}.service
EOF
