#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="${DELFTCLAW_REPO_DIR:-/root/DelftClaw}"
ENV_FILE="${DELFTCLAW_ENV_FILE:-$REPO_DIR/configs/vuk.local.env}"

cd "$REPO_DIR"
source .venv/bin/activate

set -a
source "$ENV_FILE"
set +a

IDENTITY_PATH="${DELFTCLAW_OPENCLAW_KEY_PATH:-$REPO_DIR/identity/agent_identity.json}"
IDENTITY_PORT="${IDENTITY_MCP_PORT:-7701}"
SECURITY_MCP_PORT="${DELFTCLAW_SECURITY_MCP_PORT:-7702}"
GATEWAY_HOST="${DELFTCLAW_GATEWAY_HOST:-127.0.0.1}"
GATEWAY_PORT="${DELFTCLAW_GATEWAY_PORT:-8765}"
export DELFTCLAW_GATEWAY_URL="${DELFTCLAW_GATEWAY_URL:-http://$GATEWAY_HOST:$GATEWAY_PORT}"
NETWORK_LOWER="$(printf '%s' "${DELFTCLAW_OPENCLAW_NETWORK:-REGTEST}" | tr '[:upper:]' '[:lower:]')"

mkdir -p "$REPO_DIR/logs"

cleanup() {
  echo
  echo "Stopping DelftClaw demo stack"
  kill "${IDENTITY_PID:-}" "${GATEWAY_PID:-}" "${SECURITY_MCP_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Starting identity MCP on 127.0.0.1:$IDENTITY_PORT"
python -m identity.start_identity_server \
  --network "$NETWORK_LOWER" \
  --port "$IDENTITY_PORT" \
  --identity-path "$IDENTITY_PATH" \
  > "$REPO_DIR/logs/identity_mcp.log" 2>&1 &
IDENTITY_PID=$!

echo "Starting DelftClaw gateway from $ENV_FILE"
python -m security.integration.gateway --env "$ENV_FILE" \
  > "$REPO_DIR/logs/gateway.log" 2>&1 &
GATEWAY_PID=$!

echo "Starting security MCP on 127.0.0.1:$SECURITY_MCP_PORT"
python -m security.integration.start_security_mcp_server --port "$SECURITY_MCP_PORT" \
  > "$REPO_DIR/logs/security_mcp.log" 2>&1 &
SECURITY_MCP_PID=$!

echo
echo "Stack started."
echo "Identity MCP: http://127.0.0.1:$IDENTITY_PORT/mcp"
echo "Gateway:      $DELFTCLAW_GATEWAY_URL"
echo "Security MCP: http://127.0.0.1:$SECURITY_MCP_PORT/mcp"
echo
echo "Logs:"
echo "  $REPO_DIR/logs/identity_mcp.log"
echo "  $REPO_DIR/logs/gateway.log"
echo "  $REPO_DIR/logs/security_mcp.log"
echo
echo "Press Ctrl+C to stop all three processes."

wait
