#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="${DELFTCLAW_REPO_DIR:-/root/DelftClaw}"
ENV_FILE="${DELFTCLAW_ENV_FILE:-$REPO_DIR/configs/vuk.local.env}"
EXPERIMENT_ROOT="${DELFTCLAW_EXPERIMENT_ROOT:-/root/delftclaw_real_experiment}"
AGENT_ID="${DELFTCLAW_AGENT_ID:-vuk-openclaw-vps}"
IDENTITY_PATH="${DELFTCLAW_OPENCLAW_KEY_PATH:-$REPO_DIR/identity/agent_identity.json}"

cd "$REPO_DIR"

echo "[1/7] Creating Python virtual environment"
python3 -m venv .venv
source .venv/bin/activate

echo "[2/7] Installing Python dependencies"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "[3/7] Creating local directories"
mkdir -p "$REPO_DIR/logs" "$REPO_DIR/configs" "$EXPERIMENT_ROOT"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[4/7] Writing $ENV_FILE"
  cat > "$ENV_FILE" <<EOF
DELFTCLAW_AGENT_ID=$AGENT_ID
DELFTCLAW_GATEWAY_HOST=127.0.0.1
DELFTCLAW_GATEWAY_PORT=8765
DELFTCLAW_GATEWAY_URL=http://127.0.0.1:8765
DELFTCLAW_GATEWAY_MODE=defended
DELFTCLAW_BAN_THRESHOLD=30
DELFTCLAW_MAX_TOOL_RISK=sensitive
DELFTCLAW_LOG_PATH=$REPO_DIR/logs/${AGENT_ID}_append_only.jsonl

DELFTCLAW_USE_OPENCLAW_IDENTITY=true
DELFTCLAW_ENABLE_OPENCLAW_P2P=false
DELFTCLAW_OPENCLAW_NETWORK=REGTEST
DELFTCLAW_OPENCLAW_KEY_PATH=$IDENTITY_PATH
DELFTCLAW_OPENCLAW_P2P_HOST=0.0.0.0
DELFTCLAW_OPENCLAW_P2P_PORT=9000
DELFTCLAW_OPENCLAW_WORKING_DIR=$REPO_DIR

DELFTCLAW_BITCOIN_NETWORK=mock
DELFTCLAW_BITCOIN_MIN_CONFIRMATIONS=0

DELFTCLAW_RUN_ID=vps-demo-001
DELFTCLAW_EXPERIMENT_CONDITION=defended
DELFTCLAW_EXPERIMENT_ROOT=$EXPERIMENT_ROOT
DELFTCLAW_SUBQ3_CONDITION=gvisor
DELFTCLAW_SUBQ3_MANIFEST=$EXPERIMENT_ROOT/runs/subq3-gvisor-run001/subq3_manifest.json

IDENTITY_MCP_PORT=7701
DELFTCLAW_SECURITY_MCP_PORT=7702
EOF
else
  echo "[4/7] Keeping existing $ENV_FILE"
fi

echo "[5/7] Creating shared AgentIdentity if missing"
python - "$IDENTITY_PATH" <<'PY'
from pathlib import Path
import sys

from identity.agent_identity import AgentIdentity

path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
if path.exists():
    identity = AgentIdentity.load(path)
else:
    identity = AgentIdentity(network="REGTEST", agent_index=0)
    identity.save(path)
print(identity.public_bundle()["agent_id"])
PY

echo "[6/7] Preparing canary experiment workspace"
python -m security.real_experiments.setup_canaries --root "$EXPERIMENT_ROOT"

echo "[7/7] Writing combined OpenClaw MCP config"
python - "$REPO_DIR/configs/openclaw_security_identity_mcp_config.json" <<'PY'
import json
from pathlib import Path
import sys

target = Path(sys.argv[1])
target.write_text(json.dumps({
    "mcp": {
        "servers": {
            "agent-identity": {
                "url": "http://127.0.0.1:7701/mcp",
                "transport": "streamable-http",
                "description": "Cryptographic identity, wallet, signing, and verification tools."
            },
            "delftclaw-security": {
                "url": "http://127.0.0.1:7702/mcp",
                "transport": "streamable-http",
                "description": "DelftClaw defended gateway tools for seedboxes, reputation, files, audits, and metrics."
            }
        }
    }
}, indent=2) + "\n")
print(target)
PY

echo
echo "Bootstrap complete."
echo "Next: bash deploy/vps/run_security_identity_stack.sh"
echo "Then: bash deploy/vps/smoke_test_security_identity.sh"
