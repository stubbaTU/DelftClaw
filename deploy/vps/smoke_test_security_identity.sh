#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="${DELFTCLAW_REPO_DIR:-/root/DelftClaw}"
ENV_FILE="${DELFTCLAW_ENV_FILE:-$REPO_DIR/configs/vuk.local.env}"

cd "$REPO_DIR"
source .venv/bin/activate

set -a
source "$ENV_FILE"
set +a

IDENTITY_PORT="${IDENTITY_MCP_PORT:-7701}"
SECURITY_MCP_PORT="${DELFTCLAW_SECURITY_MCP_PORT:-7702}"
GATEWAY_URL="${DELFTCLAW_GATEWAY_URL:-http://127.0.0.1:8765}"

post_json() {
  local url="$1"
  local body="$2"
  python - "$url" "$body" <<'PY'
import json
import sys
from urllib.request import Request, urlopen

url, body = sys.argv[1], sys.argv[2]
req = Request(url, data=body.encode(), headers={"Content-Type": "application/json"}, method="POST")
with urlopen(req, timeout=10) as resp:
    print(resp.read().decode())
PY
}

get_url() {
  python - "$1" <<'PY'
import sys
from urllib.request import urlopen

with urlopen(sys.argv[1], timeout=10) as resp:
    print(resp.read().decode())
PY
}

echo "[1/8] Gateway health"
get_url "$GATEWAY_URL/health"

echo "[2/8] Identity MCP health"
get_url "http://127.0.0.1:$IDENTITY_PORT/health"

echo "[3/8] Security MCP health"
get_url "http://127.0.0.1:$SECURITY_MCP_PORT/health"

echo "[4/8] Identity tool: get_identity"
post_json "http://127.0.0.1:$IDENTITY_PORT/mcp/tool/get_identity" '{"args":{}}'

echo "[4b/8] Identity and security local agent id must match"
python - "$IDENTITY_PORT" "$SECURITY_MCP_PORT" <<'PY'
import json
import sys
from urllib.request import Request, urlopen

identity_port, security_port = sys.argv[1], sys.argv[2]

def post(url: str, body: dict) -> dict:
    req = Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))

identity = post(f"http://127.0.0.1:{identity_port}/mcp/tool/get_identity", {"args": {}})
metrics = post(f"http://127.0.0.1:{security_port}/mcp/tool/delftclaw_get_metrics", {"args": {}})
identity_agent_id = identity.get("agent_id")
security_agent_id = metrics.get("local_agent_id")
print(json.dumps({
    "identity_agent_id": identity_agent_id,
    "security_local_agent_id": security_agent_id,
    "match": identity_agent_id == security_agent_id,
}, sort_keys=True))
if identity_agent_id != security_agent_id:
    raise SystemExit("identity MCP agent_id does not match security local_agent_id")
PY

echo "[5/8] Security tool: register seedbox"
post_json "http://127.0.0.1:$SECURITY_MCP_PORT/mcp/tool/delftclaw_register_seedbox" \
  '{"args":{"seedbox_id":"demo-seedbox-1","donation_address":"tb1q-demo","advertised_capacity_gb":100}}'

echo "[6/8] Security tool: index file"
post_json "http://127.0.0.1:$SECURITY_MCP_PORT/mcp/tool/delftclaw_index_seedbox_file" \
  '{"args":{"file_id":"cc-001","seedbox_id":"demo-seedbox-1","name":"Creative Commons Audio","content_url":"https://example.com/audio.mp3","tags":["Creative Commons","audio"]}}'

echo "[7/8] Security tool: list files"
post_json "http://127.0.0.1:$SECURITY_MCP_PORT/mcp/tool/delftclaw_list_files" '{"args":{}}'

echo "[8/8] Security tool: metrics"
post_json "http://127.0.0.1:$SECURITY_MCP_PORT/mcp/tool/delftclaw_get_metrics" '{"args":{}}'

echo "Smoke test complete."
