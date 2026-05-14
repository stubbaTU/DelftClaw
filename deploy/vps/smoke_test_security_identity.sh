#!/usr/bin/env bash
# Smoke-test the identity + security MCPs for a given templated INSTANCE.
#
# Reads ports + endpoints from /etc/delftclaw/instances/<instance>.env
# (the env file that bootstrap_security_identity.sh writes and that the
# templated systemd units consume). Falls back to the legacy
# configs/vuk.local.env path if DELFTCLAW_ENV_FILE is exported and points
# there, so existing dev runs still work.

set -Eeuo pipefail

INSTANCE="${INSTANCE:-${DELFTCLAW_AGENT_ID:-$(hostname -s)}}"
ENV_FILE="${DELFTCLAW_ENV_FILE:-/etc/delftclaw/instances/${INSTANCE}.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Env file not found: $ENV_FILE"
  echo "Run deploy/vps/bootstrap_security_identity.sh first (INSTANCE=${INSTANCE})."
  exit 1
fi

set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

IDENTITY_PORT="${IDENTITY_MCP_PORT:-7701}"
SECURITY_PORT="${SECURITY_MCP_PORT:-7702}"
GATEWAY_URL="${DELFTCLAW_GATEWAY_URL:-http://127.0.0.1:8765}"

post_json() {
  local url="$1"
  local body="$2"
  python3 - "$url" "$body" <<'PY'
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
  python3 - "$1" <<'PY'
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
get_url "http://127.0.0.1:$SECURITY_PORT/health"

echo "[4/8] Identity tool: get_identity"
post_json "http://127.0.0.1:$IDENTITY_PORT/mcp/tool/get_identity" '{"args":{}}'

echo "[4b/8] Identity and security local agent id must match"
python3 - "$IDENTITY_PORT" "$SECURITY_PORT" <<'PY'
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
post_json "http://127.0.0.1:$SECURITY_PORT/mcp/tool/delftclaw_register_seedbox" \
  '{"args":{"seedbox_id":"demo-seedbox-1","donation_address":"tb1q-demo","advertised_capacity_gb":100}}'

echo "[6/8] Security tool: index file"
post_json "http://127.0.0.1:$SECURITY_PORT/mcp/tool/delftclaw_index_seedbox_file" \
  '{"args":{"file_id":"cc-001","seedbox_id":"demo-seedbox-1","name":"Creative Commons Audio","content_url":"https://example.com/audio.mp3","tags":["Creative Commons","audio"]}}'

echo "[7/8] Security tool: list files"
post_json "http://127.0.0.1:$SECURITY_PORT/mcp/tool/delftclaw_list_files" '{"args":{}}'

echo "[8/8] Security tool: metrics"
post_json "http://127.0.0.1:$SECURITY_PORT/mcp/tool/delftclaw_get_metrics" '{"args":{}}'

echo "Smoke test complete."
