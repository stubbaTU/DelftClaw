#!/usr/bin/env bash
# Operator helper for the four-agent seek_cc professor demo.
#
# Usage:
#   bash deploy/vps/demo_seek_cc.sh start
#   bash deploy/vps/demo_seek_cc.sh status
#   bash deploy/vps/demo_seek_cc.sh watch
#   bash deploy/vps/demo_seek_cc.sh logs
#   bash deploy/vps/demo_seek_cc.sh mcp-config
#   bash deploy/vps/demo_seek_cc.sh probe
#   bash deploy/vps/demo_seek_cc.sh paper-demo
#   bash deploy/vps/demo_seek_cc.sh paper-demo-real
#   bash deploy/vps/demo_seek_cc.sh paper-demo-stop
#   bash deploy/vps/demo_seek_cc.sh stop

set -Eeuo pipefail

SCENARIO="${SCENARIO:-seek_cc}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
PYTHON="${PYTHON:-${REPO_ROOT}/venv/bin/python}"
if [[ ! -x "$PYTHON" && -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  PYTHON="${REPO_ROOT}/.venv/bin/python"
fi
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="python3"
fi

cd "$REPO_ROOT"
export PYTHONPATH="$REPO_ROOT"

usage() {
  sed -n '1,14p' "$0"
}

ports_json() {
  cat <<'JSON'
{
  "mcp": {
    "servers": {
      "delftclaw-alice": {
        "url": "http://127.0.0.1:18765/mcp",
        "transport": "streamable-http"
      },
      "delftclaw-bob": {
        "url": "http://127.0.0.1:18766/mcp",
        "transport": "streamable-http"
      },
      "delftclaw-charlie": {
        "url": "http://127.0.0.1:18767/mcp",
        "transport": "streamable-http"
      },
      "delftclaw-dave": {
        "url": "http://127.0.0.1:18768/mcp",
        "transport": "streamable-http"
      }
    }
  }
}
JSON
}

start_demo() {
  echo "[demo] starting ${SCENARIO}"
  "$PYTHON" -m deploy.scenario_boot "$SCENARIO"
  echo
  echo "[demo] started. Use:"
  echo "  bash deploy/vps/demo_seek_cc.sh status"
  echo "  bash deploy/vps/demo_seek_cc.sh watch"
  echo "  bash deploy/vps/demo_seek_cc.sh logs"
}

status_demo() {
  echo "[demo] systemd units"
  systemctl list-units "delftclaw-mcp@${SCENARIO}-*.service" --no-pager || true
  echo
  systemctl list-units "delftclaw-watchdog@${SCENARIO}-*.service" --no-pager || true
  echo
  echo "[demo] MCP tools exposed by each agent"
  for port in 18765 18766 18767 18768; do
    echo "--- port ${port}"
    "$PYTHON" -m deploy.probe_mcp "http://127.0.0.1:${port}/mcp" || true
  done
}

watch_demo() {
  echo "[demo] tailing systemd journals; Ctrl-C stops tailing, not the demo"
  journalctl --no-pager -f \
    -u "delftclaw-mcp@${SCENARIO}-*.service" \
    -u "delftclaw-watchdog@${SCENARIO}-*.service"
}

logs_demo() {
  local dir="/var/log/delftclaw/scenarios/${SCENARIO}"
  echo "[demo] tailing JSONL progression from ${dir}; Ctrl-C stops tailing"
  sudo mkdir -p "$dir"
  sudo touch "$dir"/alice.jsonl "$dir"/bob.jsonl "$dir"/charlie.jsonl "$dir"/dave.jsonl
  if command -v jq >/dev/null 2>&1; then
    sudo tail -q -n 20 -f "$dir"/*.jsonl | jq -R -c 'fromjson?'
  else
    sudo tail -q -n 20 -f "$dir"/*.jsonl
  fi
}

probe_demo() {
  echo "[demo] useful point-in-time MCP calls"
  for name_port in alice:18765 bob:18766 charlie:18767 dave:18768; do
    local name="${name_port%%:*}"
    local port="${name_port##*:}"
    echo "--- ${name}: peers_list"
    "$PYTHON" -m deploy.probe_mcp "http://127.0.0.1:${port}/mcp" --tool peers_list --args '{}' || true
    echo "--- ${name}: community_treasury_balance"
    "$PYTHON" -m deploy.probe_mcp "http://127.0.0.1:${port}/mcp" --tool community_treasury_balance --args '{}' || true
    echo "--- ${name}: community_log_list_recent"
    "$PYTHON" -m deploy.probe_mcp "http://127.0.0.1:${port}/mcp" --tool community_log_list_recent --args '{"limit":10}' || true
  done
}

paper_demo() {
  local root="${PAPER_DEMO_ROOT:-/var/lib/delftclaw/paper_demo}"
  local provider="${PAPER_DEMO_PROVIDER:-mock}"
  echo "[demo] running full Paper - Demo.txt checklist"
  echo "[demo] provider=${provider} root=${root}"
  "$PYTHON" -m deploy.paper_demo --provider "$provider" --root "$root" --reset
}

paper_demo_real() {
  echo "[demo] launching real OpenClaw-agent paper_demo scenario"
  "$PYTHON" -m deploy.paper_demo --real-agents
}

paper_demo_stop() {
  echo "[demo] stopping real OpenClaw-agent paper_demo scenario"
  "$PYTHON" -m deploy.paper_demo --stop-real-agents
}

stop_demo() {
  echo "[demo] stopping ${SCENARIO}"
  "$PYTHON" -m deploy.scenario_boot "$SCENARIO" --teardown
}

case "${1:-}" in
  start) start_demo ;;
  status) status_demo ;;
  watch) watch_demo ;;
  logs) logs_demo ;;
  mcp-config) ports_json ;;
  probe) probe_demo ;;
  paper-demo) paper_demo ;;
  paper-demo-real) paper_demo_real ;;
  paper-demo-stop) paper_demo_stop ;;
  stop) stop_demo ;;
  *) usage; exit 2 ;;
esac
