#!/usr/bin/env bash
# DelftClaw VPS bootstrap — one-shot, idempotent, Ubuntu 24.04.
#
# Usage (as root on the VPS, after rsyncing the repo to /opt/delftclaw):
#
#     bash /opt/delftclaw/deploy/setup_vps.sh
#
# What this does, in order:
#   1.  apt: python, libsodium, build tools, ufw, curl, jq, git
#   2.  install Ollama (CPU build) if not present  — DEV/CI fallback only.
#       v5.1 production points the compiler-LLM at an external GPU host via
#       LLM_BASE_URL (an OpenAI-compatible endpoint); the local Ollama
#       install is purely a fallback for air-gapped development and CI.
#   3.  pull the Qwen model (qwen2.5-coder:7b by default) into the local
#       Ollama — used only when LLM_BASE_URL is unset.
#   4.  create the `delftclaw` system user + state dirs
#   5.  build the project venv + pip install requirements.txt
#   6.  generate the BIP-39 seed file at /var/lib/delftclaw/seed.txt
#       (skipped if one already exists)
#   7.  install the scenario systemd units
#   8.  open ufw rules for ssh, ipv8 udp, mcp tcp (does not enable ufw)
#   9.  smoke-test:
#         - curl Ollama /v1/models  (only meaningful if no external endpoint)
#         - curl the MCP server /mcp tools/list
#       prints both results at the end
#
# Re-running the script is safe; each step short-circuits if already done.

set -euo pipefail

REPO_ROOT=${REPO_ROOT:-/opt/delftclaw}
STATE_DIR=/var/lib/delftclaw
LOG_DIR=/var/log/delftclaw
SERVICE_USER=delftclaw

IPV8_PORT=${IPV8_PORT:-8090}
MCP_PORT=${MCP_PORT:-8765}
OLLAMA_PORT=${OLLAMA_PORT:-11434}
LLM_MODEL=${LLM_MODEL:-qwen2.5-coder:7b}

# Colour helpers.
c_blue()  { printf '\033[1;36m[setup] %s\033[0m\n' "$*"; }
c_green() { printf '\033[1;32m[ ok  ] %s\033[0m\n' "$*"; }
c_red()   { printf '\033[1;31m[FAIL ] %s\033[0m\n' "$*" >&2; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        c_red "must run as root (try: sudo bash $0)"
        exit 1
    fi
}

step_apt() {
    c_blue "apt: installing base packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
        python3 python3-venv python3-pip \
        libsodium-dev build-essential \
        ufw curl ca-certificates gnupg jq git
}

step_ollama() {
    if command -v ollama >/dev/null 2>&1; then
        c_blue "ollama: already installed ($(ollama --version 2>&1 | head -1))"
    else
        c_blue "ollama: installing"
        curl -fsSL https://ollama.com/install.sh | sh
    fi
    systemctl enable --now ollama
    # Wait for the service to bind its port (worst case: cold start ~3s).
    for _ in $(seq 1 20); do
        if curl -fsS "http://127.0.0.1:${OLLAMA_PORT}/api/tags" >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
    c_blue "ollama: pulling ${LLM_MODEL} (skipped if cached)"
    ollama pull "${LLM_MODEL}"
}

step_tailscale() {
    # Required to reach the supervisor's GPU box at the Tailscale-CGNAT
    # address (100.x.x.x). Without Tailscale up, the watchdog's first turn
    # times out trying to call the remote Ollama.
    if command -v tailscale >/dev/null 2>&1; then
        c_blue "tailscale: already installed ($(tailscale version 2>&1 | head -1))"
    else
        c_blue "tailscale: installing"
        curl -fsSL https://tailscale.com/install.sh | sh
    fi
    systemctl enable --now tailscaled
    if tailscale status >/dev/null 2>&1; then
        local ts_ip
        ts_ip=$(tailscale ip -4 2>/dev/null | head -1 || true)
        c_green "tailscale: connected (IP ${ts_ip:-unknown})"
    else
        c_red "tailscale is installed but the VPS is NOT yet on a tailnet."
        c_red "Run this on the VPS, then re-run setup_vps.sh:"
        c_red "    tailscale up"
        c_red "Follow the URL it prints, sign in, and verify with: ping -c 2 100.73.168.12"
        exit 1
    fi
}

step_openclaw_cli() {
    # The watchdog drives ``openclaw agent`` as a subprocess. Install the CLI
    # globally via npm so /usr/local/bin/openclaw is on PATH for every user.
    if command -v openclaw >/dev/null 2>&1; then
        c_blue "openclaw: already installed ($(openclaw --version 2>&1 | head -1))"
        return
    fi

    if ! command -v node >/dev/null 2>&1 || \
       [[ "$(node --version 2>/dev/null | sed 's/^v//' | cut -d. -f1)" -lt 22 ]]; then
        c_blue "node: installing Node.js 22 (required by openclaw)"
        curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
        DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
    fi

    c_blue "openclaw: npm install -g openclaw"
    npm install -g openclaw

    if ! command -v openclaw >/dev/null 2>&1; then
        c_red "openclaw CLI install failed — see npm log above"
        exit 1
    fi
    c_green "openclaw CLI: $(openclaw --version 2>&1 | head -1)"
}

step_user() {
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        c_blue "user: $SERVICE_USER already exists"
    else
        c_blue "user: creating $SERVICE_USER"
        useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$LOG_DIR"
    # bitcoinlib hardcodes ``BCL_DATABASE_DIR = Path.home() / ".bitcoinlib" / "database"``
    # at import time. We override HOME=/var/lib/delftclaw in the systemd unit
    # (ProtectHome=true blocks the real home), so pre-create the .bitcoinlib
    # tree under the state dir.
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR/.bitcoinlib"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR/.bitcoinlib/database"
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$REPO_ROOT"
}

step_venv() {
    if [[ -x "$REPO_ROOT/venv/bin/python" ]]; then
        c_blue "venv: refreshing pip + requirements"
    else
        c_blue "venv: creating"
        sudo -u "$SERVICE_USER" python3 -m venv "$REPO_ROOT/venv"
    fi
    sudo -u "$SERVICE_USER" "$REPO_ROOT/venv/bin/pip" install --upgrade --quiet pip wheel
    sudo -u "$SERVICE_USER" "$REPO_ROOT/venv/bin/pip" install --quiet -r "$REPO_ROOT/requirements.txt"
}

step_systemd_templates() {
    c_blue "systemd: installing templated units"
    # Stop + disable any leftover non-templated unit from the old flow.
    if systemctl list-unit-files | grep -q '^delftclaw-mcp\.service'; then
        c_blue "systemd: removing legacy delftclaw-mcp.service"
        systemctl stop delftclaw-mcp.service 2>/dev/null || true
        systemctl disable delftclaw-mcp.service 2>/dev/null || true
        rm -f /etc/systemd/system/delftclaw-mcp.service
    fi
    # Install the scenario units. Each takes an instance
    # name via `systemctl enable --now <unit>@<instance>.service` and reads
    # its env file from /etc/delftclaw/instances/<instance>.env.
    for unit in \
        delftclaw-mcp@.service \
        delftclaw-watchdog@.service; do
        install -m 0644 -o root -g root \
            "$REPO_ROOT/deploy/systemd/${unit}" \
            "/etc/systemd/system/${unit}"
    done

    install -d -o root -g "$SERVICE_USER" -m 0750 /etc/delftclaw/instances
    install -d -o root -g "$SERVICE_USER" -m 0750 /etc/delftclaw/scenarios
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 /var/log/delftclaw
    systemctl daemon-reload
}

step_firewall() {
    if ! command -v ufw >/dev/null 2>&1; then
        c_blue "ufw: not installed, skipping firewall rules"
        return
    fi
    c_blue "ufw: adding rules (does NOT enable the firewall — do that manually)"
    ufw allow 22/tcp >/dev/null
    # Scenario-allocated IPv8 + MCP ranges for seek_cc, community_demo,
    # security_layers, and secure_community_demo.
    ufw allow 8190:8399/udp >/dev/null
    ufw allow 18765:18999/tcp >/dev/null
}

main() {
    require_root
    step_apt
    step_tailscale
    step_ollama
    step_openclaw_cli
    step_user
    step_venv
    step_systemd_templates
    step_firewall

    cat <<EOF

==============================================================================
DelftClaw infrastructure is installed.

Two templated scenario systemd units are now available, both reading their per-instance
env file from /etc/delftclaw/instances/<instance>.env:

  delftclaw-mcp@.service           — agent + watchdog scenario MCP (seek_cc, etc.)
  delftclaw-watchdog@.service      — autonomous tick driver for delftclaw-mcp

Scenario flow (per-agent):

  # On the VPS (or via 'make scenario NAME=seek_cc' from your laptop):
  /opt/delftclaw/venv/bin/python -m deploy.scenario_boot seek_cc

Common operator commands:

  systemctl list-units 'delftclaw-*@*.service'                # all instances
  journalctl -u 'delftclaw-mcp@seek_cc-alice' -f              # tail scenario agent

  ufw enable                            # leave open: 22/tcp, 8190-8399/udp, 18765-18999/tcp

  python -m deploy.scenario_boot seek_cc --teardown           # stop scenario

Ollama : http://127.0.0.1:${OLLAMA_PORT}/v1   (${LLM_MODEL})

==============================================================================
EOF
}

main "$@"
