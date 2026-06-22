#!/usr/bin/env bash
# DelftClaw VPS bootstrap — one-shot, idempotent, Ubuntu 24.04.
#
# Usage (as root on the VPS, after rsyncing the repo to /opt/delftclaw):
#
#     bash /opt/delftclaw/deploy/setup_vps.sh
#
# What this does, in order:
#   1.  apt: python, libsodium, build tools, ufw, curl, jq, git
#   2.  tailscale: install + verify the VPS is on the supervisor's tailnet
#   3.  openclaw CLI: npm install -g openclaw (and Node.js 22 if missing)
#   4.  create the `delftclaw` system user + state dirs
#   5.  build the project venv + pip install requirements.txt
#   6.  install the scenario systemd units
#   7.  open ufw rules for ssh, ipv8 udp, mcp tcp (does not enable ufw)
#
# The historical Ollama install + Qwen pull step was removed on 2026-05-26
# — the reasoning LLM now lives behind ``scripts/llm_proxy.py`` (Anthropic
# upstream by default). Re-add an Ollama step if you bring back a local
# fallback model. Re-running the script is safe; each step short-circuits
# if already done.

set -euo pipefail

REPO_ROOT=${REPO_ROOT:-/opt/delftclaw}
STATE_DIR=/var/lib/delftclaw
LOG_DIR=/var/log/delftclaw
SERVICE_USER=delftclaw

IPV8_PORT=${IPV8_PORT:-8090}
MCP_PORT=${MCP_PORT:-8765}

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

step_tailscale() {
    # Historically required to reach a supervisor's GPU box at a
    # Tailscale-CGNAT address. Now optional — the production LLM lives
    # behind ``scripts/llm_proxy.py`` on 127.0.0.1:11600. Kept because
    # some operators still use a tailnet for SSH or sidechannels.
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
        c_blue "tailscale: not on a tailnet — proceeding (tailnet no longer required)."
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
    # Scenario-allocated IPv8 + MCP ranges for admission, file_share,
    # and file_transfer.
    ufw allow 8190:8399/udp >/dev/null
    ufw allow 18765:18999/tcp >/dev/null
}

main() {
    require_root
    step_apt
    step_tailscale
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

  delftclaw-mcp@.service           — agent + watchdog scenario MCP (admission, etc.)
  delftclaw-watchdog@.service      — autonomous tick driver for delftclaw-mcp

Scenario flow (per-agent):

  # On the VPS (or via 'make scenario NAME=payment' from your laptop):
  /opt/delftclaw/venv/bin/python -m deploy.scenario_boot payment

Common operator commands:

  systemctl list-units 'delftclaw-*@*.service'                # all instances
  journalctl -u 'delftclaw-mcp@payment-alice' -f             # tail scenario agent

  ufw enable                            # leave open: 22/tcp, 8190-8399/udp, 18765-18999/tcp

  python -m deploy.scenario_boot payment --teardown          # stop scenario

Reasoning LLM goes through scripts/llm_proxy.py (Anthropic upstream by
default). Start it with:  make llm-up

==============================================================================
EOF
}

main "$@"
