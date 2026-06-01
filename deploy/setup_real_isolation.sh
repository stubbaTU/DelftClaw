#!/usr/bin/env bash
# Install real gVisor + iptables prerequisites for the integrated security demo.
#
# Run as root on the VPS:
#   bash /opt/delftclaw/deploy/setup_real_isolation.sh

set -euo pipefail

REPO_ROOT=${REPO_ROOT:-/opt/delftclaw}
PYTHON_BIN=${PYTHON_BIN:-}

c_blue()  { printf '\033[1;36m[isolation] %s\033[0m\n' "$*"; }
c_green() { printf '\033[1;32m[ ok      ] %s\033[0m\n' "$*"; }
c_red()   { printf '\033[1;31m[FAIL    ] %s\033[0m\n' "$*" >&2; }

if [[ $EUID -ne 0 ]]; then
  c_red "must run as root"
  exit 1
fi

c_blue "apt: installing Docker, iproute2, iptables, and gVisor apt dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  docker.io \
  gnupg \
  iproute2 \
  iptables \
  jq

c_blue "gVisor: configuring official apt repository"
curl -fsSL https://gvisor.dev/archive.key \
  | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  > /etc/apt/sources.list.d/gvisor.list

c_blue "gVisor: installing runsc"
apt-get update -y
apt-get install -y runsc

c_blue "Docker: enabling service and registering runsc runtime"
systemctl enable --now docker
runsc install
systemctl reload docker

c_blue "smoke: docker run --runtime=runsc busybox"
docker run --rm --runtime=runsc --network=none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  busybox:1.36 sh -c 'echo ok >/tmp/probe && echo GVISOR_READY'

if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
    PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
  else
    PYTHON_BIN="${REPO_ROOT}/venv/bin/python"
  fi
fi

c_blue "smoke: real guardrail probe"
PYTHONPATH="${REPO_ROOT}" "${PYTHON_BIN}" \
  -m security.subq3_containment.enforcement \
  --root /var/lib/delftclaw/real_isolation_smoke

c_green "real isolation prerequisites are installed"
