#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "SQ3 preparation must run as root inside the disposable VPS/VM." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE="$ROOT/security/containment_layer/profiles/apparmor_vukzero_sq3"
LOCK_DIR="/var/lib/delftclaw/sq3"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  apt-transport-https ca-certificates curl gnupg \
  docker.io nftables iptables apparmor apparmor-utils jq

install -d -m 0755 /usr/share/keyrings
curl -fsSL https://gvisor.dev/archive.key \
  | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  > /etc/apt/sources.list.d/gvisor.list
apt-get update -y

if [[ -n "${SQ3_RUNSC_VERSION:-}" ]]; then
  apt-get install -y "runsc=${SQ3_RUNSC_VERSION}"
else
  apt-get install -y runsc
fi

runsc install --runtime=runsc -- --platform=systrap
systemctl enable --now docker apparmor
systemctl restart docker

install -m 0644 "$PROFILE" /etc/apparmor.d/vukzero_sq3
apparmor_parser -r /etc/apparmor.d/vukzero_sq3

install -d -m 0755 "$LOCK_DIR"
runsc --version > "$LOCK_DIR/runsc_version.lock"
docker info --format '{{json .Runtimes}}' > "$LOCK_DIR/docker_runtimes.json"
docker info --format '{{.FirewallBackend}}' > "$LOCK_DIR/docker_firewall_backend.txt" 2>/dev/null || true
iptables --version > "$LOCK_DIR/iptables_version.txt"
nft --version > "$LOCK_DIR/nft_version.txt"

docker run --rm --runtime=runsc hello-world >/dev/null

echo "SQ3 VPS preparation complete."
echo "Pinned installed runsc version:"
cat "$LOCK_DIR/runsc_version.lock"
echo "Registered Docker runtimes:"
cat "$LOCK_DIR/docker_runtimes.json"
