#!/usr/bin/env bash
# Single-command containerized reproduction of the SQ3 factorial containment
# experiment, end to end, on a disposable Ubuntu VPS/VM (run as root):
#
#   sudo bash security/containment_layer/reproduce.sh
#
# Steps:
#   1. Host preparation via prepare_vps.sh (Docker, gVisor/runsc with the
#      systrap platform, the vukzero_sq3 AppArmor profile, nftables).
#      Kernel-level facilities cannot themselves run inside a container,
#      so this stage is host-level by necessity. Skip with
#      SQ3_SKIP_PREPARE=true if the VPS is already prepared.
#   2. Build the driver image from security/containment_layer/Dockerfile.
#   3. Run the guarded factorial workflow (preflight -> smoke -> full run)
#      inside the driver container. The driver talks to the HOST Docker
#      daemon through /var/run/docker.sock and launches the six
#      per-condition sibling containers.
#
# Why the unusual mounts:
#   --network host      nftables egress rules applied by the runner must
#                       land in the host network namespace.
#   --pid host          condition characterization observes host-like PID
#                       facts exactly as in the official runs.
#   /sys/kernel/security  read-only, so the runner can verify the AppArmor
#                       profile is loaded.
#   $WORK at an IDENTICAL path on host and container: the runner creates
#   per-trial fixtures under its --out directory and bind-mounts them into
#   the sibling containers by absolute path; the host daemon resolves those
#   paths against the HOST filesystem, so the paths must match.
#
# Outputs are copied to security/containment_layer/results/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAYER="$ROOT/security/containment_layer"
WORK="${SQ3_WORK_DIR:-/var/lib/delftclaw/sq3_reproduce}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$WORK/sq3_factorial_containment_$STAMP"
IMAGE_TAG="${SQ3_HARNESS_TAG:-vukzero-sq3-harness}"

if [[ ${EUID} -ne 0 ]]; then
  echo "reproduce.sh must run as root on a disposable Ubuntu VPS/VM." >&2
  exit 1
fi

if [[ "${SQ3_SKIP_PREPARE:-false}" != "true" ]]; then
  bash "$LAYER/prepare_vps.sh"
fi

mkdir -p "$WORK" "$LAYER/results"

docker build -t "$IMAGE_TAG" -f "$LAYER/Dockerfile" "$ROOT"

docker run --rm \
  --privileged \
  --network host \
  --pid host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /sys/kernel/security:/sys/kernel/security:ro \
  -v "$WORK":"$WORK" \
  -e SQ3_OUT="$OUT" \
  -e SQ3_IMAGE="${SQ3_IMAGE:-python:3.12-slim}" \
  -e SQ3_REPETITIONS="${SQ3_REPETITIONS:-20}" \
  -e SQ3_TIMEOUT="${SQ3_TIMEOUT:-10}" \
  "$IMAGE_TAG"

# The guarded workflow writes <OUT>_preflight, <OUT>_smoke, and <OUT>.
cp -r "$OUT" "${OUT}_preflight" "${OUT}_smoke" "$LAYER/results/" 2>/dev/null \
  || cp -r "$OUT" "$LAYER/results/"

echo "SQ3 reproduction complete. Results copied to:"
echo "  $LAYER/results/$(basename "$OUT")"
