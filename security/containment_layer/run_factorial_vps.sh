#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ -z "${PYTHON_BIN:-}" ]]; then
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT/.venv/bin/python"
  elif [[ -x "$ROOT/venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT/venv/bin/python"
  else
    echo "No repository Python environment found. Set PYTHON_BIN explicitly." >&2
    exit 1
  fi
fi
OUT="${SQ3_OUT:-results/sq3_factorial_containment_$(date +%Y%m%d_%H%M%S)}"
IMAGE="${SQ3_IMAGE:-python:3.12-slim}"
REPETITIONS="${SQ3_REPETITIONS:-20}"
TIMEOUT="${SQ3_TIMEOUT:-10}"
SMOKE_PROBES="${SQ3_SMOKE_PROBES:-A1 D1 E5}"

"$PYTHON_BIN" -m security.containment_layer.evaluation.official_runner \
  --out "${OUT}_preflight" \
  --image "$IMAGE" \
  --preflight-only

if [[ "${SQ3_SKIP_SMOKE:-false}" != "true" ]]; then
  # shellcheck disable=SC2086
  "$PYTHON_BIN" -m security.containment_layer.evaluation.official_runner \
    --out "${OUT}_smoke" \
    --image "$IMAGE" \
    --timeout "$TIMEOUT" \
    --repetitions 1 \
    --probe-ids $SMOKE_PROBES
fi

"$PYTHON_BIN" -m security.containment_layer.evaluation.official_runner \
  --out "$OUT" \
  --image "$IMAGE" \
  --timeout "$TIMEOUT" \
  --repetitions "$REPETITIONS"

echo "SQ3 factorial evaluation complete: $OUT"
