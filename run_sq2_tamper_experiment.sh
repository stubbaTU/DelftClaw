#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source .venv/bin/activate

: "${OPENAI_BASE_URL:=http://127.0.0.1:8001/v1}"
: "${OPENAI_API_KEY:=sk-local-dev}"
: "${SQ2_MODEL:=gpt-4o-mini-2024-07-18}"

OUT="results/sq2_tamper_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
curl -fsS "$OPENAI_BASE_URL/models" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  >/dev/null
{
  echo "OUT=$OUT"
  echo "started=$(date -Is)"
  echo "model=$SQ2_MODEL"
  echo "base_url=$OPENAI_BASE_URL"
} | tee "$OUT/RUN_ROOT.txt"

python -m security.accountability_layer.live_orchestrator \
  --mode live-llm \
  --conditions B1_rules_mutable C1_vukzero_accountability \
  --inject-tamper \
  --base-url "$OPENAI_BASE_URL" --api-key "$OPENAI_API_KEY" --model "$SQ2_MODEL" \
  --max-iterations 5 --estimator-interval 1 --expulsion-threshold 5 \
  --out "$OUT"
echo "finished=$(date -Is)" | tee -a "$OUT/RUN_ROOT.txt"
echo "$OUT"
