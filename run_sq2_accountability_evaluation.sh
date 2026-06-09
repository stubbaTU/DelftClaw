#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source .venv/bin/activate

: "${OPENAI_BASE_URL:=http://127.0.0.1:8001/v1}"
: "${OPENAI_API_KEY:=sk-local-dev}"
: "${SQ2_MODEL:=gpt-4o-mini-2024-07-18}"
: "${SQ2_SEEDS:=5}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROOT="results/sq2_accountability_factorial_${STAMP}"
mkdir -p "$ROOT"

curl -fsS "$OPENAI_BASE_URL/models" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  >/dev/null

{
  echo "ROOT=$ROOT"
  echo "started=$(date -Is)"
  echo "model=$SQ2_MODEL"
  echo "base_url=$OPENAI_BASE_URL"
  echo "seeds_per_cell=$SQ2_SEEDS"
  echo "strategies=naive threshold_aware sybil_split"
} | tee "$ROOT/RUN_ROOT.txt"

echo "START naive live run $(date -Is)"
python -m security.accountability_layer.generate_live_scenarios \
  --attacker-strategy naive --seeds-per-cell "$SQ2_SEEDS" \
  --out "$ROOT/scenarios_naive.jsonl"

python -m security.accountability_layer.live_orchestrator \
  --mode live-llm \
  --scenarios "$ROOT/scenarios_naive.jsonl" \
  --conditions C0_naive_reputation C1_vukzero_accountability \
  --base-url "$OPENAI_BASE_URL" --api-key "$OPENAI_API_KEY" --model "$SQ2_MODEL" \
  --max-iterations 5 --estimator-interval 1 --expulsion-threshold 5 \
  --out "$ROOT/naive"

for STRATEGY in threshold_aware sybil_split; do
  echo "START $STRATEGY live run $(date -Is)"
  python -m security.accountability_layer.generate_live_scenarios \
    --attacker-strategy "$STRATEGY" --intensities medium high --seeds-per-cell "$SQ2_SEEDS" \
    --out "$ROOT/scenarios_${STRATEGY}.jsonl"

  python -m security.accountability_layer.live_orchestrator \
    --mode live-llm \
    --scenarios "$ROOT/scenarios_${STRATEGY}.jsonl" \
    --conditions C1_vukzero_accountability \
    --base-url "$OPENAI_BASE_URL" --api-key "$OPENAI_API_KEY" --model "$SQ2_MODEL" \
    --max-iterations 5 --estimator-interval 1 --expulsion-threshold 5 \
    --out "$ROOT/$STRATEGY"

  python -m security.accountability_layer.rescore_logs \
    --run-dir "$ROOT/$STRATEGY" --out "$ROOT/$STRATEGY/analysis"
  python -m security.accountability_layer.sweep_thresholds \
    --run-dir "$ROOT/$STRATEGY" --out "$ROOT/$STRATEGY/analysis"
  python -m security.accountability_layer.sq2_statistics \
    --trials "$ROOT/$STRATEGY/analysis/sq2_rescored_trials.csv" \
    --out "$ROOT/$STRATEGY/analysis/ablation_stats"
done

python -m security.accountability_layer.rescore_logs \
  --run-dir "$ROOT/naive" --out "$ROOT/naive/analysis"
python -m security.accountability_layer.sweep_thresholds \
  --run-dir "$ROOT/naive" --out "$ROOT/naive/analysis"
python -m security.accountability_layer.sq2_statistics \
  --trials "$ROOT/naive/sq2_trials.csv" --out "$ROOT/naive/analysis/live_stats"
python -m security.accountability_layer.sq2_statistics \
  --trials "$ROOT/naive/analysis/sq2_rescored_trials.csv" \
  --out "$ROOT/naive/analysis/ablation_stats"
python -m security.accountability_layer.evaluate_beta_baseline \
  --run-dir "$ROOT/naive" --out "$ROOT/naive/analysis"

echo "finished=$(date -Is)" | tee -a "$ROOT/RUN_ROOT.txt"
echo "$ROOT"
