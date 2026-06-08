#!/usr/bin/env bash
set -u

cd "${DELFTCLAW_ROOT:-$HOME/DelftClaw}"
source .venv/bin/activate

export OPENAI_API_KEY="${OPENAI_API_KEY:-sk-local-dev}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://127.0.0.1:8001/v1}"
export OPENAI_API_BASE="${OPENAI_API_BASE:-$OPENAI_BASE_URL}"
export AGENTDOJO_MODEL="${AGENTDOJO_MODEL:-gpt-4o-mini-2024-07-18}"
export AGENTDOJO_PATH="${AGENTDOJO_PATH:-$HOME/progent/agentdojo}"
export COLUMNS="${COLUMNS:-300}"

export SECAGENT_DISABLE="True"
unset SECAGENT_POLICY_MODEL
unset SECAGENT_UPDATE
unset SECAGENT_IGNORE_UPDATE_ERROR
unset SECAGENT_SUITE

curl -fsS "$OPENAI_BASE_URL/models" >/dev/null || {
  echo "LiteLLM preflight failed: $OPENAI_BASE_URL/models is not reachable" >&2
  exit 1
}

RUN_ROOT="logs/or_openai_c1_vukzero_all4_toolknowledge_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RUN_ROOT"

{
  echo "RUN_ROOT=$RUN_ROOT"
  echo "condition=C1_agentdojo_vukzero"
  echo "repo=DelftClaw"
  echo "agentdojo_path=$AGENTDOJO_PATH"
  echo "model=$AGENTDOJO_MODEL"
  echo "actual_model=openrouter/openai/gpt-4o-mini via LiteLLM"
  echo "endpoint=$OPENAI_BASE_URL"
  echo "attack=tool_knowledge"
  echo "suites=workspace slack travel banking"
  echo "started=$(date -Is)"
} | tee "$RUN_ROOT/RUN_ROOT.txt"

for SUITE in workspace slack travel banking; do
  echo "START suite=$SUITE attack=tool_knowledge time=$(date -Is)"

  python -m security.agentdojo_vukzero.agentdojo_runner \
    --condition C1_agentdojo_vukzero \
    --suite "$SUITE" \
    --model "$AGENTDOJO_MODEL" \
    --attack tool_knowledge \
    --agentdojo-path "$AGENTDOJO_PATH" \
    --logdir "$RUN_ROOT/${SUITE}_tool_knowledge" \
    --force-rerun \
    --fail-on-error \
    > "$RUN_ROOT/${SUITE}_tool_knowledge.out" 2>&1

  STATUS=$?
  echo "END suite=$SUITE status=$STATUS time=$(date -Is)"
  if [ "$STATUS" -ne 0 ]; then
    echo "FAILED suite=$SUITE status=$STATUS" | tee -a "$RUN_ROOT/FAILED.txt"
  else
    echo "DONE suite=$SUITE" | tee -a "$RUN_ROOT/DONE.txt"
  fi
done

echo "finished=$(date -Is)" | tee -a "$RUN_ROOT/RUN_ROOT.txt"
