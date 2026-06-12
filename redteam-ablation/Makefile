# redteam-ablation -- offline harness make targets.
#
# Windows venv python (use this exact interpreter; everything is offline):
#   C:/Users/lucas/Documents/Research Project/redteam-ablation/.venv/Scripts/python.exe
#
# PY is overridable for POSIX checkouts, e.g.  make ablation PY=.venv/bin/python
PY ?= .venv/Scripts/python.exe

RUN_ID ?= smoke
N      ?= 10
MODEL  ?= claude-cli/claude-sonnet-4-6

.PHONY: help test ablation ablation-live phase-a table smoke

help:
	@echo "targets: test | ablation | ablation-live | table | smoke  (phase-a = deprecated alias of ablation)"
	@echo "vars:    PY=$(PY)  RUN_ID=$(RUN_ID)  N=$(N)  MODEL=$(MODEL)"

# Full offline test suite.
test:
	"$(PY)" -m pytest -q

# Run the offline grid (FakeRuntime, all arms) -> runs/$(RUN_ID)/trials.jsonl
ablation:
	"$(PY)" -m redteam_ablation.cli ablation --fake --n $(N) --run-id $(RUN_ID)

# Substrate 1 LIVE path (VPS-only; real OpenClaw + Sonnet, $0 metered): provisions
# per-trial HOMEs, starts the harness MCP server, runs `openclaw agent`, tails the
# session JSONL, judges. Network-touching -- never run in the offline test loop.
ablation-live:
	"$(PY)" -m redteam_ablation.cli ablation --live --n $(N) --run-id $(RUN_ID) --model $(MODEL)

# Deprecated alias (plan 2026-06-10 §1.6): kept pointing at `ablation`.
phase-a: ablation

# Aggregate runs/$(RUN_ID)/trials.jsonl -> cell_asr.csv + class_matrix.csv +
# class_entropy.csv (the `table` subcommand writes all three).
table:
	"$(PY)" -m redteam_ablation.cli table --run-id $(RUN_ID)

# Convenience: run the grid and build the table in one go.
smoke: ablation table
