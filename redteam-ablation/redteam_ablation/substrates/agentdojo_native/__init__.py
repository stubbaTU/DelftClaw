"""Substrate 2: AgentDojo native (plan 2026-06-10 §2; API_NOTES.md is the API pin).

AgentDojo (Debenedetti et al., NeurIPS 2024 D&B; MIT; ``agentdojo==0.1.35``)
runs in its OWN harness; our primitives plug in as a single defense pipeline
element (``defense.IntegrityDefenseElement``) that routes every proposed tool
call through the shared ``Dispatcher``. The suite's benign user tasks feed the
ALR (availability) side; the Workspace injection tasks form the Behaviour
control column (predicted NOT to move under integrity primitives).
"""
