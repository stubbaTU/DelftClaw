"""SQ3 system-level containment evaluation.

This package evaluates the fallout radius of a compromised agent process
against local mock protected resources. It is intentionally deterministic:
attacks are direct shell/Python/proxy/network attempts, not LLM refusals.
"""

from security.containment_layer.conditions import DEFAULT_CONDITIONS


CONDITION_C0 = "C0_uncontained"
CONDITION_C1 = "C1_vukzero_gvisor"
SUPPORTED_CONDITIONS = DEFAULT_CONDITIONS
