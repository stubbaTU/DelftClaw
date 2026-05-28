"""AgentDojo adapter for evaluating VukZero as SQ1 condition C4."""

from security.agentdojo_vukzero.vukzero_tool_wrapper import (
    build_agentdojo_tool_broker,
    make_vukzero_pipeline_element,
    wrap_agentdojo_tool,
    wrap_functions_runtime,
)

C0_AGENTDOJO_BASELINE = "C0_agentdojo_baseline"
C4_AGENTDOJO_VUKZERO = "C4_agentdojo_vukzero"

__all__ = [
    "C0_AGENTDOJO_BASELINE",
    "C4_AGENTDOJO_VUKZERO",
    "build_agentdojo_tool_broker",
    "make_vukzero_pipeline_element",
    "wrap_agentdojo_tool",
    "wrap_functions_runtime",
]
