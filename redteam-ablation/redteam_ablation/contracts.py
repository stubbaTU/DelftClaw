"""Security contracts for the redteam-ablation harness.

Vendored (copied + trimmed) from DelftClaw ``security/contracts.py`` at commit
156ce74e3d1af71009b83f3212ad67238e23eaa2. Only the symbols this harness needs
are kept: the ``ToolRisk`` enum, the ``RedTeamPayload`` / ``ToolDecision`` /
``ExecutionResult`` / ``ToolPolicy`` dataclasses, and the ``attack_success_rate``
helper. Unused symbols (SecurityAction, AccountabilityMetrics, the seedbox /
microtask / tamper / log-integrity dataclasses) were dropped. Stdlib only.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable


class ToolRisk(StrEnum):
    SAFE = "safe"
    SENSITIVE = "sensitive"
    DANGEROUS = "dangerous"


@dataclass(frozen=True)
class RedTeamPayload:
    payload_id: str
    category: str
    text: str
    expected_tool: str
    malicious: bool = True


@dataclass
class ToolDecision:
    """
    Tool request produced by an untrusted reader/reasoning layer.

    This object is a proposal, not authorization to execute.
    """
    tool_name: str
    tool_kwargs: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    source_payload: str = ""
    payload_id: str | None = None
    sender_id: str | None = None


@dataclass
class ExecutionResult:
    """
    Standard result for ASR and accountability measurements.

    attack_success is True only when an unauthorized tool actually executes.

    ``denied_by`` names the interceptor that denied the call (set by
    ``Dispatcher.dispatch`` on its deny path) so the block can be attributed
    WITHOUT re-running ``inspect`` -- it is ``None`` whenever the tool executed
    or was skipped for a reason other than an interceptor denial (e.g. an
    unknown tool with no registered policy).

    ``flagged_by`` is a LOCAL extension over the DelftClaw original (see
    VENDORED.md): the names of interceptors whose verdict carried
    ``flagged=True`` during the inspect loop (the audit-mode detections),
    in inspect order.
    """
    requested_tool: str
    executed: bool
    authorized: bool
    attack_success: bool
    reason: str
    output: Any = None
    payload_id: str | None = None
    sender_id: str | None = None
    denied_by: str | None = None
    flagged_by: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolPolicy:
    """Authorization rule for one tool exposed to the trusted actor layer."""
    name: str
    handler: Callable[[dict[str, Any]], Any]
    required_args: tuple[str, ...] = ()
    risk: ToolRisk = ToolRisk.SAFE
    max_risk: int = 1


def attack_success_rate(results: list[ExecutionResult]) -> float:
    if not results:
        return 0.0
    successes = sum(1 for result in results if result.attack_success)
    return successes / len(results)
