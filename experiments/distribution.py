"""Flow A — the distribution/adoption arm, scored.

This is the arm that mirrors the deployed demo most directly: a genesis agent
publishes one *fixed* protocol document, every peer compiles it independently
with its own model, and the compilations must behave alike on a live link. We
reproduce that as a measurement by compiling a fixed example descriptor many
times (across models and randomness settings) and scoring the compilations two
ways against the hand-written reference and against each other:

  * **conformance** — per compilation, ``evaluate_conformance`` against the
    reference oracle (absolute correctness);
  * **interop** — per pair of compilations, ``evaluate_interop`` (pairwise
    agreement), with each pair tagged ``self`` (same model) or ``cross``
    (different models), because the deployed network is heterogeneous and
    cross-model agreement is the realistic headline.

The LLM-dependent half (turning a descriptor into source) is isolated in
``compile_candidates`` so the scoring half (``score_distribution``) is a pure,
offline function of the produced sources — that is what the offline gate and the
re-runnable report rest on. The billed runner (Step 6) calls ``compile_candidates``
once and ``score_distribution`` on the result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations

from protocol.llm import LLMClient
from experiments.conformance import evaluate_conformance, evaluate_interop
from experiments.fixtures import get_spec
from experiments.live_interop import LoadedOverlay, load_overlay
from experiments.outcomes import CompileResult, Outcome, compile_classified


@dataclass(frozen=True)
class Candidate:
    """One independent compilation of the rung's fixed descriptor."""
    label: str            # stable id, e.g. "haiku@0.0#3"
    model: str            # model id (the self/cross pairing key)
    temperature: float
    result: CompileResult

    @property
    def usable(self) -> bool:
        """Loaded and passed its own vectors — eligible for behavioural scoring.
        A ``COMPILE_VECTOR_FAIL`` source loaded but is already known defective, so
        it is excluded from conformance/interop (its compile outcome is the
        finding)."""
        return self.result.outcome is Outcome.OK and self.result.source is not None


@dataclass(frozen=True)
class ConformanceRow:
    label: str
    model: str
    temperature: float
    outcome: Outcome
    conformant: bool | None     # None when the compile was not usable
    detail: str | None = None


@dataclass(frozen=True)
class InteropRow:
    a_label: str
    b_label: str
    pairing: str                # "self" | "cross"
    interop_ok: bool
    detail: str | None = None


@dataclass
class DistributionResult:
    rung: str
    conformance: list[ConformanceRow] = field(default_factory=list)
    interop: list[InteropRow] = field(default_factory=list)


def compile_candidates(
    rung: str,
    clients: list[tuple[str, str, float, LLMClient]],
    *,
    infra_retries: int = 2,
) -> list[Candidate]:
    """Compile the rung's FIXED descriptor once per client (the LLM-dependent,
    billed half). ``clients`` is ``(label, model, temperature, client)`` tuples.
    Never raises — every failure is folded into the candidate's ``CompileResult``
    outcome."""
    md_text = get_spec(rung).md_text
    out: list[Candidate] = []
    for label, model, temperature, client in clients:
        result = compile_classified(md_text, client, infra_retries=infra_retries)
        out.append(Candidate(label=label, model=model, temperature=temperature, result=result))
    return out


def _load(rung: str, candidate: Candidate) -> LoadedOverlay:
    community_id = bytes.fromhex(get_spec(rung).community_id_hex)
    assert candidate.result.source is not None
    return load_overlay(candidate.result.source, community_id)


async def score_distribution(
    rung: str,
    candidates: list[Candidate],
    *,
    pairs: list[tuple[int, int]] | None = None,
) -> DistributionResult:
    """Score already-compiled candidates against the reference and each other
    (the offline half). ``pairs`` selects which candidate index pairs to test for
    interop; when omitted, every unordered pair of usable candidates is used (the
    runner passes a sampled subset for large cells)."""
    result = DistributionResult(rung=rung)

    loaded: dict[int, LoadedOverlay] = {}
    for i, cand in enumerate(candidates):
        if not cand.usable:
            result.conformance.append(ConformanceRow(
                label=cand.label, model=cand.model, temperature=cand.temperature,
                outcome=cand.result.outcome, conformant=None, detail=cand.result.error))
            continue
        overlay = _load(rung, cand)
        loaded[i] = overlay
        conf = await evaluate_conformance(overlay, rung)
        detail = None if conf.ok else (
            f"init:{conf.as_initiator.failed} resp:{conf.as_responder.failed}")
        result.conformance.append(ConformanceRow(
            label=cand.label, model=cand.model, temperature=cand.temperature,
            outcome=cand.result.outcome, conformant=conf.ok, detail=detail))

    usable_idx = sorted(loaded)
    pair_iter = pairs if pairs is not None else list(combinations(usable_idx, 2))
    for i, j in pair_iter:
        if i not in loaded or j not in loaded:
            continue
        a, b = candidates[i], candidates[j]
        inter = await evaluate_interop(loaded[i], loaded[j], rung)
        result.interop.append(InteropRow(
            a_label=a.label, b_label=b.label,
            pairing="self" if a.model == b.model else "cross",
            interop_ok=inter.ok,
            detail=None if inter.ok else f"ab:{inter.a_to_b.failed} ba:{inter.b_to_a.failed}"))

    return result
