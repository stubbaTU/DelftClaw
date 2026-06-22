"""The two behavioural measures of the SQ3 study: conformance and interop.

Both are defined on the scenario batteries (``sq3.scenarios``) run on the live
two-/three-node mock network (``sq3.oracle.run_scenario``), and both reduce a set
of scripted checkpoints to a single verdict per protocol rung:

  * **Conformance(C)** — does a single compilation ``C`` reproduce the
    hand-written reference's behaviour? Defined as ``match(C, R) ∧ match(R, C)``:
    the candidate is exercised once as the initiating side (with the reference
    responding) and once as the responding side (with the reference initiating),
    so whichever role carries the rung's hard behaviour — the seeder's chunking,
    the payer's de-duplication, the fetcher's reassembly — is covered. This is an
    *absolute* measure against a model-independent oracle (invariant **I3**), so
    it is not the near-tautological "two compiles agree on the wire" of the old
    arm.

  * **Interop(A, B)** — do two *independent* compilations agree with each other?
    Defined as ``match(A, B) ∧ match(B, A)``. Two compilations can each be
    individually conformant yet still diverge on something the battery's
    checkpoints pin but the prose underspecified; interop is what sees that.

``match(X, Y)`` runs every scenario for the rung with ``X`` as role A and ``Y`` as
role B (any further roles filled by the reference, since they are pure senders
whose behaviour is not checkpointed) and passes iff every checkpoint passes.
Because each scenario's expected state was shown to be exactly the reference's
behaviour (the Step 2 gate), passing the checkpoints *is* matching the oracle.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.fixtures import get_spec
from experiments.live_interop import LoadedOverlay
from experiments.oracle import reference_overlay, run_scenario
from experiments.scenarios import Scenario, scenarios_for


@dataclass(frozen=True)
class MatchResult:
    """Whether ``X`` and ``Y`` matched across a rung's battery; on failure,
    ``failed`` names the first scenario whose checkpoints did not all pass."""
    ok: bool
    failed: str | None = None


async def directed_match(
    x: LoadedOverlay, y: LoadedOverlay, rung: str,
    *, scenarios: list[Scenario] | None = None,
) -> MatchResult:
    """``match(X, Y)``: X as role A, Y as role B, reference for any extra role.
    Passes iff every checkpoint of every scenario passes."""
    scs = scenarios if scenarios is not None else scenarios_for(rung)
    for sc in scs:
        spec = get_spec(sc.rung).parsed
        extra = [reference_overlay(sc.rung) for _ in range(sc.n_roles - 2)] or None
        trace = await run_scenario(x, y, sc.steps, spec=spec, extra=extra)
        if not trace.passed:
            return MatchResult(ok=False, failed=sc.name)
    return MatchResult(ok=True)


@dataclass(frozen=True)
class ConformanceResult:
    ok: bool
    as_initiator: MatchResult   # match(C, R)
    as_responder: MatchResult   # match(R, C)


async def evaluate_conformance(candidate: LoadedOverlay, rung: str) -> ConformanceResult:
    """``Conformance(C) = match(C, R) ∧ match(R, C)`` over the rung's battery."""
    scs = scenarios_for(rung)
    ref_for = lambda: reference_overlay(rung)  # noqa: E731 — fresh handle per call
    as_init = await directed_match(candidate, ref_for(), rung, scenarios=scs)
    as_resp = await directed_match(ref_for(), candidate, rung, scenarios=scs)
    return ConformanceResult(ok=as_init.ok and as_resp.ok, as_initiator=as_init, as_responder=as_resp)


@dataclass(frozen=True)
class InteropResult:
    ok: bool
    a_to_b: MatchResult
    b_to_a: MatchResult


async def evaluate_interop(a: LoadedOverlay, b: LoadedOverlay, rung: str) -> InteropResult:
    """``Interop(A, B) = match(A, B) ∧ match(B, A)`` over the rung's battery."""
    scs = scenarios_for(rung)
    ab = await directed_match(a, b, rung, scenarios=scs)
    ba = await directed_match(b, a, rung, scenarios=scs)
    return InteropResult(ok=ab.ok and ba.ok, a_to_b=ab, b_to_a=ba)
