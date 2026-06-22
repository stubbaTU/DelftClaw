"""Step 4 gate: outcome taxonomy + behavioural conformance/interop, offline.

No live endpoint. A stub ``LLMClient`` returns canned Python sources so the full
pipeline — classify the compile, then judge behaviour against the reference — is
exercised deterministically. Four canned echo sources stand in for the four
things a real model does: a correct compile, a non-loading one, one that loads
but fails its own vectors, and (via a raising client) an unreachable endpoint.
"""

from __future__ import annotations

import urllib.error

import pytest

from _echo_sources import BROKEN_BEHAVIOUR, ECHO_CID, ECHO_MD, GOOD, NON_LOADING, VECTOR_BREAKING
from experiments.conformance import evaluate_conformance, evaluate_interop
from experiments.distribution import Candidate, score_distribution
from experiments.live_interop import load_overlay
from experiments.outcomes import CompileResult, Outcome, compile_classified


class StubClient:
    """Returns a fixed source, ignoring the prompt."""
    model_id = "stub"

    def __init__(self, source: str) -> None:
        self._source = source

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        return self._source


class InfraFailClient:
    model_id = "stub"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        self.calls += 1
        raise urllib.error.URLError("simulated endpoint down")


# ---------------------------------------------------------------------------
# Outcome classification (outcomes.py)
# ---------------------------------------------------------------------------

def test_good_source_classifies_ok() -> None:
    result = compile_classified(ECHO_MD, StubClient(GOOD))
    assert result.outcome is Outcome.OK
    assert result.vectors_passed is True
    assert result.source is not None


def test_non_loading_source_is_compile_load_fail() -> None:
    result = compile_classified(ECHO_MD, StubClient(NON_LOADING))
    assert result.outcome is Outcome.COMPILE_LOAD_FAIL
    assert result.source is None


def test_vector_breaking_source_is_compile_vector_fail() -> None:
    result = compile_classified(ECHO_MD, StubClient(VECTOR_BREAKING))
    assert result.outcome is Outcome.COMPILE_VECTOR_FAIL
    assert result.vectors_passed is False
    assert result.source is not None  # it loaded; only the vectors failed


def test_infra_error_is_isolated_and_retried() -> None:
    client = InfraFailClient()
    result = compile_classified(ECHO_MD, client, infra_retries=2, _sleep=lambda _s: None)
    assert result.outcome is Outcome.INFRA_ERROR
    assert client.calls == 3  # initial + 2 retries, never counted as a compile fail


# ---------------------------------------------------------------------------
# Behavioural conformance + interop (conformance.py)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_good_compile_is_conformant() -> None:
    candidate = load_overlay(GOOD, ECHO_CID)
    result = await evaluate_conformance(candidate, "echo")
    assert result.ok


@pytest.mark.asyncio
async def test_behaviourally_broken_compile_is_not_conformant() -> None:
    """Appending "?" instead of "!" passes the descriptor's own vectors yet is
    caught the moment the broken side has to respond — exactly the divergence the
    old length-equality verdict missed."""
    candidate = load_overlay(BROKEN_BEHAVIOUR, ECHO_CID)
    result = await evaluate_conformance(candidate, "echo")
    assert not result.ok
    assert result.as_responder.ok is False        # broken when it must reply
    assert result.as_responder.failed == "echo_happy"


@pytest.mark.asyncio
async def test_two_good_compiles_interoperate() -> None:
    a = load_overlay(GOOD, ECHO_CID)
    b = load_overlay(GOOD, ECHO_CID)
    result = await evaluate_interop(a, b, "echo")
    assert result.ok


@pytest.mark.asyncio
async def test_good_and_broken_do_not_interoperate() -> None:
    good = load_overlay(GOOD, ECHO_CID)
    broken = load_overlay(BROKEN_BEHAVIOUR, ECHO_CID)
    result = await evaluate_interop(good, broken, "echo")
    assert not result.ok


# ---------------------------------------------------------------------------
# Flow-A distribution scoring (distribution.py)
# ---------------------------------------------------------------------------

def _candidate(label: str, model: str, source: str | None, outcome: Outcome) -> Candidate:
    return Candidate(
        label=label, model=model, temperature=0.0,
        result=CompileResult(outcome=outcome, source=source,
                             vectors_passed=(outcome is Outcome.OK) or None))


@pytest.mark.asyncio
async def test_score_distribution_self_and_cross_tagging_and_exclusion() -> None:
    """Three usable compiles across two models plus one vector-fail compile. The
    vector-fail one is excluded from behavioural scoring (its outcome is the
    finding); pairs are tagged self vs cross by model identity."""
    candidates = [
        _candidate("haiku#0", "haiku", GOOD, Outcome.OK),
        _candidate("haiku#1", "haiku", GOOD, Outcome.OK),
        _candidate("sonnet#0", "sonnet", GOOD, Outcome.OK),
        _candidate("haiku#2", "haiku", VECTOR_BREAKING, Outcome.COMPILE_VECTOR_FAIL),
    ]
    result = await score_distribution("echo", candidates)

    # conformance: 3 usable scored True, 1 excluded (conformant=None)
    by_label = {r.label: r for r in result.conformance}
    assert by_label["haiku#0"].conformant is True
    assert by_label["sonnet#0"].conformant is True
    assert by_label["haiku#2"].conformant is None
    assert by_label["haiku#2"].outcome is Outcome.COMPILE_VECTOR_FAIL

    # interop: only the 3 usable compiles pair -> C(3,2)=3 pairs, vector-fail excluded
    assert len(result.interop) == 3
    assert all(row.interop_ok for row in result.interop)
    pairings = sorted(row.pairing for row in result.interop)
    assert pairings == ["cross", "cross", "self"]  # haiku-haiku self; haiku-sonnet x2 cross


@pytest.mark.asyncio
async def test_score_distribution_flags_nonconformant_and_noninterop() -> None:
    candidates = [
        _candidate("good", "haiku", GOOD, Outcome.OK),
        _candidate("broken", "sonnet", BROKEN_BEHAVIOUR, Outcome.OK),
    ]
    result = await score_distribution("echo", candidates)
    conf = {r.label: r.conformant for r in result.conformance}
    assert conf == {"good": True, "broken": False}
    assert len(result.interop) == 1
    assert result.interop[0].interop_ok is False
    assert result.interop[0].pairing == "cross"
