"""P3 constitution-hash integrity interceptor (the V3 defence body).

The interceptor denies a tool call when the session constitution hash
(``context['session_constitution_hash']``) diverges from the published baseline
(``context['published_constitution_hash']``), and allows when they match. This is
the structured-input check the Configuration-class attack (SH-05) trips.
"""

from __future__ import annotations

from redteam_ablation.contracts import ToolDecision
from redteam_ablation.interceptors.constitution_check import (
    ConstitutionHashInterceptor,
)

PUBLISHED = "published-constitution-hash"
TAMPERED = "tampered-constitution-hash"


def _decision():
    return ToolDecision(tool_name="write_file", tool_kwargs={"path": "c"})


def test_name_is_p3_constitution_hash():
    # Plan 2026-06-10 §1.1: the name carries the mode tag; the default mode is strict.
    assert ConstitutionHashInterceptor().name == "P3-constitution-hash[strict]"


def test_allows_on_matching_hash():
    interceptor = ConstitutionHashInterceptor()
    verdict = interceptor.inspect(
        _decision(),
        {
            "published_constitution_hash": PUBLISHED,
            "session_constitution_hash": PUBLISHED,
        },
    )
    assert verdict.allow is True


def test_denies_on_hash_divergence():
    interceptor = ConstitutionHashInterceptor()
    verdict = interceptor.inspect(
        _decision(),
        {
            "published_constitution_hash": PUBLISHED,
            "session_constitution_hash": TAMPERED,
        },
    )
    assert verdict.allow is False
    assert verdict.reason  # a non-empty attribution reason is recorded


def test_fails_closed_when_a_hash_is_missing():
    interceptor = ConstitutionHashInterceptor()
    verdict = interceptor.inspect(
        _decision(), {"published_constitution_hash": PUBLISHED}
    )
    assert verdict.allow is False
