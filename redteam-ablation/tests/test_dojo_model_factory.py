"""Substrate-2 model-backend factory: spec required, passthrough unchanged.

The backend sub-decision is CLOSED (plan 2026-06-10: OpenRouter only). The
default (no-spec) path now raises ``ValueError`` saying a spec is required --
``"openrouter:<model-id>"`` or an explicit element -- REPLACING the old
``NotImplementedError`` gate (plan Step 1). Passing an explicit pipeline
element still returns it unchanged (the offline test seam). The spec-string
paths themselves are pinned in ``test_dojo_model_backend.py``.
"""

from __future__ import annotations

import pytest

from redteam_ablation.substrates.agentdojo_native.model import build_llm

from tests.agentdojo_stub import FakeLLM


def test_default_path_requires_a_spec():
    """build_llm(None) -> ValueError naming the supported spec form (plan
    Step 1: 'None -> ValueError saying a spec is now required' -- this
    REPLACES the old NotImplementedError)."""
    with pytest.raises(ValueError) as excinfo:
        build_llm()
    message = str(excinfo.value)
    assert "openrouter:" in message
    assert "spec" in message.lower()


def test_explicit_element_passes_through_unchanged():
    llm = FakeLLM([])
    assert build_llm(llm) is llm
