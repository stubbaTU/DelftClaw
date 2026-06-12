"""Substrate-2 OpenRouter model backend (plan 2026-06-10, Step 1).

The backend sub-decision is CLOSED: OpenRouter ONLY. ``build_llm`` accepts a
``"openrouter:<model-id>"`` spec string and returns an agentdojo ``OpenAILLM``
pointed at :data:`OPENROUTER_BASE_URL`, with the client built through an
injectable ``client_factory`` -- the seam that keeps these tests offline (no
test here constructs a real provider client, per the standing rule).

Explicit-element passthrough (the offline seam) stays pinned where it always
lived, in ``test_dojo_model_factory.py``; that file's default-path test is
updated to the new ``ValueError`` contract (plan Step 1: the spec-required
``ValueError`` REPLACES the old ``NotImplementedError``).
"""

from __future__ import annotations

import pytest

from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

# Import the MODULE, not the new names: a missing OPENROUTER_BASE_URL must
# fail the individual test with AttributeError, not kill collection.
from redteam_ablation.substrates.agentdojo_native import model


class FakeClientFactory:
    """Records construction kwargs and returns an inert sentinel client.

    The plan pins the exact call shape ``factory(api_key=key,
    base_url=OPENROUTER_BASE_URL)`` -- keyword arguments only.
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.client = object()

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.client


def test_openrouter_base_url_constant():
    """Module constant pinned verbatim (plan Step 1, first bullet)."""
    assert model.OPENROUTER_BASE_URL == "https://openrouter.ai/api/v1"


def test_openrouter_spec_builds_openai_llm(monkeypatch):
    """Happy path: spec string + key -> OpenAILLM via the injected factory."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-123")
    factory = FakeClientFactory()

    element = model.build_llm("openrouter:some/model", client_factory=factory)

    assert isinstance(element, OpenAILLM)
    assert element.model == "some/model"
    assert element.client is factory.client
    # Factory called exactly once, with exactly the pinned kwargs.
    assert factory.calls == [
        {"api_key": "sk-or-test-123", "base_url": model.OPENROUTER_BASE_URL}
    ]
    # agentdojo defaults kept (plan Step 1: reasoning_effort=None, temperature=0.0).
    assert element.reasoning_effort is None
    assert element.temperature == 0.0


def test_model_id_is_everything_after_the_first_colon(monkeypatch):
    """OpenRouter ids may contain '/' and further ':'s -- split on the FIRST
    colon only (plan Step 1: do not split on '/'; e.g. variant suffixes)."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-123")
    factory = FakeClientFactory()

    element = model.build_llm(
        "openrouter:anthropic/claude-sonnet-4-6:beta", client_factory=factory
    )

    assert element.model == "anthropic/claude-sonnet-4-6:beta"


def test_missing_api_key_raises_before_any_client(monkeypatch):
    """Missing OPENROUTER_API_KEY -> RuntimeError naming the env var, raised
    BEFORE the factory is ever called (fail loudly, nothing half-built)."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    factory = FakeClientFactory()

    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        model.build_llm("openrouter:some/model", client_factory=factory)

    assert factory.calls == []


def test_empty_api_key_raises_before_any_client(monkeypatch):
    """An empty key is as bad as a missing one: same RuntimeError, factory
    never called (plan Step 1: 'missing or empty')."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "")
    factory = FakeClientFactory()

    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        model.build_llm("openrouter:some/model", client_factory=factory)

    assert factory.calls == []


def test_empty_model_id_is_value_error(monkeypatch):
    """'openrouter:' with nothing after the colon -> ValueError; the factory
    is never called. A valid key is set so the failure can only be the id.
    ``match`` distinguishes the empty-id branch from the unknown-prefix one
    (test-review NIT)."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-123")
    factory = FakeClientFactory()

    with pytest.raises(ValueError, match="model-id"):
        model.build_llm("openrouter:", client_factory=factory)

    assert factory.calls == []


def test_whitespace_only_model_id_is_value_error(monkeypatch):
    """'openrouter:   ' is as empty as 'openrouter:' -- it must fail HERE,
    not as a provider 404 after the run dir is written (review patch A3)."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-123")
    factory = FakeClientFactory()

    with pytest.raises(ValueError, match="model-id"):
        model.build_llm("openrouter:   ", client_factory=factory)

    assert factory.calls == []


def test_padded_model_id_is_stripped(monkeypatch):
    """Accidental whitespace padding around the id is stripped, not sent to
    the provider verbatim (review patch A3)."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-123")
    factory = FakeClientFactory()

    element = model.build_llm("openrouter: some/model ", client_factory=factory)

    assert element.model == "some/model"


def test_unknown_prefix_is_value_error(monkeypatch):
    """Any other spec string (e.g. 'anthropic:x') -> ValueError listing the
    supported spec form; the factory is never called."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-123")
    factory = FakeClientFactory()

    with pytest.raises(ValueError) as excinfo:
        model.build_llm("anthropic:x", client_factory=factory)

    assert "openrouter:" in str(excinfo.value)
    assert factory.calls == []


# ---------------------------------------------------------------------------
# Attack-model alias resolution (plan 2026-06-11 attack wiring, design pin 1)
#
# Stock agentdojo attacks read the pipeline's model name out of pipeline.name
# (get_model_name_from_pipeline) and crash unless it contains a stock MODEL_NAMES
# key. resolve_attack_model_alias maps our real OpenRouter spec's FAMILY to a
# representative stock key so the attack stays 100% stock; the real spec lives
# on in meta.json.
# ---------------------------------------------------------------------------


def test_resolve_attack_model_alias_claude_family():
    """A claude/anthropic spec maps to the representative stock Claude key."""
    assert (
        model.resolve_attack_model_alias("openrouter:anthropic/claude-sonnet-4-6")
        == "claude-3-7-sonnet-20250219"
    )


def test_resolve_attack_model_alias_gpt_family():
    """A gpt/openai spec maps to the representative stock GPT-4 key."""
    assert (
        model.resolve_attack_model_alias("openrouter:openai/gpt-4o")
        == "gpt-4o-2024-05-13"
    )


def test_resolve_attack_model_alias_unknown_family_raises():
    """An unknown family is a ValueError that NAMES the offending spec, so the
    CLI rung can surface a legible fail-fast message."""
    with pytest.raises(ValueError) as excinfo:
        model.resolve_attack_model_alias("openrouter:foo/bar-9")
    assert "openrouter:foo/bar-9" in str(excinfo.value)


def test_resolved_alias_satisfies_stock_get_model_name():
    """Round-trip against the INSTALLED agentdojo: embedding the resolved key
    in a pipeline name lets the stock get_model_name_from_pipeline recover the
    prose name. Pins design pin 1 to the real package, not our own table."""
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.attacks.base_attacks import get_model_name_from_pipeline

    claude_alias = model.resolve_attack_model_alias(
        "openrouter:anthropic/claude-sonnet-4-6"
    )
    pipeline = AgentPipeline([])
    pipeline.name = f"redteam-ablation/V0/{claude_alias}"
    assert get_model_name_from_pipeline(pipeline) == "Claude"

    gpt_alias = model.resolve_attack_model_alias("openrouter:openai/gpt-4o")
    pipeline.name = f"redteam-ablation/V0/{gpt_alias}"
    assert get_model_name_from_pipeline(pipeline) == "GPT-4"
