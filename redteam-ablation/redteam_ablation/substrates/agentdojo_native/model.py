"""Substrate-2 model-backend factory (plan 2026-06-10, OpenRouter backend, Step 1).

The backend sub-decision is RESOLVED (Lucas, 2026-06-10): **OpenRouter only**.
The claude-cli wrapper was rejected as architecturally unfit (it runs its own
agent loop and executes tools itself, bypassing the ``ToolsExecutionLoop`` seam
where ``IntegrityDefenseElement`` sits); Anthropic-direct was not built -- if
ever needed it becomes another spec prefix here without committing to it now.

``build_llm`` accepts a ``"openrouter:<model-id>"`` spec string and returns an
agentdojo ``OpenAILLM`` pointed at :data:`OPENROUTER_BASE_URL` -- the same
shape as agentdojo's own ``together`` provider (``openai.OpenAI`` with a
``base_url`` override; API_NOTES §7). Constructing the client makes no network
call, but the standing test rule (no provider clients in tests) still applies,
so the client constructor is injectable via ``client_factory``. The API key
comes from ``OPENROUTER_API_KEY`` and a missing or empty key fails loudly
BEFORE any client is constructed -- nothing here may build half a backend.

Passing an explicit, already-built pipeline element returns it unchanged: the
offline test seam the runner and the dojo tests rely on. No spec at all is now
a ``ValueError`` (the backend is chosen; there is no default model to guess).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import openai
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

# OpenRouter's OpenAI-compatible endpoint (API_NOTES §7: mirrors the installed
# `together` provider precedent, with this base_url + OPENROUTER_API_KEY).
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

_SPEC_PREFIX = "openrouter:"

# Representative stock MODEL_NAMES keys per model family (attack-wiring plan
# 2026-06-11, design pin 1). Stock attacks read the model out of
# ``pipeline.name`` via ``get_model_name_from_pipeline`` and raise unless the
# name CONTAINS a stock key -- neither our pipeline names nor OpenRouter ids
# do, so the FAMILY maps to one representative key per prose model name.
_ATTACK_MODEL_ALIASES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("claude", "anthropic"), "claude-3-7-sonnet-20250219"),
    (("gpt", "openai"), "gpt-4o-2024-05-13"),
)


def build_llm(
    spec: BasePipelineElement | str | None = None,
    *,
    client_factory: Callable[..., Any] | None = None,
) -> BasePipelineElement:
    """Return the LLM pipeline element for a Substrate-2 run.

    ``spec`` as a ready pipeline element is passed through unchanged (the
    offline test seam). ``"openrouter:<model-id>"`` builds an ``OpenAILLM``
    against OpenRouter -- the model-id is everything after the FIRST colon
    (OpenRouter ids contain ``/`` and may carry ``:variant`` suffixes, so no
    further splitting). Any other spec, or no spec at all, is a ``ValueError``.

    ``client_factory`` (default ``openai.OpenAI``) is the injectable seam that
    keeps tests offline: it is called exactly once, as
    ``factory(api_key=key, base_url=OPENROUTER_BASE_URL)``, and only after the
    spec and the ``OPENROUTER_API_KEY`` env var have both validated --
    a missing or empty key is a ``RuntimeError`` with nothing half-built.
    """
    if isinstance(spec, BasePipelineElement):
        return spec
    if spec is None:
        raise ValueError(
            "a model spec is required: pass 'openrouter:<model-id>' or an "
            "explicit BasePipelineElement (backend decided 2026-06-10: "
            "OpenRouter only; there is no default model)."
        )
    if not spec.startswith(_SPEC_PREFIX):
        raise ValueError(
            f"unsupported model spec {spec!r}; the only supported form is "
            f"'openrouter:<model-id>' (backend decided 2026-06-10: OpenRouter "
            f"only)."
        )
    # .strip() so a whitespace-padded or whitespace-only id fails HERE, not as
    # an OpenRouter 404 after the run dir and meta.json are already written
    # (review patch, 2026-06-10).
    model_id = spec.split(":", 1)[1].strip()
    if not model_id:
        raise ValueError(
            f"empty model-id in spec {spec!r}; expected "
            f"'openrouter:<model-id>', e.g. 'openrouter:anthropic/"
            f"claude-sonnet-4-6'."
        )
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is missing or empty; set it before a live "
            "dojo run (no client is constructed without it)."
        )
    factory = client_factory if client_factory is not None else openai.OpenAI
    client = factory(api_key=key, base_url=OPENROUTER_BASE_URL)
    # Keep agentdojo's own defaults (reasoning_effort=None, temperature=0.0)
    # so our episodes match the stock pipeline's decoding behaviour.
    return OpenAILLM(client, model_id)


def resolve_attack_model_alias(spec: str) -> str:
    """Map a model spec's family to a representative stock agentdojo key.

    Case-insensitive substring match on the spec: ``claude``/``anthropic``
    resolve to the stock Claude key, ``gpt``/``openai`` to the stock GPT-4
    key. The alias is embedded in the attack's load-target pipeline name so
    stock attacks stay 100% stock (their prose model name comes out of the
    stock ``MODEL_NAMES`` table); the REAL spec is pinned in ``meta.json``.
    An unknown family is a ``ValueError`` naming the spec and the known
    families -- the CLI's fail-fast rung surfaces it before anything runs.
    """
    lowered = spec.lower()
    for markers, alias in _ATTACK_MODEL_ALIASES:
        if any(marker in lowered for marker in markers):
            return alias
    raise ValueError(
        f"cannot resolve an attack model alias for spec {spec!r}; known "
        f"model families: claude/anthropic, gpt/openai (stock attacks read "
        f"the model from the pipeline name, so the family must map to a "
        f"stock agentdojo model key)."
    )
