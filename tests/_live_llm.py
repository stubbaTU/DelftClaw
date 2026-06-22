"""Test helpers for the post-stub world: real LLM clients only.

The hand-written ``*_stub.py`` sources and ``StubLLMClient`` were removed so that
*all* overlay compilation goes through a live LLM. Tests therefore use one of
two real clients:

  * ``noop_llm()`` — a real ``OpenAICompatibleClient`` that is never actually
    called. Use it where a test constructs an agent/registry but never triggers
    a compile (it just needs *an* LLMClient object).

  * ``live_compiler_llm()`` — a real client wired to the endpoint in the
    environment (``LLM_BASE_URL``). If no endpoint is configured the test is
    skipped, because there is no offline way to compile an overlay any more.
    Set ``LLM_BASE_URL`` (and ``LLM_API_KEY`` / ``LLM_MODEL``) to run these for
    real, e.g. against the local proxy on :11600.
"""

from __future__ import annotations

import os

import pytest

from protocol import OpenAICompatibleClient


def noop_llm() -> OpenAICompatibleClient:
    """A real client that must never be invoked (unreachable base_url)."""
    return OpenAICompatibleClient(base_url="http://127.0.0.1:0/v1", model_id="unused")


def _endpoint() -> str | None:
    return os.environ.get("LLM_BASE_URL")


def live_compiler_llm() -> OpenAICompatibleClient:
    """Real compiler LLM from env, or skip the test when none is configured.

    Overlay compilation now requires a live model; without an endpoint there is
    nothing to test, so we skip rather than fail.
    """
    base = _endpoint()
    if not base:
        pytest.skip(
            "no live LLM endpoint configured (set LLM_BASE_URL); "
            "overlay-compile tests require a real model since stubs were removed"
        )
    return OpenAICompatibleClient(
        base_url=base,
        model_id=os.environ.get("LLM_MODEL") or "claude-haiku-4-5-20251001",
        api_key=os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or "",
    )


def compile_source(md_text: str) -> str:
    """Compile a markdown descriptor via the live LLM and return the generated
    Python source. Skips the test when no endpoint is configured."""
    from protocol import compile_overlay

    return compile_overlay(md_text, live_compiler_llm()).source


# Module-level guard for whole test modules that cannot run without an endpoint.
requires_live_llm = pytest.mark.skipif(
    not _endpoint(),
    reason="overlay-compile tests require a live LLM endpoint (LLM_BASE_URL); stubs removed",
)
