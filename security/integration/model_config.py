"""Model runtime configuration for OpenClaw-compatible remote inference backends."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ModelRuntimeConfig:
    """Resolved model endpoint settings for OpenAI-compatible model APIs."""

    base_url: str
    model: str
    api_key: str


def load_model_runtime_config(openclaw_config_path: str | Path | None = None) -> ModelRuntimeConfig:
    """Resolve model config from env first, then OpenClaw config file.

    Environment precedence:
    - ``OPENAI_API_BASE``
    - ``OPENAI_BASE_URL``
    - ``OPENAI_API_KEY``
    - ``OPENAI_MODEL``

    OpenClaw config fallback:
    - ``~/.openclaw/openclaw.json`` (or supplied path)
    - attempts to find provider URL and default model keys.
    """
    env_base = (
        os.getenv("OPENAI_API_BASE")
        or os.getenv("OPENAI_BASE_URL")
        or os.getenv("OPENAI_API_BASE_URL")
    )
    env_model = os.getenv("OPENAI_MODEL") or os.getenv("MODEL")
    env_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY") or "dummy"

    config_doc = _read_openclaw_config(openclaw_config_path)
    cfg_base = _extract_base_url(config_doc)
    cfg_model = _extract_default_model(config_doc)

    base_url = (env_base or cfg_base or "").rstrip("/")
    model = (env_model or cfg_model or "").strip()

    if not base_url:
        raise ValueError(
            "Model base URL is not configured. Set OPENAI_API_BASE/OPENAI_BASE_URL or configure ~/.openclaw/openclaw.json"
        )
    if not model:
        raise ValueError(
            "Model name is not configured. Set OPENAI_MODEL or configure a default model in ~/.openclaw/openclaw.json"
        )

    return ModelRuntimeConfig(base_url=base_url, model=model, api_key=env_key)


def _read_openclaw_config(openclaw_config_path: str | Path | None) -> dict[str, Any]:
    if openclaw_config_path is None:
        openclaw_config_path = Path.home() / ".openclaw" / "openclaw.json"
    path = Path(openclaw_config_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _extract_base_url(doc: dict[str, Any]) -> str | None:
    candidates = [
        _dig(doc, "openai", "base_url"),
        _dig(doc, "openai", "baseUrl"),
        _dig(doc, "model", "base_url"),
        _dig(doc, "model", "baseUrl"),
        _dig(doc, "providers", "openai", "base_url"),
        _dig(doc, "providers", "openai", "baseUrl"),
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_default_model(doc: dict[str, Any]) -> str | None:
    candidates = [
        _dig(doc, "model", "default"),
        _dig(doc, "model", "defaultModel"),
        _dig(doc, "defaultModel"),
        _dig(doc, "default_model"),
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _dig(doc: dict[str, Any], *path: str) -> Any:
    cur: Any = doc
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

